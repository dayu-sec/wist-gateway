//! 采集日志：数据面转发记录的**本地落盘**与管理面查看。
//!
//! ## 与事实摘要同一通道、不同落点
//!
//! agentd 把两者都打成帧发给数据面（日志 `LOGRAW:`，事实 `OBSFACT:`），warp-parse 解析成记录后
//! POST 到网关的**内部**接入端点（明文、只绑环回，见 [`super::ingest`]）。但落点不同：
//! 事实摘要是小对象、要判重与推断，进 SQLite；日志是无界的观测流，先落**本地 NDJSON 文件**
//! （见 [`crate::infra::AgentLogFile`]）。
//!
//! ## 校验的边界
//!
//! 这条路径**不带 agent 凭据**（与事实那条同因：数据面接入的身份校验方案尚未定档）。
//! 这里只做一件正确性检查：`agent_id` 必须在登记表里 —— 否则一台被吊销或拼错的机器会被写进
//! 日志文件，而没有任何一层能发现。**实例对不上发现不了**：日志帧里没有 `instance_id`
//! （`macos_agent_record` OML 不产这个字段），这是已知缺口。
//!
//! ## 为什么整批失败就回非 2xx
//!
//! 与事实那条同一个理由：warp-parse 的 http sink 对非 2xx 会重试并最终落 rescue 文件 ——
//! 那是**可见的**。反过来，若这里对永久性错误回 202，记录会静默消失。

use std::sync::Mutex;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::infra::{AgentLogFile, AgentLogRecord};

use super::ingest::preview;
use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};

/// 内部接入端点的 body 上限。
///
/// 比事实那条宽（事实是 2×摘要上限）：日志正文 `raw` 是**原文**，采集闸门允许一条多行记录到
/// 1 MiB。sink 现在是逐条发（`batch_size = 1`），把上限开大是为「将来调批量」留余量。
pub const MAX_LOG_INGEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// 单次请求最多接受的记录条数：上限的用处是「一台机器不能把网关写爆」，不是精确估算。
const MAX_LOG_RECORDS_PER_REQUEST: usize = 4096;

/// 管理面查看的默认 / 最大条数。
const DEFAULT_LOG_QUERY_LIMIT: usize = 200;
const MAX_LOG_QUERY_LIMIT: usize = 1000;

/// 追加写的进程内串行化：同一时刻只允许一个请求写日志文件。
///
/// 网关是异步的，而这里是**阻塞文件 IO**（与 `install_package` / `file_sha256_hex` 同一取舍）。
/// 串行化只为保证两次 `write_all` 不交错 —— 交错出来的半条记录会让尾部整段不可解析。
static APPEND_LOCK: Mutex<()> = Mutex::new(());

/// 数据面记录中与日志有关的字段（其余如 `biz`/`env`/`sink`/`wp_oml_name` 我们不消费）。
#[derive(Debug, Deserialize)]
struct DataPlaneLogRecord {
    /// 帧信封里的自称 agent。身份以登记表为准，这里只用来查表。
    #[serde(default)]
    agent_id: String,
    /// **采集面**与**目录单元 id**（可选）：`family` 闭集，见
    /// `doc/design/center/collection-families.md`。旧版 agentd、以及本机手工配置的输入
    /// 都不带这两个字段（`serde(default)` 兼容）。
    #[serde(default)]
    family: String,
    #[serde(default)]
    unit: String,
    #[serde(default)]
    observed_at: String,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    category: String,
    #[serde(default)]
    log_desc: String,
    /// 记录原文（OML `macos_agent_record` 的 `raw`）。
    raw: String,
}

/// 内部接入端点：接收 warp-parse 转发来的日志记录。
///
/// 接受单个记录对象，也接受记录数组（sink 的 `batch_size` 调大就会出现数组）。
pub async fn ingest_agent_logs(
    State(state): State<ApiState>,
    Json(payload): Json<Value>,
) -> Response {
    let records = match payload {
        Value::Array(items) => items,
        other => vec![other],
    };
    if records.len() > MAX_LOG_RECORDS_PER_REQUEST {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "too many records in one request: {} (limit {MAX_LOG_RECORDS_PER_REQUEST})",
                records.len()
            ),
        )
            .into_response();
    }

    let received_at = chrono::Utc::now().to_rfc3339();
    let mut accepted: Vec<AgentLogRecord> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for (index, raw) in records.iter().enumerate() {
        match parse_log_record(&state, raw, &received_at).await {
            Ok(record) => accepted.push(record),
            Err(detail) => failures.push(format!("record #{index}: {detail}")),
        }
    }

    // 有拒收就整批不落：让数据面重试并最终落 rescue（可见），而不是把
    // 「一半收到、一半丢掉」静默成 202。批次为 1 时（当前配置）代价就是那一条重试。
    let ingested = if failures.is_empty() {
        match append(&state, &accepted) {
            Ok(()) => accepted.len(),
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to append agent logs: {err}"),
                )
                    .into_response();
            }
        }
    } else {
        0
    };

    let body = json!({
        "ingested": ingested,
        "rejected": failures.len(),
        "failures": failures,
    });
    if failures.is_empty() {
        (StatusCode::ACCEPTED, Json(body)).into_response()
    } else {
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

/// 处理一条记录。`Err` 里的字符串会原样回给数据面并进日志，所以要写清是**哪一步**失败。
async fn parse_log_record(
    state: &ApiState,
    raw: &Value,
    received_at: &str,
) -> Result<AgentLogRecord, String> {
    let record: DataPlaneLogRecord = serde_json::from_value(raw.clone()).map_err(|err| {
        // 带上原始形状：数据面的记录结构变化时，这条错误要能直接指出收到了什么。
        format!(
            "not a data-plane log record: {err}; received {}",
            preview(raw)
        )
    })?;
    if record.agent_id.is_empty() {
        return Err("missing agent_id".to_string());
    }
    // 登记表是这条路径唯一的身份锚：不存在的机器不得被写进日志文件。
    let known = state
        .store
        .agent_exists(&record.agent_id)
        .await
        .map_err(|err| format!("failed to load agent {}: {err}", record.agent_id))?;
    if !known {
        return Err(format!("unknown agent_id {}", record.agent_id));
    }
    Ok(AgentLogRecord {
        agent_id: record.agent_id,
        family: record.family,
        unit: record.unit,
        observed_at: record.observed_at,
        seq: record.seq,
        category: record.category,
        log_desc: record.log_desc,
        raw: record.raw,
        received_at: received_at.to_string(),
    })
}

fn append(state: &ApiState, records: &[AgentLogRecord]) -> std::io::Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let file = AgentLogFile::new(state.config.agent_log_file());
    // 锁中毒（持锁线程 panic）不该让日志从此写不进去：取回内部值继续用。
    let _guard = APPEND_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    file.append(records)
}

/// 管理面查看的查询参数。
#[derive(Debug, Deserialize)]
pub struct AgentLogQuery {
    /// 只留这台 Agent 的记录；不填 = 全部。
    pub agent_id: Option<String>,
    /// 只留这个**采集面**的记录（闭集，如 `NetworkFirewall`）；不填 = 所有面。
    ///
    /// 为什么需要它：正文规则未就绪时 `category` 恒为泛化的 `agent.log`，
    /// 面是唯一能把“这些是 launchd 的、那些是 wifi 的”分开的字段。
    pub family: Option<String>,
    /// 最多返回多少条（默认 200，上限 1000）。
    pub limit: Option<usize>,
}

/// 管理面查看的响应。
#[derive(Debug, Serialize)]
pub struct AgentLogsResponse {
    /// 命中记录，按写入顺序（旧 → 新）。
    pub logs: Vec<AgentLogRecord>,
    /// 本次生效的条数上限。
    pub limit: usize,
    /// 回看窗口被截断：更早的记录这次没返回（不是「只有这些」）。
    pub truncated: bool,
    /// 落盘文件路径。运维要 `tail` / `grep` 原文时得知道它在哪。
    pub file: String,
}

/// 管理面：查看已落盘的采集日志。
pub async fn view_agent_logs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AgentLogQuery>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LOG_QUERY_LIMIT)
        .clamp(1, MAX_LOG_QUERY_LIMIT);
    let file = AgentLogFile::new(state.config.agent_log_file());
    match file.tail(query.agent_id.as_deref(), query.family.as_deref(), limit) {
        Ok(tail) => Json(AgentLogsResponse {
            logs: tail.records,
            limit,
            truncated: tail.truncated,
            file: file.path().display().to_string(),
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read agent logs: {err}"),
        )
            .into_response(),
    }
}
