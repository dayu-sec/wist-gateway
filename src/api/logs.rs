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

use super::codes;
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

use super::error::ApiError;
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
    ///
    /// 两种字段名都要认：旧模型（wp-rules < 1.0.18）叫 `agent_id`，当前模型叫 `agent`。
    #[serde(default, alias = "agent")]
    agent_id: String,
    /// **采集面**与**目录单元 id**（可选）：`family` 闭集，见
    /// `doc/design/center/collection-families.md`。旧版 agentd、以及本机手工配置的输入
    /// 都不带这两个字段（`serde(default)` 兼容）。
    #[serde(default)]
    family: String,
    #[serde(default)]
    unit: String,
    /// 观测时间：旧模型叫 `observed_at`，当前模型叫 `ts`。
    #[serde(default, alias = "ts")]
    observed_at: String,
    #[serde(default)]
    seq: u64,
    /// 分类 / 日志类型：旧模型叫 `category`，当前模型叫 `log_type`。
    #[serde(default, alias = "log_type")]
    category: String,
    #[serde(default)]
    log_desc: String,
    /// 记录原文（旧模型 OML 的 `raw`）。
    ///
    /// **当前模型（wp-rules ≥ 1.0.18）大多不再保留整行**：结构化规则把正文拆成字段后
    /// 就没有 `raw` 了（实测 2 万条里 1.7 万条缺它）。所以这里不再必填 —— 缺了就依次回退到
    /// `log`、最后整条记录的 JSON。否则整批 400，数据面会把每一条都写进 rescue。
    #[serde(default)]
    raw: String,
    /// 解析后的日志正文（当前模型的可读字段）。
    #[serde(default)]
    log: String,
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
        return ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            codes::INGEST_LOGS_TOO_MANY_RECORDS,
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
                return ApiError::internal(
                    codes::LOG_INGEST_APPEND_FAILED,
                    "failed to append agent logs",
                    err,
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
        // 非 2xx 是故意的：让数据面重试并最终落 rescue（可见），而不是静默丢。
        // 这个 body 是**领域响应**（逐条失败明细），不是通用错误信封 —— 保留 `{ingested,rejected,failures}`。
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
        return Err(format!(
            "not a data-plane log record: missing agent_id; received {}",
            preview(raw)
        ));
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
    let text = record_text(&record, raw);
    if let Some(kind) = contract_frame_kind(&record, raw) {
        // 事实 / 快照 / 指标帧有各自的 sink 分组；一旦误投到 `gateway-logs`（`oml=["*"]` 兑底），
        // 必须拒收 —— 否则会被当成一条「日志」写进文件。以前 `raw` 必填时正是这个 400 让误配显形的，
        // 现在 raw 可空，就要用帧类型把这张安全网补回来。
        return Err(format!(
            "not a data-plane log record: {kind} frame must not be ingested as a log; received {}",
            preview(raw)
        ));
    }
    if text.is_empty() {
        // 只有信封、没有任何内容字段的「日志」没有意义：宁可显形，也不要写一行空正文进去。
        return Err(format!(
            "not a data-plane log record: empty log body; received {}",
            preview(raw)
        ));
    }
    Ok(AgentLogRecord {
        agent_id: record.agent_id,
        family: record.family,
        unit: record.unit,
        observed_at: record.observed_at,
        seq: record.seq,
        category: record.category,
        log_desc: record.log_desc,
        raw: text,
        received_at: received_at.to_string(),
    })
}

/// 帧类型（不是日志）对应的 `log_type`：`agent_uplink` 包的三种上行帧。
const CONTRACT_FRAME_TYPES: &[&str] = &[
    "agent_uplink_obs_fact",
    "agent_uplink_obs_dsnap",
    "agent_uplink_metrics_frame",
];

/// 这条记录是不是「契约帧误投到日志通道」。
///
/// 两个判据：`log_type` 命中帧类型（新模型）；或者既没 `raw` 也没 `log`，却带着契约正文 `body`
/// （旧/未来帧形状的傅底）。命中即拒收，让误配在数据面可见（rescue），而不是静默污染日志文件。
fn contract_frame_kind(record: &DataPlaneLogRecord, raw: &Value) -> Option<String> {
    if CONTRACT_FRAME_TYPES.contains(&record.category.as_str()) {
        return Some(record.category.clone());
    }
    if record.raw.is_empty() && record.log.is_empty() && raw.get("body").is_some() {
        return Some("contract".to_string());
    }
    None
}

/// 供展示的正文：优先原文 `raw`，其次解析出的 `log`，都没有就把**内容字段**序列化成 JSON。
///
/// 为什么不直接空着：空白日志行在页面上与「采集失败」无法区分；而结构化记录本身也是证据。
/// 为什么要把信封 / 元数据字段剔掉：否则展示出来的是 `{"schema","agent","ts","dev_ip",…}`，
/// 跟正文无关。
fn record_text(record: &DataPlaneLogRecord, raw: &Value) -> String {
    if !record.raw.is_empty() {
        return record.raw.clone();
    }
    if !record.log.is_empty() {
        return record.log.clone();
    }
    content_json(raw)
}

/// 信封与元数据字段：它们不是「日志正文」，回退到 JSON 展示时要剔掉。
const ENVELOPE_FIELDS: &[&str] = &[
    "schema",
    "agent",
    "agent_id",
    "ts",
    "seq",
    "event_id",
    "now",
    "dev_ip",
    "dev_vendor",
    "dev_name",
    "dev_type",
    "log_type",
    "log_desc",
    "env",
    "tenant_id",
    "wist-gw_id",
    "sink",
    "wp_oml_name",
    "category",
    "family",
    "unit",
    "observed_at",
];

/// 把记录里剩下的**内容字段**压成一行 JSON；没有任何内容字段时返回空串（由调用方拒收）。
fn content_json(raw: &Value) -> String {
    let Some(object) = raw.as_object() else {
        return String::new();
    };
    let kept: serde_json::Map<String, Value> = object
        .iter()
        .filter(|(key, _)| !ENVELOPE_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if kept.is_empty() {
        return String::new();
    }
    serde_json::to_string(&kept).unwrap_or_default()
}

fn append(state: &ApiState, records: &[AgentLogRecord]) -> std::io::Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let file = AgentLogFile::with_retention(
        state.config.agent_log_file(),
        state.config.agent_log_retention(),
    );
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
    let file = AgentLogFile::with_retention(
        state.config.agent_log_file(),
        state.config.agent_log_retention(),
    );
    match file.tail(query.agent_id.as_deref(), query.family.as_deref(), limit) {
        Ok(tail) => Json(AgentLogsResponse {
            logs: tail.records,
            limit,
            truncated: tail.truncated,
            file: file.path().display().to_string(),
        })
        .into_response(),
        Err(err) => ApiError::internal(codes::LOGS_READ_FAILED, "failed to read agent logs", err)
            .into_response(),
    }
}
