//! 一次性调查（`investigate`）：下发命令 + 读回数据面落盘的完整报告。
//!
//! ## 两条腿，两个通道
//!
//! | 产物 | 通道 | 落点 |
//! | --- | --- | --- |
//! | 结论摘要 | **控制面**（agent 的下一次状态上报回执 `command_acks`） | 网关 `agent_commands` 表 |
//! | 完整报告 | **数据面**（agentd 发 ` IVSREP: ` 帧 → wparse） | 网关本机 `<data-plane>/data/ivsrep/*.jsonl` |
//!
//! 为什么报告不塞进 ack：ack 是每 3s 一条的控制报文，一份 `disk` 报告几十 KB —— 塞进去等于
//! 让所有机器的心跳为一次调查让路。报告走数据面与 `LOGREC`/`OBSFACT`/`DSNAP` 同一条通道，
//! 两边靠 `command_id` join（agentd 已把它写进正文）。
//!
//! ## 为什么这里只读目录、不做「收件箱」
//!
//! 报告的**写入者是 wparse**（栈里由 `business.d/agent_ivsrep.toml` 的 file sink 决定），
//! 网关只按既有布局读：`<data_plane work_dir>/data/ivsrep/`（与「采集日志」tail
//! `data/out_dat` 同一个模型，compose 已把整个 `data/` 只读挂进来）。
//! 这样网关不需要新的入站端点、不需要缓存层，也不与 wparse 争「谁是唯一写者」。
//!
//! 安全边界（这些端点能读文件，边界必须写在代码里）：
//!   - 目录是**推导**出来的固定路径，不接受调用方传路径；
//!   - 只认 `.json` / `.jsonl` / `.ndjson`，不跟随符号链接，`canonicalize` 后必须仍在根内；
//!   - 文件数 / 总字节 / 报告条数三重上限；单条报告超过上限就跳过（不截断 JSON）。
//!
//! ## 为什么报告按 `(agent, command_id)` 过滤与去重
//!
//! wparse 的 file sink 是**追加写**，且数据面在重试时会重复投递（at-least-once）。
//! 所以同一份报告可能出现多次：按 `command_id` 去重、保留 `seq` 最大的那条；
//! 归属只看**帧信封里的 `agent`**（与网关内部接入端点同一条纪律：身份不从记录字段来），
//! 信封缺 `agent` 的记录直接跳过 —— 宁可少显示一条，也不把别人的报告挂到这台机器上。
//!
//! ## 两道闸（与采集/上送授权完全无关）
//!
//! | 闸 | 回答 | 落点 |
//! | --- | --- | --- |
//! | **G1 授权** | 谁对哪台机器发起了这次调查 | `requested_by`（`admin:<token 指纹>`）随命令入库、由视图回显 |
//! | **G2 能力** | 这台机器认不认识这道题 | agent 上报的 `investigation_capabilities`；**入队前**校验，不认识回 409 |
//!
//! 调查**不**受采集面就绪度、也不受数据面上送开关约束（那两道的意义是“持续外发内容”，
//! 而调查是一次性只读证据 —— 详见 `doc/design/center/investigation-surfaces.md`）。

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wist_contracts::capability_report::InvestigationCapabilities;

use super::admin_auth::{admin_actor, require_admin_bearer};
use super::admin_ops::agent_not_found_response;
use super::agent_ops::PENDING_COMMAND_TTL_MS;
use super::{ApiError, ApiState, codes, rate_limit};
use crate::infra::StoredAgentCommand;

/// 调查命令的 kind —— 直接用词表**唯一来源**（`wist_api::status::command_kind`）。
///
/// 不在这里再写一份字面量：agentd 侧也是同一个常量（`investigate::COMMAND_KIND`），
/// 两处字面量迟早会漂（漂了以后只会在回执侧表现为一条没人认的 kind）。
const INVESTIGATE_KIND: &str = wist_api::status::command_kind::INVESTIGATE;

/// 调查题目词表（与 agentd `investigate::TOPICS` 同源口径：只增不改名）。
///
/// 新增题目=两侧一起加：这里加 id，agentd 加实现；**不要在网关猜一个题目下发**
/// （agentd 对不认识的题目回 `failed`，页面会看到一条没法解释的失败）。
const TOPICS: &[&str] = &["disk"];

/// 报告目录相对数据面工作根的位置（与 `business.d/agent_ivsrep.toml` 的 `base` 对齐）。
const REPORT_DIR: &str = "data/ivsrep";

/// 一次最多看多少个报告文件。
const MAX_REPORT_FILES: usize = 32;
/// 所有报告文件合计最多读多少字节（报告是小文件；这挡住「目录被别的产物塞满」）。
const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
/// 单个文件最多读**尾部**多少字节（sink 只追加、不轮转，所以文件一定会长过账；读尾而不是跳过）。
///
/// 2 MiB 已经是「列表最多 50 条」的十几倍：再大多读的全是页面根本不会显示的旧报告。
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// 一次最多返回多少条报告。
const MAX_REPORTS: usize = 50;

// ── 下发 ─────────────────────────────────────────────────────────────────

/// 一次调查请求（`topic` 缺省 = `disk`；其余字段缺省由题目自己定）。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchInvestigationRequest {
    #[serde(default)]
    pub topic: Option<String>,
    /// 扫描根（绝对路径）。`None` = 由题目挑（磁盘题：最紧张的文件系统挂载点）。
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub top: Option<u32>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub depth: Option<u32>,
    #[serde(default)]
    pub max_seconds: Option<u64>,
}

/// 把请求收敛成**窄参数**（与 agentd 的夹紧规则同值：网关不放宽，也不替 agent 猜）。
///
/// 返回 `(params JSON, topic)`：`topic` 还要拿去与这台 agent 自报的能力、以及本网关的
/// 允许集（`[investigations] allowed_topics`）对一遍。
fn build_params(request: &LaunchInvestigationRequest) -> Result<(String, String), Box<ApiError>> {
    let topic = request.topic.as_deref().unwrap_or("disk").trim();
    if !TOPICS.contains(&topic) {
        return Err(Box::new(ApiError::bad_request(
            codes::INVESTIGATION_UNKNOWN_TOPIC,
            format!(
                "unknown investigation topic {topic:?} (known: {})",
                TOPICS.join(", ")
            ),
        )));
    }
    let mut params = serde_json::Map::new();
    params.insert("topic".to_string(), Value::String(topic.to_string()));
    if let Some(path) = request.path.as_deref() {
        let path = path.trim();
        if path.is_empty() {
            return Err(Box::new(ApiError::bad_request(
                codes::INVESTIGATION_BAD_PARAMS,
                "path must not be blank",
            )));
        }
        if !is_safe_absolute_path(path) {
            // 相对路径取决于进程 cwd：同一台机器换一种启动方式就扫到别的目录。
            return Err(Box::new(ApiError::bad_request(
                codes::INVESTIGATION_BAD_PARAMS,
                format!("path must be an absolute path without `..`: {path:?}"),
            )));
        }
        params.insert("path".to_string(), Value::String(path.to_string()));
    }
    if let Some(top) = request.top {
        params.insert("top".to_string(), Value::from(top.clamp(1, 50)));
    }
    if let Some(depth) = request.depth {
        params.insert("depth".to_string(), Value::from(depth.clamp(1, 64)));
    }
    if let Some(max_seconds) = request.max_seconds {
        params.insert(
            "max_seconds".to_string(),
            Value::from(max_seconds.clamp(1, 30)),
        );
    }
    if let Some(min_size) = request.min_size {
        params.insert("min_size".to_string(), Value::from(min_size));
    }
    Ok((Value::Object(params).to_string(), topic.to_string()))
}

/// 本网关**允许**触发的工作面（配置 ∩ 词表）。
///
/// `None` = 全部已知面；空表 = 一个都不许。配置里写错的 id 会被静默滤掉（不会变成 500），
/// 但会从「允许集」里消失 —— 页面看得到的就是真正生效的那几个。
///
/// 参数是 `Option<&[String]>` 而不是 `&ApiState`：这条规则应该能**不搭台也能测**。
fn effective_allowed_topics(configured: Option<&[String]>) -> Vec<&'static str> {
    match configured {
        None => TOPICS.to_vec(),
        Some(allowed) => TOPICS
            .iter()
            .copied()
            .filter(|topic| allowed.iter().any(|value| value == topic))
            .collect(),
    }
}

/// 这个面在本网关是否被允许（`[investigations] allowed_topics`）。
fn ensure_allowed(state: &ApiState, topic: &str) -> Result<Vec<&'static str>, Box<ApiError>> {
    let allowed = effective_allowed_topics(state.config.investigation_allowed_topics.as_deref());
    if allowed.contains(&topic) {
        return Ok(allowed);
    }
    let listed = if allowed.is_empty() {
        "none".to_string()
    } else {
        allowed.join(", ")
    };
    Err(Box::new(ApiError::forbidden(
        codes::INVESTIGATION_NOT_ALLOWED,
        format!("investigation topic {topic:?} is disabled on this gateway (allowed: {listed})"),
    )))
}

/// 每台 agent 每小时的额度（`[investigations] max_per_agent_per_hour`；`0` = 不限）。
///
/// 数的是**发起次数**（含已被覆盖、已确认的）—— 额度拦的是“连点 / 脚本误触”，不是成果。
#[allow(clippy::result_large_err)]
async fn ensure_quota(
    state: &ApiState,
    agent_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Response> {
    let limit = state.config.investigation_max_per_agent_per_hour;
    if limit == 0 {
        return Ok(());
    }
    let since = now.timestamp_millis() - 60 * 60 * 1000;
    match state
        .store
        .count_agent_commands_since(agent_id, INVESTIGATE_KIND, since)
        .await
    {
        Ok(count) if count >= u64::from(limit) => Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            codes::INVESTIGATION_QUOTA_EXCEEDED,
            format!(
                "agent {agent_id} already has {count} investigations in the last hour \
                 (limit {limit}); check the existing reports before retrying"
            ),
        )
        .into_response()),
        Ok(_) => Ok(()),
        Err(err) => Err(ApiError::internal(
            codes::AGENT_COMMAND_LOAD_FAILED,
            "failed to count recent investigations",
            err,
        )
        .into_response()),
    }
}

/// 报告是否还在**可见保留期**内（`[investigations] report_retention_days`；`0` = 不限）。
///
/// 只影响“能不能看到”，**不删文件**：报告目录由数据面写入，网关是只读方。
/// 时间读报告自带的 `observed_at`（缺/解析不了就当仍在期，不因为脏数据把人挡在外面）。
fn within_retention(
    observed_at: &str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if retention_days == 0 {
        return true;
    }
    let Ok(observed) = chrono::DateTime::parse_from_rfc3339(observed_at) else {
        return true;
    };
    now.signed_duration_since(observed.with_timezone(&chrono::Utc))
        <= chrono::Duration::days(i64::from(retention_days))
}

/// 这台 agent 自报的调查能力；`None` = 还没报过（旧 agentd / 升级后还没上报过状态）。
#[allow(clippy::result_large_err)]
async fn load_investigation_capabilities(
    state: &ApiState,
    agent_id: &str,
) -> Result<Option<InvestigationCapabilities>, Response> {
    match state.store.get_agent(agent_id).await {
        Ok(Some(agent)) => Ok(agent.investigation_capabilities),
        Ok(None) => Err(ApiError::not_found(
            codes::AGENT_NOT_FOUND,
            format!("unknown agent {agent_id}"),
        )
        .into_response()),
        Err(err) => {
            Err(
                ApiError::internal(codes::AGENT_STORE_UNAVAILABLE, "failed to load agent", err)
                    .into_response(),
            )
        }
    }
}

/// **G2（能力闸）**：这台机器认不认识这道题。
///
/// 为什么拦在**入队前**而不是把命令发下去：agentd 对不认识的题目只能回 `failed`，
/// 而管理面上“命令失败”与“这台机器不会 / 没升级 / 没权限”是完全不同的处置。
/// 尤其是 `None`（从没报过）：**当作不可用**，宁可让菜单置灰，也不发一条注定失败的调查。
fn ensure_supported(
    capabilities: Option<&InvestigationCapabilities>,
    topic: &str,
) -> Result<(), Box<ApiError>> {
    let Some(capabilities) = capabilities else {
        return Err(Box::new(ApiError::conflict(
            codes::INVESTIGATION_UNSUPPORTED,
            "agent has not reported investigation capabilities yet \
             (agentd < 0.11.0, or no status report since the upgrade)",
        )));
    };
    if capabilities.surfaces.iter().any(|surface| surface == topic) {
        return Ok(());
    }
    let reported = if capabilities.surfaces.is_empty() {
        "none".to_string()
    } else {
        capabilities.surfaces.join(", ")
    };
    Err(Box::new(ApiError::conflict(
        codes::INVESTIGATION_UNSUPPORTED,
        format!("agent does not support investigation topic {topic:?} (reported: {reported})"),
    )))
}

/// 绝对路径且不含 `..`：题目自己还会再判一次，这里只挡住明显写错。
fn is_safe_absolute_path(path: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir))
}

/// `POST /api/v1/admin/agents/{agent_id}/investigations`：下发一次调查。
///
/// body 可省（不带 body = 默认的 `disk` 调查）：`curl -X POST` 也能用，
/// 而页面总是显式 `{}`。
pub async fn launch_agent_investigation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(agent_id): AxumPath<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    body: Option<Json<LaunchInvestigationRequest>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let request = body.map(|Json(request)| request).unwrap_or_default();
    let (params, topic) = match build_params(&request) {
        Ok(built) => built,
        Err(err) => return (*err).into_response(),
    };
    // 两道闸，顺序是刻意的：先问「这个网关让不让」（策略），再问「这台机器会不会」（能力），
    // 最后问「现在还能不能再发」（额度）。三道失败的原因不同，页面能给出不同处置。
    let allowed = match ensure_allowed(&state, &topic) {
        Ok(allowed) => allowed,
        Err(err) => return (*err).into_response(),
    };
    let capabilities = match load_investigation_capabilities(&state, &agent_id).await {
        Ok(capabilities) => capabilities,
        Err(response) => return response,
    };
    if let Err(err) = ensure_supported(capabilities.as_ref(), &topic) {
        return (*err).into_response();
    }
    let now = chrono::Utc::now();
    if let Err(response) = ensure_quota(&state, &agent_id, now).await {
        return response;
    }
    let command = StoredAgentCommand {
        // 微秒做 id：同一毫秒内连点两次也不能撞成一个（撞了会被 `DO NOTHING` 吞掉）。
        command_id: format!("cmd_{}_investigate_{}", agent_id, now.timestamp_micros()),
        agent_id: agent_id.clone(),
        kind: INVESTIGATE_KIND.to_string(),
        params,
        requested_at_ms: now.timestamp_millis(),
        acked_at: None,
        outcome: None,
        detail: None,
        // G1：审计——调查读的是客户机上的路径/文件名，必须能回答“这是谁点的”。
        requested_by: admin_actor(&state.config),
    };
    // 同 kind 的未确认命令被覆盖：连点只保留最后一次 —— 调查是只读的，跑两遍没有意义，
    // 而两份报告只会让「哪份是这次的」说不清。
    match state.store.enqueue_agent_command(&command, true).await {
        Ok(()) => Json(InvestigationLaunchResponse {
            agent_id,
            capabilities: capabilities_view(capabilities.as_ref()),
            allowed_topics: allowed.into_iter().map(str::to_string).collect(),
            command: command_view(Some(&command)),
        })
        .into_response(),
        Err(err) => ApiError::internal(
            codes::AGENT_COMMAND_STORE_FAILED,
            "failed to enqueue investigation command",
            err,
        )
        .into_response(),
    }
}

// ── 查看 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ReportDirView {
    configured: bool,
    path: Option<String>,
}

#[derive(Debug, Serialize)]
struct InvestigationCommandView {
    command_id: Option<String>,
    kind: Option<String>,
    /// 谁发起的（审计）：`admin:<token 指纹>`；空 = 本机命令 / 历史记录。
    requested_by: Option<String>,
    requested_at: Option<String>,
    acknowledged_at: Option<String>,
    outcome: Option<String>,
    detail: Option<String>,
}

fn command_view(command: Option<&StoredAgentCommand>) -> InvestigationCommandView {
    match command {
        Some(command) => InvestigationCommandView {
            command_id: Some(command.command_id.clone()),
            kind: Some(command.kind.clone()),
            requested_by: Some(command.requested_by.clone()),
            requested_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                command.requested_at_ms,
            )
            .map(|at| at.to_rfc3339()),
            acknowledged_at: command.acked_at.clone(),
            outcome: command.outcome.clone(),
            detail: command.detail.clone(),
        },
        None => InvestigationCommandView {
            command_id: None,
            kind: None,
            requested_by: None,
            requested_at: None,
            acknowledged_at: None,
            outcome: None,
            detail: None,
        },
    }
}

#[derive(Debug, Serialize)]
struct InvestigationCapabilitiesView {
    pub surfaces: Vec<String>,
    pub privileged: bool,
}

fn capabilities_view(
    capabilities: Option<&InvestigationCapabilities>,
) -> Option<InvestigationCapabilitiesView> {
    capabilities.map(|capabilities| InvestigationCapabilitiesView {
        surfaces: capabilities.surfaces.clone(),
        privileged: capabilities.privileged,
    })
}

#[derive(Debug, Serialize)]
struct InvestigationLaunchResponse {
    agent_id: String,
    /// 这台 agent 自报的调查能力（`None` = 还没报过）—— 页面据此置灰菜单。
    capabilities: Option<InvestigationCapabilitiesView>,
    /// 本网关允许的面（配置 ∩ 词表）：与 `capabilities` 的**交集**才是可点的。
    allowed_topics: Vec<String>,
    command: InvestigationCommandView,
}

/// 一条报告的**列表视图**（不带正文：列表不该为几十 KB 的报告付费）。
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct InvestigationReportView {
    pub command_id: String,
    pub topic: String,
    pub observed_at: String,
    /// 结论档：`ok` / `warn` / `fail`；报告里没写就是 `unknown`。
    pub overall: String,
    pub verdict: String,
    pub findings_ok: u64,
    pub findings_warn: u64,
    pub findings_fail: u64,
    /// 帧里的 `seq`：同 `command_id` 重复投递时按它保留最新的一条。
    pub seq: u64,
}

/// 本 agent 的**调查额度**：页面要能回答「为什么点了没反应（429）」而不必去翻配置。
#[derive(Debug, Serialize)]
struct InvestigationQuotaView {
    /// 每小时上限（`[investigations] max_per_agent_per_hour`；`0` = 不限）。
    limit_per_hour: u32,
    /// 最近一小时**已发起**次数（数的是尝试，含被覆盖/未确认的）。`None` = 库读不出来。
    used_last_hour: Option<u64>,
}

#[derive(Debug, Serialize)]
struct InvestigationListResponse {
    pub agent_id: String,
    /// 这台 agent 自报的调查能力（`None` = 还没报过）—— 与下发时的闸同一口径。
    pub capabilities: Option<InvestigationCapabilitiesView>,
    /// 本网关允许的面（配置 ∩ 词表）。
    pub allowed_topics: Vec<String>,
    /// 本 agent 的额度使用情况。
    pub quota: InvestigationQuotaView,
    /// 报告的**可见**保留天数（`0` = 不限）；超期的报告不会出现在 `reports` 里。
    pub retention_days: u32,
    pub report_dir: ReportDirView,
    pub latest_command: InvestigationCommandView,
    pub reports: Vec<InvestigationReportView>,
}

#[derive(Debug, Serialize)]
struct InvestigationReportResponse {
    pub agent_id: String,
    pub command_id: String,
    /// 报告正文（agentd `Report::to_json` 的原样对象，已含 `command_id`）。
    pub report: Value,
}

/// 报告目录：数据面工作根下的固定相对路径。未配置（没挂载）时 `None`。
fn report_dir(state: &ApiState) -> Option<PathBuf> {
    state
        .config
        .data_plane_work_dir
        .as_ref()
        .map(|root| root.join(REPORT_DIR))
}

/// `GET /api/v1/admin/agents/{agent_id}/investigations`。
///
/// 一次拿全「最近一次下发 + 这个 Agent 的报告列表」：页面只轮询这一个端点。
pub async fn list_agent_investigations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(agent_id): AxumPath<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    expire_stale_commands(&state, &agent_id).await;
    let capabilities = match load_investigation_capabilities(&state, &agent_id).await {
        Ok(capabilities) => capabilities,
        Err(response) => return response,
    };
    let command = match state
        .store
        .get_latest_agent_command(&agent_id, INVESTIGATE_KIND)
        .await
    {
        Ok(command) => command,
        Err(err) => {
            return ApiError::internal(
                codes::AGENT_COMMAND_LOAD_FAILED,
                "failed to load agent command",
                err,
            )
            .into_response();
        }
    };
    let dir = report_dir(&state);
    let retention_days = state.config.investigation_report_retention_days;
    let now = chrono::Utc::now();
    // 额度使用数：读不出来不影响整页（`None` = 页面显示 `—`，但授权/报告照常展示）。
    let used_last_hour = match state
        .store
        .count_agent_commands_since(
            &agent_id,
            INVESTIGATE_KIND,
            now.timestamp_millis() - 60 * 60 * 1000,
        )
        .await
    {
        Ok(count) => Some(count),
        Err(err) => {
            log::warn!(
                "event=InvestigationQuotaUnreadable agent_id={} detail=\"{err}\"",
                agent_id
            );
            None
        }
    };
    let reports = match dir.as_deref() {
        Some(dir) => match load_agent_reports(dir, &agent_id, retention_days, now) {
            Ok(reports) => reports,
            Err(err) => {
                // 目录不可读 ≠ 「没有报告」：说清楚，别让页面显示一片空白。
                log::warn!(
                    "event=InvestigationReportsUnreadable agent_id={} dir={} detail=\"{err}\"",
                    agent_id,
                    dir.display()
                );
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    Json(InvestigationListResponse {
        agent_id,
        capabilities: capabilities_view(capabilities.as_ref()),
        allowed_topics: effective_allowed_topics(
            state.config.investigation_allowed_topics.as_deref(),
        )
        .into_iter()
        .map(str::to_string)
        .collect(),
        quota: InvestigationQuotaView {
            limit_per_hour: state.config.investigation_max_per_agent_per_hour,
            used_last_hour,
        },
        retention_days,
        report_dir: ReportDirView {
            configured: dir.is_some(),
            path: dir.map(|dir| dir.display().to_string()),
        },
        latest_command: command_view(command.as_ref()),
        reports,
    })
    .into_response()
}

/// `GET /api/v1/admin/agents/{agent_id}/investigations/{command_id}`：读回完整报告。
pub async fn view_agent_investigation_report(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath((agent_id, command_id)): AxumPath<(String, String)>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let Some(dir) = report_dir(&state) else {
        return ApiError::not_found(
            codes::INVESTIGATION_REPORT_NOT_FOUND,
            "investigation report directory is not mounted ([data_plane] work_dir unset)",
        )
        .into_response();
    };
    match find_agent_report(
        &dir,
        &agent_id,
        &command_id,
        state.config.investigation_report_retention_days,
        chrono::Utc::now(),
    ) {
        Ok(Some(report)) => Json(InvestigationReportResponse {
            agent_id,
            command_id,
            report,
        })
        .into_response(),
        Ok(None) => ApiError::not_found(
            codes::INVESTIGATION_REPORT_NOT_FOUND,
            format!("no investigation report for command {command_id}"),
        )
        .into_response(),
        Err(err) => ApiError::internal(
            codes::INVESTIGATION_REPORT_NOT_FOUND,
            "failed to read investigation reports",
            err,
        )
        .into_response(),
    }
}

/// 与 `view_agent_fact_refresh` 同一套收口：长期离线 / 旧 agent 的命令不该永远显示「等待认领」。
async fn expire_stale_commands(state: &ApiState, agent_id: &str) {
    let now = chrono::Utc::now();
    if let Err(err) = state
        .store
        .expire_pending_agent_commands(
            agent_id,
            now.timestamp_millis() - PENDING_COMMAND_TTL_MS,
            &now.to_rfc3339(),
        )
        .await
    {
        log::warn!(
            "event=AgentCommandExpireFailed agent_id={} detail=\"{err}\"",
            agent_id
        );
    }
}

// ── 读报告 ───────────────────────────────────────────────────────────────

/// 目录里的一条记录（已按 `command_id` 去重、按 `seq` 取最新）。
#[derive(Debug)]
struct StoredReport {
    view: InvestigationReportView,
    report: Value,
}

/// 读这个 Agent 的报告（新 → 旧，最多 [`MAX_REPORTS`] 条）。
///
/// `retention_days` = 可见保留期（`0` = 不限）：超期的报告不返回。
fn load_agent_reports(
    dir: &Path,
    agent_id: &str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> io::Result<Vec<InvestigationReportView>> {
    Ok(collect_reports(dir, agent_id)?
        .into_iter()
        .filter(|report| within_retention(&report.view.observed_at, retention_days, now))
        .map(|report| report.view)
        .collect())
}

/// 找一份指定 `command_id` 的报告正文。
///
/// 同样受可见保留期约束：过期后**按 id 也读不回来**（否则“过期”只是列表看不见）。
fn find_agent_report(
    dir: &Path,
    agent_id: &str,
    command_id: &str,
    retention_days: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> io::Result<Option<Value>> {
    Ok(collect_reports(dir, agent_id)?
        .into_iter()
        .find(|report| {
            report.view.command_id == command_id
                && within_retention(&report.view.observed_at, retention_days, now)
        })
        .map(|report| report.report))
}

fn collect_reports(dir: &Path, agent_id: &str) -> io::Result<Vec<StoredReport>> {
    let canonical_root = match fs::canonicalize(dir) {
        Ok(root) => root,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut files: Vec<PathBuf> = fs::read_dir(&canonical_root)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .map(|entry| entry.path())
        .filter(|path| is_report_file(path))
        .collect();
    // 先排序再截断：`read_dir` 的顺序本来就不保证，先 `take` 就变成「每次看的文件集可能不同」，
    // 大到目录被塞满时会出现「同一份报告一会儿在一会儿没了」。
    // 倒序 = **新 → 旧**：轮转文件名通常按时间排列（`…20261030.jsonl`），而报告本身也有
    // 字节 / 条数预算 —— 预算要花在最新的证据上，不能先被最老的文件吃掉。
    files.sort_by(|left, right| right.cmp(left));
    files.truncate(MAX_REPORT_FILES);

    let mut by_command: BTreeMap<String, StoredReport> = BTreeMap::new();
    let mut total = 0u64;
    for file in files {
        // 符号链接逃逸：`read_dir` 出来的路径也要 `canonicalize` 后再判是否仍在根内。
        let Ok(real) = fs::canonicalize(&file) else {
            continue;
        };
        if !real.starts_with(&canonical_root) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&real) else {
            continue;
        };
        // 预算 = 单文件上限 ∩ 剩余总量。预算花完就不再往下读：按倒序遍历，后面的文件更旧。
        let remaining = MAX_TOTAL_BYTES.saturating_sub(total);
        let budget = metadata.len().min(MAX_FILE_BYTES).min(remaining);
        if budget == 0 {
            break;
        }
        let Ok(bytes) = read_tail(&real, budget) else {
            continue;
        };
        total += bytes.len() as u64;
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(report) = parse_report_line(&record, agent_id) else {
                continue;
            };
            // at-least-once：同一 `command_id` 保留 `seq` 最大的那条。
            match by_command.get(&report.view.command_id) {
                Some(existing) if existing.view.seq >= report.view.seq => {}
                _ => {
                    by_command.insert(report.view.command_id.clone(), report);
                }
            }
        }
    }

    let mut reports: Vec<StoredReport> = by_command.into_values().collect();
    reports.sort_by(|left, right| {
        right
            .view
            .seq
            .cmp(&left.view.seq)
            .then_with(|| right.view.observed_at.cmp(&left.view.observed_at))
    });
    reports.truncate(MAX_REPORTS);
    Ok(reports)
}

/// 读文件**尾部**至多 `budget` 字节（不足则全读），并丢掉被截断的第一行。
///
/// 为什么读尾不读头：sink 是**追加**写的，新报告在末尾；而且 wparse 不轮转报告文件
/// （`agent-ivsrep.jsonl` 会一直长），最先撞上的是“文件比上限还大”—— 那时把整个文件跳掉，
/// 页面就会从「有报告」突变成「没报告」，而这正是出事时最不能出现的假象。
fn read_tail(path: &Path, budget: u64) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len <= budget {
        let mut bytes = Vec::with_capacity(len as usize);
        file.read_to_end(&mut bytes)?;
        return Ok(bytes);
    }
    file.seek(SeekFrom::Start(len - budget))?;
    let mut bytes = Vec::with_capacity(budget as usize);
    file.read_to_end(&mut bytes)?;
    // 第一行几乎肯定被切了一半：从第一个换行之后开始（整段没有换行就什么都不要）。
    match bytes.iter().position(|byte| *byte == b'\n') {
        Some(index) => {
            bytes.drain(..=index);
        }
        None => bytes.clear(),
    }
    Ok(bytes)
}

fn is_report_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".json") || lower.ends_with(".jsonl") || lower.ends_with(".ndjson")
}

/// 把一行数据面记录解析成报告。
///
/// 记录形状（`business.d/agent_ivsrep.toml` 的 file sink 输出）：
/// ```text
/// {"schema":"v1","agent":"<id>","ts":"…","seq":12,…,"body":"<Report JSON 字符串>"}
/// ```
/// `body` 是字符串（OML 把帧正文当 `chars` 读），所以要再解一层；也接受已经是对象的情况
/// （将来 OML 改成结构化字段时不用改网关）。
fn parse_report_line(record: &Value, agent_id: &str) -> Option<StoredReport> {
    // 归属只看信封：与网关内部接入端点同一条纪律（身份不从正文自称来）。
    let envelope_agent = record.get("agent").and_then(Value::as_str)?;
    if envelope_agent != agent_id {
        return None;
    }
    let body = match record.get("body") {
        Some(Value::String(text)) => serde_json::from_str::<Value>(text).ok()?,
        Some(value @ Value::Object(_)) => value.clone(),
        _ => return None,
    };
    let command_id = body.get("command_id").and_then(Value::as_str)?.to_string();
    let topic = body
        .get("topic")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let observed_at = body
        .get("observed_at")
        .and_then(Value::as_str)
        .or_else(|| record.get("ts").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string();
    let summary = body.get("summary");
    let count = |key: &str| {
        summary
            .and_then(|summary| summary.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let overall = summary
        .and_then(|summary| summary.get("overall"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let verdict = body
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let seq = record.get("seq").and_then(Value::as_u64).unwrap_or(0);
    Some(StoredReport {
        view: InvestigationReportView {
            command_id,
            topic,
            observed_at,
            overall,
            verdict,
            findings_ok: count("ok"),
            findings_warn: count("warn"),
            findings_fail: count("fail"),
            seq,
        },
        report: body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-gateway-investigations-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn report_line(agent: &str, seq: u64, command_id: &str) -> String {
        let body = serde_json::json!({
            "command": "investigate",
            "topic": "disk",
            "report_schema": "wist.investigation.disk/v1",
            "observed_at": "2026-10-30T10:00:00Z",
            "command_id": command_id,
            "findings": [],
            "summary": { "ok": 3, "warn": 1, "fail": 0, "overall": "warn" },
            "verdict": "3 项正常 / 1 项警告 / 0 项失败"
        })
        .to_string();
        serde_json::json!({
            "schema": "v1",
            "agent": agent,
            "ts": "2026-10-30T10:00:00Z",
            "seq": seq,
            "body": body,
        })
        .to_string()
    }

    #[test]
    fn params_are_narrowed_to_the_agentd_vocabulary() {
        let (params, topic) = build_params(&LaunchInvestigationRequest {
            topic: None,
            path: Some("/var".to_string()),
            top: Some(500),
            min_size: None,
            depth: Some(0),
            max_seconds: Some(10_000),
        })
        .expect("params");
        assert_eq!(topic, "disk");
        let value: Value = serde_json::from_str(&params).expect("json");
        assert_eq!(value["topic"], "disk");
        assert_eq!(value["path"], "/var");
        assert_eq!(value["top"], 50, "top 由网关夹紧，不放宽");
        assert_eq!(value["depth"], 1);
        assert_eq!(value["max_seconds"], 30);
        assert!(value.get("min_size").is_none(), "没给就不发");
    }

    #[test]
    fn unknown_topics_and_unsafe_paths_are_rejected() {
        let unknown = build_params(&LaunchInvestigationRequest {
            topic: Some("memory".to_string()),
            ..Default::default()
        });
        assert!(unknown.is_err(), "不认识的题目必须拒绝，不能猜一个");

        for path in ["var/log", "/var/../etc", ""] {
            let err = build_params(&LaunchInvestigationRequest {
                path: Some(path.to_string()),
                ..Default::default()
            });
            assert!(err.is_err(), "path {path:?} 应被拒绝");
        }
    }

    /// `[investigations] allowed_topics`：`None` = 全开；空表 = 全关；写错的 id 被滤掉。
    #[test]
    fn the_allowed_topic_set_is_config_intersected_with_the_vocabulary() {
        assert_eq!(effective_allowed_topics(None), TOPICS.to_vec());
        assert!(
            effective_allowed_topics(Some(&[])).is_empty(),
            "空表 = 一个都不许"
        );
        assert_eq!(
            effective_allowed_topics(Some(&["disk".to_string()])),
            vec!["disk"]
        );
        // 配置里写错/写了不存在的面：静默滤掉（不能变成 500，也不能“默认放行”）。
        let configured = vec!["nope".to_string(), "disk".to_string()];
        assert_eq!(effective_allowed_topics(Some(&configured)), vec!["disk"]);
        assert!(effective_allowed_topics(Some(&["nope".to_string()])).is_empty());
    }

    /// 可见保留期：只在窗口内返回；`0` = 不限；坏时间戳留着（不因脏数据把人挡在外面）。
    #[test]
    fn reports_are_only_visible_inside_the_retention_window() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-30T12:00:00Z")
            .expect("ts")
            .with_timezone(&chrono::Utc);

        assert!(within_retention("2026-10-30T11:00:00Z", 7, now));
        assert!(!within_retention("2026-10-01T11:00:00Z", 7, now));
        // 0 = 不限。
        assert!(within_retention("2020-01-01T00:00:00Z", 0, now));
        // 缺 / 坏值：保留（宁可多显示一条，也不把“时间格式不对”变成“看不到报告”）。
        assert!(within_retention("", 7, now));
        assert!(within_retention("not-a-time", 7, now));
    }

    #[test]
    fn reports_are_filtered_by_envelope_agent_and_deduped_by_command_id() {
        let dir = temp_dir("dedupe");
        let file = dir.join("agent-ivsrep.jsonl");
        let mut text = String::new();
        text.push_str(&report_line("agent-a", 5, "cmd-1"));
        text.push('\n');
        // 同一 command_id 的重复投递（数据面 at-least-once）：保留 seq 更大的那条。
        text.push_str(&report_line("agent-a", 9, "cmd-1"));
        text.push('\n');
        text.push_str(&report_line("agent-a", 6, "cmd-2"));
        text.push('\n');
        text.push_str(&report_line("agent-b", 99, "cmd-3"));
        text.push('\n');
        // 坏行：跳过，不影响其它报告。
        text.push_str("not json\n");
        fs::write(&file, text).expect("write reports");

        let reports = load_agent_reports(&dir, "agent-a", 0, chrono::Utc::now()).expect("load");
        assert_eq!(reports.len(), 2, "只留本机的两条，且 cmd-1 去重");
        assert_eq!(reports[0].command_id, "cmd-1", "按 seq 倒序");
        assert_eq!(reports[0].seq, 9, "保留 seq 更大的那条");
        assert_eq!(reports[1].command_id, "cmd-2");
        assert_eq!(reports[0].overall, "warn");
        assert_eq!(reports[0].findings_warn, 1);

        let body = find_agent_report(&dir, "agent-a", "cmd-2", 0, chrono::Utc::now())
            .expect("find")
            .expect("report");
        assert_eq!(body["command_id"], "cmd-2");
        assert!(
            find_agent_report(&dir, "agent-a", "cmd-3", 0, chrono::Utc::now())
                .expect("find")
                .is_none(),
            "别人的报告不能挂到这台机器上"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_report_dir_is_an_empty_list_not_an_error() {
        let dir = temp_dir("missing-child").join("nope");
        assert!(
            load_agent_reports(&dir, "agent-a", 0, chrono::Utc::now())
                .expect("load")
                .is_empty()
        );
    }

    /// `body` 不是 JSON（数据面只搬字符串，不验证）：跳过，不影响相邻的好报告。
    #[test]
    fn a_record_with_an_unparsable_body_is_skipped() {
        let dir = temp_dir("bad-body");
        let mut text = String::new();
        text.push_str(&report_line("agent-a", 1, "cmd-good"));
        text.push('\n');
        text.push_str(
            &serde_json::json!({
                "schema": "v1",
                "agent": "agent-a",
                "ts": "2026-10-30T10:00:00Z",
                "seq": 2,
                "body": "not-json",
            })
            .to_string(),
        );
        text.push('\n');
        // 信封都对、但正文里没有 command_id（无法关联到命令）：同样跳过。
        text.push_str(
            &serde_json::json!({
                "schema": "v1",
                "agent": "agent-a",
                "ts": "2026-10-30T10:00:00Z",
                "seq": 3,
                "body": "{\"topic\":\"disk\"}",
            })
            .to_string(),
        );
        text.push('\n');
        fs::write(dir.join("agent-ivsrep.jsonl"), text).expect("write");

        let reports = load_agent_reports(&dir, "agent-a", 0, chrono::Utc::now()).expect("load");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].command_id, "cmd-good");
        let _ = fs::remove_dir_all(dir);
    }

    /// 目录里文件多于 [`MAX_REPORT_FILES`] 时，取哪几个必须**确定**（先排序再截断）。
    ///
    /// 以前的写法是先 `take` 再 `sort`，而 `read_dir` 的顺序本来就不保证 ——
    /// 同一份报告会出现“一会儿在一会儿没了”。取的是**新的那一批**：轮转文件名按时间排列，
    /// 留老的不如留新的。
    #[test]
    fn more_report_files_than_the_cap_keeps_the_newest_files() {
        let dir = temp_dir("many-files");
        for index in 0..(MAX_REPORT_FILES + 8) {
            fs::write(
                dir.join(format!("f{index:03}.jsonl")),
                format!(
                    "{}\n",
                    report_line("agent-a", index as u64, &format!("cmd-{index:03}"))
                ),
            )
            .expect("write");
        }

        let reports = load_agent_reports(&dir, "agent-a", 0, chrono::Utc::now()).expect("load");
        assert_eq!(reports.len(), MAX_REPORT_FILES);
        let newest = MAX_REPORT_FILES + 7;
        assert!(
            reports
                .iter()
                .any(|report| report.command_id == format!("cmd-{newest:03}")),
            "最新的文件必须在（预算要先花在新证据上）"
        );
        assert!(
            !reports.iter().any(|report| report.command_id == "cmd-000"),
            "超出上限的文件不该时而出现时而消失"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// 文件长于读取预算时，要能读到**尾部**（新报告）—— 否则 sink 不轮转，
    /// 文件一超上限页面就会从「有报告」变成「没报告」。
    #[test]
    fn an_oversized_file_still_yields_its_newest_lines() {
        let dir = temp_dir("tail");
        let mut text = String::new();
        for index in 0..20 {
            text.push_str(&report_line("agent-a", index, &format!("cmd-{index:02}")));
            text.push('\n');
        }
        let file = dir.join("agent-ivsrep.jsonl");
        fs::write(&file, &text).expect("write");

        // 预算小于文件：能且只能读到最后几行，且首行（被切了一半）不能造出假报告。
        let budget = 400u64;
        let bytes = read_tail(&file, budget).expect("read tail");
        assert!((bytes.len() as u64) <= budget, "不能超预算");
        let tail = String::from_utf8(bytes).expect("tail is utf-8");
        assert!(tail.starts_with('{'), "首行必须是被切掉后的完整行：{tail}");
        let last = tail.lines().last().expect("at least one line");
        let record: Value = serde_json::from_str(last).expect("last line parses");
        assert_eq!(record["seq"], 19, "读到的最后一行就是文件最后一行");

        // 预算 >= 文件：全读。
        let all = read_tail(&file, text.len() as u64 + 1).expect("read all");
        assert_eq!(all.len(), text.len());
        let _ = fs::remove_dir_all(dir);
    }

    /// 只认报告扩展名：同目录里别的文本产物不能被当成报告读进来。
    #[test]
    fn files_with_other_extensions_are_ignored() {
        let dir = temp_dir("extensions");
        fs::write(dir.join("notes.txt"), report_line("agent-a", 1, "cmd-txt")).expect("write txt");
        fs::write(
            dir.join("agent-ivsrep.jsonl"),
            report_line("agent-a", 2, "cmd-jsonl"),
        )
        .expect("write jsonl");

        let reports = load_agent_reports(&dir, "agent-a", 0, chrono::Utc::now()).expect("load");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].command_id, "cmd-jsonl");
        let _ = fs::remove_dir_all(dir);
    }

    /// 目录里的符号链接不能把读取带出报告目录（即使它叫 `.jsonl`）。
    #[cfg(unix)]
    #[test]
    fn symbolic_links_never_escape_the_report_directory() {
        let outside = temp_dir("outside");
        fs::write(
            outside.join("real.jsonl"),
            report_line("agent-a", 7, "cmd-evil"),
        )
        .expect("write outside");

        let dir = temp_dir("symlink");
        std::os::unix::fs::symlink(outside.join("real.jsonl"), dir.join("evil.jsonl"))
            .expect("symlink");

        assert!(
            load_agent_reports(&dir, "agent-a", 0, chrono::Utc::now())
                .expect("load")
                .is_empty(),
            "符号链接不能被当成本目录里的报告"
        );
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
    }
}
