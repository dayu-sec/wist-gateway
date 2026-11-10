//! 命令队列（只读）：网关给 agentd 排队的**一次性命令**。
//!
//! 为什么单独一个视图：命令散在各功能页（调查 / 重采 / 刷新 / 指标标签），
//! 但「这台机器现在要执行什么、哪些是中心下发的」没有一个统一答案。
//! 队列本身早就在 `agent_commands` 里（`enqueue_agent_command` 是唯一写入口），
//! 这里只把它读出来 —— 不新增入队通道，也不改 agentd 的投递协议。
//!
//! 两条口：
//!
//! | 端点 | 用途 |
//! | --- | --- |
//! | `GET /api/v1/admin/agents/{agent_id}/commands` | 单台机器：待执行 / 执行中 / 已回执 |
//! | `GET /api/v1/admin/agent-commands` | 全机队：还有谁在等 agentd（`state` 缺省只看队列态） |
//!
//! **来源（`source`）由 `requested_by` 派生**：`center*` = 中心经 gwlinkd 下发，
//! `admin*` = 网关页面/接口发起，其它 = 系统。中心侧自己的账本在 center 的
//! `commands` 里；这里回答的是「网关实际排了什么、agentd 做没做」。

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;
use wist_api::status::command_outcome;

use crate::infra::StoredAgentCommand;

use super::{
    ApiState, admin_auth::require_admin_bearer, admin_ops::agent_not_found_response, codes,
    error::ApiError, rate_limit,
};

/// 一次最多返回多少条（队列页看的是「现在要做什么」，不是历史归档）。
const MAX_QUEUE_LIMIT: usize = 200;
const DEFAULT_QUEUE_LIMIT: usize = 50;

/// 允许的状态过滤词表（闭集：未知值报 400，而不是悄悄当成 `all`）。
const STATES: &[&str] = &["queued", "claimed", "acked", "expired", "superseded", "all"];

#[derive(Debug, Default, serde::Deserialize)]
pub struct CommandQueueQuery {
    /// `queued` / `claimed` / `acked` / `expired` / `superseded` / `all`（缺省 `all`）。
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// 只在全机队口上用：按 agent 过滤。
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct QueueItemView {
    command_id: String,
    agent_id: String,
    kind: String,
    /// `queued` / `claimed` / `acked` / `expired` / `superseded`
    state: &'static str,
    /// `center` / `admin` / `system` —— 谁排的这条命令。
    source: &'static str,
    requested_by: String,
    /// 一行提示：调查是 `topic=disk`，刷新是 `what=a,b`；参数里没这两种就是空串。
    summary: String,
    requested_at: Option<String>,
    claimed_at: Option<String>,
    acknowledged_at: Option<String>,
    outcome: Option<String>,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommandQueueView {
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    state: String,
    /// 队列态计数（不受 `state` 过滤影响）：页面的徽标用它。
    counts: QueueCounts,
    commands: Vec<QueueItemView>,
}

#[derive(Debug, Serialize)]
struct QueueCounts {
    queued: u64,
    claimed: u64,
}

/// `GET /api/v1/admin/agents/{agent_id}/commands`
pub async fn admin_agent_command_queue(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Query(query): Query<CommandQueueQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    respond(&state, Some(&agent_id), query).await
}

/// `GET /api/v1/admin/agent-commands`（全机队）。
///
/// 缺省 `state=queued`：这一页的默认问题是「还有谁在等 agentd」。
pub async fn admin_command_queue(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    headers: HeaderMap,
    Query(query): Query<CommandQueueQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 全机队口的 `agent_id` 是过滤条件；不存在也不报 404（那是一张列表）。
    let agent_id = query.agent_id.clone();
    respond(&state, agent_id.as_deref(), query).await
}

async fn respond(state: &ApiState, agent_id: Option<&str>, query: CommandQueueQuery) -> Response {
    let state_filter = query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("all");
    if !STATES.contains(&state_filter) {
        return ApiError::bad_request(
            codes::INVALID_STATE,
            format!(
                "unknown state {state_filter:?} (known: {})",
                STATES.join(", ")
            ),
        )
        .into_response();
    }
    let filter = (state_filter != "all").then_some(state_filter);
    let limit = query
        .limit
        .unwrap_or(DEFAULT_QUEUE_LIMIT)
        .clamp(1, MAX_QUEUE_LIMIT);

    let commands = match state
        .store
        .list_agent_commands(agent_id, filter, limit)
        .await
    {
        Ok(commands) => commands,
        Err(err) => {
            return ApiError::internal(
                codes::AGENT_STORE_UNAVAILABLE,
                "failed to load command queue",
                err,
            )
            .into_response();
        }
    };
    let (queued, claimed) = match (
        state
            .store
            .count_agent_commands(agent_id, Some("queued"))
            .await,
        state
            .store
            .count_agent_commands(agent_id, Some("claimed"))
            .await,
    ) {
        (Ok(queued), Ok(claimed)) => (queued, claimed),
        (Err(err), _) | (_, Err(err)) => {
            return ApiError::internal(
                codes::AGENT_STORE_UNAVAILABLE,
                "failed to count command queue",
                err,
            )
            .into_response();
        }
    };

    Json(CommandQueueView {
        agent_id: agent_id.map(str::to_string),
        state: state_filter.to_string(),
        counts: QueueCounts { queued, claimed },
        commands: commands.iter().map(queue_item).collect(),
    })
    .into_response()
}

/// 命令 → 队列行：状态与来源都在网关这里派生，页面不再各猜一份。
fn queue_item(command: &StoredAgentCommand) -> QueueItemView {
    QueueItemView {
        command_id: command.command_id.clone(),
        agent_id: command.agent_id.clone(),
        kind: command.kind.clone(),
        state: queue_state(command),
        source: command_source(&command.requested_by),
        requested_by: command.requested_by.clone(),
        summary: command_summary(&command.params),
        requested_at: datetime_from_ms(command.requested_at_ms),
        claimed_at: command.claimed_at.clone(),
        acknowledged_at: command.acked_at.clone(),
        outcome: command.outcome.clone(),
        detail: command.detail.clone(),
    }
}

/// 队列态：`acked_at` 是终态谓词，具体是哪种终态看 `outcome`。
///
/// `expired` / `superseded` 也写了 `acked_at`，但它们**不是**执行完成 ——
/// 页面要能看出「这条根本没跑」，所以单独成两态。
fn queue_state(command: &StoredAgentCommand) -> &'static str {
    if command.acked_at.is_some() {
        return match command.outcome.as_deref() {
            Some(command_outcome::EXPIRED) => "expired",
            Some(command_outcome::SUPERSEDED) => "superseded",
            _ => "acked",
        };
    }
    if command.claimed_at.is_some() {
        "claimed"
    } else {
        "queued"
    }
}

/// 谁排的：`center*` = 中心经 gwlinkd 下发，`admin*` = 网关页面，其它按系统处理。
fn command_source(requested_by: &str) -> &'static str {
    let value = requested_by.trim();
    if value.starts_with("center") {
        "center"
    } else if value.starts_with("admin") {
        "admin"
    } else {
        "system"
    }
}

/// 一行提示：不从参数里泄露整块 JSON（调查的 `path`、刷新的长列表都不适合铺在列表里）。
fn command_summary(params: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(params) else {
        return String::new();
    };
    if let Some(topic) = value.get("topic").and_then(Value::as_str) {
        return format!("topic={topic}");
    }
    if let Some(what) = value.get("what").and_then(Value::as_array) {
        let items: Vec<&str> = what.iter().filter_map(Value::as_str).collect();
        if !items.is_empty() {
            return format!("what={}", items.join(","));
        }
    }
    String::new()
}

fn datetime_from_ms(ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).map(|at| at.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(outcome: Option<&str>, claimed: bool) -> StoredAgentCommand {
        StoredAgentCommand {
            command_id: "cmd_1".to_string(),
            agent_id: "agent-1".to_string(),
            kind: "investigate".to_string(),
            params: r#"{"topic":"disk","path":"/var/log"}"#.to_string(),
            requested_at_ms: 1_700_000_000_000,
            acked_at: outcome.map(|_| "2026-01-01T00:00:00Z".to_string()),
            claimed_at: claimed.then(|| "2026-01-01T00:00:00Z".to_string()),
            outcome: outcome.map(str::to_string),
            detail: None,
            requested_by: "center".to_string(),
        }
    }

    /// 队列态：终态按 outcome 细分；`expired` / `superseded` 不能被读成「执行完成」。
    #[test]
    fn queue_state_distinguishes_terminal_outcomes() {
        assert_eq!(queue_state(&command(None, false)), "queued");
        assert_eq!(queue_state(&command(None, true)), "claimed");
        assert_eq!(queue_state(&command(Some("succeeded"), true)), "acked");
        assert_eq!(queue_state(&command(Some("failed"), true)), "acked");
        assert_eq!(queue_state(&command(Some("expired"), false)), "expired");
        assert_eq!(
            queue_state(&command(Some("superseded"), false)),
            "superseded"
        );
    }

    /// 来源：这是页面回答「哪些是中心下发的」的唯一依据。
    #[test]
    fn source_is_derived_from_requested_by() {
        assert_eq!(command_source("center"), "center");
        assert_eq!(command_source("center:alice"), "center");
        assert_eq!(command_source("admin:0123456789ab"), "admin");
        assert_eq!(command_source("system"), "system");
        assert_eq!(command_source(""), "system");
    }

    /// 列表提示只带一个短字段：不把整块参数（含路径）铺到队列页。
    #[test]
    fn summary_prefers_topic_then_what() {
        assert_eq!(
            command_summary(r#"{"topic":"disk","path":"/var/log"}"#),
            "topic=disk"
        );
        assert_eq!(
            command_summary(r#"{"what":["facts","knowledge"]}"#),
            "what=facts,knowledge"
        );
        assert_eq!(command_summary("{}"), "");
        assert_eq!(command_summary("not-json"), "");
    }
}
