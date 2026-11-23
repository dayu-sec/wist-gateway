//! 执行结果的**管理面读取**：`GET /api/v1/admin/agents/{agent_id}/action-results/{action_id}`。
//!
//! 为什么需要它：`report_action_result`（agentd 上报）现在会把整份 `ReportActionResult` 落库，
//! 但**没有任何读取入口** —— 命令队列只给 `outcome` 与一行 `detail`。而清理类响应的价值全在
//! 产出里：「预览扫出了哪些文件、共多少字节」。没有这条读口，发起页就只能在盲批。
//!
//! 两条语义：
//!
//! * **按 `(agent_id, action_id)` 取**，不是按 `report_id`：agentd 每次重试都换 `report_id`，
//!   而我们要的是「这份计划的最终结果」。
//! * **结果原样透出**（`report` 字段是 JSON 对象）：形状的演进归 `wist-api` 契约，网关不镜像。

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

use crate::api::ApiState;
use crate::api::admin_auth::require_admin_bearer;
use crate::api::admin_ops::agent_not_found_response;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;

#[derive(Debug, Serialize)]
struct ActionResultView {
    agent_id: String,
    action_id: String,
    execution_id: String,
    plan_digest: String,
    /// 契约的 wire 值（`succeeded` / `failed` …）。
    final_status: String,
    /// agentd 声称的上报时刻。
    reported_at: String,
    /// 网关收到的时刻（网关墙钟）—— 机器时钟不可信，两个都留着。
    received_at: String,
    /// 整份 `ReportActionResult`（原样，不镜像结构）。
    report: Value,
}

#[derive(Debug, Serialize)]
struct ActionResultListView {
    agent_id: String,
    /// 时间倒序（最新在前）。
    results: Vec<ActionResultView>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ActionResultListQuery {
    limit: Option<usize>,
}

/// 列表上限：每条 `report` 都是几 KB 的完整报文，别一次拉几百条。
const MAX_RESULT_LIST_LIMIT: usize = 50;
const DEFAULT_RESULT_LIST_LIMIT: usize = 10;

/// `GET /api/v1/admin/agents/{agent_id}/action-results?limit=N`
///
/// 为什么要有列表：结果只在**发起页当次会话**里可见的话，刷新一次就再也找不回来 ——
/// 而结果恰恰是复核与审计要反复看的东西。
pub async fn list_action_results(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ActionResultListQuery>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_RESULT_LIST_LIMIT)
        .clamp(1, MAX_RESULT_LIST_LIMIT);
    let stored = match state.store.list_action_results(&agent_id, limit).await {
        Ok(results) => results,
        Err(err) => {
            return ApiError::internal(
                codes::ACTION_RESULT_STORE_FAILED,
                "failed to list action results",
                err,
            )
            .into_response();
        }
    };
    Json(ActionResultListView {
        agent_id,
        results: stored.iter().map(action_result_view).collect(),
    })
    .into_response()
}

/// `GET /api/v1/admin/agents/{agent_id}/action-results/{action_id}`
pub async fn get_action_result(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((agent_id, action_id)): Path<(String, String)>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let stored = match state.store.get_action_result(&agent_id, &action_id).await {
        Ok(result) => result,
        Err(err) => {
            return ApiError::internal(
                codes::ACTION_RESULT_STORE_FAILED,
                "failed to load action result",
                err,
            )
            .into_response();
        }
    };
    let Some(stored) = stored else {
        return ApiError::not_found(
            codes::ACTION_RESULT_NOT_FOUND,
            format!("no result for action {action_id} on {agent_id} yet"),
        )
        .into_response();
    };
    Json(action_result_view(&stored)).into_response()
}

fn action_result_view(stored: &crate::infra::StoredActionResult) -> ActionResultView {
    ActionResultView {
        agent_id: stored.agent_id.clone(),
        action_id: stored.action_id.clone(),
        execution_id: stored.execution_id.clone(),
        plan_digest: stored.plan_digest.clone(),
        final_status: stored.final_status.clone(),
        reported_at: stored.reported_at.clone(),
        received_at: stored.received_at.clone(),
        // 报文坏掉时给 `null` 而不是整条失败：元信息（状态 / 时间）仍然有审计价值。
        report: serde_json::from_str(&stored.report_json).unwrap_or(Value::Null),
    }
}
