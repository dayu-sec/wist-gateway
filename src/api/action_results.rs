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
    let report: Value = serde_json::from_str(&stored.report_json).unwrap_or(Value::Null);
    Json(ActionResultView {
        agent_id: stored.agent_id,
        action_id: stored.action_id,
        execution_id: stored.execution_id,
        plan_digest: stored.plan_digest,
        final_status: stored.final_status,
        reported_at: stored.reported_at,
        received_at: stored.received_at,
        report,
    })
    .into_response()
}
