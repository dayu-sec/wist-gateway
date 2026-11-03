//! 手工刷新入口：`POST /api/v1/admin/agents/{agent_id}/refresh`。
//!
//! ## 为什么复用通用 `refresh` 命令面
//!
//! agent 能刷新的来源是一个**闭集**（`wist_api::status::refresh_what::ALL`），命令台账里读到的
//! 值必须能直接抄回 agentd CLI 的 `refresh --only …`。为此单开 `metrics-labels:refresh` 会变成
//! 第二套词表，台账、页面提示、CLI 三方各说一套。
//!
//! ## 它与“写入即生效”的关系
//!
//! `PUT` / `DELETE` 管理面语义的接口（如 `metrics-labels`）在写入成功后**已经**自动排刷新，
//! 本端点只是「再发一次」，用于“改了但 agent 没拿到”的排障，不是正常生效路径。
//!
//! ## 为什么不按 kind 覆盖待执行命令
//!
//! `enqueue_agent_command(.., replace_pending_same_kind = true)` 的粒度是**命令 kind**。本端点的
//! 命令 kind 恒为 `refresh`，而 `params.what` 可以不同：若沿用覆盖语义，先刷 `policies` 再刷
//! `metrics-labels`（两键都在 3s 窗口内）会静默丢掉前者，台账里只剩一条。因此这里按**追加**
//! 入队；同一个 `what` 连点两次就是两条命令，agent 侧重复刷新是幂等的。
//!
//! 设计见 `wist-agentd/docs/design/metrics-selection-labels.md` §3.2 / §10。

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use wist_api::status::{RefreshParams, command_kind, refresh_what};

use crate::api::ApiState;
use crate::api::admin_auth::{admin_actor, require_admin_bearer};
use crate::api::admin_ops::{agent_command_response, agent_not_found_response};
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;
use crate::infra::StoredAgentCommand;

/// `POST /api/v1/admin/agents/{agent_id}/refresh`
///
/// 请求体 `{"what":["metrics-labels"]}`；响应与 `fact-refresh` 同形状（命令回执），
/// 前端可以直接复用命令台账的渲染。
///
/// `what` **必须显式给**：一次刷多个来源代价不小，空表会让页面把“什么都没说”渲染成“刷新成功”。
///
/// 请求体先收成 `serde_json::Value` 再手动解析：缺字段 / 空 body 时 axum 的 `Json` 直接回 422，
/// 而这里的契约是 400 + 稳定原因码（`empty_refresh_what`）——页面靠 `code` 分支。
pub async fn dispatch_agent_refresh(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 404 与 metrics-labels 三接口同口径：先把“有没有这台机器”收口，再判请求成立与否。
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let Some(Json(input)) = body else {
        return ApiError::bad_request(codes::EMPTY_REFRESH_WHAT, "refresh what must not be empty")
            .into_response();
    };
    let input: RefreshParams = match serde_json::from_value(input) {
        Ok(input) => input,
        Err(err) => {
            return ApiError::bad_request(
                codes::EMPTY_REFRESH_WHAT,
                format!("invalid refresh request: {err}"),
            )
            .into_response();
        }
    };
    if input.what.is_empty() {
        return ApiError::bad_request(codes::EMPTY_REFRESH_WHAT, "refresh what must not be empty")
            .into_response();
    }
    if let Some(unknown) = input
        .what
        .iter()
        .find(|item| !refresh_what::ALL.contains(&item.as_str()))
    {
        return ApiError::bad_request(
            codes::UNKNOWN_REFRESH_SOURCE,
            format!("unknown refresh source: {unknown}"),
        )
        .into_response();
    }
    let now = chrono::Utc::now();
    // 用微秒做 id：同一毫秒内的两次点击也不能撞成一个 id（撞了会被 `DO NOTHING` 吞掉）。
    let command = StoredAgentCommand {
        command_id: format!("cmd_{}_refresh_{}", agent_id, now.timestamp_micros()),
        agent_id: agent_id.clone(),
        kind: command_kind::REFRESH.to_string(),
        params: match serde_json::to_string(&input) {
            Ok(params) => params,
            // `RefreshParams` 只有 `Vec<String>`，序列化不会失败；保留分支只为不引入 `unwrap`。
            Err(err) => {
                return ApiError::internal(
                    codes::AGENT_COMMAND_STORE_FAILED,
                    "failed to encode refresh params",
                    err,
                )
                .into_response();
            }
        },
        requested_at_ms: now.timestamp_millis(),
        acked_at: None,
        claimed_at: None,
        outcome: None,
        detail: None,
        // 审计口径与调查 / fact-refresh 一致：`admin:<token 指纹>`。
        requested_by: admin_actor(&state.config),
    };
    match state.store.enqueue_agent_command(&command, false).await {
        Ok(()) => Json(agent_command_response(&agent_id, Some(command))).into_response(),
        Err(err) => ApiError::internal(
            codes::AGENT_COMMAND_STORE_FAILED,
            "failed to enqueue agent command",
            err,
        )
        .into_response(),
    }
}
