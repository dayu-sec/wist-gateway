use super::codes;
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{ApiState, error::ApiError, rate_limit};

const ADMIN_AUTH_SCOPE: &str = "admin";

/// 管理面鉴权：Admin Token（Bearer，sha256 常数时间比较）+ 鉴权失败限流。
///
/// token 原语与限流桶来自共享 crate `wist-auth`（与 wist-center / wist-ingest-ctrl 同一份）；
/// 这里只保留本服务的错误码与错误体。
/// 管理面“发起人”标识，写进审计字段（`agent_commands.requested_by`）。
///
/// 为什么不是原 token：它要进库、进页面、进日志 —— 凭据落一次就多一个泄露面。
/// 用 `sha256(token)` 的前 12 个 hex 作**指纹**：能区分不同 token（含轮换前后），
/// 却不能反推。将来管理面有了用户体系，这里换成 `user:<id>` 即可，字段类型不变。
pub(super) fn admin_actor(config: &crate::infra::AdminConfig) -> String {
    let fingerprint: String = config.admin_api_token_hash.chars().take(12).collect();
    if fingerprint.is_empty() {
        "admin:unknown".to_string()
    } else {
        format!("admin:{fingerprint}")
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn require_admin_bearer(
    state: &ApiState,
    headers: &HeaderMap,
    client_key: &str,
) -> Result<(), Response> {
    if let Some(response) = rate_limit::check_rate_limit(state, client_key, ADMIN_AUTH_SCOPE) {
        return Err(response);
    }
    let Some(token) = wist_auth::bearer_token(headers) else {
        // A missing token is an unauthenticated request, not a brute-force
        // attempt against a specific credential. Counting it toward the per-IP
        // rate limit lets an unauthenticated client (e.g. the web UI polling
        // the overview every few seconds before a token is entered) lock the IP
        // out for the block window even after the correct token is supplied.
        log::warn!(
            "event=AdminAuthMissingBearer scope={} client={client_key}",
            ADMIN_AUTH_SCOPE
        );
        return Err(ApiError::unauthorized(
            codes::MISSING_ADMIN_BEARER_TOKEN,
            "missing admin bearer token",
        )
        .into_response());
    };
    if !wist_auth::token_matches(token, &state.config.admin_api_token_hash) {
        // Invalid token: count it toward the brute-force window
        // (`record_auth_failure` logs `event=AuthFailure` / `event=AuthBlocked`).
        rate_limit::record_auth_failure(state, client_key, ADMIN_AUTH_SCOPE);
        return Err(ApiError::unauthorized(
            codes::INVALID_ADMIN_BEARER_TOKEN,
            "invalid admin bearer token",
        )
        .into_response());
    }
    rate_limit::clear_auth_failures(state, client_key, ADMIN_AUTH_SCOPE);
    Ok(())
}
