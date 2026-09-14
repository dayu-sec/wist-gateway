use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::infra::sha256_hex;

use super::{rate_limit, ApiState};

const ADMIN_AUTH_SCOPE: &str = "admin";

pub(super) fn require_admin_bearer(
    state: &ApiState,
    headers: &HeaderMap,
    client_key: &str,
) -> Result<(), Response> {
    if let Some(response) = rate_limit::check_rate_limit(state, client_key, ADMIN_AUTH_SCOPE) {
        return Err(response);
    }
    let Some(token) = bearer_token(headers) else {
        // A missing token is an unauthenticated request, not a brute-force
        // attempt against a specific credential. Counting it toward the per-IP
        // rate limit lets an unauthenticated client (e.g. the web UI polling
        // the overview every few seconds before a token is entered) lock the IP
        // out for the block window even after the correct token is supplied.
        return Err((StatusCode::UNAUTHORIZED, "missing admin bearer token").into_response());
    };
    if !constant_time_eq(
        sha256_hex(token).as_bytes(),
        state.config.admin_api_token_hash.as_bytes(),
    ) {
        rate_limit::record_auth_failure(state, client_key, ADMIN_AUTH_SCOPE);
        return Err((StatusCode::UNAUTHORIZED, "invalid admin bearer token").into_response());
    }
    rate_limit::clear_auth_failures(state, client_key, ADMIN_AUTH_SCOPE);
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}
