use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    extract::FromRequestParts,
    extract::connect_info::ConnectInfo,
    http::request::Parts,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use super::ApiState;

/// 与 `wist-auth` 默认封禁时长一致，仅用于日志。
const BLOCK_DURATION: Duration = Duration::from_secs(60);

/// 每作用域、每客户端的失败桶（`Default` = 5 次 / 60s → 封 60s）。
///
/// 桶的存储、窗口与淘汰逻辑在共享 crate `wist-auth`；这里只保留 HTTP 形态与 key 约定。
pub type RateLimitState = wist_auth::FailureLimiter<String>;

/// Peer socket address if one was injected (via the `ConnectInfo` middleware
/// in production or `MockConnectInfo` in tests), otherwise `None`.
///
/// axum 0.8 removed the `Option<ConnectInfo<T>>` extractor (`ConnectInfo` no
/// longer implements `OptionalFromRequestParts`), so this restores the
/// optional-address behavior the rate-limit code depends on.
pub struct OptionalConnectInfo(pub Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalConnectInfo
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        let addr = match ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await {
            Ok(ConnectInfo(addr)) => Some(addr),
            Err(_) => None,
        };
        Ok(OptionalConnectInfo(addr))
    }
}

/// Derive a stable per-client bucket key from the peer socket address injected by
/// [`axum::extract::connect_info::ConnectInfo`]. Client-supplied headers such as
/// `x-real-ip` / `x-forwarded-for` are intentionally ignored (they are spoofable).
/// Falls back to a single shared bucket when no connection info is available (e.g. tests).
pub fn client_key(client: Option<SocketAddr>) -> String {
    client
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn check_rate_limit(state: &ApiState, client_key: &str, scope: &str) -> Option<Response> {
    let key = rate_limit_key(client_key, scope);
    let limits = state.rate_limits.lock().ok()?;
    let retry_after = limits.blocked_for(&key)?;
    log::warn!(
        "event=AuthRateLimited scope={scope} client={client_key} retry_after_secs={retry_after}"
    );
    Some(
        (
            StatusCode::TOO_MANY_REQUESTS,
            [
                (header::RETRY_AFTER, retry_after.to_string()),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            "too many failed authentication attempts",
        )
            .into_response(),
    )
}

pub fn record_auth_failure(state: &ApiState, client_key: &str, scope: &str) {
    let key = rate_limit_key(client_key, scope);
    let Ok(limits) = state.rate_limits.lock() else {
        return;
    };
    let failures = limits.record_failure(&key);
    if limits.blocked_for(&key).is_some() {
        log::warn!(
            "event=AuthBlocked scope={scope} client={client_key} failures={failures} block_secs={}",
            BLOCK_DURATION.as_secs()
        );
    } else {
        log::warn!("event=AuthFailure scope={scope} client={client_key} failures={failures}");
    }
}

pub fn clear_auth_failures(state: &ApiState, client_key: &str, scope: &str) {
    let key = rate_limit_key(client_key, scope);
    let Ok(limits) = state.rate_limits.lock() else {
        return;
    };
    limits.clear(&key);
}

fn rate_limit_key(client_key: &str, scope: &str) -> String {
    format!("{scope}:{client_key}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_per_purpose() {
        assert_eq!(rate_limit_key("1.2.3.4", "admin"), "admin:1.2.3.4");
        assert_ne!(
            rate_limit_key("1.2.3.4", "admin"),
            rate_limit_key("1.2.3.4", "install_all")
        );
    }
}
