use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::{
    extract::connect_info::ConnectInfo,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use super::ApiState;

const MAX_FAILURES_PER_WINDOW: u32 = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const BLOCK_DURATION: Duration = Duration::from_secs(60);
/// Upper bound on tracked buckets so a rotating-IP attacker cannot grow the map
/// without limit. Oldest-first eviction keeps the bound while retaining fresh buckets.
const MAX_BUCKETS: usize = 10_000;

#[derive(Debug, Default)]
pub struct RateLimitState {
    buckets: HashMap<String, RateLimitBucket>,
}

#[derive(Debug)]
struct RateLimitBucket {
    failures: u32,
    first_failure_at: Instant,
    blocked_until: Option<Instant>,
}

/// Derive a stable per-client bucket key from the peer socket address injected by
/// [`axum::extract::connect_info::ConnectInfo`]. Client-supplied headers such as
/// `x-real-ip` / `x-forwarded-for` are intentionally ignored (they are spoofable).
/// Falls back to a single shared bucket when no connection info is available (e.g. tests).
pub fn client_key(client: Option<ConnectInfo<SocketAddr>>) -> String {
    client
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn check_rate_limit(state: &ApiState, client_key: &str, scope: &str) -> Option<Response> {
    let key = rate_limit_key(client_key, scope);
    let now = Instant::now();
    let mut limits = state.rate_limits.lock().ok()?;
    let bucket = limits.buckets.get_mut(&key)?;
    if now.duration_since(bucket.first_failure_at) > FAILURE_WINDOW {
        limits.buckets.remove(&key);
        return None;
    }
    if let Some(blocked_until) = bucket.blocked_until {
        if blocked_until > now {
            let retry_after = blocked_until
                .duration_since(now)
                .as_secs()
                .max(1)
                .to_string();
            return Some(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [
                        (header::RETRY_AFTER, retry_after),
                        (header::CACHE_CONTROL, "no-store".to_string()),
                    ],
                    "too many failed authentication attempts",
                )
                    .into_response(),
            );
        }
        limits.buckets.remove(&key);
    }
    None
}

pub fn record_auth_failure(state: &ApiState, client_key: &str, scope: &str) {
    let key = rate_limit_key(client_key, scope);
    let now = Instant::now();
    let Ok(mut limits) = state.rate_limits.lock() else {
        return;
    };
    if !limits.buckets.contains_key(&key) && limits.buckets.len() >= MAX_BUCKETS {
        evict_oldest_bucket(&mut limits.buckets);
    }
    let bucket = limits.buckets.entry(key).or_insert(RateLimitBucket {
        failures: 0,
        first_failure_at: now,
        blocked_until: None,
    });
    if now.duration_since(bucket.first_failure_at) > FAILURE_WINDOW {
        bucket.failures = 0;
        bucket.first_failure_at = now;
        bucket.blocked_until = None;
    }
    bucket.failures = bucket.failures.saturating_add(1);
    if bucket.failures >= MAX_FAILURES_PER_WINDOW {
        bucket.blocked_until = Some(now + BLOCK_DURATION);
    }
}

pub fn clear_auth_failures(state: &ApiState, client_key: &str, scope: &str) {
    let key = rate_limit_key(client_key, scope);
    let Ok(mut limits) = state.rate_limits.lock() else {
        return;
    };
    limits.buckets.remove(&key);
}

fn rate_limit_key(client_key: &str, scope: &str) -> String {
    format!("{scope}:{client_key}")
}

fn evict_oldest_bucket(buckets: &mut HashMap<String, RateLimitBucket>) {
    if let Some((oldest_key, _)) = buckets
        .iter()
        .min_by_key(|(_, bucket)| bucket.first_failure_at)
    {
        let oldest_key = oldest_key.clone();
        buckets.remove(&oldest_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_buckets_are_capped_and_evict_oldest() {
        let now = Instant::now();
        let mut buckets = HashMap::new();
        for index in 0..(MAX_BUCKETS + 50) {
            let key = format!("client-{index}");
            if !buckets.contains_key(&key) && buckets.len() >= MAX_BUCKETS {
                evict_oldest_bucket(&mut buckets);
            }
            buckets.insert(
                key,
                RateLimitBucket {
                    failures: 1,
                    first_failure_at: now - Duration::from_secs((MAX_BUCKETS + 50 - index) as u64),
                    blocked_until: None,
                },
            );
        }
        assert_eq!(buckets.len(), MAX_BUCKETS);
        // The 50 oldest entries (smallest first_failure_at) were evicted first;
        // the survivors are numeric indices 50..=10049.
        assert!(!buckets.contains_key("client-0"));
        assert!(!buckets.contains_key("client-49"));
        assert!(buckets.contains_key("client-50"));
        assert!(buckets.contains_key("client-10049"));
    }
}
