// NOTE(hand-added): 网关（容器）自述状态的**周期自采** + 页面趋势读口。
//
// 为什么自采：`gateway_*` 时序是 center 推到 **center 的** VM 的，网关这台 VM 里没有；
// 而「网关状态」页要能在中心 / gwlinkd 都不在时照看本机网关 —— 所以网关自己周期采一份、
// 存进本地环形表（与 gwlinkd 心跳轨迹同一模式，**不依赖 VM**）。
// 设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。
//
// 不与请求路径耦合：不搭在页面轮询上（那会让「有没有人看」决定趋势有没有数据），
// 也不搭在 gwlinkd 的环回读上（它挂了趋势就断了）。自身 tick。

use std::time::Duration;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::infra::StoredGatewaySelfStateSample;

use super::{ApiState, rate_limit};

/// 采样节拍（与 gwlinkd 心跳同频：30s 一拍）。
pub const SELF_STATE_SAMPLE_TICK: Duration = Duration::from_secs(30);
/// 轨迹保留窗口（2 小时 ≈ 240 拍）：环形记录，写入时裁旧。
const HISTORY_RETENTION_SECONDS: i64 = 2 * 3600;
/// 页面默认看最近 1 小时。
const DEFAULT_HISTORY_WINDOW_SECONDS: i64 = 3600;

/// 周期自采网关自述状态（后台任务；自身 tick，不搭在任何请求路径上）。
///
/// 只留**趋势用得着**的几个量（CPU / RSS / 负载 / Agent 在线 / 磁盘）：整份自述面的键
/// 随版本增删，落表会把 schema 绑死在快照形状上。
pub fn spawn_self_state_sample_tick(state: ApiState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SELF_STATE_SAMPLE_TICK);
        loop {
            ticker.tick().await;
            // gateway_id 只是回显字段，采样用不着 → 传空串。
            let snapshot = super::self_state::self_state(&state, "").await;
            let at_seconds = chrono::Utc::now().timestamp();
            let sample = StoredGatewaySelfStateSample {
                at_seconds,
                cpu_percent: snapshot.cpu_percent,
                memory_bytes: snapshot.memory_bytes,
                load_1m: snapshot.load_1m,
                online_agents: snapshot.online_agents,
                disk_usage_percent: snapshot.disk_usage_percent,
            };
            if let Err(err) = state
                .store
                .append_gateway_self_state_sample(&sample, at_seconds - HISTORY_RETENTION_SECONDS)
                .await
            {
                eprintln!("warn append gateway self state sample failed: {err}");
            }
        }
    });
}

/// 页面可见的网关自述状态轨迹（最近窗口）。
#[derive(Debug, Serialize)]
pub struct GatewaySelfStateHistoryView {
    /// 本次返回覆盖的窗口（秒）。
    pub window_seconds: i64,
    /// 窗口内的采样，按时刻升序；量不出的列是 `null`（趋势里显断线）。
    pub samples: Vec<GatewaySelfStateSampleView>,
}

/// 一条采样。
#[derive(Debug, Serialize)]
pub struct GatewaySelfStateSampleView {
    /// 采样时刻（unix 秒）。
    pub at: i64,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub load_1m: Option<f64>,
    pub online_agents: i64,
    pub disk_usage_percent: Option<f64>,
}

/// 轨迹查询参数。
#[derive(Debug, Deserialize)]
pub struct SelfStateHistoryQuery {
    #[serde(default)]
    pub window_seconds: Option<i64>,
}

/// 读取网关自述状态轨迹（页面用）：
/// `GET /api/v1/admin/gateway/self-state/history?window_seconds=`（admin bearer）。
///
/// 窗口缺省 1h，并夹到 `[60s, 保留窗口]`。
pub async fn admin_view_gateway_self_state_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Query(params): Query<SelfStateHistoryQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window_seconds = params
        .window_seconds
        .unwrap_or(DEFAULT_HISTORY_WINDOW_SECONDS)
        .clamp(60, HISTORY_RETENTION_SECONDS);
    let since_seconds = chrono::Utc::now().timestamp() - window_seconds;
    match state
        .store
        .list_gateway_self_state_samples(since_seconds)
        .await
    {
        Ok(samples) => Json(GatewaySelfStateHistoryView {
            window_seconds,
            samples: samples
                .into_iter()
                .map(|sample| GatewaySelfStateSampleView {
                    at: sample.at_seconds,
                    cpu_percent: sample.cpu_percent,
                    memory_bytes: sample.memory_bytes,
                    load_1m: sample.load_1m,
                    online_agents: sample.online_agents,
                    disk_usage_percent: sample.disk_usage_percent,
                })
                .collect(),
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read gateway self state history: {err}"),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// 视图**键集契约**：量不出的列必须是 `null` 而不是**缺键** ——
    /// 前端与网关同钉一份形状，缺键会让它在整条曲线上报错。
    #[test]
    fn history_view_serializes_the_contract_keys() {
        let view = GatewaySelfStateHistoryView {
            window_seconds: 3600,
            samples: vec![GatewaySelfStateSampleView {
                at: 1_700_000_000,
                cpu_percent: Some(1.5),
                memory_bytes: Some(1024),
                load_1m: Some(0.4),
                online_agents: 2,
                disk_usage_percent: None,
            }],
        };
        let value: Value = serde_json::to_value(view).expect("serialize");
        assert_eq!(value["window_seconds"], 3600);
        let sample = &value["samples"][0];
        for key in [
            "at",
            "cpu_percent",
            "memory_bytes",
            "load_1m",
            "online_agents",
            "disk_usage_percent",
        ] {
            assert!(sample.get(key).is_some(), "缺 {key}: {value}");
        }
        assert!(
            sample["disk_usage_percent"].is_null(),
            "量不出应是 null，不是缺键：{value}"
        );
    }
}
