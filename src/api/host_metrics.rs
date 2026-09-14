use std::net::SocketAddr;

use axum::{
    extract::{connect_info::ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use super::{admin_auth::require_admin_bearer, rate_limit, ApiState};
use crate::infra::victoria_metrics::query_json;

/// 趋势图时间窗口（秒）与采样步长（秒）。
const HISTORY_WINDOW_SECONDS: i64 = 3600;
const HISTORY_STEP_SECONDS: i64 = 30;

/// 单台主机（agent）的运行时指标快照，由控制面代理查询 VictoriaMetrics 后归一化返回。
/// 包含即时值（`query`）与近 1 小时趋势（`query_range`）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHostMetrics {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average_1m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average_5m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average_15m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_available_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_available_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<AgentHostMetricsHistory>,
}

/// 各指标的时间序列，`points` 为 `(unix 毫秒, 值)` 列表，按时间升序。
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHostMetricsHistory {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_average_1m: Vec<(i64, f64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_average_5m: Vec<(i64, f64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_average_15m: Vec<(i64, f64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_total_kb: Vec<(i64, f64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_available_kb: Vec<(i64, f64)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disk_usage_percent: Vec<(i64, f64)>,
}

/// 主机列表页用的单台主机指标摘要（仅当前值，无趋势）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHostMetricsSummary {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average_1m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_available_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage_percent: Option<f64>,
}

pub async fn get_agent_host_metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    client: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let snapshot = match state.store.load() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };
    if !snapshot.agents.contains_key(&agent_id) {
        return (StatusCode::NOT_FOUND, format!("unknown agent {agent_id}")).into_response();
    }

    match query_host_metrics(&state.config.victoria_metrics_url, &agent_id).await {
        Ok(metrics) => Json(metrics).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("failed to query metrics: {err}"),
        )
            .into_response(),
    }
}

pub async fn get_all_agents_host_metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let agent_ids = match state.store.load() {
        Ok(snapshot) => snapshot.agents.keys().cloned().collect::<Vec<_>>(),
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };

    match query_all_host_metrics(&state.config.victoria_metrics_url, &agent_ids).await {
        Ok(summaries) => Json(summaries).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("failed to query metrics: {err}"),
        )
            .into_response(),
    }
}

async fn query_all_host_metrics(
    vm_url: &str,
    agent_ids: &[String],
) -> Result<Vec<AgentHostMetricsSummary>, String> {
    if agent_ids.is_empty() {
        return Ok(Vec::new());
    }
    // 一次拉取所有主机的 system.* 指标，再按 `agent` 标签分组。
    // 注意：VictoriaMetrics 的 PromQL 字符串字面量里 `\.` 不是合法转义，
    // 用 `system..*`（`.` 匹配任意字符）即可命中全部 `system.<name>` 指标。
    let query = r#"{__name__=~"system..*"}"#;
    let instant = query_json(vm_url, "/api/v1/query", &[("query", query)]).await?;

    let mut map: std::collections::HashMap<String, AgentHostMetricsSummary> =
        std::collections::HashMap::new();
    for item in instant["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let agent = item["metric"]["agent"].as_str().unwrap_or("").to_string();
        if agent.is_empty() || !agent_ids.iter().any(|id| id == &agent) {
            continue;
        }
        let name = item["metric"]["__name__"].as_str().unwrap_or("");
        let value = scalar_value(&item);
        let entry = map
            .entry(agent.clone())
            .or_insert_with(|| AgentHostMetricsSummary {
                agent_id: agent,
                load_average_1m: None,
                memory_total_kb: None,
                memory_available_kb: None,
                disk_usage_percent: None,
            });
        match name {
            "system.load_average.1m" => entry.load_average_1m = parse_f64(value),
            "system.memory.total" => entry.memory_total_kb = parse_i64(value),
            "system.memory.available" => entry.memory_available_kb = parse_i64(value),
            "system.disk.usage" => entry.disk_usage_percent = parse_f64(value),
            _ => {}
        }
    }

    let mut summaries: Vec<AgentHostMetricsSummary> = map.into_values().collect();
    summaries.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    Ok(summaries)
}

async fn query_host_metrics(vm_url: &str, agent_id: &str) -> Result<AgentHostMetrics, String> {
    // PromQL 字符串字面量转义，避免 agent_id 里的引号/反斜杠破坏查询。
    let escaped = agent_id.replace('\\', "\\\\").replace('"', "\\\"");
    let query = format!("{{agent=\"{escaped}\"}}");

    let instant = query_json(vm_url, "/api/v1/query", &[("query", query.as_str())]).await?;

    let now = chrono::Utc::now().timestamp();
    let start = (now - HISTORY_WINDOW_SECONDS).to_string();
    let end = now.to_string();
    let step = HISTORY_STEP_SECONDS.to_string();
    let range = query_json(
        vm_url,
        "/api/v1/query_range",
        &[
            ("query", query.as_str()),
            ("start", start.as_str()),
            ("end", end.as_str()),
            ("step", step.as_str()),
        ],
    )
    .await?;

    Ok(build_metrics(agent_id, &instant, &range))
}

fn build_metrics(
    agent_id: &str,
    instant: &serde_json::Value,
    range: &serde_json::Value,
) -> AgentHostMetrics {
    let mut metrics = AgentHostMetrics {
        agent_id: agent_id.to_string(),
        load_average_1m: None,
        load_average_5m: None,
        load_average_15m: None,
        uptime_seconds: None,
        memory_total_kb: None,
        memory_available_kb: None,
        disk_usage_percent: None,
        disk_total_kb: None,
        disk_available_kb: None,
        history: None,
    };

    for item in instant["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let name = item["metric"]["__name__"].as_str().unwrap_or("");
        let value = scalar_value(&item);
        match name {
            "system.load_average.1m" => metrics.load_average_1m = parse_f64(value),
            "system.load_average.5m" => metrics.load_average_5m = parse_f64(value),
            "system.load_average.15m" => metrics.load_average_15m = parse_f64(value),
            "system.uptime" => metrics.uptime_seconds = parse_f64(value),
            "system.memory.total" => metrics.memory_total_kb = parse_i64(value),
            "system.memory.available" => metrics.memory_available_kb = parse_i64(value),
            "system.disk.usage" => metrics.disk_usage_percent = parse_f64(value),
            "system.disk.total" => metrics.disk_total_kb = parse_i64(value),
            "system.disk.available" => metrics.disk_available_kb = parse_i64(value),
            _ => {}
        }
    }

    let mut history = AgentHostMetricsHistory::default();
    for item in range["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let name = item["metric"]["__name__"].as_str().unwrap_or("");
        let points = series_points(&item);
        match name {
            "system.load_average.1m" => history.load_average_1m = points,
            "system.load_average.5m" => history.load_average_5m = points,
            "system.load_average.15m" => history.load_average_15m = points,
            "system.memory.total" => history.memory_total_kb = points,
            "system.memory.available" => history.memory_available_kb = points,
            "system.disk.usage" => history.disk_usage_percent = points,
            _ => {}
        }
    }
    metrics.history = Some(history);

    metrics
}

/// 即时查询 `value: [timestamp, "value"]` 里的值字符串。
fn scalar_value(item: &serde_json::Value) -> Option<&str> {
    item["value"].as_array()?.get(1)?.as_str()
}

/// `query_range` 的 `values: [[timestamp, "value"], ...]` → `(毫秒, 值)` 列表。
fn series_points(item: &serde_json::Value) -> Vec<(i64, f64)> {
    item["values"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|pair| {
                    let pair = pair.as_array()?;
                    let timestamp_ms = (pair.first()?.as_f64()? * 1000.0) as i64;
                    let value = pair.get(1)?.as_str()?.parse::<f64>().ok()?;
                    Some((timestamp_ms, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_f64(value: Option<&str>) -> Option<f64> {
    value.and_then(|value| value.parse::<f64>().ok())
}

fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}
