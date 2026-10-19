// NOTE(hand-added): 主机资源指标（管理面代理查询 VictoriaMetrics，并按 `agent_id` join 注册表
// 机器画像 —— 主机名 / `node_id` / 网卡地址）。对应 jumo 模型 `Control.Agent.HostMetrics`
// （binding：`AdminShowAgentHostMetrics` / `AdminListAgentHostMetrics`），响应字段与模型结构体
// `AgentHostMetrics` / `AgentHostMetricsSummary` 一致。本模块与这两条路由已声明在模型里，
// 但代码仍属手加（同 `api/mod.rs` 顶部的 hand-added 说明）：重新生成控制面代码时需回补。

use super::codes;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::HashMap;

use serde::Serialize;

use super::error::ApiError;
use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};
use crate::infra::StoredAgentIdentity;
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
    /// 机器身份（主机名 / node_id / 网卡地址）：来自注册表 join —— 数据面 VM 里没有这些标签。
    /// 空串 / 空表 = 注册表里没有这台机器的画像（老数据或被手工删过）。
    pub node_id: String,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
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
    /// 逐挂载点容量（`system.filesystem.*`）。旧字段保留兼容，但无法定位具体挂载点。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystems: Vec<AgentFilesystemMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<AgentHostMetricsHistory>,
}

/// 单个挂载点的容量快照。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentFilesystemMetrics {
    pub mount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fstype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_percent: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_kb: Option<i64>,
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
    /// 机器身份，口径与 [`AgentHostMetrics`] 一致：注册表 join 而来，缺画像时为空。
    pub node_id: String,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_average_1m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_available_kb: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage_percent: Option<f64>,
    /// 当前最紧张的挂载点使用率（`system.filesystem.usage` 的最大值）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_filesystem_usage_percent: Option<f64>,
}

pub async fn get_agent_host_metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let agent = match state.store.get_agent(&agent_id).await {
        Ok(Some(agent)) => agent,
        Ok(None) => {
            return ApiError::not_found(
                codes::AGENT_NOT_FOUND,
                format!("unknown agent {agent_id}"),
            )
            .into_response();
        }
        Err(err) => {
            return ApiError::internal(
                codes::AGENT_STORE_UNAVAILABLE,
                "failed to load agent store",
                err,
            )
            .into_response();
        }
    };

    match query_host_metrics(&state.config.victoria_metrics_url, &agent_id).await {
        Ok(mut metrics) => {
            // 指标端点自己不带主机名/IP —— 身份只能从注册表拿，这里把它 join 回去。
            metrics.node_id = agent.node_id.clone();
            metrics.hostname = agent.hostname.clone();
            metrics.ip_addresses = agent.ip_addresses.clone();
            Json(metrics).into_response()
        }
        Err(err) => ApiError::internal_with(
            StatusCode::BAD_GATEWAY,
            codes::HOST_METRICS_UNAVAILABLE,
            "failed to query metrics",
            err,
        )
        .into_response(),
    }
}

pub async fn get_all_agents_host_metrics(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 一次性取回注册表里的机器身份（node_id / hostname / ip_addresses），再按 agent_id join 到
    // 指标上。用轻量投影 `list_agent_identities`（只读身份四列、全表、无过滤）—— 不需要为拿
    // 身份把整个注册行（含 local_work / uplink_state）拉进来。
    let identities_list = match state.store.list_agent_identities().await {
        Ok(identities) => identities,
        Err(err) => {
            return ApiError::internal(
                codes::AGENT_STORE_UNAVAILABLE,
                "failed to load agent store",
                err,
            )
            .into_response();
        }
    };
    let identities: HashMap<String, StoredAgentIdentity> = identities_list
        .into_iter()
        .map(|identity| (identity.agent_id.clone(), identity))
        .collect();

    match query_all_host_metrics(&state.config.victoria_metrics_url, &identities).await {
        Ok(summaries) => Json(summaries).into_response(),
        Err(err) => ApiError::internal_with(
            StatusCode::BAD_GATEWAY,
            codes::HOST_METRICS_UNAVAILABLE,
            "failed to query metrics",
            err,
        )
        .into_response(),
    }
}

/// 拉一次所有主机的 `system.*` 指标，按 `agent` 标签分组，并给注册表里认识的机器 join 上身份。
async fn query_all_host_metrics(
    vm_url: &str,
    identities: &HashMap<String, StoredAgentIdentity>,
) -> Result<Vec<AgentHostMetricsSummary>, String> {
    if identities.is_empty() {
        return Ok(Vec::new());
    }
    // 只拉列表页实际用到的 system 指标，再按 `agent` 标签分组。
    // 逐挂载点容量上线后 `system.filesystem.*` 会按挂载点数展开；这里用名称白名单
    // 避免把全部 filesystem series 都拉给列表页。
    // 注意：VictoriaMetrics 的 PromQL 字符串字面量里 `\.` 不是合法转义，
    // 用 `.`（匹配任意字符）分隔即可。
    let query = r#"{__name__=~"system.(load_average.1m|memory.total|memory.available|disk.usage|filesystem.usage)"}"#;
    let instant = query_json(vm_url, "/api/v1/query", &[("query", query)]).await?;

    let mut map: std::collections::HashMap<String, AgentHostMetricsSummary> =
        std::collections::HashMap::new();
    for item in instant["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let agent = item["metric"]["agent"].as_str().unwrap_or("").to_string();
        // 只保留注册表里认识的 agent：`/hosts` 的语义是「有指标上报的已注册机器」。
        let Some(identity) = identities.get(&agent) else {
            continue;
        };
        let name = item["metric"]["__name__"].as_str().unwrap_or("");
        let value = scalar_value(&item);
        let entry = map
            .entry(agent.clone())
            .or_insert_with(|| AgentHostMetricsSummary {
                agent_id: agent.clone(),
                node_id: identity.node_id.clone(),
                hostname: identity.hostname.clone(),
                ip_addresses: identity.ip_addresses.clone(),
                load_average_1m: None,
                memory_total_kb: None,
                memory_available_kb: None,
                disk_usage_percent: None,
                max_filesystem_usage_percent: None,
            });
        match name {
            "system.load_average.1m" => entry.load_average_1m = parse_f64(value),
            "system.memory.total" => entry.memory_total_kb = parse_i64(value),
            "system.memory.available" => entry.memory_available_kb = parse_i64(value),
            "system.disk.usage" => entry.disk_usage_percent = parse_f64(value),
            "system.filesystem.usage" => {
                if item["metric"]["mount"].as_str().is_some()
                    && let Some(usage) = parse_f64(value)
                {
                    entry.max_filesystem_usage_percent = Some(
                        entry
                            .max_filesystem_usage_percent
                            .map_or(usage, |current| current.max(usage)),
                    );
                }
            }
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
        // 身份由 handler 从注册表 join 后写入（`build_metrics` 只关心指标本身）。
        node_id: String::new(),
        hostname: String::new(),
        ip_addresses: Vec::new(),
        load_average_1m: None,
        load_average_5m: None,
        load_average_15m: None,
        uptime_seconds: None,
        memory_total_kb: None,
        memory_available_kb: None,
        disk_usage_percent: None,
        disk_total_kb: None,
        disk_available_kb: None,
        filesystems: Vec::new(),
        history: None,
    };

    let mut filesystems: HashMap<String, AgentFilesystemMetrics> = HashMap::new();

    for item in instant["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let name = item["metric"]["__name__"].as_str().unwrap_or("");
        let value = scalar_value(&item);
        if name.starts_with("system.filesystem.")
            && matches!(
                name,
                "system.filesystem.usage"
                    | "system.filesystem.total"
                    | "system.filesystem.available"
            )
            && let Some(mount) = item["metric"]["mount"].as_str()
        {
            let fstype = item["metric"]["fstype"].as_str();
            let entry =
                filesystems
                    .entry(mount.to_string())
                    .or_insert_with(|| AgentFilesystemMetrics {
                        mount: mount.to_string(),
                        fstype: None,
                        usage_percent: None,
                        total_kb: None,
                        available_kb: None,
                    });
            if let Some(fstype) = fstype {
                entry.fstype = Some(fstype.to_string());
            }
            match name {
                "system.filesystem.usage" => entry.usage_percent = parse_f64(value),
                "system.filesystem.total" => entry.total_kb = parse_i64(value),
                "system.filesystem.available" => entry.available_kb = parse_i64(value),
                _ => {}
            }
            continue;
        }
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
    metrics.filesystems = filesystems.into_values().collect();
    metrics
        .filesystems
        .sort_by(|left, right| left.mount.cmp(&right.mount));

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

#[cfg(test)]
mod tests {
    use super::build_metrics;
    use serde_json::json;

    #[test]
    fn build_metrics_groups_filesystem_series_by_mount() {
        let instant = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system.filesystem.usage", "mount": "/var", "fstype": "xfs"}, "value": [1, "95"]},
                    {"metric": {"__name__": "system.filesystem.total", "mount": "/var", "fstype": "xfs"}, "value": [1, "20971520"]},
                    {"metric": {"__name__": "system.filesystem.available", "mount": "/var", "fstype": "xfs"}, "value": [1, "1048576"]},
                    {"metric": {"__name__": "system.filesystem.usage", "mount": "/", "fstype": "ext4"}, "value": [1, "60"]},
                    {"metric": {"__name__": "system.filesystem.usage", "mount": "/data"}, "value": [1, "50"]},
                    {"metric": {"__name__": "system.filesystem.usage"}, "value": [1, "99"]},
                    {"metric": {"__name__": "system.filesystem.inodes.usage", "mount": "/var"}, "value": [1, "88"]},
                    {"metric": {"__name__": "system.disk.usage"}, "value": [1, "26.5"]}
                ]
            }
        });
        let range = json!({"data": {"result": []}});

        let metrics = build_metrics("agent-001", &instant, &range);

        // 没有 `mount` 的 series 被忽略，不会造出一个空挂载点。
        assert_eq!(metrics.filesystems.len(), 3);
        let var = metrics
            .filesystems
            .iter()
            .find(|filesystem| filesystem.mount == "/var")
            .expect("/var filesystem");
        assert_eq!(var.fstype.as_deref(), Some("xfs"));
        assert_eq!(var.usage_percent, Some(95.0));
        assert_eq!(var.total_kb, Some(20_971_520));
        assert_eq!(var.available_kb, Some(1_048_576));

        let data = metrics
            .filesystems
            .iter()
            .find(|filesystem| filesystem.mount == "/data")
            .expect("/data filesystem");
        assert_eq!(data.fstype, None, "missing fstype stays None");
        assert_eq!(data.usage_percent, Some(50.0));

        // 旧字段仍然独立解析，保持兼容。
        assert_eq!(metrics.disk_usage_percent, Some(26.5));

        // 序列化保持 camelCase，前端按这个形状消费。
        let json = serde_json::to_value(&metrics).expect("serialize metrics");
        assert_eq!(json["filesystems"][0]["mount"], "/");
        assert_eq!(json["filesystems"][0]["usagePercent"], 60.0);
        assert_eq!(json["filesystems"][2]["mount"], "/var");
    }

    #[test]
    fn build_metrics_keeps_legacy_disk_fields_without_filesystems() {
        let instant = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system.disk.usage"}, "value": [1, "60"]},
                    {"metric": {"__name__": "system.disk.total"}, "value": [1, "20971520"]},
                    {"metric": {"__name__": "system.disk.available"}, "value": [1, "1048576"]}
                ]
            }
        });
        let range = json!({"data": {"result": []}});

        let metrics = build_metrics("agent-001", &instant, &range);

        assert!(metrics.filesystems.is_empty());
        assert_eq!(metrics.disk_usage_percent, Some(60.0));
        assert_eq!(metrics.disk_total_kb, Some(20_971_520));
        assert_eq!(metrics.disk_available_kb, Some(1_048_576));
    }
}
