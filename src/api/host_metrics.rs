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
    /// 逐挂载点容量（`system_filesystem_*`）。上面的 `disk_*` 是整盘汇总字段，二者不是同一粒度。
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
    /// 当前最紧张的挂载点使用率（`system_filesystem_usage_ratio` 的最大值）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_filesystem_usage_percent: Option<f64>,
    /// 当前最紧张的挂载点路径（与上面的百分比成对返回）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_filesystem_usage_mount: Option<String>,
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

/// 列表页只需要的指标名（白名单）。新增旧名会让列表页退回到旧口径，由测试钉住。
const SUMMARY_METRIC_NAMES: &[&str] = &[
    "system_load_average_1m",
    "system_memory_total_bytes",
    "system_memory_available_bytes",
    "system_disk_usage_ratio",
    "system_filesystem_usage_ratio",
];

/// 拉一次所有主机的 `system.*` 指标，按 `agent` 标签分组，并给注册表里认识的机器 join 上身份。
async fn query_all_host_metrics(
    vm_url: &str,
    identities: &HashMap<String, StoredAgentIdentity>,
) -> Result<Vec<AgentHostMetricsSummary>, String> {
    if identities.is_empty() {
        return Ok(Vec::new());
    }
    // 只拉列表页实际用到的指标，按名称白名单过滤：
    // 逐挂载点容量会按挂载点数展开，不能把全部序列都拉给列表页。
    let query = format!("{{__name__=~\"{}\"}}", SUMMARY_METRIC_NAMES.join("|"));
    let instant = query_json(vm_url, "/api/v1/query", &[("query", query.as_str())]).await?;

    let mut map: std::collections::HashMap<String, AgentHostMetricsSummary> =
        std::collections::HashMap::new();
    for item in instant["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let agent = item["metric"]["agent"].as_str().unwrap_or("").to_string();
        // 只保留注册表里认识的 agent：`/hosts` 的语义是「有指标上报的已注册机器」。
        // 注意：未升级的旧 agent 只写旧名（已不再解析），会暂时从这个列表消失，升级后自动回来。
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
                max_filesystem_usage_mount: None,
            });
        match name {
            "system_load_average_1m" => entry.load_average_1m = parse_f64(value),
            "system_memory_total_bytes" => {
                entry.memory_total_kb = parse_i64(value).map(|bytes| bytes / 1024)
            }
            "system_memory_available_bytes" => {
                entry.memory_available_kb = parse_i64(value).map(|bytes| bytes / 1024)
            }
            "system_disk_usage_ratio" if is_system_disk(&item) => {
                entry.disk_usage_percent = parse_f64(value).map(|ratio| ratio * 100.0)
            }
            "system_filesystem_usage_ratio" => {
                if let Some(mountpoint) = item["metric"]["mountpoint"].as_str()
                    && let Some(usage) = parse_f64(value).map(|ratio| ratio * 100.0)
                {
                    record_filesystem_usage(entry, mountpoint, usage);
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
        if matches!(
            name,
            "system_filesystem_usage_ratio"
                | "system_filesystem_total_bytes"
                | "system_filesystem_available_bytes"
        ) && let Some(mountpoint) = item["metric"]["mountpoint"].as_str()
        {
            let fstype = item["metric"]["fstype"].as_str();
            let entry = filesystems
                .entry(mountpoint.to_string())
                .or_insert_with(|| AgentFilesystemMetrics {
                    mount: mountpoint.to_string(),
                    fstype: None,
                    usage_percent: None,
                    total_kb: None,
                    available_kb: None,
                });
            if let Some(fstype) = fstype {
                entry.fstype = Some(fstype.to_string());
            }
            match name {
                "system_filesystem_usage_ratio" => {
                    entry.usage_percent = parse_f64(value).map(|ratio| ratio * 100.0)
                }
                "system_filesystem_total_bytes" => {
                    entry.total_kb = parse_i64(value).map(|bytes| bytes / 1024)
                }
                "system_filesystem_available_bytes" => {
                    entry.available_kb = parse_i64(value).map(|bytes| bytes / 1024)
                }
                _ => {}
            }
            continue;
        }
        match name {
            "system_load_average_1m" => metrics.load_average_1m = parse_f64(value),
            "system_load_average_5m" => metrics.load_average_5m = parse_f64(value),
            "system_load_average_15m" => metrics.load_average_15m = parse_f64(value),
            "system_uptime_seconds" => metrics.uptime_seconds = parse_f64(value),
            "system_memory_total_bytes" => {
                metrics.memory_total_kb = parse_i64(value).map(|bytes| bytes / 1024)
            }
            "system_memory_available_bytes" => {
                metrics.memory_available_kb = parse_i64(value).map(|bytes| bytes / 1024)
            }
            "system_disk_usage_ratio" if is_system_disk(&item) => {
                metrics.disk_usage_percent = parse_f64(value).map(|ratio| ratio * 100.0)
            }
            "system_disk_total_bytes" if is_system_disk(&item) => {
                metrics.disk_total_kb = parse_i64(value).map(|bytes| bytes / 1024)
            }
            "system_disk_available_bytes" if is_system_disk(&item) => {
                metrics.disk_available_kb = parse_i64(value).map(|bytes| bytes / 1024)
            }
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
            "system_load_average_1m" => history.load_average_1m = points,
            "system_load_average_5m" => history.load_average_5m = points,
            "system_load_average_15m" => history.load_average_15m = points,
            "system_memory_total_bytes" => {
                history.memory_total_kb = scale_points(points, 1.0 / 1024.0)
            }
            "system_memory_available_bytes" => {
                history.memory_available_kb = scale_points(points, 1.0 / 1024.0)
            }
            "system_disk_usage_ratio" => history.disk_usage_percent = scale_points(points, 100.0),
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

fn record_filesystem_usage(entry: &mut AgentHostMetricsSummary, mount: &str, usage: f64) {
    let is_worse = entry
        .max_filesystem_usage_percent
        .is_none_or(|current| usage > current);
    if is_worse {
        entry.max_filesystem_usage_percent = Some(usage);
        entry.max_filesystem_usage_mount = Some(mount.to_string());
    }
}

/// 整盘汇总字段（`diskUsagePercent` 等）只对应“系统盘”：磁盘序列按 `disk_role` 分组，
/// 不过滤会让 `system` 与 `data` 互相覆盖。缺 label 视为 `system`：唯一生产者（agentd）
/// 一定带该 label，缺失只可能来自不完整序列。
fn is_system_disk(item: &serde_json::Value) -> bool {
    match item["metric"]["disk_role"].as_str() {
        Some(role) => role == "system",
        None => true,
    }
}

fn parse_f64(value: Option<&str>) -> Option<f64> {
    // `NaN` / `±Inf` 无法进 JSON 响应，按「缺值」处理，不落 null。
    value
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

/// 时间序列按固定系数缩放（字节→KB、比例→百分比）。
fn scale_points(points: Vec<(i64, f64)>, factor: f64) -> Vec<(i64, f64)> {
    points
        .into_iter()
        .map(|(timestamp_ms, value)| (timestamp_ms, value * factor))
        .filter(|(_, value)| value.is_finite())
        .collect()
}

fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

#[cfg(test)]
mod tests {
    use super::{
        AgentHostMetricsSummary, SUMMARY_METRIC_NAMES, build_metrics, record_filesystem_usage,
    };
    use serde_json::json;

    fn summary() -> AgentHostMetricsSummary {
        AgentHostMetricsSummary {
            agent_id: "agent-1".to_string(),
            node_id: String::new(),
            hostname: String::new(),
            ip_addresses: Vec::new(),
            load_average_1m: None,
            memory_total_kb: None,
            memory_available_kb: None,
            disk_usage_percent: None,
            max_filesystem_usage_percent: None,
            max_filesystem_usage_mount: None,
        }
    }

    #[test]
    fn summary_whitelist_only_contains_canonical_names() {
        // 规范名不含 `.`；旧名（system.memory.total 等）不得回流到列表页查询。
        for name in SUMMARY_METRIC_NAMES {
            assert!(!name.contains('.'), "legacy name in whitelist: {name}");
            assert!(name.starts_with("system_"), "unexpected namespace: {name}");
        }
    }

    #[test]
    fn build_metrics_groups_filesystem_series_by_mount() {
        let instant = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system_filesystem_usage_ratio", "mountpoint": "/var", "fstype": "xfs"}, "value": [1, "0.95"]},
                    {"metric": {"__name__": "system_filesystem_total_bytes", "mountpoint": "/var", "fstype": "xfs"}, "value": [1, "21474836480"]},
                    {"metric": {"__name__": "system_filesystem_available_bytes", "mountpoint": "/var", "fstype": "xfs"}, "value": [1, "1073741824"]},
                    {"metric": {"__name__": "system_filesystem_usage_ratio", "mountpoint": "/", "fstype": "ext4"}, "value": [1, "0.6"]},
                    {"metric": {"__name__": "system_filesystem_usage_ratio", "mountpoint": "/data"}, "value": [1, "0.5"]},
                    {"metric": {"__name__": "system_filesystem_usage_ratio"}, "value": [1, "0.99"]},
                    {"metric": {"__name__": "system_filesystem_inodes", "mountpoint": "/var"}, "value": [1, "88"]},
                    {"metric": {"__name__": "system_disk_usage_ratio"}, "value": [1, "0.265"]}
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

        // 整盘汇总字段与逐挂载点列表各自独立解析。
        assert_eq!(metrics.disk_usage_percent, Some(26.5));

        // 序列化保持 camelCase，前端按这个形状消费。
        let json = serde_json::to_value(&metrics).expect("serialize metrics");
        assert_eq!(json["filesystems"][0]["mount"], "/");
        assert_eq!(json["filesystems"][0]["usagePercent"], 60.0);
        assert_eq!(json["filesystems"][2]["mount"], "/var");
    }

    #[test]
    fn keeps_the_worst_filesystem_mount() {
        let mut entry = summary();

        record_filesystem_usage(&mut entry, "/", 60.0);
        assert_eq!(entry.max_filesystem_usage_mount.as_deref(), Some("/"));

        // 更低的使用率不能覆盖更紧张的挂载点。
        record_filesystem_usage(&mut entry, "/data", 50.0);
        assert_eq!(entry.max_filesystem_usage_percent, Some(60.0));
        assert_eq!(entry.max_filesystem_usage_mount.as_deref(), Some("/"));

        record_filesystem_usage(&mut entry, "/var", 95.0);
        assert_eq!(entry.max_filesystem_usage_percent, Some(95.0));
        assert_eq!(entry.max_filesystem_usage_mount.as_deref(), Some("/var"));

        let json = serde_json::to_value(&entry).expect("serialize summary");
        assert_eq!(json["maxFilesystemUsageMount"], "/var");
    }

    #[test]
    fn non_finite_values_are_treated_as_missing() {
        let instant = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system_load_average_1m"}, "value": [1, "NaN"]},
                    {"metric": {"__name__": "system_uptime_seconds"}, "value": [1, "+Inf"]},
                    {"metric": {"__name__": "system_memory_total_bytes"}, "value": [1, "1073741824"]}
                ]
            }
        });
        let range = json!({"data": {"result": []}});

        let metrics = build_metrics("agent-001", &instant, &range);

        assert_eq!(metrics.load_average_1m, None);
        assert_eq!(metrics.uptime_seconds, None);
        assert_eq!(metrics.memory_total_kb, Some(1_048_576));
    }

    #[test]
    fn disk_summary_fields_only_read_the_system_role() {
        // `system_disk_*` 按 `disk_role` 分成 system / data 两条序列，
        // 整盘汇总字段只对应系统盘；否则 data 会随机覆盖 system。
        let instant = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system_disk_usage_ratio", "disk_role": "system"}, "value": [1, "0.6"]},
                    {"metric": {"__name__": "system_disk_usage_ratio", "disk_role": "data"}, "value": [1, "0.95"]},
                    {"metric": {"__name__": "system_disk_total_bytes", "disk_role": "system"}, "value": [1, "21474836480"]},
                    {"metric": {"__name__": "system_disk_total_bytes", "disk_role": "data"}, "value": [1, "107374182400"]}
                ]
            }
        });
        let range = json!({"data": {"result": []}});

        let metrics = build_metrics("agent-001", &instant, &range);

        assert_eq!(metrics.disk_usage_percent, Some(60.0));
        assert_eq!(metrics.disk_total_kb, Some(20_971_520));
    }

    #[test]
    fn build_metrics_ignores_legacy_names() {
        // 旧名已下线：即使 VM 里还留有旧版本 agent 的历史序列，网关也不再解读。
        let instant = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system.load_average.1m"}, "value": [1, "0.25"]},
                    {"metric": {"__name__": "system.uptime"}, "value": [1, "3600"]},
                    {"metric": {"__name__": "system.memory.total"}, "value": [1, "1048576"]},
                    {"metric": {"__name__": "system.disk.usage"}, "value": [1, "26.5"]},
                    {"metric": {"__name__": "system.filesystem.usage", "mount": "/var"}, "value": [1, "95"]}
                ]
            }
        });
        let range = json!({
            "data": {
                "result": [
                    {"metric": {"__name__": "system.memory.total"}, "values": [[1, "1048576"]]},
                    {"metric": {"__name__": "system.disk.usage"}, "values": [[1, "26.5"]]}
                ]
            }
        });

        let metrics = build_metrics("agent-001", &instant, &range);

        assert_eq!(metrics.load_average_1m, None);
        assert_eq!(metrics.uptime_seconds, None);
        assert_eq!(metrics.memory_total_kb, None);
        assert_eq!(metrics.disk_usage_percent, None);
        assert!(metrics.filesystems.is_empty());

        let history = metrics.history.expect("history");
        assert!(history.memory_total_kb.is_empty());
        assert!(history.disk_usage_percent.is_empty());
    }
}
