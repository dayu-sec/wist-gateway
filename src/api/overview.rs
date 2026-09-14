use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;

use axum::{
    extract::{connect_info::ConnectInfo, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::infra::victoria_metrics::query_json;
use crate::infra::{AgentMetricSample, StoredAgentRegistration};
use insight_control::types::{AgentRuntimeStatus, DateTime};

use super::admin_auth::require_admin_bearer;
use super::{rate_limit, AdminRuntimeState, ApiState};

#[derive(Debug, Clone, Serialize, ::jumo_derive::Jumo)]
#[serde(rename_all = "camelCase")]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Status")]
pub struct AgentOverviewMetrics {
    pub total_agents: i64,
    pub online_agents: i64,
    pub unhealthy_agents: i64,
    pub last_seen_lag_seconds: i64,
}

#[derive(Debug, Clone, Serialize, ::jumo_derive::Jumo)]
#[serde(rename_all = "camelCase")]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Status")]
pub struct RecentOnlineRegisteredAgent {
    pub agent_id: String,
    pub instance_id: String,
    pub version: String,
    pub registered_at: DateTime,
    pub online_since: DateTime,
    pub online_duration_seconds: i64,
    pub source: RecentOnlineRegisteredAgentSource,
    pub memory_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub admin_latency_ms: Option<u64>,
    pub metrics_history: Vec<AgentMetricSample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecentOnlineRegisteredAgentSource {
    Real,
    Example,
}

#[derive(Debug, Clone, Serialize, ::jumo_derive::Jumo)]
#[serde(rename_all = "camelCase")]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Status")]
pub struct AgentOverview {
    pub metrics: AgentOverviewMetrics,
    pub recent_online_agents: Vec<RecentOnlineRegisteredAgent>,
    pub abnormal_agents: Vec<AgentRuntimeStatus>,
}

pub async fn get_agent_overview(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    Json(agent_overview(&state).await).into_response()
}

const ONLINE_WINDOW_SECONDS: i64 = 300;
const HISTORY_WINDOW_SECONDS: i64 = 3600;
const HISTORY_STEP_SECONDS: i64 = 30;

pub async fn agent_overview(state: &ApiState) -> AgentOverview {
    let snapshot = state.store.load().unwrap_or_default();
    let now = DateTime::now();

    // 总览指标对「全部 agent」计算，而不是只对最近 6 张卡片（卡片列表单独 truncate）。
    let total_agents = snapshot.agents.len() as i64;
    let online_agents = snapshot
        .agents
        .values()
        .filter(|agent| agent_is_online(&agent.last_seen_at, &now))
        .count() as i64;
    let last_seen_lag_seconds = snapshot
        .agents
        .values()
        .filter_map(|agent| DateTime::from_rfc3339(&agent.last_seen_at))
        .map(|last_seen| last_seen.seconds_until(&now))
        .max()
        .unwrap_or(0);

    let stored_agents = snapshot.agents.into_values().collect::<Vec<_>>();
    let memory_agents = state
        .runtime
        .lock()
        .expect("runtime state poisoned")
        .recent_online_agents
        .clone();
    let mut recent_online_agents = recent_online_agents_from_store(stored_agents);
    for agent in memory_agents {
        if !recent_online_agents
            .iter()
            .any(|existing| existing.agent_id == agent.agent_id)
        {
            recent_online_agents.push(agent);
        }
    }
    recent_online_agents.sort_by(|left, right| right.registered_at.cmp(&left.registered_at));
    recent_online_agents.truncate(6);

    let agent_ids: Vec<String> = recent_online_agents
        .iter()
        .map(|agent| agent.agent_id.clone())
        .collect();
    let histories = agent_metrics_histories(&state.config.victoria_metrics_url, &agent_ids).await;
    for agent in &mut recent_online_agents {
        if let Some(history) = histories.get(&agent.agent_id) {
            agent.metrics_history = history.clone();
        }
    }

    AgentOverview {
        metrics: AgentOverviewMetrics {
            total_agents,
            online_agents,
            unhealthy_agents: 0,
            last_seen_lag_seconds,
        },
        recent_online_agents,
        abnormal_agents: Vec::new(),
    }
}

fn recent_online_agents_from_store(
    mut agents: Vec<StoredAgentRegistration>,
) -> Vec<RecentOnlineRegisteredAgent> {
    agents.sort_by(|left, right| right.last_seen_at.cmp(&left.last_seen_at));
    agents
        .into_iter()
        .map(|agent| {
            let registered_at =
                DateTime::from_rfc3339(&agent.registered_at).unwrap_or_else(DateTime::now);
            let online_since =
                DateTime::from_rfc3339(&agent.last_seen_at).unwrap_or_else(DateTime::now);
            let online_duration_seconds = registered_at.seconds_until(&online_since);
            recent_online_registered_agent_at(
                &agent.agent_id,
                &agent.instance_id,
                &agent.version,
                registered_at,
                online_since,
                online_duration_seconds,
                RecentOnlineRegisteredAgentSource::Real,
                agent.last_memory_bytes,
                agent.last_cpu_percent,
                agent.last_admin_latency_ms,
            )
        })
        .collect()
}

pub fn record_recent_online_agent(
    runtime: &std::sync::Arc<std::sync::Mutex<AdminRuntimeState>>,
    agent_id: &str,
    instance_id: &str,
    version: &str,
    requested_at: &str,
) {
    let now = DateTime::now();
    let registered_at = DateTime::from_rfc3339(requested_at).unwrap_or_else(DateTime::now);
    let online_duration_seconds = registered_at.seconds_until(&now);
    let agent = recent_online_registered_agent_at(
        agent_id,
        instance_id,
        version,
        registered_at,
        now,
        online_duration_seconds,
        RecentOnlineRegisteredAgentSource::Real,
        None,
        None,
        None,
    );
    let mut state = runtime.lock().expect("runtime state poisoned");
    state
        .recent_online_agents
        .retain(|existing| existing.agent_id != agent_id);
    state.recent_online_agents.insert(0, agent);
    state.recent_online_agents.truncate(6);
}

fn recent_online_registered_agent_at(
    agent_id: &str,
    instance_id: &str,
    version: &str,
    registered_at: DateTime,
    online_since: DateTime,
    online_duration_seconds: i64,
    source: RecentOnlineRegisteredAgentSource,
    memory_bytes: Option<u64>,
    cpu_percent: Option<f64>,
    admin_latency_ms: Option<u64>,
) -> RecentOnlineRegisteredAgent {
    RecentOnlineRegisteredAgent {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        version: version.to_string(),
        registered_at,
        online_since,
        online_duration_seconds,
        source,
        memory_bytes,
        cpu_percent,
        admin_latency_ms,
        metrics_history: Vec::new(),
    }
}

fn agent_is_online(last_seen_at: &str, now: &DateTime) -> bool {
    let Some(last_seen) = DateTime::from_rfc3339(last_seen_at) else {
        return false;
    };
    (0..=ONLINE_WINDOW_SECONDS).contains(&last_seen.seconds_until(now))
}

async fn agent_metrics_histories(
    vm_url: &str,
    agent_ids: &[String],
) -> HashMap<String, Vec<AgentMetricSample>> {
    let mut histories: HashMap<String, Vec<AgentMetricSample>> = HashMap::new();
    if agent_ids.is_empty() {
        return histories;
    }

    // 一次拉取三个 agent 自身上报指标，再按 (agent, 时间戳) 对齐合并成历史样本。
    let query = r#"{__name__=~"agent.memory.bytes|agent.cpu.percent|agent.admin_latency.ms"}"#;
    let now = chrono::Utc::now().timestamp();
    let start = (now - HISTORY_WINDOW_SECONDS).to_string();
    let end = now.to_string();
    let step = HISTORY_STEP_SECONDS.to_string();
    let range = match query_json(
        vm_url,
        "/api/v1/query_range",
        &[
            ("query", query),
            ("start", start.as_str()),
            ("end", end.as_str()),
            ("step", step.as_str()),
        ],
    )
    .await
    {
        Ok(range) => range,
        Err(_) => return histories,
    };

    let wanted: HashSet<&str> = agent_ids.iter().map(String::as_str).collect();
    let mut per_agent: HashMap<String, BTreeMap<i64, AgentMetricSample>> = HashMap::new();

    for item in range["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let agent = item["metric"]["agent"].as_str().unwrap_or("").to_string();
        if agent.is_empty() || !wanted.contains(agent.as_str()) {
            continue;
        }
        let name = item["metric"]["__name__"].as_str().unwrap_or("");
        for pair in item["values"].as_array().cloned().unwrap_or_default() {
            let Some(pair) = pair.as_array() else {
                continue;
            };
            let Some(timestamp_ms) = pair
                .first()
                .and_then(|value| value.as_f64())
                .map(|value| (value * 1000.0) as i64)
            else {
                continue;
            };
            let Some(value) = pair.get(1).and_then(|value| value.as_str()) else {
                continue;
            };
            let entry = per_agent
                .entry(agent.clone())
                .or_default()
                .entry(timestamp_ms)
                .or_insert_with(|| AgentMetricSample {
                    at: timestamp_rfc3339(timestamp_ms),
                    memory_bytes: None,
                    cpu_percent: None,
                    admin_latency_ms: None,
                });
            match name {
                "agent.memory.bytes" => {
                    entry.memory_bytes = value.parse::<f64>().ok().map(|value| value as u64);
                }
                "agent.cpu.percent" => {
                    entry.cpu_percent = value.parse::<f64>().ok();
                }
                "agent.admin_latency.ms" => {
                    entry.admin_latency_ms = value.parse::<f64>().ok().map(|value| value as u64);
                }
                _ => {}
            }
        }
    }

    for (agent, by_timestamp) in per_agent {
        histories.insert(agent, by_timestamp.into_values().collect());
    }
    histories
}

fn timestamp_rfc3339(timestamp_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(timestamp_ms)
        .map(|value| value.to_rfc3339())
        .unwrap_or_default()
}
