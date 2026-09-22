use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};

// ─────────────────────────────────────────────────────────────────────────────
// L1a 机械资产清单（从事实摘要派生）
// ─────────────────────────────────────────────────────────────────────────────

/// 「按软件看机器」的聚类键条数上限。见 `Store::list_software_holdings` 的注释。
const DEFAULT_SOFTWARE_LIMIT: usize = 100;
const MAX_SOFTWARE_LIMIT: usize = 500;

#[derive(Debug, Clone, Deserialize)]
pub struct SoftwareHoldingsQuery {
    pub limit: Option<usize>,
}

/// 某台机器上的一个软件条目（管理面响应）。
#[derive(Debug, Serialize)]
struct SoftwareEntryView {
    software_key: String,
    name: String,
    kind: String,
    matched_rule: String,
    path: String,
}

/// 持有某个软件的一台机器。只给 `agent_id` 与 `path`：主机名/状态属于机器台账，
/// 页面手上就有那份台账（与 `Store::list_software_holdings` 的取舍一致）。
#[derive(Debug, Serialize)]
struct SoftwareHolderView {
    agent_id: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct SoftwareHoldingView {
    software_key: String,
    name: String,
    kind: String,
    agent_count: usize,
    holders: Vec<SoftwareHolderView>,
}

#[derive(Debug, Serialize)]
struct AgentSoftwareResponse {
    agent_id: String,
    /// 总行数（= 去重后可执行路径条数）与其中 app 行数。
    paths: i64,
    apps: i64,
    entries: Vec<SoftwareEntryView>,
}

#[derive(Debug, Serialize)]
struct SoftwareHoldingsResponse {
    /// 是否因 `limit` 截断（键的总数超过返回条数）。
    truncated: bool,
    software: Vec<SoftwareHoldingView>,
}

/// 某台机器的资产清单（「按机器看软件」）。
pub async fn view_agent_software(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 先确认 agent 存在：不存在的 agent 与「存在但没上报过清单」必须能区分
    // （前者 404，后者 200 + 空清单 + 0 计数），否则运维分不清「打错 id」与「没采到」。
    match state.store.get_agent(&agent_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, format!("unknown agent {agent_id}")).into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };

    let entries = match state.store.list_agent_software(&agent_id).await {
        Ok(entries) => entries,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load software inventory: {err}"),
            )
                .into_response();
        }
    };
    let summary = match state.store.summarize_agent_software(&agent_id).await {
        Ok(summary) => summary,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to summarize software inventory: {err}"),
            )
                .into_response();
        }
    };

    Json(AgentSoftwareResponse {
        agent_id,
        paths: summary.paths,
        apps: summary.apps,
        entries: entries
            .into_iter()
            .map(|entry| SoftwareEntryView {
                software_key: entry.software_key,
                name: entry.name,
                kind: entry.kind,
                matched_rule: entry.matched_rule,
                path: entry.path,
            })
            .collect(),
    })
    .into_response()
}

/// 按软件聚合的清单（「按软件看机器」）。
pub async fn view_software_holdings(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<SoftwareHoldingsQuery>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_SOFTWARE_LIMIT)
        .clamp(1, MAX_SOFTWARE_LIMIT);

    let holdings = match state.store.list_software_holdings(limit).await {
        Ok(holdings) => holdings,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load software holdings: {err}"),
            )
                .into_response();
        }
    };
    let total_keys = match state.store.count_software_keys().await {
        Ok(total) => total,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to count software keys: {err}"),
            )
                .into_response();
        }
    };

    Json(SoftwareHoldingsResponse {
        truncated: total_keys > holdings.len() as i64,
        software: holdings
            .into_iter()
            .map(|holding| {
                let agent_count = {
                    let mut ids: Vec<&str> = holding
                        .holders
                        .iter()
                        .map(|h| h.agent_id.as_str())
                        .collect();
                    ids.sort_unstable();
                    ids.dedup();
                    ids.len()
                };
                SoftwareHoldingView {
                    software_key: holding.software_key,
                    name: holding.name,
                    kind: holding.kind,
                    agent_count,
                    holders: holding
                        .holders
                        .into_iter()
                        .map(|holder| SoftwareHolderView {
                            agent_id: holder.agent_id,
                            path: holder.path,
                        })
                        .collect(),
                }
            })
            .collect(),
    })
    .into_response()
}
