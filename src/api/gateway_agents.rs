// NOTE(hand-added): 网关环回「Agent 明细」面（供 host 侧 wist-gwlinkd 拉取后转报中心）。
//
// 背景：中心「网关详情 → Agent 状态」页要看到**每台 agent 的运行态**，而中心连不到 NAT 后的
// 网关（CR-003：全边缘只有 gwlinkd 与中心对话）。故本面把网关注册表里的 agent 明细以**环回**
// 方式暴露给本机常驻，gwlinkd 拉取后原样 POST 中心 `POST /api/v1/gateway/agents/status`
// （契约 `wist_control::ReportAgentStatus`）。与 `self_state` / `link_request` / `linkd_status` /
// `agent_package` 同一形态（环回 + 手加路由）。
//
// 模型留档：`Control.GatewayApp.AgentReportInterface`（**刻意未 `bind`**，与 SelfInterface /
// LinkRequestInterface / GwlinkdStatusInterface / AgentPackageInterface 同口径）；设计
// `wist-design/doc/design/edge/gateway-agent-report.md`。
//
// 环回（gwlinkd）：`GET /api/v1/gateway/agents?gateway_id=<id>`（loopback-only）。
// 字段 snake_case，与契约 `AgentRuntimeStatus` 同形。
//
// 为什么不让网关**直报**中心：网关在 NAT 后，中心连不到它；gwlinkd 才是唯一出站者。

use super::codes;
use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use wist_control::AgentRuntimeStatus;
use wist_control::types::DateTime;

use crate::infra::AgentQuery;

use super::error::ApiError;
use super::{ApiState, rate_limit};

#[derive(Debug, Deserialize)]
pub struct GatewayAgentsQuery {
    /// 调用方自报的网关 id（网关侧未必自持该值；原样回显供调用方核对，与自述面同口径）。
    pub gateway_id: Option<String>,
}

/// 环回「Agent 明细」响应：与中心上报契约 `wist_control::ReportAgentStatus` **同形**
/// （`gateway_id` + `agents`）。gwlinkd 拉到后以自身配置的 `gateway_id` 覆写并转报中心。
#[derive(Debug, Serialize)]
pub struct GatewayAgentsReport {
    pub gateway_id: String,
    pub agents: Vec<AgentRuntimeStatus>,
}

/// 环回读取本机 agent 明细：`GET /api/v1/gateway/agents?gateway_id=`。
pub async fn query_gateway_agents(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Query(params): Query<GatewayAgentsQuery>,
) -> Response {
    // 与自述面同一护栏：只面向**本机** host 侧常驻，非本机一律拒绝（fail-closed：
    // 取不到 peer 也拒绝，不因「没连接信息」就放行）。本机判据见 [`ApiState::is_local_host_peer`]。
    if !state.is_local_host_peer(client) {
        return ApiError::forbidden(
            codes::GATEWAY_AGENTS_LOOPBACK_ONLY,
            "gateway agents is loopback-only",
        )
        .into_response();
    }
    let gateway_id = params.gateway_id.as_deref().unwrap_or("").trim();
    if gateway_id.is_empty() {
        return ApiError::bad_request(
            codes::GATEWAY_AGENTS_MISSING_GATEWAY_ID,
            "missing gateway_id",
        )
        .into_response();
    }
    match gateway_agents(&state, gateway_id).await {
        Ok(report) => Json(report).into_response(),
        Err(err) => ApiError::internal(
            codes::AGENT_STORE_UNAVAILABLE,
            "failed to load agent store",
            err,
        )
        .into_response(),
    }
}

/// 读网关注册表并把机队投影成上报契约形状（`agent_id` 升序，由存储层保证）。
///
/// `status` 从 `last_seen_at` **现算**（与单台运行态 / 列表页共用 [`overview::agent_is_online`] 判据）；
/// `health` 与现有读投影一致恒为 `healthy`（agent 无独立健康度，在线/离线由 `status` 表达）。
///
/// 机器身份三字段（`node_id` / `hostname` / `ip_addresses`）取自注册表的机器画像：**空就报 `null`**，
/// 不把空串当成“这台机器叫空字符串”（中心页据此区分“没报上来”与“真的没有”）。
async fn gateway_agents(
    state: &ApiState,
    gateway_id: &str,
) -> Result<GatewayAgentsReport, crate::infra::StoreError> {
    let agents = state.store.list_agents(&AgentQuery::default()).await?;
    let now = DateTime::now();
    Ok(GatewayAgentsReport {
        gateway_id: gateway_id.to_string(),
        agents: agents
            .iter()
            .map(|agent| AgentRuntimeStatus {
                agent_id: agent.agent_id.clone(),
                instance_id: agent.instance_id.clone(),
                version: agent.version.clone(),
                status: if super::overview::agent_is_online(&agent.last_seen_at, &now) {
                    "online".to_string()
                } else {
                    "offline".to_string()
                },
                health: "healthy".to_string(),
                last_seen_at: DateTime::from_rfc3339(&agent.last_seen_at)
                    .unwrap_or_else(DateTime::now),
                memory_bytes: agent.last_memory_bytes.map(|value| value as i64),
                cpu_percent: agent.last_cpu_percent,
                admin_latency_ms: agent.last_admin_latency_ms.map(|value| value as i64),
                node_id: non_empty(&agent.node_id),
                hostname: non_empty(&agent.hostname),
                ip_addresses: (!agent.ip_addresses.is_empty()).then(|| agent.ip_addresses.clone()),
            })
            .collect(),
    })
}

/// 空串不是身份：统一折成 `None`（中心侧落库也保持 `NULL`，不写 `''`）。
fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 机队投影的**键集契约**（snake_case）：钉住环回响应形状 —— gwlinkd 侧有同一份 fixture 的
    /// **解析**测试，任一侧改名即爆（防拷贝漂移）。
    #[test]
    fn serializes_the_gateway_agents_contract_keys() {
        let report = GatewayAgentsReport {
            gateway_id: "gw-1".into(),
            agents: vec![AgentRuntimeStatus {
                agent_id: "agent-1".into(),
                instance_id: "inst-1".into(),
                version: "0.4.0".into(),
                status: "online".into(),
                health: "healthy".into(),
                last_seen_at: DateTime::now(),
                memory_bytes: Some(1024),
                cpu_percent: Some(1.5),
                admin_latency_ms: Some(8),
                node_id: Some("node-1".into()),
                hostname: Some("host-1".into()),
                ip_addresses: Some(vec!["en0 192.168.1.5/24".into()]),
            }],
        };
        let value: serde_json::Value = serde_json::to_value(&report).expect("serialize");
        let mut top: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        top.sort_unstable();
        assert_eq!(top, ["agents", "gateway_id"]);
        let mut agent: Vec<&str> = value["agents"][0]
            .as_object()
            .expect("agent object")
            .keys()
            .map(String::as_str)
            .collect();
        agent.sort_unstable();
        assert_eq!(
            agent,
            [
                "admin_latency_ms",
                "agent_id",
                "cpu_percent",
                "health",
                "hostname",
                "instance_id",
                "ip_addresses",
                "last_seen_at",
                "memory_bytes",
                "node_id",
                "status",
                "version",
            ]
        );
    }

    /// 空串不是身份：`""` → `null`，中心页才不会显示一台“没有名字的机器”。
    #[test]
    fn blank_identity_is_reported_as_null() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("   "), None);
        assert_eq!(non_empty(" host-1 "), Some("host-1".to_string()));
    }
}
