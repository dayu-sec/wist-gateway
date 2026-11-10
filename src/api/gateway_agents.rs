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
use wist_contracts::work::WorkSpec;
use wist_control::types::DateTime;
use wist_control::{
    AgentCollectionEntry, AgentCollectionReason, AgentDataManifest, AgentDataSource,
    AgentRuntimeStatus,
};

use crate::infra::{AgentQuery, StoreError, StoredAgentRegistration};

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
    let mut views = Vec::with_capacity(agents.len());
    for agent in &agents {
        views.push(AgentRuntimeStatus {
            agent_id: agent.agent_id.clone(),
            instance_id: agent.instance_id.clone(),
            version: agent.version.clone(),
            status: if super::overview::agent_is_online(&agent.last_seen_at, &now) {
                "online".to_string()
            } else {
                "offline".to_string()
            },
            health: "healthy".to_string(),
            last_seen_at: DateTime::from_rfc3339(&agent.last_seen_at).unwrap_or_else(DateTime::now),
            memory_bytes: agent.last_memory_bytes.map(|value| value as i64),
            cpu_percent: agent.last_cpu_percent,
            admin_latency_ms: agent.last_admin_latency_ms.map(|value| value as i64),
            node_id: non_empty(&agent.node_id),
            hostname: non_empty(&agent.hostname),
            ip_addresses: (!agent.ip_addresses.is_empty()).then(|| agent.ip_addresses.clone()),
            data_manifest: Some(agent_data_manifest(state, agent).await?),
            investigations: crate::api::investigations::recent_investigation_tasks(
                state,
                &agent.agent_id,
                chrono::Utc::now().timestamp_millis() - INVESTIGATION_TASK_RETENTION_MS,
                MAX_INVESTIGATION_TASKS,
            )
            .await?,
        });
    }
    Ok(GatewayAgentsReport {
        gateway_id: gateway_id.to_string(),
        agents: views,
    })
}

/// 数据清单里最多带多少份调查报告（摘要，按新 → 旧）。
///
/// 与网关自己的「调查报告」页（最近 50 条）不同：上报给中心的是**清单**，
/// 中心只用来回答「这台机器有哪些调查数据」；正文仍留在网关按需读取。
const MANIFEST_MAX_INVESTIGATIONS: usize = 20;

/// 调查任务状态最多带几条（与中心「最近 3 条」同口径，新 → 旧）。
const MAX_INVESTIGATION_TASKS: usize = 3;

/// 任务状态只留 7 天：更早的任务不再上报（报告本身仍可在保留期内读到）。
///
/// 与 `data_manifest.investigations` 的生命周期不同：清单是「有什么数据」，
/// 任务状态是「这条命令跑到哪了」—— 后者过期快，以免页面上堆一串没人再关心的旧命令。
const INVESTIGATION_TASK_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// 生成一台 Agent 的**数据清单**（采集授权 + 调查数据）。
///
/// 采集侧：网关注册表里的常驻工作（期望）+ agentd 上报的 `local_work`（实测）按 `work_id` 对齐；
/// 调查侧：网关本机报告目录里的摘要，口径与调查报告列表页一致。
async fn agent_data_manifest(
    state: &ApiState,
    agent: &StoredAgentRegistration,
) -> Result<AgentDataManifest, StoreError> {
    let works = state.store.list_standing_work(&agent.agent_id).await?;
    let local = agent.local_work.as_ref();
    let collection = works
        .iter()
        // 撤回与被取代的历史版本不进清单：清单答的是「现在被授权采集什么」。
        .filter(|work| work.status == "active" || work.status == "paused")
        .map(|work| {
            let local_work = local.and_then(|local| {
                local
                    .standing
                    .iter()
                    .find(|entry| entry.work_id == work.work_id)
            });
            let collection = local_work.and_then(|entry| entry.collection.as_ref());
            AgentCollectionEntry {
                family: work.family.clone(),
                work_id: work.work_id.clone(),
                status: work.status.clone(),
                plan_version: work.plan_version,
                acknowledged_version: local_work.and_then(|entry| entry.acknowledged_version),
                // 兼容字段：供未升级的中心 / 页面使用。
                collection_status: collection.and_then(|value| non_empty(&value.status)),
                collection_detail: collection.and_then(|value| non_empty(&value.detail)),
                // 新模型三字段：新消费方以 `collection_result` 为准。
                collection_prerequisites: collection
                    .and_then(|value| non_empty(&value.prerequisites)),
                collection_result: collection.and_then(|value| non_empty(&value.result)),
                collection_reasons: collection.and_then(|value| {
                    (!value.reasons.is_empty()).then(|| {
                        value
                            .reasons
                            .iter()
                            .map(|reason| AgentCollectionReason {
                                kind: reason.kind.clone(),
                                subject: reason.subject.clone(),
                                detail: reason.detail.clone(),
                            })
                            .collect()
                    })
                }),
                inputs: spec_sources(&work.spec),
            }
        })
        .collect();
    Ok(AgentDataManifest {
        collected_at: DateTime::now(),
        collection,
        investigations: crate::api::investigations::manifest_entries(
            state,
            &agent.agent_id,
            MANIFEST_MAX_INVESTIGATIONS,
        ),
    })
}

/// 从常驻工作的 `spec` 里抽出「采什么」：来源类型 + 目标（去重保序）。
///
/// spec 是网关自己物化出来的，解析失败说明库里有一份损坏的工作 —— 那是网关自己的
/// 不变式问题：清单只跳过它，不因此让整份机队上报失败。
fn spec_sources(spec: &str) -> Vec<AgentDataSource> {
    let Ok(spec) = WorkSpec::parse(spec) else {
        return Vec::new();
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut sources = Vec::new();
    for source in spec.units.into_iter().flat_map(|unit| unit.sources) {
        if seen.insert((source.kind.clone(), source.target.clone())) {
            sources.push(AgentDataSource {
                kind: source.kind,
                target: source.target,
            });
        }
    }
    sources
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
                data_manifest: Some(AgentDataManifest {
                    collected_at: DateTime::now(),
                    collection: vec![AgentCollectionEntry {
                        family: "HostMetrics".into(),
                        work_id: "work-1".into(),
                        status: "active".into(),
                        plan_version: 2,
                        acknowledged_version: Some(2),
                        collection_status: Some("ok".into()),
                        collection_detail: None,
                        collection_prerequisites: None,
                        collection_result: None,
                        collection_reasons: None,
                        inputs: vec![AgentDataSource {
                            kind: "MetricInterval".into(),
                            target: "15s".into(),
                        }],
                    }],
                    investigations: Vec::new(),
                }),
                investigations: Vec::new(),
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
                "data_manifest",
                "health",
                "hostname",
                "instance_id",
                "investigations",
                "ip_addresses",
                "last_seen_at",
                "memory_bytes",
                "node_id",
                "status",
                "version",
            ]
        );
        let manifest = &value["agents"][0]["data_manifest"];
        assert_eq!(manifest["collection"][0]["family"], "HostMetrics");
        assert_eq!(
            manifest["collection"][0]["inputs"][0]["kind"],
            "MetricInterval"
        );
    }

    /// 空串不是身份：`""` → `null`，中心页才不会显示一台“没有名字的机器”。
    #[test]
    fn blank_identity_is_reported_as_null() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("   "), None);
        assert_eq!(non_empty(" host-1 "), Some("host-1".to_string()));
    }

    /// 清单里的来源从工作 `spec` 里抽：去重（同源只留一条）且保持顺序。
    #[test]
    fn spec_sources_dedupes_kind_and_target() {
        let spec = r#"{"units":[
            {"unit_id":"u1","capability":"collect_logs","rule_ref":"r1",
             "requires_privilege":"none",
             "sources":[{"kind":"FileGlob","target":"/var/log/a.log"},
                        {"kind":"FileGlob","target":"/var/log/b.log"}]},
            {"unit_id":"u2","capability":"collect_logs","rule_ref":"r2",
             "requires_privilege":"none",
             "sources":[{"kind":"FileGlob","target":"/var/log/a.log"}]}
        ]}"#;
        let sources = spec_sources(spec);
        assert_eq!(sources.len(), 2, "同源只留一条：{sources:?}");
        assert_eq!(sources[0].target, "/var/log/a.log");
        assert_eq!(sources[1].target, "/var/log/b.log");
    }

    /// 损坏的 spec 不让整份机队上报失败：清单里这一条就是空来源。
    #[test]
    fn broken_spec_yields_no_sources() {
        assert!(spec_sources("not-json").is_empty());
    }
}
