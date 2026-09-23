use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;
use wist_control::types::{AgentRuntimeStatus, DateTime};

use crate::app::content::{MACHINE_CLASSES, platform_for_machine_class};
use crate::infra::{
    AgentQuery, DEFAULT_AGENT_UPLINK_PORT, DEFAULT_AGENT_UPLINK_SETTING_ID,
    DEFAULT_INSTALL_PACKAGE_SETTING_ID, StoredAgentClassification, StoredAgentFactSummary,
    StoredAgentInstallPackageAddress, StoredAgentUplinkAddress, StoredPurposeSuggestion,
};

use super::install_package::{PackageFetchError, fetch_into_cache};
use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};

/// 列表默认/最大分页大小（防止一次拉全表）。
const DEFAULT_AGENT_PAGE_LIMIT: u64 = 100;
const MAX_AGENT_PAGE_LIMIT: u64 = 500;
/// 安装包地址长度上限（只防意外超长输入）。
const MAX_PACKAGE_URL_LEN: usize = 2048;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentListQuery {
    pub tenant_id: Option<String>,
    pub environment_id: Option<String>,
    pub status: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

/// Agent 列表响应。
///
/// 模型里该端点声明为 `Projection<List<AgentRuntimeStatus>>`：运行态字段是投影主体，
/// 管理面额外需要的租户/环境/节点/凭据字段按「读投影形状由实现层派生」的约定在这里给出。
#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub agents: Vec<AgentListEntry>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Debug, Serialize)]
pub struct AgentListEntry {
    pub agent_id: String,
    pub instance_id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub node_id: String,
    pub hostname: String,
    pub version: String,
    pub status: String,
    pub health: String,
    pub credential_id: String,
    pub credential_status: String,
    pub credential_expires_at: String,
    pub registered_at: String,
    pub last_seen_at: DateTime,
    pub memory_bytes: Option<i64>,
    pub cpu_percent: Option<f64>,
    pub admin_latency_ms: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeCredentialRequest {
    pub credential_id: String,
}

/// 凭据吊销结果（对应模型 `AgentCredentialRevocationResult`）。
#[derive(Debug, Serialize)]
pub struct AgentCredentialRevocationResponse {
    pub agent_id: String,
    pub credential_id: String,
    pub status: String,
    pub revoked_at: DateTime,
}

/// 设置安装包地址的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct SetAgentInstallPackageRequest {
    pub package_url: String,
    pub package_sha256: Option<String>,
    pub requested_by: Option<String>,
}

/// 安装包地址响应（对应模型 `AgentInstallPackageAddress`）。
#[derive(Debug, Serialize)]
pub struct AgentInstallPackageResponse {
    pub address_id: String,
    pub package_url: String,
    pub package_sha256: Option<String>,
    pub updated_by: String,
    /// 未设置过（当前用内置默认分发地址）时为 null。
    pub updated_at: Option<DateTime>,
}

/// 设置 Agent 数据面上送地址的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct SetAgentUplinkRequest {
    pub host: String,
    /// 用 `i64` 收下再校验：用 `u16` 的话越界值会被 axum 的 JSON 提取器判成 422，
    /// 而这里约定一律用 400 + 纯文本原因回给管理面。
    pub port: i64,
    pub requested_by: Option<String>,
}

/// 数据面上送地址响应（对应模型 `AgentUplinkAddress`）。
#[derive(Debug, Serialize)]
pub struct AgentUplinkResponse {
    pub setting_id: String,
    pub host: String,
    pub port: u16,
    pub updated_by: String,
    /// 未设置过时为 null。
    pub updated_at: Option<DateTime>,
}

/// 当前生效的发现方向策略表视图（管理面）。
///
/// `configured=false` 表示这台网关没配策略表（agent 回落内建默认值），与「配了一张空表」
/// 区分开：后者在装载期就被拒了，不可能出现在这里。
#[derive(Debug, Serialize)]
pub struct DiscoveryPoliciesView {
    pub configured: bool,
    /// 未配置时为 null（不编一份空表来冒充“已配置”）。
    pub policy: Option<DiscoveryAspectPolicySet>,
    /// 每台已注册 Agent 实际生效的策略版本。
    ///
    /// 为什么**包含从未上报过的 Agent**：运维的问题是「谁还没生效」，那些从没打过状态
    /// 上报的机器必须**看得见**（`applied_policy_version=null`），而不是从列表里静默消失 ——
    /// 看不见的机器正是最可能漏掉的那一批。
    pub agents: Vec<AgentAppliedDiscoveryPolicy>,
    /// 与其它管理面视图一致：带上“这份视图是什么时候生成的”。
    pub generated_at: DateTime,
}

/// 单台 Agent 实际生效的发现方向策略版本（对应模型侧的并行类型）。
#[derive(Debug, Serialize)]
pub struct AgentAppliedDiscoveryPolicy {
    pub agent_id: String,
    /// null = 这台机器还没拉到策略表（在用内建默认周期）；0 是一个真实版本，不可混同。
    pub applied_policy_version: Option<i64>,
    pub instance_id: String,
    /// null = 从未上报过状态（只有注册记录）。
    ///
    /// 为什么不用空串：这套 API 里「没有」一律用 null（同 `applied_policy_version`、
    /// 同相邻视图的 `updated_at`），空串是另一种需要调用方另记的约定。
    pub last_seen_at: Option<String>,
}

/// Agent 用途视图（对应模型 `AgentPurposeView`）。
///
/// 三分**并列**：事实（agentd 报）/ 推断（网关算，可变可过期）/ 判定（人定，留痕）。
/// 冲突时以判定为准，但推断仍然并列展示 —— 不是谁盖掉谁。
/// 尚未上报事实的新 Agent：事实与建议都为 null，不伪造结论。
#[derive(Debug, Serialize)]
pub struct AgentPurposeResponse {
    pub agent_id: String,
    pub fact_summary: Option<StoredAgentFactSummary>,
    pub suggestion: Option<StoredPurposeSuggestion>,
    /// 人工判定：采纳建议或改判后落库（采集范围变更的前置）。
    pub classification: Option<StoredAgentClassification>,
    pub generated_at: DateTime,
}

pub async fn get_agent_runtime_status(
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
    Json(runtime_status(
        &agent.agent_id,
        &agent.instance_id,
        &agent.version,
        "online",
        "healthy",
        &agent.last_seen_at,
        agent.last_memory_bytes,
        agent.last_cpu_percent,
        agent.last_admin_latency_ms,
    ))
    .into_response()
}

/// 查看某台 Agent 的用途（对应模型 `ViewAgentPurpose`）。
///
/// 未知 agent 回 404：与 `runtime-status` 一致 —— "这台机器不存在"与"它还没报过事实"
/// 是两回事，不能都当空视图返回。
pub async fn view_agent_purpose(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
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
    let fact_summary = match state.store.get_agent_fact_summary(&agent_id).await {
        Ok(summary) => summary,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent fact summary: {err}"),
            )
                .into_response();
        }
    };
    let suggestion = match state.store.get_purpose_suggestion(&agent_id).await {
        Ok(suggestion) => suggestion,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load purpose suggestion: {err}"),
            )
                .into_response();
        }
    };
    let suggestion = refresh_suggestion_for_read(&state, fact_summary.as_ref(), suggestion).await;
    let classification = match state.store.get_agent_classification(&agent_id).await {
        Ok(classification) => classification,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent classification: {err}"),
            )
                .into_response();
        }
    };
    Json(AgentPurposeResponse {
        agent_id,
        fact_summary,
        suggestion,
        classification,
        generated_at: DateTime::now(),
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct ClassifyAgentRequest {
    pub machine_class: String,
    #[serde(default)]
    pub suggestion_id: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// 归档某台 Agent 的用途判定（人工判定）。
///
/// 采集范围是合规边界：判定是授权工作模板的前置，必须由人落这一笔。
/// 分类必须与该机器**已观测到的平台**一致（MacDaily/MacDev → macos，Linux* → linux）。
/// 平台只能从事实摘要的 `os` 判定：**没上报过事实就不放行**，而不是默认通过。
pub async fn classify_agent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<ClassifyAgentRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let machine_class = input.machine_class.trim();
    if !MACHINE_CLASSES.contains(&machine_class) {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown machine_class {machine_class:?}"),
        )
            .into_response();
    }
    let expected_platform =
        platform_for_machine_class(machine_class).expect("validated machine class has a platform");
    let summary = match state.store.get_agent_fact_summary(&agent_id).await {
        Ok(summary) => summary,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent fact summary: {err}"),
            )
                .into_response();
        }
    };
    let Some(summary) = summary else {
        return (
            StatusCode::BAD_REQUEST,
            format!("cannot classify {agent_id}: no observed platform yet (no fact summary)"),
        )
            .into_response();
    };
    if summary.os != expected_platform {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "machine_class {machine_class} belongs to {expected_platform}, but the agent platform is {}",
                summary.os
            ),
        )
            .into_response();
    }
    let classification = StoredAgentClassification {
        agent_id: agent_id.clone(),
        machine_class: machine_class.to_string(),
        suggestion_id: input.suggestion_id.filter(|value| !value.trim().is_empty()),
        note: input.note.filter(|value| !value.trim().is_empty()),
        // 网关只校验共享 admin token，暂无主体身份；先记 "admin"（模型里是 actor_identity）。
        decided_by: "admin".to_string(),
        decided_at: chrono::Utc::now().to_rfc3339(),
    };
    if let Err(err) = state
        .store
        .upsert_agent_classification(&classification)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store agent classification: {err}"),
        )
            .into_response();
    }
    Json(classification).into_response()
}

#[derive(Debug, Serialize)]
struct MachineClassCountResponse {
    machine_class: String,
    agent_count: i64,
}

#[derive(Debug, Serialize)]
struct PurposeCoverageResponse {
    total_agents: i64,
    classified_agents: i64,
    unclassified_agents: i64,
    by_class: Vec<MachineClassCountResponse>,
    generated_at: String,
}

/// 机队用途覆盖度：各类别台数 + 未归类台数。
///
/// 存在的意义就是把“4 类覆盖约 80%”从**断言**变成**可度量的数**：要挑下一个 MachineClass，
/// 看 `by_class` 分布与 `unclassified_agents`，而不是拍一个比例。
pub async fn view_purpose_coverage(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let counts = match state.store.purpose_coverage().await {
        Ok(counts) => counts,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load purpose coverage: {err}"),
            )
                .into_response();
        }
    };
    // 未归类 = 总数 − 已判定；用 max(0) 防脏数据把负数漏到页面上。
    let unclassified_agents = (counts.total_agents - counts.classified_agents).max(0);
    Json(PurposeCoverageResponse {
        total_agents: counts.total_agents,
        classified_agents: counts.classified_agents,
        unclassified_agents,
        by_class: counts
            .by_class
            .into_iter()
            .map(|(machine_class, agent_count)| MachineClassCountResponse {
                machine_class,
                agent_count,
            })
            .collect(),
        generated_at: chrono::Utc::now().to_rfc3339(),
    })
    .into_response()
}

/// 读取路径上的建议自愈：过期就重算。
///
/// 什么时候算过期：还没有建议（上次推断失败、或当时没配规则表），或建议的 `rule_set_id`
/// 与当前装载的规则册不一致（规则表改过并重启）。
///
/// 为什么放在读取路径：规则表只在启动时装载（不热加载），而 agentd 在事实内容没变时
/// 不会重发 —— 只靠「等下次上报」会让旧建议无限期留在库里。读取是天然的重算触发点，
/// 重算幂等且代价有界（一台机器一次）。
///
/// 自愈失败不该让整个页面挂掉：保留原值、问题进日志。
async fn refresh_suggestion_for_read(
    state: &ApiState,
    fact_summary: Option<&StoredAgentFactSummary>,
    suggestion: Option<StoredPurposeSuggestion>,
) -> Option<StoredPurposeSuggestion> {
    let Some(summary) = fact_summary else {
        return suggestion;
    };
    let fallback = suggestion.clone();
    match super::agent_ops::ensure_fresh_suggestion(
        state,
        summary,
        suggestion,
        &chrono::Utc::now().to_rfc3339(),
    )
    .await
    {
        Ok(suggestion) => suggestion,
        Err(detail) => {
            eprintln!(
                "warn purpose suggestion refresh failed agent_id={}: {detail}",
                summary.agent_id
            );
            fallback
        }
    }
}

/// 分页列出已注册 Agent（管理面）。
///
/// 过滤与分页下推到存储层（SQL + 索引），不再把全表拉进内存。
pub async fn list_agents(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<AgentListQuery>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let limit = query
        .limit
        .unwrap_or(DEFAULT_AGENT_PAGE_LIMIT)
        .clamp(1, MAX_AGENT_PAGE_LIMIT);
    let offset = query.offset.unwrap_or(0);
    let store_query = AgentQuery {
        tenant_id: query.tenant_id,
        environment_id: query.environment_id,
        status: query.status,
        offset,
        limit: Some(limit),
    };

    let agents = match state.store.list_agents(&store_query).await {
        Ok(agents) => agents,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };
    let total = match state.store.count_agents(&store_query).await {
        Ok(total) => total,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };

    Json(AgentListResponse {
        agents: agents.iter().map(agent_list_entry).collect(),
        total,
        limit,
        offset,
    })
    .into_response()
}

/// 吊销指定 Agent 的指定凭据（管理面）。
///
/// 吊销当前凭据后该 Agent 立即无法通过鉴权（认证路径只看当前凭据状态）。
/// 重复吊销同一凭据返回 404：不把「已经不存在的可解除对象」当成成功。
pub async fn revoke_agent_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<RevokeCredentialRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    match state
        .store
        .revoke_agent_credential(&agent_id, &input.credential_id)
        .await
    {
        Ok(true) => Json(AgentCredentialRevocationResponse {
            agent_id,
            credential_id: input.credential_id,
            status: "revoked".to_string(),
            revoked_at: DateTime::now(),
        })
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            format!(
                "unknown or already revoked credential {} for agent {agent_id}",
                input.credential_id
            ),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to revoke agent credential: {err}"),
        )
            .into_response(),
    }
}

fn agent_list_entry(agent: &crate::infra::StoredAgentRegistration) -> AgentListEntry {
    AgentListEntry {
        agent_id: agent.agent_id.clone(),
        instance_id: agent.instance_id.clone(),
        tenant_id: agent.tenant_id.clone(),
        environment_id: agent.environment_id.clone(),
        node_id: agent.node_id.clone(),
        hostname: agent.hostname.clone(),
        version: agent.version.clone(),
        status: "online".to_string(),
        health: "healthy".to_string(),
        credential_id: agent.credential_id.clone(),
        credential_status: agent.credential_status.as_str().to_string(),
        credential_expires_at: agent.credential_expires_at.clone(),
        registered_at: agent.registered_at.clone(),
        last_seen_at: DateTime::from_rfc3339(&agent.last_seen_at).unwrap_or_else(DateTime::now),
        memory_bytes: agent.last_memory_bytes.map(|value| value as i64),
        cpu_percent: agent.last_cpu_percent,
        admin_latency_ms: agent.last_admin_latency_ms.map(|value| value as i64),
    }
}

/// 查看当前的安装包**来源地址**。
///
/// 未设置过时返回空地址（`updated_by` 为空、`updated_at` 为 null）标记「未设置」，
/// 而不是 404，也不是回填分发端点：安装端始终从网关取包，这里报的是网关自己的取包来源。
pub async fn view_agent_install_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.get_agent_install_package().await {
        Ok(Some(setting)) => Json(install_package_response(&setting)).into_response(),
        // 未设置来源地址：分发走网关内置包，因此没有「来源地址」可报。
        // 这里回空串而不回填分发端点 —— 回填会让操作者以为可以把这个地址当来源保存，
        // 而那样网关会去请求自己（且没有 bootstrap token）。
        Ok(None) => Json(AgentInstallPackageResponse {
            address_id: DEFAULT_INSTALL_PACKAGE_SETTING_ID.to_string(),
            package_url: String::new(),
            package_sha256: None,
            updated_by: String::new(),
            updated_at: None,
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent install package address: {err}"),
        )
            .into_response(),
    }
}

/// 设置 wist-agentd 安装包的**来源地址**（管理面）。
///
/// 网关会立即把该地址的制品拉到本地缓存，后续安装统一从网关自身分发；
/// 拉取失败或摘要不匹配则整次操作失败，既不落库也不覆盖已有缓存。
/// 变更只影响之后新签发的安装代码与 install.sh，已签发的安装代码不变。
pub async fn set_agent_install_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<SetAgentInstallPackageRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let (package_url, expected_sha256) =
        match validate_package_address(input.package_url.trim(), input.package_sha256.as_deref()) {
            Ok(value) => value,
            Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
        };
    // 先把制品拉到网关本地：之后所有安装都从这份缓存分发，
    // 校验摘要因此与真正服务出去的内容天然同源。
    let actual_sha256 =
        match fetch_into_cache(&state.config, package_url, expected_sha256.as_deref()).await {
            Ok(sha256) => sha256,
            Err(err) => {
                let status = match &err {
                    PackageFetchError::DigestMismatch(_) => StatusCode::BAD_REQUEST,
                    PackageFetchError::SourceUnavailable(_) => StatusCode::BAD_GATEWAY,
                };
                return (status, err.to_string()).into_response();
            }
        };
    let setting = StoredAgentInstallPackageAddress {
        address_id: DEFAULT_INSTALL_PACKAGE_SETTING_ID.to_string(),
        package_url: package_url.to_string(),
        // 摘要由网关拉取后计算/校验再落库：保证它与本地缓存内容永远一致
        // （手填摘要与本地的包对不上，正是安装端 sha256 mismatch 的成因）。
        package_sha256: Some(format!("sha256:{actual_sha256}")),
        updated_by: input
            .requested_by
            .unwrap_or_else(|| "platform-maintenance-engineer".to_string()),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    match state.store.upsert_agent_install_package(&setting).await {
        Ok(()) => Json(install_package_response(&setting)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store agent install package address: {err}"),
        )
            .into_response(),
    }
}

fn install_package_response(
    setting: &StoredAgentInstallPackageAddress,
) -> AgentInstallPackageResponse {
    AgentInstallPackageResponse {
        address_id: setting.address_id.clone(),
        package_url: setting.package_url.clone(),
        package_sha256: setting.package_sha256.clone(),
        updated_by: setting.updated_by.clone(),
        updated_at: DateTime::from_rfc3339(&setting.updated_at),
    }
}

/// 查看当前生效的发现方向策略表（管理面）。
///
/// 未配置时回 `configured: false` 而不是 404：
/// “未配置”是一种合法状态（agent 回落内建默认值），管理页要能区分它和“网关挂了”。
pub async fn view_discovery_policies(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 一次拉全表（不分页）：运维要看的是「谁还没生效」，漏掉一页就是漏掉一批机器。
    // `list_agents` 在 SQL 里已按 agent_id 排序，这里再显式排一次，不把契约挂在存储层实现细节上。
    let agents = match state.store.list_agents(&AgentQuery::default()).await {
        Ok(agents) => agents,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };
    let mut agents: Vec<AgentAppliedDiscoveryPolicy> = agents
        .into_iter()
        .map(|agent| AgentAppliedDiscoveryPolicy {
            agent_id: agent.agent_id,
            applied_policy_version: agent.last_discovery_policy_version,
            instance_id: agent.instance_id,
            // 注册时会先建一行实例记录（`last_seen_at` 初值等于 `started_at`），但那不是一次
            // 状态上报。两者相等 = 注册过但一次状态都没报过，此时回 null，而不是把注册时刻
            // 冒充成“最后一次上报”。
            last_seen_at: if agent.last_seen_at == agent.started_at {
                None
            } else {
                Some(agent.last_seen_at)
            },
        })
        .collect();
    agents.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    match state.discovery_policies.as_deref() {
        Some(set) => Json(DiscoveryPoliciesView {
            configured: true,
            policy: Some(set.clone()),
            agents,
            generated_at: DateTime::now(),
        })
        .into_response(),
        None => Json(DiscoveryPoliciesView {
            configured: false,
            policy: None,
            agents,
            generated_at: DateTime::now(),
        })
        .into_response(),
    }
}

/// 查看当前的 Agent 数据面上送地址。
///
/// 未设置过时返回「未设置」标记（`host` 空、`updated_by` 空、`updated_at` 为 null）：
/// 此时网关签发的 Agent 初始配置不带 tcp 上送段，Agent 只上报自身状态，不采集日志也不上送。
pub async fn view_agent_uplink(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.get_agent_uplink().await {
        Ok(Some(setting)) => Json(uplink_response(&setting)).into_response(),
        Ok(None) => Json(AgentUplinkResponse {
            setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
            host: String::new(),
            port: DEFAULT_AGENT_UPLINK_PORT,
            updated_by: String::new(),
            updated_at: None,
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent uplink address: {err}"),
        )
            .into_response(),
    }
}

/// 设置 Agent 数据面上送地址（管理面）。
///
/// 变更只影响之后签发的安装代码所下载到的初始配置：已安装的 Agent 要重跑安装脚本才会生效
/// （初始配置只在安装时拉一次）。
pub async fn set_agent_uplink(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<SetAgentUplinkRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let (host, port) = match validate_uplink_address(&input.host, input.port) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    let setting = StoredAgentUplinkAddress {
        setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
        host: host.to_string(),
        port,
        updated_by: input
            .requested_by
            .unwrap_or_else(|| "platform-maintenance-engineer".to_string()),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    match state.store.upsert_agent_uplink(&setting).await {
        Ok(()) => Json(uplink_response(&setting)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store agent uplink address: {err}"),
        )
            .into_response(),
    }
}

fn uplink_response(setting: &StoredAgentUplinkAddress) -> AgentUplinkResponse {
    AgentUplinkResponse {
        setting_id: setting.setting_id.clone(),
        host: setting.host.clone(),
        port: setting.port,
        updated_by: setting.updated_by.clone(),
        updated_at: DateTime::from_rfc3339(&setting.updated_at),
    }
}

/// 校验数据面上送地址。
///
/// 只接受裸主机/IP + 端口：agentd 构造连接时就是 `format!("{addr}:{port}")`，
/// 所以带 scheme、路径、端口或 IPv6 字面量（含 `:`）的写法都不能接受。
fn validate_uplink_address(host: &str, port: i64) -> Result<(&str, u16), String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("host must not be empty".to_string());
    }
    if host.len() > MAX_PACKAGE_URL_LEN {
        return Err(format!("host must be at most {MAX_PACKAGE_URL_LEN} bytes"));
    }
    if host.chars().any(char::is_control) {
        return Err("host must not contain control characters".to_string());
    }
    if host.contains("://") || host.contains('/') || host.contains(':') {
        return Err(
            "host must be a bare host or IP; put the port in the separate `port` field".to_string(),
        );
    }
    if !(1..=65535).contains(&port) {
        return Err("port must be between 1 and 65535".to_string());
    }
    let port = u16::try_from(port).map_err(|_| "port must be between 1 and 65535".to_string())?;
    Ok((host, port))
}

/// 校验安装包地址与摘要。
///
/// 安装包是 Agent 的启动来源，因此地址只接受 https URL 或本机绝对路径：
/// 不允许明文 http 分发（与 `server.public_base_url` 必须 https 的口径一致）。
fn validate_package_address<'a>(
    package_url: &'a str,
    package_sha256: Option<&str>,
) -> Result<(&'a str, Option<String>), String> {
    if package_url.is_empty() {
        return Err("package_url must not be empty".to_string());
    }
    if package_url.len() > MAX_PACKAGE_URL_LEN {
        return Err(format!(
            "package_url must be at most {MAX_PACKAGE_URL_LEN} bytes"
        ));
    }
    if package_url.chars().any(char::is_control) {
        return Err("package_url must not contain control characters".to_string());
    }
    if !package_url.starts_with("https://") && !package_url.starts_with('/') {
        return Err("package_url must be an https:// URL or an absolute path".to_string());
    }
    let digest = match package_sha256
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => Some(normalize_sha256(value)?),
        None => None,
    };
    Ok((package_url, digest))
}

fn normalize_sha256(value: &str) -> Result<String, String> {
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "package_sha256 must be 64 hex characters (optionally prefixed with \"sha256:\")"
                .to_string(),
        );
    }
    Ok(format!("sha256:{}", hex.to_ascii_lowercase()))
}

async fn agent_not_found_response(state: &ApiState, agent_id: &str) -> Option<Response> {
    match state.store.agent_exists(agent_id).await {
        Ok(true) => None,
        Ok(false) => {
            Some((StatusCode::NOT_FOUND, format!("unknown agent {agent_id}")).into_response())
        }
        Err(err) => Some(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response(),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn runtime_status(
    agent_id: &str,
    instance_id: &str,
    version: &str,
    status: &str,
    health: &str,
    last_seen_at: &str,
    memory_bytes: Option<u64>,
    cpu_percent: Option<f64>,
    admin_latency_ms: Option<u64>,
) -> AgentRuntimeStatus {
    AgentRuntimeStatus {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        version: version.to_string(),
        status: status.to_string(),
        health: health.to_string(),
        memory_bytes: memory_bytes.map(|value| value as i64),
        cpu_percent,
        admin_latency_ms: admin_latency_ms.map(|value| value as i64),
        last_seen_at: DateTime::from_rfc3339(last_seen_at).unwrap_or_else(DateTime::now),
    }
}
