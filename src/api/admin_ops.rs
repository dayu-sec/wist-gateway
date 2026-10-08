use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;
use wist_control::types::DateTime;

use crate::app::content::{MACHINE_CLASSES, platform_for_machine_class};
use crate::app::work as work_rules;
use crate::app::work::WorkRejection;
use crate::infra::{
    AgentQuery, DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID, DEFAULT_AGENT_UPLINK_PORT,
    DEFAULT_AGENT_UPLINK_SETTING_ID, StoredAgentAdvertiseUrl, StoredAgentClassification,
    StoredAgentFactSummary, StoredAgentInstallPackage, StoredAgentInstallPackageAddress,
    StoredAgentRevocation, StoredAgentUplinkAddress, StoredOneShotWork, StoredPurposeSuggestion,
    StoredWorkAck, StoredWorkResult, contains_shell_metacharacters, effective_standing,
    outstanding_one_shot,
};
use wist_contracts::work::{OneShotWork, StandingWork, WorkKind, WorkReceipt};

use super::install_package::{PackageFetchError, fetch_into_package_cache};
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
    /// 机器级「最近一次已知网卡地址」（形如 `en0 192.168.1.5/24`）；空表 = 还没报过。
    pub ip_addresses: Vec<String>,
    pub version: String,
    pub status: String,
    pub health: String,
    pub credential_id: String,
    pub credential_status: String,
    pub credential_expires_at: String,
    pub registered_at: String,
    pub last_seen_at: DateTime,
    pub memory_bytes: Option<i64>,
    /// 单核口径的进程 CPU 占比（100% = 占满一个核，可能 >100），只统计 agent 进程自身。
    pub cpu_percent: Option<f64>,
    /// agent 所在机器的逻辑核数；null = 老版本 agentd 没报（与 0 区分）。
    pub cpu_cores: Option<u32>,
    /// 整机口径的 CPU 占比（0..100），由 `cpu_percent / cpu_cores` 派生；算不出时为 null。
    pub cpu_percent_of_machine: Option<f64>,
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

/// 吊销一台 Agent 的请求体（按 `agent_id` 加入拒绝名单，见 §5.6）。
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeAgentRequest {
    /// 人工填写的吊销原因；不填就是空串。
    #[serde(default)]
    pub reason_code: String,
    /// 谁吊销的（管理面录入）；不填就是空串。
    #[serde(default)]
    pub requested_by: String,
}

/// 拒绝名单视图（管理面列表）。
#[derive(Debug, Serialize)]
pub struct AgentRevocationsView {
    /// 仍在生效（未到 GC 水位）的条目，新的在前。
    pub revocations: Vec<StoredAgentRevocation>,
    pub generated_at: DateTime,
}

/// 解除吊销的结果（管理面）。
#[derive(Debug, Serialize)]
pub struct AgentRevocationLiftedResponse {
    pub agent_id: String,
    pub status: String,
}

/// 设置安装包地址的请求体：**按平台**一次一套（多平台 agentd，缺任一整体拒绝）。
#[derive(Debug, Clone, Deserialize)]
pub struct SetAgentInstallPackageRequest {
    pub artifacts: Vec<SetAgentInstallPackageArtifact>,
    pub requested_by: Option<String>,
}

/// 请求体里的一个平台制品。
#[derive(Debug, Clone, Deserialize)]
pub struct SetAgentInstallPackageArtifact {
    /// 目标平台（target-triple），如 `aarch64-apple-darwin` / `x86_64-unknown-linux-musl`。
    pub platform: String,
    pub package_url: String,
    /// 期望摘要（sha256，可带 `sha256:` 前缀）。
    ///
    /// **必填**：包的 sha256 是内容身份，网关拿块字节核对、不符即拒；缺了就没有可校验的事实来源。
    pub package_sha256: String,
}

/// 安装包来源响应：**按平台**列出已录入的一份。
#[derive(Debug, Serialize)]
pub struct AgentInstallPackageResponse {
    pub packages: Vec<AgentInstallPackagePlatform>,
}

/// 一个平台的当前安装包来源（对应模型 `AgentInstallPackageAddress`，`address_id` = 平台）。
#[derive(Debug, Serialize)]
pub struct AgentInstallPackagePlatform {
    /// 目标平台（target-triple）。
    pub platform: String,
    pub package_url: String,
    pub package_sha256: Option<String>,
    pub updated_by: String,
    /// 未设置过时为 null。
    pub updated_at: Option<DateTime>,
}

/// 安装包录入历史里的一条（列表用）。
///
/// 模型 `Control.Agent.Enrollment.AgentInstallPackageHistoryEntry`（升级计划从这里选包）。
/// **不加 `serde(rename_all)`**：对外协议是 snake_case，前端按它解析。
#[derive(Debug, Serialize, ::jumo_derive::Jumo)]
#[jumo(
    kind = "struct",
    domain = "Control",
    module = "Control.Agent.Enrollment"
)]
pub struct AgentInstallPackageHistoryEntry {
    pub package_id: String,
    pub source: String,
    pub package_sha256: String,
    pub version: String,
    pub arch: String,
    /// 由网关派生的下载地址（可直接给 agent 用）：
    /// `<生效对外基址>/api/v1/agent/packages/<package_id>`。
    pub agent_package_url: String,
    pub created_by: String,
    pub created_at: String,
}

/// 安装包录入历史列表响应。
#[derive(Debug, Serialize)]
pub struct AgentInstallPackageHistoryResponse {
    pub packages: Vec<AgentInstallPackageHistoryEntry>,
}

/// 设置 Agent 数据面上送地址的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct SetAgentUplinkRequest {
    pub host: String,
    /// 用 `i64` 收下再校验：用 `u16` 的话越界值会被 axum 的 JSON 提取器判成 422，
    /// 而这里约定一律用 400 + 纯文本原因回给管理面。
    pub port: i64,
    /// 部署级启用开关：`true` = 本网关授权的所有 agent 都启用主机内容上送（日志 / 指标），
    /// 不必先派工。
    ///
    /// **缺省（不带这个键）= 保持已存的值**，而不是「关掉」：
    ///   * 已存值没有（从未录入过）→ `false`，所以老客户端**永远不可能顺手把全队打开**；
    ///   * 已存值是 `true` → 保持 `true`，所以老客户端改一下地址也不会**静默掉全队的上送**。
    ///
    /// 只有显式 `false` 才关。两个方向都是安全的那一侧。
    #[serde(default)]
    pub enabled: Option<bool>,
    pub requested_by: Option<String>,
}

/// 数据面上送地址响应（对应模型 `AgentUplinkAddress`）。
#[derive(Debug, Serialize)]
pub struct AgentUplinkResponse {
    pub setting_id: String,
    pub host: String,
    pub port: u16,
    /// 部署级启用开关的生效值（见 [`SetAgentUplinkRequest::enabled`]）。
    pub enabled: bool,
    pub updated_by: String,
    /// 未设置过时为 null。
    pub updated_at: Option<DateTime>,
    /// 这个 `enabled` 是不是管理面**录入**的（而不是部署派生的默认 `false`）。
    ///
    /// 为什么需要它：地址与开关共用一个响应，页面要能区分「没录入过」与「录入过一次不开」。
    /// 与 `updated_at` 同口径（它是同一行设置的更新时刻，派生值里为空）。
    pub enabled_configured: bool,
}

/// 设置网关对外地址的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct SetAgentAdvertiseUrlRequest {
    /// 对外基址，形如 `https://gateway.example.com`；允许带尾斜杠，保存时裁掉。
    pub url: String,
    pub requested_by: Option<String>,
}

/// 网关对外地址响应。
///
/// `url` 为空 = 管理面没设置过，此时网关实际用的是配置文件里的
/// `server.public_base_url`，也就是 `fallback_url`。管理面要能回答「不设置的话
/// agent 会连到哪里」，所以两个都给，而不是只回一个空值。
#[derive(Debug, Serialize)]
pub struct AgentAdvertiseUrlResponse {
    pub setting_id: String,
    /// 管理面设置值；未设置时为空串。
    pub url: String,
    /// 未设置时网关实际使用的基址（配置文件值，无尾斜杠）。
    pub fallback_url: String,
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
    let certificate_status = match state.store.get_agent_certificate_status(&agent_id).await {
        Ok(status) => status.map(|status| wist_api::status::AgentCertificateStatus {
            not_after: status.not_after,
            remaining_seconds: status.remaining_seconds,
            state: status.state,
            last_renewal: status.last_renewal,
        }),
        Err(err) => {
            // 这是 agent 自报的**可观测性**字段（§5.5），非安全关键：读不出来就降级成
            // 「未上报」并记一行，不要把整个运行态接口（它还有 revoked 等关键信息）打成 500。
            eprintln!(
                "event=AgentCertificateStatusReadFailed agent_id={agent_id} detail=\"{err}\""
            );
            None
        }
    };
    let revoked = match state.store.is_agent_revoked(&agent_id).await {
        Ok(revoked) => revoked,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent revocation: {err}"),
            )
                .into_response();
        }
    };
    Json(runtime_status(
        &agent.agent_id,
        &agent.instance_id,
        &agent.version,
        // 与列表页共用同一在线口径：不写死 "online"，否则同一台机器两处答案会相反。
        agent_status_label(&agent.last_seen_at),
        "healthy",
        &agent.node_id,
        &agent.hostname,
        &agent.ip_addresses,
        &agent.last_seen_at,
        agent.last_memory_bytes,
        agent.last_cpu_percent,
        agent.last_cpu_cores,
        agent.last_admin_latency_ms,
        agent.uplink_state,
        certificate_status,
        revoked,
    ))
    .into_response()
}

/// 删除一台**离线** Agent（连同它的实例、凭据与所有派生态数据）—— **不可恢复**。
///
/// 只允许离线：在线机器还在上报，删了它下一刻会用旧凭据重连、可能又注册回来，运维看到的
/// 「删了又回来」比不删更困惑；而且它可能正写库。离线才删得干净。
///
/// 判据与列表 / 运行态**同一处**（`overview::agent_is_online`，300s 窗口）—— 不然会出现
/// 「列表说离线、却删不掉」这种自相矛盾。
///
/// 前端要两次确认：删除不可恢复，一次点击不够。
pub async fn delete_agent(
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
    if super::overview::agent_is_online(&agent.last_seen_at, &DateTime::now()) {
        return (
            StatusCode::CONFLICT,
            format!("agent {agent_id} is online; only offline agents can be deleted"),
        )
            .into_response();
    }
    match state.store.delete_agent(&agent_id).await {
        Ok(true) => Json(AgentDeletionResult {
            agent_id,
            deleted_at: DateTime::now(),
        })
        .into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, format!("unknown agent {agent_id}")).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to delete agent: {err}"),
        )
            .into_response(),
    }
}

/// 删除一台 Agent 的结果回执（模型 `Control.Agent.Identity.AgentDeletionResult`）。
///
/// 为什么回一个体而不回 204：模型里每个 bind entry 都要一个具名 `status` 类型，
/// 没有“无体”这个概念；顺带前端也能拿 `agent_id` 做提示。
/// **不加 `serde(rename_all)`**：对外协议是 snake_case，前端按它解析。
#[derive(Debug, Serialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Identity")]
pub struct AgentDeletionResult {
    pub agent_id: String,
    pub deleted_at: DateTime,
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

/// 把授权/撤回被拒的原因映射成 HTTP 状态。
///
/// 三档分开是有意的：
///   * `BadRequest` —— 请求本身不成立（写错了面名、把 macOS 专有面派给 Linux 机器）；
///   * `Conflict` —— 请求成立但与当前状态冲突（采集未就绪、版本回退、不可中断却要暂停）：
///     它是「现在不行」，人该做的是等采集就绪或换个动作，而不是改请求；
///   * `NotFound` —— 目标不存在。
fn rejection_response(rejection: WorkRejection) -> Response {
    let status = match &rejection {
        WorkRejection::NotFound(_) => StatusCode::NOT_FOUND,
        WorkRejection::BadRequest(_) => StatusCode::BAD_REQUEST,
        WorkRejection::Conflict(_) => StatusCode::CONFLICT,
    };
    (status, rejection.message().to_string()).into_response()
}

#[derive(Debug, Deserialize)]
pub struct GrantWorkRequest {
    /// `Standing` | `OneShot`（与模型 `WorkKind` 同形）。
    pub work_kind: String,
    /// 常驻工作按**面**授权（`Standing` 时必填）。
    #[serde(default)]
    pub family: Option<String>,
    /// 一次性工作按**动作**授权（`OneShot` 时必填）。
    #[serde(default)]
    pub action: Option<String>,
    /// 常驻：留空 = 由网关按事实从采集目录展开；写了 = 必须是该面上的目录单元。
    #[serde(default)]
    pub spec: String,
    #[serde(default)]
    pub plan_version: Option<i64>,
    #[serde(default)]
    pub scheduled_at: Option<String>,
    #[serde(default)]
    pub deadline_at: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<i64>,
}

/// 授权或更新某 Agent 的工作（`AdminGrantWork`）。
///
/// `work_kind` 决定哪些字段必填 —— 这层校验必须在实现里，且要报得清楚：
/// 「派一份常驻工作」与「派一件升级」需要的东西不一样，共用一个模糊的接口只会
/// 让人对着 400 猜自己漏了什么。
pub async fn grant_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<GrantWorkRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    match input.work_kind.trim() {
        "Standing" => grant_standing_work(&state, &agent_id, &input).await,
        "OneShot" => grant_one_shot_work(&state, &agent_id, &input).await,
        other => (
            StatusCode::BAD_REQUEST,
            format!("unknown work_kind {other:?} (Standing | OneShot)"),
        )
            .into_response(),
    }
}

/// 派一份常驻工作：面就绪度闸门 → 用途判定 → 按事实展开或校验 spec → 落库。
///
/// 顺序不是随意排的：先要判定（否则不知道是哪类机器、取不到模板），再要采集就绪
/// （否则展开出来的单元落不了数据面），最后才谈内容。
async fn grant_standing_work(
    state: &ApiState,
    agent_id: &str,
    input: &GrantWorkRequest,
) -> Response {
    let knowledge = state.knowledge();
    let Some(content) = knowledge.content.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "collection content is not loaded: 配置 [content] 三件套后重启网关",
        )
            .into_response();
    };
    let family = match input.family.as_deref().map(str::trim) {
        Some(family) if !family.is_empty() => family,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "family is required for work_kind = Standing",
            )
                .into_response();
        }
    };
    let classification = match state.store.get_agent_classification(agent_id).await {
        Ok(classification) => classification,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent classification: {err}"),
            )
                .into_response();
        }
    };
    let Some(classification) = classification else {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "cannot grant work to {agent_id}: 先归档用途判定（AgentClassification）—— 它决定取哪份模板"
            ),
        )
            .into_response();
    };
    let Some(platform) = platform_for_machine_class(&classification.machine_class) else {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "machine class {:?} maps to no platform",
                classification.machine_class
            ),
        )
            .into_response();
    };
    if let Err(rejection) = work_rules::check_family_grantable(content, family, platform) {
        return rejection_response(rejection);
    }
    let existing = match state.store.list_standing_work(agent_id).await {
        Ok(works) => works.into_iter().find(|work| work.family == family),
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load standing work: {err}"),
            )
                .into_response();
        }
    };
    let requested_spec = input.spec.trim();
    let spec_result = if requested_spec.is_empty() {
        let facts = match state.store.get_agent_fact_summary(agent_id).await {
            Ok(facts) => facts,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load agent fact summary: {err}"),
                )
                    .into_response();
            }
        };
        let Some(facts) = facts else {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "cannot derive the work spec for {agent_id}: 还没有事实摘要（无事实就无从裁剪）"
                ),
            )
                .into_response();
        };
        work_rules::derive_spec(
            content,
            &classification.machine_class,
            platform,
            family,
            &facts,
        )
    } else {
        work_rules::validate_spec(content, platform, family, requested_spec)
    };
    let (spec, catalog_version) = match spec_result {
        Ok(pair) => pair,
        Err(rejection) => return rejection_response(rejection),
    };
    let plan_version = match work_rules::next_plan_version(
        existing.as_ref().map(|work| work.plan_version),
        input.plan_version,
    ) {
        Ok(version) => version,
        Err(rejection) => return rejection_response(rejection),
    };
    let now = chrono::Utc::now().to_rfc3339();
    let work = StandingWork {
        work_id: existing
            .as_ref()
            .map(|work| work.work_id.clone())
            .unwrap_or_else(|| standing_work_id(agent_id, family)),
        agent_id: agent_id.to_string(),
        family: family.to_string(),
        spec,
        catalog_version,
        proposal_id: None,
        plan_version,
        effective_from: now.clone(),
        status: "active".to_string(),
        updated_by: "admin".to_string(),
        updated_at: now.clone(),
    };
    if let Err(err) = state.store.save_standing_work(&work).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store standing work: {err}"),
        )
            .into_response();
    }
    finish_work_mutation(
        state,
        agent_id,
        WorkReceipt {
            work_id: work.work_id.clone(),
            agent_id: agent_id.to_string(),
            work_kind: WorkKind::Standing,
            status: "accepted".to_string(),
            plan_version: work.plan_version,
            created_at: now,
        },
    )
    .await
}

/// 派一件一次性工作：动作 + 期限 + 预算，落库为 `dispatched` 等 Agent 确认。
async fn grant_one_shot_work(
    state: &ApiState,
    agent_id: &str,
    input: &GrantWorkRequest,
) -> Response {
    let action = match input.action.as_deref().map(str::trim) {
        Some(action) if !action.is_empty() => action,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "action is required for work_kind = OneShot",
            )
                .into_response();
        }
    };
    if input.spec.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "spec is required for work_kind = OneShot",
        )
            .into_response();
    }
    // 绝对截止是必填：没有截止的「一次性工作」与常驻工作无从分辨，
    // 而两者的暂停、恢复、结算语义完全不同。
    let Some(deadline_at) = input
        .deadline_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            "deadline_at is required for work_kind = OneShot",
        )
            .into_response();
    };
    if chrono::DateTime::parse_from_rfc3339(deadline_at).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            format!("deadline_at must be RFC3339, got {deadline_at:?}"),
        )
            .into_response();
    }
    let timeout_seconds = match input.timeout_seconds {
        Some(value) if value > 0 => value,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "timeout_seconds must be a positive number of seconds",
            )
                .into_response();
        }
    };
    let now = chrono::Utc::now().to_rfc3339();
    let scheduled_at = input
        .scheduled_at
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&now)
        .to_string();
    if chrono::DateTime::parse_from_rfc3339(&scheduled_at).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            format!("scheduled_at must be RFC3339, got {scheduled_at:?}"),
        )
            .into_response();
    }
    // `interruptible` 不在请求体里（模型消息也没这个字段）：一件活能不能中途暂停是
    // **动作目录的属性**，不该由每次派发的人各自声明 —— 否则同一种动作会因为两次派发
    // 的口径不同而行为不一。动作目录就位前，一律按不可中断收（宁可拒绝暂停，
    // 也不给人一个「以为暂停了、其实半个进程挂着」的假象）。
    let work = OneShotWork {
        work_id: one_shot_work_id(agent_id, action, &now),
        agent_id: agent_id.to_string(),
        action: action.to_string(),
        spec: input.spec.trim().to_string(),
        scheduled_at,
        deadline_at: deadline_at.to_string(),
        timeout_seconds,
        interruptible: false,
        status: "dispatched".to_string(),
        paused_at: None,
        paused_total_seconds: 0,
        current_step: None,
        completed_steps: Vec::new(),
        attempt: 0,
        issued_by: "admin".to_string(),
        issued_at: now.clone(),
    };
    let plan_version = 1;
    if let Err(err) = state
        .store
        .save_one_shot_work(&StoredOneShotWork {
            work: work.clone(),
            pre_pause_status: None,
        })
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store one-shot work: {err}"),
        )
            .into_response();
    }
    finish_work_mutation(
        state,
        agent_id,
        WorkReceipt {
            work_id: work.work_id.clone(),
            agent_id: agent_id.to_string(),
            work_kind: WorkKind::OneShot,
            status: "accepted".to_string(),
            plan_version,
            created_at: now,
        },
    )
    .await
}

/// 撤回一份工作：常驻 → `revoked`（撤销授权），一次性 → `canceled`（取消未了结的活）。
///
/// 为什么两种工作共用一条路由：对运维而言「別再做了」是一个动作；分两条路只是因为
/// 落地状态不同。参数里带 `reason_code` 是为了留痕 —— 「谁撤的」好查，「为什么撤」
/// 只能靠当时记的那一句。
#[derive(Debug, Deserialize)]
pub struct RevokeWorkRequest {
    #[serde(default)]
    pub reason_code: String,
}

pub async fn revoke_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((agent_id, work_id)): Path<(String, String)>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<RevokeWorkRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let now = chrono::Utc::now().to_rfc3339();
    let reason = input.reason_code.trim();
    match load_work(&state, &agent_id, &work_id).await {
        Err(response) => *response,
        Ok(LoadedWork::Standing(work)) => {
            if work.status == "revoked" {
                return (
                    StatusCode::CONFLICT,
                    format!("standing work {work_id} is already revoked"),
                )
                    .into_response();
            }
            let revoked = StandingWork {
                status: "revoked".to_string(),
                updated_at: now.clone(),
                ..work
            };
            if let Err(err) = state.store.save_standing_work(&revoked).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store standing work: {err}"),
                )
                    .into_response();
            }
            // `reason_code` 收下但暂不落库：审计事件（WorkRevoked）还没建。
            // 宁可在回执里如实回报，也不凭一个没人读的列假装留了痕。
            let _ = reason;
            finish_work_mutation(
                &state,
                &agent_id,
                WorkReceipt {
                    work_id: revoked.work_id.clone(),
                    agent_id: agent_id.clone(),
                    work_kind: WorkKind::Standing,
                    status: "revoked".to_string(),
                    plan_version: revoked.plan_version,
                    created_at: now,
                },
            )
            .await
        }
        Ok(LoadedWork::OneShot(stored)) => {
            if !stored.work.is_outstanding() {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "one-shot work {work_id} is already {} (terminal)",
                        stored.work.status
                    ),
                )
                    .into_response();
            }
            let mut canceled = stored;
            canceled.work.status = "canceled".to_string();
            canceled.work.paused_at = None;
            canceled.pre_pause_status = None;
            if let Err(err) = state.store.save_one_shot_work(&canceled).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store one-shot work: {err}"),
                )
                    .into_response();
            }
            finish_work_mutation(
                &state,
                &agent_id,
                WorkReceipt {
                    work_id: canceled.work.work_id.clone(),
                    agent_id: agent_id.clone(),
                    work_kind: WorkKind::OneShot,
                    status: "revoked".to_string(),
                    plan_version: 1,
                    created_at: now,
                },
            )
            .await
        }
    }
}

pub async fn pause_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((agent_id, work_id)): Path<(String, String)>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let now = chrono::Utc::now().to_rfc3339();
    match load_work(&state, &agent_id, &work_id).await {
        Err(response) => *response,
        Ok(LoadedWork::Standing(work)) => {
            if work.status != "active" {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "standing work {work_id} is {}; only active work can be paused",
                        work.status
                    ),
                )
                    .into_response();
            }
            let paused = StandingWork {
                status: "paused".to_string(),
                updated_by: "admin".to_string(),
                updated_at: now.clone(),
                ..work
            };
            if let Err(err) = state.store.save_standing_work(&paused).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store standing work: {err}"),
                )
                    .into_response();
            }
            finish_work_mutation(
                &state,
                &agent_id,
                WorkReceipt {
                    work_id: paused.work_id.clone(),
                    agent_id: agent_id.clone(),
                    work_kind: WorkKind::Standing,
                    status: "paused".to_string(),
                    plan_version: paused.plan_version,
                    created_at: now,
                },
            )
            .await
        }
        Ok(LoadedWork::OneShot(stored)) => {
            let paused = match work_rules::pause_one_shot(&stored, &now) {
                Ok(paused) => paused,
                Err(rejection) => return rejection_response(rejection),
            };
            if let Err(err) = state.store.save_one_shot_work(&paused).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store one-shot work: {err}"),
                )
                    .into_response();
            }
            finish_work_mutation(
                &state,
                &agent_id,
                WorkReceipt {
                    work_id: paused.work.work_id.clone(),
                    agent_id: agent_id.clone(),
                    work_kind: WorkKind::OneShot,
                    status: "paused".to_string(),
                    plan_version: 1,
                    created_at: now,
                },
            )
            .await
        }
    }
}

pub async fn resume_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((agent_id, work_id)): Path<(String, String)>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let now = chrono::Utc::now();
    let now_text = now.to_rfc3339();
    match load_work(&state, &agent_id, &work_id).await {
        Err(response) => *response,
        Ok(LoadedWork::Standing(work)) => {
            if work.status != "paused" {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "standing work {work_id} is {}; only paused work can be resumed",
                        work.status
                    ),
                )
                    .into_response();
            }
            // 恢复**不重新审定**：仍用暂停前的同一版本（`plan_version` 不动）。
            let resumed = StandingWork {
                status: "active".to_string(),
                updated_by: "admin".to_string(),
                updated_at: now_text.clone(),
                ..work
            };
            if let Err(err) = state.store.save_standing_work(&resumed).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store standing work: {err}"),
                )
                    .into_response();
            }
            finish_work_mutation(
                &state,
                &agent_id,
                WorkReceipt {
                    work_id: resumed.work_id.clone(),
                    agent_id: agent_id.clone(),
                    work_kind: WorkKind::Standing,
                    status: "resumed".to_string(),
                    plan_version: resumed.plan_version,
                    created_at: now_text,
                },
            )
            .await
        }
        Ok(LoadedWork::OneShot(stored)) => {
            let resumed = match work_rules::resume_one_shot(&stored, now.timestamp_millis()) {
                Ok(resumed) => resumed,
                Err(rejection) => return rejection_response(rejection),
            };
            if let Err(err) = state.store.save_one_shot_work(&resumed).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store one-shot work: {err}"),
                )
                    .into_response();
            }
            let receipt = WorkReceipt {
                work_id: resumed.work.work_id.clone(),
                agent_id: agent_id.clone(),
                work_kind: WorkKind::OneShot,
                status: "resumed".to_string(),
                plan_version: 1,
                created_at: now_text,
            };
            finish_work_mutation(&state, &agent_id, receipt).await
        }
    }
}

enum LoadedWork {
    Standing(StandingWork),
    OneShot(StoredOneShotWork),
}

/// 按 `work_id` 找一份工作（两种都找）。找不到或不属于该 agent 都回 404。
///
/// 为什么要检查归属：路由里既有 agent 又有 work，只按 work_id 找就会让
/// 「用 A 机器的路径去改 B 机器的工作」这种错操作合法化。
///
/// 错误类型用 `Box<Response>`：`Response` 很大，直接当 `Err` 会让整条
/// `Result` 变胖（clippy 的 `result_large_err`），而这个返回值每次都在热路径上。
async fn load_work(
    state: &ApiState,
    agent_id: &str,
    work_id: &str,
) -> Result<LoadedWork, Box<Response>> {
    let standing = state
        .store
        .get_standing_work(work_id)
        .await
        .map_err(|err| {
            Box::new(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load standing work: {err}"),
                )
                    .into_response(),
            )
        })?;
    if let Some(work) = standing {
        if work.agent_id != agent_id {
            return Err(Box::new(not_found_work(agent_id, work_id)));
        }
        return Ok(LoadedWork::Standing(work));
    }
    let one_shot = state
        .store
        .get_one_shot_work(work_id)
        .await
        .map_err(|err| {
            Box::new(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load one-shot work: {err}"),
                )
                    .into_response(),
            )
        })?;
    match one_shot {
        Some(work) if work.work.agent_id == agent_id => Ok(LoadedWork::OneShot(work)),
        _ => Err(Box::new(not_found_work(agent_id, work_id))),
    }
}

fn not_found_work(agent_id: &str, work_id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        format!("unknown work {work_id} on agent {agent_id}"),
    )
        .into_response()
}

/// 改完工作后统一收尾：推进授权序号并把回执交给调用方。
///
/// 序号在这里推（而不是各 handler 自己推）是为了不漏：漏推一次的后果是
/// Agent 认为快照没变，于是期望与实际安静地不一致。
async fn finish_work_mutation(state: &ApiState, agent_id: &str, receipt: WorkReceipt) -> Response {
    if let Err(err) = state
        .store
        .next_work_sequence(agent_id, &receipt.created_at)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to bump work sequence: {err}"),
        )
            .into_response();
    }
    Json(receipt).into_response()
}

/// 常驻工作的 id 是**确定性**的：一台机器的一个面就一份工作。
///
/// 用确定性 id 而不是随机 id，是为了让「改一份已有的授权」天然幂等 ——
/// 否则每次改动都会多出一份「同一面的历史版本」，而它们都还停在 active 上。
fn standing_work_id(agent_id: &str, family: &str) -> String {
    format!("work-{agent_id}-{family}")
}

/// 一次性工作的 id 带时间戳与内容摘要：同一动作可以派多次，各自独立结算。
fn one_shot_work_id(agent_id: &str, action: &str, issued_at: &str) -> String {
    let digest = crate::infra::sha256_hex(&format!("{agent_id}|{action}|{issued_at}"));
    format!("work-{agent_id}-{action}-{}", &digest[..12])
}

#[derive(Debug, Serialize)]
struct StandingWorkView {
    #[serde(flatten)]
    work: StandingWork,
    /// Agent 最近一次确认；从未确认过是 `None`（那就是漂移）。
    ack: Option<StoredWorkAck>,
}

#[derive(Debug, Serialize)]
struct OneShotWorkView {
    #[serde(flatten)]
    work: OneShotWork,
    ack: Option<StoredWorkAck>,
    /// agentd 上报的执行结果（进度/终态）；从未上报过就是 `None`。
    ///
    /// 与 `ack` 并列而不合并：两个都是「最新一次」，但回答的是不同的问题 ——
    /// 一个是「我收到了」，一个是「我做得怎么样了」。
    result: Option<StoredWorkResult>,
}

#[derive(Debug, Serialize)]
struct AgentWorkView {
    agent_id: String,
    /// 授权序号：与 Agent 手上那份比对即知是否变化。
    sequence: i64,
    /// **只看当前生效的**（active/paused）。历史版本靠下面两个列表看。
    standing: Vec<StandingWorkView>,
    one_shot: Vec<OneShotWorkView>,
    /// 已撤回/被取代的常驻工作（审计用，不下发）。
    retired_standing: Vec<StandingWork>,
    /// 已了结的一次性工作（审计用，不下发）。
    ///
    /// 仍用 `OneShotWorkView`（而非裸 `OneShotWork`）是为了带上 `result`：
    /// 「失败原因 / 回滚到哪一版」正是这活在**了结之后**才最需要看的东西，
    /// 只留在未了结清单里等于做完就看不见了。
    settled_one_shot: Vec<OneShotWorkView>,
    /// agent 上报的**本机工作视图**（它实际在采哪些文件、一次性工作做到哪一步）。
    /// `None` = 这台 agent 还没报过（旧版本 agentd 不发这个字段）。
    ///
    /// 与 `standing`（网关**授权**了什么）并列而不合并：一个是「我发了什么」，
    /// 一个是「它真的在干什么」—— 本机手工加的输入、暂停、来源接不接得了，只有后者能回答。
    local: Option<wist_contracts::local_work::AgentLocalWork>,
    generated_at: String,
}

/// 查看某 Agent 的工作（**手加端点**：模型里只有授权/撤回，没有查看）。
///
/// 为什么必须有：授权是个「声明」，运维看不到声明就等于没有控制。页面上的
/// 「暂停一下」「撤掉」都得先看到手上有什么；`ack` 一并给出，是为了让漂移
/// （期望版本 vs 确认版本）当场可见，不用去别处对时间戳。
pub async fn view_agent_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let standing = match state.store.list_standing_work(&agent_id).await {
        Ok(works) => works,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load standing work: {err}"),
            )
                .into_response();
        }
    };
    let one_shot = match state.store.list_one_shot_work(&agent_id).await {
        Ok(works) => works,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load one-shot work: {err}"),
            )
                .into_response();
        }
    };
    let mut standing_views = Vec::new();
    for work in effective_standing(&standing) {
        let ack = match load_ack(&state, &work.work_id).await {
            Ok(ack) => ack,
            Err(response) => return *response,
        };
        standing_views.push(StandingWorkView { work, ack });
    }
    let mut one_shot_views = Vec::new();
    for work in outstanding_one_shot(&one_shot) {
        let ack = match load_ack(&state, &work.work_id).await {
            Ok(ack) => ack,
            Err(response) => return *response,
        };
        let result = match load_work_result(&state, &work.work_id).await {
            Ok(result) => result,
            Err(response) => return *response,
        };
        one_shot_views.push(OneShotWorkView { work, ack, result });
    }
    let retired_standing = standing
        .into_iter()
        .filter(|work| !matches!(work.status.as_str(), "active" | "paused"))
        .collect();
    let mut settled_one_shot = Vec::new();
    for work in one_shot
        .into_iter()
        .filter(|work| !work.work.is_outstanding())
    {
        let ack = match load_ack(&state, &work.work.work_id).await {
            Ok(ack) => ack,
            Err(response) => return *response,
        };
        let result = match load_work_result(&state, &work.work.work_id).await {
            Ok(result) => result,
            Err(response) => return *response,
        };
        settled_one_shot.push(OneShotWorkView {
            work: work.work,
            ack,
            result,
        });
    }
    let sequence = match state.store.work_sequence(&agent_id).await {
        Ok(sequence) => sequence,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load work sequence: {err}"),
            )
                .into_response();
        }
    };
    // 本机工作视图：agent 上报的「我真的在干什么」。读不到就是没报过（`None`），
    // 但**读失败必须报错** —— 拿它冒充「没报过」会让页面静默显示空。
    let local = match state.store.get_agent(&agent_id).await {
        Ok(agent) => agent.and_then(|agent| agent.local_work),
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent store: {err}"),
            )
                .into_response();
        }
    };
    Json(AgentWorkView {
        agent_id,
        sequence,
        standing: standing_views,
        one_shot: one_shot_views,
        retired_standing,
        settled_one_shot,
        local,
        generated_at: chrono::Utc::now().to_rfc3339(),
    })
    .into_response()
}

async fn load_ack(state: &ApiState, work_id: &str) -> Result<Option<StoredWorkAck>, Box<Response>> {
    state.store.get_work_ack(work_id).await.map_err(|err| {
        Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load work ack: {err}"),
            )
                .into_response(),
        )
    })
}

/// 读某件一次性工作的执行结果；读不动就如实报错，**不降级成 `None`** ——
/// `None` 的语义是「从没报过」，拿它冒充读失败会把「页面看不到结果」变成静默。
async fn load_work_result(
    state: &ApiState,
    work_id: &str,
) -> Result<Option<StoredWorkResult>, Box<Response>> {
    state.store.get_work_result(work_id).await.map_err(|err| {
        Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load work result: {err}"),
            )
                .into_response(),
        )
    })
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
/// **注意（mTLS 收口后）**：agent 的凭据只是**客户端证书**，而认证只看证书，不再查凭据行的
/// 状态 —— 所以「吊销一份凭据」**不再能切断**这个 agent（它拿同一张证书、或自续一张新证书
/// 都还能进来）。想要真正切断，用拒绝名单（`revoke_agent`，按 `agent_id`，且可解除）。
/// 本端点保留为**记录/审计**用途（把某一版凭据标成已吊销，管理视图可见），不当作安全闸门。
///
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

/// 把一个 `agent_id` 加入**拒绝名单**（吊销，§5.6）。
///
/// 与 `revoke_agent_credential` 的区别：那个吊销的是**一份凭据**，agent 换个凭据 / 拿证书
/// 自续就能回来；这个拒的是 **agent_id 本身** —— 攻击者续签、重签都还是同一个 `agent_id`，
/// 所以是真正「立即生效且跳续签持续」的切断点。
///
/// 条目不是永久的：`retain_until` = 该 agent 当前证书的自然过期时间（拿不到时回落配置的
/// 客户端证书有效期 `agent.client_cert_ttl_seconds`，即证书的上限寿命），到点由 GC 清掉 ——
/// 那时它只能带 token 重装。要提前恢复就调解除接口。
pub async fn revoke_agent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<RevokeAgentRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 一步拿 agent：既校验存在（否则 404），又要它的当前证书到期时间做 GC 水位。
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
    let now = chrono::Utc::now();
    let entry = StoredAgentRevocation {
        entry_id: format!("denylist-{agent_id}"),
        agent_id: agent_id.clone(),
        reason_code: input.reason_code.trim().to_string(),
        denied_by: input.requested_by.trim().to_string(),
        denied_at: now.to_rfc3339(),
        retain_until: certificate_retention_until(
            &agent.credential_expires_at,
            state.config.credential_ttl_seconds,
            state.config.client_cert_ttl_seconds,
            now,
        )
        .to_rfc3339(),
    };
    if let Err(err) = state.store.revoke_agent(&entry).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to revoke agent: {err}"),
        )
            .into_response();
    }
    eprintln!(
        "audit agent_revoked agent_id={} retain_until={} reason_code={}",
        entry.agent_id, entry.retain_until, entry.reason_code
    );
    Json(entry).into_response()
}

/// 从拒绝名单移除一个 `agent_id`（解除吊销）；不在名单里返回 404。
pub async fn lift_agent_revocation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.lift_agent_revocation(&agent_id).await {
        Ok(true) => {
            eprintln!("audit agent_revocation_lifted agent_id={agent_id}");
            Json(AgentRevocationLiftedResponse {
                agent_id,
                status: "lifted".to_string(),
            })
            .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            format!("agent {agent_id} is not in the revocation list"),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to lift agent revocation: {err}"),
        )
            .into_response(),
    }
}

/// 列出拒绝名单（管理面）。条目很多时也只给「仍在生效」的那批（见 `list_agent_revocations`）。
pub async fn list_agent_revocations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_agent_revocations().await {
        Ok(revocations) => Json(AgentRevocationsView {
            revocations,
            generated_at: DateTime::now(),
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to list agent revocations: {err}"),
        )
            .into_response(),
    }
}

/// 拒绝名单条目的 GC 水位：留到**被吊销的 agent 手上所有凭据都失效**之后（§5.6）。
///
/// 为什么不能只看一个时间源：agent 手上可能**同时**有 bearer 凭据（到期 = 库里的
/// `credential_expires_at`，即 bearer TTL）与客户端证书（寿命上限 = `client_cert_ttl_seconds`，
/// 两者可独立配置）。只按 bearer 的到期算，会在证书还没过期时就把条目清掉 —— 被吊销的
/// agent 于是重新获得访问权，正是 §5.6 要防的。所以取两者**较晚者**：
///   * 库里那条 bearer 凭据的实际到期（可解析且在将来时用实际值，否则用 TTL 兜底）；
///   * 「现在 + 客户端证书有效期」—— 只要证书有效期没被**历史性下调**（当前配置小于当初
///     签发时的值，极少见），任何在世证书的到期都不会晚于它。
fn certificate_retention_until(
    credential_expires_at: &str,
    credential_ttl_seconds: i64,
    client_cert_ttl_seconds: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let bearer_until = chrono::DateTime::parse_from_rfc3339(credential_expires_at)
        .ok()
        .map(|until| until.with_timezone(&chrono::Utc))
        .filter(|until| *until > now)
        .unwrap_or_else(|| now + chrono::Duration::seconds(credential_ttl_seconds));
    let certificate_until = now + chrono::Duration::seconds(client_cert_ttl_seconds);
    bearer_until.max(certificate_until)
}

/// 在线口径（**列表与单台运行态共用**）：从 `last_seen_at` 现算 `"online"` / `"offline"`。
///
/// 派生只此一处。曾经两处各写一遍就漂过：列表按 `last_seen_at` 现算、单台运行态接口把
/// `"online"` 写死 —— 同一台几天没上报的机器，列表说离线、点进详情说在线，运维会误判
/// （据此给一台已经死掉的机器派活，那件工作会一直挂到过期）。
fn agent_status_label(last_seen_at: &str) -> &'static str {
    if super::overview::agent_is_online(last_seen_at, &DateTime::now()) {
        "online"
    } else {
        "offline"
    }
}

fn agent_list_entry(agent: &crate::infra::StoredAgentRegistration) -> AgentListEntry {
    // `status` 从 `last_seen_at` **现算**（不写死 "online"）：机队索引页（升级计划）要据此把
    // **离线**机器排除掉 —— 一台几天没上报的机器还报 "online"，页面就会把升级派给它，
    // 然后那件工作一直挂着到过期。与单台运行态共用同一判据（`agent_status_label`）。
    AgentListEntry {
        agent_id: agent.agent_id.clone(),
        instance_id: agent.instance_id.clone(),
        tenant_id: agent.tenant_id.clone(),
        environment_id: agent.environment_id.clone(),
        node_id: agent.node_id.clone(),
        hostname: agent.hostname.clone(),
        ip_addresses: agent.ip_addresses.clone(),
        version: agent.version.clone(),
        status: agent_status_label(&agent.last_seen_at).to_string(),
        health: "healthy".to_string(),
        credential_id: agent.credential_id.clone(),
        credential_status: agent.credential_status.as_str().to_string(),
        credential_expires_at: agent.credential_expires_at.clone(),
        registered_at: agent.registered_at.clone(),
        last_seen_at: DateTime::from_rfc3339(&agent.last_seen_at).unwrap_or_else(DateTime::now),
        memory_bytes: agent.last_memory_bytes.map(|value| value as i64),
        cpu_percent: agent.last_cpu_percent,
        cpu_cores: agent.last_cpu_cores,
        cpu_percent_of_machine: cpu_percent_of_machine(
            agent.last_cpu_percent,
            agent.last_cpu_cores,
        ),
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
    match state.store.list_agent_install_package_addresses().await {
        Ok(settings) => Json(install_package_response(&settings)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent install package address: {err}"),
        )
            .into_response(),
    }
}

/// 设置 wist-agentd 安装包的**来源地址**（管理面，**按平台**）。
///
/// 网关会立即把每个平台的制品拉到本地缓存，后续安装从网关自身分发；
/// 任一平台的拉取/校验失败则整次操作失败，既不落库也不覆盖已有缓存。
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
    if input.artifacts.is_empty() {
        return (StatusCode::BAD_REQUEST, "artifacts must not be empty").into_response();
    }
    // 第一阶段：平台去重 + 逐项校验来源地址；任一不合格整体拒绝（不写任何东西）。
    let mut seen = std::collections::BTreeSet::new();
    let mut prepared: Vec<(String, String, String)> = Vec::with_capacity(input.artifacts.len());
    for artifact in &input.artifacts {
        let platform = artifact.platform.trim();
        if platform.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                "artifact.platform must not be empty",
            )
                .into_response();
        }
        if !seen.insert(platform.to_string()) {
            return (
                StatusCode::BAD_REQUEST,
                format!("duplicate platform `{platform}`"),
            )
                .into_response();
        }
        let (package_url, expected_sha256) =
            match validate_package_address(artifact.package_url.trim(), &artifact.package_sha256) {
                Ok(value) => value,
                Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
            };
        prepared.push((
            platform.to_string(),
            package_url.to_string(),
            expected_sha256,
        ));
    }
    // 第二阶段：全部拉到网关本地（拉取/校验失败整次不生效，不覆盖已有缓存）。
    // 同时核「声明的平台」与「包内读出的 triple」：不符即拒，免得把错平台的包挂到某槽。
    let mut fetched = Vec::with_capacity(prepared.len());
    for (platform, package_url, expected_sha256) in &prepared {
        let cached = match fetch_into_package_cache(
            &state.config,
            platform,
            package_url,
            Some(expected_sha256.as_str()),
        )
        .await
        {
            Ok(cached) => cached,
            Err(err) => {
                let status = match &err {
                    PackageFetchError::DigestMismatch(_) => StatusCode::BAD_REQUEST,
                    // 超限归「来源侧的问题」这一档（与「拿不到」同一回执，不改既有状态码）。
                    PackageFetchError::SourceUnavailable(_) | PackageFetchError::TooLarge(_) => {
                        StatusCode::BAD_GATEWAY
                    }
                };
                return (status, err.to_string()).into_response();
            }
        };
        if !cached.arch.is_empty() && cached.arch != *platform {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "artifact platform `{platform}` does not match the package triple `{}`",
                    cached.arch
                ),
            )
                .into_response();
        }
        fetched.push((platform.clone(), package_url.clone(), cached));
    }
    let requested_by = input
        .requested_by
        .unwrap_or_else(|| "platform-maintenance-engineer".to_string());
    let recorded_at = chrono::Utc::now().to_rfc3339();
    // 第三阶段：落库（每平台一份设置 + 一条内容寻址历史）。
    for (platform, package_url, cached) in fetched {
        let package_sha256 = format!("sha256:{}", cached.sha256);
        let setting = StoredAgentInstallPackageAddress {
            address_id: platform.clone(),
            package_url: package_url.clone(),
            // 摘要由网关拉取后计算/校验再落库：保证它与本地缓存内容永远一致
            // （手填摘要与本地的包对不上，正是安装端 sha256 mismatch 的成因）。
            package_sha256: Some(package_sha256.clone()),
            updated_by: requested_by.clone(),
            updated_at: recorded_at.clone(),
        };
        if let Err(err) = state.store.upsert_agent_install_package(&setting).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store agent install package address: {err}"),
            )
                .into_response();
        }
        // 追加录入历史：内容寻址（package_id）幂等，同一个包重复录入覆盖同一行。
        let history = StoredAgentInstallPackage {
            package_id: cached.package_id.clone(),
            source: package_url,
            package_sha256,
            version: cached.version.clone(),
            arch: cached.arch.clone(),
            cached_path: cached.cached_path.to_string_lossy().to_string(),
            created_by: requested_by.clone(),
            created_at: recorded_at.clone(),
        };
        if let Err(err) = state
            .store
            .upsert_agent_install_package_by_id(&history)
            .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store agent install package history: {err}"),
            )
                .into_response();
        }
    }
    // 回读一遍给回执（已按平台列出）。
    match state.store.list_agent_install_package_addresses().await {
        Ok(settings) => Json(install_package_response(&settings)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent install package address: {err}"),
        )
            .into_response(),
    }
}

/// 列出 wist-agentd 安装包的**录入历史**（管理面）。
///
/// 按录入时间倒序返回；每条带内容寻址 id（可用于 `GET /api/v1/agent/packages/{package_id}`
/// 按条目取包，备份升级用）。`source` 只是留痕，取包走网关自己的副本。
pub async fn list_agent_install_packages(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_agent_install_packages().await {
        Ok(entries) => {
            // 基址只取一次（`effective_advertise_base` 会读库设置），循环里复用。
            let base = super::install::effective_advertise_base(&state.config, &state.store).await;
            let packages = entries
                .into_iter()
                .map(|entry| AgentInstallPackageHistoryEntry {
                    agent_package_url: state
                        .config
                        .agent_package_url_by_id_at(&base, &entry.package_id),
                    package_id: entry.package_id,
                    source: entry.source,
                    package_sha256: entry.package_sha256,
                    version: entry.version,
                    arch: entry.arch,
                    created_by: entry.created_by,
                    created_at: entry.created_at,
                })
                .collect();
            Json(AgentInstallPackageHistoryResponse { packages }).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent install package history: {err}"),
        )
            .into_response(),
    }
}

fn install_package_response(
    settings: &[StoredAgentInstallPackageAddress],
) -> AgentInstallPackageResponse {
    AgentInstallPackageResponse {
        packages: settings
            .iter()
            .map(|setting| AgentInstallPackagePlatform {
                platform: setting.address_id.clone(),
                package_url: setting.package_url.clone(),
                package_sha256: setting.package_sha256.clone(),
                updated_by: setting.updated_by.clone(),
                updated_at: DateTime::from_rfc3339(&setting.updated_at),
            })
            .collect(),
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
    let knowledge = state.knowledge();
    match knowledge.discovery_policies.as_deref() {
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

/// 查看当前生效的 Agent 数据面上送地址。
///
/// 生效值取「管理面设置 → 部署配置派生 → 都没有」（见
/// [`super::install::effective_agent_uplink`]）：没在管理面设过时，它就是**同一个域名 + 数据面端口**
/// （即「这台网关的数据面在哪」），`updated_at` 为 null，管理面据此显示「来自部署配置」。
///
/// 都没有（连对外基址都取不出主机名）才真是「未设置」：`host` 空、`updated_by` 空、`updated_at` 为 null，
/// 此时网关给 Agent 算出的上送授权只能是待命（没有目标），Agent 只上报自身状态，不采集日志也不上送数据面。
///
/// 这个地址是**运行期**生效的：它是 `uplink:poll` 现算 `AgentUplinkGrant` 时的目标来源，
/// 管理面改一次，已在网的 Agent 下一个 poll（30s 内）就换目标 —— 不需要重装。
pub async fn view_agent_uplink(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match super::install::effective_agent_uplink(&state.config, &state.store).await {
        Ok(Some(setting)) => Json(uplink_response(&setting)).into_response(),
        Ok(None) => Json(AgentUplinkResponse {
            setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
            host: String::new(),
            port: DEFAULT_AGENT_UPLINK_PORT,
            enabled: false,
            updated_by: String::new(),
            updated_at: None,
            enabled_configured: false,
        })
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent uplink address: {err}"),
        )
            .into_response(),
    }
}

/// 设置 Agent 数据面上送地址与**部署级启用开关**（管理面）。
///
/// 记录的是「数据面（warp-parse）在哪」这个控制面事实：它既是新签发初始配置里
/// `[telemetry.logs.output.tcp]` 的取值，也是运行期 `uplink:poll` 现算上送授权时的
/// 目标来源 —— 所以改这里对所有已签发的 Agent **立即**生效（下一个 poll 就拿到新目标），
/// 不需要重跑安装脚本。
///
/// 只在「要指到别处」时才需要用它：没设过时生效的是**部署配置派生**的目标（同一域名 + 数据面端口，
/// 见 [`super::install::effective_agent_uplink`]），所以「一台机器、一个域名」的部署不必录入。
///
/// 但只有地址不等于启用：网关现算的判据是「**该 Agent 有生效工作** 或 **开关打开**」且「有目标」。
/// 开关回答的是另一半问题 —— 「这套网关现在收不收数据」—— 所以新装机不必先派工也能开始上送；
/// 代价是开关打开时，**撤回工作不再能把某一台单独关掉**（要单独停就关开关或吊销那台 agent，
/// 见 `docs/design/agent-uplink-enablement.md` §4.1）。
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
    // 缺省 = 保持已存值（见 `SetAgentUplinkRequest::enabled`）。读不到已存值就 500，
    // 不把「读库失败」伪装成「关掉」——那会静默掐掉全队的上送。
    let enabled = match input.enabled {
        Some(value) => value,
        None => match state.store.get_agent_uplink().await {
            Ok(stored) => stored.map(|setting| setting.enabled).unwrap_or(false),
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load agent uplink address: {err}"),
                )
                    .into_response();
            }
        },
    };
    let setting = StoredAgentUplinkAddress {
        setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
        host: host.to_string(),
        port,
        enabled,
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
        enabled: setting.enabled,
        updated_by: setting.updated_by.clone(),
        updated_at: DateTime::from_rfc3339(&setting.updated_at),
        // 派生值没有 updated_at（构造时留空），它就是「不是管理面录入的」。
        enabled_configured: !setting.updated_at.is_empty(),
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

/// 查看网关对外地址。
///
/// 未设置过时 `url` 为空、`updated_at` 为 null，但 `fallback_url` 仍给出网关当前
/// **实际**使用的基址（配置文件里的 `server.public_base_url`）—— 管理面据此能回答
/// 「不设置会怎样」，否则界面上只剩一个空值。
pub async fn view_agent_advertise_url(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.get_agent_advertise_url().await {
        Ok(setting) => Json(advertise_url_response(
            setting.as_ref(),
            &state.config.public_base_url,
        ))
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load gateway advertise url: {err}"),
        )
            .into_response(),
    }
}

/// 设置网关对外地址（管理面）。
///
/// 变更只影响**之后**签发的安装代码：安装命令 / install.sh / 安装包的分发地址、
/// 以及新装 Agent 初始配置里的 `[control_plane] endpoint` 都由它派生。已安装的
/// agent 要重跑安装脚本才会拿到新值（初始配置只在安装时拉一次）。
pub async fn set_agent_advertise_url(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<SetAgentAdvertiseUrlRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let url = match validate_advertise_url(&input.url) {
        Ok(value) => value,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };
    let setting = StoredAgentAdvertiseUrl {
        setting_id: DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID.to_string(),
        url: url.to_string(),
        updated_by: input
            .requested_by
            .unwrap_or_else(|| "platform-maintenance-engineer".to_string()),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    match state.store.upsert_agent_advertise_url(&setting).await {
        Ok(()) => Json(advertise_url_response(
            Some(&setting),
            &state.config.public_base_url,
        ))
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store gateway advertise url: {err}"),
        )
            .into_response(),
    }
}

fn advertise_url_response(
    setting: Option<&StoredAgentAdvertiseUrl>,
    fallback: &str,
) -> AgentAdvertiseUrlResponse {
    AgentAdvertiseUrlResponse {
        setting_id: DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID.to_string(),
        url: setting.map(|value| value.url.clone()).unwrap_or_default(),
        fallback_url: fallback.trim_end_matches('/').to_string(),
        updated_by: setting
            .map(|value| value.updated_by.clone())
            .unwrap_or_default(),
        updated_at: setting.and_then(|value| DateTime::from_rfc3339(&value.updated_at)),
    }
}

/// 校验网关对外地址。
///
/// 与 `server.public_base_url` 同口径：它会被拼进安装命令与 install.sh 里的 URL，
/// 所以必须 https，且不含空白或 shell 元字符（复用配置层同一个判据，不另写一份 ——
/// 两处各写一份迟早会漂移）。尾斜杠允许，保存时裁掉。
fn validate_advertise_url(value: &str) -> Result<&str, String> {
    let url = value.trim().trim_end_matches('/');
    if url.is_empty() {
        return Err("url must not be empty".to_string());
    }
    if url.len() > MAX_PACKAGE_URL_LEN {
        return Err(format!("url must be at most {MAX_PACKAGE_URL_LEN} bytes"));
    }
    if url.chars().any(char::is_control) {
        return Err("url must not contain control characters".to_string());
    }
    if !url.starts_with("https://") {
        return Err("url must be an https:// URL".to_string());
    }
    if url.len() == "https://".len() {
        return Err("url must include a host".to_string());
    }
    if contains_shell_metacharacters(url) {
        return Err("url must not contain whitespace or shell metacharacters".to_string());
    }
    Ok(url)
}

/// 校验安装包地址与摘要。
///
/// 安装包是 Agent 的启动来源，因此地址只接受 https URL 或本机绝对路径：
/// 不允许明文 http 分发（与 `server.public_base_url` 必须 https 的口径一致）。
/// 摘要**必填**（64 hex，可带 `sha256:` 前缀）；空 / 形态不对一律 400。
fn validate_package_address<'a>(
    package_url: &'a str,
    package_sha256: &str,
) -> Result<(&'a str, String), String> {
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
    Ok((package_url, normalize_sha256(package_sha256.trim())?))
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
    node_id: &str,
    hostname: &str,
    ip_addresses: &[String],
    last_seen_at: &str,
    memory_bytes: Option<u64>,
    cpu_percent: Option<f64>,
    cpu_cores: Option<u32>,
    admin_latency_ms: Option<u64>,
    uplink_state: Option<wist_contracts::agent_uplink::AgentUplinkState>,
    certificate_status: Option<wist_api::status::AgentCertificateStatus>,
    revoked: bool,
) -> AgentRuntimeStatusView {
    AgentRuntimeStatusView {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        version: version.to_string(),
        status: status.to_string(),
        health: health.to_string(),
        node_id: node_id.to_string(),
        hostname: hostname.to_string(),
        ip_addresses: ip_addresses.to_vec(),
        memory_bytes: memory_bytes.map(|value| value as i64),
        cpu_percent,
        cpu_cores,
        cpu_percent_of_machine: cpu_percent_of_machine(cpu_percent, cpu_cores),
        admin_latency_ms: admin_latency_ms.map(|value| value as i64),
        last_seen_at: DateTime::from_rfc3339(last_seen_at).unwrap_or_else(DateTime::now),
        uplink_state,
        certificate_status,
        revoked,
    }
}

/// 把单核口径的进程 CPU 占比换算成整机口径（0..100）。
///
/// **派生只此一处**：`cpu_percent` 是单核口径（100% = 占满一个核，多线程进程可 >100），
/// 整机占比 = `cpu_percent / cpu_cores`。`cpu_cores` 为 `None`（老版本 agentd 没报）或
/// `0`（上报了非法核数）时返回 `None`：既不除零，也不默认成 0 —— 把「测不到」写成 0
/// 会在页面上伪造出一段「整机空闲」的假读数。`cpu_percent` 缺失时同样返回 `None`。
pub(super) fn cpu_percent_of_machine(
    cpu_percent: Option<f64>,
    cpu_cores: Option<u32>,
) -> Option<f64> {
    let cores = cpu_cores.filter(|cores| *cores > 0)?;
    Some(cpu_percent? / f64::from(cores))
}

/// 单台 Agent 运行态视图（对应模型 `AgentRuntimeStatus` 的读投影形状）。
///
/// 为什么在实现层派生：管理面还要呈现网关**派生**的整机 CPU 占比（`cpu_percent_of_machine`）
/// 与派生所需的口径字段（`cpu_cores`），模型 `AgentRuntimeStatus` 里没有这两个字段。
/// 与 `AgentListEntry` 同一约定：运行态字段取自模型，管理面额外需要的字段由实现层补出。
#[derive(Debug, Serialize)]
pub struct AgentRuntimeStatusView {
    pub agent_id: String,
    pub instance_id: String,
    pub version: String,
    pub status: String,
    pub health: String,
    /// 机器名 / `node_id` / 网卡地址：注册表里「这是哪台机器」的展示依据。
    /// 凭证书首触重建登记的机器靠状态上报补齐（见迁移 0023）。
    pub node_id: String,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub last_seen_at: DateTime,
    pub memory_bytes: Option<i64>,
    /// 单核口径的进程 CPU 占比（100% = 占满一个核，可能 >100），只统计 agent 进程自身。
    pub cpu_percent: Option<f64>,
    /// agent 所在机器的逻辑核数；null = 老版本 agentd 没报（与 0 区分）。
    pub cpu_cores: Option<u32>,
    /// 整机口径的 CPU 占比（0..100），由 `cpu_percent / cpu_cores` 派生；算不出时为 null。
    pub cpu_percent_of_machine: Option<f64>,
    pub admin_latency_ms: Option<i64>,
    /// agent 上报的**实际生效**采集输出状态（它与网关下发的 `agent_uplink` 是一对：
    /// 一个说「要它怎样」，一个说「它实际成了怎样」）。null = 这台 agent 还没报过
    /// （旧版本 agentd 不发这个字段）。
    ///
    /// 为什么放在运行状态这里：运维问「这台为什么不上送」时查的就是这个响应，
    /// 待命 / 本机 file 出口 / 目标是谁 / 控制面下发还是本机 / 出口是否在失败，一屏给全。
    pub uplink_state: Option<wist_contracts::agent_uplink::AgentUplinkState>,
    /// agent 上报的**客户端证书状态**（mTLS）；null = 还没报过 / 没证书。
    ///
    /// 为什么要有它：证书快到期 / 已过期需重装这件事，只有本机能判（服务端在握手期就验完了，
    /// 而过期证书根本进不来）。见 `docs/design/agent-identity-mtls.md` §5.5。
    pub certificate_status: Option<wist_api::status::AgentCertificateStatus>,
    /// 这台 agent 是否在**拒绝名单**内（被吊销，§5.6）。true 时它的任何凭据路径都会被 401
    /// `certificate_revoked`，页面应据此把「被吊销」与「离线」区分开 —— 离线会自己回来，
    /// 被吊销不会。原因 / GC 水位见拒绝名单列表接口。
    pub revoked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(value: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(value)
            .expect("rfc3339")
            .with_timezone(&chrono::Utc)
    }

    /// bearer 凭据的实际到期在将来、且**晚于**证书窗：取它（真正的失效点）。
    #[test]
    fn retention_uses_the_bearer_expiry_when_it_is_the_later_one() {
        let now = at("2026-09-29T00:00:00Z");
        // bearer 到期 60 天，证书窗 37 天 → 取 bearer。
        let until =
            certificate_retention_until("2026-11-28T00:00:00+00:00", 60 * 86_400, 37 * 86_400, now);
        assert_eq!(until, at("2026-11-28T00:00:00Z"));
    }

    /// **关键**：bearer 到期早于证书窗时，必须取证书窗 —— 否则会在被吊销的证书还没过期时
    /// 就把条目 GC 掉，被吊销的 agent 重新获得访问权（§5.6）。
    #[test]
    fn retention_never_ends_before_the_certificate_can_no_longer_exist() {
        let now = at("2026-09-29T00:00:00Z");
        // bearer 只剩 30 天，但证书能活到 37 天：取「now + 37 天」。
        let until =
            certificate_retention_until("2026-10-29T00:00:00+00:00", 30 * 86_400, 37 * 86_400, now);
        assert_eq!(until, now + chrono::Duration::days(37));
    }

    /// 拿不到 / 不可解析 / 已过去：bearer 侧用 TTL 兜底；再与证书窗取较晚者。
    #[test]
    fn retention_falls_back_to_the_ttls_when_bearer_expiry_cannot_be_used() {
        let now = at("2026-09-29T00:00:00Z");
        for unusable in ["", "not-a-time", "2026-01-01T00:00:00+00:00"] {
            assert_eq!(
                certificate_retention_until(unusable, 30 * 86_400, 37 * 86_400, now),
                now + chrono::Duration::days(37),
                "unusable bearer expiry {unusable:?} must fall back to the ttl windows"
            );
            // bearer TTL 比证书窗长时，取 bearer。
            assert_eq!(
                certificate_retention_until(unusable, 60 * 86_400, 37 * 86_400, now),
                now + chrono::Duration::days(60),
            );
        }
    }
}
