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
    AgentQuery, DEFAULT_AGENT_UPLINK_PORT, DEFAULT_AGENT_UPLINK_SETTING_ID,
    DEFAULT_INSTALL_PACKAGE_SETTING_ID, StoredAgentClassification, StoredAgentFactSummary,
    StoredAgentInstallPackageAddress, StoredAgentUplinkAddress, StoredOneShotWork,
    StoredPurposeSuggestion, StoredWorkAck, effective_standing, outstanding_one_shot,
};
use wist_contracts::work::{OneShotWork, StandingWork, WorkKind, WorkReceipt};

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
        agent.last_cpu_cores,
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

/// 把授权/撤回被拒的原因映射成 HTTP 状态。
///
/// 三档分开是有意的：
///   * `BadRequest` —— 请求本身不成立（写错了面名、把 macOS 专有面派给 Linux 机器）；
///   * `Conflict` —— 请求成立但与当前状态冲突（规则未就绪、版本回退、不可中断却要暂停）：
///     它是「现在不行」，人该做的是等规则就绪或换个动作，而不是改请求；
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
/// 顺序不是随意排的：先要判定（否则不知道是哪类机器、取不到模板），再要规则就绪
/// （否则展开出来的单元落不了数据面），最后才谈内容。
async fn grant_standing_work(
    state: &ApiState,
    agent_id: &str,
    input: &GrantWorkRequest,
) -> Response {
    let Some(content) = state.content.as_deref() else {
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
    settled_one_shot: Vec<OneShotWork>,
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
        one_shot_views.push(OneShotWorkView { work, ack });
    }
    let retired_standing = standing
        .into_iter()
        .filter(|work| !matches!(work.status.as_str(), "active" | "paused"))
        .collect();
    let settled_one_shot = one_shot
        .into_iter()
        .filter(|work| !work.work.is_outstanding())
        .map(|work| work.work)
        .collect();
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
    Json(AgentWorkView {
        agent_id,
        sequence,
        standing: standing_views,
        one_shot: one_shot_views,
        retired_standing,
        settled_one_shot,
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
    cpu_cores: Option<u32>,
    admin_latency_ms: Option<u64>,
) -> AgentRuntimeStatusView {
    AgentRuntimeStatusView {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        version: version.to_string(),
        status: status.to_string(),
        health: health.to_string(),
        memory_bytes: memory_bytes.map(|value| value as i64),
        cpu_percent,
        cpu_cores,
        cpu_percent_of_machine: cpu_percent_of_machine(cpu_percent, cpu_cores),
        admin_latency_ms: admin_latency_ms.map(|value| value as i64),
        last_seen_at: DateTime::from_rfc3339(last_seen_at).unwrap_or_else(DateTime::now),
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
