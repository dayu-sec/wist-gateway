//! 执行计划的**审批 → 签发**：`/api/v1/admin/approvals`。
//!
//! 这一组端点是「响应能力」B 线的控制面闭环。它回答三个问题：
//!
//! 1. **这份计划批没批**（`POST /agents/{id}/approvals` + 投票）；
//! 2. **批的是不是这一份**（审批绑 `plan_digest`，签发时重算比对）；
//! 3. **谁签的**（attestation 由控制面私钥签，被管端用本地公钥验）。
//!
//! 三条刻意的取舍：
//!
//! * **投票人来自鉴权身份**（`admin:<token 指纹>`），不接受客户端自填 —— 否则
//!   「另一个人批了」可以由一个人伪造。
//! * **签发的有效期不晚于计划本身**，且审批单自己有过期时刻。一份审批单不该永远有效。
//! * **单次审批**：R2 / R3 都是**一票就够**。多票机制（R3 要两名审批人）已去掉 ——
//!   单 admin token 下所有票共享同一指纹，凑不出第二个身份，留着只会让 R3 变成
//!   「永远批不了」。`required_approvers` 字段仍在（它进签名覆盖），将来 center 接手
//!   身份体系后想恢复多票，改策略与两端下限即可，不用动契约。

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use wist_contracts::action_plan::{ActionPlan, RiskLevel, plan_digest};

use crate::api::admin_auth::{admin_actor, require_admin_bearer};
use crate::api::admin_ops::agent_not_found_response;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;
use crate::api::{ApiState, action_plans};
use crate::infra::{SignError, StoredActionApproval, StoredActionApprovalVote};

/// 分配审批单 id 的最大尝试次数。
///
/// 撞主键是极端情况（同一微秒 + 同一随机值）—— 3 次已经远超需要。
/// 超过就如实报内部错误，而不是无限重试。
const APPROVAL_ID_ATTEMPTS: usize = 3;

/// 审批单 id：`apv_{agent_id}_{micros}_{rand4}`。
///
/// 随机后缀不是装饰：只靠微秒的话，「同一微秒内两次提交」会撞主键，
/// 而调用方看到的会是 500 —— 它通常只是在重试。
fn new_approval_id(agent_id: &str, now: DateTime<Utc>) -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut suffix = [0u8; 4];
    if SystemRandom::new().fill(&mut suffix).is_ok() {
        let hex: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("apv_{agent_id}_{}_{hex}", now.timestamp_micros())
    } else {
        // 随机源不可用是极端情况：退回时间戳（仍有有界重试兼底）。
        format!("apv_{agent_id}_{}", now.timestamp_micros())
    }
}

/// 风险等级要求的最少审批人数。
///
/// **策略只有两档**：`0`（R0/R1 只读，免审）/ `1`（R2/R3 写，单次审批）。
/// R3 保留为枚举值（契约里有、审计可辨），但**不再要求两名审批人**：多票机制已去掉。
///
/// 与 agentd 的 `plan_review::policy_min_approvers` **各写一份**，不是疏忽：
/// 两端各自硬编码下限，一方被改不会让另一方自动放宽。想改策略就两边都改。
fn required_approvers_for(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::R0 | RiskLevel::R1 => 0,
        RiskLevel::R2 | RiskLevel::R3 => 1,
    }
}

fn risk_level_wire(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::R0 => "R0",
        RiskLevel::R1 => "R1",
        RiskLevel::R2 => "R2",
        RiskLevel::R3 => "R3",
    }
}

#[cfg(test)]
fn risk_level_from_wire(value: &str) -> Option<RiskLevel> {
    match value {
        "R0" => Some(RiskLevel::R0),
        "R1" => Some(RiskLevel::R1),
        "R2" => Some(RiskLevel::R2),
        "R3" => Some(RiskLevel::R3),
        _ => None,
    }
}

fn format_ts(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// 客户端可控字符串进日志前的洗白。
///
/// `issued_by` / `key_id` 来自请求，直接拼进 `log::info!` 会让攻击者能用 `\n`
/// 伪造一整行日志（比如伪造成 `event=ApprovalIssuedExternal`）。这里把控制字符
/// 换成 `?` 并截断，日志始终一行、字段边界不会被撑破。
fn log_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .take(120)
        .collect()
}

fn parse_ts(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

// ── 请求 / 响应形状 ──

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApprovalRequest {
    plan: ActionPlan,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VoteRequest {
    /// `approve` | `reject`
    decision: String,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListQuery {
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IssueQuery {
    /// 签发后是否立即下发（缺省 `true`）。设 `false` 只签发，自己再调 `/plans`。
    #[serde(default)]
    dispatch: Option<bool>,
}

#[derive(Debug, Serialize)]
struct VoteView {
    approver: String,
    decision: String,
    comment: Option<String>,
    voted_at: String,
}

#[derive(Debug, Serialize)]
struct ApprovalView {
    approval_id: String,
    agent_id: String,
    plan_digest: String,
    risk_level: String,
    requested_by: String,
    reason: Option<String>,
    requested_at: String,
    expires_at: String,
    required_approvers: i64,
    status: String,
    approved_at: Option<String>,
    votes: Vec<VoteView>,
    issued: bool,
    /// 审批时的计划原文（**已由网关写入 `approval_ref`**）：前端拿它去比对 / 展示。
    plan: Option<serde_json::Value>,
    issued_plan: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct IssueResponse {
    #[serde(flatten)]
    approval: ApprovalView,
    /// 签发后自动下发时返回的命令 id；`dispatch=false` 时为 `None`。
    dispatched_command_id: Option<String>,
}

/// 审批单视图。
///
/// `include_plans = false` 用于**列表**：计划原文可能上千字节，一页几十条就会把响应撑大；
/// 单条查询与签发响应才带完整内容。
fn approval_view(
    approval: &StoredActionApproval,
    votes: Vec<StoredActionApprovalVote>,
    include_plans: bool,
) -> ApprovalView {
    ApprovalView {
        approval_id: approval.approval_id.clone(),
        agent_id: approval.agent_id.clone(),
        plan_digest: approval.plan_digest.clone(),
        risk_level: approval.risk_level.clone(),
        requested_by: approval.requested_by.clone(),
        reason: approval.reason.clone(),
        requested_at: approval.requested_at.clone(),
        expires_at: approval.expires_at.clone(),
        required_approvers: approval.required_approvers,
        status: approval.status.clone(),
        approved_at: approval.approved_at.clone(),
        votes: votes
            .into_iter()
            .map(|vote| VoteView {
                approver: vote.approver,
                decision: vote.decision,
                comment: vote.comment,
                voted_at: vote.voted_at,
            })
            .collect(),
        issued: approval.issued_plan_json.is_some(),
        // 解析失败（不该发生）就当作没带，不阻断整个视图。
        plan: if include_plans {
            serde_json::from_str(&approval.plan_json).ok()
        } else {
            None
        },
        issued_plan: if include_plans {
            approval
                .issued_plan_json
                .as_deref()
                .and_then(|json| serde_json::from_str(json).ok())
        } else {
            None
        },
    }
}

#[allow(clippy::result_large_err)]
async fn load_votes(
    state: &ApiState,
    approval_id: &str,
) -> Result<Vec<StoredActionApprovalVote>, Response> {
    state
        .store
        .list_action_approval_votes(approval_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::APPROVAL_LOAD_FAILED,
                "failed to load approval votes",
                err,
            )
            .into_response()
        })
}

/// 投票后的状态推进（纯函数，便于单测）。
///
/// 一票否决优先：只要有 `reject`，审批单就是 `rejected`，不会因为人数够了又变回 `approved`。
fn next_approval_status(
    required_approvers: i64,
    votes: &[StoredActionApprovalVote],
    now: DateTime<Utc>,
) -> (&'static str, Option<String>) {
    let approvals = votes.iter().filter(|vote| vote.is_approve()).count();
    let rejections = votes.len() - approvals;
    let required = usize::try_from(required_approvers).unwrap_or(usize::MAX);
    if rejections > 0 {
        ("rejected", None)
    } else if approvals >= required {
        ("approved", Some(format_ts(now)))
    } else {
        ("pending", None)
    }
}

// ── POST /api/v1/admin/agents/{agent_id}/approvals ──

/// 提交一份计划等待审批。**入参是未签发的计划**（带 attestation 的直接下发即可）。
pub async fn create_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let Some(Json(input)) = body else {
        return ApiError::bad_request(
            codes::ACTION_PLAN_INVALID,
            "approval request body is required",
        )
        .into_response();
    };
    let request: CreateApprovalRequest = match serde_json::from_value(input) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::bad_request(
                codes::ACTION_PLAN_INVALID,
                format!("invalid approval request: {err}"),
            )
            .into_response();
        }
    };
    let mut plan = request.plan;
    if plan.target.agent_id != agent_id {
        return ApiError::bad_request(
            codes::ACTION_PLAN_TARGET_MISMATCH,
            format!(
                "plan targets {}, path targets {agent_id}",
                plan.target.agent_id
            ),
        )
        .into_response();
    }
    if plan.attestation.is_some() {
        return ApiError::bad_request(
            codes::ACTION_PLAN_INVALID,
            "plan already carries an attestation; submit the unsigned plan for approval",
        )
        .into_response();
    }

    let risk = plan.constraints.risk_level;
    let required = required_approvers_for(risk);
    if required == 0 {
        return ApiError::bad_request(
            codes::APPROVAL_NOT_REQUIRED,
            format!(
                "risk level {} does not require approval; dispatch it directly",
                risk_level_wire(risk)
            ),
        )
        .into_response();
    }
    // 单票制下这个分支不可达（见 `required_approvers_for`）。仍然保留：将来若有人
    // 把 R3 改回 2 票，网关会明确拒绝而不是静默地「等第二个人永远等不到」。
    if required > 1 {
        return ApiError::conflict(
            codes::APPROVAL_POLICY_UNSUPPORTED,
            format!(
                "risk level {} requires {required} distinct approvers, but this gateway \
                 enforces single-approval policy",
                risk_level_wire(risk)
            ),
        )
        .into_response();
    }

    // 形状坏的计划不该进入审批队列：批完之后再签发，等于把错误固化成一份“已批准”的记录。
    // `approval_ref` 的具体值到铸 id 时才写回，但形状与它无关。
    if let Err(err) = wist_validate::action_plan::validate_action_plan(&plan) {
        return ApiError::bad_request(
            codes::ACTION_PLAN_INVALID,
            format!("invalid action plan: {}", err.code),
        )
        .into_response();
    }

    let reason = request.reason;
    let requested_by = admin_actor(&state.config);
    let mut stored: Option<StoredActionApproval> = None;
    for _ in 0..APPROVAL_ID_ATTEMPTS {
        let now = Utc::now();
        let approval_id = new_approval_id(&agent_id, now);
        // 审批单号是**网关铸的**，所以由网关写回计划：客户端提交时填的 `approval_ref`
        // 一律被覆盖 —— 否则它可以先写一个自己的引用，审批完再拿走。
        plan.constraints.approval_ref = Some(approval_id.clone());
        plan.constraints.approval_mode = wist_contracts::action_plan::ApprovalMode::Required;
        let plan_json = match serde_json::to_string(&plan) {
            Ok(json) => json,
            Err(err) => {
                return ApiError::internal(
                    codes::APPROVAL_STORE_FAILED,
                    "failed to encode action plan",
                    err,
                )
                .into_response();
            }
        };
        let candidate = StoredActionApproval {
            approval_id,
            agent_id: agent_id.clone(),
            // 摘要必须在写回 `approval_ref` **之后**算：它参与摘要。
            plan_digest: plan_digest(&plan),
            risk_level: risk_level_wire(risk).to_string(),
            requested_by: requested_by.clone(),
            reason: reason.clone(),
            requested_at: format_ts(now),
            plan_json,
            required_approvers: i64::from(required),
            status: "pending".to_string(),
            approved_at: None,
            expires_at: format_ts(now + Duration::seconds(state.config.plan_approval_ttl_seconds)),
            issued_plan_json: None,
        };
        match state.store.try_insert_action_approval(&candidate).await {
            Ok(true) => {
                stored = Some(candidate);
                break;
            }
            // 同一个 id 已经存在（极端并发 / 重试）：换一个 id 再来，不把冲突变成 500。
            Ok(false) => continue,
            Err(err) => {
                return ApiError::internal(
                    codes::APPROVAL_STORE_FAILED,
                    "failed to store approval",
                    err,
                )
                .into_response();
            }
        }
    }
    let Some(approval) = stored else {
        return ApiError::internal(
            codes::APPROVAL_STORE_FAILED,
            "failed to allocate a unique approval id",
            "exhausted retries",
        )
        .into_response();
    };
    log::info!(
        "event=ActionApprovalRequested approval_id={} agent_id={} risk={} digest={}",
        approval.approval_id,
        approval.agent_id,
        approval.risk_level,
        approval.plan_digest
    );
    Json(approval_view(&approval, Vec::new(), true)).into_response()
}

// ── GET /api/v1/admin/approvals/{approval_id} ──

pub async fn get_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(approval_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let approval = match load_approval(&state, &approval_id).await {
        Ok(approval) => approval,
        Err(response) => return response,
    };
    let votes = match load_votes(&state, &approval_id).await {
        Ok(votes) => votes,
        Err(response) => return response,
    };
    Json(approval_view(&approval, votes, true)).into_response()
}

// ── GET /api/v1/admin/approvals ──

pub async fn list_approvals(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Query(query): Query<ListQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let approvals = match state
        .store
        .list_action_approvals(query.agent_id.as_deref())
        .await
    {
        Ok(approvals) => approvals,
        Err(err) => {
            return ApiError::internal(
                codes::APPROVAL_LOAD_FAILED,
                "failed to load approvals",
                err,
            )
            .into_response();
        }
    };
    let mut views = Vec::with_capacity(approvals.len());
    for approval in approvals {
        // 列表不带计划原文：那是单条详情与签发响应的事。
        let votes = match load_votes(&state, &approval.approval_id).await {
            Ok(votes) => votes,
            Err(response) => return response,
        };
        views.push(approval_view(&approval, votes, false));
    }
    Json(views).into_response()
}

// ── POST /api/v1/admin/approvals/{approval_id}/votes ──

/// 投一票。审批人身份由 **bearer token 指纹**派生，客户端不能自填。
pub async fn vote_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(approval_id): Path<String>,
    body: Option<Json<serde_json::Value>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(Json(input)) = body else {
        return ApiError::bad_request(codes::ACTION_PLAN_INVALID, "vote body is required")
            .into_response();
    };
    let request: VoteRequest = match serde_json::from_value(input) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::bad_request(
                codes::ACTION_PLAN_INVALID,
                format!("invalid vote: {err}"),
            )
            .into_response();
        }
    };
    if request.decision != "approve" && request.decision != "reject" {
        return ApiError::bad_request(
            codes::ACTION_PLAN_INVALID,
            "decision must be `approve` or `reject`",
        )
        .into_response();
    }

    let mut approval = match load_approval(&state, &approval_id).await {
        Ok(approval) => approval,
        Err(response) => return response,
    };
    if approval.issued_plan_json.is_some() {
        return ApiError::conflict(
            codes::APPROVAL_ALREADY_ISSUED,
            "approval has already been issued",
        )
        .into_response();
    }
    if approval.status != "pending" {
        return ApiError::conflict(
            codes::APPROVAL_CLOSED,
            format!("approval is already {}", approval.status),
        )
        .into_response();
    }
    let now = Utc::now();
    if let Some(expires) = parse_ts(&approval.expires_at)
        && now >= expires
    {
        let _ = state
            .store
            .set_action_approval_status(&approval_id, "expired", None)
            .await;
        return ApiError::conflict(
            codes::APPROVAL_EXPIRED,
            format!("approval expired at {}", approval.expires_at),
        )
        .into_response();
    }

    let vote = StoredActionApprovalVote {
        approval_id: approval_id.clone(),
        // 这是唯一可信的审批人来源：token 指纹（不可反推、轮换前后可区分）。
        approver: admin_actor(&state.config),
        decision: request.decision,
        comment: request.comment,
        voted_at: format_ts(now),
    };
    if let Err(err) = state.store.upsert_action_approval_vote(&vote).await {
        return ApiError::internal(codes::APPROVAL_STORE_FAILED, "failed to store vote", err)
            .into_response();
    }

    let votes = match load_votes(&state, &approval_id).await {
        Ok(votes) => votes,
        Err(response) => return response,
    };
    let (next_status, approved_at) = next_approval_status(approval.required_approvers, &votes, now);
    if next_status != "pending" {
        // 只有真的到终态才写库：`pending → pending` 的无意义 UPDATE 会让
        // “最后修改时间”这类审计字段失去区分力。
        if let Err(err) = state
            .store
            .set_action_approval_status(&approval_id, next_status, approved_at.as_deref())
            .await
        {
            return ApiError::internal(
                codes::APPROVAL_STORE_FAILED,
                "failed to update approval status",
                err,
            )
            .into_response();
        }
    }
    approval.status = next_status.to_string();
    approval.approved_at = approved_at;
    log::info!(
        "event=ActionApprovalVoted approval_id={} approver={} decision={} status={}",
        approval_id,
        vote.approver,
        vote.decision,
        approval.status
    );
    Json(approval_view(&approval, votes, true)).into_response()
}

// ── GET /api/v1/admin/approvals/{approval_id}/signing-payload ──

/// 待签包：给审批机（`wist-approve`）的一切它需要、而**不需要相信页面**的东西。
///
/// 只给**事实**（审批人名单 / 摘要 / 计划原文 / 计划到期），不替审批机填
/// `key_id` / `issued_by` / `signed_at` —— 那些属于签名方，网关代填就变成"网关也在决定签名内容"。
#[derive(Debug, Serialize)]
struct SigningPayloadView {
    approval_id: String,
    agent_id: String,
    plan_digest: String,
    risk_level: String,
    approvers: Vec<String>,
    required_approvers: u8,
    approved_at: Option<String>,
    /// 计划原文（含审批时写入的 `approval_ref`）。CLI 用它本地重算摘要。
    plan: serde_json::Value,
    /// 计划自身的到期时刻：证明的 `expires_at` 不能晚于它。
    plan_expires_at: String,
}

pub async fn signing_payload(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(approval_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let approval = match load_approval(&state, &approval_id).await {
        Ok(approval) => approval,
        Err(response) => return response,
    };
    if approval.issued_plan_json.is_some() {
        return ApiError::conflict(
            codes::APPROVAL_ALREADY_ISSUED,
            "approval has already been issued",
        )
        .into_response();
    }
    let now = Utc::now();
    if let Some(expires) = parse_ts(&approval.expires_at)
        && now >= expires
    {
        return ApiError::conflict(
            codes::APPROVAL_EXPIRED,
            format!("approval expired at {}", approval.expires_at),
        )
        .into_response();
    }
    if approval.status != "approved" {
        let (code, detail) = match approval.status.as_str() {
            "rejected" => (codes::APPROVAL_CLOSED, "approval was rejected".to_string()),
            "expired" => (codes::APPROVAL_EXPIRED, "approval expired".to_string()),
            other => (
                codes::APPROVAL_INCOMPLETE,
                format!(
                    "approval is {other} (needs {} approver(s))",
                    approval.required_approvers
                ),
            ),
        };
        return ApiError::conflict(code, detail).into_response();
    }
    let votes = match load_votes(&state, &approval_id).await {
        Ok(votes) => votes,
        Err(response) => return response,
    };
    let approvers: Vec<String> = votes
        .iter()
        .filter(|vote| vote.is_approve())
        .map(|vote| vote.approver.clone())
        .collect();
    let Ok(required) = u8::try_from(approval.required_approvers) else {
        return ApiError::internal(
            codes::ACTION_PLAN_INVALID,
            "stored approval has an invalid required_approvers",
            approval.required_approvers,
        )
        .into_response();
    };
    if approvers.len() < usize::from(required) {
        return ApiError::conflict(
            codes::APPROVAL_INCOMPLETE,
            format!(
                "approval has {} approved vote(s), needs {required}",
                approvers.len()
            ),
        )
        .into_response();
    }
    let plan: ActionPlan = match serde_json::from_str(&approval.plan_json) {
        Ok(plan) => plan,
        Err(err) => {
            return ApiError::internal(
                codes::ACTION_PLAN_INVALID,
                "stored approval plan is not a valid action plan",
                err,
            )
            .into_response();
        }
    };
    // 能力闸同样放在**签名之前**：一台不会跑这份计划的机器，不该让人白签一次。
    if let Err(response) =
        action_plans::ensure_plan_capable(&state, &approval.agent_id, &plan).await
    {
        return response;
    }
    Json(SigningPayloadView {
        approval_id: approval.approval_id.clone(),
        agent_id: approval.agent_id.clone(),
        plan_digest: approval.plan_digest.clone(),
        risk_level: approval.risk_level.clone(),
        approvers,
        required_approvers: required,
        approved_at: approval.approved_at.clone(),
        plan: serde_json::from_str(&approval.plan_json).unwrap_or(serde_json::Value::Null),
        plan_expires_at: plan.meta.expires_at.clone(),
    })
    .into_response()
}

// ── POST /api/v1/admin/approvals/{approval_id}/issue ──

/// 签发请求体（可选）：带 `attestation` = **外部签发**（私钥在审批人手上）。
///
/// `attestation` 可缺省：老客户端/页面仍会发 `{}`（表示「用网关自己的私钥签」），
/// 把缺省当成错误会让所有旧调用方一起 422。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRequest {
    #[serde(default)]
    attestation: Option<wist_contracts::action_plan::ActionPlanAttestation>,
}

/// 满足人数后签发：填 `attestation` 写回库，并（默认）立即下发。
pub async fn issue_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(approval_id): Path<String>,
    Query(query): Query<IssueQuery>,
    body: Option<Json<IssueRequest>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 两条路径：请求体带 attestation = 外部签发；不带 = 网关自签（需要 `[plan_signing]`）。
    let external = body.and_then(|Json(request)| request.attestation);
    let signer = state.config.plan_signer.clone();
    if external.is_none() && signer.is_none() {
        return ApiError::unavailable(
            codes::PLAN_SIGNING_UNAVAILABLE,
            "plan signing key is not configured ([plan_signing] key_file)",
        )
        .into_response();
    }

    let mut approval = match load_approval(&state, &approval_id).await {
        Ok(approval) => approval,
        Err(response) => return response,
    };
    if approval.issued_plan_json.is_some() {
        return ApiError::conflict(
            codes::APPROVAL_ALREADY_ISSUED,
            "approval has already been issued",
        )
        .into_response();
    }
    let now = Utc::now();
    if let Some(expires) = parse_ts(&approval.expires_at)
        && now >= expires
    {
        let _ = state
            .store
            .set_action_approval_status(&approval_id, "expired", None)
            .await;
        return ApiError::conflict(
            codes::APPROVAL_EXPIRED,
            format!("approval expired at {}", approval.expires_at),
        )
        .into_response();
    }
    if approval.status != "approved" {
        // 分开报：页面要能区分「被否决」「已过期」「还差人」——三者该做的事完全不同。
        let (code, detail) = match approval.status.as_str() {
            "rejected" => (codes::APPROVAL_CLOSED, "approval was rejected".to_string()),
            "expired" => (codes::APPROVAL_EXPIRED, "approval expired".to_string()),
            other => (
                codes::APPROVAL_INCOMPLETE,
                format!(
                    "approval is {other} (needs {} approver(s))",
                    approval.required_approvers
                ),
            ),
        };
        return ApiError::conflict(code, detail).into_response();
    }

    let votes = match load_votes(&state, &approval_id).await {
        Ok(votes) => votes,
        Err(response) => return response,
    };
    let approvers: Vec<String> = votes
        .iter()
        .filter(|vote| vote.is_approve())
        .map(|vote| vote.approver.clone())
        .collect();
    // 存进去的值应该是 1..=3；越界说明行被改坏了，不是“审批未完成”。
    let Ok(required) = u8::try_from(approval.required_approvers) else {
        return ApiError::internal(
            codes::ACTION_PLAN_INVALID,
            "stored approval has an invalid required_approvers",
            approval.required_approvers,
        )
        .into_response();
    };
    // 防御：`status == approved` 本来就该保证人数够了，但库被改坏时不能靠一个标志位。
    // 签出去的 attestation 是不能撤回的 —— 宁可在这里回 409。
    if approvers.len() < usize::from(required) {
        return ApiError::conflict(
            codes::APPROVAL_INCOMPLETE,
            format!(
                "approval has {} approved vote(s), needs {required}",
                approvers.len()
            ),
        )
        .into_response();
    }

    let mut plan: ActionPlan = match serde_json::from_str(&approval.plan_json) {
        Ok(plan) => plan,
        Err(err) => {
            return ApiError::internal(
                codes::ACTION_PLAN_INVALID,
                "stored approval plan is not a valid action plan",
                err,
            )
            .into_response();
        }
    };
    // 能力闸放在**签发之前**：这台机器不会跑就不该签，否则签名只能攒着等升级。
    // 闸在签发前，审批单仍是 `approved`、未签发，机器上报能力后重试即可。
    if let Err(response) =
        action_plans::ensure_plan_capable(&state, &approval.agent_id, &plan).await
    {
        return response;
    }
    // 两条路径：外部签发（私钥在审批人手上）不碰 `plan_signer`；
    // 网关自签保持原样（含「重算摘要不一致 → 重走审批」的判断）。
    match external {
        Some(attestation) => {
            let key_id = attestation.key_id.clone();
            if let Err(response) = apply_external_attestation(
                &state,
                &approval,
                &approvers,
                required,
                &mut plan,
                attestation,
                now,
            )
            .await
            {
                // 拒绝要留痕：外部签发下「为什么这条签名没收」是最常被问的一句。
                log::warn!(
                    "event=ExternalAttestationRejected approval_id={} agent_id={} key_id={} status={}",
                    approval.approval_id,
                    approval.agent_id,
                    log_field(&key_id),
                    response.status().as_u16()
                );
                return response;
            }
        }
        None => {
            let Some(signer) = signer else {
                // 上面已判过：这里不可达，但不用 `unwrap` 在安全路径上。
                return ApiError::unavailable(
                    codes::PLAN_SIGNING_UNAVAILABLE,
                    "plan signing key is not configured",
                )
                .into_response();
            };
            // 签发时重算摘要：不一致说明审批之后计划被改过（重走审批，而不是重签一份新的）。
            if let Err(err) = signer.sign(
                &mut plan,
                &approval.approval_id,
                approvers,
                required,
                &approval.plan_digest,
                now,
            ) {
                // 按变体映射，不看文案：文案一改就会把 409 静默变成 500。
                return match err {
                    SignError::PlanChanged { .. } => {
                        ApiError::conflict(codes::PLAN_CHANGED_SINCE_APPROVAL, err.to_string())
                            .into_response()
                    }
                    SignError::PlanExpired => {
                        ApiError::conflict(codes::APPROVAL_EXPIRED, err.to_string()).into_response()
                    }
                    SignError::AlreadyAttested => {
                        ApiError::conflict(codes::APPROVAL_ALREADY_ISSUED, err.to_string())
                            .into_response()
                    }
                    SignError::Invalid(_) => {
                        ApiError::internal(codes::APPROVAL_STORE_FAILED, "failed to sign plan", err)
                            .into_response()
                    }
                };
            }
        }
    }
    let issued_json = match serde_json::to_string(&plan) {
        Ok(json) => json,
        Err(err) => {
            return ApiError::internal(
                codes::APPROVAL_STORE_FAILED,
                "failed to encode issued plan",
                err,
            )
            .into_response();
        }
    };
    match state
        .store
        .set_action_approval_issued(&approval_id, &issued_json)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // 并发签发：另一路已经写进去了。不覆盖，如实回 409。
            return ApiError::conflict(
                codes::APPROVAL_ALREADY_ISSUED,
                "approval has already been issued",
            )
            .into_response();
        }
        Err(err) => {
            return ApiError::internal(
                codes::APPROVAL_STORE_FAILED,
                "failed to store issued plan",
                err,
            )
            .into_response();
        }
    }
    approval.issued_plan_json = Some(issued_json);

    // 默认直接下发：审批 → 签发 → 投递是「一次响应」的完整一步。
    let dispatched_command_id = if query.dispatch.unwrap_or(true) {
        match action_plans::enqueue_plan(&state, &approval.agent_id, &plan).await {
            Ok(command) => Some(command.command_id),
            Err(err) => {
                // 入队失败必须把「已签发」退回去：否则这张单永久显示已签发、队列里却没有命令，
                // 重签又会被 `approval_already_issued` 拒 —— 只能重新发起，且审计上看不出为什么。
                // 回滚失败只记日志（响应仍是原始错误），这时确实需要人工处理。
                if let Err(rollback) = state.store.clear_action_approval_issued(&approval_id).await
                {
                    log::error!(
                        "event=ActionApprovalIssueRollbackFailed approval_id={} detail=\"{rollback}\"",
                        approval_id
                    );
                }
                return err.into_response();
            }
        }
    } else {
        None
    };

    log::info!(
        "event=ActionApprovalIssued approval_id={} agent_id={} command_id={}",
        approval.approval_id,
        approval.agent_id,
        dispatched_command_id.as_deref().unwrap_or("-")
    );
    Json(IssueResponse {
        approval: approval_view(&approval, votes, true),
        dispatched_command_id,
    })
    .into_response()
}

/// 校验一份**外部签发**的 attestation，通过后写回 `plan.attestation`。
///
/// 这是外部签发模式的安全核心：**七条校验一条都不能省**。它只回答
/// 「这份签名是不是这把已登记钥匙对**这份已批准的计划**签的」，
/// 不回答「这台机器该不该执行」—— 后者是 agentd 的锚。
///
/// 特别防「confused deputy」：计划原文**只从库里读**，不信任请求体里的任何计划字段；
/// 请求体里只有一份 `attestation`。
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
async fn apply_external_attestation(
    state: &ApiState,
    approval: &StoredActionApproval,
    approvers: &[String],
    required: u8,
    plan: &mut ActionPlan,
    attestation: wist_contracts::action_plan::ActionPlanAttestation,
    now: DateTime<Utc>,
) -> Result<(), Response> {
    // 1) 形状：只有把证明挂上去才能校验它（`wist-validate` 是「整份计划」的校验）。
    let mut candidate = plan.clone();
    candidate.attestation = Some(attestation.clone());
    if let Err(err) = wist_validate::action_plan::validate_action_plan(&candidate) {
        return Err(ApiError::bad_request(
            codes::ATTESTATION_INVALID,
            format!("attestation shape is invalid: {}", err.code),
        )
        .into_response());
    }

    // 2) 摘要：审批时的、现在重算的、证明里写的，三者必须一致。
    let recomputed = plan_digest(&candidate);
    if recomputed != approval.plan_digest || attestation.plan_digest != recomputed {
        return Err(ApiError::conflict(
            codes::PLAN_DIGEST_MISMATCH,
            format!(
                "plan changed since approval (approved {}, now {recomputed}, attested {})",
                approval.plan_digest, attestation.plan_digest
            ),
        )
        .into_response());
    }

    // 3) 审批单：不能拿 A 单的签名去签 B 单。
    if attestation.approval.approval_id != approval.approval_id {
        return Err(ApiError::conflict(
            codes::APPROVAL_MISMATCH,
            format!(
                "attestation is for approval {} but issuing {}",
                attestation.approval.approval_id, approval.approval_id
            ),
        )
        .into_response());
    }

    // 4) 审批事实：签名方不能自己往里塞“多一个人”或改人数下限。
    let mut expected: Vec<String> = approvers.to_vec();
    expected.sort();
    let mut claimed: Vec<String> = attestation.approval.approvers.clone();
    claimed.sort();
    if claimed != expected {
        return Err(ApiError::conflict(
            codes::APPROVAL_MISMATCH,
            format!("attestation approvers {claimed:?} do not match recorded votes {expected:?}"),
        )
        .into_response());
    }
    if attestation.approval.required_approvers != required {
        return Err(ApiError::conflict(
            codes::APPROVAL_MISMATCH,
            format!(
                "attestation required_approvers {} != recorded {required}",
                attestation.approval.required_approvers
            ),
        )
        .into_response());
    }

    // 5) 风险：不能「批了 R1、跑 R2」。
    if attestation.risk_level != plan.constraints.risk_level {
        return Err(ApiError::conflict(
            codes::APPROVAL_RISK_MISMATCH,
            format!(
                "attestation risk {} != plan risk {:?}",
                risk_level_wire(attestation.risk_level),
                plan.constraints.risk_level
            ),
        )
        .into_response());
    }

    // 6) 有效期：证明不能已过期，也不能活得比计划长。
    let Some(expires) = parse_ts(&attestation.expires_at) else {
        return Err(ApiError::bad_request(
            codes::ATTESTATION_INVALID,
            "attestation expires_at is not RFC3339",
        )
        .into_response());
    };
    if expires <= now {
        return Err(ApiError::conflict(
            codes::ATTESTATION_INVALID,
            format!("attestation expired at {}", attestation.expires_at),
        )
        .into_response());
    }
    if let Some(plan_expires) = parse_ts(&plan.meta.expires_at)
        && expires > plan_expires
    {
        return Err(ApiError::bad_request(
            codes::ATTESTATION_INVALID,
            format!(
                "attestation expires_at {} is later than plan expires_at {}",
                attestation.expires_at, plan.meta.expires_at
            ),
        )
        .into_response());
    }

    // 7) 钥匙已登记、未吊销，且签名验得过。
    // 先区分「一条都没登记」与「这把没登记」：前者是还没配外部签发，后者可能是填错 key_id。
    match state.store.list_approver_keys().await {
        Ok(keys) if keys.is_empty() => {
            return Err(ApiError::unavailable(
                codes::APPROVER_KEY_UNREGISTERED,
                "no approver key registered; import one before using external signing",
            )
            .into_response());
        }
        Ok(_) => {}
        Err(err) => {
            return Err(ApiError::internal(
                codes::APPROVER_KEY_STORE_FAILED,
                "failed to list approver keys",
                err,
            )
            .into_response());
        }
    }
    let key = match state.store.get_approver_key(&attestation.key_id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            return Err(ApiError::conflict(
                codes::APPROVER_KEY_UNKNOWN,
                format!("approver key {} is not registered", attestation.key_id),
            )
            .into_response());
        }
        Err(err) => {
            return Err(ApiError::internal(
                codes::APPROVER_KEY_STORE_FAILED,
                "failed to load approver key",
                err,
            )
            .into_response());
        }
    };
    if !key.is_active() {
        return Err(ApiError::conflict(
            codes::APPROVER_KEY_REVOKED,
            format!("approver key {} has been revoked", attestation.key_id),
        )
        .into_response());
    }
    let fingerprint = match crate::api::approver_keys::verify_attestation_signature(
        &key.public_key,
        &attestation.signing_payload(),
        &attestation.signature,
    ) {
        Ok(fingerprint) => fingerprint,
        Err(code) => {
            return Err(ApiError::bad_request(
                code,
                "attestation signature does not verify against the registered key",
            )
            .into_response());
        }
    };
    // `issued_by` 在签名覆盖范围内，改不了；只如实记下并与登记属主比对（审计用）。
    if attestation.issued_by != key.owner {
        log::warn!(
            "event=ApproverKeyOwnerMismatch approval_id={} key_id={} declared_issued_by={} registered_owner={}",
            approval.approval_id,
            log_field(&key.key_id),
            log_field(&attestation.issued_by),
            log_field(&key.owner)
        );
    }
    log::info!(
        "event=ApprovalIssuedExternal approval_id={} agent_id={} key_id={} fingerprint={} issued_by={}",
        approval.approval_id,
        approval.agent_id,
        log_field(&key.key_id),
        fingerprint,
        log_field(&attestation.issued_by)
    );
    plan.attestation = Some(attestation);
    Ok(())
}

#[allow(clippy::result_large_err)]
async fn load_approval(
    state: &ApiState,
    approval_id: &str,
) -> Result<StoredActionApproval, Response> {
    match state.store.get_action_approval(approval_id).await {
        Ok(Some(approval)) => Ok(approval),
        Ok(None) => Err(ApiError::not_found(
            codes::APPROVAL_NOT_FOUND,
            format!("unknown approval {approval_id}"),
        )
        .into_response()),
        Err(err) => {
            Err(
                ApiError::internal(codes::APPROVAL_LOAD_FAILED, "failed to load approval", err)
                    .into_response(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 同一微秒内连续分配也必须互不相同：只靠时间戳会撞主键 → 给调用方一个 500。
    #[test]
    fn approval_ids_are_unique_within_the_same_microsecond() {
        let now = DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .expect("parse")
            .with_timezone(&Utc);
        let ids: std::collections::BTreeSet<String> =
            (0..1000).map(|_| new_approval_id("agent-1", now)).collect();
        assert_eq!(ids.len(), 1000, "id 必须互不相同");
        assert!(ids.iter().all(|id| id.starts_with("apv_agent-1_")));
    }

    #[test]
    fn risk_levels_map_to_the_expected_minimums() {
        assert_eq!(required_approvers_for(RiskLevel::R0), 0);
        assert_eq!(required_approvers_for(RiskLevel::R1), 0);
        assert_eq!(required_approvers_for(RiskLevel::R2), 1);
        assert_eq!(required_approvers_for(RiskLevel::R3), 1);
    }

    #[test]
    fn risk_level_wire_names_match_the_contract() {
        for risk in [RiskLevel::R0, RiskLevel::R1, RiskLevel::R2, RiskLevel::R3] {
            let wire = risk_level_wire(risk);
            assert_eq!(risk_level_from_wire(wire), Some(risk));
            assert_eq!(serde_json::to_value(risk).expect("wire"), wire);
        }
    }

    #[test]
    fn timestamps_round_trip_as_utc_seconds() {
        let now = DateTime::parse_from_rfc3339("2026-06-01T12:34:56.789Z")
            .expect("parse")
            .with_timezone(&Utc);
        let rendered = format_ts(now);
        assert_eq!(rendered, "2026-06-01T12:34:56Z");
        assert_eq!(parse_ts(&rendered), Some(now - Duration::milliseconds(789)));
    }

    fn vote(approver: &str, decision: &str) -> StoredActionApprovalVote {
        StoredActionApprovalVote {
            approval_id: "apv-1".to_string(),
            approver: approver.to_string(),
            decision: decision.to_string(),
            comment: None,
            voted_at: "2026-06-01T00:00:00Z".to_string(),
        }
    }

    fn now_ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .expect("parse")
            .with_timezone(&Utc)
    }

    #[test]
    fn one_approval_meets_an_r2_quorum() {
        let votes = vec![vote("admin:a", "approve")];
        let (status, approved_at) = next_approval_status(1, &votes, now_ts());
        assert_eq!(status, "approved");
        assert_eq!(approved_at.as_deref(), Some("2026-06-01T00:00:00Z"));
    }

    #[test]
    fn too_few_approvals_stay_pending() {
        let votes = vec![vote("admin:a", "approve")];
        let (status, approved_at) = next_approval_status(2, &votes, now_ts());
        assert_eq!(status, "pending");
        assert!(approved_at.is_none());
    }

    /// 一票否决优先：`approve` 再多也不能把已经 `reject` 的单子翻回来。
    #[test]
    fn a_rejection_wins_over_enough_approvals() {
        let votes = vec![vote("admin:a", "approve"), vote("admin:b", "reject")];
        let (status, approved_at) = next_approval_status(1, &votes, now_ts());
        assert_eq!(status, "rejected");
        assert!(approved_at.is_none());
    }

    /// 存坏的 `required_approvers`（`<= 0`）不能变成“零人就能批”。
    #[test]
    fn a_non_positive_quorum_never_auto_approves_without_a_vote() {
        let (status, _) = next_approval_status(-1, &[], now_ts());
        assert_eq!(status, "pending");
    }

    #[test]
    fn the_brief_view_omits_plan_bodies() {
        let approval = StoredActionApproval {
            approval_id: "apv-1".to_string(),
            agent_id: "agent-1".to_string(),
            plan_digest: "plan-v1:sha256:00".to_string(),
            risk_level: "R2".to_string(),
            requested_by: "admin:a".to_string(),
            reason: None,
            requested_at: "2026-06-01T00:00:00Z".to_string(),
            plan_json: "{\"kind\":\"action_plan\"}".to_string(),
            required_approvers: 1,
            status: "pending".to_string(),
            approved_at: None,
            expires_at: "2026-06-02T00:00:00Z".to_string(),
            issued_plan_json: Some("{\"kind\":\"action_plan\"}".to_string()),
        };
        let brief = approval_view(&approval, Vec::new(), false);
        assert!(brief.plan.is_none());
        assert!(brief.issued_plan.is_none());
        assert!(brief.issued, "issued 标记不能因为不带原文就丢掉");

        let full = approval_view(&approval, Vec::new(), true);
        assert!(full.plan.is_some());
        assert!(full.issued_plan.is_some());
    }
}
