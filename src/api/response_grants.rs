//! 响应授权单（时间窗授权）：`/api/v1/admin/agents/{id}/response-grant`。
//!
//! 这是与 `action_approval` **并列**的第二条授权来源：
//!
//! * `action_approval`：人批了**这一份**计划（绑 `plan_digest`，一次一审）；
//! * `response_grant`：给这台机器一段**有期限**的窗口，窗口内满足风险上限的动作可以直接下发。
//!
//! 授权单是「提前批发出去的审批权」，所以比单次审批更严：
//!
//! 1. **必须有期限** —— 请求用 `duration_minutes` 而不是绝对时刻（客户端时钟不可信），
//!    服务端按自己的墙钟算 `not_after`；范围 `15min..=7d`，**没有"无限期"这个选项**。
//! 2. **风险上限一期封在 R2** —— R3 是破坏性动作，必须一次一议。
//! 3. **撤销是软删** —— 打 `revoked_at`，行留着，审计要能回答"谁什么时候撤的"。
//!
//! 放行时网关用同一把 `[plan_signing]` 私钥**即时签发**证明（`approval_id = grant_id`），
//! 所以 agentd 看到的仍是一份"摘要对得上、签名验得过"的计划，本地终审逻辑不需要改。

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use wist_contracts::action_plan::{ActionPlan, RiskLevel, plan_digest};

use crate::api::admin_auth::{admin_actor, require_admin_bearer};
use crate::api::admin_ops::agent_not_found_response;
use crate::api::error::ApiError;
use crate::api::{ApiState, action_plans, codes, rate_limit};
use crate::infra::StoredResponseGrant;

/// 默认窗口：一天。够一次排障/一次巡检，又不至于"给忘了"。
pub const DEFAULT_GRANT_MINUTES: u32 = 24 * 60;
/// 上限 7 天。再长就不该叫"临时授权"了。
pub const MAX_GRANT_MINUTES: u32 = 7 * 24 * 60;
/// 下限 15 分钟：比这更短，签发动作本身比窗口还费事。
pub const MIN_GRANT_MINUTES: u32 = 15;

/// 一期允许授权单覆盖到的最高风险。
const MAX_GRANT_RISK: RiskLevel = RiskLevel::R2;

fn default_grant_minutes() -> u32 {
    DEFAULT_GRANT_MINUTES
}

fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::R0 => 0,
        RiskLevel::R1 => 1,
        RiskLevel::R2 => 2,
        RiskLevel::R3 => 3,
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

fn parse_risk(value: &str) -> Option<RiskLevel> {
    match value.trim() {
        "R0" => Some(RiskLevel::R0),
        "R1" => Some(RiskLevel::R1),
        "R2" => Some(RiskLevel::R2),
        "R3" => Some(RiskLevel::R3),
        _ => None,
    }
}

fn parse_ts(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

fn format_ts(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// 授权单实例号：`grn_{agent_id}_{micros}_{rand4}`。
///
/// 每次签发都换新号（哪怕签给同一台机器）：审计要能区分"同一张单"与"撤销后重签"。
fn new_grant_id(agent_id: &str, now: DateTime<Utc>) -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut suffix = [0u8; 4];
    if SystemRandom::new().fill(&mut suffix).is_ok() {
        let hex: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("grn_{agent_id}_{}_{hex}", now.timestamp_micros())
    } else {
        // 随机源不可用是极端情况：退回时间戳（重复只会让审计看起来更密，不影响判定）。
        format!("grn_{agent_id}_{}", now.timestamp_micros())
    }
}

/// 授权单的**生效状态**。由服务端算好，前端不自己比时间（客户端时钟不可信）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    /// 窗口内，可用。
    Active,
    /// 还没到 `not_before`。
    Pending,
    /// 过了 `not_after`。
    Expired,
    /// 已撤销（`revoked_at` 非空）—— 即使时间还在窗口内也无效。
    Revoked,
}

impl GrantState {
    fn wire(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

pub fn grant_state(grant: &StoredResponseGrant, now: DateTime<Utc>) -> GrantState {
    if grant.revoked_at.is_some() {
        return GrantState::Revoked;
    }
    let Some(not_before) = parse_ts(&grant.not_before) else {
        return GrantState::Expired;
    };
    let Some(not_after) = parse_ts(&grant.not_after) else {
        return GrantState::Expired;
    };
    if now < not_before {
        return GrantState::Pending;
    }
    if now >= not_after {
        return GrantState::Expired;
    }
    GrantState::Active
}

/// 一次下发能否被这张授权单放行。
pub enum GrantDecision<'a> {
    /// 放行，并把放行所依据的那张单子带出去（调用方要用它签发证明）。
    Allowed(&'a StoredResponseGrant),
    /// 拒绝时的稳定原因码 + 给运维看的说明。
    Denied { code: &'static str, detail: String },
}

/// 判定：状态 → 风险上限 → opcode 白名单。
///
/// 顺序是刻意的：先说"这张单子现在能不能用"，再说"这个动作在不在范围内" —— 反过来会让
/// "授权早过期了"被报成"风险不够"，运维会去改风险上限而不是续期。
pub fn evaluate_grant<'a>(
    grant: Option<&'a StoredResponseGrant>,
    risk: RiskLevel,
    ops: &[String],
    now: DateTime<Utc>,
) -> GrantDecision<'a> {
    let Some(grant) = grant else {
        return GrantDecision::Denied {
            code: codes::RESPONSE_GRANT_MISSING,
            detail: "这台机器还没有响应授权单：先在「响应授权」页给它签发一段时间窗授权"
                .to_string(),
        };
    };
    match grant_state(grant, now) {
        GrantState::Active => {}
        GrantState::Pending => {
            return GrantDecision::Denied {
                code: codes::RESPONSE_GRANT_NOT_YET_VALID,
                detail: format!("授权单要到 {} 才生效", grant.not_before),
            };
        }
        GrantState::Expired => {
            return GrantDecision::Denied {
                code: codes::RESPONSE_GRANT_EXPIRED,
                detail: format!("授权单已于 {} 到期，需要重新签发", grant.not_after),
            };
        }
        GrantState::Revoked => {
            return GrantDecision::Denied {
                code: codes::RESPONSE_GRANT_REVOKED,
                detail: "授权单已被撤销".to_string(),
            };
        }
    }

    let Some(granted_risk) = parse_risk(&grant.max_risk) else {
        return GrantDecision::Denied {
            code: codes::RESPONSE_GRANT_INVALID,
            detail: format!("存下来的授权单风险上限不合法：{}", grant.max_risk),
        };
    };
    if risk_rank(risk) > risk_rank(granted_risk) {
        return GrantDecision::Denied {
            code: codes::RESPONSE_GRANT_INSUFFICIENT,
            detail: format!(
                "计划风险 {} 超过授权单上限 {}",
                risk_level_wire(risk),
                risk_level_wire(granted_risk)
            ),
        };
    }

    if let Some(allowed) = grant.opcodes.as_deref() {
        for op in ops {
            if !allowed.iter().any(|candidate| candidate == op) {
                return GrantDecision::Denied {
                    code: codes::RESPONSE_GRANT_INSUFFICIENT,
                    detail: format!("op `{op}` 不在授权单的 opcode 白名单里"),
                };
            }
        }
    }

    GrantDecision::Allowed(grant)
}

// ── HTTP ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutResponseGrantRequest {
    /// `R0` / `R1` / `R2`（`R3` 一期不允许）。
    pub max_risk: String,
    /// 可选 opcode 白名单；省略 = 不按 op 收窄（仍受 `max_risk` 约束）。
    #[serde(default)]
    pub opcodes: Option<Vec<String>>,
    /// 窗口长度（分钟）。省略 = 默认 24h（`DEFAULT_GRANT_MINUTES`）。
    ///
    /// 允许省略但仍然**不可能无限期**：服务端总是会落一个有限的 `not_after`。
    #[serde(default = "default_grant_minutes")]
    pub duration_minutes: u32,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResponseGrantView {
    pub grant_id: String,
    pub max_risk: String,
    pub opcodes: Option<Vec<String>>,
    pub not_before: String,
    pub not_after: String,
    pub reason: Option<String>,
    pub granted_by: String,
    pub granted_at: String,
    pub revoked_at: Option<String>,
    /// `active` / `pending` / `expired` / `revoked`（服务端按自己的时钟判定）。
    pub state: String,
    /// 距离到期还有多少秒；非 `active` 时为 `0`。
    pub remaining_seconds: i64,
}

#[derive(Debug, Serialize)]
pub struct ResponseGrantResponse {
    pub agent_id: String,
    /// `null` = 这台机器从未签发过授权单。
    pub grant: Option<ResponseGrantView>,
}

fn grant_view(grant: &StoredResponseGrant, now: DateTime<Utc>) -> ResponseGrantView {
    let state = grant_state(grant, now);
    let remaining_seconds = if state == GrantState::Active {
        parse_ts(&grant.not_after)
            .map(|not_after| (not_after - now).num_seconds().max(0))
            .unwrap_or(0)
    } else {
        0
    };
    ResponseGrantView {
        grant_id: grant.grant_id.clone(),
        max_risk: grant.max_risk.clone(),
        opcodes: grant.opcodes.clone(),
        not_before: grant.not_before.clone(),
        not_after: grant.not_after.clone(),
        reason: grant.reason.clone(),
        granted_by: grant.granted_by.clone(),
        granted_at: grant.granted_at.clone(),
        revoked_at: grant.revoked_at.clone(),
        state: state.wire().to_string(),
        remaining_seconds,
    }
}

async fn load_grant(
    state: &ApiState,
    agent_id: &str,
) -> Result<Option<StoredResponseGrant>, Response> {
    state
        .store
        .get_response_grant(agent_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::RESPONSE_GRANT_STORE_FAILED,
                "failed to load response grant",
                err,
            )
            .into_response()
        })
}

async fn grant_response(state: &ApiState, agent_id: String) -> Result<Response, Response> {
    let grant = load_grant(state, &agent_id).await?;
    let now = Utc::now();
    Ok(Json(ResponseGrantResponse {
        agent_id,
        grant: grant.as_ref().map(|grant| grant_view(grant, now)),
    })
    .into_response())
}

/// `GET /api/v1/admin/agents/{agent_id}/response-grant`
pub async fn get_response_grant(
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
    match grant_response(&state, agent_id).await {
        Ok(response) => response,
        Err(response) => response,
    }
}

/// `PUT /api/v1/admin/agents/{agent_id}/response-grant`：签发 / 重新签发（覆盖）。
pub async fn put_response_grant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
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
            codes::RESPONSE_GRANT_INVALID,
            "response grant body is required",
        )
        .into_response();
    };
    let request: PutResponseGrantRequest = match serde_json::from_value(input) {
        Ok(request) => request,
        Err(err) => {
            return ApiError::bad_request(
                codes::RESPONSE_GRANT_INVALID,
                format!("invalid response grant request: {err}"),
            )
            .into_response();
        }
    };

    let Some(max_risk) = parse_risk(&request.max_risk) else {
        return ApiError::bad_request(
            codes::RESPONSE_GRANT_INVALID,
            format!(
                "unknown risk level {:?} (expected R0 / R1 / R2)",
                request.max_risk
            ),
        )
        .into_response();
    };
    if risk_rank(max_risk) > risk_rank(MAX_GRANT_RISK) {
        return ApiError::bad_request(
            codes::RESPONSE_GRANT_INVALID,
            format!(
                "risk level {} cannot be covered by a time-window grant (max {}); \
                 destructive actions must be approved one by one",
                risk_level_wire(max_risk),
                risk_level_wire(MAX_GRANT_RISK)
            ),
        )
        .into_response();
    }
    if !(MIN_GRANT_MINUTES..=MAX_GRANT_MINUTES).contains(&request.duration_minutes) {
        return ApiError::bad_request(
            codes::RESPONSE_GRANT_INVALID,
            format!(
                "duration_minutes must be between {MIN_GRANT_MINUTES} and {MAX_GRANT_MINUTES} \
                 (got {}); open-ended grants are not allowed",
                request.duration_minutes
            ),
        )
        .into_response();
    }

    // 白名单只做形状校验：网关没有 opcode 注册表（那是 agentd 的），
    // 未知 op 会被 agentd 在执行/能力闸拒掉。这里拦住空串与重复。
    let opcodes = match request.opcodes {
        None => None,
        Some(raw) => {
            let mut cleaned: Vec<String> = Vec::with_capacity(raw.len());
            for op in raw {
                let trimmed = op.trim();
                if trimmed.is_empty() {
                    return ApiError::bad_request(
                        codes::RESPONSE_GRANT_INVALID,
                        "opcodes must not contain empty entries",
                    )
                    .into_response();
                }
                if !cleaned.iter().any(|existing| existing == trimmed) {
                    cleaned.push(trimmed.to_string());
                }
            }
            if cleaned.is_empty() {
                // 空数组与「不限制」是两件事：空数组会让任何 op 都过不了，
                // 与其让人以为"允许全部"，不如明确拒绝。
                return ApiError::bad_request(
                    codes::RESPONSE_GRANT_INVALID,
                    "opcodes must not be an empty array; omit the field to allow all opcodes \
                     within max_risk",
                )
                .into_response();
            }
            Some(cleaned)
        }
    };

    let now = Utc::now();
    let grant = StoredResponseGrant {
        agent_id: agent_id.clone(),
        grant_id: new_grant_id(&agent_id, now),
        max_risk: risk_level_wire(max_risk).to_string(),
        opcodes,
        not_before: format_ts(now),
        not_after: format_ts(now + Duration::minutes(i64::from(request.duration_minutes))),
        reason: request.reason,
        granted_by: admin_actor(&state.config),
        granted_at: format_ts(now),
        revoked_at: None,
    };
    if let Err(err) = state.store.upsert_response_grant(&grant).await {
        return ApiError::internal(
            codes::RESPONSE_GRANT_STORE_FAILED,
            "failed to save response grant",
            err,
        )
        .into_response();
    }
    log::info!(
        "event=ResponseGrantIssued agent_id={agent_id} grant_id={} max_risk={} not_after={} by={}",
        grant.grant_id,
        grant.max_risk,
        grant.not_after,
        grant.granted_by
    );
    match grant_response(&state, agent_id).await {
        Ok(response) => response,
        Err(response) => response,
    }
}

/// `DELETE /api/v1/admin/agents/{agent_id}/response-grant`：撤销（软删）。
///
/// 撤销后仍返回视图（`state = revoked`）—— 比 404 更能回答"它是什么时候被撤的"。
pub async fn delete_response_grant(
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
    let revoked_at = format_ts(Utc::now());
    match state
        .store
        .revoke_response_grant(&agent_id, &revoked_at)
        .await
    {
        Ok(true) => log::info!(
            "event=ResponseGrantRevoked agent_id={agent_id} by={}",
            admin_actor(&state.config)
        ),
        // 没有生效中的单子：不当作错误（撤销是幂等的），但仍然如实返回当前视图。
        Ok(false) => {}
        Err(err) => {
            return ApiError::internal(
                codes::RESPONSE_GRANT_STORE_FAILED,
                "failed to revoke response grant",
                err,
            )
            .into_response();
        }
    }
    match grant_response(&state, agent_id).await {
        Ok(response) => response,
        Err(response) => response,
    }
}

/// 走授权单放行时，把计划和证明补成"可下发的样子"。
///
/// 三件事必须按顺序：写 `approval_ref` → 算摘要 → 签。摘要包含 `approval_ref`，
/// 先算后写会让签名对不上一份被改过的计划。
///
/// 返回 `Ok(true)` = 已签发；`Ok(false)` = 没有签发私钥、但风险等级不需要证明（R0/R1）。
#[allow(clippy::result_large_err)]
pub(crate) fn authorize_under_grant(
    state: &ApiState,
    plan: &mut ActionPlan,
    grant: &StoredResponseGrant,
    now: DateTime<Utc>,
) -> Result<bool, Response> {
    let risk = plan.constraints.risk_level;
    let needs_proof = risk_rank(risk) > 0;
    let Some(signer) = state.config.plan_signer.clone() else {
        if needs_proof {
            // 不降级：一份没有证明的写动作在 `enforced = true` 的机器上会被拒，
            // 与其让它在机器上失败，不如在这里说清「去配 [plan_signing]」。
            return Err(ApiError::unavailable(
                codes::PLAN_SIGNING_UNAVAILABLE,
                "gateway has no plan signing key ([plan_signing] key_file); \
                 write actions cannot be dispatched under a grant without a proof",
            )
            .into_response());
        }
        // R0/R1：agentd 不要求证明，照常下发，只是审计里没有 attestation。
        plan.constraints.approval_ref = Some(grant.grant_id.clone());
        plan.constraints.approval_mode = wist_contracts::action_plan::ApprovalMode::NotRequired;
        return Ok(false);
    };

    plan.constraints.approval_ref = Some(grant.grant_id.clone());
    plan.constraints.approval_mode = wist_contracts::action_plan::ApprovalMode::Required;
    let digest = plan_digest(plan);
    signer
        .sign(
            plan,
            &grant.grant_id,
            vec![grant.granted_by.clone()],
            1,
            &digest,
            now,
        )
        .map_err(|err| {
            ApiError::internal(
                codes::RESPONSE_GRANT_STORE_FAILED,
                "failed to sign plan under response grant",
                err.to_string(),
            )
            .into_response()
        })?;
    Ok(true)
}

/// 计划里真正会跑的 op（与能力闸同一口径：`required_capabilities` ∪ `steps[].op`）。
pub(crate) fn plan_opcodes(plan: &ActionPlan) -> Vec<String> {
    action_plans::required_opcodes(plan).into_iter().collect()
}
