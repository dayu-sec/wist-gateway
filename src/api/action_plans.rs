//! 下发执行计划：`POST /api/v1/admin/agents/{agent_id}/plans`。
//!
//! 本端点把一份 `ActionPlan` 写进命令队列（`kind = action_plan`，`params` 就是计划 JSON 原文）。
//! 它**不做审批**，但**必须有授权来源**：只处理「靠时间窗授权单放行」这一条路
//! （见 `api/response_grants.rs`）。另一条路是审批 —— 那条由 `issue_approval` 直接入队，
//! 不经过本函数。真正的本地终审在 agentd（结构 / 过期 / 目标 / 能力 / 审批），
//! 因为「这台机器认不认识这个 op」只有它自己知道。
//!
//! 三条刻意的取舍：
//!
//! 1. **不覆盖同 kind 的待执行命令**：两份计划是两件事，覆盖会静默丢一件。
//!    重复投递由 agentd 的 `action_id + plan_digest` 去重。
//! 2. **入队前做能力闸**（E2）：这台机器上报的 `exec_capabilities` 必须包含计划要的
//!    op（`required_capabilities` ∪ `program.steps[].op`）与 `execution_profile`。
//!    **没报过 = 不可用**（`action_plan_capability_unknown`），而不是「什么都会」——
//!    否则管理面上看到的是「命令已下发」，几秒后才变成一条看不懂的失败 ack。
//!    能力闸只是**前置拦截**，agentd 仍会自己再判一遍（两边口径不同：它看真正的注册表）。
//! 3. **不接受客户端自带的 attestation**：网关没有 agentd 的信任锚，无法验证一份证明的真假；
//!    照单全收等于任何人自己造一个证明就能绕过授权。已签发的计划只由网关自己入队
//!    （审批流 `issue_approval` / 授权单放行），不走这个端点。
//! 4. **必须有授权来源**：本端点只处理「靠时间窗授权单放行」这一条路（见 `api/response_grants.rs`）；
//!    没有有效授权单就拒（`response_grant_missing` / `expired` / `insufficient`）。

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use wist_api::status::command_kind;
use wist_contracts::action_plan::{ActionPlan, STEP_KIND_INVOKE};
use wist_contracts::capability_report::ExecCapabilities;

use crate::api::ApiState;
use crate::api::admin_auth::{admin_actor, require_admin_bearer};
use crate::api::admin_ops::{agent_command_response, agent_not_found_response};
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;
use crate::api::response_grants;
use crate::infra::StoredAgentCommand;

/// `POST /api/v1/admin/agents/{agent_id}/plans`
///
/// body 是一份完整的 `ActionPlan`（与 agentd `run-plan --plan` 读的文件同形）。
/// 响应与其它命令端点同形状，前端可以复用命令台账渲染。
pub async fn dispatch_agent_plan(
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
        return ApiError::bad_request(codes::ACTION_PLAN_INVALID, "action plan body is required")
            .into_response();
    };
    let plan: ActionPlan = match serde_json::from_value(input) {
        Ok(plan) => plan,
        Err(err) => {
            return ApiError::bad_request(
                codes::ACTION_PLAN_INVALID,
                format!("invalid action plan: {err}"),
            )
            .into_response();
        }
    };
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

    // 形状校验放在**签发之前**：现在出口会盖一个签名，不能给一份形状非法的计划盖章
    // （签名会把它固化成一份「看起来已授权」的东西）。agentd 仍会再验一遍，两边口径不同。
    if let Err(err) = wist_validate::action_plan::validate_action_plan(&plan) {
        return ApiError::bad_request(
            codes::ACTION_PLAN_INVALID,
            format!("invalid action plan: {}", err.code),
        )
        .into_response();
    }

    // 能力闸：只在计划真的要求了东西时才查（空集 = 没有可拦的）。
    if let Err(response) = ensure_plan_capable(&state, &agent_id, &plan).await {
        return response;
    }

    // 带签发证明的计划只能由**网关自己**签发后下发（审批流 / 授权单），不能接受客户端自带。
    //
    // 为什么：网关没有信任锚（那是 agentd 的），所以它无法验证一份证明的真假 —— 如果这里
    // 照单全收，任何人都能自己造一个 `attestation` 绕过授权，然后靠 `enforced = false` 的
    // 机器放行。真正「已签发」的计划走 `enqueue_plan`（`issue_approval` / 授权单放行），
    // 不经过这个端点。
    if plan.attestation.is_some() {
        return ApiError::bad_request(
            codes::ACTION_PLAN_INVALID,
            "plan already carries an attestation; attested plans are dispatched by the approval \
             flow or under a response grant, not through this endpoint",
        )
        .into_response();
    }

    // 授权闸（见 `response_grants`）：没有有效的授权单就不允许直发。
    //
    // 注意这是**两条并列路径**里的一条：另一条是审批（`issue_approval` 直接入队，
    // 不经过本函数）。所以到这里的计划只有「靠授权单放行」这一条出路。
    let mut plan = plan;
    let now = chrono::Utc::now();
    let grant = match state.store.get_response_grant(&agent_id).await {
        Ok(grant) => grant,
        Err(err) => {
            return ApiError::internal(
                codes::RESPONSE_GRANT_STORE_FAILED,
                "failed to load response grant",
                err,
            )
            .into_response();
        }
    };
    let ops = response_grants::plan_opcodes(&plan);
    match response_grants::evaluate_grant(grant.as_ref(), plan.constraints.risk_level, &ops, now) {
        response_grants::GrantDecision::Allowed(grant) => {
            if let Err(response) =
                response_grants::authorize_under_grant(&state, &mut plan, grant, now)
            {
                return response;
            }
        }
        response_grants::GrantDecision::Denied { code, detail } => {
            return ApiError::forbidden(code, detail).into_response();
        }
    }

    match enqueue_plan(&state, &agent_id, &plan).await {
        Ok(command) => Json(agent_command_response(&agent_id, Some(command))).into_response(),
        Err(err) => err.into_response(),
    }
}

/// 把一份（可能已签发的）计划写进命令队列。
///
/// 抽出来是因为**两个入口**都要用它：E2 的直发（`dispatch_agent_plan`）与 E3 的
/// 审批签发后自动下发（`issue_approval`）。两处各写一遍入库逻辑，`kind` / `requested_by`
/// 这种审计字段迟早会漂。
#[allow(clippy::result_large_err)]
pub(crate) async fn enqueue_plan(
    state: &ApiState,
    agent_id: &str,
    plan: &ActionPlan,
) -> Result<StoredAgentCommand, ApiError> {
    let params = serde_json::to_string(plan).map_err(|err| {
        ApiError::internal(
            codes::AGENT_COMMAND_STORE_FAILED,
            "failed to encode action plan",
            err,
        )
    })?;
    let now = chrono::Utc::now();
    let command = StoredAgentCommand {
        // 微秒做 id：同一毫秒内连发两份计划不能撞成一个（撞了会被 `DO NOTHING` 吞掉）。
        command_id: format!("cmd_{agent_id}_plan_{}", now.timestamp_micros()),
        agent_id: agent_id.to_string(),
        kind: command_kind::ACTION_PLAN.to_string(),
        params,
        requested_at_ms: now.timestamp_millis(),
        acked_at: None,
        claimed_at: None,
        outcome: None,
        detail: None,
        // 审计：与调查 / 刷新同一口径（`admin:<token 指纹>`）。
        requested_by: admin_actor(&state.config),
    };
    // 追加而不是覆盖：两份计划是两件事。
    state
        .store
        .enqueue_agent_command(&command, false)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::AGENT_COMMAND_STORE_FAILED,
                "failed to enqueue action plan",
                err,
            )
        })?;
    Ok(command)
}

/// 能力闸的**唯一入口**：E2 直发与 E3 审批签发后下发都走它。
///
/// 两处各写一遍必然漂（一处忘了 profile、一处忘了并上 `steps[].op`），
/// 而漏掉的代价是「页面说已下发，几秒后一条看不懂的失败 ack」。
#[allow(clippy::result_large_err)]
pub(crate) async fn ensure_plan_capable(
    state: &ApiState,
    agent_id: &str,
    plan: &ActionPlan,
) -> Result<(), Response> {
    let required = required_opcodes(plan);
    if required.is_empty() {
        return Ok(());
    }
    let capabilities = load_exec_capabilities(state, agent_id).await?;
    ensure_capable(
        capabilities.as_ref(),
        &plan.constraints.execution_profile,
        &required,
    )
    .map_err(|error| (*error).into_response())
}

/// 计划真正需要的能力 = `required_capabilities` ∪ `program` 里 `invoke` 步的 `op`。
///
/// 为什么要带上后者：`required_capabilities` 是计划作者的**声明**，它可以漏写；
/// 真正会跑的却是 `steps[].op`。两边取并集，漏写的计划也拦得住。
pub(crate) fn required_opcodes(plan: &ActionPlan) -> BTreeSet<String> {
    let mut required: BTreeSet<String> = plan
        .constraints
        .required_capabilities
        .iter()
        .filter(|op| !op.trim().is_empty())
        .cloned()
        .collect();
    for step in &plan.program.steps {
        if step.kind == STEP_KIND_INVOKE
            && let Some(op) = step.op.as_deref()
            && !op.trim().is_empty()
        {
            required.insert(op.to_string());
        }
    }
    required
}

/// 这台 agent 自报的执行能力；`None` = 还没报过（E2 之前的 agentd）。
#[allow(clippy::result_large_err)]
async fn load_exec_capabilities(
    state: &ApiState,
    agent_id: &str,
) -> Result<Option<ExecCapabilities>, Response> {
    match state.store.get_agent(agent_id).await {
        Ok(Some(agent)) => Ok(agent.exec_capabilities),
        Ok(None) => Err(ApiError::not_found(
            codes::AGENT_NOT_FOUND,
            format!("unknown agent {agent_id}"),
        )
        .into_response()),
        Err(err) => {
            Err(
                ApiError::internal(codes::AGENT_STORE_UNAVAILABLE, "failed to load agent", err)
                    .into_response(),
            )
        }
    }
}

/// **能力闸**：这台机器认不认识这份计划要的 op / 执行 profile。
///
/// `None`（从没报过）按**不可用**处理：宁可现在回 409 让人去升级 agentd，
/// 也不要排一条注定被回 `capability_missing` 的计划。
fn ensure_capable(
    capabilities: Option<&ExecCapabilities>,
    profile: &str,
    required: &BTreeSet<String>,
) -> Result<(), Box<ApiError>> {
    let Some(capabilities) = capabilities else {
        return Err(Box::new(ApiError::conflict(
            codes::ACTION_PLAN_CAPABILITY_UNKNOWN,
            "agent has not reported exec capabilities yet \
             (agentd < 0.37.0, or no status report since the upgrade)",
        )));
    };

    let missing: Vec<&str> = required
        .iter()
        .map(String::as_str)
        .filter(|op| !capabilities.opcodes.iter().any(|have| have == op))
        .collect();
    if !missing.is_empty() {
        return Err(Box::new(ApiError::conflict(
            codes::ACTION_PLAN_CAPABILITY_MISSING,
            format!(
                "agent does not support op(s) {} (reported: {})",
                missing.join(", "),
                list_or_none(&capabilities.opcodes)
            ),
        )));
    }

    // profile 也定口径：发给 `agent_exec_v2` 的计划不能落到只会 v1 的机器上。
    if !profile.is_empty()
        && !capabilities
            .execution_profiles
            .iter()
            .any(|have| have == profile)
    {
        return Err(Box::new(ApiError::conflict(
            codes::ACTION_PLAN_CAPABILITY_MISSING,
            format!(
                "agent does not support execution profile {profile:?} (reported: {})",
                list_or_none(&capabilities.execution_profiles)
            ),
        )));
    }

    Ok(())
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}
