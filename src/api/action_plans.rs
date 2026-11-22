//! 下发执行计划：`POST /api/v1/admin/agents/{agent_id}/plans`。
//!
//! 只做**投递**，不做审批：本端点把一份 `ActionPlan` 写进命令队列，`kind = action_plan`，
//! `params` 就是计划 JSON 原文。真正的本地终审在 agentd（结构 / 过期 / 目标 / 能力 / 审批），
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
//! 3. **不验签**：网关没有 agentd 的信任锚，验签只发生在执行侧。但带 attestation 的计划
//!    会在这里**重算摘要并比对**（`plan_digest_mismatch`）—— 那能拆穿「批完又改」，
//!    而且比让 agentd 几秒后回一条失败 ack 早得多。

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

    // 能力闸：只在计划真的要求了东西时才查（空集 = 没有可拦的）。
    if let Err(response) = ensure_plan_capable(&state, &agent_id, &plan).await {
        return response;
    }

    // 带签发证明：先确认「签的是这一份」。网关不验签（那是 agentd 的事，它才有信任锚），
    // 但摘要不一致意味着审批后被改过 —— 现在回 400 比几秒后一条看不懂的失败 ack 好。
    if let Some(attestation) = plan.attestation.as_ref() {
        let expected = wist_contracts::action_plan::plan_digest(&plan);
        if attestation.plan_digest != expected {
            return ApiError::bad_request(
                codes::PLAN_DIGEST_MISMATCH,
                format!(
                    "plan digest does not match its attestation (attested {}, computed {expected})",
                    attestation.plan_digest
                ),
            )
            .into_response();
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
fn required_opcodes(plan: &ActionPlan) -> BTreeSet<String> {
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
