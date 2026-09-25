//! 灰度发布计划（对应模型 `Control.Rollout`）的管理面接口。
//!
//! 计划是「编排层」：批准/推进时才把阶段内的 target 物化成一件件 `OneShotWork`，
//! 结果经 `ReportWorkResult` 回填到计划条目（见 `reconcile_rollout_entry`）。
//!
//! 发布确认流程：`approve`（确认整份计划、进入第一阶段）与 `advance`（确认进入下一阶段）
//! 是两处人工闸门 —— 灰度发布的「确认无问题再推下一批」就落在这两个动作上。
//! 首版只强制 `manual` 推进；`all_succeeded` / `success_rate:` 自动推进见 `app/rollout.rs` 的缺口。

use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::app::rollout as rules;
use crate::infra::{
    StoredOneShotWork, StoredRolloutPhase, StoredRolloutPlan, StoredRolloutPlanEntry, sha256_hex,
};

use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};

#[derive(Debug, Clone, Deserialize)]
pub struct RolloutPhaseRequest {
    #[serde(default)]
    pub target_ids: Vec<String>,
    pub advance_rule: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRolloutPlanRequest {
    pub action: String,
    pub spec: String,
    pub phases: Vec<RolloutPhaseRequest>,
    pub deadline_at: String,
    pub timeout_seconds: i64,
    #[serde(default)]
    pub batch_size: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlanRefRequest {
    pub plan_id: String,
}

// ── 视图（读投影：模型里只到「计划 + 条目」的形状，汇总计数由实现层派生） ──

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPhaseView {
    pub phase_index: i64,
    pub target_ids: Vec<String>,
    pub advance_rule: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanView {
    pub plan_id: String,
    pub action: String,
    pub spec: String,
    pub deadline_at: String,
    pub timeout_seconds: i64,
    pub phases: Vec<RolloutPhaseView>,
    pub batch_size: i64,
    pub current_phase: i64,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanEntryView {
    pub target_id: String,
    pub work_id: Option<String>,
    pub status: String,
    pub detail: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RolloutPlanDetailView {
    pub plan: RolloutPlanView,
    pub entries: Vec<RolloutPlanEntryView>,
}

fn phase_view(phase: &StoredRolloutPhase) -> RolloutPhaseView {
    RolloutPhaseView {
        phase_index: phase.phase_index,
        target_ids: phase.target_ids.clone(),
        advance_rule: phase.advance_rule.clone(),
        status: phase.status.clone(),
    }
}

fn plan_view(plan: &StoredRolloutPlan) -> RolloutPlanView {
    RolloutPlanView {
        plan_id: plan.plan_id.clone(),
        action: plan.action.clone(),
        spec: plan.spec.clone(),
        deadline_at: plan.deadline_at.clone(),
        timeout_seconds: plan.timeout_seconds,
        phases: plan.phases.iter().map(phase_view).collect(),
        batch_size: plan.batch_size,
        current_phase: plan.current_phase,
        status: plan.status.clone(),
        created_by: plan.created_by.clone(),
        created_at: plan.created_at.clone(),
        approved_by: plan.approved_by.clone(),
        approved_at: plan.approved_at.clone(),
    }
}

fn entry_view(entry: &StoredRolloutPlanEntry) -> RolloutPlanEntryView {
    RolloutPlanEntryView {
        target_id: entry.target_id.clone(),
        work_id: entry.work_id.clone(),
        status: entry.status.clone(),
        detail: entry.detail.clone(),
        updated_at: entry.updated_at.clone(),
    }
}

/// 计划 id：创建时间戳的摘要。同一纳秒内建两份相同计划才可能撞（可接受）。
fn rollout_plan_id(now: &str) -> String {
    format!("plan-{}", &sha256_hex(now)[..12])
}

/// 把请求折算成落库的计划与全量 target 清单（按阶段顺序去重）。
#[allow(clippy::result_large_err)]
fn build_plan(
    input: &CreateRolloutPlanRequest,
) -> Result<(StoredRolloutPlan, Vec<String>), Response> {
    let action = input.action.trim();
    if action.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "action is required").into_response());
    }
    let spec = input.spec.trim();
    if spec.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "spec is required").into_response());
    }
    let deadline_at = input.deadline_at.trim();
    if chrono::DateTime::parse_from_rfc3339(deadline_at).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("deadline_at must be RFC3339, got {deadline_at:?}"),
        )
            .into_response());
    }
    if input.timeout_seconds <= 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "timeout_seconds must be a positive number of seconds",
        )
            .into_response());
    }
    if input.phases.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "phases must name at least one phase",
        )
            .into_response());
    }
    let mut phases = Vec::with_capacity(input.phases.len());
    let mut seen: HashSet<String> = HashSet::new();
    let mut all_targets = Vec::new();
    for (index, phase) in input.phases.iter().enumerate() {
        if phase.target_ids.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("phase {} must name at least one target", index + 1),
            )
                .into_response());
        }
        if let Err(err) = rules::validate_advance_rule(&phase.advance_rule) {
            return Err((StatusCode::BAD_REQUEST, err).into_response());
        }
        for target in &phase.target_ids {
            if !seen.insert(target.clone()) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("target {target} appears in more than one phase"),
                )
                    .into_response());
            }
            all_targets.push(target.clone());
        }
        phases.push(StoredRolloutPhase {
            phase_index: (index + 1) as i64,
            target_ids: phase.target_ids.clone(),
            advance_rule: phase.advance_rule.trim().to_string(),
            status: "pending".to_string(),
        });
    }
    let now = chrono::Utc::now().to_rfc3339();
    let plan = StoredRolloutPlan {
        plan_id: rollout_plan_id(&now),
        action: action.to_string(),
        spec: spec.to_string(),
        deadline_at: deadline_at.to_string(),
        timeout_seconds: input.timeout_seconds,
        phases,
        batch_size: input.batch_size.max(0),
        current_phase: 0,
        status: "draft".to_string(),
        created_by: "admin".to_string(),
        created_at: now,
        approved_by: None,
        approved_at: None,
    };
    Ok((plan, all_targets))
}

/// 把一批 target 物化成一次性工作 + 计划条目（幂等：work_id 确定性）。
#[allow(clippy::result_large_err)]
async fn materialize_targets(
    state: &ApiState,
    plan: &StoredRolloutPlan,
    targets: &[String],
    now: &str,
) -> Result<(), Response> {
    for target in targets {
        let work = rules::build_one_shot_work(plan, target, now);
        let work_id = work.work_id.clone();
        if let Err(err) = state
            .store
            .save_one_shot_work(&StoredOneShotWork {
                work,
                pre_pause_status: None,
            })
            .await
        {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store one-shot work: {err}"),
            )
                .into_response());
        }
        // 物化出工作后 bump 该 target 的授权序号：agent 下一次 poll_work 就能看到它。
        if let Err(err) = state.store.next_work_sequence(target, now).await {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to bump work sequence: {err}"),
            )
                .into_response());
        }
        let entry = StoredRolloutPlanEntry {
            plan_id: plan.plan_id.clone(),
            target_id: target.clone(),
            work_id: Some(work_id),
            status: "dispatched".to_string(),
            detail: String::new(),
            updated_at: now.to_string(),
        };
        if let Err(err) = state.store.upsert_rollout_plan_entry(&entry).await {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store rollout plan entry: {err}"),
            )
                .into_response());
        }
    }
    Ok(())
}

/// 阶段开始时物化第一批（受 `batch_size` 节流）。
#[allow(clippy::result_large_err)]
async fn materialize_phase_start(
    state: &ApiState,
    plan: &StoredRolloutPlan,
    phase: &StoredRolloutPhase,
    now: &str,
) -> Result<(), Response> {
    let targets = rules::phase_start_targets(phase, plan.batch_size);
    materialize_targets(state, plan, &targets, now).await
}

/// 终态结果回填后，补够 `batch_size` 台在飞（节流）。
#[allow(clippy::result_large_err)]
async fn refill_phase(
    state: &ApiState,
    plan: &StoredRolloutPlan,
    phase: &StoredRolloutPhase,
    entries: &[StoredRolloutPlanEntry],
    now: &str,
) -> Result<(), Response> {
    let targets = rules::next_refill_targets(phase, entries, plan.batch_size);
    if targets.is_empty() {
        return Ok(());
    }
    materialize_targets(state, plan, &targets, now).await
}

/// 把一份 `rolling` 计划推进一个阶段（标记当前阶段 completed，物化下一阶段，或收敛为 completed）。
#[allow(clippy::result_large_err)]
async fn advance_plan(state: &ApiState, plan: &mut StoredRolloutPlan) -> Result<(), Response> {
    let idx = plan.current_phase as usize;
    let now = chrono::Utc::now().to_rfc3339();
    plan.phases[idx - 1].status = "completed".to_string();
    if idx == plan.phases.len() {
        plan.status = "completed".to_string();
    } else {
        let next_phase = plan.phases[idx].clone();
        materialize_phase_start(state, plan, &next_phase, &now).await?;
        plan.phases[idx].status = "rolling".to_string();
        plan.current_phase = (idx + 1) as i64;
    }
    if let Err(err) = state.store.save_rollout_plan(plan).await {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store rollout plan: {err}"),
        )
            .into_response());
    }
    Ok(())
}

/// 终态结果回填后推进阶段：先补够 `batch_size` 台在飞，再按 `advance_rule` 自动推进。
///
/// 只对**终态**结果调用（running 只是进度，不释放一个在飞槽位）。失败记日志、不影响结果上报。
async fn progress_phase_after_terminal_result(
    state: &ApiState,
    plan_id: &str,
) -> Result<(), String> {
    let Some(mut plan) = state
        .store
        .get_rollout_plan(plan_id)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Ok(());
    };
    if plan.status != "rolling" {
        return Ok(());
    }
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return Ok(());
    }
    let phase = plan.phases[idx - 1].clone();
    let entries = state
        .store
        .list_rollout_plan_entries(plan_id)
        .await
        .map_err(|err| err.to_string())?;
    let now = chrono::Utc::now().to_rfc3339();

    // 1) 节流：补够 batch_size 台在飞。
    if let Err(response) = refill_phase(state, &plan, &phase, &entries, &now).await {
        return Err(format!("refill rollout phase: {}", response.status()));
    }

    // 2) 自动推进（refill 后重读，因为 refill 可能刚把 pending 物化成 dispatched）。
    if phase.advance_rule == rules::ADVANCE_RULE_MANUAL {
        return Ok(());
    }
    let entries = state
        .store
        .list_rollout_plan_entries(plan_id)
        .await
        .map_err(|err| err.to_string())?;
    let phase_entries: Vec<StoredRolloutPlanEntry> = entries
        .iter()
        .filter(|entry| phase.target_ids.contains(&entry.target_id))
        .cloned()
        .collect();
    if !rules::phase_should_advance(&phase.advance_rule, &phase_entries) {
        return Ok(());
    }
    if let Err(response) = advance_plan(state, &mut plan).await {
        return Err(format!("auto-advance rollout plan: {}", response.status()));
    }
    Ok(())
}

pub async fn create_rollout_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<CreateRolloutPlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let (plan, all_targets) = match build_plan(&input) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // target 存在性校验：物化到不存在的 agent 只会静默落库、永不 poll，不如在建计划时就拒。
    // 用一次「全量 agent id」换 N 次单点查：建计划是低频管理动作，读全量更省。
    let known = match state.store.list_agent_ids().await {
        Ok(ids) => ids.into_iter().collect::<HashSet<_>>(),
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to list agent ids: {err}"),
            )
                .into_response();
        }
    };
    let unknown: Vec<&str> = all_targets
        .iter()
        .map(String::as_str)
        .filter(|target| !known.contains(*target))
        .collect();
    if !unknown.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            format!("unknown target(s): {}", unknown.join(", ")),
        )
            .into_response();
    }
    let now = plan.created_at.clone();
    if let Err(err) = state.store.save_rollout_plan(&plan).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store rollout plan: {err}"),
        )
            .into_response();
    }
    // 条目在创建时先按全量 target 落成 `pending`：未到阶段前就能在视图里看到整个范围。
    for target in &all_targets {
        let entry = StoredRolloutPlanEntry {
            plan_id: plan.plan_id.clone(),
            target_id: target.clone(),
            work_id: None,
            status: "pending".to_string(),
            detail: String::new(),
            updated_at: now.clone(),
        };
        if let Err(err) = state.store.upsert_rollout_plan_entry(&entry).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store rollout plan entry: {err}"),
            )
                .into_response();
        }
    }
    (StatusCode::CREATED, Json(plan_view(&plan))).into_response()
}

pub async fn list_rollout_plans(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_rollout_plans().await {
        Ok(plans) => Json(plans.iter().map(plan_view).collect::<Vec<_>>()).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to list rollout plans: {err}"),
        )
            .into_response(),
    }
}

pub async fn approve_rollout_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<PlanRefRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = input.plan_id.trim().to_string();
    let Some(mut plan) = (match state.store.get_rollout_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load rollout plan: {err}"),
            )
                .into_response();
        }
    }) else {
        return (
            StatusCode::NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
            .into_response();
    };
    if plan.status != "draft" {
        return (
            StatusCode::CONFLICT,
            format!(
                "rollout plan {plan_id} is {}, only draft can be approved",
                plan.status
            ),
        )
            .into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    // 先物化再落状态：物化是幂等的（work_id 确定性 + upsert），半途失败重试安全；
    // 反过来（先落 rolling）会让一次失败把计划停在「已 rolling、但工作没发全」的中间态。
    let first_phase = plan.phases[0].clone();
    if let Err(response) = materialize_phase_start(&state, &plan, &first_phase, &now).await {
        return response;
    }
    plan.status = "rolling".to_string();
    plan.current_phase = 1;
    plan.phases[0].status = "rolling".to_string();
    plan.approved_by = Some("admin".to_string());
    plan.approved_at = Some(now);
    if let Err(err) = state.store.save_rollout_plan(&plan).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store rollout plan: {err}"),
        )
            .into_response();
    }
    Json(plan_view(&plan)).into_response()
}

pub async fn advance_rollout_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<PlanRefRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = input.plan_id.trim().to_string();
    let Some(mut plan) = (match state.store.get_rollout_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load rollout plan: {err}"),
            )
                .into_response();
        }
    }) else {
        return (
            StatusCode::NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
            .into_response();
    };
    if plan.status != "rolling" {
        return (
            StatusCode::CONFLICT,
            format!("rollout plan {plan_id} is {}, not rolling", plan.status),
        )
            .into_response();
    }
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return (
            StatusCode::CONFLICT,
            format!("rollout plan {plan_id} has no phase to advance"),
        )
            .into_response();
    }
    // 推进：当前阶段划 completed，物化下一阶段（受 batch_size 节流）或收敛为 completed。
    if let Err(response) = advance_plan(&state, &mut plan).await {
        return response;
    }
    Json(plan_view(&plan)).into_response()
}

pub async fn view_rollout_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(plan_id): Path<String>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let Some(plan) = (match state.store.get_rollout_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load rollout plan: {err}"),
            )
                .into_response();
        }
    }) else {
        return (
            StatusCode::NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
            .into_response();
    };
    let entries = match state.store.list_rollout_plan_entries(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to list rollout plan entries: {err}"),
            )
                .into_response();
        }
    };
    Json(RolloutPlanDetailView {
        plan: plan_view(&plan),
        entries: entries.iter().map(entry_view).collect(),
    })
    .into_response()
}

/// 结果上报回填：找到这份工作对应的计划条目，把工作状态折算成条目状态；
/// 若是终态结果，再补够 `batch_size` 台在飞、并按 `advance_rule` 自动推进。
pub(crate) async fn reconcile_rollout_result(
    state: &ApiState,
    work_id: &str,
    status: &str,
    detail: &str,
) -> Result<(), String> {
    let store = state.store.as_ref();
    let Some(entry) = store
        .find_rollout_plan_entry_by_work(work_id)
        .await
        .map_err(|err| err.to_string())?
    else {
        // 不是计划物化出来的工作，无条目可回填。
        return Ok(());
    };
    let plan_id = entry.plan_id.clone();
    let mut updated = entry;
    updated.status = rules::entry_status_for(status).to_string();
    updated.detail = detail.to_string();
    updated.updated_at = chrono::Utc::now().to_rfc3339();
    store
        .upsert_rollout_plan_entry(&updated)
        .await
        .map_err(|err| err.to_string())?;

    // running 只是进度，不释放一个在飞槽位，也不谈推进。
    if !matches!(status, "succeeded" | "failed") {
        return Ok(());
    }
    progress_phase_after_terminal_result(state, &plan_id).await
}
