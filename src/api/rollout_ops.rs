//! 灰度发布计划（对应模型 `Control.Rollout`）的管理面接口。
//!
//! 计划是「编排层」：批准/推进时才把阶段内的 target 物化成一件件 `OneShotWork`，
//! 结果经 `ReportWorkResult` 回填到计划条目（见 `reconcile_rollout_entry`）。
//!
//! 发布确认流程：`approve`（确认整份计划、进入第一阶段）与 `advance`（确认进入下一阶段）
//! 是两处人工闸门 —— 灰度发布的「确认无问题再推下一批」就落在这两个动作上。
//! 编排口径（批准 / 推进 / 闸门 / 结果回填后自动推进 / 重试重开）在共享 crate
//! `wist_release::plan`（与中心同一份）；本模块只做映射、物化与落库。

use super::codes;
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
    StoredAgentInstallPackage, StoredOneShotWork, StoredRolloutPhase, StoredRolloutPlan,
    StoredRolloutPlanEntry,
};

use super::{
    ApiState, admin_auth::require_admin_bearer, error::ApiError, install::effective_advertise_base,
    install_package, rate_limit,
};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRolloutPlanRequest {
    pub action: String,
    pub spec: String,
    /// 计划要铺到的目标（网关是 agent_id）；阶段由**服务端**按阶梯切分。
    pub target_ids: Vec<String>,
    /// 灰度阶段数（1 个金丝雀 → 10% → 30% → 70% → 全量）。
    pub phase_count: i64,
    pub deadline_at: String,
    pub timeout_seconds: i64,
    #[serde(default)]
    pub batch_size: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlanRefRequest {
    pub plan_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetryRolloutPlanRequest {
    pub plan_id: String,
    /// 要重试的目标；省略 / 为空 = 该计划里**所有**失败目标。
    #[serde(default)]
    pub target_ids: Vec<String>,
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

/// 计划 id：`plan-<action>-<yyyyMMdd-HHmmss>-<short>`（口径在共享 crate `wist_release::rollout`）。
fn rollout_plan_id(action: &str, now: &str) -> String {
    wist_release::rollout::plan_id(action, now)
}

/// 把网关的阶段记录 ↔ 共享的中立 [`wist_release::plan::PhaseDraft`] 互转。
///
/// 编排口径（切段 / 批准 / 推进 / 闸门 / 重开）只认中立形状；网关只负责映射、物化与落库。
fn to_drafts(phases: &[StoredRolloutPhase]) -> Vec<wist_release::plan::PhaseDraft> {
    phases
        .iter()
        .map(|phase| wist_release::plan::PhaseDraft {
            index: phase.phase_index,
            target_ids: phase.target_ids.clone(),
            advance_rule: phase.advance_rule.clone(),
            status: phase.status.clone(),
        })
        .collect()
}

fn apply_drafts(phases: &mut [StoredRolloutPhase], drafts: Vec<wist_release::plan::PhaseDraft>) {
    for (phase, draft) in phases.iter_mut().zip(drafts) {
        phase.phase_index = draft.index;
        phase.target_ids = draft.target_ids;
        phase.advance_rule = draft.advance_rule;
        phase.status = draft.status;
    }
}

/// 某阶段各条目的状态（按 target_id 过滤；闸门 / 收尾只看这些）。
fn phase_entry_statuses<'a>(
    entries: &'a [StoredRolloutPlanEntry],
    target_ids: &[String],
) -> Vec<&'a str> {
    entries
        .iter()
        .filter(|entry| target_ids.contains(&entry.target_id))
        .map(|entry| entry.status.as_str())
        .collect()
}

/// agent 上报的 `(os, arch)` → agentd 发布平台（target-triple）。
///
/// agent 用 `std::env::consts::OS` / `ARCH` 自报（macOS-ARM 报 `macos` / `aarch64`），
/// 与 [`install_package`] 的平台集逐字对齐 —— 认不出就返回 `None`（宁可拒，也不猜）。
fn agent_target_triple(os: &str, arch: &str) -> Option<&'static str> {
    match (os.trim(), arch.trim()) {
        ("linux", "x86_64") => Some(install_package::PLATFORM_LINUX_X86),
        ("linux", "aarch64") => Some(install_package::PLATFORM_LINUX_ARM),
        ("macos", "aarch64") | ("macos", "arm64") => Some(install_package::PLATFORM_MACOS_ARM),
        _ => None,
    }
}

/// 计划 spec 的选择方式：按**版本**解析制品（新）还是原样透传（旧 / 显式制品）。
enum PlanSelection {
    /// 按版本：制品按每个目标 agent 的平台在派活时解析。
    Version { version: String },
    /// 显式制品，或不是本形状的旧 spec：整份原样透传给所有目标。
    Explicit,
}

/// 判定一份计划 spec 走哪条路。
///
/// 计划 spec 的形状（网关级，**不是** agentd 吃的 `UpgradeSpec`）：
/// `{"target_version":"<版本>"}`（按版本）或 `{"package_url","package_sha256",…}`（显式制品）。
///
/// - 有非空 `package_url` → **显式制品**（旧），整份透传；
/// - 否则有非空 `target_version` → **按版本**解析；
/// - 否则：键**出现过**但取不出可用值（`""` / `null` / 非字符串）→ 报错（空版本既不安全也不
///   完整，不能当显式透传）；键**从未出现**（`{}` / 非对象 / 非 JSON）→ `Explicit`（旧行为）。
///
/// 用裸 `serde_json::Value` 而不是反序列化进结构体：`Option<String>` 会把「键缺失」与「键在但值是
/// `null` / 非字符串」都读成 `None`，判不出后者是坏 spec。
fn plan_selection(spec: &str) -> Result<PlanSelection, String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(spec) else {
        return Ok(PlanSelection::Explicit); // 非 JSON：原样透传（旧行为）
    };
    let Some(object) = value.as_object() else {
        return Ok(PlanSelection::Explicit); // 非对象：原样透传
    };
    // 取字符串键的 trim 后值；缺键 / 非字符串 / null 一律读作空串。
    let text = |key: &str| -> String {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    if !text("package_url").is_empty() {
        return Ok(PlanSelection::Explicit);
    }
    let version = text("target_version");
    if !version.is_empty() {
        return Ok(PlanSelection::Version { version });
    }
    // 键出现过但取不出可用值 → 坏 spec；从未出现 → 不是本形状，原样透传（不越权改判旧计划）。
    if object.contains_key("package_url") || object.contains_key("target_version") {
        return Err(
            "upgrade spec must carry either a non-empty package_url or a non-empty target_version"
                .to_string(),
        );
    }
    Ok(PlanSelection::Explicit)
}

/// 在安装包历史里选**该版本、该平台**要下发的那一份。
///
/// 历史由 `list_agent_install_packages` 按 `created_at` 倒序给出，所以命中的是**最新**录入的
/// 那一份。建计划与派活都走这一个函数，保证「校验存在的」与「实际下发的」是同一份。
fn select_agent_package<'a>(
    history: &'a [StoredAgentInstallPackage],
    version: &str,
    platform: &str,
) -> Option<&'a StoredAgentInstallPackage> {
    history
        .iter()
        .find(|entry| entry.version.trim() == version && entry.arch.trim() == platform)
}

/// agent 平台查找失败的原因（决定对外状态码）。
enum PlatformError {
    /// 读库失败 —— 基础设施问题，不是调用方的错。`message` 可对外，`cause` 只进日志。
    Store { message: String, cause: String },
    /// 事实层面找不到平台：还没报过 / 平台不在已知发布集。
    Unavailable(String),
}

impl PlatformError {
    /// `unavailable` 是「事实层面找不到平台」时的状态码（建计划取 `400`、派活取 `409`）；
    /// 读库失败一律 `500`。
    fn into_response(self, unavailable: StatusCode) -> Response {
        match self {
            PlatformError::Store { message, cause } => {
                ApiError::internal(codes::ROLLOUT_PLATFORM_STORE_FAILED, message, cause)
                    .into_response()
            }
            PlatformError::Unavailable(message) => {
                ApiError::new(unavailable, codes::ROLLOUT_PLATFORM_UNAVAILABLE, message)
                    .into_response()
            }
        }
    }
}

/// 读某台 agent 的 agentd 发布平台（target-triple）。
///
/// 读库失败与「没有平台」分开回报：前者是基础设施问题（`500`），后者是调用/现状问题。
async fn agent_platform(state: &ApiState, agent_id: &str) -> Result<&'static str, PlatformError> {
    let summary = state
        .store
        .get_agent_fact_summary(agent_id)
        .await
        .map_err(|err| PlatformError::Store {
            message: format!("failed to read agent {agent_id} platform"),
            cause: err.to_string(),
        })?;
    let Some(summary) = summary else {
        return Err(PlatformError::Unavailable(format!(
            "agent {agent_id} has not reported a platform yet"
        )));
    };
    agent_target_triple(&summary.os, &summary.arch).ok_or_else(|| {
        PlatformError::Unavailable(format!(
            "agent {agent_id} platform {}/{} is not a known agentd release platform",
            summary.os, summary.arch
        ))
    })
}

/// 出站给 agentd 的 `upgrade` spec 必须**完整**：`package_url` 与 `package_sha256` 都得是非空
/// 字符串 —— agentd 的 `UpgradeSpec` 对这两个键**没有** serde default，缺了会以 `spec_invalid`
/// 拒绝（`missing field `package_url``）。派活前先在网关这侧校验，把半截 spec 挡在这里，而不是
/// 让它到 agent 上才炸；也能挡住「前端/镜像先升、网关没升」那类版本错配造成的空壳 spec。
fn ensure_agent_upgrade_spec(spec: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(spec)
        .map_err(|err| format!("upgrade spec is not valid JSON: {err}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "upgrade spec must be a JSON object".to_string())?;
    for key in ["package_url", "package_sha256"] {
        let present = object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.trim().is_empty());
        if !present {
            return Err(format!("upgrade spec is missing a non-empty `{key}`"));
        }
    }
    Ok(())
}

/// 解析某目标 agent **实际要执行**的动作 spec。
///
/// 按版本选择的计划：用该 agent 的平台在安装包历史里找到对应制品，填上 `package_url`
/// （内容寻址的网关分发地址）与 `package_sha256`。**不写 `target_version`** —— agentd 要求
/// 它与包内自报版本逐字一致，而计划里存的是**发布版本**（可能带 `v` / 预发布后缀）。
///
/// 从计划 spec **出发**（而不是从零拼）再覆盖制品键，是为了不吞掉计划里带的其它键
/// （如 `allow_downgrade`）。显式制品 / 非本形状 / 非 upgrade 的 spec 原样透传。
#[allow(clippy::result_large_err)]
async fn dispatch_spec_for(
    state: &ApiState,
    plan: &StoredRolloutPlan,
    agent_id: &str,
) -> Result<String, Response> {
    // 只有 upgrade 走版本解析：别的动作就算 spec 里出现 `target_version`，也不替它重建 spec。
    if plan.action != "upgrade" {
        return Ok(plan.spec.clone());
    }
    let selection = plan_selection(&plan.spec).map_err(|message| {
        ApiError::conflict(codes::ROLLOUT_PLAN_SPEC_INVALID, message).into_response()
    })?;
    let PlanSelection::Version { version } = selection else {
        // 显式制品的旧计划：原样透传，但出站前先确认它完整 —— 缺 `package_url` 的 spec 到 agentd
        // 只会以 `spec_invalid` 拒绝，在网关这侧就挡住，报错更清楚。
        ensure_agent_upgrade_spec(&plan.spec).map_err(|message| {
            ApiError::conflict(codes::ROLLOUT_UPGRADE_SPEC_INVALID, message).into_response()
        })?;
        return Ok(plan.spec.clone());
    };
    let platform = agent_platform(state, agent_id)
        .await
        .map_err(|err| err.into_response(StatusCode::CONFLICT))?;
    let history = state
        .store
        .list_agent_install_packages()
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::ROLLOUT_PACKAGE_LIST_FAILED,
                "failed to list agent install packages",
                err,
            )
            .into_response()
        })?;
    let Some(package) = select_agent_package(&history, &version, platform) else {
        return Err(ApiError::conflict(
            codes::ROLLOUT_PACKAGE_NOT_FOUND,
            format!("no agent install package for version {version} on platform {platform}"),
        )
        .into_response());
    };
    let base = effective_advertise_base(&state.config, &state.store).await;
    let package_url = state
        .config
        .agent_package_url_by_id_at(&base, &package.package_id);
    let mut resolved: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&plan.spec).unwrap_or_default();
    resolved.remove("target_version");
    resolved.insert("package_url".into(), serde_json::Value::String(package_url));
    resolved.insert(
        "package_sha256".into(),
        serde_json::Value::String(package.package_sha256.clone()),
    );
    let resolved = serde_json::Value::Object(resolved).to_string();
    ensure_agent_upgrade_spec(&resolved).map_err(|message| {
        ApiError::conflict(codes::ROLLOUT_UPGRADE_SPEC_INVALID, message).into_response()
    })?;
    Ok(resolved)
}

/// 把请求折算成落库的计划与全量 target 清单。
///
/// **阶段由服务端按阶梯切分**（共享口径 `wist_release::rollout::plan_phases`）：客户端只给
/// 目标与阶段数，不再自己切 —— 中心与网关同一套，也免得客户端的 target 清单不可信。
#[allow(clippy::result_large_err)]
fn build_plan(
    input: &CreateRolloutPlanRequest,
) -> Result<(StoredRolloutPlan, Vec<String>), Response> {
    let action = input.action.trim();
    if action.is_empty() {
        return Err(
            ApiError::bad_request(codes::ROLLOUT_ACTION_REQUIRED, "action is required")
                .into_response(),
        );
    }
    let spec = input.spec.trim();
    if spec.is_empty() {
        return Err(
            ApiError::bad_request(codes::ROLLOUT_SPEC_REQUIRED, "spec is required").into_response(),
        );
    }
    let deadline_at = input.deadline_at.trim();
    if chrono::DateTime::parse_from_rfc3339(deadline_at).is_err() {
        return Err(ApiError::bad_request(
            codes::ROLLOUT_DEADLINE_INVALID,
            format!("deadline_at must be RFC3339, got {deadline_at:?}"),
        )
        .into_response());
    }
    if input.timeout_seconds <= 0 {
        return Err(ApiError::bad_request(
            codes::ROLLOUT_TIMEOUT_INVALID,
            "timeout_seconds must be a positive number of seconds",
        )
        .into_response());
    }
    // 目标去重、按阶梯切段、固定闸门策略 —— 口径在共享 crate `wist_release::plan`。
    let drafts = match wist_release::plan::build_phase_drafts(&input.target_ids, input.phase_count)
    {
        Ok(drafts) => drafts,
        Err(err) => {
            return Err(ApiError::bad_request(codes::ROLLOUT_PHASES_INVALID, err).into_response());
        }
    };
    let phases: Vec<StoredRolloutPhase> = drafts
        .into_iter()
        .map(|draft| StoredRolloutPhase {
            phase_index: draft.index,
            target_ids: draft.target_ids,
            advance_rule: draft.advance_rule,
            status: draft.status,
        })
        .collect();
    let all_targets: Vec<String> = phases
        .iter()
        .flat_map(|phase| phase.target_ids.iter().cloned())
        .collect();
    let now = chrono::Utc::now().to_rfc3339();
    let plan = StoredRolloutPlan {
        plan_id: rollout_plan_id(action, &now),
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
        // 按版本选择的计划：制品随**目标 agent 的平台**解析；显式制品的旧计划原样透传。
        let spec = match dispatch_spec_for(state, plan, target).await {
            Ok(spec) => spec,
            Err(response) => return Err(response),
        };
        let work = rules::build_one_shot_work(plan, target, &spec, now);
        let work_id = work.work_id.clone();
        if let Err(err) = state
            .store
            .save_one_shot_work(&StoredOneShotWork {
                work,
                pre_pause_status: None,
            })
            .await
        {
            return Err(ApiError::internal(
                codes::ROLLOUT_WORK_STORE_FAILED,
                "failed to store one-shot work",
                err,
            )
            .into_response());
        }
        // 物化出工作后 bump 该 target 的授权序号：agent 下一次 poll_work 就能看到它。
        if let Err(err) = state.store.next_work_sequence(target, now).await {
            return Err(ApiError::internal(
                codes::ROLLOUT_WORK_SEQUENCE_FAILED,
                "failed to bump work sequence",
                err,
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
            return Err(ApiError::internal(
                codes::ROLLOUT_PLAN_ENTRY_STORE_FAILED,
                "failed to store rollout plan entry",
                err,
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

/// 把一份 `rolling` 计划推进一个阶段（标记当前阶段 completed，物化下一阶段，或**收尾**）。
///
/// 收尾（末阶段）时看本段结果：**有失败就落 `failed`**，否则 `completed` —— 不把失败抹成
/// 「完成」（曾因此让界面把一次失败报成成功）。
#[allow(clippy::result_large_err)]
async fn advance_plan(state: &ApiState, plan: &mut StoredRolloutPlan) -> Result<(), Response> {
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return Ok(());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let entries = match state.store.list_rollout_plan_entries(&plan.plan_id).await {
        Ok(entries) => entries,
        Err(err) => {
            return Err(ApiError::internal(
                codes::ROLLOUT_ENTRY_LIST_FAILED,
                "failed to list rollout plan entries",
                err,
            )
            .into_response());
        }
    };
    // 推进口径在共享 crate：当前段 completed；末段收尾（有失败落 failed），其余进下一段。
    let statuses = phase_entry_statuses(&entries, &plan.phases[idx - 1].target_ids);
    let mut drafts = to_drafts(&plan.phases);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    let step = wist_release::plan::advance(&mut drafts, &mut current_phase, &mut status, &statuses);
    // 进下一段：先物化（共享口径已把该段置 rolling），再落回网关记录。
    if let Some(wist_release::plan::AdvanceStep::NextPhase { index }) = step {
        let draft = &drafts[(index - 1) as usize];
        let next_phase = StoredRolloutPhase {
            phase_index: draft.index,
            target_ids: draft.target_ids.clone(),
            advance_rule: draft.advance_rule.clone(),
            status: draft.status.clone(),
        };
        materialize_phase_start(state, plan, &next_phase, &now).await?;
    }
    apply_drafts(&mut plan.phases, drafts);
    plan.current_phase = current_phase;
    plan.status = status;
    if let Err(err) = state.store.save_rollout_plan(plan).await {
        return Err(ApiError::internal(
            codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err,
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
    //    决策口径在共享 crate：末阶段了结即收尾（不看闸门）；其余段 `manual` 不放行，
    //    `all_succeeded` / `success_rate:` 满足才自动推进。
    let entries = state
        .store
        .list_rollout_plan_entries(plan_id)
        .await
        .map_err(|err| err.to_string())?;
    let statuses = phase_entry_statuses(&entries, &phase.target_ids);
    let mut drafts = to_drafts(&plan.phases);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    let should_advance = wist_release::plan::progress_after_terminal(
        &mut drafts,
        &mut current_phase,
        &mut status,
        &statuses,
    )
    .is_some();
    if should_advance && let Err(response) = advance_plan(state, &mut plan).await {
        return Err(format!("auto-advance rollout plan: {}", response.status()));
    }
    Ok(())
}

/// 读路径上的**自愈**：末阶段已全部了结、计划却还挂在 `rolling` → 收敛为 `completed`。
///
/// 终态结果回填是主要触发点，但网关当时不在、或结果由更早的版本处理时，计划会留在 `rolling`
/// 等人点一下。而「末阶段不需要人工闸门」这条结论与触发点无关，顺手对一次账比留一个要人手点的
/// 坑更省事。只在真满足条件时写，**幂等**。
#[allow(clippy::result_large_err)]
async fn converge_finished_plan(
    state: &ApiState,
    plan: StoredRolloutPlan,
) -> Result<StoredRolloutPlan, Response> {
    if plan.status != "rolling" || plan.current_phase == 0 {
        return Ok(plan);
    }
    let idx = plan.current_phase as usize;
    if idx != plan.phases.len() {
        return Ok(plan);
    }
    let target_ids = plan.phases[idx - 1].target_ids.clone();
    let entries = state
        .store
        .list_rollout_plan_entries(&plan.plan_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::ROLLOUT_ENTRY_LIST_FAILED,
                "failed to list rollout plan entries",
                err,
            )
            .into_response()
        })?;
    let phase_entries: Vec<StoredRolloutPlanEntry> = entries
        .into_iter()
        .filter(|entry| target_ids.contains(&entry.target_id))
        .collect();
    if !rules::phase_settled(&phase_entries) {
        return Ok(plan);
    }
    let mut plan = plan;
    advance_plan(state, &mut plan).await?;
    Ok(plan)
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
            return ApiError::internal(
                codes::ROLLOUT_AGENT_LIST_FAILED,
                "failed to list agent ids",
                err,
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
        return ApiError::bad_request(
            codes::ROLLOUT_UNKNOWN_TARGETS,
            format!("unknown target(s): {}", unknown.join(", ")),
        )
        .into_response();
    }
    // 按版本选择的升级计划：建计划时就确认**每个目标平台**在该版本下都有安装包 ——
    // 挑不到就整份拒（与中心「一次录入即齐备」同口径），不把失败推迟到派活时逐台暴露。
    if plan.action == "upgrade" {
        match plan_selection(&plan.spec) {
            Err(message) => {
                return ApiError::bad_request(codes::ROLLOUT_PLAN_SPEC_INVALID, message)
                    .into_response();
            }
            Ok(PlanSelection::Version { version }) => {
                let history = match state.store.list_agent_install_packages().await {
                    Ok(history) => history,
                    Err(err) => {
                        return ApiError::internal(
                            codes::ROLLOUT_PACKAGE_LIST_FAILED,
                            "failed to list agent install packages",
                            err,
                        )
                        .into_response();
                    }
                };
                // 一次列出**所有**不合规的目标（缺包 / 没报平台 / 平台无制品），不是见一个报一个。
                let mut problems: Vec<String> = Vec::new();
                for target in &all_targets {
                    match agent_platform(&state, target).await {
                        Ok(platform) => {
                            if select_agent_package(&history, &version, platform).is_none() {
                                problems.push(format!(
                                    "{target} ({platform}): no package for version {version}"
                                ));
                            }
                        }
                        Err(PlatformError::Unavailable(message)) => problems.push(message),
                        Err(err @ PlatformError::Store { .. }) => {
                            return err.into_response(StatusCode::BAD_REQUEST);
                        }
                    }
                }
                if !problems.is_empty() {
                    return ApiError::bad_request(
                        codes::ROLLOUT_VERSION_INCOMPLETE,
                        format!(
                            "version {version} cannot be rolled out to every target platform: {}",
                            problems.join("; ")
                        ),
                    )
                    .into_response();
                }
            }
            Ok(PlanSelection::Explicit) => {}
        }
    }
    let now = plan.created_at.clone();
    if let Err(err) = state.store.save_rollout_plan(&plan).await {
        return ApiError::internal(
            codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err,
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
            return ApiError::internal(
                codes::ROLLOUT_PLAN_ENTRY_STORE_FAILED,
                "failed to store rollout plan entry",
                err,
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
        Err(err) => ApiError::internal(
            codes::ROLLOUT_PLAN_LIST_FAILED,
            "failed to list rollout plans",
            err,
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
            return ApiError::internal(
                codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err,
            )
            .into_response();
        }
    }) else {
        return ApiError::not_found(
            codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    if plan.status != "draft" {
        return ApiError::conflict(
            codes::ROLLOUT_PLAN_CONFLICT,
            format!(
                "rollout plan {plan_id} is {}, only draft can be approved",
                plan.status
            ),
        )
        .into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    // 空阶段没有第一段可开：显式拒，不靠索引 `phases[0]` 撞出 panic（与中心 approve 同一道闸）。
    if plan.phases.is_empty() {
        return ApiError::conflict(
            codes::ROLLOUT_PLAN_CONFLICT,
            format!("rollout plan {plan_id} has no phase"),
        )
        .into_response();
    }
    // 先物化再落状态：物化是幂等的（work_id 确定性 + upsert），半途失败重试安全；
    // 反过来（先落 rolling）会让一次失败把计划停在「已 rolling、但工作没发全」的中间态。
    let first_phase = plan.phases[0].clone();
    if let Err(response) = materialize_phase_start(&state, &plan, &first_phase, &now).await {
        return response;
    }
    let mut drafts = to_drafts(&plan.phases);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    wist_release::plan::approve(&mut drafts, &mut current_phase, &mut status);
    apply_drafts(&mut plan.phases, drafts);
    plan.current_phase = current_phase;
    plan.status = status;
    plan.approved_by = Some("admin".to_string());
    plan.approved_at = Some(now);
    if let Err(err) = state.store.save_rollout_plan(&plan).await {
        return ApiError::internal(
            codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err,
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
            return ApiError::internal(
                codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err,
            )
            .into_response();
        }
    }) else {
        return ApiError::not_found(
            codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    if plan.status != "rolling" {
        return ApiError::conflict(
            codes::ROLLOUT_PLAN_CONFLICT,
            format!("rollout plan {plan_id} is {}, not rolling", plan.status),
        )
        .into_response();
    }
    let idx = plan.current_phase as usize;
    if idx == 0 || idx > plan.phases.len() {
        return ApiError::conflict(
            codes::ROLLOUT_PLAN_CONFLICT,
            format!("rollout plan {plan_id} has no phase to advance"),
        )
        .into_response();
    }
    // 人工闸门：当前阶段须**已全部了结**（含失败）—— 「金丝雀确认无问题再推下一批」。
    // 口径在共享 crate `wist_release::plan`（与中心同一份）。
    let entries = match state.store.list_rollout_plan_entries(&plan_id).await {
        Ok(entries) => entries,
        Err(err) => {
            return ApiError::internal(
                codes::ROLLOUT_ENTRY_LIST_FAILED,
                "failed to list rollout plan entries",
                err,
            )
            .into_response();
        }
    };
    let statuses = phase_entry_statuses(&entries, &plan.phases[idx - 1].target_ids);
    if let Some(reason) = wist_release::plan::advance_gate_blocker(
        &plan.status,
        &to_drafts(&plan.phases),
        plan.current_phase,
        &statuses,
    ) {
        return ApiError::conflict(
            codes::ROLLOUT_ADVANCE_BLOCKED,
            format!("cannot advance rollout plan {plan_id}: {reason}"),
        )
        .into_response();
    }
    // 推进：当前阶段划 completed，物化下一阶段（受 batch_size 节流）或收敛为 completed。
    if let Err(response) = advance_plan(&state, &mut plan).await {
        return response;
    }
    Json(plan_view(&plan)).into_response()
}

/// 重试计划里**失败**的目标：`POST /api/v1/admin/rollout-plans/retry`。
///
/// body `{ plan_id, target_ids?: [...] }`；`target_ids` 省略 / 为空 = 该计划里**所有**失败目标。
/// 为每个目标重新物化一件**新 `work_id`** 的升级工作（agentd 才肯重跑，见
/// [`crate::app::rollout::retry_work_id`]），并把它们所在的阶段与计划重开为 `rolling` ——
/// 于是推进 / 金丝雀闸门照常可用；当前阶段因重新变为未了结而被闸门重新要求。
#[allow(clippy::result_large_err)]
pub async fn retry_rollout_plan(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<RetryRolloutPlanRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let plan_id = input.plan_id.trim().to_string();
    let Some(mut plan) = (match state.store.get_rollout_plan(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return ApiError::internal(
                codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err,
            )
            .into_response();
        }
    }) else {
        return ApiError::not_found(
            codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    // 草稿阶段还没派过任何工作 —— 没有「失败」可言。
    if plan.status == "draft" {
        return ApiError::conflict(
            codes::ROLLOUT_PLAN_CONFLICT,
            format!("rollout plan {plan_id} is draft; approve it before retrying"),
        )
        .into_response();
    }
    let entries = match state.store.list_rollout_plan_entries(&plan_id).await {
        Ok(entries) => entries,
        Err(err) => {
            return ApiError::internal(
                codes::ROLLOUT_ENTRY_LIST_FAILED,
                "failed to list rollout plan entries",
                err,
            )
            .into_response();
        }
    };
    let requested: Option<HashSet<String>> = {
        let set: HashSet<String> = input
            .target_ids
            .iter()
            .map(|target| target.trim().to_string())
            .filter(|target| !target.is_empty())
            .collect();
        (!set.is_empty()).then_some(set)
    };
    let failed: Vec<StoredRolloutPlanEntry> = entries
        .into_iter()
        .filter(|entry| {
            entry.status == "failed"
                && requested
                    .as_ref()
                    .is_none_or(|set| set.contains(&entry.target_id))
        })
        .collect();
    if failed.is_empty() {
        return ApiError::bad_request(
            codes::ROLLOUT_NO_FAILED_TARGET,
            format!("rollout plan {plan_id} has no failed target to retry"),
        )
        .into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    // 先全部解析（解析失败整体不落库），再逐个写 —— 与 `materialize_targets` 同一取舍。
    let mut prepared: Vec<(String, String, String)> = Vec::with_capacity(failed.len());
    for entry in &failed {
        let spec = match dispatch_spec_for(&state, &plan, &entry.target_id).await {
            Ok(spec) => spec,
            Err(response) => return response,
        };
        let work_id = rules::retry_work_id(&plan.plan_id, &entry.target_id, &now);
        prepared.push((entry.target_id.clone(), work_id, spec));
    }
    for (target, work_id, spec) in &prepared {
        let work = rules::build_one_shot_work_with_id(&plan, target, work_id.clone(), spec, &now);
        if let Err(err) = state
            .store
            .save_one_shot_work(&StoredOneShotWork {
                work,
                pre_pause_status: None,
            })
            .await
        {
            return ApiError::internal(
                codes::ROLLOUT_WORK_STORE_FAILED,
                "failed to store one-shot work",
                err,
            )
            .into_response();
        }
        if let Err(err) = state.store.next_work_sequence(target, &now).await {
            return ApiError::internal(
                codes::ROLLOUT_WORK_SEQUENCE_FAILED,
                "failed to bump work sequence",
                err,
            )
            .into_response();
        }
        let entry = StoredRolloutPlanEntry {
            plan_id: plan.plan_id.clone(),
            target_id: target.clone(),
            work_id: Some(work_id.clone()),
            status: "dispatched".to_string(),
            detail: String::new(),
            updated_at: now.clone(),
        };
        if let Err(err) = state.store.upsert_rollout_plan_entry(&entry).await {
            return ApiError::internal(
                codes::ROLLOUT_PLAN_ENTRY_STORE_FAILED,
                "failed to store rollout plan entry",
                err,
            )
            .into_response();
        }
    }
    // 重开：被重试目标所在阶段改回 rolling；计划改回 rolling；current_phase 指回最靠后的那段
    // （推进闸门据此要求该段重新了结）。
    let retried: Vec<String> = prepared
        .iter()
        .map(|(target, _, _)| target.clone())
        .collect();
    let mut drafts = to_drafts(&plan.phases);
    let mut current_phase = plan.current_phase;
    let mut status = plan.status.clone();
    wist_release::plan::reopen_for_retry(&mut drafts, &mut current_phase, &mut status, &retried);
    apply_drafts(&mut plan.phases, drafts);
    plan.current_phase = current_phase;
    plan.status = status;
    if let Err(err) = state.store.save_rollout_plan(&plan).await {
        return ApiError::internal(
            codes::ROLLOUT_PLAN_STORE_FAILED,
            "failed to store rollout plan",
            err,
        )
        .into_response();
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
            return ApiError::internal(
                codes::ROLLOUT_PLAN_LOAD_FAILED,
                "failed to load rollout plan",
                err,
            )
            .into_response();
        }
    }) else {
        return ApiError::not_found(
            codes::ROLLOUT_PLAN_NOT_FOUND,
            format!("unknown rollout plan {plan_id}"),
        )
        .into_response();
    };
    // 顺手对一次账：末阶段已了结但计划还挂着（见函数注释）→ 收敛为 completed，幂等。
    let plan = match converge_finished_plan(&state, plan).await {
        Ok(plan) => plan,
        Err(response) => return response,
    };
    let entries = match state.store.list_rollout_plan_entries(&plan_id).await {
        Ok(value) => value,
        Err(err) => {
            return ApiError::internal(
                codes::ROLLOUT_ENTRY_LIST_FAILED,
                "failed to list rollout plan entries",
                err,
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
    let entry_status = rules::entry_status_for(status);
    updated.status = entry_status.to_string();
    updated.detail = detail.to_string();
    updated.updated_at = chrono::Utc::now().to_rfc3339();
    store
        .upsert_rollout_plan_entry(&updated)
        .await
        .map_err(|err| err.to_string())?;

    // 「在飞」只是进度，不释放一个在飞槽位，也不谈推进。
    if !matches!(entry_status, "succeeded" | "failed") {
        return Ok(());
    }
    progress_phase_after_terminal_result(state, &plan_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::StoredAgentInstallPackage;

    #[test]
    fn agent_target_triple_maps_only_published_platforms() {
        assert_eq!(
            agent_target_triple("linux", "x86_64"),
            Some(install_package::PLATFORM_LINUX_X86)
        );
        assert_eq!(
            agent_target_triple("linux", "aarch64"),
            Some(install_package::PLATFORM_LINUX_ARM)
        );
        assert_eq!(
            agent_target_triple("macos", "aarch64"),
            Some(install_package::PLATFORM_MACOS_ARM)
        );
        assert_eq!(
            agent_target_triple("macos", "arm64"),
            Some(install_package::PLATFORM_MACOS_ARM)
        );
        // 两侧空白照常认（口径不依赖调用方先 trim）。
        assert_eq!(
            agent_target_triple(" linux ", " x86_64 "),
            Some(install_package::PLATFORM_LINUX_X86)
        );
        // 没有 agentd 发布制品的平台一律 None —— 宁可拒，也不猜到别的平台。
        assert_eq!(agent_target_triple("macos", "x86_64"), None);
        assert_eq!(agent_target_triple("linux", "arm64"), None);
        assert_eq!(agent_target_triple("windows", "x86_64"), None);
        assert_eq!(agent_target_triple("Linux", "x86_64"), None);
        assert_eq!(agent_target_triple("", ""), None);
    }

    #[test]
    fn plan_selection_reads_version_explicit_and_rejects_an_empty_version() {
        assert!(matches!(
            plan_selection(r#"{"target_version":"0.1.9"}"#),
            Ok(PlanSelection::Version { version }) if version == "0.1.9"
        ));
        // 版本两侧空白裁掉。
        assert!(matches!(
            plan_selection(r#"{"target_version":" 0.1.9 "}"#),
            Ok(PlanSelection::Version { version }) if version == "0.1.9"
        ));
        // 显式制品（无论是否同时带 version）→ Explicit 透传。
        assert!(matches!(
            plan_selection(r#"{"package_url":"/srv/p.tar.gz","package_sha256":"abc"}"#),
            Ok(PlanSelection::Explicit)
        ));
        assert!(matches!(
            plan_selection(r#"{"target_version":"0.1.9","package_url":"/srv/p.tar.gz"}"#),
            Ok(PlanSelection::Explicit)
        ));
        // 空 / 全空白 version 且无制品 → 坏 spec（不能当 Explicit 把空壳透传给 agentd）。
        assert!(plan_selection(r#"{"target_version":""}"#).is_err());
        assert!(plan_selection(r#"{"target_version":"   "}"#).is_err());
        assert!(plan_selection(r#"{"package_url":""}"#).is_err());
        // null / 非字符串值（键在但取不出）同样是坏 spec —— Option<String> 会把它误读成「没给」。
        assert!(plan_selection(r#"{"target_version":null}"#).is_err());
        assert!(plan_selection(r#"{"target_version":123}"#).is_err());
        assert!(plan_selection(r#"{"package_url":null}"#).is_err());
        assert!(plan_selection(r#"{"package_url":"   "}"#).is_err());
        // 键从未出现（非 JSON / 非对象 / 空对象 / 别的键）→ Explicit 透传（旧行为）。
        assert!(matches!(plan_selection("x"), Ok(PlanSelection::Explicit)));
        assert!(matches!(plan_selection("{}"), Ok(PlanSelection::Explicit)));
        assert!(matches!(
            plan_selection("[1,2]"),
            Ok(PlanSelection::Explicit)
        ));
        assert!(matches!(
            plan_selection(r#"{"foo":1}"#),
            Ok(PlanSelection::Explicit)
        ));
        assert!(matches!(
            plan_selection(r#""x""#),
            Ok(PlanSelection::Explicit)
        ));
        assert!(matches!(
            plan_selection("[1,2]"),
            Ok(PlanSelection::Explicit)
        ));
    }

    fn pkg(id: &str, version: &str, arch: &str) -> StoredAgentInstallPackage {
        StoredAgentInstallPackage {
            package_id: id.to_string(),
            source: String::new(),
            package_sha256: String::new(),
            version: version.to_string(),
            arch: arch.to_string(),
            cached_path: String::new(),
            created_by: String::new(),
            created_at: String::new(),
        }
    }

    #[test]
    fn select_agent_package_picks_the_newest_for_the_exact_version_and_platform() {
        // 历史按 created_at 倒序：最新在前 → find 命中「最新」。
        let history = vec![
            pkg("pkg-new", "0.1.9", "aarch64-apple-darwin"),
            pkg("pkg-old", "0.1.9", "aarch64-apple-darwin"),
            pkg("pkg-linux", "0.1.9", "x86_64-unknown-linux-musl"),
            pkg("pkg-otherver", "0.1.8", "aarch64-apple-darwin"),
        ];
        assert_eq!(
            select_agent_package(&history, "0.1.9", "aarch64-apple-darwin")
                .map(|entry| entry.package_id.as_str()),
            Some("pkg-new")
        );
        assert_eq!(
            select_agent_package(&history, "0.1.9", "x86_64-unknown-linux-musl")
                .map(|entry| entry.package_id.as_str()),
            Some("pkg-linux")
        );
        // 该平台没有 / 该版本没有 → None（建计划据此拒）。
        assert!(select_agent_package(&history, "0.1.9", "aarch64-unknown-linux-musl").is_none());
        assert!(select_agent_package(&history, "9.9.9", "aarch64-apple-darwin").is_none());
    }

    #[test]
    fn ensure_agent_upgrade_spec_requires_url_and_sha() {
        // 完整 → Ok。
        assert!(
            ensure_agent_upgrade_spec(
                r#"{"package_url":"/srv/p.tar.gz","package_sha256":"sha256:abc"}"#
            )
            .is_ok()
        );
        // 缺 package_url（正是「版本没解析」的空壳形状）→ 拒。
        assert!(
            ensure_agent_upgrade_spec(r#"{"target_version":"0.1.9","allow_downgrade":true}"#)
                .is_err()
        );
        assert!(ensure_agent_upgrade_spec(r#"{"package_url":""}"#).is_err());
        assert!(ensure_agent_upgrade_spec(r#"{"package_sha256":"x"}"#).is_err());
        assert!(
            ensure_agent_upgrade_spec(r#"{"package_url":"   ","package_sha256":"x"}"#).is_err()
        );
        // 非 JSON / 非对象 → 拒。
        assert!(ensure_agent_upgrade_spec("x").is_err());
        assert!(ensure_agent_upgrade_spec("[1]").is_err());
    }
}
