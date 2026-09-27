//! 灰度发布计划（对应模型 `Control.Rollout`）的校验与物化。
//!
//! 与 `app/work.rs` 同一分层：这里只管「推进闸门合不合法 / 一个 target 怎么物化成工作 /
//! 结果怎么折算成条目状态」，不碰 HTTP 也不碰数据库。物化只构造 `OneShotWork`，落库在 api 层。

use crate::infra::{StoredRolloutPhase, StoredRolloutPlan, StoredRolloutPlanEntry};
use wist_contracts::work::OneShotWork;

/// 阶段推进闸门的合法取值。
pub const ADVANCE_RULE_MANUAL: &str = "manual";
pub const ADVANCE_RULE_ALL_SUCCEEDED: &str = "all_succeeded";
/// `success_rate:<NN>` 前缀（成功率阈值，0..=100）。
pub const ADVANCE_RULE_SUCCESS_RATE_PREFIX: &str = "success_rate:";

/// 校验推进闸门是否合法。
///
/// 取值是 `manual` / `all_succeeded` / `success_rate:<0..=100>`。首版只强制 `manual` 生效
/// （推进都要人工确认），自动推进两条是留待实现的缺口 —— 见 `impl/usecases.json`。
pub fn validate_advance_rule(rule: &str) -> Result<(), String> {
    let rule = rule.trim();
    if rule == ADVANCE_RULE_MANUAL || rule == ADVANCE_RULE_ALL_SUCCEEDED {
        return Ok(());
    }
    if let Some(rate) = rule.strip_prefix(ADVANCE_RULE_SUCCESS_RATE_PREFIX)
        && let Ok(value) = rate.trim().parse::<u32>()
        && value <= 100
    {
        return Ok(());
    }
    Err(format!(
        "advance_rule {rule:?} must be \"manual\", \"all_succeeded\", or \"success_rate:<0..=100>\""
    ))
}

/// agent 上报的工作状态 → 计划条目的状态。
///
/// `running` 等「在飞」状态都归 `dispatched`（条目只区分「还没做 / 在做 / 做成了 / 没成」）；
/// `rolled_back` 在 agentd 侧已映射成 `failed` 上报，网关这里不单列。
pub fn entry_status_for(work_status: &str) -> &'static str {
    match work_status {
        "succeeded" => "succeeded",
        "failed" => "failed",
        _ => "dispatched",
    }
}

/// 一个计划里的 target 物化成的那件一次性工作的 `work_id`。
///
/// **确定性**（不含时间）：同一 target 重试物化会得到同一个 `work_id`，配合 `save_one_shot_work`
/// 的 upsert 幂等 —— 不会因为推进重试而给同一 target 并出两件升级。
pub fn rollout_work_id(plan_id: &str, target_id: &str) -> String {
    let digest = crate::infra::sha256_hex(&format!("{plan_id}|{target_id}"));
    format!("work-{plan_id}-{}", &digest[..12])
}

/// 把计划里的一个 target 物化成一件一次性工作：`spec` 原样带上，`scheduled_at` 取当下。
pub fn build_one_shot_work(plan: &StoredRolloutPlan, target_id: &str, now: &str) -> OneShotWork {
    OneShotWork {
        work_id: rollout_work_id(&plan.plan_id, target_id),
        agent_id: target_id.to_string(),
        action: plan.action.clone(),
        spec: plan.spec.clone(),
        scheduled_at: now.to_string(),
        deadline_at: plan.deadline_at.clone(),
        timeout_seconds: plan.timeout_seconds,
        // 与 `grant_one_shot_work` 同一取舍：动作目录就位前一律按不可中断收，
        // 升级这种动作本就不该中途暂停。
        interruptible: false,
        status: "dispatched".to_string(),
        paused_at: None,
        paused_total_seconds: 0,
        current_step: None,
        completed_steps: Vec::new(),
        attempt: 0,
        issued_by: format!("rollout:{}", plan.plan_id),
        issued_at: now.to_string(),
    }
}

/// 阶段是否已**全部了结**：每个 target 都到了 `succeeded` / `failed` 终态。
///
/// 空阶段不算了结 —— `all` 在空集上恒真，那会把「一个目标都没有的阶段」当成可推进。
pub fn phase_settled(entries: &[StoredRolloutPlanEntry]) -> bool {
    !entries.is_empty()
        && entries
            .iter()
            .all(|entry| matches!(entry.status.as_str(), "succeeded" | "failed"))
}

/// 阶段推进闸门是否放行（自动推进判定）。
///
/// 前提是阶段**全部了结**才谈推进：还有 target 在飞就没出结果，不能拿半截结果判「成没成」。
/// `manual` 永远不自动放行（要人工 advance 确认）。
pub fn phase_should_advance(rule: &str, entries: &[StoredRolloutPlanEntry]) -> bool {
    if !phase_settled(entries) {
        return false;
    }
    let total = entries.len() as u64;
    if total == 0 {
        return false;
    }
    let succeeded = entries
        .iter()
        .filter(|entry| entry.status == "succeeded")
        .count() as u64;
    match rule.trim() {
        ADVANCE_RULE_MANUAL => false,
        ADVANCE_RULE_ALL_SUCCEEDED => succeeded == total,
        _ => {
            if let Some(rate) = rule.trim().strip_prefix(ADVANCE_RULE_SUCCESS_RATE_PREFIX)
                && let Ok(threshold) = rate.trim().parse::<u64>()
            {
                // succeeded / total >= threshold / 100，全程整数，避免浮点误差。
                return succeeded * 100 >= threshold * total;
            }
            false
        }
    }
}

/// 阶段开始时先物化哪些 target：`batch_size <= 0` = 全量；否则最多前 `batch_size` 个。
pub fn phase_start_targets(phase: &StoredRolloutPhase, batch_size: i64) -> Vec<String> {
    if batch_size <= 0 {
        return phase.target_ids.clone();
    }
    let take = (batch_size as usize).min(phase.target_ids.len());
    phase.target_ids[..take].to_vec()
}

/// 按 target 找条目。
fn entry_for<'a>(
    entries: &'a [StoredRolloutPlanEntry],
    target_id: &str,
) -> Option<&'a StoredRolloutPlanEntry> {
    entries.iter().find(|entry| entry.target_id == target_id)
}

/// 阶段内补够 `batch_size` 台在飞：从还在 `pending` 的 target 里再挑下一批物化。
///
/// 只补「在飞数 < batch_size」的差额；`batch_size <= 0` = 不节流，不需要补。
pub fn next_refill_targets(
    phase: &StoredRolloutPhase,
    entries: &[StoredRolloutPlanEntry],
    batch_size: i64,
) -> Vec<String> {
    if batch_size <= 0 {
        return Vec::new();
    }
    let in_flight = phase
        .target_ids
        .iter()
        .filter(|target| {
            entry_for(entries, target)
                .map(|entry| entry.status == "dispatched")
                .unwrap_or(false)
        })
        .count();
    let needed = (batch_size as usize).saturating_sub(in_flight);
    if needed == 0 {
        return Vec::new();
    }
    phase
        .target_ids
        .iter()
        .filter(|target| {
            entry_for(entries, target)
                .map(|entry| entry.status == "pending")
                .unwrap_or(false)
        })
        .take(needed)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::StoredRolloutPhase;

    #[test]
    fn advance_rule_accepts_the_documented_values_and_rejects_garbage() {
        assert!(validate_advance_rule("manual").is_ok());
        assert!(validate_advance_rule("all_succeeded").is_ok());
        assert!(validate_advance_rule("success_rate:80").is_ok());
        assert!(validate_advance_rule("success_rate:100").is_ok());
        assert!(validate_advance_rule("success_rate:0").is_ok());

        assert!(validate_advance_rule("").is_err());
        assert!(validate_advance_rule("auto").is_err());
        assert!(validate_advance_rule("success_rate:101").is_err());
        assert!(validate_advance_rule("success_rate:abc").is_err());
    }

    #[test]
    fn entry_status_folds_in_flight_and_terminal_onto_the_closed_set() {
        assert_eq!(entry_status_for("succeeded"), "succeeded");
        assert_eq!(entry_status_for("failed"), "failed");
        // running / dispatched / accepted 都是「在飞」。
        assert_eq!(entry_status_for("running"), "dispatched");
        assert_eq!(entry_status_for("dispatched"), "dispatched");
        assert_eq!(entry_status_for("accepted"), "dispatched");
    }

    #[test]
    fn work_id_is_deterministic_per_target() {
        let id = rollout_work_id("plan-1", "agent-a");
        assert_eq!(id, rollout_work_id("plan-1", "agent-a"));
        assert_ne!(id, rollout_work_id("plan-1", "agent-b"));
        assert_ne!(id, rollout_work_id("plan-2", "agent-a"));
        assert!(id.starts_with("work-plan-1-"));
    }

    #[test]
    fn build_one_shot_work_copies_the_plan_facts_verbatim() {
        let plan = StoredRolloutPlan {
            plan_id: "plan-1".to_string(),
            action: "upgrade".to_string(),
            spec: "{\"target_version\":\"0.1.4\"}".to_string(),
            deadline_at: "2026-10-01T00:00:00Z".to_string(),
            timeout_seconds: 600,
            phases: vec![StoredRolloutPhase {
                phase_index: 1,
                target_ids: vec!["agent-a".to_string()],
                advance_rule: "manual".to_string(),
                status: "pending".to_string(),
            }],
            batch_size: 0,
            current_phase: 0,
            status: "draft".to_string(),
            created_by: "admin".to_string(),
            created_at: "2026-09-25T00:00:00Z".to_string(),
            approved_by: None,
            approved_at: None,
        };
        let work = build_one_shot_work(&plan, "agent-a", "2026-09-25T01:00:00Z");
        assert_eq!(work.work_id, rollout_work_id("plan-1", "agent-a"));
        assert_eq!(work.agent_id, "agent-a");
        assert_eq!(work.action, "upgrade");
        assert_eq!(work.spec, "{\"target_version\":\"0.1.4\"}");
        assert_eq!(work.deadline_at, "2026-10-01T00:00:00Z");
        assert_eq!(work.timeout_seconds, 600);
        assert!(!work.interruptible);
        assert_eq!(work.status, "dispatched");
    }

    fn entry(target: &str, status: &str) -> StoredRolloutPlanEntry {
        StoredRolloutPlanEntry {
            plan_id: "plan-1".to_string(),
            target_id: target.to_string(),
            work_id: Some(format!("work-{target}")),
            status: status.to_string(),
            detail: String::new(),
            updated_at: "t".to_string(),
        }
    }

    #[test]
    fn phase_advances_only_when_settled_and_the_rule_holds() {
        // 没全部了结就不放行（还有在飞的）。
        let in_flight = [entry("a", "succeeded"), entry("b", "dispatched")];
        assert!(!phase_should_advance("all_succeeded", &in_flight));
        assert!(!phase_should_advance("success_rate:50", &in_flight));

        let all_ok = [entry("a", "succeeded"), entry("b", "succeeded")];
        assert!(phase_should_advance("all_succeeded", &all_ok));
        assert!(phase_should_advance("success_rate:100", &all_ok));

        let one_failed = [entry("a", "succeeded"), entry("b", "failed")];
        assert!(!phase_should_advance("all_succeeded", &one_failed));
        assert!(phase_should_advance("success_rate:50", &one_failed));
        assert!(!phase_should_advance("success_rate:51", &one_failed));

        // manual 永不自动放行。
        assert!(!phase_should_advance("manual", &all_ok));
    }

    #[test]
    fn phase_start_targets_respects_batch_size() {
        let phase = StoredRolloutPhase {
            phase_index: 1,
            target_ids: vec!["a".into(), "b".into(), "c".into()],
            advance_rule: "manual".into(),
            status: "pending".into(),
        };
        // 0 = 不节流，全量。
        assert_eq!(phase_start_targets(&phase, 0), vec!["a", "b", "c"]);
        // N = 前 N 个。
        assert_eq!(phase_start_targets(&phase, 2), vec!["a", "b"]);
        assert_eq!(phase_start_targets(&phase, 10), vec!["a", "b", "c"]);
    }

    #[test]
    fn refill_targets_keep_the_batch_in_flight() {
        let phase = StoredRolloutPhase {
            phase_index: 1,
            target_ids: vec!["a".into(), "b".into(), "c".into(), "d".into()],
            advance_rule: "manual".into(),
            status: "rolling".into(),
        };
        // a 在飞、b/c/d 都 pending，batch_size=2 → 还差 1 台，补 b。
        let entries = [
            entry("a", "dispatched"),
            entry("b", "pending"),
            entry("c", "pending"),
            entry("d", "pending"),
        ];
        assert_eq!(next_refill_targets(&phase, &entries, 2), vec!["b"]);
        // a、b 都结束了，c/d pending，batch_size=2 → 补 c、d。
        let entries = [
            entry("a", "succeeded"),
            entry("b", "failed"),
            entry("c", "pending"),
            entry("d", "pending"),
        ];
        assert_eq!(next_refill_targets(&phase, &entries, 2), vec!["c", "d"]);
        // 不节流：补什么都不用。
        assert!(next_refill_targets(&phase, &entries, 0).is_empty());
    }
}
