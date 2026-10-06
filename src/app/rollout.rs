//! 灰度发布计划（对应模型 `Control.Rollout`）的**推进口径**：接入共享 crate + 网关独有的物化。
//!
//! 口径本身（闸门校验、阶段能不能推进、批次节流、条目状态折叠、确定性 work_id）在共享 crate
//! `wist-release::rollout` —— 中心算阶段、网关放行与物化，两边**同一份**。本模块只把那些口径
//! **接到网关的存储类型**（`StoredRollout*`）上，外加一件网关独有的物化：把目标变成
//! `OneShotWork`。
//!
//! 与 `app/work.rs` 同一分层：这里不碰 HTTP 也不碰数据库。

use crate::infra::{StoredRolloutPhase, StoredRolloutPlan, StoredRolloutPlanEntry};
use wist_contracts::work::OneShotWork;

/// 目标的确定性 `work_id`：`work-<plan_id>-<sha256 前 12 位>`（口径在共享 crate）。
pub use wist_release::rollout::target_work_id as rollout_work_id;
pub use wist_release::rollout::{
    ADVANCE_RULE_ALL_SUCCEEDED, ADVANCE_RULE_MANUAL, ADVANCE_RULE_SUCCESS_RATE_PREFIX,
    entry_status_for, validate_advance_rule,
};

/// 条目状态列（口径函数只要状态，不关心 target_id 与更新时间）。
fn statuses(entries: &[StoredRolloutPlanEntry]) -> Vec<&str> {
    entries.iter().map(|entry| entry.status.as_str()).collect()
}

/// 阶段是否已**全部了结**：每个目标都到了 `succeeded` / `failed` 终态。空阶段不算了结。
pub fn phase_settled(entries: &[StoredRolloutPlanEntry]) -> bool {
    wist_release::rollout::phase_settled(&statuses(entries))
}

/// 阶段推进闸门是否放行（自动推进判定）。前提是阶段已全部了结。
pub fn phase_should_advance(rule: &str, entries: &[StoredRolloutPlanEntry]) -> bool {
    wist_release::rollout::phase_should_advance(rule, &statuses(entries))
}

/// 阶段开始时先物化哪些目标：`batch_size <= 0` = 全量；否则最多前 `batch_size` 个。
pub fn phase_start_targets(phase: &StoredRolloutPhase, batch_size: i64) -> Vec<String> {
    wist_release::rollout::phase_start_targets(&phase.target_ids, batch_size)
}

/// 阶段内补够 `batch_size` 台在飞：从还在 `pending` 的目标里再挑下一批物化。
pub fn next_refill_targets(
    phase: &StoredRolloutPhase,
    entries: &[StoredRolloutPlanEntry],
    batch_size: i64,
) -> Vec<String> {
    let states: Vec<wist_release::rollout::TargetStatus<'_>> = entries
        .iter()
        .map(|entry| (entry.target_id.as_str(), entry.status.as_str()))
        .collect();
    wist_release::rollout::next_refill_targets(&phase.target_ids, &states, batch_size)
}

/// 把计划里的一个目标物化成一件一次性工作：`spec` 原样带上，`scheduled_at` 取当下。
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::StoredRolloutPhase;

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

    /// 适配层要真的把网关的存储行映射成口径要的状态（**规则本身**在 crate 里测）。
    #[test]
    fn stored_entries_are_mapped_onto_the_shared_rules() {
        let phase = StoredRolloutPhase {
            phase_index: 1,
            target_ids: vec!["a".into(), "b".into(), "c".into()],
            advance_rule: "manual".into(),
            status: "rolling".into(),
        };

        // 还有在飞的 → 不了结、不放行。
        let in_flight = [entry("a", "dispatched"), entry("b", "pending")];
        assert!(!phase_settled(&in_flight));
        assert!(!phase_should_advance("all_succeeded", &in_flight));
        // 全终态 → 了结，放不放行由闸门说了算。
        let settled = [entry("a", "succeeded"), entry("b", "failed")];
        assert!(phase_settled(&settled));
        assert!(phase_should_advance("success_rate:50", &settled));
        assert!(!phase_should_advance("all_succeeded", &settled));
        // 空阶段不算了结（`all` 在空集上恒真）。
        assert!(!phase_settled(&[]));

        // 节流：在飞数只看 `dispatched`。
        let states = [
            entry("a", "dispatched"),
            entry("b", "pending"),
            entry("c", "pending"),
        ];
        assert_eq!(next_refill_targets(&phase, &states, 2), vec!["b"]);
        assert_eq!(
            next_refill_targets(&phase, &states, 0),
            Vec::<String>::new()
        );
        assert_eq!(phase_start_targets(&phase, 2), vec!["a", "b"]);
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
}
