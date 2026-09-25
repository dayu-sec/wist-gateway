//! 工作授权（对应模型 `Control.Agent.Work`）的**校验与状态机**。
//!
//! 只管「能不能授权 / 能不能暂停 / 撤回到哪个状态」，不碰 HTTP 也不碰数据库：
//! 处理器负责取数、落库与状态码，判断集中在这里，才测得到（api 层的测试只能打整条路由）。
//!
//! 这里落实几条模型里的硬规矩：
//!   * 授权闸门是**面就绪度**：面在规则未就绪时不展开、也不许授权（渐进启用）；
//!   * 工作内容**不是自由文本**：`spec` 要么由采集目录按事实展开得来，要么逐条校验是
//!     该面在该平台上的单元；
//!   * 判定是授权的前置：没有用途判定就没有机器类别，也就取不到模板；
//!   * 一次性工作只有「可中断 + 正在跑」才允许暂停 —— 不可中断的**拒绝**，
//!     而不是「尽力暂停」（挂起半个升级进程比不暂停更危险）。

use crate::app::content::{ContentSet, FAMILIES, family_applies_to};
use crate::infra::{StoredAgentFactSummary, StoredOneShotWork};
use wist_contracts::work::{OneShotWork, WorkSpec, WorkSpecSource, WorkSpecUnit};

/// 授权/撤回被拒的原因。映射成 HTTP 状态码是 api 层的事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkRejection {
    /// 目标不存在（未知 agent / 未知工作）。
    NotFound(String),
    /// 请求本身不成立（未知面、面不适用、spec 不是目录里的单元……）。
    BadRequest(String),
    /// 请求成立但与当前状态冲突（规则未就绪、版本回退、不可中断却要暂停……）。
    Conflict(String),
}

impl WorkRejection {
    pub fn message(&self) -> &str {
        match self {
            WorkRejection::NotFound(message)
            | WorkRejection::BadRequest(message)
            | WorkRejection::Conflict(message) => message,
        }
    }
}

/// `family` 是否是采集面闭集里的名字（笔误要响，不能当自由字符串收下）。
pub fn check_family(family: &str) -> Result<(), WorkRejection> {
    if FAMILIES.contains(&family) {
        return Ok(());
    }
    Err(WorkRejection::BadRequest(format!(
        "unknown collection family {family:?}"
    )))
}

/// 面在该平台上是否**可授权**：先看适不适用，再看**采集就绪度**。
///
/// 两步分开报，是因为它们是两件事：不适用是**配置错误**（人该换个面），
/// 采集未就绪是**进度问题**（人该等采集要素齐）—— 混成一句话就会把人引向错误的下一步。
///
/// 注意这里**不**看 `rule_ref`（解析就绪）：采原文不需要解析规则。
pub fn check_family_grantable(
    content: &ContentSet,
    family: &str,
    platform: &str,
) -> Result<(), WorkRejection> {
    check_family(family)?;
    if !family_applies_to(family, platform) {
        return Err(WorkRejection::BadRequest(format!(
            "collection family {family} does not apply to platform {platform}"
        )));
    }
    if !content.is_family_ready(platform, family) {
        return Err(WorkRejection::Conflict(format!(
            "collection family {family} is not ready on {platform} (collect_not_ready): \
             该面还没有 status = active 的采集单元"
        )));
    }
    Ok(())
}

/// 按事实裁剪定出 `spec`：用该机器类别的模板展开，取这个面的选中单元。
///
/// 这是设计的正路（内容 = 目录条目组合，不是自由文本）：先把机器类别变成模板，
/// 再用**事实**过滤单元，得到的就是「这台机器真的该采的东西」。
pub fn derive_spec(
    content: &ContentSet,
    machine_class: &str,
    platform: &str,
    family: &str,
    facts: &StoredAgentFactSummary,
) -> Result<(String, i64), WorkRejection> {
    let Some(template) = content.template_for_machine_class(machine_class) else {
        return Err(WorkRejection::Conflict(format!(
            "no work template for machine class {machine_class}"
        )));
    };
    if template.platform != platform {
        return Err(WorkRejection::Conflict(format!(
            "template {} is for {}, but the agent is {platform}",
            template.template_id, template.platform
        )));
    }
    let expansion = content
        .expand(&template.template_id, facts)
        .map_err(WorkRejection::Conflict)?;
    let Some(work) = expansion.works.iter().find(|work| work.family == family) else {
        // 展开里没有这个面：要么它没进模板，要么选中集为空（事实不满足 / 事实没采到）。
        // 如实说清是哪种，别让人对着「没展开」猜。
        let reasons: Vec<String> = expansion
            .excluded_units
            .iter()
            .filter(|excluded| {
                content
                    .units()
                    .any(|unit| unit.unit_id == excluded.unit_id && unit.family == family)
            })
            .map(|excluded| format!("{}={}", excluded.unit_id, excluded.reason_code))
            .collect();
        let detail = if reasons.is_empty() {
            format!(
                "template {} does not include family {family}",
                template.template_id
            )
        } else {
            format!("no unit selected for {family}: {}", reasons.join(", "))
        };
        return Err(WorkRejection::Conflict(detail));
    };
    materialize_spec(content, &work.selected_units).map(|spec| (spec, work.catalog_version))
}

/// 把选中的单元**物化**成工作参数（`spec` 的内容）。
///
/// 为什么要物化而不是只存一串 `unit_id`：agentd 拿到工作要能直接照做，
/// 而「采什么（来源）」与「用什么规则解析（`rule_ref`）」只存在网关的采集目录里。
/// 详见 `wist_contracts::work::WorkSpec` 的注释。
fn materialize_spec(content: &ContentSet, unit_ids: &[String]) -> Result<String, WorkRejection> {
    let mut units = Vec::with_capacity(unit_ids.len());
    for unit_id in unit_ids {
        let Some(unit) = content.units().find(|unit| unit.unit_id == *unit_id) else {
            // 展开出来的单元不在目录里 —— 这是网关自己的不变式被破坏，
            // 不能当无事发生发出去（工作参数里的单元必须是能落地的真单元）。
            return Err(WorkRejection::Conflict(format!(
                "selected unit {unit_id:?} is not in the collection catalog"
            )));
        };
        units.push(WorkSpecUnit {
            unit_id: unit.unit_id.clone(),
            capability: unit.capability.clone(),
            rule_ref: unit.rule_ref.clone(),
            requires_privilege: unit.requires_privilege.clone(),
            sources: unit
                .sources
                .iter()
                .map(|source| WorkSpecSource {
                    kind: source.kind.clone(),
                    target: source.target.clone(),
                    // 「怎么读这条来源」跟工作内容一起发出去：agentd 不该自己去猜文件格式，
                    // 策展在目录里已经知道并声明了。
                    multiline: source.multiline.clone(),
                })
                .collect(),
        });
    }
    WorkSpec { units }
        .encode()
        .map_err(|err| WorkRejection::Conflict(format!("failed to encode work spec: {err}")))
}

/// 校验人工给定的 `spec`：**逐条**必须是该面在该平台上的目录单元。
///
/// 允许手写是为了微调，但微调不等于可以凭空写 —— 不在目录里的单元落不了数据面规则，
/// 收下来只会在几小时后变成一条无人能解释的「采集不到数据」。
pub fn validate_spec(
    content: &ContentSet,
    platform: &str,
    family: &str,
    requested_spec: &str,
) -> Result<(String, i64), WorkRejection> {
    let mut selected = Vec::new();
    for token in requested_spec
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let Some(unit) = content.units().find(|unit| unit.unit_id == token) else {
            return Err(WorkRejection::BadRequest(format!(
                "spec unit {token:?} is not in the collection catalog"
            )));
        };
        if unit.family != family || unit.platform != platform {
            return Err(WorkRejection::BadRequest(format!(
                "spec unit {token:?} belongs to {} on {}, not to {family} on {platform}",
                unit.family, unit.platform
            )));
        }
        selected.push(token.to_string());
    }
    if selected.is_empty() {
        return Err(WorkRejection::BadRequest(
            "spec must name at least one collection unit (或留空，由网关按事实展开)".to_string(),
        ));
    }
    materialize_spec(content, &selected).map(|spec| (spec, content.catalog_version))
}

/// 定出这次授权的期望版本。
///
/// 不给 `plan_version` 就由网关 +1（模型的口径：网关每次改动 +1）；
/// 给了就必须**往前**走 —— 允许指定是为了让调用方对齐外部记录，
/// 但回退版本号会让「Agent 手上是哪一版」这个问题失去意义。
pub fn next_plan_version(
    existing: Option<i64>,
    requested: Option<i64>,
) -> Result<i64, WorkRejection> {
    let current = existing.unwrap_or(0);
    match requested {
        None => Ok(current + 1),
        Some(version) if version <= current => Err(WorkRejection::Conflict(format!(
            "plan_version {version} does not advance the current version {current}"
        ))),
        Some(version) => Ok(version),
    }
}

/// 暂停一份一次性工作（返回改写后的落库形状）。
///
/// 只有「可中断 + 正在做」才允许：别的组合一律拒绝，并说清是哪一条不满足。
pub fn pause_one_shot(
    stored: &StoredOneShotWork,
    now: &str,
) -> Result<StoredOneShotWork, WorkRejection> {
    let work = &stored.work;
    if !work.interruptible {
        return Err(WorkRejection::Conflict(format!(
            "one-shot work {} is not interruptible; refusing to pause a running \
             uninterruptible action",
            work.work_id
        )));
    }
    if !matches!(work.status.as_str(), "accepted" | "running") {
        return Err(WorkRejection::Conflict(format!(
            "one-shot work {} is {}; only accepted/running work can be paused",
            work.work_id, work.status
        )));
    }
    let mut paused = stored.clone();
    paused.pre_pause_status = Some(work.status.clone());
    paused.work.status = "paused".to_string();
    paused.work.paused_at = Some(now.to_string());
    Ok(paused)
}

/// 恢复一份被暂停的一次性工作：回到暂停前的状态，并把本次暂停时长计入累计。
///
/// 「累计暂停秒数」不是装饰：它是「暂停期间不消耗执行预算」这条规矩的**唯一依据**，
/// 没有它就只能靠信任。
pub fn resume_one_shot(
    stored: &StoredOneShotWork,
    now_ms: i64,
) -> Result<StoredOneShotWork, WorkRejection> {
    let work = &stored.work;
    if work.status != "paused" {
        return Err(WorkRejection::Conflict(format!(
            "one-shot work {} is {}; only paused work can be resumed",
            work.work_id, work.status
        )));
    }
    let previous = stored
        .pre_pause_status
        .clone()
        .unwrap_or_else(|| "running".to_string());
    let paused_seconds = match work.paused_at.as_deref().and_then(parse_epoch_millis) {
        Some(paused_at_ms) => ((now_ms - paused_at_ms).max(0)) / 1000,
        // 没有暂停起点就记 0：宁可少记，也不猜一个时长写进审计。
        None => 0,
    };
    let mut resumed = stored.clone();
    resumed.work.status = previous;
    resumed.work.paused_at = None;
    resumed.work.paused_total_seconds += paused_seconds;
    resumed.pre_pause_status = None;
    Ok(resumed)
}

/// 解析 RFC3339 时间戳为毫秒；解析不了返回 `None`（调用方不猜）。
fn parse_epoch_millis(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.timestamp_millis())
}

/// 一次性工作的落库清单里的 `completed_steps` 与 `current_step` 一致性：
/// 断点必须落在已完成步骤之后，不能在里头（否则恢复就是把做过的再做一遍）。
pub fn check_resume_breakpoint(work: &OneShotWork) -> Result<(), WorkRejection> {
    // 断点不能落在已完成步骤里：否则恢复就是把做过的再做一遍。
    if let (Some(current), false) = (
        work.current_step.as_deref(),
        work.completed_steps.is_empty(),
    ) && work.completed_steps.iter().any(|step| step == current)
    {
        return Err(WorkRejection::Conflict(format!(
            "current_step {current:?} is already in completed_steps"
        )));
    }
    Ok(())
}

/// 一次性工作的**到期判定**：到了该终结的时点就给出终态，否则 `None`。
///
/// 两条约束各自独立、任一先到即终结（照模型 `OneShotWork`）：
///
///   * `deadline_at` —— 绝对截止，**暂停也照走** → `expired`；
///   * `timeout_seconds` —— 执行预算，**暂停期间不计** → `timed_out`。
///
/// 两条都到点时记 `expired`：业务截止比执行预算更硬。
///
/// 为什么要有这一步：网关是**唯一**同时知道「现在」与这两条业务约束的地方。没有它，
/// 一件卡住的活（agent 掉线、升级器僵住）会在页面上永远显示「执行中」——
/// 而「它没成」这个结论只存在于终态里。
///
/// 预算的**起算点**取 `scheduled_at`（计划开始时间；授权时缺省即当下），并减掉暂停时长
/// （含仍在进行的那次）。这是现有字段里最接近「开始执行」的锚点 —— 要精确到「agent 真正
/// 开跑」得让它报开始时间，而它现在只报结果。代价是 `dispatched` → `accepted` 那段往返
/// 要吃掉预算；方向保守（宁可早判超时），且分钟级预算下可忽略。
///
/// 时间戳解析不了就不判（上游已校验格式，这里是防御）：截止与预算两条互不牵连。
pub fn overdue_terminal_status(work: &OneShotWork, now_ms: i64) -> Option<&'static str> {
    if !work.is_outstanding() {
        return None;
    }
    if let Some(deadline_ms) = parse_epoch_millis(&work.deadline_at)
        && now_ms >= deadline_ms
    {
        return Some("expired");
    }
    let start_ms = parse_epoch_millis(&work.scheduled_at)?;
    let mut paused_seconds = work.paused_total_seconds;
    if let Some(paused_at_ms) = work.paused_at.as_deref().and_then(parse_epoch_millis) {
        // 正暂停着：这一段还没计进 paused_total_seconds，得一并减掉，
        // 否则「暂停期间不消耗预算」在超时判定里就不成立。
        paused_seconds += (now_ms - paused_at_ms).max(0) / 1000;
    }
    let consumed_seconds = (now_ms - start_ms).max(0) / 1000 - paused_seconds;
    if consumed_seconds >= work.timeout_seconds {
        return Some("timed_out");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::StoredOneShotWork;

    fn one_shot(status: &str, interruptible: bool) -> StoredOneShotWork {
        StoredOneShotWork {
            work: OneShotWork {
                work_id: "work-1".to_string(),
                agent_id: "agent-1".to_string(),
                action: "upgrade".to_string(),
                spec: "0.1.4".to_string(),
                scheduled_at: "2026-09-23T00:00:00Z".to_string(),
                deadline_at: "2026-09-24T00:00:00Z".to_string(),
                timeout_seconds: 600,
                interruptible,
                status: status.to_string(),
                paused_at: None,
                paused_total_seconds: 0,
                current_step: Some("download".to_string()),
                completed_steps: vec![],
                attempt: 0,
                issued_by: "admin".to_string(),
                issued_at: "2026-09-23T00:00:00Z".to_string(),
            },
            pre_pause_status: None,
        }
    }

    #[test]
    fn deadline_breach_expires_and_budget_breach_times_out() {
        // 基准：scheduled 2026-09-23T00:00:00Z、deadline 次日 00:00、预算 600s。
        let work = one_shot("running", false);
        let scheduled = parse_epoch_millis("2026-09-23T00:00:00Z").unwrap();

        // 刚派下去：两条都没到。
        assert_eq!(overdue_terminal_status(&work.work, scheduled), None);
        // 预算尽（600s），截止还没到 → timed_out。
        assert_eq!(
            overdue_terminal_status(&work.work, scheduled + 600_000),
            Some("timed_out")
        );
        // 截止到点 → expired（即使预算也早尽了，业务截止优先）。
        assert_eq!(
            overdue_terminal_status(
                &work.work,
                parse_epoch_millis("2026-09-24T00:00:00Z").unwrap()
            ),
            Some("expired")
        );
    }

    #[test]
    fn pause_freezes_the_budget_but_not_the_deadline() {
        let mut work = one_shot("paused", true);
        let scheduled = parse_epoch_millis("2026-09-23T00:00:00Z").unwrap();
        // 暂停了 1 小时且仍在暂停中：预算只该消耗 0，超时不该判。
        work.work.paused_at = Some("2026-09-23T00:01:00Z".to_string());
        assert_eq!(
            overdue_terminal_status(&work.work, scheduled + 3_600_000),
            None
        );
        // 但截止照走：同一件活到点仍取 expired。
        assert_eq!(
            overdue_terminal_status(
                &work.work,
                parse_epoch_millis("2026-09-24T00:00:00Z").unwrap()
            ),
            Some("expired")
        );
    }

    #[test]
    fn terminal_work_is_never_re_judged() {
        let scheduled = parse_epoch_millis("2026-09-23T00:00:00Z").unwrap();
        let far_future = parse_epoch_millis("2027-01-01T00:00:00Z").unwrap();
        for status in ["succeeded", "failed", "timed_out", "canceled", "expired"] {
            assert_eq!(
                overdue_terminal_status(&one_shot(status, false).work, far_future),
                None
            );
        }
        // 未了结的才判。
        assert_eq!(
            overdue_terminal_status(&one_shot("dispatched", false).work, scheduled + 600_000),
            Some("timed_out")
        );
    }

    #[test]
    fn plan_version_advances_and_never_rewinds() {
        // 首次授权没有前置版本 → 1。
        assert_eq!(next_plan_version(None, None).unwrap(), 1);
        // 改一次 → +1。
        assert_eq!(next_plan_version(Some(1), None).unwrap(), 2);
        // 调用方指定同一版或更旧：拒绝（回退会让「Agent 手上是哪一版」失去意义）。
        assert!(next_plan_version(Some(3), Some(3)).is_err());
        assert!(next_plan_version(Some(3), Some(2)).is_err());
        assert_eq!(next_plan_version(Some(3), Some(4)).unwrap(), 4);
    }

    #[test]
    fn uninterruptible_work_refuses_to_pause() {
        let err = pause_one_shot(&one_shot("running", false), "2026-09-23T00:00:00Z").unwrap_err();
        assert!(matches!(err, WorkRejection::Conflict(_)));
        assert!(err.message().contains("not interruptible"));
    }

    #[test]
    fn only_running_interruptible_work_pauses() {
        assert!(pause_one_shot(&one_shot("dispatched", true), "t").is_err());
        assert!(pause_one_shot(&one_shot("succeeded", true), "t").is_err());

        let paused = pause_one_shot(&one_shot("running", true), "2026-09-23T00:10:00Z").unwrap();
        assert_eq!(paused.work.status, "paused");
        assert_eq!(
            paused.work.paused_at.as_deref(),
            Some("2026-09-23T00:10:00Z")
        );
        // 记下暂停前的状态：恢复要回到它，不能一律猜成 running。
        assert_eq!(paused.pre_pause_status.as_deref(), Some("running"));
    }

    #[test]
    fn resume_returns_to_the_status_we_paused_from_and_banks_the_pause() {
        let paused = pause_one_shot(&one_shot("accepted", true), "2026-09-23T00:00:00Z").unwrap();
        let now_ms = parse_epoch_millis("2026-09-23T00:05:00Z").unwrap();
        let resumed = resume_one_shot(&paused, now_ms).unwrap();
        assert_eq!(resumed.work.status, "accepted");
        assert_eq!(resumed.work.paused_at, None);
        assert_eq!(resumed.work.paused_total_seconds, 300);
        assert_eq!(resumed.pre_pause_status, None);
    }

    #[test]
    fn resume_without_a_pause_start_banks_zero_rather_than_guessing() {
        let mut paused = one_shot("paused", true);
        paused.pre_pause_status = Some("running".to_string());
        let resumed = resume_one_shot(&paused, 1_000_000).unwrap();
        assert_eq!(resumed.work.paused_total_seconds, 0);
        assert_eq!(resumed.work.status, "running");
    }

    #[test]
    fn resuming_work_that_is_not_paused_is_rejected() {
        let err = resume_one_shot(&one_shot("running", true), 0).unwrap_err();
        assert!(err.message().contains("only paused work can be resumed"));
    }

    #[test]
    fn breakpoint_must_not_repeat_a_completed_step() {
        let mut work = one_shot("running", true).work;
        work.completed_steps = vec!["download".to_string()];
        work.current_step = Some("download".to_string());
        assert!(check_resume_breakpoint(&work).is_err());

        work.current_step = Some("install".to_string());
        assert!(check_resume_breakpoint(&work).is_ok());
    }

    // ── 授权闸门与 spec 解析（用内联内容集，不依赖仓里的策展数据） ──

    const CATALOG: &str = r#"

catalog_version = 1
origin = "Gateway"
published_at = "2026-09-22T00:00:00Z"

[[units]]
unit_id = "mac-metrics"
family = "HostMetrics"
capability = "collect_metrics"
platform = "macos"
match = ""
rule_ref = "agent_uplink"
requires_privilege = "none"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"

[[units]]
unit_id = "mac-tcc"
family = "PrivacyTcc"
capability = "collect_logs"
platform = "macos"
match = ""
rule_ref = "macos/tcc"
requires_privilege = "fda"
status = "active"

# 混合来源：统一日志谓词（agentd 还没实现）+ 一份可直接 tail 的文件。
# 只要有一条来源 agentd 能执行，这个单元就算**采集就绪** —— 另一条接不了的
# 由 agentd 如实报成 unsupported，不影响这个面能被派下去。
[[units.sources]]
kind = "UnifiedLogPredicate"
target = "subsystem == tccd"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/tcc.log"

[[units]]
unit_id = "linux-metrics"
family = "HostMetrics"
capability = "collect_metrics"
platform = "linux"
match = ""
rule_ref = "agent_uplink"
requires_privilege = "none"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"

[[units]]
unit_id = "linux-db"
family = "DatabaseService"
capability = "collect_logs"
platform = "linux"
match = "installed:postgresql"
rule_ref = "linux/db"
requires_privilege = "root"
status = "active"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/postgresql.log"

[[units]]
unit_id = "linux-compute-draft"
family = "ComputeWorkload"
capability = "collect_logs"
platform = "linux"
match = ""
rule_ref = ""
requires_privilege = "none"
status = "draft"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/slurm/*"
"#;

    const PACKS: &str = r#"

[[pack]]
pack_id = "macos-base"
platform = "macos"
kind = "Baseline"
families = ["HostMetrics"]
unit_refs = ["mac-metrics"]
catalog_version = 1
status = "active"

[[pack]]
pack_id = "macos-privacy"
platform = "macos"
kind = "Feature"
families = ["PrivacyTcc"]
unit_refs = ["mac-tcc"]
catalog_version = 1
status = "active"

[[pack]]
pack_id = "linux-base"
platform = "linux"
kind = "Baseline"
families = ["HostMetrics"]
unit_refs = ["linux-metrics"]
catalog_version = 1
status = "active"

[[pack]]
pack_id = "linux-compute"
platform = "linux"
kind = "Feature"
families = ["ComputeWorkload"]
unit_refs = ["linux-compute-draft"]
catalog_version = 1
status = "draft"

[[pack]]
pack_id = "linux-datastore"
platform = "linux"
kind = "Feature"
families = ["DatabaseService"]
unit_refs = ["linux-db"]
catalog_version = 1
status = "active"
"#;

    const TEMPLATES: &str = r#"

[[template]]
template_id = "macos-daily"
machine_class = "MacDaily"
platform = "macos"
pack_refs = ["macos-base", "macos-privacy"]
catalog_version = 1
template_version = 1
status = "active"

[[template]]
template_id = "linux-data"
machine_class = "LinuxData"
platform = "linux"
pack_refs = ["linux-base"]
catalog_version = 1
template_version = 1
status = "active"

[[template]]
template_id = "linux-compute"
machine_class = "LinuxCompute"
platform = "linux"
pack_refs = ["linux-base", "linux-datastore"]
catalog_version = 1
template_version = 1
status = "active"
"#;

    fn content() -> ContentSet {
        crate::app::content::parse_content(CATALOG, PACKS, TEMPLATES).expect("fixture parses")
    }

    fn facts(packages: &[&str]) -> StoredAgentFactSummary {
        StoredAgentFactSummary {
            os: "linux".to_string(),
            packages: packages.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_platform_specific_family_is_not_grantable_on_the_other_platform() {
        // PrivacyTcc 是 macOS 专有面。对一台 Linux 机器报「采集未就绪」是把
        // 「不适用」说成了「没准备好」，会把人引向错误的下一步。
        let content = content();
        let err = check_family_grantable(&content, "PrivacyTcc", "linux").unwrap_err();
        assert!(matches!(err, WorkRejection::BadRequest(_)));
        assert!(err.message().contains("does not apply to platform linux"));

        assert!(check_family_grantable(&content, "PrivacyTcc", "macos").is_ok());
    }

    #[test]
    fn a_family_without_active_units_is_blocked_as_collect_not_ready() {
        let content = content();
        let err = check_family_grantable(&content, "ComputeWorkload", "linux").unwrap_err();
        assert!(matches!(err, WorkRejection::Conflict(_)));
        assert!(err.message().contains("collect_not_ready"));
    }

    #[test]
    fn a_typo_in_the_family_name_is_a_bad_request_not_a_new_family() {
        let content = content();
        let err = check_family_grantable(&content, "HostMetric", "macos").unwrap_err();
        assert!(matches!(err, WorkRejection::BadRequest(_)));
        assert!(err.message().contains("unknown collection family"));
    }

    #[test]
    fn derives_the_spec_from_the_catalog_and_the_machines_own_facts() {
        let content = content();
        // 装了 postgresql → 这个面有得采，spec 就是该单元。
        let (spec, catalog_version) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
        )
        .unwrap();
        // spec 是**物化**的工作参数：agentd 要能拿着它直接采（含来源与规则标识）。
        let spec = WorkSpec::parse(&spec).expect("spec 是可解析的工作参数");
        assert_eq!(spec.units.len(), 1);
        assert_eq!(spec.units[0].unit_id, "linux-db");
        assert_eq!(spec.units[0].capability, "collect_logs");
        assert_eq!(spec.units[0].rule_ref, "linux/db");
        assert_eq!(spec.units[0].requires_privilege, "root");
        assert_eq!(spec.units[0].sources.len(), 1);
        assert_eq!(spec.units[0].sources[0].kind, "FileGlob");
        assert_eq!(spec.units[0].sources[0].target, "/var/log/postgresql.log");
        // 目录没声明读法 → 一行一条。
        assert_eq!(spec.units[0].sources[0].multiline, "none");
        assert_eq!(catalog_version, 1);
    }

    #[test]
    fn a_sources_read_mode_travels_with_the_work_spec() {
        // 「怎么读这条来源」是工作内容的一部分：策展在目录里声明，agentd 不自己猜。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\nmultiline = \"indented\"",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
        )
        .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("parse");
        assert_eq!(spec.units[0].sources[0].multiline, "indented");
    }

    #[test]
    fn derivation_says_which_kind_of_reason_it_was_that_nothing_got_selected() {
        let content = content();
        // 事实采到了、但里面没有 postgresql → 条件不满足。
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["nginx"]),
        )
        .unwrap_err();
        assert!(err.message().contains("match_unsatisfied"), "{err:?}");

        // 一份包都没采到 → 无法判定（不是「没装」）。
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&[]),
        )
        .unwrap_err();
        assert!(err.message().contains("fact_not_collected"), "{err:?}");
    }

    #[test]
    fn a_family_the_template_does_not_cover_cannot_be_granted_by_itself() {
        let content = content();
        // LinuxData 的模板里只有 HostMetrics；DatabaseService 虽然在目录里，但不在该模板。
        let err = derive_spec(
            &content,
            "LinuxData",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
        )
        .unwrap_err();
        assert!(err.message().contains("does not include family"), "{err:?}");
    }

    #[test]
    fn hand_written_spec_must_name_units_of_that_family_on_that_platform() {
        let content = content();
        let (spec, _) = validate_spec(&content, "macos", "HostMetrics", " mac-metrics ").unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec 是可解析的工作参数");
        assert_eq!(spec.units.len(), 1);
        assert_eq!(spec.units[0].unit_id, "mac-metrics");
        assert_eq!(spec.metric_interval_seconds(), Some(15));

        let err = validate_spec(&content, "macos", "HostMetrics", "nope").unwrap_err();
        assert!(err.message().contains("not in the collection catalog"));

        // 单元存在但属于别的面：也得报错，不能默默收下。
        let err = validate_spec(&content, "macos", "HostMetrics", "mac-tcc").unwrap_err();
        assert!(err.message().contains("not to HostMetrics on macos"));

        // 空 spec：交给调用方去走「按事实展开」那条路。
        let err = validate_spec(&content, "macos", "HostMetrics", "  ").unwrap_err();
        assert!(matches!(err, WorkRejection::BadRequest(_)));
    }
}
