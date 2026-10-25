//! 工作授权（对应模型 `Control.Agent.Work`）的**校验与状态机**。
//!
//! 只管「能不能授权 / 能不能暂停 / 撤回到哪个状态」，不碰 HTTP 也不碰数据库：
//! 处理器负责取数、落库与状态码，判断集中在这里，才测得到（api 层的测试只能打整条路由）。
//!
//! 这里落实几条模型里的硬规矩：
//!   * 授权闸门是**面就绪度**：面在采集未就绪时不展开、也不许授权（渐进启用）；
//!   * 工作内容**不是自由文本**：`spec` 要么由采集目录按事实展开得来，要么逐条校验是
//!     该面在该平台上的单元；
//!   * 判定是授权的前置：没有用途判定就没有机器类别，也就取不到模板；
//!   * 一次性工作只有「可中断 + 正在跑」才允许暂停 —— 不可中断的**拒绝**，
//!     而不是「尽力暂停」（挂起半个升级进程比不暂停更危险）。

use std::collections::BTreeSet;

use crate::app::content::{ContentSet, UnitSource};
use crate::infra::{StoredAgentFactSummary, StoredOneShotWork};
use wist_contracts::capability_report::LogsCapabilities;
use wist_contracts::work::{
    DROP_IF_CONTAINS_SUBSTRING, OneShotWork, WorkSpec, WorkSpecSource, WorkSpecUnit,
    is_explicit_path,
};

/// 授权/撤回被拒的原因。映射成 HTTP 状态码是 api 层的事。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkRejection {
    /// 目标不存在（未知 agent / 未知工作）。
    NotFound(String),
    /// 请求本身不成立（未知面、面不适用、spec 不是目录里的单元……）。
    BadRequest(String),
    /// 请求成立但与当前状态冲突（采集未就绪、版本回退、不可中断却要暂停……）。
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

/// `family` 是否是采集面词表里的名字（笔误要响，不能当自由字符串收下）。
///
/// 词表来自已装载的知识库（`catalog.toml` 的 `[[families]]`），不是代码里的常量 ——
/// 加面只改数据，网关不发版。
pub fn check_family(content: &ContentSet, family: &str) -> Result<(), WorkRejection> {
    if content.has_family(family) {
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
    check_family(content, family)?;
    if !content.family_applies_to(family, platform) {
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
    capabilities: Option<&wist_contracts::capability_report::LogsCapabilities>,
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
            .map(|excluded| {
                // 带上**卡在哪条条件**上：只有 `fact_not_collected` 时，运维看得出
                // “事实没采到”，却不知道是哪一条（`path_exists:` 的还是 `installed:` 的）——
                // 前者要等探测白名单下来，后者要装包或等包清单探针，处置完全不同。
                match &excluded.condition {
                    Some(condition) => {
                        format!("{}={}({condition})", excluded.unit_id, excluded.reason_code)
                    }
                    None => format!("{}={}", excluded.unit_id, excluded.reason_code),
                }
            })
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
    materialize_spec(content, &work.selected_units, Some(facts), capabilities)
        .map(|spec| (spec, work.catalog_version))
}

/// 容器过滤器的**减法维度**：缺能力时去掉该维度是安全的（只会多采，不会少采）。
///
/// 入参是 `missing_log_capabilities` 的形状（`filters:<维度名>`）。
/// 与包含式维度相对：去掉 `*_in` 等于全收，与策展意图相反，所以仍然裁源。
fn is_subtractive_filter_dimension(missing: &str) -> bool {
    let Some(dimension) = missing.strip_prefix("filters:") else {
        return false;
    };
    dimension == wist_contracts::work::FILTER_POD_NOT_IN
        || dimension == wist_contracts::work::FILTER_NAME_NOT_IN
}

/// 把选中的单元**物化**成工作参数（`spec` 的内容）。
///
/// 为什么要物化而不是只存一串 `unit_id`：agentd 拿到工作要能直接照做，
/// 而「采什么（来源）」与「用什么规则解析（`rule_ref`）」只存在网关的采集目录里。
/// 详见 `wist_contracts::work::WorkSpec` 的注释。
///
/// `facts` 有值时按「已探测且不存在」裁剪显式路径来源；`None` 用于人工手写 spec
/// （运维显式点名，应当看得见失败，而不是被网关静默删掉）。
///
/// `capabilities` 有值时（agent 报过能力清单，D7）再按「这台机器真能不能采」裁剪：
/// 没声明的形态/导出器会被剔掉，并在拒绝文案里点名缺了什么 —— 否则就是「派下去 → agent 报
/// unsupported → 这个面静默没数据」。`None`（旧 agentd 没报）**不做能力裁剪**：
/// 那时“不知道”不等于“不会”，退回契约判据（与 D7 之前一致）。
///
/// 两类**减法**不裁源（去掉只会多采，不会少采）：
///   * `drop_if_contains` 不支持/未上报 → 去掉字段继续采（上送量变大，而不是面消失）；
///   * 容器过滤器的 `pod_not_in` / `name_not_in` 维度缺失 → 去掉该维度继续采
///     （见 [`is_subtractive_filter_dimension`]）。
///
/// 其余新增**字段/维度**仍裁源：旧 agentd 收到未知字段会 `deny_unknown_fields` 拒收整份 spec；
/// 包含式维度（`namespace_in` / `name_in`）去掉等于全采 —— 两种都不能替策展做决定。
fn materialize_spec(
    content: &ContentSet,
    unit_ids: &[String],
    facts: Option<&StoredAgentFactSummary>,
    capabilities: Option<&wist_contracts::capability_report::LogsCapabilities>,
) -> Result<String, WorkRejection> {
    let mut units = Vec::with_capacity(unit_ids.len());
    let mut absent: BTreeSet<String> = BTreeSet::new();
    let mut unsupported: BTreeSet<String> = BTreeSet::new();
    let mut degraded: BTreeSet<String> = BTreeSet::new();
    for unit_id in unit_ids {
        let Some(unit) = content.units().find(|unit| unit.unit_id == *unit_id) else {
            // 展开出来的单元不在目录里 —— 这是网关自己的不变式被破坏，
            // 不能当无事发生发出去（工作参数里的单元必须是能落地的真单元）。
            return Err(WorkRejection::Conflict(format!(
                "selected unit {unit_id:?} is not in the collection catalog"
            )));
        };
        let mut sources = Vec::with_capacity(unit.sources.len());
        for source in &unit.sources {
            if source_is_absent_on_this_machine(source, facts) {
                absent.insert(source.target.clone());
                continue;
            }
            // 先拼成 wire 形态：能力判据看的就是**将要发出去的那条来源**
            // （字段一字不差，避免“按目录字段判、发出去却多带一个字段”）。
            let mut candidate = WorkSpecSource {
                kind: source.kind.clone(),
                target: source.target.clone(),
                // 「怎么读这条来源」跟工作内容一起发出去：agentd 不该自己去猜文件格式，
                // 策展在目录里已经知道并声明了。
                multiline: source.multiline.clone(),
                // 选源排除项同样属于「这份采集面不该采什么」，跟着单元走。
                exclude_globs: source.exclude_globs.clone(),
                // W2 的结构化选源同理：namespace / pod 的选择是策展结论，不是 agent 本地偏好。
                filters: source.filters.clone(),
                // W4 的噪音行子串：同属“这份采集面不该采什么”，跟单元一起走。
                drop_if_contains: source.drop_if_contains.clone(),
            };
            // `drop_if_contains` 是**减法**（只减少上送量）：agent 不认识时**去掉这个字段**
            // 继续采，而不是把整条来源裁掉 —— 后者会让 `linux-auth-session` 这种
            // “两条来源都带过滤器”的面在老 agent 上直接不可授权（少采变成不采）。
            if !candidate.drop_if_contains.is_empty()
                && !declares_noise_filter(capabilities, DROP_IF_CONTAINS_SUBSTRING)
            {
                candidate.drop_if_contains.clear();
                degraded.insert(source.target.clone());
            }
            // D7：agent 报了能力清单就按它裁剪；没报（None）就退回契约判据。
            if let Some(capabilities) = capabilities
                && let Some(missing) =
                    wist_contracts::work::missing_log_capabilities(&candidate, capabilities)
                && !missing.is_empty()
            {
                // 缺的**全是减法维度**（`pod_not_in` / `name_not_in`）→ 去掉这些维度继续采。
                // 有任一包含式维度缺失 → 仍然裁源（去掉等于全收，不能替策展做这个决定）。
                if missing
                    .iter()
                    .any(|dimension| !is_subtractive_filter_dimension(dimension))
                {
                    // 文案形状：`<来源>: <缺的能力>`。外层统一加“这台 agent 没声明能力”的帽子，
                    // 避免“agent 未声明 …”这种中英混排套在英文句子里的双层括号。
                    unsupported.insert(format!("{}: {}", source.target, missing.join(", ")));
                    continue;
                }
                for dimension in &missing {
                    match dimension.strip_prefix("filters:") {
                        Some(wist_contracts::work::FILTER_POD_NOT_IN) => {
                            candidate.filters.pod_not_in.clear();
                        }
                        Some(wist_contracts::work::FILTER_NAME_NOT_IN) => {
                            candidate.filters.name_not_in.clear();
                        }
                        _ => {}
                    }
                }
                degraded.insert(source.target.clone());
            }
            sources.push(candidate);
        }
        if sources.is_empty() {
            // 整条单元都被裁掉：不把「零来源的单元」发下去
            // （agentd 会建一个永远空转、每轮报路径不存在的 input）。
            continue;
        }
        units.push(WorkSpecUnit {
            unit_id: unit.unit_id.clone(),
            capability: unit.capability.clone(),
            rule_ref: unit.rule_ref.clone(),
            requires_privilege: unit.requires_privilege.clone(),
            sources,
        });
    }
    if units.is_empty() {
        // 两种“没来源”的原因分开写：一个是“这台机器上确实没有”（探测过且不存在），
        // 另一个是“这台机器的 agent 不会采”（能力清单里没声明）。合并成一句话
        // 会让人把后者当成前者去查文件。
        let mut reasons = Vec::new();
        if !absent.is_empty() {
            reasons.push(format!(
                "explicit paths absent on this agent ({})",
                absent.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        if !unsupported.is_empty() {
            reasons.push(format!(
                "agent does not declare capabilities for [{}]",
                unsupported.into_iter().collect::<Vec<_>>().join("; ")
            ));
        }
        if reasons.is_empty() {
            reasons.push("no source".to_string());
        }
        return Err(WorkRejection::Conflict(format!(
            "no collectable source for units {unit_ids:?}: {}",
            reasons.join("; ")
        )));
    }
    // 部分裁剪不能静默：单元还在，但其中某条来源被剔了 —— 不记一行，
    // 运维只会看到“这个面怎么少了一半数据”。探测裁剪（absent）是既有行为，这里只补 D7 这条。
    if !unsupported.is_empty() {
        log::info!(
            "event=WorkSourceDropped reason=capability units={:?} sources={:?}",
            unit_ids,
            unsupported
        );
    }
    // 降级也不能静默：来源还在、但噪音过滤被去掉了 —— 上送量会变大，运维要能对账。
    if !degraded.is_empty() {
        log::info!(
            "event=WorkSourceDegraded reason=drop_if_contains units={:?} sources={:?}",
            unit_ids,
            degraded
        );
    }
    WorkSpec { units }
        .encode()
        .map_err(|err| WorkRejection::Conflict(format!("failed to encode work spec: {err}")))
}

/// 这台 agent 是否声明了某项噪音行丢弃能力。
///
/// `None`（没报能力清单）时按**不支持**处理：这个字段是减法、忽略它只会多采，
/// 而发过去会让 pre-D7 的 agentd 因 `deny_unknown_fields` **整份拒收**（连别的面一起停）。
fn declares_noise_filter(capabilities: Option<&LogsCapabilities>, mode: &str) -> bool {
    capabilities.is_some_and(|caps| caps.drop_if_contains.iter().any(|value| value == mode))
}

/// 这条来源在这台机器上是否**已被探测且确认不存在**。
///
/// 只看显式文件路径：`没探测过 ≠ 不存在`（三态语义）；通配与导出器都不参与裁剪。
fn source_is_absent_on_this_machine(
    source: &UnitSource,
    facts: Option<&StoredAgentFactSummary>,
) -> bool {
    let Some(facts) = facts else {
        return false;
    };
    if source.kind != "FileGlob" || !is_explicit_path(&source.target) {
        return false;
    }
    let probed = facts.probed_paths.iter().any(|path| path == &source.target);
    let present = facts
        .present_paths
        .iter()
        .any(|path| path == &source.target);
    probed && !present
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
    capabilities: Option<&LogsCapabilities>,
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
    // 人工手写的 spec **不按事实裁剪**（运维显式点名的路径要“看得见失败”，`facts` 传 None）；
    // 但**能力裁剪照做**：能力不匹配的后果不是“这个文件采不到”，而是 agentd
    // `deny_unknown_fields` **整份拒收**（连没点名的那几个面一起停）。
    materialize_spec(content, &selected, None, capabilities)
        .map(|spec| (spec, content.catalog_version))
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
    use wist_contracts::capability_report::LogsCapabilities;
    use wist_contracts::work::{FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB};

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

    fn real_content() -> ContentSet {
        crate::app::content::load_content(
            &crate::test_support::knowledge_file("catalog.toml"),
            &crate::test_support::knowledge_file("packs.toml"),
            &crate::test_support::knowledge_file("templates.toml"),
        )
        .expect("load checked-in content")
    }

    fn facts(packages: &[&str]) -> StoredAgentFactSummary {
        StoredAgentFactSummary {
            os: "linux".to_string(),
            packages: packages.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        }
    }

    fn facts_with_paths(
        os: &str,
        packages: &[&str],
        probed: &[&str],
        present: &[&str],
    ) -> StoredAgentFactSummary {
        StoredAgentFactSummary {
            os: os.to_string(),
            packages: packages.iter().map(|value| value.to_string()).collect(),
            probed_paths: probed.iter().map(|value| value.to_string()).collect(),
            present_paths: present.iter().map(|value| value.to_string()).collect(),
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .unwrap_err();
        assert!(err.message().contains("fact_not_collected"), "{err:?}");
        // 文案要指出**卡在哪条条件**：只说 `fact_not_collected`，没人知道是 `installed:`
        // 还是 `path_exists:` —— 而这两者的处置完全不同。
        assert!(
            err.message().contains("installed:postgresql"),
            "缺少条件详情：{err:?}"
        );
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
            None,
        )
        .unwrap_err();
        assert!(err.message().contains("does not include family"), "{err:?}");
    }

    #[test]
    fn hand_written_spec_must_name_units_of_that_family_on_that_platform() {
        let content = content();
        let (spec, _) =
            validate_spec(&content, "macos", "HostMetrics", " mac-metrics ", None).unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec 是可解析的工作参数");
        assert_eq!(spec.units.len(), 1);
        assert_eq!(spec.units[0].unit_id, "mac-metrics");
        assert_eq!(spec.metric_interval_seconds(), Some(15));

        let err = validate_spec(&content, "macos", "HostMetrics", "nope", None).unwrap_err();
        assert!(err.message().contains("not in the collection catalog"));

        // 单元存在但属于别的面：也得报错，不能默默收下。
        let err = validate_spec(&content, "macos", "HostMetrics", "mac-tcc", None).unwrap_err();
        assert!(err.message().contains("not to HostMetrics on macos"));

        // 空 spec：交给调用方去走「按事实展开」那条路。
        let err = validate_spec(&content, "macos", "HostMetrics", "  ", None).unwrap_err();
        assert!(matches!(err, WorkRejection::BadRequest(_)));
    }

    // ── W0：按事实裁剪不存在的显式路径 ─────────────────────────────

    #[test]
    fn an_absent_explicit_path_is_not_dispatched() {
        // tcc 单元还有一条 UnifiedLogPredicate；文件被确认不存在时只裁掉文件来源。
        let content = content();
        let (spec, _) = derive_spec(
            &content,
            "MacDaily",
            "macos",
            "PrivacyTcc",
            &facts_with_paths("macos", &[], &["/var/log/tcc.log"], &[]),
            None,
        )
        .unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units.len(), 1);
        assert_eq!(spec.units[0].sources.len(), 1);
        assert_eq!(spec.units[0].sources[0].kind, "UnifiedLogPredicate");
    }

    #[test]
    fn an_unprobed_path_is_not_treated_as_absent() {
        // 没探测过 ≠ 不存在：宁可先派下去（失败了看得见），也不悄悄删掉一条来源。
        let content = content();
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts_with_paths("linux", &["postgresql"], &[], &[]),
            None,
        )
        .unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units[0].sources.len(), 1);
        assert_eq!(spec.units[0].sources[0].target, "/var/log/postgresql.log");
    }

    #[test]
    fn a_unit_whose_only_source_is_absent_is_not_dispatched() {
        let content = content();
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts_with_paths("linux", &["postgresql"], &["/var/log/postgresql.log"], &[]),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, WorkRejection::Conflict(_)));
        assert!(err.message().contains("explicit paths absent"), "{err:?}");
        assert!(err.message().contains("/var/log/postgresql.log"), "{err:?}");
    }

    // ── D7：按 agent 自报的能力裁剪 ──

    fn logs_caps(file_inputs: &[&str], exporters: &[&str]) -> LogsCapabilities {
        LogsCapabilities {
            file_inputs: file_inputs.iter().map(|v| v.to_string()).collect(),
            exporters: exporters.iter().map(|v| v.to_string()).collect(),
            ..LogsCapabilities::default()
        }
    }

    #[test]
    fn a_source_the_agent_cannot_collect_is_not_dispatched() {
        let content = content();
        // 这台 agent 只声明了 glob（没声明“显式路径”）：目录里的 DB 单元是显式路径 → 不派。
        let caps = logs_caps(&[FILE_INPUT_GLOB], &[]);
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&caps),
        )
        .unwrap_err();
        assert!(matches!(err, WorkRejection::Conflict(_)));
        assert!(
            err.message().contains("does not declare capabilities"),
            "{err:?}"
        );
        // 形状钉住：`<来源>: <缺的能力>` —— 运维要能直接把这两段拿去对照目录与 agent 版本。
        assert!(
            err.message().contains(&format!(
                "/var/log/postgresql.log: file_inputs:{FILE_INPUT_ABSOLUTE_PATH}"
            )),
            "{err:?}"
        );
    }

    #[test]
    fn a_declared_capability_keeps_the_source_and_an_unknown_agent_keeps_legacy_behaviour() {
        let content = content();
        let facts = facts(&["postgresql"]);

        // 声明齐了 → 照常派生。
        let full = logs_caps(&[FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB], &[]);
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts,
            Some(&full),
        )
        .expect("declared capability derives");
        assert!(spec.contains("/var/log/postgresql.log"), "{spec}");

        // 旧 agentd（没报能力清单）→ **不做能力裁剪**，与 D7 之前一致。
        let (legacy, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts,
            None,
        )
        .expect("unknown capabilities still derive");
        assert!(legacy.contains("/var/log/postgresql.log"), "{legacy}");
    }

    #[test]
    fn an_exporter_the_agent_does_not_have_blocks_the_unit() {
        // 内核面唯一的来源是 `Exporter journalctl-kernel`；旧 agent 不认识它（词表里没有）。
        // 目录里把它改成 active 后，网关必须在**派活时**就拦住，而不是派下去等 unsupported。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"Exporter\"\ntarget = \"journalctl-kernel\"",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let caps = logs_caps(
            &[FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB],
            &["nft-ruleset"],
        );
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&caps),
        )
        .unwrap_err();
        assert!(
            err.message().contains("exporters:journalctl-kernel"),
            "{err:?}"
        );
    }

    #[test]
    fn a_partially_supported_unit_keeps_the_sources_it_can_collect() {
        // 同一单元里两条来源：一条 agent 会采、一条不会 → 只剔后者，不把整个单元丢掉。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\n\n\
             [[units.sources]]\nkind = \"Exporter\"\ntarget = \"journalctl-kernel\"",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let caps = logs_caps(&[FILE_INPUT_ABSOLUTE_PATH], &[]);
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&caps),
        )
        .expect("the collectable source survives");
        assert!(spec.contains("/var/log/postgresql.log"), "{spec}");
        assert!(!spec.contains("journalctl-kernel"), "{spec}");
    }

    #[test]
    fn only_the_absent_sources_are_dropped_from_a_multi_source_unit() {
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\n\n\
             [[units.sources]]\nkind = \"FileGlob\"\ntarget = \"/var/log/postgresql-extra.log\"",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts_with_paths(
                "linux",
                &["postgresql"],
                &["/var/log/postgresql.log", "/var/log/postgresql-extra.log"],
                &["/var/log/postgresql.log"],
            ),
            None,
        )
        .unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        let targets: Vec<&str> = spec.units[0]
            .sources
            .iter()
            .map(|source| source.target.as_str())
            .collect();
        assert_eq!(targets, vec!["/var/log/postgresql.log"]);
        // 裁剪不改变单元的解析规则与权限声明。
        assert_eq!(spec.units[0].rule_ref, "linux/db");
        assert_eq!(spec.units[0].requires_privilege, "root");
    }

    // ── W1：选源排除项跟着单元走 ───────────────────────────────

    #[test]
    fn source_exclude_globs_are_dispatched_with_the_unit() {
        // 排除项不在网关这一层求值：它是「这份采集面不该采什么」的声明，
        // 要在 agentd 端按实际展开结果匹配。不传下去，容器单元就只能退回成
        // 「把业务名写进 pattern」。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql/*.log\"\n\
             exclude_globs = [\"/var/log/postgresql/archive-*.log\"]",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts_with_paths("linux", &["postgresql"], &[], &[]),
            None,
        )
        .unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units[0].sources[0].target, "/var/log/postgresql/*.log");
        assert_eq!(
            spec.units[0].sources[0].exclude_globs,
            vec!["/var/log/postgresql/archive-*.log".to_string()]
        );
    }

    // ── W2：容器选源过滤器跟着单元走 ───────────────────────

    #[test]
    fn container_filters_are_dispatched_with_the_unit() {
        // 过滤器不在网关求值（网关没有文件系统事实），它只是把**策展结论**传到 agentd：
        // agentd 在发现阶段按文件名里的 pod / namespace 求值。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/containers/*.log\"\n\
             filters = { namespace_in = [\"prod\"], pod_not_in = [\"debug-pod\"] }",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts_with_paths("linux", &["postgresql"], &[], &[]),
            None,
        )
        .unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units[0].sources[0].target, "/var/log/containers/*.log");
        assert_eq!(
            spec.units[0].sources[0].filters.namespace_in,
            vec!["prod".to_string()]
        );
        assert_eq!(
            spec.units[0].sources[0].filters.pod_not_in,
            vec!["debug-pod".to_string()]
        );
    }

    #[test]
    fn container_filters_are_dropped_when_the_agent_does_not_declare_them() {
        // G1：带 `filters` 的 spec 落到不认识的 agentd 上会被 `deny_unknown_fields`
        // **整份拒收** —— 所以网关必须在派活时就按能力轴裁掉这条来源，而不是发下去等报错。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/containers/*.log\"\n\
             filters = { namespace_in = [\"prod\"] }",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let caps = logs_caps(&[FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB], &[]);
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts_with_paths("linux", &["postgresql"], &[], &[]),
            Some(&caps),
        )
        .unwrap_err();
        assert!(err.message().contains("filters:namespace_in"), "{err:?}");
    }

    #[test]
    fn noise_needles_travel_from_the_catalog_into_the_spec() {
        // W4：子串丢弃是**读法的一部分**，跟单元一起发下去；agentd 不自己猜该丢什么。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\n\
             drop_if_contains = [\"pam_unix(cron:session)\"]",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        // 只有**声明了这条能力**的 agent 才拿到子串；不声明/未报的走降级（见下一个用例）。
        let capable = LogsCapabilities {
            drop_if_contains: vec!["substring".to_string()],
            ..logs_caps(&[FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB], &[])
        };
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&capable),
        )
        .unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(
            spec.units[0].sources[0].drop_if_contains,
            vec!["pam_unix(cron:session)".to_string()]
        );
    }

    #[test]
    fn a_source_with_noise_needles_is_degraded_when_the_agent_lacks_that_capability() {
        // `drop_if_contains` 是**减法**：旧 agentd 不认识时去掉这个字段继续采（上送量变大），
        // 而不是把整条来源裁掉 —— `linux-auth-session` 两条来源都带过滤器，
        // 裁源会让整个面不可授权（少采变成不采）。也不得发下去：会把整份 spec 拒收。
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\n\
             drop_if_contains = [\"noise\"]",
            1,
        );
        let content =
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses");
        let old = logs_caps(&[FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB], &[]);
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&old),
        )
        .expect("the source survives without the noise filter");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units[0].sources.len(), 1);
        assert!(
            spec.units[0].sources[0].drop_if_contains.is_empty(),
            "{spec:?}"
        );

        // 没报能力清单（pre-D7）：同样去掉字段（发过去会整份拒收）。
        let (legacy, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            None,
        )
        .expect("legacy agents still get the source");
        let legacy = WorkSpec::parse(&legacy).expect("spec");
        assert!(legacy.units[0].sources[0].drop_if_contains.is_empty());
    }

    #[test]
    fn subtractive_filter_dimensions_are_dropped_instead_of_dropping_the_source() {
        // `pod_not_in` / `name_not_in` 是**减法**维度：旧 agent 不认识时去掉该维度继续采
        // （上送量变大），而不是把整条来源裁掉 —— 单来源单元裁掉就等于“少采变成不采”。
        let with_filters = |expr: &str| {
            let catalog = CATALOG.replacen(
                "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
                &format!(
                    "kind = \"FileGlob\"\ntarget = \"/var/log/containers/*.log\"\nfilters = {{ {expr} }}"
                ),
                1,
            );
            crate::app::content::parse_content(&catalog, PACKS, TEMPLATES).expect("fixture parses")
        };
        // 只声明文件能力、一个 filters 维度都不声明（= 0.9.4 及以前）。
        let old = logs_caps(&[FILE_INPUT_ABSOLUTE_PATH, FILE_INPUT_GLOB], &[]);

        let content = with_filters("pod_not_in = [\"debug-pod\"], name_not_in = [\"fluent-bit\"]");
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&old),
        )
        .expect("the source survives without subtractive filters");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units[0].sources.len(), 1);
        assert!(
            spec.units[0].sources[0].filters.is_empty(),
            "减法维度应当被去掉：{spec:?}"
        );

        // 包含式维度不能降级：去掉 `name_in` 就是全收，与策展意图相反 → 仍然裁源。
        let content = with_filters("name_in = [\"mysql\"]");
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "DatabaseService",
            &facts(&["postgresql"]),
            Some(&old),
        )
        .expect_err("inclusive dimension still crops the source");
        assert!(
            err.message().contains("does not declare capabilities"),
            "{err:?}"
        );
    }

    #[test]
    fn a_hand_written_spec_is_not_filtered_by_path_facts() {
        // 人工点名是运维的显式动作：不过滤，失败了也要看得见。
        let content = content();
        let (spec, _) =
            validate_spec(&content, "linux", "DatabaseService", "linux-db", None).unwrap();
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units[0].sources.len(), 1);
        assert_eq!(spec.units[0].sources[0].target, "/var/log/postgresql.log");
    }

    #[test]
    fn the_real_catalog_dispatches_only_the_auth_file_that_exists() {
        // 真实目录 + 真实事实：Debian 系（auth.log 在、secure 不在）只应派 auth.log。
        // 这是 W0 要修的那个具体问题：旧行为会把 secure 一起派下去，每轮报路径不存在。
        let content = real_content();
        let facts = facts_with_paths(
            "linux",
            &[],
            &["/var/log/auth.log", "/var/log/secure"],
            &["/var/log/auth.log"],
        );
        let (spec, _) = derive_spec(&content, "LinuxHost", "linux", "LoginSession", &facts, None)
            .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units.len(), 1);
        assert_eq!(spec.units[0].unit_id, "linux-auth-session");
        let targets: Vec<&str> = spec.units[0]
            .sources
            .iter()
            .map(|source| source.target.as_str())
            .collect();
        assert_eq!(targets, vec!["/var/log/auth.log"]);
    }

    #[test]
    fn the_real_catalog_dispatches_container_stdout_only_where_the_symlink_root_exists() {
        // G2 验收：容器单元靠 `path_exists:/var/log/containers` 做事实门。
        // 有目录 → 派 `/var/log/containers/*.log`；没目录 → 面在展开阶段就不展开。
        let content = real_content();
        let present = facts_with_paths(
            "linux",
            &["postgresql"],
            &["/var/log/containers"],
            &["/var/log/containers"],
        );
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "ContainerWorkload",
            &present,
            None,
        )
        .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert!(
            spec.units.iter().any(|unit| {
                unit.unit_id == "linux-container-stdout"
                    && unit
                        .sources
                        .iter()
                        .any(|source| source.target == "/var/log/containers/*.log")
            }),
            "{spec:?}"
        );

        let absent = facts_with_paths("linux", &["postgresql"], &["/var/log/containers"], &[]);
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "ContainerWorkload",
            &absent,
            None,
        )
        .expect_err("no container root and the slurm/nvidia unit is still draft");
        assert!(
            err.message()
                .contains("no unit selected for ContainerWorkload"),
            "{err:?}"
        );
    }

    #[test]
    fn the_real_catalog_dispatches_docker_stdout_only_where_the_docker_root_exists() {
        // M0 验收：纯 Docker 主机的容器单元靠 `path_exists:/var/lib/docker/containers` 做事实门。
        let content = real_content();
        // 白名单必须包含 docker 根目录 —— 否则 agent 根本不探测它，`path_exists` 永远是
        // 「无法判定」（`fact_not_collected`），这个面永远授不了权（就是 agentd 0.9.2 修的那类 bug）。
        assert!(
            content
                .probe_paths()
                .iter()
                .any(|path| path == "/var/lib/docker/containers"),
            "探测白名单缺 docker 根目录：{:?}",
            content.probe_paths()
        );
        // 否定条件同样要靠探测才能判定：不探 `/var/log/containers` 的话，纯 Docker 主机上
        // `not_path_exists` 永远 Unknown，单元反而展不开。
        //
        // 光断言“白名单里有这条路径”证明不了什么 —— k8s 单元的正条件也会把它带进来。
        // 所以先钉住“真实目录里的 docker 单元**确实带了**这条否定条件”，再验白名单
        // （否定条件的白名单推导本身由 content.rs 的 fixture 用例覆盖）。
        let docker = content
            .units()
            .find(|unit| unit.unit_id == "linux-docker-container-stdout")
            .expect("docker container unit");
        assert!(
            docker
                .match_expr
                .contains("not_path_exists:/var/log/containers"),
            "docker 单元缺去重条件：{}",
            docker.match_expr
        );
        assert!(
            content
                .probe_paths()
                .iter()
                .any(|path| path == "/var/log/containers"),
            "探测白名单缺 k8s 容器根目录：{:?}",
            content.probe_paths()
        );
        let present = facts_with_paths(
            "linux",
            &["postgresql"],
            &["/var/lib/docker/containers", "/var/log/containers"],
            &["/var/lib/docker/containers"],
        );
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "ContainerWorkload",
            &present,
            None,
        )
        .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert!(
            spec.units.iter().any(|unit| {
                unit.unit_id == "linux-docker-container-stdout"
                    && unit.sources.iter().any(|source| {
                        source.target == "/var/lib/docker/containers/*/*-json.log*"
                            && source.multiline == "none"
                    })
            }),
            "{spec:?}"
        );

        // k8s + cri-dockerd：两个根目录都在，容器面只交给 k8s 单元，不再重复采。
        let both = facts_with_paths(
            "linux",
            &["postgresql"],
            &["/var/lib/docker/containers", "/var/log/containers"],
            &["/var/lib/docker/containers", "/var/log/containers"],
        );
        let (spec, _) = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "ContainerWorkload",
            &both,
            None,
        )
        .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert!(
            spec.units
                .iter()
                .any(|unit| unit.unit_id == "linux-container-stdout"),
            "{spec:?}"
        );
        assert!(
            spec.units
                .iter()
                .all(|unit| unit.unit_id != "linux-docker-container-stdout"),
            "k8s 节点上 docker 单元不应该再命中：{spec:?}"
        );

        // 没有 docker 目录 → 该单元不派（`linux-compute-workload` 仍是 draft）。
        let absent = facts_with_paths(
            "linux",
            &["postgresql"],
            &["/var/lib/docker/containers", "/var/log/containers"],
            &[],
        );
        let err = derive_spec(
            &content,
            "LinuxCompute",
            "linux",
            "ContainerWorkload",
            &absent,
            None,
        )
        .expect_err("no docker root");
        assert!(
            err.message()
                .contains("linux-docker-container-stdout=match_unsatisfied"),
            "{err:?}"
        );
    }

    #[test]
    fn a_pure_docker_host_on_the_baseline_class_still_gets_the_container_face() {
        // B2 验收（面拆分后）：容器 stdout 是**主机普遍能力**，不按机器用途分发。
        // 只跑业务容器的机器落 `LinuxHost`（模板只有基线包）也必须能拿到这个面 ——
        // 以前容器单元挂在 `linux-workload`（只属于 compute/data 模板），这类机器根本没有面。
        let content = real_content();
        let facts = facts_with_paths(
            "linux",
            &[],
            // 否定条件也要“探测过”才能判定：只探 docker 根的话，
            // `not_path_exists:/var/log/containers` 会落 Unknown，单元反而不展开。
            &["/var/lib/docker/containers", "/var/log/containers"],
            &["/var/lib/docker/containers"],
        );
        let expansion = content.expand("linux-host", &facts).expect("expand");
        let containers = expansion
            .works
            .iter()
            .find(|work| work.family == "ContainerWorkload")
            .expect("LinuxHost 也应当有 ContainerWorkload 面");
        assert_eq!(
            containers.selected_units,
            vec!["linux-docker-container-stdout".to_string()]
        );
    }

    #[test]
    fn a_ready_family_does_not_dispatch_its_draft_units() {
        // 面就绪（至少一条 active）不等于面里每个单元都已就绪。
        // 容器面（`ContainerWorkload`）有两条 active 单元；作业/加速卡面（`ComputeWorkload`）
        // 只剩 draft 的 slurm/nvidia 单元 —— 后者即使 `match` 命中也不能派
        // （否则会派下 agentd 不保证能执行的来源）。
        let content = real_content();
        let facts = facts_with_paths(
            "linux",
            &["slurm", "kubelet"],
            &["/var/log/containers"],
            &["/var/log/containers"],
        );
        let expansion = content.expand("linux-compute", &facts).expect("expand");
        let containers = expansion
            .works
            .iter()
            .find(|work| work.family == "ContainerWorkload")
            .expect("ContainerWorkload work");
        assert_eq!(
            containers.selected_units,
            vec!["linux-container-stdout".to_string()]
        );
        // slurm 装了、kubelet 也跑了（`match` 命中），但单元还是 draft。
        assert!(
            expansion.excluded_units.iter().any(|unit| {
                unit.unit_id == "linux-compute-workload" && unit.reason_code == "collect_not_ready"
            }),
            "{:?}",
            expansion.excluded_units
        );
    }

    #[test]
    fn the_real_catalog_dispatches_the_db_unit_from_its_log_directories() {
        // G3 验收：DB 单元的事实门必须是 `path_exists` —— 包清单探针还没实现
        // （`packages` 恒空），用 `installed:` 做门会让这个面永远展不开。
        let content = real_content();
        let present = facts_with_paths(
            "linux",
            &[],
            &["/var/log/postgresql", "/var/log/mysql"],
            &["/var/log/postgresql"],
        );
        let (spec, _) = derive_spec(
            &content,
            "LinuxData",
            "linux",
            "DatabaseService",
            &present,
            None,
        )
        .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        assert_eq!(spec.units.len(), 1);
        let sources = &spec.units[0].sources;
        assert!(
            sources
                .iter()
                .any(|source| source.target == "/var/log/postgresql/*.csv"
                    && source.multiline == "postgres_csv"),
            "{sources:?}"
        );
        assert!(sources.iter().any(|source| {
            source.target == "/var/log/mysql/*slow*.log" && source.multiline == "mysql_slow"
        }));
    }

    #[test]
    fn a_secure_only_host_dispatches_only_secure() {
        // RHEL 系：secure 在、auth.log 不在 —— 反向也要成立。
        let content = real_content();
        let facts = facts_with_paths(
            "linux",
            &[],
            &["/var/log/auth.log", "/var/log/secure"],
            &["/var/log/secure"],
        );
        let (spec, _) = derive_spec(&content, "LinuxHost", "linux", "LoginSession", &facts, None)
            .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        let targets: Vec<&str> = spec.units[0]
            .sources
            .iter()
            .map(|source| source.target.as_str())
            .collect();
        assert_eq!(targets, vec!["/var/log/secure"]);
    }

    #[test]
    fn a_host_with_neither_auth_file_does_not_get_a_login_work() {
        // 两条都不在：面在展开阶段就被 `path_exists` 门控排除，不是派一份空活。
        let content = real_content();
        let facts = facts_with_paths("linux", &[], &["/var/log/auth.log", "/var/log/secure"], &[]);
        let err =
            derive_spec(&content, "LinuxHost", "linux", "LoginSession", &facts, None).unwrap_err();
        assert!(
            err.message().contains("no unit selected for LoginSession"),
            "{err:?}"
        );
        assert!(err.message().contains("linux-auth-session"), "{err:?}");
    }

    #[test]
    fn ubuntu_package_logs_dispatch_only_the_existing_files() {
        // 顺带修掉的那个问题：Ubuntu 不再派 dnf.log / yum.log 两条永远失败的输入。
        let content = real_content();
        let facts = facts_with_paths(
            "linux",
            &[],
            &[
                "/var/log/dpkg.log",
                "/var/log/apt/history.log",
                "/var/log/dnf.log",
                "/var/log/yum.log",
            ],
            &["/var/log/dpkg.log", "/var/log/apt/history.log"],
        );
        let (spec, _) = derive_spec(
            &content,
            "LinuxHost",
            "linux",
            "SoftwareChange",
            &facts,
            None,
        )
        .expect("derives");
        let spec = WorkSpec::parse(&spec).expect("spec");
        let targets: Vec<&str> = spec.units[0]
            .sources
            .iter()
            .map(|source| source.target.as_str())
            .collect();
        assert_eq!(
            targets,
            vec!["/var/log/dpkg.log", "/var/log/apt/history.log"]
        );
    }

    #[test]
    fn globs_and_exporters_are_never_filtered_by_path_facts() {
        // 裁剪只针对**显式文件路径**：通配与导出器不参与（即使事实里出现同名串）。
        let facts = facts_with_paths("linux", &[], &["/var/log/misc/*", "dmesg:panic"], &[]);
        let glob = UnitSource {
            filters: Default::default(),
            kind: "FileGlob".to_string(),
            target: "/var/log/misc/*".to_string(),
            multiline: "none".to_string(),
            exclude_globs: Vec::new(),
            drop_if_contains: Vec::new(),
        };
        let exporter = UnitSource {
            filters: Default::default(),
            kind: "Exporter".to_string(),
            target: "dmesg:panic".to_string(),
            multiline: "none".to_string(),
            exclude_globs: Vec::new(),
            drop_if_contains: Vec::new(),
        };
        assert!(!source_is_absent_on_this_machine(&glob, Some(&facts)));
        assert!(!source_is_absent_on_this_machine(&exporter, Some(&facts)));
    }
}
