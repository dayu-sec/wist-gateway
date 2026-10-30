//! 采集预检（collection preflight）：回答「这台机器现在能不能授权某个采集面，为什么不能」。
//!
//! ## 为什么需要它
//!
//! 授权被拒时网关只能回一句：
//!
//! ```text
//! no unit selected for ContainerWorkload:
//!   linux-docker-container-stdout=match_unsatisfied(path_exists:/var/lib/docker/containers)
//! ```
//!
//! 现场要么 SSH 上去 `ls`（agentd 装在客户主机上，登录成本极高），要么猜。而那句提示里
//! 混着三件必须分开的事：**探过但不在**（这台机器确实没有）、**没探过**（不知道）、
//! **摘要过期**（网关手里的是旧账）。预检把这三件事分开报，并给出下一步该做什么。
//!
//! ## 调用方向：网关发起，机器自己探
//!
//! agentd 以 root 跑在客户主机上，**CLI 能看到的它都看得到** —— 所以「必须有人登录」不是
//! 能力问题，是调用方向问题。预检走已有的**一次性命令通道**：
//!
//! 1. 管理面 `POST …/collection-preflight` → 入队一条 `refresh_facts`（params 带路径白名单）；
//! 2. agentd 在下一个状态上报（≤3s）认领，本机三态探路径，回传
//!    `POST /api/v1/agent/collection-preflight`；
//! 3. 网关把实测结果落 [`StoredAgentPathProbe`]，页面 `GET …/collection-preflight` 拿结论。
//!
//! 端到端 ≈ 3～5 秒，全程零登录。
//!
//! 命令 kind 刻意**复用 `refresh_facts`**（而不是新开一种）：已经装在现场的旧 agentd 不认识
//! 新 kind 会回 `unsupported`，那就等于「要升级才能用」—— 而客户的机器不该为了看一个结论升级。
//! 复用旧 kind 时旧 agentd 会做**整轮重采**（忽略 params），路径照样被探到、事实照样重报，
//! 结论依然能出来，只是没有 `unreadable` 这一层证据。新旧都能用。
//!
//! ## 一份判定，不是一份证据转储
//!
//! 求值直接复用授权那条路径（[`ContentSet::expand`]），所以不会出现「预检说可以、授权却拒绝」。
//! 响应给人两样东西：**一个结论**（`verdict` + `summary`）和**每个面一个状态**
//! （`grantable` / `absent` / `unprobed` / `unreadable` / `not_ready`）。证据（逐单元、
//! 逐路径）附在后面，供排障时看，不要求人先读懂它。

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use wist_contracts::API_VERSION_V1;

use crate::api::ApiState;
use crate::api::admin_auth::require_admin_bearer;
use crate::api::admin_ops::agent_not_found_response;
use crate::api::agent_ops::authenticate_agent;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;
use crate::app::content::{ContentSet, Expansion, Unit, platform_for_machine_class};
use crate::app::log_source::{SourceContext, is_under_roots, resolve_dirs};
use crate::infra::{
    StoredAgentFactSummary, StoredAgentPathProbe, StoredLogSource, UnreadablePath,
    VerifiedAgentIdentity,
};

/// 实测结果超过这个年龄就标 `stale`。
///
/// 门槛比事实摘要的节流（5 分钟）宽一倍：预检是**按需**发生的，不是周期上报，
/// 10 分钟前探过的路径仍然能回答「这台机器大概是什么形状」。真正决定可信度的是
/// `probe.source`（实测 / 上报）与 `not_probed_paths`（目录变新后还没来得及探）。
pub const STALE_PROBE_SECONDS: i64 = 600;

/// Agent 侧一次预检回传的 `kind`。
pub const PREFLIGHT_KIND: &str = "collection_preflight";

/// 单次回传的路径上限（目录里通常只有十几个）。防的是畸形/恶意客户端撑大存储。
const MAX_PROBE_PATHS: usize = 512;

/// 单条路径的长度上限。
///
/// 路径长度本身也是**攻击面**：不卡的话一条 2MB 的“路径”会被原样存进 JSON 列，
/// 之后每次 GET 都把它读出来。真实容器/日志路径远低于这个值。
const MAX_PROBE_PATH_LEN: usize = 1024;

// ─────────────────────────────────────────────────────────────────────────────
// 线格式：Agent → 网关
// ─────────────────────────────────────────────────────────────────────────────

/// agentd 探完本机路径后的回传。
///
/// **不加 `deny_unknown_fields`**：这是新端点，将来的 agentd 多带一个字段不该被旧网关 400 ——
/// 预检是排障通道，它自己先挂了就失去了意义。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AgentPreflightReport {
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub kind: String,
    pub agent_id: String,
    #[serde(default)]
    pub instance_id: String,
    /// 本机探完的时刻（RFC3339）。空 = 用网关收到的时刻。
    #[serde(default)]
    pub observed_at: String,
    /// 本次实际探过的绝对路径。
    #[serde(default)]
    pub probed_paths: Vec<String>,
    /// 其中存在的路径（`probed_paths` 的子集）。
    #[serde(default)]
    pub present_paths: Vec<String>,
    /// 探不了（权限 / IO）。**不在** `probed_paths` 里 —— 否则「不知道」会伪装成「确认没有」。
    #[serde(default)]
    pub unreadable_paths: Vec<UnreadablePath>,
}

/// 让 agentd 只探路径、不做整轮重采的命令参数。
///
/// 复用 `refresh_facts` 这个 kind 时，旧 agentd 会忽略 params（退化成整轮重采，仍然可用）；
/// 新 agentd 认出 `scope = paths` 就只探这些路径并回传，省掉一次全量采集。
pub fn probe_command_params(paths: &[String]) -> String {
    serde_json::json!({ "scope": "paths", "paths": paths }).to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// 视图：网关 → 人 / 页面 / CLI
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct PreflightView {
    pub agent_id: String,
    pub machine_class: Option<String>,
    pub platform: Option<String>,
    pub catalog_version: Option<i64>,
    /// `grantable` | `partial` | `blocked` | `undetermined`
    pub verdict: String,
    /// 只在 `undetermined` 时给：
    /// `no_content` | `unclassified` | `no_template` | `no_facts` | `catalog_error`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub undetermined_reason: Option<String>,
    /// 一句中文结论（可直接贴进工单）。细节在各面的 `reason` 与证据里。
    pub summary: String,
    pub probe: ProbeView,
    pub families: Vec<FamilyView>,
    pub generated_at: String,
}

/// 这次求值用的路径事实从哪来。
#[derive(Debug, Serialize)]
pub struct ProbeView {
    /// `probe`（本机实测）/ `reported`（事实摘要里的路径）/ `none`
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    /// 超过 [`STALE_PROBE_SECONDS`]。`source = none` 时为 `false`。
    pub stale: bool,
    /// 已下发探测命令、agent 还没回传（页面据此显示「正在探测」并轮询）。
    pub pending: bool,
    /// 那条命令是什么时候入队的。给页面算「已经等了多久」—— 等 30s 是正常的 3s tick
    /// 被拖延一下，等 10 分钟就是机器/agentd 根本没在跑。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_since: Option<String>,
    pub probed_paths: Vec<String>,
    pub present_paths: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unreadable_paths: Vec<UnreadablePath>,
    /// 目录要求探、但这次没探到的路径（目录比实测结果新，或 agent 跳过了）。
    /// 非空 = 证据不完整，值得再探一次。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_probed_paths: Vec<String>,
}

/// 一个采集面在这台机器上的**结论**。
#[derive(Debug, Serialize)]
pub struct FamilyView {
    pub family: String,
    /// `grantable` | `absent` | `unprobed` | `unreadable` | `not_ready` | `source_unresolved`
    /// | `agent_too_old`
    ///
    /// 这些值就是「能不能授、不能的话为什么」，与授权时的排除原因一一对应。
    pub state: String,
    /// 支撑该状态的一句话（`grantable` 且全部实例都定位到时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// 将被选中的单元（`state = grantable` 时非空）。
    pub selected_units: Vec<String>,
    /// 证据：该面在这台机器上的每条单元。
    pub units: Vec<UnitView>,
    /// 这个面辖区内「看到了几个实例、定位到几个」（只对带 `from_dir` 的面有意义）。
    ///
    /// 为什么要单独给结构而不是只写在 `reason` 里：`reason` 是一句话，
    /// 页面以后要按实例展开时得靠它；且 `grantable` 时 `reason` 通常为空，
    /// 而「2 个实例，1 个没定位」恰恰是能授权、但值得人知道的状态。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<InstanceCount>,
}

/// 一个面上的实例计数。
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct InstanceCount {
    /// 有可用目录（已过 roots）的实例数。
    pub resolved: usize,
    /// 看得见的实例总数（含 `evidence = unresolved` 的占位）。
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct UnitView {
    pub unit_id: String,
    /// `selected` | `match_unsatisfied` | `fact_not_collected` | `unreadable` | `collect_not_ready`
    /// | `source_not_resolved` | `agent_too_old`
    pub result: String,
    /// 原始条件表达式（排障用的真相，别翻译）。
    pub match_expr: String,
    /// `agent_too_old` 时：本单元要求的最低 agentd 版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_agentd_version: Option<String>,
    /// `path_exists` / `not_path_exists` 条件的实测值。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathFactView>,
    /// 服务在、但没解析到日志目录的服务清单（`source_not_resolved` 时非空）。
    ///
    /// 为什么要单独列出来：处置是「配覆盖 / 开搜索」，人得知道是哪个服务没找到；
    /// 只回一句「找不到日志」会让人从第一个服务开始一个一个猜。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved_sources: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PathFactView {
    pub path: String,
    /// `present` | `absent` | `unreadable` | `unprobed`
    pub state: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 求值
// ─────────────────────────────────────────────────────────────────────────────

/// 求值入口：**只读**（不写库、不发命令）。
///
/// 入队探测命令的两处调用方是 [`run_agent_preflight`]（人点了一下）与
/// 授权被拒时的 [`enqueue_if_evidence_missing`]（自动）—— 读与写刻意分开。
#[allow(clippy::result_large_err)]
pub async fn evaluate(state: &ApiState, agent_id: &str) -> Result<PreflightView, ApiError> {
    let classification = state
        .store
        .get_agent_classification(agent_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::PREFLIGHT_UNAVAILABLE,
                "failed to load agent classification",
                err,
            )
        })?;
    let reported = state
        .store
        .get_agent_fact_summary(agent_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::PREFLIGHT_UNAVAILABLE,
                "failed to load agent fact summary",
                err,
            )
        })?;
    let probe = state
        .store
        .get_agent_path_probe(agent_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::PREFLIGHT_UNAVAILABLE,
                "failed to load agent path probe",
                err,
            )
        })?;
    // agentd 版本：知识库可以声明“本单元要求 ≥ X”。拿不到（还没报过）就当不满足 ——
    // 与授权那条路同源，否则会出现「预检说可以、授权却拒绝」。
    let agent_version = match state.store.get_agent(agent_id).await {
        Ok(Some(agent)) => Some(agent.version),
        Ok(None) => None,
        Err(err) => {
            return Err(ApiError::internal(
                codes::PREFLIGHT_UNAVAILABLE,
                "failed to load agent version",
                err,
            ));
        }
    };
    // 「有没有命令在飞」只影响展示：读失败不该把结论也弄没。
    //
    // 而且命令“在路上”不等于“结果还没回来”：agentd 先回传实测、回执跟在下一拍
    // 状态上报里（≤3s）。不区分的话，页面会明明已经看到结论却又显示「探测中」。
    let latest_command = state
        .store
        .get_latest_agent_command(agent_id, wist_api::status::command_kind::REFRESH_FACTS)
        .await
        .unwrap_or_else(|err| {
            log::warn!("event=PreflightPendingUnknown agent_id={agent_id} detail=\"{err}\"");
            None
        });
    let (pending, pending_since) = match latest_command.as_ref() {
        Some(command) if command.acked_at.is_none() && command.outcome.is_none() => {
            if probe_reported_after(probe.as_ref(), command.requested_at_ms) {
                (false, None)
            } else {
                (
                    true,
                    chrono::DateTime::from_timestamp_millis(command.requested_at_ms)
                        .map(|at| at.to_rfc3339()),
                )
            }
        }
        _ => (false, None),
    };

    let content = state.knowledge().content.clone();
    let now = chrono::Utc::now();
    // 日志源候选：与授权那条路**同一份**（否则会出现「预检说可以、授权却拒绝」）。
    let log_sources = state
        .store
        .list_agent_log_sources(agent_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::PREFLIGHT_UNAVAILABLE,
                "failed to load agent log sources",
                err,
            )
        })?;
    let sources = crate::app::log_source::SourceContext {
        log_sources: &log_sources,
        roots: &state.config.allowed_source_roots,
        agent_version: agent_version.as_deref(),
    };
    Ok(build_view(
        agent_id,
        classification.map(|item| item.machine_class),
        reported,
        probe,
        content,
        sources,
        pending,
        pending_since,
        now,
    ))
}

/// 授权的求值事实：**与预检同一份**（摘要 + 路径维度被本机实测覆盖）。
///
/// 为什么两边必须同源：预检的全部意义是「先告诉你能不能授」。如果授权那条路还用
/// 旧摘要，就会出现「预检说可以、授权却拒绝」—— 那比没有预检更让人失去信任。
///
/// 只覆盖路径维度：探针只探路径，拿它覆盖其它维度会把 `installed:` 类条件全变成
/// 「无法判定」（那是病，不是解法）。
pub async fn evaluation_facts(
    state: &ApiState,
    agent_id: &str,
) -> Result<Option<StoredAgentFactSummary>, crate::infra::StoreError> {
    let reported = state.store.get_agent_fact_summary(agent_id).await?;
    let probe = state.store.get_agent_path_probe(agent_id).await?;
    Ok(merge_facts(reported, probe.as_ref()))
}

/// 事实摘要与路径实测的**唯一**合并规则（预检与授权共用）。
fn merge_facts(
    reported: Option<StoredAgentFactSummary>,
    probe: Option<&StoredAgentPathProbe>,
) -> Option<StoredAgentFactSummary> {
    if reported.is_none() && probe.is_none() {
        return None;
    }
    let mut facts = reported.unwrap_or_default();
    if let Some(probe) = probe {
        // 实测是路径维度的全集：没列进来的路径算「没探过」（而不是沿用旧摘要）。
        facts.probed_paths = probe.probed_paths.clone();
        facts.present_paths = probe.present_paths.clone();
    }
    Some(facts)
}

/// 纯求值（除了读时钟）—— 入参就是全部输入，方便单测。
#[allow(clippy::too_many_arguments)]
fn build_view(
    agent_id: &str,
    machine_class: Option<String>,
    reported: Option<StoredAgentFactSummary>,
    probe: Option<StoredAgentPathProbe>,
    content: Option<std::sync::Arc<ContentSet>>,
    sources: crate::app::log_source::SourceContext<'_>,
    pending: bool,
    pending_since: Option<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> PreflightView {
    // 求值用的事实 = 摘要 + **路径维度被实测覆盖**（与授权那条路**同一份**，
    // 见 [`evaluation_facts`]；否则会出现「预检说可以、授权却拒绝」）。
    let merged = merge_facts(reported.clone(), probe.as_ref());
    let has_facts = merged.is_some();
    let facts = merged.unwrap_or_default();
    let unreadable = probe
        .as_ref()
        .map(|value| value.unreadable_paths.clone())
        .unwrap_or_default();
    let unreadable_set: BTreeSet<&str> = unreadable.iter().map(|item| item.path.as_str()).collect();

    let (source, observed_at) = match (probe.as_ref(), reported.as_ref()) {
        (Some(probe), _) => ("probe", Some(probe.observed_at.clone())),
        (None, Some(reported)) => ("reported", Some(reported.observed_at.clone())),
        (None, None) => ("none", None),
    };
    let age = observed_at.as_deref().and_then(|at| age_seconds(at, now));
    let probe_view = ProbeView {
        source: source.to_string(),
        observed_at: observed_at.clone(),
        stale: observed_at.is_some() && age.is_none_or(|age| age > STALE_PROBE_SECONDS),
        pending,
        pending_since,
        probed_paths: facts.probed_paths.clone(),
        present_paths: facts.present_paths.clone(),
        unreadable_paths: unreadable.clone(),
        not_probed_paths: Vec::new(),
    };

    let mut view = PreflightView {
        agent_id: agent_id.to_string(),
        machine_class: None,
        platform: None,
        catalog_version: None,
        verdict: "undetermined".to_string(),
        undetermined_reason: Some("no_content".to_string()),
        summary: String::new(),
        probe: probe_view,
        families: Vec::new(),
        generated_at: now.to_rfc3339(),
    };

    let Some(content) = content else {
        view.summary = "网关还没有装载采集目录，无法判断".to_string();
        return view;
    };

    let Some(machine_class) = machine_class else {
        view.undetermined_reason = Some("unclassified".to_string());
        view.summary = "这台机器还没判定用途，先判定机器类型".to_string();
        return view;
    };
    view.machine_class = Some(machine_class.clone());
    let Some(platform) = platform_for_machine_class(&machine_class) else {
        view.undetermined_reason = Some("unclassified".to_string());
        view.summary = format!("机器类型 {machine_class} 不认识");
        return view;
    };
    view.platform = Some(platform.to_string());
    // 目录变了（新增了路径）而实测结果还是旧的：如实标出来，别假装探过。
    // 只比**本平台**的路径：拿全平台名单比会永远非空（Linux 机器不该去探 macOS 的路径），
    // 那样「证据不完整就自动重探」会退化成「每次 409 都发命令」。
    if source != "none" {
        let probed: BTreeSet<&str> = facts.probed_paths.iter().map(String::as_str).collect();
        view.probe.not_probed_paths = content
            .probe_paths_for_platform(platform)
            .into_iter()
            .filter(|path| {
                !probed.contains(path.as_str()) && !unreadable_set.contains(path.as_str())
            })
            .collect();
    }
    let Some(template) = content.template_for_machine_class(&machine_class) else {
        view.undetermined_reason = Some("no_template".to_string());
        view.summary = format!("机器类型 {machine_class} 没有对应的采集模板");
        return view;
    };
    view.catalog_version = Some(template.catalog_version);
    if !has_facts {
        view.undetermined_reason = Some("no_facts".to_string());
        view.summary = "这台机器还没上报过事实，先探一次（点『预检』即可，不用登录）".to_string();
        return view;
    }

    let expansion = match content.expand(&template.template_id, &facts, sources) {
        Ok(expansion) => expansion,
        Err(err) => {
            // 模板/目录自相矛盾：如实报，不编结论。
            view.undetermined_reason = Some("catalog_error".to_string());
            view.summary = format!("采集目录自相矛盾：{err}");
            return view;
        }
    };

    for family in &template.family_scope {
        let selected_units: Vec<String> = expansion
            .works
            .iter()
            .find(|work| &work.family == family)
            .map(|work| work.selected_units.clone())
            .unwrap_or_default();
        let family_units: Vec<&Unit> = content
            .units()
            .filter(|unit| &unit.family == family && unit.platform == platform)
            .collect();
        let mut units = Vec::new();
        for unit in &family_units {
            let excluded = expansion
                .excluded_units
                .iter()
                .find(|excluded| excluded.unit_id == unit.unit_id);
            let paths = path_facts_for(&unit.match_expr, &facts, &unreadable_set);
            // `fact_not_collected` 再sharp一次：这条路径其实是「探不了」而不是「没探过」。
            let result = if selected_units.contains(&unit.unit_id) {
                "selected"
            } else if let Some(excluded) = excluded {
                let unreadable_condition = excluded
                    .condition
                    .as_deref()
                    .is_some_and(|condition| condition_is_unreadable(condition, &unreadable_set));
                if excluded.reason_code == "fact_not_collected" && unreadable_condition {
                    "unreadable"
                } else {
                    excluded.reason_code.as_str()
                }
            } else {
                // 面就绪后 expand 会把该面的**每条**单元分到选中或排除里，
                // 走到这里说明目录/模板被改坏了 —— 如实标，不猜。
                "fact_not_collected"
            };
            units.push(UnitView {
                unit_id: unit.unit_id.clone(),
                result: result.to_string(),
                match_expr: unit.match_expr.clone(),
                paths,
                unresolved_sources: excluded
                    .and_then(|excluded| excluded.condition.as_deref())
                    .and_then(|condition| condition.strip_prefix("log_source:"))
                    .map(|rest| {
                        rest.split(',')
                            .filter(|service| !service.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                min_agentd_version: excluded
                    .filter(|excluded| excluded.reason_code == "agent_too_old")
                    .and_then(|excluded| excluded.condition.as_deref())
                    .and_then(|condition| condition.strip_prefix("agentd_min_version:"))
                    .map(str::to_string),
            });
        }

        let state = if !selected_units.is_empty() {
            "grantable"
        } else if units.iter().any(|unit| unit.result == "collect_not_ready") {
            "not_ready"
        } else if units.iter().any(|unit| unit.result == "agent_too_old") {
            // 比“没探到 / 找不到日志”更前置：旧 agentd 根本承接不了这些来源，
            // 再让运维去查路径只会把人带到错方向。
            "agent_too_old"
        } else if units.iter().any(|unit| unit.result == "unreadable") {
            "unreadable"
        } else if units
            .iter()
            .any(|unit| unit.result == "source_not_resolved")
        {
            // 比「还没探」具体：探多少次不会变出一个目录来，处置是「配覆盖 / 开搜索」。
            "source_unresolved"
        } else if units.iter().any(|unit| unit.result == "fact_not_collected") {
            "unprobed"
        } else {
            "absent"
        };
        let instances = family_instances(&family_units, sources);
        let out_of_roots = family_out_of_roots(&family_units, sources);
        let reason = family_reason(
            state,
            &units,
            &unreadable,
            &expansion,
            instances.as_ref(),
            out_of_roots,
            sources.agent_version,
        );
        view.families.push(FamilyView {
            family: family.clone(),
            state: state.to_string(),
            reason,
            selected_units,
            units,
            instances,
        });
    }

    let total = view.families.len();
    let grantable = view
        .families
        .iter()
        .filter(|family| family.state == "grantable")
        .count();
    view.undetermined_reason = None;
    view.verdict = if grantable == 0 {
        "blocked".to_string()
    } else if grantable == total {
        "grantable".to_string()
    } else {
        "partial".to_string()
    };
    view.summary = match grantable {
        0 => match view.families.first() {
            Some(family) => match family.reason.as_deref() {
                Some(reason) => format!("没有可授权的采集面：{} {reason}", family.family),
                None => format!("没有可授权的采集面（{} 个面都不满足）", total),
            },
            None => "模板里没有采集面".to_string(),
        },
        count if count == total => format!("全部 {total} 个采集面都可授权"),
        count => format!(
            "{count}/{total} 个采集面可授权：{}",
            view.families
                .iter()
                .filter(|family| family.state == "grantable")
                .map(|family| family.family.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    if pending {
        view.summary.push_str("（已下发本机探测，约 3 秒后重试）");
    }
    view
}

/// 这个面辖区内的服务（`from_dir` 的 key）。
///
/// 一个面可以覆盖多个服务（`linux-db-service` 就是 postgres/mysql/redis/mongodb）。
fn family_services<'a>(units: &[&'a Unit]) -> BTreeSet<&'a str> {
    units
        .iter()
        .flat_map(|unit| unit.sources.iter())
        .filter_map(|source| source.log_service())
        .collect()
}

/// 「看到了几个实例、其中几个能采」—— 分母来自 `evidence = unresolved` 的占位行。
///
/// `None` = 这个面根本不靠日志目录（没有 `from_dir`），或一个实例也没看见。
fn family_instances(units: &[&Unit], sources: SourceContext<'_>) -> Option<InstanceCount> {
    let services = family_services(units);
    if services.is_empty() {
        return None;
    }
    let mut total = 0usize;
    let mut resolved = 0usize;
    for service in services {
        let rows: Vec<&StoredLogSource> = sources
            .log_sources
            .iter()
            .filter(|row| row.service == service)
            .collect();
        total += rows
            .iter()
            .map(|row| row.source_ref.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        resolved += resolve_dirs(rows.iter().copied(), service, sources.roots).len();
    }
    (total > 0).then_some(InstanceCount { resolved, total })
}

/// 有多少条候选被 `allowed_source_roots` 挡在外面。
///
/// 为什么要单独数：容器里跑的 PG 常把数据目录放在 named volume（
/// `/var/lib/docker/volumes/...`）—— 目录**是找到了**，只是不在默认 roots 里。
/// 不把这件事说出来，衜障会直接去查 `logging_collector`，方向就错了。
fn family_out_of_roots(units: &[&Unit], sources: SourceContext<'_>) -> usize {
    let services = family_services(units);
    sources
        .log_sources
        .iter()
        .filter(|row| services.contains(row.service.as_str()))
        .filter(|row| !row.dir.trim().is_empty() && !is_under_roots(&row.dir, sources.roots))
        .count()
}

/// 面级一句话：**只说该做什么**，不复述状态名。
///
/// 所有取值都限定在**这个面自己的单元**里：`expand` 的排除集是全域的，直接 `find`
/// 会把别的面的条件当成这个面的原因（现场会看到「容器面」报出数据库的条件）。
fn family_reason(
    state: &str,
    units: &[UnitView],
    unreadable: &[UnreadablePath],
    expansion: &Expansion,
    instances: Option<&InstanceCount>,
    out_of_roots: usize,
    agent_version: Option<&str>,
) -> Option<String> {
    match state {
        // 能授权但**没授全**："2 个实例，1 个没定位" 必须说出来，
        // 否则人会以为两个实例都在采。全部定位到时不扰民（返回 `None`）。
        "grantable" => instances.and_then(|counts| {
            (counts.resolved < counts.total).then(|| {
                format!(
                    "{} 个实例，其中 {} 个未定位（已定位的仍在采）",
                    counts.total,
                    counts.total - counts.resolved
                )
            })
        }),
        "not_ready" => Some("知识库还没把该面的采集单元标成 active（策展未就绪）".to_string()),
        "agent_too_old" => {
            // 点名**要求的版本**与**当前版本**：处置就一个字“升级”，别让人去查路径。
            let required = units
                .iter()
                .filter(|unit| unit.result == "agent_too_old")
                .find_map(|unit| unit.min_agentd_version.as_deref())
                .unwrap_or("");
            let current = match agent_version
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                Some(current) => format!("当前 {current}"),
                None => "当前版本还没上报".to_string(),
            };
            if required.is_empty() {
                Some(format!(
                    "这台机器的 agentd 版本太旧（{current}），升级后自动恢复"
                ))
            } else {
                Some(format!(
                    "这台机器的 agentd 需要 ≥ {required}（{current}），升级后自动恢复"
                ))
            }
        }
        "unreadable" => {
            // 点名**本面**探不了的那条路径，并把原始错误带上：
            // 「该去要权限」与「该换机器」只有这个错误文本能区分。
            let path = units
                .iter()
                .flat_map(|unit| unit.paths.iter())
                .find(|path| path.state == "unreadable")?
                .path
                .as_str();
            match unreadable.iter().find(|item| item.path == path) {
                Some(item) => Some(format!("探不了 {path}：{}", item.error)),
                None => Some(format!("探不了 {path}")),
            }
        }
        "unprobed" => units
            .iter()
            .flat_map(|unit| unit.paths.iter())
            .find(|path| path.state == "unprobed")
            .map(|path| format!("还没探过 {}", path.path))
            .or_else(|| {
                // 非路径条件（`installed:` / `port:` …）：本面无从判定时也要说清是哪一条。
                scoped_condition(units, expansion, "fact_not_collected")
                    .map(|condition| format!("无法判定条件 {condition}"))
            }),
        "source_unresolved" => {
            // 名字是**服务**，不是路径：这里要回答的是「哪个服务的日志没找到」，
            // 而路径恰恰是还没确定的那件事。
            let services: Vec<&str> = units
                .iter()
                .flat_map(|unit| unit.unresolved_sources.iter().map(String::as_str))
                .collect();
            let counts = match instances {
                Some(counts) if counts.total > 0 => format!(
                    "{} 个实例在监听，其中 {} 个已定位",
                    counts.total, counts.resolved
                ),
                _ => "服务在".to_string(),
            };
            let mut reason = if services.is_empty() {
                format!("{counts}，但找不到日志目录（先配人工覆盖，或开受限搜索）")
            } else {
                format!(
                    "{counts}，但找不到 {} 的日志目录（先配人工覆盖，或开受限搜索）",
                    services.join(", ")
                )
            };
            if out_of_roots > 0 {
                reason.push_str(&format!(
                    "；另有 {out_of_roots} 条候选在 allowed_source_roots 外，需要放宽 [collection] 配置"
                ));
            }
            Some(reason)
        }
        _ => units
            .iter()
            .find(|unit| unit.result == "match_unsatisfied")
            .map(|unit| {
                // 优先用实测路径说人话；没有路径条件（如 `installed:`）就退回原始条件。
                //
                // **不要写「这台机器没有 X」**：路径只是目录约定的位置，服务完全可能装在
                // `/data/db/...` 下。那句断言会把运维带去查「是不是没装」，方向刚好相反。
                match unit.paths.iter().find(|path| path.state == "absent") {
                    Some(path) => format!(
                        "目录约定的位置没有 {}（服务可能装在非标准目录，尚未自动定位）",
                        path.path
                    ),
                    None => match scoped_condition(units, expansion, "match_unsatisfied") {
                        Some(condition) => format!("不满足条件 {condition}"),
                        None => format!("不满足条件 {}", unit.match_expr),
                    },
                }
            }),
    }
}

/// 在**本面**的单元里找第一条该原因的条件（跨面取值是 bug，不是便利）。
fn scoped_condition<'a>(
    units: &[UnitView],
    expansion: &'a Expansion,
    reason_code: &str,
) -> Option<&'a str> {
    let unit_ids: BTreeSet<&str> = units.iter().map(|unit| unit.unit_id.as_str()).collect();
    expansion
        .excluded_units
        .iter()
        .find(|excluded| {
            excluded.reason_code == reason_code && unit_ids.contains(excluded.unit_id.as_str())
        })
        .and_then(|excluded| excluded.condition.as_deref())
}

/// 从 `match` 表达式里挑出 `path_exists:` / `not_path_exists:` 的路径及其实测值。
///
/// 条件值可以写成 `path_exists:/a|/b`（任一命中即成立），所以 `|` 也要拆开 ——
/// 否则页面上会显示一条不存在的"路径"，人会照着它去 `ls`。
fn path_facts_for(
    match_expr: &str,
    facts: &StoredAgentFactSummary,
    unreadable: &BTreeSet<&str>,
) -> Vec<PathFactView> {
    let probed: BTreeSet<&str> = facts.probed_paths.iter().map(String::as_str).collect();
    let present: BTreeSet<&str> = facts.present_paths.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    // `any:port:5432|path_exists:/a` 里的路径也要显示：否则「端口不够、看路径」那半边
    // 在页面上完全看不见，人无从判断到底探过没探过。
    let mut push = |kind: &str, value: &str| {
        if kind != "path_exists" && kind != "not_path_exists" {
            return;
        }
        for path in value
            .split('|')
            .map(str::trim)
            .filter(|path| path.starts_with('/'))
        {
            let state = if present.contains(path) {
                "present"
            } else if probed.contains(path) {
                // 探过但不在（`not_path_exists` 条件正是靠这一条成立）。
                "absent"
            } else if unreadable.contains(path) {
                "unreadable"
            } else {
                "unprobed"
            };
            if out.iter().any(|item: &PathFactView| item.path == path) {
                continue;
            }
            out.push(PathFactView {
                path: path.to_string(),
                state: state.to_string(),
            });
        }
    };
    for token in match_expr.split([';', ' ']) {
        let token = token.trim();
        let Some((kind, value)) = token.split_once(':') else {
            continue;
        };
        if kind == "any" {
            for sub in value.split('|') {
                if let Some((sub_kind, sub_value)) = sub.split_once(':') {
                    push(sub_kind.trim(), sub_value);
                }
            }
            continue;
        }
        push(kind, value);
    }
    out
}

/// `path_exists:/a|/b` 的值是**候选集**：任一路径探不了，这条条件就“无法判定”，
/// 而不是“还没探”（后者会让人去重复一遍已经跑过的探测）。
fn condition_is_unreadable(condition: &str, unreadable: &BTreeSet<&str>) -> bool {
    let Some((kind, value)) = condition.split_once(':') else {
        return false;
    };
    if kind != "path_exists" && kind != "not_path_exists" {
        return false;
    }
    value
        .split('|')
        .map(str::trim)
        .any(|path| unreadable.contains(path))
}

fn age_seconds(observed_at: &str, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(observed_at)
        .ok()
        .map(|at| (now - at.with_timezone(&chrono::Utc)).num_seconds().max(0))
}

/// 实测结果是不是**这条命令之后**才拿到的。
///
/// 是 = 结果已经回来了，只是回执还在下一拍状态上报里 —— 此时不该再显示「探测中」。
/// 时间解析不了就当没有（宁可多显示 2 秒「探测中」，也不要拿一份错时序当成已回传）。
fn probe_reported_after(probe: Option<&StoredAgentPathProbe>, requested_at_ms: i64) -> bool {
    let Some(probe) = probe else {
        return false;
    };
    parse_rfc3339_millis(&probe.observed_at).is_some_and(|at| at >= requested_at_ms)
}

fn parse_rfc3339_millis(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|at| at.timestamp_millis())
}

// ─────────────────────────────────────────────────────────────────────────────
// 管理面入口
// ─────────────────────────────────────────────────────────────────────────────

/// `GET /api/v1/admin/agents/{agent_id}/collection-preflight`
///
/// 看结论。不触发任何动作 —— 页面先 GET，看到 `probe.source = none` 或
/// `probe.not_probed_paths` 非空时再 POST。
pub async fn view_agent_preflight(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    match evaluate(&state, &agent_id).await {
        Ok(view) => Json(view).into_response(),
        Err(err) => err.into_response(),
    }
}

/// `POST /api/v1/admin/agents/{agent_id}/collection-preflight`
///
/// 让**机器自己**再探一次（不需要任何人登录）。返回的是入队后的视图：
/// `probe.pending = true`，调用方据此轮询 GET。
///
/// 重复点击是幂等的：同 kind 的未确认命令会被覆盖（`superseded`）。
pub async fn run_agent_preflight(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    match enqueue_probe(&state, &agent_id).await {
        Ok(()) => {}
        Err(err) => return err.into_response(),
    }
    match evaluate(&state, &agent_id).await {
        Ok(view) => Json(view).into_response(),
        Err(err) => err.into_response(),
    }
}

/// 授权被拒（409）时顺手让机器再探一次 —— **只在「证据缺失」时**。
///
/// 为什么放在 409 上：这是现场唯一的入口（人点了授权、被拒了）。让他再去点一次「预检」
/// 是多余的一步；探针是只读、毫秒级的，代价可以忽略。页面下一次重试（≥3s）就拿到实测了。
///
/// 已经探全的证据不再重探（`not_probed_paths` 为空且没有 `unprobed` 面）——
/// 那种情况下重探不会改变结论，只是白跑一趟。
pub async fn enqueue_if_evidence_missing(state: &ApiState, agent_id: &str) -> bool {
    let Ok(view) = evaluate(state, agent_id).await else {
        return false;
    };
    let missing = !view.probe.not_probed_paths.is_empty()
        || view
            .families
            .iter()
            .any(|family| family.state == "unprobed");
    if !missing {
        return false;
    }
    enqueue_probe(state, agent_id).await.is_ok()
}

/// 这条命令是「只探路径」还是「整轮重采」。
///
/// 判据必须与 agentd 的 `parse_probe_request` 同源：那里认 `scope = paths`，
/// 这里就只认这个（发出去的空 params 一律当整轮重采）。
fn probe_command_is_path_scoped(params: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(params.trim())
        .ok()
        .and_then(|value| value.get("scope")?.as_str().map(str::to_string))
        .is_some_and(|scope| scope == "paths")
}

/// 入队一条「只探这些路径」的命令。
///
/// 路径取自当前目录（`ContentSet::probe_paths`）—— 它同时是授权求值要用的那批，
/// 同源才不会出现「求值要的路径没探」。
#[allow(clippy::result_large_err)]
async fn enqueue_probe(state: &ApiState, agent_id: &str) -> Result<(), ApiError> {
    let Some(content) = state.knowledge().content.clone() else {
        // 没有目录就没有可探的路径；结论本身已经是 `no_content`，不必入队。
        return Ok(());
    };
    // 已经有一条**全量重采**在路上：它会连路径一起刷新。再发一条只探路径的命令
    // 会把它顶掉（同 kind 覆盖），反而丢掉进程/端口那部分 —— 那是净损失。
    // 探针命令之间才会互相覆盖（重复点击只保留最后一次，这才是想要的）。
    if let Ok(Some(pending)) = state
        .store
        .get_latest_agent_command(agent_id, wist_api::status::command_kind::REFRESH_FACTS)
        .await
        && pending.acked_at.is_none()
        && pending.outcome.is_none()
        && !probe_command_is_path_scoped(&pending.params)
    {
        return Ok(());
    }
    // 只探**这台机器所在平台**的路径（见 `probe_paths_for_platform`）。没判定就没有
    // 可回答的问题 —— 探了也不会改变 `unclassified` 那个结论。
    let platform = state
        .store
        .get_agent_classification(agent_id)
        .await
        .ok()
        .flatten()
        .and_then(|classification| platform_for_machine_class(&classification.machine_class));
    let Some(platform) = platform else {
        return Ok(());
    };
    let paths = content.probe_paths_for_platform(platform);
    if paths.is_empty() {
        return Ok(());
    }
    let now = chrono::Utc::now();
    let command = crate::infra::StoredAgentCommand {
        // 微秒做 id：同一毫秒内的两次点击不能撞成一个 id（撞了会被 `DO NOTHING` 吞掉）。
        command_id: format!("cmd_{agent_id}_preflight_{}", now.timestamp_micros()),
        agent_id: agent_id.to_string(),
        kind: wist_api::status::command_kind::REFRESH_FACTS.to_string(),
        params: probe_command_params(&paths),
        requested_at_ms: now.timestamp_millis(),
        acked_at: None,
        outcome: None,
        detail: None,
        // 采集预检也是管理面发起的动作：“谁让这台机器去探路径”一并留痕。
        requested_by: super::admin_auth::admin_actor(&state.config),
    };
    state
        .store
        .enqueue_agent_command(&command, true)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::PREFLIGHT_UNAVAILABLE,
                "failed to enqueue collection preflight",
                err,
            )
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent 入口
// ─────────────────────────────────────────────────────────────────────────────

/// `POST /api/v1/agent/collection-preflight`
///
/// **agentd 自己调**（不是人跑 CLI）。带上本机实测的路径结果 → 网关落库 → 返回同一份视图
/// （agent 一般不看，但让实验室用 curl 复现时行为一致）。
///
/// 校验只做**自洽性**（`present ⊆ probed`），不校验「路径是否在目录白名单内」：
/// 目录在命令下发和回传之间可能被换版，为这个 400 会白白丢掉一次实测结果 ——
/// 而多出来的路径对求值无害（求值只查 `match` 里出现过的路径）。
pub async fn agent_preflight(
    State(state): State<ApiState>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<AgentPreflightReport>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != PREFLIGHT_KIND {
        return ApiError::bad_request(
            codes::INVALID_PREFLIGHT_REQUEST,
            "invalid collection preflight report",
        )
        .into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        return response;
    }
    if let Err(message) = validate_report(&input) {
        return ApiError::bad_request(codes::INVALID_PREFLIGHT_REQUEST, message).into_response();
    }

    let now = chrono::Utc::now();
    let observed_at = normalize_observed_at(&input.observed_at, now);
    let probe = StoredAgentPathProbe {
        agent_id: input.agent_id.clone(),
        observed_at: observed_at.clone(),
        probed_paths: input.probed_paths.clone(),
        present_paths: input.present_paths.clone(),
        unreadable_paths: input.unreadable_paths.clone(),
        received_at: now.to_rfc3339(),
    };
    // 乱序到达的结果不能把更新的那份盖掉：重试 / 双发 / 两次点击都可能造成乱序，
    // 而「谁更新」只有 `observed_at` 能回答。读失败就照写（不因读抖动卡住回传）。
    if let Ok(Some(existing)) = state.store.get_agent_path_probe(&input.agent_id).await
        && let (Some(existing_at), Some(new_at)) = (
            parse_rfc3339_millis(&existing.observed_at),
            parse_rfc3339_millis(&observed_at),
        )
        && existing_at > new_at
    {
        log::info!(
            "event=CollectionPreflightIgnoredStale agent_id={} existing={} incoming={}",
            input.agent_id,
            existing.observed_at,
            observed_at
        );
        return match evaluate(&state, &input.agent_id).await {
            Ok(view) => Json(view).into_response(),
            Err(err) => err.into_response(),
        };
    }
    if let Err(err) = state.store.upsert_agent_path_probe(&probe).await {
        return ApiError::internal(
            codes::PREFLIGHT_UNAVAILABLE,
            "failed to store collection preflight",
            err,
        )
        .into_response();
    }
    log::info!(
        "event=CollectionPreflightReported agent_id={} probed={} present={} unreadable={}",
        input.agent_id,
        input.probed_paths.len(),
        input.present_paths.len(),
        input.unreadable_paths.len()
    );
    match evaluate(&state, &input.agent_id).await {
        Ok(view) => Json(view).into_response(),
        Err(err) => err.into_response(),
    }
}

/// 把 agent 报上来的观测时刻变成可信的一份。
///
/// 客户主机的时钟是**最不可靠的输入**之一（快照时间经常跑偏几小时）：
///   * 解析不了 → 用网关收到的时刻；
///   * 跑到了未来（> 5 分钟）→ 用网关收到的时刻。否则 `stale` 会永远为假，
///     而一个“永远新鲜”的证据比没有证据更危险；
///   * 过去的时间原样保留 —— 那是真实信息（例如 machine 刚重启、agentd 刚起来）。
fn normalize_observed_at(raw: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::minutes(5);
    match chrono::DateTime::parse_from_rfc3339(raw.trim()) {
        Ok(at) => {
            let at = at.with_timezone(&chrono::Utc);
            if at > now + MAX_FUTURE_SKEW {
                log::warn!(
                    "event=CollectionPreflightClockSkew reported={} gateway={}（用网关时刻）",
                    raw,
                    now.to_rfc3339()
                );
                now.to_rfc3339()
            } else {
                at.to_rfc3339()
            }
        }
        Err(_) => now.to_rfc3339(),
    }
}

fn validate_report(input: &AgentPreflightReport) -> Result<(), String> {
    if input.probed_paths.len() + input.unreadable_paths.len() > MAX_PROBE_PATHS {
        return Err(format!(
            "too many paths (max {MAX_PROBE_PATHS}): probed={} unreadable={}",
            input.probed_paths.len(),
            input.unreadable_paths.len()
        ));
    }
    let probed: BTreeSet<&str> = input.probed_paths.iter().map(String::as_str).collect();
    if let Some(not_probed) = input
        .present_paths
        .iter()
        .find(|path| !probed.contains(path.as_str()))
    {
        // 子集关系不成立 = 上报方坏了。静默收下会让求值读到一套自相矛盾的事实。
        return Err(format!(
            "present path {not_probed:?} was not probed (present must be a subset of probed)"
        ));
    }
    if input
        .probed_paths
        .iter()
        .chain(input.unreadable_paths.iter().map(|item| &item.path))
        .any(|path| !path.starts_with('/'))
    {
        return Err("path probe results must be absolute paths".to_string());
    }
    if let Some(long) = input
        .probed_paths
        .iter()
        .chain(input.unreadable_paths.iter().map(|item| &item.path))
        .find(|path| path.len() > MAX_PROBE_PATH_LEN)
    {
        return Err(format!(
            "path is too long ({} > {MAX_PROBE_PATH_LEN}): {}…",
            long.len(),
            &long[..32.min(long.len())]
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(probed: &[&str], present: &[&str]) -> StoredAgentFactSummary {
        StoredAgentFactSummary {
            probed_paths: probed.iter().map(|value| value.to_string()).collect(),
            present_paths: present.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn path_facts_split_alternatives_and_name_the_state() {
        let facts = facts(&["/var/log/containers"], &["/var/log/containers"]);
        let unreadable: BTreeSet<&str> = ["/var/log/pods"].into_iter().collect();
        let out = path_facts_for(
            "installed:docker;path_exists:/a|/b;not_path_exists:/var/log/containers;\
             path_exists:/var/log/pods",
            &facts,
            &unreadable,
        );

        let states: Vec<(&str, &str)> = out
            .iter()
            .map(|fact| (fact.path.as_str(), fact.state.as_str()))
            .collect();
        assert_eq!(
            states,
            vec![
                ("/a", "unprobed"),
                ("/b", "unprobed"),
                // 否定条件也要给实测值：它同样是「为什么没命中」的证据。
                ("/var/log/containers", "present"),
                ("/var/log/pods", "unreadable"),
            ]
        );
    }

    #[test]
    fn a_probed_but_missing_path_is_absent_not_unprobed() {
        let facts = facts(&["/var/lib/docker/containers"], &[]);
        let out = path_facts_for(
            "path_exists:/var/lib/docker/containers",
            &facts,
            &BTreeSet::new(),
        );
        assert_eq!(out[0].state, "absent");
    }

    #[test]
    fn validate_rejects_present_paths_that_were_not_probed() {
        let report = AgentPreflightReport {
            probed_paths: vec!["/a".to_string()],
            present_paths: vec!["/b".to_string()],
            ..Default::default()
        };
        assert!(validate_report(&report).is_err());
    }

    #[test]
    fn validate_rejects_relative_paths() {
        let report = AgentPreflightReport {
            probed_paths: vec!["relative/path".to_string()],
            ..Default::default()
        };
        assert!(validate_report(&report).is_err());
    }

    #[test]
    fn validate_accepts_a_consistent_report() {
        let report = AgentPreflightReport {
            probed_paths: vec!["/a".to_string()],
            present_paths: vec!["/a".to_string()],
            unreadable_paths: vec![UnreadablePath {
                path: "/b".to_string(),
                error: "permission denied".to_string(),
            }],
            ..Default::default()
        };
        assert!(validate_report(&report).is_ok());
    }

    fn view_unit(unit_id: &str, result: &str, paths: Vec<PathFactView>) -> UnitView {
        UnitView {
            unit_id: unit_id.to_string(),
            result: result.to_string(),
            match_expr: String::new(),
            paths,
            unresolved_sources: Vec::new(),
            min_agentd_version: None,
        }
    }

    fn path(path: &str, state: &str) -> PathFactView {
        PathFactView {
            path: path.to_string(),
            state: state.to_string(),
        }
    }

    fn expansion_with(excluded: Vec<crate::app::content::ExcludedUnit>) -> Expansion {
        Expansion {
            template_id: "t".to_string(),
            machine_class: "LinuxHost".to_string(),
            platform: "linux".to_string(),
            works: Vec::new(),
            excluded_units: excluded,
        }
    }

    #[test]
    fn a_family_reason_never_borrows_another_familys_condition() {
        // `expand` 的排除集是**全域**的；直接 find 会让「容器面」报出数据库的条件。
        let units = vec![view_unit("linux-db", "fact_not_collected", Vec::new())];
        let expansion = expansion_with(vec![
            crate::app::content::ExcludedUnit {
                unit_id: "linux-container-stdout".to_string(),
                reason_code: "fact_not_collected".to_string(),
                condition: Some("path_exists:/var/log/containers".to_string()),
            },
            crate::app::content::ExcludedUnit {
                unit_id: "linux-db".to_string(),
                reason_code: "fact_not_collected".to_string(),
                condition: Some("installed:postgresql".to_string()),
            },
        ]);

        let reason =
            family_reason("unprobed", &units, &[], &expansion, None, 0, None).expect("reason");
        assert!(reason.contains("installed:postgresql"), "{reason}");
        assert!(!reason.contains("/var/log/containers"), "{reason}");
    }

    /// 字段名被**页面读取**且是可选的：名字漂了只会静默不显示，所以钉住。
    #[test]
    fn a_unit_view_pins_the_min_agentd_version_wire_name() {
        let mut unit = view_unit("linux-db", "agent_too_old", Vec::new());
        unit.min_agentd_version = Some("0.10.0".to_string());
        let json = serde_json::to_value(&unit).expect("serialize");
        assert_eq!(json["min_agentd_version"], "0.10.0");

        // 没有要求时不输出：旧响应字节不变（页面按“没有要求”处理）。
        let json = serde_json::to_value(view_unit("u", "selected", Vec::new())).expect("serialize");
        assert!(json.get("min_agentd_version").is_none(), "{json}");
    }

    #[test]
    fn an_agent_too_old_reason_names_both_versions() {
        let mut unit = view_unit("linux-db", "agent_too_old", Vec::new());
        unit.min_agentd_version = Some("0.10.0".to_string());
        let reason = family_reason(
            "agent_too_old",
            &[unit],
            &[],
            &empty_expansion(),
            None,
            0,
            Some("0.9.13"),
        )
        .expect("reason");
        assert_eq!(
            reason,
            "这台机器的 agentd 需要 ≥ 0.10.0（当前 0.9.13），升级后自动恢复"
        );
    }

    #[test]
    fn an_agent_too_old_reason_handles_a_missing_version() {
        let mut unit = view_unit("linux-db", "agent_too_old", Vec::new());
        unit.min_agentd_version = Some("0.10.0".to_string());
        let reason = family_reason(
            "agent_too_old",
            &[unit],
            &[],
            &empty_expansion(),
            None,
            0,
            None,
        )
        .expect("reason");
        assert!(reason.contains("还没上报"), "{reason}");
    }

    #[test]
    fn an_unreadable_reason_names_the_familys_own_path() {
        let units = vec![view_unit(
            "linux-docker-container-stdout",
            "unreadable",
            vec![path("/var/lib/docker/containers", "unreadable")],
        )];
        let unreadable = vec![
            UnreadablePath {
                path: "/var/log/pods".to_string(),
                error: "denied-pods".to_string(),
            },
            UnreadablePath {
                path: "/var/lib/docker/containers".to_string(),
                error: "denied-docker".to_string(),
            },
        ];

        let reason = family_reason(
            "unreadable",
            &units,
            &unreadable,
            &empty_expansion(),
            None,
            0,
            None,
        )
        .expect("reason");
        assert_eq!(reason, "探不了 /var/lib/docker/containers：denied-docker");
    }

    #[test]
    fn an_absent_condition_falls_back_to_this_familys_condition() {
        let units = vec![view_unit("linux-db", "match_unsatisfied", Vec::new())];
        let expansion = expansion_with(vec![
            crate::app::content::ExcludedUnit {
                unit_id: "linux-container-stdout".to_string(),
                reason_code: "match_unsatisfied".to_string(),
                condition: Some("path_exists:/var/log/containers".to_string()),
            },
            crate::app::content::ExcludedUnit {
                unit_id: "linux-db".to_string(),
                reason_code: "match_unsatisfied".to_string(),
                condition: Some("installed:postgresql".to_string()),
            },
        ]);

        let reason =
            family_reason("absent", &units, &[], &expansion, None, 0, None).expect("reason");
        assert!(reason.contains("installed:postgresql"), "{reason}");
    }

    #[test]
    fn an_absent_path_says_the_expected_location_is_empty_not_that_the_host_lacks_it() {
        // 这句话以前是「这台机器没有 /var/log/postgresql」，现场会照着它去查「是不是没装数据库」。
        // 实际路径只是目录约定的位置，结论只能到「约定位置没有」为止。
        let units = vec![view_unit(
            "linux-db",
            "match_unsatisfied",
            vec![path("/var/log/postgresql", "absent")],
        )];

        let reason = family_reason("absent", &units, &[], &empty_expansion(), None, 0, None)
            .expect("reason");
        assert_eq!(
            reason,
            "目录约定的位置没有 /var/log/postgresql（服务可能装在非标准目录，尚未自动定位）"
        );
        assert!(!reason.contains("这台机器没有"), "{reason}");
    }

    fn empty_expansion() -> Expansion {
        expansion_with(Vec::new())
    }

    #[test]
    fn an_alternation_with_one_unreadable_path_is_still_unreadable() {
        // `path_exists:/a|/b` 的值是候选集，任一路径探不了 → 条件无法判定，
        // 而不是“还没探”（后者会让人去重复一遍已经跑过的探测）。
        let unreadable: BTreeSet<&str> = ["/b"].into_iter().collect();
        assert!(condition_is_unreadable("path_exists:/a|/b", &unreadable));
        assert!(!condition_is_unreadable("path_exists:/a|/c", &unreadable));
        // 非路径条件不参与这个判断（`installed:` 的“不知道”另有来源）。
        assert!(!condition_is_unreadable(
            "installed:postgresql",
            &unreadable
        ));
    }

    #[test]
    fn validate_rejects_absurdly_long_paths() {
        let long = format!("/{}", "a".repeat(2048));
        let report = AgentPreflightReport {
            probed_paths: vec![long],
            ..Default::default()
        };
        assert!(validate_report(&report).is_err());
    }

    #[test]
    fn observed_at_falls_back_to_the_gateway_clock_when_it_cannot_be_trusted() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        // 空 / 垃圾：用网关时刻（不能拿一个假时间当事实）。
        assert_eq!(normalize_observed_at("", now), now.to_rfc3339());
        assert_eq!(normalize_observed_at("yesterday", now), now.to_rfc3339());

        // 客户主机时钟跑到未来：用网关时刻，否则 `stale` 永远为假。
        let future = (now + chrono::Duration::minutes(30)).to_rfc3339();
        assert_eq!(normalize_observed_at(&future, now), now.to_rfc3339());

        // 过去的时间是真信息，原样保留（只做时区归一）。
        let past = "2026-10-26T10:00:00Z";
        assert_eq!(
            normalize_observed_at(past, now),
            chrono::DateTime::parse_from_rfc3339(past)
                .unwrap()
                .with_timezone(&chrono::Utc)
                .to_rfc3339()
        );

        // 轻微超前（5 分钟内）仍按 agent 的时刻 —— 正常网络/时钟抖动不该被改写。
        let slightly_ahead = (now + chrono::Duration::seconds(30)).to_rfc3339();
        assert_eq!(normalize_observed_at(&slightly_ahead, now), slightly_ahead);
    }

    #[test]
    fn age_seconds_is_none_for_an_unparseable_timestamp() {
        let now = chrono::Utc::now();
        assert_eq!(age_seconds("not a timestamp", now), None);
        assert_eq!(age_seconds(&now.to_rfc3339(), now), Some(0));
    }
}
