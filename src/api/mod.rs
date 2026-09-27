// @jumo generated
// @jumo hash=2ff63c2da808b5ca

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

use crate::app::content::ContentSet;
use crate::app::purpose::PurposeRuleTable;
use crate::infra::{AdminConfig, Store};
use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;

mod admin_auth;
mod admin_ops;
mod agent_ops;
mod enrollment;
mod host_metrics;
mod ingest;
mod install;
// NOTE(hand-added): 安装包的拉取/本地缓存（管理面设置来源地址后网关先拉到本地，
// 之后统一从网关分发）。对应 jumo 模型 WistGatewayManagementInterface 的
// AdminSetAgentInstallPackageAddress 与 AgentInstallPackageAddress；新路由未变，
// 只是 POST 的语义落实到本模块。重新生成控制面代码时需回补本模块。
mod install_package;
// NOTE(hand-added): 采集日志的本地落盘与查看（数据面转发 + 管理面读文件）。
// 不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics / pipeline 同一模式。
// 重新生成控制面代码时需回补本模块与下方路由。
mod logs;
mod overview;
// NOTE(hand-added): pipeline 不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics
// 同一模式（模型里也没有 host-metrics 路由）。重新生成控制面代码时需回补本模块与下方路由。
mod pipeline;
mod rate_limit;
// NOTE(hand-added): 采集内容目录的只读视图（模板组成 + 面就绪度）。不在 jumo 静态模型
// binding.mju 的声明里，与 software_ops 同一模式。重新生成控制面代码时需回补本模块与路由。
mod content_ops;
// NOTE(hand-added): L1a 机械资产清单（从事实摘要派生）。不在 jumo 静态模型 binding.mju
// 的声明里，与 host_metrics / pipeline 同一模式。重新生成控制面代码时需回补本模块与下方路由。
mod software_ops;
// NOTE(hand-added): 灰度发布计划（模型 Control.Rollout）：创建/列表/批准/推进/查看。
// 计划是编排层，批准/推进时才物化成 OneShotWork；与 agent_ops 的 submit_work_result
// 通过 reconcile_rollout_entry 回填条目。重新生成控制面代码时需回补本模块与下方路由。
mod rollout_ops;

pub mod wist_gateway_management_interface;
pub mod wist_gateway_public_install_interface;
pub use wist_gateway_management_interface::WarpGatewayManagementInterface;
pub mod wist_agentd_online_registration_interface;
pub use wist_agentd_online_registration_interface::WistAgentdOnlineRegistrationInterface;

use admin_ops::{
    classify_agent, get_agent_runtime_status, grant_work, list_agent_install_packages, list_agents,
    pause_work, resume_work, revoke_agent_credential, revoke_work, set_agent_advertise_url,
    set_agent_install_package, set_agent_uplink, view_agent_advertise_url,
    view_agent_install_package, view_agent_purpose, view_agent_uplink, view_agent_work,
    view_discovery_policies, view_purpose_coverage,
};
use agent_ops::{
    ack_work, poll_agent_uplink, poll_control_commands, poll_discovery_policies, poll_work,
    renew_agent_credential, report_action_result, submit_agent_status, submit_work_result,
};
use content_ops::view_content;
use enrollment::enroll_agent;
use host_metrics::{get_agent_host_metrics, get_all_agents_host_metrics};
use ingest::{MAX_INGEST_BODY_BYTES, ingest_agent_facts};
use install::{
    download_agent_package, download_agent_package_by_id, get_agent_initial_config_with_token,
    get_agent_install_code, get_agent_install_script, get_agent_install_script_signature,
};
use logs::{MAX_LOG_INGEST_BODY_BYTES, ingest_agent_logs, view_agent_logs};
use overview::{RecentOnlineRegisteredAgent, get_agent_overview};
use pipeline::get_pipeline_topology;
use rollout_ops::{
    advance_rollout_plan, approve_rollout_plan, create_rollout_plan, list_rollout_plans,
    view_rollout_plan,
};
use software_ops::{view_agent_software, view_software_holdings};

pub mod work_expiry;
pub use work_expiry::{
    ONE_SHOT_EXPIRY_TICK, expire_overdue_one_shot_works, spawn_one_shot_expiry_tick,
};

#[derive(Debug, Clone)]
pub struct ApiState {
    pub config: AdminConfig,
    pub store: Arc<dyn Store>,
    pub runtime: Arc<Mutex<AdminRuntimeState>>,
    pub rate_limits: Arc<Mutex<rate_limit::RateLimitState>>,
    /// 已装载的用途推断规则表；未配置 `[purpose] rules_file` 时为 `None`。
    ///
    /// 启动时装载一次并缓存（改规则通过重启生效）：规则表是策展数据，改它要走审定，
    /// 不做热加载 —— 热加载会让"哪一版规则算出的这个建议"变得说不清。
    pub purpose_rules: Option<Arc<PurposeRuleTable>>,
    /// 已装载的发现方向策略表；未配置 `[discovery] policies_file` 时为 `None`。
    ///
    /// 与规则表同理：启动时装载一次并缓存（改策略通过重启生效）。`None` 时下发端点
    /// 回 503，而不是发一份空表 —— 空表会让「平台没发布策略」与「从未配置」无法区分。
    pub discovery_policies: Option<Arc<DiscoveryAspectPolicySet>>,
    /// 已装载的采集内容集（catalog + packs + templates）；三者缺一则为 `None`。
    ///
    /// 与规则表/策略表同理：启动时装载一次并缓存（改内容通过重启生效）。`None` 时
    /// 内容相关能力（模板展开）不可用，但不影响事实入库 / 用途推断 / 资产清单。
    pub content: Option<Arc<ContentSet>>,
}

/// 启动时装载规则表。
///
/// `AdminConfig::validate` 已经解析过一次（配置错就起不来），走到这里还失败，
/// 说明文件在启动后被改动过 —— 记一条警告并当作"未配置"。事实照常入库。
fn load_purpose_rules(config: &AdminConfig) -> Option<Arc<PurposeRuleTable>> {
    let path = config.purpose_rules_file.as_deref()?;
    match crate::app::purpose::load_rule_table(path) {
        Ok(table) => Some(Arc::new(table)),
        Err(err) => {
            eprintln!(
                "warning: failed to load purpose rule table {}: {err}",
                path.display()
            );
            None
        }
    }
}

/// 启动时装载发现方向策略表。
///
/// 与规则表同样的退化策略：`AdminConfig::validate` 已经校验过一次（配置错就起不来），
/// 走到这里还失败，说明文件在启动后被改动过 —— 记一条警告并当作"未配置"（端点回 503）。
fn load_discovery_policies(config: &AdminConfig) -> Option<Arc<DiscoveryAspectPolicySet>> {
    let path = config.discovery_policies_file.as_deref()?;
    match crate::app::discovery_policy::load_policy_table(path) {
        Ok(set) => Some(Arc::new(set)),
        Err(err) => {
            eprintln!(
                "warning: failed to load discovery aspect policy table {}: {err}",
                path.display()
            );
            None
        }
    }
}

/// 启动时装载采集内容三件套（catalog / packs / templates）。
///
/// 与规则表/策略表同样的退化策略：`AdminConfig::validate` 已用真实装载器校验过一次
/// （内容写错就起不来），走到这里还失败说明文件在启动后被改动过 —— 记警告并当作“未装载”。
fn load_content(config: &AdminConfig) -> Option<Arc<ContentSet>> {
    let catalog = config.content_catalog_file.as_deref()?;
    let packs = config.content_packs_file.as_deref()?;
    let templates = config.content_templates_file.as_deref()?;
    match crate::app::content::load_content(catalog, packs, templates) {
        Ok(set) => Some(Arc::new(set)),
        Err(err) => {
            eprintln!("warning: failed to load collection content: {err}");
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct AdminRuntimeState {
    pub recent_online_agents: Vec<RecentOnlineRegisteredAgent>,
}

pub fn router(config: AdminConfig, store: Arc<dyn Store>) -> Router {
    router_with_state(build_state(config, store))
}

/// 装配共享状态。两个监听（对外 HTTPS / 数据面内部 HTTP）**共用同一份**：
/// 规则表、策略表、会话运行态与限流器都只能有一份，否则两条路径的行为会不一致。
pub fn build_state(config: AdminConfig, store: Arc<dyn Store>) -> ApiState {
    let purpose_rules = load_purpose_rules(&config);
    let discovery_policies = load_discovery_policies(&config);
    let content = load_content(&config);
    ApiState {
        config,
        store,
        runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
        rate_limits: Arc::new(Mutex::new(rate_limit::RateLimitState::default())),
        purpose_rules,
        discovery_policies,
        content,
    }
}

/// 数据面订阅端的**内部**路由：只含内部接入端点，不挂任何管理面/agent 面路由。
///
/// 为什么要单独一个 router：它要挂到**明文**监听上（见 `main.rs` 与 `infra::config` 的 `[ingest]` 段）。
/// 对外那张监听是 HTTPS（自签证书），而 warp-parse 的 sink 连接器没有 TLS 参数，接不上。
pub fn ingest_router(state: ApiState) -> Router {
    Router::new()
        .route(
            "/api/v1/ingest/agent-facts",
            post(ingest_agent_facts).layer(DefaultBodyLimit::max(MAX_INGEST_BODY_BYTES)),
        )
        // NOTE(hand-added): 采集日志的落盘（同一张内部监听，见 api/logs.rs）。
        .route(
            "/api/v1/ingest/agent-logs",
            post(ingest_agent_logs).layer(DefaultBodyLimit::max(MAX_LOG_INGEST_BODY_BYTES)),
        )
        .with_state(state)
}

pub fn router_with_state(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/agent/install-code", get(get_agent_install_code))
        .route(
            "/api/v1/agent/install/{arch}/install.sh",
            get(get_agent_install_script),
        )
        .route(
            "/api/v1/agent/install/{arch}/install.sh.sig",
            get(get_agent_install_script_signature),
        )
        .route(
            "/api/v1/agent/initial-config",
            get(get_agent_initial_config_with_token),
        )
        .route(
            "/api/v1/agent/packages/current",
            get(download_agent_package),
        )
        // NOTE(hand-added): 按内容寻址 id 取某个录入过的安装包（升级路径）。
        // 与 `packages/current` 共存：matchit 静态段优先，`current` 仍走上面那条。
        // 鉴权与 current 一致（bootstrap token 或 agent 凭据）。
        .route(
            "/api/v1/agent/packages/{package_id}",
            get(download_agent_package_by_id),
        )
        .route("/api/v1/agent/enroll", post(enroll_agent))
        .route("/api/v1/agent/status", post(submit_agent_status))
        // （agentd 上报事实**摘要**的原控制面路由 `POST /api/v1/agent/facts` 已删。）
        // 事实统一走数据面：agentd 发 `OBSFACT:` 帧 → warp-parse → 网关的**内部**端点
        // `/api/v1/ingest/agent-facts`（见 `ingest_router` 与 api/ingest.rs）。
        // 见 doc/design/center/agent-work-delivery-plan.md §4.1。
        .route(
            "/api/v1/agent/credentials:renew",
            post(renew_agent_credential),
        )
        .route(
            "/api/v1/agent/control-commands:poll",
            post(poll_control_commands),
        )
        .route("/api/v1/agent/action-results", post(report_action_result))
        // NOTE(hand-added): agentd 拉取发现方向策略表。带 `:poll` 后缀以标明它是幂等的
        // “拉当前版本”，而不是一次汇报。已在 jumo 模型 WistAgentdOnlineRegistrationInterface
        // 声明；重新生成控制面代码时需回补本路由。
        .route(
            "/api/v1/agent/discovery-policies:poll",
            post(poll_discovery_policies),
        )
        // NOTE(hand-added): 工作授权快照的拉取与确认（jumo 模型
        // WistAgentdOnlineRegistrationInterface 的 PollWork / AckWork）。
        // 与策略表同类：幂等内容、可重复拉取；断网重启后重新拉一次就回到期望状态。
        .route("/api/v1/agent/work:poll", post(poll_work))
        // NOTE(hand-added): 数据面上送启用的拉取。模型侧已补齐
        // `message` / `entry` / `flow` / `actor can` / 用例 / `bind`（见设计文档 §7）。
        // 与 work:poll 同类：幂等内容、可重复拉取，但刻意走**独立端点**而不是给 WorkGrant 加字段 ——
        // WorkGrant 两侧都 `deny_unknown_fields`，加字段会让「新网关 + 旧 agentd」解析失败（舰队级停摆）。
        // 旧 agentd 不调它，新 agentd 遇旧网关得 404 后回落本机配置。
        // 重新生成控制面代码时需回补本路由。
        .route("/api/v1/agent/uplink:poll", post(poll_agent_uplink))
        .route("/api/v1/agent/work:ack", post(ack_work))
        // 一次性工作的执行结果（进度/终态）。与 ack 分开：确认回答「我收到了」，
        // 结果回答「我做得怎么样了」——失效代价不同，不挤一条路。
        .route("/api/v1/agent/work:result", post(submit_work_result))
        .route("/api/v1/admin/agents/overview", get(get_agent_overview))
        .route(
            "/api/v1/admin/agents/host-metrics",
            get(get_all_agents_host_metrics),
        )
        .route(
            "/api/v1/admin/agents/{agent_id}/runtime-status",
            get(get_agent_runtime_status),
        )
        // NOTE(hand-added): Agent 用途视图（事实/推断/判定并列）。已在 jumo 模型
        // WistGatewayManagementInterface.AdminViewAgentPurpose 声明。
        .route(
            "/api/v1/admin/agents/{agent_id}/purpose",
            get(view_agent_purpose),
        )
        // NOTE(hand-added): 用途判定的写入（人工判定）与机队覆盖度。已在 jumo 模型
        // WistGatewayManagementInterface（AdminClassifyAgent / AdminViewPurposeCoverage）声明。
        .route(
            "/api/v1/admin/agents/{agent_id}/classification",
            post(classify_agent),
        )
        .route(
            "/api/v1/admin/agents/purpose-coverage",
            get(view_purpose_coverage),
        )
        // NOTE(hand-added): 工作授权／撤回／暂停／继续 + 查看（jumo 模型
        // WistGatewayManagementInterface 的 AdminGrantWork / AdminRevokeWork /
        // AdminPauseWork / AdminResumeWork）。查看了模型里没有，是为了“看得到才能控制”。
        .route(
            "/api/v1/admin/agents/{agent_id}/work",
            get(view_agent_work).post(grant_work),
        )
        .route(
            "/api/v1/admin/agents/{agent_id}/work/{work_id}/revoke",
            post(revoke_work),
        )
        .route(
            "/api/v1/admin/agents/{agent_id}/work/{work_id}/pause",
            post(pause_work),
        )
        .route(
            "/api/v1/admin/agents/{agent_id}/work/{work_id}/resume",
            post(resume_work),
        )
        .route(
            "/api/v1/admin/agents/{agent_id}/host-metrics",
            get(get_agent_host_metrics),
        )
        // NOTE(hand-added): 数据采集吞吐视图（见 api/pipeline.rs 顶部说明）
        .route(
            "/api/v1/admin/pipeline/topology",
            get(get_pipeline_topology),
        )
        // NOTE(hand-added): L1a 机械资产清单（见 api/software_ops.rs 顶部说明）。
        // 「按软件看机器」在前，「按机器看软件」在后 —— 后者要 `{agent_id}` 路径参数，
        // 两条路由不冲突，但把静态段放前面更不容易让人误以为是同一个前缀。
        .route("/api/v1/admin/software", get(view_software_holdings))
        .route(
            "/api/v1/admin/agents/{agent_id}/software",
            get(view_agent_software),
        )
        // NOTE(hand-added): 采集内容目录的只读视图（模板组成 + 面就绪度）。见
        // api/content_ops.rs 顶部说明。
        .route("/api/v1/admin/content", get(view_content))
        // NOTE(hand-added): 采集日志的查看（读本地落盘文件）。见 api/logs.rs 顶部说明。
        .route("/api/v1/admin/logs", get(view_agent_logs))
        // NOTE(hand-added): wist-agentd 安装包地址的读取/设置。已在 jumo 模型
        // WistGatewayManagementInterface（AdminViewAgentInstallPackageAddress /
        // AdminSetAgentInstallPackageAddress）中声明。
        .route(
            "/api/v1/admin/agent/install-package",
            get(view_agent_install_package).post(set_agent_install_package),
        )
        // NOTE(hand-added): 安装包录入历史列表（管理面）。与安装包地址成对：
        // 地址记当前生效来源，这条记历史录入过的包（每条带内容寻址 id）。
        .route(
            "/api/v1/admin/agent/install-packages",
            get(list_agent_install_packages),
        )
        // NOTE(hand-added): Agent 数据面上送地址的读取/设置。它是 `uplink:poll` 现算上送
        // 授权时的目标来源；未设置时授权只能是待命（没有目标，Agent 不采集日志也不上送数据面）。
        .route(
            "/api/v1/admin/agent/uplink",
            get(view_agent_uplink).post(set_agent_uplink),
        )
        // NOTE(hand-added): 网关对外地址的读取/设置。它是控制平台对 agent 宣告的地址：
        // 新签发 Agent 初始配置里的 [control_plane] endpoint，以及安装命令 / install.sh /
        // 安装包的分发基址都由它派生；未设置时回落配置文件里的 server.public_base_url。
        // 重新生成控制面代码时这条路由与上面两条设置路由都要保住。
        .route(
            "/api/v1/admin/agent/advertise-url",
            get(view_agent_advertise_url).post(set_agent_advertise_url),
        )
        // NOTE(hand-added): Agent 管理面列表与凭据吊销。已在 jumo 模型
        // WistGatewayManagementInterface（AdminListAgents / AdminRevokeAgentCredential）中声明，
        // 重新生成控制面代码时需保证这两条路由不丢失。
        // NOTE(hand-added): 发现方向策略表视图（管理面）。
        .route(
            "/api/v1/admin/discovery-policies",
            get(view_discovery_policies),
        )
        .route("/api/v1/admin/agents", get(list_agents))
        .route(
            "/api/v1/admin/agents/{agent_id}/credentials:revoke",
            post(revoke_agent_credential),
        )
        // NOTE(hand-added): 灰度发布计划（模型 Control.Rollout）：创建/列表/批准/推进/查看。
        // 已在模型 WistGatewayManagementInterface 声明；重新生成控制面代码时需回补这些路由。
        .route(
            "/api/v1/admin/rollout-plans",
            get(list_rollout_plans).post(create_rollout_plan),
        )
        .route(
            "/api/v1/admin/rollout-plans/approve",
            post(approve_rollout_plan),
        )
        .route(
            "/api/v1/admin/rollout-plans/advance",
            post(advance_rollout_plan),
        )
        .route(
            "/api/v1/admin/rollout-plans/{plan_id}",
            get(view_rollout_plan),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests;
