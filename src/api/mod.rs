// @jumo generated
// @jumo hash=2ff63c2da808b5ca

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};

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
mod overview;
// NOTE(hand-added): pipeline 不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics
// 同一模式（模型里也没有 host-metrics 路由）。重新生成控制面代码时需回补本模块与下方路由。
mod pipeline;
mod rate_limit;
// NOTE(hand-added): L1a 机械资产清单（从事实摘要派生）。不在 jumo 静态模型 binding.mju
// 的声明里，与 host_metrics / pipeline 同一模式。重新生成控制面代码时需回补本模块与下方路由。
mod software_ops;

pub mod wist_gateway_management_interface;
pub mod wist_gateway_public_install_interface;
pub use wist_gateway_management_interface::WarpGatewayManagementInterface;
pub mod wist_agentd_online_registration_interface;
pub use wist_agentd_online_registration_interface::WistAgentdOnlineRegistrationInterface;

use admin_ops::{
    get_agent_runtime_status, list_agents, revoke_agent_credential, set_agent_install_package,
    set_agent_uplink, view_agent_install_package, view_agent_purpose, view_agent_uplink,
    view_discovery_policies,
};
use agent_ops::{
    poll_control_commands, poll_discovery_policies, renew_agent_credential, report_action_result,
    submit_agent_status,
};
use enrollment::enroll_agent;
use host_metrics::{get_agent_host_metrics, get_all_agents_host_metrics};
use ingest::{MAX_INGEST_BODY_BYTES, ingest_agent_facts};
use install::{
    download_agent_package, get_agent_initial_config_with_token, get_agent_install_code,
    get_agent_install_script, get_agent_install_script_signature,
};
use overview::{RecentOnlineRegisteredAgent, get_agent_overview};
use pipeline::get_pipeline_topology;
use software_ops::{view_agent_software, view_software_holdings};

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
    ApiState {
        config,
        store,
        runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
        rate_limits: Arc::new(Mutex::new(rate_limit::RateLimitState::default())),
        purpose_rules,
        discovery_policies,
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
        // NOTE(hand-added): wist-agentd 安装包地址的读取/设置。已在 jumo 模型
        // WistGatewayManagementInterface（AdminViewAgentInstallPackageAddress /
        // AdminSetAgentInstallPackageAddress）中声明。
        .route(
            "/api/v1/admin/agent/install-package",
            get(view_agent_install_package).post(set_agent_install_package),
        )
        // NOTE(hand-added): Agent 数据面上送地址的读取/设置。未设置时网关签发的初始配置
        // 不带 tcp 上送段（Agent 只上报自身状态，不采集日志也不上送数据面）。
        .route(
            "/api/v1/admin/agent/uplink",
            get(view_agent_uplink).post(set_agent_uplink),
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
        .with_state(state)
}

#[cfg(test)]
mod tests;
