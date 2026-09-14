// @jumo generated
// @jumo hash=2ff63c2da808b5ca

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    routing::{get, post},
};

use crate::infra::{AdminConfig, AdminStore};

mod admin_auth;
mod admin_ops;
mod agent_ops;
mod enrollment;
mod host_metrics;
mod install;
mod overview;
// NOTE(hand-added): pipeline 不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics
// 同一模式（模型里也没有 host-metrics 路由）。重新生成控制面代码时需回补本模块与下方路由。
mod pipeline;
mod rate_limit;

pub mod wist_gateway_management_interface;
pub mod wist_gateway_public_install_interface;
pub use wist_gateway_management_interface::WarpGateWayManagementInterface;
pub mod wist_agent_online_registration_interface;
pub use wist_agent_online_registration_interface::WpAgentOnlineRegistrationInterface;

use admin_ops::{get_agent_runtime_status, pause_agent, upgrade_agent};
use agent_ops::{
    poll_control_commands, renew_agent_credential, report_action_result, submit_agent_status,
};
use enrollment::enroll_agent;
use host_metrics::{get_agent_host_metrics, get_all_agents_host_metrics};
use install::{
    download_agent_package, get_agent_initial_config_with_token, get_agent_install_code,
    get_agent_install_script, get_agent_install_script_signature,
};
use overview::{RecentOnlineRegisteredAgent, get_agent_overview};
use pipeline::get_pipeline_topology;

#[derive(Debug, Clone)]
pub struct ApiState {
    pub config: AdminConfig,
    pub store: AdminStore,
    pub runtime: Arc<Mutex<AdminRuntimeState>>,
    pub rate_limits: Arc<Mutex<rate_limit::RateLimitState>>,
}

#[derive(Debug, Default)]
pub struct AdminRuntimeState {
    pub recent_online_agents: Vec<RecentOnlineRegisteredAgent>,
}

pub fn router(config: AdminConfig) -> Router {
    let store = AdminStore::new(config.store_file.clone());
    Router::new()
        .route("/api/v1/agent/install-code", get(get_agent_install_code))
        .route(
            "/api/v1/agent/install/:arch/install.sh",
            get(get_agent_install_script),
        )
        .route(
            "/api/v1/agent/install/:arch/install.sh.sig",
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
        .route(
            "/api/v1/agent/credentials:renew",
            post(renew_agent_credential),
        )
        .route(
            "/api/v1/agent/control-commands:poll",
            post(poll_control_commands),
        )
        .route("/api/v1/agent/action-results", post(report_action_result))
        .route("/api/v1/admin/agents/overview", get(get_agent_overview))
        .route(
            "/api/v1/admin/agents/host-metrics",
            get(get_all_agents_host_metrics),
        )
        .route(
            "/api/v1/admin/agents/:agent_id/runtime-status",
            get(get_agent_runtime_status),
        )
        .route(
            "/api/v1/admin/agents/:agent_id/host-metrics",
            get(get_agent_host_metrics),
        )
        // NOTE(hand-added): 数据采集吞吐视图（见 api/pipeline.rs 顶部说明）
        .route(
            "/api/v1/admin/pipeline/topology",
            get(get_pipeline_topology),
        )
        .route("/api/v1/admin/agents/:agent_id/pause", post(pause_agent))
        .route(
            "/api/v1/admin/agents/:agent_id/upgrade",
            post(upgrade_agent),
        )
        .with_state(ApiState {
            config,
            store,
            runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
            rate_limits: Arc::new(Mutex::new(rate_limit::RateLimitState::default())),
        })
}

#[cfg(test)]
mod tests;
