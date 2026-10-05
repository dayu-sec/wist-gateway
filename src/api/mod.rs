// @jumo generated
// @jumo hash=2ff63c2da808b5ca

use std::sync::{Arc, Mutex, RwLock};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
};

use crate::app::knowledge::LoadedKnowledge;
use crate::infra::{AdminConfig, AgentCa, Store};

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
// NOTE(hand-added): 知识库内容包的管理面（录入 / 历史 / 激活回滚 / 生效视图 / 锁在旧版的工作）。
// 与安装包那套的关键差别是**录入 ≠ 生效**。不在 jumo 静态模型 binding.mju 的声明里，
// 重新生成控制面代码时需回补本模块与下方路由。设计见
// docs/design/knowledge-content-management.md §7。
mod knowledge_ops;
// NOTE(hand-added): L1a 机械资产清单（从事实摘要派生）。不在 jumo 静态模型 binding.mju
// 的声明里，与 host_metrics / pipeline 同一模式。重新生成控制面代码时需回补本模块与下方路由。
mod software_ops;
// NOTE(hand-added): 灰度发布计划（模型 Control.Rollout）：创建/列表/批准/推进/查看。
// 计划是编排层，批准/推进时才物化成 OneShotWork；与 agent_ops 的 submit_work_result
// 通过 reconcile_rollout_entry 回填条目。重新生成控制面代码时需回补本模块与下方路由。
mod rollout_ops;
// NOTE(hand-added): 网关自述面（环回；CR-003）。对应 jumo 模型 Control.GatewayApp.SelfInterface
// 的 QuerySelfState（模型 bind 未定、环回鉴权未决），故路由手加。供 host 侧 wist-gwlinkd 消费。
mod self_state;
// NOTE(hand-added): 网关侧「接入请求」通道（页面发起接入；CR-003）。对应 jumo 模型
// Control.GatewayApp.LinkRequestInterface（环回），故路由手加。见 api/link_request.rs 与设计
// `wist-design/doc/design/edge/gateway-onboard-request.md`。重新生成控制面代码时需回补本模块与下方路由。
mod link_request;
// NOTE(hand-added): gwlinkd 状态心跳（环回；CR-003）。gwlinkd 纯出站、页面拉不到它，故它每拍
// 把自身状态推到网关。见 api/linkd_status.rs 与设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。
mod linkd_status;
// NOTE(hand-added): agent 面（edge seam B：gateway ↔ agentd）的路由按 API 版本集中到
// `api/agent_api/`（版本并存约定见 design/foundation/api-seam-inventory.md §7）。
// 加 v2 = 新增版本子模块 + 往 `VERSIONS` 加一行。重新生成控制面代码时需回补本模块。
mod agent_api;

pub mod wist_gateway_management_interface;
pub mod wist_gateway_public_install_interface;
pub use wist_gateway_management_interface::WarpGatewayManagementInterface;
pub mod wist_agentd_online_registration_interface;
pub use wist_agentd_online_registration_interface::WistAgentdOnlineRegistrationInterface;

use admin_ops::{
    classify_agent, delete_agent, get_agent_runtime_status, grant_work, lift_agent_revocation,
    list_agent_install_packages, list_agent_revocations, list_agents, pause_work, resume_work,
    revoke_agent, revoke_agent_credential, revoke_work, set_agent_advertise_url,
    set_agent_install_package, set_agent_uplink, view_agent_advertise_url,
    view_agent_install_package, view_agent_purpose, view_agent_uplink, view_agent_work,
    view_discovery_policies, view_purpose_coverage,
};
use content_ops::view_content;
use host_metrics::{get_agent_host_metrics, get_all_agents_host_metrics};
use ingest::{MAX_INGEST_BODY_BYTES, ingest_agent_facts};
use install::{
    download_agent_package, download_agent_package_by_id, get_agent_initial_config_with_token,
    get_agent_install_code, get_agent_install_script, get_agent_install_script_signature,
};
use knowledge_ops::{
    activate_knowledge_package, list_knowledge_packages, record_knowledge_package, view_knowledge,
    view_knowledge_locks, view_knowledge_package,
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

// NOTE(hand-added): 拒绝名单的周期 GC（§5.6）。与 `work_expiry` 同一模式（自身 tick，
// 不搭在任何请求路径上）。重新生成控制面代码时需回补本模块与 `main` 里那一行 spawn。
pub mod revocation_gc;
pub use revocation_gc::{REVOCATION_GC_TICK, spawn_revocation_gc_tick};

#[derive(Debug, Clone)]
pub struct ApiState {
    pub config: AdminConfig,
    pub store: Arc<dyn Store>,
    pub runtime: Arc<Mutex<AdminRuntimeState>>,
    pub rate_limits: Arc<Mutex<rate_limit::RateLimitState>>,
    /// 当前装载着的**知识库内容**（采集目录三件套 + 用途规则 + 发现策略）。
    ///
    /// 三个块放在**同一个 `Arc` 里整体换**，而不是三个各自可换的字段：切版时"模板已是新的、
    /// 规则还是旧的"这种半新半旧视图，会让"这条建议按哪版算的"又变得说不清。
    ///
    /// 为什么是 `RwLock<Arc<…>>` 而不是一个普通字段：管理面激活/回滚要在**不重启**的前提下
    /// 换掉它（设计 §8.1 选 B）。读多写极少，所以用读写锁；读路径必须先 `clone` 出 `Arc`
    /// 再放开锁（`RwLockReadGuard` 不能跨 `.await` 持有）。
    knowledge: Arc<RwLock<Arc<LoadedKnowledge>>>,
    /// agent 客户端证书的签发 CA。`None` = 未配置（不开 mTLS 签发，注册只发 bearer）。
    ///
    /// 启动时装载一次（配置错了 `AdminConfig::validate` 就已经拒绝启动）。它的根**只留服务端**
    /// 当 client 验证信任锚，**不下发**给 agent（见 `docs/design/agent-identity-mtls.md` §4.1）。
    pub agent_ca: Option<Arc<AgentCa>>,
}

impl ApiState {
    /// 当前装载着的知识库内容（采集目录 / 用途规则 / 发现策略三块的整体快照）。
    ///
    /// 返回 `Arc` 快照而不是 guard：读写锁的 guard 不是 `Send`，持着它跨 `.await`
    /// 会让 handler 编不过；而且拿到快照后即使中途有人激活了新版，本次请求看到的
    /// 仍是**一致的一份**（不会一半新一半旧）。
    pub fn knowledge(&self) -> Arc<LoadedKnowledge> {
        // 写侧只在“激活/回滚”这一条管理动作上持锁，且持锁期间不做 I/O（先验后切），
        // 所以中毒（写侧 panic）按“取回最后一版”处理，比把整个控制面带崩合理。
        Arc::clone(&self.knowledge.read().unwrap_or_else(|err| err.into_inner()))
    }

    /// 整体换掉知识库内容（管理面激活/回滚时调用）。
    ///
    /// 换的是 `Arc`，读侧下一次取到的就是新的一份。**调用方必须“先验后切”**：
    /// 新版内容已经装载成功才允许换（设计 §8.6），否则等于把网关推到半可用。
    pub fn replace_knowledge(&self, knowledge: Arc<LoadedKnowledge>) {
        let mut guard = self
            .knowledge
            .write()
            .unwrap_or_else(|err| err.into_inner());
        *guard = knowledge;
    }
}

/// 会话运行态（最近上线过的 agent 等），进程内一份。
///
/// 知识库三个块（采集目录 / 用途规则 / 发现策略）的装载不在这里：
/// 它们已收到 [`crate::app::knowledge`] —— 那里还要管"按优先级解析来源（生效包 / 启动期
/// `source_dir` / 配置文件）"与"运行时整体换版"两件本模块管不了的事。
#[derive(Debug, Default)]
pub struct AdminRuntimeState {
    pub recent_online_agents: Vec<RecentOnlineRegisteredAgent>,
    /// 累计接收的数据面事实条数（自进程启动）—— 数据面吞吐的一个信号。
    pub ingest_accepted_total: u64,
    /// 累计被拒的事实条数（自进程启动）。
    pub ingest_rejected_total: u64,
    /// 最近一次接收事实的时刻（未接收过为 `None`）。
    pub last_ingest_at: Option<wist_control::types::DateTime>,
}

pub fn router(config: AdminConfig, store: Arc<dyn Store>) -> Router {
    router_with_state(build_state(config, store))
}

/// 装配共享状态（**过渡期**入口：知识库从配置文件装载）。
///
/// 保留它是因为它被大量测试当夹具用（测试确实是通过 `[content]` 等文件路径喂内容的）。
/// 生产路径走 [`build_state_with_knowledge`]。
pub fn build_state(config: AdminConfig, store: Arc<dyn Store>) -> ApiState {
    let knowledge = LoadedKnowledge::from_config(&config);
    build_state_with_knowledge(config, store, knowledge)
}

/// 装配共享状态，知识库内容由调用方给定（启动期：`LoadedKnowledge::resolve`）。
///
/// 两个监听（对外 HTTPS / 数据面内部 HTTP）**共用同一份**：知识库三个块、会话运行态与
/// 限流器都只能有一份，否则两条路径的行为会不一致。
pub fn build_state_with_knowledge(
    config: AdminConfig,
    store: Arc<dyn Store>,
    knowledge: LoadedKnowledge,
) -> ApiState {
    let agent_ca = load_agent_ca(&config);
    ApiState {
        config,
        store,
        runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
        rate_limits: Arc::new(Mutex::new(rate_limit::RateLimitState::default())),
        knowledge: Arc::new(RwLock::new(Arc::new(knowledge))),
        agent_ca,
    }
}

/// 装载 agent 客户端证书的签发 CA（未配置 = 不开 mTLS 签发）。
///
/// `AdminConfig::validate` 已经解析过一次（配置错就起不来）；走到这里再失败只可能是启动后
/// 文件被改坏 —— 记一条警告并当作「未配置」，注册回落成只发 bearer，而不是把网关整个拒了。
fn load_agent_ca(config: &AdminConfig) -> Option<Arc<AgentCa>> {
    let (cert_file, key_file) = config.agent_ca_files()?;
    match AgentCa::load(cert_file, key_file) {
        Ok(ca) => Some(Arc::new(ca)),
        Err(err) => {
            eprintln!(
                "warning: agent CA is configured but unusable; mTLS issuance disabled: {err}"
            );
            None
        }
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
    let router: Router<ApiState> = Router::new()
        .route("/api/v1/agent/install-code", get(get_agent_install_code))
        // NOTE(hand-added): 网关自述面（环回；CR-003）。见上方 `mod self_state` 说明。
        .route(
            "/api/v1/gateway/self-state",
            get(self_state::query_self_state),
        )
        // NOTE(hand-added): 接入请求通道（环回；CR-003）。见上方 `mod link_request` 说明。
        .route(
            "/api/v1/gateway/link-request",
            get(link_request::query_gateway_link_request),
        )
        .route(
            "/api/v1/gateway/link-result",
            post(link_request::report_gateway_link_result),
        )
        // NOTE(hand-added): gwlinkd 状态心跳（环回；CR-003）。见 api/linkd_status.rs 说明。
        .route(
            "/api/v1/gateway/linkd-status",
            post(linkd_status::report_gateway_linkd_status),
        )
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
        // agent 面（edge seam B：gateway ↔ agentd）路由集中在 `api/agent_api/`：按 API 版本分表，
        // 由 `agent_api::mount` 统一挂上（版本并存约定见 api-seam-inventory.md §7）。
        .route("/api/v1/admin/agents/overview", get(get_agent_overview))
        .route(
            "/api/v1/admin/agents/host-metrics",
            get(get_all_agents_host_metrics),
        )
        .route(
            "/api/v1/admin/agents/{agent_id}/runtime-status",
            get(get_agent_runtime_status),
        )
        // NOTE(hand-added): 删除**离线** Agent（jumo 模型 WistGatewayManagementInterface
        // 的 AdminDeleteAgent）。在线机器会被 409 拒（判据与列表/运行态同一处）。
        .route("/api/v1/admin/agents/{agent_id}", delete(delete_agent))
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
        // NOTE(hand-added): 知识库内容包的管理面（设计 §7）。与安装包那套的差别是
        // **录入 ≠ 生效**：`POST …/packages` 只落盘登记，切指针要另外调 `…/{id}/activate`。
        // 重新生成控制面代码时这几条路由与 `api/knowledge_ops.rs` 都要保住。
        .route("/api/v1/admin/knowledge", get(view_knowledge))
        .route(
            "/api/v1/admin/knowledge/packages",
            get(list_knowledge_packages).post(record_knowledge_package),
        )
        .route(
            "/api/v1/admin/knowledge/packages/{package_id}",
            get(view_knowledge_package),
        )
        // 切生效指针（激活 / 回滚）。为什么是**独立动作**而不是录入的副作用：见设计 I2。
        .route(
            "/api/v1/admin/knowledge/packages/{package_id}/activate",
            post(activate_knowledge_package),
        )
        // 谁还锁在旧版目录（换版不追改在跑的工作，所以要看得见）。
        .route("/api/v1/admin/knowledge/locks", get(view_knowledge_locks))
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
        // NOTE(hand-added): 页面发起接入（网关侧命令源，供 host gwlinkd 环回拉取）。见
        // api/link_request.rs 与设计 edge/gateway-onboard-request.md。
        .route(
            "/api/v1/admin/gateway/link-request",
            get(link_request::admin_view_gateway_link_request)
                .post(link_request::admin_set_gateway_link_request),
        )
        // NOTE(hand-added): gwlinkd 状态读侧（页面）。见 api/linkd_status.rs。
        .route(
            "/api/v1/admin/gateway/linkd-status",
            get(linkd_status::admin_view_gateway_linkd_status),
        )
        // NOTE(hand-added): 网关**自身**状态读侧（页面）—— 环回自述面只服务本机 gwlinkd，
        // 浏览器够不到；这是同一份计算的 admin 读口。见 api/self_state.rs。
        .route(
            "/api/v1/admin/gateway/self-state",
            get(self_state::admin_view_gateway_self_state),
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
        // NOTE(hand-added): 拒绝名单（吊销状态表，设计文档 agent-identity-mtls.md §5.6）。
        // 与 `credentials:revoke` 不同：那个吊销一份凭据（可换凭据 / 证书自续绕开），
        // 这个拒的是 agent_id 本身 —— 续签、重签同 id 仍被拒。
        // 静态段（`agent-revocations`）与本段不冲突：前缀不同（`agents/` vs `agent-revocations`）。
        .route(
            "/api/v1/admin/agents/{agent_id}/revocation",
            post(revoke_agent).delete(lift_agent_revocation),
        )
        .route(
            "/api/v1/admin/agent-revocations",
            get(list_agent_revocations),
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
        );
    agent_api::mount(router).with_state(state)
}

#[cfg(test)]
mod tests;
