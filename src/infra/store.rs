//! 控制面持久化契约。
//!
//! 这里只定义 [`Store`] trait 与领域记录类型；具体后端在
//! [`crate::infra::sqlite_store`]（SQLite，默认）等模块实现。
//!
//! 设计要点：
//! * trait 是 `async` 的，因为 SQL 后端是异步的。用 `#[async_trait]` 而不是原生
//!   `async fn in trait`：原生形式在 trait object 下不可 dyn（E0038），而
//!   `Arc<dyn Store>` 正是上层（`ApiState`）持有存储的方式。
//! * 记录类型沿用早期单文件存储的名字（`StoredEnrollmentToken` /
//!   `StoredAgentRegistration`），但 `StoredAgentRegistration` 现在是
//!   `agents ⋈ 当前 instance ⋈ 当前 credential` 的读投影，DB 里是三张表。
//! * 注册 token 的「预留 → 落库 / 回滚」协议保持原样（`reserved_at` + TTL），
//!   只是从「整体重写 JSON」换成单事务，因此并发下不再依赖文件锁。

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use wist_api::agent_status::AgentWorkStateChange;
// `pub use`：SQLite 后端用 `use super::store::*` 取领域类型（与 `StoreError` 同理）。
pub use wist_contracts::work::{OneShotWork, StandingWork};
pub use wist_error::{StoreError, StoreReason};

pub type StoreResult<T> = Result<T, StoreError>;

// ─────────────────────────────────────────────────────────────────────────────
// 记录类型
// ─────────────────────────────────────────────────────────────────────────────

/// 注册 token 状态。序列化为小写 snake_case。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredEnrollmentTokenStatus {
    Active,
    Reserved,
    Used,
    Expired,
    Revoked,
}

impl StoredEnrollmentTokenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// 未知取值按「已吊销」处理（fail closed）：这些值由本服务写入，
    /// 出现未知值意味着数据被外部改动或版本不匹配，不应据此放行注册。
    pub fn parse(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "reserved" => Self::Reserved,
            "used" => Self::Used,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => Self::Revoked,
        }
    }
}

/// 注册 token 的服务端记录（对应模型 `AgentEnrollmentToken`）。
///
/// 只存 hash；`token_id` 用于审计与吊销，`allowed_node_selector` / `issued_by`
/// 记录签发来源与宿主机约束。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEnrollmentToken {
    #[serde(default)]
    pub token_id: String,
    pub token_hash: String,
    pub tenant_id: String,
    pub environment_id: String,
    #[serde(default)]
    pub issued_by: String,
    #[serde(default)]
    pub allowed_node_selector: Option<String>,
    pub max_uses: u32,
    pub used_count: u32,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub reserved_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    pub status: StoredEnrollmentTokenStatus,
}

/// Agent 凭据状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StoredCredentialStatus {
    #[default]
    Active,
    Expired,
    Revoked,
}

impl StoredCredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "expired" => Self::Expired,
            "revoked" => Self::Revoked,
            _ => Self::Revoked,
        }
    }
}

/// Agent 的读投影：身份 + 当前实例 + 当前凭据 + 最近一次上报。
///
/// 字段与早期单文件存储保持一致，因此上层 handler 无需改动读路径。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredAgentRegistration {
    pub agent_id: String,
    pub instance_id: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub node_id: String,
    pub hostname: String,
    pub machine_id: String,
    /// 机器级「最近一次已知网卡地址」（形如 `en0 192.168.1.5/24`，来自状态上报的机器画像）；
    /// 空表 = 还没报过 / 确实没有地址。
    pub ip_addresses: Vec<String>,
    pub version: String,
    pub credential_id: String,
    pub credential_token_hash: String,
    pub credential_issued_at: String,
    pub credential_expires_at: String,
    pub credential_status: StoredCredentialStatus,
    pub registered_at: String,
    pub last_seen_at: String,
    /// 当前实例的开始时刻（历史起点）。
    ///
    /// 注册时 `agent_instances` 行就把 `last_seen_at` 初始化成 `started_at`，只有真正的心跳
    /// （状态上报）才会推进 `last_seen_at`。因此 `last_seen_at == started_at` 是“注册过但
    /// 一次状态都没报过”的判据 —— 管理面用它把 `last_seen_at` 显示成空串。
    pub started_at: String,
    pub last_memory_bytes: Option<u64>,
    /// 最近一次上报的 CPU 占用，**单核口径**（100% = 占满一个核；多线程进程可 >100）。
    ///
    /// 只统计 agent 进程**自己**的 CPU 时间，不代表整机负载。整机占比由
    /// `cpu_percent / cpu_cores` 派生（管理面读投影）。
    pub last_cpu_percent: Option<f64>,
    /// 最近一次上报的**逻辑核数**（agent 所在机器）；`None` = 老版本 agentd 没报。
    ///
    /// `None` 与 `Some(0)` 不同：前者是「不知道核数」，后者是「报了非法值」，两者都不能
    /// 拿来做整机占比的除数（`cpu_percent_of_machine` 由此返回 `None`）。
    pub last_cpu_cores: Option<u32>,
    pub last_admin_latency_ms: Option<u64>,
    /// 本机**实际生效**的发现方向策略版本；`None` = 还没拿到策略表（在用内建默认周期）。
    pub last_discovery_policy_version: Option<i64>,
    /// 最近一次状态上报携带的工作状态变化（paused/resumed），非告警/失败。
    pub work_state_changes: Option<Vec<AgentWorkStateChange>>,
    /// 最近一次上报的**本机工作内容视图**（agentd 的 `state/work.json` 子集）。
    /// `None` = 这台 agent 还没报过（旧版本 agentd 不发这个字段）。
    pub local_work: Option<wist_contracts::local_work::AgentLocalWork>,
    /// 最近一次上报的**实际生效**采集输出状态（它与网关的 `agent_uplink` 下发值是一对：
    /// 一个说「要它怎样」，一个说「它实际成了怎样」）。
    /// `None` = 这台 agent 还没报过（旧版本 agentd 不发这个字段）。
    pub uplink_state: Option<wist_contracts::agent_uplink::AgentUplinkState>,
}

/// 历史实例记录（一个 Agent 可有多个）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredAgentInstance {
    pub instance_id: String,
    pub agent_id: String,
    pub boot_id: String,
    pub version: String,
    pub started_at: String,
    pub last_seen_at: String,
    pub memory_bytes: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub admin_latency_ms: Option<u64>,
}

/// 单例设置行 id：安装包地址只有一个生效值（与模型的 `address_id` 对应）。
pub const DEFAULT_INSTALL_PACKAGE_SETTING_ID: &str = "default";

/// 单例设置行 id：数据面上送地址只有一个生效值。
pub const DEFAULT_AGENT_UPLINK_SETTING_ID: &str = "default";

/// 单例设置行 id：网关对外地址只有一个生效值。
pub const DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID: &str = "default";

/// 知识库生效指针的单例 id（`knowledge_active.setting_id`）。
pub const DEFAULT_KNOWLEDGE_SETTING_ID: &str = "default";

/// 单例设置行 id：网关接入请求只有一个生效值。
pub const DEFAULT_GATEWAY_LINK_REQUEST_SETTING_ID: &str = "default";

/// 单例设置行 id：gwlinkd 状态（心跳）只有一个生效值。
pub const DEFAULT_GATEWAY_LINKD_STATUS_SETTING_ID: &str = "default";

/// 数据面 TCP 入口的约定默认端口（与 wparse `topology/sources/tcp_1` 一致）。
pub const DEFAULT_AGENT_UPLINK_PORT: u16 = 9000;

/// Agent 数据面上送地址设置（网关据此渲染 Agent 初始配置里的 tcp 上送段）。
///
/// `enabled` 是本设置上的**部署级启用开关**（`0022_agent_uplink_enabled.sql`）：它说的是
/// 「这套网关现在收不收数据面数据」，与「这台机器有没有活」是**并集**关系
/// （见 `agent_ops::build_agent_uplink_grant`）。默认 `false` = 只按派工启用，即升级前的行为。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredAgentUplinkAddress {
    pub setting_id: String,
    pub host: String,
    pub port: u16,
    /// 部署级启用开关（见类型文档）。派生值恒为 `false` —— 派生只说明「能连到哪」，
    /// 不说明「该不该连」。
    #[serde(default)]
    pub enabled: bool,
    pub updated_by: String,
    pub updated_at: String,
}

/// 网关侧一次性「接入请求」：运维在页面提交、host 侧 gwlinkd 环回拉取执行。
///
/// 载荷是 Center 页「连接 Gateway」给的一整套接入物（地址 + 券 + CA）。接入券明文被
/// gwlinkd 消费后由网关清空；`status` 供页面显示生命周期。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredGatewayLinkRequest {
    pub setting_id: String,
    pub gateway_id: String,
    pub center_endpoint: String,
    /// 一次性接入券**明文**：仅随本请求一次性交给 gwlinkd；被消费后清空。
    pub link_token: String,
    /// CA-S 信任锚（中心服务器证书信任根，PEM 内容）。
    pub trust_bundle_pem: String,
    /// `Pending` / `Connecting` / `Connected` / `Failed`。
    pub status: String,
    /// 失败原因（供页面显示）。
    pub result_detail: String,
    pub requested_by: String,
    pub requested_at: String,
    pub updated_at: String,
}

/// 网关侧「gwlinkd 状态」：host 侧 gwlinkd **周期心跳**推来、网关 Web 读展示。
///
/// gwlinkd 纯出站（无入站面），页面拉不到它，所以状态只能由它推。载荷**无密钥**（admin 可原样回显）。
/// 设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。可选字段用空串（不用 NULL）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredGatewayLinkdStatus {
    pub setting_id: String,
    pub gateway_id: String,
    pub instance_id: String,
    /// gwlinkd 版本。
    pub version: String,
    /// 当前接入的中心（未接入时空串）。
    pub center_endpoint: String,
    /// `WaitingLinkRequest` / `Linking` / `Linked` / `Degraded`。
    pub state: String,
    /// 客户端证书到期（RFC3339；空串 = 无）。
    pub credential_expires_at: String,
    /// 最近一次成功向中心 status 上报的时刻（RFC3339；空串 = 未成功过）。
    pub last_center_report_at: String,
    /// 最近失败摘要（空串 = 无）。
    pub last_error: String,
    /// gwlinkd 打的心跳时刻（RFC3339，原样存，供对齐排障）。
    pub reported_at: String,
    /// 网关收到本心跳的时刻（RFC3339，**网关时钟**）——失联判定用它，不受时钟偏移影响。
    pub received_at: String,
}

/// agent 上报的**客户端证书状态**（最近一次）。
///
/// 为什么要存：证书与到期时间只有本机知道（服务端在握手期就验完了，而过期证书进不来），
/// 而「哪些机器快到期 / 已过期需重装」要在页面上提前看到。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgentCertificateStatus {
    pub agent_id: String,
    pub not_after: String,
    pub remaining_seconds: i64,
    /// `valid` / `renew_due` / `expired`（agent 本地判定，网关不重算）。
    pub state: String,
    /// agent 本机**最近一次续签判定**（§5.5）；`None` = 老版本 agentd 没报过（落库时保留上一次）。
    pub last_renewal: Option<wist_api::agent_status::AgentCredentialRenewal>,
    pub reported_at: String,
}

/// 拒绝名单（吊销状态表）里的一条，按 `agent_id` 分行。
///
/// 对应模型 `Agent.Certificate.AgentCertificateDenylistEntry`（字段与模型一致）。
/// 见 `docs/design/agent-identity-mtls.md` §5.6：这是「立即生效且跳续签持续」的拒绝点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentRevocation {
    /// 代理主键（`denylist-<agent_id>`）；语义键是 `agent_id`，一台 agent 一条。
    pub entry_id: String,
    pub agent_id: String,
    /// 吊销原因（人工填写，可空串）。
    pub reason_code: String,
    /// 谁吊销的（管理面录入，可空串）。
    pub denied_by: String,
    /// 加入名单的时刻（RFC3339）。
    pub denied_at: String,
    /// GC 水位（RFC3339）：条目保留到被吊销证书的自然过期时间为止。
    pub retain_until: String,
}

/// 网关对外地址设置（管理面设置；未设置时回落到 `server.public_base_url`）。
///
/// 它是「控制平台对 agent 宣告的地址」的唯一来源：渲染 Agent 初始配置的
/// `[control_plane] endpoint`，也是安装命令 / install.sh / 安装包分发 URL 的基址。
/// 之所以要能从管理面改：`server.public_base_url` 是启动期配置，而对外入口
/// （域名、端口、反代）常由部署侧决定并会随后调整，拿内部地址当 agent 的默认
/// 控制面地址会让装出来的 agent 连不上。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredAgentAdvertiseUrl {
    pub setting_id: String,
    /// 对外基址，形如 `https://gateway.example.com`（无尾斜杠）。
    pub url: String,
    pub updated_by: String,
    pub updated_at: String,
}

/// wist-agentd 安装包地址设置（对应模型 `AgentInstallPackageAddress`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredAgentInstallPackageAddress {
    pub address_id: String,
    pub package_url: String,
    /// 可选校验摘要，统一形如 `sha256:<64 hex>`。
    pub package_sha256: Option<String>,
    pub updated_by: String,
    pub updated_at: String,
}

/// 一条安装包**录入历史**（对应 `agent_install_package_history` 表，每个包一行）。
///
/// 与单例行 [`StoredAgentInstallPackageAddress`] 的区别：那张表只记「当前生效来源」，
/// 这张表按内容寻址（`package_id`）保留每个录入过的包自带的那份副本，供升级按条目取包。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredAgentInstallPackage {
    /// 内容寻址键：`pkg-<sha256 前 16 位>`；同一个包重复录入落在同一行（幂等）。
    pub package_id: String,
    /// 原始录入地址（`/abs/path` 或 `https://…`），只作留痕。
    pub source: String,
    /// 网关据自己缓存的字节算出的摘要，统一 `sha256:<64 hex>`。
    pub package_sha256: String,
    /// 包内目录名读到的版本；读不到为空串。
    pub version: String,
    /// 包内目录名读到的目标三元组；读不到为空串。
    pub arch: String,
    /// 网关自己存的那份副本路径。
    pub cached_path: String,
    pub created_by: String,
    pub created_at: String,
}

/// 知识库**内容包**：管理面录入的策展数据，内容寻址，一行一个包。
///
/// 设计见 `docs/design/knowledge-content-management.md` §6.1。与安装包历史表
/// ([`StoredAgentInstallPackage`]) 同构（`package_id` 幂等、`source` 只留痕、
/// 网关自己存副本），差别是 `cached_path` 指向**目录**而不是单个文件 ——
/// 网关解析的是解开的五份数据，不是归档。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredKnowledgePackage {
    /// 内容寻址键：`kbp-<sha256 前 16 位>`；同一个包重复录入落在同一行。
    pub package_id: String,
    /// 原始录入（`/abs/path` 或 `https://…`），只作留痕。
    pub source: String,
    /// 网关据自己缓存的那份字节算出的摘要，统一 `sha256:<64 hex>`。
    pub package_sha256: String,
    /// 制品版本（包内目录名 / `manifest.json` 的 `version`）。
    pub version: String,
    /// 五份数据各自声明的版本（读不到就留 `None`）。
    pub catalog_version: Option<i64>,
    pub template_version: Option<i64>,
    pub policy_version: Option<i64>,
    pub purpose_version: Option<i64>,
    /// 内容所依赖的解析器契约版本（设计 §10）。
    pub parser_abi: i64,
    /// 签发者公钥指纹；未签名时为空串。
    pub signed_by: String,
    /// 网关自己存的那份**目录**路径（每版一份，旧版留着）。
    pub cached_path: String,
    pub created_by: String,
    pub created_at: String,
}

/// 知识库**生效指针**（单例）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredKnowledgeActive {
    pub package_id: String,
    /// 单调递增的世代号：每次激活 +1。派生结果"算自哪一版"的表级锚（设计 §8.2）。
    pub generation: i64,
    pub activated_by: String,
    pub activated_at: String,
}

/// 切生效指针的参数。
#[derive(Debug, Clone)]
pub struct KnowledgeActivation<'a> {
    pub package_id: &'a str,
    /// `activate` | `rollback` | `repair`。
    pub reason: &'a str,
    pub requested_by: &'a str,
    pub created_at: &'a str,
}

/// 一条知识库**切换留痕**（`knowledge_activation_log`）。
///
/// 回滚也是切换，所以同一条流：`reason` 区分意图，`from_package` 为空表示首次激活。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredKnowledgeActivation {
    pub from_package: Option<String>,
    pub to_package: String,
    pub generation: i64,
    pub reason: String,
    pub requested_by: String,
    pub created_at: String,
}
/// 时序指标样本 DTO（历史在 VictoriaMetrics，库里只留最近值）。
///
/// 带 `#[jumo]` 注解是因为它作为 `RecentOnlineRegisteredAgent.metrics_history` 的
/// 元素类型出现在模型里（`Control.Agent.Status`）—— 不注它，模型侧就是一个「只在代码里存在」
/// 的黑盒子，字段对不上没人会发现。
#[derive(Debug, Clone, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Status")]
pub struct AgentStatusMetricSample {
    pub at: String,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    /// 单核口径的进程 CPU 占比（100% = 占满一个核，可能 >100），只统计 agent 进程自身。
    #[serde(default)]
    pub cpu_percent: Option<f64>,
    /// 整机口径的 CPU 占比（0..100），由 `cpu_percent / cpu_cores` 派生；算不出时为 `None`。
    #[serde(default)]
    pub cpu_percent_of_machine: Option<f64>,
    /// agent 所在机器的逻辑核数；`None` = 该采样点没有核数（老版本 agentd 没报）。
    #[serde(default)]
    pub cpu_cores: Option<u32>,
    #[serde(default)]
    pub admin_latency_ms: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent 事实摘要与用途推断
// ─────────────────────────────────────────────────────────────────────────────

/// Agent 事实摘要（对应模型 `AgentFactSummary`）：覆盖式，一台一条。
///
/// 幂等键是 `content_digest`（不是 `revision`：后者每轮无条件 +1）。
/// **它是网关自己算的**（`wist_contracts::fact_summary`），不是照抄 agent 的声明 ——
/// 用 agent 声明判重的话，agent 侧算法一退化就会把所有上报当重复、静默停在旧内容上。
/// 去重前的进程条数单独留一个 `process_count`，因为去重会毁掉基数。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredAgentFactSummary {
    pub agent_id: String,
    pub content_digest: String,
    pub revision: i64,
    pub observed_at: String,
    pub os: String,
    pub arch: String,
    pub process_count: i64,
    /// 去重后的进程可执行标识（macOS 是完整路径，Linux 是 basename）。
    pub process_executables: Vec<String>,
    pub packages: Vec<String>,
    pub listen_ports: Vec<String>,
    /// 发现方向 `host` 的 `host.id`。**留痕/展示**：不进内容摘要、不参与判重。
    ///
    /// 与它下面两项一样，值会在内容不变的情况下变（改名、换网），所以 `duplicate`
    /// 路径也要一起刷 —— 见 [`AgentFactSummaryMarks`]。
    pub host_id: String,
    /// `host.name`。
    pub host_name: String,
    /// 网卡地址，每块网卡一条，形如 `en0 192.168.1.5/24`。
    pub network_addresses: Vec<String>,
    pub received_at: String,
}

/// 一条命中依据（对应模型 `PurposeSignal`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPurposeSignal {
    pub rule_id: String,
    pub kind: String,
    /// 实际命中规则的那个信号值（回答"命中了什么"）。
    pub value: String,
    pub weight: i64,
}

/// 用途建议（对应模型 `PurposeSuggestion`）：可变可过期，改规则或来新事实即重算。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPurposeSuggestion {
    pub agent_id: String,
    pub suggestion_id: String,
    /// `MachineClass` 裸名（MacDaily / MacDev / LinuxHost / LinuxCompute / LinuxData）。
    pub suggested_class: String,
    /// 0..100。
    pub confidence: i64,
    /// `rule` | `model`（模型线在中心）。
    pub method: String,
    pub rule_set_id: Option<String>,
    /// 算这条建议时规则表的 `purpose_version`；老行（迁移前）为 `None`。
    ///
    /// 与 `rule_set_id` 一起构成**过期判据**：两者任一变了就要重算（§8.2）。
    pub purpose_version: Option<i64>,
    /// 逐条命中依据；没有依据的建议不给人工看。
    pub signals: Vec<StoredPurposeSignal>,
    /// 依据哪一版事实算的，与 `computed_at` 区分开。
    pub observed_at: String,
    pub computed_at: String,
}

/// 人工判定（对应模型 `AgentClassification`）：一台一条，改判即更新并留痕。
///
/// 与 `StoredPurposeSuggestion` 分表：建议是**机器算的、可变可过期**；判定是**人定的、要留痕**的。
/// 两者会并存且不一致（冲突以判定为准，但并列展示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentClassification {
    pub agent_id: String,
    /// `MachineClass` 裸名（MacDaily / MacDev / LinuxHost / LinuxCompute / LinuxData）。
    pub machine_class: String,
    /// 采纳了哪次建议；人工直判/推翻建议时为空。
    pub suggestion_id: Option<String>,
    pub note: Option<String>,
    pub decided_by: String,
    pub decided_at: String,
}

/// 机队用途覆盖度（派生统计）：让“4 类覆盖多少”从断言变成一个可度量的数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurposeCoverageCounts {
    pub total_agents: i64,
    /// 已有人工判定的台数。
    pub classified_agents: i64,
    /// `(machine_class, agent_count)`，按类别名排序。
    pub by_class: Vec<(String, i64)>,
}

/// Agent 的工作确认回执（网关侧留痕，模型里没有对应元素）。
///
/// 为什么单独一张表：确认是 **Agent 侧的事实**（我手上是这个版本），与工作自身的
/// **期望状态**是两回事。两者比对即得漂移 —— 一直没确认的就是漂移。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWorkAck {
    pub work_id: String,
    pub agent_id: String,
    /// `Standing` | `OneShot`。
    pub work_kind: String,
    pub plan_version: i64,
    pub acknowledged_at: String,
}

/// 一次性工作的**执行结果**（agentd 上报的进度/终态）。一份工作一条，覆盖式。
///
/// 与 [`StoredWorkAck`] 分开两份记录：确认回答「我收到了」，结果回答「我做得怎么样了」。
/// 混成一条会让「一次执行结果的上报」改写「确认」的含义，而两者的失效代价完全不同。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredWorkResult {
    pub work_id: String,
    pub agent_id: String,
    /// 见 `wist_contracts::work::AGENT_REPORTABLE_WORK_STATUSES`。
    pub status: String,
    /// 人看的说明（失败原因原样带上）。
    pub detail: String,
    pub reported_at: String,
}

/// 一次性工作的落库形状：契约 [`OneShotWork`] + **网关侧**的状态机器字段。
///
/// 为什么要包一层而不是把 `pre_pause_status` 加进契约：恢复要回到暂停前的状态，
/// 而「暂停前是什么」是**网关自己的状态机**的事，agentd 不需要知道（它只看到 `paused`）。
/// 加进契约就等于把一个纯网关概念泄露给了两侧。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOneShotWork {
    pub work: OneShotWork,
    /// 暂停前的状态（如 `running` / `accepted`）；非暂停态为 `None`。
    pub pre_pause_status: Option<String>,
}

/// 灰度发布计划的一个阶段（对应模型 `RolloutPhase`）。
///
/// 目标范围与推进闸门创建后不变，只有 `status` 在走（`pending` → `rolling` → `completed`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRolloutPhase {
    pub phase_index: i64,
    pub target_ids: Vec<String>,
    /// `manual` | `all_succeeded` | `success_rate:<NN>`（自动推进见 `app/rollout.rs` 的缺口说明）。
    pub advance_rule: String,
    pub status: String,
}

/// 灰度发布计划（对应模型 `RolloutPlan`）。
///
/// 阶段以 JSON 数组随计划一行落库（见 `0012_rollout_plan.sql` 的注释）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRolloutPlan {
    pub plan_id: String,
    pub action: String,
    pub spec: String,
    pub deadline_at: String,
    pub timeout_seconds: i64,
    pub phases: Vec<StoredRolloutPhase>,
    /// 每个阶段内同时执行的目标数（节流；首版只存不控）。
    pub batch_size: i64,
    pub current_phase: i64,
    pub status: String,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
}

/// 灰度发布计划里某个目标的执行进度（对应模型 `RolloutPlanEntry`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRolloutPlanEntry {
    pub plan_id: String,
    pub target_id: String,
    /// 物化出的那件一次性工作的 `work_id`；尚未派发时为 `None`。
    pub work_id: Option<String>,
    /// `pending` | `dispatched` | `succeeded` | `failed`。
    pub status: String,
    pub detail: String,
    pub updated_at: String,
}

pub use wist_contracts::work::{
    ONE_SHOT_TERMINAL_STATUSES, ONE_SHOT_WORK_STATUSES, STANDING_WORK_STATUSES, WorkKind,
    WorkReceipt,
};

/// 未了结的一次性工作（终态的不再出现在快照里）。
pub fn outstanding_one_shot(works: &[StoredOneShotWork]) -> Vec<OneShotWork> {
    works
        .iter()
        .filter(|stored| stored.work.is_outstanding())
        .map(|stored| stored.work.clone())
        .collect()
}

/// 当前生效的常驻工作：`active` 与 `paused` 都要下发。
///
/// 为什么 `paused` 也在快照里：暂停是**期望状态的一部分** —— Agent 处于暂停时「没在做」
/// 不算漂移，期望就是不做。不下发 paused，Agent 就分不清「暂停」与「授权被撤」。
pub fn effective_standing(works: &[StandingWork]) -> Vec<StandingWork> {
    works
        .iter()
        .filter(|work| matches!(work.status.as_str(), "active" | "paused"))
        .cloned()
        .collect()
}

/// 事实上报的**留痕**：内容没变时只刷这几项，用来回答「什么时候又见到同一份内容」。
///
/// 故意不含三个内容列（`process_executables` / `packages` / `listen_ports`）与
/// `content_digest`：`duplicate` 的前提就是内容没变，重写它们既浪费，
/// 又会把「损坏列自愈」混进判重路径。
///
/// 三个展示字段（`host_id` / `host_name` / `network_addresses`）**要在这里**刷，虽然它们
/// 同样不进内容摘要：内容（可执行标识集合）没变而机器名、IP 变了是常态 —— DHCP 换地址、
/// 改机器名，进程集合不会动，于是每轮上报都走 `duplicate`。不在这里一起刷，页面上的网卡
/// 地址就会停在几天前那一轮，而旁边「入库时间」写着刚刚：两个数字自相矛盾，运维会以为
/// 采集坏了。它们与 `content_digest` 无关，刷它们不破坏判重语义。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentFactSummaryMarks {
    /// 快照 revision（每轮 refresh 无条件 +1）。
    pub revision: i64,
    pub observed_at: String,
    /// 去重前的进程条数。
    pub process_count: i64,
    /// 展示字段：仅留痕，可随内容不变而变化。
    pub host_id: String,
    pub host_name: String,
    pub network_addresses: Vec<String>,
    pub received_at: String,
}

/// 清单里的一行：`(agent_id, path)` 唯一。
///
/// 它是事实摘要里 `process_executables` 的**机械投影**（见 `app::inventory`），
/// 不是独立事实源：摘要内容一变就整台重建，因此它随时可由摘要重算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSoftwareEntry {
    pub agent_id: String,
    /// 机械聚类键（`.app` 包路径，或路径本身）。
    pub software_key: String,
    /// 展示名（`.app` 名去后缀，否则 basename）。
    pub name: String,
    /// `app` | `binary`。
    pub kind: String,
    /// 命中的归并规则（回答「这个名字是怎么来的」）。
    pub matched_rule: String,
    pub path: String,
    pub received_at: String,
}

/// 一台机器在清单里的汇总（「按机器看软件」头部计数用，不必把整张表读出来数）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoftwareInventorySummary {
    /// 总行数（= 去重后的可执行路径条数）。
    pub paths: i64,
    /// 其中 `kind = app` 的行数。
    pub apps: i64,
}

/// 「按软件看机器」的一行：一个聚类键 + 持有它的机器（按 `agent_id` 升序）。
///
/// 只带 `agent_id` 与 `path`，不带主机名/状态：那属于机器台账，而调用方（管理面/页面）
/// 手上就有台账 —— 库里再存一份会过期的副本没意义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSoftwareHolding {
    pub software_key: String,
    pub name: String,
    pub kind: String,
    pub holders: Vec<SoftwareHolder>,
}

/// 某台机器上的某条路径。
#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(
    kind = "struct",
    domain = "Control",
    module = "Control.Agent.Inventory"
)]
pub struct SoftwareHolder {
    pub agent_id: String,
    pub path: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 操作入参 / 拒绝原因
// ─────────────────────────────────────────────────────────────────────────────

/// 校验一次性引导 token（未认证安装路径）。
#[derive(Debug, Clone)]
pub struct BootstrapTokenCheck<'a> {
    pub token_hash: &'a str,
    pub tenant_id: &'a str,
    pub environment_id: &'a str,
    /// 预留超时回收阈值（秒）。
    pub reservation_ttl_seconds: i64,
}

/// 注册 token 被拒绝的原因。同一组原因在安装路径与注册路径下的对外文案不同，
/// 因此这里只表达语义，文案由调用方决定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentTokenRejection {
    Unknown,
    /// 租户或环境绑定不匹配。两者在既有实现中复用同一句对外文案，
    /// 因此这里也归为一个变体。
    EnvironmentMismatch,
    HashMismatch,
    InvalidExpiration,
    Expired,
    NotActive,
    Exhausted,
}

impl EnrollmentTokenRejection {
    /// 注册（enroll）路径使用的对外错误码。
    pub fn rejection_code(self) -> &'static str {
        "invalid_enrollment_token"
    }
}

impl fmt::Display for EnrollmentTokenRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 仅作**服务端审计/日志**用的具体原因：这些串不再作为 401 响应体返回
        // （对外统一为不可区分口径，见 install.rs），以免泄露「存在但过期/已消费」。
        let message = match self {
            Self::Unknown => "unknown enrollment token",
            Self::EnvironmentMismatch => "enrollment token environment mismatch",
            Self::HashMismatch => "enrollment token hash mismatch",
            Self::InvalidExpiration => "enrollment token has invalid expiration",
            Self::Expired => "enrollment token is expired",
            Self::NotActive => "enrollment token is not active",
            Self::Exhausted => "enrollment token is exhausted",
        };
        f.write_str(message)
    }
}

/// 预留一次性注册 token。
#[derive(Debug, Clone)]
pub struct ReserveEnrollmentToken<'a> {
    pub token_hash: &'a str,
    pub tenant_id: &'a str,
    pub environment_id: &'a str,
    /// 本次注册将要使用的 agent_id（用于重复注册判定）。
    pub agent_id: &'a str,
    pub reservation_ttl_seconds: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationRejection {
    InvalidToken,
    DuplicateAgent,
}

impl ReservationRejection {
    pub fn rejection_code(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_enrollment_token",
            Self::DuplicateAgent => "duplicate_agent_registration",
        }
    }
}

impl fmt::Display for ReservationRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.rejection_code())
    }
}

/// 落库一次注册：更新 token 状态 + 建 Agent 身份/实例/凭据（单事务）。
#[derive(Debug, Clone)]
pub struct CommitRegistration<'a> {
    pub token_hash: &'a str,
    pub agent_id: &'a str,
    pub instance_id: &'a str,
    pub boot_id: &'a str,
    pub tenant_id: &'a str,
    pub environment_id: &'a str,
    pub node_id: &'a str,
    pub hostname: &'a str,
    pub machine_id: &'a str,
    pub version: &'a str,
    pub credential_id: &'a str,
    pub credential_token_hash: &'a str,
    pub credential_issued_at: &'a str,
    pub credential_expires_at: &'a str,
    pub registered_at: &'a str,
    pub now: &'a str,
}

/// 凭客户端证书重建一条 agent 登记所需的最小字段。
///
/// 机器画像（node_id / hostname / machine_id / instance_id）在**首触时未知**：证书只承载
/// 稳定身份（agent_id / tenant / environment）与证书自身的指纹/有效期。这些画像字段留空，
/// 等 agent 后续的状态上报补齐。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRegistration<'a> {
    pub agent_id: &'a str,
    pub tenant_id: &'a str,
    pub environment_id: &'a str,
    pub credential_id: &'a str,
    /// 证书指纹（sha256 lowercase hex）→ 落在 `agent_credentials.token_hash`，`auth_scheme = 'certificate'`。
    pub credential_fingerprint: &'a str,
    pub credential_issued_at: &'a str,
    pub credential_expires_at: &'a str,
    pub registered_at: &'a str,
    pub now: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRejection {
    InvalidToken,
    DuplicateAgent,
}

impl CommitRejection {
    pub fn rejection_code(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_enrollment_token",
            Self::DuplicateAgent => "duplicate_agent_registration",
        }
    }
}

impl fmt::Display for CommitRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.rejection_code())
    }
}

/// 状态上报写入（幂等更新当前实例；Agent 不存在时返回 `false`，不静默丢弃）。
#[derive(Debug, Clone)]
pub struct AgentStatusUpdate<'a> {
    pub agent_id: &'a str,
    pub instance_id: &'a str,
    pub boot_id: &'a str,
    pub version: &'a str,
    pub last_seen_at: &'a str,
    pub memory_bytes: Option<u64>,
    /// CPU 占用，**单核口径**（100% = 占满一个核；多线程进程可 >100），只统计 agent 进程自身。
    pub cpu_percent: Option<f64>,
    /// agent 所在机器的**逻辑核数**；`None` = 老版本 agentd 没报（与 `Some(0)` 区分）。
    pub cpu_cores: Option<u32>,
    pub admin_latency_ms: Option<u64>,
    /// 本机**实际生效**的发现方向策略版本；`None` = 还没拿到策略表（区别于「生效了第 0 版」）。
    pub discovery_policy_version: Option<i64>,
    pub work_state_changes: Option<Vec<AgentWorkStateChange>>,
    /// 本机**工作内容视图**（agentd 的 `state/work.json` 子集）：我手里有哪些工作、各自在采哪些
    /// 文件。`None` = 这次没带（旧版本 agentd）—— 落库后保持上一次的值。
    pub local_work: Option<wist_contracts::local_work::AgentLocalWork>,
    /// 本机**实际生效**的采集输出状态（控制面要它怎样 ≠ 它实际成了怎样）：`None` = 这次没带
    /// （旧版本 agentd）—— 落库后**保持上一次的值**，不清空。运维问的是「这台为什么不上送」，
    /// 一次没带就把最后一次可信的生效状态擦掉，反而会让原因从页面上消失。
    pub uplink_state: Option<wist_contracts::agent_uplink::AgentUplinkState>,
}

/// 机器画像回填（agentd 状态上报携带的 `HostProfile`）。
///
/// 为什么单独一条写路径（而不是塞进 `AgentStatusUpdate`）：机器画像只在注册方式为**证书首触重建**
/// 时为空、需要补齐，且变化极少 —— 单列一条 `UPDATE` 既不动状态写入那条热路径，也避免把每个
/// `AgentStatusUpdate` 构造点都拖着改。
#[derive(Debug, Clone)]
pub struct AgentMachineProfileUpdate<'a> {
    pub agent_id: &'a str,
    pub node_id: &'a str,
    pub hostname: &'a str,
    pub machine_id: &'a str,
    /// 网卡地址的 JSON 数组文本；`None` = 本次没带（保持上一次的值）。
    pub ip_addresses: Option<&'a str>,
    pub updated_at: &'a str,
}

/// 轮换 Agent 凭据（校验当前凭据后写入新凭据）。
///
/// `current_token_hash` 为 `None` = 凭据已由**证书**验明（mTLS 是唯一凭据路径），不再要求
/// 客户端同时出示旧 token —— 那正是「自愈一次就死」的病根。`new_token_hash` 在证书路径下
/// 存的是**新证书指纹**（`auth_scheme = 'certificate'`）。
#[derive(Debug, Clone)]
pub struct RenewCredential<'a> {
    pub agent_id: &'a str,
    pub instance_id: &'a str,
    pub current_token_hash: Option<&'a str>,
    pub new_credential_id: &'a str,
    pub new_token_hash: &'a str,
    pub auth_scheme: &'a str,
    pub issued_at: &'a str,
    pub expires_at: &'a str,
}

/// Agent 列表查询条件（分页 + 过滤）。
#[derive(Debug, Clone, Default)]
pub struct AgentQuery {
    pub tenant_id: Option<String>,
    pub environment_id: Option<String>,
    pub status: Option<String>,
    pub offset: u64,
    pub limit: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Store trait
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait Store: Send + Sync + fmt::Debug {
    // ── 注册 token ──

    async fn insert_enrollment_token(&self, token: &StoredEnrollmentToken) -> StoreResult<()>;

    /// 校验引导 token；**失败时已发生的状态变更（过期标记、预留回收）必须落库**。
    async fn validate_bootstrap_token(
        &self,
        check: &BootstrapTokenCheck<'_>,
    ) -> StoreResult<Result<(), EnrollmentTokenRejection>>;

    /// 原子预留一次使用：token 置 Reserved、used_count += 1，并保证 agent 未注册。
    async fn reserve_enrollment_token(
        &self,
        request: &ReserveEnrollmentToken<'_>,
    ) -> StoreResult<Result<(), ReservationRejection>>;

    /// 落库注册：token 状态收尾 + 写 agents/agent_instances/agent_credentials（单事务）。
    async fn commit_reserved_registration(
        &self,
        request: &CommitRegistration<'_>,
    ) -> StoreResult<Result<(), CommitRejection>>;

    /// 首触重建登记：mTLS 证书验证通过、但库里没有这条记录时，凭证书身份补一条。
    ///
    /// 只在 mTLS 生效时调用（见 `docs/design/agent-identity-mtls.md` §5.3）。**幂等**：
    /// 该 agent 已存在时不改动任何东西，返回 `Ok(false)`；真正新建返回 `Ok(true)`。
    async fn register_agent_from_certificate(
        &self,
        registration: &CertificateRegistration<'_>,
    ) -> StoreResult<bool>;

    /// 归还预留（凭据签发或落库失败时）。
    async fn rollback_enrollment_token_reservation(&self, token_hash: &str) -> StoreResult<()>;

    /// 吊销注册 token（存在则置 revoked，返回是否命中）。
    async fn revoke_enrollment_token(&self, token_id: &str) -> StoreResult<bool>;

    /// 按明文 hash 读回 token 记录（审计/排查与测试断言用）。
    async fn get_enrollment_token(
        &self,
        token_hash: &str,
    ) -> StoreResult<Option<StoredEnrollmentToken>>;

    // ── Agent ──

    async fn get_agent(&self, agent_id: &str) -> StoreResult<Option<StoredAgentRegistration>>;

    async fn agent_exists(&self, agent_id: &str) -> StoreResult<bool>;

    async fn list_agents(&self, query: &AgentQuery) -> StoreResult<Vec<StoredAgentRegistration>>;

    /// 删除一台 Agent：注册、实例、凭据，以及**所有**以它为主键的派生态行（一个事务）。
    ///
    /// 为什么要连派生表一起删：只有 `agent_instances` / `agent_credentials` 建了
    /// `ON DELETE CASCADE`，其余 per-agent 表（事实摘要 / 用途 / 软件清单 / 分类 / 工作…）
    /// 没有外键 —— 只删 `agents` 会留下一堆无主的「幽灵」行，之后按 `agent_id` 查还会命中陈旧数据。
    ///
    /// 返回是否确实删掉了一台（`false` = 本来就不存在）。
    async fn delete_agent(&self, agent_id: &str) -> StoreResult<bool>;

    /// 读取 wist-agentd 安装包地址设置；未设置过返回 `None`（调用方回落到内置默认地址）。
    async fn get_agent_install_package(
        &self,
    ) -> StoreResult<Option<StoredAgentInstallPackageAddress>>;

    /// 写入/覆盖 wist-agentd 安装包地址设置。
    async fn upsert_agent_install_package(
        &self,
        setting: &StoredAgentInstallPackageAddress,
    ) -> StoreResult<()>;

    /// 列出安装包录入历史，按 `created_at` 倒序（最近录入的在前）。
    async fn list_agent_install_packages(&self) -> StoreResult<Vec<StoredAgentInstallPackage>>;

    /// 按内容寻址 id 读一条安装包录入历史；不存在返回 `None`。
    async fn get_agent_install_package_by_id(
        &self,
        package_id: &str,
    ) -> StoreResult<Option<StoredAgentInstallPackage>>;

    /// 写入/覆盖一条安装包录入历史（按 `package_id` 幂等）。
    async fn upsert_agent_install_package_by_id(
        &self,
        package: &StoredAgentInstallPackage,
    ) -> StoreResult<()>;

    /// 读取 Agent 数据面上送地址设置；未设置过返回 `None`（调用方不下发上送段）。
    async fn get_agent_uplink(&self) -> StoreResult<Option<StoredAgentUplinkAddress>>;

    /// 写入/覆盖 Agent 数据面上送地址设置。
    async fn upsert_agent_uplink(&self, setting: &StoredAgentUplinkAddress) -> StoreResult<()>;

    /// 读取网关接入请求；未提交过返回 `None`（调用方按「无待办」处理）。
    async fn get_gateway_link_request(&self) -> StoreResult<Option<StoredGatewayLinkRequest>>;

    /// 写入/覆盖网关接入请求（单例）。
    async fn upsert_gateway_link_request(
        &self,
        request: &StoredGatewayLinkRequest,
    ) -> StoreResult<()>;

    /// 清空网关接入请求（消费 / 完成接入后移除待办）。
    async fn clear_gateway_link_request(&self) -> StoreResult<()>;

    /// 读取 gwlinkd 状态（最近一次心跳）；从未上报过返回 `None`。
    async fn get_gateway_linkd_status(&self) -> StoreResult<Option<StoredGatewayLinkdStatus>>;

    /// 写入/覆盖 gwlinkd 状态（单例；幂等心跳）。
    async fn upsert_gateway_linkd_status(
        &self,
        status: &StoredGatewayLinkdStatus,
    ) -> StoreResult<()>;

    /// 落 agent 上报的客户端证书状态（最近一次为准）。
    async fn upsert_agent_certificate_status(
        &self,
        status: &StoredAgentCertificateStatus,
    ) -> StoreResult<()>;

    /// 读某台 agent 最近一次上报的证书状态；没报过返回 `None`。
    async fn get_agent_certificate_status(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredAgentCertificateStatus>>;

    // ── 拒绝名单（吊销状态表，§5.6）──

    /// 把一台 agent 加入拒绝名单（按 `agent_id` upsert：重复吊销只刷新原因与水位）。
    async fn revoke_agent(&self, entry: &StoredAgentRevocation) -> StoreResult<()>;

    /// 从拒绝名单移除；返回是否确实移除了（`false` = 本来就不在名单里）。
    async fn lift_agent_revocation(&self, agent_id: &str) -> StoreResult<bool>;

    /// 是否在拒绝名单内，且**尚未到 GC 水位**（`retain_until > 现在`）。
    ///
    /// 用「当前时刻」而非只看行是否存在：条目按证书生命周期保留，过了水位即使还没被
    /// 物理删除，也不应再拦 —— 那时被吊销的那张证书早已过期，agent 只能带 token 重装。
    async fn is_agent_revoked(&self, agent_id: &str) -> StoreResult<bool>;

    /// 列出拒绝名单里**尚未到 GC 水位**的全部条目（按 `denied_at` 倒序，页面用）。
    async fn list_agent_revocations(&self) -> StoreResult<Vec<StoredAgentRevocation>>;

    /// 删除已到 GC 水位的条目，返回删除数（后台 tick 定期调用，防止列表无限增长）。
    async fn purge_expired_agent_revocations(&self) -> StoreResult<u64>;

    /// 读取网关对外地址设置；未设置过返回 `None`（调用方回落 `server.public_base_url`）。
    async fn get_agent_advertise_url(&self) -> StoreResult<Option<StoredAgentAdvertiseUrl>>;

    /// 写入/覆盖网关对外地址设置。
    async fn upsert_agent_advertise_url(
        &self,
        setting: &StoredAgentAdvertiseUrl,
    ) -> StoreResult<()>;

    // ── Agent 事实摘要与用途推断 ──

    /// 读取事实摘要；未上报过返回 `None`。
    async fn get_agent_fact_summary(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredAgentFactSummary>>;

    /// 只读事实摘要的幂等键（`content_digest`）；未上报过返回 `None`。
    ///
    /// 为什么单独开一个：`get_agent_fact_summary` 会反序列化三个 JSON 列，而这些列
    /// 一旦损坏就返回 Err。判重路径只要摘要，不该被它卡死 —— 否则新摘要永远写不进去，
    /// 坏行也就无法被覆盖自愈。
    async fn get_agent_fact_summary_digest(&self, agent_id: &str) -> StoreResult<Option<String>>;

    /// 写入/覆盖事实摘要（一台一条）。
    ///
    /// 是否重复上报由调用方先查再决，本方法本身是**无条件覆盖**。
    async fn upsert_agent_fact_summary(&self, summary: &StoredAgentFactSummary) -> StoreResult<()>;

    /// 只刷留痕字段（`revision` / `observed_at` / `process_count` / `received_at` 与三个
    /// 展示字段），**不动**内容列与 `content_digest`。返回是否真的命中了行。
    ///
    /// 为什么单独开一个：`duplicate` 路径已经判定内容没变，此时重写整行（含三个 JSON 列）
    /// 纯属浪费；更重要的是，那会把「读坏列 → 拒绝写入」的自愈路径混进判重路径 ——
    /// 判重只该看一个 id，坏列不该把刷留痕也堵死。
    ///
    /// 返回 `false`（行不存在）说明行在判重与刷新之间被删了，调用方需要知晓。
    async fn touch_agent_fact_summary_marks(
        &self,
        agent_id: &str,
        marks: &AgentFactSummaryMarks,
    ) -> StoreResult<bool>;

    /// 用这台机器的清单**替换**它此前全部行（覆盖式重建），返回写入的行数。
    ///
    /// 为什么是「替换」而不是 upsert：清单是摘要的投影，而摘要每次都是**全量**上报 ——
    /// 上次有、这次没有的路径就是「不再观测到」，必须删掉。留着会让「哪些机器装了 X」
    /// 永久多出幽灵条目，而这类错误在页面上看不出来（只是多一行）。
    ///
    /// 传空切片是合法输入（摘要里没有可执行标识）：那会清空该 agent 的行，也是正确结果。
    async fn replace_agent_software_inventory(
        &self,
        agent_id: &str,
        entries: &[StoredSoftwareEntry],
    ) -> StoreResult<usize>;

    /// 这台机器有没有清单行。
    ///
    /// `duplicate` 路径用它决定要不要补建一次：内容没变时投影也不必重算，
    /// 但「上次投影没写成」（进程被杀、库锁）需要一次自愈机会。
    async fn agent_has_software_inventory(&self, agent_id: &str) -> StoreResult<bool>;

    /// 某台机器的清单（按 `kind`、`software_key`、`path` 排序）。
    async fn list_agent_software(&self, agent_id: &str) -> StoreResult<Vec<StoredSoftwareEntry>>;

    /// 某台机器的清单汇总（总行数 / 其中 app 行数）。
    async fn summarize_agent_software(
        &self,
        agent_id: &str,
    ) -> StoreResult<SoftwareInventorySummary>;

    /// 「按软件看机器」：取**持有机器数最多**的前 `limit` 个聚类键及其持有者。
    ///
    /// 为什么要 limit：`software_key` 是机械聚类键，元素数随「机器数 × 路径数」增长；
    /// 一次把所有键都读出来会在几百台机器时就把响应撞大（而页面一次也看不完）。
    async fn list_software_holdings(&self, limit: usize)
    -> StoreResult<Vec<StoredSoftwareHolding>>;

    /// 聚类键总数（用来告诉调用方 `list_software_holdings` 是不是截断了）。
    async fn count_software_keys(&self) -> StoreResult<i64>;

    /// 读取用途建议；未算过返回 `None`。
    async fn get_purpose_suggestion(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredPurposeSuggestion>>;

    /// 写入/覆盖用途建议（一台一条）。
    async fn upsert_purpose_suggestion(
        &self,
        suggestion: &StoredPurposeSuggestion,
    ) -> StoreResult<()>;

    /// 删除用途建议，返回是否删掉了东西。
    ///
    /// 新事实确实不该产出建议时（无规则册命中且无基线）用它：留着照旧事实算出的
    /// 旧结论比没有结论更误导。
    async fn clear_purpose_suggestion(&self, agent_id: &str) -> StoreResult<bool>;

    /// 读取人工判定；未判定返回 `None`。
    async fn get_agent_classification(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredAgentClassification>>;

    /// 写入/覆盖人工判定（一台一条）。
    async fn upsert_agent_classification(
        &self,
        classification: &StoredAgentClassification,
    ) -> StoreResult<()>;

    /// 机队用途覆盖度：总台数 / 已判定台数 / 各类别台数。
    async fn purpose_coverage(&self) -> StoreResult<PurposeCoverageCounts>;

    /// 写入/覆盖一份常驻工作（`work_id` 为主键）。
    ///
    /// 落库形状直接就是契约类型 `StandingWork`：库里的列与它一一对应，
    /// 再造一层 `Stored*` 只会多一个会漂移的映射。「更新」也走这里（同一 `work_id`）。
    async fn save_standing_work(&self, work: &StandingWork) -> StoreResult<()>;

    /// 按 `work_id` 读一份常驻工作。
    async fn get_standing_work(&self, work_id: &str) -> StoreResult<Option<StandingWork>>;

    /// 某 Agent 的**全部**常驻工作（含暂停/被取代/已撤回 —— 留痕要看得到）。
    async fn list_standing_work(&self, agent_id: &str) -> StoreResult<Vec<StandingWork>>;

    /// 写入/覆盖一份一次性工作（`work_id` 为主键）。
    async fn save_one_shot_work(&self, work: &StoredOneShotWork) -> StoreResult<()>;

    /// 按 `work_id` 读一份一次性工作。
    async fn get_one_shot_work(&self, work_id: &str) -> StoreResult<Option<StoredOneShotWork>>;

    /// 某 Agent 的**全部**一次性工作（含终态 —— 快照要筛，审计要全）。
    async fn list_one_shot_work(&self, agent_id: &str) -> StoreResult<Vec<StoredOneShotWork>>;

    /// **所有**未了结的一次性工作（跨 Agent）：到期判定要一次扫全机队。
    ///
    /// 为什么不按 agent 逐个扫：到期是工作自己的属性，不是「agent 来问了」的属性 ——
    /// agent 掉线时恰恰是这活最可能卡住的时候，那时没有 poll 可搭。
    async fn list_outstanding_one_shot_work(&self) -> StoreResult<Vec<StoredOneShotWork>>;

    /// 把一件**仍未了结**的一次性工作推入终态，返回是否真的推了。
    ///
    /// 为什么是条件更新（`WHERE status NOT IN 终态`）而不是「先读后写」：到期扫描与
    /// agent 的结果上报是两条会交错的路径 —— 列表读出来到现在，agent 可能刚把 `succeeded`
    /// 报进来。一条原子 UPDATE 就不会把 agent 报的终态覆盖成 `expired`：
    /// 「它成了」比「它超时了」更可信，抹掉它只会让页面与结果记录互相打脸。
    async fn terminate_outstanding_one_shot_work(
        &self,
        work_id: &str,
        status: &str,
    ) -> StoreResult<bool>;

    /// 写工作确认回执（一份工作一条，覆盖旧的）。
    async fn upsert_work_ack(&self, ack: &StoredWorkAck) -> StoreResult<()>;

    /// 读某份工作的确认回执；从未确认过返回 `None`（那就是漂移）。
    async fn get_work_ack(&self, work_id: &str) -> StoreResult<Option<StoredWorkAck>>;

    /// 写一次性工作的执行结果（一份工作一条，覆盖旧的）。
    async fn upsert_work_result(&self, result: &StoredWorkResult) -> StoreResult<()>;

    /// 读某份工作的执行结果；从未上报过返回 `None`。
    async fn get_work_result(&self, work_id: &str) -> StoreResult<Option<StoredWorkResult>>;

    /// 授权序号自增并返回新值（首次从 1 开始）。
    async fn next_work_sequence(&self, agent_id: &str, updated_at: &str) -> StoreResult<i64>;

    /// 读授权序号；从未授权过任何工作时返回 0。
    async fn work_sequence(&self, agent_id: &str) -> StoreResult<i64>;

    // ── 灰度发布计划 ──

    /// 写入/覆盖一份灰度发布计划（`plan_id` 为主键）。
    async fn save_rollout_plan(&self, plan: &StoredRolloutPlan) -> StoreResult<()>;

    /// 按 `plan_id` 读一份灰度发布计划。
    async fn get_rollout_plan(&self, plan_id: &str) -> StoreResult<Option<StoredRolloutPlan>>;

    /// 全部灰度发布计划（按创建时间倒序，供管理面列表）。
    async fn list_rollout_plans(&self) -> StoreResult<Vec<StoredRolloutPlan>>;

    /// 写/覆盖一条计划条目（`plan_id` + `target_id` 为主键）。
    async fn upsert_rollout_plan_entry(&self, entry: &StoredRolloutPlanEntry) -> StoreResult<()>;

    /// 某计划的全部条目。
    async fn list_rollout_plan_entries(
        &self,
        plan_id: &str,
    ) -> StoreResult<Vec<StoredRolloutPlanEntry>>;

    /// 按 `work_id` 找计划条目（结果上报回填用）；不是计划物化出来的工作返回 `None`。
    async fn find_rollout_plan_entry_by_work(
        &self,
        work_id: &str,
    ) -> StoreResult<Option<StoredRolloutPlanEntry>>;

    /// 满足同一过滤条件的 Agent 总数（分页用）。
    async fn count_agents(&self, query: &AgentQuery) -> StoreResult<u64>;

    async fn list_agent_ids(&self) -> StoreResult<Vec<String>>;

    async fn list_agent_instances(&self, agent_id: &str) -> StoreResult<Vec<StoredAgentInstance>>;

    /// 写入最近一次状态上报；返回 `false` 表示该 Agent 不存在（不再静默丢弃）。
    async fn record_agent_status(&self, update: &AgentStatusUpdate<'_>) -> StoreResult<bool>;

    /// 回填机器画像（机器名 / `node_id` / `machine_id` / 网卡地址）。
    ///
    /// 只在字段非空时覆盖 —— 老版本 agentd / 本次没带，都不该把已知的画像擦掉。
    /// 返回 `false` 表示该 Agent 不存在。
    async fn record_agent_machine_profile(
        &self,
        update: &AgentMachineProfileUpdate<'_>,
    ) -> StoreResult<bool>;

    /// 轮换凭据；返回 `false` 表示校验未通过（Agent/实例/当前凭据不匹配或已非 active）。
    async fn renew_agent_credential(&self, request: &RenewCredential<'_>) -> StoreResult<bool>;

    /// 吊销凭据（按 agent_id + credential_id 精确定位）。
    async fn revoke_agent_credential(
        &self,
        agent_id: &str,
        credential_id: &str,
    ) -> StoreResult<bool>;

    // ── 知识库内容包（设计 §6.1）──

    /// 录入一个包（幂等 upsert）：同一个 `package_id` 重复录入落同一行。
    async fn upsert_knowledge_package(&self, package: &StoredKnowledgePackage) -> StoreResult<()>;

    async fn knowledge_package(
        &self,
        package_id: &str,
    ) -> StoreResult<Option<StoredKnowledgePackage>>;

    /// 录入过的包，最近优先（管理面历史列表）。
    async fn list_knowledge_packages(&self) -> StoreResult<Vec<StoredKnowledgePackage>>;

    /// 当前生效指针。从未激活过返回 `None` —— 那是「空载」，不是错误（设计 §8.5）。
    async fn knowledge_active(&self) -> StoreResult<Option<StoredKnowledgeActive>>;

    /// 切生效指针：`generation` 在上一次基础上 +1，并写一条审计，**单事务**。
    /// 返回切换后的指针（调用方据此换内存里的那一份）。
    async fn activate_knowledge(
        &self,
        activation: &KnowledgeActivation<'_>,
    ) -> StoreResult<StoredKnowledgeActive>;

    /// 切换留痕，最近优先（管理面展示“谁什么时候把内容切到了哪一版”）。
    async fn list_knowledge_activations(
        &self,
        limit: u64,
    ) -> StoreResult<Vec<StoredKnowledgeActivation>>;

    /// **谁还锁在旧版目录**：按 `catalog_version` 分组统计常驻工作数（设计 §8.3）。
    ///
    /// 换版**不追改**在跑的工作，它们继续按自己那一版展开 —— 所以“换完了还有多少在跑老目录”
    /// 必须看得见，否则清理旧包时就是盲删。
    async fn standing_work_catalog_versions(&self) -> StoreResult<Vec<(i64, u64)>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// 旧版单文件 JSON 存储（仅用于一次性导入）
// ─────────────────────────────────────────────────────────────────────────────

/// 旧版 `state/wist-gateway-store.json` 的形状。
///
/// 只用于把已有部署的注册表导入 SQLite；导入后文件会被改名，不再被读取。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LegacyStoreSnapshot {
    pub enrollment_tokens: HashMap<String, StoredEnrollmentToken>,
    pub agents: HashMap<String, StoredAgentRegistration>,
}

/// 旧数据里缺 `token_id`（该字段是引入 SQLite 时才加的），按 hash 前缀补一个可审计 id。
pub fn legacy_token_id(token_hash: &str) -> String {
    let prefix: String = token_hash.chars().take(12).collect();
    format!("legacy-{prefix}")
}
