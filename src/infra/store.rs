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

use wist_contracts::gateway::AgentWorkStateChange;
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
    pub last_cpu_percent: Option<f64>,
    pub last_admin_latency_ms: Option<u64>,
    /// 本机**实际生效**的发现方向策略版本；`None` = 还没拿到策略表（在用内建默认周期）。
    pub last_discovery_policy_version: Option<i64>,
    /// 最近一次状态上报携带的工作状态变化（paused/resumed），非告警/失败。
    pub work_state_changes: Option<Vec<AgentWorkStateChange>>,
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

/// 数据面 TCP 入口的约定默认端口（与 wparse `topology/sources/tcp_1` 一致）。
pub const DEFAULT_AGENT_UPLINK_PORT: u16 = 9000;

/// Agent 数据面上送地址设置（网关据此渲染 Agent 初始配置里的 tcp 上送段）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredAgentUplinkAddress {
    pub setting_id: String,
    pub host: String,
    pub port: u16,
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

/// 时序指标样本 DTO（历史在 VictoriaMetrics，库里只留最近值）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetricSample {
    pub at: String,
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub cpu_percent: Option<f64>,
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
    /// `MachineClass` 裸名（MacDaily / MacDev / LinuxCompute / LinuxData）。
    pub suggested_class: String,
    /// 0..100。
    pub confidence: i64,
    /// `rule` | `model`（模型线在中心）。
    pub method: String,
    pub rule_set_id: Option<String>,
    /// 逐条命中依据；没有依据的建议不给人工看。
    pub signals: Vec<StoredPurposeSignal>,
    /// 依据哪一版事实算的，与 `computed_at` 区分开。
    pub observed_at: String,
    pub computed_at: String,
}

/// 事实上报的**留痕**：内容没变时只刷这几项，用来回答「什么时候又见到同一份内容」。
///
/// 故意不含三个内容列（`process_executables` / `packages` / `listen_ports`）与
/// `content_digest`：`duplicate` 的前提就是内容没变，重写它们既浪费，
/// 又会把「损坏列自愈」混进判重路径。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentFactSummaryMarks {
    /// 快照 revision（每轮 refresh 无条件 +1）。
    pub revision: i64,
    pub observed_at: String,
    /// 去重前的进程条数。
    pub process_count: i64,
    pub received_at: String,
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
        // 与安装路径（install.rs）既有对外文案逐字一致。
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
    pub cpu_percent: Option<f64>,
    pub admin_latency_ms: Option<u64>,
    /// 本机**实际生效**的发现方向策略版本；`None` = 还没拿到策略表（区别于「生效了第 0 版」）。
    pub discovery_policy_version: Option<i64>,
    pub work_state_changes: Option<Vec<AgentWorkStateChange>>,
}

/// 轮换 Agent 凭据（校验当前凭据后写入新凭据）。
#[derive(Debug, Clone)]
pub struct RenewCredential<'a> {
    pub agent_id: &'a str,
    pub instance_id: &'a str,
    pub current_token_hash: &'a str,
    pub new_credential_id: &'a str,
    pub new_token_hash: &'a str,
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

    /// 读取 wist-agentd 安装包地址设置；未设置过返回 `None`（调用方回落到内置默认地址）。
    async fn get_agent_install_package(
        &self,
    ) -> StoreResult<Option<StoredAgentInstallPackageAddress>>;

    /// 写入/覆盖 wist-agentd 安装包地址设置。
    async fn upsert_agent_install_package(
        &self,
        setting: &StoredAgentInstallPackageAddress,
    ) -> StoreResult<()>;

    /// 读取 Agent 数据面上送地址设置；未设置过返回 `None`（调用方不下发上送段）。
    async fn get_agent_uplink(&self) -> StoreResult<Option<StoredAgentUplinkAddress>>;

    /// 写入/覆盖 Agent 数据面上送地址设置。
    async fn upsert_agent_uplink(&self, setting: &StoredAgentUplinkAddress) -> StoreResult<()>;

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

    /// 只刷留痕字段（`revision` / `observed_at` / `process_count` / `received_at`），
    /// **不动**内容列与 `content_digest`。返回是否真的命中了行。
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

    /// 满足同一过滤条件的 Agent 总数（分页用）。
    async fn count_agents(&self, query: &AgentQuery) -> StoreResult<u64>;

    async fn list_agent_ids(&self) -> StoreResult<Vec<String>>;

    async fn list_agent_instances(&self, agent_id: &str) -> StoreResult<Vec<StoredAgentInstance>>;

    /// 写入最近一次状态上报；返回 `false` 表示该 Agent 不存在（不再静默丢弃）。
    async fn record_agent_status(&self, update: &AgentStatusUpdate<'_>) -> StoreResult<bool>;

    /// 轮换凭据；返回 `false` 表示校验未通过（Agent/实例/当前凭据不匹配或已非 active）。
    async fn renew_agent_credential(&self, request: &RenewCredential<'_>) -> StoreResult<bool>;

    /// 吊销凭据（按 agent_id + credential_id 精确定位）。
    async fn revoke_agent_credential(
        &self,
        agent_id: &str,
        credential_id: &str,
    ) -> StoreResult<bool>;
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
