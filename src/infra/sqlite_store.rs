//! SQLite 后端（默认存储）。
//!
//! * 内嵌、零外部服务：数据库文件放在已有挂载的 state 目录里，不引入新进程/端口。
//! * schema 由 `migrations/sqlite/*.sql` 通过 [`sqlx::migrate!`] 在启动时执行，
//!   已有库同样会补新表/新列（不像 initdb 脚本只在空数据卷跑一次）。
//! * 需要真事务的几处（预留 token、落库注册）用 `pool.begin()`，因此并发下不再
//!   依赖早期的「进程内 mutex + 文件锁 + 整体重写 JSON」。
//!
//! 单写者约束：WAL 下同机可并发读、写串行；**不跨主机共享**。因此当前实现假定
//! 控制面单副本（与 docker-compose 里 1 个 gateway 容器一致）。要多副本负载均衡
//! 就需要换成共享数据库（同一 [`crate::infra::Store`] trait 下的 Postgres 实现）。

use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use orion_error::{conversion::ToStructError, prelude::*};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteRow, SqliteSynchronous,
};
use sqlx::{QueryBuilder, Row, Sqlite};
use wist_error::StoreReason;

use super::store::*;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

const TOKEN_COLUMNS: &str = "token_id, token_hash, tenant_id, environment_id, issued_by, \
                             allowed_node_selector, max_uses, used_count, status, issued_at, \
                             expires_at, reserved_at, revoked_at";

/// Agent 读投影：身份 + 当前实例 + 当前凭据。
const AGENT_PROJECTION: &str = "SELECT a.agent_id, a.tenant_id, a.environment_id, a.node_id, \
     a.hostname, a.machine_id, a.registered_at, \
     COALESCE(a.current_instance_id, '') AS instance_id, \
     COALESCE(i.version, '') AS version, \
     COALESCE(i.last_seen_at, '') AS last_seen_at, \
     COALESCE(i.started_at, '') AS started_at, \
     i.memory_bytes, i.cpu_percent, i.cpu_cores, i.admin_latency_ms, i.work_state_changes, \
     i.discovery_policy_version, i.local_work, i.uplink_state, \
     COALESCE(a.current_credential_id, '') AS credential_id, \
     COALESCE(c.token_hash, '') AS credential_token_hash, \
     COALESCE(c.issued_at, '') AS credential_issued_at, \
     COALESCE(c.expires_at, '') AS credential_expires_at, \
     COALESCE(c.status, 'active') AS credential_status \
     FROM agents a \
     LEFT JOIN agent_instances i ON i.instance_id = a.current_instance_id \
     LEFT JOIN agent_credentials c ON c.credential_id = a.current_credential_id";

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

/// 删一台 Agent 时要清的 per-agent 表（**子表在前**），与 `delete_agent` 配套。
///
/// 只列**真正按 `agent_id` 分行**的表：`agent_uplink` / `agent_advertise_url` 是单例设置
/// （`setting_id` 主键），`agent_discovery_policy_version` / `local_work` 是 `agent_instances`
/// 的列 —— 都不在这里。`agents` 本身也不列：它是主表，由 `delete_agent` 最后删。
///
/// 第二个元素只是审计/报错用的说明，进 `sql_error` 的 `detail`。
const DELETE_AGENT_TABLES: &[(&str, &str)] = &[
    (
        "agent_purpose_suggestion",
        "delete agent purpose suggestion",
    ),
    ("agent_fact_summary", "delete agent fact summary"),
    ("agent_classification", "delete agent classification"),
    (
        "agent_software_inventory",
        "delete agent software inventory",
    ),
    ("agent_work_result", "delete agent work result"),
    ("work_ack", "delete agent work ack"),
    ("one_shot_work", "delete agent one-shot work"),
    ("standing_work", "delete agent standing work"),
    ("agent_work_sequence", "delete agent work sequence"),
    ("agent_credentials", "delete agent credentials"),
    ("agent_instances", "delete agent instances"),
];

fn sql_error(err: impl std::fmt::Display, detail: &str) -> StoreError {
    StoreReason::Sql
        .to_err()
        .with_detail(format!("{detail}: {err}"))
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// SQLite 没有无符号整数类型，`u64` 也不实现 `Encode`（可能溢出 i64），
/// 因此写入前显式收敛到 i64；读取侧由 sqlx 的 `u64` decode 做溢出检查。
fn to_sql_int(value: Option<u64>) -> Option<i64> {
    value.map(|value| i64::try_from(value).unwrap_or(i64::MAX))
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

/// 拒绝名单条目是否仍然「生效」：`retain_until` 可解析且晚于 `now`。
///
/// 解析失败按**仍生效**处理（与 `credential_is_expired` 解析失败即判过期同一口径：
/// 安全侧 fail-closed）。要放行就走解除名单，不指望坏行自己过期。
fn revocation_is_live(retain_until: &str, now: DateTime<Utc>) -> bool {
    match parse_rfc3339(retain_until) {
        Some(until) => until > now,
        None => true,
    }
}

/// 回收超时的预留（与既有 `recover_expired_reservation` 语义一致：`reserved_at`
/// 缺失或不可解析视为立即可回收）。返回是否发生了回收。
fn recover_stale_reservation(
    token: &mut StoredEnrollmentToken,
    now: DateTime<Utc>,
    ttl_seconds: i64,
) -> bool {
    if token.status != StoredEnrollmentTokenStatus::Reserved {
        return false;
    }
    let stale = match token.reserved_at.as_deref().and_then(parse_rfc3339) {
        Some(reserved_at) => (now - reserved_at).num_seconds() >= ttl_seconds,
        None => true,
    };
    if stale {
        token.used_count = token.used_count.saturating_sub(1);
        token.reserved_at = None;
        token.status = StoredEnrollmentTokenStatus::Active;
    }
    stale
}

impl SqliteStore {
    /// 打开（必要时创建）SQLite 库并执行迁移。
    ///
    /// DSN 形如 `sqlite:/var/lib/wist-gateway/gateway.db` 或 `sqlite::memory:`。
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let in_memory = database_url.contains(":memory:");
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(|err| sql_error(err, "invalid sqlite dsn"))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(10))
            .foreign_keys(true);
        // 内存库是「每连接一个库」，必须单连接，否则迁移与查询会落在不同库上。
        let max_connections = if in_memory { 1 } else { 5 };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(|err| sql_error(err, "connect sqlite"))?;
        MIGRATOR
            .run(&pool)
            .await
            .map_err(|err| sql_error(err, "run sqlite migrations"))?;
        // 拒绝名单的 GC **不在这里**：它不是「打开库」的职责，而是运行期的周期清扫
        // （见 `api::spawn_revocation_gc_tick`）。只放一处，免得两个触发点各自漂移。
        Ok(Self { pool })
    }

    /// 按文件路径打开默认库（父目录会自动创建）。
    pub async fn connect_path(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).source_err(StoreReason::Io, "create sqlite dir")?;
        }
        Self::connect(&format!("sqlite:{}", path.display())).await
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// 一次性导入旧版单文件 JSON 存储。
    ///
    /// 仅在库中既无 Agent 也无注册 token 时导入（避免覆盖已有数据），导入成功后
    /// 把源文件改名为 `*.imported`，防止重复导入。返回是否真的导入了数据。
    pub async fn import_legacy_json(&self, path: &Path) -> StoreResult<bool> {
        if !path.exists() {
            return Ok(false);
        }
        let agent_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents")
            .fetch_one(&self.pool)
            .await
            .map_err(|err| sql_error(err, "count agents"))?;
        let token_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enrollment_tokens")
            .fetch_one(&self.pool)
            .await
            .map_err(|err| sql_error(err, "count enrollment tokens"))?;
        if agent_count > 0 || token_count > 0 {
            return Ok(false);
        }
        let raw = fs::read_to_string(path).source_err(StoreReason::Io, "read legacy store")?;
        if raw.trim().is_empty() {
            return Ok(false);
        }
        let snapshot: LegacyStoreSnapshot =
            serde_json::from_str(&raw).source_err(StoreReason::Json, "parse legacy store")?;
        if snapshot.agents.is_empty() && snapshot.enrollment_tokens.is_empty() {
            return Ok(false);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin legacy import"))?;

        for token in snapshot.enrollment_tokens.into_values() {
            let mut token = token;
            if token.token_id.is_empty() {
                token.token_id = legacy_token_id(&token.token_hash);
            }
            insert_token(&mut tx, &token).await?;
        }

        for mut agent in snapshot.agents.into_values() {
            if agent.agent_id.is_empty() {
                continue;
            }
            let registered_at = if agent.registered_at.is_empty() {
                now_rfc3339()
            } else {
                agent.registered_at.clone()
            };
            let last_seen_at = if agent.last_seen_at.is_empty() {
                registered_at.clone()
            } else {
                agent.last_seen_at.clone()
            };
            let instance_id = agent.instance_id.clone();
            let credential_id = agent.credential_id.clone();
            if agent.credential_issued_at.is_empty() {
                agent.credential_issued_at = registered_at.clone();
            }
            if agent.credential_status == StoredCredentialStatus::Active
                && agent.credential_expires_at.is_empty()
            {
                // 旧数据缺过期时间时给一个明确的过去时间，避免被当成永不过期。
                agent.credential_expires_at = registered_at.clone();
            }

            sqlx::query(
                "INSERT OR REPLACE INTO agents (agent_id, tenant_id, environment_id, node_id, \
                 hostname, machine_id, status, current_instance_id, current_credential_id, \
                 registered_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?8, ?9, ?9)",
            )
            .bind(&agent.agent_id)
            .bind(&agent.tenant_id)
            .bind(&agent.environment_id)
            .bind(&agent.node_id)
            .bind(&agent.hostname)
            .bind(&agent.machine_id)
            .bind(&instance_id)
            .bind(&credential_id)
            .bind(&registered_at)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, "import legacy agent"))?;

            if !instance_id.is_empty() {
                let work_state_changes = serialize_work_state_changes(agent.work_state_changes)?;
                sqlx::query(
                    "INSERT OR REPLACE INTO agent_instances (instance_id, agent_id, boot_id, \
                     version, started_at, last_seen_at, memory_bytes, cpu_percent, \
                     cpu_cores, admin_latency_ms, work_state_changes) \
                     VALUES (?1, ?2, '', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .bind(&instance_id)
                .bind(&agent.agent_id)
                .bind(&agent.version)
                .bind(&registered_at)
                .bind(&last_seen_at)
                .bind(to_sql_int(agent.last_memory_bytes))
                .bind(agent.last_cpu_percent)
                .bind(agent.last_cpu_cores)
                .bind(to_sql_int(agent.last_admin_latency_ms))
                .bind(work_state_changes)
                .execute(&mut *tx)
                .await
                .map_err(|err| sql_error(err, "import legacy instance"))?;
            }

            if !credential_id.is_empty() && !agent.credential_token_hash.is_empty() {
                sqlx::query(
                    "INSERT OR REPLACE INTO agent_credentials (credential_id, agent_id, \
                     instance_id, auth_scheme, token_hash, status, issued_at, expires_at, \
                     revoked_at) VALUES (?1, ?2, ?3, 'bearer', ?4, ?5, ?6, ?7, NULL)",
                )
                .bind(&credential_id)
                .bind(&agent.agent_id)
                .bind(&instance_id)
                .bind(&agent.credential_token_hash)
                .bind(agent.credential_status.as_str())
                .bind(&agent.credential_issued_at)
                .bind(&agent.credential_expires_at)
                .execute(&mut *tx)
                .await
                .map_err(|err| sql_error(err, "import legacy credential"))?;
            }
        }

        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit legacy import"))?;

        let imported = imported_path(path);
        fs::rename(path, &imported).source_err(StoreReason::Io, "archive legacy store")?;
        Ok(true)
    }
}

fn imported_path(path: &Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".imported");
    std::path::PathBuf::from(value)
}

fn serialize_work_state_changes(
    changes: Option<Vec<wist_contracts::gateway::AgentWorkStateChange>>,
) -> StoreResult<Option<String>> {
    match changes {
        Some(changes) => serde_json::to_string(&changes)
            .map(Some)
            .source_err(StoreReason::Json, "serialize work state changes"),
        None => Ok(None),
    }
}

/// 本机工作视图落一个 TEXT 列（只留最近一份）。
fn serialize_local_work(
    value: Option<wist_contracts::local_work::AgentLocalWork>,
) -> StoreResult<Option<String>> {
    match value {
        Some(value) => serde_json::to_string(&value)
            .map(Some)
            .source_err(StoreReason::Json, "serialize local work view"),
        None => Ok(None),
    }
}

/// 实际生效的采集输出状态落一个 TEXT 列（只留最近一份），与 `serialize_local_work` 同形。
fn serialize_uplink_state(
    value: Option<wist_contracts::agent_uplink::AgentUplinkState>,
) -> StoreResult<Option<String>> {
    match value {
        Some(value) => serde_json::to_string(&value)
            .map(Some)
            .source_err(StoreReason::Json, "serialize agent uplink state"),
        None => Ok(None),
    }
}

/// 与 `deserialize_work_state_changes` 同一条取舍：读到坏 JSON 就当「没报过」（`None`），
/// 不让一列坏数据把「读取 agent」整条路打挂。
fn deserialize_local_work(
    raw: Option<String>,
) -> Option<wist_contracts::local_work::AgentLocalWork> {
    match raw.as_deref() {
        Some(value) if !value.is_empty() => serde_json::from_str(value).ok(),
        _ => None,
    }
}

/// 与 `deserialize_local_work` 同一条取舍：读到坏 JSON 就当「没报过」（`None`），
/// 不让一列坏数据把「读取 agent」整条路打挂。
fn deserialize_uplink_state(
    raw: Option<String>,
) -> Option<wist_contracts::agent_uplink::AgentUplinkState> {
    match raw.as_deref() {
        Some(value) if !value.is_empty() => serde_json::from_str(value).ok(),
        _ => None,
    }
}

/// 最近一次续签判定落一个 TEXT 列（只留最近一份），与 `serialize_uplink_state` 同形。
fn serialize_renewal_report(
    value: Option<wist_contracts::gateway::AgentCredentialRenewal>,
) -> StoreResult<Option<String>> {
    match value {
        Some(value) => serde_json::to_string(&value)
            .map(Some)
            .source_err(StoreReason::Json, "serialize agent credential renewal"),
        None => Ok(None),
    }
}

/// 与 `deserialize_local_work` 同一条取舍：读到坏 JSON 就当「没报过」（`None`）。
fn deserialize_renewal_report(
    raw: Option<String>,
) -> Option<wist_contracts::gateway::AgentCredentialRenewal> {
    match raw.as_deref() {
        Some(value) if !value.is_empty() => serde_json::from_str(value).ok(),
        _ => None,
    }
}

fn deserialize_work_state_changes(
    raw: Option<String>,
) -> Option<Vec<wist_contracts::gateway::AgentWorkStateChange>> {
    match raw.as_deref() {
        Some(value) if !value.is_empty() => serde_json::from_str(value).ok(),
        _ => None,
    }
}

/// 事实摘要里的三个字符串集合以 JSON 数组落 TEXT 列。
fn serialize_json_array<T: serde::Serialize>(
    values: &[T],
    detail: &'static str,
) -> StoreResult<String> {
    serde_json::to_string(values).source_err(StoreReason::Json, detail)
}

/// 与 `deserialize_work_state_changes` 不同，这里**不吞错**：列里的 JSON 是本服务自己写的，
/// 解析失败就是不变式被破坏；静默当成空集会让推断静默退化成基线类别，那比报错更坏。
fn deserialize_json_array<T: serde::de::DeserializeOwned>(
    raw: &str,
    detail: &'static str,
) -> StoreResult<Vec<T>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(raw).source_err(StoreReason::Json, detail)
}

/// 读取列值的统一入口：把 sqlx 的类型错误映射成 `StoreReason::Sql`。
macro_rules! column {
    ($row:expr, $name:literal) => {
        $row.try_get($name).map_err(|err| {
            StoreReason::Sql
                .to_err()
                .with_detail(format!("read column {}: {err}", $name))
        })?
    };
}

fn token_from_row(row: &SqliteRow) -> StoreResult<StoredEnrollmentToken> {
    let status: String = column!(row, "status");
    Ok(StoredEnrollmentToken {
        token_id: column!(row, "token_id"),
        token_hash: column!(row, "token_hash"),
        tenant_id: column!(row, "tenant_id"),
        environment_id: column!(row, "environment_id"),
        issued_by: column!(row, "issued_by"),
        allowed_node_selector: column!(row, "allowed_node_selector"),
        max_uses: column!(row, "max_uses"),
        used_count: column!(row, "used_count"),
        status: StoredEnrollmentTokenStatus::parse(&status),
        issued_at: column!(row, "issued_at"),
        expires_at: column!(row, "expires_at"),
        reserved_at: column!(row, "reserved_at"),
        revoked_at: column!(row, "revoked_at"),
    })
}

/// 把 [`AgentQuery`] 的过滤条件追加到 builder（`list_agents` 与 `count_agents` 共用）。
fn push_agent_filters(builder: &mut QueryBuilder<Sqlite>, query: &AgentQuery) {
    builder.push(" WHERE 1 = 1");
    if let Some(tenant_id) = query.tenant_id.as_deref() {
        builder.push(" AND a.tenant_id = ").push_bind(tenant_id);
    }
    if let Some(environment_id) = query.environment_id.as_deref() {
        builder
            .push(" AND a.environment_id = ")
            .push_bind(environment_id);
    }
    if let Some(status) = query.status.as_deref() {
        builder.push(" AND a.status = ").push_bind(status);
    }
}

fn software_entry_from_row(row: &SqliteRow) -> StoreResult<StoredSoftwareEntry> {
    Ok(StoredSoftwareEntry {
        agent_id: column!(row, "agent_id"),
        software_key: column!(row, "software_key"),
        name: column!(row, "name"),
        kind: column!(row, "kind"),
        matched_rule: column!(row, "matched_rule"),
        path: column!(row, "path"),
        received_at: column!(row, "received_at"),
    })
}

fn agent_from_row(row: &SqliteRow) -> StoreResult<StoredAgentRegistration> {
    let credential_status: String = column!(row, "credential_status");
    let work_state_changes: Option<String> = column!(row, "work_state_changes");
    let local_work: Option<String> = column!(row, "local_work");
    let uplink_state: Option<String> = column!(row, "uplink_state");
    Ok(StoredAgentRegistration {
        agent_id: column!(row, "agent_id"),
        instance_id: column!(row, "instance_id"),
        tenant_id: column!(row, "tenant_id"),
        environment_id: column!(row, "environment_id"),
        node_id: column!(row, "node_id"),
        hostname: column!(row, "hostname"),
        machine_id: column!(row, "machine_id"),
        version: column!(row, "version"),
        credential_id: column!(row, "credential_id"),
        credential_token_hash: column!(row, "credential_token_hash"),
        credential_issued_at: column!(row, "credential_issued_at"),
        credential_expires_at: column!(row, "credential_expires_at"),
        credential_status: StoredCredentialStatus::parse(&credential_status),
        registered_at: column!(row, "registered_at"),
        last_seen_at: column!(row, "last_seen_at"),
        started_at: column!(row, "started_at"),
        last_memory_bytes: column!(row, "memory_bytes"),
        last_cpu_percent: column!(row, "cpu_percent"),
        last_cpu_cores: column!(row, "cpu_cores"),
        last_admin_latency_ms: column!(row, "admin_latency_ms"),
        last_discovery_policy_version: column!(row, "discovery_policy_version"),
        work_state_changes: deserialize_work_state_changes(work_state_changes),
        local_work: deserialize_local_work(local_work),
        uplink_state: deserialize_uplink_state(uplink_state),
    })
}

fn agent_install_package_from_row(row: &SqliteRow) -> StoreResult<StoredAgentInstallPackage> {
    Ok(StoredAgentInstallPackage {
        package_id: column!(row, "package_id"),
        source: column!(row, "source"),
        package_sha256: column!(row, "package_sha256"),
        version: column!(row, "version"),
        arch: column!(row, "arch"),
        cached_path: column!(row, "cached_path"),
        created_by: column!(row, "created_by"),
        created_at: column!(row, "created_at"),
    })
}

fn knowledge_package_from_row(row: &SqliteRow) -> StoreResult<StoredKnowledgePackage> {
    Ok(StoredKnowledgePackage {
        package_id: column!(row, "package_id"),
        source: column!(row, "source"),
        package_sha256: column!(row, "package_sha256"),
        version: column!(row, "version"),
        catalog_version: column!(row, "catalog_version"),
        template_version: column!(row, "template_version"),
        policy_version: column!(row, "policy_version"),
        purpose_version: column!(row, "purpose_version"),
        parser_abi: column!(row, "parser_abi"),
        signed_by: column!(row, "signed_by"),
        cached_path: column!(row, "cached_path"),
        created_by: column!(row, "created_by"),
        created_at: column!(row, "created_at"),
    })
}

async fn insert_token(tx: &mut SqliteConnection, token: &StoredEnrollmentToken) -> StoreResult<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO enrollment_tokens (token_id, token_hash, tenant_id, \
         environment_id, issued_by, allowed_node_selector, max_uses, used_count, status, \
         issued_at, expires_at, reserved_at, revoked_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )
    .bind(&token.token_id)
    .bind(&token.token_hash)
    .bind(&token.tenant_id)
    .bind(&token.environment_id)
    .bind(&token.issued_by)
    .bind(&token.allowed_node_selector)
    .bind(token.max_uses as i64)
    .bind(token.used_count as i64)
    .bind(token.status.as_str())
    .bind(&token.issued_at)
    .bind(&token.expires_at)
    .bind(&token.reserved_at)
    .bind(&token.revoked_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| sql_error(err, "insert enrollment token"))?;
    Ok(())
}

async fn fetch_token(
    tx: &mut SqliteConnection,
    token_hash: &str,
) -> StoreResult<Option<StoredEnrollmentToken>> {
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {TOKEN_COLUMNS} FROM enrollment_tokens WHERE token_hash = ?1"
    )))
    .bind(token_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| sql_error(err, "select enrollment token"))?;
    row.as_ref().map(token_from_row).transpose()
}

async fn persist_token_state(
    tx: &mut SqliteConnection,
    token: &StoredEnrollmentToken,
) -> StoreResult<()> {
    sqlx::query(
        "UPDATE enrollment_tokens SET status = ?1, used_count = ?2, reserved_at = ?3, \
         revoked_at = ?4 WHERE token_hash = ?5",
    )
    .bind(token.status.as_str())
    .bind(token.used_count as i64)
    .bind(&token.reserved_at)
    .bind(&token.revoked_at)
    .bind(&token.token_hash)
    .execute(&mut *tx)
    .await
    .map_err(|err| sql_error(err, "update enrollment token"))?;
    Ok(())
}

async fn agent_exists_tx(tx: &mut SqliteConnection, agent_id: &str) -> StoreResult<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM agents WHERE agent_id = ?1")
        .bind(agent_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "select agent"))?;
    Ok(found.is_some())
}

#[async_trait]
impl Store for SqliteStore {
    async fn insert_enrollment_token(&self, token: &StoredEnrollmentToken) -> StoreResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin insert token"))?;
        insert_token(&mut tx, token).await?;
        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit insert token"))?;
        Ok(())
    }

    async fn validate_bootstrap_token(
        &self,
        check: &BootstrapTokenCheck<'_>,
    ) -> StoreResult<Result<(), EnrollmentTokenRejection>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin validate bootstrap token"))?;
        let now = Utc::now();
        let Some(mut token) = fetch_token(&mut tx, check.token_hash).await? else {
            return Ok(Err(EnrollmentTokenRejection::Unknown));
        };

        // 与既有实现一致：租户与环境任一不匹配都返回同一句文案。
        if token.tenant_id != check.tenant_id || token.environment_id != check.environment_id {
            return Ok(Err(EnrollmentTokenRejection::EnvironmentMismatch));
        }
        if token.token_hash != check.token_hash {
            return Ok(Err(EnrollmentTokenRejection::HashMismatch));
        }

        let Some(expires_at) = parse_rfc3339(&token.expires_at) else {
            return Ok(Err(EnrollmentTokenRejection::InvalidExpiration));
        };

        // 关键：过期标记/预留回收即使随后返回错误也要落库（安装路径依赖该语义）。
        if now >= expires_at {
            token.status = StoredEnrollmentTokenStatus::Expired;
            persist_token_state(&mut tx, &token).await?;
            tx.commit()
                .await
                .map_err(|err| sql_error(err, "commit validate bootstrap token"))?;
            return Ok(Err(EnrollmentTokenRejection::Expired));
        }

        let recovered = recover_stale_reservation(&mut token, now, check.reservation_ttl_seconds);

        let rejection = if token.status != StoredEnrollmentTokenStatus::Active {
            Some(EnrollmentTokenRejection::NotActive)
        } else if token.used_count >= token.max_uses {
            Some(EnrollmentTokenRejection::Exhausted)
        } else {
            None
        };

        if recovered {
            persist_token_state(&mut tx, &token).await?;
            tx.commit()
                .await
                .map_err(|err| sql_error(err, "commit validate bootstrap token"))?;
        }
        Ok(match rejection {
            Some(rejection) => Err(rejection),
            None => Ok(()),
        })
    }

    async fn reserve_enrollment_token(
        &self,
        request: &ReserveEnrollmentToken<'_>,
    ) -> StoreResult<Result<(), ReservationRejection>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin reserve token"))?;
        let now = Utc::now();
        let Some(mut token) = fetch_token(&mut tx, request.token_hash).await? else {
            return Ok(Err(ReservationRejection::InvalidToken));
        };
        if token.tenant_id != request.tenant_id || token.environment_id != request.environment_id {
            return Ok(Err(ReservationRejection::InvalidToken));
        }
        // 预留回收与后续失败同事务：拒绝时不落库（与既有 update_result 回滚语义一致）。
        recover_stale_reservation(&mut token, now, request.reservation_ttl_seconds);
        if token.status != StoredEnrollmentTokenStatus::Active
            || token.used_count >= token.max_uses
            || token.token_hash != request.token_hash
        {
            return Ok(Err(ReservationRejection::InvalidToken));
        }
        let Some(expires_at) = parse_rfc3339(&token.expires_at) else {
            return Ok(Err(ReservationRejection::InvalidToken));
        };
        if now >= expires_at {
            return Ok(Err(ReservationRejection::InvalidToken));
        }
        if agent_exists_tx(&mut tx, request.agent_id).await? {
            return Ok(Err(ReservationRejection::DuplicateAgent));
        }

        token.used_count = token.used_count.saturating_add(1);
        token.reserved_at = Some(now.to_rfc3339());
        token.status = StoredEnrollmentTokenStatus::Reserved;
        persist_token_state(&mut tx, &token).await?;
        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit reserve token"))?;
        Ok(Ok(()))
    }

    async fn commit_reserved_registration(
        &self,
        request: &CommitRegistration<'_>,
    ) -> StoreResult<Result<(), CommitRejection>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin commit registration"))?;
        let Some(mut token) = fetch_token(&mut tx, request.token_hash).await? else {
            return Ok(Err(CommitRejection::InvalidToken));
        };
        if token.status != StoredEnrollmentTokenStatus::Reserved
            || token.token_hash != request.token_hash
        {
            return Ok(Err(CommitRejection::InvalidToken));
        }
        if agent_exists_tx(&mut tx, request.agent_id).await? {
            return Ok(Err(CommitRejection::DuplicateAgent));
        }

        // ① token 收尾
        token.status = if token.used_count >= token.max_uses {
            StoredEnrollmentTokenStatus::Used
        } else {
            StoredEnrollmentTokenStatus::Active
        };
        token.reserved_at = None;
        persist_token_state(&mut tx, &token).await?;

        // ② Agent 身份
        sqlx::query(
            "INSERT INTO agents (agent_id, tenant_id, environment_id, node_id, hostname, \
             machine_id, status, current_instance_id, current_credential_id, registered_at, \
             updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?8, ?9, ?10)",
        )
        .bind(request.agent_id)
        .bind(request.tenant_id)
        .bind(request.environment_id)
        .bind(request.node_id)
        .bind(request.hostname)
        .bind(request.machine_id)
        .bind(request.instance_id)
        .bind(request.credential_id)
        .bind(request.registered_at)
        .bind(request.now)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "insert agent"))?;

        // ③ Agent 实例（历史起点）
        if !request.instance_id.is_empty() {
            sqlx::query(
                "INSERT INTO agent_instances (instance_id, agent_id, boot_id, version, \
                 started_at, last_seen_at, memory_bytes, cpu_percent, admin_latency_ms, \
                 work_state_changes) VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL, NULL, NULL, NULL)",
            )
            .bind(request.instance_id)
            .bind(request.agent_id)
            .bind(request.boot_id)
            .bind(request.version)
            .bind(request.now)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, "insert agent instance"))?;
        }

        // ④ 凭据
        sqlx::query(
            "INSERT INTO agent_credentials (credential_id, agent_id, instance_id, auth_scheme, \
             token_hash, status, issued_at, expires_at, revoked_at) \
             VALUES (?1, ?2, ?3, 'bearer', ?4, 'active', ?5, ?6, NULL)",
        )
        .bind(request.credential_id)
        .bind(request.agent_id)
        .bind(request.instance_id)
        .bind(request.credential_token_hash)
        .bind(request.credential_issued_at)
        .bind(request.credential_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "insert agent credential"))?;

        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit registration"))?;
        Ok(Ok(()))
    }

    async fn register_agent_from_certificate(
        &self,
        registration: &CertificateRegistration<'_>,
    ) -> StoreResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin register agent from certificate"))?;
        // 幂等：已存在就一个字段都不碰（不刷新凭据/时间戳）。库丢/换网关后，多台 agent
        // 会并发首触，谁先到谁建，后到的重入必须是无操作而不是覆盖。
        if agent_exists_tx(&mut tx, registration.agent_id).await? {
            return Ok(false);
        }

        // 只写已知的稳定身份；机器画像（node_id/hostname/machine_id）留给后续状态上报，
        // 故置 ''。
        //
        // `current_instance_id` 故意留 NULL（而不是像注册路径那样填一个 instance_id）：
        // 首触时实例本来就未知，且 `get_agent` 的投影对 `agent_instances` 用的是
        // `LEFT JOIN`（见 AGENT_PROJECTION），NULL 不会把整行滤掉 —— 记录仍能读到，
        // 投影里 `instance_id` 经 COALESCE 退化为 ''。再造一条 boot_id/version 都空的
        // 「幽灵实例」反而会污染 `agent_instances`（那张表的语义是「每次真实 Agentd
        // 启动一条」），等 agent 首次上包由 `record_agent_status` 正常写入当前实例。
        sqlx::query(
            "INSERT INTO agents (agent_id, tenant_id, environment_id, node_id, hostname, \
             machine_id, status, current_instance_id, current_credential_id, registered_at, \
             updated_at) VALUES (?1, ?2, ?3, '', '', '', 'active', NULL, ?4, ?5, ?6)",
        )
        .bind(registration.agent_id)
        .bind(registration.tenant_id)
        .bind(registration.environment_id)
        .bind(registration.credential_id)
        .bind(registration.registered_at)
        .bind(registration.now)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "insert agent from certificate"))?;

        // 凭据：证书路径与注册路径的区别只在 `auth_scheme = 'certificate'`，指纹仍占
        // `token_hash` 那列（该列有唯一索引，天然防止同一张证书重复落库）。instance_id
        // 与 agents.current_instance_id 口径一致，留空。
        sqlx::query(
            "INSERT INTO agent_credentials (credential_id, agent_id, instance_id, auth_scheme, \
             token_hash, status, issued_at, expires_at, revoked_at) \
             VALUES (?1, ?2, '', 'certificate', ?3, 'active', ?4, ?5, NULL)",
        )
        .bind(registration.credential_id)
        .bind(registration.agent_id)
        .bind(registration.credential_fingerprint)
        .bind(registration.credential_issued_at)
        .bind(registration.credential_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "insert certificate credential"))?;

        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit register agent from certificate"))?;
        Ok(true)
    }

    async fn rollback_enrollment_token_reservation(&self, token_hash: &str) -> StoreResult<()> {
        // 只归还处于 reserved 的预留；其它状态为无操作（与既有实现一致）。
        sqlx::query(
            "UPDATE enrollment_tokens SET used_count = CASE WHEN used_count > 0 THEN used_count - 1 \
             ELSE 0 END, reserved_at = NULL, status = 'active' \
             WHERE token_hash = ?1 AND status = 'reserved'",
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "rollback token reservation"))?;
        Ok(())
    }

    async fn get_enrollment_token(
        &self,
        token_hash: &str,
    ) -> StoreResult<Option<StoredEnrollmentToken>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|err| sql_error(err, "acquire connection"))?;
        fetch_token(&mut conn, token_hash).await
    }

    async fn revoke_enrollment_token(&self, token_id: &str) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE enrollment_tokens SET status = 'revoked', revoked_at = ?1, reserved_at = NULL \
             WHERE token_id = ?2 AND status != 'revoked'",
        )
        .bind(now_rfc3339())
        .bind(token_id)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "revoke enrollment token"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_agent(&self, agent_id: &str) -> StoreResult<Option<StoredAgentRegistration>> {
        let mut builder = QueryBuilder::<Sqlite>::new(AGENT_PROJECTION);
        builder.push(" WHERE a.agent_id = ").push_bind(agent_id);
        let row = builder
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| sql_error(err, "select agent"))?;
        row.as_ref().map(agent_from_row).transpose()
    }

    async fn find_agent_by_credential_token_hash(
        &self,
        token_hash: &str,
    ) -> StoreResult<Option<StoredAgentRegistration>> {
        // 只匹配「当前凭据」：投影的 `c` 是 agents.current_credential_id 指向的那一行，
        // 所以轮换/吊销过的旧凭据不会命中（与 authenticate_agent 的口径一致）。
        let mut builder = QueryBuilder::<Sqlite>::new(AGENT_PROJECTION);
        builder.push(" WHERE c.token_hash = ").push_bind(token_hash);
        let row = builder
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| sql_error(err, "select agent by credential token hash"))?;
        row.as_ref().map(agent_from_row).transpose()
    }

    async fn agent_exists(&self, agent_id: &str) -> StoreResult<bool> {
        let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM agents WHERE agent_id = ?1")
            .bind(agent_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| sql_error(err, "select agent"))?;
        Ok(found.is_some())
    }

    async fn list_agents(&self, query: &AgentQuery) -> StoreResult<Vec<StoredAgentRegistration>> {
        let mut builder = QueryBuilder::<Sqlite>::new(AGENT_PROJECTION);
        push_agent_filters(&mut builder, query);
        builder.push(" ORDER BY a.agent_id");
        if let Some(limit) = query.limit {
            builder.push(" LIMIT ").push_bind(limit as i64);
        } else {
            builder.push(" LIMIT -1");
        }
        builder.push(" OFFSET ").push_bind(query.offset as i64);

        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|err| sql_error(err, "list agents"))?;
        rows.iter().map(agent_from_row).collect()
    }

    async fn get_agent_install_package(
        &self,
    ) -> StoreResult<Option<StoredAgentInstallPackageAddress>> {
        let row = sqlx::query(
            "SELECT address_id, package_url, package_sha256, updated_by, updated_at \
             FROM agent_install_package WHERE address_id = ?1",
        )
        .bind(DEFAULT_INSTALL_PACKAGE_SETTING_ID)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent install package"))?;
        match row {
            Some(row) => Ok(Some(StoredAgentInstallPackageAddress {
                address_id: column!(row, "address_id"),
                package_url: column!(row, "package_url"),
                package_sha256: column!(row, "package_sha256"),
                updated_by: column!(row, "updated_by"),
                updated_at: column!(row, "updated_at"),
            })),
            None => Ok(None),
        }
    }

    async fn list_agent_install_packages(&self) -> StoreResult<Vec<StoredAgentInstallPackage>> {
        // 按录入时间倒序：最近录入的排前面（管理面列表与「刚录的那个」对齐）。
        let rows = sqlx::query(
            "SELECT package_id, source, package_sha256, version, arch, cached_path, \
             created_by, created_at FROM agent_install_package_history \
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list agent install packages"))?;
        rows.iter().map(agent_install_package_from_row).collect()
    }

    async fn get_agent_install_package_by_id(
        &self,
        package_id: &str,
    ) -> StoreResult<Option<StoredAgentInstallPackage>> {
        let row = sqlx::query(
            "SELECT package_id, source, package_sha256, version, arch, cached_path, \
             created_by, created_at FROM agent_install_package_history WHERE package_id = ?1",
        )
        .bind(package_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent install package by id"))?;
        row.as_ref().map(agent_install_package_from_row).transpose()
    }

    async fn upsert_agent_install_package_by_id(
        &self,
        package: &StoredAgentInstallPackage,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_install_package_history (package_id, source, package_sha256, \
             version, arch, cached_path, created_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT (package_id) DO UPDATE SET source = excluded.source, \
             package_sha256 = excluded.package_sha256, version = excluded.version, \
             arch = excluded.arch, cached_path = excluded.cached_path, \
             created_by = excluded.created_by, created_at = excluded.created_at",
        )
        .bind(&package.package_id)
        .bind(&package.source)
        .bind(&package.package_sha256)
        .bind(&package.version)
        .bind(&package.arch)
        .bind(&package.cached_path)
        .bind(&package.created_by)
        .bind(&package.created_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent install package by id"))?;
        Ok(())
    }

    async fn upsert_agent_install_package(
        &self,
        setting: &StoredAgentInstallPackageAddress,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_install_package (address_id, package_url, package_sha256, \
             updated_by, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (address_id) DO UPDATE SET package_url = excluded.package_url, \
             package_sha256 = excluded.package_sha256, updated_by = excluded.updated_by, \
             updated_at = excluded.updated_at",
        )
        .bind(DEFAULT_INSTALL_PACKAGE_SETTING_ID)
        .bind(&setting.package_url)
        .bind(&setting.package_sha256)
        .bind(&setting.updated_by)
        .bind(&setting.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent install package"))?;
        Ok(())
    }

    async fn get_agent_uplink(&self) -> StoreResult<Option<StoredAgentUplinkAddress>> {
        let row = sqlx::query(
            "SELECT setting_id, host, port, updated_by, updated_at \
             FROM agent_uplink WHERE setting_id = ?1",
        )
        .bind(DEFAULT_AGENT_UPLINK_SETTING_ID)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent uplink"))?;
        match row {
            Some(row) => Ok(Some(StoredAgentUplinkAddress {
                setting_id: column!(row, "setting_id"),
                host: column!(row, "host"),
                port: column!(row, "port"),
                updated_by: column!(row, "updated_by"),
                updated_at: column!(row, "updated_at"),
            })),
            None => Ok(None),
        }
    }

    async fn upsert_agent_uplink(&self, setting: &StoredAgentUplinkAddress) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_uplink (setting_id, host, port, updated_by, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (setting_id) DO UPDATE SET host = excluded.host, \
             port = excluded.port, updated_by = excluded.updated_by, \
             updated_at = excluded.updated_at",
        )
        .bind(DEFAULT_AGENT_UPLINK_SETTING_ID)
        .bind(&setting.host)
        .bind(i64::from(setting.port))
        .bind(&setting.updated_by)
        .bind(&setting.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent uplink"))?;
        Ok(())
    }

    async fn upsert_agent_certificate_status(
        &self,
        status: &StoredAgentCertificateStatus,
    ) -> StoreResult<()> {
        let last_renewal_json = serialize_renewal_report(status.last_renewal.clone())?;
        sqlx::query(
            "INSERT INTO agent_certificate_status (agent_id, not_after, remaining_seconds, state, \
             last_renewal_json, reported_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (agent_id) DO UPDATE SET not_after = excluded.not_after, \
             remaining_seconds = excluded.remaining_seconds, state = excluded.state, \
             last_renewal_json = CASE WHEN excluded.last_renewal_json IS NULL \
             THEN agent_certificate_status.last_renewal_json ELSE excluded.last_renewal_json END, \
             reported_at = excluded.reported_at",
        )
        .bind(&status.agent_id)
        .bind(&status.not_after)
        .bind(status.remaining_seconds)
        .bind(&status.state)
        .bind(&last_renewal_json)
        .bind(&status.reported_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent certificate status"))?;
        Ok(())
    }

    async fn get_agent_certificate_status(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredAgentCertificateStatus>> {
        let row = sqlx::query(
            "SELECT agent_id, not_after, remaining_seconds, state, last_renewal_json, reported_at \
             FROM agent_certificate_status WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "load agent certificate status"))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let last_renewal_json: Option<String> = row
            .try_get("last_renewal_json")
            .map_err(|err| sql_error(err, "last_renewal_json"))?;
        Ok(Some(StoredAgentCertificateStatus {
            agent_id: row
                .try_get("agent_id")
                .map_err(|err| sql_error(err, "agent_id"))?,
            not_after: row
                .try_get("not_after")
                .map_err(|err| sql_error(err, "not_after"))?,
            remaining_seconds: row
                .try_get("remaining_seconds")
                .map_err(|err| sql_error(err, "remaining_seconds"))?,
            state: row
                .try_get("state")
                .map_err(|err| sql_error(err, "state"))?,
            last_renewal: deserialize_renewal_report(last_renewal_json),
            reported_at: row
                .try_get("reported_at")
                .map_err(|err| sql_error(err, "reported_at"))?,
        }))
    }

    async fn revoke_agent(&self, entry: &StoredAgentRevocation) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_certificate_denylist (entry_id, agent_id, reason_code, denied_by, \
             denied_at, retain_until) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (agent_id) DO UPDATE SET reason_code = excluded.reason_code, \
             denied_by = excluded.denied_by, denied_at = excluded.denied_at, \
             retain_until = excluded.retain_until",
        )
        .bind(&entry.entry_id)
        .bind(&entry.agent_id)
        .bind(&entry.reason_code)
        .bind(&entry.denied_by)
        .bind(&entry.denied_at)
        .bind(&entry.retain_until)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "revoke agent"))?;
        Ok(())
    }

    async fn lift_agent_revocation(&self, agent_id: &str) -> StoreResult<bool> {
        let result = sqlx::query("DELETE FROM agent_certificate_denylist WHERE agent_id = ?1")
            .bind(agent_id)
            .execute(&self.pool)
            .await
            .map_err(|err| sql_error(err, "lift agent revocation"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn is_agent_revoked(&self, agent_id: &str) -> StoreResult<bool> {
        let retain_until: Option<String> = sqlx::query_scalar(
            "SELECT retain_until FROM agent_certificate_denylist WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "check agent revocation"))?;
        let Some(retain_until) = retain_until else {
            return Ok(false);
        };
        Ok(revocation_is_live(&retain_until, Utc::now()))
    }

    async fn list_agent_revocations(&self) -> StoreResult<Vec<StoredAgentRevocation>> {
        let rows = sqlx::query(
            "SELECT entry_id, agent_id, reason_code, denied_by, denied_at, retain_until \
             FROM agent_certificate_denylist",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list agent revocations"))?;
        let now = Utc::now();
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            let retain_until: String = column!(row, "retain_until");
            if !revocation_is_live(&retain_until, now) {
                continue;
            }
            entries.push(StoredAgentRevocation {
                entry_id: column!(row, "entry_id"),
                agent_id: column!(row, "agent_id"),
                reason_code: column!(row, "reason_code"),
                denied_by: column!(row, "denied_by"),
                denied_at: column!(row, "denied_at"),
                retain_until,
            });
        }
        // 新的在前：页面默认看到最近吊销的。
        entries.sort_by(|a, b| b.denied_at.cmp(&a.denied_at));
        Ok(entries)
    }

    async fn purge_expired_agent_revocations(&self) -> StoreResult<u64> {
        let rows = sqlx::query("SELECT agent_id, retain_until FROM agent_certificate_denylist")
            .fetch_all(&self.pool)
            .await
            .map_err(|err| sql_error(err, "scan agent revocations"))?;
        let now = Utc::now();
        let mut removed = 0u64;
        for row in &rows {
            let retain_until: String = column!(row, "retain_until");
            // 只清**可解析且已过水位**的；坏行留给人处理（见 `revocation_is_live`）。
            if let Some(until) = parse_rfc3339(&retain_until)
                && until <= now
            {
                let agent_id: String = column!(row, "agent_id");
                // 条件删除（CAS）：只删快照里那条水位已过的记录。若扫描与删除之间管理面把同一
                // agent 重新吊销（upsert 刷了新水位），这里的 `retain_until` 就对不上 → 不删，
                // 避免把一条**仍在生效**的吊销静默丢掉。
                let result = sqlx::query(
                    "DELETE FROM agent_certificate_denylist WHERE agent_id = ?1 AND retain_until = ?2",
                )
                .bind(&agent_id)
                .bind(&retain_until)
                .execute(&self.pool)
                .await
                .map_err(|err| sql_error(err, "purge agent revocation"))?;
                removed += result.rows_affected();
            }
        }
        Ok(removed)
    }

    async fn get_agent_advertise_url(&self) -> StoreResult<Option<StoredAgentAdvertiseUrl>> {
        let row = sqlx::query(
            "SELECT setting_id, url, updated_by, updated_at \
             FROM agent_advertise_url WHERE setting_id = ?1",
        )
        .bind(DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent advertise url"))?;
        match row {
            Some(row) => Ok(Some(StoredAgentAdvertiseUrl {
                setting_id: column!(row, "setting_id"),
                url: column!(row, "url"),
                updated_by: column!(row, "updated_by"),
                updated_at: column!(row, "updated_at"),
            })),
            None => Ok(None),
        }
    }

    async fn upsert_agent_advertise_url(
        &self,
        setting: &StoredAgentAdvertiseUrl,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_advertise_url (setting_id, url, updated_by, updated_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (setting_id) DO UPDATE SET url = excluded.url, \
             updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        )
        .bind(DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID)
        .bind(&setting.url)
        .bind(&setting.updated_by)
        .bind(&setting.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent advertise url"))?;
        Ok(())
    }

    async fn count_agents(&self, query: &AgentQuery) -> StoreResult<u64> {
        let mut builder = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM agents a");
        push_agent_filters(&mut builder, query);
        let total: i64 = builder
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(|err| sql_error(err, "count agents"))?;
        Ok(u64::try_from(total).unwrap_or(0))
    }

    async fn list_agent_ids(&self) -> StoreResult<Vec<String>> {
        let rows = sqlx::query("SELECT agent_id FROM agents ORDER BY agent_id")
            .fetch_all(&self.pool)
            .await
            .map_err(|err| sql_error(err, "list agent ids"))?;
        let mut ids = Vec::with_capacity(rows.len());
        for row in &rows {
            ids.push(column!(row, "agent_id"));
        }
        Ok(ids)
    }

    async fn list_agent_instances(&self, agent_id: &str) -> StoreResult<Vec<StoredAgentInstance>> {
        let rows = sqlx::query(
            "SELECT instance_id, agent_id, boot_id, version, started_at, last_seen_at, \
             memory_bytes, cpu_percent, admin_latency_ms FROM agent_instances \
             WHERE agent_id = ?1 ORDER BY last_seen_at DESC, instance_id",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list agent instances"))?;
        let mut instances = Vec::with_capacity(rows.len());
        for row in &rows {
            instances.push(StoredAgentInstance {
                instance_id: column!(row, "instance_id"),
                agent_id: column!(row, "agent_id"),
                boot_id: column!(row, "boot_id"),
                version: column!(row, "version"),
                started_at: column!(row, "started_at"),
                last_seen_at: column!(row, "last_seen_at"),
                memory_bytes: column!(row, "memory_bytes"),
                cpu_percent: column!(row, "cpu_percent"),
                admin_latency_ms: column!(row, "admin_latency_ms"),
            });
        }
        Ok(instances)
    }

    async fn record_agent_status(&self, update: &AgentStatusUpdate<'_>) -> StoreResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin record agent status"))?;
        if !agent_exists_tx(&mut tx, update.agent_id).await? {
            // 不再静默丢弃：调用方据此返回 404/409。
            return Ok(false);
        }

        let current_instance: Option<String> =
            sqlx::query_scalar("SELECT current_instance_id FROM agents WHERE agent_id = ?1")
                .bind(update.agent_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| sql_error(err, "select current instance"))?;
        let instance_id = if update.instance_id.is_empty() {
            current_instance.clone().unwrap_or_default()
        } else {
            update.instance_id.to_string()
        };

        if !instance_id.is_empty() {
            let work_state_changes =
                serialize_work_state_changes(update.work_state_changes.clone())?;
            let local_work = serialize_local_work(update.local_work.clone())?;
            let uplink_state = serialize_uplink_state(update.uplink_state.clone())?;
            // 实例行不存在则新建（Agentd 重启换 boot_id / instance_id 时保留历史）。
            sqlx::query(
                "INSERT INTO agent_instances (instance_id, agent_id, boot_id, version, \
                 started_at, last_seen_at, memory_bytes, cpu_percent, cpu_cores, admin_latency_ms, \
                 work_state_changes, discovery_policy_version, local_work, uplink_state) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
                 ON CONFLICT (instance_id) DO UPDATE SET version = excluded.version, \
                 boot_id = CASE WHEN excluded.boot_id = '' THEN agent_instances.boot_id \
                 ELSE excluded.boot_id END, \
                 last_seen_at = excluded.last_seen_at, \
                 memory_bytes = excluded.memory_bytes, cpu_percent = excluded.cpu_percent, \
                 cpu_cores = excluded.cpu_cores, \
                 admin_latency_ms = excluded.admin_latency_ms, \
                 work_state_changes = excluded.work_state_changes, \
                 discovery_policy_version = excluded.discovery_policy_version, \
                 local_work = CASE WHEN excluded.local_work IS NULL \
                 THEN agent_instances.local_work ELSE excluded.local_work END, \
                 uplink_state = CASE WHEN excluded.uplink_state IS NULL \
                 THEN agent_instances.uplink_state ELSE excluded.uplink_state END",
            )
            .bind(&instance_id)
            .bind(update.agent_id)
            .bind(update.boot_id)
            .bind(update.version)
            .bind(update.last_seen_at)
            .bind(to_sql_int(update.memory_bytes))
            .bind(update.cpu_percent)
            .bind(update.cpu_cores)
            .bind(to_sql_int(update.admin_latency_ms))
            .bind(work_state_changes)
            .bind(update.discovery_policy_version)
            .bind(local_work)
            .bind(uplink_state)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, "upsert agent instance"))?;
        }

        sqlx::query(
            "UPDATE agents SET current_instance_id = ?1, updated_at = ?2 WHERE agent_id = ?3",
        )
        .bind(if instance_id.is_empty() {
            None
        } else {
            Some(instance_id.as_str())
        })
        .bind(update.last_seen_at)
        .bind(update.agent_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "update agent status"))?;

        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit record agent status"))?;
        Ok(true)
    }

    async fn renew_agent_credential(&self, request: &RenewCredential<'_>) -> StoreResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin renew credential"))?;

        let row = sqlx::query(
            "SELECT a.current_instance_id, c.credential_id, c.token_hash, c.status, \
             c.expires_at FROM agents a \
             LEFT JOIN agent_credentials c ON c.credential_id = a.current_credential_id \
             WHERE a.agent_id = ?1",
        )
        .bind(request.agent_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "select agent credential"))?;
        let Some(row) = row else {
            return Ok(false);
        };
        let current_instance: Option<String> = column!(row, "current_instance_id");
        let credential_id: Option<String> = column!(row, "credential_id");
        let token_hash: Option<String> = column!(row, "token_hash");
        let status: Option<String> = column!(row, "status");

        let matches = current_instance.as_deref() == Some(request.instance_id)
            && token_hash.as_deref() == Some(request.current_token_hash)
            && credential_id.is_some()
            && status.as_deref().map(StoredCredentialStatus::parse)
                == Some(StoredCredentialStatus::Active);
        if !matches {
            return Ok(false);
        }

        let now = now_rfc3339();
        // 旧凭据立即失效（轮换语义），保留行以便审计。
        sqlx::query(
            "UPDATE agent_credentials SET status = 'revoked', revoked_at = ?1 \
             WHERE credential_id = ?2",
        )
        .bind(&now)
        .bind(credential_id.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "revoke previous credential"))?;

        sqlx::query(
            "INSERT INTO agent_credentials (credential_id, agent_id, instance_id, auth_scheme, \
             token_hash, status, issued_at, expires_at, revoked_at) \
             VALUES (?1, ?2, ?3, 'bearer', ?4, 'active', ?5, ?6, NULL)",
        )
        .bind(request.new_credential_id)
        .bind(request.agent_id)
        .bind(request.instance_id)
        .bind(request.new_token_hash)
        .bind(request.issued_at)
        .bind(request.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "insert renewed credential"))?;

        sqlx::query(
            "UPDATE agents SET current_credential_id = ?1, updated_at = ?2 WHERE agent_id = ?3",
        )
        .bind(request.new_credential_id)
        .bind(&now)
        .bind(request.agent_id)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "update agent credential pointer"))?;

        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit renew credential"))?;
        Ok(true)
    }

    async fn revoke_agent_credential(
        &self,
        agent_id: &str,
        credential_id: &str,
    ) -> StoreResult<bool> {
        let result = sqlx::query(
            "UPDATE agent_credentials SET status = 'revoked', revoked_at = ?1 \
             WHERE agent_id = ?2 AND credential_id = ?3 AND status != 'revoked'",
        )
        .bind(now_rfc3339())
        .bind(agent_id)
        .bind(credential_id)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "revoke agent credential"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_agent(&self, agent_id: &str) -> StoreResult<bool> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin delete agent"))?;
        // 先删派生行、最后删 `agents`。`agent_purpose_suggestion` 挂在 `agent_fact_summary`
        // 上（级联），所以它排在 fact_summary 之前；其余各表互不相干。
        // 顺序写成「子 → 父」，即便哪天关了外键级联也照样干净。
        // 表名是编译期常量，`format!` 只拼表名本身（无参数注入面）。
        for (table, detail) in DELETE_AGENT_TABLES {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DELETE FROM {table} WHERE agent_id = ?1"
            )))
            .bind(agent_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, detail))?;
        }
        let deleted = sqlx::query("DELETE FROM agents WHERE agent_id = ?1")
            .bind(agent_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, "delete agent"))?;
        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit delete agent"))?;
        Ok(deleted.rows_affected() > 0)
    }

    // ── Agent 事实摘要与用途推断 ──

    async fn get_agent_fact_summary(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredAgentFactSummary>> {
        let row = sqlx::query(
            "SELECT agent_id, content_digest, revision, observed_at, os, arch, process_count, \
             process_executables, packages, listen_ports, host_id, host_name, network_addresses, \
             received_at \
             FROM agent_fact_summary WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent fact summary"))?;
        row.as_ref().map(fact_summary_from_row).transpose()
    }

    async fn get_agent_fact_summary_digest(&self, agent_id: &str) -> StoreResult<Option<String>> {
        let row = sqlx::query("SELECT content_digest FROM agent_fact_summary WHERE agent_id = ?1")
            .bind(agent_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| sql_error(err, "select agent fact summary digest"))?;
        match row {
            Some(row) => Ok(Some(column!(row, "content_digest"))),
            None => Ok(None),
        }
    }

    async fn upsert_agent_fact_summary(&self, summary: &StoredAgentFactSummary) -> StoreResult<()> {
        let process_executables = serialize_json_array(
            &summary.process_executables,
            "serialize process executables",
        )?;
        let packages = serialize_json_array(&summary.packages, "serialize packages")?;
        let listen_ports = serialize_json_array(&summary.listen_ports, "serialize listen ports")?;
        let network_addresses =
            serialize_json_array(&summary.network_addresses, "serialize network addresses")?;
        sqlx::query(
            "INSERT INTO agent_fact_summary (agent_id, content_digest, revision, observed_at, os, \
             arch, process_count, process_executables, packages, listen_ports, host_id, host_name, \
             network_addresses, received_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
             ON CONFLICT (agent_id) DO UPDATE SET content_digest = excluded.content_digest, \
             revision = excluded.revision, observed_at = excluded.observed_at, os = excluded.os, \
             arch = excluded.arch, process_count = excluded.process_count, \
             process_executables = excluded.process_executables, packages = excluded.packages, \
             listen_ports = excluded.listen_ports, host_id = excluded.host_id, \
             host_name = excluded.host_name, network_addresses = excluded.network_addresses, \
             received_at = excluded.received_at",
        )
        .bind(&summary.agent_id)
        .bind(&summary.content_digest)
        .bind(summary.revision)
        .bind(&summary.observed_at)
        .bind(&summary.os)
        .bind(&summary.arch)
        .bind(summary.process_count)
        .bind(process_executables)
        .bind(packages)
        .bind(listen_ports)
        .bind(&summary.host_id)
        .bind(&summary.host_name)
        .bind(network_addresses)
        .bind(&summary.received_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent fact summary"))?;
        Ok(())
    }

    async fn touch_agent_fact_summary_marks(
        &self,
        agent_id: &str,
        marks: &AgentFactSummaryMarks,
    ) -> StoreResult<bool> {
        let network_addresses =
            serialize_json_array(&marks.network_addresses, "serialize network addresses")?;
        let result = sqlx::query(
            "UPDATE agent_fact_summary SET revision = ?2, observed_at = ?3, \
             process_count = ?4, host_id = ?5, host_name = ?6, network_addresses = ?7, \
             received_at = ?8 WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .bind(marks.revision)
        .bind(&marks.observed_at)
        .bind(marks.process_count)
        .bind(&marks.host_id)
        .bind(&marks.host_name)
        .bind(network_addresses)
        .bind(&marks.received_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "touch agent fact summary marks"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn replace_agent_software_inventory(
        &self,
        agent_id: &str,
        entries: &[StoredSoftwareEntry],
    ) -> StoreResult<usize> {
        // 一个事务里「先删后插」：中间态不能让读者看见（管理面可能正好在这时查）。
        // 也正因为在一个事务里，插到一半撞主键会整体回滚 —— 宁可这台机器的清单保持旧值，
        // 也不要留下一半新一半旧的半成品。
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin software inventory replace"))?;
        sqlx::query("DELETE FROM agent_software_inventory WHERE agent_id = ?1")
            .bind(agent_id)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, "clear software inventory"))?;
        for entry in entries {
            sqlx::query(
                "INSERT INTO agent_software_inventory (agent_id, software_key, name, kind, \
                 matched_rule, path, received_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&entry.agent_id)
            .bind(&entry.software_key)
            .bind(&entry.name)
            .bind(&entry.kind)
            .bind(&entry.matched_rule)
            .bind(&entry.path)
            .bind(&entry.received_at)
            .execute(&mut *tx)
            .await
            .map_err(|err| sql_error(err, "insert software inventory entry"))?;
        }
        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit software inventory replace"))?;
        Ok(entries.len())
    }

    async fn agent_has_software_inventory(&self, agent_id: &str) -> StoreResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_software_inventory WHERE agent_id = ?1 LIMIT 1",
        )
        .bind(agent_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| sql_error(err, "count software inventory"))?;
        Ok(count > 0)
    }

    async fn list_agent_software(&self, agent_id: &str) -> StoreResult<Vec<StoredSoftwareEntry>> {
        let rows = sqlx::query(
            "SELECT agent_id, software_key, name, kind, matched_rule, path, received_at \
             FROM agent_software_inventory WHERE agent_id = ?1 \
             ORDER BY kind, software_key, path",
        )
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list agent software inventory"))?;
        rows.iter().map(software_entry_from_row).collect()
    }

    async fn summarize_agent_software(
        &self,
        agent_id: &str,
    ) -> StoreResult<SoftwareInventorySummary> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS paths, \
             COALESCE(SUM(CASE WHEN kind = 'app' THEN 1 ELSE 0 END), 0) AS apps \
             FROM agent_software_inventory WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| sql_error(err, "summarize software inventory"))?;
        Ok(SoftwareInventorySummary {
            paths: column!(row, "paths"),
            apps: column!(row, "apps"),
        })
    }

    async fn list_software_holdings(
        &self,
        limit: usize,
    ) -> StoreResult<Vec<StoredSoftwareHolding>> {
        // 一条查询拿完：子查询先定「持有机器数最多的前 limit 个键」，外层再把它们的行取回。
        // 这样不必在 Rust 里拼 IN (?, ?, ...)，也不必让调用方逐个键回库（N+1）。
        // 返回行数上界是 `limit × 机器数`，由调用方把 limit 控在合理范围。
        let rows = sqlx::query(
            "SELECT software_key, name, kind, agent_id, path FROM agent_software_inventory \
             WHERE software_key IN (\
               SELECT software_key FROM agent_software_inventory \
               GROUP BY software_key \
               ORDER BY COUNT(DISTINCT agent_id) DESC, software_key \
               LIMIT ?1\
             ) \
             ORDER BY software_key, agent_id, path",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list software holdings"))?;
        // 行已按 software_key 排序，所以同键的行必然相邻 —— 一次顺序折叠即可分组，
        // 不必用 HashMap 再排一遍（排序键还得跟 SQL 保持一致，那是两处真相）。
        let mut holdings: Vec<StoredSoftwareHolding> = Vec::new();
        for row in rows.iter() {
            let key: String = column!(row, "software_key");
            let holder = SoftwareHolder {
                agent_id: column!(row, "agent_id"),
                path: column!(row, "path"),
            };
            match holdings.last_mut() {
                Some(current) if current.software_key == key => current.holders.push(holder),
                _ => holdings.push(StoredSoftwareHolding {
                    software_key: key,
                    name: column!(row, "name"),
                    kind: column!(row, "kind"),
                    holders: vec![holder],
                }),
            }
        }
        Ok(holdings)
    }

    async fn count_software_keys(&self) -> StoreResult<i64> {
        sqlx::query_scalar("SELECT COUNT(DISTINCT software_key) FROM agent_software_inventory")
            .fetch_one(&self.pool)
            .await
            .map_err(|err| sql_error(err, "count software keys"))
    }

    async fn get_purpose_suggestion(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredPurposeSuggestion>> {
        let row = sqlx::query(
            "SELECT agent_id, suggestion_id, suggested_class, confidence, method, rule_set_id, \
             purpose_version, signals, observed_at, computed_at \
             FROM agent_purpose_suggestion WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent purpose suggestion"))?;
        row.as_ref().map(purpose_suggestion_from_row).transpose()
    }

    async fn upsert_purpose_suggestion(
        &self,
        suggestion: &StoredPurposeSuggestion,
    ) -> StoreResult<()> {
        let signals = serialize_json_array(&suggestion.signals, "serialize purpose signals")?;
        sqlx::query(
            "INSERT INTO agent_purpose_suggestion (agent_id, suggestion_id, suggested_class, \
             confidence, method, rule_set_id, purpose_version, signals, observed_at, computed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT (agent_id) DO UPDATE SET suggestion_id = excluded.suggestion_id, \
             suggested_class = excluded.suggested_class, confidence = excluded.confidence, \
             method = excluded.method, rule_set_id = excluded.rule_set_id, \
             purpose_version = excluded.purpose_version, \
             signals = excluded.signals, observed_at = excluded.observed_at, \
             computed_at = excluded.computed_at",
        )
        .bind(&suggestion.agent_id)
        .bind(&suggestion.suggestion_id)
        .bind(&suggestion.suggested_class)
        .bind(suggestion.confidence)
        .bind(&suggestion.method)
        .bind(&suggestion.rule_set_id)
        .bind(suggestion.purpose_version)
        .bind(signals)
        .bind(&suggestion.observed_at)
        .bind(&suggestion.computed_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent purpose suggestion"))?;
        Ok(())
    }

    async fn clear_purpose_suggestion(&self, agent_id: &str) -> StoreResult<bool> {
        let result = sqlx::query("DELETE FROM agent_purpose_suggestion WHERE agent_id = ?1")
            .bind(agent_id)
            .execute(&self.pool)
            .await
            .map_err(|err| sql_error(err, "clear agent purpose suggestion"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_agent_classification(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredAgentClassification>> {
        let row = sqlx::query(
            "SELECT agent_id, machine_class, suggestion_id, note, decided_by, decided_at \
             FROM agent_classification WHERE agent_id = ?1",
        )
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select agent classification"))?;
        row.as_ref().map(classification_from_row).transpose()
    }

    async fn upsert_agent_classification(
        &self,
        classification: &StoredAgentClassification,
    ) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_classification (agent_id, machine_class, suggestion_id, note, \
             decided_by, decided_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (agent_id) DO UPDATE SET machine_class = excluded.machine_class, \
             suggestion_id = excluded.suggestion_id, note = excluded.note, \
             decided_by = excluded.decided_by, decided_at = excluded.decided_at",
        )
        .bind(&classification.agent_id)
        .bind(&classification.machine_class)
        .bind(&classification.suggestion_id)
        .bind(&classification.note)
        .bind(&classification.decided_by)
        .bind(&classification.decided_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert agent classification"))?;
        Ok(())
    }

    async fn purpose_coverage(&self) -> StoreResult<PurposeCoverageCounts> {
        let total_agents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agents")
            .fetch_one(&self.pool)
            .await
            .map_err(|err| sql_error(err, "count agents"))?;
        let classified_agents: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_classification")
                .fetch_one(&self.pool)
                .await
                .map_err(|err| sql_error(err, "count agent classifications"))?;
        let rows = sqlx::query(
            "SELECT machine_class, COUNT(*) AS agent_count FROM agent_classification \
             GROUP BY machine_class ORDER BY machine_class",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "group agent classifications"))?;
        let mut by_class = Vec::with_capacity(rows.len());
        for row in &rows {
            by_class.push((column!(row, "machine_class"), column!(row, "agent_count")));
        }
        Ok(PurposeCoverageCounts {
            total_agents,
            classified_agents,
            by_class,
        })
    }

    async fn save_standing_work(&self, work: &StandingWork) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO standing_work (work_id, agent_id, family, spec, catalog_version, \
             proposal_id, plan_version, effective_from, status, updated_by, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT (work_id) DO UPDATE SET agent_id = excluded.agent_id, \
             family = excluded.family, spec = excluded.spec, \
             catalog_version = excluded.catalog_version, proposal_id = excluded.proposal_id, \
             plan_version = excluded.plan_version, effective_from = excluded.effective_from, \
             status = excluded.status, updated_by = excluded.updated_by, \
             updated_at = excluded.updated_at",
        )
        .bind(&work.work_id)
        .bind(&work.agent_id)
        .bind(&work.family)
        .bind(&work.spec)
        .bind(work.catalog_version)
        .bind(&work.proposal_id)
        .bind(work.plan_version)
        .bind(&work.effective_from)
        .bind(&work.status)
        .bind(&work.updated_by)
        .bind(&work.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert standing work"))?;
        Ok(())
    }

    async fn get_standing_work(&self, work_id: &str) -> StoreResult<Option<StandingWork>> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {STANDING_WORK_COLUMNS} FROM standing_work WHERE work_id = ?1"
        )))
        .bind(work_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select standing work"))?;
        row.as_ref().map(standing_work_from_row).transpose()
    }

    async fn list_standing_work(&self, agent_id: &str) -> StoreResult<Vec<StandingWork>> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {STANDING_WORK_COLUMNS} FROM standing_work WHERE agent_id = ?1 \
             ORDER BY family"
        )))
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list standing work"))?;
        rows.iter().map(standing_work_from_row).collect()
    }

    async fn save_one_shot_work(&self, work: &StoredOneShotWork) -> StoreResult<()> {
        let item = &work.work;
        let completed_steps =
            serialize_json_array(&item.completed_steps, "encode one-shot completed steps")?;
        sqlx::query(
            "INSERT INTO one_shot_work (work_id, agent_id, action, spec, scheduled_at, \
             deadline_at, timeout_seconds, interruptible, status, paused_at, pre_pause_status, \
             paused_total_seconds, current_step, completed_steps, attempt, issued_by, issued_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17) \
             ON CONFLICT (work_id) DO UPDATE SET agent_id = excluded.agent_id, \
             action = excluded.action, spec = excluded.spec, \
             scheduled_at = excluded.scheduled_at, deadline_at = excluded.deadline_at, \
             timeout_seconds = excluded.timeout_seconds, \
             interruptible = excluded.interruptible, status = excluded.status, \
             paused_at = excluded.paused_at, \
             pre_pause_status = excluded.pre_pause_status, \
             paused_total_seconds = excluded.paused_total_seconds, \
             current_step = excluded.current_step, \
             completed_steps = excluded.completed_steps, attempt = excluded.attempt, \
             issued_by = excluded.issued_by, issued_at = excluded.issued_at",
        )
        .bind(&item.work_id)
        .bind(&item.agent_id)
        .bind(&item.action)
        .bind(&item.spec)
        .bind(&item.scheduled_at)
        .bind(&item.deadline_at)
        .bind(item.timeout_seconds)
        .bind(item.interruptible)
        .bind(&item.status)
        .bind(&item.paused_at)
        .bind(&work.pre_pause_status)
        .bind(item.paused_total_seconds)
        .bind(&item.current_step)
        .bind(&completed_steps)
        .bind(item.attempt)
        .bind(&item.issued_by)
        .bind(&item.issued_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert one-shot work"))?;
        Ok(())
    }

    async fn get_one_shot_work(&self, work_id: &str) -> StoreResult<Option<StoredOneShotWork>> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ONE_SHOT_WORK_COLUMNS} FROM one_shot_work WHERE work_id = ?1"
        )))
        .bind(work_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select one-shot work"))?;
        row.as_ref().map(one_shot_work_from_row).transpose()
    }

    async fn list_one_shot_work(&self, agent_id: &str) -> StoreResult<Vec<StoredOneShotWork>> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ONE_SHOT_WORK_COLUMNS} FROM one_shot_work WHERE agent_id = ?1 \
             ORDER BY issued_at"
        )))
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list one-shot work"))?;
        rows.iter().map(one_shot_work_from_row).collect()
    }

    async fn list_outstanding_one_shot_work(&self) -> StoreResult<Vec<StoredOneShotWork>> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ONE_SHOT_WORK_COLUMNS} FROM one_shot_work \
             WHERE status NOT IN ({}) ORDER BY issued_at",
            one_shot_terminal_status_sql()
        )))
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list outstanding one-shot work"))?;
        rows.iter().map(one_shot_work_from_row).collect()
    }

    async fn terminate_outstanding_one_shot_work(
        &self,
        work_id: &str,
        status: &str,
    ) -> StoreResult<bool> {
        let result = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE one_shot_work SET status = ?2 WHERE work_id = ?1 \
             AND status NOT IN ({})",
            one_shot_terminal_status_sql()
        )))
        .bind(work_id)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "terminate one-shot work"))?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_work_ack(&self, ack: &StoredWorkAck) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO work_ack (work_id, agent_id, work_kind, plan_version, acknowledged_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (work_id) DO UPDATE SET agent_id = excluded.agent_id, \
             work_kind = excluded.work_kind, plan_version = excluded.plan_version, \
             acknowledged_at = excluded.acknowledged_at",
        )
        .bind(&ack.work_id)
        .bind(&ack.agent_id)
        .bind(&ack.work_kind)
        .bind(ack.plan_version)
        .bind(&ack.acknowledged_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert work ack"))?;
        Ok(())
    }

    async fn get_work_ack(&self, work_id: &str) -> StoreResult<Option<StoredWorkAck>> {
        let row = sqlx::query(
            "SELECT work_id, agent_id, work_kind, plan_version, acknowledged_at \
             FROM work_ack WHERE work_id = ?1",
        )
        .bind(work_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select work ack"))?;
        row.as_ref()
            .map(|row| {
                Ok(StoredWorkAck {
                    work_id: column!(row, "work_id"),
                    agent_id: column!(row, "agent_id"),
                    work_kind: column!(row, "work_kind"),
                    plan_version: column!(row, "plan_version"),
                    acknowledged_at: column!(row, "acknowledged_at"),
                })
            })
            .transpose()
    }

    async fn upsert_work_result(&self, result: &StoredWorkResult) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO agent_work_result (work_id, agent_id, status, detail, reported_at) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (work_id) DO UPDATE SET agent_id = excluded.agent_id, \
             status = excluded.status, detail = excluded.detail, \
             reported_at = excluded.reported_at",
        )
        .bind(&result.work_id)
        .bind(&result.agent_id)
        .bind(&result.status)
        .bind(&result.detail)
        .bind(&result.reported_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert work result"))?;
        Ok(())
    }

    async fn get_work_result(&self, work_id: &str) -> StoreResult<Option<StoredWorkResult>> {
        let row = sqlx::query(
            "SELECT work_id, agent_id, status, detail, reported_at \
             FROM agent_work_result WHERE work_id = ?1",
        )
        .bind(work_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select work result"))?;
        row.as_ref()
            .map(|row| {
                Ok(StoredWorkResult {
                    work_id: column!(row, "work_id"),
                    agent_id: column!(row, "agent_id"),
                    status: column!(row, "status"),
                    detail: column!(row, "detail"),
                    reported_at: column!(row, "reported_at"),
                })
            })
            .transpose()
    }

    async fn next_work_sequence(&self, agent_id: &str, updated_at: &str) -> StoreResult<i64> {
        // 用 RETURNING 一次完成「读-改-写」：序号是漂移判定的依据，
        // 分两次查会在两次查询之间给并发留出「两方拿到同一个号」的缝。
        let sequence: i64 = sqlx::query_scalar(
            "INSERT INTO agent_work_sequence (agent_id, sequence, updated_at) \
             VALUES (?1, 1, ?2) \
             ON CONFLICT (agent_id) DO UPDATE SET sequence = sequence + 1, \
             updated_at = excluded.updated_at \
             RETURNING sequence",
        )
        .bind(agent_id)
        .bind(updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| sql_error(err, "bump work sequence"))?;
        Ok(sequence)
    }

    async fn work_sequence(&self, agent_id: &str) -> StoreResult<i64> {
        let sequence: Option<i64> =
            sqlx::query_scalar("SELECT sequence FROM agent_work_sequence WHERE agent_id = ?1")
                .bind(agent_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|err| sql_error(err, "select work sequence"))?;
        Ok(sequence.unwrap_or(0))
    }

    async fn save_rollout_plan(&self, plan: &StoredRolloutPlan) -> StoreResult<()> {
        let phases_json = serialize_json_array(&plan.phases, "encode rollout plan phases")?;
        sqlx::query(
            "INSERT INTO rollout_plan (plan_id, action, spec, deadline_at, timeout_seconds, \
             phases_json, batch_size, current_phase, status, created_by, created_at, \
             approved_by, approved_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT (plan_id) DO UPDATE SET action = excluded.action, \
             spec = excluded.spec, deadline_at = excluded.deadline_at, \
             timeout_seconds = excluded.timeout_seconds, phases_json = excluded.phases_json, \
             batch_size = excluded.batch_size, current_phase = excluded.current_phase, \
             status = excluded.status, approved_by = excluded.approved_by, \
             approved_at = excluded.approved_at",
        )
        .bind(&plan.plan_id)
        .bind(&plan.action)
        .bind(&plan.spec)
        .bind(&plan.deadline_at)
        .bind(plan.timeout_seconds)
        .bind(&phases_json)
        .bind(plan.batch_size)
        .bind(plan.current_phase)
        .bind(&plan.status)
        .bind(&plan.created_by)
        .bind(&plan.created_at)
        .bind(&plan.approved_by)
        .bind(&plan.approved_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert rollout plan"))?;
        Ok(())
    }

    async fn get_rollout_plan(&self, plan_id: &str) -> StoreResult<Option<StoredRolloutPlan>> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ROLLOUT_PLAN_COLUMNS} FROM rollout_plan WHERE plan_id = ?1"
        )))
        .bind(plan_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select rollout plan"))?;
        row.as_ref().map(rollout_plan_from_row).transpose()
    }

    async fn list_rollout_plans(&self) -> StoreResult<Vec<StoredRolloutPlan>> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ROLLOUT_PLAN_COLUMNS} FROM rollout_plan ORDER BY created_at DESC"
        )))
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list rollout plans"))?;
        rows.iter().map(rollout_plan_from_row).collect()
    }

    async fn upsert_rollout_plan_entry(&self, entry: &StoredRolloutPlanEntry) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO rollout_plan_entry (plan_id, target_id, work_id, status, detail, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (plan_id, target_id) DO UPDATE SET work_id = excluded.work_id, \
             status = excluded.status, detail = excluded.detail, updated_at = excluded.updated_at",
        )
        .bind(&entry.plan_id)
        .bind(&entry.target_id)
        .bind(&entry.work_id)
        .bind(&entry.status)
        .bind(&entry.detail)
        .bind(&entry.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert rollout plan entry"))?;
        Ok(())
    }

    async fn list_rollout_plan_entries(
        &self,
        plan_id: &str,
    ) -> StoreResult<Vec<StoredRolloutPlanEntry>> {
        let rows = sqlx::query(
            "SELECT plan_id, target_id, work_id, status, detail, updated_at \
             FROM rollout_plan_entry WHERE plan_id = ?1 ORDER BY target_id",
        )
        .bind(plan_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| sql_error(err, "list rollout plan entries"))?;
        rows.iter().map(rollout_plan_entry_from_row).collect()
    }

    async fn find_rollout_plan_entry_by_work(
        &self,
        work_id: &str,
    ) -> StoreResult<Option<StoredRolloutPlanEntry>> {
        let row = sqlx::query(
            "SELECT plan_id, target_id, work_id, status, detail, updated_at \
             FROM rollout_plan_entry WHERE work_id = ?1",
        )
        .bind(work_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "find rollout plan entry by work"))?;
        row.as_ref().map(rollout_plan_entry_from_row).transpose()
    }

    // ── 知识库内容包（设计 §6.1）──

    async fn upsert_knowledge_package(&self, package: &StoredKnowledgePackage) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO knowledge_package (package_id, source, package_sha256, version, \
             catalog_version, template_version, policy_version, purpose_version, parser_abi, \
             signed_by, cached_path, created_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT (package_id) DO UPDATE SET source = excluded.source, \
             package_sha256 = excluded.package_sha256, version = excluded.version, \
             catalog_version = excluded.catalog_version, \
             template_version = excluded.template_version, \
             policy_version = excluded.policy_version, \
             purpose_version = excluded.purpose_version, parser_abi = excluded.parser_abi, \
             signed_by = excluded.signed_by, cached_path = excluded.cached_path, \
             created_by = excluded.created_by, created_at = excluded.created_at",
        )
        .bind(&package.package_id)
        .bind(&package.source)
        .bind(&package.package_sha256)
        .bind(&package.version)
        .bind(package.catalog_version)
        .bind(package.template_version)
        .bind(package.policy_version)
        .bind(package.purpose_version)
        .bind(package.parser_abi)
        .bind(&package.signed_by)
        .bind(&package.cached_path)
        .bind(&package.created_by)
        .bind(&package.created_at)
        .execute(&self.pool)
        .await
        .map_err(|err| sql_error(err, "upsert knowledge package"))?;
        Ok(())
    }

    async fn knowledge_package(
        &self,
        package_id: &str,
    ) -> StoreResult<Option<StoredKnowledgePackage>> {
        let row = sqlx::query(
            "SELECT package_id, source, package_sha256, version, catalog_version, \
             template_version, policy_version, purpose_version, parser_abi, signed_by, \
             cached_path, created_by, created_at \
             FROM knowledge_package WHERE package_id = ?1",
        )
        .bind(package_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select knowledge package"))?;
        row.as_ref().map(knowledge_package_from_row).transpose()
    }

    async fn knowledge_active(&self) -> StoreResult<Option<StoredKnowledgeActive>> {
        let row = sqlx::query(
            "SELECT package_id, generation, activated_by, activated_at \
             FROM knowledge_active WHERE setting_id = ?1",
        )
        .bind(DEFAULT_KNOWLEDGE_SETTING_ID)
        .fetch_optional(&self.pool)
        .await
        .map_err(|err| sql_error(err, "select active knowledge"))?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some(StoredKnowledgeActive {
            package_id: column!(row, "package_id"),
            generation: column!(row, "generation"),
            activated_by: column!(row, "activated_by"),
            activated_at: column!(row, "activated_at"),
        }))
    }

    async fn activate_knowledge(
        &self,
        activation: &KnowledgeActivation<'_>,
    ) -> StoreResult<StoredKnowledgeActive> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|err| sql_error(err, "begin activate knowledge"))?;
        // 世代号在上一版基础上 +1：必须**单调**，否则"哪一代算的"会重复、归因就失真。
        // 同时读出上一版包 id —— 它是审计里的 `from_package`。
        let previous: Option<(i64, String)> = sqlx::query_as(
            "SELECT generation, package_id FROM knowledge_active WHERE setting_id = ?1",
        )
        .bind(DEFAULT_KNOWLEDGE_SETTING_ID)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "select knowledge generation"))?;
        let (generation, from_package) = match previous {
            Some((generation, package_id)) => (generation + 1, Some(package_id)),
            None => (1, None),
        };
        sqlx::query(
            "INSERT INTO knowledge_active (setting_id, package_id, generation, activated_by, \
             activated_at) VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT (setting_id) DO UPDATE SET package_id = excluded.package_id, \
             generation = excluded.generation, activated_by = excluded.activated_by, \
             activated_at = excluded.activated_at",
        )
        .bind(DEFAULT_KNOWLEDGE_SETTING_ID)
        .bind(activation.package_id)
        .bind(generation)
        .bind(activation.requested_by)
        .bind(activation.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "activate knowledge"))?;
        sqlx::query(
            "INSERT INTO knowledge_activation_log (from_package, to_package, generation, reason, \
             requested_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(from_package)
        .bind(activation.package_id)
        .bind(generation)
        .bind(activation.reason)
        .bind(activation.requested_by)
        .bind(activation.created_at)
        .execute(&mut *tx)
        .await
        .map_err(|err| sql_error(err, "log knowledge activation"))?;
        tx.commit()
            .await
            .map_err(|err| sql_error(err, "commit activate knowledge"))?;
        Ok(StoredKnowledgeActive {
            package_id: activation.package_id.to_string(),
            generation,
            activated_by: activation.requested_by.to_string(),
            activated_at: activation.created_at.to_string(),
        })
    }
}

/// 列清单单独提出来：读单行与读全表必须选同一组列，
/// 两处各写一遍迟早会漏掉新列（而漏掉的列在那个查询里静默变成默认值）。
const STANDING_WORK_COLUMNS: &str = "work_id, agent_id, family, spec, catalog_version, proposal_id, \
     plan_version, effective_from, status, updated_by, updated_at";

const ONE_SHOT_WORK_COLUMNS: &str = "work_id, agent_id, action, spec, scheduled_at, deadline_at, \
     timeout_seconds, interruptible, status, paused_at, pre_pause_status, paused_total_seconds, \
     current_step, completed_steps, attempt, issued_by, issued_at";

/// 终态取值拼成 `'a', 'b'`，供 `NOT IN (...)` 用。
///
/// 从契约取（不写死字面量）：它一改，这里跟着改，不会各自漂移。
fn one_shot_terminal_status_sql() -> String {
    wist_contracts::work::ONE_SHOT_TERMINAL_STATUSES
        .iter()
        .map(|status| format!("'{status}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// 灰度发布计划的列清单（读单行与读全表选同一组列）。
const ROLLOUT_PLAN_COLUMNS: &str = "plan_id, action, spec, deadline_at, timeout_seconds, \
     phases_json, batch_size, current_phase, status, created_by, created_at, approved_by, approved_at";

fn rollout_plan_from_row(row: &SqliteRow) -> StoreResult<StoredRolloutPlan> {
    let phases_json: String = column!(row, "phases_json");
    Ok(StoredRolloutPlan {
        plan_id: column!(row, "plan_id"),
        action: column!(row, "action"),
        spec: column!(row, "spec"),
        deadline_at: column!(row, "deadline_at"),
        timeout_seconds: column!(row, "timeout_seconds"),
        phases: deserialize_json_array(&phases_json, "decode rollout plan phases")?,
        batch_size: column!(row, "batch_size"),
        current_phase: column!(row, "current_phase"),
        status: column!(row, "status"),
        created_by: column!(row, "created_by"),
        created_at: column!(row, "created_at"),
        approved_by: column!(row, "approved_by"),
        approved_at: column!(row, "approved_at"),
    })
}

fn rollout_plan_entry_from_row(row: &SqliteRow) -> StoreResult<StoredRolloutPlanEntry> {
    Ok(StoredRolloutPlanEntry {
        plan_id: column!(row, "plan_id"),
        target_id: column!(row, "target_id"),
        work_id: column!(row, "work_id"),
        status: column!(row, "status"),
        detail: column!(row, "detail"),
        updated_at: column!(row, "updated_at"),
    })
}

fn standing_work_from_row(row: &SqliteRow) -> StoreResult<StandingWork> {
    Ok(StandingWork {
        work_id: column!(row, "work_id"),
        agent_id: column!(row, "agent_id"),
        family: column!(row, "family"),
        spec: column!(row, "spec"),
        catalog_version: column!(row, "catalog_version"),
        proposal_id: column!(row, "proposal_id"),
        plan_version: column!(row, "plan_version"),
        effective_from: column!(row, "effective_from"),
        status: column!(row, "status"),
        updated_by: column!(row, "updated_by"),
        updated_at: column!(row, "updated_at"),
    })
}

/// SQLite 没有布尔类型，`interruptible` 存 0/1，读回来时映射。
fn one_shot_work_from_row(row: &SqliteRow) -> StoreResult<StoredOneShotWork> {
    let completed_steps: String = column!(row, "completed_steps");
    Ok(StoredOneShotWork {
        work: OneShotWork {
            work_id: column!(row, "work_id"),
            agent_id: column!(row, "agent_id"),
            action: column!(row, "action"),
            spec: column!(row, "spec"),
            scheduled_at: column!(row, "scheduled_at"),
            deadline_at: column!(row, "deadline_at"),
            timeout_seconds: column!(row, "timeout_seconds"),
            interruptible: column!(row, "interruptible"),
            status: column!(row, "status"),
            paused_at: column!(row, "paused_at"),
            paused_total_seconds: column!(row, "paused_total_seconds"),
            current_step: column!(row, "current_step"),
            completed_steps: deserialize_json_array(
                &completed_steps,
                "read one-shot completed steps",
            )?,
            attempt: column!(row, "attempt"),
            issued_by: column!(row, "issued_by"),
            issued_at: column!(row, "issued_at"),
        },
        pre_pause_status: column!(row, "pre_pause_status"),
    })
}

fn fact_summary_from_row(row: &SqliteRow) -> StoreResult<StoredAgentFactSummary> {
    let process_executables: String = column!(row, "process_executables");
    let packages: String = column!(row, "packages");
    let listen_ports: String = column!(row, "listen_ports");
    let network_addresses: String = column!(row, "network_addresses");
    Ok(StoredAgentFactSummary {
        agent_id: column!(row, "agent_id"),
        content_digest: column!(row, "content_digest"),
        revision: column!(row, "revision"),
        observed_at: column!(row, "observed_at"),
        os: column!(row, "os"),
        arch: column!(row, "arch"),
        process_count: column!(row, "process_count"),
        process_executables: deserialize_json_array(
            &process_executables,
            "read process executables",
        )?,
        packages: deserialize_json_array(&packages, "read packages")?,
        listen_ports: deserialize_json_array(&listen_ports, "read listen ports")?,
        host_id: column!(row, "host_id"),
        host_name: column!(row, "host_name"),
        network_addresses: deserialize_json_array(&network_addresses, "read network addresses")?,
        received_at: column!(row, "received_at"),
    })
}

fn classification_from_row(row: &SqliteRow) -> StoreResult<StoredAgentClassification> {
    Ok(StoredAgentClassification {
        agent_id: column!(row, "agent_id"),
        machine_class: column!(row, "machine_class"),
        suggestion_id: column!(row, "suggestion_id"),
        note: column!(row, "note"),
        decided_by: column!(row, "decided_by"),
        decided_at: column!(row, "decided_at"),
    })
}

fn purpose_suggestion_from_row(row: &SqliteRow) -> StoreResult<StoredPurposeSuggestion> {
    let signals: String = column!(row, "signals");
    Ok(StoredPurposeSuggestion {
        agent_id: column!(row, "agent_id"),
        suggestion_id: column!(row, "suggestion_id"),
        suggested_class: column!(row, "suggested_class"),
        confidence: column!(row, "confidence"),
        method: column!(row, "method"),
        rule_set_id: column!(row, "rule_set_id"),
        purpose_version: column!(row, "purpose_version"),
        signals: deserialize_json_array(&signals, "read purpose signals")?,
        observed_at: column!(row, "observed_at"),
        computed_at: column!(row, "computed_at"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "tenant-test";
    const ENVIRONMENT: &str = "env-test";
    const RESERVATION_TTL: i64 = 60;

    async fn store() -> SqliteStore {
        SqliteStore::connect("sqlite::memory:")
            .await
            .expect("open sqlite store")
    }

    fn token(token_hash: &str, max_uses: u32) -> StoredEnrollmentToken {
        StoredEnrollmentToken {
            token_id: format!("token-{token_hash}"),
            token_hash: token_hash.to_string(),
            tenant_id: TENANT.to_string(),
            environment_id: ENVIRONMENT.to_string(),
            issued_by: "test".to_string(),
            allowed_node_selector: None,
            max_uses,
            used_count: 0,
            status: StoredEnrollmentTokenStatus::Active,
            issued_at: now_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            reserved_at: None,
            revoked_at: None,
        }
    }

    fn reserve<'a>(token_hash: &'a str, agent_id: &'a str) -> ReserveEnrollmentToken<'a> {
        ReserveEnrollmentToken {
            token_hash,
            tenant_id: TENANT,
            environment_id: ENVIRONMENT,
            agent_id,
            reservation_ttl_seconds: RESERVATION_TTL,
        }
    }

    fn bootstrap<'a>(token_hash: &'a str) -> BootstrapTokenCheck<'a> {
        BootstrapTokenCheck {
            token_hash,
            tenant_id: TENANT,
            environment_id: ENVIRONMENT,
            reservation_ttl_seconds: RESERVATION_TTL,
        }
    }

    async fn register(store: &SqliteStore, token_hash: &str, agent_id: &str, instance_id: &str) {
        // 凭据 id/hash 按 agent 派生，保证多 Agent 测试不撞 token_hash 唯一约束。
        let credential_id = format!("cred-{agent_id}");
        let credential_token_hash = format!("cred-hash-{agent_id}");
        store
            .insert_enrollment_token(&token(token_hash, 1))
            .await
            .unwrap();
        store
            .validate_bootstrap_token(&bootstrap(token_hash))
            .await
            .unwrap()
            .expect("token valid");
        store
            .reserve_enrollment_token(&reserve(token_hash, agent_id))
            .await
            .unwrap()
            .expect("reserved");
        let request = CommitRegistration {
            token_hash,
            agent_id,
            instance_id,
            boot_id: "boot-1",
            tenant_id: TENANT,
            environment_id: ENVIRONMENT,
            node_id: "node-1",
            hostname: "host-1",
            machine_id: "machine-1",
            version: "0.1.0",
            credential_id: &credential_id,
            credential_token_hash: &credential_token_hash,
            credential_issued_at: "2026-01-01T00:00:00+00:00",
            credential_expires_at: "2026-12-31T00:00:00+00:00",
            registered_at: "2026-01-01T00:00:00+00:00",
            now: "2026-01-01T00:00:00+00:00",
        };
        store
            .commit_reserved_registration(&request)
            .await
            .unwrap()
            .expect("committed");
    }

    fn cert_registration<'a>(
        agent_id: &'a str,
        credential_id: &'a str,
        fingerprint: &'a str,
        registered_at: &'a str,
        now: &'a str,
    ) -> CertificateRegistration<'a> {
        CertificateRegistration {
            agent_id,
            tenant_id: TENANT,
            environment_id: ENVIRONMENT,
            credential_id,
            credential_fingerprint: fingerprint,
            credential_issued_at: "2026-01-01T00:00:00+00:00",
            credential_expires_at: "2026-12-31T00:00:00+00:00",
            registered_at,
            now,
        }
    }

    /// 库丢/换网关后的首触：证书验链通过但库里没有登记 → 凭证书身份补一条，且必须能被
    /// `get_agent` 读到（重建路径不能在投影上「建了却读不出」）。
    #[tokio::test]
    async fn register_agent_from_certificate_rebuilds_missing_agent() {
        let store = store().await;
        assert!(store.get_agent("agent-cert").await.unwrap().is_none());

        let registration = cert_registration(
            "agent-cert",
            "cred-cert",
            "fingerprint-cert",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        );
        assert!(
            store
                .register_agent_from_certificate(&registration)
                .await
                .unwrap(),
            "首次接触应真正新建登记"
        );

        let agent = store.get_agent("agent-cert").await.unwrap().expect("agent");
        assert_eq!(agent.agent_id, "agent-cert");
        assert_eq!(agent.tenant_id, TENANT);
        assert_eq!(agent.environment_id, ENVIRONMENT);
        assert_eq!(agent.credential_id, "cred-cert");
        assert_eq!(agent.credential_token_hash, "fingerprint-cert");
        assert_eq!(agent.credential_status, StoredCredentialStatus::Active);
        // 首触时画像未知：node_id/hostname/machine_id 留空是预期，不算异常。
        assert_eq!(agent.node_id, "");
    }

    /// 幂等：同一张证书重入（并发首触 / 换网关后重复接触）不得改写已存在的登记。
    #[tokio::test]
    async fn register_agent_from_certificate_is_idempotent() {
        let store = store().await;
        let first = cert_registration(
            "agent-cert-2",
            "cred-cert-2",
            "fingerprint-cert-2",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        );
        assert!(store.register_agent_from_certificate(&first).await.unwrap());

        // 第二次带上不同的时间戳：若实现不是无操作，registered_at 会被改写。
        let second = cert_registration(
            "agent-cert-2",
            "cred-cert-2",
            "fingerprint-cert-2",
            "2026-06-01T00:00:00+00:00",
            "2026-06-01T00:00:00+00:00",
        );
        assert!(
            !store
                .register_agent_from_certificate(&second)
                .await
                .unwrap(),
            "已存在时应返回 false 且不动任何字段"
        );

        let after = store
            .get_agent("agent-cert-2")
            .await
            .unwrap()
            .expect("agent");
        assert_eq!(after.registered_at, "2026-01-01T00:00:00+00:00");
    }

    #[tokio::test]
    async fn registers_agent_and_consumes_one_time_token() {
        let store = store().await;
        register(&store, "hash-a", "agent-1", "inst-1").await;

        let token = store
            .get_enrollment_token("hash-a")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(token.used_count, 1);
        assert_eq!(token.status, StoredEnrollmentTokenStatus::Used);
        assert!(token.reserved_at.is_none());

        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.tenant_id, TENANT);
        assert_eq!(agent.instance_id, "inst-1");
        assert_eq!(agent.version, "0.1.0");
        assert_eq!(agent.credential_id, "cred-agent-1");
        assert_eq!(agent.credential_status, StoredCredentialStatus::Active);

        // 一次性 token 不能重放
        let replay = store
            .reserve_enrollment_token(&reserve("hash-a", "agent-2"))
            .await
            .unwrap();
        assert_eq!(replay, Err(ReservationRejection::InvalidToken));
    }

    /// `delete_agent` 要把**没有外键**的派生态行也清干净 —— 不是只删 `agents`。
    ///
    /// 只有 `agent_instances` / `agent_credentials` 建了 `ON DELETE CASCADE`；其余 per-agent 表
    /// 只删 `agents` 会留下无主的「幽灵」行，之后按 `agent_id` 查还会命中陈旧数据。
    #[tokio::test]
    async fn delete_agent_purges_rows_that_do_not_cascade() {
        let store = store().await;
        register(&store, "hash-del", "agent-del", "inst-del").await;
        register(&store, "hash-keep", "agent-keep", "inst-keep").await;

        // 两张**没有外键**的 per-agent 表：删 agents 不会连带它们（本测试要证明显式删除生效）。
        sqlx::query(
            "INSERT INTO agent_work_sequence (agent_id, sequence, updated_at) \
             VALUES ('agent-del', 7, '2026-01-01T00:00:00Z'), \
                    ('agent-keep', 1, '2026-01-01T00:00:00Z')",
        )
        .execute(&store.pool)
        .await
        .expect("seed work sequence");
        sqlx::query(
            "INSERT INTO agent_classification \
             (agent_id, machine_class, suggestion_id, note, decided_by, decided_at) \
             VALUES ('agent-del', 'LinuxCompute', NULL, NULL, 'admin', '2026-01-01T00:00:00Z')",
        )
        .execute(&store.pool)
        .await
        .expect("seed classification");

        assert!(store.delete_agent("agent-del").await.expect("delete"));

        for table in [
            "agent_work_sequence",
            "agent_classification",
            "agent_instances",
            "agent_credentials",
        ] {
            let left: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*) FROM {table} WHERE agent_id = 'agent-del'"
            )))
            .fetch_one(&store.pool)
            .await
            .expect("count");
            assert_eq!(left, 0, "{table} 仍留着 agent-del 的行");
        }
        assert!(store.get_agent("agent-del").await.expect("get").is_none());

        // 不误伤别的 agent；重复删除返回 false。
        let kept: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM agent_work_sequence WHERE agent_id = 'agent-keep'",
        )
        .fetch_one(&store.pool)
        .await
        .expect("count kept");
        assert_eq!(kept, 1);
        assert!(
            !store
                .delete_agent("agent-del")
                .await
                .expect("second delete")
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_agent_without_committing() {
        let store = store().await;
        register(&store, "hash-b", "agent-1", "inst-1").await;

        // 另发一张全新 token，但用已注册的 agent_id 去预留：应判重复且不消费该 token。
        store
            .insert_enrollment_token(&token("hash-b2", 1))
            .await
            .unwrap();
        let second = store
            .reserve_enrollment_token(&reserve("hash-b2", "agent-1"))
            .await
            .unwrap();
        assert_eq!(second, Err(ReservationRejection::DuplicateAgent));
        let untouched = store
            .get_enrollment_token("hash-b2")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(untouched.status, StoredEnrollmentTokenStatus::Active);
        assert_eq!(untouched.used_count, 0);
    }

    #[tokio::test]
    async fn recovers_stale_reservation() {
        let store = store().await;
        store
            .insert_enrollment_token(&token("hash-c", 1))
            .await
            .unwrap();
        store
            .reserve_enrollment_token(&reserve("hash-c", "agent-1"))
            .await
            .unwrap()
            .expect("reserved");

        // 把预留时间推到 TTL 之前，模拟进程在发放凭据时崩溃。
        let stale = (Utc::now() - chrono::Duration::seconds(RESERVATION_TTL * 2)).to_rfc3339();
        sqlx::query("UPDATE enrollment_tokens SET reserved_at = ?1 WHERE token_hash = ?2")
            .bind(&stale)
            .bind("hash-c")
            .execute(store.pool())
            .await
            .unwrap();

        store
            .validate_bootstrap_token(&bootstrap("hash-c"))
            .await
            .unwrap()
            .expect("recovered token is usable");
        let token = store
            .get_enrollment_token("hash-c")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(token.status, StoredEnrollmentTokenStatus::Active);
        assert_eq!(token.used_count, 0);
        assert!(token.reserved_at.is_none());
    }

    #[tokio::test]
    async fn rollback_returns_reserved_use() {
        let store = store().await;
        store
            .insert_enrollment_token(&token("hash-d", 1))
            .await
            .unwrap();
        store
            .reserve_enrollment_token(&reserve("hash-d", "agent-1"))
            .await
            .unwrap()
            .expect("reserved");
        store
            .rollback_enrollment_token_reservation("hash-d")
            .await
            .unwrap();

        let token = store
            .get_enrollment_token("hash-d")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(token.status, StoredEnrollmentTokenStatus::Active);
        assert_eq!(token.used_count, 0);
        assert!(token.reserved_at.is_none());
    }

    #[tokio::test]
    async fn expired_token_is_marked_and_rejected() {
        let store = store().await;
        let mut expired = token("hash-e", 1);
        expired.expires_at = (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        store.insert_enrollment_token(&expired).await.unwrap();

        let result = store
            .validate_bootstrap_token(&bootstrap("hash-e"))
            .await
            .unwrap();
        assert_eq!(result, Err(EnrollmentTokenRejection::Expired));
        let stored = store
            .get_enrollment_token("hash-e")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(stored.status, StoredEnrollmentTokenStatus::Expired);
    }

    #[tokio::test]
    async fn tracks_instances_per_agent_and_avoids_silent_drop() {
        let store = store().await;
        register(&store, "hash-f", "agent-1", "inst-1").await;

        // 未知 Agent 不再静默成功。
        let missing = store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-unknown",
                instance_id: "inst-x",
                boot_id: "",
                version: "0.1.0",
                last_seen_at: "2026-01-02T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        assert!(!missing);

        // 同一个 Agent 换 boot/实例：保留两行历史，current 指向最新。
        for (instance_id, seen_at, memory) in [
            ("inst-1", "2026-01-02T00:00:00+00:00", Some(1024u64)),
            ("inst-2", "2026-01-03T00:00:00+00:00", Some(2048u64)),
        ] {
            let recorded = store
                .record_agent_status(&AgentStatusUpdate {
                    agent_id: "agent-1",
                    instance_id,
                    boot_id: "boot-1",
                    version: "0.2.0",
                    last_seen_at: seen_at,
                    memory_bytes: memory,
                    cpu_percent: Some(1.5),
                    cpu_cores: None,
                    admin_latency_ms: Some(7),
                    discovery_policy_version: None,
                    work_state_changes: None,
                    local_work: None,
                    uplink_state: None,
                })
                .await
                .unwrap();
            assert!(recorded);
        }

        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.instance_id, "inst-2");
        assert_eq!(agent.last_seen_at, "2026-01-03T00:00:00+00:00");
        assert_eq!(agent.last_memory_bytes, Some(2048));

        let instances = store.list_agent_instances("agent-1").await.unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0].instance_id, "inst-2");
    }

    #[tokio::test]
    async fn migration_adds_agent_discovery_policy_version_column() {
        // 迁移 0005 是 ALTER TABLE ADD COLUMN（SQLite 不支持 ADD COLUMN IF NOT EXISTS），
        // 直接查 pragma 确认列真存在，而不是只靠“插得进去”。
        let store = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_instances')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert!(
            columns
                .iter()
                .any(|name| name == "discovery_policy_version"),
            "{columns:?}"
        );
    }

    #[tokio::test]
    async fn migration_adds_agent_cpu_cores_column() {
        // 迁移 0010 同样只是 ALTER TABLE ADD COLUMN（SQLite 不支持 ADD COLUMN IF NOT EXISTS），
        // 直接查 pragma 确认列真存在，而不是只靠“插得进去”。
        let store = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_instances')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert!(
            columns.iter().any(|name| name == "cpu_cores"),
            "{columns:?}"
        );
    }

    #[tokio::test]
    async fn migration_adds_agent_local_work_column() {
        // 迁移 0013 同样只是 ALTER TABLE ADD COLUMN（SQLite 不支持 ADD COLUMN IF NOT EXISTS），
        // 直接查 pragma 确认列真存在，而不是只靠“插得进去”。
        let store = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_instances')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert!(
            columns.iter().any(|name| name == "local_work"),
            "{columns:?}"
        );
    }

    #[tokio::test]
    async fn migration_adds_agent_uplink_state_column() {
        // 迁移 0015 同样只是 ALTER TABLE ADD COLUMN（SQLite 不支持 ADD COLUMN IF NOT EXISTS），
        // 直接查 pragma 确认列真存在，而不是只靠“插得进去”。
        let store = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_instances')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert!(
            columns.iter().any(|name| name == "uplink_state"),
            "{columns:?}"
        );
    }

    #[tokio::test]
    async fn migration_adds_agent_certificate_status_table() {
        // 迁移 0017 新建一张表（CREATE TABLE IF NOT EXISTS），在已有库上不会重跑建表，
        // 因此直接查 pragma 确认列真存在，而不是只靠“插得进去”。
        let store = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_certificate_status')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        for expected in [
            "agent_id",
            "not_after",
            "remaining_seconds",
            "state",
            "reported_at",
        ] {
            assert!(columns.iter().any(|name| name == expected), "{columns:?}");
        }
    }

    #[tokio::test]
    async fn migration_adds_agent_certificate_renewal_column() {
        // 迁移 0019 只是 ALTER TABLE ADD COLUMN（SQLite 不支持 ADD COLUMN IF NOT EXISTS），
        // 直接查 pragma 确认列真存在。
        let store = store().await;
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('agent_certificate_status')")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert!(
            columns.iter().any(|name| name == "last_renewal_json"),
            "{columns:?}"
        );
    }

    #[tokio::test]
    async fn migration_adds_agent_install_package_history_table() {
        // 迁移 0016 新建一张表（CREATE TABLE IF NOT EXISTS），不会在已有库上重跑建表，
        // 因此直接查 pragma 确认表/列真存在，而不是只靠“插得进去”。
        let store = store().await;
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM pragma_table_info('agent_install_package_history')",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        for expected in [
            "package_id",
            "source",
            "package_sha256",
            "version",
            "arch",
            "cached_path",
            "created_by",
            "created_at",
        ] {
            assert!(
                columns.iter().any(|name| name == expected),
                "missing column {expected}: {columns:?}"
            );
        }
    }

    fn local_work_view() -> wist_contracts::local_work::AgentLocalWork {
        wist_contracts::local_work::AgentLocalWork {
            recorded_at: "2026-01-05T00:00:00+00:00".to_string(),
            gateway_sequence: 7,
            standing: vec![wist_contracts::local_work::AgentLocalStandingWork {
                work_id: "work-1".to_string(),
                family: "SystemLogs".to_string(),
                status: "active".to_string(),
                plan_version: 3,
                acknowledged_version: Some(3),
                effective_from: "2026-01-04T00:00:00+00:00".to_string(),
                tasks: vec![wist_contracts::local_work::AgentLocalTask {
                    input_id: "work-SystemLogs-syslog".to_string(),
                    path: "/var/log/system.log".to_string(),
                    startup_position: "tail".to_string(),
                }],
            }],
            one_shot: Vec::new(),
            // 本机手工加的输入：不在 work.json 里，但也是「在采的文件」。
            local_inputs: vec![wist_contracts::local_work::AgentLocalTask {
                input_id: "manual-app".to_string(),
                path: "/var/log/app.log".to_string(),
                startup_position: "tail".to_string(),
            }],
            metrics_interval_seconds: Some(15),
        }
    }

    #[tokio::test]
    async fn stores_and_reads_back_the_local_work_view() {
        let store = store().await;
        register(&store, "hash-m", "agent-1", "inst-1").await;

        // 旧 agent（没带这个字段）：写入不失败，读出为 None。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.1.0",
                last_seen_at: "2026-01-02T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert!(agent.local_work.is_none());

        // 上报本机工作视图：读写一致（standing.tasks 与手工输入都在）。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.2.0",
                last_seen_at: "2026-01-03T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: Some(local_work_view()),
                uplink_state: None,
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.local_work, Some(local_work_view()));

        // 关键语义（与 `AgentStatusReport::local_work` 的文档口径一致）：本次没带（None）
        // 保持上一次的值，不清成 NULL —— 否则一次不带该字段的旧版心跳就会把「在采哪些文件」
        // 的最后一份可信快照擦掉。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.2.0",
                last_seen_at: "2026-01-04T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.local_work, Some(local_work_view()));
    }

    fn uplink_state(
        kind: &str,
        target: Option<&str>,
        source: &str,
        output_write_failing: bool,
    ) -> wist_contracts::agent_uplink::AgentUplinkState {
        wist_contracts::agent_uplink::AgentUplinkState {
            enabled: true,
            kind: kind.to_string(),
            target: target.map(str::to_string),
            source: source.to_string(),
            output_write_failing,
        }
    }

    #[tokio::test]
    async fn stores_uplink_state_and_keeps_it_when_the_next_report_omits_it() {
        let store = store().await;
        register(&store, "hash-u", "agent-1", "inst-1").await;

        // 旧 agent（没带这个字段）：写入不失败，读出为 None。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.1.0",
                last_seen_at: "2026-01-02T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert!(agent.uplink_state.is_none());

        // 上报实际生效的上送状态：读写一致（target / source / 失败标志逐项对得上）。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.2.0",
                last_seen_at: "2026-01-03T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: Some(uplink_state("tcp", Some("10.0.1.9:9000"), "grant", true)),
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(
            agent.uplink_state,
            Some(uplink_state("tcp", Some("10.0.1.9:9000"), "grant", true))
        );

        // 关键语义（与 local_work 的文档口径一致）：本次没带（None）保持上一次的值，
        // 不清成 NULL —— 否则「这台为什么不上送」的最后一份可信答案会被一次旧版心跳擦掉。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.2.0",
                last_seen_at: "2026-01-04T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(
            agent.uplink_state,
            Some(uplink_state("tcp", Some("10.0.1.9:9000"), "grant", true))
        );
    }

    #[tokio::test]
    async fn stores_agent_discovery_policy_version_and_distinguishes_none_from_zero() {
        let store = store().await;
        register(&store, "hash-l", "agent-1", "inst-1").await;

        // 旧 agent（没带新字段）：写入必须不失败，且留 NULL。
        let legacy = store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.1.0",
                last_seen_at: "2026-01-02T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        assert!(legacy);
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.last_discovery_policy_version, None);

        // 上报实际生效的版本：读写一致。
        let recorded = store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.2.0",
                last_seen_at: "2026-01-03T00:00:00+00:00",
                memory_bytes: Some(4096),
                cpu_percent: Some(1.5),
                cpu_cores: None,
                admin_latency_ms: Some(7),
                discovery_policy_version: Some(2),
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        assert!(recorded);
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.last_discovery_policy_version, Some(2));

        // 版本 0 是一个真实版本，必须与 None（还没拉到）区分开。
        store
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-1",
                instance_id: "inst-1",
                boot_id: "boot-1",
                version: "0.2.0",
                last_seen_at: "2026-01-04T00:00:00+00:00",
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: Some(0),
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .unwrap();
        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.last_discovery_policy_version, Some(0));
    }

    #[tokio::test]
    async fn renews_credential_and_invalidates_previous_hash() {
        let store = store().await;
        register(&store, "hash-g", "agent-1", "inst-1").await;

        let renewed = store
            .renew_agent_credential(&RenewCredential {
                agent_id: "agent-1",
                instance_id: "inst-1",
                current_token_hash: "cred-hash-agent-1",
                new_credential_id: "cred-2",
                new_token_hash: "cred-hash-2",
                issued_at: "2026-02-01T00:00:00+00:00",
                expires_at: "2027-01-01T00:00:00+00:00",
            })
            .await
            .unwrap();
        assert!(renewed);

        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.credential_id, "cred-2");
        assert_eq!(agent.credential_token_hash, "cred-hash-2");
        assert_eq!(agent.credential_status, StoredCredentialStatus::Active);

        // 旧凭据立即失效，且不能再用来续期。
        let with_old = store
            .renew_agent_credential(&RenewCredential {
                agent_id: "agent-1",
                instance_id: "inst-1",
                current_token_hash: "cred-hash-agent-1",
                new_credential_id: "cred-3",
                new_token_hash: "cred-hash-3",
                issued_at: "2026-02-02T00:00:00+00:00",
                expires_at: "2027-01-01T00:00:00+00:00",
            })
            .await
            .unwrap();
        assert!(!with_old);
    }

    #[tokio::test]
    async fn revoking_current_credential_locks_agent_out() {
        let store = store().await;
        register(&store, "hash-h", "agent-1", "inst-1").await;

        assert!(
            store
                .revoke_agent_credential("agent-1", "cred-agent-1")
                .await
                .unwrap()
        );
        // 重复吊销是无操作。
        assert!(
            !store
                .revoke_agent_credential("agent-1", "cred-agent-1")
                .await
                .unwrap()
        );

        let agent = store.get_agent("agent-1").await.unwrap().expect("agent");
        assert_eq!(agent.credential_status, StoredCredentialStatus::Revoked);
    }

    #[tokio::test]
    async fn finds_agent_by_current_credential_token_hash_only() {
        let store = store().await;
        register(&store, "hash-c", "agent-1", "inst-1").await;

        // 当前凭据 hash 命中（升级取包只有 token，没有 agent_id/instance_id）。
        let found = store
            .find_agent_by_credential_token_hash("cred-hash-agent-1")
            .await
            .unwrap()
            .expect("current credential must resolve to its agent");
        assert_eq!(found.agent_id, "agent-1");

        // 未知 hash → None（不能凭一个不存在的 token 拿到任何 agent）。
        assert!(
            store
                .find_agent_by_credential_token_hash("no-such-hash")
                .await
                .unwrap()
                .is_none()
        );

        // 轮换后旧 hash 不再是“当前凭据”，查不到；新 hash 查得到。
        assert!(
            store
                .renew_agent_credential(&RenewCredential {
                    agent_id: "agent-1",
                    instance_id: "inst-1",
                    current_token_hash: "cred-hash-agent-1",
                    new_credential_id: "cred-next",
                    new_token_hash: "cred-hash-next",
                    issued_at: "2026-02-01T00:00:00+00:00",
                    expires_at: "2027-01-01T00:00:00+00:00",
                })
                .await
                .unwrap()
        );
        assert!(
            store
                .find_agent_by_credential_token_hash("cred-hash-agent-1")
                .await
                .unwrap()
                .is_none(),
            "rotated-out credential must not resolve"
        );
        let renewed = store
            .find_agent_by_credential_token_hash("cred-hash-next")
            .await
            .unwrap()
            .expect("new credential resolves");
        assert_eq!(renewed.agent_id, "agent-1");
    }

    #[tokio::test]
    async fn credential_token_hash_lookup_returns_agent_for_revoked_or_expired_current_credential()
    {
        // 该查询只按「当前凭据」那一行匹配 `token_hash`，**不**在 SQL 里过滤状态/有效期：
        // 吊销/过期的拒绝是 API 层 `authenticate_agent_credential_token` 的职责。
        // 这里钉住分层契约，防止将来误以为查询本身已经做过状态过滤而省略 API 侧判定。
        let store = store().await;
        register(&store, "hash-k", "agent-1", "inst-1").await;

        // 已吊销的当前凭据：行仍在（保留审计），hash 仍解析到 agent，但状态是 revoked。
        assert!(
            store
                .revoke_agent_credential("agent-1", "cred-agent-1")
                .await
                .unwrap()
        );
        let revoked = store
            .find_agent_by_credential_token_hash("cred-hash-agent-1")
            .await
            .unwrap()
            .expect("revoked current credential still resolves so the API can reject it");
        assert_eq!(revoked.agent_id, "agent-1");
        assert_eq!(revoked.credential_status, StoredCredentialStatus::Revoked);

        // 过期的当前凭据（状态仍 active）：同样解析得到，过期判定交给 API 层。
        register(&store, "hash-l", "agent-2", "inst-2").await;
        sqlx::query("UPDATE agent_credentials SET expires_at = ?1 WHERE credential_id = ?2")
            .bind("2020-01-01T00:00:00+00:00")
            .bind("cred-agent-2")
            .execute(store.pool())
            .await
            .unwrap();
        let expired = store
            .find_agent_by_credential_token_hash("cred-hash-agent-2")
            .await
            .unwrap()
            .expect("expired current credential still resolves so the API can reject it");
        assert_eq!(expired.credential_status, StoredCredentialStatus::Active);
        assert_eq!(expired.credential_expires_at, "2020-01-01T00:00:00+00:00");
    }

    #[tokio::test]
    async fn lists_and_filters_agents_with_pagination() {
        let store = store().await;
        register(&store, "hash-i", "agent-1", "inst-1").await;
        register(&store, "hash-j", "agent-2", "inst-2").await;

        let all = store.list_agents(&AgentQuery::default()).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].agent_id, "agent-1");

        let page = store
            .list_agents(&AgentQuery {
                limit: Some(1),
                offset: 1,
                ..AgentQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].agent_id, "agent-2");

        let other_tenant = store
            .list_agents(&AgentQuery {
                tenant_id: Some("tenant-other".to_string()),
                ..AgentQuery::default()
            })
            .await
            .unwrap();
        assert!(other_tenant.is_empty());

        let ids = store.list_agent_ids().await.unwrap();
        assert_eq!(ids, vec!["agent-1".to_string(), "agent-2".to_string()]);
        assert!(store.agent_exists("agent-1").await.unwrap());
        assert!(!store.agent_exists("agent-3").await.unwrap());
    }

    #[tokio::test]
    async fn revokes_enrollment_token_by_id() {
        let store = store().await;
        store
            .insert_enrollment_token(&token("hash-k", 1))
            .await
            .unwrap();

        assert!(store.revoke_enrollment_token("token-hash-k").await.unwrap());
        assert!(!store.revoke_enrollment_token("token-hash-k").await.unwrap());

        let stored = store
            .get_enrollment_token("hash-k")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(stored.status, StoredEnrollmentTokenStatus::Revoked);
        assert!(stored.revoked_at.is_some());

        let result = store
            .validate_bootstrap_token(&bootstrap("hash-k"))
            .await
            .unwrap();
        assert_eq!(result, Err(EnrollmentTokenRejection::NotActive));
    }

    #[tokio::test]
    async fn imports_legacy_json_store_once() {
        let dir = std::env::temp_dir().join(format!(
            "wist-gateway-legacy-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let legacy_path = dir.join("wist-gateway-store.json");
        std::fs::write(
            &legacy_path,
            r#"{
              "enrollment_tokens": {},
              "agents": {
                "agent-legacy": {
                  "agent_id": "agent-legacy",
                  "instance_id": "inst-legacy",
                  "tenant_id": "tenant-test",
                  "environment_id": "env-test",
                  "node_id": "node-legacy",
                  "hostname": "host-legacy",
                  "machine_id": "machine-legacy",
                  "version": "0.0.9",
                  "credential_id": "cred-legacy",
                  "credential_token_hash": "cred-hash-legacy",
                  "credential_issued_at": "2025-12-01T00:00:00+00:00",
                  "credential_expires_at": "2026-12-01T00:00:00+00:00",
                  "credential_status": "active",
                  "registered_at": "2025-12-01T00:00:00+00:00",
                  "last_seen_at": "2026-01-01T00:00:00+00:00"
                }
              }
            }"#,
        )
        .unwrap();
        let store = SqliteStore::connect_path(&dir.join("db.sqlite"))
            .await
            .unwrap();

        assert!(store.import_legacy_json(&legacy_path).await.unwrap());
        let agent = store
            .get_agent("agent-legacy")
            .await
            .unwrap()
            .expect("imported agent");
        assert_eq!(agent.credential_token_hash, "cred-hash-legacy");
        assert_eq!(agent.version, "0.0.9");
        // 源文件已归档，二次启动不会重复导入。
        assert!(!legacy_path.exists());
        assert!(!store.import_legacy_json(&legacy_path).await.unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn upserts_and_reads_agent_classification() {
        let store = store().await;
        // 未判定时为 None（页面看到的是“还没人定”，不是某个默认值）。
        assert!(
            store
                .get_agent_classification("agent-a")
                .await
                .unwrap()
                .is_none()
        );

        let first = StoredAgentClassification {
            agent_id: "agent-a".to_string(),
            machine_class: "MacDev".to_string(),
            suggestion_id: Some("sug-1".to_string()),
            note: Some("人看过".to_string()),
            decided_by: "admin".to_string(),
            decided_at: "2026-09-23T00:00:00Z".to_string(),
        };
        store.upsert_agent_classification(&first).await.unwrap();
        assert_eq!(
            store.get_agent_classification("agent-a").await.unwrap(),
            Some(first.clone())
        );

        // 改判即覆盖（一台一条）。
        let second = StoredAgentClassification {
            machine_class: "MacDaily".to_string(),
            suggestion_id: None,
            ..first
        };
        store.upsert_agent_classification(&second).await.unwrap();
        assert_eq!(
            store.get_agent_classification("agent-a").await.unwrap(),
            Some(second)
        );

        // 覆盖度：库里没有 agents 行 → total 0，但已判定 1 台（不崩、不自相矛盾）。
        let coverage = store.purpose_coverage().await.unwrap();
        assert_eq!(coverage.total_agents, 0);
        assert_eq!(coverage.classified_agents, 1);
        assert_eq!(coverage.by_class, vec![("MacDaily".to_string(), 1)]);
    }

    #[tokio::test]
    async fn stores_agent_install_package_address() {
        let store = store().await;
        // 未设置过时为 None（调用方回落到内置默认地址）。
        assert!(store.get_agent_install_package().await.unwrap().is_none());

        let setting = StoredAgentInstallPackageAddress {
            address_id: DEFAULT_INSTALL_PACKAGE_SETTING_ID.to_string(),
            package_url: "https://mirror.example.com/agentd.tar.gz".to_string(),
            package_sha256: Some("sha256:abc".to_string()),
            updated_by: "platform-eng".to_string(),
            updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        };
        store.upsert_agent_install_package(&setting).await.unwrap();

        let loaded = store
            .get_agent_install_package()
            .await
            .unwrap()
            .expect("setting");
        assert_eq!(loaded.package_url, setting.package_url);
        assert_eq!(loaded.package_sha256, setting.package_sha256);
        assert_eq!(loaded.updated_by, "platform-eng");

        // 单例覆盖写入。
        let updated = StoredAgentInstallPackageAddress {
            package_url: "https://other.example.com/agentd.tar.gz".to_string(),
            ..setting.clone()
        };
        store.upsert_agent_install_package(&updated).await.unwrap();
        let loaded = store
            .get_agent_install_package()
            .await
            .unwrap()
            .expect("setting");
        assert_eq!(
            loaded.package_url,
            "https://other.example.com/agentd.tar.gz"
        );
    }

    #[tokio::test]
    async fn stores_agent_install_package_history() {
        let store = store().await;
        // 未录入过时为空列表（而不是报错）。
        assert!(
            store
                .list_agent_install_packages()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .get_agent_install_package_by_id("pkg-missing")
                .await
                .unwrap()
                .is_none()
        );

        let first = StoredAgentInstallPackage {
            package_id: "pkg-0000000000000001".to_string(),
            source: "/tmp/agentd-0.1.9.tar.gz".to_string(),
            package_sha256: "sha256:aaa".to_string(),
            version: "0.1.9".to_string(),
            arch: "aarch64-apple-darwin".to_string(),
            cached_path: "/state/install-package/history/pkg-0000000000000001".to_string(),
            created_by: "platform-eng".to_string(),
            created_at: "2026-01-01T00:00:00+00:00".to_string(),
        };
        store
            .upsert_agent_install_package_by_id(&first)
            .await
            .unwrap();
        let loaded = store
            .get_agent_install_package_by_id(&first.package_id)
            .await
            .unwrap()
            .expect("history entry");
        assert_eq!(loaded.source, first.source);
        assert_eq!(loaded.package_sha256, first.package_sha256);
        assert_eq!(loaded.version, "0.1.9");
        assert_eq!(loaded.arch, "aarch64-apple-darwin");
        assert_eq!(loaded.created_by, "platform-eng");

        // 同 package_id 再写覆盖同一行（内容寻址幂等）。
        let updated = StoredAgentInstallPackage {
            source: "https://mirror.example.com/agentd-0.1.9.tar.gz".to_string(),
            created_at: "2026-01-02T00:00:00+00:00".to_string(),
            ..first.clone()
        };
        store
            .upsert_agent_install_package_by_id(&updated)
            .await
            .unwrap();
        let list = store.list_agent_install_packages().await.unwrap();
        assert_eq!(list.len(), 1, "same package_id must stay one row");
        assert_eq!(list[0].source, updated.source);

        // 新包排前面（created_at DESC）。
        let second = StoredAgentInstallPackage {
            package_id: "pkg-0000000000000002".to_string(),
            created_at: "2026-01-03T00:00:00+00:00".to_string(),
            ..first.clone()
        };
        store
            .upsert_agent_install_package_by_id(&second)
            .await
            .unwrap();
        let list = store.list_agent_install_packages().await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].package_id, second.package_id);
        assert_eq!(list[1].package_id, first.package_id);
    }

    #[tokio::test]
    async fn stores_agent_uplink_address() {
        let store = store().await;
        // 未设置过时为 None（调用方按「不下发上送段」处理）。
        assert!(store.get_agent_uplink().await.unwrap().is_none());

        let setting = StoredAgentUplinkAddress {
            setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
            host: "10.0.1.9".to_string(),
            port: 9000,
            updated_by: "platform-eng".to_string(),
            updated_at: "2026-01-01T00:00:00+00:00".to_string(),
        };
        store.upsert_agent_uplink(&setting).await.unwrap();

        let loaded = store.get_agent_uplink().await.unwrap().expect("setting");
        assert_eq!(loaded.host, "10.0.1.9");
        assert_eq!(loaded.port, 9000);
        assert_eq!(loaded.updated_by, "platform-eng");

        // 单例覆盖写入（端口也要跟着换）。
        let updated = StoredAgentUplinkAddress {
            host: "10.0.2.10".to_string(),
            port: 9100,
            ..setting.clone()
        };
        store.upsert_agent_uplink(&updated).await.unwrap();
        let loaded = store.get_agent_uplink().await.unwrap().expect("setting");
        assert_eq!(loaded.host, "10.0.2.10");
        assert_eq!(loaded.port, 9100);
    }

    #[tokio::test]
    async fn rejects_token_bound_to_another_tenant() {
        let store = store().await;
        let mut foreign = token("hash-tenant", 1);
        foreign.tenant_id = "tenant-other".to_string();
        store.insert_enrollment_token(&foreign).await.unwrap();

        // 安装路径：租户不匹配必须被拦住（回归保护）。
        let validated = store
            .validate_bootstrap_token(&bootstrap("hash-tenant"))
            .await
            .unwrap();
        assert_eq!(
            validated,
            Err(EnrollmentTokenRejection::EnvironmentMismatch)
        );

        // 注册路径：同样不可预留，且不消费该 token。
        let reserved = store
            .reserve_enrollment_token(&reserve("hash-tenant", "agent-1"))
            .await
            .unwrap();
        assert_eq!(reserved, Err(ReservationRejection::InvalidToken));
        let untouched = store
            .get_enrollment_token("hash-tenant")
            .await
            .unwrap()
            .expect("token");
        assert_eq!(untouched.status, StoredEnrollmentTokenStatus::Active);
        assert_eq!(untouched.used_count, 0);
    }

    // ── L1a 机械资产清单 ───────────────────────────────────────────────

    fn entry(agent_id: &str, key: &str, kind: &str, path: &str) -> StoredSoftwareEntry {
        StoredSoftwareEntry {
            agent_id: agent_id.to_string(),
            software_key: key.to_string(),
            name: "demo".to_string(),
            kind: kind.to_string(),
            matched_rule: "test".to_string(),
            path: path.to_string(),
            received_at: "2026-09-22T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn replaces_software_inventory_instead_of_appending() {
        // 清单是摘要的**投影**：上次有、这次没有的路径必须消失，否则「哪些机器装了 X」
        // 会永久多出幽灵条目，而页面上看不出来（只是多一行）。
        let store = store().await;
        store
            .replace_agent_software_inventory(
                "agent-a",
                &[
                    entry(
                        "agent-a",
                        "/Applications/Firefox.app",
                        "app",
                        "/Applications/Firefox.app/Contents/MacOS/firefox",
                    ),
                    entry("agent-a", "/usr/bin/true", "binary", "/usr/bin/true"),
                ],
            )
            .await
            .unwrap();
        assert!(store.agent_has_software_inventory("agent-a").await.unwrap());

        let written = store
            .replace_agent_software_inventory(
                "agent-a",
                &[entry("agent-a", "/usr/bin/true", "binary", "/usr/bin/true")],
            )
            .await
            .unwrap();
        assert_eq!(written, 1);

        let entries = store.list_agent_software("agent-a").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].software_key, "/usr/bin/true");

        // 不同 agent 互不干扰：一个 agent 的重建不得清掉另一个的。
        store
            .replace_agent_software_inventory(
                "agent-b",
                &[entry(
                    "agent-b",
                    "/usr/bin/false",
                    "binary",
                    "/usr/bin/false",
                )],
            )
            .await
            .unwrap();
        store
            .replace_agent_software_inventory("agent-a", &[])
            .await
            .unwrap();
        assert_eq!(store.list_agent_software("agent-a").await.unwrap().len(), 0);
        assert_eq!(store.list_agent_software("agent-b").await.unwrap().len(), 1);
        assert!(!store.agent_has_software_inventory("agent-a").await.unwrap());
    }

    #[tokio::test]
    async fn summarizes_and_groups_software_inventory() {
        let store = store().await;
        // 同一 `.app` 两个可执行文件 → 一个键（`software_key`），两条路径（`path`）。
        store
            .replace_agent_software_inventory(
                "agent-a",
                &[
                    entry("agent-a", "/Applications/Firefox.app", "app", "firefox"),
                    entry(
                        "agent-a",
                        "/Applications/Firefox.app",
                        "app",
                        "plugin-container",
                    ),
                    entry("agent-a", "/usr/bin/true", "binary", "/usr/bin/true"),
                ],
            )
            .await
            .unwrap();
        // agent-b 持有同一 `.app`（另一条路径）→ 该键应算 2 台机器。
        store
            .replace_agent_software_inventory(
                "agent-b",
                &[entry(
                    "agent-b",
                    "/Applications/Firefox.app",
                    "app",
                    "firefox",
                )],
            )
            .await
            .unwrap();

        let summary = store.summarize_agent_software("agent-a").await.unwrap();
        assert_eq!(summary.paths, 3);
        assert_eq!(summary.apps, 2);
        assert!(store.agent_has_software_inventory("agent-a").await.unwrap());

        // 键总数 2（Firefox.app / /usr/bin/true），但 holder 行数是 4。
        assert_eq!(store.count_software_keys().await.unwrap(), 2);
        let holdings = store.list_software_holdings(10).await.unwrap();
        assert_eq!(holdings.len(), 2);
        // 排序按「持有机器数降序」：Firefox.app 有 2 台，必须排第一。
        assert_eq!(holdings[0].software_key, "/Applications/Firefox.app");
        assert_eq!(holdings[0].holders.len(), 3);
        let mut agents: Vec<&str> = holdings[0]
            .holders
            .iter()
            .map(|holder| holder.agent_id.as_str())
            .collect();
        agents.sort_unstable();
        agents.dedup();
        assert_eq!(agents, vec!["agent-a", "agent-b"]);

        // limit 生效，并且调用方据此能知道截断了。
        let one = store.list_software_holdings(1).await.unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].software_key, "/Applications/Firefox.app");
    }

    fn standing(work_id: &str, agent_id: &str, family: &str, plan_version: i64) -> StandingWork {
        StandingWork {
            work_id: work_id.to_string(),
            agent_id: agent_id.to_string(),
            family: family.to_string(),
            spec: "unit-a".to_string(),
            catalog_version: 1,
            proposal_id: None,
            plan_version,
            effective_from: "2026-09-23T00:00:00Z".to_string(),
            status: "active".to_string(),
            updated_by: "admin".to_string(),
            updated_at: "2026-09-23T00:00:00Z".to_string(),
        }
    }

    fn one_shot(work_id: &str, agent_id: &str, status: &str) -> StoredOneShotWork {
        StoredOneShotWork {
            work: OneShotWork {
                work_id: work_id.to_string(),
                agent_id: agent_id.to_string(),
                action: "upgrade".to_string(),
                spec: "0.1.4".to_string(),
                scheduled_at: "2026-09-23T00:00:00Z".to_string(),
                deadline_at: "2026-09-24T00:00:00Z".to_string(),
                timeout_seconds: 600,
                interruptible: true,
                status: status.to_string(),
                paused_at: Some("2026-09-23T00:10:00Z".to_string()),
                paused_total_seconds: 42,
                current_step: Some("install".to_string()),
                completed_steps: vec!["download".to_string()],
                attempt: 1,
                issued_by: "admin".to_string(),
                issued_at: "2026-09-23T00:00:00Z".to_string(),
            },
            pre_pause_status: Some("running".to_string()),
        }
    }

    #[tokio::test]
    async fn stores_standing_work_per_work_id_and_lists_it_per_agent() {
        let store = store().await;
        assert!(store.get_standing_work("work-a").await.unwrap().is_none());

        store
            .save_standing_work(&standing("work-a", "agent-a", "HostMetrics", 1))
            .await
            .unwrap();
        store
            .save_standing_work(&standing("work-b", "agent-a", "LoginSession", 1))
            .await
            .unwrap();
        store
            .save_standing_work(&standing("work-c", "agent-b", "HostMetrics", 1))
            .await
            .unwrap();

        // 同一 work_id 再存一次 = 改这一份，不是多出一份。
        store
            .save_standing_work(&standing("work-a", "agent-a", "HostMetrics", 2))
            .await
            .unwrap();

        let loaded = store.get_standing_work("work-a").await.unwrap().unwrap();
        assert_eq!(loaded.plan_version, 2);

        // 按 agent 取，且**全量**（含暂停/已撤回 —— 留痕要看得到）。
        let mut revoked = standing("work-b", "agent-a", "LoginSession", 2);
        revoked.status = "revoked".to_string();
        store.save_standing_work(&revoked).await.unwrap();

        let works = store.list_standing_work("agent-a").await.unwrap();
        assert_eq!(works.len(), 2);
        assert_eq!(works[0].family, "HostMetrics");
        assert_eq!(works[1].status, "revoked");
        assert_eq!(store.list_standing_work("agent-b").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn outstanding_one_shot_listing_covers_the_fleet_and_skips_terminal_work() {
        let store = store().await;
        store
            .save_one_shot_work(&one_shot("work-run", "agent-a", "running"))
            .await
            .unwrap();
        store
            .save_one_shot_work(&one_shot("work-done", "agent-b", "succeeded"))
            .await
            .unwrap();

        // 跨 agent 一次取齐（到期判定要扫全机队），但**只带未了结的**。
        let outstanding = store.list_outstanding_one_shot_work().await.unwrap();
        let ids: Vec<&str> = outstanding
            .iter()
            .map(|stored| stored.work.work_id.as_str())
            .collect();
        assert_eq!(ids, vec!["work-run"]);
    }

    #[tokio::test]
    async fn terminating_one_shot_work_never_overwrites_a_settled_one() {
        let store = store().await;
        store
            .save_one_shot_work(&one_shot("work-1", "agent-a", "running"))
            .await
            .unwrap();

        assert!(
            store
                .terminate_outstanding_one_shot_work("work-1", "expired")
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_one_shot_work("work-1")
                .await
                .unwrap()
                .unwrap()
                .work
                .status,
            "expired"
        );
        // 再推一次：已经终态了，不重复推（返回 false，状态不被改写）。
        assert!(
            !store
                .terminate_outstanding_one_shot_work("work-1", "timed_out")
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_one_shot_work("work-1")
                .await
                .unwrap()
                .unwrap()
                .work
                .status,
            "expired"
        );

        // agent 报的终态不会被覆盖：这正是用条件更新而不是先读后写的理由。
        store
            .save_one_shot_work(&one_shot("work-2", "agent-a", "succeeded"))
            .await
            .unwrap();
        assert!(
            !store
                .terminate_outstanding_one_shot_work("work-2", "expired")
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get_one_shot_work("work-2")
                .await
                .unwrap()
                .unwrap()
                .work
                .status,
            "succeeded"
        );
    }

    #[tokio::test]
    async fn round_trips_one_shot_work_including_the_pause_state_machine() {
        let store = store().await;
        let original = one_shot("work-1", "agent-a", "paused");
        store.save_one_shot_work(&original).await.unwrap();

        let loaded = store.get_one_shot_work("work-1").await.unwrap().unwrap();
        assert_eq!(loaded, original);
        // 布尔、JSON 数组、可空字段都得真的过得去（SQLite 没有布尔类型）。
        assert!(loaded.work.interruptible);
        assert_eq!(loaded.work.completed_steps, vec!["download".to_string()]);
        assert_eq!(loaded.work.current_step.as_deref(), Some("install"));
        assert_eq!(loaded.work.paused_total_seconds, 42);
        assert_eq!(loaded.pre_pause_status.as_deref(), Some("running"));

        // 终态也留在库里（快照会筛，审计要全）。
        let mut finished = original.clone();
        finished.work.status = "succeeded".to_string();
        finished.work.paused_at = None;
        finished.pre_pause_status = None;
        store.save_one_shot_work(&finished).await.unwrap();
        let works = store.list_one_shot_work("agent-a").await.unwrap();
        assert_eq!(works.len(), 1);
        assert_eq!(works[0].work.status, "succeeded");
        assert_eq!(works[0].pre_pause_status, None);
    }

    #[tokio::test]
    async fn work_sequence_is_monotonic_per_agent_and_starts_at_zero() {
        let store = store().await;
        // 从未授权过：0（而不是 1 —— 否则首个快照看起来也像“变过了”）。
        assert_eq!(store.work_sequence("agent-a").await.unwrap(), 0);

        assert_eq!(
            store
                .next_work_sequence("agent-a", "2026-09-23T00:00:00Z")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .next_work_sequence("agent-a", "2026-09-23T00:00:01Z")
                .await
                .unwrap(),
            2
        );
        // 另一个 agent 自己从 1 开始（序号是 per-agent 的）。
        assert_eq!(
            store
                .next_work_sequence("agent-b", "2026-09-23T00:00:02Z")
                .await
                .unwrap(),
            1
        );
        assert_eq!(store.work_sequence("agent-a").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn work_result_keeps_one_row_per_work() {
        let store = store().await;
        assert!(store.get_work_result("work-1").await.unwrap().is_none());

        store
            .upsert_work_result(&StoredWorkResult {
                work_id: "work-1".to_string(),
                agent_id: "agent-a".to_string(),
                status: "running".to_string(),
                detail: String::new(),
                reported_at: "2026-09-23T00:00:00Z".to_string(),
            })
            .await
            .unwrap();
        store
            .upsert_work_result(&StoredWorkResult {
                work_id: "work-1".to_string(),
                agent_id: "agent-a".to_string(),
                status: "failed".to_string(),
                detail: "digest mismatch".to_string(),
                reported_at: "2026-09-23T00:02:00Z".to_string(),
            })
            .await
            .unwrap();

        // 一份工作一条：只留最新那次上报（运维问的是“现在怎么样了”）。
        let result = store.get_work_result("work-1").await.unwrap().unwrap();
        assert_eq!(result.status, "failed");
        assert_eq!(result.detail, "digest mismatch");
        assert_eq!(result.reported_at, "2026-09-23T00:02:00Z");
    }

    #[tokio::test]
    async fn work_ack_keeps_one_row_per_work() {
        let store = store().await;
        assert!(store.get_work_ack("work-1").await.unwrap().is_none());

        store
            .upsert_work_ack(&StoredWorkAck {
                work_id: "work-1".to_string(),
                agent_id: "agent-a".to_string(),
                work_kind: "Standing".to_string(),
                plan_version: 1,
                acknowledged_at: "2026-09-23T00:00:00Z".to_string(),
            })
            .await
            .unwrap();
        store
            .upsert_work_ack(&StoredWorkAck {
                work_id: "work-1".to_string(),
                agent_id: "agent-a".to_string(),
                work_kind: "Standing".to_string(),
                plan_version: 2,
                acknowledged_at: "2026-09-23T00:01:00Z".to_string(),
            })
            .await
            .unwrap();

        // 一份工作一条：只留最新那次确认（漂移看的是“现在手上是哪一版”）。
        let ack = store.get_work_ack("work-1").await.unwrap().unwrap();
        assert_eq!(ack.plan_version, 2);
        assert_eq!(ack.acknowledged_at, "2026-09-23T00:01:00Z");
    }

    // ── 拒绝名单（吊销状态表，§5.6）──

    fn revocation(agent_id: &str, reason: &str, retain_in_days: i64) -> StoredAgentRevocation {
        StoredAgentRevocation {
            entry_id: format!("denylist-{agent_id}"),
            agent_id: agent_id.to_string(),
            reason_code: reason.to_string(),
            denied_by: "admin".to_string(),
            denied_at: now_rfc3339(),
            retain_until: (Utc::now() + chrono::Duration::days(retain_in_days)).to_rfc3339(),
        }
    }

    #[tokio::test]
    async fn revocation_blocks_only_the_listed_agent_and_lifts_cleanly() {
        let store = store().await;
        store
            .revoke_agent(&revocation("agent-live", "compromised", 30))
            .await
            .unwrap();

        assert!(store.is_agent_revoked("agent-live").await.unwrap());
        assert!(!store.is_agent_revoked("agent-other").await.unwrap());

        let entries = store.list_agent_revocations().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].agent_id, "agent-live");
        assert_eq!(entries[0].reason_code, "compromised");
        assert_eq!(entries[0].entry_id, "denylist-agent-live");

        assert!(store.lift_agent_revocation("agent-live").await.unwrap());
        assert!(!store.is_agent_revoked("agent-live").await.unwrap());
        // 再解除一次：本来就不在，返回 false（不把空操作当命中）。
        assert!(!store.lift_agent_revocation("agent-live").await.unwrap());
    }

    /// 过了 GC 水位的条目**不再拦**（即便行还在），且 `purge` 会把它真正删掉。
    #[tokio::test]
    async fn expired_revocations_stop_blocking_and_are_purged() {
        let store = store().await;
        store
            .revoke_agent(&revocation("agent-retired", "retired", -1))
            .await
            .unwrap();

        assert!(!store.is_agent_revoked("agent-retired").await.unwrap());
        assert!(store.list_agent_revocations().await.unwrap().is_empty());

        assert_eq!(store.purge_expired_agent_revocations().await.unwrap(), 1);
        // 清过之后没有残留（未过水位的不会被误删）。
        assert_eq!(store.purge_expired_agent_revocations().await.unwrap(), 0);
    }

    /// 重复吊销同一 agent：刷新原因与水位，不插重复行（一台 agent 一条）。
    #[tokio::test]
    async fn revoking_twice_refreshes_the_single_entry() {
        let store = store().await;
        store
            .revoke_agent(&revocation("agent-x", "first", 10))
            .await
            .unwrap();
        store
            .revoke_agent(&revocation("agent-x", "again", 20))
            .await
            .unwrap();

        let entries = store.list_agent_revocations().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason_code, "again");
    }

    /// 坏行（`retain_until` 不可解析）按**仍生效**处理：与 `credential_is_expired` 解析失败即判
    /// 过期同一口径（安全侧 fail-closed）。这类行不会被 `purge` 自然清掉，要放行只能走解除名单。
    #[tokio::test]
    async fn an_unparseable_retention_stays_enforcing_and_is_not_purged() {
        let store = store().await;
        store
            .revoke_agent(&StoredAgentRevocation {
                entry_id: "denylist-agent-bad".to_string(),
                agent_id: "agent-bad".to_string(),
                reason_code: "tampered".to_string(),
                denied_by: "admin".to_string(),
                denied_at: now_rfc3339(),
                retain_until: "not-a-timestamp".to_string(),
            })
            .await
            .unwrap();

        assert!(store.is_agent_revoked("agent-bad").await.unwrap());
        assert!(
            store
                .list_agent_revocations()
                .await
                .unwrap()
                .iter()
                .any(|entry| entry.agent_id == "agent-bad")
        );
        // `purge` 只清「可解析且已过水位」的，不动坏行。
        assert_eq!(store.purge_expired_agent_revocations().await.unwrap(), 0);
        assert!(store.is_agent_revoked("agent-bad").await.unwrap());
    }

    /// 列表按 `denied_at` 新的在前（页面默认看最近吊销的）。
    #[tokio::test]
    async fn revocation_list_is_newest_first() {
        let store = store().await;
        store
            .revoke_agent(&StoredAgentRevocation {
                entry_id: "denylist-old".to_string(),
                agent_id: "agent-old".to_string(),
                reason_code: "".to_string(),
                denied_by: "".to_string(),
                denied_at: "2026-01-01T00:00:00+00:00".to_string(),
                retain_until: "2026-12-01T00:00:00+00:00".to_string(),
            })
            .await
            .unwrap();
        store
            .revoke_agent(&StoredAgentRevocation {
                entry_id: "denylist-new".to_string(),
                agent_id: "agent-new".to_string(),
                reason_code: "".to_string(),
                denied_by: "".to_string(),
                denied_at: "2026-09-01T00:00:00+00:00".to_string(),
                retain_until: "2026-12-01T00:00:00+00:00".to_string(),
            })
            .await
            .unwrap();

        let entries = store.list_agent_revocations().await.unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|e| e.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["agent-new", "agent-old"]
        );
    }

    /// 证书状态里的「最近一次续签判定」能原样往返（JSON 列），且在下一份上报里被覆盖。
    #[tokio::test]
    async fn certificate_status_round_trips_the_last_renewal() {
        let store = store().await;
        // 先落一台 agent（证书状态表有外键指向 agents）。
        store
            .register_agent_from_certificate(&cert_registration(
                "agent-c",
                "cred-c",
                "fp-c",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ))
            .await
            .unwrap();
        let renewal = wist_contracts::gateway::AgentCredentialRenewal {
            outcome: "renewed".to_string(),
            checked_at: "2026-10-01T00:00:00+00:00".to_string(),
            detail: "credential renewed".to_string(),
            not_after: "2026-11-01T00:00:00+00:00".to_string(),
        };
        store
            .upsert_agent_certificate_status(&StoredAgentCertificateStatus {
                agent_id: "agent-c".to_string(),
                not_after: "2026-11-01T00:00:00+00:00".to_string(),
                remaining_seconds: 100,
                state: "valid".to_string(),
                last_renewal: Some(renewal.clone()),
                reported_at: "2026-10-01T00:00:00+00:00".to_string(),
            })
            .await
            .unwrap();

        let read = store
            .get_agent_certificate_status("agent-c")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.last_renewal.as_ref(), Some(&renewal));

        // 旧版本 agentd（不带 last_renewal）：**保留上一次**的值（与 local_work / uplink_state 同口径）——
        // 降级或本机台账一时读不到时，不该把已经看到的续签记录丢掉。
        store
            .upsert_agent_certificate_status(&StoredAgentCertificateStatus {
                agent_id: "agent-c".to_string(),
                not_after: "2026-11-01T00:00:00+00:00".to_string(),
                remaining_seconds: 100,
                state: "valid".to_string(),
                last_renewal: None,
                reported_at: "2026-10-01T01:00:00+00:00".to_string(),
            })
            .await
            .unwrap();
        let kept = store
            .get_agent_certificate_status("agent-c")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.last_renewal.as_ref(), Some(&renewal));
        // 必填子字段照常覆盖（只有可选的那份保留）。
        assert_eq!(kept.state, "valid");
    }

    // ── 知识库内容包（设计 §6.1）──

    fn knowledge_package(package_id: &str) -> StoredKnowledgePackage {
        StoredKnowledgePackage {
            package_id: package_id.to_string(),
            source: "/packages/wist-knowledge-0.1.0.tar.gz".to_string(),
            package_sha256: format!("sha256:{package_id}"),
            version: "0.1.0".to_string(),
            catalog_version: Some(2),
            template_version: Some(1),
            policy_version: Some(1),
            purpose_version: Some(1),
            parser_abi: 1,
            signed_by: String::new(),
            cached_path: format!("/state/knowledge/{package_id}"),
            created_by: "admin".to_string(),
            created_at: "2026-09-30T00:00:00Z".to_string(),
        }
    }

    fn knowledge_activation<'a>(package_id: &'a str, reason: &'a str) -> KnowledgeActivation<'a> {
        KnowledgeActivation {
            package_id,
            reason,
            requested_by: "admin",
            created_at: "2026-09-30T00:00:00Z",
        }
    }

    #[tokio::test]
    async fn activates_knowledge_with_monotonic_generations_and_an_audit_trail() {
        let store = store().await;
        // 从未激活过 = 空载，**不是**错误（设计 §8.5）。
        assert!(store.knowledge_active().await.unwrap().is_none());

        for package_id in ["kbp-a", "kbp-b"] {
            store
                .upsert_knowledge_package(&knowledge_package(package_id))
                .await
                .unwrap();
        }
        // 内容寻址幂等：同一个包重复录入落同一行。
        store
            .upsert_knowledge_package(&knowledge_package("kbp-a"))
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM knowledge_package")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);

        let first = store
            .activate_knowledge(&knowledge_activation("kbp-a", "activate"))
            .await
            .unwrap();
        assert_eq!((first.generation, first.package_id.as_str()), (1, "kbp-a"));
        let second = store
            .activate_knowledge(&knowledge_activation("kbp-b", "activate"))
            .await
            .unwrap();
        assert_eq!(second.generation, 2);
        // 回滚也是一次切换：世代继续往前走（**不是**回到 1）—— 否则"哪一代算的"会重复。
        let rolled = store
            .activate_knowledge(&knowledge_activation("kbp-a", "rollback"))
            .await
            .unwrap();
        assert_eq!(rolled.generation, 3);
        assert_eq!(
            store.knowledge_active().await.unwrap().unwrap().package_id,
            "kbp-a"
        );

        // 审计：三次切换各一条，首条的 `from_package` 为空（首次激活没有"从哪来"）。
        let log: Vec<(Option<String>, String, i64, String)> = sqlx::query_as(
            "SELECT from_package, to_package, generation, reason \
             FROM knowledge_activation_log ORDER BY id",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        assert_eq!(log.len(), 3);
        assert!(log[0].0.is_none());
        assert_eq!(log[0].1.as_str(), "kbp-a");
        assert_eq!((log[2].3.as_str(), log[2].2), ("rollback", 3));
    }
}
