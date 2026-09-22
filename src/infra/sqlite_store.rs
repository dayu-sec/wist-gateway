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
     i.memory_bytes, i.cpu_percent, i.admin_latency_ms, i.work_state_changes, \
     i.discovery_policy_version, \
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
                     admin_latency_ms, work_state_changes) \
                     VALUES (?1, ?2, '', ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .bind(&instance_id)
                .bind(&agent.agent_id)
                .bind(&agent.version)
                .bind(&registered_at)
                .bind(&last_seen_at)
                .bind(to_sql_int(agent.last_memory_bytes))
                .bind(agent.last_cpu_percent)
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

fn agent_from_row(row: &SqliteRow) -> StoreResult<StoredAgentRegistration> {
    let credential_status: String = column!(row, "credential_status");
    let work_state_changes: Option<String> = column!(row, "work_state_changes");
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
        last_admin_latency_ms: column!(row, "admin_latency_ms"),
        last_discovery_policy_version: column!(row, "discovery_policy_version"),
        work_state_changes: deserialize_work_state_changes(work_state_changes),
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
            // 实例行不存在则新建（Agentd 重启换 boot_id / instance_id 时保留历史）。
            sqlx::query(
                "INSERT INTO agent_instances (instance_id, agent_id, boot_id, version, \
                 started_at, last_seen_at, memory_bytes, cpu_percent, admin_latency_ms, \
                 work_state_changes, discovery_policy_version) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT (instance_id) DO UPDATE SET version = excluded.version, \
                 boot_id = CASE WHEN excluded.boot_id = '' THEN agent_instances.boot_id \
                 ELSE excluded.boot_id END, \
                 last_seen_at = excluded.last_seen_at, \
                 memory_bytes = excluded.memory_bytes, cpu_percent = excluded.cpu_percent, \
                 admin_latency_ms = excluded.admin_latency_ms, \
                 work_state_changes = excluded.work_state_changes, \
                 discovery_policy_version = excluded.discovery_policy_version",
            )
            .bind(&instance_id)
            .bind(update.agent_id)
            .bind(update.boot_id)
            .bind(update.version)
            .bind(update.last_seen_at)
            .bind(to_sql_int(update.memory_bytes))
            .bind(update.cpu_percent)
            .bind(to_sql_int(update.admin_latency_ms))
            .bind(work_state_changes)
            .bind(update.discovery_policy_version)
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

    async fn get_purpose_suggestion(
        &self,
        agent_id: &str,
    ) -> StoreResult<Option<StoredPurposeSuggestion>> {
        let row = sqlx::query(
            "SELECT agent_id, suggestion_id, suggested_class, confidence, method, rule_set_id, \
             signals, observed_at, computed_at \
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
             confidence, method, rule_set_id, signals, observed_at, computed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
             ON CONFLICT (agent_id) DO UPDATE SET suggestion_id = excluded.suggestion_id, \
             suggested_class = excluded.suggested_class, confidence = excluded.confidence, \
             method = excluded.method, rule_set_id = excluded.rule_set_id, \
             signals = excluded.signals, observed_at = excluded.observed_at, \
             computed_at = excluded.computed_at",
        )
        .bind(&suggestion.agent_id)
        .bind(&suggestion.suggestion_id)
        .bind(&suggestion.suggested_class)
        .bind(suggestion.confidence)
        .bind(&suggestion.method)
        .bind(&suggestion.rule_set_id)
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

fn purpose_suggestion_from_row(row: &SqliteRow) -> StoreResult<StoredPurposeSuggestion> {
    let signals: String = column!(row, "signals");
    Ok(StoredPurposeSuggestion {
        agent_id: column!(row, "agent_id"),
        suggestion_id: column!(row, "suggestion_id"),
        suggested_class: column!(row, "suggested_class"),
        confidence: column!(row, "confidence"),
        method: column!(row, "method"),
        rule_set_id: column!(row, "rule_set_id"),
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
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
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
                    admin_latency_ms: Some(7),
                    discovery_policy_version: None,
                    work_state_changes: None,
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
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
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
                admin_latency_ms: Some(7),
                discovery_policy_version: Some(2),
                work_state_changes: None,
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
                admin_latency_ms: None,
                discovery_policy_version: Some(0),
                work_state_changes: None,
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
}
