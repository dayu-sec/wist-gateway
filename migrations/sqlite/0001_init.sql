-- 控制平台持久化 schema（SQLite）
--
-- 与静态模型 static/control/module/agent/* 的分层对齐：注册 token、Agent 身份、
-- Agent 实例、Agent 凭据各自独立成表，不再像早期单文件存储那样把身份/实例/凭据
-- 压成一行。
--
-- 约定：
--   * 时间列统一 TEXT + RFC3339（与 HTTP 契约、VictoriaMetrics 口径一致）；
--   * 状态列统一小写 snake_case（active/reserved/used/expired/revoked/...）；
--   * 明文 token 从不落库，只存 sha256。
--
-- 由 sqlx::migrate! 在启动时执行（记在 _sqlx_migrations 表），不再依赖
-- 数据库卷首次初始化——新增列/表在已有库上也会生效。

-- ── AgentEnrollment ──
-- 注册 token：主键是 token_id（可审计），token_hash 唯一索引用于按明文查找。
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_id              TEXT PRIMARY KEY,
  token_hash            TEXT NOT NULL UNIQUE,
  tenant_id             TEXT NOT NULL,
  environment_id        TEXT NOT NULL,
  issued_by             TEXT NOT NULL DEFAULT '',
  allowed_node_selector TEXT,
  max_uses              INTEGER NOT NULL DEFAULT 1,
  used_count            INTEGER NOT NULL DEFAULT 0,
  status                TEXT NOT NULL DEFAULT 'active',
  issued_at             TEXT NOT NULL,
  expires_at            TEXT NOT NULL,
  reserved_at           TEXT,
  revoked_at            TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_status
  ON enrollment_tokens (status, expires_at);

-- ── AgentIdentity ──
-- current_instance_id / current_credential_id 指向「当前」实例与凭据，
-- 历史留在各自表里（一个 Agent 可有多实例、多凭据）。
CREATE TABLE IF NOT EXISTS agents (
  agent_id             TEXT PRIMARY KEY,
  tenant_id            TEXT NOT NULL,
  environment_id       TEXT NOT NULL,
  node_id              TEXT NOT NULL DEFAULT '',
  hostname             TEXT NOT NULL DEFAULT '',
  machine_id           TEXT NOT NULL DEFAULT '',
  status               TEXT NOT NULL DEFAULT 'active',
  current_instance_id  TEXT,
  current_credential_id TEXT,
  registered_at        TEXT NOT NULL,
  updated_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant_env
  ON agents (tenant_id, environment_id);

-- ── AgentInstance ──
-- 每次 Agentd 重启/换 boot_id 是一条新记录，不再覆盖旧的 instance_id。
-- 最近一次上报的指标与工作状态变化落在本表（历史时序仍在 VictoriaMetrics）。
CREATE TABLE IF NOT EXISTS agent_instances (
  instance_id        TEXT PRIMARY KEY,
  agent_id           TEXT NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
  boot_id            TEXT NOT NULL DEFAULT '',
  version            TEXT NOT NULL DEFAULT '',
  started_at         TEXT NOT NULL,
  last_seen_at       TEXT NOT NULL,
  memory_bytes       INTEGER,
  cpu_percent        REAL,
  admin_latency_ms   INTEGER,
  work_state_changes TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_instances_agent
  ON agent_instances (agent_id, last_seen_at DESC);

-- ── CredentialBundle ──
-- 凭据可轮换、可吊销：轮换新增一行并更新 agents.current_credential_id，
-- 吊销把 status 置 revoked 并记 revoked_at（早期实现只有一个枚举值从未写入）。
CREATE TABLE IF NOT EXISTS agent_credentials (
  credential_id TEXT PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
  instance_id   TEXT NOT NULL DEFAULT '',
  auth_scheme   TEXT NOT NULL DEFAULT 'bearer',
  token_hash    TEXT NOT NULL UNIQUE,
  status        TEXT NOT NULL DEFAULT 'active',
  issued_at     TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  revoked_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent
  ON agent_credentials (agent_id, issued_at DESC);
