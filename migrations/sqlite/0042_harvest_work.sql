-- 云资产采集（harvest）的**工作授权**：worker / 证书 / standing / one_shot / ack / result / sequence。
--
-- 为什么不复用 agent 的 work 表（`0009_work_grant.sql`）：那四张表的列名、查询与页面
-- 都绑 `agent_id`，把采集器混进去会让机队视图出现「不是机器的行」。
-- 形状照抄，命名换成 harvest（设计见 `docs/design/harvest-work-grant.md` §5）。
--
-- 同一版删除旧的中心侧开关表（D5：不做兼容层）：采集指令改由 standing 下发，
-- 「开/关」= `status=active|paused`。

CREATE TABLE IF NOT EXISTS harvest_worker (
  worker_id     TEXT PRIMARY KEY,          -- harvest:<source_code>
  source_code   TEXT NOT NULL,
  instance_id   TEXT NOT NULL,
  -- pending | active | revoked
  status        TEXT NOT NULL,
  enrolled_at   TEXT NOT NULL,
  last_seen_at  TEXT,
  revoked_at    TEXT,
  revoked_by    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS harvest_credential (
  credential_id TEXT PRIMARY KEY,
  worker_id     TEXT NOT NULL,
  -- 吊销依据（CA 签出的序列号，小写 hex）
  cert_serial   TEXT NOT NULL,
  -- 证书 DER 的 SHA-256（小写 hex），页面展示与审计
  cert_sha256   TEXT NOT NULL,
  issued_at     TEXT NOT NULL,
  not_after     TEXT NOT NULL,
  revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_harvest_credential_worker ON harvest_credential (worker_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_harvest_credential_serial ON harvest_credential (cert_serial);

-- 常驻工作：一个 worker 一条（family = inventory）。
CREATE TABLE IF NOT EXISTS harvest_standing_work (
  work_id         TEXT PRIMARY KEY,
  worker_id       TEXT NOT NULL,
  family          TEXT NOT NULL,
  -- 结构化 spec 的 JSON（不是自由文本；由网关校验后才落库）
  spec            TEXT NOT NULL,
  catalog_version INTEGER NOT NULL DEFAULT 0,
  proposal_id     TEXT,
  -- 期望版本：每次改动 +1；harvest 回报实际版本，与它比对即得漂移
  plan_version    INTEGER NOT NULL,
  effective_from  TEXT NOT NULL,
  -- active | paused
  status          TEXT NOT NULL,
  updated_by      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_standing_worker
  ON harvest_standing_work (worker_id);

-- 一次性工作：本期（P1）网关不派，表先建好，P2 直接写。
CREATE TABLE IF NOT EXISTS harvest_one_shot_work (
  work_id              TEXT PRIMARY KEY,
  worker_id            TEXT NOT NULL,
  action               TEXT NOT NULL,
  spec                 TEXT NOT NULL,
  scheduled_at         TEXT NOT NULL,
  deadline_at          TEXT NOT NULL,
  timeout_seconds      INTEGER NOT NULL,
  interruptible        INTEGER NOT NULL,
  status               TEXT NOT NULL,
  paused_at            TEXT,
  pre_pause_status     TEXT,
  paused_total_seconds INTEGER NOT NULL DEFAULT 0,
  current_step         TEXT,
  completed_steps      TEXT NOT NULL DEFAULT '[]',
  attempt              INTEGER NOT NULL DEFAULT 0,
  issued_by            TEXT NOT NULL,
  issued_at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_one_shot_worker
  ON harvest_one_shot_work (worker_id, status);

-- 确认：回答「期望的版本真到了吗」（一份工作一条最新）
CREATE TABLE IF NOT EXISTS harvest_work_ack (
  work_id         TEXT PRIMARY KEY,
  worker_id       TEXT NOT NULL,
  work_kind       TEXT NOT NULL,           -- standing | one_shot
  plan_version    INTEGER NOT NULL,
  acknowledged_at TEXT NOT NULL
);

-- 执行结果：回答「做得怎么样」（P2 写入，P1 只建表）
CREATE TABLE IF NOT EXISTS harvest_work_result (
  work_id     TEXT PRIMARY KEY,
  worker_id   TEXT NOT NULL,
  status      TEXT NOT NULL,               -- running | succeeded | failed | timed_out | canceled | expired
  detail      TEXT NOT NULL DEFAULT '',
  reported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_result_worker ON harvest_work_result (worker_id);
CREATE INDEX IF NOT EXISTS idx_harvest_ack_worker ON harvest_work_ack (worker_id);

-- 授权序号：worker 据此判断快照有没有变化（不承担指令重放语义）
CREATE TABLE IF NOT EXISTS harvest_work_sequence (
  worker_id  TEXT PRIMARY KEY,
  sequence   INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

-- 一次性接入券：只存 sha256 摘要（与 wist-cred 同一口径）；券的明文只出现一次。
CREATE TABLE IF NOT EXISTS harvest_enrollment_ticket (
  ticket_hash TEXT PRIMARY KEY,
  worker_id   TEXT NOT NULL,
  source_code TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  consumed_at TEXT,
  created_by  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_ticket_worker ON harvest_enrollment_ticket (worker_id);

-- D5：旧开关同一版下线。**不删数据**：重命名保留为审计事实（现场还能查到
-- 「升级前采集是开还是关」）。注意没有自动合成 standing —— 升级后必须重新授权
-- （采集请求里的 source_code 属于本机配置，迁移无法替它决定）。
ALTER TABLE harvest_setting RENAME TO harvest_setting_removed_0042;
