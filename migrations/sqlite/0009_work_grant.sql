-- 工作授权（对应模型 Control.Agent.Work：StandingWork / OneShotWork / WorkGrant）
--
-- 为什么两张表而不是一张加 kind 列：两种工作的字段几乎不重叠
-- （常驻有 family/catalog_version/plan_version；一次性有 action/scheduled_at/deadline_at/
-- timeout_seconds/步级断点）。塞一张表就得让一半字段恒为 NULL，还得在每条查询里
-- 自己记住「哪些列对哪种 kind 有意义」—— 那正是约束该由表结构承担的部分。
--
-- 为什么不删行而用状态：`superseded`（被新版本取代）与 `revoked`（授权被撤）都是
-- **审计事实**，删了就答不出「这台机器上个月采过什么、谁撤的」。

CREATE TABLE IF NOT EXISTS standing_work (
  work_id         TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  -- CollectionFamily 裸名（与 content.rs 的 FAMILIES 同源）。
  family          TEXT NOT NULL,
  -- 工作参数：采集目录条目组成的清单（不是自由文本）。
  spec            TEXT NOT NULL,
  catalog_version INTEGER NOT NULL,
  -- 指向已批准的提案；人工直填 spec 时为空。
  proposal_id     TEXT,
  -- 期望版本：网关每次改动 +1。agentd 回报实际版本，与它比对即得漂移。
  plan_version    INTEGER NOT NULL,
  effective_from  TEXT NOT NULL,
  -- active | paused | superseded | revoked
  status          TEXT NOT NULL,
  updated_by      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_standing_work_agent ON standing_work (agent_id);

CREATE TABLE IF NOT EXISTS one_shot_work (
  work_id              TEXT PRIMARY KEY,
  agent_id             TEXT NOT NULL,
  action               TEXT NOT NULL,
  spec                 TEXT NOT NULL,
  scheduled_at         TEXT NOT NULL,
  -- 绝对截止：暂停也照走（不由暂停顺延）。
  deadline_at          TEXT NOT NULL,
  -- 执行预算（秒）：只在实际执行时消耗。
  timeout_seconds      INTEGER NOT NULL,
  -- 只有可中断的动作才允许运行中暂停。
  interruptible        INTEGER NOT NULL,
  -- dispatched | accepted | running | paused | succeeded | failed | timed_out | canceled | expired
  status               TEXT NOT NULL,
  paused_at            TEXT,
  -- 暂停前的状态：恢复要回到它，不能一律猜成 running。
  pre_pause_status     TEXT,
  -- 累计暂停时长（秒）：审计用，也是「预算未被暂停消耗」的核对依据。
  paused_total_seconds INTEGER NOT NULL DEFAULT 0,
  current_step         TEXT,
  -- JSON 数组：已完成步骤保留，恢复时 current_step 重做。
  completed_steps      TEXT NOT NULL DEFAULT '[]',
  attempt              INTEGER NOT NULL DEFAULT 0,
  issued_by            TEXT NOT NULL,
  issued_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_one_shot_work_agent ON one_shot_work (agent_id);

-- Agent 的确认回执：一份工作一条（最新一次），回答「期望的版本真到了吗」。
--
-- 为什么不并进两张工作表：确认是**Agent 侧的事实**，与工作自身的期望状态是两回事；
-- 并进去之后，就只有「更新工作」这一条路径能写确认，且看不出确认来自哪次拉取。
CREATE TABLE IF NOT EXISTS work_ack (
  work_id         TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  work_kind       TEXT NOT NULL,
  plan_version    INTEGER NOT NULL,
  acknowledged_at TEXT NOT NULL
);

-- 授权序号：Agent 据此判断快照有没有变化（不承担「指令重放」语义）。
--
-- 单调递增而不是「按更新时间取最大值」：同一秒内的两次改动也要能被区分，
-- 否则「改了什么」会变成无法判定的事。
CREATE TABLE IF NOT EXISTS agent_work_sequence (
  agent_id   TEXT PRIMARY KEY,
  sequence   INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
