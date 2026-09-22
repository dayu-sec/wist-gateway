-- Agent 事实摘要（agentd → 网关，控制面）与由此算出的用途建议
--
-- 为什么放网关库：摘要只服务用途推断（网关侧按规则表算），去重后 10~30 KB，
-- 与控制面其它状态同量级。原文快照（一台几百 KB）走数据面给中心做资产整理，
-- **不进本库** —— 这是架构级约束，不是实现细节。
--
-- 覆盖式：一台 Agent 一行（PRIMARY KEY agent_id）。网关不需要事实的时间序列，
-- 要历史是中心资产整理的事。
--
-- 幂等键是 content_digest，不是 revision：revision 每轮 refresh 无条件 +1，
-- 拿它判重等于每轮都算新的。

CREATE TABLE IF NOT EXISTS agent_fact_summary (
  agent_id            TEXT PRIMARY KEY,
  -- 内容摘要：事实上报的幂等键。
  content_digest      TEXT NOT NULL,
  -- 仅留痕，不参与判重。
  revision            INTEGER NOT NULL,
  observed_at         TEXT NOT NULL,
  os                  TEXT NOT NULL,
  arch                TEXT NOT NULL,
  -- 去重前的进程条数（去重会毁掉基数，留一个原始计数备查）。
  process_count       INTEGER NOT NULL,
  -- JSON 数组，已去重。
  process_executables TEXT NOT NULL,
  -- JSON 数组（仅 linux；macOS 侧待定）。
  packages            TEXT NOT NULL,
  -- JSON 数组。
  listen_ports        TEXT NOT NULL,
  received_at         TEXT NOT NULL
);

-- 用途建议：按规则表从事实摘要算出，**可变可过期**（改规则或来新事实即重算）。
-- 人工判定（模型 AgentClassification）要等管理面实现，不在此表。
CREATE TABLE IF NOT EXISTS agent_purpose_suggestion (
  agent_id        TEXT PRIMARY KEY
                  REFERENCES agent_fact_summary (agent_id) ON DELETE CASCADE,
  suggestion_id   TEXT NOT NULL,
  -- MachineClass 裸名（MacDaily / MacDev / LinuxCompute / LinuxData）。
  suggested_class TEXT NOT NULL,
  -- 0..100。
  confidence      INTEGER NOT NULL,
  -- rule | model（模型线在中心）。
  method          TEXT NOT NULL,
  rule_set_id     TEXT,
  -- JSON 数组：逐条命中依据，回答"凭什么这么判"。
  signals         TEXT NOT NULL,
  -- 依据哪一版事实算的（事实的时间），与算的时刻区分开。
  observed_at     TEXT NOT NULL,
  computed_at     TEXT NOT NULL
);
