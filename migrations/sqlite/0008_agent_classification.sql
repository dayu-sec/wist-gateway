-- 用途的人工判定（对应模型 Control.Agent.Purpose.AgentClassification）
--
-- 一台机器一条：改判即更新（覆盖），判定人与时间留痕（`decided_by` / `decided_at`）。
-- 为什么与建议分表：`agent_purpose_suggestion` 是**机器算的、可变可过期**的；
-- 判定是**人定的、要留痕**的。两者会并存且不一致（以判定为准，但并列展示），
-- 合并成一张表就再也说不清「这一版是谁的意思」。
--
-- 判定是授权工作模板的前置（采集范围 = 合规边界），所以它必须独立持久化、可追溯。

CREATE TABLE IF NOT EXISTS agent_classification (
  agent_id      TEXT PRIMARY KEY,
  -- MachineClass 裸名（MacDaily / MacDev / LinuxCompute / LinuxData）。
  machine_class TEXT NOT NULL,
  -- 采纳了哪次建议；人工直判/推翻建议时为空。
  suggestion_id TEXT,
  note          TEXT,
  -- 谁判的、什么时候（网关只校验共享 admin token，暂无主体身份，先记 "admin"）。
  decided_by    TEXT NOT NULL,
  decided_at    TEXT NOT NULL
);
