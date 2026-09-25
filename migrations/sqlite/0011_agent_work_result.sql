-- 一次性工作的**执行结果**（agentd → 网关，控制面）
--
-- 为什么单独一张表而不是往 one_shot_work 上加列：那张表是**授权的快照**（网关派了什么），
--   本表是**执行的事实**（机器上做成了没有）。两者由不同的人写、出错的代价也不同 ——
--   混在一行里，一次执行结果的上报就会改写授权记录。与 work_ack 同一个取舍。
--
-- 为什么一份工作一条（覆盖式）：运维要回答的是「这件活现在怎么样了」，
--   不是「它历史上报过几次」。过程细节在 agent 侧的 state/upgrade.json 与升级器日志里。
--
-- 为什么可空/可为空表：从没上报过 = 这一行不存在（不是空字符串）：
--   「还没报」与「报了但没写说明」是两回事。
CREATE TABLE IF NOT EXISTS agent_work_result (
  work_id     TEXT PRIMARY KEY,
  agent_id    TEXT NOT NULL,
  -- 取 AGENT_REPORTABLE_WORK_STATUSES：running | succeeded | failed（由接入端点校验）。
  status      TEXT NOT NULL,
  -- 人看的说明：失败原因原样带上（「摘要不符」「新版 60s 没起来，已回滚到 0.1.3」）。
  detail      TEXT NOT NULL DEFAULT '',
  reported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_work_result_agent ON agent_work_result (agent_id);
