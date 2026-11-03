-- 网关下发给 agent 的一次性命令队列（一台可有多条，按 `command_id` 去重）。
--
-- 与 `standing_work` / 上送 / 策略这类**期望状态**分开：那些是可重拉的幂等快照，
-- 这里是**一次执行**的动作，有明确的 command_id、执行结果与“未被确认就重发”的语义。
--
-- 投递通道：agentd 每 3s 的状态上报，响应体（`AgentStatusAck.commands`）里带待执行命令；
-- agentd 在下一次上报里用 `command_acks` 回传结果，网关据此写 acked_at / outcome。
--
--   * 未确认（acked_at IS NULL）才会下发；
--   * 同 kind 可以“覆盖式入队”（旧命令标成 superseded，避免重复点击排出一串）；
--   * 行不因网关重启丢失，离线机器上线后仍能拿到（过期由 agent 侧按 requested_at_ms 判）。

CREATE TABLE IF NOT EXISTS agent_commands (
  command_id      TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  -- 命令词表（wist_api::status::command_kind），如 refresh_facts。
  kind            TEXT NOT NULL,
  -- 命令参数（JSON 文本；空 = 无参数）。
  params          TEXT NOT NULL DEFAULT '',
  requested_at_ms INTEGER NOT NULL,
  -- agent 回传结果的时刻；NULL = 还没处理。
  acked_at        TEXT,
  -- 见 wist_api::status::command_outcome（网关侧另有 superseded）。
  outcome         TEXT,
  detail          TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_commands_pending
  ON agent_commands (agent_id, acked_at, requested_at_ms);
