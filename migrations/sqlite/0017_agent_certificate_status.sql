-- ── Agent 客户端证书状态（mTLS）──
-- 由 agent 在状态上报里带上（`AgentStatusReport.certificate_status`）：证书与到期时间
-- 只有本机知道（服务端在握手期就验完了，而且**过期证书根本进不来**）。
-- 「哪些机器快到期 / 已过期需重装」正是运维要提前看到的（docs/design/agent-identity-mtls.md §5.5）。
--
-- 一台 agent 一条「最近一次上报」——与 agent_uplink_state / agent_local_work 同口径。
CREATE TABLE IF NOT EXISTS agent_certificate_status (
  agent_id          TEXT PRIMARY KEY REFERENCES agents (agent_id) ON DELETE CASCADE,
  not_after         TEXT NOT NULL,
  remaining_seconds INTEGER NOT NULL,
  state             TEXT NOT NULL,
  reported_at       TEXT NOT NULL
);
