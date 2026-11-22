-- 执行计划的**审批单**与**投票**（E3 / 响应能力 B 线）。
--
-- 为什么审批单独落两张表，而不是复用 `agent_commands`：
--
--   * `agent_commands` 是「发给这台机器的一条命令」，生命周期是**投递**（入队 → 认领 → ack）；
--   * 审批是「人同意了这个变更」，生命周期是**决策**（待批 → 够人 → 签发 → 下发），
--     而且必须在投递之前完成。混进命令表会让「还没批」和「还没送到」看起来一样。
--
-- 两条关键语义：
--
--   1. **审批绑摘要，不绑 action_id**。审批的语义是「批准了**这一份**」；
--      `plan_json` 存审批时的原文，签发时重算摘要比对，不一致 = 审批后被改过（重走审批）。
--   2. **投票人来自鉴权身份**，不接受客户端自填（见 `api/action_approvals.rs`）。
--      `(approval_id, approver)` 唯一：同一个人改主意是覆盖，不是加一票。

CREATE TABLE IF NOT EXISTS action_approval (
  approval_id        TEXT PRIMARY KEY,
  agent_id           TEXT NOT NULL,
  -- 提交审批时算出的内容摘要（`plan-v1:sha256:<hex>`）。
  plan_digest        TEXT NOT NULL,
  -- 契约的 wire 名：`R0` / `R1` / `R2` / `R3`。
  risk_level         TEXT NOT NULL,
  requested_by       TEXT NOT NULL,
  reason             TEXT,
  requested_at       TEXT NOT NULL,
  -- 提交审批时的计划原文（防「审批后改内容再签发」）。
  plan_json          TEXT NOT NULL,
  -- 这张单需要几个人批；提交时按风险等级定下，之后不可改。
  required_approvers INTEGER NOT NULL,
  -- `pending` | `approved` | `rejected` | `expired`。
  status             TEXT NOT NULL,
  approved_at        TEXT,
  -- 审批单自身的过期时刻；过了不能再投票/签发。
  expires_at         TEXT NOT NULL,
  -- 签发后的完整计划（含 attestation）。NULL = 还没签发。
  issued_plan_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_action_approval_agent
  ON action_approval (agent_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS action_approval_vote (
  approval_id TEXT NOT NULL,
  approver    TEXT NOT NULL,
  -- `approve` | `reject`
  decision    TEXT NOT NULL,
  comment     TEXT,
  voted_at    TEXT NOT NULL,
  PRIMARY KEY (approval_id, approver)
);

CREATE INDEX IF NOT EXISTS idx_action_approval_vote_approval
  ON action_approval_vote (approval_id);
