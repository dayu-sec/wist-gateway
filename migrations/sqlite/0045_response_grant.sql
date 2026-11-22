-- 执行计划的**响应授权单**（时间窗授权）。
--
-- 为什么要有这张表：审批是「人批了这一份计划」，一次一审；可运维里大量动作是
-- 重复的只读/低风险操作（看进程、读日志、清已轮转日志），每次都要人点一下不现实。
-- 授权单 = **提前批发出去的审批权**：给某台机器一段**有期限**的授权窗口，
-- 窗口内满足风险上限的动作可以直接下发。
--
-- 三条关键语义：
--
--   1. **必须有期限**（`not_after` 非空）。禁止无限期授权 —— 那就是「永久免审」，
--      等于把审批形同虚设。
--   2. **到期自动失效**：判定时比较时间，不靠定时任务清理（没有清理 = 没有漏清）。
--   3. **发放是审计动作**：谁给的（`granted_by`）、为什么（`reason`）、什么时候（`granted_at`）、
--      撤销时间（`revoked_at`）都要留下。撤销是软删，不物理删行。
--
-- 与 `action_approval` 的关系：两条**并列**的授权来源。
--   * `action_approval` → 一次一审（绑 `plan_digest`）；
--   * `response_grant`   → 窗口内放行（绑 `agent_id` + 风险上限 + opcode 白名单）。
-- 下发时网关先看授权单、再看审批，全都没有就拒（见 `api/action_plans.rs`）。

CREATE TABLE IF NOT EXISTS response_grant (
  -- 一台机器同一时刻只有一张生效的授权单；重新签发 = 覆盖（并换新的 `grant_id`）。
  agent_id     TEXT PRIMARY KEY,
  -- 每张授权单实例的号（`grn_<agent>_<micros>_<rand4>`）。进 attestation 的
  -- `approval.approval_id` 与计划的 `constraints.approval_ref`，审计可回溯到"哪一次授权"。
  grant_id     TEXT NOT NULL,
  -- 风险上限（wire 名 `R0`..`R3`）。一期由 API 限制在 R2。
  max_risk     TEXT NOT NULL,
  -- 可选 opcode 白名单（JSON 数组）；NULL = 不按 op 收窄（仍受 `max_risk` 约束）。
  opcodes_json TEXT,
  not_before   TEXT NOT NULL,
  not_after    TEXT NOT NULL,
  reason       TEXT,
  -- `admin:<token 指纹>`。
  granted_by   TEXT NOT NULL,
  granted_at   TEXT NOT NULL,
  -- 非空 = 已撤销（软删，保留审计）。
  revoked_at   TEXT
);
