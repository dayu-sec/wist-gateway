-- Agent 事实摘要补「路径探测」两列（agentd → 网关，控制面）
--
-- 为什么加：采集单元的 `match` 需要判断「某个绝对路径在不在」（典型用例
--   `/var/log/sudo.log`：RHEL 默认有、Debian 需在 sudoers 里配 logfile）。
--   agentd 按网关随发现策略下发的白名单探测后上报。
--
-- 为什么是两列：
--   - `probed_paths`：**实际探测过**的路径（白名单）；
--   - `present_paths`：其中存在的那些（子集）。
--   只报存在项的话，空列表会同时意味着「没探测」与「探测了但不存在」，
--   `match` 的三态求值就退化成了二态（把「无法判定」说成「不满足」）。
--
-- 为什么进 content_digest：它们会改变派活结果（哪些单元进 spec），
--   必须参与变更检测；`FactContent` 的版本随之从 `fact-v1` 升到 `fact-v2`，
--   升级后每个 agent 会强制重报一次（这正是版本前缀要的语义）。
--
-- 覆盖式：行随 ON CONFLICT (agent_id) DO UPDATE 更新，只需加列，无需回填历史。

ALTER TABLE agent_fact_summary ADD COLUMN probed_paths TEXT NOT NULL DEFAULT '[]';
ALTER TABLE agent_fact_summary ADD COLUMN present_paths TEXT NOT NULL DEFAULT '[]';
