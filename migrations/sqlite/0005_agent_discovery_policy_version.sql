-- Agent **实际生效**的发现方向策略版本（agentd → 网关，控制面）
--
-- 为什么放在 agent_instances（而不是 agents）：最近一次上报的运行态（memory_bytes /
--   cpu_percent / admin_latency_ms）都在这一行，「这台机器现在生效哪一版策略」同样是
--   **最近一次上报的快照**，不是身份属性。历史时序仍在 VictoriaMetrics，本库只保最新值。
--
-- 为什么可空：NULL = 这台机器还没拿到策略表（agentd 在用内建默认周期），必须与
--   version=0（确实生效了第 0 版）区分开。用 0 冒充「没拿到」会让运维把「从没拉过」
--   误判成「拉到过并生效」——而运维要回答的正是那句「我改了策略，哪些机器还没生效」。
--
-- 覆盖式：行随 ON CONFLICT (instance_id) DO UPDATE 更新，只需加列，无需回填历史。

ALTER TABLE agent_instances ADD COLUMN discovery_policy_version INTEGER;
