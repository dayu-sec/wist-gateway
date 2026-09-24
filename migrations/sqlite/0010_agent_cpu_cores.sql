-- Agent 所在机器的逻辑核数（agentd → 网关，控制面）
--
-- 为什么放在 agent_instances（不是 agents）：`cpu_percent` 是**单核口径**（100% = 占满一个核，
--   多线程进程可 >100），只统计 agent 进程自身的 CPU 时间；口径核数与 memory/cpu/latency/
--   discovery_policy_version 同类 —— 都是**最近一次上报的运行态快照**，不是身份属性。
--   管理面拿它把单核口径换算成整机占比（`cpu_percent / cpu_cores`，0..100）再呈现。
--
-- 为什么可空：NULL = 老版本 agentd 没上报核数，必须与 `0`（确实报了 0，非法核数）区分开。
--   换算（除法）在核数为 NULL 或 0 时都必须返回「算不出」，不能除零、更不能默认成 0 ——
--   把「测不到」写成 0 会在页面上伪造出一段「整机空闲」的假读数。
--
-- 覆盖式：行随 ON CONFLICT (instance_id) DO UPDATE 更新，只需加列，无需回填历史。

ALTER TABLE agent_instances ADD COLUMN cpu_cores INTEGER;
