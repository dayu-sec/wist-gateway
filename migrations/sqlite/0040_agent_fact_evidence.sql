-- Agent 事实摘要补「推断证据」两列（agentd → 网关）
--
-- 为什么加：选择类 label `app` 只允许从**高置信度来源**取值（规范 §3.4 规则 3）。
-- 本阶段可信的来源有两个，都由 agentd 采集、随摘要上送：
--
--   * `service_units`：进程 cgroup 路径里的 systemd 单元（已归一：去掉 `.service` 等
--     类型后缀、`foo@实例` 归到 `foo`、小写）。部署者命名的，不是从可执行名猜的。
--   * `container_names`：容器名（k8s 下就是 pod spec 里的容器名）。
--
-- 为什么进 content_digest：证据变了但摘要不变，网关会把这份报表当 `duplicate` 丢掉，
-- 于是指标永远带着旧 `app`，而没有任何一层能发现。`FactContent` 随之升到 `fact-v4`。
--
-- 为什么是 JSON 数组列而不是子表：读路径永远要「这台机器的全部证据」一次性拿到，
-- 没有「按证据反查机器」的需求（`app` 的查询走指标序列本身）。
--
-- 覆盖式：行随 ON CONFLICT (agent_id) DO UPDATE 更新，只需加列，无需回填历史。

ALTER TABLE agent_fact_summary ADD COLUMN service_units TEXT NOT NULL DEFAULT '[]';
ALTER TABLE agent_fact_summary ADD COLUMN container_names TEXT NOT NULL DEFAULT '[]';
