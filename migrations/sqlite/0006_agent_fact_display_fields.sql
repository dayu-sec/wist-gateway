-- Agent 事实上报的**留痕/展示**字段：主机标识 / 主机名 / 网卡地址（agentd → 网关，控制面）
--
-- 为什么加：agentd 一直在采集发现方向的 host.id / host.name 与网卡地址，却从未上报，
--   运维在用途页上只看得见进程/包/端口，看不见「这台机器到底是谁」。契约补了这三个字段，
--   网关落库后管理面直接呈现（`AgentPurposeResponse.fact_summary`）。
--
-- 为什么不进 content_digest：这三项回答的是「这台机器长什么样」，不是「它是干什么用的」。
--   机器名会改、笔记本会换网（DHCP），这些变化不影响推断，放进摘要就等于每次换网都触发
--   一次重报与重算（规则的 observed_at 会跟着乱跳）。所以它们只落展示列，`fact-v1`
--   字段集因此**没变**，不需要 bump 版本、不需要强制重报。
--
-- 为什么 NOT NULL DEFAULT 而不是可空：上报体里这三个字段是 `serde(default)` 的
--   `String` / `Vec<String>`，网关本来就分不出「没上报」与「上报了空值」；再加一层 NULL
--   只是把 `Option` 推给整条读取路径，换不来任何可行动的差别。统一空串 / 空数组，
--   页面对空值显示「—」并注明「旧版 agentd 不带这些字段」即可（与 0005 的取舍相反，
--   那里 NULL 与 0 是两个可行动的语义，必须分开）。
--
-- 覆盖式：行随 ON CONFLICT (agent_id) DO UPDATE 更新，只需加列，无需回填历史。

ALTER TABLE agent_fact_summary ADD COLUMN host_id TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_fact_summary ADD COLUMN host_name TEXT NOT NULL DEFAULT '';
-- JSON 数组，与 process_executables 同一约定（每块网卡一条，形如 "en0 192.168.1.5/24"）。
ALTER TABLE agent_fact_summary ADD COLUMN network_addresses TEXT NOT NULL DEFAULT '[]';
