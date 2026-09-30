-- 用途建议再多记一个**版本锚**：规则表的 `purpose_version`
--
-- 为什么需要：建议的过期判据是「规则册变了吗」。原来只看 `rule_set_id`（如 `macos-v1`）
-- —— 那只是**分册 id**，策展侧改内容时若忘了改它，内容变了而版本没变，读取路径看不出过期，
-- 就会一直把旧结论当现役（见 `api/agent_ops.rs::ensure_fresh_suggestion`）。
-- 有了表级 `purpose_version`，改内容就必须 bump 它，判据才真正成立
-- （设计见 docs/design/knowledge-content-management.md §8.2）。
--
-- 为什么可空：NULL = 这一行是老版本写的（那时还没有这个字段）。
-- 读取路径会把 NULL 判成"版本未知 ⇒ 过期"，于是**重算一次并把版本补上** —— 这是有意的：
-- 迁移后每个 agent 的第一份建议会把锚补齐，且只发生一次。用 0 冒充"第 0 版"反而更糟：
-- 0 是一个**看似合理的版本号**，会让人以为旧行真的是第 0 版算的。
-- 与 `agent_instances.discovery_policy_version` 同为"可空且 NULL 有意义"的列。

ALTER TABLE agent_purpose_suggestion ADD COLUMN purpose_version INTEGER;
