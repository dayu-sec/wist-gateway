-- ── 按 agent_id 的拒绝名单（吊销状态表）──
-- 见 docs/design/agent-identity-mtls.md §5.6，实体为模型 Agent.Certificate 的
-- AgentCertificateDenylistEntry（字段与模型一致）。
--
-- 为什么需要它：续签的凭据就是**旧证书本身**，所以「停止续签」拦不住持有私钥的攻击者
-- （它能自己续签续命）。必须有一个**立即生效、且跳续签持续**的拒绝点 —— 就是这张表。
--
-- 拒的是 agent_id（不是证书序列号）：攻击者续签 / 重签都还是同一个 agent_id → 仍被拒；
-- 它若换 agent_id，就变成新身份，得走首注册（需 token），拿不到原 agent 的授权。
--
-- **没有外键**（刻意不 `REFERENCES agents`）：吊销要能比「删掉 agent 记录」活得更久 ——
-- 否则删一台被入侵的机器，反而把封锁一起删了，它可以换个 token 又回来。条目由
-- `retain_until` 这一列做 GC（保留到「被吊销的那张证书自然过期」为止，不无限增长）。
CREATE TABLE IF NOT EXISTS agent_certificate_denylist (
  -- 代理主键（模型 `unique entry_id`）；语义键是 agent_id，一台 agent 一条。
  entry_id     TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL UNIQUE,
  -- 吊销原因（人工填写，可空串）。
  reason_code  TEXT NOT NULL,
  -- 谁吊销的（管理面录入，可空串）。
  denied_by    TEXT NOT NULL,
  -- 加入名单的时刻（RFC3339）。
  denied_at    TEXT NOT NULL,
  -- GC 水位（RFC3339）：条目只需留到被吊销证书的自然过期时间为止（§5.6）。
  retain_until TEXT NOT NULL
);

-- GC 按水位清理。比较在**应用层**做（RFC3339 文本比较在不同时区写法下不可靠），所以 SQL 里
-- 不按 `retain_until` 过滤，也就不建索引 —— 表本来就只有每客户 10²–10³ 量级。
