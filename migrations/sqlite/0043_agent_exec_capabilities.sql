-- 执行能力（E2）：agentd 上报「本机能跑哪些 opcode、支持哪个执行 profile」。
--
-- 为什么整份存 JSON 而不是拆表：opcode 会随 E1/E3 增加，拆表就要为「每次加一条 op」
-- 做一次迁移；这里只用来回答「这台机器认不认识这份计划」，不需要按 op 检索。
--
-- `NULL` = 还没报过（E2 之前的 agentd）。这个差别在**入队前**很关键：
-- 网关把「没报过」按**不可用**处理（409），而不是当成「什么都会」。

ALTER TABLE agent_instances ADD COLUMN exec_capabilities TEXT;
