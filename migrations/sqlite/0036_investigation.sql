-- 调查能力上报 + 一次性命令的发起人（审计）。
--
-- 两件事放进同一个迁移，因为它们属于同一次改动（`investigate` 的 G1/G2 两道闸）：
--
-- 1. `agent_instances.investigation_capabilities`（TEXT，JSON）：
--    agentd 上报「本机真的实现了哪些调查面、是否 root」（`InvestigationCapabilities`）。
--    网关据此**在入队前**判断，而不是把命令发下去换一个 `unsupported`/`failed`。
--    与同处的 `logs_capabilities` 同口径：只留最近一份；旧 agentd 不报时**保持上一次的值**。
--
-- 2. `agent_commands.requested_by`（TEXT）：
--    谁发起的这条命令（`admin:<指纹>`；本机命令为空）。调查面读的是客户机上的
--    路径/文件名 —— 一次按需读取必须能回答“这是谁点的”，否则审计链是断的。
--    空串 = 迁移前的历史记录 / 本机触发。

ALTER TABLE agent_instances ADD COLUMN investigation_capabilities TEXT;

ALTER TABLE agent_commands ADD COLUMN requested_by TEXT;
