-- agentd 上报的**本机工作内容视图**（`state/work.json` 的子集）：只保留最近一份。
--
-- 把「这台 agent 真的在采哪些文件」带到网关上 —— 网关知道自己**授权**了什么，但那不等于
-- agent 实际在采什么（本机手工加的输入、工作暂停、来源今天接不接得了，只有 agent 知道）。
-- 旧版本 agentd 不上报此字段，列为空。
ALTER TABLE agent_instances ADD COLUMN local_work TEXT;
