-- agentd 上报的**最近一次续签判定**（`AgentCredentialRenewal`，§5.5）：只保留最近一份。
--
-- 续签是后台动作，**不记录就等于静默**：agentd 把本地台账（`identity/renewal.json`）原样带上来
-- （`证书状态.last_renewal`），网关只存 / 展示，不重算。存 JSON 文本（与契约同形）——
-- 它是「一次判定」的整体，拆成四列只会让读写两端各自拼装。
--
-- 为什么可空：NULL = 老版本 agentd 没上报（或本机还没做过续签判定），与「跑了但没结论」区分开。
-- 覆盖式：行随 `ON CONFLICT (agent_id) DO UPDATE` 更新，只需加列，无需回填历史。
ALTER TABLE agent_certificate_status ADD COLUMN last_renewal_json TEXT;
