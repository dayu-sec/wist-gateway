-- 机器画像补齐：网卡地址（agentd → 网关，控制面）
--
-- 背景：凭证书**首触重建**登记时，机器画像（node_id / hostname / machine_id）全是空的
--   （证书只承载稳定身份，见 0001 的 agents 表），原设计靠「后续状态上报补齐」，但状态上报
--   契约以前没有这些字段 —— 于是经证书注册的机器在管理面**只剩一个 ID**，运维认不出是哪台。
--   现在 agentd 每次状态上报带上 `HostProfile`，网关在这里回填。
--
-- 为什么加在 agents（不是 agent_instances）：机器画像是**身份属性**（换实例/重启不变），
--   与 node_id / hostname / machine_id 同表。node_id/hostname/machine_id 三列已存在，本次只补
--   ip_addresses（机器级「最近一次已知地址」，随 DHCP 变化，覆盖式更新即可）。
--
-- 为什么可空：NULL = 老版本 agentd 没报 / 还没补过；与空 JSON 数组区分开
--   （后者是「报了，确实没有地址」）。存量机器会在下一次状态上报时自动补齐，无需回填历史。

ALTER TABLE agents ADD COLUMN ip_addresses TEXT;
