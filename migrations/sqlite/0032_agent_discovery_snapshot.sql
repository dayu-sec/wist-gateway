-- 原文发现快照（DSNAP）上送的控制面设置 + Agent 自报的生效值。
--
-- 为什么需要它：上送周期在**每台机器**上应当不同（资产变化快的关键主机更密，容器/进程
-- 密集的机器更疏），而逐台改 agentd.toml 不可运维。设置由管理面（gateway-web）录入，
-- Agent 通过 `agent/discovery-snapshot:poll` 拉取。
--
-- 三种 scope 共用一张表（都很小，行数 = 机器数 × 2）：
--   * 'global'  —— 本网关所有 Agent 的默认；
--   * 'agent'   —— 单机覆盖（`agent_id` 精确），优先级高于 global；
--   * 'applied' —— Agent **自报**的实际生效值（每台一行，随 poll 覆盖）。
--
-- 语义与 `agent_uplink` 一致：控制面**有**设置就按控制面的；**没有**设置时网关不下发
-- （204），Agent 回落本机 `[discovery]`。这是刻意的 —— 本机配置是离线 / 旧网关 /
-- 未入网时唯一的来源，不能被一个「空设置」永久压掉。

CREATE TABLE IF NOT EXISTS agent_discovery_snapshot (
  -- global | agent | applied
  scope            TEXT NOT NULL,
  -- global 行为空串；agent / applied 行为 agent_id。
  agent_id         TEXT NOT NULL DEFAULT '',
  -- 是否上送原文快照。
  enabled          INTEGER NOT NULL,
  -- 上送周期（秒）。写入前由 API 夹到 >= 60。
  interval_seconds INTEGER NOT NULL,
  -- applied 行专用：control_plane | local_config。设置行为空串。
  source           TEXT NOT NULL DEFAULT '',
  -- 设置行的修改人（applied 行为空）。
  updated_by       TEXT NOT NULL DEFAULT '',
  updated_at       TEXT NOT NULL,
  PRIMARY KEY (scope, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_discovery_snapshot_scope
  ON agent_discovery_snapshot (scope, agent_id);
