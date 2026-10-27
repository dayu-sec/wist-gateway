-- 一台机器上「某个服务的日志目录在哪」的候选（一台多行）。
--
-- 为什么单独一张表，而不是塞进 `agent_fact_summary` 或 `agent_path_probe`：
--
--   * 节奏不同：解析随发现 tick 跑（L2a），摘要有 5 分钟节流，路径实测是**按需**的；
--   * 失败面不同：「服务在、但找不到日志」要与「路径探不了」「还没探」分开报，
--     合并进任一方都会把处置方向带错；
--   * 报文不能加字段：`AgentStatusReport` / `AgentUplinkGrant` / `DiscoveryPoliciesReturned`
--     都是 `deny_unknown_fields`，加字段会让整舰队 400 —— 所以走独立端点 + 独立表。
--
-- 一行 = 一个**实例**的一条候选。主键带上 `origin`：
-- 解析值与人工覆盖必须**并存**在同一个实例上，否则「删覆盖即回落」就要求重新解析一次，
-- 而覆盖恰恰是拿不到进程证据时用的 —— 那时根本解析不出来。
-- `source_ref` 优先用 `port:<n>`（pid 重启就换，不该多出一条），没有监听端口才退到 `pid:<n>`。
-- 多实例（5432 / 5433）= 多行，彼此独立。
--
-- `origin`：`agent` = 本机解析出来的；`override` = 人通过管理 API 显式指定（应急口）。

CREATE TABLE IF NOT EXISTS agent_log_source (
  agent_id    TEXT NOT NULL,
  -- 服务标识（v1 封闭词表：postgresql / mysql / redis / mongodb）。
  service     TEXT NOT NULL,
  -- 本机实例引用：`port:<n>` / `pid:<n>` / `override`。
  source_ref  TEXT NOT NULL,
  -- 日志**目录**（绝对路径，必须落在网关的 allowed_source_roots 内）。
  dir         TEXT NOT NULL,
  -- 依据词表：human / cmdline_datadir / env_datadir / open_fd / config_file / cwd / search_hit。
  evidence    TEXT NOT NULL,
  -- 原始依据片段（≤ 512 字符），给人看 / 给审计。
  detail      TEXT NOT NULL,
  -- 0..100；只用于同一 evidence 档内排序，不参与判定。
  confidence  INTEGER NOT NULL,
  -- `agent` | `override`
  origin      TEXT NOT NULL,
  -- 这条候选的观测时刻（agent 的墙钟）。
  observed_at TEXT NOT NULL,
  -- 网关收到 / 改写的时刻（覆盖被改过时以它为准）。
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (agent_id, service, source_ref, origin)
);

-- 求值永远按「这台机器的全部候选」读，按服务筛。
CREATE INDEX IF NOT EXISTS idx_agent_log_source_agent ON agent_log_source (agent_id, service);
