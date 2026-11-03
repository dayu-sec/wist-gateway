-- Agent 数据面上送地址（管理面设置，单例行）
--
-- Agent（wist-agentd）把采集到的日志与指标通过 TCP 上送到数据面（warp-parse）的入口。
-- 网关签发 Agent 初始配置时把本值渲染进 `[telemetry.logs.output.tcp]`（`addr` / `port`）。
--
-- 未设置时不下发上送段：Agent 只上报自身状态，**不采集日志、也不上送数据面**。
-- 这个「未知就不采」的取舍是有意的：本地 file sink 无上限（历史上写满过磁盘），
-- 而上送路径的本地缓冲有 256 MiB 上限（agentd `spool_max_bytes` 默认值 + `pause`）。
-- 本表不存默认值，避免把默认值固化进数据。

CREATE TABLE IF NOT EXISTS agent_uplink (
  -- 单例设置的固定 id（DEFAULT_AGENT_UPLINK_SETTING_ID）。
  setting_id TEXT PRIMARY KEY,
  -- 数据面主机（IPv4 或主机名）。
  host       TEXT NOT NULL,
  -- 数据面 TCP 入口端口（wparse `topology/sources/tcp_1`）。
  port       INTEGER NOT NULL,
  -- 最后修改人（取自命令的 requested_by）。
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
