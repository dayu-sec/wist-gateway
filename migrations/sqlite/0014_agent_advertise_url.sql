-- 网关对外地址（管理面设置，单例行）
--
-- 网关（控制平台）对目标主机**对外可见**的基址。它决定两件事：
--   1. 新签发 Agent 初始配置里的 `[control_plane] endpoint`（agent 据此接入控制面）；
--   2. 安装命令 / install.sh / 安装包分发 URL 的基址。
--
-- 为什么需要它：`server.public_base_url` 是启动期配置，而对外入口（域名、端口、反代）
-- 常由部署侧决定、且会随后调整。拿 `127.0.0.1` 或容器内部地址当 agent 的默认控制面地址，
-- 装出来的 agent 必然连不上（中心侧设计文档同样明确：不能用内部地址当默认控制面地址）。
--
-- 未设置时回落到 `server.public_base_url` —— 本表不存默认值，避免把「启动时的配置值」
-- 固化进数据，导致改配置后旧值仍然生效。
--
-- 只影响**之后**签发的安装代码与新装 Agent：已安装的 agent 要重跑安装脚本才会拿到新值
-- （初始配置只在安装时拉一次）。

CREATE TABLE IF NOT EXISTS agent_advertise_url (
  -- 单例设置的固定 id（DEFAULT_AGENT_ADVERTISE_URL_SETTING_ID）。
  setting_id TEXT PRIMARY KEY,
  -- 对外基址，形如 https://gateway.example.com（无尾斜杠）。
  url        TEXT NOT NULL,
  -- 最后修改人（取自命令的 requested_by）。
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
