-- 批量安装码策略（管理面设置，单例行）
--
-- 两个旋钮：
--   * batch_ttl_seconds：「批量安装」签发的 token 活多久（窗口本身是暴露面，必须短）；
--   * batch_max_uses：一张批量码最多能注册多少台（泄露时的爆炸半径）。
--
-- 为什么放管理面而不是只放配置文件：新机房 / 新客户装机潮时，运维要在页面上当场调
-- 窗口与批量大小，改配置文件 + 重启网关代价太大。这两个值只影响**之后签发**的批量码，
-- 改错不会动已在网的机器，也不需要重启。
--
-- 未设置时回落到 `[agent] batch_bootstrap_ttl_seconds` / `batch_bootstrap_max_uses`
-- —— 本表不存默认值，避免把启动时的配置值固化进数据（改配置后旧值不再生效）。

CREATE TABLE IF NOT EXISTS agent_install_policy (
  -- 单例设置的固定 id（DEFAULT_AGENT_INSTALL_POLICY_SETTING_ID）。
  setting_id        TEXT PRIMARY KEY,
  -- 批量码有效期（秒）。
  batch_ttl_seconds INTEGER NOT NULL,
  -- 批量码最多可注册台数。
  batch_max_uses    INTEGER NOT NULL,
  -- 最后修改人（取自命令的 requested_by）。
  updated_by        TEXT NOT NULL DEFAULT '',
  updated_at        TEXT NOT NULL
);
