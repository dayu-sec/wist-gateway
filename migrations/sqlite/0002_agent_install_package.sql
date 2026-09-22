-- wist-agentd 安装包地址（管理面设置，单例行）
--
-- 对应模型 Control.AgentInstallPackageAddress：网关分发 wist-agentd 安装包时使用的
-- 来源地址与校验摘要。设置后新签发的安装代码与 install.sh 使用该地址；未设置时由实现层
-- 回落到配置派生的网关自身分发地址（本表不存默认值，避免把默认值固化进数据）。

CREATE TABLE IF NOT EXISTS agent_install_package (
  -- 单例设置的固定 id（DEFAULT_INSTALL_PACKAGE_SETTING_ID）。
  address_id     TEXT PRIMARY KEY,
  -- 安装包地址：https URL 或本机绝对路径。
  package_url    TEXT NOT NULL,
  -- 可选校验摘要，统一存 `sha256:<64 hex>`。
  package_sha256 TEXT,
  -- 最后修改人（取自命令的 requested_by）。
  updated_by     TEXT NOT NULL DEFAULT '',
  updated_at     TEXT NOT NULL
);
