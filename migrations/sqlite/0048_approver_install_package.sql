-- wist-approve（审批终端）安装包来源（管理面录入，每个平台一行）
--
-- 与 `agent_install_package` 同一套语义：管理面录入来源 → 网关拉取并缓存到本地 →
-- 分发端点只读缓存（`/api/v1/approver/packages/{platform}`），于是**分发出去的字节**
-- 与 install.sh 里内嵌的 sha256 天然同源。
--
-- 与 agent 包的差别（刻意的）：
--   · 没有「历史」表：审批终端不需要按条目回滚，换版本 = 重新录入一行（按 platform 幂等覆盖）。
--   · 一行就是一个平台（platform 主键），不设单例 address 表 —— 三个平台的来源本来就可以不同。
--
-- `source` 只作留痕，**不作为取包来源**：真正服务出去的是 `cached_path` 指向的字节。

CREATE TABLE IF NOT EXISTS approver_install_package (
  -- 目标三元组（与网关分发白名单同一组：*-linux-musl / *-apple-darwin）。
  platform       TEXT PRIMARY KEY,
  -- 原始录入（/abs/path 或 https://…）。只留痕。
  source         TEXT NOT NULL,
  -- 网关据自己缓存的那份字节算出来的摘要，统一 `sha256:<64 hex>`。
  package_sha256 TEXT NOT NULL,
  -- 网关自己存的那份副本（分发端点读它）。
  cached_path    TEXT NOT NULL,
  -- 从包名 / 包内目录名读到的版本（如 0.58.0）；读不到留空串。
  version        TEXT NOT NULL DEFAULT '',
  -- 最后修改人（取自命令的 requested_by）。
  updated_by     TEXT NOT NULL DEFAULT '',
  updated_at     TEXT NOT NULL
);
