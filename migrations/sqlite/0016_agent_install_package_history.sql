-- wist-agentd 安装包**录入历史**（内容寻址，一行一个包）
--
-- 与 `agent_install_package`（单例行，只记当前生效来源）是一对：那张表回答
-- 「现在分发的是哪个来源」，这张表回答「历史上录入过哪些包、各自从哪里来、网关
-- 自己存的那份副本在哪」。升级场景要按条目取包，所以每个包必须单独存一份副本，
-- 而不能只保留单例缓存里最后一份。
--
-- package_id 是内容寻址键（`pkg-<sha256 前 16 位>`）：同一个包重复录入落在同一行
-- （ON CONFLICT 覆盖），因此这张表既是历史也是幂等去重表。
--
-- source 只作留痕，**不作为取包来源**：真正服务出去的是 `cached_path` 指向的字节。

CREATE TABLE IF NOT EXISTS agent_install_package_history (
  -- 内容寻址：pkg-<sha256 前 16 位>。同一个包重复录入落在同一行（幂等）。
  package_id     TEXT PRIMARY KEY,
  -- 原始录入（/abs/path 或 https://…）。只作留痕，不作为取包来源。
  source         TEXT NOT NULL,
  -- 网关据自己缓存的那份字节算出来的摘要，统一 `sha256:<64 hex>`。
  package_sha256 TEXT NOT NULL,
  -- 包内目录名里读到的版本（如 0.1.9）；读不到留空串。
  version        TEXT NOT NULL DEFAULT '',
  -- 包内目录名里读到的目标三元组（如 aarch64-apple-darwin）；读不到留空串。
  arch           TEXT NOT NULL DEFAULT '',
  -- 网关自己存的那份副本路径（每个包一份）。
  cached_path    TEXT NOT NULL,
  created_by     TEXT NOT NULL DEFAULT '',
  created_at     TEXT NOT NULL
);

-- 列表按录入时间倒序（最近录入的排前面），加索引避免随历史增长退化。
CREATE INDEX IF NOT EXISTS idx_agent_install_package_history_created
  ON agent_install_package_history (created_at DESC);
