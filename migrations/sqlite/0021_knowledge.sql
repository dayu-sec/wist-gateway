-- 知识库内容包（策展数据经管理面录入网关）
--
-- 设计见 docs/design/knowledge-content-management.md §6。三张表与「Agent 安装包」同构，
-- 但有一处**必须不同**：安装包"录入即生效"（只有一个来源单例），知识库要"先录入、
-- 验过、再切"，所以生效指针（knowledge_active）与录入表（knowledge_package）是两件事，
-- 且切换要留痕（knowledge_activation_log）。

-- 录入过的包：内容寻址，一行一个包。同一个包重复录入落同一行（幂等）。
--
-- 与 `agent_install_package_history` 的差别：那个 `cached_path` 指向**一个文件**（tarball），
-- 这里指向**一个目录**（解开的五份数据 + manifest.json）—— 网关自己解析的是目录，不是归档。
-- 每一版都留着：在跑的常驻工作锁在它展开时那一版目录上（`standing_work.catalog_version`），
-- 换版不追改，所以旧版目录不能删。
CREATE TABLE IF NOT EXISTS knowledge_package (
  -- 内容寻址：kbp-<sha256 前 16 位>。
  package_id      TEXT PRIMARY KEY,
  -- 原始录入（/abs/path 或 https://…）。只作留痕，不作为取包来源。
  source          TEXT NOT NULL,
  -- 网关据自己缓存的那份字节算出来的摘要，统一 `sha256:<64 hex>`。
  package_sha256  TEXT NOT NULL,
  -- 制品版本（包内目录名 / manifest.json 的 version）。
  version         TEXT NOT NULL DEFAULT '',
  -- 五份数据各自声明的版本；读不到留 NULL。
  catalog_version  INTEGER,
  template_version INTEGER,
  policy_version   INTEGER,
  purpose_version  INTEGER,
  -- 内容所依赖的解析器契约版本（§10）。不兼容的包**可录入、不可激活**。
  parser_abi      INTEGER NOT NULL DEFAULT 1,
  -- 签发者公钥指纹；未签名时为空串（M1 允许不签名）。
  signed_by       TEXT NOT NULL DEFAULT '',
  -- 网关自己存的那份**目录**路径。
  cached_path     TEXT NOT NULL,
  created_by      TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_knowledge_package_created
  ON knowledge_package (created_at DESC);

-- 生效指针（单例）：现在装载到内存里的是哪一个包、第几代。
CREATE TABLE IF NOT EXISTS knowledge_active (
  -- 单例设置的固定 id（DEFAULT_KNOWLEDGE_SETTING_ID）。
  setting_id   TEXT PRIMARY KEY,
  package_id   TEXT NOT NULL,
  -- 单调递增的世代号：每次激活 +1。它是"派生结果算自哪一版"的**表级锚**
  -- （工作锁看 catalog_version，建议看 rule_set_id + purpose_version，整集看它）。
  generation   INTEGER NOT NULL,
  activated_by TEXT NOT NULL DEFAULT '',
  activated_at TEXT NOT NULL
);

-- 切换留痕：回滚也是切换，也要留痕（谁、什么时候、从哪一版到哪一版、为什么）。
CREATE TABLE IF NOT EXISTS knowledge_activation_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  -- 首次激活为空。
  from_package TEXT,
  to_package   TEXT NOT NULL,
  generation   INTEGER NOT NULL,
  -- activate | rollback | repair
  reason       TEXT NOT NULL DEFAULT '',
  requested_by TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL
);
