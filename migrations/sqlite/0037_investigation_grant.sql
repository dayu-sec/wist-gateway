-- 一次性调查的**按 agent 授权**（一台一行；无行 = 继承网关默认）。
--
-- 为什么要在网关配置（`[investigations] allowed_topics`）之外再加一层：
--
--   * 配置是**上界**：环境级策略（谁可以在这套网关上读什么），改它要重启；
--   * 这台表是**下界**：某台机器实际开哪几个面，页面上点一下就能改，即时生效。
--   * 有效集 = 上界 ∩ 本表 ∩ agent 自报的能力。谁都不能越过上界，所以“页面误点”不会
--     扩大策略面子；要扩大必须先改配置（那是策略级变更）。
--
-- `topics` 存 JSON 数组（与 `agent_path_probe.probed_paths` 同一口径：列表就走 TEXT+JSON，
-- 不为此开一张关联表 —— 面是闭集，最多几条）。
-- 空数组 = 这台机器一个面都不开（显式关闭），与“没有行 = 继承”是两件事。

CREATE TABLE IF NOT EXISTS investigation_grant (
  agent_id     TEXT PRIMARY KEY,
  -- JSON 数组：允许的题目 id（必须在网关词表与 `[investigations] allowed_topics` 之内）。
  topics       TEXT NOT NULL,
  -- 最近一次修改的时刻（RFC3339，网关墙钟）。
  updated_at   TEXT NOT NULL,
  -- 谁改的（`admin:<token 指纹>`，与 `agent_commands.requested_by` 同一口径；不可反推）。
  updated_by   TEXT NOT NULL
);
