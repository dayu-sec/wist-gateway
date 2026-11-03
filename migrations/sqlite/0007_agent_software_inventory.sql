-- L1a 机械资产清单：从**事实摘要**派生出的「这台机器上有什么」（按可执行路径归并）
--
-- 为什么放网关库，而不是只放中心：清单是**集合视图**问题，而网关持台账（agents 表）并收
--   全部机器的事实 —— 它天然就是机队聚合点。而且「网关不接中心时仍完全可用」是已定的架构
--   原则（agent-purpose-inference.md §7）：清单只在中心算，等于把核心能力绑死在中心上。
--   归一化到 CPE/purl 与漏洞关联才属中心（KB 高频变，是策展数据的**分发成本**问题，不是算力）。
--
-- 为什么是**派生表**：它是 `agent_fact_summary.process_executables` 的机械投影 ——
--   每次内容变化时按 agent **覆盖式重建**，不记历史（要历史是中心/事件通道的事）。
--   因此它随时可由摘要重算：损坏或过期都不致命，删表重建即可。
--
-- 为什么不直接从 `process_executables` 查：那要每台机器反序列化一遍 JSON 再做集合运算，
--   「哪些机器装了 X」会退化成扫全表 + N 次 JSON 解析。建成带索引的表之后它是一条索引查询。
--   代价是写放大（每次入库重写这台机器的行），量级见下。
--
-- 量级：每台机器 = 去重后的可执行路径条数（10^2~10^3）。1000 台 ≈ 20 万~200 万行，
--   行很小（几个短文本 + 一条路径），SQLite 放得下。
--
-- `software_key` 是**机械**聚类键，不是软件身份：`.app` 包归到包路径，其余归到自身路径。
--   **没有版本列**：版本与 vendor 要读目标机器上的文件（`Info.plist` / `/var/lib/dpkg/status`），
--   网关读不到 —— 那是采集侧（agentd）的探针工作（L1b）。不提前占位成空列。

CREATE TABLE IF NOT EXISTS agent_software_inventory (
  agent_id     TEXT NOT NULL,
  -- 机械聚类键：`/Applications/Firefox.app`，或某条二进制路径本身。
  software_key TEXT NOT NULL,
  -- 展示名：`.app` 包名去掉后缀，否则路径的 basename。
  name         TEXT NOT NULL,
  -- app（macOS `.app` 包）| binary（其余可执行路径）。页面默认只看 app。
  kind         TEXT NOT NULL,
  -- 命中的归并规则，回答「这个名字是怎么来的」。
  matched_rule TEXT NOT NULL,
  path         TEXT NOT NULL,
  received_at  TEXT NOT NULL,
  -- 一个 agent 的同一条路径只有一行：这是「覆盖式重建」的物理保证，
  -- 也让重复写入自然幂等。
  PRIMARY KEY (agent_id, path)
);

-- 「按软件找机器」的支撑索引。
CREATE INDEX IF NOT EXISTS idx_agent_software_inventory_key
  ON agent_software_inventory (software_key);
