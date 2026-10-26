-- 采集预检的**本机实测**结果（一台一行，覆盖式）。
--
-- 为什么要单独一张表，而不是塞进 `agent_fact_summary`：
--
--   * 事实摘要是**全量**（进程/端口/包/路径），预检只回答**路径维度**，而且它的价值
--     恰恰在于「比摘要新」—— 合并进摘要会让「这条路径是什么时候探的」说不清；
--   * 预检是**按需**发生的（授权被拒时、页面上点一下），摘要是有节流的周期上报；
--     两种节奏混在一行里，任何一方写入都会把另一方的时间戳踩掉；
--   * 预检要带 `unreadable_paths`（探不了的路径 + 原始错误），而摘要的线格式
--     （`ReportAgentFactSummary`）不能加字段 —— 那是全舰队 `deny_unknown_fields` 的报文。
--
-- 求值口径：**有探针结果就用它覆盖路径维度**，其它维度（包/端口/os）继续用事实摘要。
-- 探针结果里的 `probed_paths` 是本次实测的全集，没列进来的路径算「没探过」。

CREATE TABLE IF NOT EXISTS agent_path_probe (
  agent_id         TEXT PRIMARY KEY,
  -- agent 侧探完的时刻（RFC3339，agent 的墙钟）。
  observed_at      TEXT NOT NULL,
  -- JSON 数组：本次实际探过的绝对路径。
  probed_paths     TEXT NOT NULL,
  -- JSON 数组：其中存在的路径（`probed_paths` 的子集）。
  present_paths    TEXT NOT NULL,
  -- JSON 数组 [{path, error}]：探不了（权限 / IO）。**不在** `probed_paths` 里。
  unreadable_paths TEXT NOT NULL,
  -- 网关收到并落库的时刻。
  received_at      TEXT NOT NULL
);
