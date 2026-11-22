-- 执行计划的**结果**（agentd 上报的 `ReportActionResult`）。
--
-- 为什么需要单独落库：`report_action_result` 过去只回 ack，**结果直接丢弃**。命令队列只能看到
-- `outcome`（成功 / 失败）与一行 `detail`，看不到真正的产出 —— 而清理类动作的价值恰恰在产出：
-- 「预览扫出了哪些文件、共多少字节」。没有它，人只能盲批。
--
-- 两条语义：
--
--   1. **按 `(agent_id, action_id)` 幂等**：同一份计划重投（重试）不产生第二行。
--      不用 `report_id`：agentd 每次重试会换 `report_id`，而我们要的是"这份计划的最终结果"。
--   2. **整份报文原样存**（`report_json`）：结果的形状由 `wist-api` 的契约演进，
--      网关不镜像它的结构 —— 镜像一份就会在加字段时静默丢数据。
--
-- 只留**最新一次**（后到覆盖先到）：执行结果的价值是"现在是什么样"，历史由数据面报告承担。

CREATE TABLE IF NOT EXISTS action_result (
  agent_id     TEXT NOT NULL,
  action_id    TEXT NOT NULL,
  execution_id TEXT NOT NULL,
  plan_digest  TEXT NOT NULL,
  -- 契约的 wire 值：`succeeded` / `failed` / `partial` …（见 `FinalStatus`）。
  final_status TEXT NOT NULL,
  -- 整份 `ReportActionResult` 的 JSON 原文。
  report_json  TEXT NOT NULL,
  -- agentd 声称的上报时刻（RFC3339）。
  reported_at  TEXT NOT NULL,
  -- 网关收到的时刻（网关墙钟）—— 与 `reported_at` 分开，机器时钟不可信。
  received_at  TEXT NOT NULL,
  PRIMARY KEY (agent_id, action_id)
);
