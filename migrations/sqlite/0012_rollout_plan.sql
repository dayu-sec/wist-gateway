-- 灰度发布计划（对应模型 Control.Rollout：RolloutPlan / RolloutPhase / RolloutPlanEntry）
--
-- 与 one_shot_work 的关系：计划是「编排层」，批准/推进时才把阶段内的 target 物化成一
-- 件件 OneShotWork(action, spec)。RolloutPlanEntry.work_id 指向那件工作，结果经
-- ReportWorkResult 回填到条目 —— 计划不重复存工作内容，spec 只在 plan 这一行。
--
-- 阶段为什么以 JSON 数组随计划一行存（而不是子表）：阶段创建后只有 status 在走，
-- target_ids / advance_rule 都不变；阶段数小（几段），整体读写比三表 join 简单；
-- 且「推进」要同时改 current_phase 与阶段 status，放一行里就是一条原子 UPDATE。

CREATE TABLE IF NOT EXISTS rollout_plan (
  plan_id         TEXT PRIMARY KEY,
  action          TEXT NOT NULL,
  spec            TEXT NOT NULL,
  deadline_at     TEXT NOT NULL,
  timeout_seconds INTEGER NOT NULL,
  phases_json     TEXT NOT NULL,
  batch_size      INTEGER NOT NULL,
  current_phase   INTEGER NOT NULL DEFAULT 0,
  -- draft | rolling | completed（模型里的 approved/failed/canceled 留待后续，见 api/rollout_ops.rs）
  status          TEXT NOT NULL,
  created_by      TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  approved_by     TEXT,
  approved_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_rollout_plan_created ON rollout_plan (created_at);

CREATE TABLE IF NOT EXISTS rollout_plan_entry (
  plan_id    TEXT NOT NULL,
  target_id  TEXT NOT NULL,
  work_id    TEXT,
  -- pending | dispatched | succeeded | failed（rolled_back 在 agentd 侧映射成 failed 后上报，网关不再单列）
  status     TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (plan_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_rollout_plan_entry_work ON rollout_plan_entry (work_id);
