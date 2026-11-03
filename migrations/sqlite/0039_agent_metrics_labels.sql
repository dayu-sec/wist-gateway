-- 每台机器的**选择类 label 手工覆盖**（一台一行；没有行 = 没有手工覆盖）。
--
-- 为什么只存「手工覆盖」，不存合并后的生效值：
--
--   * 生效值 = 部署默认 ∪ 推断 ∪ 手工覆盖，三层里只有最后一层是**人写的**；
--   * 把合并结果落库会让「改了部署默认」这件事分不清是配置生效了还是库里的旧值还在；
--   * 一台机器没有行时，`revision` 视为 0，agent 拿到的是纯部署默认值。
--
-- `overrides_json` 是 `{"env":"prod","cluster":"kafka-prod"}` 这样的扁平对象（值都是字符串）。
-- 之所以存 JSON 而不是一行一键：读路径永远要「这台机器的全部覆盖」一次性拿到，
-- 拆行只多一次 join，换不来任何查询能力（没有「按 label 值查机器」的需求）。
--
-- `revision`：这台机器的手工覆盖版本，每次写入 +1。agent 用它判断「有没有变」。
-- `updated_by`：谁改的（与工作/调查同一口径，`admin:<token 指纹>`），审计用。

CREATE TABLE IF NOT EXISTS agent_metrics_labels (
  agent_id       TEXT NOT NULL PRIMARY KEY,
  overrides_json TEXT NOT NULL,
  revision       INTEGER NOT NULL,
  updated_at     TEXT NOT NULL,
  updated_by     TEXT NOT NULL
);
