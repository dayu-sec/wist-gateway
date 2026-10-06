-- 网关（容器）自述状态轨迹（单库、最近窗口的环形记录）
--
-- gwlinkd 心跳轨迹（0026）记的是**宿主侧常驻**；这张表记的是**网关容器自己**
-- （`GET /admin/gateway/self-state` 同一份计算）：CPU / 内存 / 负载 / Agent 在线 / 磁盘。
-- 页面「网关（容器）」tab 据此画趋势 —— 这页要能在**中心/gwlinkd 都不在**时照看本机网关，
-- 所以不依赖 VM（`gateway_*` 是 center 推到 center 的 VM 的，网关这台的 VM 里没有）。
--
-- 网关自己**周期自采**（30s 一拍），写入时裁掉窗口外的旧行（保留 2h ≈ 240 行）。
-- 时刻用网关时钟 unix 秒并作主键：同秒重复采样落同一行（不翻倍）。
-- 量不出的列写 NULL（不假装 0）—— 趋势里就是断线，比一条贴着 0 的假平线诚实。

CREATE TABLE IF NOT EXISTS gateway_self_state_history (
  -- 采样时刻（unix 秒，网关时钟）。
  at_seconds           INTEGER PRIMARY KEY,
  -- 网关进程 CPU 占比（单核口径，100% = 占满一核；可能 >100）。量不出为 NULL。
  cpu_percent          REAL,
  -- 网关进程常驻内存（字节，RSS）。量不出为 NULL。
  memory_bytes         INTEGER,
  -- 主机 1 分钟负载。量不出为 NULL。
  load_1m              REAL,
  -- 已登记 Agent 中在线的台数（恒有值）。
  online_agents        INTEGER NOT NULL DEFAULT 0,
  -- 主盘使用率（0..100）。量不出为 NULL。
  disk_usage_percent   REAL
);
