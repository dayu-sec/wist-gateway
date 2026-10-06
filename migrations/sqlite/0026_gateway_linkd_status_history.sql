-- gwlinkd 心跳轨迹（单库、最近窗口的环形记录）
--
-- 单例行 `gateway_linkd_status` 只回答「刚才那一拍在不在」；页面还要回答
-- 「最近一小时稳不稳」（掉线过几次、心跳有没有断档）。所以每拍心跳**追加**一行，
-- 写入时顺手裁掉窗口外的旧行 —— 保留量很小（30s 一拍 × 2h ≈ 240 行）。
-- 设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。
--
-- 时刻用**网关时钟**（unix 秒，与失联判定同源，不受两端时钟偏移影响），并作主键：
-- 同一秒内的重复心跳落在同一行（不翻倍）。`state` 是那一刻 gwlinkd 自报的状态。
-- 载荷无密钥，admin 可原样读。

CREATE TABLE IF NOT EXISTS gateway_linkd_status_history (
  -- 网关收到该心跳的时刻（unix 秒，网关时钟）。
  at_seconds  INTEGER PRIMARY KEY,
  -- 那一刻 gwlinkd 自报的状态（WaitingLinkRequest / Linking / Linked / Degraded…）。
  state       TEXT NOT NULL DEFAULT ''
);
