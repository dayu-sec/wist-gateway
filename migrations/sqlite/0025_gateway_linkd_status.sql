-- gwlinkd 状态（心跳；单例行）
--
-- host 侧常驻 `wist-gwlinkd` **纯出站**（无入站面），页面拉不到它 —— 所以它每拍把自身状态
-- **环回 POST** 到网关，网关存这一行、admin 视图暴露给 Web，据此展示「宿主侧常驻在不在跑」。
-- 设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。
--
-- 未上报过时不建行（调用方按「未检测到 gwlinkd」处理）；重复心跳覆盖同一行。
-- 可选字段用空串（不用 NULL）。`received_at` = 网关时钟，失联判定用它。

CREATE TABLE IF NOT EXISTS gateway_linkd_status (
  -- 单例设置行 id（DEFAULT_GATEWAY_LINKD_STATUS_SETTING_ID）。
  setting_id             TEXT PRIMARY KEY,
  gateway_id             TEXT NOT NULL DEFAULT '',
  instance_id            TEXT NOT NULL DEFAULT '',
  -- gwlinkd 版本。
  version                TEXT NOT NULL DEFAULT '',
  -- 当前接入的中心（未接入时空串）。
  center_endpoint        TEXT NOT NULL DEFAULT '',
  -- WaitingLinkRequest / Linking / Linked / Degraded
  state                  TEXT NOT NULL DEFAULT '',
  -- 客户端证书到期（RFC3339；空串 = 无）。
  credential_expires_at  TEXT NOT NULL DEFAULT '',
  -- 最近一次成功向中心 status 上报的时刻（RFC3339；空串 = 未成功过）。
  last_center_report_at  TEXT NOT NULL DEFAULT '',
  -- 最近失败摘要（空串 = 无）。
  last_error             TEXT NOT NULL DEFAULT '',
  -- gwlinkd 打的心跳时刻（RFC3339，原样存）。
  reported_at            TEXT NOT NULL DEFAULT '',
  -- 网关收到本心跳的时刻（RFC3339，网关时钟）——失联判定用。
  received_at            TEXT NOT NULL DEFAULT ''
);
