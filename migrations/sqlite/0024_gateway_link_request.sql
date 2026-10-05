-- 网关侧「接入请求」缓冲（单例行）
--
-- 运维在网关「链接上级」页提交（中心地址 + 一次性接入券 + CA-S 信任锚）；host 侧常驻
-- `wist-gwlinkd` 通过**环回**接口定时拉取并完成 link-upstream / register，再回报结果。
-- 这样接入由网关侧发起（私钥在本机生成），而 gwlinkd 仍**纯出站**、无需任何入站服务。
--
-- 未提交过时不建行（调用方按「无待办」处理）。接入券明文被 gwlinkd 消费后由网关清空。

CREATE TABLE IF NOT EXISTS gateway_link_request (
  -- 单例设置行 id（DEFAULT_GATEWAY_LINK_REQUEST_SETTING_ID）。
  setting_id       TEXT PRIMARY KEY,
  gateway_id       TEXT NOT NULL DEFAULT '',
  -- 中心基地址（https，形如 https://center.example）。
  center_endpoint  TEXT NOT NULL DEFAULT '',
  -- 一次性接入券**明文**：仅随本请求一次性交给 gwlinkd；被消费后清空。
  link_token       TEXT NOT NULL DEFAULT '',
  -- CA-S 信任锚（中心服务器证书信任根，PEM 内容）。
  trust_bundle_pem TEXT NOT NULL DEFAULT '',
  -- Pending / Connecting / Connected / Failed
  status           TEXT NOT NULL DEFAULT 'Pending',
  -- 失败原因（供页面显示）。
  result_detail    TEXT NOT NULL DEFAULT '',
  -- 最后提交人（取自命令的 requested_by）。
  requested_by     TEXT NOT NULL DEFAULT '',
  requested_at     TEXT NOT NULL DEFAULT '',
  updated_at       TEXT NOT NULL DEFAULT ''
);
