-- 宿主依赖工具版本（gwlinkd 心跳携带）
--
-- 网关栈由 gops 部署、升级也经 gops 执行；gx 是 gops 的运行底座。二者按交付约定装在
-- 宿主 `$HOME/bin`，容器里的网关看不见 —— 由宿主侧常驻 gwlinkd 探测后随心跳推来，
-- 页面展示、中心也可经状态上报知道版本。
--
-- 空串 = 未安装 / 探测失败（与既有可选字段用空串表达「无」同口径，不用 NULL）。

ALTER TABLE gateway_linkd_status ADD COLUMN gops_version TEXT NOT NULL DEFAULT '';
ALTER TABLE gateway_linkd_status ADD COLUMN gx_version TEXT NOT NULL DEFAULT '';
