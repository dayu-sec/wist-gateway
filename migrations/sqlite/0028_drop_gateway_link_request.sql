-- 接入待办改挂进程内存（`ApiState::link_request`），不再落库：删除该单例表。
-- 链接关系的**持久记录**改由 gwlinkd 在「链接上级」页那一下 action 里写进 `gwlinkd.toml`
-- （见 wist-gwlinkd）；网关这里只做「取一次」的过路，重启即丢，重提即可。
DROP TABLE IF EXISTS gateway_link_request;
