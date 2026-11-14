-- 云资产采集（harvest）的**中心侧开关**：`wist-harvest` 自己轮询 `GET /api/v1/harvest/control`。
--
-- 为什么是单行表：一个网关只服务一个客户，采集开不开是网关级决定，没有「按 agent 覆盖」
-- 这种形态（与 agent_discovery_snapshot 的多行设置不同）。
-- 为什么放库里而不是配置文件：开关要能在管理面改、要能审计谁改的 —— 配置文件改完还要重启。
create table if not exists harvest_setting (
  id         integer primary key check (id = 1),
  enabled    integer not null default 0,
  updated_by text    not null default '',
  updated_at text    not null default (datetime('now'))
);

-- 首次启动就有一行（默认关闭：装上去不等于开始采）。
insert or ignore into harvest_setting (id, enabled, updated_by, updated_at)
values (1, 0, '', datetime('now'));
