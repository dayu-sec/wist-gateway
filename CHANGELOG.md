# 更新日志

本文件记录 `wist-gateway` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.26.1-alpha] - 2026-10-29

### 变更（发版带上升级兼容声明）

- 新增仓根 `compat.json`：`requires: { "wist-center": ">=0.24.0" }`，
  `supports: { "wist-gwlinkd": ">=0.18.0", "wist-agentd": ">=0.10.0" }`，
  `compat_mode=true` + `coexists_with: { "wist-center": ">=0.22.0" }`。
- 两个平台的 tarball 都带 `compat.json`（与二进制同级）；中心发布 / 计划批准时据此判定兼容性。

## [0.26.0-alpha] - 2026-10-29

### 新增（升级兼容检查）

按包内可选的 `compat.json`（`requires` / `supports` / `coexists_with` / `compat_mode` /
`bridge` / `reversible`，口径在 `wist-release` 的 `compat` 模块）在所有**包管理入口**做检查：

- **安装包录入** `POST /api/v1/admin/agent/install-package`（人工录入与中心环回推送**共用**这条内核）：
  先全部取包 + 验摘要 + 解析身份 + 兼容检查，**全部平台通过后才写包缓存**；任何一台不满足 →
  `409 install_package_incompatible`（`compatibility` 带逐条原因），**不落缓存**（否则被拒的包
  仍会被 Agent 装走）。响应增加 `compatibility[]`，历史列表（`packages[]`）也带兼容报告。
- **知识库包录入 / 激活**：录入时 `409 package_incompatible`；激活时按**当前网关版本**重算
  （录入 ≠ 生效，生效时再校一次）。
- **计划下发**（rollout）：选中包后检查，不兼容 → `409 rollout_package_incompatible`。
- 新增错误码：`install_package_incompatible` / `knowledge_package_incompatible` /
  `package_incompatible` / `rollout_package_incompatible`。
- 没有 `compat.json` → `compatibility.status = unknown`（允许，但**显式**显示“未验证兼容性”）；
  只有 `requires` 被明确违反才阻断，`supports` 越界 / peer 版本未知只告警。

### 依赖

- `wist-release` 升到 **0.6.1**（新增 `compat` 模块；本仓已切回 registry 依赖，不再走 path）。

## [0.25.0-alpha] - 2026-10-28

### 新增（数据面配置与规则：只读浏览接口）

页面「数据采集 → 配置与规则」需要看到 wparse **实际在用**的配置与规则（也就是宿主
`data-plane-run/work` 的内容）。新增两条只读接口：

- `GET /api/v1/admin/data-plane/files` —— 白名单目录树（`entries[]` 为扁平路径表，
  前端自行建树），带 `truncated` 标志；
- `GET /api/v1/admin/data-plane/file?path=…` —— 单个文件内容（大小 / 修改时间 /
  `binary` / `truncated` / `content`）。

安全与降级：

- **白名单**：只开放 `conf` / `topology` / `connectors` / `models` 四个目录与
  `wparse.local.toml` 一个文件；其余一律不列不可读。
- **逃逸检查**：拒绝绝对路径、`..`、反斜杠、`.` 分量；`canonicalize` 之后仍要求
  顶层分量落在白名单内 —— 挡住指向外部的符号链接；列目录时不展开符号链接。
- **单文件 1 MiB 上限**，超出置 `truncated`；非 UTF-8 只回元数据、不回正文。
- **未挂载即 503**（`data_plane_unavailable`）：新配置项 `[data_plane] work_dir`
  缺省为空，不写就没有这个页面，不影响网关启动；配了也不做存在性校验。
- 新增错误码：`data_plane_unavailable` / `data_plane_path_invalid` /
  `data_plane_file_not_found` / `data_plane_read_failed`。

### 配套

- 页面：`wist-gateway-web v0.20.0-alpha`（`/pipeline` 新增「配置与规则」tab）。
- 栈：`wist-gateway-stack v0.5.0-alpha`（compose 把宿主 `data-plane-run/work`
  只读挂到 `/data-plane`，模板写 `[data_plane] work_dir = "/data-plane"`）。

## [0.24.0-alpha] - 2026-10-28

### 新增

- **Agent 总览：最近上线 Agent 带 `hostname` / `ip_addresses`**：页面主标题用机器名、第二行用 IP，
  `agent_id` 退为底部次级标识（排障 / 日志关联用）。旧 agentd 不报网卡地址时为空，
  前端回落 `agentId`。

### 修复

- 同 0.23.1-alpha：日志接入兼容当前模型的字段名（`agent` / `ts` / `log_type` 别名）与可选 `raw`。

### 配套

- 页面：`wist-gateway-web v0.19.0-alpha`（与本版的 hostname / IP 卡片配套）。

## [0.23.1-alpha] - 2026-10-28

### 修复

- **日志接入兼容当前模型（wp-rules ≥ 1.0.18）的字段名与缺失 `raw`**：
  - `agent_id` / `observed_at` / `category` 增加别名（`agent` / `ts` / `log_type`），
    旧记录形状不变；
  - `raw` 改为**可选**：优先 `raw`，其次 `log`，都没有就把内容字段（剔除信封/元数据）
    压成 JSON 展示；
  - 只有信封、没有任何内容字段的记录仍拒收（错误文案带上收到的形状）。
- **背景**：新模型把日志正文拆成字段后大多不再保留整行（实测 2 万条里 1.7 万条缺 `raw`）。
  旧实现要求 `raw` 必填且只认旧字段名，导致数据面一开日志出站就整批 400，
  把每条都写进 `data/rescue/gateway-logs`（实测 1 分钟 ~350 MB）。
- 验证：`cargo test --lib ingest_endpoint` 16 passed（含新增的两种记录形状）。

## [0.23.0-alpha] - 2026-10-27

### 新增（日志源动态定位：服务装在非标准目录也能采到）

- **日志源候选**：agentd 上报「本机看到的数据库实例 → 它的日志目录」，网关逐条校验后落库
  （新端点 `POST /api/v1/agent/log-sources`，新表 `agent_log_source`）。
  支持多实例、容器（`/proc/<pid>/root` → 宿主可见路径），以及「看得见实例但找不到目录」的占位 ——
  预检因此能说「2 个实例，其中 1 个未定位」。
- **人工覆盖（仅 API，不做界面）**：`GET/PUT/DELETE /api/v1/admin/agents/{id}/log-sources`。
  写入时校验 `allowed_source_roots`（人也不能越权）；删除即回落到解析值；覆盖与解析值并存。
- **受限搜索的生效范围下发**：`POST /api/v1/agent/source-search-policy:poll`。
  生效值 = 知识库 `[[units]] search_roots` ∩ `[collection] allowed_source_roots`（在网关算好，
  被裁掉的留一行日志）。agentd 侧没有配置，拿不到就不搜索。
- **最低 agentd 版本**：知识库可声明包级 / 单元级 `min_agentd_version`（取高者）。不达标的机器
  预检给 `agent_too_old`（「需要 ≥ X（当前 Y），升级后自动恢复」）、授权被拒；**已在跑的工作不自动停**。
- **采集面视图**：`GET /api/v1/admin/content` 的单元增加 `search_roots` 与 `min_agentd_version`。

### 变更（预检状态更诚实）

- 新增面状态 `source_unresolved`（服务在、找不到日志目录）与 `agent_too_old`（agentd 太旧），
  与原有的「本机没有」分开报 —— 三者处置完全不同（配覆盖 / 升级 / 换机器）。
- `absent` 的文案不再断言「这台机器没有」，改为「目录约定的位置没有（服务可能装在非标准目录）」。

### 升级注意

- 新表由迁移 `0035_agent_log_source.sql` 自动建。
- 知识库里的 `search_roots` / `min_agentd_version` 是**新字段**：**网关必须先升级**，
  否则旧网关会拒绝加载整份知识包。
- 新状态值需要配套 `wist-gateway-web >= 0.18.0`（页面遇到未知枚举值会整页报错）。

## [0.22.0-alpha] - 2026-10-26

### 新增（采集预检：为什么这台机器授权不了）

- **管理面** `GET /api/v1/admin/agents/{agent_id}/collection-preflight`：给出结论
  （`grantable` / `partial` / `blocked` / `undetermined`）、一句话原因，以及**每个采集面**的状态
  （可授权 / 本机没有 / 还没探 / 探不了 / 策展未就绪）。证据（逐单元、逐路径实测）附在后面。
- **管理面** `POST …/collection-preflight`：让**机器自己**再探一次。命令走一次性命令通道，
  agentd 在下一个状态上报里认领（≤3s），本机探完回传，网关落库后页面轮询可见。
  **不需要任何人登录客户机**。
- **Agent 端点** `POST /api/v1/agent/collection-preflight`（mTLS）：agentd 回传本机路径实测
  （探过 / 存在 / 探不了 + 原始错误）。
- **授权被 409 拒时自动探测**：`POST …/work` 返回 409 且证据缺失时，网关自动入队一次探测，
  下一次重试（≥3s）就拿到实测 —— 从「授权失败」到「知道为什么」不用再点一次。
- **存储**：迁移 `0034_agent_path_probe.sql`（一台一行；与事实摘要分开，因为它只覆盖路径
  维度且有自己的观测时刻）。删 Agent 时级联清理。

### 修复（判定与证据的一致性）

- **授权与预检现在用同一份事实**（事实摘要 + 路径维度被最新实测覆盖）。此前授权只看摘要，
  会出现「预检说可以、授权却拒绝」。
- **探不了的路径不再被当成「确认不存在」**：网关区分「探过但不在」与「没探过 / 探不了」，
  前者是这台机器确实没有，后者要查权限或再探一次 —— 两种处置方向完全相反。
- **探测白名单按平台收窄**：不再让 Linux 机器去探 macOS 的路径，也不再把「别的平台的路径」
  误报成「还没探」。
- **agent 时钟偏差**：报上来的观测时刻解析不了或跑到未来（>5 分钟）时改用网关时刻，
  否则摘要会「永远新鲜」。乱序到达的旧实测不会覆盖更新的那一份。

## [0.21.0-alpha] - 2026-10-26

### 新增（原文快照上送：按机器设置）

- **Agent 端点** `POST /api/v1/agent/discovery-snapshot:poll`：下发解析后的快照上送设置
  （单机覆盖 > 全局；两层都没有则 `204`，由 agent 用本机 `[discovery]`）。
  新端点而不是给既有契约加字段，理由见 `agent_api/v1.rs` 里 `uplink:poll` 同一段注释。
- **管理面 API**（web「Gateway 信息 → 原文快照上送」使用）：
  `GET/POST/DELETE /api/v1/admin/discovery/snapshot`（全局）、
  `POST/DELETE /api/v1/admin/agents/{agent_id}/discovery/snapshot`（单机覆盖）。
  周期 < 60s 一律 400（不静默夹取 —— 页面显示成功、agent 收到另一个值最难查）。
- **实际生效回显**：agent 在 poll 请求里搭车回传当前生效值，管理面据此标出「配了 1 小时、
  实际还是 5 分钟」这类分叉（典型原因：旧 agentd、或单机覆盖没清）。
- **存储**：迁移 `0032_agent_discovery_snapshot.sql`。一张表、三种 scope
  （`global` / `agent` / `applied`）；`applied` 行只在值变化时写，不把心跳放大成写事务。

### 新增（通用的一次性命令通道）

- **模型**：命令是**通用信封**（`command_id` / `kind` / `params` / `requested_at_ms`），不是
  每条命令一个字段。新增一种命令只加 `kind` 词表值 + agentd 一个执行分支。
- **管理面接口**（admin bearer，首个命令 `refresh_facts`）：
  - `POST /api/v1/admin/agents/{agent_id}/fact-refresh`：入队一条命令（同 kind 未执行的旧命令
    标成 `superseded`，重复点击不会排出一串）；返回 `command_id` / `kind` / `requested_at`。
  - `GET /api/v1/admin/agents/{agent_id}/fact-refresh`：查最近一条与结果
    （`acknowledged_at` / `outcome` / `detail`）。
- **下发通道**：命令搭在 agent 状态上报的回执里（`AgentStatusAck.commands`）。agent 每 3s
  上报一次，所以**≤3s 到达**；不需要给 agent 加入站监听，也不改工作快照。
- **结果**：agent 在下一次上报里带 `command_acks`（`succeeded` / `failed` / `no_uplink` /
  `throttled` / `stale` / `unsupported`），网关按 `command_id` 落库；未确认前每次回执都重发。
- **收口**：未确认的命令只保留 **1 小时**（`PENDING_COMMAND_TTL_MS`），超过就不再下发、标 `expired`。
  两个入口都会扫：状态上报（下发前）与管理面 `GET`（一台不再上报的 Agent 不会在页面上
  永远显示「等待认领」）。与 agentd 的 `stale`（10 分钟）刻意错开：给机器短暂离线留一次
  真正的执行机会。
- **存储**：迁移 `0033_agent_commands.sql`（`agent_commands`，一台多行；命令不因网关重启丢失）。

### 升级提示

- 依赖 `wist-api` 的 `AgentCommand` / `AgentCommandAck`；`AgentStatusReport` 是
  `deny_unknown_fields`，所以 **本网关必须先于 agentd 升级**：旧网关收到带 `command_acks`
  的新报文会整份 400。没有结果时 agentd 不发该字段，未升级的 agent 也不受影响。

## [0.20.5-alpha] - 2026-10-25

### 变更

- **面词表新增 `ContainerWorkload`**（`FAMILIES` 与 `LINUX_ONLY_FAMILIES`）。带 `[[families]]` 的
  知识包本来就按**数据**装载面词表，这一步只为两件事保持一致：旧包回落、以及
  “面闭集 vs 模型”的测试与授权校验。
- **测试跟上面拆分**：两个容器单元的派活用例改到 `ContainerWorkload`；
  新增“`LinuxHost` + docker 根存在也能展开容器面”的验收位（面拆分要解决的正是这个：
  容器 stdout 是主机普遍能力，不该由机器用途决定）。
- `ComputeWorkload` 现在只有 draft 单元，断言从“可采就绪”改为“未就绪”（诚实状态）。

## [0.20.4-alpha] - 2026-10-24

### 修复

- **`match` 装载期改为 fail-closed 校验**。以前写坏的表达式会在求值层**静默**变成两种相反后果：
  * 漏冒号（如 `not_path_exists`）会被 `parse_conditions` 丢弃 → 空表达式 = 平台基线必采
    → cri-dockerd 主机上两个容器单元**双采**；
  * 漏分号（`path_exists:/a not_path_exists:/b`）会把第二个条件并进第一个值，以 `/` 开头
    骗过绝对路径校验 → 单元**永不展开**，报错还指向一条假路径。

  现在装载期逐片段校验：必须有 `kind:value`、kind 必须在闭集里（`MATCH_KINDS`）、
  值不能为空或含空白（含空白 = 几乎肯定是漏了 `;`）。
- **减法过滤维度缺能力时不再整条裁源**：`pod_not_in` / `name_not_in` 只减不增，
  旧 agentd 不认识时**去掉该维度继续采**（与 `drop_if_contains` 同一档）。
  包含式维度（`namespace_in` / `name_in`）仍然裁源 —— 去掉等于全收。
  以前单来源容器单元碰到这种情况会直接“面不可授权”（少采变成不采）。
- `filters` 的目标校验改用契约共享的 `is_container_log_target`：接受目录形态
  （`…/containers`），不再只认字面 `contains("/containers/")`。

### 依赖

- `wist-contracts` 0.9.8。

## [0.20.3-alpha] - 2026-10-24

### 新增

- **`match` 支持否定条件 `not_path_exists:<绝对路径>`**：三态求值 —— 任一路径探测到且存在
  → 不满足；全部探测过且都不存在 → 满足；有路径没探过 → 无法判定（不拿“没探”冒充“不存在”）。
  否定条件里的路径也进**探测白名单**（`probe_paths`），否则单元永远展不开；装载期要求
  绝对路径（与 `path_exists` 同口径）。用途：`k8s + cri-dockerd` 主机上把纯 Docker 容器
  单元排除掉，避免同一份日志被 `/var/log/containers` 与 docker 目录各采一遍。
- **`filters.name_in` / `name_not_in` 的装载校验按维度分开**：
  `namespace_in` / `pod_not_in` 仍要求来源在 `/var/log/containers` 下；
  `name_in` / `name_not_in` 放宽到目标含 `containers/` 的来源（不写死 data-root）。
  能力轴随 `CONTAINER_FILTERS` 自动扩到 4 维，旧 agentd 未声明的维度照旧裁源。

### 依赖

- `wist-contracts` 0.9.7。

## [0.20.2-alpha] - 2026-10-24

### 变更

- **`work_conflict` 文案带上“卡在哪条条件”**：
  `linux-db-service=fact_not_collected` →
  `linux-db-service=fact_not_collected(path_exists:/var/log/postgresql)`。
  只有原因码时，看不出是 `path_exists:`（等探测白名单）还是 `installed:`（装包 / 等包清单
  探针）—— 两者的处置完全不同。
- **管理面 `GET /api/v1/admin/discovery-policies` 回网关实际会下发的那一份**：
  `probe_paths` 不再恒为空，与 agent 的 poll 接口同源（都从采集目录的 `path_exists:` 推导）。
  以前回策略表原样，运维无法自证“网关到底让 agent 探了什么”。

## [0.20.1-alpha] - 2026-10-24

### 新增

- **能力轴补全（G1 / G3）**：`materialize_spec` 除了 `file_inputs` / `multiline_modes` /
  `exporters`，还按 `filters:<维度>` 与 `drop_if_contains:substring` 裁剪来源。
  带这些字段的 spec 落到旧 agentd 会被 `deny_unknown_fields` **整份拒收** —— 现在在派活时
  就点名缺什么，不把坏参数发下去。
- **目录装载期新增 `drop_if_contains` 校验**（只许 `FileGlob`；精确子串、限条数 / 长度），
  与管理面 `sources[].drop_if_contains` 输出。
- 读法词表改为**直接复用契约** `MULTILINE_MODES`：新增 `mysql_slow` / `postgres_csv` 时
  不再需要两处手抄。

### 变更

- 能力判定改为看**即将发出去的 wire 来源**（先拼 `WorkSpecSource`，再按它判能力），
  避免“按目录字段判、发出去却多带一个字段”的偏差。
- **`drop_if_contains` 改为降级而不是裁源**：agent 不支持/没报能力时去掉该字段继续采
  （`event=WorkSourceDegraded`）。裁源会让 `linux-auth-session` 这种两条来源都带过滤器的面
  在老 agent 上直接不可授权，且“少采”变成“不采”。
- **就绪不再把同面的 `draft` 单元一起派**：`expand()` 先按 `unit.status = active` 过滤
  （未就绪单元进 `collect_not_ready`）。以前只要面就绪，同面的 draft 单元也会被出发。
- **人工 `spec=` 也做能力裁剪**（不再只看事实）：能力不匹配会导致 agentd 整份拒收，
  不是“这个文件采不到”，不该被当作可见失败放过去。
- **用途规则册跟上 `fact-v3`**：`listen_port` 规则要求稳定服务端口（装载期拒掉临时区间的
  端口，否则是一条永远不命中的死规则），且端口按**数值**比对 —— 字符串包含会让 `35432`
  命中 `5432`，一台机器上百个临时端口时这是必然事件。

## [0.20.0-alpha] - 2026-10-23

### 新增

- **容器选源可以用结构化过滤器（W2）**：`[[units.sources]]` 支持 `filters = { namespace_in, pod_not_in }`，
  随工作参数下发；装载期校验（只允许 `FileGlob`、值必须是精确名字、目标必须在 `/var/log/containers` 下）。
  管理面 `sources[]` 一并返回（空不输出，旧响应字节不变）。
- **派活按 agent 自报的日志能力裁剪（D7）**：agent 上报自己能采的 `file_inputs` /
  `multiline_modes` / `exporters` 后，网关不再把「这台机器接不了的来源」派下去，
  而是直接不派、并说明了缺什么。**旧 agentd（不报清单）行为不变**。
- 主机列表带出 `logs_capabilities`（页面暂未渲染）。

### 变更

- 采集目录里 `linux-kernel-system` 改走 `journalctl-kernel` 后，网关无需改动：
  `EXPORTER_IDS` 跟随契约自动认识它。
- 部分裁剪不再静默：单元仍在、但某条来源因能力被剔时记
  `event=WorkSourceDropped reason=capability`。

### 升级提示

- **依赖 `wist-contracts` 0.9.4 / `wist-api` 0.9.1**；发布顺序 contracts → api → 本仓。
- ⚠ 本仓必须**先于 agentd** 升级：`AgentStatusReport` 是 `deny_unknown_fields`，
  旧网关收到 `logs_capabilities` 会**整份拒收**，agentd 会一直报 400。
- 知识库 `0.5.0`（内核面改走 journald）必须等**本版部署后**再推送：
  旧网关不认识 `journalctl-kernel`，会把「active 但无可执行来源」当成装载错误。

## [0.19.0-alpha] - 2026-10-22

### 新增

- **采集目录接受文件族 glob 来源（W1）**：`FileGlob` 的 target 现在可以是绝对路径 + 单层通配
  （`/var/log/containers/*.log`），`**` 仍被拒（采集端未实现递归展开）。
  `active` 单元的「至少一条可执行来源」判据随 `wist-contracts` 0.9.1 自动放宽。
- **来源级 `exclude_globs`**：`[[units.sources]]` 可声明绝对路径排除项（只允许 `FileGlob`，
  相对路径被拒），随工作参数一起下发；管理面 `content-catalog` 的 `sources[]`
  也会返回 `exclude_globs`（空则不输出，旧响应字节不变）。

### 变更

- 派活物化（`materialize_spec`）透传 `exclude_globs`；按事实裁剪仍只针对**显式路径**，
  文件族不参与（通配目标不探存在性）。

### 升级提示

- **依赖 `wist-contracts` 0.9.1**；先发 contracts 再发本仓。
- 知识库里靠通配的单元**仍保持 `draft`**：机队里还有不认识 glob 的旧 agentd，
  要等能力协商/机队验证后再单独发一版目录翻 `active`。
- **目录与网关的耦合**：`catalog.toml` 的 `[[units.sources]]` 若写了 `exclude_globs`，
  需要网关 ≥ 0.19（旧网关的 `SourceRow` 是 `deny_unknown_fields`，会把整份目录判为非法）。
  当前目录没有单元声明排除项，所以本版无此约束。

## [0.18.1-alpha] - 2026-10-19

### 新增

- **主机列表摘要带上最紧张挂载点路径**：新增 `maxFilesystemUsageMount`，与
  `maxFilesystemUsagePercent` 成对返回；列表页可以直接显示「95% · /var」。

## [0.18.0-alpha] - 2026-10-19

### 新增

- **主机指标逐挂载点容量**：`GET /api/v1/admin/agents/{id}/host-metrics` 新增 `filesystems[]`
  （`mount` / `fstype` / `usagePercent` / `totalKb` / `availableKb`），主机列表摘要新增
  `maxFilesystemUsagePercent`；旧 `disk*` 字段保留兼容。

### 修复

- **COS 示例桶名对齐当前对象存储**：`wist-1347593047` → `github-1347593047`
  （解析逻辑不变，仅示例、测试与前端提示）。

## [0.17.0-alpha] - 2026-10-18

### 新增

- **gwlinkd 心跳带上宿主依赖工具版本**：`POST /api/v1/gateway/linkd-status` 新增
  `gops_version` / `gx_version`（可选）；admin 视图同步返回（空串 = 未安装 / 探测失败）。
  网关栈由 `gops` 部署与升级，容器里看不见这两个工具 —— 只有宿主侧 gwlinkd 能探测。
- 存储：`gateway_linkd_status` 加两列（迁移 `0030`），心跳单行 upsert 一并更新；
  页面在「接入代理」明细里能看到宿主工具是否就绪。

### 兼容性

- 老 gwlinkd 不传这两个键 → 存空串，页面显示「—」；新 gwlinkd 对旧网关也安全
  （载荷反序列化不拒绝未知字段）。

## [0.16.0-alpha] - 2026-10-18

### 新增

- **`POST /api/v1/gateway/knowledge-package`（环回，仅同机 gwlinkd）**：中心下发知识库包的
  接收面 —— 与 admin 录入**同内核**（校验摘要 / 验签 → 内容寻址缓存 → 记历史），
  `activate = true` 时在同一次请求里切生效指针。
  - 载荷：`{source, sha256, origin?, activate?, requested_by?}`；`source` 是网关能取的
    容器内路径，`origin` 只作 provenance（网关不用它取包）。
  - 非环回一律 403（`knowledge_package_loopback_only`）。
  - 签名旁文件按既有约定读 `<source>.sig`：gwlinkd 交付时会把 `.sig` 一起落到投放目录。

### 升级提示

- 中心「知识库下发」需要本版网关；顺序：**网关 → gwlinkd → 中心 → 前端**。
- 本版无端点 / 存储 / 迁移变更，可独立升级。

## [0.15.0-alpha] - 2026-10-18

### 新增

- **`POST /api/v1/admin/cos/resolve`：解析腾讯 COS 路径**（管理面，供录入页一键填充）。
  输入 `github-1347593047/wist-agentd/v0.5.0-alpha`（也接受 `cos://桶/前缀` 与带 region 的
  `https://<桶>.cos.<region>.myqcloud.com/…`），按发布命名约定展开各平台制品，返回与
  GitHub Release 解析**同形**的 `{version, assets:[{name, artifact_url, sha256, platform}]}`。
  - **无凭据**：桶公有读，sha256 随对象自定义元数据 `x-cos-meta-artifact-sha256` 带回
    （COS 只存 MD5 ETag）；按命名约定拼候选对象地址逐个匿名 `HEAD`。
  - 下载 host 带 region，用错 region 时 COS 只回 404：路径里带了就用，否则读
    `WIST_GATEWAY_COS_REGION`，都没有时按常见区域逐个探测。整体 60s 上限。
  - 兼容两种制品命名：文件名带 `v`（agentd / gwlinkd）与不带 `v`（知识库打包脚本）。

### 升级提示

- 前端 `wist-gateway-web` ≥ 0.11.0 的「一键填充（COS 路径）」依赖本接口；旧网关会 404。

## [0.14.0-alpha] - 2026-10-18

### 新增

- **`GET /api/v1/admin/content` 返回采集单元明细（`units`）**：每个单元的来源、`match` 前提、
  `rule_ref`、权限与**来源可执行性**（与派活闸门同一判据）。管理面因此能展开看到
  「这个面具体采什么」，而不只是计数。
- **`match` 支持 `path_exists:<绝对路径>`**：只在路径真存在时才派该单元（三态：
  没探测过 = 无法判定，探测过但不存在 = 不命中）。探测白名单由目录的 `path_exists`
  条件推导，随发现策略下发给 agentd。

### 变更

- **事实摘要随 `wist-contracts 0.9` / `wist-api 0.9` 升级**：落库增加 `probed_paths` /
  `present_paths`（迁移 `0029`），摘要版本 `fact-v2`。
- **入库校验**：「存在的路径」必须是「探测过的路径」的子集，否则拒收（不静默丢弃）。

### 升级提示

- **先升网关，再升 agentd，最后上新知识包**：新 agentd 多报两个字段，旧网关
  （`deny_unknown_fields`）会拒整份事实上报。

## [0.13.0-alpha] - 2026-10-18

### 新增

- **采集面词表改由知识库装载**：`catalog.toml` 新增 `[[families]]`（面 ID、平台归属、
  中英文名称与说明），网关装载后用它做值域校验与平台判断 —— **新增采集面不再需要发网关**。
  `FAMILIES` 常量降级为**旧包回落**（包还没有 `[[families]]` 时用它，避免升级即拒载）。
- **`GET /api/v1/admin/content` 返回 `families`**：ID、`platforms`、`semantics_version`
  与中英文名称/说明，供管理面直接渲染（面名是协议值，不翻译）。

### 变更

- **词表追加式校验**：激活知识包时对比当前生效词表，删面 / 改名（值集上等于删 + 增）
  直接拒绝，错误码 `vocabulary_not_append_only`；`reason = rollback` 除外（回滚本就要落回旧版）。
- **面与平台的对应改读词表的 `platforms`**：`MACOS_ONLY` / `LINUX_ONLY` 两份常量只留给旧包回落。

### 升级提示

- **必须先升级网关，再激活带 `[[families]]` 的知识包**：旧网关的目录结构是
  `deny_unknown_fields`，遇到不认识的 `families` 会拒载整包。顺序：网关 → 知识包 → 激活。

## [0.12.0-alpha] - 2026-10-17

### 修复

- **安装命令不再要求目标机有 OpenSSL ≥ 3**：Linux 引导命令改用「命令内嵌的脚本 sha256」校验
  （`sha256sum`，缺失时 `shasum`），一致才执行；不匹配则明确报错且**不执行**（fail-closed）。
  此前用 `openssl pkeyutl -verify -rawin`，它要求 OpenSSL ≥ 3.0 —— EL7/8、Ubuntu 16.04–20.04、
  Debian 8–11 一律报 `pkeyutl: Option unknown option -rawin`，脚本没跑、也装不上。现在底线回到
  「curl + systemd」的老发行版（见 README「Supported target hosts」：Ubuntu 20.04+ / Debian 11+ /
  EL8+ / macOS 11+）。
- **某平台未录入安装包时**：该平台的安装命令不再下发一条注定 503 的命令，而是直接说明
  「网关当前没有该平台的包、去哪补」。

### 变更

- **移除安装脚本签名（`.sig`）**：它唯一的消费者就是上面那条 OpenSSL 校验。随之删除
  `GET /api/v1/agent/install/{platform}/install.sh.sig`、`[agent] signing_key_file` 及其
  **启动校验**（不再要求该文件存在）、`init-config` 的签名密钥生成。
  **无需迁移**：旧配置里残留的 `signing_key_file` 会被静默忽略；磁盘上旧的
  `install-script-signing-*.pkcs8.pem` 已无消费者、可删。
  已发出的旧安装命令（若还留着）会因摘要不匹配而拒跑 —— 重新复制一次命令即可。
- 知识库内容包的验签**不受影响**（`[knowledge] signing_public_key_file` 是另一把钥匙，仍保留）。

## [0.11.0-alpha] - 2026-10-16

### 新增

- **`[server] self_face_allow`**：给非标准网络（自建网桥 / 宿主源 IP 被 SNAT 成别处）显式列出可信
  对端（IP 或 CIDR）。一般不用填 —— 容器里会自动认默认网关。`/0` 会被**拒启**（那等于把无鉴权的
  环回面公开给所有地址）。

### 修复

- **容器部署下宿主侧常驻（`wist-gwlinkd`）连不上网关**：网关跑在容器里时，本机环回面（自述面 /
  接入请求 / gwlinkd 心跳 / agent 包下发）会把宿主自己的连接当成「外来」而一律 403 —— 表现为
  `journalctl -u wist-gwlinkd` 每 30s 一对 `LinkRequestFailed` / `LinkdStatusPushFailed`，且网关页
  「接入代理」报「未检测到 gwlinkd 心跳」（进程其实活着）。现在这些面把**容器所在网络的网关**
  （= 宿主在该网络上的地址）也认作本机。**外部客户端仍被拒**（在发布端口上它们带的是真实源 IP）。
  排查入口：启动日志新增 `event=LocalHostPeers loopback + container_gateway=<ip> + allow=[…]`。

## [0.10.0-alpha] - 2026-10-15

### 新增

- **安装脚本支持「重装（替换客户端证书）」**：`WIST_AGENTD_REINSTALL=1`（自我提权重跑时用 `--reinstall`
  回传）—— 先停旧服务，再用 `wist-agentd enroll --force` 丢掉本机旧身份、凭一次性 token 换一张新证书后
  重建服务。用于证书已过期 / 换过网关 / 本机身份错乱。默认（首次安装与升级）**不会**动本机已有证书。

### 变更

- **安装脚本只装系统级**：agentd 0.4.0 起 `service` 子命令不再接受作用域旗标，脚本因此不再支持
  `WIST_AGENTD_SCOPE=user`（以前传 `--system` 会让安装卡在第 4 步）。

### 修复

- **总览「最近上线注册 Agent」不再硬截到 6 张**：以前 7 台的网关会出现「已接入 Agent = 7、下面只列 6」
  且不提示被截断，多出来的那台在总览页根本看不到 —— 上限改为 100（前端在截断时会明说）。
- **安装脚本装错平台立刻拒绝**（在提权 / 下载**之前**判断，含 Rosetta 归一化），装完**自检二进制**；
  旧服务停不掉时不再误报成「本来就没有」。

## [0.9.3-alpha] - 2026-10-14

### 变更

- **制品推送到 COS 时自带 sha256**：上传的每个对象带自定义元数据 `x-cos-meta-artifact-sha256`
  （COS 只存 MD5 ETag，GitHub 资产摘要过不来）；可用 `coscli stat`（HEAD）读回。`x-cos-meta-`
  是 COS 对自定义元数据的强制前缀。

## [0.9.2-alpha] - 2026-10-13

### 变更

- **发布时可选把制品推送到腾讯云 COS**：打 tag 时新增 `upload-cos` job，把各平台 tarball 上传到
  `cos://<桶>/wist-gateway/<tag>/` 与 `.../latest/`（未配置 `COS_BUCKET` 时自动跳过，不影响发布）。

## [0.9.1-alpha] - 2026-10-13

### 变更

- **分层配置读取改用共享 crate `wist-config`**（与 `wist-center` / `wist-gwlinkd` 同一套口径）：接口层配置的
  路径解析 + 「段可重合、**叶子键不许重复**」合并 + 可选的同目录 `.env` 插值不再在本仓手写；
  行为与 0.9.0 一致（**不提供 pub 文件时行为不变**）。

## [0.9.0-alpha] - 2026-10-12

### 新增

- **接口层配置（`wist-gateway-pub.toml`）**：主配置之外可再读一份**接口层**文件，承载**现场选择**
  （对外基址 / 归属等）。与主配置**段可重合、叶子键不许重复**（重复即启动即错，fail-closed）。
  路径由 `WIST_GATEWAY_PUB_CONFIG` 显式指定，否则取主配置同目录的同名文件（**存在才用**）。
  于是「渲染物（可被升级/重渲覆盖）」与「现场态（升级必须保留）」可分开存放；
  **不提供 pub 文件时行为与之前完全一致**。
- **公开端点 `GET /api/v1/version`（无鉴权）**：返回网关版本（编译期烧入），供管理页面在
  **未登录**时也显示后端版本号。

## [0.8.0-alpha] - 2026-10-11

### 变更

- **对齐生态 0.8**：`wist-contracts` / `wist-api` 由 `0.7` 升到 `0.8`（后者删了 agent 的本地运行配置
  `agent_config` 模块），`wist-release` 收到 `0.6`。无线上 JSON 变化。
- **运行日志实现改用共享 crate `wist-log`**：删掉本仓 `logging.rs`，`[log]` 段由 `wist_log::init`
  装配（级别 / 格式 / 落点 / 轮转），与 center / gwlinkd / agentd 同口径；键名规范为 `max_seconds`
  （旧名 `max_age_seconds` 以 alias 继续接受）。
- **配置键名精简（可读性）**：`[agent]` 段去掉冗余前缀/词 —— `agent_ca_cert_file` → `ca_cert_file`、
  `agent_ca_key_file` → `ca_key_file`、`bootstrap_token_ttl_seconds` → `bootstrap_ttl_seconds`、
  `install_script_signing_private_key_file` → `signing_key_file`。段名已含 `agent`，键里不重复；
  该键签名的是**安装脚本**，段内无别的签名密钥、且只有私钥文件，故取最短名（省去 `install_`/`script_`/`private_`）。
  模板 `wist-gateway.toml` 同步。
  迁移：`RawAgentConfig` 有意无 `deny_unknown_fields`（兼容历史键），**旧键会被静默忽略**；其中
  `signing_key_file` 为必填，旧键会导致启动报 missing field。升级请用新版模板重渲染
  （`gops sys localize`），不要沿用旧配置。
- **配置里的 `${SEC_...}` 解析改用 `orion-sec` + `orion-variate`**：所有字符串字段支持 `${VAR}` /
  `${VAR:default}`；变量来源为**进程环境变量优先**，其下是密钥文件（`WIST_GATEWAY_SEC_FILE` 指定，
  或 orion 默认 `./.galaxy/sec_value.yml` / `~/.galaxy/sec_value.yml`），键规范成 `SEC_<UPPER>`。
  **展开后仍含占位符 → 拒绝启动**（fail-closed）。据此 `server.admin_api_token` 等密钥可以留成
  `${SEC_...}` 由外部注入，**配置不再写明文**。依赖：`orion-sec 0.7` / `orion-variate 0.14`
  （`orion-error` 从两份收敛到 0.9 一份）。

## [0.7.0-alpha] - 2026-10-10

### 新增

- **中心交付 Agent 包到网关包管理（发布 ②）**：`POST /api/v1/gateway/agent-package`（**loopback-only**，仅本机
  host 侧常驻 `wist-gwlinkd` 可用）。**取包由 gwlinkd 完成**（它持中心信任、是唯一面向中心者），把包落到本机路径后
  交付本端点；载荷 `{artifacts:[{platform,package_url(=本机路径),origin(=中心地址,留痕),package_sha256}],requested_by?}`，
  与 `POST /api/v1/admin/agent/install-package` **共用同一内核**（校验摘要 → 从本机路径取 → 落每平台设置 + 内容寻址历史）。
  非环回 / 取不到对端一律 403；坏输入整次不生效。`origin` 记进历史的 `source` 作 provenance（设置里的来源仍是网关能取的本机路径）。
  见设计 `doc/design/edge/center-content-delivery.md`（分层：中心内容 gwlinkd 取、网关只托管）与 `.../agent-package-push-to-gateways.md`（特性）。

### 变更

- **`init-config` 覆盖已存在配置时明确告知**：不再静默覆盖 —— 打印 `overwrote existing config`（新建仍是
  `generated admin config`），与 `wist-gwlinkd init-config` 同口径。
- **运行日志支持配置 `[log]` 段**：`level`（过滤器指令）、`format`（`text` | `json`）、`file`（给了就写文件、
  相对配置目录解析、自动建父目录；否则 stderr）。优先级 **`RUST_LOG` > `[log] level` > 缺省 `info`**。
  文件**写满自轮转**：`max_bytes`（单文件上限，缺省 64 MiB）、`keep_files`（保留分卷数，缺省 4）、
  `max_age_seconds`（分卷保留时长，缺省 7 天）—— 日志文件不再无界增长。
  注意与 `[logs]`（**被采集 agent 日志**的落盘保留）区分：`[log]` 是**网关进程自己**的运行日志。
  日志在读到配置之后才初始化；配置读不了时退写 stderr。`init-config` 模板同步。
- **对齐生态版本（收口漂移）**：`wist-contracts` `0.3 → 0.7`、`wist-api` `0.6 → 0.7`、
  `wist-control` `0.11 → 0.14`。0.4–0.7 期间 `enrollment` / `gateway` / `work` / `agent_uplink` 的 seam
  报文陆续迁入 `wist-api`，本仓领域类型改自 `wist-contracts 0.7` 取 —— **纯版本 pin，无代码改动**，
  依赖图里 `wist_contracts` 单版本（不再双份）。
- **管理面错误响应统一为 `{ "error": { code, message, … } }` 信封**：跨进程 wire 类型放在
  `wist_shared::protocol`（`ProtocolError` / `Severity` / `ProtocolErrorEnvelope`，设计 §6 指定之家），
  axum 侧的 `api::error::ApiError` 负责投影。**全部**管理面 / agent 面端点从 `(StatusCode, format!("…{err}"))`
  改为 `ApiError`：4xx 给**稳定 `code`** + 可暴露 `message`；5xx 把内部因果链移进本地日志（`internal(...)`）、
  对外不再泄 `err.to_string()`；带 `Cache-Control: no-store` 的错误响应经 `with_no_store()` 保留该头。
  前端 `requestJson` 相应地**全局**解析信封（`ApiError.code` / `.detail`），各页面提示随之复用（
  未识别 code 时回退原文）。ingest（facts / logs）的逐条失败响应 `{ingested,rejected,failures}`
  是领域响应，不套信封、保持原样。
- **升级 `orion-error` 0.8 → 0.9、`wist-error` 0.1 → 0.2**：`wist-error` 同步升级以对齐 `orion-error` 0.9
  的错误身份 trait（否则依赖树里两版 `DomainReason` 共存、`ConfigReason`/`StoreReason` 无法满足
  0.9 的 `ToStructError` / `SourceErr` 约束）。本仓直接依赖随之升到 0.9；对外行为不变。
- **运行日志接入 `log` / `env_logger`**：启动 / 监听 / TLS 握手与连接失败 / 知识库来源 / ingest /
  legacy store 导入等运行期诊断从 `println!` / `eprintln!` 改走 `log`，级别由 `RUST_LOG` 控制（缺省
  `info`），落 stderr（systemd / journald 收集）。
- **进程边界统一到结构化错误**：`main` 的 `Box<dyn Error>` 边界改为 `wist_error::AppError`（`orion-error`）——
  配置 / 库 / TLS / 绑端口的失败以 `display_chain` 打印**完整因果链**再退非零；`init-config` / `build_store` /
  `serve_tls` 同步。对外行为不变。
- **错误信封加固（P0–P3 复核）**：管理面错误 `code` 收敛为**唯一词表** `api::codes`（174 个稳定码，
  调用点只引用常量，附唯一性 / 契约关键码守护测试；`knowledge` 录入错误码与词表对齐）。`ApiError` 按 status
  **默认填 `severity` / `retryable`**（5xx→`error`；`429/502/503/504`→可重试；其余 4xx→不可重试；其它 5xx 不臆断）。
  新增 `error::logged_op`（对齐 `wist-gwlinkd` 的结构化生命周期日志）用于**低频外呼**（GitHub release / agent 包解析），
  并新增 `ApiError::handled` 只投影、**不再记** —— 避免同一故障记两条。落库错误记完整 `display_chain`；
  `try_init` 失败不再静默（打印告警）；`[log] file` 明确由进程自轮转、**不要**再挂 logrotate。

### 修复

- 环回写口的**生产注入层**补测试（`main.rs` `inject_connection_context`）：钉住真实对端 → 环回判定，
  防该层被漏改导致所有环回写口 fail-closed（403）却无人察觉。

## [0.6.0-alpha] - 2026-10-08

### 新增

- **失败的升级目标可以重试**：`POST /api/v1/admin/rollout-plans/retry`
  （body `{plan_id, target_ids?}`；`target_ids` 不传 = 该计划全部失败项）。为每个失败目标派一件
  **新工作**（新的 `work_id` —— agentd 只对没跑过的 id 才重跑），并把计划 / 阶段重开为「进行中」，
  接着走推进闸门；逐台或一次全部都可。草稿计划与没有失败项的计划会被拒。

### 变更

- **升级计划可按「版本」下发（不必再手选制品）**：新建 Agent 升级计划时只给 agentd 版本，
  网关在派活时按**每个目标 Agent 的平台**（macOS-ARM / Linux x86_64·ARM64）自动挑对应平台的
  安装包下发。建计划时即校验「每个目标平台都有该版本的包」——缺任一平台当场 **400** 并列出缺的
  目标与平台，不再等到逐台派活才失败。显式制品（`package_url`）的老计划行为不变。

## [0.5.0-alpha] - 2026-10-08

### 新增

- **解析 GitHub Release（安装包页一键填充）**：`POST /api/v1/admin/github-release/resolve`
  （body `{release_url}`）—— 从 release 页面地址拉出 tag 与各平台资产
  （`{version, assets: [{name, artifact_url, sha256, platform}]}`，`platform` = 从文件名读出的
  target-triple）。供「安装包」页按平台自动填址+摘要（对齐 gops 的录入范式）。
  与中心 `wist-center` 同款口径；公开仓匿名即可，私有仓可设 `WIST_GATEWAY_GITHUB_TOKEN` / `GITHUB_TOKEN`。

## [0.4.0-alpha] - 2026-10-08

### 变更（不兼容）

- **Agent 安装包改为按平台托管（多平台）**：`wist-agentd` 和 galaxy-ops 一样是三平台制品
  （macOS-ARM + Linux x86_64/ARM64），而网关此前只能托管**一份**当前包 —— 换平台的机器装到的是错包。
  现在按平台（target-triple）各托管一份：
  - `POST /api/v1/admin/agent/install-package` 请求体改为 `{artifacts: [{platform, package_url, package_sha256}], requested_by?}`；
    一次提交多平台，任一拉取/校验失败整次不生效（不落库、不覆盖缓存）；平台与包内 triple 不符即拒。
  - `GET /api/v1/admin/agent/install-package` 响应改为 `{packages: [{platform, package_url, package_sha256, updated_by, updated_at}]}`（**去掉**单值 `address_id` / 顶层 `package_url`）。
  - 安装脚本路由改为**平台化**：`/api/v1/agent/install/{platform}/install.sh`（+ `.sig`）；
    包下发 `GET /api/v1/agent/packages/current?platform=<triple>`（缺 `platform` 回 400）。
  - 缓存在 `state/install-package/current/<platform>`；存储 `agent_install_package` 复用 `address_id` 列作平台键（无 schema 改动，旧的 `default` 行需重录）。
  - 安装代码/引导包：`AgentBootstrapBundle.platforms`（`wist-control` 0.11）列出各平台的脚本地址 + 包地址/摘要；三条安装命令各指向自己平台的脚本。
  - 已签发的安装命令会失效（脚本 URL 变了），需重发。

## [0.3.0-alpha] - 2026-10-07

### 新增

- **主机指标带上机器身份**：`GET /api/v1/admin/agents/{agent_id}/host-metrics` 与
  `GET /api/v1/admin/agents/host-metrics`（列表）的响应新增 `node_id` / `hostname` /
  `ip_addresses` —— 指标本身只有 `agent` 标签，主机身份由网关 **join 注册表**补齐
  （不往指标标签里塞，避免重复与过期）。列表用轻量身份投影读注册表，不拉整个注册行。

### 变更

- **Agent 安装包 / 知识库包的摘要改为必填**：`POST /api/v1/admin/agent/install-package`（`package_sha256`）
  与 `POST /api/v1/admin/knowledge/packages`（`sha256`）缺字段即 422、空串即 400 ——不再「不给就跳过校验」；
  `scripts/import-package.sh` 同步带上摘要（`import-knowledge.sh` 本已带）。

## [0.2.0-alpha] - 2026-10-07

### 新增

- **代理日志采集与裁剪**：网关接收 Agent 上报日志并落盘（`state/logs/agent-logs.ndjson`），按大小轮转、
  按份数/时长裁剪（`[logs] max_bytes / keep_files / max_age_seconds`），管理面可看最近日志。

### 变更

- **灰度推进闸门收紧**：`advance` 要求当前阶段**已全部了结**（含失败）才放行；末阶段有失败落 `failed`、
  否则 `completed`（不再把失败抹成「完成」）。口径在共享 crate `wist-release::rollout`。

## [0.1.29-alpha] - 2026-10-06

### 变更

- **`reqwest` 0.12 → 0.13**（`features = ["json", "query", "rustls"]`）：本仓是最后一个 0.12 的落单者，
  而共享 crate `wist-release` 已升到 0.13 —— 不跟就是构建里带**两份 reqwest**。现在四仓（center /
  gateway / gwlinkd / agentd）与 crate 全在 0.13.5。**行为不变**。
  - 顺带修了一个潜在断链：`webpki-roots` 不是 reqwest 0.13 的 feature（它只是可选依赖的隐式
    feature，且 reqwest 源码并不引用），0.13.5 已把它去掉 —— 0.13 里 TLS 根由 `rustls`
    （系统根）决定。

## [0.1.28-alpha] - 2026-10-06

### 变更

- **灰度发布计划的推进口径收进共享 crate `wist-release` 0.3**（`rollout` 模块）：阶段推进闸门的
  校验、`phase_settled` / `phase_should_advance`、批次节流（`phase_start_targets` /
  `next_refill_targets`）、条目状态折叠、以及**确定性 work id** 统一由共享 crate 提供 ——
  与中心算阶段的是同一份口径。本仓 `app/rollout.rs` 只剩「接到网关存储类型上」的适配，
  外加网关独有的物化（target → `OneShotWork`）。**行为不变**。

## [0.1.27-alpha] - 2026-10-06

### 变更

- **自述面带上网关对外域名**：`GatewaySelfState` 加 `public_base_url`（管理面「对外地址」优先，
  未设回落 `[server] public_base_url`）—— 网关自己才知道这个值，host 侧 `wist-gwlinkd` 读自述面后
  随注册 / 状态上报转带给中心。**线上 JSON 加键（向后兼容）**，无行为变化。
- **安装包内核收进共享 crate `wist-release` 0.2**：包来源读取 / 摘要校验 / 身份解析（含架构名表）/ 
  内容寻址 id 由共享 crate 提供，中心与网关共用一份；本仓 `api/install_package.rs` 只剩薄转发。
  **身份解析口径不变**：agent 包仍是「只认包内目录名、且必须切出已知 target-triple」的严格口径。
- 顺带把三处同类副本收编到同一 crate：`infra::secret::bytes_sha256_hex`（转发 `sha256_hex_bytes`）、
  知识库包的 `kbp-` id（转发 `content_id`，与安装包 `pkg-` 同一份逻辑）、知识库 `read_source`
  （**读字节机制**转发，**策略与错误分类**留本仓：16 MiB / 60s / 「来源是目录」提示）。

## [0.1.26-alpha] - 2026-10-06

### 新增

- **gwlinkd 心跳轨迹**：新增 `GET /api/v1/admin/gateway/linkd-status/history?window_seconds=`（admin bearer）。
  网关收到每拍心跳时顺手落一条**环形记录**（`0026_gateway_linkd_status_history`：同秒去重、写时裁旧、
  保留 2h），页面据此画「最近一小时稳不稳」（状态条 + 心跳间隔）。窗口缺省 1h，夹到 `[60s, 2h]`。
  轨迹写失败**不影响**心跳受理——当前态才是页面「在不在跑」的主判据。
- **网关自身状态轨迹**：新增 `GET /api/v1/admin/gateway/self-state/history?window_seconds=`（admin bearer）。
  网关**自身 tick** 每 30s 自采自述面（CPU / RSS / load / 在线 agent 数 / 磁盘），落
  `0027_gateway_self_state_history`（保留 2h）；**量不出的列写 `null`**，不假装 0。
  采样与请求路径**解耦**：不搭页面轮询、不搭 gwlinkd 回环读。

## [0.1.25-alpha] - 2026-10-06

### 变更

- 依赖 `wist-api` `0.5` → **`0.6`**：该版把杂物袋模块 `gateway` 拆成
  `action_plan` / `action_result` / `facts` / `discovery_policies`，并把 `agent_status` / `agent_uplink`
  改名为 `status` / `uplink`（**线上 JSON 不变**）。本仓只改 `use` / 类型路径，**无行为变化**。

## [0.1.24-alpha] - 2026-10-06

### 变更

- 依赖 `wist-api` `0.4` → **`0.5`**（该版把 `gateway` / `work` / `agent_uplink` 规范成 `v1` 子模块，
  报文路径经 `pub use v1::*` 不变——**非破坏、无行为变化**）。

## [0.1.23-alpha] - 2026-10-05

### 变更

- **`work` / `agent_uplink` 的 seam 报文改用 `wist-api`**：`PollWork` / `WorkGrant` / `AckWork` /
  `WorkAccepted` / `ReportWorkResult` / `WorkResultAccepted`（`wist-api::work`）与 `PollAgentUplink` /
  `AgentUplinkGrant`（`wist-api::agent_uplink`）；**领域 / 状态类仍在 `wist-contracts`**。
  **线上 JSON 不变**。依赖 `wist-api` 0.4。

## [0.1.22-alpha] - 2026-10-05

### 变更

- **agent 面其余 seam 报文改用 `wist-api::gateway`**：action-plan / action-results / facts /
  discovery-policies（`DispatchActionPlan` / `ActionPlanAck` / `ReportActionResult` /
  `ReportAgentFactSummary` / `PollDiscoveryPolicies` 等）由 `wist-api` 提供
  （`wist_contracts::gateway` 已整体移出）。**线上 JSON 不变**。

## [0.1.21-alpha] - 2026-10-05

### 变更

- **`agent/status` 报文改用独立 seam crate `wist-api` 0.2**：`AgentStatusReport` / `AgentStatusAck` /
  `AgentWorkState` / `AgentWorkStateChange` / `AgentCertificateStatus` / `AgentCredentialRenewal`
  由 `wist_api::agent_status` 提供（`wist_contracts::gateway` 里的对应报文已移出）。**线上 JSON 不变**。

## [0.1.20-alpha] - 2026-10-05

### 变更

- **对齐 `wist-contracts` 0.3；agent 注册/续期报文改用独立 seam crate `wist-api` 0.1**：
  `agent/enroll`、`agent/credentials:renew` 的请求/响应体由 `wist_api::enrollment` 提供
  （`wist_contracts::enrollment` 里的报文已移出）。**线上 JSON 不变**，纯依赖归位。
  报文引用的领域类型（`HostProfile` / `CredentialBundle` 等）仍在 `wist-contracts`。

## [0.1.19-alpha] - 2026-10-05

### 变更

- **对齐 `wist-contracts` 依赖**：由 `0.1` 升至 `0.2`（实际 0.2.0），与 `wist-center` 统一契约版本。
  网关侧用到的 agent 面契约（工作 / 上送 / 机器画像等）在 0.2.0 中未变；0.2.0 的破坏性变更集中在
  **网关 ↔ 中心注册/凭据（mTLS）** 类型，网关不消费这些类型，故无需改动。

## [0.1.18-alpha] - 2026-10-05

### 变更

- **对齐 `wist-control` 依赖**：由 `0.1` 升至 `0.6`（实际 0.6.1），与 `wist-center` / `wist-gwlinkd`
  统一契约版本、消除版本漂移。本网关用到的类型（`PollControlCommands` / `SubmitEnrollmentRequest` /
  `AgentInstallCode` / `AgentRuntimeStatus` / `DateTime` 等）在 0.6.1 中保持兼容。

## [0.1.17-alpha] - 2026-10-05

### 新增

- **gwlinkd 状态通道**（CR-003）：环回 `POST /api/v1/gateway/linkd-status`（host 侧 `wist-gwlinkd` 心跳推
  自身状态）+ admin `GET /api/v1/admin/gateway/linkd-status`（页面读；含服务端按**网关时钟**算的
  `age_seconds` / `stale`）。单行表 `gateway_linkd_status`（迁移 0025）；载荷**无密钥**（admin 可原样回显）。
  设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。

### 变更

- **接入请求的 CA 改为按 scheme 条件必需**：`POST /api/v1/admin/gateway/link-request` 只在
  `center_endpoint` 为 `https://` 时才要求 `trust_bundle_pem`；明文 `http://` 中心允许为空（无 TLS 可校）。
  https 无 CA 仍拒绝 —— 不允许静默回落到系统根。

- **自述面富化（进程 / 机队 / 存储 / 数据面 / 主机资源）**：`GatewaySelfState`（环回
  `GET /api/v1/gateway/self-state`）与 admin 读口（`GET /api/v1/admin/gateway/self-state`）新增
  `uptime_seconds` / 进程 `cpu_percent` / `memory_bytes` / 机队 `agent_count` / `online_agents` / `offline_agents` /
  `last_seen_lag_seconds` / `store_bytes` / 数据面 `ingest_accepted_total` / `ingest_rejected_total` /
  `last_ingest_at` / 主机 `memory_total_bytes` / `load_1m` / `load_5m` / `load_15m` /
  `disk_usage_percent` / `disk_total_bytes` / `disk_available_bytes`。量不出即 `null`。
  新增依赖 `sysinfo`（与 `wist-agentd` 同版本）。

## [0.1.16-alpha] - 2026-10-05

### 新增

- **页面发起接入的网关侧通道**（CR-003）：新增 admin 面 `POST/GET /api/v1/admin/gateway/link-request`
  （页面提交/查看接入物；视图**不回传**接入券与 CA）与环回 `GET /api/v1/gateway/link-request`
  + `POST /api/v1/gateway/link-result`（供 host 侧 `wist-gwlinkd` 拉取/回报）。
  存储：新增 `gateway_link_request` 单例表（迁移 0024）。见设计
  `wist-design/doc/design/edge/gateway-onboard-request.md`。

## [0.1.15-alpha] - 2026-10-03

### 新增

- **Agent 列表与运行状态能看到「这是哪台机器」**：机队页新增 **IP 列**，运行状态响应带上
  `hostname` / `node_id` / `ip_addresses`。凭客户端证书首触注册的机器以前机器画像是空的，
  现在由 agent 的状态上报自动补齐（网关侧新增原子回填，空值不覆盖已知画像）。
  依赖 `wist-contracts` 0.1.14。

### 说明

- **上线须先网关、后 agent**：状态上报契约新增了字段，旧网关会拒收带新字段的上报。

## [0.1.14-alpha] - 2026-10-03

### 新增

- **`Exporter`（定时导出器）来源可采**：采集内容目录里配了 `Exporter` 的单元不再被一律判成
  「接不了」—— 只要目标是**已知导出器 ID**（journald / `last` / `smartctl` / `nft` /
  `iptables-save` / `dmesg` / `auditd`），该单元就能置 `active` 并派下去采。
  判据与 agentd **同一个**（`wist-contracts::work::is_executable_source`，随 contracts 0.1.13 抬档）。

### 修复

- **知识库目录抬档后，知识包相关用例跟着走**：不再因 `catalog_version` 变化而假红。

### 说明

- 采集就绪度（单元 `status`）与解析就绪度（单元 `rule_ref`）口径不变：导出器只解决「采得到」。

## [0.1.13-alpha] - 2026-10-02

### 变更

- **新增机器类别 `LinuxHost`（通用 Linux 服务器）**。以前 Linux 只有「计算服务器 / 数据服务器」两类，
  一台普通服务器（docker/nginx/… 这类）用途规则一条都不命中，于是**永远没有用途建议** ——
  工作页也就无从归档、更派不出采集任务。现在 `linux-v1` 规则册带上了基线兜底：无命中时给出
  `LinuxHost`（置信度 0），普通 Linux 机器从此有建议可采纳。
- **Linux 侧第一个能真正派下去的采集面**：`linux-host-metrics`（主机指标，周期采）标为采集就绪。
  以前 Linux 的单元全是 `draft`，「面就绪」闸门对 Linux 全关 —— 判了类别也派不出活。
- **知识库版本抬档**：目录 `catalog_version` 2 → 3、用途规则 `purpose_version` 1 → 2。内容改了
  版本号要跟着走，否则 0.1.1 与 0.1.2 两版内容同标一版，`standing_work.catalog_version`
  这个归因锚就说不清「这条工作算自哪一版」。

## [0.1.12-alpha] - 2026-10-01

### 变更

- **知识库装载不再阻止网关启动**。以前「生效指针指向的包副本缺失/损坏」会让网关**拒绝启动**
  （现场真踩过：搬了库没搬盘 → 网关反复重启，页面上只看到连不上，日志埋在容器 stdout 里）。
  现在改成**告警 + 逐级回落**：管理面生效包 → 启动期 `source_dir` → 配置文件 → 空载。
  拒绝启动等于把**处置入口**（管理面）也一起关掉 —— 报错让人“用管理面切到另一个包”，
  而管理面正是起不来的那个进程。
- **新增 `[knowledge] source_dir`（出厂初始包）**：一个已解开的包目录。干净机器上管理面还没
  激活过任何包时就有内容可用，不必先手工导入一次；管理面一旦切了**可用**的包，包就接管。
  它配错/没铺只告警回落，**不挡启动**。
- **启动日志多一行** `knowledge source = package:<id> | dir:<path> | config-files | none`：
  一眼看出这次到底装的是哪一份。以前“空载”是完全静默的，现在不会再悄悄发生。
- 知识包不可用时的报错更有指向：给到**一个文件**（最容易犯的：把 tar.gz 制品当目录）会
  明说“要的是已解开的包目录”，不再含糊成一句 io 错误。

## [0.1.11-alpha] - 2026-10-01

### 变更

- **新增数据面上送的「启用开关」**（管理面「Gateway 信息」页）：打开后，本网关授权的**所有**
  Agent 都会开始上送日志与指标，**不必先逐台派工**。新装的机器由此不再“注册成功却什么也干不了”——
  这是这个开关存在的全部理由。默认**关闭**，升级后的行为与升级前**逐字一致**；
  开关与上送地址**共处一页**（那一页之前是只读的，改地址只能改部署配置）。
  改动对**已在网**的 Agent 下一个上报周期（≤30s）生效，**不需要重装**。
  代价要写清楚：它的粒度是**部署级** —— 开关打开时，撤回某台的工作**不再能单独停掉那台**
  （要单独停，就关开关或吊销该 Agent）。
- 上送设置与开关同一行存储：用旧客户端只提交地址时，**开关保持原值**——不会被顺带打开，
  也不会被静默关掉（后者会一次性掐掉全队上送，是更危险的那个方向）。
- 「Gateway 信息」页从**只读**改为分界：网关对外地址仍只读（由部署配置决定），
  数据面上送地址与开关变为**可改**；打开开关前会提示这是全队动作、影响多少台已注册 Agent。

## [0.1.10-alpha] - 2026-09-30

### 变更

- **Agent 身份收口为客户端证书（mTLS），删除 bearer 凭据**：agent 的日常上报 / 派活 / 数据面 /
  取包 / 续期都**只认 CA 签的客户端证书**，不再解析 `Authorization` 头；注册回包只下发客户端证书，
  不再下发 bearer token。
- **升级取包只接受 bootstrap token（新装）或客户端证书（升级）**，凭据 token 取包路径删除。
- **注册要求带 CSR**：未配 agent CA 或未带 CSR 直接拒绝（不再静默回落 bearer）。

### 修复

- **库丢失 / 换网关后的“自愈重建”能正常续期**：此前重建登记的实例未知，会把自愈后的第一次
  证书续期误判为 401；现已放行（身份已由证书验明）。
- 升级取包不再接受「未登记 / 已删除」agent 的证书。

## [0.1.9-alpha] - 2026-09-29

### 变更

- **新装 Agent 默认申请客户端证书（mTLS）**：生成的注册材料由 `credential_request = "bearer"` 改为
  `"csr"`。配合网关侧配置的 agent CA（`agent.agent_ca_cert_file` / `agent_ca_key_file`），agent 注册时就会
  用本地 CSR 换到一张客户端证书 —— 这也是**换库/丢库后 agent 能自动重建身份**（网关按证书重建登记）的前提。
  未配 agent CA 时行为不变（证书申请被忽略，回落 bearer）。

## [0.1.8-alpha] - 2026-09-29

### 变更

- **新装 Agent 的上送目标不必再人工录入**：管理面没设过「数据面上送地址」时，网关按部署配置派生
  ——与 Agent 拿到的控制面地址**同域** + 数据面端口 9000。「一台机器、一个域名」的部署因此
  **装完 + 派活即可上送**，不存在「地址还没录」这一步；待命期也会把进程列表等事实摘要推上去。
  管理面设过的值仍然优先（留给「数据面在另一台机器 / 非约定端口」的部署）。
- **`agent.package_file` 已删除**（破坏性）：安装包只认管理面录入的那一份。以前配置文件里那份
  「内置包」既可能与录入的来源不一致（分发地址与校验摘要各说一套），又会在文件缺失时把整个
  控制面拖下水。现在没录入就是**没有可用包**：`/api/v1/agent/packages/current` 回 `503`，
  安装脚本/签名回 `500` 且说明去哪补。

### 修复

- 安装包缺失时的错误口径不再把「录过但副本丢了」说成「未录入」。
- 老配置里残留的 `agent.package_file` 不会导致启动失败（未知键被忽略）。

## [0.1.7-alpha] - 2026-09-29

### 变更

- **内置 agent 安装包改为可选**：`agent.package_file` 为空、或指向的文件不存在，都**不再阻断启动**
  （只在日志里留一条告警）。以前一个包里缺失的安装包会让整个控制面起不来。
  真正用到它的端点会在被调用时明确报错：安装脚本 / 签名 → `500 未配置 agent 安装包…`；
  `/api/v1/agent/packages/current` 无可用包 → `503`。
