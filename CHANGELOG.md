# 更新日志

本文件记录 `wist-gateway` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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
