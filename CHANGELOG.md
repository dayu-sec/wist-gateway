# 更新日志

本文件记录 `wist-gateway` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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
