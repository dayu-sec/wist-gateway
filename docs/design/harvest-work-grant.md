# wist-harvest 的工作授权（work grant）

> 状态：**设计稿（待评审）**。日期 2026-11-14。
>
> 已定决策：
> - **D1 = b**：harvest 用**独立的 worker 身份与凭据**，不复用 admin token；
> - **D2 = 新表**：按形状照抄 agent 的 work 表，但不与 `standing_work` / `one_shot_work` 混用；
> - **D3 = spec 由 admin 直填结构化参数**：采集目录（catalog）+ 提案（proposal）审批留到 P3；
> - **D4 = 接入与 agentd 一致**：本地生成密钥 → 交 CSR → 网关 CA 签客户端证书（mTLS），无 bearer 轨道；
> - **D5 = 不做兼容层**：**同版本发布、直接改**，旧 `enabled` 开关与 `/harvest/control` 一并删除，
>   不接受新老混版（混版时旧 harvest 会因 404 停采，是 fail-closed，不是采错）；
> - **D6 = `cadence.mode` 支持 `on_demand`**：只在收到一次性工作时采，不做定时；
> - **D7 = 云账号凭据不进网关**：授权只说「用哪个凭据」，真值仍只在宿主 secret 文件（§3.4）。
>
> 参照实现：`wist-api/src/work/v1.rs`（报文）、`wist-contracts/src/work.rs`（领域类型）、
> `wist-gateway/src/api/agent_ops.rs`（`poll_work` / `ack_work` / `submit_work_result`）、
> `wist-agentd/src/control/work.rs`（客户端应用与漂移）、`docs/design/agent-uplink-enablement.md`
> （「拉期望状态」的同一套取舍）。

---

## 1. 问题

### 1.1 现状（逐条，均已核实）

| 面 | 现状 | 位置 |
|---|---|---|
| 开关 | `harvest_setting` 单行布尔（`enabled`） | `migrations/sqlite/0041_harvest_setting.sql` |
| 下发 | `GET /api/v1/harvest/control` → `{enabled, revision?}`，harvest 每 30s 轮询 | `wist-gateway/src/api/harvest.rs`、`wist-harvest/crates/harvest-app/src/control.rs` |
| 采集范围 | 静态文件 `sources.d/source.toml`（vendor / assets / regions） | `wist-harvest` 容器挂载 |
| 节奏 | 容器启动参数 `run --run-at 00:30 --jitter 300s` | `docker-compose.yml` |
| 手工触发 | 无接口，只能 `docker exec ... wist-harvest once` | — |

### 1.2 五个缺陷

1. **没有工作身份**：开关是「网关级」的，答不出「谁在采」「采的是哪个源」。
2. **没有工作范围**：`enabled=true` 意味着「按文件里写死的范围全采」，改范围要改文件 + 重启。
3. **没有版本与漂移**：改了 `source.toml` 之后，中心和现场谁对谁错无从判断。
4. **没有确认**：网关不知道采集器有没有真的按它说的做。
5. **没有结果与审计**：跑没跑、成没成、跑了多久，只存在于容器日志里；「立即采集」无法审计。

这五条正是 agentd 的 work grant 已经解决的：`poll → WorkGrant{standing, one_shot, sequence}` →
`ack` → `result`，`plan_version` 不一致即漂移。

---

## 2. 目标与非目标

**目标**

- 采集指令**只来自网关**：standing（采什么、什么节奏）+ one_shot（立即跑一轮 / 重扫）。
- 本机配置只保留「怎么连、怎么跑」：worker 端点、`spool_dir` / `state_dir`、sink endpoint、超时与重试。
- 有 worker 身份、确认、结果、审计与漂移判定。
- 「立即采集」是一等公民（一次性工作），有 deadline、终态、结果回显。
- 云账号凭据**不进网关**：网关只持有凭据引用名（`credential_ref`），真值仍只在宿主
  `.wist/sec-value.yml`（§3.4）。

**非目标（本期不做）**

- 不改 agentd 的 work 契约与四张表；不动 `/api/v1/agent/*`。
- 不做采集目录 / 提案审批（D3）：`spec` 由 admin 直填，`proposal_id` 字段留空占位。
- 不做 harvest 多实例高可用 / 跨机抢占：一个 source 一个实例，进程内已有 flock 租约。
- 不做按客户多维聚合：一个网关仍只服务一个客户，租户身份由发送通道打标（不变）。

---

## 3. 角色、身份与凭据（D1 = b）

### 3.1 标识

| 字段 | 规则 | 例 |
|---|---|---|
| `worker_id` | `harvest:<source_code>`，source_code 取自数据源定义 | `harvest:tencent-cloud-prod` |
| `instance_id` | 进程启动生成，重启即换（与 agentd 的 `inst-<boot>` 同理） | `hinst-1792120077` |
| `source_code` | 数据源身份；一个 worker 只对应一个 source | `tencent-cloud-prod` |

**为什么一个 worker 一个 source**：一个数据源 = 一个供应商的**一个**账号（D11），多供应商 = 多个 worker/实例。
一个 worker 对应一条 standing，语义最简单，也避免「一份 spec 里混多个账号」导致失败归因不清。
同一供应商的第二个账号不在本设计范围内（那是另一个客户/另一套栈）。

### 3.2 接入（enrollment）——与 agentd 同一套（D4）

照抄 `docs/design/agent-identity-mtls.md` 的形态，不发明第二套：

```
① admin 在管理面签发一次性接入券（ttl 短、可吊销；与 agent 安装码同一张表/同一套语义）
② 现场把券写进 .wist/sec-value.yml（不进配置文件、不进页面、不进备份）
③ harvest 首启：本地生成密钥对（私钥不出这台机器）→ 生成 CSR
④ POST /api/v1/harvest/enroll {ticket, worker_id, instance_id, csr}   ← TLS 监听
⑤ 网关按 worker_id 填 subject / URI SAN，用 agent-ca 签客户端证书（37 天）
⑥ 证书与私钥落在采集器自己的 `state_dir/identity/`（`client.crt` / `client.key`，0600；
   私钥不出这台机器、不进备份），库里登记序列号/指纹
⑦ 到期前用**上一张证书**做链式续期（与 agentd 同一窗口与口径）：客户端读自己证书的
   `notAfter`，剩 ≤7 天就调 `POST /api/v1/harvest/credentials:renew`（同一把钥匙重签 CSR），
   新证书**先写临时文件再改名**；续期失败继续用旧证书并在下一拍再试
```

- **CSR 里的 subject/SAN 一律忽略**，主体由网关按 `worker_id` 生成（与 agent 同一条纪律，
  否则接入方能自封任意身份）。
- 身份 URI SAN 形如 `spiffe://<tenant>/<env>/harvest/<source_code>`（与 agent 的
  `spiffe://<tenant>/<env>/agent/<agent_id>` 同一条解析规则，靠 `/harvest/` 与 `/agent/` 段区分）。
- **没有 bearer 轨道**：P1 就是 mTLS（agentd 已经把 bearer 删干净了，harvest 不要重新引入）。
- 凭据**不进** `harvest.toml`（配置文件会进包、进备份）。
- `enroll` 成功 = worker 行建立（`status=pending`），第一次 `work:poll` 后转 `active`。
- 吊销：管理面 `POST /admin/harvest/workers/{worker_id}/revoke` 把 worker 置 `revoked`、
  证书记录标吊销。**执行点在应用层**（三个 worker 入口都回 403），**不是 mTLS 握手拒绝** ——
  验链器没有 CRL；证书序列号只用于审计，握手层吊销留 P3。
  harvest 收到 403 后**停止调度**（立即掉到「未授权」态）并打一条日志「凭据已吊销，停止采集」，
  但进程**不退出、也不停轮询**：撤销是网关侧的事实，客户端持续重试只是把「已吊销」
  这个事实反复读出来；等管理员解除吊销或补好证书，下一个重连周期就自动恢复
  （容器不重启也能自愈 —— 这是「同栈自动接入」的另一半）。

### 3.3 心跳

`work:poll` 即心跳：网关更新 `last_seen_at`。超过 `3 × poll_interval` 没 poll 的 worker 在页面上
标「失联」（与 agent 的 `last_seen_at` 口径一致）。

### 3.4 云账号凭据的边界（D7：授权 ≠ 凭据）

**结论：云 API 的 SecretId/SecretKey 永远不经过网关。** 这条是 agentd 的现成纪律，照抄：

> `wist-agentd/src/control/work.rs` 的 `KafkaGrant` 注释：
> 「只有“允许采”这一个结论：端点/协议/机制全部由 agentd 自探，凭据走本机 Secret。」

落地形态：

```toml
# 网关下发的 spec 里只有引用名，没有真值
"credential_ref": "tcloud:prod"
```

```toml
# 宿主 .wist/sec-value.yml（0640，属组 = 容器 gid；只读挂到容器 /secrets）
toc_secretid__prod  = "AKID..."
toc_secretkey__prod = "..."
```

```toml
# 本机 sources.d/<source>.toml：只写「从哪读」，core 不认识具体键名
[credential]
secret_id  = { file = "/secrets/sec-value.yml", field = "toc_secretid__prod" }
secret_key = { file = "/secrets/sec-value.yml", field = "toc_secretkey__prod" }
```

- 凭据**只在宿主**：不进网关 DB、不进工作授权、不进包、不进备份、不进页面。
- 启动时把真值注册进 `redact`（`harvest-tencent/src/source.rs` 现在就做），日志/报告/manifest
  的失败原因统一 `***`。
- 轮换 = 改宿主 secret 文件 → 重启 harvest（凭据在启动时加载）。若要免重启，P2 加「每轮开始前
  重读 `SecretRef`」；即便如此也不改「网关不持有真值」这条。
- **多供应商 = 多 worker**（D11：同一供应商只保留**一个**账号）：`credential_ref` 与 `source_code`
  一一对应；密钥文件里的键名按**来源（vendor）**区分（`toc_secretid` / `aws_access_key_id`），
  **不需要** `source` 后缀——那层后缀只为“同厂商多账号”服务，而那种场景本设计不支持。

**为什么不把云凭据放到网关下发**：一旦下发，网关就变成「云凭据库」——备份、日志、页面、支持
人员的最小权限都要重新评估；而收益只是「少一个现场文件」。真要集中管理，那是一个独立项目
（信封加密 + 按 worker 公钥封装 + 只读一次 + 审计），不属于本设计。

---

## 4. 线上契约（新端点）

**旧通道直接删除（D5）**：`GET /api/v1/harvest/control` 与 `harvest_setting.enabled` 在同一版里移除，
不做「新旧双写」也不做回落。新能力全部是新端点（`wist-contract-compat` 的铁律：加能力开新端点，
不往语义已被占用的路径里塞）。

### 4.1 端点

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/harvest/enroll` | 接入券换长期凭据 |
| POST | `/api/v1/harvest/credentials:renew` | 用上一张证书续期（同一把钥匙重签 CSR） |
| POST | `/api/v1/harvest/work:poll` | 拉工作授权快照（幂等） |
| POST | `/api/v1/harvest/work:ack` | 确认收到（`plan_version` 变化后也必须确认） |
| POST | `/api/v1/harvest/work:result` | 上报一次性工作的执行结果 |

鉴权：**mTLS 客户端证书**（D4，与 agentd 同一套 CA 与接入流程）。**不用 admin token**。
路由挂在 TLS 监听（不是明文 ingest 面）：`work:poll` / `work:ack` / `work:result` /
`credentials:renew` 都要求客户端出示证书；`enroll` 只凭一次性接入券（没有证书）。

**同栈部署怎么连**（这条决定现场能否「起栈即接入」）：

- 网关叶证书的 SAN 是 `<WEB_DOMAIN>,localhost,127.0.0.1` —— **不含服务名 `gateway`**。
  用 `https://gateway:3000` 连会在 TLS 验名阶段失败。
- 因此 compose 给 gateway 容器加一个**与 SAN 同名的网络别名** `${WEB_DOMAIN}`，
  harvest 的 `[gateway].endpoint` 默认留空，由 `scripts/init-harvest.sh` 按 `WEB_DOMAIN`
  推导成 `https://<WEB_DOMAIN>:3000`（容器内端口 3000，宿主 `${GATEWAY_PORT}`=443，两者别写混）。
- 结果是：**内网直连**（DNS 解析到 gateway 容器）+ **按对外域名验签**（证书 SAN 匹配），
  客户端不需要放宽任何校验（不引入 `danger_accept_invalid_hostnames`，也不加 SNI 覆盖）。
  跨机部署时显式填对端网关的 TLS 入口即可。

### 4.2 报文

全部 `#[serde(deny_unknown_fields)]`，`api_version` 固定 `"v1"`，`kind` 区分语义。

**poll**

```json
{
  "api_version": "v1",
  "kind": "poll_harvest_work",
  "worker_id": "harvest:tencent-cloud-prod",
  "instance_id": "hinst-1792120077",
  "last_seen_sequence": 12,
  "wait_ms": 0,
  "requested_at": "2026-11-14T08:30:00Z"
}
```

`last_seen_sequence` 只用于「这份跟我手上的一样吗」的短路；`wait_ms` 为将来的长轮询预留
（现在立即返回，字段先占位，免得改协议）。

**grant（响应）**

```json
{
  "worker_id": "harvest:tencent-cloud-prod",
  "source_code": "tencent-cloud-prod",
  "standing": {
    "work_id": "hsw:harvest:tencent-cloud-prod:inventory",
    "family": "inventory",
    "spec": {
      "credential_ref": "tcloud:prod",
      "vendor": "TENCENT_CLOUD",
      "assets": ["vpc", "subnet", "cloud_host", "eip"],
      "regions": "auto",
      "cadence": { "mode": "daily", "at": "00:30", "jitter_seconds": 300 },
      "rate": { "qps": 5.0 }
    },
    "catalog_version": 0,
    "proposal_id": null,
    "plan_version": 3,
    "effective_from": "2026-11-14T00:00:00Z",
    "status": "active",
    "updated_by": "admin",
    "updated_at": "2026-11-14T08:00:00Z"
  },
  "one_shot": [
    {
      "work_id": "hos:harvest:tencent-cloud-prod:inventory.run:20261114T083000Z",
      "action": "inventory.run",
      "spec": { "assets": ["vpc", "subnet"], "regions": ["ap-guangzhou"], "fresh": false },
      "scheduled_at": "2026-11-14T08:30:00Z",
      "deadline_at": "2026-11-14T09:30:00Z",
      "timeout_seconds": 3600,
      "interruptible": true,
      "status": "dispatched",
      "attempt": 0,
      "issued_by": "admin",
      "issued_at": "2026-11-14T08:30:00Z"
    }
  ],
  "sequence": 13,
  "granted_at": "2026-11-14T08:30:05Z"
}
```

- `standing` 可为 `null`（= 未授权 / 已撤销；此时 harvest 不调度）。
- `one_shot` 只带**未了结**的；已被撤回/过期的不再出现。
- 快照幂等：同一 `sequence` 重复拉取内容一致（除 `granted_at`）。

**ack**

```json
{
  "api_version": "v1",
  "kind": "ack_harvest_work",
  "worker_id": "harvest:tencent-cloud-prod",
  "instance_id": "hinst-1792120077",
  "work_id": "hsw:harvest:tencent-cloud-prod:inventory",
  "plan_version": 3,
  "acknowledged_at": "2026-11-14T08:30:06Z"
}
```

响应 `HarvestWorkAccepted { work_id, status: accepted|stale|unknown, accepted_at }`。
`plan_version` 变化后必须重新 ack，否则网关判定漂移（页面标红）。

**result**

```json
{
  "api_version": "v1",
  "kind": "report_harvest_work_result",
  "worker_id": "harvest:tencent-cloud-prod",
  "instance_id": "hinst-1792120077",
  "work_id": "hos:harvest:tencent-cloud-prod:inventory.run:20261114T083000Z",
  "status": "succeeded",
  "detail": "3 regions / 128 vpc / 402 subnet / 96 eip，耗时 4m12s",
  "reported_at": "2026-11-14T08:34:17Z"
}
```

- `status ∈ {running, succeeded, failed}`（与 agentd 的上报状态集一致）；进度用 `running` + `detail`。
- 覆盖式存储：一条工作一行，页面回答「这件活现在怎么样了」，不保留历史上报。
- `stale` 语义：工作已到终态（撤回 / 超时 / 已报过终态）时，结果**不覆盖**，响应 `status=stale`。

### 4.3 spec

`spec` 是**结构化对象**（不是 agentd 那种「字符串里套 JSON」的历史形态；新契约没有这个包袱）。

**standing（`family = "inventory"`）**

| 字段 | 类型 | 说明 |
|---|---|---|
| `credential_ref` | string | 凭据**引用名**（如 `tcloud:prod`）；网关只存名字，真值在宿主 secret 文件（§3.4） |
| `vendor` | string | `TENCENT_CLOUD` / `AWS`；与数据源定义一致，启动校验不一致即拒绝应用 |
| `assets` | string[] | `cloud_host` / `vpc` / `subnet` / `eip`；空数组 = 什么都不采（合法，但页面告警） |
| `regions` | string \| string[] | `"auto"` = 由采集器自己列全区域；数组 = 白名单 |
| `cadence` | object | `{mode:"daily", at:"HH:MM", jitter_seconds}` / `{mode:"interval", seconds}` / `{mode:"on_demand"}`；`on_demand` = 不排定时，只在收到 one_shot 时采（D6） |
| `rate` | object? | `{qps, burst}`；缺省用本机默认 |

**one_shot**

| action | spec | 说明 |
|---|---|---|
| `inventory.run` | `{assets?, regions?, fresh?}` | 立即跑一轮；`fresh=true` 忽略可续跑 spool |
| `inventory.rescan` | `{fresh:true}` | 强制开新 `snap_id`（下游按幂等键去重） |

> `cost.pull`（账单）**本期不做**：它落分片 + manifest、不进数据平面，生命周期与 inventory
> 不同，等采集链路稳定后单独排。

**三条纪律**（照抄 agentd 的教训）：

1. **解析失败不当“没事可做”**：spec 非法 → 上报 `failed` + 原样细节，页面显示「参数坏了」，
   harvest 不调度，而不是静默空转。
2. **整体替换**：不做字段级 merge；任何改动都 `plan_version += 1`。
3. **网关负责物化**：admin 提交的是「意图」，落库前由网关校验（`credential_ref` 非空、
   `assets` 取值合法、`regions` 为 `"auto"` 或非空数组、`cadence` 合法、状态合法）。
   **P1 不校验 `vendor` 与源的一致性**（网关没有源→厂商注册表）：采集器在应用时校验，
   不匹配就上报 `failed`；等 P3 的采集目录落地再前移到网关。

`cadence` 是**普通结构 + `mode` 判别字段**（`deny_unknown_fields`），不是 tagged enum ——
serde 的 `deny_unknown_fields` 对 tagged enum 不生效（多字段会被静默接受）。

### 4.4 客户端语义（harvest 侧）

| 场景 | 行为 |
|---|---|
| `work:poll` 404 | **版本不匹配**（网关没有工作授权端点）→ 不调度 + 报错，**不回落**任何旧通道（D5）；仍然重试（升级完网关就自愈） |
| `work:poll` 5xx / 网络失败 | 沿用上一份 grant（不打乱在跑的轮次）；**首拍失败则按未授权处理**（不采），与现有 fail-closed 一致；连续 6 拍（≈3 分钟）失败就**停用上一份授权**并重建连接（顺带重查证书） |
| 401 / mTLS 被拒 | 证书失效或被吊销 → 立即停调度；**客户端不退出、不退化成终态**，按拍重试（每拍只吼一次），证书修好/吊销解除后自动恢复 |
| 启动时没有证书也没有接入券 | 不退出：常驻、不调度，按 `poll_interval` 重试连接（同栈时 `harvest-bootstrap` 补上券即可自愈） |
| 证书剩 ≤7 天 | 建立连接时先续期（`credentials:renew`），成功才用新证书；失败继续用旧的 |
| 长跑进程（不重启） | **每 6 小时主动重连一次**：续期只发生在 `connect()`，只靠启动那一次的话，一次网络抖动就会让证书在 30 天后过期（= 又回到要人工干预） |
| 证书已过期 | 连接报错并要求重新接入（删 `identity/` 后重启，`bootstrap` 会重签券）；不自动删证书 |
| `sequence` 未变 | 短路，不重新应用 |
| `plan_version` 变大 | 停止当前调度 → 应用新 cadence/spec → ack |
| ack 版本**比期望新** | 网关回 `stale`（库被回滚 / 重建）：重新拉取即可自愈，回 `unknown` 会永久漂移 |
| 收到 one_shot | 先报 `running` → 按 `scheduled_at`/`deadline_at` 执行 → 报 `succeeded`/`failed`（**结果就是回执，不再单独 ack**） |
| one_shot 的动作语义 | `inventory.rescan` 一律 `fresh=true`（不看 `spec.fresh`）；`inventory.run` 才看 |
| 上一轮仍在跑 | 新的一次性工作**排队**（不丢弃），当前轮结束立刻开始；排到时已过 `deadline_at` 则直接报 `failed`（`detail="排队超期"`） |
| one_shot 失败 | **不反哺调度器**：一次手动失败不该把站点当天的定时采集整体拖后 |
| 重启 | `sequence` 从 0 重拉；**未了结的一次性工作会被重新执行**（本期不落盘已消费集合，重启代价是多跑一轮，不是数据损伤） |
| `service.enabled=false`（本地硬关） | 不调度、不上报任何结果，**但照旧 poll**：心跳与证书续期必须继续（否则硬关 37 天后证书过期，本地改回 true 也用不了） |

**已知取舍**：轮询断开后「沿用上一份授权」有 **≈3 分钟**窗口（6 拍 × 30s）。归零会让
「00:30 恰好抖 30 秒」丢掉一整天那一轮，而授权本身是幂等的 —— 选择可用性优先。
真要收紧，就在**触发那一刻**再判一次「上次成功 poll 距今 < 2×poll_interval」，而不是
把续用窗口设成 0。

---

## 5. 数据模型（D2 = 新表）

不复用 agent 的 work 表：那四张表的列名、查询与页面都绑 `agent_id`，混用会把「采集器」
塞进机队视图，且让 agent 的读写路径承担无关的回归面。

```sql
-- ① worker 登记与证书（无 bearer；身份就是证书，库里只存序列号/指纹供吊销与审计）
CREATE TABLE IF NOT EXISTS harvest_worker (
  worker_id     TEXT PRIMARY KEY,          -- harvest:<source_code>
  source_code   TEXT NOT NULL,
  instance_id   TEXT NOT NULL,
  credential_id TEXT NOT NULL,             -- 指向 harvest_credential（证书记录）
  status        TEXT NOT NULL,             -- pending | active | revoked
  enrolled_at   TEXT NOT NULL,
  last_seen_at  TEXT,
  revoked_at    TEXT,
  revoked_by    TEXT
);

CREATE TABLE IF NOT EXISTS harvest_credential (
  credential_id TEXT PRIMARY KEY,
  worker_id     TEXT NOT NULL,
  cert_serial   TEXT NOT NULL,             -- 吊销依据（CA 签出的序列号）
  cert_sha256   TEXT NOT NULL,             -- 指纹，页面展示与审计
  issued_at     TEXT NOT NULL,
  not_after     TEXT NOT NULL,             -- 37 天，链式续期
  revoked_at    TEXT
);

-- ② 常驻工作（一个 worker 一条，family 固定 inventory）
CREATE TABLE IF NOT EXISTS harvest_standing_work (
  work_id         TEXT PRIMARY KEY,
  worker_id       TEXT NOT NULL,
  family          TEXT NOT NULL,           -- inventory
  spec            TEXT NOT NULL,           -- JSON（结构化 spec）
  catalog_version INTEGER NOT NULL DEFAULT 0,
  proposal_id     TEXT,                    -- D3：本期恒为 NULL
  plan_version    INTEGER NOT NULL,
  effective_from  TEXT NOT NULL,
  status          TEXT NOT NULL,           -- active | paused | revoked（P1 单行；历史行 P2）
  updated_by      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_standing_worker ON harvest_standing_work (worker_id);

-- ③ 一次性工作
CREATE TABLE IF NOT EXISTS harvest_one_shot_work (
  work_id          TEXT PRIMARY KEY,
  worker_id        TEXT NOT NULL,
  action           TEXT NOT NULL,          -- inventory.run | inventory.rescan
  spec             TEXT NOT NULL,          -- JSON
  scheduled_at     TEXT NOT NULL,
  deadline_at      TEXT NOT NULL,
  timeout_seconds  INTEGER NOT NULL,
  interruptible    INTEGER NOT NULL,
  status           TEXT NOT NULL,
  pre_pause_status TEXT,
  paused_at        TEXT,
  paused_total_seconds INTEGER NOT NULL DEFAULT 0,
  current_step     TEXT,
  completed_steps  TEXT NOT NULL DEFAULT '[]',
  attempt          INTEGER NOT NULL DEFAULT 0,
  issued_by        TEXT NOT NULL,
  issued_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_one_shot_worker ON harvest_one_shot_work (worker_id, status);

-- ④ 确认（回答「期望的版本真到了吗」）
CREATE TABLE IF NOT EXISTS harvest_work_ack (
  work_id         TEXT PRIMARY KEY,
  worker_id       TEXT NOT NULL,
  work_kind       TEXT NOT NULL,           -- standing | one_shot
  plan_version    INTEGER NOT NULL,
  acknowledged_at TEXT NOT NULL
);

-- ⑤ 执行结果（回答「做得怎么样」）
CREATE TABLE IF NOT EXISTS harvest_work_result (
  work_id     TEXT PRIMARY KEY,
  worker_id   TEXT NOT NULL,
  status      TEXT NOT NULL,               -- running | succeeded | failed | timed_out | canceled | expired
  detail      TEXT NOT NULL DEFAULT '',
  reported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_harvest_result_worker ON harvest_work_result (worker_id);

-- ⑥ 授权序号（只用于判「快照变没变」）
CREATE TABLE IF NOT EXISTS harvest_work_sequence (
  worker_id  TEXT PRIMARY KEY,
  sequence   INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
```

**为什么 result 不复用 ack**：确认回答「我收到了」，结果回答「做成没有」；两者失败代价不同
（结果丢了 = 一次改变云上采集状态的动作没人知道结果）。与 `work_ack` / `agent_work_result`
的拆分理由一致。

---

## 6. 状态机

**standing**

```
（无） --grant--> active --pause--> paused --resume--> active
                    |                  |
                    +--revoke--------> revoked（终态，不删行）
                    +--replace-------> superseded（换 spec 产生的历史行）
```

- 只有 `active` 才采。
**实现对齐（P1）**：`harvest_standing_work` 目前是**单行 upsert**（`ON CONFLICT (work_id)`，
`worker_id` 上只有普通索引）。设计里的 `superseded` 历史行与「历史」页留到 P2；
P1 只保留当前授权 + `plan_version`。`revoked` 是终态：写入后暂停/继续都不再生效。

**one_shot**

```
dispatched --ack--> accepted --start--> running --成功--> succeeded
     |                 |                  |--失败--> failed
     |                 |                  |--超预算--> timed_out
     |                 |                  |--撤回--> canceled
     |                 +--过 deadline--> expired
     +--过 deadline--> expired
```

- `running` 可以多次上报（进度），终态只认第一次。
- `timed_out` 由网关判定（`scheduled_at`/`running` 起点 + `timeout_seconds`），不依赖采集器在线。

**漂移判定**

```
drift = (standing.status == "active") && (
           ack.plan_version != standing.plan_version
        || (ack 缺失 && now - standing.updated_at > 300s)
        )
```

实现把它折成三态（`ack_state`）：`in_sync` / `awaiting_ack`（还在 300s 宽限内）/ `drift`；
`standing` 非 active 时为 `inactive`。页面按这个三态渲染徽标，**不能把刚保存的授权直接标成漂移**。

---

## 7. 关键时序

**正常一轮**

```
harvest                          gateway
  |-- work:poll (seq=12) ---------->|
  |<-- grant (seq=13) --------------|
  |-- ack(plan_version=3) ---------->|
  |   （到点 / 收到 one_shot）
  |-- work:result(running) --------->|
  |-- work:result(succeeded) ------->|
```

**改 spec（漂移）**

```
admin 改 cadence → plan_version 3→4 → sequence +1
harvest 下一拍 poll 拿到 4 → 停调度 → 应用新 cadence → ack(4)
网关比对 ack.plan_version == standing.plan_version → 漂移消除
```

**手工触发（one_shot）**

```
admin 点「立即采集」→ 网关插 one_shot(dispatched, deadline=+60m) → sequence +1
harvest poll → ack → 到点执行 → running… → succeeded
页面「最近一次采集」直接读 harvest_work_result
```

**版本不匹配（D5：不兼容混版）**

```
harvest 与 gateway 必须同版本火车发布；混版时：
  新 harvest + 旧网关：work:poll 404 → 停止调度 + 报错（fail-closed，不会按旧行为错采）
  旧 harvest + 新网关：旧端点已删 → 404 → 停止调度（同上）
```

---

## 8. 管理面与页面

**管理面（HTTPS admin）**

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/admin/harvest/enroll-ticket` | 签发一次性接入券（明文只返回一次） |
| GET | `/api/v1/admin/harvest/workers` | worker 列表（状态 / 来源 / 心跳） |
| POST | `/api/v1/admin/harvest/workers/{worker_id}/revoke` | 吊销 worker（三个 worker 入口随后均 403） |
| PUT | `/api/v1/admin/harvest/standing` | 授权 / 改 spec（`plan_version` 在 SQL 里 +1） |
| POST | `/api/v1/admin/harvest/standing/{work_id}/{pause\|resume\|revoke}` | 暂停 / 继续 / 撤销（撤销是终态） |
| POST | `/api/v1/admin/harvest/one-shot` | 派一件一次性工作（动作 + 可选 spec 覆盖） |
| POST | `/api/v1/admin/harvest/one-shot/{work_id}/cancel` | 撤回未了结的一次性工作 |
| GET | `/api/v1/admin/harvest/works` | standing + 确认 + `ack_state` + 未了结的一次性工作（页面两张表） |

**gateway-web「云资产采集」页**

| 区块 | 字段 / 操作 |
|---|---|
| worker | worker_id、source、凭据状态、最近心跳、`失联/吊销` 徽标；右键操作：「立即采集」「忽略缓存重扫」 |
| 常驻工作 | 资产类型多选、区域、节奏（daily / interval / **on_demand**）、`credential_ref`、`plan_version`、状态、`漂移` 徽标；操作：保存（+1 版本）/ 暂停 / 撤销（P3：可编辑，P2 只读展示）|
| 手动触发记录 | `action / status（dispatched→running→终态）/ detail / issued_at / deadline_at`，未了结的可「撤回」 |

页面只读 `harvest_*` 的表投影，不读云凭据（与现状一致：`sec-value.yml` 不进页面）。
一次性工作的状态以后端工作行为准（结果上报会把它推进到终态），`detail` 直接展示——
失败原因原样给运维看，不要在页面上做二次翻译。

---

## 9. 迁移与升级（D5：不做兼容层）

**一个版本火车发完三仓**（gateway / harvest / web），不接受新老混版：

| 步骤 | 动作 |
|---|---|
| 1 | 网关镜像：新端点 + 六张表；**同一版删** `harvest_setting` 与 `/harvest/control` |
| 2 | harvest 镜像：只走 `work:poll`；旧 `[control]` 配置段删除 |
| 3 | gateway-web：开关页换成工作授权页 |
| 4 | 发布窗口内 harvest 停采（fail-closed），采完再走 standing/one_shot |

**一次性数据迁移（不是兼容层）**：**不做自动合成** —— `source_code` 属于本机数据源定义，
迁移无法替它决定，而「开/关」这一事实也没有地方挂（P1 一个 worker 一条 standing）。
因此 0042 **重命名**旧表为 `harvest_setting_removed_0042`（保留审计事实，不删数据）。

**同栈部署的自动化（`wist-harvest bootstrap`）**：栈里多一个一次性容器 `harvest-bootstrap`
（在 gateway 之后、harvest 之前跑）：

1. **接入就在 bootstrap 里做完**：用 `.wist/sec-value.yml` 里的 `admin_token` 调
   `POST /admin/harvest/enroll-ticket` 现签一张券，**当场换证书**并写到
   `<state_dir>/identity/`（0600，`run` 起来直接用）。
   - 顺序不能反：worker 行是 `enroll` 才建的，先建 standing 会 `harvest_worker_not_found`。
   - **不读 `state/enroll.ticket`**：那份可能是上一轮用过的旧券（券只能消费一次），
     拿它只会永远失败且下一轮读到同一份。要么现场显式给券，要么现签一张。
2. 仅当 `[service] enabled=true` **且该 worker 从未被授权过**时，用 `sources.d/source.toml`
   的 assets / regions 派生一条 `plan_version=1` 的 active standing（`updated_by` 仍由 admin token 指纹记录）。
   节奏取站点的 `HARVEST_RUN_AT` / `HARVEST_JITTER_SECONDS`（compose 同时传给 bootstrap 与 run）。

两条都是幂等的：已有证书 / 已有 standing 就跳过。因此「起栈即接入、开即采」，但券与授权
依然留痕（谁签的、什么时候建的）。

启动顺序与降级：compose 里 `harvest` 依赖 `harvest-bootstrap: service_completed_successfully`，
所以正常路径是「证书已就位 → harvest 直接开始轮询」。**但 harvest 不把这件事当启动前提**：
没有券/没有证书时它只打一条 warn、常驻不调度，按 `poll_interval` 重试 —— 因此 bootstrap 超时、
网关晚起、证书被删，都不需要人工重启容器（用户明确要求：失败要后台重试，不要等人重启）。
bootstrap 自己也因此**只告警、不炸启动**（退出 0）；只有「配置自相矛盾」才退 3。

**回滚**：三仓一起回退到上一版。因为旧表被删，**不支持只回退 harvest**。
这也是 D5 的代价，验收时必须把「回滚演练」算进去。

---

## 10. 观测与排障

**日志事件（harvest 侧）**

| event | 含义 |
|---|---|
| `HarvestWorkPolled` | 拿到新 sequence（首次 / 变化时打） |
| `HarvestWorkApplied` | spec 应用成功（含 plan_version） |
| `HarvestWorkDrift` | 本地生效版本 ≠ 期望版本 |
| `HarvestOneShotStarted/Finished` | 一次性动作生命周期（含 detail 摘要） |
| `HarvestCertificateRejected` | mTLS 握手被拒（吊销/过期）→ 停调度并持续重试 |
| `HarvestCertificateRenewed` | 证书临近到期已续期（附新旧 `notAfter`） |
| `HarvestGatewayConnected` | 接入成功（首次连上 / 断线后恢复） |

**常见故障**

| 现象 | 判定 | 处置 |
|---|---|---|
| 页面「未确认」 | 网关没收到 ack | 看 harvest 日志 poll 是否 200；网络/凭据 |
| 页面「漂移」 | ack.plan_version 落后 | 看 harvest 是否应用失败（spec 非法） |
| 「立即采集」一直是 dispatched | 采集器没 poll 或没 ack | 看 worker `last_seen_at` |
| 一直 running 超过 timeout | 云 API 卡住 | 网关判 `timed_out`；查 harvest 日志的云 API 请求 |
| 401 / mTLS 握手失败 | 证书被吊销或过期 | 看 worker 列表里的 `revoked` 徽标；过期就删 `identity/` 重启（bootstrap 重签券），吊销就解除吊销 —— 客户端会自己恢复 |
| 容器日志反复「接入网关失败」 | 没券 / 没证书 / 域名解析不到 | 查 `state/enroll.ticket`、`identity/client.crt`、以及 `docker exec … getent hosts <WEB_DOMAIN>` |

---

## 11. 测试与验收

**契约测试（wist-api / gateway）**

- poll 幂等：同 sequence 两次拉取内容一致；
- poll 未授权：`standing=null`、`one_shot=[]`；
- ack `stale`：旧 plan_version 的 ack 被识别为 stale；
- result `stale`：终态后再报不覆盖；
- 报文 `deny_unknown_fields`：多一个字段必须 400。

**客户端测试（wist-harvest）**

- 404（网关旧）→ 停采 + 报错，不回落；
- mTLS 握手失败 / 证书吊销 → 终态停采；
- 5xx 沿用上一份 grant；
- 重启不重复执行已消费的 one_shot（`state_dir/work.json`）；
- plan_version 变化 → 旧调度停止、新 cadence 生效；
- `cadence.mode=on_demand` → 不排定时，只响应 one_shot；
- one_shot 排队 / 超期 → `failed(detail="排队超期")`。

**端到端（栈内）**

- 用腾讯云真实账号跑 `inventory.run`（VPC 数量 > 0）→ atlas `network_domain` 出现真实 VPC；
- 页面「立即采集」→ 30s 内状态从 dispatched 变 running → succeeded，detail 有计数。

**版本约束（无兼容矩阵）**

| gateway | harvest | 期望 |
|---|---|---|
| 新 | 新 | 正常工作授权化 |
| 任一混版 | — | **停采并报错**（404 / 端点缺失），不得静默沿用旧行为 |

---

## 12. 分期

| 期 | 交付 | 依赖 |
|---|---|---|
| P1 | 报文 + 六张表 + mTLS 接入（券/CSR/续期/吊销）+ poll/ack + standing 管理面 + 页面只读 + `bootstrap`（同栈自动接入/初始授权） | 无 |
| P2 | one_shot（`inventory.run` / `inventory.rescan`）+ `work:result` 上报 + 页面「立即采集 / 忽略缓存重扫 / 撤回」+ 结果回显 + 到期回收 | P1 |
| P3 | standing 的页面编辑（资产多选 / 区域 / 节奏保存）、spec 目录化（catalog + 提案审批）、凭据轮换自动化、多**供应商**（vendor）展示 | P2、`knowledge-content-management.md` |

> D4 把 enrolment 与 mTLS 提前到 P1：它决定报文里的身份字段与信任锚，晚做等于返工。
> `worker_id` / `instance_id` P1 定型，不再动契约。

---

## 13. 决策记录

| # | 问题 | 结论 |
|---|---|---|
| 1 | `cadence.mode` 要不要 `on_demand` | **要**（D6）。`on_demand` = 不排定时，只响应 one_shot；页面选它时隐藏「节奏」时间字段 |
| 2 | `cost.pull` 是否本期入 | **不进**。本期 action 只有 `inventory.run` / `inventory.rescan`；`cost` 链路已存在，后续单独接 |
| 3 | 旧「开/关」是否保留并映射 | **不保留**（D5）。同版直接改，不做双写/回落；一次性迁移后删 `harvest_setting` |
| 4 | 接入券走 `wist-cred` 还是网关自签 | **与 agentd 一致**（D4）：复用网关的接入券 + `agent-ca` + CSR 流程，不引入第二套信任体系 |
| 5 | 云账号凭据怎么给 harvest | **不下发**（D7）。网关只存 `credential_ref`，真值只在宿主 `.wist/sec-value.yml`（§3.4） |
| 6 | 同栈部署要不要人工接入 | **不要**（D8 = B）：`harvest-bootstrap` 自动签券并建初始 standing，券与授权都留痕 |
| 7 | 失败后靠不靠重启恢复 | **不靠**（D9）：接入 / 续期 / 轮询都在后台退避重试；`bootstrap` 失败不再是启动前提 |
| 8 | 同栈端点怎么写 | **用域名不用服务名**（D10）：compose 给 gateway 加 `${WEB_DOMAIN}` 网络别名，`endpoint` 留空由 `WEB_DOMAIN` 推导 —— 证书 SAN 与验名一致，客户端不放宽校验 |
| 9 | 要不要支持同一供应商多个账号 | **不支持**（D11）：一供应商一账号一 worker。多账号一律走**多供应商**；真需要同厂商两个账号时，是另一个客户/另一套栈（换 `source_code` + 独立实例），不往本设计里塞。因此密钥键名按 vendor 命名即可，网关也不需要 vendor 注册表 |
