# 网关换域名 / 下发控制面端点（需求与方案）

> 状态：**需求与方案已定，暂不实现**（先记录）。
> 关联：[`gateway-access-security.md`](./gateway-access-security.md) §3.1（域名 = 网关身份）、§9（分期落地）、§8.1（网关短时不可用）。

---

## 1. 背景与需求

网关**对外域名**就是它的身份：它同时是证书 SAN、agentd 的 `control_plane.endpoint`、以及安装命令 / `install.sh` / 安装包分发 URL 的基址。

现状下要**变更这个域名**（例：测试域 `c-dev01.test.gw.jingang.cloud` 换到生产域），按最朴素的做法要**逐台重装 agent** —— 而重装成本高（发安装码、取包、装服务、重新注册）。

**需求：**

- 换域名**不应要求逐台重装 agent**。
- 最坏只接受**短暂不可上报**（并在恢复后**完整回放、不丢数据**）。
- 变更**不牺牲安全**：不能让"改 DNS / 改地址"变成伪造网关的途径。

**非目标（本方案不做，另案）：**

- 信任锚轮换（换 CA / 从自签叶证书切到 CA）。
- mTLS 身份锚迁移（把 agent 身份从数据库迁到证书）。
- 多级树拓扑。

---

## 2. 现状约束（来自代码与现网，方案据此推导）

1. **agent 本地只记两样东西**：`control_plane.endpoint`（域名）+ `control_plane.trust_bundle`（CA 根）。
   **凭据**（`bearer_token` / `credential_id`）存在 `state/`，不写配置。→ 换域名只动 endpoint；**锚不变 → 不需要重装、甚至不需要重新注册**。
2. **endpoint 是每次调用现读的**：agentd 对控制面的每个请求都读 `config.control_plane.endpoint`
   （`uplink:poll`、`work:poll`、`ack_work`、`report_work_result`、`renew_credential`）。
   → **改内存即下一轮（≤30s）生效，不强制进程重启**。
3. **但配置是启动时读一次进内存**（`AgentConfig`）→ 远端改**必须持久化**（写 `state/`，或回写 `agentd.toml`），否则一重启就退回旧地址。
4. **网关侧两条运行时设置**（DB，管理面「Gateway 初始化」页）：
   - `agent_advertise_url` —— 控制面对 agent **宣告**的地址，决定新装 agent 的 `endpoint`；**设置优先于** `server.public_base_url`（`effective_advertise_base`）。
   - `agent_uplink` —— 数据面 `host:port`，`uplink:poll` 现算。
5. **本地数据缓冲是有界且不丢的**：spool 默认 `spool_max_bytes = 268435456`（256 MiB），`spool_over_limit = "pause"` —— 满则**停读源 + 停 checkpoint**，回放成功自动恢复（`wist-agentd/docs/design/log-file-input-spec.md` §6.4 / §11.2）。
6. **现状没有「下发控制面 endpoint」的通道**：`uplink:poll` 只回**数据面**目标，不回控制面地址。

---

## 3. 方案对比

| 方案 | 做法 | 成本 | 主要取舍 |
| --- | --- | --- | --- |
| **A. 别名保留旧域名** | DNS 里旧记录不撤、证书 SAN 里旧名不删；新装用新名 | ≈ 0（多一条记录 + 一个 SAN） | 旧名长期占着（要一直持有该域 + 留在 SAN） |
| **B. 逐台改配置** | 逐台改 `control_plane.endpoint` + 重启 agentd | 逐台（比重装便宜） | 需人工触达每台；可作为 C 不可用时的兜底 |
| **C. 网关注册下发**（本方案） | 通过已有控制通道把新 endpoint 下发给 agent，agent 落盘 → 生效 | 网关侧一次配置 | 需给 agentd 加「下发/落盘/回退」三件事（见 §4） |

A 与 C 不互斥：**过渡窗口内旧域名本就必须仍可达**，A 是 C 送达的前提；A 也是零成本兜底。

---

## 4. 方案 C 设计（待实现）

### 4.1 数据流

- **网关侧**：新增「控制面端点」运行期设置 / 下发字段。语义可复用 `agent_advertise_url` —— 它本就是「网关希望 agent 连的地址」。
- **载体**：搭在 agent 主动出站的既有调用上（`uplink:poll` 或状态上报的响应里带一个 `control_plane_endpoint` 字段）。不新开连接、不要求网关反连 agent。
- **agentd 侧**：
  1. 收到 → 校验（https、有主机名、无控制字符 / shell 元字符、长度 —— **与 `server.public_base_url` 同口径**，复用同一判据）；
  2. 落盘到 `state/`（**不直接改 `agentd.toml`**，配置文件常是 root 所有）；
  3. 更新内存 config → 下一轮 poll 用新地址。

### 4.2 生效方式

- **不要求进程重启**（约束 2：endpoint 现读）；落盘保证重启后仍是新地址。

### 4.3 回退与安全（本方案的关键）

- **旧地址保留为 fallback**：新地址调用失败 → 回落旧地址，等下次成功 poll 再重试切换。→ **错推自愈**，把「永久锁定」压回「短暂」。
- 备选：两阶段（先连上新地址握手成功，再提交）。推荐 **fallback**（实现更简单，无需额外握手往返）。
- **送达只能走旧端点**：所以下发窗口内旧域名必须仍可达 —— 与方案 A 叠加。
- 下发通道**复用现有 bearer 凭据**；不接受控制字符 / shell 元字符。

### 4.4 与证书的关系

- 新 endpoint 的证书 SAN **必须含新域名**，否则 rustls 拒绝（`gateway-access-security.md` §3.3）。
- 本方案**不含锚轮换**，所以 `trust_bundle`（CA 根）不变、agent 不重装。
- 若将来要**同时换锚**：必须**先**用旧通道把新锚下发（否则切过去即被拒），复杂度升一档，另案。

---

## 5. 边界与取舍（必须记清的「短暂」到底多短）

1. **「短暂不能上报」有上限**：spool 256 MiB；满则背压停读源。**量不丢**，但源日志若在期间被 rotate / 删除，那段补不回 —— 别把窗口拉长。
2. **期间控制能力缺失**：授权 / 暂停 / 撤回 / 升级下不去。数据无碍。
3. **永久锁定的唯一成因** = **新地址错 且 旧地址不可达**（这条通道是你唯一的修复路径）。加 fallback 即消除。
4. **幂等**：重复下发同一地址无副作用。

---

## 6. 落地范围（本批）

- **做**：下发控制面 endpoint + 落盘 + 生效 + **旧地址 fallback**。
- **不做**：信任锚轮换、mTLS 身份迁移、多级拓扑。

---

## 7. 验收

- **单机切换**：改网关「控制面地址」→ ≤30s（一个 poll 周期）agent 改用新地址；期间产生的日志 spool 不丢。
- **回退**：把新地址改成不可达 → agent 回落旧地址，控制面连接自愈。
- **持久化**：切换后重启 agentd，仍是新地址。
- **边界**：非法地址被拒；重复下发无副作用。
- **数据完整性**：切换窗口内产生的日志在恢复后**全部回放**（对账条数）。

---

## 附：现网换域名操作清单（runbook）

1. 新域名 DNS A 记录就位（**旧记录先别撤**，TTL 短）。
2. 网关配置 + 证书：用同一张 CA 重签 SAN 含**新旧域名**的叶证书、改 `[server] public_base_url`，重启网关（证书只在启动时加载）。
   现成脚本：`DRY_RUN=1 ./dev/setup-domain.sh <新域名> c-dev01.test.gw.jingang.cloud` → 核对 → 去掉 `DRY_RUN` 正式跑（它会复用 CA、重签叶证书、改 `listen_addr`/`public_base_url`/`trust_bundle`，**不碰 admin token**）。端口不变加 `--keep-listen`。
3. 管理面「Gateway 初始化」页：把**网关对外地址**改为 `https://<新域名>`；**数据面上送地址** host 改为 `<新域名>`。
   > ⚠️ 这两条在 DB 里、**覆盖配置文件值**：只改配置文件而漏掉它们，新装 agent 仍会连旧域名。
4. 新装 agent 自动用新域名；**老 agent 只要旧域名还在就继续跑**（方案 A）。
5. 要彻底退役旧域名时，才需要触达老 agent —— 优先走方案 C（下发），否则退路是逐台改 `endpoint`（方案 B）或重装（下策）。
