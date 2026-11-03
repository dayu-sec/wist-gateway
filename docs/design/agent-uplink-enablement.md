# 数据面上送的启用与诊断（开关 / 原因 / 终态可见）

> 状态：**设计稿（待评审）**。定位：回答「新装的 Agent 为什么什么也干不了」与「它哑掉了为什么
> 没人知道」这两个问题，并把答案落成**三个可独立交付**的改动。
>
> **进度（2026-10-01）**：**§4.2 / §4.1 / §4.3 均已实现并验证**。
> - §4.2（wist-agentd 单侧）：终态落盘 `state/auth_terminal.json` + 每 `TERMINAL_RETRY_INTERVAL`
>   （300s）一次状态上报重试 + `diagnose` 新增 `identity.terminal` 检查；
>   e2e 新增「网关恢复后不重启即自愈」用例（`tests/agent_certificate_revoked_e2e.rs` 3 个全过）。
> - §4.1（wist-gateway + wist-gateway-web，**契约不变**）：迁移
>   `0022_agent_uplink_enabled.sql`（`enabled` 列，默认 0）+ `build_agent_uplink_grant` 改并集 +
>   管理面 API 收发该开关 + `/gateway-info` 的上送卡从只读改为可写（target + 开关）；
>   网关单测 486 全绿、web 17 个契约测试全过、`tsc -b` / `vite build` 干净。
> - §4.3（wist-agentd，仅 3a）：待命提示改为**并列两种原因 + 指到两处**，删掉那段死分支；
>   agentd 单测 546 全绿。**精确化变体没做**，理由见 §4.3。
>
> 相关：[`agent-identity-mtls.md`](./agent-identity-mtls.md)（凭据终态 code、续期、拒绝名单）、
> [`gateway-domain-change.md`](./gateway-domain-change.md)（同一类「管理面设置 + 运行期生效」）、
> [`gateway-access-security.md`](./gateway-access-security.md)（数据面信任边界）。
>
> 命名提醒：本文的「上送」一律指 **主机内容**（日志 / 指标）走数据面 TCP；**事实摘要不受它管**
> —— 事实在待命期也照常上报（`daemon.rs:1006-1023`），这是既有决策，本文不改。

> **标注约定**：**【现状】** = 代码已具备；**【待做】** = 本文要求、今天还不具备。

---

## 1. 目的与范围

**要解决的问题**：三个互相独立的缺口，症状却都指向同一句抱怨 ——「新装的机器什么也干不了 /
哑了没人知道」：

| 缺口 | 症状 |
| --- | --- |
| 上送启用只有一条**隐式**路径（有生效工作） | 新装机注册成功，却**永远待命**；管理面没有开关、也没有入口 |
| 凭据终态**不可自愈、外部不可见** | 机器静默数小时，`diagnose` 一路 OK |
| 待命原因的**诊断口径**是错的 | 提示指向「网关侧没有上送地址」，而地址明明配着 |

**范围**：上送授权的计算途径（§4.1）、凭据终态的自愈与可见（§4.2）、诊断口径（§4.3）。

**不在范围**：mTLS 身份体系本身（见 `agent-identity-mtls.md`）；数据面 ingest 的身份校验
（计划中的独立议题，见该文 §9 风险行）；上送地址的部署派生规则（`effective_agent_uplink`，已有）。

---

## 2. 现状（代码核对）

### 2.1 授权怎么算

**【现状】** 上送授权没有存储，是**每次被问到时现算**的（`agent_ops.rs:384-410`）：

```rust
// 语义摘要（原文见 agent_ops.rs:398-409，此处省去 await? 与 &state.store）
let has_work = !effective_standing(list_standing_work(agent_id)).is_empty()
            || !outstanding_one_shot(list_one_shot_work(agent_id)).is_empty();
let uplink = effective_agent_uplink(&config, &store).await?;   // 管理面设置 → 部署配置派生
match (has_work, uplink) {
    (true, Some(setting)) => enabled_at(setting.host, setting.port, granted_at),
    _                     => standby(granted_at),
}
```

两级来源与判据：

| 维 | 来源 | 现状 |
| --- | --- | --- |
| **要不要开** | 有生效工作（常驻 / 一次性） | 唯一来源，**没有独立开关** |
| **往哪开** | `agent_uplink` 表 → 派生（网关对外 host + 数据面端口） | 已具备（`install.rs:422-447`） |

### 2.2 为什么「新装了什么也干不了」

**【现状】** 新装机注册成功，但 `has_work = false` → 授权恒为 `standby`。管理面既没有
「启用上送」的开关，也没有录入入口 —— 启用**只由派活隐式决定**。

这不是要改的语义错，而是缺一个**明确动作**：运维想说「这台/这一批可以开始上送了」，
今天唯一的表达方式是替它派一份工作。

### 2.3 为什么「哑掉没人知道」

**【现状】** agentd 认到网关的**终态 code**（`TERMINAL_AUTH_CODES`，`enrollment.rs:43-48`：
`certificate_revoked` / `certificate_mismatch`）后，整轮 tick 被跳过（`daemon.rs:815-829`）：

```rust
if terminal {
    tokio::time::sleep(TICK_INTERVAL).await;
    continue;   // 状态 / 工作 / 上送 / 续期 / 本机采集 全部停
}
```

三个后果叠在一起就成了坑：

1. **不自愈** —— 终态只按「网关明确拒了」判定，之后**不再问**，凭据后来好了它也不知道；
2. **不落盘、不退出** —— 标志只在内存（进程留着是为了避开 KeepAlive 重启风暴），所以状态跨重启
   即清，但**只要不重启就永远静默**；
3. **外部不可见** —— `diagnose` 是新进程、没有这个标志，于是它照样报
   `[OK] 控制面可达且凭据被接受`（`doctor.rs:904-908` 自己发的一次 `fetch_uplink_grant`），
   页面上也只有一个「离线」。

### 2.4 为什么会「诊断指错方向」

**【现状】** `doctor.rs:1006-1011` 只用「grant 里有没有 `target`」来选提示语：

```rust
let why = if grant.target().is_some() {
    "控制面给过目标但没启用（多半是还没有生效工作）→ 到管理面派一份常驻工作"
} else {
    "控制面没给目标（网关侧没有可用的数据面上送地址）→ 在网关侧确认上送地址"
};
```

而**待命的两种原因都不带 target**（`AgentUplinkGrant::standby` 恒 `host/port = None`，
`wist-contracts/src/agent_uplink.rs:80-88`），于是「这台没有活」被一律解读成「网关侧没配上送地址」。

### 2.5 一次实测（2026-09-30，开发态）

一台新注册的 agent（`agent-host-9660eb694f0b`，agentd 0.1.17）：

| 时刻 | 现象 |
| --- | --- |
| 13:02:23 | 注册成功（`agent_instances.last_seen_at == started_at == registered_at`） |
| 13:02 → 16:59 | **四个小时里零外发**：状态没更新、`discovery_policy_version` 空、事实 0 行 |
| 16:56:41 | `diagnose` 报 `[OK] 控制面可达且凭据被接受`（grant 正常返回）+ `[WARN] 待命` |
| 16:59 | `launchctl kickstart -k` 重启一次 → `last_seen_at` 立刻更新、事实入库（891 进程） |

同一份 store 里，`agent_uplink` 明明有 `default → c-dev01.test.gw.jingang.cloud:9000`。
**结论：地址没问题、凭据没问题、网络没问题 —— 卡住的就是内存里的终态标志。**

---

## 3. 目标与不变式

**目标**

1. 新装机**零人工派活**也能被授权开始上送（由一个明确的开关表达）。
2. 凭据终态**能自愈**（网关恢复接受即自动恢复，不需要人工重启）。
3. 一个哑掉的 agent 能**被外部看见并说清原因**（`diagnose` 与页面）。

**不变式**（不得因为改动破坏）

- **事实摘要与授权正交**：待命期照常上报（`daemon.rs:1006-1023`）；开关也不得影响它。
- **默认零行为变化**：所有开关默认关闭，升级后行为与今天逐字一致。
- **不外发错**：任何"不确定"的判定都收敛到「待命」（今天的方向），不猜目标、不放宽凭据。
- **终态仍不重试成灾**：保留「不每 3s 刷日志」的初衷（`daemon.rs:822-823`）。

---

## 4. 决策

### 4.1 部署级「上送启用」开关

**决策**：`agent_uplink` 设置项增加一个 `enabled`，语义是**并集**而不是替代：

```
启用 = 有生效工作（今天） 或 开关打开（新增）
目标 = effective_agent_uplink()（不变）
两者缺一 → standby（不变）
```

- **为什么是部署级**：真正的运维问题是「这套网关现在收不收数据面数据」。按机器开关要面对
  「新机器怎么自动获得开关」的老问题，等于换了个地方重演 §2.2。细粒度（按机器 / 按工作族）
  列为开放项（§8）。
- **为什么是并集**：开关回答的是部署级问题（「这套网关收不收数据」），**它会盖过**「这台没有
  工作」—— 即开关打开时，**撤回工作不再能把某一台单独关掉**（要单独停就关开关，或吊销那台
  agent）。这是刻意的粒度取舍：否则开关对新装机（永远没工作）就不起作用。粒度细化列为开放项。
- **风险要写在页面上**：开关一开，**所有已注册机器**的日志/指标都会开始上送。录入区必须
  明确写这句，并在保存前给出影响面（至少给台数）。
- **默认 `false`**：升级后行为与今天完全一致。
- **实现后补的一点**：响应里多了一个 `enabled_configured`（这个 `enabled` 是不是管理面**录入**的），
  因为它与地址共用同一个响应，页面得能区分「从未录入过」与「录入过一次、开着/关着」；
  与 `updated_at` 同口径。请求里的 `enabled` 是 `Option<bool>`：前端表单**总是显式发**它，
  而**缺省 = 保持已存值**（既不能让老客户顺手把全队打开，也不能让它静默掉全队的上送）。
- **入口**：放在 `/gateway-info` 的「数据面上送地址」卡（从只读改为可写，target + 开关）。
  对外地址那一项仍**只读** —— 它由部署配置决定（改它要换域名/证书），管理面没有录入的必要。

### 4.2 终态可自愈 + 可诊断

**决策**：保留「不退出、不刷日志」，但补上**低频重试**与**落盘**。

- **重试**：终态下唯一允许的控制面请求 = **状态上报**，周期取与事实摘要同一尺度
  （5 分钟，`TERMINAL_RETRY_INTERVAL`），成功即清终态。**进入终态后的首个 tick 先试一次**
  （不等一个完整周期）—— 重启读回台账的机器因此能在一个 tick 内自愈，而不是白等 5 分钟。
  - 为什么用状态上报而不是 `uplink:poll`：它就是当初判终态的那条请求（`daemon.rs:937-943`），
    语义一致；且 `diagnose` 的探测口径也能与之对齐，不会「工具说一套、进程做一套」。
  - 失败**静默**：只在「进入终态」与「恢复」各打一行，中间不刷。
  - 联调口径：`WIST_AGENTD_TERMINAL_RETRY_SECS` 可压小这个间隔（仅供 e2e / 联调，见
    `docs/usage/agentd-install-and-usage.md` §4.6）—— 不能为了可测性把生产值调小。
- **落盘**：`state/auth_terminal.json`（`code` / `source` / `detected_at` / `attempts`）。
  - 启动时读回 → 日志里补一行「仍处终态（自 X 起）」，并**继续**低频重试（而不是等人工）。
  - **读不动** → 按「没有终态」继续，并把那份坏文件清掉（留着只会让 `diagnose` 每次 WARN，
    而守护进程永远走不到「清台账」那条路）；宁可多发几次请求，也不凭空造一个不可自愈的静默。
  - 恢复时删除；**删不掉**（目录突然不可写）就下轮再试 —— 机器已恢复却留着一份终态台账，
    `diagnose` 会一直报 FAIL，一个会撒谎的信号比没有信号更糟。
- **换 code 要跟着改**：仍被拒但网关换了理由（先 `certificate_revoked`，取消后又
  `certificate_mismatch`）时，台账的 code / since / source 都跟着走并留一行
  `AuthTerminalReasonChanged` —— 两个 code 的处置完全不同。
- **可见**：`diagnose` 新增一条检查 —— 文件存在即 `[FAIL]`，带 code 与处置
  （复用 `terminal_auth_advice`）。
- **不做**：让 agent 在终态里上报「我卡在终态」。被拒时它本来就发不出去（`agent-identity-mtls.md`
  §5.6 已定：被吊销以**网关侧**为准），页面上的离线 + last_seen 判据已经足够（`overview.rs:247`）。

### 4.3 待命原因的口径

**决策**：**先做 3a，明确不做 `reason` 字段。**

- **3a（文案 + 零契约变更）**：待命提示并列两种可能 ——「①这台没有生效工作 ②网关侧没有可用的
  上送目标/开关未开」，并保留本机配置目标的展示（已经在打），末尾给出「到管理面确认：开关与
  上送地址 / 这台有没有派工」。
- **可选的精确化（不破契约，但本次没做）**：网关用「`enabled = true` 但 `host/port` 为空」表示
  「开关开了、但没目标可以指」。它确实能区分三种原因里的两种，代价是**改变授权协议的一个形状**：
  目前 `enabled = true` 恒带目标，而这个新形状会让 `effective_output` 回落到**本机**的 `enabled`
  ——在一台本机配置写着 `enabled = true` 的机器上，它就真的开始外发了。那已经超出「改口径」的
  范围（§3 的「不外发错」不变式），所以本轮只做 3a。将来真需要时按 §6 的方式评估。
- **明确不做**：给 `AgentUplinkGrant` 加 `reason`。契约是 `deny_unknown_fields`
  （`a_newer_gateway_field_is_rejected_rather_than_ignored` 守的就是这条不变量），加字段是
  **破坏性变更**，代价（gateway 与 agentd 必须同批、混版期一串噪音日志）不抵收益（省一次猜）。
  将来真要精确到三种原因时再议，处理方式见 §6。

---

## 5. 实现拆分

**wist-gateway**

- 存储：新增迁移 `migrations/sqlite/0022_agent_uplink_enabled.sql`
  （`ALTER TABLE agent_uplink ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0;`）；
  `infra/store.rs:208` 的 `StoredAgentUplinkAddress` 加 `enabled: bool`，`get/upsert_agent_uplink` 读写该列；
- 派生值 `api/install.rs:435`：`enabled = false`（部署派生 **≠** 已启用）；
- 判定 `api/agent_ops.rs:394`：`want = has_work || uplink.enabled`；
- 管理面 `api/admin_ops.rs:2081/2119`：`AgentUplinkResponse` / `SetAgentUplinkRequest` 加
  `enabled`；`runtime-status` 的 `uplink_state` 形状不变（它说的是 **agent 实际生效**，
  `wist-contracts/src/agent_uplink.rs:117`）。

**wist-agentd**

- 终态落盘 / 读回 / 清除（`state/auth_terminal.json`）；
- 终态下 5 分钟一次的状态上报重试；两行留痕（进入、恢复）；
- `diagnose` 新增「凭据终态」检查，带 code 与处置；
- 待命提示改口径（§4.3 的 3a）。

**wist-gateway-web**

- `SubsystemGatewayInfoPage.tsx:172-234` 的「数据面上送地址」卡从**只读改成可写**：目标 + 开关
  （页头与页内「本页只读」的文案要一起改，`SubsystemGatewayInfoPage.tsx:60/74/76` 的注释就是
  当初为"只读"写的）；
- `api/admin.ts:275/283` + normalize 同步 `enabled`；`hooks/index.ts:264` 的 `useSetAgentUplink`
  **已存在**（只是没有页面用），直接接上。

**契约**：不改（`wist-contracts` 无需升版）。

---

## 6. 迁移与兼容

- **存储**：新列默认 `0`，旧库升上来后行为与今天逐字一致（这是 §3 的「默认零行为变化」）。
- **终态文件**：新文件，旧 agentd 不认识，无兼容问题。
- **若将来加 `AgentUplinkGrant.reason`**（本文不做）：契约 `deny_unknown_fields` ⇒ 必须
  gateway 与 agentd **同批**升级；混版时老 agentd 会把 grant 解析失败记为
  `UplinkFetch::Failed`，**保留上次 grant**（`control/uplink.rs:44-58`），不会静默走错，但会有
  一串 `event=UplinkGrantFailed`。发布序：先 gateway 后 agentd，接受中间那段噪音。
- **现场已知的重复身份**：库里积了三台同类记录（`…20affeee1df3` / `…397cfc253d6d` /
  `…9660eb694f0b`），是「重装丢私钥 → 换 agent_id」攒出来的，与本改动无关；离线记录可用页面的
  删除（已支持）清理。

---

## 7. 验收

1. 新装一台（注册成功、**不派任何工作**）→ 开关打开后 ≤1 个 poll 周期（30s）内开始上送日志/指标；
   开关关闭时行为与今天一致。
2. 事实摘要在「待命」与「启用」两种状态下**都**照常上报。
3. 制造一次终态（网关回 `certificate_mismatch`）→ agentd 静默但每 5 分钟重试一次；网关恢复接受后
   **无需人工重启**即回到正常 tick，且日志**只有**「进入终态」与「恢复」两行。
4. 终态跨重启保留，且 `diagnose` 在终态期间报 `[FAIL]` 并给出该 code 的处置。
5. 地址确实配着时，待命提示**不再**指向「网关侧没有上送地址」。
6. `/gateway-info` 能改目标与开关；保存后已入网 agent 在下一个 poll 生效，**无需重装**。
7. 开关默认关闭时，回归今天的行为（含 `build_agent_uplink_grant` 的四种组合）。

---

## 8. 开放项

1. **开关的作用域**：部署级（本文）vs 按机器 / 按工作族。倾向部署级 —— 细粒度会把「新机器怎么
   自动获得开关」的问题搬回来。先不做。
2. **开关打开前的影响面提示**：页面是否显示「将影响 N 台」并在保存前确认。倾向要（这是全队动作），
   实现时与 UX 一起定。
3. **`reason` 字段**：本文用 §4.3 的零契约方案替代。若要精确到「没地址 / 没开关 / 没活」三种，
   再按 §6 的方式评估破坏性变更。
4. **页面如何呈现「凭据终态」**：今天只有「离线」。是否要在机队视图上把它标成
   「凭据被拒（需处理）」而不是普通离线 —— 需要 agent 侧上报一个终态标记，而终态期间它发不出去
   （§4.2），所以倾向**不做**，靠 `diagnose` 与运维流程覆盖。

---

## 9. 交付顺序

1. **§4.2 终态自愈 + 可诊断**（最独立、最小，且它是「机器哑掉没人知道」的根因）；
2. **§4.1 开关 + 入口**（做完后新装机才真正能跑起来）；
3. **§4.3 口径**（3a 半小时，可随手带上）。

发布面（按 rust-gx）：`wist-gateway`（制品 → alpha）、`wist-agentd`（制品 → alpha）、
`wist-gateway-web`（制品 → alpha）。契约不动。
