# 响应审批与签发 —— 实施计划

> 本文是执行清单，不是设计。设计见：
> - [`plan-attestation.md`](./plan-attestation.md) — 协议（证明形状 / 规范化 / 摘要 / 判定）
> - [`plan-external-signing.md`](./plan-external-signing.md) — 审批在哪做、谁持私钥、CLI、演进
> - [`wist-agentd/docs/design/plan-anchor-distribution.md`](../../../wist-agentd/docs/design/plan-anchor-distribution.md) — 锚怎么铺到机队
>
> 决策前提：**V1 用 CLI 审批、单审批人、网关不持私钥**。
>
> **进度**：M1（网关接口）、M2（`wist-approve` CLI）已落地并有测试；M3（前端去按钮）、M4（本机端到端）未做。
> ⚠️ **M1 不能单独上线到线上站点**：网关切外部签发后，页面那个「签发并下发」按钮会回
> `503 plan_signing_unavailable`（它发的请求体是 `{}`）—— M1 与 M3 必须同版本发布。

## 1. 范围

### 1.1 做

| 期 | 内容 | 影响的仓 |
|---|---|---|
| **V1（本期）** | 网关外部签发接口 + 审批公钥登记 + `wist-approve` CLI + 页面去掉批准入口 | `wist-gateway`、`wist-gateway-web` |
| V2 | agentd 锚目录化 + 升级搭车（解决 40 台的铺/换） | `wist-agentd`、`wist-gateway` |
| V3 | 角色分离（维护者/审批者 + approver scope token + 禁止自批） | `wist-gateway`、`wist-gateway-web` |
| V4 | 客户侧签名服务 + 钉钉/手机 | 新仓 / 客户侧 |

**V1 不动 agentd、不动栈。** 锚用现有的 `[attestation] trusted_keys`（一把钥匙）手工/CM 铺即可。

### 1.2 不做（本期明确排除）

- 多签 / R3 双人（`plan-external-signing.md` §8）
- 钉钉 / 手机审批 / 签名服务（V4）
- KMS 后端（接口按「本地私钥 + 可选 KMS」预留，实现后置）
- 锚目录化 / `anchor_sync`（V2）

## 2. V1-M1：网关外部签发接口

### 2.1 改动文件

| 文件 | 改动 |
|---|---|
| `migrations/sqlite/00NN_approver_key.sql` | 新表 `approver_key`（`key_id` 主键 / `owner` / `public_key` / `fingerprint` / `added_by` / `added_at` / `revoked_at`） |
| `src/infra/store.rs` `sqlite_store.rs` | trait + 实现：`upsert_approver_key` / `list_approver_keys` / `get_approver_key` / `revoke_approver_key` |
| `src/api/action_approvals.rs` | 新增 `signing_payload()`；`issue_approval` 支持请求体 `{attestation}` |
| `src/api/approver_keys.rs`（新） | `GET / POST / DELETE /api/v1/admin/approver-keys`；导入时算指纹、页面展示 |
| `src/api/codes.rs` | 新错误码（见 §2.3） |
| `src/api/mod.rs` | 挂路由 |
| `src/api/tests.rs` | 见 §2.4 |

### 2.2 接口

```
GET  /api/v1/admin/approvals/{id}/signing-payload
     → { approval_id, agent_id, approval{plan_digest,risk_level,approvers,required_approvers,approved_at,expires_at},
         plan, signing_payload }

POST /api/v1/admin/approvals/{id}/issue
     body 省略        → 现状（网关自签，需 [plan_signing]）
     body {attestation} → 外部签发：校验后注入 plan 并下发
```

### 2.3 校验与错误码（一条都不能少）

| 校验 | 错误码 | 状态 |
|---|---|---|
| 证明形状（`wist-validate`） | `attestation_invalid` | 400 |
| `plan_digest` == 库里重算值 | `plan_digest_mismatch` | 409 |
| `approval_id` 一致 | `approval_mismatch` | 409 |
| `approvers` / `required_approvers` 与投票一致 | `approval_mismatch` | 409 |
| `risk_level` 与库中计划一致 | `approval_risk_mismatch` | 409 |
| 签名 key 已登记且未吊销 | `approver_key_unknown` / `approver_key_revoked` | 409 |
| 公钥验签通过 | `signature_invalid` | 400 |
| 未登记任何公钥（外部模式） | `approver_key_unregistered` | 503 |

`issued_by` 一律从登记表取（`owner` + `key_id`），**不接受客户端声明**。

### 2.4 测试（API 层）

1. happy path：登记公钥 → 提交审批 → 批准 → `signing-payload` → 外部签署 → `issue` → 入队；
2. 篡改计划后签名 → `plan_digest_mismatch`；
3. 伪造 `approvers`（多写一个人）→ `approval_mismatch`；
4. 未登记 key_id → `approver_key_unknown`；
5. 已吊销 key_id → `approver_key_revoked`；
6. 签名用错钥匙 → `signature_invalid`；
7. **confused deputy**：请求体里夹带一份「别的计划」→ 只用库里的 `plan_json`，摘要校验失败；
8. 无请求体 → 仍走网关自签（回归保护）；
9. 无任何公钥且无 `[plan_signing]` → `503 approver_key_unregistered`。

### 2.5 验收 / 回滚

- `cargo fmt --check` + `cargo test --release --all --locked` 全绿（基线 1075）；
- 回滚：新端点与旧 `issue` 并存，去掉前端入口即可回到纯网关自签。

## 3. V1-M2：`wist-approve` CLI

### 3.1 放哪

**V1 放同仓 workspace 成员 `wist-approve/`**（根 `Cargo.toml` 加 `[workspace] members = ["wist-approve"]`）。

理由：

- 不新建仓、不动发布流水线；
- HTTP 客户端（`reqwest` blocking + `rustls-tls`）与 `clap` 只进 CLI，不污染网关二进制；
- 将来加 `wist-approve-svc` 只需再加一个 bin。

> 备选（若 workspace 化影响 CI）：`src/bin/wist-approve.rs`。缺点是网关 crate 的依赖全被编译一遍，
> 发布制品也混在一起。**默认走 workspace 成员。**

### 3.2 结构

```
wist-approve/
├── Cargo.toml
└── src/
    ├── lib.rs        # core：摘要重算、计划渲染器、签名、密钥读写
    ├── canonical.rs  # 与 wist-contracts 的规范化对齐（黄金向量测试）
    ├── render.rs     # op → 人读参数（未知 op / 未知字段 → 拒绝）
    ├── signing.rs    # PKCS#8 载入、Ed25519 签名、Zeroize
    ├── client.rs     # 网关 API（list/show/payload/vote/issue）
    └── main.rs       # clap 命令面
```

依赖：`wist-contracts`（registry 版本，**不要 path**）、`ring` 或 `ed25519-dalek`、`clap`、`reqwest`(blocking, rustls)、`serde_json`、`zeroize`。

### 3.3 命令面（V1）

```
key generate --out <path>              # 0600；打印 key_id + 指纹
key show     --key <path>
list         --gateway <url> [--token-file]
show         <approval_id>
approve      <approval_id>             # 仅投票
approve --sign <approval_id> --key <path>   # 投票 + 签名 + 提交
sign         <approval_id> --key <path>     # 已批单再签
submit       --attestation <file>      # air-gap 带回
status       <approval_id>
```

全局：`--ca-file`（私有 CA）、`--token-file`（默认 `~/.wist/approver.token`，0600）。

### 3.4 测试

| 用例 | 断言 |
|---|---|
| 黄金向量 | 对 `wist-contracts` 的 sample plan，`canonical` 输出摘要 == `plan-v1:sha256:a57a1ac0…` |
| 摘要不一致 | 包里的 hex 被改 → 拒绝签名（`digest_mismatch_local`） |
| 未知 op | `render` 返回 Err，命令退出码非零，不签名 |
| 未知字段 | 同上（除非 `--allow-unknown-fields`） |
| 密钥权限 | 0644 的文件 → 拒绝加载 |
| 签名可验 | 生成的 attestation 用公钥验过（单测内） |

### 3.5 验收

- 本机对着运行中的网关跑通「approve --sign」一条 R2（见 §5）；
- CLI 独立重算的摘要与网关一致（黄金向量 + 实跑双保险）。

## 4. V1-M3：前端

| 文件 | 改动 |
|---|---|
| `src/components/ApprovalsPage`（响应审批页） | **删掉批准/驳回/签发按钮**；保留状态、计划摘要、`plan_digest` 指纹、`key_id` 期望值；给出一条可复制的 `wist-approve` 命令 |
| 新增「审批公钥」区块 | 导入公钥、显示指纹、吊销；提示用语说明「签名在审批机上完成」 |
| 状态展示 | `pending / approved（待签）/ issued / dispatched` |

验收：单账号在页面上**无法**把一条审批变成已签发；页面文案不再暗示「点一下就下发」。

> 注：M3 之前页面仍可签发（走网关自签）。若某站点已切外部签发，必须在同一版本删掉按钮 ——
> 否则会出现「点了签发但服务端没有私钥」的 503 死路。

## 5. V1-M4：本机端到端（验证清单）

前提：网关 ≥ 含 M1 的版本；agentd 0.42（已支持 `[attestation]`）。

1. 审批机生成钥匙：`wist-approve key generate --out ~/.wist/site.key` → 记下 `key_id` 与指纹；
2. 页面「审批公钥」导入 `site.key.pub.pem`，核对指纹；
3. agentd 侧钉锚（**需 sudo**）：
   ```toml
   [attestation]
   enforced = false
   trusted_keys = [{ key_id = "…", public_key_pem_file = "/etc/wist-agentd/site.pub.pem" }]
   ```
   然后重启服务；
4. 提交一条 R2（金丝雀参数：`min_age_hours=8760`，匹配不到文件）→ 批准 → `approve --sign`；
5. 预期：命令队列 `acked/succeeded`；结果 `detail` 出现「attestation 已验签」；
6. 再翻 `enforced = true` 重启，重复一次确认仍通过。

## 6. V2：锚目录化 + 升级搭车

按 `plan-anchor-distribution.md` 执行。要点复述（避免误读）：

- 升级器**第一批**拿不到锚（旧 upgrader 忽略 `anchors`）→ 首次铺仍要带外；
- 升级通道只允许 **add** 新 key_id，**不允许覆盖已有**；
- 锚失败不阻断升级；`enforced` 不由升级携带；
- 启动期只校验形状，坏文件/冲突在 review 期降级。

## 7. V3：角色分离

| 项 | 内容 |
|---|---|
| 角色 | `maintainer` / `approver`（两个 scoped token） |
| 路由授权 | 审批投票/签发 → `approver`；计划提交/授权/升级 → `maintainer` |
| 禁止自批 | `requester == approver` → `409 self_approval_forbidden`（站点可显式放行） |
| CLI 凭据 | 只接受 `approver` scope（`approvals:list|read|vote|submit-attestation`） |

> V1 的临时状态：CLI 只能用 admin token。**必须在 V1 的发布说明里标注这是临时缺口**，
> 并在 V3 收掉（否则「维护者/审批者」分离无从谈起）。

## 8. 测试矩阵

| 层 | 覆盖 |
|---|---|
| 契约 / 规范化 | `wist-contracts` 黄金向量；CLI 侧同向量对照 |
| 网关 API | §2.4 九条（含 confused deputy 与旧路径回归） |
| CLI | §3.4 六条 |
| agentd（V2） | 目录扫描 / 逐文件降级 / 冲突告警 / anchors 六条规则 |
| 端到端 | §5 六步（advisory → enforced） |

## 9. 风险与回滚

| 风险 | 处置 |
|---|---|
| 网关升级后页面按钮仍能点 → 503 | M1 与 M3 **同版本发布**，或网关在外部模式下让页面自动隐藏入口 |
| CLI 密钥放笔记本被拷 | V1 先 0600 + 文档告警；V1.1 加口令加密（argon2 + AEAD） |
| admin token 被 CLI 拿走 | 临时缺口，V3 收；发布说明必须写 |
| 40 台锚靠手工 | V1 可接受（一把钥匙）；V2 上目录化 + 搭车 |
| 自签与外部签并存造成混淆 | 用请求体是否带 `attestation` 分流；日志与结果里标注 `issued_by` 来源 |

## 10. 任务清单（可勾选）

**M1 网关**
- [x] `approver_key` 迁移 + store CRUD
- [x] `GET /approvals/{id}/signing-payload`
- [x] `POST /approvals/{id}/issue` 接受 attestation（7 条校验）
- [x] `approver-keys` 管理接口（导入 / 列表 / 吊销 + 指纹）
- [x] 九条 API 测试
- [x] 审批终端分发面（`/api/v1/approver/packages|install|digests`，公开无鉴权）
- [ ] 发版（`wist-gateway` minor）

**M2 CLI**
- [x] workspace 化 + `wist-approve` 骨架
- [x] `canonical` 黄金向量（直接复用 `wist-contracts`，不写第二份）
- [x] `render`（未知 op/字段拒绝）
- [x] `signing`（PKCS#8 / 权限检查 / 自检验签）
- [x] `client` + 七个命令
- [x] 单测八条
- [x] 打制品 / 分发通道：CI `build-approver-cli`（三平台 tarball）+ 网关 `/api/v1/approver/…`
      + 栈 `scripts/install-approver-package.sh` 投放

**M3 前端**
- [x] 审批页去按钮 + 「下一步」命令行（含驳回命令）
- [x] 审批公钥管理区块（导入 / 指纹 / 吊销 + 重新启用）
- [x] 「安装审批终端」区块（按平台 + Agent 对外地址拼 `install.sh` 命令；没设对外地址就不给命令、改提示去设置）
- [x] 接口 + hooks（`useApproverKeys` / `useRegisterApproverKey` / `useRevokeApproverKey`）
- [x] `npm run build` + approval / approval-state / approval-error / i18n / routes 全绿
- [ ] 发版（`wist-gateway-web` minor，与 M1 同批）

**M4 端到端**
- [x] 开发态网关（`dev/svc.sh start gateway`）跑通：生成钥匙 → 登记公钥 → 提交 R2 → CLI `approve` → CLI `sign` → 已签发并下发
- [x] 第三方独立验签（Node `crypto.verify`，按 canonical_json 重算字节）
- [ ] agentd 侧「attestation 已验签」（需把真机指向带 M1 的网关，随发布做）

## 11. 五轮评审结论（V1 实现）

每轮一个视角，只看代码不看设计意图；已修的都补了测试。

| 轮 | 视角 | 发现 | 处置 |
|---|---|---|---|
| 1 | 安全 / 授权 | ① 吊销过的公钥能被一次「重导同一 key_id」静默复活（吊销常伴随安全事件）；② `issued_by` 是客户端可控字符串，直接拼进日志可伪造整行（日志注入）；③ 拒绝路径无留痕，现场问「为什么这条签名没收」只能翻响应体 | ① 加 `reactivate: true` 才恢复，判定放进 SQL 的 `CASE`（不可被竞态绕过）；② 两边日志都过 `log_field()`（控制字符→`?`，截断 120）；③ 加 `event=ExternalAttestationRejected`（含 HTTP 状态） |
| 2 | 并发 / 一致性 | ① 登记与吊销并发时，先读后写的实现存在「复活」窗口；② 重复签发靠 `issued_plan_json IS NULL` 收口（这条本来就对）；③ 待签包与 issue 之间若有人改票，`approvers` 比对会 fail-closed（本来就对） | ① 改为「SQL 内判定 + 写后回读」，响应以库里真实状态为准，冲突时打 `ApproverKeyRegisterKeptRevoked` |
| 3 | 契约 / 兼容 | ① 老客户端发 `{}` 会被 `IssueRequest` 的必填字段打成 422；② 错误码精度：`approval_mismatch` 的「换单」场景实际被 `wist-validate` 先拦（`approval_ref` 与 `approval_id` 绑定），回 400 `attestation_invalid` | ① `attestation` 改 `Option` + `#[serde(default)]`，`{}` / `null` 都回到网关自签；② 不改行为，改测试与文档写明「两道闸、先撞哪道」 |
| 4 | CLI 健壮性 | ① `approve --sign` 忘带 `--key` 会**先投票再报错**（票不可撤回）；② 非 TTY/无输入时确认默认取消（本来就对）；③ 过期计划/ttl≤0 都会拒签（本来就对） | ① 参数校验提前到投票之前；② 补 5 条单测：过期计划、ttl 非正、摘要不符、签名往返+篡改、有效期钳到计划到期 |
| 5 | 运维 / 文档 | ① 设计稿写「`issued_by` 由网关按属主填写」——签名覆盖范围内改不了；② 命令面缺 `reject`；③ 登记表缺 `reactivate` 语义；④ CLI 私钥权限口径比网关更严（0600）没写 | 全部回写设计稿；页面对应加「重新启用已吊销的钥匙」勾选 |

### 测试账（V1）

| 层 | 数量 | 覆盖 |
|---|---|---|
| 网关 API（外部签发 + 审批公钥） | 20 | happy path / 摘要 / 审批单 / 投票人数 / 风险 / 有效期（过期、超计划）/ 非 ed25519 算法 / 未登记 / 已吊销 / 坏签名 / 空注册表 / 已签发后取包 / `dispatch=false` / `attestation:null` 回退自签 / 轮换后旧钥失效 / 登记入口校验（key_id 穿越、非 PEM）/ 吊销复活 / 列表含吊销行 / 鉴权 401 |
| 网关单元（ed25519 / approver_keys / store） | 8 | PEM 往返、指纹稳定、大小写 hex、key_id 形状、错误信封、**吊销后重导不复活（SQL 层）** |
| CLI（lib） | 12 | PEM 往返 / key_id 派生 / 拒绝覆盖 / `--force` 覆盖 / 拒绝 0644 / 错误 label 的 PEM / 渲染已知 op / 拒绝未知 op / 拒绝未知参数 / 拒绝非对象 args / 拒绝非单一 invoke 步 / 错误信封 |
| CLI（bin） | 8 | 过期计划 / 非正 ttl / 摘要不符 / 签名往返+篡改 / 有效期钳制 / 事实拷贝（approvers/risk/key_id/issued_by）/ 非 hex 签名 / **`--version` 带发布版本与目标平台** |
| 前端 | 9 个契约测试 | build + approval / approval-state / approval-error / i18n / routes / launch / action-results / **approver-keys（含「审批页不得再有投票/签发」的源码闸）** / **approver-install（triple 白名单、命令形状、基址来源、页面确实渲染）** |

### 未覆盖（说明白，不装作做了）

- **并发实测**：重复签发、登记/吊销竞态靠 SQL 语义与单元测试保证，没有多线程压测。
- **CLI ↔ 真实网关的自动化**：M4 是做了一次手动端到端（含第三方验签），未写成 CI 测试（需要起网关 + 造 agent）。
- **agentd 侧验签**：由 agentd 自己 0.40+ 的测试覆盖；真机闭合等发布后做。
- **投放脚本的自动化**：`scripts/install-approver-package.sh` 在栈仓手工实跑过（投放 / 幂等 /
  带前缀目录的 tarball / `--check` 版本对不上），未写 shell 测试；`dev/lint.sh` 的 shellcheck 覆盖语法。

### 第六轮：制品与分发（补上的一个真缺陷）

前五轮只审了「签发链」，没审「CLI 怎么到客户手里」。补审时发现一个**只在发布后才发作**的错：

| 发现 | 处置 |
|---|---|
| 网关分发白名单复用的是 agent 的 `supported_agent_platform`（Linux 是 **musl** triple），
但 `build-approver-cli` 矩阵与安装脚本写的是 **gnu** —— 三者不一致。后果：`/api/v1/approver/install/x86_64-unknown-linux-gnu/install.sh` 在路由层就被白名单挡成 **404**；
栈脚本即使把文件投下去，也投在网关**不会去读**的目录里（下载端点恒 **503**） | 统一到 **musl**（并与堆的 `import-package.sh` / `check-stack.sh` 一致）：CI 改 musl target + `musl-gcc` 链接器，并在打包步骤对**当次产物**断言 `statically linked`；安装脚本的平台判定改 musl；栈脚本 triple 改 musl |
| 为什么必须是静态 musl（而不是“能跑就行”） | 审批人客户的人，跳板机常是 CentOS 7/8 这类老系统；gnu 制品绑 glibc 2.39，在那边连加载器都过不去。本地用 `cargo zigbuild --target x86_64-unknown-linux-musl` 验过：`ELF … statically linked`，4.3 MB |
| `--version` 恒定打印 crate 版本 `0.1.0`，与 Release tag 对不上（客户报障时无法确认装的是哪一版） | `wist-approve/build.rs` 把 `WIST_APPROVE_VERSION`（CI 传 `github.ref_name`）与 `TARGET` 编进二进制；`--version` 输出 `wist-approve v0.57.0-alpha (x86_64-unknown-linux-musl)`，本地构建回退到 crate 版本 |
| 栈脚本把 `ARTIFACT_HOME` 当“GitHub 组织基址”用 —— 与栈里那个同名变量（wist-knowledge 的源基址，默认指向 COS 镜像）**语义冲突** | 改成 `APPROVER_ARTIFACT_BASE`（含仓库 + 渠道，地址 = `<基址>/<tag>/<文件名>`），与 `ARTIFACT_HOME` + `KNOWLEDGE_PATH` 同形态；`upload-cos` 本就把附件原样推到 `<prefix=仓名>/<tag>/<文件名>`，所以同一段路径 GitHub 与 COS 都成立 |
| 换 tag 不会自动换制品（文件名固定，网关无从知道盘上这份是哪版） | V1 先把 tag 记在 `state/approver-package/VERSION`，`--check` 报告「制品是哪个 tag 投的」并与当前 `GATEWAY_TAG` 比对；真正的版本闸（`--version` ↔ `compat`）排 V2 |
| 为什么不把投放接进 `localize` | 隔离站点没外网，挂上去会让 `gops sys localize` 与升级的 `regenerate` 阶段直接失败；且 `gx.download` 的 `reuse_cache` 对固定文件名不判版本。写进 README / CHANGELOG 作为部署后手工一步 |
