# 知识库内容的管理与发布（策展数据进网关）

> 状态：**设计稿（待评审）**。已定：**§8.1 选 B（热加载 + 世代归因）**，连带 **§17.1**
> （`purpose_version`）为其前置。定位：网关侧的**管理面入口 + 存储 + 生效语义 + 离线投放**，
> 以及它与 `wist-knowledge` 制品之间的**包契约**。
>
> 相关：`wist-knowledge`（创作源 + 制品，已发 `v0.1.0`）、
> [`gateway-domain-change.md`](./gateway-domain-change.md)（同一类"管理面设置 + 生效"问题）、
> [`agent-identity-mtls.md`](./agent-identity-mtls.md)（Ed25519 与信任锚的既有做法）。
>
> 命名提醒：**代码里叫 `content`（策展数据），仓里叫 `wist-knowledge`**，本稿统称"知识库内容"。

---

## 1. 目的与范围

**要解决的问题**：知识库内容（采集目录/包/模板 + 用途规则 + 发现策略）今天只能靠
「改网关卡器的 `wist-gateway.toml` + 把文件放进配置目录 + 重启」落地。管理面**没有入口**：
没有来源设置、没有录入历史、没有生效/回滚、没有页面。

**范围**：包契约、存储模型、管理面 API、生效语义、受控加载、离线投放、可观测性、前端入口。

**不在范围**：中心侧的统一分发；内容创作流程本身（在 `wist-knowledge`）；
`purpose-rules.toml` 的规则内容（是策展产物，不是网关的事）。

---

## 2. 现状（代码核对）

### 2.1 今天怎么装载

| 内容块 | 配置字段（`infra/config.rs:120-150`） | 启动期装载 | 运行态持有 |
| --- | --- | --- | --- |
| 采集目录三件套 | `[content] catalog_file / packs_file / templates_file` | `load_content`（`api/mod.rs:162`） | `ApiState.content`（`:114`） |
| 用途规则表 | `[purpose] rules_file` | `load_purpose_rules`（`:126`） | `ApiState.purpose_rules`（`:104`） |
| 发现方向策略 | `[discovery] policies_file` | `load_discovery_policies`（`:144`） | `ApiState.discovery_policies`（`:109`） |

- 三者都是**启动期装载一次**、装进**不可变**的 `Option<Arc<…>>`（`api/mod.rs:99-116` 的注释写明
  "改规则通过重启生效，**不做热加载**"）。
- `AdminConfig::validate` 在启动前用真实装载器校验过一次（**内容写错就起不来**，
  `api/mod.rs:160`）；`build_state` 里那次装载若再失败，只记警告并降级为"未装载"。
- 管理面只有**只读**视图：`GET /api/v1/admin/content`（`api/mod.rs:367`）、
  `GET /api/v1/admin/discovery-policies`（`:401`）。

### 2.2 为什么不够

1. **部署耦合**：换一版模板要改 toml、动文件、重启网关 —— 而网关是**容器**，
   宿主路径在容器里根本看不见（这个坑已经在安装包上踩过，解法是 `scripts/import-package.sh`）。
2. **没有审计**：谁都答不出"现在生效的是哪一版、谁什么时候换的、换之前是哪版"。
3. **换版有中断**：重启是部署动作（`docker compose restart`），不是管理动作。
4. **空载无声**：没配 → `/admin/content` 回 503（正文只有一句 `content catalog is not configured`，
   见 `api/content_ops.rs:76-84`），页面上通常只呈现一句笼统失败提示。运维要回答的
   "为什么没推系统类型 / 为什么没派活"，今天**无处可看**。

### 2.3 现网实际状态

`gateway-alone/wist-gateway-stack/configs/gateway/wist-gateway.toml` 里 `[content]` / `[purpose]` /
`[discovery]` **三段都没有**，也没有 `content/` 目录 → 网关**空载**：
不产"系统类型"建议、不产用途建议、发现策略走 agentd 内建默认值。

### 2.4 可复用的参照物：Agent 安装包

| 构件 | 位置 |
| --- | --- |
| 当前生效来源（单例） | `agent_install_package`（`migrations/sqlite/0002_*.sql`：address / sha256 / updated_by / updated_at） |
| 录入历史（内容寻址） | `agent_install_package_history`（`0016_*.sql`：`pkg-<sha16>` / source 留痕 / sha256 / version / arch / **cached_path** / created_by / created_at） |
| 拉取 + 双份缓存 + 解析身份 | `api/install_package.rs`：`fetch_into_package_cache`（`:132`）、`package_id_for_sha256`（`:156`）、`read_package_identity`（`:322`） |
| "没有内置回落" | `effective_package_path`（`:83`）——来源**只认**管理面录入那份 |
| 管理面 API | `GET/POST /api/v1/admin/agent/install-package`（`api/mod.rs:373`）、`GET …/install-packages`（`:379`） |
| 离线投放 | `wist-gateway-stack/scripts/import-package.sh`（宿主 `packages/` → 容器内 `/packages/…`，`--set` 顺手设来源） |
| 前端 | `/install-package`（`wist-gateway-web/src/App.tsx:29`） |

**知识库照这套骨架走**，但有三处**必须不一样**（见 §4、§8）。

---

## 3. 目标与不变式

| # | 不变式 | 依据 |
| --- | --- | --- |
| I1 | 内容**只有一个真相**：来源只认 store，**退役**配置文件里的 `*_file` | 同 `agent.package_file` 的先例（"两处真相必然漂移"） |
| I2 | **录入 ≠ 生效**：`录包` 与 `切指针` 是两个动作，切可回滚 | 这是与安装包最大的差别（见 §4） |
| I3 | **不追改在跑的东西**：已授权工作锁在展开时那一版目录（`standing_work.catalog_version`，`0009_work_grant.sql`） | 既有约定 |
| I4 | **不匹配就不生效**：sha256 / 签名 / schema 兼容 / 逐文件解析校验，任一不过**拒绝激活** | 同"校验不过起不来" |
| I5 | **空载必须看得见**：不是 503 哑谜，而是页面上明确写出"未配置知识库 + 补什么" | §2.2(4) |

---

## 4. 概念模型

| 概念 | 是什么 | 今天对应的东西 |
| --- | --- | --- |
| **包**（`package_id`） | 一次录入的内容寻址副本（`kbp-<sha256 前 16 位>`），落在网关自己的目录里 | 安装包的 `pkg-…` |
| **内容版本** | 包内五份文件各自声明的版本（`catalog_version` / `template_version` / `policy_version` / 规则表版本） | 已有，但 **purpose 缺版本字段**（§17） |
| **生效指针** | 单例：现在生效的是哪个 `package_id` + 一个**单调递增的世代号** `generation` | 安装包的 `agent_install_package` 单例（但那个没有"世代"） |
| **工作锁** | 每条已授权工作记的 `catalog_version`：它展开时用的是哪一版目录 | 已有（`standing_work.catalog_version`） |

**与安装包的三处差别**（本设计的重点）：

1. **录入与生效分离**（I2）：安装包"录入即生效"（只有一个来源单例），因为分发出去的就是那一份。
   知识库要**先录入、验过、再切**，所以必须有独立的生效指针（`knowledge_active`）与切换留痕（`knowledge_activation_log`）。
2. **网关是消费者、不是仓库**：不需要"分发地址"这种对外的来源设置，也不需要"按 id 取包给外人"的端点。
   包只被**网关自己**装载。
3. **必须支持旧版共存**（I3）：安装包换版后老的升级计划按 id 取旧包即可；
   知识库换版后，**锁在旧目录版本的工作仍在跑**，所以 `<state>/knowledge/<package_id>/` 里每一版都要留着。

---

## 5. 包契约（与 `wist-knowledge` 制品的接口）

### 5.1 文件名与顶层目录（**已就绪**）

```
wist-knowledge-<version>.tar.gz         顶层一层同名目录
  └── wist-knowledge-<version>/
        catalog.toml  packs.toml  templates.toml  purpose-rules.toml  aspect-policies.toml
        manifest.json
```

已按安装包同一约定对齐（`<名字>-<版本>`，见 `api/install_package.rs` 的 `read_package_identity`）。
顺带记录一个**已验证的既有缺陷**：`wist-agentd` 的发布包顶层是 `artifacts/` 且包名带 `v` 前缀，
所以 `read_package_identity` 对它恒返回空串 —— 升级历史里的 version/arch 一直是空的。
**知识库的包不要重复这个错**（本设计以契约形式钉住顶层目录名）。

### 5.2 `manifest.json` 字段

| 字段 | 现状 | 本设计 | 说明 |
| --- | --- | --- | --- |
| `name` / `version` | ✓ | ✓ | 制品名与制品版本（tag 去 `v`） |
| `created_at` / `commit` | ✓ | ✓ | 留痕（`created_at` 使包**不可复现**，见 §17） |
| `content_versions` | ✓ | ✓ | `catalog_version` / `template_version[]` / `policy_version` |
| `files` | ✓ | ✓ | 文件名 → sha256（**网关逐条核对**，不信任何单一摘要） |
| `parser_abi` | ✗ | **新增（整数）** | 内容所依赖的网关解析器契约版本，见 §10 |
| `channel` | ✗ | 可选 | 若将来知识仓再分通道，用它表达；当前组件制**不需要** |

### 5.3 签名（`.sig`）

- 产物：`.sha256` + `.sig`（与 `.tar.gz` 同名不同后缀，一起投放/下载）。
- 签名对象 = **sha256 摘要的十六进制文本**（就是 `.sha256` 里那串，不带文件名）：
  运维拿 openssl 能手工重验，也不受压缩实现差异影响。格式：base64 的 Ed25519 签名，一行。
- 谁签 / 谁验：**`wist-knowledge` 的 CI 签**（私钥只在 GitHub secret），**网关只验**（公钥在配置）。
  与 install.sh 的签名方向相反（那个是网关签、目标主机验）——**另一把钥匙**，不复用。
- 完整口径（包括"它到底挡什么、挡不了什么"）见 §9。

### 5.4 校验顺序（录入时就跑完，任一失败即拒收）

```
读到字节 → 1) sha256（对得上调用方给的期望值，若给了）
        → 2) 签名（若配了公钥；M2 起必过）
        → 3) 解包到**临时目录**，逐条核对 manifest.files 的 sha256
        → 4) manifest 自洽（content_versions 与文件里声明的版本一致）
        → 5) parser_abi 与本网关兼容（§10）
        → 6) 用**真实装载器**逐块解析校验（load_content / load_rule_table / load_policy_table）
        → 7) 原子 rename 进 <state>/knowledge/<package_id>/
```

第 6 步是关键：**用什么解析器校验，就用什么解析器装载**（同一份代码），避免"校验一套、装载一套"。

---

## 6. 存储模型

### 6.1 表（草案）

```sql
-- 录入过的知识库包（内容寻址，一行一个包）—— 对应 agent_install_package_history
CREATE TABLE IF NOT EXISTS knowledge_package (
  package_id     TEXT PRIMARY KEY,          -- kbp-<sha256 前 16 位>（幂等：同包重复录入落同一行）
  source         TEXT NOT NULL,             -- 原始录入（/abs/path 或 https://…）。只留痕，不做取包来源
  package_sha256 TEXT NOT NULL,             -- 网关据自己缓存的那份字节算的，`sha256:<64 hex>`
  version        TEXT NOT NULL DEFAULT '',  -- 制品版本（包内目录名 / manifest.version）
  catalog_version    INTEGER,
  template_version   INTEGER,
  policy_version     INTEGER,
  parser_abi     INTEGER NOT NULL,
  signed_by      TEXT NOT NULL DEFAULT '',  -- 签发者标识（公钥指纹）；M1 为空
  cached_path    TEXT NOT NULL,             -- <state>/knowledge/<package_id>
  created_by     TEXT NOT NULL DEFAULT '',
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_package_created ON knowledge_package (created_at DESC);

-- 生效指针（单例）
CREATE TABLE IF NOT EXISTS knowledge_active (
  setting_id   TEXT PRIMARY KEY,            -- 固定 id
  package_id   TEXT NOT NULL,
  generation   INTEGER NOT NULL,            -- 单调递增：装载到内存的那一份的世代号
  activated_by TEXT NOT NULL DEFAULT '',
  activated_at TEXT NOT NULL
);

-- 切换留痕（审计）：回滚也要留痕
CREATE TABLE IF NOT EXISTS knowledge_activation_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  from_package TEXT,                        -- 首次激活为空
  to_package   TEXT NOT NULL,
  generation   INTEGER NOT NULL,
  reason       TEXT NOT NULL DEFAULT '',    -- activate | rollback | repair
  requested_by TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL
);
```

### 6.2 目录布局

```
<网关状态目录>/knowledge/
  kbp-3f2a…/            # 每个包一份，按内容寻址；**旧版留着**（I3）
    catalog.toml  packs.toml  templates.toml  purpose-rules.toml  aspect-policies.toml
    manifest.json
```

安装包的单例缓存在 `AdminConfig::install_package_cache_path()`（`infra/config.rs:517`）；
知识库**不需要单例缓存**——生效指针指向哪份就直接读哪份。

---

## 7. 管理面 API（草案）

| 方法 | 路由 | 语义 | M1 |
| --- | --- | --- | --- |
| `GET` | `/api/v1/admin/knowledge` | **当前生效**：`source` / `package_id` / `generation` / 四个内容版本 / 激活人时间 / 最近几次切换；未配置时 `configured: false` + 一句"怎么办"（**不是 503**，见 I5） | ✓ |
| `POST` | `/api/v1/admin/knowledge/packages` | **录入**：`{source: "https://…" \| "/容器内/绝对/路径", sha256?: "…", activate?: bool}`。跑完 §5.4 全链，返回该包视图（含逐文件 sha256、是否生效）。**默认不激活**（I2） | ✓ |
| `GET` | `/api/v1/admin/knowledge/packages` | 录入历史：内容寻址 id、版本、四个内容版本、sha256、`available`（副本还在不在）、录入人/时间、**是否当前生效** | ✓ |
| `GET` | `/api/v1/admin/knowledge/packages/{package_id}` | 单包明细（含副本里实际有哪些文件、各自 sha256） | ✓ |
| `POST` | `/api/v1/admin/knowledge/packages/{package_id}/activate` | **切生效指针**：`{reason?: activate\|rollback\|repair, requested_by?}` → 热换成这一版，`generation += 1`，写审计 | ✓ |
| `GET` | `/api/v1/admin/knowledge/locks` | **谁还锁在旧版**：按 `catalog_version` 分组统计**在跑**的常驻工作数 | ✓ |
| `GET` | `/api/v1/admin/content` | 保留（`api/mod.rs`）："当前生效内容集"的只读视图 —— 激活后就地反映新版，**不重启** | ✓ |

**为什么 activate 是独立动作而不是录入的副作用**：安装包是"录入即生效"（只有一份要分发出去的东西），
知识库要先录入、验过、再切，才有"回滚"与"旧版共存"（设计 I2）。

**为什么是 `/…/{package_id}/activate` 而不是设计早稿里的 `…/{id}:activate`**：`:activate` 那种写法要靠
路由库在**同一段**里同时认参数与字面量（matchit 不保证），而仓里已有的 `credentials:revoke` 是**单独一段字面量**
（本身不含参数）。跟着已有写法走，不赌路由库的行为。

**没有**"设置来源地址"这一对路由（与安装包的差别 2）：来源是录入动作的参数，不作为持久设置。

错误码（正文 JSON `{code, message}`；状态码按"谁能修"分）：

| code | HTTP | 何时 | M1 |
| --- | --- | --- | --- |
| `package_source_invalid` | 400 | 来源写法不合法（不是 https 也不是**容器内**绝对路径），或 `reason` 取值非法 | ✓ |
| `package_sha256_mismatch` | 400 | 期望摘要与实际不符 | ✓ |
| `package_source_unavailable` | 502 | 来源拿不到：文件不存在 / HTTP 失败 / 超限 / 落盘失败 | ✓ |
| `package_manifest_inconsistent` | 422 | `manifest.json` 缺失/解析失败/名字不对；`files` 里的 sha256 对不上；`content_versions` 与文件里声明的不一致 | ✓ |
| `package_content_invalid` | 422 | 真实装载器校验不过（附逐块错误） | ✓ |
| `package_not_found` | 404 | 激活/查看一个没录入过的 `package_id` | ✓ |
| `package_store_failed` | 500 | 落库失败 | ✓ |
| `package_signature_invalid` | 422 | 签名验不过 / 配了公钥但包没签名 | M2 |
| `package_parser_abi_unsupported` | 422 | `parser_abi` 不在网关支持区间（**可录入、不可激活**，见 §10） | M2 |

---

## 8. 生效语义（本设计的核心）

### 8.1 热加载 vs 重启（**决策：B 热加载 + 世代归因**）

现有代码里有一条**反向**决策（`api/mod.rs:100-103`）：

> "启动时装载一次并缓存（改规则通过重启生效）……**不做热加载** —— 热加载会让
> 『哪一版规则算出的这个建议』变得说不清。"

**本设计推翻它**（决策日 2026-09-30）：

| 方案 | 结论 |
| --- | --- |
| A. 保持不热加载：入口只负责"把包弄进来 + 校验 + 记历史"，换版仍走重启 | 否：管理入口的价值就是"不用重启"；容器里重启是**部署动作**且带中断，等于回到"改配置文件"那条路 |
| **B. 热加载 + 世代归因** | **采用** |

**为什么推翻是安全的**：原注释担心的"说不清"是**可修的**，但要同时做到三条，缺一不可：

1. 装载状态必须**可换**：`ApiState` 的 `content` / `purpose_rules` / `discovery_policies`
   （`api/mod.rs:104-116`）从"启动期一次写入的 `Option<Arc<…>>`"改成**可换容器**
   （`ArcSwap`／`RwLock<Option<Arc<…>>>`）。
2. 每次装载带**世代号**（`knowledge_active.generation`），并在管理面暴露（§7）。
3. 一切**派生结果**都要记下它算自哪一版（§8.2 的三个锚）—— 这条不补齐，热加载才真的"说不清"。

**配套硬要求**（不满足就不许上热加载）：

- **`purpose_version` 必须先补**（§17.1）：规则表当前没有版本字段，第 3 条锚不成立。
- 切换**只影响之后**的计算与展开，不重算、不追改（§8.2"算完就算完"、§8.3 工作锁）。
- 切换失败**不允许**把现状打回空载（§8.6 先验后切）。

### 8.2 归因：三个锚

| 派生结果 | 锚 | 现状 |
| --- | --- | --- |
| 已授权工作（采集范围） | `standing_work.catalog_version` | 已有 ✓ |
| 用途建议 | `agent_purpose_suggestion.rule_set_id` + `computed_at` | 已有，但**规则表缺版本字段**（`purpose_version`），改内容不改 `rule_set_id` 时会真说不清 → **前置补齐** |
| 整个生效集 | `knowledge_active.generation` / `package_id` | 本设计新增；`/admin/knowledge` 与 `/admin/content` 都暴露 |

**"算完就算完"**：切换世代**不重算**已产出的建议（与"不追改在跑的工作"同口径）；
但切换动作本身留痕（`knowledge_activation_log`），页面能看到"这条建议是按 pkg-A 算的"。

### 8.3 旧版共存与工作锁

- 激活新版**不动**任何已授权的 `standing_work`：它们继续按自己的 `catalog_version` 展开、下发。
- **新**的授权/提案用新版本的目录展开。
- `GET /admin/knowledge/locks` 回答"还有多少工作锁在旧版"，让人能决定什么时候清理旧包。

### 8.4 回滚

回滚 = 把生效指针指回上一个 `package_id`（`POST …:activate` 复用，`reason=rollback`）。
因为**每一版的副本都留着**（§4 差别 3），回滚不需要重新下载；
但**回滚也不会撤销**新版期间产出的建议（同 §8.2"算完就算完"）。

### 8.5 启动期行为

| 情形 | 行为 |
| --- | --- |
| 生效指针为空（从未录入） | **正常启动**、空载；`/admin/knowledge` 回 `configured:false` 并给出"怎么配"（I5） |
| 生效指针指向的副本缺失/损坏 | **拒绝启动**（与"内容写错就起不来"同口径）：静默空载会让平台悄悄停掉建议与派活 |
| 有包但解析器校验不过 | 同上（这份内容本来就不该被激活；能走到这一步说明磁盘副本被改过） |

### 8.6 失败原子性与并发

- 录入全程在**临时目录**里做，最后 `rename`（同文件系统）；半成品不会进 `<state>/knowledge/`。
- 激活是**单写**：切指针写库 + 换内存，串行化；两个并发激活以后写者为准并各自留痕。
- 装载失败**不允许**把现状打回空载：先在新内容上装载成功，再换指针（**先验后切**）。

### 8.7 空载的可观测性（直接回应实际踩到的坑）

页面必须一句话回答运维的三个问题（这次现场就是卡在这里）：

```
知识库   未配置          ← 现在生效的是哪一版
影响     不产「系统类型」建议 / 不产用途建议；发现策略用 agentd 内建默认值
怎么办   录入一个包并激活（包从哪里来：见 wist-knowledge 的 Release 附件）
         或离线投放：scripts/import-knowledge.sh <包> --set
```

---

## 9. 签名与信任链

**就一把钥匙，与安装脚本那套同一简单度**（不做多密钥共存、不做并存轮换窗口）。

**方向与安装脚本相反**，所以是**另一把**钥匙：

| | 谁签 | 谁验 | 私钥在哪 |
| --- | --- | --- | --- |
| 安装脚本 | 网关 | 目标主机（`install.sh.sig`） | 网关 |
| **内容包** | **发布侧（`wist-knowledge` 的 CI）** | **网关** | **只在 CI secret** |

网关**只需要公钥**：私钥永远不进网关、不进仓、不放到被管机器上。

### 9.1 签什么

签的是 **sha256 摘要的十六进制文本**（就是 `.sha256` 里那串，不带文件名）：

```bash
printf '%s' "<64位hex>" > msg
openssl pkeyutl -sign -rawin -inkey knowledge-signing.pkcs8.pem -in msg -out sig.bin
base64 < sig.bin > wist-knowledge-<版本>.tar.gz.sig      # 一行
```

为什么签摘要而不是裸 tarball：`.sha256` 里已经有那串，运维**拿 openssl 能手工重验**；
签 tarball 反而得先生成摘要。产物就是同名的三个文件：`.tar.gz` / `.sha256` / `.sig`。

### 9.2 网关侧

```toml
[knowledge]
signing_public_key_file = "state/knowledge-signing.pub.pem"   # 不给 = 不验签（只记 sha256）
```

- **配了就必验**：签名缺失/验不过 → 拒收（`package_signature_invalid`，422）；
- 验收通过把公钥**指纹**（sha256 前 16 位）记进 `knowledge_package.signed_by` ——
  单密钥时它是个常量，但它把"这套网关当时信哪把钥匙"钉进每一行包，换钥匙后回头看旧行能分辨；
- **公钥怎么来**：`wist-knowledge/scripts/gen-signing-key.sh` 一次生成一对；
  私钥进 CI secret `KNOWLEDGE_SIGNING_KEY`，公钥可入库/可公开，部署时拷到网关配置目录。
- **轮换** = 换文件 + 重启（与安装脚本那把密钥同一处置）；不设"两把公钥并存"的窗口。

### 9.3 它到底挡什么（诚实边界）

| 挡 | 挡不住 |
| --- | --- |
| 传输/存放中被替换（**.sha256 与包来自同一条链，只靠摘要挡不住替换**） | 拿下了网关**宿主机**的人（他能改二进制、改库、改挂载目录 —— 那是权限问题，不是包真不真） |
| 拿错包 / 贴错文件（内容只认发布流水线那把私钥） | 私钥本身泄露（整个机制归零；所以私钥只在 CI，不进任何开发机） |
| **离线投放**跨不受信环节（U 盘 / 跳板机 —— 那条路没有 TLS） | 私钥丢失后继续发新版（要去**每台**网关换公钥） |

所以它的主战场是**离线投放**；在线从 Release 拉的那条路有 TLS + "只认官方 Release" 流程兑底，签名是加分。

**代价**（所以不把它弄得更复杂）：一把钥匙只需 `gen-signing-key.sh` 跑一次 + 一个 CI secret；
多密钥/轮换窗口/CRL 这类东西只有真出现"中心侧向多客户分发"时才值得谈。

---

## 10. 兼容：不造 `parser_abi`，靠 `deny_unknown_fields`

**问题**：知识库与网关**独立发版**。会出现"内容按新字段写、网关还不认识"。

**曾经的想法**：在 `manifest.json` 里声明 `parser_abi`、网关声明支持区间、不匹配就不允许激活。
**现在不这么做**（太复杂，而且它挡的是同一件事的另一个入口）：

> 网关的 serde **不 `deny_unknown_fields`** 时，**新内容配旧网关会静默忽略新字段** ——
> 内容看着生效了，行为却没变。这才是真危险的那个分支。

**采用的做法**：所有内容体的反序列化都加 `deny_unknown_fields` ——
策展侧写了一个本版网关不认识的键，**录入时就当场报错**（`package_manifest_inconsistent` / `package_content_invalid`），
而不是静默忽略。

现状核对（“已经做到几分”）：

| 内容体 | `deny_unknown_fields` |
| --- | --- |
| 采集目录 / 包 / 模板（`app/content.rs`） | ✓ 早就有 |
| 发现方向策略表（`wist-contracts/discovery_policy.rs`） | ✓ 早就有 |
| 用途规则表（`app/purpose.rs`） | **本批补上**（三行），并且把 toml 的原话放进错误 detail（“unknown field `future_knob`”否则会被 `source_raw_err` 的固定文案吃掉） |

**向下兼容**靠 `#[serde(default)]`：旧内容配新网关照常。
**向上兼容不做**：新内容配旧网关就得报错 —— 那是**想要的**，不是缺点。

---

## 11. 离线投放（容器 vs 宿主）

与安装包同一形态（`scripts/import-package.sh` 的思路）：

```
scripts/import-knowledge.sh <包文件|目录|--latest> [--set] [--dry-run]
  → 复制进宿主 <stack>/packages/（只读挂到容器 /packages）
  → 打印容器内路径与 sha256
  → --set：调用管理 API 录入（可选再 :activate）
```

宿主路径 → 容器内路径的映射要**脚本自己说清**（现场踩过的坑：界面填宿主路径，容器读不到 → HTTP 502）。
stack 侧可接到 `gops sys localize` / runbook 上，做到"部署完就有一个可用的知识库"（可选，见 §14）。

---

## 12. 前端入口

新增 `/knowledge` 页（与 `/install-package` 对称）：

1. **顶部状态条**：当前生效版本 / `generation` / 激活时间 / 激活人；未配置时按 §8.7 的三行显示。
2. **录入**：来源（URL / 路径）+ 可选期望 sha256 + "录入"按钮 → 展示逐项校验结果（§5.4 的 7 步）。
3. **历史表**：内容寻址 id、版本、各内容版本、sha256、是否验签过、录入人/时间、**是否生效**；
   行内动作：激活 / 回滚（指向上一版）/ 查看明细。
4. **锁在旧版的工作**（§8.3）：按 `catalog_version` 的数据，点进去看是哪些机器/工作。
5. 与既有页面一致：只读信息优先、动作二次确认（同"删除需两次确认"的既有口径）。

---

## 13. 与现有配置的关系

- **退役** `[content] catalog_file/packs_file/templates_file`、`[purpose] rules_file`、
  `[discovery] policies_file`（I1）。先例：`agent.package_file` 已被删除（"不再有配置里的内置包回落"）。
- **新增** `[knowledge]` 段：

```toml
[knowledge]
# 验签公钥（Ed25519 SPKI PEM，相对配置目录）。**不给 = 不验签**（只记 sha256）。
signing_public_key_file = "state/knowledge-signing.pub.pem"
```

注意两个**刻意不做成配置项**的东西：

- 包副本目录：跟安装包缓存同一约定（取状态目录下的 `knowledge/`），不另开一个可配的 `state_dir`；
- 大小上限与拉取超时：与安装包一样是**代码常量**（`MAX_PACKAGE_BYTES` / `FETCH_TIMEOUT`）——
  它们是实现约束，不是部署选项，写进配置只会多一处可以配错的地方。

- **代码命名**：模块仍叫 `content`（`app/content.rs`），新增部分叫 `knowledge`。
  要不要把代码侧也统一改名，见 §17（成本 vs 收益）。
- **dev 态**：`wist-gateway-stack/dev/svc.sh` 现在是"拷文件 + 写 `[content]`"（`ensure_content_files`）。
  退役配置字段后，它应改成**起网关后调管理 API 录包并激活** —— 好处是开发态也走同一条真实通路。
- **迁移**：现网本来就是空载，不存在数据搬迁；但**部署脚本要补一步**（否则上线后仍空载）。
  这是本次改动最容易被忽略的运维步骤，写进 runbook。

---

## 14. 落地拆分

| 阶段 | 内容 | 交付判据 |
| --- | --- | --- |
| **M1 最小可用** | 三张表 + 目录布局 + 录入（URL/路径）+ 全链校验（sha256/manifest 自洽/装载器校验）+ **激活/回滚 + 热加载 + 世代** + `/admin/knowledge*` 只读+录入+激活 + `import-knowledge.sh` | 不重启即换版；回滚可用；空载可见（§8.7）；e2e 通过 |
| **M2 信任与兼容** | `.sig` 签名与验签（**一把公钥**，与安装脚本同一简单度）+ `deny_unknown_fields` 补齐（§10）+ 历史页（筛选/时间区间） | 配了公钥时未签名的包**录不进去**；未知字段当场报错而非静默忽略 |
| **M3 体验与治理** | 完整 `/knowledge` 页（历史/明细/锁旧版下钻）+ dev svc.sh 改走 API + stack 的 localize 钩子 + 旧包清理策略 | 部署后自动有知识库；运维无需看 toml |

**已完成**：

- **M1 的地基**（§8.1 选 B 的全部内容）+ 管理面入口 + 投放脚本 —— 见提交 `3452b89` / `ec6a710`；
- **M2 的信任部分**（单钥签名，§9）与**兼容部分**（`deny_unknown_fields`，§10）。

剩下的是 **M3 与前端**（§12）。

---

## 15. 取舍与明确不做的

| 不做 | 为什么 |
| --- | --- |
| 中心侧统一分发（一个中心管多客户的知识库） | 消费方是网关自己；中心分发是另一件事（跨客户、权限、离线），后面单独设计 |
| **多密钥共存 / 轮换窗口 / CRL** | 就一把钥匙的活（§9）：多那把钥匙只在出现"多方分发"时才值得谈，现在上就是把简单事做贵 |
| **`manifest.parser_abi` 字段与支持区间** | 要挡的"新内容配旧网关被静默忽略"用 `deny_unknown_fields` 就能挡（§10），而且更便宜、更直接 |
| 自动把在跑的工作升级到新目录版本 | 违反 I3：采集范围是**合规边界**，不能因为换了内容就悄悄扩大 |
| 重算历史建议 | "算完就算完"；否则每次换版都要全量重算，且答案会变（历史不可复现） |
| 包内"部分块"（例如只发规则表） | M1 要求五份齐全、同版；将来若真需要，`manifest.files` 已能表达"哪几块"，届时再加"部分包"语义 |
| 内容在线编辑（在页面上改 TOML） | 内容要**审定**、要过校验、要进版本；在线改就是绕过整条链 |

---

## 16. 验收

1. **不重启换版**：录入 `v0.1.0` 并激活 → `/admin/content` 能看到模板；录入并激活新版 →
   同一个端点的响应变成新版，**进程未重启**（看启动时间）。
2. **录入 ≠ 生效**：录入新包但不激活 → 内容仍按旧版展开。
3. **回滚**：切回旧版 → 内容回到旧版；`knowledge_activation_log` 有三条留痕（含 `rollback`）。
4. **不追改在跑的工作**：换版后用 `GET /admin/knowledge/locks` 看到旧 `catalog_version` 下的工作数不变；
   新授权用新版本。
5. **校验拦截**：篡改包内任一个 toml（改 sha256）→ 录入即拒（`package_manifest_inconsistent`）；
   把 `catalog_version` 改坏 → `package_content_invalid`。
6. **空载可见**：清库启动 → `/admin/knowledge` 回 `configured:false` 且带"怎么办"；
   `/admin/content` **不再**只回 503。
7. **生效包损坏**：手动删掉 `<state>/knowledge/<生效 id>/catalog.toml` → 网关**拒绝启动**并指出路径。
8. **离线投放**：只在宿主放包、容器内调 `import-knowledge.sh --set` → 端到端可用（不出现 502）。
9. **签名**：没签名的包在配了公钥的网关上被拒（`package_signature_invalid`）；签名被改一个字节被拒；
   跨工具契约（发布侧 openssl 签 → 网关 ring 验）有过一次真实制品的验证。
10. **未知字段**：在任一内容 TOML 里加一个本版网关不认识的键 → 录入/装载**当场报错并点名字段**
    （而不是静默忽略）。
11. **e2e**：`wist-knowledge` 发 tag → 从 Release 下载包 → 录入 → 激活 → 网关推出"系统类型"建议
    （即**打通"知识库发版 → 网关生效"整条链**，这也是当初"没有设置入口"要解决的问题）。

---

## 17. 开放项

1. **`purpose-rules.toml` 的版本字段**：已补（`purpose_version`，§8.2 的归因锚）。
2. **包不可复现**：`manifest.created_at` 使同一版内容每次打包摘要不同。
   若要"同版内容 ⇒ 同摘要"（有利于跨环境比对与缓存），改成用 `SOURCE_DATE_EPOCH` / commit 时间。
3. **命名统一**：代码里是 `content`、仓里是 `wist-knowledge`、配置新增 `[knowledge]` —— 要不要把代码侧
   也改名（成本：一次大范围重命名 + 模型仓注释；收益：少一层心智转换）。建议**暂不改**，在文档里钉住对应关系。
4. **旧包清理**：`<state>/knowledge/` 会随版本增长。策略（保留最近 N 版 / 被工作锁住的必留 / 手工删）
   留到 M3 定。
5. **知识仓要不要再分通道**：本仓已定为**组件**（只在 `main`、tag 无后缀）。
   若将来需要"内容先发 beta 再上生产"，就用 `manifest.channel` + 网关侧"只允许激活 stable"表达，
   而不是回到制品分支模型。
