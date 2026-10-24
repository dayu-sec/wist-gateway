//! 采集内容目录：`catalog` / `packs` / `templates` 三份策展数据的装载、校验与「按面展开」。
//!
//! 与 `purpose.rs` / `discovery_policy.rs` 同类：内容值留知识库仓 `wist-knowledge/`，
//! 这里只**读**，不内嵌默认副本（内嵌就有两份真相，改内容时必然漂移）。
//!
//! 三层 + 一层积木（对应模型 `Control.Agent.Content`）：
//!   采集单元 CollectionUnit —— 能采什么（来源 + 解析规则）；
//!   内容包 ContentPack —— 可复用的单元组合（平台基线 / 特征包）；
//!   常驻工作模板 WorkTemplate —— 这类机器该采什么 = 平台基线包 ⊕ 特征包（**组合，非继承**）。
//!
//! 两条关键设计在这里落实：
//!   1. **就绪度分三层，不再混成一个**：单元的 `status` 是「**采集就绪度**」（能不能派下去采原文），
//!      单元的 `rule_ref` 是「**解析就绪度**」（采下来能不能归类、抽字段 —— 独立信号，**不是**闸门），
//!      包/模板的 `status` 是「策展成熟度」。授权闸门是**面就绪度**（该面至少一个 `active` 单元），
//!      未就绪的面**不展开**并留痕。
//!   2. **事实缺位 ≠ 条件不满足**：`match` 求值三态，探针没采到时报「无法判定」，不冒充「没装」。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use orion_error::conversion::ToStructError;
use orion_error::prelude::*;
use serde::Deserialize;
use wist_contracts::fact_summary::EPHEMERAL_PORT_START;
use wist_contracts::work::{
    CONTAINER_LOG_ROOT, ContainerFilters, EXECUTABLE_SOURCE_KINDS, is_container_log_target,
    is_executable_source, is_explicit_path,
};
use wist_error::{ConfigError, ConfigReason, ConfigResult};

use crate::infra::StoredAgentFactSummary;

/// 平台闭集（与 agentd 上报的 `os` 同源）。
pub const PLATFORMS: &[&str] = &["macos", "linux"];
/// 采集面闭集（与模型 `families.mju` 的 `variant CollectionFamily` **逐字一致**）。
///
/// **运行期以知识库词表为准**（`catalog.toml` 的 `[[families]]`，见 [`FamilyMeta`]）；
/// 这里的常量只剩**旧包回落**：包还没有 `[[families]]` 时用它，避免升级即拒载。
/// 两侧的一致性由两个测试钉住：本常量 vs 模型（`the_family_closed_set_matches_the_model`）、
/// 知识库词表 vs 模型（`the_knowledge_vocabulary_matches_the_model`）。
/// 含义与维护规矩（**只增不改名**）见 `doc/design/center/collection-families.md`。
pub const FAMILIES: &[&str] = &[
    "LoginSession",
    "PrivilegeExecution",
    "SoftwareChange",
    "ServiceLifecycle",
    "CrashPanic",
    "NetworkFirewall",
    "RebootPower",
    "MiscSystem",
    "HostMetrics",
    "PrivacyTcc",
    "GatekeeperQuarantine",
    "DevToolchain",
    "KernelSystem",
    "DatabaseService",
    "StorageHealth",
    "ComputeWorkload",
    "BackupJob",
    "NetworkService",
];
/// 只在 macOS 出现的面（照 `families.mju` 的分类）。**仅用于旧包回落**：
/// 带 `[[families]]` 的包按词表里的 `platforms` 判，不看这里。
const MACOS_ONLY_FAMILIES: &[&str] = &["PrivacyTcc", "GatekeeperQuarantine", "DevToolchain"];
/// 只在 Linux 出现的面（同样仅用于旧包回落）。
const LINUX_ONLY_FAMILIES: &[&str] = &[
    "KernelSystem",
    "DatabaseService",
    "StorageHealth",
    "ComputeWorkload",
    "BackupJob",
    "NetworkService",
];
/// 能力闭集。
pub const CAPABILITIES: &[&str] = &["collect_logs", "collect_metrics"];
/// 采集来源类型闭集（与模型 `variant CollectionSourceKind` 一致）。
pub const SOURCE_KINDS: &[&str] = &[
    "FileGlob",
    "Exporter",
    "UnifiedLogPredicate",
    "MetricInterval",
];
/// 来源的读法闭集：**直接复用契约词表**（与 agentd `MultilineMode` 同源）。
///
/// 以前这里是手抄的一份数组 —— 加一种读法（W4 的 `mysql_slow` / `postgres_csv`）
/// 就得两处改，忘一处就是“目录写了、网关说不认识”。
pub use wist_contracts::work::MULTILINE_MODES;
/// 权限闭集。
pub const PRIVILEGES: &[&str] = &["none", "root", "fda"];
/// `match` 条件 kind 闭集（与 [`eval_condition`] 认识的分支一致）。
///
/// 装载期必须校验：`parse_conditions` 会**静默丢弃**没有 `:` 的片段，而空表达式等于
/// “平台基线必采”。所以写坏的表达式（漏冒号 / 漏分号 / 拼错 kind）在求值层有两种
/// 相反的静默后果：要么条件整个消失（双采），要么单元永不展开（少采）——
/// 两种都只能靠装载期报错才能被发现。
pub const MATCH_KINDS: &[&str] = &[
    "installed",
    "port",
    "path_exists",
    "not_path_exists",
    "device",
    "service",
    "resource",
];
/// 单元**采集就绪度**（能不能派下去采原文；与解析规则无关）。
pub const UNIT_STATUSES: &[&str] = &["active", "draft", "deprecated"];
/// 包的性质。
pub const PACK_KINDS: &[&str] = &["Baseline", "Feature"];
/// 机器类别闭集（与模型 `variant MachineClass` 一致）。
pub const MACHINE_CLASSES: &[&str] = &[
    "MacDaily",
    "MacDev",
    "LinuxHost",
    "LinuxCompute",
    "LinuxData",
];

fn invalid(detail: impl Into<String>) -> ConfigError {
    ConfigReason::Validation.to_err().with_detail(detail)
}

// ─────────────────────────────────────────────────────────────────────────────
// 原始 TOML 形状（`deny_unknown_fields`：笔误要响，不能被静默忽略）
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    catalog_version: i64,
    #[serde(default)]
    #[allow(dead_code)]
    origin: String,
    #[serde(default)]
    #[allow(dead_code)]
    published_at: String,
    #[serde(default)]
    superseded_by: Option<i64>,
    /// 采集面词表。**空 = 旧包**（还没有 `[[families]]`），回落内置基线（过渡期）。
    #[serde(default)]
    families: Vec<FamilyRow>,
    #[serde(default)]
    units: Vec<UnitRow>,
}

/// `[[families]]` 的一行：面的**元数据**（值在知识库，不在代码）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FamilyRow {
    /// 协议值：大小写敏感，只增不改名。
    id: String,
    /// 允许出现的平台。空 = 全平台。
    #[serde(default)]
    platforms: Vec<String>,
    /// 语义版本：改语义要出新面，这里只用于审计。
    #[serde(default)]
    semantics_version: i64,
    #[serde(default)]
    name_zh: String,
    #[serde(default)]
    name_en: String,
    #[serde(default)]
    summary_zh: String,
    #[serde(default)]
    summary_en: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitRow {
    unit_id: String,
    family: String,
    capability: String,
    platform: String,
    // `match` 是 Rust 关键字，字段另起名；它不是“匹配”而是“采集前提条件”。
    #[serde(default, rename = "match")]
    match_expr: String,
    #[serde(default)]
    rule_ref: String,
    requires_privilege: String,
    status: String,
    #[serde(default)]
    sources: Vec<SourceRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRow {
    kind: String,
    target: String,
    #[serde(default = "default_multiline")]
    multiline: String,
    /// 从文件族匹配集里剔掉的绝对路径 glob（默认空，只对 `FileGlob` 有意义）。
    #[serde(default)]
    exclude_globs: Vec<String>,
    /// 容器选源的结构化过滤器（默认空，只对容器选源有意义）。
    #[serde(default)]
    filters: ContainerFilters,
    /// 噪音行丢弃的**精确子串**（默认空，只对 `FileGlob` 有意义）。
    #[serde(default)]
    drop_if_contains: Vec<String>,
}

fn default_multiline() -> String {
    "none".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PacksFile {
    #[serde(default)]
    pack: Vec<PackRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackRow {
    pack_id: String,
    platform: String,
    kind: String,
    #[serde(default)]
    families: Vec<String>,
    #[serde(default)]
    unit_refs: Vec<String>,
    catalog_version: i64,
    status: String,
    #[serde(default)]
    #[allow(dead_code)]
    curated_by: String,
    #[serde(default)]
    #[allow(dead_code)]
    curated_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplatesFile {
    #[serde(default)]
    template: Vec<TemplateRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateRow {
    template_id: String,
    machine_class: String,
    platform: String,
    #[serde(default)]
    pack_refs: Vec<String>,
    catalog_version: i64,
    #[serde(default)]
    template_version: i64,
    status: String,
    #[serde(default)]
    #[allow(dead_code)]
    curated_by: String,
    #[serde(default)]
    #[allow(dead_code)]
    curated_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// 已装载、已校验的内容集
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Unit {
    pub unit_id: String,
    pub family: String,
    pub capability: String,
    pub platform: String,
    pub match_expr: String,
    /// **解析就绪度**（独立信号，**不参与**派活闸门）：非空 = 有解析规则，采下来的记录能被
    /// 归类、抽字段；空 = 只落原文 —— 帧进得来、落得下，但下游只能拿到未归类的原文。
    ///
    /// 为什么不拿它当闸门：**能采 ≠ 能解析**。采集就是 tail 一个文件、把原文发出去，
    /// 它不需要任何解析规则；规则是数据面的事。卡在这里会把「先收原文样本、后补规则」
    /// 这条最省的路堵死。
    pub rule_ref: String,
    pub requires_privilege: String,
    /// **采集就绪度**：`active` = 采集要素齐（有来源，且至少一条来源 agentd 真能执行）
    /// → 可以派下去采原文。派活闸门看的就是它。
    pub status: String,
    /// 采集来源（一个单元可有多条）。
    pub sources: Vec<UnitSource>,
}

/// 已装载的采集来源：类型 + 取值 + **怎么读它**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSource {
    pub kind: String,
    pub target: String,
    /// `none`（一行一条）| `indented`（行首缩进是上一条的续行）|
    /// `mysql_slow` / `postgres_csv`（W4；词表见 `wist_contracts::work::MULTILINE_MODES`）。
    pub multiline: String,
    /// 从匹配集里剔掉的绝对路径 glob；空 = 不排除。
    pub exclude_globs: Vec<String>,
    /// 容器选源的结构化过滤器（namespace / pod）；空 = 不过滤。
    pub filters: ContainerFilters,
    /// 含这些子串的记录整条丢弃；空 = 不丢。
    pub drop_if_contains: Vec<String>,
}

impl Unit {
    /// 采集就绪（`status = active`）：能不能派下去采。
    pub fn collect_ready(&self) -> bool {
        self.status == "active"
    }

    /// 解析就绪（`rule_ref` 非空）：采下来能不能归类、抽字段。
    pub fn parse_ready(&self) -> bool {
        !self.rule_ref.trim().is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Pack {
    pub pack_id: String,
    pub platform: String,
    /// `Baseline` | `Feature`。
    pub kind: String,
    pub unit_refs: Vec<String>,
    /// 策展成熟度（人定，与单元的采集就绪度无关）。
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct Template {
    pub template_id: String,
    pub machine_class: String,
    pub platform: String,
    pub pack_refs: Vec<String>,
    pub catalog_version: i64,
    pub template_version: i64,
    /// 策展成熟度（**不是**授权闸门）。
    pub status: String,
    /// 派生：`pack_refs` 展开后的面集。
    pub family_scope: Vec<String>,
    /// 派生：展开后单元能力的并集。
    pub capability_scope: Vec<String>,
}

/// 某采集面在某平台上的就绪度（派生）。
///
/// **两个轴分开报**，因为它们回答的是不同的问题：
///   - 采集（`active_units` / [`Self::collect_ready`]）：能不能派下去把原文拿回来；
///   - 解析（`parse_ready_units` / [`Self::parse_ready`]）：拿回来的东西能不能被归类、抽字段。
///
/// 只看前者会把「采到了但认不出是谁」当成已就绪，只看后者会拿规则去卡采集。
#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Content")]
pub struct FamilyReadiness {
    pub family: String,
    pub platform: String,
    /// 该面上**采集就绪**的单元数（`status = active`）。
    pub active_units: usize,
    /// 该面上**解析就绪**的 `active` 单元数（`rule_ref` 非空）。
    pub parse_ready_units: usize,
    pub total_units: usize,
}

impl FamilyReadiness {
    /// 采集就绪：这个面能被派下去采。
    pub fn collect_ready(&self) -> bool {
        self.active_units > 0
    }

    /// 解析就绪：这个面采下来的记录能被归类、抽字段。
    ///
    /// **不参与闸门**：`false` 只意味着记录会以未归类的原文落地（当前是单个 `agent.log` 类）。
    pub fn parse_ready(&self) -> bool {
        self.parse_ready_units > 0
    }
}

/// 一个采集面的元数据（词表条目）。
///
/// **值来自知识库**（`catalog.toml` 的 `[[families]]`），不来自代码：加面只改数据。
/// 内置的 [`FAMILIES`] 只在旧包没有 `[[families]]` 时兜底（过渡期，见 `build_vocabulary`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyMeta {
    pub id: String,
    /// 允许出现的平台；空 = 全平台。
    pub platforms: Vec<String>,
    pub semantics_version: i64,
    pub name_zh: String,
    pub name_en: String,
    pub summary_zh: String,
    pub summary_en: String,
}

impl FamilyMeta {
    /// 这个面是否可能出现在该平台。
    pub fn applies_to(&self, platform: &str) -> bool {
        self.platforms.is_empty() || self.platforms.iter().any(|value| value == platform)
    }
}

/// 一份已装载、已校验的内容集。
#[derive(Debug, Clone)]
pub struct ContentSet {
    pub catalog_version: i64,
    pub superseded_by: Option<i64>,
    /// 面词表（`id → 元数据`）。
    families: BTreeMap<String, FamilyMeta>,
    units: BTreeMap<String, Unit>,
    packs: BTreeMap<String, Pack>,
    templates: BTreeMap<String, Template>,
}

/// 从三份文件装载内容集。
pub fn load_content(
    catalog_file: &Path,
    packs_file: &Path,
    templates_file: &Path,
) -> ConfigResult<ContentSet> {
    let catalog = std::fs::read_to_string(catalog_file)
        .source_err(ConfigReason::Io, "read collection catalog")?;
    let packs =
        std::fs::read_to_string(packs_file).source_err(ConfigReason::Io, "read content packs")?;
    let templates = std::fs::read_to_string(templates_file)
        .source_err(ConfigReason::Io, "read work templates")?;
    parse_content(&catalog, &packs, &templates)
}

/// 解析并校验三份内容文本（测试与热加载都用它）。
pub fn parse_content(
    catalog_text: &str,
    packs_text: &str,
    templates_text: &str,
) -> ConfigResult<ContentSet> {
    let catalog: CatalogFile = toml::from_str(catalog_text)
        .source_raw_err(ConfigReason::Parse, "parse collection catalog")?;
    let packs: PacksFile =
        toml::from_str(packs_text).source_raw_err(ConfigReason::Parse, "parse content packs")?;
    let templates: TemplatesFile = toml::from_str(templates_text)
        .source_raw_err(ConfigReason::Parse, "parse work templates")?;
    build_content(catalog, packs, templates)
}

fn build_content(
    catalog: CatalogFile,
    packs: PacksFile,
    templates: TemplatesFile,
) -> ConfigResult<ContentSet> {
    let families = build_vocabulary(&catalog.families)?;
    let catalog_version = validate_catalog(&catalog, &families)?;
    let units = catalog
        .units
        .into_iter()
        .map(|row| {
            let unit = Unit {
                unit_id: row.unit_id,
                family: row.family,
                capability: row.capability,
                platform: row.platform,
                match_expr: row.match_expr,
                rule_ref: row.rule_ref,
                requires_privilege: row.requires_privilege,
                status: row.status,
                sources: row
                    .sources
                    .into_iter()
                    .map(|source| UnitSource {
                        kind: source.kind,
                        target: source.target,
                        multiline: source.multiline,
                        exclude_globs: source.exclude_globs,
                        filters: source.filters,
                        drop_if_contains: source.drop_if_contains,
                    })
                    .collect(),
            };
            (unit.unit_id.clone(), unit)
        })
        .collect::<BTreeMap<_, _>>();

    validate_unique_active_paths(&units)?;

    let packs = validate_packs(&packs, catalog_version, &units)?;
    let templates = validate_templates(&templates, catalog_version, &packs, &units)?;

    Ok(ContentSet {
        catalog_version,
        superseded_by: catalog.superseded_by,
        families,
        units,
        packs,
        templates,
    })
}

/// 把 `[[families]]` 变成词表；**旧包（字段为空）回落内置基线**。
///
/// 为什么留回落而不是直接拒：已经装在现场的包还没有 `[[families]]`（它们先于本字段），
/// 拒载会把升级变成事故。等所有在役包都带上词表后删掉 `FAMILIES` 与这条回落
/// （见 `doc/design/center/collection-family-capability-contract.md` §12.1 第 1 步）。
fn build_vocabulary(rows: &[FamilyRow]) -> ConfigResult<BTreeMap<String, FamilyMeta>> {
    if rows.is_empty() {
        return Ok(default_vocabulary());
    }
    let mut vocabulary: BTreeMap<String, FamilyMeta> = BTreeMap::new();
    for row in rows {
        let id = row.id.trim();
        if id.is_empty() {
            return Err(invalid("[[families]] has an empty id"));
        }
        if row.id != id {
            return Err(invalid(format!(
                "family {id:?}: id 不能带前后空白（协议值原样写进数据帧）"
            )));
        }
        for platform in &row.platforms {
            if !PLATFORMS.contains(&platform.as_str()) {
                return Err(invalid(format!(
                    "family {id:?}: unknown platform {platform:?}"
                )));
            }
        }
        let meta = FamilyMeta {
            id: id.to_string(),
            platforms: row.platforms.clone(),
            semantics_version: row.semantics_version,
            name_zh: row.name_zh.clone(),
            name_en: row.name_en.clone(),
            summary_zh: row.summary_zh.clone(),
            summary_en: row.summary_en.clone(),
        };
        if vocabulary.insert(meta.id.clone(), meta).is_some() {
            return Err(invalid(format!("duplicate family {id:?}")));
        }
    }
    Ok(vocabulary)
}

/// 内置基线：旧包（无 `[[families]]`）的过渡期词表。
///
/// 平台归属从 `MACOS_ONLY_FAMILIES` / `LINUX_ONLY_FAMILIES` 推——这两个常量是**模型分类的
/// 影子**，只在这一条回落路上用到。
fn default_vocabulary() -> BTreeMap<String, FamilyMeta> {
    FAMILIES
        .iter()
        .map(|id| {
            let platforms = if MACOS_ONLY_FAMILIES.contains(id) {
                vec!["macos".to_string()]
            } else if LINUX_ONLY_FAMILIES.contains(id) {
                vec!["linux".to_string()]
            } else {
                Vec::new()
            };
            let meta = FamilyMeta {
                id: (*id).to_string(),
                platforms,
                semantics_version: 0,
                name_zh: String::new(),
                name_en: String::new(),
                summary_zh: String::new(),
                summary_en: String::new(),
            };
            (meta.id.clone(), meta)
        })
        .collect()
}

fn validate_catalog(
    catalog: &CatalogFile,
    families: &BTreeMap<String, FamilyMeta>,
) -> ConfigResult<i64> {
    if catalog.catalog_version < 1 {
        return Err(invalid(format!(
            "catalog_version {} must be >= 1",
            catalog.catalog_version
        )));
    }
    if catalog.units.is_empty() {
        return Err(invalid("catalog has no units"));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for unit in &catalog.units {
        validate_unit(unit, families)?;
        if !seen.insert(unit.unit_id.as_str()) {
            return Err(invalid(format!("duplicate unit_id {:?}", unit.unit_id)));
        }
    }
    Ok(catalog.catalog_version)
}

/// 同一平台上，同一个文件只能被**一个** `active` 单元采集。
///
/// 一条来源对应一条采集任务：两个 active 单元写同一个路径，agentd 会建两个 input
/// （各自 checkpoint），同一批行被上送两次。而「一份文件出多个 log_type」应当由数据面
/// 按正文分派，不是重复读。只约束 active×active —— draft 单元允许并列（渐进启用）。
///
/// 能查的只有**同字串**的 target：显式路径、目录、glob 都一样。两条不同的 glob 是否重叠
/// （`/var/log/*.log` 与 `/var/log/app*.log`）在装载期无法判定，只能靠策展约束。
fn validate_unique_active_paths(units: &BTreeMap<String, Unit>) -> ConfigResult<()> {
    let mut claimed: BTreeMap<(String, String), String> = BTreeMap::new();
    for unit in units.values() {
        if unit.status != "active" {
            continue;
        }
        for source in &unit.sources {
            if source.kind != "FileGlob" {
                continue;
            }
            match claimed.insert(
                (unit.platform.clone(), source.target.clone()),
                unit.unit_id.clone(),
            ) {
                None => {}
                Some(existing) if existing == unit.unit_id => {
                    return Err(invalid(format!(
                        "unit {}: source target {:?} is declared more than once",
                        unit.unit_id, source.target
                    )));
                }
                Some(existing) => {
                    return Err(invalid(format!(
                        "unit {}: target {:?} is already collected by unit {existing} on {} \
                         (同一文件只允许一个 active 单元采集；多个 log_type 由数据面按正文分派)",
                        unit.unit_id, source.target, unit.platform
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_unit(unit: &UnitRow, families: &BTreeMap<String, FamilyMeta>) -> ConfigResult<()> {
    let id = unit.unit_id.as_str();
    if id.trim().is_empty() {
        return Err(invalid("empty unit_id"));
    }
    let Some(meta) = families.get(unit.family.as_str()) else {
        return Err(invalid(format!(
            "unit {id}: unknown family {:?}",
            unit.family
        )));
    };
    if !CAPABILITIES.contains(&unit.capability.as_str()) {
        return Err(invalid(format!(
            "unit {id}: unknown capability {:?}",
            unit.capability
        )));
    }
    if !PLATFORMS.contains(&unit.platform.as_str()) {
        return Err(invalid(format!(
            "unit {id}: unknown platform {:?}",
            unit.platform
        )));
    }
    if !PRIVILEGES.contains(&unit.requires_privilege.as_str()) {
        return Err(invalid(format!(
            "unit {id}: unknown requires_privilege {:?}",
            unit.requires_privilege
        )));
    }
    if !UNIT_STATUSES.contains(&unit.status.as_str()) {
        return Err(invalid(format!(
            "unit {id}: unknown status {:?}",
            unit.status
        )));
    }
    // 面与平台的对应：词表里声明的 `platforms` 是唯一依据。
    if !meta.applies_to(unit.platform.as_str()) {
        return Err(invalid(format!(
            "unit {id}: family {:?} does not apply to platform {:?} (allowed: {:?})",
            unit.family, unit.platform, meta.platforms
        )));
    }
    // `match` 的形状校验（装载期，fail-closed）：
    //   * 每个**非空片段**必须有 `kind:values` —— 漏冒号会被静默丢弃，而空表达式 = 必采；
    //   * kind 必须在闭集里 —— 写错/新 kind 在求值层只会得到 `Unknown`，单元永远展不开；
    //   * `path_exists` / `not_path_exists` 的值必须是绝对路径：相对路径的结果取决于进程
    //     cwd，同一台机器换一种启动方式就翻面，不能当事实（agentd 侧也会丢弃）。
    for raw in unit
        .match_expr
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let Some((kind, rest)) = raw.split_once(':') else {
            return Err(invalid(format!(
                "unit {id}: match 条件 {raw:?} 缺少 ':'（形如 kind:value）"
            )));
        };
        let kind = kind.trim();
        if !MATCH_KINDS.contains(&kind) {
            return Err(invalid(format!(
                "unit {id}: match 条件 {raw:?} 的 kind 未知（允许：{MATCH_KINDS:?}）"
            )));
        }
        let values: Vec<&str> = rest
            .split('|')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect();
        if values.is_empty() {
            return Err(invalid(format!("unit {id}: match 条件 {raw:?} 没有值")));
        }
        // 值里不能有空白：漏写 `;` 会把下一个条件并进前一个值
        // （`path_exists:/a not_path_exists:/b` —— 它以 `/` 开头，能骗过绝对路径校验）。
        if let Some(bad) = values
            .iter()
            .find(|value| value.contains(char::is_whitespace))
        {
            return Err(invalid(format!(
                "unit {id}: match 条件 {raw:?} 的值 {bad:?} 含空白（是不是漏写了 ';'？）"
            )));
        }
        if (kind == "path_exists" || kind == "not_path_exists")
            && let Some(bad) = values.iter().find(|value| !value.starts_with('/'))
        {
            return Err(invalid(format!(
                "unit {id}: {kind} expects absolute paths, got {bad:?}"
            )));
        }
    }
    if unit.sources.is_empty() {
        return Err(invalid(format!("unit {id}: no sources")));
    }
    for source in &unit.sources {
        if !SOURCE_KINDS.contains(&source.kind.as_str()) {
            return Err(invalid(format!(
                "unit {id}: unknown source kind {:?}",
                source.kind
            )));
        }
        if source.target.trim().is_empty() {
            return Err(invalid(format!(
                "unit {id}: source {} has empty target",
                source.kind
            )));
        }
        if !MULTILINE_MODES.contains(&source.multiline.as_str()) {
            return Err(invalid(format!(
                "unit {id}: source {} has unknown multiline {:?}",
                source.kind, source.multiline
            )));
        }
        // 排除项只在文件族有意义，且必须是**绝对路径**：匹配是对展开后的完整路径做的，
        // 相对路径的结果取决于进程 cwd —— 同一台机器换一种启动方式就会少采一个文件。
        if !source.exclude_globs.is_empty() && source.kind != "FileGlob" {
            return Err(invalid(format!(
                "unit {id}: source {} cannot declare exclude_globs (只对 FileGlob 有意义)",
                source.kind
            )));
        }
        if let Some(bad) = source
            .exclude_globs
            .iter()
            .find(|pattern| !pattern.starts_with('/'))
        {
            return Err(invalid(format!(
                "unit {id}: exclude_globs expects absolute paths, got {bad:?}"
            )));
        }
        // 容器过滤器（W2）：结构化选源，只对**容器选源根**下的来源有意义。
        //
        // 为什么卡目标：过滤器求值靠文件名 `<pod>_<ns>_<container>-<id>.log`。写在别的路径
        // 上只会得到「一个都匹配不上」。与其让它在运行时静默采不到，不如在装载期拒掉。
        if !source.filters.is_empty() {
            if source.kind != "FileGlob" {
                return Err(invalid(format!(
                    "unit {id}: source {} cannot declare filters (只对 FileGlob 有意义)",
                    source.kind
                )));
            }
            if let Err(reason) = source.filters.validate() {
                return Err(invalid(format!("unit {id}: filters {reason}")));
            }
            // 维度决定目标形态（两类载体的信息位置不同）：
            //   * `namespace_in` / `pod_not_in` 靠**文件名** `<pod>_<ns>_<container>-<id>.log`
            //     解析 → 只能在 k8s 的 `/var/log/containers` 下；
            //   * `name_in` / `name_not_in` 也支持纯 Docker（文件名只有容器 id，名字在同目录
            //     `config.v2.json`）→ 只要求目标里真的有 `containers/` 这一段（不写死 data-root）。
            let k8s_shape =
                !source.filters.namespace_in.is_empty() || !source.filters.pod_not_in.is_empty();
            let name_shape =
                !source.filters.name_in.is_empty() || !source.filters.name_not_in.is_empty();
            if k8s_shape {
                let root = CONTAINER_LOG_ROOT;
                let under_root =
                    source.target == root || source.target.starts_with(&format!("{root}/"));
                if !under_root {
                    return Err(invalid(format!(
                        "unit {id}: filters 只能用在 {root} 下的来源（当前 {}）",
                        source.target
                    )));
                }
            }
            if name_shape && !is_container_log_target(&source.target) {
                return Err(invalid(format!(
                    "unit {id}: filters name_in / name_not_in 要求来源在容器日志目录下（当前 {}）",
                    source.target
                )));
            }
        }
        // 噪音行丢弃（W4）：只对可读文件有意义，且必须是**精确子串**（不是正则 / pattern）。
        if !source.drop_if_contains.is_empty() {
            if source.kind != "FileGlob" {
                return Err(invalid(format!(
                    "unit {id}: source {} cannot declare drop_if_contains (只对 FileGlob 有意义)",
                    source.kind
                )));
            }
            if let Err(reason) =
                wist_contracts::work::validate_drop_if_contains(&source.drop_if_contains)
            {
                return Err(invalid(format!("unit {id}: {reason}")));
            }
        }
        // 多行归并只对可 tail 的文件来源有意义。写在别的 kind 上不是“多一个无害的字段”，
        // 而是对人误导读它的人 —— 要么策展想表达别的意思，要么放错了位置。
        if source.multiline != "none" && source.kind != "FileGlob" {
            return Err(invalid(format!(
                "unit {id}: source {} cannot declare multiline {:?} (只对 FileGlob 有意义)",
                source.kind, source.multiline
            )));
        }
    }
    // 「采集就绪」不能只靠人喊：`active` 必须有一条**agentd 今天真能采**的来源。
    //
    // 这里刻意**不看** `rule_ref`：采原文不需要解析规则，拿它当闸门是把「能解析」当成「能采」。
    // 卡住的是「这条来源采集端到底能不能执行」（`is_executable_source`，与 agentd 同源：
    // kind 要能执行，`FileGlob` 的 target 还要是**可采的绝对路径**（显式路径或单层 glob），
    // `Exporter` 的 ID 还要在 `EXPORTER_IDS` 里）。否则就会出现「网关说可采、agent 拿到后报
    // unsupported」这种自相矛盾的运行态。
    if unit.status == "active"
        && !unit
            .sources
            .iter()
            .any(|source| is_executable_source(&source.kind, &source.target))
    {
        return Err(invalid(format!(
            "unit {id}: status = active but no source agentd can collect \
             (kind 要去 {EXECUTABLE_SOURCE_KINDS:?}；FileGlob 的 target 要是绝对路径 \
             （显式路径或单层 glob，不支持 `**`）、Exporter 的 ID 要在 EXPORTER_IDS 里)"
        )));
    }
    Ok(())
}

fn validate_packs(
    file: &PacksFile,
    catalog_version: i64,
    units: &BTreeMap<String, Unit>,
) -> ConfigResult<BTreeMap<String, Pack>> {
    let mut packs: BTreeMap<String, Pack> = BTreeMap::new();
    // 每平台恰好一个 Baseline 包。
    let mut baselines: BTreeMap<&str, &str> = BTreeMap::new();
    for row in &file.pack {
        let id = row.pack_id.as_str();
        if !PLATFORMS.contains(&row.platform.as_str()) {
            return Err(invalid(format!(
                "pack {id}: unknown platform {:?}",
                row.platform
            )));
        }
        if !PACK_KINDS.contains(&row.kind.as_str()) {
            return Err(invalid(format!("pack {id}: unknown kind {:?}", row.kind)));
        }
        if row.catalog_version != catalog_version {
            return Err(invalid(format!(
                "pack {id}: catalog_version {} != catalog {}",
                row.catalog_version, catalog_version
            )));
        }
        if row.unit_refs.is_empty() {
            return Err(invalid(format!("pack {id}: no unit_refs")));
        }
        let mut derived_families: BTreeSet<String> = BTreeSet::new();
        for unit_ref in &row.unit_refs {
            let unit = units.get(unit_ref).ok_or_else(|| {
                invalid(format!(
                    "pack {id}: unit_ref {unit_ref:?} not found in catalog"
                ))
            })?;
            if unit.platform != row.platform {
                return Err(invalid(format!(
                    "pack {id}: unit {unit_ref:?} platform {} != pack platform {}",
                    unit.platform, row.platform
                )));
            }
            derived_families.insert(unit.family.clone());
        }
        // 包自己声明的 `families` 必须等于它引用单元的面集 —— 它不是可以手写的偏好，
        // 而是可从 unit_refs 推出来的，写歪了就该拦（否则页面/审计上看到的面是假的）。
        let declared: BTreeSet<String> = row.families.iter().cloned().collect();
        if declared != derived_families {
            return Err(invalid(format!(
                "pack {id}: families {declared:?} != families of unit_refs {derived_families:?}"
            )));
        }
        if row.kind == "Baseline"
            && let Some(existing) = baselines.insert(row.platform.as_str(), id)
        {
            return Err(invalid(format!(
                "pack {id}: platform {} already has baseline pack {existing:?}",
                row.platform
            )));
        }
        let pack = Pack {
            pack_id: row.pack_id.clone(),
            platform: row.platform.clone(),
            kind: row.kind.clone(),
            unit_refs: row.unit_refs.clone(),
            status: row.status.clone(),
        };
        if packs.insert(row.pack_id.clone(), pack).is_some() {
            return Err(invalid(format!("duplicate pack_id {id:?}")));
        }
    }
    for platform in PLATFORMS {
        if !baselines.contains_key(platform) {
            return Err(invalid(format!(
                "platform {platform} has no Baseline pack (每个平台恰好一个基线包)"
            )));
        }
    }
    Ok(packs)
}

fn validate_templates(
    file: &TemplatesFile,
    catalog_version: i64,
    packs: &BTreeMap<String, Pack>,
    units: &BTreeMap<String, Unit>,
) -> ConfigResult<BTreeMap<String, Template>> {
    let mut templates = BTreeMap::new();
    for row in &file.template {
        let id = row.template_id.as_str();
        if !MACHINE_CLASSES.contains(&row.machine_class.as_str()) {
            return Err(invalid(format!(
                "template {id}: unknown machine_class {:?}",
                row.machine_class
            )));
        }
        if !PLATFORMS.contains(&row.platform.as_str()) {
            return Err(invalid(format!(
                "template {id}: unknown platform {:?}",
                row.platform
            )));
        }
        let expected_platform = platform_for_machine_class(&row.machine_class)
            .expect("validated machine class has a platform");
        if expected_platform != row.platform {
            return Err(invalid(format!(
                "template {id}: machine_class {} belongs to {expected_platform}, not {}",
                row.machine_class, row.platform
            )));
        }
        if row.catalog_version != catalog_version {
            return Err(invalid(format!(
                "template {id}: catalog_version {} != catalog {}",
                row.catalog_version, catalog_version
            )));
        }
        if row.pack_refs.is_empty() {
            return Err(invalid(format!("template {id}: no pack_refs")));
        }
        let mut has_baseline = false;
        for pack_ref in &row.pack_refs {
            let pack = packs.get(pack_ref).ok_or_else(|| {
                invalid(format!("template {id}: pack_ref {pack_ref:?} not found"))
            })?;
            if pack.platform != row.platform {
                return Err(invalid(format!(
                    "template {id}: pack {pack_ref:?} platform {} != template platform {}",
                    pack.platform, row.platform
                )));
            }
            if pack.kind == "Baseline" {
                has_baseline = true;
            }
        }
        if !has_baseline {
            return Err(invalid(format!(
                "template {id}: pack_refs must include the platform baseline pack"
            )));
        }

        let (family_scope, capability_scope) = derive_scope(&row.pack_refs, packs, units);
        if family_scope.is_empty() {
            return Err(invalid(format!("template {id}: empty family_scope")));
        }
        // 每个面在该平台上至少要有一个单元，否则是“定义了但采不到”。
        for family in &family_scope {
            let has_unit = units
                .values()
                .any(|unit| unit.platform == row.platform && unit.family == *family);
            if !has_unit {
                return Err(invalid(format!(
                    "template {id}: family {family:?} has no unit on platform {}",
                    row.platform
                )));
            }
        }

        let template = Template {
            template_id: row.template_id.clone(),
            machine_class: row.machine_class.clone(),
            platform: row.platform.clone(),
            pack_refs: row.pack_refs.clone(),
            catalog_version: row.catalog_version,
            template_version: row.template_version,
            status: row.status.clone(),
            family_scope,
            capability_scope,
        };
        if templates
            .insert(row.template_id.clone(), template)
            .is_some()
        {
            return Err(invalid(format!("duplicate template_id {id:?}")));
        }
    }
    Ok(templates)
}

/// 平台 → 机器类别的对应（分类必须与机器平台一致）。
pub fn platform_for_machine_class(machine_class: &str) -> Option<&'static str> {
    match machine_class {
        "MacDaily" | "MacDev" => Some("macos"),
        "LinuxHost" | "LinuxCompute" | "LinuxData" => Some("linux"),
        _ => None,
    }
}

/// 词表**追加式**校验：新词表不得删除旧面。
///
/// 改名在值集上等同于「删旧名 + 加新名」，因此只能验「删」——但这已经能挡住两类真实错误：
/// 手滑删掉一条，或把改名当成无害修改。返回被删掉的面（供报错直接列出）。
///
/// 回滚不走这里（`activate` 的 `reason = rollback` 是有意的旧版落地，见 `knowledge_ops`）。
pub fn check_vocabulary_append_only(old: &ContentSet, new: &ContentSet) -> Result<(), Vec<String>> {
    let removed: Vec<String> = old
        .families
        .keys()
        .filter(|id| !new.families.contains_key(*id))
        .cloned()
        .collect();
    if removed.is_empty() {
        Ok(())
    } else {
        Err(removed)
    }
}

/// 由 `pack_refs` 派生 `(family_scope, capability_scope)`（保持稳定顺序）。
fn derive_scope(
    pack_refs: &[String],
    packs: &BTreeMap<String, Pack>,
    units: &BTreeMap<String, Unit>,
) -> (Vec<String>, Vec<String>) {
    let mut families: Vec<String> = Vec::new();
    let mut capabilities: Vec<String> = Vec::new();
    for pack_ref in pack_refs {
        let Some(pack) = packs.get(pack_ref) else {
            continue;
        };
        for unit_ref in &pack.unit_refs {
            let Some(unit) = units.get(unit_ref) else {
                continue;
            };
            if !families.contains(&unit.family) {
                families.push(unit.family.clone());
            }
            if !capabilities.contains(&unit.capability) {
                capabilities.push(unit.capability.clone());
            }
        }
    }
    (families, capabilities)
}

// ─────────────────────────────────────────────────────────────────────────────
// 查询与展开
// ─────────────────────────────────────────────────────────────────────────────

impl ContentSet {
    pub fn units(&self) -> impl Iterator<Item = &Unit> {
        self.units.values()
    }

    pub fn packs(&self) -> impl Iterator<Item = &Pack> {
        self.packs.values()
    }

    pub fn templates(&self) -> impl Iterator<Item = &Template> {
        self.templates.values()
    }

    /// 面词表（按 `id` 排序，稳定）。
    pub fn families(&self) -> impl Iterator<Item = &FamilyMeta> {
        self.families.values()
    }

    pub fn family(&self, id: &str) -> Option<&FamilyMeta> {
        self.families.get(id)
    }

    /// 这个词是不是词表里的合法值。
    pub fn has_family(&self, id: &str) -> bool {
        self.families.contains_key(id)
    }

    /// 目录里 `match` 用到的 `path_exists:<绝对路径>`，以及所有**显式文件来源**的目标。
    ///
    /// 这是网关下发给 agentd 的**探测白名单**：agentd 只探这些路径，不探任意路径。
    /// 派活求值与探测白名单同源，避免「求值要的路径没下发」这种静默永不命中的情况。
    ///
    /// 显式来源也要探：派活物化时按「探测过且不存在」把来源裁掉
    /// （`work.rs::materialize_spec`），否则 Ubuntu 上会派 `dnf.log`、RHEL 上派 `auth.log`
    /// 这类永远失败的输入。探测白名单与裁剪判据必须同源。
    pub fn probe_paths(&self) -> Vec<String> {
        let mut paths: BTreeSet<String> = BTreeSet::new();
        for unit in self.units.values() {
            for condition in parse_conditions(&unit.match_expr) {
                // 否定条件也要探：不探就永远是「无法判定」，那个单元永远展不开。
                if condition.kind != "path_exists" && condition.kind != "not_path_exists" {
                    continue;
                }
                for value in condition.values {
                    if value.starts_with('/') {
                        paths.insert(value);
                    }
                }
            }
            for source in &unit.sources {
                if source.kind == "FileGlob" && is_explicit_path(&source.target) {
                    paths.insert(source.target.clone());
                }
            }
        }
        paths.into_iter().collect()
    }

    /// 某个采集面是否可能出现在某平台上（依据词表的 `platforms`）。
    ///
    /// 与 [`Self::is_family_ready`] 分工不同：那个回答「采集要素齐不齐」，
    /// 这个回答「这个面在这类机器上存不存在」。派活时要分开报 —— 对一台 Linux 机器说
    /// 「TCC 面采集未就绪」是把**不适用**说成了**没准备好**，会把人引向错误的下一步。
    pub fn family_applies_to(&self, family: &str, platform: &str) -> bool {
        PLATFORMS.contains(&platform)
            && self
                .families
                .get(family)
                .is_some_and(|meta| meta.applies_to(platform))
    }

    pub fn template(&self, template_id: &str) -> Option<&Template> {
        self.templates.get(template_id)
    }

    pub fn template_for_machine_class(&self, machine_class: &str) -> Option<&Template> {
        self.templates
            .values()
            .find(|template| template.machine_class == machine_class)
    }

    /// 某平台所有（出现过的）面的就绪度（采集轴 + 解析轴）。
    pub fn family_readiness(&self, platform: &str) -> Vec<FamilyReadiness> {
        // (采集就绪数, 解析就绪数, 总数)
        let mut per_family: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
        for unit in self.units.values().filter(|unit| unit.platform == platform) {
            let entry = per_family.entry(unit.family.as_str()).or_insert((0, 0, 0));
            entry.2 += 1;
            if unit.collect_ready() {
                entry.0 += 1;
                if unit.parse_ready() {
                    entry.1 += 1;
                }
            }
        }
        per_family
            .into_iter()
            .map(|(family, (active, parse_ready, total))| FamilyReadiness {
                family: family.to_string(),
                platform: platform.to_string(),
                active_units: active,
                parse_ready_units: parse_ready,
                total_units: total,
            })
            .collect()
    }

    /// 面在某平台上是否**采集就绪**（至少一个 `active` 单元）——「能不能派下去采」。
    pub fn is_family_ready(&self, platform: &str, family: &str) -> bool {
        self.units
            .values()
            .any(|unit| unit.platform == platform && unit.family == family && unit.collect_ready())
    }

    /// 按模板把一台机器展开成「一面一份」的常驻工作（**未落库**，纯计算）。
    ///
    /// 规则：
    ///   - **采集就绪**的**单元**（`status = active`）才参与 `match` 求值；
    ///     同一面里的 `draft` 单元即使条件命中也不展开（进 `excluded_units(collect_not_ready)`）——
    ///     面就绪（至少一条 active）不等于面里每个单元都已就绪；
    ///   - 面没有任何 `active` 单元时整面不展开（其所有单元进 `collect_not_ready`）；
    ///   - 就绪面里，`match` 三态过滤：命中 → 选中；不命中 → `match_unsatisfied`；
    ///     无法判定（事实没采到）→ `fact_not_collected`；
    ///   - 选中集为空的面不产生工作（但排除项仍留痕）。
    ///
    /// **不**看 `rule_ref`：能不能采与能不能解析是两件事（见 [`Unit::parse_ready`]）。
    pub fn expand(
        &self,
        template_id: &str,
        facts: &StoredAgentFactSummary,
    ) -> Result<Expansion, String> {
        let template = self
            .templates
            .get(template_id)
            .ok_or_else(|| format!("unknown template {template_id:?}"))?;

        let mut works = Vec::new();
        let mut excluded = Vec::new();

        for family in &template.family_scope {
            let units: Vec<&Unit> = self
                .units
                .values()
                .filter(|unit| unit.platform == template.platform && unit.family == *family)
                .collect();

            if !self.is_family_ready(&template.platform, family) {
                for unit in units {
                    excluded.push(ExcludedUnit {
                        unit_id: unit.unit_id.clone(),
                        reason_code: "collect_not_ready".to_string(),
                        condition: None,
                    });
                }
                continue;
            }

            let mut selected = Vec::new();
            for unit in units {
                // **单元自己的采集就绪度是派活闸门**：一个面里可能同时有一条 active
                // （容器 stdout）和一条 draft（slurm/nvidia）。面级就绪不能把 draft 单元一起放下去 ——
                // 那会派下 agentd 还不保证能执行的来源。
                if !unit.collect_ready() {
                    excluded.push(ExcludedUnit {
                        unit_id: unit.unit_id.clone(),
                        reason_code: "collect_not_ready".to_string(),
                        condition: None,
                    });
                    continue;
                }
                match eval_match(&unit.match_expr, facts) {
                    Truth::Yes => selected.push(unit.unit_id.clone()),
                    Truth::No => excluded.push(ExcludedUnit {
                        unit_id: unit.unit_id.clone(),
                        reason_code: "match_unsatisfied".to_string(),
                        condition: first_non_yes_condition(&unit.match_expr, facts, false),
                    }),
                    Truth::Unknown => excluded.push(ExcludedUnit {
                        unit_id: unit.unit_id.clone(),
                        reason_code: "fact_not_collected".to_string(),
                        condition: first_non_yes_condition(&unit.match_expr, facts, true),
                    }),
                }
            }
            if selected.is_empty() {
                continue;
            }
            works.push(ExpandedWork {
                family: family.clone(),
                capability: capability_of(self, &template.platform, family),
                catalog_version: template.catalog_version,
                selected_units: selected,
            });
        }

        Ok(Expansion {
            template_id: template.template_id.clone(),
            machine_class: template.machine_class.clone(),
            platform: template.platform.clone(),
            works,
            excluded_units: excluded,
        })
    }
}

fn capability_of(content: &ContentSet, platform: &str, family: &str) -> String {
    content
        .units
        .values()
        .find(|unit| unit.platform == platform && unit.family == family)
        .map(|unit| unit.capability.clone())
        .unwrap_or_default()
}

/// 展开结果（一份模板 → 若干「一面一份」的工作 + 全量排除留痕）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    pub template_id: String,
    pub machine_class: String,
    pub platform: String,
    pub works: Vec<ExpandedWork>,
    /// 没进任何工作的单元及原因（含未就绪面）。
    pub excluded_units: Vec<ExcludedUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedWork {
    pub family: String,
    pub capability: String,
    pub catalog_version: i64,
    pub selected_units: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedUnit {
    pub unit_id: String,
    /// `collect_not_ready` | `match_unsatisfied` | `fact_not_collected`。
    pub reason_code: String,
    /// 不满足/无法判定的那条条件（如 `installed:postgresql`）。
    pub condition: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// match 求值（三态）
// ─────────────────────────────────────────────────────────────────────────────

/// `match` 求值三态 —— 关键是**无法判定**与**不满足**分开。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truth {
    Yes,
    No,
    Unknown,
}

/// 条件：`kind:value(|value)*`。条件之间用 `;`（**且**）。
struct Condition {
    raw: String,
    kind: String,
    values: Vec<String>,
}

fn parse_conditions(expr: &str) -> Vec<Condition> {
    expr.split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let (kind, rest) = part.split_once(':')?;
            Some(Condition {
                raw: part.to_string(),
                kind: kind.trim().to_string(),
                values: rest
                    .split('|')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .collect()
}

/// 求值：空表达式 = 平台基线必采（`Yes`）。
fn eval_match(expr: &str, facts: &StoredAgentFactSummary) -> Truth {
    let conditions = parse_conditions(expr);
    if conditions.is_empty() {
        return Truth::Yes;
    }
    let mut saw_unknown = false;
    for condition in &conditions {
        match eval_condition(condition, facts) {
            Truth::No => return Truth::No,
            Truth::Unknown => saw_unknown = true,
            Truth::Yes => {}
        }
    }
    if saw_unknown {
        Truth::Unknown
    } else {
        Truth::Yes
    }
}

/// 找第一条导致非 `Yes` 的条件文本（给审计留痕）。
fn first_non_yes_condition(
    expr: &str,
    facts: &StoredAgentFactSummary,
    want_unknown: bool,
) -> Option<String> {
    for condition in parse_conditions(expr) {
        let truth = eval_condition(&condition, facts);
        if want_unknown && truth == Truth::Unknown {
            return Some(condition.raw);
        }
        if !want_unknown && truth == Truth::No {
            return Some(condition.raw);
        }
    }
    None
}

fn eval_condition(condition: &Condition, facts: &StoredAgentFactSummary) -> Truth {
    // `path_exists` / `not_path_exists` 需要的是「探测过才判得出来」，与其它 kind 的
    // 「空事实 = 无法判定」不同，所以单独走分支。
    if condition.kind == "path_exists" {
        return eval_path_exists(condition, facts);
    }
    if condition.kind == "not_path_exists" {
        return eval_not_path_exists(condition, facts);
    }

    // 端口是**数值**集合，包名是**文本**：两者共用不了 `contains`。
    // 端口用子串匹配会把 `tcp:35432` 判成命中 `5432`（临时端口撞 4 位 pattern 是常态）。
    if condition.kind == "port" {
        return eval_port_condition(condition, facts);
    }

    let haystack: &[String] = match condition.kind.as_str() {
        // 已装包清单：探针没实现时**恒空** → 空表示“没采”，不是“没装”。
        "installed" => &facts.packages,
        // 设备 / 服务单元 / 资源量：摘要里**没有**这些事实 → 恒为“无法判定”。
        "device" | "service" | "resource" => return Truth::Unknown,
        // 未知 kind 也按“无法判定”，不冒充否定。
        _ => return Truth::Unknown,
    };
    if haystack.is_empty() {
        // 事实缺位：不是“不满足”，是“无法判定”。
        return Truth::Unknown;
    }
    let matched = condition.values.iter().any(|value| {
        let needle = value.to_lowercase();
        haystack
            .iter()
            .any(|fact| fact.to_lowercase().contains(&needle))
    });
    if matched { Truth::Yes } else { Truth::No }
}

/// `port:` 的求值（三态）。
///
/// 事实里只采**稳定服务端口**：`>= EPHEMERAL_PORT_START` 的监听被有意过滤掉了。
/// 所以「没命中」有两种不同含义，不能都答 `No`：
/// - 条件端口在采集区间内（`< EPHEMERAL_PORT_START`）→ `No`：那个区间是完整的，没命中就是没监听。
/// - 条件端口落在被过滤的区间 → `Unknown`：我们没采，不等于没监听。
///   真把高端口条件写进目录时，它应该表现为「无法判定」并被审计看到，而不是静默变成「不满足」。
/// - 端口事实整体为空（旧 agent / 没采到）→ `Unknown`。
///
/// 语义是 **OR**：任一条命中即 `Yes`，命中优先于「无法判定」。
fn eval_port_condition(condition: &Condition, facts: &StoredAgentFactSummary) -> Truth {
    if condition.values.is_empty() || facts.listen_ports.is_empty() {
        // 事实缺位（或条件没写值）：不是“不满足”，是“无法判定”。
        return Truth::Unknown;
    }
    let mut saw_uncollected = false;
    for value in &condition.values {
        if facts
            .listen_ports
            .iter()
            .any(|fact| listen_port_equals(fact, value))
        {
            return Truth::Yes;
        }
        match value.trim().parse::<u16>() {
            Ok(port) if port < EPHEMERAL_PORT_START => {}
            // 数字但落在被过滤的区间，或根本不是数字：都答不了「没有」。
            _ => saw_uncollected = true,
        }
    }
    if saw_uncollected {
        Truth::Unknown
    } else {
        Truth::No
    }
}

/// 事实里的端口是 `<proto>:<port>`（旧 agent 可能只有裸端口），条件里写的是裸端口。
fn listen_port_equals(fact: &str, expected: &str) -> bool {
    fact.split_once(':').map_or(fact, |(_, port)| port).trim() == expected.trim()
}

/// `path_exists:/a|/b` 的求值。
///
/// 语义是 **OR**：任一路径存在 → Yes；全部**探测过**且都不存在 → No；
/// 有路径没被探测过（旧 agent / 该路径不在白名单）→ Unknown。
fn eval_path_exists(condition: &Condition, facts: &StoredAgentFactSummary) -> Truth {
    if condition.values.is_empty() {
        return Truth::Unknown;
    }
    let mut all_probed = true;
    for value in &condition.values {
        let probed = facts.probed_paths.iter().any(|path| path == value);
        if probed && facts.present_paths.iter().any(|path| path == value) {
            return Truth::Yes;
        }
        if !probed {
            all_probed = false;
        }
    }
    if all_probed {
        Truth::No
    } else {
        Truth::Unknown
    }
}

/// `not_path_exists:` 的三态求值（否定条件）。
///
/// 语义与 [`eval_path_exists`] 镜像但**方向相反**：
/// - 任一个值**探测到且存在** → `No`（否定条件不成立）；
/// - 所有值都探测过且都不存在 → `Yes`；
/// - 有値没探测过 → `Unknown`（不拿“没探”冒充“不存在”）。
///
/// 用途：纯 Docker 主机的容器单元。`k8s + cri-dockerd` 的机器上 kubelet 会把 pod 日志
/// 指向 docker 的 json 文件，两个单元会同时命中 → 用 `not_path_exists:/var/log/containers`
/// 把这个单元排除掉，不重复采集。
fn eval_not_path_exists(condition: &Condition, facts: &StoredAgentFactSummary) -> Truth {
    if condition.values.is_empty() {
        return Truth::Unknown;
    }
    let mut all_probed = true;
    for value in &condition.values {
        let probed = facts.probed_paths.iter().any(|path| path == value);
        if !probed {
            all_probed = false;
            continue;
        }
        if facts.present_paths.iter().any(|path| path == value) {
            return Truth::No;
        }
    }
    if all_probed {
        Truth::Yes
    } else {
        Truth::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = r#"
catalog_version = 1
origin = "Gateway"
published_at = "2026-09-22T00:00:00Z"

[[units]]
unit_id = "mac-metrics"
family = "HostMetrics"
capability = "collect_metrics"
platform = "macos"
match = ""
rule_ref = "agent_uplink"
requires_privilege = "none"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"

[[units]]
unit_id = "linux-metrics"
family = "HostMetrics"
capability = "collect_metrics"
platform = "linux"
match = ""
rule_ref = "agent_uplink"
requires_privilege = "root"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"

[[units]]
unit_id = "linux-db"
family = "DatabaseService"
capability = "collect_logs"
platform = "linux"
match = "installed:postgresql"
rule_ref = "linux/db"
requires_privilege = "root"
status = "active"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/postgresql.log"
"#;

    const PACKS: &str = r#"
[[pack]]
pack_id = "macos-base"
platform = "macos"
kind = "Baseline"
families = ["HostMetrics"]
unit_refs = ["mac-metrics"]
catalog_version = 1
status = "active"

[[pack]]
pack_id = "linux-base"
platform = "linux"
kind = "Baseline"
families = ["HostMetrics"]
unit_refs = ["linux-metrics"]
catalog_version = 1
status = "active"

[[pack]]
pack_id = "linux-datastore"
platform = "linux"
kind = "Feature"
families = ["DatabaseService"]
unit_refs = ["linux-db"]
catalog_version = 1
status = "active"
"#;

    const TEMPLATES: &str = r#"
[[template]]
template_id = "macos-daily"
machine_class = "MacDaily"
platform = "macos"
pack_refs = ["macos-base"]
catalog_version = 1
template_version = 1
status = "active"

[[template]]
template_id = "linux-data"
machine_class = "LinuxData"
platform = "linux"
pack_refs = ["linux-base", "linux-datastore"]
catalog_version = 1
template_version = 1
status = "active"
"#;

    fn minimal() -> ContentSet {
        parse_content(CATALOG, PACKS, TEMPLATES).expect("minimal content parses")
    }

    fn facts(os: &str, packages: &[&str]) -> StoredAgentFactSummary {
        StoredAgentFactSummary {
            os: os.to_string(),
            packages: packages.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_family_closed_set_matches_the_model() {
        // 采集面是**闭集**：网关白名单与模型必须逐字一致，否则会出现
        // 「模型里有个面、网关拒了它」或「网关放行了一个模型里不存在的面」。
        // 靠人守必然漂（现在就有一个：launchd 的归属两处说法不同），所以钉在这里。
        let path = crate::test_support::model_file(
            "jumo/model/static/control/module/agent/content/families.mju",
        );
        let text = std::fs::read_to_string(&path).expect("read families.mju");
        let mut model = parse_family_variant(&text);
        assert!(
            !model.is_empty(),
            "一个面都没解析出来：families.mju 的写法变了？"
        );
        model.sort();
        let mut model_unique = model.clone();
        model_unique.dedup();
        assert_eq!(model_unique.len(), model.len(), "模型里有重复的面名");

        let mut gateway: Vec<String> = FAMILIES
            .iter()
            .map(|family| (*family).to_string())
            .collect();
        gateway.sort();
        assert_eq!(
            model_unique, gateway,
            "面闭集两边不一致：模型 families.mju vs 网关 FAMILIES"
        );
    }

    /// 词表的**值**在知识库：不在内置常量里的面，只要 `[[families]]` 声明了就能用；
    /// 平台归属与「词表外拒收」也由这份数据决定，而不是代码里的两份常量。
    #[test]
    fn the_vocabulary_comes_from_the_catalog_not_from_the_const() {
        let vocabulary = build_vocabulary(&[
            family_row("ContainerRuntime", &["linux"]),
            family_row("HostMetrics", &[]),
        ])
        .expect("vocabulary");

        assert!(vocabulary.contains_key("ContainerRuntime"));
        assert!(
            !vocabulary.contains_key("LoginSession"),
            "没在词表里声明的面不该凭空出现"
        );
        assert_eq!(
            vocabulary["ContainerRuntime"].platforms,
            vec!["linux".to_string()]
        );

        validate_unit(&unit_row("u1", "ContainerRuntime", "linux"), &vocabulary)
            .expect("valid unit");

        let err = validate_unit(&unit_row("u2", "ContainerRuntime", "macos"), &vocabulary)
            .expect_err("platform mismatch");
        assert!(
            err.to_string().contains("does not apply to platform"),
            "报错要说清是平台不适用：{err}"
        );

        let err = validate_unit(&unit_row("u3", "LoginSession", "linux"), &vocabulary)
            .expect_err("unknown family");
        assert!(err.to_string().contains("unknown family"), "{err}");
    }

    /// 平台归属也来自词表，而不是代码里的两份常量。
    #[test]
    fn a_family_platform_comes_from_the_vocabulary() {
        let catalog = r#"
catalog_version = 1
origin = "Gateway"
published_at = "2026-10-18T00:00:00Z"

[[families]]
id = "MacOnly"
platforms = ["macos"]

[[units]]
unit_id = "u1"
family = "MacOnly"
capability = "collect_logs"
platform = "linux"
match = ""
rule_ref = ""
requires_privilege = "none"
status = "draft"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/x.log"
"#;
        let err = parse_content(catalog, "", "").expect_err("must reject platform mismatch");
        assert!(
            err.to_string().contains("does not apply to platform"),
            "报错要说清是平台不适用：{err}"
        );
    }

    /// 词表外的面名仍然是错（拼写错误不能被当成新面收下）。
    #[test]
    fn a_unit_outside_the_vocabulary_is_rejected() {
        let catalog = r#"
catalog_version = 1
origin = "Gateway"
published_at = "2026-10-18T00:00:00Z"

[[families]]
id = "Alpha"

[[units]]
unit_id = "u1"
family = "Beta"
capability = "collect_logs"
platform = "linux"
match = ""
rule_ref = ""
requires_privilege = "none"
status = "draft"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/x.log"
"#;
        let err = parse_content(catalog, "", "").expect_err("must reject unknown family");
        assert!(err.to_string().contains("unknown family"));
    }

    /// 词表只增：删掉一个面要报出来（改名在值集上就是「删 + 增」）。
    #[test]
    fn the_vocabulary_is_append_only() {
        let old = content_with_families(&["Alpha", "Beta"]);
        let same = content_with_families(&["Alpha", "Beta"]);
        let added = content_with_families(&["Alpha", "Beta", "Gamma"]);
        let removed = content_with_families(&["Alpha"]);

        assert!(check_vocabulary_append_only(&old, &same).is_ok());
        assert!(check_vocabulary_append_only(&old, &added).is_ok());
        assert_eq!(
            check_vocabulary_append_only(&old, &removed),
            Err(vec!["Beta".to_string()])
        );
    }

    /// 改名在值集上就是「旧名消失 + 新名出现」—— 必须当成删除报出来。
    #[test]
    fn a_rename_is_reported_as_a_removal() {
        let old = content_with_families(&["LoginSession"]);
        let renamed = content_with_families(&["UserSession"]);
        assert_eq!(
            check_vocabulary_append_only(&old, &renamed),
            Err(vec!["LoginSession".to_string()])
        );
    }

    /// 空词表 = 旧包，回落内置基线（不能因为没词表就拒载，否则升级即事故）。
    #[test]
    fn an_empty_vocabulary_falls_back_to_the_built_in_baseline() {
        let vocabulary = build_vocabulary(&[]).expect("fallback");
        assert_eq!(vocabulary.len(), FAMILIES.len());
        assert!(vocabulary.contains_key("LoginSession"));
        assert_eq!(
            vocabulary["PrivacyTcc"].platforms,
            vec!["macos".to_string()],
            "基线里的平台归属也要跟着推出来"
        );
    }

    #[test]
    fn duplicate_family_ids_are_rejected() {
        let err = build_vocabulary(&[family_row("Alpha", &[]), family_row("Alpha", &[])])
            .expect_err("duplicate");
        assert!(err.to_string().contains("duplicate family"), "{err}");
    }

    #[test]
    fn a_family_id_must_not_carry_surrounding_whitespace() {
        // 前后空白会变成两个不同的协议值（统计/回溯从此分叉），必须在装载时就拒。
        let err = build_vocabulary(&[family_row(" Alpha", &[])]).expect_err("whitespace");
        assert!(err.to_string().contains("前后空白"), "{err}");
    }

    #[test]
    fn a_family_platform_must_be_known() {
        let err =
            build_vocabulary(&[family_row("Alpha", &["windows"])]).expect_err("unknown platform");
        assert!(err.to_string().contains("unknown platform"), "{err}");
    }

    /// 词表外的面在任何平台上都不适用；未知平台也不适用（两道都读过词表）。
    #[test]
    fn an_unknown_family_does_not_apply_to_any_platform() {
        let content = content_with_families(&["Alpha"]);
        assert!(content.family_applies_to("Alpha", "linux"));
        assert!(content.family_applies_to("Alpha", "macos"));
        assert!(!content.family_applies_to("Beta", "linux"));
        assert!(!content.family_applies_to("Alpha", "windows"));
        assert!(!content.has_family("Beta"));
    }

    /// 知识库里的**真实**词表必须与模型一致（CI 的模型一致校验）。
    #[test]
    fn the_knowledge_vocabulary_matches_the_model() {
        let catalog = std::fs::read_to_string(crate::test_support::knowledge_file("catalog.toml"))
            .expect("read catalog.toml");
        let packs = std::fs::read_to_string(crate::test_support::knowledge_file("packs.toml"))
            .expect("read packs.toml");
        let templates =
            std::fs::read_to_string(crate::test_support::knowledge_file("templates.toml"))
                .expect("read templates.toml");
        let content = parse_content(&catalog, &packs, &templates).expect("real knowledge parses");

        let path = crate::test_support::model_file(
            "jumo/model/static/control/module/agent/content/families.mju",
        );
        let text = std::fs::read_to_string(&path).expect("read families.mju");
        let mut model = parse_family_variant(&text);
        model.sort();

        let mut vocabulary: Vec<String> = content.families().map(|meta| meta.id.clone()).collect();
        vocabulary.sort();
        assert_eq!(
            model, vocabulary,
            "面词表不一致：模型 families.mju vs 知识库 catalog.toml 的 [[families]]"
        );

        // 展示文案是页面直接渲染的东西：真数据里不能有空洞（缺了只能回落成 ID）。
        for meta in content.families() {
            for (field, value) in [
                ("name_zh", &meta.name_zh),
                ("name_en", &meta.name_en),
                ("summary_zh", &meta.summary_zh),
                ("summary_en", &meta.summary_en),
            ] {
                assert!(
                    !value.trim().is_empty(),
                    "family {}: {field} 为空（页面会退回面 ID）",
                    meta.id
                );
            }
        }
    }

    /// `[[families]]` 的一行（测试用）。
    fn family_row(id: &str, platforms: &[&str]) -> FamilyRow {
        FamilyRow {
            id: id.to_string(),
            platforms: platforms.iter().map(|value| value.to_string()).collect(),
            semantics_version: 0,
            name_zh: String::new(),
            name_en: String::new(),
            summary_zh: String::new(),
            summary_en: String::new(),
        }
    }

    /// 一个最小单元（测试用）：只关心面与平台，来源给一条可执行的显式路径。
    fn unit_row(id: &str, family: &str, platform: &str) -> UnitRow {
        UnitRow {
            unit_id: id.to_string(),
            family: family.to_string(),
            capability: "collect_logs".to_string(),
            platform: platform.to_string(),
            match_expr: String::new(),
            rule_ref: String::new(),
            requires_privilege: "none".to_string(),
            status: "draft".to_string(),
            sources: vec![SourceRow {
                filters: Default::default(),
                kind: "FileGlob".to_string(),
                target: "/var/log/x.log".to_string(),
                multiline: "none".to_string(),
                exclude_globs: Vec::new(),
                drop_if_contains: Vec::new(),
            }],
        }
    }

    /// 只带词表的 `ContentSet`：追加式校验只看面集合，不需要单元/包/模板。
    fn content_with_families(ids: &[&str]) -> ContentSet {
        let families = ids
            .iter()
            .map(|id| {
                (
                    (*id).to_string(),
                    FamilyMeta {
                        id: (*id).to_string(),
                        platforms: Vec::new(),
                        semantics_version: 0,
                        name_zh: String::new(),
                        name_en: String::new(),
                        summary_zh: String::new(),
                        summary_en: String::new(),
                    },
                )
            })
            .collect();
        ContentSet {
            catalog_version: 1,
            superseded_by: None,
            families,
            units: Default::default(),
            packs: Default::default(),
            templates: Default::default(),
        }
    }

    /// 从 `families.mju` 里取出 `variant CollectionFamily` 的成员名。
    ///
    /// 故意写得很笨（按行 + 括号计数）：这个文件是固定写法，**写法一变就让测试红**，
    /// 比引一个 `.mju` 解析器划算。
    fn parse_family_variant(text: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut in_variant = false;
        let mut in_meta = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if !in_variant {
                in_variant = line.starts_with("variant CollectionFamily");
                continue;
            }
            if in_meta {
                if line.starts_with('}') {
                    in_meta = false;
                }
                continue;
            }
            if line.starts_with("meta") {
                in_meta = true;
                continue;
            }
            if line.starts_with('}') {
                break;
            }
            names.extend(line.split_whitespace().map(str::to_string));
        }
        names
    }

    #[test]
    fn parses_a_minimal_valid_content_set() {
        let set = minimal();
        assert_eq!(set.catalog_version, 1);
        assert_eq!(set.templates().count(), 2);
        let daily = set.template("macos-daily").expect("macos-daily");
        assert_eq!(daily.family_scope, vec!["HostMetrics"]);
        assert_eq!(daily.capability_scope, vec!["collect_metrics"]);
        let data = set.template("linux-data").expect("linux-data");
        assert_eq!(data.family_scope, vec!["HostMetrics", "DatabaseService"]);
    }

    #[test]
    fn reads_the_checked_in_content_set() {
        // 真实策展数据必须能通过校验（防止手改 TOML 后网关带病启动）。
        let set = load_content(
            &crate::test_support::knowledge_file("catalog.toml"),
            &crate::test_support::knowledge_file("packs.toml"),
            &crate::test_support::knowledge_file("templates.toml"),
        )
        .expect("load checked-in content");
        // 目录版本要随内容一起抬（见 catalog.toml 头部约定）：旧工作锁在它展开时那一版上。
        assert_eq!(
            set.catalog_version,
            crate::test_support::real_catalog_version()
        );
        assert_eq!(set.templates().count(), 5);
        assert_eq!(
            set.template("macos-daily")
                .expect("macos-daily")
                .family_scope
                .len(),
            10
        );
        // 采集就绪与解析就绪是**两个轴**，分开看：
        //   采集就绪（显式单路径 / 指标周期）：SoftwareChange / NetworkFirewall /
        //     ServiceLifecycle / RebootPower / HostMetrics —— 注意 NetworkFirewall 与
        //     ServiceLifecycle 都是**会轮转**的文件族，靠**显式路径 + inode 跟踪**采，
        //     不是靠 `wifi.log*` 这种通配（通配会把历史轮转产物也纳进来）；
        //   RebootPower 的 rule_ref 为空 → **解析未就绪**，但照样可采；
        //   PrivacyTcc 的来源是 Exporter（agentd 还没实现）。
        assert!(set.is_family_ready("macos", "HostMetrics"));
        assert!(set.is_family_ready("macos", "SoftwareChange"));
        assert!(set.is_family_ready("macos", "RebootPower"));
        assert!(set.is_family_ready("macos", "NetworkFirewall"));
        assert!(set.is_family_ready("macos", "ServiceLifecycle"));
        assert!(!set.is_family_ready("macos", "PrivacyTcc"));
        assert!(!set.is_family_ready("macos", "CrashPanic"));

        let readiness = set.family_readiness("macos");
        let by_family = |family: &str| {
            readiness
                .iter()
                .find(|entry| entry.family == family)
                .unwrap_or_else(|| panic!("no readiness for {family}"))
        };
        let reboot = by_family("RebootPower");
        assert_eq!(
            (
                reboot.active_units,
                reboot.parse_ready_units,
                reboot.total_units
            ),
            (1, 0, 1)
        );
        assert!(reboot.collect_ready() && !reboot.parse_ready());
        let tcc = by_family("PrivacyTcc");
        assert!(!tcc.collect_ready());

        // Linux 侧现在 12 个面全开：文件来源（auth/secure、sudo.log、dpkg/apt/dnf/yum、
        //   audit.log 整文件、容器 stdout、DB csvlog/slow）+ 导出器（ServiceLifecycle/CrashPanic/
        //   NetworkFirewall/RebootPower/KernelSystem/StorageHealth）+ 指标面。
        //   日志面 `rule_ref` 为空 = **可采但解析未就绪**（原文照收，只归在泛化 agent.log）。
        for family in [
            "LoginSession",
            "PrivilegeExecution",
            "SoftwareChange",
            "ServiceLifecycle",
            "CrashPanic",
            "NetworkFirewall",
            "RebootPower",
            "KernelSystem",
            "StorageHealth",
            "HostMetrics",
            "ComputeWorkload",
            "DatabaseService",
        ] {
            assert!(
                set.is_family_ready("linux", family),
                "linux {family} 应当采集就绪"
            );
        }
        let linux_readiness = set.family_readiness("linux");
        let linux_by_family = |family: &str| {
            linux_readiness
                .iter()
                .find(|entry| entry.family == family)
                .unwrap_or_else(|| panic!("no linux readiness for {family}"))
        };
        let login = linux_by_family("LoginSession");
        assert!(
            login.collect_ready() && !login.parse_ready(),
            "linux LoginSession 应当可采但解析未就绪（rule_ref 为空）"
        );
        assert_eq!(
            (
                login.active_units,
                login.parse_ready_units,
                login.total_units
            ),
            (1, 0, 1)
        );
        let linux_metrics = linux_by_family("HostMetrics");
        assert!(
            linux_metrics.collect_ready() && linux_metrics.parse_ready(),
            "linux HostMetrics 应当采集就绪且解析就绪（rule_ref = agent_uplink）"
        );
    }

    #[test]
    fn every_machine_class_can_be_classified_and_dispatched() {
        // 不变量：一个机器类别若没有平台映射、没有模板，或模板展开后一个可派面都没有，
        // 「归档判定」过后就**一定派不出工作**（能判用途却不产采集任务）。
        // 加了类别却漏配模板/映射、或单元没开采集就绪，靠这条当场挡住 ——
        // `LinuxHost` 与 `linux-host-metrics` 就是为此。
        let set = load_content(
            &crate::test_support::knowledge_file("catalog.toml"),
            &crate::test_support::knowledge_file("packs.toml"),
            &crate::test_support::knowledge_file("templates.toml"),
        )
        .expect("load checked-in content");
        for class in MACHINE_CLASSES {
            let platform = platform_for_machine_class(class)
                .unwrap_or_else(|| panic!("机器类别 {class} 没有平台映射"));
            let template = set.template_for_machine_class(class).unwrap_or_else(|| {
                panic!("机器类别 {class} 没有模板：派活会在 derive_spec 处被拒")
            });
            // 空事实下也要**至少有一个面能派**：模板存在但每个面都「采集未就绪」，
            // 等于给运维一个能归档、却什么都派不出去的类别。
            let expansion = set
                .expand(&template.template_id, &facts(platform, &[]))
                .expect("expand");
            assert!(
                !expansion.works.is_empty(),
                "机器类别 {class} 的模板 {} 展开后 0 个可派面（单元没有 status = active？）",
                template.template_id
            );
        }
    }

    #[test]
    fn expands_the_collect_ready_families_and_records_the_rest() {
        let set = load_content(
            &crate::test_support::knowledge_file("catalog.toml"),
            &crate::test_support::knowledge_file("packs.toml"),
            &crate::test_support::knowledge_file("templates.toml"),
        )
        .expect("load checked-in content");
        let expansion = set
            .expand("macos-daily", &facts("macos", &[]))
            .expect("expand");
        // 采集就绪的面按包内行序展开（macos-base 的 unit_refs 顺序）；
        // 剩下 5 个面的单元留痕 —— 事件型（`.ips`）、目录型、或来源类型未实现。
        assert_eq!(
            expansion
                .works
                .iter()
                .map(|work| work.family.as_str())
                .collect::<Vec<_>>(),
            vec![
                "SoftwareChange",
                "NetworkFirewall",
                "ServiceLifecycle",
                "RebootPower",
                "HostMetrics"
            ]
        );
        assert_eq!(
            expansion.works[0].selected_units,
            vec!["mac-software-change"]
        );
        assert_eq!(expansion.works[1].selected_units, vec!["mac-network-wifi"]);
        assert_eq!(expansion.works[4].selected_units, vec!["mac-host-metrics"]);
        assert_eq!(
            expansion
                .excluded_units
                .iter()
                .map(|unit| unit.unit_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "mac-login-session",
                "mac-crash-panic",
                "mac-privacy-tcc",
                "mac-gatekeeper",
                "mac-misc-system"
            ]
        );
        assert!(
            expansion
                .excluded_units
                .iter()
                .all(|unit| unit.reason_code == "collect_not_ready")
        );
    }

    #[test]
    fn linux_host_expands_the_collect_ready_families() {
        // LinuxHost 模板（`linux-base` 包）10 个面全采集就绪：文件来源 + 导出器
        // （含 W3 的内核日志 `journalctl-kernel`）+ 指标面。
        // 别让「Linux 只能采指标」的旧状态悄悄回来。
        let set = load_content(
            &crate::test_support::knowledge_file("catalog.toml"),
            &crate::test_support::knowledge_file("packs.toml"),
            &crate::test_support::knowledge_file("templates.toml"),
        )
        .expect("load checked-in content");
        let mut host_facts = facts("linux", &[]);
        // 路径门控要“探测过且存在”才命中；这里模拟 Debian 系（auth.log、sudo.log、audit.log 都在）
        // 且本机是 systemd（内核日志面才展开）。
        host_facts.probed_paths = vec![
            "/var/log/auth.log".to_string(),
            "/var/log/sudo.log".to_string(),
            "/var/log/audit/audit.log".to_string(),
            "/run/systemd/journal".to_string(),
        ];
        host_facts.present_paths = host_facts.probed_paths.clone();
        let expansion = set.expand("linux-host", &host_facts).expect("expand");
        assert_eq!(
            expansion
                .works
                .iter()
                .map(|work| work.family.as_str())
                .collect::<Vec<_>>(),
            vec![
                "LoginSession",
                "PrivilegeExecution",
                "SoftwareChange",
                "ServiceLifecycle",
                "CrashPanic",
                "NetworkFirewall",
                "RebootPower",
                "KernelSystem",
                "StorageHealth",
                "HostMetrics"
            ]
        );
        assert_eq!(
            expansion.works[0].selected_units,
            vec!["linux-auth-session"]
        );
        // 全部采集就绪 → 没有被排除的单元。
        assert!(
            expansion.excluded_units.is_empty(),
            "{:?}",
            expansion.excluded_units
        );
    }

    #[test]
    fn path_exists_is_three_state_and_needs_probing() {
        let expr = "path_exists:/var/log/sudo.log";
        let facts_with = |probed: &[&str], present: &[&str]| StoredAgentFactSummary {
            probed_paths: probed.iter().map(|value| value.to_string()).collect(),
            present_paths: present.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        };

        // 没探测过 → 无法判定（不是「不存在」）。
        assert_eq!(eval_match(expr, &facts_with(&[], &[])), Truth::Unknown);

        // 探测过、但不存在 → 不满足。
        assert_eq!(
            eval_match(expr, &facts_with(&["/var/log/sudo.log"], &[])),
            Truth::No
        );

        // 存在 → 满足。
        assert_eq!(
            eval_match(
                expr,
                &facts_with(&["/var/log/sudo.log"], &["/var/log/sudo.log"])
            ),
            Truth::Yes
        );

        // 多条是 OR：任一路径存在即可。
        assert_eq!(
            eval_match("path_exists:/a|/b", &facts_with(&["/a", "/b"], &["/b"])),
            Truth::Yes
        );

        // 只探了 /a（不存在）、/b 没探 → 无法判定，不说「两个都不存在」。
        assert_eq!(
            eval_match("path_exists:/a|/b", &facts_with(&["/a"], &[])),
            Truth::Unknown
        );

        // 与其它条件用 `;` 组合是 **AND**：路径命中、但包事实缺位 → 仍无法判定。
        assert_eq!(
            eval_match(
                "path_exists:/a;installed:nginx",
                &facts_with(&["/a"], &["/a"])
            ),
            Truth::Unknown
        );

        // 「存在」但没标「探测过」= 自相矛盾的上报：按无法判定处理，不冒充命中。
        assert_eq!(
            eval_match(expr, &facts_with(&[], &["/var/log/sudo.log"])),
            Truth::Unknown
        );
    }

    #[test]
    fn not_path_exists_is_the_mirror_image_in_three_states() {
        // 用途：`k8s + cri-dockerd` 的机器上，kubelet 把 pod 日志指向 docker 的 json 文件，
        // 两个容器单元会同时命中 —— 用否定条件把 docker 单元排除掉。
        let expr = "not_path_exists:/var/log/containers";
        let facts_with = |probed: &[&str], present: &[&str]| StoredAgentFactSummary {
            probed_paths: probed.iter().map(|value| value.to_string()).collect(),
            present_paths: present.iter().map(|value| value.to_string()).collect(),
            ..Default::default()
        };

        // 没探过 → 无法判定（不拿“没探”冒充“不存在”）。
        assert_eq!(eval_match(expr, &facts_with(&[], &[])), Truth::Unknown);
        // 探过、不存在 → 满足（纯 Docker 主机）。
        assert_eq!(
            eval_match(expr, &facts_with(&["/var/log/containers"], &[])),
            Truth::Yes
        );
        // 探过、存在 → 不满足（k8s 节点）。
        assert_eq!(
            eval_match(
                expr,
                &facts_with(&["/var/log/containers"], &["/var/log/containers"])
            ),
            Truth::No
        );

        // 与肯定条件用 `;` 组合是 AND：两个都得成立。
        let both = "path_exists:/var/lib/docker/containers; not_path_exists:/var/log/containers";
        assert_eq!(
            eval_match(
                both,
                &facts_with(
                    &["/var/lib/docker/containers", "/var/log/containers"],
                    &["/var/lib/docker/containers"]
                )
            ),
            Truth::Yes
        );
        assert_eq!(
            eval_match(
                both,
                &facts_with(
                    &["/var/lib/docker/containers", "/var/log/containers"],
                    &["/var/lib/docker/containers", "/var/log/containers"]
                )
            ),
            Truth::No
        );
        // 否定条件自身没探过 → 整条无法判定。
        assert_eq!(
            eval_match(
                both,
                &facts_with(
                    &["/var/lib/docker/containers"],
                    &["/var/lib/docker/containers"]
                )
            ),
            Truth::Unknown
        );
    }

    #[test]
    fn probe_paths_cover_match_conditions_and_explicit_sources() {
        let catalog = CATALOG.replacen(
            "match = \"\"",
            "match = \"path_exists:/var/log/sudo.log\"",
            1,
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("parses");
        assert_eq!(
            set.probe_paths(),
            vec![
                "/var/log/postgresql.log".to_string(),
                "/var/log/sudo.log".to_string()
            ]
        );
        // 没有路径条件时，显式文件来源仍然要探（派活裁剪要用）。
        assert_eq!(
            minimal().probe_paths(),
            vec!["/var/log/postgresql.log".to_string()]
        );

        // 否定条件的路径**也必须**进白名单：不探就永远是「无法判定」，单元永远展不开。
        let negated = CATALOG.replacen(
            "match = \"\"",
            "match = \"not_path_exists:/var/log/containers\"",
            1,
        );
        let set = parse_with(&negated, PACKS, TEMPLATES).expect("parses");
        assert!(
            set.probe_paths()
                .contains(&"/var/log/containers".to_string()),
            "{:?}",
            set.probe_paths()
        );
    }

    #[test]
    fn path_exists_rejects_relative_paths() {
        let catalog = CATALOG.replacen("match = \"\"", "match = \"path_exists:relative.log\"", 1);
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("relative path");
        assert!(err.to_string().contains("absolute paths"), "{err}");
    }

    #[test]
    fn match_is_three_state() {
        let set = minimal();

        // 事实缺位（包探针未采）→ 无法判定，不冒充“没装”。
        let unknown = set
            .expand("linux-data", &facts("linux", &[]))
            .expect("expand");
        assert_eq!(unknown.works.len(), 1);
        let db = unknown
            .excluded_units
            .iter()
            .find(|unit| unit.unit_id == "linux-db")
            .expect("linux-db excluded");
        assert_eq!(db.reason_code, "fact_not_collected");
        assert_eq!(db.condition.as_deref(), Some("installed:postgresql"));

        // 事实在、且满足 → 选中。
        let satisfied = set
            .expand("linux-data", &facts("linux", &["postgresql-14"]))
            .expect("expand");
        assert_eq!(satisfied.works.len(), 2);
        assert!(satisfied.excluded_units.is_empty());

        // 事实在、但不满足 → 报“条件不满足”（与“无法判定”区分开）。
        let unsatisfied = set
            .expand("linux-data", &facts("linux", &["nginx"]))
            .expect("expand");
        let db = unsatisfied
            .excluded_units
            .iter()
            .find(|unit| unit.unit_id == "linux-db")
            .expect("linux-db excluded");
        assert_eq!(db.reason_code, "match_unsatisfied");
    }

    // ── 逐条拒绝规则（手写内容数据的笔误必须在这里被拦住）─────────────────

    fn parse_with(catalog: &str, packs: &str, templates: &str) -> ConfigResult<ContentSet> {
        parse_content(catalog, packs, templates)
    }

    #[test]
    fn accepts_an_active_unit_without_a_rule_ref() {
        // 采原文不需要解析规则：空 `rule_ref` 不再是错误（见 catalog.toml 头部约定）。
        let catalog = CATALOG.replacen("rule_ref = \"agent_uplink\"", "rule_ref = \"\"", 1);
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("active without rule_ref");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "mac-metrics")
            .expect("mac-metrics");
        assert!(unit.collect_ready());
        assert!(!unit.parse_ready(), "解析未就绪只影响归类，不影响能不能采");
    }

    #[test]
    fn rejects_an_active_unit_whose_sources_agentd_cannot_execute() {
        // 反过来：「采集就绪」不能只靠人喊 —— 唯一来源换成**未知导出器 ID** 就拦。
        let catalog = CATALOG.replacen("kind = \"MetricInterval\"", "kind = \"Exporter\"", 1);
        // target 仍是 `15s`：不是已知导出器 ID（见 `EXPORTER_IDS`）。
        let err = parse_with(&catalog, PACKS, TEMPLATES)
            .expect_err("active without an executable source");
        assert!(
            err.to_string().contains("no source agentd can collect"),
            "{err}"
        );
    }

    #[test]
    fn accepts_an_active_unit_backed_by_a_known_exporter() {
        // 已知导出器 ID（契约 `EXPORTER_IDS`）= 可执行：`Exporter` 来源能撑起一个 active 单元。
        let catalog = CATALOG
            .replacen("kind = \"MetricInterval\"", "kind = \"Exporter\"", 1)
            .replacen("target = \"15s\"", "target = \"smartctl\"", 1);
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("known exporter is executable");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "mac-metrics")
            .expect("mac-metrics");
        assert!(unit.collect_ready());
    }

    // ── W1：文件族 glob ──────────────────────────────────────────────

    #[test]
    fn accepts_an_active_unit_backed_by_a_file_family_glob() {
        // W1 起单层 glob 是可执行来源：容器日志的选源就是一条 glob + 排除项。
        let catalog = format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"linux-container-stdout\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             exclude_globs = [\"/var/log/containers/*_kube-system_*.log\"]\n"
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("glob source is executable");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-container-stdout")
            .expect("container unit");
        assert!(unit.collect_ready());
        assert_eq!(
            unit.sources[0].exclude_globs,
            vec!["/var/log/containers/*_kube-system_*.log".to_string()]
        );
        // 文件族不参与探测白名单：白名单只收**显式**路径（探测不到就裁剪的前提不成立）。
        assert!(
            !set.probe_paths()
                .contains(&"/var/log/containers/*.log".to_string())
        );
    }

    #[test]
    fn rejects_recursive_globs_on_an_active_unit() {
        // `**` 没实现：接受它就等于承诺一个采不到的面。
        let catalog = CATALOG.replacen(
            "target = \"/var/log/postgresql.log\"",
            "target = \"/var/log/**/*.log\"",
            1,
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("recursive glob");
        assert!(
            err.to_string().contains("no source agentd can collect"),
            "{err}"
        );
    }

    #[test]
    fn rejects_relative_exclude_globs() {
        // 排除项按**展开后的完整路径**匹配：相对路径的结果取决于进程 cwd。
        let catalog = CATALOG.replacen(
            "target = \"/var/log/postgresql.log\"",
            "target = \"/var/log/postgresql/*.log\"\nexclude_globs = [\"*/archive/*\"]",
            1,
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("relative exclude");
        assert!(
            err.to_string()
                .contains("exclude_globs expects absolute paths"),
            "{err}"
        );
    }

    // ── W2：容器选源的结构化过滤器 ──────────────────────────────

    /// 一条挂在 `/var/log/containers` 下的容器单元（`filters` 由调用方拼）。
    fn container_unit_with(sources: &str) -> String {
        format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"linux-container-stdout\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             {sources}"
        )
    }

    #[test]
    fn loads_container_filters_on_a_container_source() {
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             filters = { namespace_in = [\"prod\"], pod_not_in = [\"debug-pod\"] }\n",
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("filters accepted");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-container-stdout")
            .expect("container unit");
        assert_eq!(
            unit.sources[0].filters.namespace_in,
            vec!["prod".to_string()]
        );
        assert_eq!(
            unit.sources[0].filters.pod_not_in,
            vec!["debug-pod".to_string()]
        );
    }

    #[test]
    fn accepts_name_filters_on_docker_and_directory_shaped_targets() {
        // name 维度不靠 k8s 文件名：纯 Docker 载体与目录形态都必须能过装载。
        // （旧的 `contains("/containers/")` 会把 `…/containers` 这种目录形态错拒；
        //   agentd 的显式目录来源是允许的，两边口径必须一致。）
        for target in [
            "/var/lib/docker/containers/*/*-json.log*",
            "/var/lib/docker/containers",
            "/var/log/containers",
            "/var/log/containers/*.log",
        ] {
            let catalog = container_unit_with(&format!(
                "[[units.sources]]\n\
                 kind = \"FileGlob\"\n\
                 target = \"{target}\"\n\
                 filters = {{ name_in = [\"mysql\"], name_not_in = [\"fluent-bit\"] }}\n"
            ));
            parse_with(&catalog, PACKS, TEMPLATES).unwrap_or_else(|err| panic!("{target}: {err}"));
        }

        // 非容器路径仍然要拒：过滤器写在别处只会“一个都匹配不上”。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/mysql/*.log\"\n\
             filters = { name_in = [\"mysql\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("non-container target");
        assert!(err.to_string().contains("name_in / name_not_in"), "{err}");

        // k8s 维仍限定在 `/var/log/containers` 下（docker 根目录上写 namespace 没有意义）。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/lib/docker/containers/*/*-json.log*\"\n\
             filters = { namespace_in = [\"prod\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("k8s dimension on docker root");
        assert!(err.to_string().contains("filters 只能用在"), "{err}");
    }

    #[test]
    fn rejects_filters_on_a_non_container_source() {
        // 过滤器靠文件名 `<pod>_<ns>_<container>-<id>.log` 求值；写在别的路径上
        // 只会得到“一个都匹配不上”——与其运行时静默采不到，不如装载期拒掉。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/postgresql/*.log\"\n\
             filters = { namespace_in = [\"prod\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("filters off container root");
        assert!(err.to_string().contains("filters 只能用在"), "{err}");
    }

    #[test]
    fn rejects_filters_on_a_non_file_glob_source() {
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"Exporter\"\n\
             target = \"journalctl-kernel\"\n\
             filters = { namespace_in = [\"prod\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("filters on exporter");
        assert!(err.to_string().contains("cannot declare filters"), "{err}");
    }

    #[test]
    fn rejects_filter_values_that_can_never_match() {
        // 过滤器存的是**精确名字**：通配符 / 空白永远对不上。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             filters = { namespace_in = [\"pro*\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("wildcard filter");
        assert!(err.to_string().contains("含通配符"), "{err}");
    }

    #[test]
    fn rejects_malformed_match_conditions() {
        // 装载期必须 fail-closed：写坏的表达式在求值层是**静默**的两种相反后果——
        // 条件整个消失（→ 双采）或单元永不展开（→ 少采）。
        let with_match = |expr: &str| {
            let catalog = format!(
                "{CATALOG}\n\
                 [[units]]\n\
                 unit_id = \"linux-docker-container-stdout\"\n\
                 family = \"DatabaseService\"\n\
                 capability = \"collect_logs\"\n\
                 platform = \"linux\"\n\
                 match = \"{expr}\"\n\
                 rule_ref = \"\"\n\
                 requires_privilege = \"root\"\n\
                 status = \"active\"\n\n\
                 [[units.sources]]\n\
                 kind = \"FileGlob\"\n\
                 target = \"/var/lib/docker/containers/*/*-json.log*\"\n"
            );
            parse_with(&catalog, PACKS, TEMPLATES)
        };

        // 漏冒号：`parse_conditions` 会直接丢掉这个片段 → 空表达式 = 平台基线必采。
        let err = with_match("not_path_exists").expect_err("missing colon");
        assert!(err.to_string().contains("缺少 ':'"), "{err}");

        // 拼错 kind：求值层只会得到 `Unknown`（单元永远展不开），装载期应当报错。
        let err = with_match("not_path_exist:/var/log/containers").expect_err("unknown kind");
        assert!(err.to_string().contains("kind 未知"), "{err}");

        // 漏分号：第二个条件会被并进第一个值，且以 `/` 开头能骗过绝对路径校验。
        let err = with_match(
            "path_exists:/var/lib/docker/containers not_path_exists:/var/log/containers",
        )
        .expect_err("missing semicolon");
        assert!(err.to_string().contains("漏写了 ';'"), "{err}");

        // 只有 kind、没有值。
        let err = with_match("not_path_exists:").expect_err("no value");
        assert!(err.to_string().contains("没有值"), "{err}");

        // 正常组合还是要通过。
        with_match("path_exists:/var/lib/docker/containers; not_path_exists:/var/log/containers")
            .expect("well-formed expression");
    }

    #[test]
    fn validates_not_path_exists_the_same_way_as_path_exists() {
        // 两种条件共用一套要求：绝对路径、至少一个值。
        // 相对路径的探测结果依赖进程 cwd，不能当事实；而“没探过”会被当作无法判定，
        // 于是写错的否条件不会报错、只会让单元永远展不开 —— 装载期拦下来更省事。
        let with_match = |expr: &str| {
            let catalog = format!(
                "{CATALOG}\n\
                 [[units]]\n\
                 unit_id = \"linux-docker-container-stdout\"\n\
                 family = \"DatabaseService\"\n\
                 capability = \"collect_logs\"\n\
                 platform = \"linux\"\n\
                 match = \"{expr}\"\n\
                 rule_ref = \"\"\n\
                 requires_privilege = \"root\"\n\
                 status = \"active\"\n\n\
                 [[units.sources]]\n\
                 kind = \"FileGlob\"\n\
                 target = \"/var/lib/docker/containers/*/*-json.log\"\n"
            );
            parse_with(&catalog, PACKS, TEMPLATES)
        };

        with_match("path_exists:/var/lib/docker/containers;not_path_exists:/var/log/containers")
            .expect("absolute paths are accepted");

        let err = with_match("not_path_exists:var/log/containers").expect_err("relative path");
        assert!(
            err.to_string()
                .contains("not_path_exists expects absolute paths"),
            "{err}"
        );

        let err = with_match("not_path_exists:").expect_err("no path");
        assert!(err.to_string().contains("没有值"), "{err}");
    }

    #[test]
    fn rejects_a_misspelled_filter_key() {
        // `filters` 内部是 `deny_unknown_fields`：拼错的键不能静默变成「不过滤」——
        // 那会让策展人以为只采 prod，实际整个集群都采。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             filters = { namespaces = [\"prod\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("typo in filters");
        // 报错只能看到「目录解析失败」这一层（serde 的 `unknown field` 细节被包装吃掉了）；
        // 关键是**必须拒绝**，不能静默按空过滤器装载。
        assert!(!err.to_string().is_empty(), "{err}");
    }

    #[test]
    fn rejects_a_path_that_merely_shares_the_container_root_prefix() {
        // `/var/log/containers-backup` 不是容器目录：只拿 `starts_with` 判会把它的文件
        // 当成容器日志（结果一个都解析不出名字 → 静默全丢）。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers-backup/*.log\"\n\
             filters = { namespace_in = [\"prod\"] }\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("prefix lookalike");
        assert!(err.to_string().contains("filters 只能用在"), "{err}");
    }

    #[test]
    fn filters_do_not_affect_collect_readiness() {
        // 就绪度只问「agentd 能不能采这条来源」；选哪些 pod 是策展选择，不是执行能力。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             filters = { namespace_in = [\"prod\"] }\n",
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("parses");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-container-stdout")
            .expect("container unit");
        assert!(unit.collect_ready(), "带 filters 的 active 单元仍然可采");
        assert!(
            !set.probe_paths()
                .contains(&"/var/log/containers/*.log".to_string()),
            "文件族不参与探测白名单（同 W1）"
        );
    }

    // ── W4：噪音行丢弃（`drop_if_contains`）────────────────────────

    #[test]
    fn loads_drop_if_contains_on_a_file_source() {
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             drop_if_contains = [\"pam_unix(cron:session)\", \"systemd-logind\"]\n",
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("drop_if_contains accepted");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-container-stdout")
            .expect("container unit");
        assert_eq!(
            unit.sources[0].drop_if_contains,
            vec![
                "pam_unix(cron:session)".to_string(),
                "systemd-logind".to_string()
            ]
        );
    }

    #[test]
    fn rejects_drop_if_contains_on_a_non_file_source() {
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"Exporter\"\n\
             target = \"journalctl-kernel\"\n\
             drop_if_contains = [\"noise\"]\n",
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("drop on exporter");
        assert!(
            err.to_string().contains("cannot declare drop_if_contains"),
            "{err}"
        );
    }

    #[test]
    fn rejects_noise_needles_that_are_not_exact_substrings() {
        // 首尾空白 / 重复都得拒：它们看上去能匹配，实际永远不命中（或只命中一半），
        // 而现场看到的表现是“明明配了却还在采”。
        for values in ["[\" lead\"]", "[\"trail \"]", "[\"dup\", \"dup\"]"] {
            let catalog = container_unit_with(&format!(
                "[[units.sources]]\nkind = \"FileGlob\"\ntarget = \"/var/log/containers/*.log\"\ndrop_if_contains = {values}\n"
            ));
            let err =
                parse_with(&catalog, PACKS, TEMPLATES).expect_err("needle shape must be rejected");
            assert!(err.to_string().contains("drop_if_contains"), "{err}");
        }
    }

    #[test]
    fn drop_if_contains_does_not_affect_collect_readiness() {
        // 丢噪音是读法的一部分，不是新的采集能力 —— 但**旧 agentd 不认识这个字段**，
        // 所以它在 D7 里是单独的能力轴（`drop_if_contains:substring`），
        // 而不是拿来卡 `active`。
        let catalog = container_unit_with(
            "[[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\
             drop_if_contains = [\"noise\"]\n",
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("parses");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-container-stdout")
            .expect("container unit");
        assert!(unit.collect_ready());
    }

    #[test]
    fn rejects_exclude_globs_on_a_non_file_source() {
        // 写在别的 kind 上不是“多一个无害的字段”：要么策展想表达别的意思，要么放错了位置。
        let catalog = CATALOG.replacen(
            "kind = \"MetricInterval\"\ntarget = \"15s\"",
            "kind = \"MetricInterval\"\ntarget = \"15s\"\nexclude_globs = [\"/var/log/x.log\"]",
            1,
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("exclude on metric");
        assert!(
            err.to_string().contains("cannot declare exclude_globs"),
            "{err}"
        );
    }

    #[test]
    fn rejects_an_unknown_family() {
        let catalog = CATALOG.replacen("family = \"HostMetrics\"", "family = \"Nope\"", 1);
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("unknown family");
        assert!(err.to_string().contains("unknown family"), "{err}");
    }

    #[test]
    fn rejects_a_macos_only_family_on_linux() {
        // 把 macOS 单元的面改成只在 Linux 出现的面。
        // （单元级校验先于包级校验，所以包的 families 不必同步改。）
        let catalog = CATALOG.replacen(
            "unit_id = \"mac-metrics\"\nfamily = \"HostMetrics\"",
            "unit_id = \"mac-metrics\"\nfamily = \"DatabaseService\"",
            1,
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("linux-only family on macos");
        assert!(
            err.to_string().contains("does not apply to platform"),
            "{err}"
        );
    }

    #[test]
    fn rejects_an_unknown_source_kind() {
        let catalog = CATALOG.replacen("kind = \"MetricInterval\"", "kind = \"Glob\"", 1);
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("unknown source kind");
        assert!(err.to_string().contains("unknown source kind"), "{err}");
    }

    #[test]
    fn loads_a_sources_read_mode_and_defaults_it_to_single_line() {
        let set = parse_with(CATALOG, PACKS, TEMPLATES).expect("fixture parses");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-db")
            .expect("linux-db");
        // 未声明 → 一行一条。取错默认值会把多行日志粘成一条（无声的内容损坏）。
        assert_eq!(unit.sources[0].multiline, "none");

        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\nmultiline = \"indented\"",
            1,
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("parses");
        let unit = set
            .units()
            .find(|unit| unit.unit_id == "linux-db")
            .expect("linux-db");
        assert_eq!(unit.sources[0].multiline, "indented");
    }

    #[test]
    fn rejects_an_unknown_multiline_mode() {
        let catalog = CATALOG.replacen(
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql.log\"\nmultiline = \"guessed\"",
            1,
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("unknown multiline");
        assert!(err.to_string().contains("unknown multiline"), "{err}");
    }

    #[test]
    fn rejects_a_read_mode_on_a_source_that_is_not_a_file() {
        // 多行归并只对可 tail 的文件有意义。写在指标来源上不是“多一个无害的字段”，
        // 而是错——要么策展想表达别的意思，要么放错了位置。
        let catalog = CATALOG.replacen(
            "kind = \"MetricInterval\"\ntarget = \"15s\"",
            "kind = \"MetricInterval\"\ntarget = \"15s\"\nmultiline = \"indented\"",
            1,
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("multiline on MetricInterval");
        assert!(err.to_string().contains("只对 FileGlob 有意义"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        // 多出来的字段要响：静默忽略会让 `spec_fragment` 这种旧写法被当成“没配置”。
        let catalog = CATALOG.replacen(
            "requires_privilege = \"none\"",
            "requires_privilege = \"none\"\nspec_fragment = \"x\"",
            1,
        );
        assert!(parse_with(&catalog, PACKS, TEMPLATES).is_err());
    }

    #[test]
    fn rejects_a_missing_baseline_pack() {
        let packs = PACKS.replacen(
            "pack_id = \"linux-base\"\nplatform = \"linux\"\nkind = \"Baseline\"",
            "pack_id = \"linux-base\"\nplatform = \"linux\"\nkind = \"Feature\"",
            1,
        );
        let err = parse_with(CATALOG, &packs, TEMPLATES).expect_err("no baseline for linux");
        assert!(err.to_string().contains("Baseline"), "{err}");
    }

    #[test]
    fn rejects_a_pack_family_mismatch() {
        let packs = PACKS.replacen(
            "families = [\"HostMetrics\"]\nunit_refs = [\"linux-metrics\"]",
            "families = [\"MiscSystem\"]\nunit_refs = [\"linux-metrics\"]",
            1,
        );
        let err = parse_with(CATALOG, &packs, TEMPLATES).expect_err("family mismatch");
        assert!(err.to_string().contains("families"), "{err}");
    }

    #[test]
    fn rejects_a_dangling_unit_ref() {
        let packs = PACKS.replacen("unit_refs = [\"mac-metrics\"]", "unit_refs = [\"nope\"]", 1);
        let err = parse_with(CATALOG, &packs, TEMPLATES).expect_err("dangling unit_ref");
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn rejects_a_template_whose_machine_class_platform_disagrees() {
        let templates = TEMPLATES.replacen(
            "template_id = \"linux-data\"\nmachine_class = \"LinuxData\"",
            "template_id = \"linux-data\"\nmachine_class = \"MacDev\"",
            1,
        );
        let err = parse_with(CATALOG, PACKS, &templates).expect_err("class/platform mismatch");
        assert!(err.to_string().contains("belongs to"), "{err}");
    }

    // ── W0：探测白名单与「同一文件只读一次」 ─────────────────────────────

    #[test]
    fn probe_paths_includes_explicit_file_sources() {
        // 派活裁剪要靠探测结果；显式来源不在白名单里，裁剪就永远只能当「没探测过」。
        let content = minimal();
        assert!(
            content
                .probe_paths()
                .contains(&"/var/log/postgresql.log".to_string()),
            "explicit FileGlob target must be probed"
        );
    }

    #[test]
    fn rejects_two_active_units_collecting_the_same_file() {
        // 同一文件两个 active 单元 = agentd 建两个 input、同一批行上送两次。
        let catalog = format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"linux-db-2\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/postgresql.log\"\n"
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("duplicate active path");
        assert!(
            err.to_string().contains("already collected by unit"),
            "{err}"
        );
        assert!(err.to_string().contains("linux-db"), "{err}");
    }

    #[test]
    fn rejects_two_active_units_with_the_same_glob_target() {
        // 两条 active 单元写同一条 glob = agentd 两个 input 读同一批文件，行会重复上送。
        // 重叠的不同 glob（`/var/log/*.log` vs `/var/log/app*.log`）装载期查不出，但**同字串**
        // 的必须拦下。
        let catalog = format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"linux-container-a\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n\n\
             [[units]]\n\
             unit_id = \"linux-container-b\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/containers/*.log\"\n"
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("duplicate glob target");
        assert!(
            err.to_string().contains("already collected by unit"),
            "{err}"
        );
        assert!(err.to_string().contains("linux-container-a"), "{err}");
    }

    #[test]
    fn a_draft_unit_may_share_a_path_with_an_active_unit() {
        // draft 不派活：允许与 active 并列，否则「先策展、后启用」的路被堵死。
        let catalog = format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"linux-db-draft\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"draft\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/postgresql.log\"\n"
        );
        parse_with(&catalog, PACKS, TEMPLATES).expect("draft may share the path");
    }

    #[test]
    fn rejects_a_unit_that_declares_the_same_file_twice() {
        // 同一个单元里写两遍同一路径也是重复采集，错误信息要说清是“同一单元重复声明”。
        let catalog = format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"linux-db-dup\"\n\
             family = \"DatabaseService\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/dup-only.log\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/dup-only.log\"\n"
        );
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("same file twice");
        assert!(err.to_string().contains("declared more than once"), "{err}");
    }

    #[test]
    fn the_same_path_may_be_collected_on_different_platforms() {
        // 同一路径在 macOS / Linux 各采一次不算重复：它们不是同一批机器上的两个 input。
        let catalog = format!(
            "{CATALOG}\n\
             [[units]]\n\
             unit_id = \"mac-shared\"\n\
             family = \"MiscSystem\"\n\
             capability = \"collect_logs\"\n\
             platform = \"macos\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/shared.log\"\n\n\
             [[units]]\n\
             unit_id = \"linux-shared\"\n\
             family = \"MiscSystem\"\n\
             capability = \"collect_logs\"\n\
             platform = \"linux\"\n\
             match = \"\"\n\
             rule_ref = \"\"\n\
             requires_privilege = \"root\"\n\
             status = \"active\"\n\n\
             [[units.sources]]\n\
             kind = \"FileGlob\"\n\
             target = \"/var/log/shared.log\"\n"
        );
        parse_with(&catalog, PACKS, TEMPLATES).expect("different platforms may share a path");
    }

    #[test]
    fn probe_paths_dedupes_a_path_that_is_both_a_condition_and_a_source() {
        // `path_exists` 与来源写同一路径时只探一次（BTreeSet 去重）。
        let catalog = CATALOG.replacen(
            "match = \"installed:postgresql\"",
            "match = \"path_exists:/var/log/postgresql.log\"",
            1,
        );
        let set = parse_with(&catalog, PACKS, TEMPLATES).expect("parses");
        assert_eq!(
            set.probe_paths(),
            vec!["/var/log/postgresql.log".to_string()]
        );
    }

    #[test]
    fn port_conditions_match_exactly_ignoring_the_protocol_prefix() {
        // 端口是数值：`tcp:35432` 不得命中 `5432`。用 contains 时，机器上几十个随机
        // 临时端口几乎必然撞上 4 位 pattern。
        let mut facts = StoredAgentFactSummary {
            listen_ports: vec!["tcp:35432".to_string(), "tcp:8080".to_string()],
            ..StoredAgentFactSummary::default()
        };

        assert_eq!(eval_match("port:5432", &facts), Truth::No);
        assert_eq!(eval_match("port:8080", &facts), Truth::Yes);
        assert_eq!(eval_match("port:8080|8443", &facts), Truth::Yes);

        // 旧 agent 报的裸端口形状也要能判（升级过渡期两边共存）。
        facts.listen_ports = vec!["5432".to_string()];
        assert_eq!(eval_match("port:5432", &facts), Truth::Yes);

        // 空清单 = “没采”，不是“没有”：不能冒充否定。
        facts.listen_ports.clear();
        assert_eq!(eval_match("port:5432", &facts), Truth::Unknown);
    }

    #[test]
    fn port_conditions_separate_not_listening_from_not_collected() {
        let facts = StoredAgentFactSummary {
            listen_ports: vec!["tcp:8080".to_string()],
            ..StoredAgentFactSummary::default()
        };

        // 采集区间完整：没命中就是没监听。
        assert_eq!(eval_match("port:9999", &facts), Truth::No);
        // 临时区间被有意过滤：答「无法判定」，不冒充「没监听」。
        assert_eq!(eval_match("port:40000", &facts), Truth::Unknown);
        // 一组里既有命中、又有没采的区间 → 命中优先。
        assert_eq!(eval_match("port:40000|8080", &facts), Truth::Yes);
    }
}
