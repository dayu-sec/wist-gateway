//! 采集内容目录：`catalog` / `packs` / `templates` 三份策展数据的装载、校验与「按面展开」。
//!
//! 与 `purpose.rs` / `discovery_policy.rs` 同类：内容值留模型仓的 `jumo/model/content/`，
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
use wist_contracts::work::{EXECUTABLE_SOURCE_KINDS, is_executable_source};
use wist_error::{ConfigError, ConfigReason, ConfigResult};

use crate::infra::StoredAgentFactSummary;

/// 平台闭集（与 agentd 上报的 `os` 同源）。
pub const PLATFORMS: &[&str] = &["macos", "linux"];
/// 采集面闭集（与模型 `families.mju` 的 `variant CollectionFamily` **逐字一致**）。
///
/// 为什么以常量形式放在这里：网关装载采集目录时要**拒掉未知的面**（面名写错不能静默收下），
/// 而运行期不能去读模型仓。两侧的一致性由测试钉住
/// （`the_family_closed_set_matches_the_model`）—— 加面/改名要同时改两处。
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
/// 只在 macOS 出现的面（照 `families.mju` 的分类）。
const MACOS_ONLY_FAMILIES: &[&str] = &["PrivacyTcc", "GatekeeperQuarantine", "DevToolchain"];
/// 只在 Linux 出现的面。
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
/// 来源的读法闭集（与 agentd `MultilineMode` 一致）。
pub const MULTILINE_MODES: &[&str] = &["none", "indented"];
/// 权限闭集。
pub const PRIVILEGES: &[&str] = &["none", "root", "fda"];
/// 单元**采集就绪度**（能不能派下去采原文；与解析规则无关）。
pub const UNIT_STATUSES: &[&str] = &["active", "draft", "deprecated"];
/// 包的性质。
pub const PACK_KINDS: &[&str] = &["Baseline", "Feature"];
/// 机器类别闭集（与模型 `variant MachineClass` 一致）。
pub const MACHINE_CLASSES: &[&str] = &["MacDaily", "MacDev", "LinuxCompute", "LinuxData"];

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
    #[serde(default)]
    units: Vec<UnitRow>,
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
    /// `none`（一行一条）| `indented`（行首缩进是上一条的续行）。
    pub multiline: String,
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
    /// 策展成熟度（人定，与单元规则就绪度无关）。
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

/// 一份已装载、已校验的内容集。
#[derive(Debug, Clone)]
pub struct ContentSet {
    pub catalog_version: i64,
    pub superseded_by: Option<i64>,
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
    let catalog_version = validate_catalog(&catalog)?;
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
                    })
                    .collect(),
            };
            (unit.unit_id.clone(), unit)
        })
        .collect::<BTreeMap<_, _>>();

    let packs = validate_packs(&packs, catalog_version, &units)?;
    let templates = validate_templates(&templates, catalog_version, &packs, &units)?;

    Ok(ContentSet {
        catalog_version,
        superseded_by: catalog.superseded_by,
        units,
        packs,
        templates,
    })
}

fn validate_catalog(catalog: &CatalogFile) -> ConfigResult<i64> {
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
        validate_unit(unit)?;
        if !seen.insert(unit.unit_id.as_str()) {
            return Err(invalid(format!("duplicate unit_id {:?}", unit.unit_id)));
        }
    }
    Ok(catalog.catalog_version)
}

fn validate_unit(unit: &UnitRow) -> ConfigResult<()> {
    let id = unit.unit_id.as_str();
    if id.trim().is_empty() {
        return Err(invalid("empty unit_id"));
    }
    if !FAMILIES.contains(&unit.family.as_str()) {
        return Err(invalid(format!(
            "unit {id}: unknown family {:?}",
            unit.family
        )));
    }
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
    // 面与平台的对应：macOS 侧重的面不该出现在 linux 单元上，反之亦然。
    if MACOS_ONLY_FAMILIES.contains(&unit.family.as_str()) && unit.platform != "macos" {
        return Err(invalid(format!(
            "unit {id}: family {:?} is macOS-only but platform is {:?}",
            unit.family, unit.platform
        )));
    }
    if LINUX_ONLY_FAMILIES.contains(&unit.family.as_str()) && unit.platform != "linux" {
        return Err(invalid(format!(
            "unit {id}: family {:?} is Linux-only but platform is {:?}",
            unit.family, unit.platform
        )));
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
    // kind 要能执行，`FileGlob` 的 target 还要是**显式绝对路径** —— 通配与 `~` 采集端还没实现）。
    // 否则就会出现「网关说可采、agent 拿到后报 unsupported」这种自相矛盾的运行态。
    if unit.status == "active"
        && !unit
            .sources
            .iter()
            .any(|source| is_executable_source(&source.kind, &source.target))
    {
        return Err(invalid(format!(
            "unit {id}: status = active but no source agentd can collect \
             (kind 要去 {EXECUTABLE_SOURCE_KINDS:?}，且 FileGlob 的 target 必须是显式绝对路径：\
              通配与 `~` 采集端尚未实现，见 wist-agentd/docs/design/log-file-input-spec.md §2)"
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
        "LinuxCompute" | "LinuxData" => Some("linux"),
        _ => None,
    }
}

/// 某个采集面是否可能出现在某平台上（照 `families.mju` 的分类）。
///
/// 与 [`ContentSet::is_family_ready`] 分工不同：那个回答「采集要素齐不齐」，
/// 这个回答「这个面在这类机器上存不存在」。派活时要分开报 —— 对一台 Linux 机器说
/// 「TCC 面采集未就绪」是把**不适用**说成了**没准备好**，会把人引向错误的下一步。
pub fn family_applies_to(family: &str, platform: &str) -> bool {
    if !FAMILIES.contains(&family) || !PLATFORMS.contains(&platform) {
        return false;
    }
    if MACOS_ONLY_FAMILIES.contains(&family) {
        return platform == "macos";
    }
    if LINUX_ONLY_FAMILIES.contains(&family) {
        return platform == "linux";
    }
    true
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
    ///   - **采集就绪**的面才展开成工作；未就绪的面（没有 `active` 单元）的单元进
    ///     `excluded_units(collect_not_ready)`；
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
    let haystack: &[String] = match condition.kind.as_str() {
        // 已装包清单：探针没实现时**恒空** → 空表示“没采”，不是“没装”。
        "installed" => &facts.packages,
        // 监听端口。
        "port" => &facts.listen_ports,
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
        let path = Path::new(
            "../../wist-design/jumo/model/static/control/module/agent/content/families.mju",
        );
        if !path.exists() {
            // 未随模型仓部署时跳过（与 `reads_the_checked_in_content_set` 同一取舍）。
            return;
        }
        let text = std::fs::read_to_string(path).expect("read families.mju");
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
        let dir = Path::new("../../wist-design/jumo/model/content");
        if !dir.exists() {
            return;
        }
        let set = load_content(
            &dir.join("catalog.toml"),
            &dir.join("packs.toml"),
            &dir.join("templates.toml"),
        )
        .expect("load checked-in content");
        // 目录版本要随内容一起抬（见 catalog.toml 头部约定）：旧工作锁在它展开时那一版上。
        assert_eq!(set.catalog_version, 2);
        assert_eq!(set.templates().count(), 4);
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
    }

    #[test]
    fn expands_the_collect_ready_families_and_records_the_rest() {
        let dir = Path::new("../../wist-design/jumo/model/content");
        if !dir.exists() {
            return;
        }
        let set = load_content(
            &dir.join("catalog.toml"),
            &dir.join("packs.toml"),
            &dir.join("templates.toml"),
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
        // 反过来：「采集就绪」不能只靠人喊 —— 唯一来源换成 Exporter（agentd 还没实现）就拦。
        let catalog = CATALOG.replacen("kind = \"MetricInterval\"", "kind = \"Exporter\"", 1);
        let err = parse_with(&catalog, PACKS, TEMPLATES)
            .expect_err("active without an executable source");
        assert!(
            err.to_string().contains("no source agentd can collect"),
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
        assert!(err.to_string().contains("Linux-only"), "{err}");
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
}
