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
//!   1. **就绪度两义**：单元的 `status` 是「规则就绪度」，包/模板的 `status` 是「策展成熟度」。
//!      授权闸门是**面就绪度**（该面至少一个 `active` 单元），未就绪的面**不展开**并留痕。
//!   2. **事实缺位 ≠ 条件不满足**：`match` 求值三态，探针没采到时报「无法判定」，不冒充「没装」。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use orion_error::conversion::ToStructError;
use orion_error::prelude::*;
use serde::Deserialize;
use wist_error::{ConfigError, ConfigReason, ConfigResult};

use crate::infra::StoredAgentFactSummary;

/// 平台闭集（与 agentd 上报的 `os` 同源）。
pub const PLATFORMS: &[&str] = &["macos", "linux"];
/// 采集面闭集（与模型 `variant CollectionFamily` 一致）。
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
/// 单元规则就绪度。
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
    pub rule_ref: String,
    pub requires_privilege: String,
    /// `active` = 规则已就绪、能落数据面。授权闸门看它。
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
    pub fn is_ready(&self) -> bool {
        self.status == "active"
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
#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Control", module = "Control.Agent.Content")]
pub struct FamilyReadiness {
    pub family: String,
    pub platform: String,
    /// 该面上 `status = active` 的单元数。
    pub active_units: usize,
    pub total_units: usize,
}

impl FamilyReadiness {
    pub fn is_ready(&self) -> bool {
        self.active_units > 0
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
    // 「规则就绪」不能只靠人喊：`active` 必须带解析规则（rule_ref 非空）。
    if unit.status == "active" && unit.rule_ref.trim().is_empty() {
        return Err(invalid(format!(
            "unit {id}: status = active but rule_ref is empty (规则未就绪的单元不能标 active)"
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
/// 与 [`ContentSet::is_family_ready`] 分工不同：那个回答「规则写好了吗」，
/// 这个回答「这个面在这类机器上存不存在」。派活时要分开报 —— 对一台 Linux 机器说
/// 「TCC 面规则未就绪」是把**不适用**说成了**没写好**，会把人引向错误的下一步。
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

    /// 某平台所有（出现过的）面的就绪度。
    pub fn family_readiness(&self, platform: &str) -> Vec<FamilyReadiness> {
        let mut per_family: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for unit in self.units.values().filter(|unit| unit.platform == platform) {
            let entry = per_family.entry(unit.family.as_str()).or_insert((0, 0));
            entry.1 += 1;
            if unit.is_ready() {
                entry.0 += 1;
            }
        }
        per_family
            .into_iter()
            .map(|(family, (active, total))| FamilyReadiness {
                family: family.to_string(),
                platform: platform.to_string(),
                active_units: active,
                total_units: total,
            })
            .collect()
    }

    /// 面在某平台上是否就绪（至少一个 `active` 单元）。
    pub fn is_family_ready(&self, platform: &str, family: &str) -> bool {
        self.units
            .values()
            .any(|unit| unit.platform == platform && unit.family == family && unit.is_ready())
    }

    /// 按模板把一台机器展开成「一面一份」的常驻工作（**未落库**，纯计算）。
    ///
    /// 规则：
    ///   - 就绪的面才展开成工作；未就绪的面的单元进 `excluded_units(rule_not_ready)`；
    ///   - 就绪面里，`match` 三态过滤：命中 → 选中；不命中 → `match_unsatisfied`；
    ///     无法判定（事实没采到）→ `fact_not_collected`；
    ///   - 选中集为空的面不产生工作（但排除项仍留痕）。
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
                        reason_code: "rule_not_ready".to_string(),
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
    /// `rule_not_ready` | `match_unsatisfied` | `fact_not_collected`。
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
target = "/var/log/postgresql/*"
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
        assert_eq!(set.catalog_version, 1);
        assert_eq!(set.templates().count(), 4);
        assert_eq!(
            set.template("macos-daily")
                .expect("macos-daily")
                .family_scope
                .len(),
            10
        );
        // 就绪度：当前只有 HostMetrics 这一面有 active 单元。
        assert!(set.is_family_ready("macos", "HostMetrics"));
        assert!(!set.is_family_ready("macos", "CrashPanic"));
    }

    #[test]
    fn expands_only_ready_families_and_records_the_rest() {
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
        // 就绪的面按包内行序展开（macos-base 里 SoftwareChange 在 HostMetrics 前）；
        // 其余 8 个面全部 is rule_not_ready 留痕。
        assert_eq!(
            expansion
                .works
                .iter()
                .map(|work| work.family.as_str())
                .collect::<Vec<_>>(),
            vec!["SoftwareChange", "HostMetrics"]
        );
        assert_eq!(
            expansion.works[0].selected_units,
            vec!["mac-software-change"]
        );
        assert_eq!(expansion.works[1].selected_units, vec!["mac-host-metrics"]);
        assert_eq!(expansion.excluded_units.len(), 8);
        assert!(
            expansion
                .excluded_units
                .iter()
                .all(|unit| unit.reason_code == "rule_not_ready")
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
    fn rejects_an_active_unit_without_a_rule_ref() {
        let catalog = CATALOG.replacen("rule_ref = \"agent_uplink\"", "rule_ref = \"\"", 1);
        let err = parse_with(&catalog, PACKS, TEMPLATES).expect_err("active without rule_ref");
        assert!(err.to_string().contains("active"), "{err}");
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
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql/*\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql/*\"\nmultiline = \"indented\"",
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
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql/*\"",
            "kind = \"FileGlob\"\ntarget = \"/var/log/postgresql/*\"\nmultiline = \"guessed\"",
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
