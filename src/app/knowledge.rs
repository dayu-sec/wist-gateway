//! 知识库内容的装载与持有（设计：`docs/design/knowledge-content-management.md`）。
//!
//! 「知识库内容」= 采集目录三件套（catalog / packs / templates）+ 用途规则表 + 发现方向策略表。
//! 它们**不是**网关卡器里的一段配置，而是可以独立发版、经管理面录入、并**运行时切换**的策展数据。
//!
//! 本模块负责三件事：
//!   1. 把一份内容（三个块）装成 [`LoadedKnowledge`]，供 [`crate::api::ApiState`] 换进换出；
//!   2. 决定**从哪来**：管理面登记的生效包（`<state>/knowledge/<package_id>/`）优先；
//!      还没有生效包时，过渡期回落配置文件里的 `*_file`（设计 §13：入口落地后删掉这条）；
//!   3. 装载失败的语义（设计 §8.5）：**生效包损坏 = 拒绝启动**；从未录入 = 正常启动、空载。
//!
//! 为什么值得热加载（设计 §8.1 选 B）：归因靠三个锚 —— 本模块的 `generation`、
//! `standing_work.catalog_version`、`agent_purpose_suggestion.rule_set_id + purpose_version`。
//! 三点齐了，"这条结论是哪一版内容算出来的"才答得上来。

use std::{fmt, path::Path, sync::Arc};

use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;

use crate::app::content::ContentSet;
use crate::app::purpose::PurposeRuleTable;
use crate::infra::{AdminConfig, Store, StoredKnowledgePackage};

/// 包内五份数据的文件名（与 `wist-knowledge` 制品一致）。
///
/// **五份齐全**是 M1 的契约（设计 §5.1）：缺任何一份都视为坏包，
/// 而不是"缺的那块不装载"—— 半装载的网关比空载更难排查（三个块描述的正是同一批策展内容）。
pub const PACKAGE_FILES: [&str; 5] = [
    "catalog.toml",
    "packs.toml",
    "templates.toml",
    "purpose-rules.toml",
    "aspect-policies.toml",
];

/// 当前装载着的知识库内容。
///
/// 三个块**必须同生同换**：一次切换要么三块都是新版的，要么都不换 ——
/// 半新半旧的视图（模板是新的、规则是旧的）会让"这条建议按哪版算的"又变得说不清。
#[derive(Debug)]
pub struct LoadedKnowledge {
    pub source: KnowledgeSource,
    /// 世代号：每次激活 +1（`knowledge_active.generation`）。未走管理面时为 0。
    pub generation: i64,
    pub content: Option<Arc<ContentSet>>,
    pub purpose_rules: Option<Arc<PurposeRuleTable>>,
    pub discovery_policies: Option<Arc<DiscoveryAspectPolicySet>>,
}

/// 这份内容从哪来 —— 决定了"空载"该怎么向人解释（设计 §8.7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnowledgeSource {
    /// 未配置：网关空载（不产"系统类型"建议、不产用途建议、发现策略用 agentd 内建值）。
    /// **不是错误**，但必须在管理面看得见。
    None,
    /// 过渡期：仍从配置文件里的 `[content]` / `[purpose]` / `[discovery]` 装载。
    ConfigFiles,
    /// 管理面登记的生效包。
    Package { package_id: String },
}

impl Default for LoadedKnowledge {
    fn default() -> Self {
        Self::none()
    }
}

impl LoadedKnowledge {
    /// 空载（从未配置）。
    pub fn none() -> Self {
        Self {
            source: KnowledgeSource::None,
            generation: 0,
            content: None,
            purpose_rules: None,
            discovery_policies: None,
        }
    }

    /// 过渡期路径：从配置文件里的三个 `*_file` 装载。
    ///
    /// 与旧行为一致（`AdminConfig::validate` 已经校验过一次，走到这里再失败说明启动后文件
    /// 被改坏）：记一条警告并当作"未装载"，而不是把网关整个拒了。
    /// 管理面入口落地后这条路随 `[content]` / `[purpose]` / `[discovery]` 的 `*_file` 一起删。
    pub fn from_config(config: &AdminConfig) -> Self {
        let content = match (
            config.content_catalog_file.as_deref(),
            config.content_packs_file.as_deref(),
            config.content_templates_file.as_deref(),
        ) {
            (Some(catalog), Some(packs), Some(templates)) => {
                match crate::app::content::load_content(catalog, packs, templates) {
                    Ok(set) => Some(Arc::new(set)),
                    Err(err) => {
                        eprintln!("warning: failed to load collection content: {err}");
                        None
                    }
                }
            }
            _ => None,
        };
        let purpose_rules = match config.purpose_rules_file.as_deref() {
            Some(path) => match crate::app::purpose::load_rule_table(path) {
                Ok(table) => Some(Arc::new(table)),
                Err(err) => {
                    eprintln!(
                        "warning: failed to load purpose rule table {}: {err}",
                        path.display()
                    );
                    None
                }
            },
            None => None,
        };
        let discovery_policies = match config.discovery_policies_file.as_deref() {
            Some(path) => match crate::app::discovery_policy::load_policy_table(path) {
                Ok(set) => Some(Arc::new(set)),
                Err(err) => {
                    eprintln!(
                        "warning: failed to load discovery aspect policy table {}: {err}",
                        path.display()
                    );
                    None
                }
            },
            None => None,
        };
        let configured =
            content.is_some() || purpose_rules.is_some() || discovery_policies.is_some();
        Self {
            source: if configured {
                KnowledgeSource::ConfigFiles
            } else {
                KnowledgeSource::None
            },
            generation: 0,
            content,
            purpose_rules,
            discovery_policies,
        }
    }

    /// 按**管理面登记的生效包**装载（启动期调用，见设计 §8.5）。
    ///
    /// * 没有生效指针 → 回落 [`Self::from_config`]（过渡期），即今天的空载/配置态不变；
    /// * 有生效指针 → 从 `<state>/knowledge/<package_id>/` 装载五份数据，
    ///   **任一失败即返回 `Err`**，由调用方拒绝启动（静默空载会让平台悄悄停掉建议与派活）。
    pub async fn from_store(
        config: &AdminConfig,
        store: &Arc<dyn Store>,
    ) -> Result<Self, KnowledgeLoadError> {
        let active = store
            .knowledge_active()
            .await
            .map_err(|err| KnowledgeLoadError::new(format!("读取知识库生效指针失败：{err}")))?;
        let Some(active) = active else {
            return Ok(Self::from_config(config));
        };
        let dir = config.knowledge_package_dir(&active.package_id);
        let mut loaded = Self::load_package_dir(&dir)?;
        loaded.source = KnowledgeSource::Package {
            package_id: active.package_id,
        };
        loaded.generation = active.generation;
        Ok(loaded)
    }

    /// 从一个包目录装载五份数据；缺文件、内容非法都以 `Err` 报出（附目录路径）。
    fn load_package_dir(dir: &Path) -> Result<Self, KnowledgeLoadError> {
        let at = |name: &str| dir.join(name);
        let content = crate::app::content::load_content(
            &at("catalog.toml"),
            &at("packs.toml"),
            &at("templates.toml"),
        )
        .map_err(|err| KnowledgeLoadError::at(dir, format!("采集目录三件套：{err}")))?;
        let purpose_rules = crate::app::purpose::load_rule_table(&at("purpose-rules.toml"))
            .map_err(|err| KnowledgeLoadError::at(dir, format!("用途规则表：{err}")))?;
        let discovery_policies =
            crate::app::discovery_policy::load_policy_table(&at("aspect-policies.toml"))
                .map_err(|err| KnowledgeLoadError::at(dir, format!("发现方向策略表：{err}")))?;
        Ok(Self {
            source: KnowledgeSource::None,
            generation: 0,
            content: Some(Arc::new(content)),
            purpose_rules: Some(Arc::new(purpose_rules)),
            discovery_policies: Some(Arc::new(discovery_policies)),
        })
    }
}

/// 生效知识包装载失败：**这个错误会让网关拒绝启动**（设计 §8.5），所以消息必须能直接指导处置。
#[derive(Debug)]
pub struct KnowledgeLoadError(String);

impl KnowledgeLoadError {
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }

    fn at(dir: &Path, detail: impl fmt::Display) -> Self {
        Self(format!(
            "生效知识包不可用（{}）：{detail}\n  \
             处置：修好这份副本，或用管理面切到另一个包；\n  \
             在此之前网关不会启动 —— 带着空内容起会让平台悄悄停掉建议与派活。",
            dir.display()
        ))
    }
}

impl fmt::Display for KnowledgeLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KnowledgeLoadError {}

// ─────────────────────────────────────────────────────────────────────────────
// 录入（设计 §5.4 的校验链）与激活前装载
// ─────────────────────────────────────────────────────────────────────────────

/// 制品名：包内 `manifest.json` 必须自报这个名，否则说明"传错了包"。
pub const PACKAGE_NAME: &str = "wist-knowledge";

/// 内容寻址 id：`kbp-<sha256 前 16 位>`（裸 hex）。
///
/// 与安装包的 `pkg-<…>` 同口径：前 16 位（64 bit）足够区分一台网关里录入过的包，
/// 同时保持目录名短、可读。
///
/// 摘要算的是**来源制品（tarball）的字节**，不是解开后的目录 —— 这样它与发布侧
/// `wist-knowledge-<版本>.tar.gz.sha256` 是同一个数，运维拿它核对不会两边对不上；
/// 代价是同一份内容重打包会得到不同的 id（压缩不可复现），但那本就不是"同一个制品"。
pub fn package_id_for_sha256(sha256_hex: &str) -> String {
    let prefix: String = sha256_hex.chars().take(16).collect();
    format!("kbp-{prefix}")
}

/// 录入失败的原因。分类是为了让管理面能给出**可操作**的错误码（设计 §7）。
#[derive(Debug)]
pub enum KnowledgeRecordError {
    /// 来源写法不合法（不是 https URL、也不是绝对路径）。
    SourceInvalid(String),
    /// 来源拿不到（文件不存在 / HTTP 失败 / 超限）。
    SourceUnavailable(String),
    /// 期望摘要与实际不符。
    DigestMismatch(String),
    /// 包自报的 `manifest.json` 与包内实际内容对不上。
    ManifestInconsistent(String),
    /// 内容不合法（真实装载器校验不过）。
    ContentInvalid(String),
    /// 配了验签公钥，但签名缺失 / 验不过 / 格式错。
    SignatureInvalid(String),
    /// 落库失败。
    Store(String),
}

impl KnowledgeRecordError {
    /// 管理面错误码（设计 §7 的 `code`）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::SourceInvalid(_) => "package_source_invalid",
            Self::SourceUnavailable(_) => "package_source_unavailable",
            Self::DigestMismatch(_) => "package_sha256_mismatch",
            Self::ManifestInconsistent(_) => "package_manifest_inconsistent",
            Self::ContentInvalid(_) => "package_content_invalid",
            Self::SignatureInvalid(_) => "package_signature_invalid",
            Self::Store(_) => "package_store_failed",
        }
    }
}

impl fmt::Display for KnowledgeRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceInvalid(message)
            | Self::SourceUnavailable(message)
            | Self::DigestMismatch(message)
            | Self::ManifestInconsistent(message)
            | Self::ContentInvalid(message)
            | Self::SignatureInvalid(message)
            | Self::Store(message) => f.write_str(message),
        }
    }
}

/// 一次成功录入的产物。
#[derive(Debug)]
pub struct RecordedKnowledge {
    pub package_id: String,
    /// 来源制品字节的摘要（裸 hex），与发布侧 `.sha256` 同一个数。
    pub sha256: String,
    /// 网关自己存的那份**目录**。
    pub cached_path: std::path::PathBuf,
    /// 已校验通过的那一份（激活时直接换它，不必重装）。
    pub loaded: LoadedKnowledge,
}

/// 包内 `manifest.json`（打包侧 `scripts/package.sh` 产出）。
///
/// 只取这里用得上的字段：`files` 用来**逐条核对**（不信任何单一摘要），
/// `content_versions` 用来与装载结果**交叉核对**（手改 TOML 忘了 bump 版本会在这里露出来）。
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct PackageManifest {
    name: String,
    version: String,
    content_versions: serde_json::Map<String, serde_json::Value>,
    files: std::collections::BTreeMap<String, String>,
}

/// 校验链（设计 §5.4）：拉字节 → 摘要 → 解到**临时目录** → 逐条核对 → manifest 自洽
/// → 真实装载器校验 → 原子换入。
///
/// M1 不做签名与 `parser_abi` 强制（设计 §9/§10 排在 M2）。
pub async fn record_package(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    source: &str,
    expected_sha256: Option<&str>,
    created_by: &str,
    created_at: &str,
) -> Result<RecordedKnowledge, KnowledgeRecordError> {
    let source = source.trim();
    if source.is_empty() {
        return Err(KnowledgeRecordError::SourceInvalid(
            "来源不能为空：给 https:// 链接或容器内绝对路径".to_string(),
        ));
    }
    if !source.starts_with("https://") && !source.starts_with('/') {
        return Err(KnowledgeRecordError::SourceInvalid(format!(
            "来源必须是 https:// 链接或**容器内**绝对路径（当前：{source}）\
             —— 网关跑在容器里，读不到宿主路径"
        )));
    }
    let bytes = read_source(source).await?;
    let sha256 = crate::infra::bytes_sha256_hex(&bytes);
    if let Some(expected) = expected_sha256.map(str::trim).filter(|v| !v.is_empty()) {
        let expected_hex = expected
            .strip_prefix("sha256:")
            .unwrap_or(expected)
            .to_ascii_lowercase();
        if expected_hex != sha256 {
            return Err(KnowledgeRecordError::DigestMismatch(format!(
                "知识库包 sha256 不一致：期望 {expected_hex}，实际 {sha256}"
            )));
        }
    }
    let package_id = package_id_for_sha256(&sha256);

    // 验签（设计 §9）：配了公钥就**必须**过。签名放在 `<来源>.sig`（发布侧同名 + `.sig`）。
    // 网关只拿公钥 —— 私钥在发布侧（wist-knowledge 的 CI），网关永远拿不到也不应该拿到。
    let signed_by = match config.knowledge_signing_public_key.as_deref() {
        Some(public_key) => {
            let signature = read_signature(source).await?;
            // 签的是**摘要的十六进制文本**：与 `*.sha256` 里那串是同一段字节，
            // 运维拿 openssl 能手工重验；签裸 tarball 反而要先生成摘要。
            if !crate::infra::verify_ed25519(public_key, sha256.as_bytes(), &signature) {
                return Err(KnowledgeRecordError::SignatureInvalid(format!(
                    "签名验不过：{source}.sig 与 {source} 的 sha256（{sha256}）对不上 —— \
                     包被动过，或签名不是这套发布私钥签的"
                )));
            }
            crate::infra::public_key_fingerprint(public_key)
        }
        // 未配公钥 = 不验签，只记摘要（M1 行为）。
        None => String::new(),
    };

    // 解到临时目录：校验没过之前，半成品不进 `<state>/knowledge/`。
    let staging = config
        .knowledge_dir()
        .join(format!(".staging-{package_id}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|err| {
        KnowledgeRecordError::SourceUnavailable(format!(
            "创建临时目录失败 {}：{err}",
            staging.display()
        ))
    })?;
    let unpacked = unpack_into(&bytes, &staging);
    let result = match unpacked {
        Ok(()) => validate_package(&staging, &package_id),
        Err(err) => Err(err),
    };
    let validated = match result {
        Ok(validated) => validated,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(err);
        }
    };

    // 原子换入 `<state>/knowledge/<package_id>/`。
    // 目标已存在就**换掉**（可能是上次录入留下的、也可能被人改过）—— 重复录入因此也是修复。
    let cached_path = config.knowledge_package_dir(&package_id);
    if cached_path.exists() {
        std::fs::remove_dir_all(&cached_path).map_err(|err| {
            KnowledgeRecordError::SourceUnavailable(format!(
                "替换旧副本失败 {}：{err}",
                cached_path.display()
            ))
        })?;
    }
    if let Some(parent) = cached_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            KnowledgeRecordError::SourceUnavailable(format!(
                "创建知识库目录失败 {}：{err}",
                parent.display()
            ))
        })?;
    }
    std::fs::rename(&validated.package_root, &cached_path).map_err(|err| {
        KnowledgeRecordError::SourceUnavailable(format!(
            "落盘失败 {} → {}：{err}",
            validated.package_root.display(),
            cached_path.display()
        ))
    })?;
    let _ = std::fs::remove_dir_all(&staging);

    let row = StoredKnowledgePackage {
        package_id: package_id.clone(),
        source: source.to_string(),
        package_sha256: format!("sha256:{sha256}"),
        version: validated.manifest.version.clone(),
        catalog_version: validated.catalog_version,
        template_version: validated.template_version,
        policy_version: validated.policy_version,
        purpose_version: validated.purpose_version,
        parser_abi: 1,
        signed_by,
        cached_path: cached_path.to_string_lossy().to_string(),
        created_by: created_by.to_string(),
        created_at: created_at.to_string(),
    };
    store
        .upsert_knowledge_package(&row)
        .await
        .map_err(|err| KnowledgeRecordError::Store(format!("落库失败：{err}")))?;

    // `load_package_dir` 装出来的这一份 `source` 还是默认的 `None`，而 `activate: true` 的
    // 一次性路径会把 `loaded` **直接**交给 `activate_loaded`，它只认 `KnowledgeSource::Package`。
    // 在这里补上标签 —— 与 `load_recorded_package` 同一口径（两条激活路径的输入必须同形）；
    // 少了这一步，那条路径必然以 HTTP 500「内部错误：切的是未登记的包」收场。
    let mut loaded = validated.loaded;
    loaded.source = KnowledgeSource::Package {
        package_id: package_id.clone(),
    };

    Ok(RecordedKnowledge {
        package_id,
        sha256,
        cached_path,
        loaded,
    })
}

/// 激活前的装载：直接读**已录副本**并重新校验（设计 §8.6“先验后切”）。
///
/// 为什么要重验而不是直接信任入库时的那次：副本在盘上，可能被改过或被删过；
/// 拿一个早已损坏的目录去切，等于把网关推到“半可用”。
pub fn load_recorded_package(
    config: &AdminConfig,
    package_id: &str,
) -> Result<LoadedKnowledge, KnowledgeRecordError> {
    let dir = config.knowledge_package_dir(package_id);
    let mut loaded = LoadedKnowledge::load_package_dir(&dir)
        .map_err(|err| KnowledgeRecordError::ContentInvalid(err.to_string()))?;
    loaded.source = KnowledgeSource::Package {
        package_id: package_id.to_string(),
    };
    Ok(loaded)
}

struct ValidatedPackage {
    package_root: std::path::PathBuf,
    manifest: PackageManifest,
    loaded: LoadedKnowledge,
    catalog_version: Option<i64>,
    template_version: Option<i64>,
    policy_version: Option<i64>,
    purpose_version: Option<i64>,
}

/// 校验一个已解开的包目录（包根 = 含 `manifest.json` 的那一层）。
fn validate_package(
    staging: &Path,
    package_id: &str,
) -> Result<ValidatedPackage, KnowledgeRecordError> {
    let package_root = locate_package_root(staging).ok_or_else(|| {
        KnowledgeRecordError::ManifestInconsistent(format!(
            "包内找不到 manifest.json（顶层一层目录应为 `wist-knowledge-<版本>/`）：{}",
            staging.display()
        ))
    })?;
    let manifest_text =
        std::fs::read_to_string(package_root.join("manifest.json")).map_err(|err| {
            KnowledgeRecordError::ManifestInconsistent(format!("读 manifest.json 失败：{err}"))
        })?;
    let manifest: PackageManifest = serde_json::from_str(&manifest_text).map_err(|err| {
        KnowledgeRecordError::ManifestInconsistent(format!("manifest.json 解析失败：{err}"))
    })?;
    if manifest.name != PACKAGE_NAME {
        return Err(KnowledgeRecordError::ManifestInconsistent(format!(
            "包自报的名字是 {:?}，不是 {PACKAGE_NAME:?} —— 传错包了？",
            manifest.name
        )));
    }
    if manifest.files.is_empty() {
        return Err(KnowledgeRecordError::ManifestInconsistent(
            "manifest.json 的 files 为空：它必须逐条给出包内文件的 sha256".to_string(),
        ));
    }
    // 逐条核对：**不信任任何单一摘要** —— 目录级的摘要说不出“哪个文件被换了”。
    for (name, expected) in &manifest.files {
        let path = package_root.join(name);
        let bytes = std::fs::read(&path).map_err(|err| {
            KnowledgeRecordError::ManifestInconsistent(format!(
                "manifest 列了 {name}，但读不到：{err}"
            ))
        })?;
        let actual = crate::infra::bytes_sha256_hex(&bytes);
        let expected = expected
            .strip_prefix("sha256:")
            .unwrap_or(expected)
            .to_ascii_lowercase();
        if actual != expected {
            return Err(KnowledgeRecordError::ManifestInconsistent(format!(
                "{name} 与 manifest 记的 sha256 不一致（期望 {expected}，实际 {actual}）"
            )));
        }
    }
    // 真实装载器校验：**用什么装载就用什么校验**（同一份代码，不走两套）。
    let loaded = LoadedKnowledge::load_package_dir(&package_root)
        .map_err(|err| KnowledgeRecordError::ContentInvalid(err.to_string()))?;

    // manifest 自洽：声明的版本必须与文件里实际声明的一致。
    let declared_catalog = manifest_version(&manifest, "catalog_version");
    let declared_purpose = manifest_version(&manifest, "purpose_version");
    let declared_policy = manifest_version(&manifest, "policy_version");
    let actual_catalog = loaded.content.as_ref().map(|set| set.catalog_version);
    let actual_purpose = loaded
        .purpose_rules
        .as_ref()
        .map(|table| i64::from(table.purpose_version));
    let actual_policy = loaded
        .discovery_policies
        .as_ref()
        .map(|set| set.policy_version);
    for (label, declared, actual) in [
        ("catalog_version", declared_catalog, actual_catalog),
        ("purpose_version", declared_purpose, actual_purpose),
        ("policy_version", declared_policy, actual_policy),
    ] {
        if let (Some(declared), Some(actual)) = (declared, actual)
            && declared != actual
        {
            return Err(KnowledgeRecordError::ManifestInconsistent(format!(
                "manifest 声明的 {label} 是 {declared}，文件里实际是 {actual} \
                 —— 打包后改过内容？重打一版（{package_id}）"
            )));
        }
    }
    let template_version = manifest_template_version(&manifest);
    Ok(ValidatedPackage {
        package_root,
        manifest,
        loaded,
        catalog_version: actual_catalog.or(declared_catalog),
        template_version,
        policy_version: actual_policy.or(declared_policy),
        purpose_version: actual_purpose.or(declared_purpose),
    })
}

/// 包根：`manifest.json` 所在的那一层（顶层若套了一层目录就进去）。
fn locate_package_root(staging: &Path) -> Option<std::path::PathBuf> {
    if staging.join("manifest.json").is_file() {
        return Some(staging.to_path_buf());
    }
    let mut entries = std::fs::read_dir(staging).ok()?;
    let children: Vec<_> = entries.by_ref().filter_map(Result::ok).collect();
    if children.len() != 1 {
        return None;
    }
    let child = children.into_iter().next()?.path();
    child.join("manifest.json").is_file().then_some(child)
}

/// 解开 tar.gz 到 `staging`。
///
/// 只收 tar.gz（与发布侧制品一致）：目录来源不做特例 —— "什么算同一份内容" 的判据
/// 会因此分叉（目录没有天然摘要），而摘要正是内容寻址的基础。
fn unpack_into(bytes: &[u8], staging: &Path) -> Result<(), KnowledgeRecordError> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(staging).map_err(|err| {
        KnowledgeRecordError::ManifestInconsistent(format!("解包失败（期望 tar.gz 制品）：{err}"))
    })
}

fn manifest_version(manifest: &PackageManifest, key: &str) -> Option<i64> {
    match manifest.content_versions.get(key) {
        Some(serde_json::Value::Number(number)) => number.as_i64(),
        _ => None,
    }
}

/// `template_version` 在包内是**一份名列各模板**的数组，取唯一值；不唯一就留空
/// （宁可空着，也不要随便挑一个冒充"包版本"）。
fn manifest_template_version(manifest: &PackageManifest) -> Option<i64> {
    match manifest.content_versions.get("template_version") {
        Some(serde_json::Value::Number(number)) => number.as_i64(),
        Some(serde_json::Value::Array(values)) => {
            let mut numbers = values.iter().filter_map(serde_json::Value::as_i64);
            let first = numbers.next()?;
            numbers.all(|value| value == first).then_some(first)
        }
        _ => None,
    }
}

/// 读 `<来源>.sig` 并解 base64。
///
/// 为什么签名文件跟着来源名走：发布侧产物就是 `wist-knowledge-<版本>.tar.gz` + `.sha256` + `.sig`，
/// 三者同名不同后缀。离线投放时一起拷进 `packages/`，不用在管理面多填一个字段。
async fn read_signature(source: &str) -> Result<Vec<u8>, KnowledgeRecordError> {
    use base64::Engine as _;

    let path = format!("{source}.sig");
    let bytes = read_source(&path).await.map_err(|err| match err {
        // 配了公钥就必须有签名：这里把"来源拿不到"重述成"签名缺失"，
        // 否则运维看到的是 `读不到来源 …tar.gz.sig`，容易误以为是包本身坏了。
        KnowledgeRecordError::SourceUnavailable(message) => KnowledgeRecordError::SignatureInvalid(
            format!("{message}（配了验签公钥，就必须提供 `<来源>.sig`）"),
        ),
        other => other,
    })?;
    let text = String::from_utf8(bytes)
        .map_err(|err| KnowledgeRecordError::SignatureInvalid(format!("{path} 不是文本：{err}")))?;
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|err| {
            KnowledgeRecordError::SignatureInvalid(format!("{path} 不是合法 base64：{err}"))
        })
}

/// 读来源字节：`https://` 走 HTTP，`/absolute/path` 读本机文件（容器内路径）。
async fn read_source(source: &str) -> Result<Vec<u8>, KnowledgeRecordError> {
    if source.starts_with('/') {
        let path = Path::new(source);
        let metadata = std::fs::metadata(path).map_err(|err| {
            KnowledgeRecordError::SourceUnavailable(format!("读不到来源 {source}：{err}"))
        })?;
        if metadata.is_dir() {
            return Err(KnowledgeRecordError::SourceInvalid(format!(
                "来源是目录：知识库包必须是 **tar.gz 制品**（{source}）"
            )));
        }
        if metadata.len() > MAX_PACKAGE_BYTES {
            return Err(KnowledgeRecordError::SourceUnavailable(format!(
                "来源 {} 有 {} 字节，超过上限 {MAX_PACKAGE_BYTES}",
                source,
                metadata.len()
            )));
        }
        return std::fs::read(path).map_err(|err| {
            KnowledgeRecordError::SourceUnavailable(format!("读不到来源 {source}：{err}"))
        });
    }
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|err| {
            KnowledgeRecordError::SourceUnavailable(format!("构建 http 客户端失败：{err}"))
        })?;
    let response = client.get(source).send().await.map_err(|err| {
        KnowledgeRecordError::SourceUnavailable(format!("拉取 {source} 失败：{err}"))
    })?;
    if !response.status().is_success() {
        return Err(KnowledgeRecordError::SourceUnavailable(format!(
            "来源 {source} 返回 HTTP {}",
            response.status()
        )));
    }
    if let Some(len) = response.content_length()
        && len > MAX_PACKAGE_BYTES
    {
        return Err(KnowledgeRecordError::SourceUnavailable(format!(
            "来源 {source} 有 {len} 字节，超过上限 {MAX_PACKAGE_BYTES}"
        )));
    }
    let bytes = response.bytes().await.map_err(|err| {
        KnowledgeRecordError::SourceUnavailable(format!("读 {source} 正文失败：{err}"))
    })?;
    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(KnowledgeRecordError::SourceUnavailable(format!(
            "来源 {source} 有 {} 字节，超过上限 {MAX_PACKAGE_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

/// 拉取超时：内容包不大（几 KB～几 MB），但不能无限等。
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// 包大小上限：防止误填地址把任意大文件灌进网关磁盘。
const MAX_PACKAGE_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 进程内自增，保证并行跑的用例**目录不撞**。
    ///
    /// 不用时间戳：`SystemTime::now()` 的精度不足以保证同一 tick 内两次调用不同值，
    /// 而三条用例并行跑时撞了目录就会互相覆盖对方的副本（观察到过一次这种假失败）。
    static PACKAGE_SEQ: AtomicU64 = AtomicU64::new(0);

    /// 把 `wist-knowledge` 仓里的五份**真实**数据拷进一个临时包目录。
    ///
    /// 用真数据而不是内联夹具：这里要验的正是"策展数据能被网关装载器吃下"，
    /// 内联夹具只验得动测试自己编的那份。
    fn stage_real_package() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-knowledge-pkg-{}-{}",
            std::process::id(),
            PACKAGE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create package dir");
        for name in PACKAGE_FILES {
            fs::copy(crate::test_support::knowledge_file(name), dir.join(name))
                .unwrap_or_else(|err| panic!("copy {name}: {err}"));
        }
        dir
    }

    #[test]
    fn loads_a_complete_package() {
        let dir = stage_real_package();
        let loaded = LoadedKnowledge::load_package_dir(&dir).expect("load package");
        assert_eq!(
            loaded.content.as_deref().map(|set| set.catalog_version),
            Some(2)
        );
        assert_eq!(
            loaded
                .purpose_rules
                .as_deref()
                .map(|table| table.purpose_version),
            Some(1)
        );
        assert!(loaded.discovery_policies.is_some());
        // 这份还只是"装好了"：来源与世代由 `from_store` 在登记之后填上。
        assert_eq!(loaded.source, KnowledgeSource::None);
        assert_eq!(loaded.generation, 0);
    }

    #[test]
    fn a_missing_file_makes_the_package_unusable() {
        let dir = stage_real_package();
        fs::remove_file(dir.join("templates.toml")).expect("remove templates");
        let err = LoadedKnowledge::load_package_dir(&dir).expect_err("must refuse");
        let text = err.to_string();
        // 拒启的消息必须能直接指导处置：说清是哪一份包、哪个目录。
        assert!(text.contains("生效知识包不可用"), "{text}");
        assert!(text.contains(&dir.display().to_string()), "{text}");
    }

    #[test]
    fn a_corrupted_file_makes_the_package_unusable() {
        let dir = stage_real_package();
        fs::write(dir.join("aspect-policies.toml"), "policy_version = \"x\"\n")
            .expect("corrupt policies");
        let err = LoadedKnowledge::load_package_dir(&dir).expect_err("must refuse");
        assert!(err.to_string().contains("发现方向策略表"), "{err}");
    }

    // ── 录入（校验链）───────────────────────────────────────────────────────

    /// 与 `test_support::knowledge_package_tarball` 同一件事的本地别名（读起来短一点）。
    fn build_package_tarball(root: &Path, corrupt_after_manifest: bool) -> std::path::PathBuf {
        crate::test_support::knowledge_package_tarball(root, corrupt_after_manifest)
    }

    /// 制品里那层目录名里的版本（与 `test_support` 造制品时用的后缀一致）。
    const PACKAGE_NAME_SUFFIX: &str = "9.9.9-test";

    async fn record(
        store: &Arc<dyn Store>,
        config: &AdminConfig,
        source: &str,
    ) -> Result<RecordedKnowledge, KnowledgeRecordError> {
        record_package(config, store, source, None, "admin", "2026-09-30T00:00:00Z").await
    }

    #[tokio::test]
    async fn records_a_package_from_a_local_tarball() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (config, root) = test_config();
        let tarball = build_package_tarball(&root, false);

        let recorded = record(&store, &config, tarball.to_str().expect("path"))
            .await
            .expect("record");
        // 内容寻址：id 就是来源制品摘要的前 16 位。
        assert!(recorded.package_id.starts_with("kbp-"));
        assert_eq!(recorded.package_id, package_id_for_sha256(&recorded.sha256));
        // 副本落在 <state>/knowledge/<id>/，且是**目录**不是文件。
        assert!(recorded.cached_path.is_dir());
        assert!(recorded.cached_path.join("catalog.toml").is_file());
        // 已校验通过的那一份直接可用（激活时不必重装）。
        assert_eq!(
            recorded
                .loaded
                .content
                .as_deref()
                .map(|set| set.catalog_version),
            Some(2)
        );

        // 落库：版本从**文件实际声明**取值（不是只信 manifest）。
        let row = store
            .knowledge_package(&recorded.package_id)
            .await
            .expect("read")
            .expect("row");
        assert_eq!(row.catalog_version, Some(2));
        assert_eq!(row.purpose_version, Some(1));
        assert_eq!(row.policy_version, Some(1));
        assert_eq!(row.template_version, Some(1));
        assert_eq!(row.version, PACKAGE_NAME_SUFFIX);
        assert!(row.package_sha256.starts_with("sha256:"));
    }

    #[tokio::test]
    async fn a_tampered_payload_is_rejected() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (config, root) = test_config();
        // manifest 记的是原字节，包里的 catalog.toml 却在打包后被改过。
        let tarball = build_package_tarball(&root, true);
        let err = record(&store, &config, tarball.to_str().expect("path"))
            .await
            .expect_err("must refuse");
        assert_eq!(err.code(), "package_manifest_inconsistent");
        assert!(err.to_string().contains("catalog.toml"), "{err}");
        // 拒收的包不会留下副本（半成品不进 `<state>/knowledge/`）。
        let knowledge_dir = config.knowledge_dir();
        let leftovers: Vec<_> = fs::read_dir(&knowledge_dir)
            .map(|entries| entries.filter_map(Result::ok).collect())
            .unwrap_or_default();
        assert!(
            leftovers.is_empty(),
            "拒收后不该留下任何副本：{leftovers:?}"
        );
    }

    #[tokio::test]
    async fn a_wrong_expected_digest_is_rejected() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (config, root) = test_config();
        let tarball = build_package_tarball(&root, false);
        let err = record_package(
            &config,
            &store,
            tarball.to_str().expect("path"),
            Some(&"0".repeat(64)),
            "admin",
            "2026-09-30T00:00:00Z",
        )
        .await
        .expect_err("must refuse");
        assert_eq!(err.code(), "package_sha256_mismatch");
    }

    #[tokio::test]
    async fn a_bad_source_is_rejected_before_any_io() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (config, root) = test_config();
        let err = record(&store, &config, "relative/path.tar.gz")
            .await
            .expect_err("must refuse");
        assert_eq!(err.code(), "package_source_invalid");
        // 目录也不行：包的判据是"来源制品的摘要"，目录没有天然摘要。
        let err = record(&store, &config, root.to_str().expect("path"))
            .await
            .expect_err("must refuse");
        assert_eq!(err.code(), "package_source_invalid");
    }

    #[test]
    fn loading_a_recorded_package_keeps_its_identity() {
        let (config, root) = test_config();
        let tarball = build_package_tarball(&root, false);
        // 走一次真实录入，拿到 id，再用激活前的那条装载路径读回来。
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let recorded = runtime.block_on(async {
            let store: Arc<dyn Store> = Arc::new(
                crate::infra::SqliteStore::connect("sqlite::memory:")
                    .await
                    .expect("store"),
            );
            record(&store, &config, tarball.to_str().expect("path"))
                .await
                .expect("record")
        });
        let loaded = load_recorded_package(&config, &recorded.package_id).expect("load recorded");
        assert_eq!(
            loaded.source,
            KnowledgeSource::Package {
                package_id: recorded.package_id.clone()
            }
        );
        assert_eq!(
            loaded.content.as_deref().map(|set| set.catalog_version),
            Some(2)
        );
    }

    // ── 验签（设计 §9：一把公钥，与安装脚本同一简单度）──────────────────

    /// 配了公钥 → 只接受 **发布侧那把私钥**签过的包，并记下公钥指纹。
    #[tokio::test]
    async fn verifies_the_release_signature_when_a_public_key_is_configured() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (mut config, root) = test_config();
        let signing = crate::test_support::knowledge_signing_key(&root);
        config.knowledge_signing_public_key = Some(signing.public_raw.clone());
        config.knowledge_signing_public_key_file = Some(signing.public_pem_path.clone());
        let tarball = build_package_tarball(&root, false);
        crate::test_support::sign_knowledge_package(&tarball, &signing.private_key);

        let recorded = record(&store, &config, tarball.to_str().expect("path"))
            .await
            .expect("record signed package");
        let row = store
            .knowledge_package(&recorded.package_id)
            .await
            .expect("read")
            .expect("row");
        // 指纹落库：换钥匙后回头看旧行，能看出它们是被不同锚接受的。
        assert_eq!(
            row.signed_by,
            crate::infra::public_key_fingerprint(&signing.public_raw)
        );
        assert!(!row.signed_by.is_empty());
    }

    /// 配了公钥但包没签名 → 拒。
    #[tokio::test]
    async fn refuses_an_unsigned_package_when_a_public_key_is_configured() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (mut config, root) = test_config();
        let signing = crate::test_support::knowledge_signing_key(&root);
        config.knowledge_signing_public_key = Some(signing.public_raw.clone());
        let tarball = build_package_tarball(&root, false);

        let err = record(&store, &config, tarball.to_str().expect("path"))
            .await
            .expect_err("must refuse");
        assert_eq!(err.code(), "package_signature_invalid");
        assert!(err.to_string().contains(".sig"), "{err}");
    }

    /// 签名被动过一个字节 → 拒（换包或换签名都过不了）。
    #[tokio::test]
    async fn refuses_a_tampered_signature() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (mut config, root) = test_config();
        let signing = crate::test_support::knowledge_signing_key(&root);
        config.knowledge_signing_public_key = Some(signing.public_raw.clone());
        let tarball = build_package_tarball(&root, false);
        let sig = crate::test_support::sign_knowledge_package(&tarball, &signing.private_key);
        // 把签名的最后一个 base64 字符换掉：内容合法、形状合法，就是验不过。
        let text = fs::read_to_string(&sig).expect("read sig");
        let mut chars: Vec<char> = text.trim().chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        fs::write(&sig, chars.into_iter().collect::<String>()).expect("write sig");

        let err = record(&store, &config, tarball.to_str().expect("path"))
            .await
            .expect_err("must refuse");
        assert_eq!(err.code(), "package_signature_invalid");
    }

    /// 没配公钥 → 不验签（只记摘要），否则今天所有部署都会突然录不进包。
    #[tokio::test]
    async fn skips_signature_check_when_no_public_key_is_configured() {
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (config, root) = test_config();
        assert!(config.knowledge_signing_public_key.is_none());
        let tarball = build_package_tarball(&root, false);
        let recorded = record(&store, &config, tarball.to_str().expect("path"))
            .await
            .expect("record unsigned package");
        let row = store
            .knowledge_package(&recorded.package_id)
            .await
            .expect("read")
            .expect("row");
        assert!(row.signed_by.is_empty(), "没验签就不该声称有签发者");
    }

    /// 一个只用来定位临时目录的配置：知识库目录与 sqlite 同址（与真实部署同一约定）。
    fn test_config() -> (AdminConfig, std::path::PathBuf) {
        let root = crate::test_support::unique_temp_dir("wist-knowledge-rec");
        let config = crate::infra::config::config_for_tests(&root);
        (config, root)
    }

    /// 用**真实 `scripts/package.sh` 产物**跑一次完整录入。
    ///
    /// 默认跳过（要真制品），显式跑：
    /// `WIST_KNOWLEDGE_TEST_PACKAGE=<tar.gz> cargo test -- --ignored records_the_real_artifact`
    /// 它验的是**契约**：打包脚本产出的 manifest 形状网关真能吃下。
    ///
    /// 再加 `WIST_KNOWLEDGE_TEST_PUBKEY=<knowledge-signing.pub.pem>` 则一并验签 ——
    /// 这一步连的是**跨工具**契约：发布侧 openssl 签、网关（ring）验，两边不各自为政。
    #[tokio::test]
    #[ignore = "需要真实制品：设 WIST_KNOWLEDGE_TEST_PACKAGE 后加 --ignored 跑"]
    async fn records_the_real_artifact() {
        let path = std::env::var("WIST_KNOWLEDGE_TEST_PACKAGE")
            .expect("WIST_KNOWLEDGE_TEST_PACKAGE 必须指向 scripts/package.sh 产出的 tar.gz");
        let store: Arc<dyn Store> = Arc::new(
            crate::infra::SqliteStore::connect("sqlite::memory:")
                .await
                .expect("store"),
        );
        let (mut config, _root) = test_config();
        if let Ok(public_key_path) = std::env::var("WIST_KNOWLEDGE_TEST_PUBKEY") {
            let pem = fs::read_to_string(&public_key_path).expect("读验签公钥");
            config.knowledge_signing_public_key =
                Some(crate::infra::parse_ed25519_public_key_pem(&pem).expect("解析验签公钥"));
        }
        let recorded = record(&store, &config, &path)
            .await
            .expect("record real artifact");
        let row = store
            .knowledge_package(&recorded.package_id)
            .await
            .expect("read")
            .expect("row");
        assert!(row.version.starts_with("0."), "版本读到了：{}", row.version);
        assert_eq!(row.purpose_version, Some(1));
        assert_eq!(
            recorded
                .loaded
                .content
                .as_deref()
                .map(|set| set.catalog_version),
            Some(2)
        );
        if config.knowledge_signing_public_key.is_some() {
            assert!(
                !row.signed_by.is_empty(),
                "配了公钥且验签通过，就该记下签发者指纹"
            );
        }
    }
}
