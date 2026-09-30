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
use crate::infra::{AdminConfig, Store};

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
}
