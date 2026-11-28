//! 导出器运行参数表（知识库 `exporters.toml`）：二进制**搜索目录** + 周期 / 超时。
//!
//! ## 为什么这些值是数据
//!
//! 工具装在哪个目录是**纯环境信息**（usrmerge / busybox / 最小容器镜像 / Homebrew / 自建前缀），
//! 写死在 agentd 里就意味着每遇到一种新环境就要发一版 root 守护进程。周期 / 超时是策略。
//!
//! ## 数据能改什么、不能改什么
//!
//! 能改：**去哪几个目录找**（`bin_dirs`）、**多久跑一次**（`period_secs` / `timeout_secs`）。
//! 不能改：**跑什么** —— `id` 必须是契约 [`EXPORTER_IDS`] 里已登记的，二进制名与参数
//! 都留在 agentd 代码里。所以「换一版知识库」永远不会变成「让全舰队执行任意命令」。
//!
//! ## 校验不过 = 整份拒载
//!
//! 半份坏策略会让一部分机器悄悄换了搜索范围，排查成本远高于**拒绝装载**
//! （旧包没有这份文件，装载走的是“可选”路径，不受影响）。

use std::path::Path;

use serde::Deserialize;
use wist_contracts::work::EXPORTER_IDS;

/// 单平台最多允许的搜索目录数（防止把整盘目录塞进来拖慢每次解析）。
pub const MAX_BIN_DIRS: usize = 16;
/// 周期下界：再密就是在拿导出器当采集器用，会把机器拖住。
pub const MIN_PERIOD_SECS: u64 = 10;
/// 周期上界（24h）。
pub const MAX_PERIOD_SECS: u64 = 24 * 3600;
/// 单次导出超时的上下界。
pub const MIN_TIMEOUT_SECS: u64 = 1;
pub const MAX_TIMEOUT_SECS: u64 = 300;

/// 允许作为**二进制搜索目录**的系统目录前缀。
///
/// 这是安全边界：知识库只能把搜索范围指向系统目录，不能指向 `/tmp`、家目录、`/root`
/// 这类可被非 root 写入的位置（那等于允许“谁能在那儿放文件，谁就能决定 agent 执行什么”）。
/// `/opt` 与 `/snap` 保留，是因为自建/打包安装常常落在那里。
const ALLOWED_BIN_DIR_PREFIXES: &[&str] = &["/usr", "/bin", "/sbin", "/opt", "/snap"];

/// 整份表（与 `wist-knowledge/exporters.toml` 一一对应）。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterPolicyTable {
    pub exporters_version: i64,
    /// 发布时间（审计用；与其它策展数据同形）。
    #[serde(default)]
    pub published_at: String,
    #[serde(default)]
    pub platform: Vec<PlatformBinDirs>,
    /// 逐导出器的周期/超时覆盖；空 = 全用 agentd 内置值。
    #[serde(default)]
    pub exporter: Vec<ExporterOverride>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformBinDirs {
    pub platform: String,
    #[serde(default)]
    pub bin_dirs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterOverride {
    pub id: String,
    #[serde(default)]
    pub period_secs: Option<u64>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

impl ExporterPolicyTable {
    /// 某平台生效的搜索目录（空 = 让 agentd 用内置表）。
    pub fn bin_dirs_for(&self, platform: &str) -> Vec<String> {
        self.platform
            .iter()
            .find(|row| row.platform == platform)
            .map(|row| row.bin_dirs.clone())
            .unwrap_or_default()
    }

    /// 周期/超时覆盖（只回**实际写了**的项）。
    ///
    /// 这份表里的覆盖**不分平台**：同一个导出器在各平台的节奏应当一致；
    /// 真要分平台，那是新字段的事（不在这一版偷加语义）。
    pub fn overrides(&self) -> Vec<ExporterOverrideView> {
        self.exporter
            .iter()
            .map(|row| ExporterOverrideView {
                id: row.id.clone(),
                period_secs: row.period_secs,
                timeout_secs: row.timeout_secs,
            })
            .collect()
    }
}

/// 下发用的覆盖项（与 agentd 侧的 JSON 形状一致）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExporterOverrideView {
    pub id: String,
    pub period_secs: Option<u64>,
    pub timeout_secs: Option<u64>,
}

/// 装载 + 校验。`None` = 文件不在（旧包 / 未配置），不是错误。
pub fn load_optional(path: &Path) -> Result<Option<ExporterPolicyTable>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("读 {} 失败：{err}", path.display())),
    };
    let table: ExporterPolicyTable =
        toml::from_str(&text).map_err(|err| format!("解析 {} 失败：{err}", path.display()))?;
    validate(&table)?;
    Ok(Some(table))
}

/// 结构校验：越界、未知 ID、重复行、非系统目录都拒。
pub fn validate(table: &ExporterPolicyTable) -> Result<(), String> {
    if table.exporters_version < 1 {
        return Err(format!(
            "exporters_version 必须 >= 1（当前 {}）",
            table.exporters_version
        ));
    }

    let mut seen_platforms: Vec<&str> = Vec::new();
    for row in &table.platform {
        if !matches!(row.platform.as_str(), "linux" | "macos") {
            return Err(format!(
                "platform 只能是 linux / macos（当前 {:?}）",
                row.platform
            ));
        }
        if seen_platforms.contains(&row.platform.as_str()) {
            return Err(format!("platform {:?} 重复声明", row.platform));
        }
        seen_platforms.push(row.platform.as_str());
        let mut seen_dirs: Vec<&str> = Vec::new();
        if row.bin_dirs.len() > MAX_BIN_DIRS {
            return Err(format!(
                "platform {:?} 的 bin_dirs 最多 {MAX_BIN_DIRS} 项（当前 {}）",
                row.platform,
                row.bin_dirs.len()
            ));
        }
        for dir in &row.bin_dirs {
            if seen_dirs.contains(&dir.as_str()) {
                return Err(format!(
                    "platform {:?} 的目录 {dir:?} 重复声明",
                    row.platform
                ));
            }
            seen_dirs.push(dir.as_str());
            validate_bin_dir(&row.platform, dir)?;
        }
    }

    let mut seen_ids: Vec<&str> = Vec::new();
    for row in &table.exporter {
        if !EXPORTER_IDS.contains(&row.id.as_str()) {
            return Err(format!(
                "未知导出器 id {:?}（数据不能引入新命令；已登记：{EXPORTER_IDS:?}）",
                row.id
            ));
        }
        if seen_ids.contains(&row.id.as_str()) {
            return Err(format!("导出器 {:?} 重复声明", row.id));
        }
        seen_ids.push(row.id.as_str());
        if row.period_secs.is_none() && row.timeout_secs.is_none() {
            return Err(format!(
                "导出器 {:?} 既没写 period_secs 也没写 timeout_secs",
                row.id
            ));
        }
        if let Some(period) = row.period_secs
            && !(MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(&period)
        {
            return Err(format!(
                "导出器 {:?} 的 period_secs={period} 越界（{MIN_PERIOD_SECS}..={MAX_PERIOD_SECS}）",
                row.id
            ));
        }
        if let Some(timeout) = row.timeout_secs
            && !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&timeout)
        {
            return Err(format!(
                "导出器 {:?} 的 timeout_secs={timeout} 越界（{MIN_TIMEOUT_SECS}..={MAX_TIMEOUT_SECS}）",
                row.id
            ));
        }
    }
    Ok(())
}

fn validate_bin_dir(platform: &str, dir: &str) -> Result<(), String> {
    if !dir.starts_with('/') {
        return Err(format!("platform {platform:?} 的目录 {dir:?} 不是绝对路径"));
    }
    if dir.contains("..") {
        return Err(format!("platform {platform:?} 的目录 {dir:?} 含 `..`"));
    }
    if dir
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '$' | '`' | ';' | '|' | '&' | '\n' | '\r'))
    {
        return Err(format!(
            "platform {platform:?} 的目录 {dir:?} 含 shell 元字符 / 通配符"
        ));
    }
    let allowed = ALLOWED_BIN_DIR_PREFIXES.iter().any(|root| {
        dir == *root
            || dir
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    });
    if !allowed {
        return Err(format!(
            "platform {platform:?} 的目录 {dir:?} 不在系统目录白名单内（只允许 {} 下）",
            ALLOWED_BIN_DIR_PREFIXES.join(" / ")
        ));
    }
    if dir.len() > 1 && dir.ends_with('/') {
        return Err(format!(
            "platform {platform:?} 的目录 {dir:?} 结尾多了 `/`（会拼出 `//binary`）"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(
        platforms: Vec<PlatformBinDirs>,
        exporters: Vec<ExporterOverride>,
    ) -> ExporterPolicyTable {
        ExporterPolicyTable {
            exporters_version: 1,
            published_at: String::new(),
            platform: platforms,
            exporter: exporters,
        }
    }

    fn platform(name: &str, dirs: &[&str]) -> PlatformBinDirs {
        PlatformBinDirs {
            platform: name.to_string(),
            bin_dirs: dirs.iter().map(|dir| (*dir).to_string()).collect(),
        }
    }

    #[test]
    fn a_reasonable_table_passes() {
        let table = table(
            vec![
                platform("linux", &["/usr/bin", "/bin", "/usr/local/sbin"]),
                platform("macos", &["/opt/homebrew/bin"]),
            ],
            vec![ExporterOverride {
                id: "dmesg".to_string(),
                period_secs: Some(300),
                timeout_secs: None,
            }],
        );
        validate(&table).expect("合法");
        assert_eq!(table.bin_dirs_for("linux").len(), 3);
        assert!(table.bin_dirs_for("windows").is_empty());
        assert_eq!(table.overrides()[0].id, "dmesg");
    }

    #[test]
    fn the_shipped_knowledge_file_is_valid() {
        // 跨仓真实数据：改坏了这里当场红（与 `the_knowledge_vocabulary_matches_the_model` 同一姿态）。
        let path = crate::test_support::knowledge_file("exporters.toml");
        let table = load_optional(&path)
            .expect("装载")
            .expect("这份包应当带 exporters.toml");
        assert!(table.exporters_version >= 1);
        assert!(
            !table.bin_dirs_for("linux").is_empty(),
            "linux 的搜索目录不能为空（空 = 回落 agentd 内置值，数据就白写了）"
        );
    }

    #[test]
    fn unknown_ids_and_unsafe_dirs_are_refused() {
        let unknown = table(
            vec![],
            vec![ExporterOverride {
                id: "rm-rf".to_string(),
                period_secs: Some(300),
                timeout_secs: None,
            }],
        );
        assert!(validate(&unknown).unwrap_err().contains("未知导出器"));

        for dir in [
            "relative/bin",
            "/usr/bin/../..",
            "/tmp/bin",
            "/home/x/bin",
            "/usr/bin/*",
        ] {
            let bad = table(vec![platform("linux", &[dir])], vec![]);
            assert!(
                validate(&bad).is_err(),
                "{dir:?} 不该被接受：{:?}",
                validate(&bad)
            );
        }
    }

    #[test]
    fn periods_and_timeouts_are_bounded() {
        let too_fast = table(
            vec![],
            vec![ExporterOverride {
                id: "dmesg".to_string(),
                period_secs: Some(1),
                timeout_secs: None,
            }],
        );
        assert!(validate(&too_fast).unwrap_err().contains("period_secs"));
        let too_slow = table(
            vec![],
            vec![ExporterOverride {
                id: "dmesg".to_string(),
                period_secs: None,
                timeout_secs: Some(3600),
            }],
        );
        assert!(validate(&too_slow).unwrap_err().contains("timeout_secs"));
        let empty = table(
            vec![],
            vec![ExporterOverride {
                id: "dmesg".to_string(),
                period_secs: None,
                timeout_secs: None,
            }],
        );
        assert!(validate(&empty).is_err());
    }

    /// 同一平台重复列同一目录：拒（否则每次解析多一次 stat，且改表时看不出多了一条）。
    #[test]
    fn duplicate_directories_are_refused() {
        let duplicated = table(vec![platform("linux", &["/usr/bin", "/usr/bin"])], vec![]);
        assert!(validate(&duplicated).unwrap_err().contains("重复声明"));
        // 同一目录跨平台出现是合法的（linux 与 macos 都有 /usr/bin）。
        let across_platforms = table(
            vec![
                platform("linux", &["/usr/bin"]),
                platform("macos", &["/usr/bin"]),
            ],
            vec![],
        );
        validate(&across_platforms).expect("跨平台重复不算错");
    }

    /// 文件不在 = 可选（旧包），不是错误；文件坏了 = 错误（不能静默退回内置值）。
    #[test]
    fn a_missing_file_is_optional_but_a_broken_one_is_an_error() {
        let dir =
            std::env::temp_dir().join(format!("wist-gw-exporter-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("exporters.toml");
        assert!(load_optional(&path).expect("missing is fine").is_none());

        std::fs::write(&path, b"exporters_version = 0").expect("write");
        assert!(load_optional(&path).is_err(), "版本 0 要被拒");

        std::fs::write(&path, b"this is not toml").expect("write");
        assert!(load_optional(&path).is_err(), "坏 TOML 要报错");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
