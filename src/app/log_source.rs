//! 日志源定位的**纯逻辑**：路径规范化、roots 判定、按实例展开。
//!
//! 为什么单独一个模块：这段判据要**同时**被三处用 —— 管理 API（写入校验）、
//! 目录装载期（结构校验）、派活物化（`from_dir` 解析）。三处各写一遍，
//! 「什么算合法目录」就会有三套口径，而它是安全边界，不允许漂。
//!
//! 分层约定（见 `doc/design/edge/log-source-resolution.md`）：
//!
//! * **网关是唯一判定方**：agent 只上报「看到了什么 + 依据」，不决定采什么；
//! * **roots 是网关策略**：解析出来的、人显式指定的，都要过同一道闸；
//! * **覆盖不能越权**：人指定 roots 外的目录同样被拒 —— 要放宽就改网关配置（策略级变更）。

use std::collections::BTreeSet;

use wist_contracts::work::ContainerFilters;

use crate::infra::StoredLogSource;

/// 是否为通配元字符（与 `wist_contracts::work` 同口径）。
fn has_glob_meta(value: &str) -> bool {
    value.contains(['*', '?', '['])
}

/// 依据词表（v1）。
///
/// 网关按它做**上报期校验**：规则叫 `cmdline_datadir`、上报写 `cmdline` 这种拼写漂移
/// 会让候选静默丢失（页面只看到「找不到日志」）。`human` 只用于人工覆盖 ——
/// agent 自称 `human` 一律拒收（那等于把人的显式意图冒充成机器解析）。
pub const LOG_SOURCE_EVIDENCE: &[&str] = &[
    "human",
    "cmdline_datadir",
    "cmdline_logfile",
    "env_datadir",
    "open_fd",
    "config_file",
    "cwd",
    "search_hit",
    // 「看得见这个实例，但找不到它的日志目录」。它不是一条候选（`dir` 为空），
    // 存在的意义只有一个：让页面能说「2 个实例，1 个没定位」——
    // 否则分母永远只有成功解析的那几个，永远不会出现“部分”。
    "unresolved",
];

/// 规范化一个「日志目录」：绝对路径、无 `..`、无通配、无尾斜杠。
///
/// 拒绝而不是「尽力修」：目录来自人要写的 API / 策展写的目录，**猜它的意思**比报错危险得多
/// （`/data/../etc` 要不要放行？放行就等于绕过 roots）。
pub fn normalize_dir(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("目录不能为空".to_string());
    }
    if value.contains('\0') {
        return Err("目录里不能含 NUL".to_string());
    }
    if !value.starts_with('/') {
        return Err(format!("目录必须是绝对路径，got {value:?}"));
    }
    if value.contains('\\') {
        return Err(format!("目录不支持 Windows 分隔符，got {value:?}"));
    }
    if has_glob_meta(value) {
        return Err(format!(
            "目录里不能含通配符（pattern 请写在目录里），got {value:?}"
        ));
    }
    if value.split('/').any(|segment| segment == "..") {
        return Err(format!("目录里不能含 `..`，got {value:?}"));
    }
    if value == "/" {
        return Err("目录不能是根 `/`".to_string());
    }
    let trimmed = value.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("目录不能是根 `/`".to_string());
    }
    Ok(trimmed.to_string())
}

/// `dir` 是否落在 `roots` 里（**按路径段**判前缀）。
///
/// 必须按段判：字符串前缀会让 `/data` 放行 `/database` —— 那是安全边界，不是便利函数。
pub fn is_under_roots(dir: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        root == "/" || dir == root.as_str() || {
            dir.strip_prefix(root.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        }
    })
}

/// 规范化并校验 roots（装载期用）：每个 root 都必须是合法目录，且不是 `/`。
///
/// 返回**去重后**的列表：重复 roots 无害，但它会让「roots 有几个」这类审计问题多出噪声。
pub fn normalize_roots(raw: &[String]) -> Result<Vec<String>, String> {
    normalize_root_list("allowed_source_roots", raw)
        .map_err(|err| format!("{err}（roots 必须是普通目录，不能是 `/`）"))
}

/// L3 搜索根的上限（与 agentd 的 `search::MAX_SEARCH_ROOTS` 同值，两侧各持一份常量）。
///
/// 为什么不能只靠“知识库是签名产物”兜底：上限是**运行期成本**的保证 ——
/// 一个把 `/data` 写错的包不该让全舰队去扫盘。
pub const MAX_SEARCH_ROOTS: usize = 8;

/// 知识库 unit 级 `search_roots`：L3 的**舰队级上限**。
///
/// 拒载而不是丢弃：知识库是签名产物，写错的 root 是策展 bug —— 静默丢掉会让人以为
/// “搜索开着”，实际从来没搜过。
pub fn normalize_search_roots(unit_id: &str, raw: &[String]) -> Result<Vec<String>, String> {
    if raw.len() > MAX_SEARCH_ROOTS {
        return Err(format!(
            "unit {unit_id}: search_roots 最多 {MAX_SEARCH_ROOTS} 条（got {}）",
            raw.len()
        ));
    }
    normalize_root_list(&format!("unit {unit_id}: search_roots"), raw)
        .map_err(|err| format!("{err}（默认不搜：不写就不开 L3）"))
}

fn normalize_root_list(label: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut roots = Vec::new();
    let mut seen = BTreeSet::new();
    for root in raw {
        let root = normalize_dir(root).map_err(|err| format!("{label}: {err}"))?;
        if seen.insert(root.clone()) {
            roots.push(root);
        }
    }
    Ok(roots)
}

/// 一条路径的父目录（`/var/log/postgresql/*.csv` → `/var/log/postgresql`）。
///
/// 用途：判断「目录字面值这条来源还能不能用」—— 父目录被**实测为不存在**时，
/// 采它只会得到 0 文件，不如如实报「找不到日志」。
pub fn parent_dir(path: &str) -> Option<&str> {
    let (parent, _) = path.rsplit_once('/')?;
    if parent.is_empty() {
        Some("/")
    } else {
        Some(parent)
    }
}

/// 把目录与文件名 pattern 拼成一条绝对路径 glob。
///
/// pattern 在装载期已经保证是**单层文件名**（不含 `/`），所以这里只做拼接。
pub fn join_pattern(dir: &str, pattern: &str) -> String {
    if dir == "/" {
        format!("/{pattern}")
    } else {
        format!("{dir}/{pattern}")
    }
}

/// 一条目录候选在**这一台机器**上的取舍结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSource {
    pub kind: String,
    /// 物化后的绝对路径 / glob。
    pub target: String,
    pub multiline: String,
    pub exclude_globs: Vec<String>,
    pub filters: ContainerFilters,
    pub drop_if_contains: Vec<String>,
    /// `catalog`：目录里的字面值；`resolved`：由 `from_dir` 解析出来的。
    pub origin: &'static str,
    /// 实例引用（`port:5432`）；目录字面值没有。
    pub instance: String,
}

impl ResolvedSource {
    pub fn from_catalog(source: &crate::app::content::UnitSource) -> Self {
        Self {
            kind: source.kind.clone(),
            target: source.target.clone(),
            multiline: source.multiline.clone(),
            exclude_globs: source.exclude_globs.clone(),
            filters: source.filters.clone(),
            drop_if_contains: source.drop_if_contains.clone(),
            origin: "catalog",
            instance: String::new(),
        }
    }

    fn from_resolved(source: &crate::app::content::UnitSource, dir: &str, instance: &str) -> Self {
        Self {
            kind: source.kind.clone(),
            target: join_pattern(dir, &source.pattern),
            multiline: source.multiline.clone(),
            exclude_globs: source.exclude_globs.clone(),
            filters: source.filters.clone(),
            drop_if_contains: source.drop_if_contains.clone(),
            origin: "resolved",
            instance: instance.to_string(),
        }
    }
}

/// 一个单元的来源解析结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitSources {
    /// 这条单元今天真能采的来源（已去重、顺序确定）。
    pub sources: Vec<ResolvedSource>,
    /// 被判定为「这台机器上不存在」而剔掉的字面路径（给 409 文案用）。
    pub absent: Vec<String>,
    /// `from_dir` 的目录没解析到（给「服务在、找不到日志」用）。
    pub unresolved: Vec<String>,
}

/// 目录候选的**取舍规则**（唯一一处）：
///
/// 1. 只有**同一服务**的候选参与；
/// 2. **覆盖优先**：只要该服务有 `origin = override` 的候选，解析值就不参与；
/// 3. 每个实例只取第一条（列表已是「覆盖在前、证据可信度降序」）；
/// 4. 出 roots 的候选直接丢（覆盖也不例外 —— 人不能扩大安全边界）；
/// 5. **覆盖失效不回落**：覆盖存在但出 roots 时，解析值**不**顶替它的位置 ——
///    结果为空（`unresolved`），让人看到「我设的覆盖已经不生效了」。
pub fn resolve_dirs<'a>(
    candidates: impl Iterator<Item = &'a StoredLogSource>,
    service: &str,
    roots: &[String],
) -> Vec<(String, String)> {
    let matching: Vec<&StoredLogSource> = candidates
        .filter(|candidate| candidate.service == service)
        // `unresolved` 行只参与**计数**（分母），不提供目录：它们没有可采的东西。
        .filter(|candidate| !candidate.dir.trim().is_empty())
        .collect();
    let has_override = matching.iter().any(|candidate| candidate.is_override());
    let mut seen_refs: BTreeSet<String> = BTreeSet::new();
    matching
        .into_iter()
        .filter(|candidate| !has_override || candidate.is_override())
        .filter(|candidate| is_under_roots(&candidate.dir, roots))
        // 同一实例的多条证据只取第一条（列表已是「覆盖在前、证据可信度降序」）。
        .filter(|candidate| seen_refs.insert(candidate.source_ref.clone()))
        .map(|candidate| (candidate.source_ref.clone(), candidate.dir.clone()))
        .collect()
}

/// 一次求值要的**全部日志源输入**。
///
/// 为什么打包成一个结构体：预检与授权必须拿**同一份**输入（否则「预检说可以、授权却拒绝」），
/// 而参数已经很多了 —— 两个 `&[...]` 分开传，早晚有一处忘记同步。
#[derive(Debug, Clone, Copy, Default)]
pub struct SourceContext<'a> {
    /// 这台机器已上报 / 已被人工指定的全部候选（覆盖在前）。
    pub log_sources: &'a [StoredLogSource],
    /// 网关策略：允许落地的目录 roots。
    pub roots: &'a [String],
    /// 这台机器自报的 agentd 版本（`None` = 还没报过）。
    ///
    /// 只用于知识库声明的最低版本闸门：拿不准（没报 / 报了个没法比的串）就**当不满足**，
    /// 与能力协商同一姿态 —— 宁可少派，不派下去换一个 `unsupported`。
    pub agent_version: Option<&'a str>,
}

/// 一个单元的来源解析：字面值按实测裁掉不存在的，`from_dir` 按实例展开。
///
/// **这是「采什么」的唯一入口**：预检（`expand`）与派活（`materialize_spec`）都走它，
/// 所以「页面说能授」与「授权发下去的 spec」不会对不上。
pub fn resolve_unit_sources(
    unit: &crate::app::content::Unit,
    facts: Option<&crate::infra::StoredAgentFactSummary>,
    context: SourceContext<'_>,
) -> UnitSources {
    let mut out = UnitSources::default();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for source in &unit.sources {
        if let Some(service) = source.log_service() {
            let dirs = resolve_dirs(context.log_sources.iter(), service, context.roots);
            if dirs.is_empty() {
                // 服务在、但没有任何可用目录：不要退化成「采目录字面值」（那会在
                // 非标准部署上静默采一个空目录，页面却显示「已授权」）。
                out.unresolved.push(service.to_string());
                continue;
            }
            for (instance, dir) in dirs {
                let resolved = ResolvedSource::from_resolved(source, &dir, &instance);
                if seen.insert((resolved.kind.clone(), resolved.target.clone())) {
                    out.sources.push(resolved);
                }
            }
            continue;
        }
        if catalog_source_is_absent(source, facts) {
            out.absent.push(source.target.clone());
            continue;
        }
        let resolved = ResolvedSource::from_catalog(source);
        if seen.insert((resolved.kind.clone(), resolved.target.clone())) {
            out.sources.push(resolved);
        }
    }
    out
}

/// 目录字面值这条来源**还能不能用**。
///
/// 两档判据（都是三态：**没探过 ≠ 不存在**）：
/// * 目标本身是显式文件且实测不存在 → 采不到；
/// * 目标（或其 glob）的**父目录**实测不存在 → 同样采不到，而且这正是
///   「服务装在非标准目录」的现场特征（`/var/log/postgresql` 不在）。
pub fn catalog_source_is_absent(
    source: &crate::app::content::UnitSource,
    facts: Option<&crate::infra::StoredAgentFactSummary>,
) -> bool {
    use wist_contracts::work::is_explicit_path;

    let Some(facts) = facts else {
        return false;
    };
    if source.kind != "FileGlob" {
        return false;
    }
    let probed = |path: &str| facts.probed_paths.iter().any(|item| item == path);
    let present = |path: &str| facts.present_paths.iter().any(|item| item == path);
    if is_explicit_path(&source.target) && probed(&source.target) && !present(&source.target) {
        return true;
    }
    match parent_dir(&source.target) {
        Some(parent) => probed(parent) && !present(parent),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dir_rejects_anything_that_could_escape_roots() {
        assert_eq!(normalize_dir(" /data/pg/log/ ").unwrap(), "/data/pg/log");
        assert!(normalize_dir("").is_err());
        assert!(normalize_dir("data/pg").is_err(), "相对路径不能放行");
        assert!(
            normalize_dir("/data/../etc").is_err(),
            "`..` 等于绕过 roots"
        );
        assert!(normalize_dir("/data/*/log").is_err(), "通配不是目录");
        assert!(normalize_dir("/data\\pg").is_err());
        assert!(normalize_dir("/").is_err());
    }

    #[test]
    fn roots_match_by_path_segment_not_by_string_prefix() {
        let roots = vec!["/data".to_string(), "/var/log".to_string()];
        assert!(is_under_roots("/data", &roots));
        assert!(is_under_roots("/data/pg/log", &roots));
        assert!(!is_under_roots("/database/pg", &roots), "字符串前缀不算");
        assert!(is_under_roots("/var/log/postgresql", &roots));
        assert!(!is_under_roots("/opt/pg", &roots), "没声明的 root");
        assert!(!is_under_roots("/data2", &roots));
    }

    #[test]
    fn normalize_roots_rejects_root_and_dedupes() {
        assert!(normalize_roots(&["/".to_string()]).is_err());
        assert!(normalize_roots(&["relative".to_string()]).is_err());
        assert_eq!(
            normalize_roots(&[
                "/data/".to_string(),
                "/data".to_string(),
                "/srv".to_string()
            ])
            .unwrap(),
            vec!["/data".to_string(), "/srv".to_string()]
        );
        // 空列表是合法输入：等于「只允许目录字面值」。
        assert!(normalize_roots(&[]).unwrap().is_empty());
    }

    #[test]
    fn parent_and_join() {
        assert_eq!(
            parent_dir("/var/log/postgresql/*.csv"),
            Some("/var/log/postgresql")
        );
        assert_eq!(parent_dir("/var/log/auth.log"), Some("/var/log"));
        assert_eq!(parent_dir("/auth.log"), Some("/"));
        assert_eq!(parent_dir("relative.log"), None);
        assert_eq!(join_pattern("/data/pg/log", "*.csv"), "/data/pg/log/*.csv");
        assert_eq!(join_pattern("/", "*.log"), "/*.log");
    }

    fn candidate(origin: &str, service: &str, dir: &str, source_ref: &str) -> StoredLogSource {
        StoredLogSource {
            agent_id: "agent-a".to_string(),
            service: service.to_string(),
            source_ref: source_ref.to_string(),
            dir: dir.to_string(),
            evidence: if origin == "override" {
                "human".to_string()
            } else {
                "cmdline_datadir".to_string()
            },
            detail: String::new(),
            confidence: 90,
            origin: origin.to_string(),
            observed_at: "2026-10-26T00:00:00Z".to_string(),
            updated_at: "2026-10-26T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn override_wins_over_resolved_for_the_same_service() {
        let roots = vec!["/data".to_string(), "/opt".to_string()];
        let resolved = candidate("agent", "postgresql", "/data/pg/log", "port:5432");
        let overridden = candidate("override", "postgresql", "/opt/pg/log", "override");
        let dirs = resolve_dirs([&resolved, &overridden].into_iter(), "postgresql", &roots);
        // 覆盖存在时解析值不参与 —— 不是“两条都采”。
        assert_eq!(
            dirs,
            vec![("override".to_string(), "/opt/pg/log".to_string())]
        );
    }

    #[test]
    fn multi_instance_expands_one_dir_per_instance() {
        let roots = vec!["/data".to_string()];
        let first = candidate("agent", "postgresql", "/data/pg1/log", "port:5432");
        let second = candidate("agent", "postgresql", "/data/pg2/log", "port:5433");
        let other = candidate("agent", "mysql", "/data/mysql", "port:3306");
        let dirs = resolve_dirs([&first, &second, &other].into_iter(), "postgresql", &roots);
        // 另一个服务的候选不参与；两个实例各一条。
        assert_eq!(
            dirs,
            vec![
                ("port:5432".to_string(), "/data/pg1/log".to_string()),
                ("port:5433".to_string(), "/data/pg2/log".to_string()),
            ]
        );
    }

    #[test]
    fn out_of_roots_candidates_are_dropped_even_when_they_are_overrides() {
        let roots = vec!["/data".to_string()];
        let escaped = candidate("override", "postgresql", "/etc/pg", "override");
        assert!(resolve_dirs([&escaped].into_iter(), "postgresql", &roots).is_empty());
    }
}
