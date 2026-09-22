//! 用途推断：按规则表从事实摘要算出「建议 + 逐条依据 + 置信度」。
//!
//! 规则线在网关（可解释、可测、离线自足），规则表本身是**策展数据**
//! （模型仓 `jumo/model/content/purpose-rules.toml`），改它要走审定。
//!
//! 所以这里只**读**表，不在代码里内嵌默认副本 —— 内嵌就会有两份真相，
//! 改规则时必然漂移（这也是把发现方向策略值放进 jumo 模型的同一条理由）。
//! 未配置规则表时：摘要照常入库，但不产出建议（宁可不猜）。

use std::collections::BTreeMap;
use std::path::Path;

use orion_error::prelude::*;
use serde::Deserialize;
use wist_error::{ConfigReason, ConfigResult};

use crate::infra::{StoredAgentFactSummary, StoredPurposeSignal, StoredPurposeSuggestion};

/// 规则表：按平台分册的集合。
///
/// TOML 形状是 `[[rule_set]]` + `[[rule_set.rules]]`，因此字段名就是 `rule_set`。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PurposeRuleTable {
    #[serde(default)]
    rule_set: Vec<PurposeRuleSet>,
}

/// 某一平台的规则全集（对应模型 `PurposeRuleSet`）。
#[derive(Debug, Clone, Deserialize)]
pub struct PurposeRuleSet {
    pub rule_set_id: String,
    /// `macos` / `linux`（与 agentd 上报的 `os` 同源：`std::env::consts::OS`）。
    pub platform: String,
    /// **无任何规则命中**时的基线类别；留空 = 不产出建议（宁可不猜）。
    #[serde(default)]
    pub baseline_class: Option<String>,
    /// 低于此总分视为「信号太弱」，置信度打折。
    #[serde(default)]
    pub weak_score: i64,
    #[serde(default)]
    pub published_at: Option<String>,
    #[serde(default)]
    pub rules: Vec<PurposeRule>,
}

/// 一条规则（对应模型 `PurposeRule`）。
#[derive(Debug, Clone, Deserialize)]
pub struct PurposeRule {
    pub rule_id: String,
    /// `process` / `process_path` / `listen_port` / `package` / `unit`。
    pub kind: String,
    pub pattern: String,
    /// 命中 `pattern` 但同时也命中这里的，不算命中。
    #[serde(default)]
    pub exclude_pattern: Option<String>,
    /// 空 = 只留依据不加分。
    #[serde(default)]
    pub machine_class: Option<String>,
    /// 强特征 ~40、中 ~30、弱 ~10~20；可为负，表示反向证据。
    #[serde(default)]
    pub weight: i64,
}

impl PurposeRuleTable {
    /// 取该平台的规则册。两个平台判据完全不同，一台机器只用自己那册。
    pub fn for_platform(&self, platform: &str) -> Option<&PurposeRuleSet> {
        self.rule_set.iter().find(|set| set.platform == platform)
    }

    pub fn is_empty(&self) -> bool {
        self.rule_set.is_empty()
    }
}

/// 从文件装载规则表。
pub fn load_rule_table(path: &Path) -> ConfigResult<PurposeRuleTable> {
    let text =
        std::fs::read_to_string(path).source_err(ConfigReason::Io, "read purpose rule table")?;
    parse_rule_table(&text)
}

/// 解析规则表文本（测试与热加载都用它，避免只能通过文件系统验证）。
pub fn parse_rule_table(text: &str) -> ConfigResult<PurposeRuleTable> {
    // 与 config.rs 一致：toml 的 error 走 `source_raw_err`，`source_err` 的 trait bound 不满足。
    toml::from_str(text).source_raw_err(ConfigReason::Parse, "parse purpose rule table")
}

/// 命中判定：大小写不敏感子串。
///
/// 排除是按**值**判的，不是按机器：`/Applications/WorkBuddy.app/…/node_modules`
/// 这条路径既含 `node_modules` 也含 `/Applications/`，于是不算开发特征 ——
/// 它是「装了应用」，不是「在开发」。
fn value_matches(value: &str, pattern: &str, exclude_pattern: Option<&str>) -> bool {
    let haystack = value.to_lowercase();
    if !haystack.contains(&pattern.to_lowercase()) {
        return false;
    }
    match exclude_pattern {
        Some(exclude) if !exclude.is_empty() => !haystack.contains(&exclude.to_lowercase()),
        _ => true,
    }
}

/// 某类规则在哪个信号集合上匹配。
///
/// `unit`（采集单元）不在摘要里：摘要只带「机械可压缩」的事实，单元是否有规则
/// 属于内容就绪度，不该由 agentd 报。
fn signals_for<'a>(
    rule: &PurposeRule,
    summary: &'a StoredAgentFactSummary,
) -> Option<&'a [String]> {
    match rule.kind.as_str() {
        "process" | "process_path" => Some(&summary.process_executables),
        "package" => Some(&summary.packages),
        "listen_port" => Some(&summary.listen_ports),
        _ => None,
    }
}

/// 取最高分与次高分。同分时按类别名定序（`BTreeMap` 已按 key 有序），保证可复现。
fn top_two(scores: &BTreeMap<String, i64>) -> Option<(String, i64, i64)> {
    let mut ranked: Vec<(&String, i64)> = scores.iter().map(|(key, value)| (key, *value)).collect();
    ranked.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    let (first, highest) = ranked.first().copied()?;
    let second = ranked.get(1).map(|(_, value)| *value).unwrap_or(0);
    Some((first.clone(), highest, second))
}

/// 按规则表推断用途。
///
/// 计分与规则表头部注释一致：命中即给该类加一次 `weight`（**与命中次数无关**，
/// 所以去重后的摘要正好够用），再取 `s1`/`s2` 算
/// `confidence = 100 × (s1 − s2) / s1`，总分低于 `weak_score` 再打对折。
///
/// 返回 `None` 只表示「不该给出建议」：平台无规则册，或既无规则命中又无基线类别。
pub fn infer(
    summary: &StoredAgentFactSummary,
    table: &PurposeRuleTable,
    suggestion_id: &str,
    computed_at: &str,
) -> Option<StoredPurposeSuggestion> {
    let rule_set = table.for_platform(&summary.os)?;

    let mut scores: BTreeMap<String, i64> = BTreeMap::new();
    let mut signals: Vec<StoredPurposeSignal> = Vec::new();
    for rule in &rule_set.rules {
        let Some(values) = signals_for(rule, summary) else {
            continue;
        };
        let Some(matched) = values
            .iter()
            .find(|value| value_matches(value, &rule.pattern, rule.exclude_pattern.as_deref()))
        else {
            continue;
        };
        // 只留依据不加分的规则（machine_class 为空）也要进依据列表。
        if let Some(class) = rule.machine_class.as_deref() {
            *scores.entry(class.to_string()).or_insert(0) += rule.weight;
        }
        signals.push(StoredPurposeSignal {
            rule_id: rule.rule_id.clone(),
            kind: rule.kind.clone(),
            value: matched.clone(),
            weight: rule.weight,
        });
    }

    let (suggested_class, confidence) = match top_two(&scores) {
        Some((class, highest, second)) if highest > 0 => {
            let mut confidence = 100 * (highest - second) / highest;
            if highest < rule_set.weak_score {
                confidence /= 2;
            }
            // 反向证据（负权重）会把 s2 拉到负数，公式可能算出 >100，夹回来。
            (class, confidence.clamp(0, 100))
        }
        // 无规则命中、总分不为正：有基线就用基线（置信度 0），没有就不给建议。
        _ => (rule_set.baseline_class.clone()?, 0),
    };

    Some(StoredPurposeSuggestion {
        agent_id: summary.agent_id.clone(),
        suggestion_id: suggestion_id.to_string(),
        suggested_class,
        confidence,
        method: "rule".to_string(),
        rule_set_id: Some(rule_set.rule_set_id.clone()),
        signals,
        observed_at: summary.observed_at.clone(),
        computed_at: computed_at.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE_TABLE: &str = r#"
[[rule_set]]
rule_set_id = "macos-v1"
platform = "macos"
baseline_class = "MacDaily"
weak_score = 20

[[rule_set.rules]]
rule_id = "mac-dev-xcodebuild"
kind = "process"
pattern = "xcodebuild"
machine_class = "MacDev"
weight = 40

[[rule_set.rules]]
rule_id = "mac-dev-homebrew-arm"
kind = "process_path"
pattern = "/opt/homebrew"
machine_class = "MacDev"
weight = 30

[[rule_set.rules]]
rule_id = "mac-dev-node-modules"
kind = "process_path"
pattern = "node_modules"
exclude_pattern = "/Applications/"
machine_class = "MacDev"
weight = 20

[[rule_set.rules]]
rule_id = "mac-daily-safari"
kind = "process_path"
pattern = "/Safari.app"
machine_class = "MacDaily"
weight = 10

[[rule_set.rules]]
rule_id = "evidence-only"
kind = "process"
pattern = "launchd"
weight = 0

[[rule_set]]
rule_set_id = "linux-v1"
platform = "linux"
weak_score = 20

[[rule_set.rules]]
rule_id = "linux-data-postgres"
kind = "process"
pattern = "postgres"
machine_class = "LinuxData"
weight = 40
"#;

    fn summary(os: &str, processes: &[&str]) -> StoredAgentFactSummary {
        StoredAgentFactSummary {
            agent_id: "agent-001".to_string(),
            content_digest: "sha256:digest".to_string(),
            revision: 1,
            observed_at: "2026-09-22T00:00:00Z".to_string(),
            os: os.to_string(),
            arch: "arm64".to_string(),
            process_count: processes.len() as i64,
            process_executables: processes.iter().map(|value| value.to_string()).collect(),
            packages: Vec::new(),
            listen_ports: Vec::new(),
            received_at: "2026-09-22T00:00:01Z".to_string(),
        }
    }

    fn table() -> PurposeRuleTable {
        parse_rule_table(RULE_TABLE).expect("parse rule table")
    }

    #[test]
    fn scores_matched_rules_and_lists_evidence() {
        let suggestion = infer(
            &summary("macos", &["/Applications/Xcode.app/xcodebuild", "launchd"]),
            &table(),
            "sug-1",
            "2026-09-22T00:00:02Z",
        )
        .expect("suggestion");

        assert_eq!(suggestion.suggested_class, "MacDev");
        // 40 分、无次高分 → 100；40 >= weak_score(20) 不打折。
        assert_eq!(suggestion.confidence, 100);
        assert_eq!(suggestion.rule_set_id.as_deref(), Some("macos-v1"));
        assert_eq!(suggestion.method, "rule");
        assert_eq!(suggestion.observed_at, "2026-09-22T00:00:00Z");
        assert_eq!(suggestion.computed_at, "2026-09-22T00:00:02Z");
        // 只留依据不加分的规则也要在依据里。
        let rule_ids: Vec<&str> = suggestion
            .signals
            .iter()
            .map(|signal| signal.rule_id.as_str())
            .collect();
        assert_eq!(rule_ids, vec!["mac-dev-xcodebuild", "evidence-only"]);
        assert_eq!(
            suggestion.signals[0].value,
            "/Applications/Xcode.app/xcodebuild"
        );
        assert_eq!(suggestion.signals[0].kind, "process");
        assert_eq!(suggestion.signals[0].weight, 40);
    }

    #[test]
    fn exclude_pattern_disqualifies_the_value_not_the_rule() {
        // WorkBuddy 自带的 node_modules 与真正开发目录共存：被排除的那条路径不算命中，
        // 但 /opt/homebrew 仍然算。
        let suggestion = infer(
            &summary(
                "macos",
                &[
                    "/Applications/WorkBuddy.app/Contents/Resources/node_modules/x",
                    "/opt/homebrew/bin/mise",
                ],
            ),
            &table(),
            "sug-1",
            "2026-09-22T00:00:02Z",
        )
        .expect("suggestion");

        assert_eq!(suggestion.suggested_class, "MacDev");
        let rule_ids: Vec<&str> = suggestion
            .signals
            .iter()
            .map(|signal| signal.rule_id.as_str())
            .collect();
        assert_eq!(rule_ids, vec!["mac-dev-homebrew-arm"]);
    }

    #[test]
    fn a_rule_scores_once_however_many_values_match() {
        // 去重后的摘要 + 「命中即加一次分」：多条 homebrew 路径不会把分数堆高。
        let one = infer(
            &summary("macos", &["/opt/homebrew/bin/mise"]),
            &table(),
            "s",
            "t",
        )
        .expect("suggestion");
        let many = infer(
            &summary(
                "macos",
                &[
                    "/opt/homebrew/bin/mise",
                    "/opt/homebrew/bin/rg",
                    "/opt/homebrew/Cellar/foo",
                ],
            ),
            &table(),
            "s",
            "t",
        )
        .expect("suggestion");
        assert_eq!(one.confidence, many.confidence);
        assert_eq!(one.signals.len(), many.signals.len());
    }

    #[test]
    fn confidence_is_the_margin_over_the_runner_up() {
        // MacDev 40 对 MacDaily 10 → 100 × 30 / 40 = 75。
        let suggestion = infer(
            &summary(
                "macos",
                &[
                    "/Applications/Xcode.app/xcodebuild",
                    "/Applications/Safari.app/x",
                ],
            ),
            &table(),
            "s",
            "t",
        )
        .expect("suggestion");
        assert_eq!(suggestion.suggested_class, "MacDev");
        assert_eq!(suggestion.confidence, 75);
    }

    #[test]
    fn weak_signal_halves_the_confidence() {
        // Safari 10 分：命中 MacDaily，但 10 < weak_score(20) → 100 打对折。
        let suggestion = infer(
            &summary("macos", &["/Applications/Safari.app/Contents/MacOS/Safari"]),
            &table(),
            "s",
            "t",
        )
        .expect("suggestion");
        assert_eq!(suggestion.suggested_class, "MacDaily");
        assert_eq!(suggestion.confidence, 50);
    }

    #[test]
    fn falls_back_to_baseline_with_zero_confidence() {
        let suggestion = infer(
            &summary("macos", &["/usr/bin/some-unknown-tool"]),
            &table(),
            "s",
            "t",
        )
        .expect("baseline suggestion");
        assert_eq!(suggestion.suggested_class, "MacDaily");
        assert_eq!(suggestion.confidence, 0);
        assert!(suggestion.signals.is_empty());
    }

    #[test]
    fn no_rule_set_for_the_platform_means_no_suggestion() {
        // linux 那册没有 baseline_class：无命中就不猜（`None` 不是空建议）。
        assert!(infer(&summary("linux", &["/usr/bin/nothing"]), &table(), "s", "t").is_none());
        // 完全认不出的平台更是如此。
        assert!(infer(&summary("windows", &[]), &table(), "s", "t").is_none());
    }

    #[test]
    fn linux_rules_match_on_process_names() {
        let suggestion = infer(&summary("linux", &["postgres", "sshd"]), &table(), "s", "t")
            .expect("suggestion");
        assert_eq!(suggestion.suggested_class, "LinuxData");
        assert_eq!(suggestion.confidence, 100);
        assert_eq!(suggestion.rule_set_id.as_deref(), Some("linux-v1"));
    }

    #[test]
    fn package_and_port_rules_read_their_own_signal_sets() {
        let mut facts = summary("linux", &[]);
        facts.packages = vec!["postgresql-16".to_string()];
        facts.listen_ports = vec!["5432".to_string()];
        let suggestion = infer(&facts, &table(), "s", "t");
        // 这份精简规则表里没有 package/port 规则，但换用真的规则表时走的是同一条路径；
        // 这里断言 signals_for 不会把包名当进程名看。
        assert!(suggestion.is_none() || suggestion.unwrap().signals.is_empty());
    }

    #[test]
    fn parses_the_checked_in_rule_table() {
        // 真实策展数据必须能解析（防止手改 TOML 后网关静默不推断）。
        let path = std::path::Path::new("../../wist-design/jumo/model/content/purpose-rules.toml");
        if !path.exists() {
            return;
        }
        let table = load_rule_table(path).expect("load checked-in rule table");
        assert!(!table.is_empty());
        let macos = table.for_platform("macos").expect("macos rule set");
        assert_eq!(macos.rule_set_id, "macos-v1");
        assert_eq!(macos.baseline_class.as_deref(), Some("MacDaily"));
        let linux = table.for_platform("linux").expect("linux rule set");
        assert_eq!(linux.rule_set_id, "linux-v1");
        // 两个平台判据完全不同，所以必须各有一册。
        assert!(!macos.rules.is_empty());
        assert!(!linux.rules.is_empty());
    }
}
