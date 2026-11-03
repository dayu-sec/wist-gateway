//! 发现方向策略表：平台策展，网关启动时装载并**校验**，再通过控制面下发给 agentd。
//!
//! 与用途规则表同类（`purpose.rs`）：表本身是**策展数据**
//! （知识库仓 `wist-knowledge/aspect-policies.toml`），改它要走审定。
//! 所以这里只**读**表，不在代码里内嵌默认副本 —— 内嵌就会有两份真相，
//! 改策略时必然漂移（agentd 的 `refresh_interval()` 里那份字面量正是漂移的样本）。
//! 未配置策略表时不提供端点：agentd 继续用自己的内建默认值，行为与从前一致。
//!
//! 为什么必须在装载期拦：表是**手写的**，写错一个字的后果是静默的 ——
//! 少一条方向、平台拼错、周期区间颠倒，都不会让任何一处报错，只会让 agentd
//! 悄悄回落到内建默认值，于是「发布了一份半截表」看起来与「成功发布」没有区别。
//! 宁可在启动时失败并指出是哪条方向，也不要静默地不下发。

use std::collections::BTreeSet;
use std::path::Path;

use orion_error::conversion::ToStructError;
use orion_error::prelude::*;
use wist_contracts::discovery_policy::{
    DISCOVERY_ASPECTS, DISCOVERY_PLATFORMS, DiscoveryAspectPolicy, DiscoveryAspectPolicySet,
};
use wist_error::{ConfigError, ConfigReason, ConfigResult};

/// 从文件装载策略表。
pub fn load_policy_table(path: &Path) -> ConfigResult<DiscoveryAspectPolicySet> {
    let text = std::fs::read_to_string(path)
        .source_err(ConfigReason::Io, "read discovery aspect policy table")?;
    parse_policy_table(&text)
}

/// 解析策略表文本（测试与热加载都用它，避免只能通过文件系统验证）。
pub fn parse_policy_table(text: &str) -> ConfigResult<DiscoveryAspectPolicySet> {
    // 与 config.rs 一致：toml 的 error 走 `source_raw_err`，`source_err` 的 trait bound 不满足。
    let mut set: DiscoveryAspectPolicySet = toml::from_str(text)
        .source_raw_err(ConfigReason::Parse, "parse discovery aspect policy table")?;
    validate_policy_table(&mut set)?;
    Ok(set)
}

fn invalid(detail: impl Into<String>) -> ConfigError {
    ConfigReason::Validation.to_err().with_detail(detail)
}

/// 装载期校验。
///
/// 逐条方向先查（未知/重复/区间/开关/平台），最后再查**缺项**：缺一条方向时
/// agentd 会静默回落到它自己的内建默认值，于是一份「半发布」的表看起来与成功发布
/// 没有区别 —— 所以缺项必须在这里被拦下，而不是留给运行期去发现。
fn validate_policy_table(set: &mut DiscoveryAspectPolicySet) -> ConfigResult<()> {
    if set.policy_version < 1 {
        return Err(invalid(format!(
            "policy_version {} must be >= 1",
            set.policy_version
        )));
    }
    if set.published_at.trim().is_empty() {
        return Err(invalid("empty published_at"));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for policy in &set.policies {
        validate_policy(policy, &mut seen)?;
    }
    for aspect in DISCOVERY_ASPECTS {
        if !seen.contains(aspect) {
            return Err(invalid(format!(
                "missing aspect {aspect:?} (expected exactly one policy for each of {DISCOVERY_ASPECTS:?})"
            )));
        }
    }
    Ok(())
}

fn validate_policy<'a>(
    policy: &'a DiscoveryAspectPolicy,
    seen: &mut BTreeSet<&'a str>,
) -> ConfigResult<()> {
    let aspect = policy.aspect.as_str();
    if !DISCOVERY_ASPECTS.contains(&aspect) {
        return Err(invalid(format!(
            "unknown aspect {aspect:?} (expected one of {DISCOVERY_ASPECTS:?})"
        )));
    }
    if !seen.insert(aspect) {
        return Err(invalid(format!("duplicate aspect {aspect:?}")));
    }
    if policy.min_interval_seconds < 1 {
        return Err(invalid(format!(
            "aspect {aspect}: min_interval_seconds {} must be >= 1",
            policy.min_interval_seconds
        )));
    }
    if policy.default_interval_seconds < policy.min_interval_seconds {
        return Err(invalid(format!(
            "aspect {aspect}: default_interval_seconds {} < min_interval_seconds {}",
            policy.default_interval_seconds, policy.min_interval_seconds
        )));
    }
    if policy.default_interval_seconds > policy.max_interval_seconds {
        return Err(invalid(format!(
            "aspect {aspect}: default_interval_seconds {} > max_interval_seconds {}",
            policy.default_interval_seconds, policy.max_interval_seconds
        )));
    }
    // 基线面回答「我是什么」，是自识别与派活的底座：把它关掉等于让 gateway 认不出
    // 这台机器是什么，所以 baseline 的方向不允许默认关。
    if policy.baseline && !policy.enabled_by_default {
        return Err(invalid(format!(
            "aspect {aspect}: baseline aspect must be enabled_by_default"
        )));
    }
    // 空平台等于「所有平台都不采」：声明了却永远产出为空的方向不该报。
    if policy.platforms.is_empty() {
        return Err(invalid(format!("aspect {aspect}: empty platforms")));
    }
    for platform in &policy.platforms {
        if !DISCOVERY_PLATFORMS.contains(&platform.as_str()) {
            return Err(invalid(format!(
                "aspect {aspect}: unknown platform {platform:?} (expected one of {DISCOVERY_PLATFORMS:?})"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一条方向的 TOML 片段；默认值全部合法，用例按需改一处来验某条规则。
    struct PolicyText {
        aspect: &'static str,
        default: i64,
        min: i64,
        max: i64,
        baseline: bool,
        enabled: bool,
        platforms: &'static str,
        extra: &'static str,
    }

    impl Default for PolicyText {
        fn default() -> Self {
            Self {
                aspect: "host",
                default: 300,
                min: 60,
                max: 1800,
                baseline: false,
                enabled: true,
                platforms: r#"["macos", "linux"]"#,
                extra: "",
            }
        }
    }

    impl PolicyText {
        fn render(&self) -> String {
            format!(
                "\n[[policies]]\naspect = \"{}\"\ndefault_interval_seconds = {}\n\
                 min_interval_seconds = {}\nmax_interval_seconds = {}\nbaseline = {}\n\
                 enabled_by_default = {}\nplatforms = {}\nyields = \"x\"\n{}",
                self.aspect,
                self.default,
                self.min,
                self.max,
                self.baseline,
                self.enabled,
                self.platforms,
                self.extra
            )
        }
    }

    /// 用给定方向列表拼一份表（版本/发布时间取合法值）。
    fn table_from(aspects: &[&'static str]) -> String {
        let mut body = String::new();
        for aspect in aspects.iter().copied() {
            body.push_str(
                &PolicyText {
                    aspect,
                    ..PolicyText::default()
                }
                .render(),
            );
        }
        format!("policy_version = 1\npublished_at = \"2026-09-22T00:00:00Z\"\n{body}")
    }

    /// 七个方向各一条的合法表。
    fn valid_table() -> String {
        let mut body = String::new();
        for aspect in DISCOVERY_ASPECTS {
            body.push_str(
                &PolicyText {
                    aspect,
                    // host 是基线面：必须默认开，否则触发 baseline 那条校验。
                    baseline: aspect == "host",
                    ..PolicyText::default()
                }
                .render(),
            );
        }
        format!("policy_version = 1\npublished_at = \"2026-09-22T00:00:00Z\"\n{body}")
    }

    /// 单条方向的表，供逐条拒绝用例使用（缺项检查在逐条之后，所以单条即可命中）。
    fn table_with_one(policy: &PolicyText) -> String {
        format!(
            "policy_version = 1\npublished_at = \"2026-09-22T00:00:00Z\"\n{}",
            policy.render()
        )
    }

    #[test]
    fn parses_a_valid_table() {
        let set = parse_policy_table(&valid_table()).expect("valid table parses");
        assert_eq!(set.policy_version, 1);
        assert_eq!(set.policies.len(), DISCOVERY_ASPECTS.len());
        assert!(set.for_aspect("host").expect("host policy").baseline);
        assert_eq!(set.interval_seconds_for("host"), Some(300));
    }

    #[test]
    fn parses_the_checked_in_policy_table() {
        // 真实策展数据必须能通过校验（防止手改 TOML 后网关带病下发）。
        let path = crate::test_support::knowledge_file("aspect-policies.toml");
        let set = load_policy_table(&path).expect("load checked-in policy table");
        assert!(set.policy_version >= 1);
        assert_eq!(set.policies.len(), DISCOVERY_ASPECTS.len());
        for aspect in DISCOVERY_ASPECTS {
            assert!(set.for_aspect(aspect).is_some(), "missing aspect {aspect}");
        }
        assert!(set.for_aspect("host").expect("host policy").baseline);
    }

    // ── 逐条拒绝规则（手写策展数据的笔误必须在这里被拦住）─────────────────

    #[test]
    fn rejects_a_version_below_one() {
        let text = format!(
            "policy_version = 0\npublished_at = \"x\"\n{}",
            PolicyText::default().render()
        );
        let err = parse_policy_table(&text).expect_err("version 0 must be rejected");
        assert!(err.to_string().contains("policy_version"), "{err}");
    }

    #[test]
    fn rejects_an_empty_published_at() {
        let text = format!(
            "policy_version = 1\npublished_at = \"   \"\n{}",
            PolicyText::default().render()
        );
        let err = parse_policy_table(&text).expect_err("blank published_at must be rejected");
        assert!(err.to_string().contains("published_at"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_aspect() {
        let text = table_with_one(&PolicyText {
            aspect: "gpu",
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("unknown aspect must be rejected");
        assert!(err.to_string().contains("unknown aspect"), "{err}");
    }

    #[test]
    fn rejects_a_duplicate_aspect() {
        let text = format!(
            "policy_version = 1\npublished_at = \"x\"\n{}{}",
            PolicyText::default().render(),
            PolicyText::default().render()
        );
        let err = parse_policy_table(&text).expect_err("duplicate aspect must be rejected");
        assert!(err.to_string().contains("duplicate aspect"), "{err}");
    }

    #[test]
    fn rejects_a_missing_aspect() {
        // 少一条：agentd 会静默回落到内建默认值，半发布的表看起来像成功发布。
        let incomplete: Vec<&str> = DISCOVERY_ASPECTS
            .iter()
            .copied()
            .filter(|aspect| *aspect != "package")
            .collect();
        let err =
            parse_policy_table(&table_from(&incomplete)).expect_err("missing must be rejected");
        assert!(err.to_string().contains("missing aspect"), "{err}");
        assert!(err.to_string().contains("package"), "{err}");
    }

    #[test]
    fn rejects_a_min_interval_below_one() {
        let text = table_with_one(&PolicyText {
            min: 0,
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("min < 1 must be rejected");
        assert!(err.to_string().contains("min_interval_seconds"), "{err}");
    }

    #[test]
    fn rejects_a_default_below_min() {
        let text = table_with_one(&PolicyText {
            default: 30,
            min: 60,
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("default < min must be rejected");
        assert!(
            err.to_string().contains("default_interval_seconds"),
            "{err}"
        );
    }

    #[test]
    fn rejects_a_default_above_max() {
        let text = table_with_one(&PolicyText {
            default: 9999,
            max: 1800,
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("default > max must be rejected");
        assert!(err.to_string().contains("max_interval_seconds"), "{err}");
    }

    #[test]
    fn rejects_a_baseline_aspect_that_is_disabled() {
        // 基线面不可关：关掉它等于让网关认不出这台机器是什么。
        let text = table_with_one(&PolicyText {
            baseline: true,
            enabled: false,
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("disabled baseline must be rejected");
        assert!(err.to_string().contains("baseline"), "{err}");
    }

    #[test]
    fn rejects_empty_platforms() {
        let text = table_with_one(&PolicyText {
            platforms: "[]",
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("empty platforms must be rejected");
        assert!(err.to_string().contains("empty platforms"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_platform() {
        // 平台拼错会让这条方向永远不被授权下去，而且不报错。
        let text = table_with_one(&PolicyText {
            platforms: r#"["windows"]"#,
            ..PolicyText::default()
        });
        let err = parse_policy_table(&text).expect_err("unknown platform must be rejected");
        assert!(err.to_string().contains("unknown platform"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        // 多出来的字段必须是响亮的错误，而不是静默忽略：静默忽略会让笔误（比如把
        // `default_interval_seconds` 拼错）被当成「没配置」而悄悄用上默认值。
        let text = table_with_one(&PolicyText {
            extra: "default_intervall_seconds = 300\n",
            ..PolicyText::default()
        });
        assert!(parse_policy_table(&text).is_err());
    }
}
