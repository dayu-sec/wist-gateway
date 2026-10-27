//! agentd 版本的比较（知识库声明「最低版本」时用）。
//!
//! ## 为什么不用现成的 semver 依赖
//!
//! 这里只需要**比较**，不需要 range / 解析表达式；而版本串的形态就三种：
//! `0.9.13`、`0.9.13-alpha`、偶尔带 `v` 前缀或 `+build` 后缀。一个 30 行的比较器
//! 比引入依赖更好审，也能明确写出**我们自己的**取舍：
//!
//! * 数字段按数值比较（`0.9.9 < 0.9.13`，不是字符串序）；
//! * 有预发布后缀的**小于**同号正式版（`0.9.13-alpha < 0.9.13`）；
//! * 预发布后缀之间按 semver 的规矩：数字段按数值、字母段按字典序，数字 < 字母。
//!
//! ## 解析失败怎么办
//!
//! * **要求的版本**解析不出来 → 视为「没有要求」（放行）。装载期已经拒载过，
//!   走到这里说明是程序 bug；宁可少拦也不要把整面卡死。
//! * **agent 报的版本**解析不出来 / 没报 → 视为「不满足」（拦）。这正是能力协商的
//!   一贯姿态：拿不准就不派，别派下去换一个 `unsupported`。

use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct AgentVersion {
    /// 数字段（`0.9.13` → `[0, 9, 13]`）。
    parts: Vec<u64>,
    /// 预发布后缀（`alpha` / `beta.1` / `rc.2`）；`None` = 正式版。
    prerelease: Option<String>,
}

/// 相等**以比较为准**：`parse` 会把 `0.9` 补成 `0.9.0`，但预发布标识的数值写法
/// （`rc.01` vs `rc.1`）仍可能“比较相等、字段不等”。从 `cmp` 派生相等就不会自相矛盾。
impl PartialEq for AgentVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for AgentVersion {}

impl AgentVersion {
    pub fn parse(raw: &str) -> Option<Self> {
        let value = raw.trim();
        if value.is_empty() {
            return None;
        }
        // `v0.9.13` / `0.9.13+build.7`：前缀与构建元数据都不参与比较。
        let value = value.strip_prefix('v').unwrap_or(value);
        let value = value.split('+').next().unwrap_or(value);
        let (core, prerelease) = match value.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre.to_string())),
            Some((core, _)) => (core, None),
            None => (value, None),
        };
        let mut parts = Vec::new();
        for segment in core.split('.') {
            // 允许 `0.9`（两段）：缺的段按 0 处理，与 semver 的常见宽松写法一致。
            parts.push(segment.parse::<u64>().ok()?);
        }
        // 允许 `0.9`（两段）：缺的段按 0 处理，与 semver 的常见宽松写法一致。
        while parts.len() < 3 {
            parts.push(0);
        }
        Some(Self { parts, prerelease })
    }

    /// 规范化成可显示 / 可落库的串（去掉 `v` 与 `+build`）。
    pub fn normalized(&self) -> String {
        let core = self
            .parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".");
        match &self.prerelease {
            Some(pre) => format!("{core}-{pre}"),
            None => core,
        }
    }
}

impl Ord for AgentVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // 先比数字段（短的补 0 已在 parse 里做过，这里仍按位比到两者较短的那个）。
        for index in 0..self.parts.len().max(other.parts.len()) {
            let left = self.parts.get(index).copied().unwrap_or(0);
            let right = other.parts.get(index).copied().unwrap_or(0);
            match left.cmp(&right) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        // 数字相同：**没有**预发布后缀的更大（正式版 > 预发布）。
        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => compare_prerelease(left, right),
        }
    }
}

impl PartialOrd for AgentVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(left: &str, right: &str) -> Ordering {
    let left: Vec<&str> = left.split('.').collect();
    let right: Vec<&str> = right.split('.').collect();
    for index in 0..left.len().max(right.len()) {
        match (left.get(index), right.get(index)) {
            (Some(a), Some(b)) => {
                let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                    (Ok(a), Ok(b)) => a.cmp(&b),
                    // 数字标识小于字母标识（semver §11）。
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => a.cmp(b),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            // 标识少的一段更大（`alpha` > `alpha.1`）。
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => break,
        }
    }
    Ordering::Equal
}

/// 两个下限取**高者**（包级 vs 单元级）。
///
/// 一律返回规范化后的串，便于直接展示 / 落库。
pub fn highest(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value.to_string()),
        (Some(left), Some(right)) => {
            match (AgentVersion::parse(left), AgentVersion::parse(right)) {
                (Some(left), Some(right)) => Some(if left >= right {
                    left.normalized()
                } else {
                    right.normalized()
                }),
                // 解析不了的那个不参与（装载期已经拒载，这里是防御）。
                (Some(left), None) => Some(left.normalized()),
                (None, Some(right)) => Some(right.normalized()),
                (None, None) => None,
            }
        }
    }
}

/// 这台机器够不够 `required`。
///
/// `current` = agent 自报的版本（`None` = 还没报过 / 旧版没带）：**不够**。
pub fn meets_minimum(current: Option<&str>, required: &str) -> bool {
    let Some(required) = AgentVersion::parse(required) else {
        // 要求的版本本身不合法：装载期已经拒载过，走到这里说明是程序 bug —— 放行。
        return true;
    };
    let Some(current) = current.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    match AgentVersion::parse(current) {
        Some(current) => current >= required,
        // agent 报了个没法比的东西：拿不准就不放行（与能力协商同一姿态）。
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_segments_are_compared_as_numbers() {
        assert!(meets_minimum(Some("0.9.13"), "0.9.9"));
        assert!(!meets_minimum(Some("0.9.9"), "0.9.13"));
        assert!(meets_minimum(Some("0.10.0"), "0.9.99"));
        assert!(meets_minimum(Some("1.0.0"), "0.99.99"));
    }

    #[test]
    fn a_prerelease_is_older_than_its_release() {
        assert!(!meets_minimum(Some("0.9.13-alpha"), "0.9.13"));
        assert!(meets_minimum(Some("0.9.13"), "0.9.13-alpha"));
        assert!(meets_minimum(Some("0.9.13-beta"), "0.9.13-alpha"));
        assert!(meets_minimum(Some("0.10.0-alpha"), "0.9.13"));
    }

    #[test]
    fn prefixes_and_build_metadata_do_not_matter() {
        assert!(meets_minimum(Some("v0.9.13"), "0.9.13"));
        assert!(meets_minimum(Some("0.9.13+build.7"), "0.9.13"));
        assert_eq!(
            AgentVersion::parse("v1.2.3-rc.1+build").map(|v| v.normalized()),
            Some("1.2.3-rc.1".to_string())
        );
    }

    #[test]
    fn an_unknown_or_unparsable_current_version_is_not_enough() {
        assert!(!meets_minimum(None, "0.9.13"));
        assert!(!meets_minimum(Some(""), "0.9.13"));
        assert!(!meets_minimum(Some("not-a-version"), "0.9.13"));
    }

    #[test]
    fn an_unparsable_requirement_never_blocks() {
        // 装载期会拒载这种值；这里是纵深防御（宁可少拦，也不要把整面卡死）。
        assert!(meets_minimum(Some("0.9.1"), "not-a-version"));
    }

    #[test]
    fn two_segment_versions_are_accepted() {
        assert!(meets_minimum(Some("0.9"), "0.9.0"));
        assert!(!meets_minimum(Some("0.9"), "0.10"));
    }
}
