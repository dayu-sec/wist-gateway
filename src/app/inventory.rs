//! L1a 机械资产清单：把「可执行标识集合」归并成清单行。
//!
//! 这里只做**机械**归并（路径 → 软件键 + 展示名），**不做识别**：软件名/版本/vendor 要读
//! **目标机器上的文件**（macOS `Info.plist`、Linux `/var/lib/dpkg/status`），网关读不到 ——
//! 那是采集侧（agentd）的探针工作。归属分层见
//! `doc/design/center/agent-work-delivery-plan.md` §8.2。
//!
//! 为什么规则只有两条：归并结果会作为「这台机器有什么」呈现给运维，**猜测越少越不会误导**。
//! 宁可只把 `.app` 包聚起来、其余按路径原样列出，也不要在这里编造软件身份。

use std::collections::HashSet;

use crate::infra::StoredSoftwareEntry;

/// macOS 应用包后缀。
const APP_BUNDLE_SUFFIX: &str = ".app";
/// 命中规则：`Foo.app/...` → `Foo.app`。
const RULE_APP_BUNDLE: &str = "macos-app-bundle";
/// 命中规则：没有可归并的结构，按路径本身算一项。
const RULE_PATH: &str = "unix-path";
/// 条目类型：macOS 应用包。
pub const KIND_APP: &str = "app";
/// 条目类型：其余可执行路径。
pub const KIND_BINARY: &str = "binary";

/// 把一台机器的可执行标识归并成清单行。
///
/// `executables` 语义上已去重（fact summary 侧用 `BTreeSet` 构造），但这里仍防御性去重：
/// 一条重复路径会撞主键 `(agent_id, path)` 并让整批写入失败。
pub fn derive_inventory(
    agent_id: &str,
    executables: &[String],
    received_at: &str,
) -> Vec<StoredSoftwareEntry> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for raw in executables {
        let path = raw.trim();
        if path.is_empty() || !seen.insert(path) {
            continue;
        }
        let (software_key, name, kind, matched_rule) = match app_bundle_of(path) {
            Some(bundle) => (
                bundle.to_string(),
                app_bundle_name(bundle),
                KIND_APP,
                RULE_APP_BUNDLE,
            ),
            None => (
                path.to_string(),
                basename(path).to_string(),
                KIND_BINARY,
                RULE_PATH,
            ),
        };
        entries.push(StoredSoftwareEntry {
            agent_id: agent_id.to_string(),
            software_key,
            name,
            kind: kind.to_string(),
            matched_rule: matched_rule.to_string(),
            path: path.to_string(),
            received_at: received_at.to_string(),
        });
    }
    entries
}

/// 取路径里**最外层**的 `.app` 包（到 `.app` 为止，含后缀）。
///
/// 取最外层而不是最内层：`WeChat.app/Contents/.../WeChatAppEx.app/...` 应当归到
/// `WeChat.app` —— 运维看到的「装了 WeChat」才是他要的粒度。
fn app_bundle_of(path: &str) -> Option<&str> {
    let index = path.find(&format!("{APP_BUNDLE_SUFFIX}/"))?;
    Some(&path[..index + APP_BUNDLE_SUFFIX.len()])
}

/// `.app` 包的展示名（basename 去掉后缀）。中文/非 ASCII 名字原样保留。
fn app_bundle_name(bundle: &str) -> String {
    let name = basename(bundle);
    name.strip_suffix(APP_BUNDLE_SUFFIX)
        .unwrap_or(name)
        .to_string()
}

/// 路径最后一段。没有 `/` 时（Linux 侧 `comm` 只是裸名）返回原串。
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[index + 1..],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive(paths: &[&str]) -> Vec<StoredSoftwareEntry> {
        let owned: Vec<String> = paths.iter().map(|value| value.to_string()).collect();
        derive_inventory("agent-a", &owned, "2026-09-22T00:00:00Z")
    }

    #[test]
    fn groups_app_bundles_by_the_outer_bundle() {
        let entries = derive(&[
            "/Applications/Firefox.app/Contents/MacOS/firefox",
            "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container",
        ]);
        assert_eq!(entries.len(), 2);
        // 两条路径都归到**最外层**包：运维看到的粒度是「装了 Firefox」。
        assert!(
            entries
                .iter()
                .all(|e| e.software_key == "/Applications/Firefox.app")
        );
        assert!(entries.iter().all(|e| e.name == "Firefox"));
        assert!(entries.iter().all(|e| e.kind == KIND_APP));
        assert!(entries.iter().all(|e| e.matched_rule == RULE_APP_BUNDLE));
    }

    #[test]
    fn keeps_non_bundle_paths_as_their_own_entry() {
        let entries = derive(&["/usr/libexec/sshd-keygen-wrapper", "launchd"]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].software_key, "/usr/libexec/sshd-keygen-wrapper");
        assert_eq!(entries[0].name, "sshd-keygen-wrapper");
        assert_eq!(entries[0].kind, KIND_BINARY);
        // Linux 侧 `comm` 只是裸名：没有 `/` 时 basename 就是原串，不能凭空造路径。
        assert_eq!(entries[1].software_key, "launchd");
        assert_eq!(entries[1].name, "launchd");
    }

    #[test]
    fn keeps_non_ascii_bundle_names() {
        let entries = derive(&["/Applications/微信.app/Contents/MacOS/WeChat"]);
        assert_eq!(entries[0].name, "微信");
        assert_eq!(entries[0].software_key, "/Applications/微信.app");
    }

    #[test]
    fn skips_blank_paths_and_defensively_dedupes() {
        // 一条重复路径会撞主键 (agent_id, path) 并让整批写入失败，所以这里必须挡住。
        let entries = derive(&["/usr/bin/true", "", "   ", "/usr/bin/true"]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/usr/bin/true");
    }

    #[test]
    fn every_entry_carries_the_agent_and_received_at() {
        let entries = derive(&["/usr/bin/true"]);
        assert_eq!(entries[0].agent_id, "agent-a");
        assert_eq!(entries[0].received_at, "2026-09-22T00:00:00Z");
    }
}
