//! GitHub Release 解析：从 release 页面 URL 拉出 tag（版本）与各平台制品地址（含 sha256）。
//!
//! 供「安装包」页按平台一键填充：输入
//! `https://github.com/<owner>/<repo>/releases/tag/<tag>` → 返回 `{version, assets[]}`，
//! 每个 asset 带 `artifact_url`（`browser_download_url`）、`sha256`（GitHub 资产 `digest`，
//! 缺失为 `None`）与 `platform`（完整 target-triple，如 `aarch64-apple-darwin`；解析不出为 `None`）。
//!
//! 鉴权：公开仓可匿名（受 GitHub 匿名限流 60/h 约束）；私有仓 / 提高限流可设
//! `WIST_GATEWAY_GITHUB_TOKEN`（或回退 `GITHUB_TOKEN`）环境变量。
//!
//! 与中心 `wist-center/src/infra/github.rs` 同款口径（同一份 `read_package_identity` 宽松解析）。

use std::time::Duration;

use serde::Deserialize;

use wist_release::package::read_package_identity;

const GITHUB_API: &str = "https://api.github.com";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// 解析结果：版本（= release tag）与制品清单。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedRelease {
    pub version: String,
    pub assets: Vec<ResolvedAsset>,
}

/// 单个制品：地址 + 摘要 + 平台槽位。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedAsset {
    pub name: String,
    pub artifact_url: String,
    /// GitHub 资产摘要（`sha256:<hex>` 去掉前缀的裸小写 hex）；缺失为 `None`。
    pub sha256: Option<String>,
    /// 完整 target-triple（如 `aarch64-apple-darwin` / `x86_64-unknown-linux-musl`）；
    /// 文件名解析不出为 `None`。
    pub platform: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    /// 例：`sha256:3f9a…`（GitHub 2024 起为资产提供摘要；旧资产可能没有）。
    #[serde(default)]
    digest: Option<String>,
}

/// 从 release 页面 URL 解析出 `(owner, repo, tag)`；
/// 只认 `[https://]github.com/<owner>/<repo>/releases/tag/<tag>`（忽略 query / fragment / 末尾斜杠）。
fn parse_release_url(url: &str) -> Option<(String, String, String)> {
    let url = url.trim();
    let url = url.split(['?', '#']).next().unwrap_or(url);
    let url = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
        .or_else(|| url.strip_prefix("github.com/"))?;
    let url = url.trim_end_matches('/');
    let mut parts = url.splitn(3, '/');
    let owner = parts.next().filter(|value| !value.is_empty())?;
    let repo = parts.next().filter(|value| !value.is_empty())?;
    let rest = parts.next()?;
    let tag = rest.strip_prefix("releases/tag/")?;
    if tag.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string(), tag.to_string()))
}

/// 解析 GitHub release：拉 tag 与资产清单。`token` 为空则匿名请求。
pub async fn resolve_github_release(
    release_url: &str,
    token: Option<&str>,
) -> Result<ResolvedRelease, String> {
    let (owner, repo, tag) = parse_release_url(release_url).ok_or_else(|| {
        "not a GitHub release URL (expected https://github.com/<owner>/<repo>/releases/tag/<tag>)"
            .to_string()
    })?;
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to build http client: {err}"))?;
    let api = format!("{GITHUB_API}/repos/{owner}/{repo}/releases/tags/{tag}");
    let mut request = client
        .get(&api)
        .header("user-agent", "wist-gateway")
        .header("accept", "application/vnd.github+json");
    if let Some(token) = token.filter(|value| !value.is_empty()) {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("failed to reach GitHub: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "GitHub API returned {} for {owner}/{repo}@{tag}",
            response.status()
        ));
    }
    let release: GitHubRelease = response
        .json()
        .await
        .map_err(|err| format!("failed to parse GitHub release payload: {err}"))?;

    let assets = release
        .assets
        .into_iter()
        .map(|asset| {
            // 从**文件名**读完整 target-triple（宽松口径，回落文件名）；读不出即为 None。
            let (_, arch) = read_package_identity(&asset.name, &[]);
            let platform = (!arch.is_empty()).then_some(arch);
            // `sha256:<hex>` → 裸小写 hex。
            let sha256 = asset
                .digest
                .as_deref()
                .and_then(|digest| digest.strip_prefix("sha256:"))
                .map(|hex| hex.trim().to_ascii_lowercase())
                .filter(|hex| !hex.is_empty());
            ResolvedAsset {
                name: asset.name,
                artifact_url: asset.browser_download_url,
                sha256,
                platform,
            }
        })
        .collect();

    Ok(ResolvedRelease {
        version: release.tag_name,
        assets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_urls() {
        assert_eq!(
            parse_release_url("https://github.com/dayu-sec/wist-agentd/releases/tag/v0.2.1-alpha"),
            Some((
                "dayu-sec".to_string(),
                "wist-agentd".to_string(),
                "v0.2.1-alpha".to_string()
            ))
        );
        // 允许末尾斜杠 / query / fragment / 无 scheme。
        assert_eq!(
            parse_release_url("github.com/a/b/releases/tag/v1.0?x=1#y"),
            Some(("a".to_string(), "b".to_string(), "v1.0".to_string()))
        );
        assert_eq!(parse_release_url("https://github.com/a/b"), None);
        assert_eq!(
            parse_release_url("https://gitlab.com/a/b/releases/tag/v1"),
            None
        );
    }

    #[test]
    fn maps_asset_names_to_target_triples() {
        let (_, arch) =
            read_package_identity("wist-agentd-0.2.1-alpha-aarch64-apple-darwin.tar.gz", &[]);
        assert_eq!(arch, "aarch64-apple-darwin");
        let (_, musl) = read_package_identity(
            "wist-agentd-0.2.1-alpha-x86_64-unknown-linux-musl.tar.gz",
            &[],
        );
        assert_eq!(musl, "x86_64-unknown-linux-musl");
        // 非制品（如 .sha256 清单）：读不出平台。
        let (_, none) = read_package_identity("wist-agentd-0.2.1-alpha.sha256", &[]);
        assert!(none.is_empty());
    }
}
