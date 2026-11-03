//! 腾讯 COS 路径解析：把一个 `bucket + component/version` 前缀展开成各平台制品的
//! 下载地址 / sha256 / 平台 —— 镜像 [`crate::infra::github`] 的 GitHub release 解析。
//!
//! 供网关「安装包录入」页一键填充多平台制品：输入
//! `github-1347593047/wist-gwlinkd/v0.9.3-alpha`（或 `cos://…` / 带 region 的下载地址）→
//! 返回 `{version, assets[]}`，每个 asset 带 `artifact_url`（COS 虚拟主机公开地址）、
//! `sha256`（对象自定义元数据 `x-cos-meta-artifact-sha256`，缺失为 `None`）与
//! `platform`（完整 target-triple，如 `x86_64-unknown-linux-musl`；单制品为 `None`）。
//!
//! **无凭据**：制品桶是「公有读私有写」（对象可匿名 GET，列对象匿名被拒），且上传时把 sha256
//! 写进了对象自定义元数据。因此这里不依赖对象存储凭据，也不做 ListObjects —— 而是按发布
//! 流水线的**命名约定**拼出候选对象地址（`<组件>/<版本>/<组件>-<版本>[-<三元组>].tar.gz`），
//! 逐个匿名 `HEAD` 校验并读回 sha256。（浏览器端做不了：COS 未开 CORS，故由网关代劳。）
//!
//! 与中心 `wist-center/src/infra/cos.rs` 同款口径（桶 / 命名约定 / 元数据头 / region 探测）。

use std::time::Duration;

use super::github::{ResolvedAsset, ResolvedRelease};

/** COS 自定义元数据里承载 sha256 的对象头（COS 只存 MD5 ETag，sha256 得随对象自带）。 */
const COS_SHA256_HEADER: &str = "x-cos-meta-artifact-sha256";
/** 覆盖 region 的环境变量（设定后只用它，不逐个试）。 */
const COS_REGION_ENV: &str = "WIST_GATEWAY_COS_REGION";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/**
 * 没在路径 / env 里指定 region 时**逐个尝试**的候选区域（命中即止）。
 *
 * 为什么得试：COS 的下载 host 里带 region（`<桶>.cos.<region>.myqcloud.com`），**地址不固定**；
 * 用错 region 时 COS 只回 404（不给重定向、不提示正确 region），也没有开全局加速域名。
 * 所以「能取到对象的那个 region」就是对的。顺序按常见度排，桶在靠后区域时会多花几跳。
 */
const REGION_CANDIDATES: [&str; 16] = [
    "ap-guangzhou",
    "ap-hongkong",
    "ap-shanghai",
    "ap-beijing",
    "ap-nanjing",
    "ap-chengdu",
    "ap-chongqing",
    "ap-singapore",
    "ap-seoul",
    "ap-tokyo",
    "ap-bangkok",
    "ap-mumbai",
    "ap-siliconvalley",
    "na-siliconvalley",
    "na-ashburn",
    "eu-frankfurt",
];

/// 多平台组件在发布矩阵里的三元组（与各仓 release.yml 的 `matrix.target`、网关侧
/// `install_package.rs` 的 `PLATFORM_*` 同表）。单制品组件（如 `wist-gateway-stack`）不带三元组，
/// 由 [`resolve_cos_path`] 另外补一个「无三元组」候选。
const KNOWN_PLATFORMS: [&str; 3] = [
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
];

/// 归一化后的 COS 路径：桶、键前缀、以及（虚拟主机写法里的）region。
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCosPath {
    bucket: String,
    prefix: String,
    region: Option<String>,
}

/// 把 `(bucket, prefix, region)` 归整：去空白、prefix 去末尾斜杠；桶或前缀为空即报错。
fn assemble(bucket: &str, prefix: &str, region: Option<String>) -> Result<ParsedCosPath, String> {
    let bucket = bucket.trim();
    let prefix = prefix.trim().trim_end_matches('/');
    if bucket.is_empty() {
        return Err("cos path bucket must not be empty".to_string());
    }
    if prefix.is_empty() {
        return Err("cos path prefix must not be empty".to_string());
    }
    Ok(ParsedCosPath {
        bucket: bucket.to_string(),
        prefix: prefix.to_string(),
        region,
    })
}

/// 解析 COS 路径。接受三种写法（忽略 query / fragment 与末尾斜杠）：
/// 1. `cos://<bucket>/<prefix...>`（coscli 的 `cos://` URL）；
/// 2. `<bucket>/<prefix...>`（裸 bucket + 键前缀，bucket = 首段）；
/// 3. `https://<bucket>.cos.<region>.myqcloud.com/<prefix...>`（虚拟主机下载地址，region 从中读出）。
fn parse_cos_path(cos_path: &str) -> Result<ParsedCosPath, String> {
    let raw = cos_path.trim();
    if raw.is_empty() {
        return Err("cos path must not be empty".to_string());
    }
    // 去掉 query / fragment（对三种写法都适用）。
    let raw = raw.split(['?', '#']).next().unwrap_or(raw);

    if let Some(rest) = raw.strip_prefix("cos://") {
        let rest = rest.trim_end_matches('/');
        let (bucket, prefix) = rest.split_once('/').ok_or_else(|| {
            "cos path must include a bucket and a prefix (cos://<bucket>/<prefix>)".to_string()
        })?;
        return assemble(bucket, prefix, None);
    }

    for scheme in ["https://", "http://"] {
        if let Some(rest) = raw.strip_prefix(scheme) {
            let host_end = rest
                .find('/')
                .ok_or_else(|| "cos path must include an object prefix".to_string())?;
            let host = &rest[..host_end];
            let path = rest[host_end + 1..].trim_end_matches('/');
            // 虚拟主机风格：`<bucket>.cos.<region>.myqcloud.com` → bucket + region 都读得出；
            // 否则（path 风格）退回「首段即 bucket」，region 留空（交给默认值 / env）。
            return match host.split_once(".cos.") {
                Some((bucket, rest)) => {
                    let region = rest.split('.').next().filter(|value| !value.is_empty());
                    assemble(bucket, path, region.map(str::to_string))
                }
                None => {
                    let (bucket, prefix) = path
                        .split_once('/')
                        .ok_or_else(|| "cos path must include a bucket and a prefix".to_string())?;
                    assemble(bucket, prefix, None)
                }
            };
        }
    }

    // 裸 `<bucket>/<prefix...>`。
    let raw = raw.trim_end_matches('/');
    let (bucket, prefix) = raw.split_once('/').ok_or_else(|| {
        "cos path must include a bucket and a prefix (expected <bucket>/<prefix>)".to_string()
    })?;
    assemble(bucket, prefix, None)
}

/// 归一化 sha256：去空白、小写；空即 `None`。
fn normalize_sha256(value: Option<&str>) -> Option<String> {
    value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

/// region 取值：路径里带（虚拟主机写法）> `WIST_GATEWAY_COS_REGION`；都没有返回 `None`
/// （调用方按 [`REGION_CANDIDATES`] 逐个试 —— 用错 region 时 COS 回 404，取得到的那个就是对的）。
fn resolve_region(from_path: Option<String>) -> Option<String> {
    from_path
        .or_else(|| std::env::var(COS_REGION_ENV).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 解析 COS 路径：按命名约定拼出候选制品地址，逐个匿名 `HEAD`，保留存在的那些。
///
/// 约定（与各仓 release.yml 的 `upload-cos` 一致）：对象键为
/// `{prefix}/{组件}-{版本}[-{三元组}].tar.gz`，其中 `prefix = {组件}/{版本}`。
///
/// 该前缀下要试的对象键：三平台 + 一个「无三元组」的单制品形态（如 `wist-gateway-stack`）。
///
/// **版本号在文件名里可能不带 `v`**：知识库的打包脚本用 `${GITHUB_REF_NAME#v}` 命名制品
/// （`wist-knowledge-0.1.1.tar.gz`），而 COS 前缀仍带 v（`wist-knowledge/v0.1.1/`）。
/// agentd / gwlinkd 的制品名保留 v，所以两种都试 —— 多出来的那个 HEAD 只在没命中时发生。
fn artifact_keys(
    prefix_key: &str,
    component: &str,
    version: &str,
) -> Vec<(String, Option<String>)> {
    let stem = format!("{component}-{version}");
    let mut candidates: Vec<(String, Option<String>)> = KNOWN_PLATFORMS
        .iter()
        .map(|triple| {
            (
                format!("{prefix_key}/{stem}-{triple}.tar.gz"),
                Some((*triple).to_string()),
            )
        })
        .collect();
    candidates.push((format!("{prefix_key}/{stem}.tar.gz"), None));
    if let Some(bare) = version.strip_prefix('v') {
        let alt_stem = format!("{component}-{bare}");
        if alt_stem != stem {
            candidates.push((format!("{prefix_key}/{alt_stem}.tar.gz"), None));
        }
    }
    candidates
}

/// region 不固定：路径（虚拟主机写法）或 `WIST_GATEWAY_COS_REGION` 给了就用它；都没给就按
/// [`REGION_CANDIDATES`] 逐个试，第一个能取到对象的 region 即命中。
pub async fn resolve_cos_path(cos_path: &str) -> Result<ResolvedRelease, String> {
    let parsed = parse_cos_path(cos_path)?;

    let segments: Vec<&str> = parsed
        .prefix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.len() < 2 {
        return Err("cos path must be <bucket>/<component>/<version> (e.g. \
             github-1347593047/wist-gwlinkd/v0.9.3-alpha)"
            .to_string());
    }
    let component = segments[0];
    let version = segments[segments.len() - 1];
    let prefix_key = parsed.prefix.trim_matches('/');
    let candidates = artifact_keys(prefix_key, component, version);

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|err| format!("failed to build http client: {err}"))?;

    let regions: Vec<String> = match resolve_region(parsed.region.clone()) {
        Some(region) => vec![region],
        None => REGION_CANDIDATES.iter().map(|r| (*r).to_string()).collect(),
    };

    for region in &regions {
        let base = format!("https://{}.cos.{region}.myqcloud.com", parsed.bucket);
        let mut assets: Vec<ResolvedAsset> = Vec::new();
        for (key, platform) in &candidates {
            let artifact_url = format!("{base}/{key}");
            match client.head(&artifact_url).send().await {
                Ok(response) if response.status().is_success() => {
                    let sha256 = normalize_sha256(
                        response
                            .headers()
                            .get(COS_SHA256_HEADER)
                            .and_then(|value| value.to_str().ok()),
                    );
                    let name = key.rsplit('/').next().unwrap_or(key).to_string();
                    assets.push(ResolvedAsset {
                        name,
                        artifact_url,
                        sha256,
                        platform: platform.clone(),
                    });
                }
                // 该形态不存在（或缺平台）→ 跳过。
                Ok(response) => log::debug!("cos HEAD {artifact_url} -> {}", response.status()),
                Err(err) => log::debug!("cos HEAD {artifact_url} failed: {err}"),
            }
        }
        if !assets.is_empty() {
            // 确定性输出（与 GitHub resolver 一样供逐行填充）。
            assets.sort_by(|a, b| a.name.cmp(&b.name));
            return Ok(ResolvedRelease {
                version: version.to_string(),
                assets,
            });
        }
    }

    Err(format!(
        "no artifacts found under {}/{prefix_key} (tried regions: {})",
        parsed.bucket,
        regions.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(bucket: &str, prefix: &str, region: Option<&str>) -> ParsedCosPath {
        ParsedCosPath {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            region: region.map(str::to_string),
        }
    }

    #[test]
    fn parses_all_accepted_cos_path_forms() {
        // 1. cos:// URL。
        assert_eq!(
            parse_cos_path("cos://github-1347593047/wist-gwlinkd/v0.9.3-alpha"),
            Ok(parsed(
                "github-1347593047",
                "wist-gwlinkd/v0.9.3-alpha",
                None
            ))
        );
        // 2. 裸 bucket/prefix。
        assert_eq!(
            parse_cos_path("github-1347593047/wist-gwlinkd/v0.9.3-alpha"),
            Ok(parsed(
                "github-1347593047",
                "wist-gwlinkd/v0.9.3-alpha",
                None
            ))
        );
        // 3. 虚拟主机下载地址（含 query / fragment / 末尾斜杠）→ 顺带读出 region。
        assert_eq!(
            parse_cos_path(
                "https://github-1347593047.cos.ap-hongkong.myqcloud.com/wist-gwlinkd/v0.9.3-alpha/?x=1#y"
            ),
            Ok(parsed(
                "github-1347593047",
                "wist-gwlinkd/v0.9.3-alpha",
                Some("ap-hongkong")
            ))
        );
        // 空白环绕也归一化。
        assert_eq!(
            parse_cos_path("  github-1347593047/wist-gwlinkd/v0.9.3-alpha  "),
            Ok(parsed(
                "github-1347593047",
                "wist-gwlinkd/v0.9.3-alpha",
                None
            ))
        );
    }

    #[test]
    fn rejects_malformed_cos_paths() {
        for bad in [
            "",
            "   ",
            "cos://github-1347593047",  // 缺 prefix
            "github-1347593047",        // 裸形式缺 prefix
            "cos:///wist-gwlinkd/v1",   // 空 bucket
            "cos://github-1347593047/", // 空 prefix
            "github-1347593047/",       // 空 prefix
        ] {
            assert!(parse_cos_path(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn tries_both_v_and_bare_version_artifact_names() {
        // agentd / gwlinkd：文件名保留 v；知识库：文件名去掉 v（打包脚本 `${GITHUB_REF_NAME#v}`）。
        let agentd = artifact_keys("wist-agentd", "wist-agentd", "v0.4.0-alpha");
        assert!(agentd.iter().any(|(key, _)| {
            key.ends_with("/wist-agentd-v0.4.0-alpha-x86_64-unknown-linux-musl.tar.gz")
        }));
        assert!(
            agentd
                .iter()
                .any(|(key, _)| key.ends_with("/wist-agentd-v0.4.0-alpha.tar.gz"))
        );
        // 额外补的「不带 v」形态：知识库命中靠它。
        assert!(
            agentd
                .iter()
                .any(|(key, _)| key.ends_with("/wist-agentd-0.4.0-alpha.tar.gz"))
        );

        let knowledge = artifact_keys("wist-knowledge", "wist-knowledge", "v0.1.1");
        assert!(
            knowledge
                .iter()
                .any(|(key, _)| key.ends_with("/wist-knowledge-0.1.1.tar.gz"))
        );
        // 无 v 或本来就不带 v 的版本：不重复追加。
        let bare = artifact_keys("wist-knowledge", "wist-knowledge", "0.1.1");
        assert_eq!(
            bare.iter()
                .filter(|(key, _)| key.ends_with("/wist-knowledge-0.1.1.tar.gz"))
                .count(),
            1
        );
    }

    #[test]
    fn normalizes_sha256() {
        assert_eq!(
            normalize_sha256(Some("  DEADBEEF  ")),
            Some("deadbeef".into())
        );
        assert_eq!(normalize_sha256(Some("   ")), None);
        assert_eq!(normalize_sha256(None), None);
    }
}
