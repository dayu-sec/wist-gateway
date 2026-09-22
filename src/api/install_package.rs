//! wist-agentd 安装包的获取、本地缓存与生效来源解析。
//!
//! 管理面设置安装包**来源地址**时，网关先把制品拉到本地（[`fetch_into_cache`]），
//! 之后所有安装都从网关自身的 `/api/v1/agent/packages/current` 取这份缓存
//! （[`effective_package_path`]）。这样做有两个目的：
//!
//! 1. 安装脚本里内嵌的校验摘要与真正分发出去的内容**天然同源** —— 不会再出现
//!    「分发地址认管理面设置、校验摘要认配置里的本地包」这种矛盾（它会让安装端必然报
//!    `agent package sha256 mismatch`）；
//! 2. 目标主机不必直连外网或第三方制品库，内网 / 离线环境也能安装。
//!
//! 来源地址支持两种形式（与 [`super::admin_ops::validate_package_address`] 的口径一致）：
//! `https://…` 走 HTTP 拉取；`/absolute/path` 直接读本机文件。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::infra::{AdminConfig, Store, bytes_sha256_hex};

/// 拉取超时：制品可能几十 MB，给足时间，但不能无限等。
const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// 制品大小上限：防止误填地址把任意大文件灌进网关磁盘。
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;

/// 拉取来源制品时的失败原因；调用方据此区分「管理面填错了摘要」与「来源拿不到」。
#[derive(Debug)]
pub enum PackageFetchError {
    /// 管理面填写的期望摘要与拉取到的内容不符。
    DigestMismatch(String),
    /// 来源不可达 / 读取失败 / 超过大小上限。
    SourceUnavailable(String),
}

impl std::fmt::Display for PackageFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestMismatch(message) | Self::SourceUnavailable(message) => {
                f.write_str(message)
            }
        }
    }
}

/// 网关实际分发的安装包来源。
///
/// `url` 恒为网关自身的分发端点（目标主机只连网关）；`sha256` 是裸 hex，
/// 与实际会被服务出去的那份制品同源，可直接嵌入 install.sh 用于校验。
#[derive(Debug, Clone)]
pub struct AgentPackageSource {
    pub url: String,
    pub sha256: String,
}

impl AgentPackageSource {
    /// 从某个本地制品文件构造来源（分发地址恒为网关端点）。
    pub fn from_local_file(config: &AdminConfig, path: PathBuf) -> Result<Self, String> {
        Ok(Self {
            url: config.agent_package_url(),
            sha256: file_sha256_hex(&path)?,
        })
    }
}

/// 生效的本地制品路径：管理面设置过**且**缓存存在时用缓存，否则回落到内置包。
///
/// 读设置失败或缓存文件丢失都不阻断安装分发，只回落并留下告警 ——
/// 与「安装端点不该因为管理面的一次读失败而整体不可用」的取舍一致。
pub async fn effective_package_path(config: &AdminConfig, store: &Arc<dyn Store>) -> PathBuf {
    let cached = config.install_package_cache_path();
    match store.get_agent_install_package().await {
        Ok(Some(_)) if cached.is_file() => cached,
        Ok(_) => config.agent_package_file.clone(),
        Err(err) => {
            eprintln!("warning: failed to read agent install package address: {err}");
            config.agent_package_file.clone()
        }
    }
}

/// 解析当前生效的安装包来源（分发地址 + 同源摘要）。
pub async fn resolve_agent_package(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
) -> Result<AgentPackageSource, String> {
    let path = effective_package_path(config, store).await;
    AgentPackageSource::from_local_file(config, path)
}

/// 把来源地址的制品拉取到网关本地缓存，返回其 sha256（裸 hex）。
///
/// `expected_sha256` 是管理面填写的期望摘要（可带 `sha256:` 前缀）：填写即表示
/// 「我认可这个字节序列」，不匹配直接拒绝，既不改缓存也不落库。
pub async fn fetch_into_cache(
    config: &AdminConfig,
    source: &str,
    expected_sha256: Option<&str>,
) -> Result<String, PackageFetchError> {
    let bytes = read_source(source).await?;
    let actual = bytes_sha256_hex(&bytes);
    if let Some(expected) = expected_sha256 {
        let expected_hex = expected
            .strip_prefix("sha256:")
            .unwrap_or(expected)
            .to_ascii_lowercase();
        if actual != expected_hex {
            return Err(PackageFetchError::DigestMismatch(format!(
                "agent package sha256 mismatch: expected {expected_hex} got {actual}"
            )));
        }
    }
    write_cache(config, &bytes)?;
    Ok(actual)
}

fn write_cache(config: &AdminConfig, bytes: &[u8]) -> Result<(), PackageFetchError> {
    let path = config.install_package_cache_path();
    let dir = path.parent().ok_or_else(|| {
        PackageFetchError::SourceUnavailable(format!(
            "invalid package cache path {}",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(dir).map_err(|err| {
        PackageFetchError::SourceUnavailable(format!(
            "failed to create package cache dir {}: {err}",
            dir.display()
        ))
    })?;
    // 先写临时文件再改名：拉取中途失败不会留下半截文件被当成有效缓存。
    let partial = path.with_extension("partial");
    std::fs::write(&partial, bytes).map_err(|err| {
        PackageFetchError::SourceUnavailable(format!(
            "failed to write package cache {}: {err}",
            partial.display()
        ))
    })?;
    std::fs::rename(&partial, &path).map_err(|err| {
        PackageFetchError::SourceUnavailable(format!(
            "failed to activate package cache {}: {err}",
            path.display()
        ))
    })?;
    Ok(())
}

async fn read_source(source: &str) -> Result<Vec<u8>, PackageFetchError> {
    // 本机绝对路径：直接读文件（与「https 链接或主机绝对路径」的地址口径对应）。
    if source.starts_with('/') {
        return std::fs::read(source).map_err(|err| {
            PackageFetchError::SourceUnavailable(format!(
                "failed to read package from {source}: {err}"
            ))
        });
    }
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|err| {
            PackageFetchError::SourceUnavailable(format!("failed to build http client: {err}"))
        })?;
    let response = client.get(source).send().await.map_err(|err| {
        PackageFetchError::SourceUnavailable(format!(
            "failed to fetch package from {source}: {err}"
        ))
    })?;
    if !response.status().is_success() {
        return Err(PackageFetchError::SourceUnavailable(format!(
            "package source {source} returned HTTP {}",
            response.status()
        )));
    }
    if let Some(len) = response.content_length()
        && len > MAX_PACKAGE_BYTES
    {
        return Err(PackageFetchError::SourceUnavailable(format!(
            "package at {source} is {len} bytes, over the {MAX_PACKAGE_BYTES} byte limit"
        )));
    }
    let bytes = response.bytes().await.map_err(|err| {
        PackageFetchError::SourceUnavailable(format!(
            "failed to read package body from {source}: {err}"
        ))
    })?;
    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(PackageFetchError::SourceUnavailable(format!(
            "package at {source} is {} bytes, over the {MAX_PACKAGE_BYTES} byte limit",
            bytes.len()
        )));
    }
    Ok(bytes.to_vec())
}

/// 文件 sha256（裸 hex）。
///
/// 按 (路径, mtime, 大小) 缓存：分发端点与签发安装代码都会用到摘要，而制品可能几十 MB，
/// 不能每次请求都整读一遍。缓存键含路径，因为现在有内置包与管理面缓存两个候选制品。
pub fn file_sha256_hex(path: &Path) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|err| err.to_string())?;
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let len = metadata.len();
    let mut cache = PACKAGE_HASH_CACHE
        .lock()
        .map_err(|_| "package hash cache poisoned".to_string())?;
    if let Some(entry) = cache.as_ref()
        && entry.path == path
        && entry.modified == modified
        && entry.len == len
    {
        return Ok(entry.hash.clone());
    }
    let bytes = std::fs::read(path).map_err(|err| err.to_string())?;
    let hash = bytes_sha256_hex(&bytes);
    *cache = Some(PackageHashCacheEntry {
        path: path.to_path_buf(),
        modified,
        len,
        hash: hash.clone(),
    });
    Ok(hash)
}

struct PackageHashCacheEntry {
    path: PathBuf,
    modified: SystemTime,
    len: u64,
    hash: String,
}

static PACKAGE_HASH_CACHE: Mutex<Option<PackageHashCacheEntry>> = Mutex::new(None);

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-install-package-{label}-{}",
            std::process::id() as u64
                + std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn file_sha256_hex_matches_known_digest() {
        let dir = temp_dir("sha");
        let file = dir.join("pkg");
        std::fs::write(&file, b"abc").expect("write");
        // sha256("abc")
        assert_eq!(
            file_sha256_hex(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_sha256_hex_cache_follows_content_change() {
        let dir = temp_dir("cache");
        let file = dir.join("pkg");
        std::fs::write(&file, b"abc").expect("write");
        let first = file_sha256_hex(&file).unwrap();
        // 同大小、不同内容：缓存必须靠 mtime 失效，否则会返回旧摘要。
        std::fs::write(&file, b"abd").expect("rewrite");
        let second = file_sha256_hex(&file).unwrap();
        assert_ne!(first, second, "cache must invalidate when the file changes");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_sha256_hex_cache_does_not_cross_paths() {
        let dir = temp_dir("cross");
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"abc").expect("write a");
        std::fs::write(&b, b"abd").expect("write b");
        let hash_a = file_sha256_hex(&a).unwrap();
        let hash_b = file_sha256_hex(&b).unwrap();
        assert_ne!(hash_a, hash_b, "cache must be keyed by path");
        std::fs::remove_dir_all(&dir).ok();
    }
}
