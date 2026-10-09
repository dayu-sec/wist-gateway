//! wist-agentd 安装包的获取、本地缓存与生效来源解析。
//!
//! 管理面设置安装包**来源地址**时，网关先把制品拉到本地（[`fetch_into_package_cache`]），
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
use std::time::SystemTime;

use crate::infra::{AdminConfig, Store, bytes_sha256_hex};

// 安装包内核（来源读取 / 摘要校验 / 身份解析 / 命名）已收进共享 crate `wist-release`，
// 中心与网关共用一份，不再各写一遍。
use wist_release::package::read_verified_source;

/// 取包失败：沿用本模块原名（共享 crate 的类型）。
/// 调用方据此区分「管理面填错了摘要」与「来源拿不到」。
pub use wist_release::package::PackageError as PackageFetchError;
/// 内容寻址 id：`pkg-<sha256 前 16 位>`（裸 hex）——转出自共享 crate。
pub use wist_release::package::package_id_for_sha256;
/// 二进制包身份：只认包内顶层目录名、且必须切出已知 target-triple（读不出整体留空）。
/// 与中心托管包的宽松口径（`read_package_identity`，可回落来源文件名）刻意分开 ——
/// agent 安装包读不出架构时宁可不报，也不把版本错切出来。
pub use wist_release::package::read_binary_package_identity as read_package_identity;

/// agentd 的已知发布平台（target-triple），与 `wist-agentd` 发布矩阵一致。
/// 网关按平台分别托管安装包（macOS-ARM + Linux x86_64/ARM64）。
pub const PLATFORM_LINUX_X86: &str = "x86_64-unknown-linux-musl";
pub const PLATFORM_LINUX_ARM: &str = "aarch64-unknown-linux-musl";
pub const PLATFORM_MACOS_ARM: &str = "aarch64-apple-darwin";

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
    ///
    /// `base` 是**生效的对外基址**（网关对外地址设置；未设置时由调用方传入
    /// `server.public_base_url`）。分发地址必须与安装命令里给出的地址同源，
    /// 否则目标主机拿到的是一个连不上的网关地址。
    pub fn from_local_file(
        config: &AdminConfig,
        base: &str,
        platform: &str,
        path: PathBuf,
    ) -> Result<Self, String> {
        Ok(Self {
            url: config.agent_package_url_at(base, platform),
            sha256: file_sha256_hex(&path)?,
        })
    }
}

/// 生效的本地制品路径：**只有**管理面录入过、且缓存的副本还在时才有值。
///
/// 返回 `None` = 没有可用的安装包（从未录入、或录过的副本已不在）—— 不报错，
/// 由调用方决定怎么提示（安装/分发端点会明确拒绝）。
///
/// 为什么不再有「配置里的内置包」这个回落：安装包只能有一个来源（管理面录入那份），
/// 否则又会回到「分发地址认管理面、校验摘要认配置文件」那种矛盾。
///
/// 读设置失败同样只回落为「没有包」并留下告警 —— 与「安装端点不该因为管理面的一次读失败
/// 而整体不可用」的取舍一致。
pub async fn effective_package_path(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    platform: &str,
) -> Option<PathBuf> {
    let cached = config.install_package_cache_path(platform);
    match store.get_agent_install_package(platform).await {
        Ok(Some(_)) if cached.is_file() => Some(cached),
        Ok(_) => None,
        Err(err) => {
            log::warn!("warning: failed to read agent install package address: {err}");
            None
        }
    }
}

/// 解析当前生效的安装包来源（分发地址 + 同源摘要）。
///
/// `base` 是生效的对外基址，见 [`AgentPackageSource::from_local_file`]。
pub async fn resolve_agent_package(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    base: &str,
    platform: &str,
) -> Result<AgentPackageSource, String> {
    let Some(path) = effective_package_path(config, store, platform).await else {
        return Err(format!(
            "平台 {platform} 没有可用的 agent 安装包：管理面未录入来源，或录入的副本已不在 —— 到「安装包」页看一眼（重新录入会重新拉取）"
        ));
    };
    AgentPackageSource::from_local_file(config, base, platform, path)
}

/// 解析**全部已录入平台**的安装包来源（签发安装代码时组多平台 bundle 用）。
///
/// 只列「记录在案且缓存副本仍在」的平台；某个平台的副本丢了就跳过（只记告警），
/// 不让一个坏平台把整份安装代码弄成不可用。
pub async fn resolve_agent_platform_packages(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    base: &str,
) -> Result<Vec<(String, AgentPackageSource)>, String> {
    let settings = store
        .list_agent_install_package_addresses()
        .await
        .map_err(|err| format!("failed to list agent install packages: {err}"))?;
    let mut resolved = Vec::new();
    for setting in settings {
        let platform = setting.address_id;
        match effective_package_path(config, store, &platform).await {
            Some(path) => {
                resolved.push((
                    platform.clone(),
                    AgentPackageSource::from_local_file(config, base, &platform, path)?,
                ));
            }
            None => log::warn!(
                "warning: recorded agent install package for platform {platform} has no cached copy; skipped"
            ),
        }
    }
    Ok(resolved)
}

/// 一次录入的完整产物：单例缓存与按条副本都已落盘，并已解析出包身份。
#[derive(Debug, Clone)]
pub struct CachedInstallPackage {
    /// 裸 hex sha256（不带 `sha256:` 前缀）。
    pub sha256: String,
    /// 内容寻址 id：`pkg-<sha256 前 16 位>`。
    pub package_id: String,
    /// 网关自己存的那份副本路径。
    pub cached_path: PathBuf,
    /// 包内目录名解析出的版本/架构（解析不出为空串）。
    pub version: String,
    pub arch: String,
}

/// 把来源制品拉到网关本地：**同时**写单例缓存（安装用）与按条副本（升级用）。
///
/// 来源只读一次：读到的字节同时用于写两份缓存与解析包身份，避免重复拉取几十 MB 的制品。
pub async fn fetch_into_package_cache(
    config: &AdminConfig,
    platform: &str,
    source: &str,
    expected_sha256: Option<&str>,
) -> Result<CachedInstallPackage, PackageFetchError> {
    let (bytes, sha256) = read_verified_source(source, expected_sha256).await?;
    // 按平台的当前缓存：安装路径 /api/v1/agent/packages/current?platform= 从它分发。
    write_cache_to(&config.install_package_cache_path(platform), &bytes)?;
    let package_id = package_id_for_sha256(&sha256);
    let cached_path = config.install_package_history_path(&package_id);
    write_cache_to(&cached_path, &bytes)?;
    let (version, arch) = read_package_identity(&bytes);
    Ok(CachedInstallPackage {
        sha256,
        package_id,
        cached_path,
        version,
        arch,
    })
}

fn write_cache_to(path: &Path, bytes: &[u8]) -> Result<(), PackageFetchError> {
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
    std::fs::rename(&partial, path).map_err(|err| {
        PackageFetchError::SourceUnavailable(format!(
            "failed to activate package cache {}: {err}",
            path.display()
        ))
    })?;
    Ok(())
}

/// 文件 sha256（裸 hex）。
///
/// 按 (路径, mtime, 大小) 缓存：分发端点与签发安装代码都会用到摘要，而制品可能几十 MB，
/// 不能每次请求都整读一遍。
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

// 包身份解析（顶层目录名 → version/arch，且要求已知 target-triple）已收进共享 crate
// `wist-release`（`read_binary_package_identity`，本模块在上面转出为 `read_package_identity`），
// 未知三元组表的唯一来源也在那里。

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

    /// 把任意字节压成 gzip（构造「合法 gzip 但载荷不是 tar」的输入用）。
    fn gzip_of(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    /// 构造一个 gzip 包住的 tar：按顺序写入 `(归档内路径, 内容)` 若干条目。
    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, *path, *contents)
                .expect("append tar entry");
        }
        gzip_of(&builder.into_inner().expect("finish tar"))
    }

    #[test]
    fn package_id_for_sha256_is_stable_prefixed_and_digest_sized() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let id = package_id_for_sha256(digest);
        assert_eq!(id, "pkg-0123456789abcdef");
        assert!(id.starts_with("pkg-"));
        assert_eq!(id.len(), "pkg-".len() + 16);
        // 同一 sha256 两次得到同一 id（幂等，内容寻址的前提）。
        assert_eq!(package_id_for_sha256(digest), id);

        // 不同 sha256 得到不同 id。
        let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        assert_ne!(package_id_for_sha256(other), id);
        assert_eq!(package_id_for_sha256(other), "pkg-fedcba9876543210");
    }

    #[test]
    fn read_package_identity_returns_empty_for_non_tar_gzip() {
        // 合法 gzip，但载荷不是 tar：读不出身份，不 panic、留空。
        assert_eq!(
            read_package_identity(&gzip_of(b"this is not a tar archive")),
            (String::new(), String::new())
        );
    }

    #[test]
    fn read_package_identity_returns_empty_for_plain_dot_entry() {
        // 顶层条目就是 `./`：取不到普通段 → 留空（不 panic）。
        let bytes = tar_gz(&[("./", b"")]);
        assert_eq!(
            read_package_identity(&bytes),
            (String::new(), String::new())
        );
    }

    #[test]
    fn read_package_identity_skips_leading_dot_slash() {
        // `./wist-agentd-…/…`：跳过 CurDir 段，仍能取到目录名。
        let bytes = tar_gz(&[(
            "./wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
            b"bin",
        )]);
        assert_eq!(
            read_package_identity(&bytes),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_uses_only_the_first_entry() {
        // 两个条目：只看第一个（顶层目录名是哪个就报哪个）。
        let bytes = tar_gz(&[
            (
                "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
                b"first",
            ),
            (
                "wist-agentd-9.9.9-aarch64-apple-darwin/wist-agentd",
                b"second",
            ),
        ]);
        assert_eq!(
            read_package_identity(&bytes),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_reads_a_symlink_entry_name() {
        // 首个条目是符号链接：取其自身路径名即可，不跟随、不 panic。
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_mtime(0);
        builder
            .append_link(
                &mut header,
                "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
                "..",
            )
            .expect("append symlink");
        let bytes = gzip_of(&builder.into_inner().expect("finish tar"));
        assert_eq!(
            read_package_identity(&bytes),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_tolerates_absurd_declared_size() {
        // 头部声明的条目大小离谱（约 4 EiB）：只读头部取名，不按声明大小分配/读取，不 panic。
        let mut header = tar::Header::new_gnu();
        header
            .set_path("wist-agentd-1.2.3-x86_64-unknown-linux-gnu/")
            .expect("path");
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(1 << 62);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_cksum();
        let bytes = gzip_of(header.as_bytes());
        assert_eq!(
            read_package_identity(&bytes),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_handles_a_large_payload_package() {
        // 包里带一大块内容：只读首个条目的头部，不受体积影响。
        let big = vec![0u8; 4 * 1024 * 1024];
        let bytes = tar_gz(&[
            (
                "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/README",
                b"readme",
            ),
            (
                "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
                &big,
            ),
        ]);
        assert_eq!(
            read_package_identity(&bytes),
            ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn read_package_identity_parses_prerelease_and_four_segment_versions() {
        assert_eq!(
            read_package_identity(&tar_gz(&[(
                "wist-agentd-0.2.0-beta.1-aarch64-apple-darwin/wist-agentd",
                b"x",
            )])),
            (
                "0.2.0-beta.1".to_string(),
                "aarch64-apple-darwin".to_string()
            )
        );
        assert_eq!(
            read_package_identity(&tar_gz(&[(
                "wist-agentd-1.2.3.4-x86_64-unknown-linux-gnu/wist-agentd",
                b"x",
            )])),
            (
                "1.2.3.4".to_string(),
                "x86_64-unknown-linux-gnu".to_string()
            )
        );
    }

    #[test]
    fn read_package_identity_returns_empty_for_unknown_triple() {
        // 三元组不认识：整体留空，而不是把版本错切出来。
        assert_eq!(
            read_package_identity(&tar_gz(&[(
                "wist-agentd-1.2.3-some-unknown-triple/wist-agentd",
                b"x",
            )])),
            (String::new(), String::new())
        );
        // 连 `-<triple>` 都没有（整名就是一个未知词）：同样留空。
        assert_eq!(
            read_package_identity(&tar_gz(&[("wist-agentd-1.2.3/wist-agentd", b"x")])),
            (String::new(), String::new())
        );
    }
}
