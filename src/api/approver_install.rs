//! `wist-approve` 的**分发面**：`/api/v1/approver/…`。
//!
//! 为什么由网关分发，而不是只发 GitHub Release：
//!
//! * 审批人是**客户内部的人**，他们能访问的是自己那台网关，而不是 GitHub/TCR；
//! * 隔离站点根本没有外网 —— 网关是唯一必然可达的地址；
//! * 与 agent 安装脚本同一形态：`curl -fsSLk … | sh` 落地，摘要内嵌、TLS 只当传输层。
//!
//! 三条刻意的约束：
//!
//! 1. **公开、无鉴权**。二进制与脚本都不含任何凭据；真正需要管控的是 token 与私钥，
//!    它们**不**随包分发（token 按人签发、私钥由审批人自己生成）。
//! 2. **路径固定、不做目录遍历**。平台只认白名单；文件名是常量。
//! 3. **每次现算摘要**。脚本里内嵌的 sha256 必须和当前这份文件一致 —— 否则装机时校验失败，
//!    而不是装上一个来路不明的东西。

use std::path::PathBuf;

use axum::{
    extract::{Path, State},
    http::header,
    response::{IntoResponse, Response},
};

use crate::api::ApiState;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::install::{effective_advertise_base, supported_agent_platform};
use crate::infra::{AdminConfig, bytes_sha256_hex};

const INSTALL_SCRIPT_TEMPLATE: &str = include_str!("approver-install.sh");
const BINARY_NAME: &str = "wist-approve";
const NO_STORE: &str = "no-store";

/// 审批终端制品在磁盘上的落点：`<state>/approver-package/<platform>/wist-approve`。
///
/// 这是**站点覆盖**位置：放在 state 下（而不是 `packages/`）是因为它是**网关自己分发的东西**，
/// 与 agent 的「当前生效安装包」缓存同性质；`state/` 本就是容器里唯一可写且随容器持久的位置。
/// 留空也没关系 —— 镜像里烘了每个平台的制品（[`builtin_package_path`]）。
pub(crate) fn approver_package_path(config: &AdminConfig, platform: &str) -> PathBuf {
    let state_dir = config
        .sqlite_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    state_dir
        .join("approver-package")
        .join(platform)
        .join(BINARY_NAME)
}

/// 镜像里烘进去的制品目录（`docker/Dockerfile` 的 `COPY` 目标）。
///
/// **为什么必须内置**：现场是多站点 / 四十台起步，不能要求谁登录网关主机手工跑一次投放脚本
/// （落一次地就忘一次，症状就是审批人装不上 CLI：503）。内置 = 与网关版本天然一致，
/// 且隔离站点（没有外网）也能分发。
///
/// 非容器部署可以用 `WIST_APPROVER_PACKAGE_DIR` 指到自己的目录。
const BUILTIN_PACKAGE_DIR: &str = "/usr/share/wist/approver-package";

fn builtin_package_dir() -> PathBuf {
    std::env::var_os("WIST_APPROVER_PACKAGE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(BUILTIN_PACKAGE_DIR))
}

fn builtin_package_path(platform: &str) -> PathBuf {
    builtin_package_dir().join(platform).join(BINARY_NAME)
}

/// 依次尝试多个候选文件，返回第一个读到的。
///
/// 抽成纯函数是为了能直接测「覆盖优先 / 回落内置 / 都没有」—— 走 HTTP 测就只能靠
/// 环境变量，而全局 env 在并行测试里不可靠。
fn first_readable(candidates: &[PathBuf]) -> Option<(PathBuf, Vec<u8>)> {
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            return Some((path.clone(), bytes));
        }
    }
    None
}

fn unknown_platform_response() -> Response {
    ApiError::not_found(
        codes::UNKNOWN_PLATFORM,
        "unknown approver platform (expected a target triple such as aarch64-apple-darwin)",
    )
    .into_response()
}

fn package_unavailable(platform: &str) -> Response {
    ApiError::handled(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        codes::APPROVER_PACKAGE_UNAVAILABLE,
        format!("wist-approve package for platform {platform} is not available on this gateway"),
    )
    .with_no_store()
    .into_response()
}

/// 读制品：**站点覆盖优先，其次镜像内置**。
///
/// `Err` 包一层 `Box`：`axum::http::Response` 有 128 字节，直接当 `Err` 会踩
/// `clippy::result_large_err`，而这个函数在热路径上并不会真失败到需要优化 ——
/// 只是把错误路径的开销挪到堆上，`Ok` 路径不受影响。
fn read_package(config: &AdminConfig, platform: &str) -> Result<(PathBuf, Vec<u8>), Box<Response>> {
    let candidates = [
        approver_package_path(config, platform),
        builtin_package_path(platform),
    ];
    match first_readable(&candidates) {
        Some(found) => Ok(found),
        None => {
            log::warn!(
                "approver package missing for platform {platform}; tried {} and {}",
                candidates[0].display(),
                candidates[1].display()
            );
            Err(Box::new(package_unavailable(platform)))
        }
    }
}

/// `GET /api/v1/approver/packages/{platform}` —— 二进制本体。
pub async fn download_approver_package(
    State(state): State<ApiState>,
    Path(platform): Path<String>,
) -> Response {
    let Ok(platform) = supported_agent_platform(&platform) else {
        return unknown_platform_response();
    };
    let (_, bytes) = match read_package(&state.config, platform) {
        Ok(package) => package,
        Err(response) => return *response,
    };
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"wist-approve\"",
            ),
            // 同一个 tag 下制品不会变；缓存几分钟能省掉重复下载，又不会把新制品挡在缓存后面。
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        bytes,
    )
        .into_response()
}

/// `GET /api/v1/approver/install/{platform}/digests` —— 供页面显示「运行前该核对的值」。
///
/// 脚本本身也是用 `curl -k` 下来的（TLS 只当传输层），所以真正的完整性锚是
/// **脚本摘要由人核对**、**二进制摘要由脚本核对**。这个端点把两个值都给出来。
#[derive(serde::Serialize)]
struct ApproverDigests {
    platform: String,
    package_sha256: String,
    script_sha256: String,
}

pub async fn get_approver_digests(
    State(state): State<ApiState>,
    Path(platform): Path<String>,
) -> Response {
    let Ok(platform) = supported_agent_platform(&platform) else {
        return unknown_platform_response();
    };
    let (_, bytes) = match read_package(&state.config, platform) {
        Ok(package) => package,
        Err(response) => return *response,
    };
    let base = effective_advertise_base(&state.config, &state.store).await;
    let script = render_install_script(&state.config, platform, &bytes, &base);
    let digests = ApproverDigests {
        platform: platform.to_string(),
        package_sha256: bytes_sha256_hex(&bytes),
        script_sha256: bytes_sha256_hex(script.as_bytes()),
    };
    ([(header::CACHE_CONTROL, NO_STORE)], axum::Json(digests)).into_response()
}

/// `GET /api/v1/approver/install/{platform}/install.sh`
pub async fn get_approver_install_script(
    State(state): State<ApiState>,
    Path(platform): Path<String>,
) -> Response {
    let Ok(platform) = supported_agent_platform(&platform) else {
        return unknown_platform_response();
    };
    let (_, bytes) = match read_package(&state.config, platform) {
        Ok(package) => package,
        Err(response) => return *response,
    };
    let base = effective_advertise_base(&state.config, &state.store).await;
    let script = render_install_script(&state.config, platform, &bytes, &base);
    (
        [
            (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
            (header::CACHE_CONTROL, NO_STORE),
        ],
        script,
    )
        .into_response()
}

fn render_install_script(
    config: &AdminConfig,
    platform: &str,
    package: &[u8],
    base: &str,
) -> String {
    INSTALL_SCRIPT_TEMPLATE
        .replace("{{PLATFORM}}", platform)
        .replace(
            "{{PACKAGE_URL}}",
            &format!(
                "{}/api/v1/approver/packages/{platform}",
                base.trim_end_matches('/')
            ),
        )
        .replace("{{PACKAGE_SHA256}}", &bytes_sha256_hex(package))
        .replace("{{BASE_URL}}", base.trim_end_matches('/'))
        // CA 是公开信息；用 `--ca-file` 校验管理面 TLS，与 agent 侧同一个信任锚。
        .replace("{{TRUST_BUNDLE}}", &config.trust_bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 安装脚本的平台判定必须覆盖白名单里的**每一个** triple。
    ///
    /// 白名单是 `supported_agent_platform`（与 agent 包共用），脚本里的 `case` 是**第二份**
    /// 平行的平台表 —— 两份一旦不同步，症状是「路由认得、脚本却说不认识」直接中止，
    /// 而不是一个能看懂的报错。刚发布时就撞过一次同类型的错：白名单是 musl、CI 与脚本写 gnu。
    /// 内置制品目录的默认位置必须与 `docker/Dockerfile` 的 `COPY` 目标**逐字一致**。
    /// 两边漂了不会报错，只会在现场表现为「审批人下载 503」—— 而单元测试全绿。
    #[test]
    fn builtin_dir_matches_the_dockerfile() {
        assert_eq!(BUILTIN_PACKAGE_DIR, "/usr/share/wist/approver-package");
        let dockerfile = include_str!("../../docker/Dockerfile");
        assert!(
            dockerfile.contains(&format!("approver-package {BUILTIN_PACKAGE_DIR}")),
            "Dockerfile 没有把制品 COPY 到 {BUILTIN_PACKAGE_DIR}"
        );
    }

    #[test]
    fn site_override_wins_over_the_image_copy() {
        let root = crate::test_support::unique_temp_dir("approver-pkg-override");
        let site = root.join("site");
        let image = root.join("image");
        std::fs::create_dir_all(&site).expect("site dir");
        std::fs::create_dir_all(&image).expect("image dir");
        std::fs::write(site.join("wist-approve"), b"site").expect("write site");
        std::fs::write(image.join("wist-approve"), b"image").expect("write image");

        let found = first_readable(&[site.join("wist-approve"), image.join("wist-approve")])
            .expect("must find one");
        assert_eq!(
            found.1, b"site",
            "站点覆盖必须优先（否则换 CLI 就得等网关发版）"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn falls_back_to_the_image_copy() {
        let root = crate::test_support::unique_temp_dir("approver-pkg-builtin");
        let site = root.join("site");
        let image = root.join("image");
        std::fs::create_dir_all(&image).expect("image dir");
        std::fs::write(image.join("wist-approve"), b"image").expect("write image");

        let found = first_readable(&[site.join("wist-approve"), image.join("wist-approve")])
            .expect("must fall back to the image copy");
        assert_eq!(found.1, b"image");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reports_unavailable_when_neither_exists() {
        let root = crate::test_support::unique_temp_dir("approver-pkg-none");
        assert!(
            first_readable(&[
                root.join("site").join("wist-approve"),
                root.join("image").join("wist-approve"),
            ])
            .is_none(),
            "一个都没有时必须是 None（调用方据此回 503）"
        );
    }

    #[test]
    fn install_script_handles_every_whitelisted_platform() {
        use crate::api::install_package::{
            PLATFORM_LINUX_ARM, PLATFORM_LINUX_X86, PLATFORM_MACOS_ARM,
        };
        for platform in [PLATFORM_LINUX_X86, PLATFORM_LINUX_ARM, PLATFORM_MACOS_ARM] {
            assert!(
                supported_agent_platform(platform).is_ok(),
                "{platform} 必须仍在白名单里"
            );
            assert!(
                INSTALL_SCRIPT_TEMPLATE.contains(&format!("{platform}) EXPECT=")),
                "install.sh 缺对 {platform} 的平台判定（白名单加了、脚本没跟）"
            );
        }
    }

    #[test]
    fn template_has_no_unrendered_placeholders() {
        let rendered = INSTALL_SCRIPT_TEMPLATE
            .replace("{{PLATFORM}}", "aarch64-apple-darwin")
            .replace("{{PACKAGE_URL}}", "https://gw/api/v1/approver/packages/x")
            .replace("{{PACKAGE_SHA256}}", "00")
            .replace("{{BASE_URL}}", "https://gw")
            .replace("{{TRUST_BUNDLE}}", "-----BEGIN CERTIFICATE-----");
        assert!(
            !rendered.contains("{{"),
            "install.sh 模板里还有未替换的占位符：{rendered}"
        );
        assert!(rendered.contains("wist-approve"), "must install the binary");
        assert!(
            rendered.contains("gateway-ca.crt.pem"),
            "must drop the gateway CA for --ca-file"
        );
    }
}
