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
/// 放在 state 下（而不是 `packages/`）是因为它是**网关自己分发的东西**，与 agent 的
/// 「当前生效安装包」缓存同性质；`state/` 本就是容器里唯一可写且随容器持久的位置。
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

/// 读不到制品 → 503（平台认识，只是这台网关没放包）。
///
/// `Err` 包一层 `Box`：`axum::http::Response` 有 128 字节，直接当 `Err` 会踩
/// `clippy::result_large_err`，而这个函数在热路径上并不会真失败到需要优化 ——
/// 只是把错误路径的开销挪到堆上，`Ok` 路径不受影响。
fn read_package(config: &AdminConfig, platform: &str) -> Result<(PathBuf, Vec<u8>), Box<Response>> {
    let path = approver_package_path(config, platform);
    match std::fs::read(&path) {
        Ok(bytes) => Ok((path, bytes)),
        Err(err) => {
            log::warn!(
                "approver package missing for platform {platform} at {}: {err}",
                path.display()
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
