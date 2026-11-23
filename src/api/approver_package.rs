//! `wist-approve`（审批终端）安装包的**来源管理**：录入 → 网关拉取并缓存 → 分发只读缓存。
//!
//! 与 agent 安装包（[`super::install_package`]）同一套逻辑，差别只有两处（都写在迁移注释里）：
//! 没有按内容寻址的历史表（换版本 = 重新录入一行），以及**缓存的是原包**（tar.gz）——
//! 网关不解包，由安装脚本解，网关也就不需要多一份归档依赖。
//!
//! 分发端点（[`super::approver_install`]）只读这里落盘的缓存，因此
//! 「install.sh 里内嵌的 sha256」与「真正发出去的字节」永远同源。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::admin_auth::require_admin_bearer;
use crate::api::admin_ops::{normalize_sha256, validate_package_url};
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::install::supported_agent_platform;
use crate::api::install_package::{PackageFetchError, fetch_verified_package, write_cache_to};
use crate::api::{ApiState, rate_limit};
use crate::infra::{AdminConfig, Store, StoredApproverInstallPackage};

/// 录入人缺省值（与 agent 安装包的 `requested_by` 缺省一致）。
const DEFAULT_RECORDED_BY: &str = "platform-maintenance-engineer";

/// 缓存落点：`<state>/approver-package/<platform>/package.tar.gz`。
pub(crate) fn cached_package_path(config: &AdminConfig, platform: &str) -> PathBuf {
    config.approver_package_cache_path(platform)
}

/// 生效的取包路径：**记录在案且缓存副本还在**时才有值。
///
/// 与 agent 包同一判断：只有记录没有文件（盘被清过）也算「没有包」，让调用方明确拒绝，
/// 而不是把一个陈旧的半截文件发出去。
pub(crate) async fn effective_package_path(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    platform: &str,
) -> Option<PathBuf> {
    let path = cached_package_path(config, platform);
    match store.get_approver_install_package(platform).await {
        Ok(Some(_)) if path.is_file() => Some(path),
        Ok(_) => None,
        Err(err) => {
            log::warn!("failed to read approver install package record: {err}");
            None
        }
    }
}

#[derive(Debug, Serialize)]
struct ApproverPackageView {
    platform: String,
    source: String,
    package_sha256: String,
    version: String,
    updated_by: String,
    updated_at: String,
    /// 缓存的包还在盘上（不在 = 分发端点会回 503，重新录入即可）。
    available: bool,
}

impl ApproverPackageView {
    fn from_stored(record: &StoredApproverInstallPackage) -> Self {
        Self {
            platform: record.platform.clone(),
            source: record.source.clone(),
            package_sha256: record.package_sha256.clone(),
            version: record.version.clone(),
            updated_by: record.updated_by.clone(),
            updated_at: record.updated_at.clone(),
            available: Path::new(&record.cached_path).is_file(),
        }
    }
}

/// `GET /api/v1/admin/approver/install-package` —— 三个平台各录了什么。
pub async fn view_approver_install_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_approver_install_packages().await {
        Ok(records) => {
            let views: Vec<ApproverPackageView> = records
                .iter()
                .map(ApproverPackageView::from_stored)
                .collect();
            axum::Json(serde_json::json!({ "packages": views })).into_response()
        }
        Err(err) => ApiError::internal(
            codes::INSTALL_PACKAGE_ADDRESS_UNAVAILABLE,
            "failed to read approver install package",
            err,
        )
        .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SetApproverInstallPackageRequest {
    pub platform: String,
    /// `https://…` 或本机绝对路径（容器里就是 `/packages/<文件名>`）。
    pub source: String,
    /// 可选：期望摘要（`sha256:<hex>` 或裸 hex）。给了就必须一致。
    #[serde(default)]
    pub package_sha256: Option<String>,
    /// 留痕用的录入人；不给用缺省值。
    #[serde(default)]
    pub requested_by: Option<String>,
}

/// `POST /api/v1/admin/approver/install-package` —— 录入一个平台的包并当场拉取。
///
/// 拉取失败**整次不生效**（不写记录、不留半截缓存）：与 agent 包同一取舍。
pub async fn set_approver_install_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    axum::Json(input): axum::Json<SetApproverInstallPackageRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let platform = match supported_agent_platform(input.platform.trim()) {
        Ok(platform) => platform,
        Err(()) => {
            return ApiError::bad_request(
                codes::INSTALL_PACKAGE_PLATFORM_REQUIRED,
                "platform must be a known target triple",
            )
            .into_response();
        }
    };
    // 来源地址与（可选的）摘要：地址规则与 agent 包共用一份实现，不另写一份。
    let source = match validate_package_url(input.source.trim()) {
        Ok(source) => source.to_string(),
        Err(message) => {
            return ApiError::bad_request(codes::INSTALL_PACKAGE_ADDRESS_INVALID, message)
                .into_response();
        }
    };
    let expected_sha256 = match input
        .package_sha256
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(sha) => match normalize_sha256(sha) {
            Ok(sha) => Some(sha),
            Err(message) => {
                return ApiError::bad_request(codes::INSTALL_PACKAGE_ADDRESS_INVALID, message)
                    .into_response();
            }
        },
        None => None,
    };

    let verified = match fetch_verified_package(&source, expected_sha256.as_deref()).await {
        Ok(verified) => verified,
        Err(err) => {
            let (status, code) = match &err {
                PackageFetchError::DigestMismatch(_) => (
                    StatusCode::BAD_REQUEST,
                    codes::INSTALL_PACKAGE_DIGEST_MISMATCH,
                ),
                PackageFetchError::SourceUnavailable(_) | PackageFetchError::TooLarge(_) => (
                    StatusCode::BAD_GATEWAY,
                    codes::INSTALL_PACKAGE_SOURCE_UNAVAILABLE,
                ),
            };
            return ApiError::internal_with(
                status,
                code,
                format!("approver install package for {platform} ({source}): {err}"),
                err,
            )
            .into_response();
        }
    };

    // 包内目录名读出的架构必须与录入的平台一致（读不出来就不拦：现场常手搓包）。
    if !verified.arch.is_empty() && verified.arch != platform {
        return ApiError::bad_request(
            codes::INSTALL_PACKAGE_PLATFORM_MISMATCH,
            format!(
                "package looks like {} but was recorded as {platform}",
                verified.arch
            ),
        )
        .into_response();
    }

    let cached_path = cached_package_path(&state.config, platform);
    if let Err(err) = write_cache_to(&cached_path, &verified.bytes) {
        return ApiError::internal(
            codes::INSTALL_PACKAGE_ADDRESS_STORE_FAILED,
            "failed to cache approver install package",
            err,
        )
        .into_response();
    }

    let record = StoredApproverInstallPackage {
        platform: platform.to_string(),
        source,
        // 摘要由网关对**自己缓存的字节**计算：与分发内容永远一致。
        package_sha256: format!("sha256:{}", verified.sha256),
        cached_path: cached_path.display().to_string(),
        version: verified.version,
        updated_by: input
            .requested_by
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_RECORDED_BY.to_string()),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };
    if let Err(err) = state.store.upsert_approver_install_package(&record).await {
        return ApiError::internal(
            codes::INSTALL_PACKAGE_ADDRESS_STORE_FAILED,
            "failed to store approver install package",
            err,
        )
        .into_response();
    }

    log::info!(
        "approver install package for {platform} recorded: version={} sha256={}",
        record.version,
        record.package_sha256
    );
    axum::Json(ApproverPackageView::from_stored(&record)).into_response()
}

/// `DELETE /api/v1/admin/approver/install-package/{platform}` —— 撤销某个平台的来源。
///
/// 只删记录、**不删缓存副本**（与 agent 包同一取舍）：删了就不再分发，盘上那份留着，
/// 现场回滚不必重新拉取。
pub async fn delete_approver_install_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    AxumPath(platform): AxumPath<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let platform = match supported_agent_platform(platform.trim()) {
        Ok(platform) => platform,
        Err(()) => {
            return ApiError::bad_request(
                codes::INSTALL_PACKAGE_PLATFORM_REQUIRED,
                "platform must be a known target triple",
            )
            .into_response();
        }
    };
    match state.store.delete_approver_install_package(platform).await {
        Ok(removed) => axum::Json(serde_json::json!({ "removed": removed })).into_response(),
        Err(err) => ApiError::internal(
            codes::INSTALL_PACKAGE_ADDRESS_STORE_FAILED,
            "failed to delete approver install package",
            err,
        )
        .into_response(),
    }
}
