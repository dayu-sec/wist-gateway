//! 云资产采集（harvest）的中心侧开关。
//!
//! ## 分层
//!
//! 开关的**语义**在中心（这张表 + 这两个接口），执行不经过 gwlinkd：
//! `wist-harvest` 自己定时轮询 [`harvest_control`]，下一拍就生效、不用重启容器
//! （契约见 harvest 仓的 `[control]` 与 `crates/harvest-app/src/control.rs`）。
//!
//! ## 两个面
//!
//! - **读**：`GET /api/v1/harvest/control`，挂在**明文 ingest 监听**上（`ingest_router`）——
//!   harvest 与服务同栈，明文内网即可，不必为它准备 TLS 信任锚。
//! - **读写**：`GET`/`PUT /api/v1/admin/harvest`，挂在管理面 HTTPS 上，给页面用。
//!
//! ## 鉴权
//!
//! 两面都走管理面 admin token。harvest 只需要**读**，但 token 是同一个（部署上的取舍）——
//! 因此 harvest 的出网面必须收窄到同栈内网，别让它拿到公网可达的管理面入口。
//!
//! ## 失败语义
//!
//! 读接口在库不可用时回 5xx，**不**回落成 "enabled=false"：采集器对 5xx 的处理是
//! fail-closed（首拍失败不采、之后沿用上一拍），所以「读不到」和「明确关闭」必须能区分。

use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::{ApiState, admin_auth::require_admin_bearer, error::ApiError, rate_limit};

const HARVEST_STORE_FAILED: &str = "harvest_setting_store_failed";

/// `PUT /api/v1/admin/harvest` 的请求体。
#[derive(Debug, Deserialize)]
pub struct SetHarvestRequest {
    pub enabled: bool,
}

/// 采集器轮询用：`GET /api/v1/harvest/control`。
///
/// 返回 `{"enabled": bool, "updatedAt": "...", "updatedBy": "..."}`。
/// harvest 只读 `enabled`（`revision` 字段它按可选处理，这里先不给）。
pub async fn harvest_control(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.harvest_setting().await {
        Ok(setting) => Json(json!({
            "enabled": setting.enabled,
            "updatedAt": setting.updated_at,
            "updatedBy": setting.updated_by,
        }))
        .into_response(),
        Err(err) => ApiError::internal(HARVEST_STORE_FAILED, "failed to read harvest setting", err)
            .into_response(),
    }
}

/// 管理面读：`GET /api/v1/admin/harvest`。
pub async fn view_harvest_setting(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.harvest_setting().await {
        Ok(setting) => Json(json!({
            "enabled": setting.enabled,
            "updatedAt": setting.updated_at,
            "updatedBy": setting.updated_by,
        }))
        .into_response(),
        Err(err) => ApiError::internal(HARVEST_STORE_FAILED, "failed to read harvest setting", err)
            .into_response(),
    }
}

/// 管理面写：`PUT /api/v1/admin/harvest`（幂等，写的是同一行）。
pub async fn set_harvest_setting(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(request): Json<SetHarvestRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let actor = super::admin_auth::admin_actor(&state.config);
    match state
        .store
        .set_harvest_setting(request.enabled, &actor)
        .await
    {
        Ok(setting) => Json(json!({
            "enabled": setting.enabled,
            "updatedAt": setting.updated_at,
            "updatedBy": setting.updated_by,
        }))
        .into_response(),
        Err(err) => {
            ApiError::internal(HARVEST_STORE_FAILED, "failed to write harvest setting", err)
                .into_response()
        }
    }
}
