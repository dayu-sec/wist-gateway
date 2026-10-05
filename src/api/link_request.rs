// NOTE(hand-added): 网关侧「接入请求」通道（页面发起接入；CR-003）。
//
// 对应模型 `Control.GatewayApp.LinkRequestInterface`（环回）与设计
// `wist-design/doc/design/edge/gateway-onboard-request.md`。落地走「手加 + 模型留档」（同 self_state）。
//
// 两个面：
// - **admin（页面）**：`POST/GET /api/v1/admin/gateway/link-request`（admin bearer）。
//   运维把 Center 页给的接入物（中心地址 + 一次性接入券 + CA-S 信任锚）提交到本机网关；
//   CA 仅对 **https** 中心必需（明文 http 无 TLS 可校，可省）。
// - **环回（gwlinkd）**：`GET /api/v1/gateway/link-request` + `POST /api/v1/gateway/link-result`
//   （loopback-only）。host 侧常驻拉取待办、完成接入后回报结果。
//
// 字段 snake_case（环回面与 gwlinkd DTO 一致；admin 面沿用网关既有 snake_case 约定）。
// 一次性接入券**明文**只经环回面交付 gwlinkd；admin 视图**不返回**券与 CA。

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::infra::{DEFAULT_GATEWAY_LINK_REQUEST_SETTING_ID, StoredGatewayLinkRequest};

use super::{ApiState, rate_limit};

const STATUS_PENDING: &str = "Pending";
const STATUS_CONNECTING: &str = "Connecting";
const STATUS_CONNECTED: &str = "Connected";
const STATUS_FAILED: &str = "Failed";

/// 提交接入请求（admin）。接入物来自 Center 页「连接 Gateway」。
#[derive(Debug, Deserialize)]
pub struct SetGatewayLinkRequestRequest {
    /// 本网关在中心侧的标识（可留空，gwlinkd 以自身配置为准）。
    #[serde(default)]
    pub gateway_id: String,
    pub center_endpoint: String,
    /// 一次性接入券明文（Center 页一次性展示）。
    pub link_token: String,
    /// CA-S 信任锚（control-center.pem 内容）。
    pub trust_bundle_pem: String,
    #[serde(default)]
    pub requested_by: String,
}

/// 页面可见的接入请求视图（**不含**接入券明文与 CA）。
#[derive(Debug, Serialize)]
pub struct GatewayLinkRequestView {
    pub has_request: bool,
    pub gateway_id: String,
    pub center_endpoint: String,
    pub status: String,
    pub result_detail: String,
    pub requested_by: String,
    pub requested_at: String,
}

/// gwlinkd 拉取到的接入请求（**含**接入券明文 + CA）。
#[derive(Debug, Serialize)]
pub struct GatewayLinkRequestFulfillment {
    pub has_request: bool,
    pub gateway_id: String,
    pub center_endpoint: String,
    pub link_token: String,
    pub trust_bundle_pem: String,
    pub status: String,
}

/// gwlinkd 回报接入结果（环回）。
#[derive(Debug, Deserialize)]
pub struct ReportGatewayLinkResultRequest {
    #[serde(default)]
    pub gateway_id: String,
    /// `Connected` | `Failed`。
    pub status: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct GatewayLinkResultAccepted {
    pub gateway_id: String,
    pub accepted_at: String,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn view(request: &StoredGatewayLinkRequest) -> GatewayLinkRequestView {
    GatewayLinkRequestView {
        has_request: true,
        gateway_id: request.gateway_id.clone(),
        center_endpoint: request.center_endpoint.clone(),
        status: request.status.clone(),
        result_detail: request.result_detail.clone(),
        requested_by: request.requested_by.clone(),
        requested_at: request.requested_at.clone(),
    }
}

fn empty_view() -> GatewayLinkRequestView {
    GatewayLinkRequestView {
        has_request: false,
        gateway_id: String::new(),
        center_endpoint: String::new(),
        status: String::new(),
        result_detail: String::new(),
        requested_by: String::new(),
        requested_at: String::new(),
    }
}

fn fulfillment(request: &StoredGatewayLinkRequest) -> GatewayLinkRequestFulfillment {
    GatewayLinkRequestFulfillment {
        has_request: true,
        gateway_id: request.gateway_id.clone(),
        center_endpoint: request.center_endpoint.clone(),
        link_token: request.link_token.clone(),
        trust_bundle_pem: request.trust_bundle_pem.clone(),
        status: request.status.clone(),
    }
}

fn empty_fulfillment() -> GatewayLinkRequestFulfillment {
    GatewayLinkRequestFulfillment {
        has_request: false,
        gateway_id: String::new(),
        center_endpoint: String::new(),
        link_token: String::new(),
        trust_bundle_pem: String::new(),
        status: String::new(),
    }
}

/// 提交接入请求：`POST /api/v1/admin/gateway/link-request`（admin bearer）。
pub async fn admin_set_gateway_link_request(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<SetGatewayLinkRequestRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let center_endpoint = input.center_endpoint.trim();
    let link_token = input.link_token.trim();
    let trust_bundle_pem = input.trust_bundle_pem.trim();
    if center_endpoint.is_empty() || link_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "center_endpoint / link_token must not be empty",
        )
            .into_response();
    }
    // CA 信任锚仅对 **https** 中心必需：明文 http 无 TLS 可校，允许为空；
    // 而 https 无 CA 则拒绝 —— 否则 gwlinkd 会静默回落到系统根（信任被悄悄放宽）。
    if center_endpoint.starts_with("https://") && trust_bundle_pem.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "https center requires trust_bundle_pem (CA trust anchor)",
        )
            .into_response();
    }
    let now = now_rfc3339();
    let request = StoredGatewayLinkRequest {
        setting_id: DEFAULT_GATEWAY_LINK_REQUEST_SETTING_ID.to_string(),
        gateway_id: input.gateway_id.trim().to_string(),
        center_endpoint: center_endpoint.to_string(),
        link_token: link_token.to_string(),
        trust_bundle_pem: trust_bundle_pem.to_string(),
        status: STATUS_PENDING.to_string(),
        result_detail: String::new(),
        requested_by: input.requested_by.trim().to_string(),
        requested_at: now.clone(),
        updated_at: now,
    };
    if let Err(err) = state.store.upsert_gateway_link_request(&request).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store link request: {err}"),
        )
            .into_response();
    }
    Json(view(&request)).into_response()
}

/// 读取接入请求状态：`GET /api/v1/admin/gateway/link-request`（admin bearer；页面用）。
pub async fn admin_view_gateway_link_request(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.get_gateway_link_request().await {
        Ok(Some(request)) => Json(view(&request)).into_response(),
        Ok(None) => Json(empty_view()).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read link request: {err}"),
        )
            .into_response(),
    }
}

/// gwlinkd 拉取待办：`GET /api/v1/gateway/link-request`（loopback-only）。
///
/// 非终态（`Pending`/`Connecting`）返回请求本体（**含**接入券明文 + CA）并把 `Pending` 推进到
/// `Connecting`；终态（`Connected`）返回 `has_request=false`。
pub async fn query_gateway_link_request(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    if !client.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return (StatusCode::FORBIDDEN, "link-request is loopback-only").into_response();
    }
    match state.store.get_gateway_link_request().await {
        // 只派发**未终态**的请求：`Pending`（推进到 `Connecting`）/ `Connecting`。
        // `Failed` 不再派发 —— 同一张（多半已被消费的）券重试只会反复失败；让操作者在页面重提。
        Ok(Some(mut request)) if is_serveable(&request.status) => {
            if request.status == STATUS_PENDING {
                request.status = STATUS_CONNECTING.to_string();
                request.updated_at = now_rfc3339();
                let _ = state.store.upsert_gateway_link_request(&request).await;
            }
            Json(fulfillment(&request)).into_response()
        }
        Ok(_) => Json(empty_fulfillment()).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read link request: {err}"),
        )
            .into_response(),
    }
}

/// 可派发给 gwlinkd 的状态：未终态（`Pending` / `Connecting`）。
fn is_serveable(status: &str) -> bool {
    status == STATUS_PENDING || status == STATUS_CONNECTING
}

/// gwlinkd 回报结果：`POST /api/v1/gateway/link-result`（loopback-only）。
///
/// `Connected` → 记终态并**清空接入券明文与 CA**（已消费）；`Failed` → 记终态 + 原因（可重提）。
pub async fn report_gateway_link_result(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<ReportGatewayLinkResultRequest>,
) -> Response {
    if !client.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return (StatusCode::FORBIDDEN, "link-result is loopback-only").into_response();
    }
    let status = match input.status.trim() {
        "Connected" => STATUS_CONNECTED,
        "Failed" => STATUS_FAILED,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("status must be Connected|Failed, got {other:?}"),
            )
                .into_response();
        }
    };
    match state.store.get_gateway_link_request().await {
        Ok(Some(mut request)) => {
            request.status = status.to_string();
            request.result_detail = input.detail.trim().to_string();
            request.updated_at = now_rfc3339();
            if status == STATUS_CONNECTED {
                // 已消费：不再需要明文券与 CA。
                request.link_token.clear();
                request.trust_bundle_pem.clear();
            }
            let gateway_id = if input.gateway_id.trim().is_empty() {
                request.gateway_id.clone()
            } else {
                input.gateway_id.trim().to_string()
            };
            if let Err(err) = state.store.upsert_gateway_link_request(&request).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to store link result: {err}"),
                )
                    .into_response();
            }
            Json(GatewayLinkResultAccepted {
                gateway_id,
                accepted_at: now_rfc3339(),
            })
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no link request").into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to read link request: {err}"),
        )
            .into_response(),
    }
}
