// NOTE(hand-added): 网关侧「gwlinkd 状态」通道（环回心跳；CR-003）。
//
// gwlinkd **纯出站**（无入站面），页面拉不到它 —— 所以它每拍把自身状态**环回 POST** 到网关；
// 网关存单行、admin 视图暴露给 Web，据此展示「宿主侧常驻在不在跑」。载荷**无密钥**（可原样回显）。
// 设计 `wist-design/doc/design/edge/gateway-linkd-status.md`。
//
// 两个面：
// - **环回（gwlinkd）**：`POST /api/v1/gateway/linkd-status`（loopback-only）。
// - **admin（页面）**：`GET /api/v1/admin/gateway/linkd-status`（admin bearer）。

use super::codes;
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::infra::{DEFAULT_GATEWAY_LINKD_STATUS_SETTING_ID, StoredGatewayLinkdStatus};

use super::error::ApiError;
use super::{ApiState, rate_limit};

/// 失联阈值：心跳约 30s 一拍，超过 3 拍（90s）未见即判失联。
const STALE_AFTER_SECONDS: i64 = 90;

/// 心跳轨迹保留窗口（2 小时 ≈ 240 拍）：环形记录，写入时裁掉窗口外的旧行。
const HISTORY_RETENTION_SECONDS: i64 = 2 * 3600;
/// 页面默认看最近 1 小时（与中心侧「最近 1 小时趋势」口径一致）。
const DEFAULT_HISTORY_WINDOW_SECONDS: i64 = 3600;

/// gwlinkd 自报状态（心跳；无密钥）。字段 snake_case，与 gwlinkd 的 DTO 同钉一份形状。
#[derive(Debug, Deserialize)]
pub struct ReportGatewayLinkdStatusRequest {
    #[serde(default)]
    pub gateway_id: String,
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub center_endpoint: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    #[serde(default)]
    pub last_center_report_at: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// gwlinkd 打的心跳时刻（RFC3339）。
    #[serde(default)]
    pub reported_at: String,
}

/// 页面可见的 gwlinkd 状态视图（含服务端算的 `age_seconds` / `stale`）。
#[derive(Debug, Serialize)]
pub struct GatewayLinkdStatusView {
    pub has_status: bool,
    pub gateway_id: String,
    pub instance_id: String,
    pub version: String,
    pub center_endpoint: String,
    pub state: String,
    pub credential_expires_at: String,
    pub last_center_report_at: String,
    pub last_error: String,
    pub reported_at: String,
    pub received_at: String,
    /// 距最近一次心跳的秒数（服务端按**网关时钟**算）。
    pub age_seconds: i64,
    pub stale: bool,
}

/// 心跳受理回执。
#[derive(Debug, Serialize)]
pub struct GatewayLinkdStatusAccepted {
    pub gateway_id: String,
    pub received_at: String,
}

/// 页面可见的 gwlinkd 心跳轨迹（最近窗口的环形记录）。
#[derive(Debug, Serialize)]
pub struct GatewayLinkdHistoryView {
    /// 本次返回覆盖的窗口（秒）。
    pub window_seconds: i64,
    /// 窗口内的心跳，按时刻升序；断档 = 相邻两点之间 gwlinkd 没在跑。
    pub samples: Vec<GatewayLinkdHeartbeatView>,
}

/// 一条心跳（页面画「状态条 / 心跳间隔」用）。
#[derive(Debug, Serialize)]
pub struct GatewayLinkdHeartbeatView {
    /// 网关收到心跳的时刻（unix 秒）。
    pub at: i64,
    /// 那一刻 gwlinkd 自报的状态。
    pub state: String,
}

/// 轨迹查询参数。
#[derive(Debug, Deserialize)]
pub struct LinkdHistoryQuery {
    #[serde(default)]
    pub window_seconds: Option<i64>,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// 距 `received_at` 的秒数（解析失败 → `None`）。
fn age_seconds(received_at: &str) -> Option<i64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(received_at).ok()?;
    Some(
        chrono::Utc::now()
            .signed_duration_since(parsed.with_timezone(&chrono::Utc))
            .num_seconds()
            .max(0),
    )
}

fn view(status: &StoredGatewayLinkdStatus) -> GatewayLinkdStatusView {
    let age = age_seconds(&status.received_at);
    GatewayLinkdStatusView {
        has_status: true,
        gateway_id: status.gateway_id.clone(),
        instance_id: status.instance_id.clone(),
        version: status.version.clone(),
        center_endpoint: status.center_endpoint.clone(),
        state: status.state.clone(),
        credential_expires_at: status.credential_expires_at.clone(),
        last_center_report_at: status.last_center_report_at.clone(),
        last_error: status.last_error.clone(),
        reported_at: status.reported_at.clone(),
        received_at: status.received_at.clone(),
        age_seconds: age.unwrap_or(0),
        // 解析不出来时按**失联**处理（宁可疑，不假装在线）。
        stale: age
            .map(|seconds| seconds > STALE_AFTER_SECONDS)
            .unwrap_or(true),
    }
}

fn empty_view() -> GatewayLinkdStatusView {
    GatewayLinkdStatusView {
        has_status: false,
        gateway_id: String::new(),
        instance_id: String::new(),
        version: String::new(),
        center_endpoint: String::new(),
        state: String::new(),
        credential_expires_at: String::new(),
        last_center_report_at: String::new(),
        last_error: String::new(),
        reported_at: String::new(),
        received_at: String::new(),
        age_seconds: 0,
        stale: false,
    }
}

/// gwlinkd 心跳：`POST /api/v1/gateway/linkd-status`（loopback-only）。
pub async fn report_gateway_linkd_status(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<ReportGatewayLinkdStatusRequest>,
) -> Response {
    if !client.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return ApiError::forbidden(
            codes::LINKD_STATUS_LOOPBACK_ONLY,
            "linkd-status is loopback-only",
        )
        .into_response();
    }
    let received_at = now_rfc3339();
    let received_at_seconds = chrono::Utc::now().timestamp();
    let status = StoredGatewayLinkdStatus {
        setting_id: DEFAULT_GATEWAY_LINKD_STATUS_SETTING_ID.to_string(),
        gateway_id: input.gateway_id.trim().to_string(),
        instance_id: input.instance_id.trim().to_string(),
        version: input.version.trim().to_string(),
        center_endpoint: input.center_endpoint.trim().to_string(),
        state: input.state.trim().to_string(),
        credential_expires_at: input
            .credential_expires_at
            .unwrap_or_default()
            .trim()
            .to_string(),
        last_center_report_at: input
            .last_center_report_at
            .unwrap_or_default()
            .trim()
            .to_string(),
        last_error: input.last_error.unwrap_or_default().trim().to_string(),
        reported_at: input.reported_at.trim().to_string(),
        received_at: received_at.clone(),
    };
    if let Err(err) = state.store.upsert_gateway_linkd_status(&status).await {
        return ApiError::internal(
            codes::LINKD_STATUS_APPEND_FAILED,
            "failed to store linkd status",
            err,
        )
        .into_response();
    }
    // 顺手落一条心跳轨迹（供页面看「最近一小时稳不稳」）。
    // 轨迹写失败**不影响**心跳本身受理 —— 当前态（上面那行）才是页面「在不在跑」的主判据。
    if let Err(err) = state
        .store
        .append_gateway_linkd_heartbeat(
            received_at_seconds,
            &status.state,
            received_at_seconds - HISTORY_RETENTION_SECONDS,
        )
        .await
    {
        log::warn!("warn append gateway linkd heartbeat failed: {err}");
    }
    Json(GatewayLinkdStatusAccepted {
        gateway_id: status.gateway_id,
        received_at,
    })
    .into_response()
}

/// 读取 gwlinkd 状态（页面用）：`GET /api/v1/admin/gateway/linkd-status`（admin bearer）。
pub async fn admin_view_gateway_linkd_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.get_gateway_linkd_status().await {
        Ok(Some(status)) => Json(view(&status)).into_response(),
        Ok(None) => Json(empty_view()).into_response(),
        Err(err) => ApiError::internal(
            codes::LINKD_STATUS_READ_FAILED,
            "failed to read linkd status",
            err,
        )
        .into_response(),
    }
}

/// 读取 gwlinkd 心跳轨迹（页面用）：
/// `GET /api/v1/admin/gateway/linkd-status/history?window_seconds=`（admin bearer）。
///
/// 窗口缺省 1h，并夹到 `[60s, 保留窗口]` —— 防止页面要一个数据库里根本没有的更大窗口
/// （那只会白扫一遍）。
pub async fn admin_view_gateway_linkd_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Query(params): Query<LinkdHistoryQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let window_seconds = params
        .window_seconds
        .unwrap_or(DEFAULT_HISTORY_WINDOW_SECONDS)
        .clamp(60, HISTORY_RETENTION_SECONDS);
    let since_seconds = chrono::Utc::now().timestamp() - window_seconds;
    match state
        .store
        .list_gateway_linkd_heartbeats(since_seconds)
        .await
    {
        Ok(heartbeats) => Json(GatewayLinkdHistoryView {
            window_seconds,
            samples: heartbeats
                .into_iter()
                .map(|heartbeat| GatewayLinkdHeartbeatView {
                    at: heartbeat.at_seconds,
                    state: heartbeat.state,
                })
                .collect(),
        })
        .into_response(),
        Err(err) => ApiError::internal(
            codes::LINKD_STATUS_HISTORY_READ_FAILED,
            "failed to read linkd history",
            err,
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// 视图**键集契约**（snake_case）。gwlinkd 侧 `linkd_status.rs` 有同一形状的测试 —— 任一侧改名即爆。
    #[test]
    fn view_serializes_the_contract_keys() {
        let stored = StoredGatewayLinkdStatus {
            setting_id: DEFAULT_GATEWAY_LINKD_STATUS_SETTING_ID.to_string(),
            gateway_id: "gw-1".into(),
            instance_id: "gw-1/inst-1".into(),
            version: "0.4.0".into(),
            center_endpoint: "https://center.example".into(),
            state: "Linked".into(),
            credential_expires_at: "2026-12-01T00:00:00+00:00".into(),
            last_center_report_at: "2026-10-05T00:00:00+00:00".into(),
            last_error: String::new(),
            reported_at: chrono::Utc::now().to_rfc3339(),
            received_at: chrono::Utc::now().to_rfc3339(),
        };
        let value: Value = serde_json::to_value(view(&stored)).expect("serialize");
        let object = value.as_object().expect("object");
        for key in [
            "has_status",
            "gateway_id",
            "instance_id",
            "version",
            "center_endpoint",
            "state",
            "credential_expires_at",
            "last_center_report_at",
            "last_error",
            "reported_at",
            "received_at",
            "age_seconds",
            "stale",
        ] {
            assert!(object.contains_key(key), "缺 {key}: {value}");
        }
        assert_eq!(value["stale"], Value::Bool(false), "刚心跳：不算失联");
    }

    #[test]
    fn stale_is_true_when_heartbeat_is_old() {
        let old = (chrono::Utc::now() - chrono::Duration::seconds(300)).to_rfc3339();
        let stored = StoredGatewayLinkdStatus {
            received_at: old,
            ..Default::default()
        };
        assert!(view(&stored).stale, "5 分钟前的心跳应判失联");
    }

    /// 失联阈值边界：`stale = age > 90s`（恰 90 不算，越 1 秒才算）。
    /// 阈值写错（>= / >）会让页面在 90s 整点儿误报或迟报一格。
    #[test]
    fn stale_boundary_is_three_heartbeats() {
        let aged = |secs: i64| StoredGatewayLinkdStatus {
            received_at: (chrono::Utc::now() - chrono::Duration::seconds(secs)).to_rfc3339(),
            ..Default::default()
        };
        assert!(!view(&aged(90)).stale, "恰 90s 未越界，不算失联");
        assert!(view(&aged(91)).stale, "越 90s 即失联");
    }

    /// `received_at` 解析不出时**按失联处理**（宁可疑，不假装在线）：
    /// 不能用「解析失败 → 当作刚刚心跳」把一台状态未知的机器报成健康。
    #[test]
    fn unparseable_received_at_is_treated_as_stale() {
        let stored = StoredGatewayLinkdStatus {
            received_at: "not-a-timestamp".into(),
            ..Default::default()
        };
        let value = view(&stored);
        assert_eq!(value.age_seconds, 0, "解析不出就报 0，不 panic");
        assert!(value.stale, "解析不出应按失联处理");
    }

    /// 空态（从未上报）也是**全字段契约**：前端 `normalize` 每个键都 required，空态不能缺键。
    #[test]
    fn empty_view_keeps_the_full_false_contract() {
        let value: Value = serde_json::to_value(empty_view()).expect("serialize");
        let object = value.as_object().expect("object");
        for key in [
            "has_status",
            "gateway_id",
            "instance_id",
            "version",
            "center_endpoint",
            "state",
            "credential_expires_at",
            "last_center_report_at",
            "last_error",
            "reported_at",
            "received_at",
            "age_seconds",
            "stale",
        ] {
            assert!(object.contains_key(key), "空态缺键 {key}: {value}");
        }
        assert_eq!(value["has_status"], Value::Bool(false));
        assert_eq!(
            value["stale"],
            Value::Bool(false),
            "空态不是「失联」，是「从未有过」"
        );
        assert_eq!(value["age_seconds"], Value::from(0));
    }
}
