// NOTE(hand-added): 网关侧「Agent 包下发」通道（环回写入；发布 ②）。
//
// 中心「发布 ②」把 `wist-agentd` 包推进网关包管理的意图，由 host 侧常驻 `wist-gwlinkd` 拉取后
// **环回 POST** 到本端点。网关把它当一次「设置来源」处理（校验摘要 + 拉到本地 + 记内容寻址历史），
// 于是包进入网关包管理、可供之后的 Agent 升级选择 —— **升不升由网关决定**（② 只交付包）。
//
// gwlinkd 纯出站，本通道是它出站轮询的一站（与 self-state / link-request / linkd-status 同一形态）。
// 口径与设计见 `wist-design/doc/design/edge/agent-package-push-to-gateways.md`。
//
// 环回（gwlinkd）：`POST /api/v1/gateway/agent-package`（loopback-only）。
// 与 admin 端点 `POST /api/v1/admin/agent/install-package` **同内核**（`apply_agent_install_package`），
// 区别只在鉴权口径（环回 vs admin bearer）与语义来源（中心推送 vs 人工录入）。

use super::codes;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};

use super::error::ApiError;
use super::{
    ApiState,
    admin_ops::{SetAgentInstallPackageRequest, apply_agent_install_package},
    rate_limit,
};

/// 中心交付 agentd 包：`POST /api/v1/gateway/agent-package`（loopback-only）。
///
/// 载荷与 admin 端点同形 + `origin`：`{artifacts:[{platform, package_url, origin?, package_sha256}], requested_by?}`。
/// **取包在 gwlinkd、托管在网关**：gwlinkd 持 CA-S 取到包，落到本机路径后交付本端点；
/// 内核复用 [`apply_agent_install_package`]（校验 → 从 `package_url`（本机路径）取 → 落库设置 + 内容寻址历史 → 回读）。
/// `origin` = 中心镜像地址（**留痕**，网关不用它取包）。分层见设计 `edge/center-content-delivery.md`。
/// 非环回请求一律拒绝（该端点只给同机的 gwlinkd 用，不对外暴露写通路）。
pub async fn receive_agent_package(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<SetAgentInstallPackageRequest>,
) -> Response {
    if !client.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return ApiError::forbidden(
            codes::AGENT_PACKAGE_LOOPBACK_ONLY,
            "agent-package is loopback-only",
        )
        .into_response();
    }
    apply_agent_install_package(&state, input).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 交付载荷的**键集契约**（snake_case）。gwlinkd 侧会钉同一形状 —— 任一侧改名即爆。
    #[test]
    fn payload_parses_the_push_contract() {
        let fixture = r#"{
            "artifacts": [
                {
                    "platform": "aarch64-apple-darwin",
                    "package_url": "/packages/wist-agentd-0.1.9-aarch64-apple-darwin.tar.gz",
                    "origin": "https://center.example/api/v1/releases/artifact/wist-agentd/0.1.9/wist-agentd-0.1.9-aarch64-apple-darwin.tar.gz",
                    "package_sha256": "sha256:3f9a1c0d5e7b2a6489f0c1d2e3a4b5c6d7e8f9012345678abcdef0123456789"
                }
            ],
            "requested_by": "wist-gwlinkd"
        }"#;
        let parsed: SetAgentInstallPackageRequest =
            serde_json::from_str(fixture).expect("parse push payload");
        assert_eq!(parsed.artifacts.len(), 1);
        assert_eq!(parsed.artifacts[0].platform, "aarch64-apple-darwin");
        assert_eq!(
            parsed.artifacts[0].package_sha256,
            "sha256:3f9a1c0d5e7b2a6489f0c1d2e3a4b5c6d7e8f9012345678abcdef0123456789"
        );
        assert_eq!(
            parsed.artifacts[0].origin.as_deref(),
            Some(
                "https://center.example/api/v1/releases/artifact/wist-agentd/0.1.9/wist-agentd-0.1.9-aarch64-apple-darwin.tar.gz"
            )
        );
        assert_eq!(parsed.requested_by.as_deref(), Some("wist-gwlinkd"));
    }

    /// `origin` 可省：人填来源（admin 端点）不带它。
    #[test]
    fn payload_allows_omitting_origin() {
        let fixture = r#"{"artifacts":[{"platform":"aarch64-apple-darwin","package_url":"/abs/pkg","package_sha256":"sha256:00"}]}"#;
        let parsed: SetAgentInstallPackageRequest =
            serde_json::from_str(fixture).expect("parse push payload");
        assert_eq!(parsed.artifacts[0].origin, None);
    }

    /// `requested_by` 可省：缺省时由内核回落默认操作者。
    #[test]
    fn payload_allows_omitting_requested_by() {
        let fixture = r#"{"artifacts":[{"platform":"x86_64-unknown-linux-musl","package_url":"/abs/pkg","package_sha256":"sha256:00"}]}"#;
        let parsed: SetAgentInstallPackageRequest =
            serde_json::from_str(fixture).expect("parse push payload");
        assert_eq!(parsed.artifacts.len(), 1);
        assert_eq!(parsed.requested_by, None);
    }
}
