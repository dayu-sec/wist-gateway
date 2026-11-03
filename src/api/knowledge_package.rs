// NOTE(hand-added): 网关侧「知识库包下发」通道（环回写入）。
//
// 中心把 `wist-knowledge` 包交给网关知识库管理的意图，由宿主侧常驻 `wist-gwlinkd` 拉取后
// **环回 POST** 到本端点。网关把它当一次普通录入处理（校验摘要 / 验签 → 内容寻址缓存 →
// 记历史），**录不录、激活不激活**都由载荷决定 —— 与 admin 端点 `POST /api/v1/admin/knowledge/packages`
// 同内核（`app::knowledge::record_package` + `knowledge_ops::activate_loaded`）。
//
// 与「Agent 包下发」的差别：知识库是**内容**，不重建网关、不涉及升级；`activate` 决定录入后
// 是否立刻切生效指针（缺省 false —— 录入 ≠ 生效）。
//
// 环回（gwlinkd）：`POST /api/v1/gateway/knowledge-package`（loopback-only）。
// 分层与口径见设计 `wist-design/doc/design/edge/center-content-delivery.md`、
// `wist-design/doc/design/edge/knowledge-package-push-to-gateways.md`。

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::knowledge_ops::{
    DEFAULT_ACTOR, activate_loaded, knowledge_error, record_error_response, store_failure,
};
use super::{ApiState, codes, rate_limit};

/// 中心交付知识库包：`POST /api/v1/gateway/knowledge-package`（loopback-only）。
///
/// 载荷：`{source, sha256, origin?, activate?, requested_by?}`。
/// - `source`：网关**能取**的来源 —— gwlinkd 已落地的本机路径（容器可见，如 `/packages/<file>`）；
/// - `origin`：中心镜像地址（**provenance/留痕**；网关不据此取包，因它不持中心信任）；
/// - `sha256`：中心给的期望摘要（与来源字节核对，不符即拒）；
/// - `activate`：录入后是否立即激活（缺省 false）。
///
/// 非环回请求一律拒绝（只给同机 gwlinkd 用，不对外暴露写通路）。
pub async fn receive_knowledge_package(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<ReceiveKnowledgePackageRequest>,
) -> Response {
    if !state.is_local_host_peer(client) {
        return ApiError::forbidden(
            codes::KNOWLEDGE_PACKAGE_LOOPBACK_ONLY,
            "knowledge-package is loopback-only",
        )
        .into_response();
    }
    let actor = input
        .requested_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_ACTOR)
        .to_string();
    // 摘要必填：与 admin 录入同一道闸（空串也拒，否则会被当成「未给」而跳过校验）。
    let expected_sha256 = input.sha256.trim();
    if expected_sha256.is_empty() {
        return knowledge_error(
            StatusCode::BAD_REQUEST,
            codes::SHA256_REQUIRED,
            "期望摘要 sha256 必填（中心下发的载荷里应带 artifact_sha256）".to_string(),
        );
    }
    if let Some(origin) = input
        .origin
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        // 只留痕：网关**不用**它取包（中心内容由 gwlinkd 取，网关不持中心信任）。
        log::info!(
            "event=KnowledgePackageReceivedByPush source={} origin={origin} activate={}",
            input.source,
            input.activate
        );
    }
    let recorded_at = chrono::Utc::now().to_rfc3339();
    let recorded = match crate::app::knowledge::record_package(
        &state.config,
        &state.store,
        &input.source,
        Some(expected_sha256),
        &actor,
        &recorded_at,
    )
    .await
    {
        Ok(recorded) => recorded,
        Err(err) => return record_error_response(err),
    };
    if input.activate
        && let Err(response) = activate_loaded(&state, recorded.loaded, "activate", &actor).await
    {
        return response;
    }
    let package = match state.store.knowledge_package(&recorded.package_id).await {
        Ok(Some(package)) => package,
        Ok(None) => {
            return knowledge_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::PACKAGE_STORE_FAILED,
                "录入成功但读不回该包".to_string(),
            );
        }
        Err(err) => return store_failure("读回该包失败", err.display_chain()),
    };
    let active = state
        .store
        .knowledge_active()
        .await
        .ok()
        .flatten()
        .map(|row| row.package_id);
    Json(ReceivedKnowledgePackage {
        package_id: package.package_id.clone(),
        version: package.version.clone(),
        active: active.as_deref() == Some(package.package_id.as_str()),
    })
    .into_response()
}

/// 中心交付载荷：与 admin 端点**同内核**，区别只在鉴权口径（环回）与语义来源（中心推送）。
#[derive(Debug, Clone, Deserialize)]
pub struct ReceiveKnowledgePackageRequest {
    /// 网关能取的来源：gwlinkd 落地的**容器内**绝对路径。
    pub source: String,
    /// 期望摘要（裸 hex / `sha256:` 前缀）。
    pub sha256: String,
    /// 中心镜像地址（留痕；网关不用它取包）。
    #[serde(default)]
    pub origin: Option<String>,
    /// 录入后是否立即激活。缺省 `false`。
    #[serde(default)]
    pub activate: bool,
    #[serde(default)]
    pub requested_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReceivedKnowledgePackage {
    package_id: String,
    version: String,
    /// 这次交付之后，它是不是当前生效的那一版。
    active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 交付载荷的**键集契约**（snake_case）。gwlinkd 侧钉同一形状 —— 任一侧改名即爆。
    #[test]
    fn payload_parses_the_push_contract() {
        let fixture = r#"{
            "source": "/packages/wist-knowledge-0.3.0.tar.gz",
            "sha256": "780d6375472e069016209755a42bfdaa89876da03670d2c9ffc8d397bc52c6ec",
            "origin": "https://center.example/api/v1/releases/artifact/wist-knowledge/0.3.0/wist-knowledge-0.3.0.tar.gz",
            "activate": true,
            "requested_by": "wist-gwlinkd"
        }"#;
        let parsed: ReceiveKnowledgePackageRequest =
            serde_json::from_str(fixture).expect("parse push payload");
        assert_eq!(parsed.source, "/packages/wist-knowledge-0.3.0.tar.gz");
        assert_eq!(
            parsed.sha256,
            "780d6375472e069016209755a42bfdaa89876da03670d2c9ffc8d397bc52c6ec"
        );
        assert!(parsed.activate);
        assert_eq!(parsed.requested_by.as_deref(), Some("wist-gwlinkd"));
    }

    /// `activate` 缺省 = 不激活（录入 ≠ 生效）；`origin` 可省。
    #[test]
    fn activate_defaults_to_false_and_origin_is_optional() {
        let parsed: ReceiveKnowledgePackageRequest =
            serde_json::from_str(r#"{"source":"/packages/k.tar.gz","sha256":"aa"}"#)
                .expect("parse minimal payload");
        assert!(!parsed.activate);
        assert!(parsed.origin.is_none());
        assert!(parsed.requested_by.is_none());
    }
}
