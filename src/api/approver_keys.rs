//! 审批公钥登记：`/api/v1/admin/approver-keys`。
//!
//! **外部签发模式**的配套：私钥在审批人手上（`wist-approve`），网关只持有公钥。
//! 这里的公钥只有两个用途：
//!
//! 1. **挡垃圾** —— 收到 attestation 时验一遍，别把签坏的/伪造的计划发到机器上；
//! 2. **供人核对** —— 页面与 CLI 都显示同一串指纹（DER 的 sha256 前 16 位）。
//!
//! 它**不是授权源**：真正的授权在执行侧（agentd 的锚，`enforced = true` 时验不过就拒）。
//! 所以吊销一把公钥不会让已签发的计划失效，只会让后续用这把钥匙签的单进不来。
//!
//! 三条刻意的取舍：
//!
//! * `key_id` 必须与 agentd 锚、`attestation.key_id` 三者同名 —— 换钥匙时靠它对齐；
//! * 导入即校验：不是 Ed25519 SPKI PEM 的一律拒绝（存下来只会让指纹永远对不上）；
//! * 吊销是软删：打 `revoked_at`，不删行，审计要能回答「什么时候被谁撤的」。

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::api::admin_auth::{admin_actor, require_admin_bearer};
use crate::api::error::ApiError;
use crate::api::{ApiState, codes, rate_limit};
use crate::infra::{
    StoredApproverKey, hex_decode, parse_ed25519_public_key_pem, public_key_fingerprint,
};

/// `key_id` 的合法形状。
///
/// 它同时是 agentd 锚目录里的**文件名**，所以不允许 `/`、`..`、空串这类东西 ——
/// 客户端拿到错误时要能一眼看出「这个名字不能用」，而不是等到落盘时才炸。
const KEY_ID_MAX_LEN: usize = 64;

/// 客户端可控字符串进日志前的洗白（与 `action_approvals` 同一口径）。
fn log_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .take(120)
        .collect()
}

fn valid_key_id(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= KEY_ID_MAX_LEN
        && key_id != "."
        && key_id != ".."
        && key_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterApproverKeyRequest {
    /// 与 agentd 锚、`attestation.key_id` 同名。
    pub key_id: String,
    /// 属主（`user:<id>` / `role:approver` / `admin:<指纹>`）。只用于审计与展示。
    pub owner: String,
    /// Ed25519 SPKI PEM（公开信息）。
    pub public_key: String,
    /// 重新启用一把**已吊销**的钥匙。
    ///
    /// 默认拒绝：吊销往往是一次安全事件（钥匙疑似泄露），不能被一次重试/一张旧页面
    /// 提交静默撤销掉。要重新启用就显式写 `"reactivate": true`（并留审计）。
    #[serde(default)]
    pub reactivate: bool,
}

#[derive(Debug, Serialize)]
struct ApproverKeyView {
    key_id: String,
    owner: String,
    fingerprint: String,
    added_by: String,
    added_at: String,
    /// `None` = 生效中。
    revoked_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApproverKeyListView {
    keys: Vec<ApproverKeyView>,
}

fn key_view(key: &StoredApproverKey) -> ApproverKeyView {
    ApproverKeyView {
        key_id: key.key_id.clone(),
        owner: key.owner.clone(),
        fingerprint: key.fingerprint.clone(),
        added_by: key.added_by.clone(),
        added_at: key.added_at.clone(),
        revoked_at: key.revoked_at.clone(),
    }
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// `GET /api/v1/admin/approver-keys`
///
/// 含已吊销的行：审计要看「这把钥匙什么时候被撤的」，列表里藏掉就查不到了。
pub async fn list_approver_keys(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_approver_keys().await {
        Ok(keys) => Json(ApproverKeyListView {
            keys: keys.iter().map(key_view).collect(),
        })
        .into_response(),
        Err(err) => ApiError::internal(
            codes::APPROVER_KEY_STORE_FAILED,
            "failed to list approver keys",
            err,
        )
        .into_response(),
    }
}

/// `POST /api/v1/admin/approver-keys`（导入 / 覆盖）。
///
/// 同名 `key_id` 重复导入就是**轮换**：公钥换了、指纹跟着换。想保留旧的并行期，
/// 用另一个 `key_id` 导一把新的（agentd 侧锚也并存）。
pub async fn register_approver_key(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(request): Json<RegisterApproverKeyRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let key_id = request.key_id.trim().to_string();
    if !valid_key_id(&key_id) {
        return ApiError::bad_request(
            codes::APPROVER_KEY_INVALID,
            format!(
                "key_id must match [A-Za-z0-9._-]{{1,{KEY_ID_MAX_LEN}}} and must not be '.' or '..'"
            ),
        )
        .into_response();
    }
    let owner = request.owner.trim().to_string();
    if owner.is_empty() {
        return ApiError::bad_request(codes::APPROVER_KEY_INVALID, "owner must not be empty")
            .into_response();
    }
    // 先解析再存：不会解析的 PEM 存下来只会让指纹永远对不上（登记时说得清，事后说不清）。
    if let Err(reason) = parse_ed25519_public_key_pem(&request.public_key) {
        return ApiError::bad_request(
            codes::APPROVER_KEY_INVALID,
            format!("public_key is not an Ed25519 SPKI PEM: {reason}"),
        )
        .into_response();
    }
    let fingerprint = match crate::infra::public_key_fingerprint_from_pem(&request.public_key) {
        Ok(fingerprint) => fingerprint,
        Err(reason) => {
            return ApiError::bad_request(
                codes::APPROVER_KEY_INVALID,
                format!("failed to fingerprint public_key: {reason}"),
            )
            .into_response();
        }
    };

    // 吊销过的钥匙不能被一次重试静默复活：必须先看它是哪次被撤的。
    match state.store.get_approver_key(&key_id).await {
        Ok(Some(existing)) if !existing.is_active() && !request.reactivate => {
            return ApiError::conflict(
                codes::APPROVER_KEY_REVOKED,
                format!(
                    "approver key {key_id} was revoked at {}; pass \"reactivate\": true to re-enable it",
                    existing.revoked_at.as_deref().unwrap_or("unknown")
                ),
            )
            .into_response();
        }
        Ok(_) => {}
        Err(err) => {
            return ApiError::internal(
                codes::APPROVER_KEY_STORE_FAILED,
                "failed to load approver key",
                err,
            )
            .into_response();
        }
    }

    let key = StoredApproverKey {
        key_id,
        owner,
        public_key: request.public_key,
        fingerprint,
        added_by: admin_actor(&state.config),
        added_at: timestamp_now(),
        revoked_at: None,
    };
    if let Err(err) = state
        .store
        .upsert_approver_key(&key, request.reactivate)
        .await
    {
        return ApiError::internal(
            codes::APPROVER_KEY_STORE_FAILED,
            "failed to store approver key",
            err,
        )
        .into_response();
    }
    // 回读一次：写入与「并发吊销」撞上时，上面那条 UPSERT 会保留 `revoked_at`（不会把
    // 吊销撤回去）。响应必须以**库里真实状态**为准，否则人以为已经重新启用、实际没有。
    let stored = match state.store.get_approver_key(&key.key_id).await {
        Ok(Some(stored)) => stored,
        Ok(None) => key.clone(),
        Err(err) => {
            log::warn!(
                "approver key {} re-read failed after upsert: {err}",
                key.key_id
            );
            key.clone()
        }
    };
    if !stored.is_active() {
        log::warn!(
            "event=ApproverKeyRegisterKeptRevoked key_id={} reactivate_requested={}",
            log_field(&stored.key_id),
            request.reactivate
        );
    }
    log::info!(
        "event=ApproverKeyRegistered key_id={} owner={} fingerprint={} added_by={} reactivate={}",
        log_field(&stored.key_id),
        log_field(&stored.owner),
        stored.fingerprint,
        log_field(&stored.added_by),
        request.reactivate
    );
    Json(key_view(&stored)).into_response()
}

/// `DELETE /api/v1/admin/approver-keys/{key_id}`（吊销）。
pub async fn revoke_approver_key(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(key_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let revoked_at = timestamp_now();
    match state.store.revoke_approver_key(&key_id, &revoked_at).await {
        Ok(true) => {
            log::info!(
                "event=ApproverKeyRevoked key_id={} revoked_at={} revoked_by={}",
                key_id,
                revoked_at,
                admin_actor(&state.config)
            );
            Json(serde_json::json!({ "key_id": key_id, "revoked_at": revoked_at })).into_response()
        }
        Ok(false) => ApiError::not_found(
            codes::APPROVER_KEY_NOT_FOUND,
            format!("no active approver key {key_id}"),
        )
        .into_response(),
        Err(err) => ApiError::internal(
            codes::APPROVER_KEY_STORE_FAILED,
            "failed to revoke approver key",
            err,
        )
        .into_response(),
    }
}

/// 校验一份 attestation 的签名（供 `issue` 复用）。
///
/// 返回 `Ok(fingerprint)`；失败时给稳定 code，调用方不要再猜原因。
pub(crate) fn verify_attestation_signature(
    public_key_pem: &str,
    signing_payload: &[u8],
    signature_hex: &str,
) -> Result<String, &'static str> {
    let public_key = parse_ed25519_public_key_pem(public_key_pem)
        .map_err(|_| codes::ATTESTATION_SIGNATURE_INVALID)?;
    let signature = hex_decode(signature_hex).ok_or(codes::ATTESTATION_SIGNATURE_INVALID)?;
    if !crate::infra::verify_ed25519(&public_key, signing_payload, &signature) {
        return Err(codes::ATTESTATION_SIGNATURE_INVALID);
    }
    Ok(public_key_fingerprint(&public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_shape_is_strict() {
        assert!(valid_key_id("gw-plan-k1"));
        assert!(valid_key_id("site.approver_2026-1"));
        assert!(!valid_key_id(""));
        assert!(!valid_key_id("."));
        assert!(!valid_key_id(".."));
        assert!(!valid_key_id("../etc/passwd"));
        assert!(!valid_key_id("a/b"));
        assert!(!valid_key_id(&"x".repeat(KEY_ID_MAX_LEN + 1)));
    }

    #[test]
    fn signature_verification_rejects_bad_input() {
        assert_eq!(
            verify_attestation_signature("not a pem", b"x", "00"),
            Err(codes::ATTESTATION_SIGNATURE_INVALID)
        );
        assert_eq!(
            verify_attestation_signature("not a pem", b"x", "zz"),
            Err(codes::ATTESTATION_SIGNATURE_INVALID)
        );
    }
}
