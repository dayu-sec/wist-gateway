//! 云资产采集（harvest）的**工作授权**：worker 接入 + 拉取/确认 + 管理面。
//!
//! 设计见 `docs/design/harvest-work-grant.md`。三条边界：
//!
//! 1. **身份是证书**（mTLS，与 agentd 同一把 CA）：worker 面只认
//!    `VerifiedHarvestIdentity`（由 TLS 层验链后注入，客户端伪造不了）。
//! 2. **云账号凭据不下发**：`spec.credential_ref` 只是一个引用名，真值在宿主 secret 文件。
//! 3. **不做旧开关兼容**：`/api/v1/harvest/control` 与 `harvest_setting` 已随本版删除，
//!    「开/关」= `standing.status`。

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, NaiveTime, Utc};
use serde::Deserialize;
use serde_json::json;
use wist_api::harvest_work::{
    AckHarvestWork, FAMILY_INVENTORY, HarvestCertificateRenewal, HarvestCertificateRenewed,
    HarvestEnrollmentEnvelope, HarvestEnrollmentOutcome, HarvestEnrollmentRequest, HarvestRegions,
    HarvestResultAccepted, HarvestSpec, HarvestWorkAccepted, HarvestWorkGrant, OneShotHarvestSpec,
    OneShotHarvestWork, PollHarvestWork, ReportHarvestResult, STATUS_ACTIVE, STATUS_PAUSED,
    STATUS_REVOKED, StandingHarvestWork,
};

use crate::infra::{
    HarvestCertificateIdentity, HarvestCertificateRecord, HarvestResultOutcome, HarvestWorker,
    StoredHarvestAck, StoredHarvestOneShot, StoredHarvestResult, StoredHarvestStanding,
    StoredHarvestTicket, VerifiedHarvestIdentity, new_secret_token, sha256_hex,
};

use super::{
    ApiState,
    admin_auth::{admin_actor, require_admin_bearer},
    error::ApiError,
    rate_limit,
};

const API_VERSION_V1: &str = "v1";

/// 接入券默认有效期 / 上限。
const DEFAULT_TICKET_TTL_SECONDS: i64 = 24 * 60 * 60;
const MAX_TICKET_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// 契约里认识的采集面。
const KNOWN_ASSETS: &[&str] = &["cloud_host", "vpc", "subnet", "eip"];

/// 本期一次性动作（`cost.pull` 不进）。
const ONE_SHOT_ACTIONS: &[&str] = &["inventory.run", "inventory.rescan"];

/// 一次性工作允许上报的状态（终态由网关根据工作行判定，客户端不能自己宣布 `timed_out`）。
const REPORTABLE_STATUSES: &[&str] = &["running", "succeeded", "failed"];

/// 一次性工作的默认时长：1 小时；上限 24 小时（全量采集可能很久，但不能无限挂）。
const DEFAULT_ONE_SHOT_TIMEOUT_SECONDS: i64 = 3600;
const MAX_ONE_SHOT_TIMEOUT_SECONDS: i64 = 24 * 60 * 60;

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn store_failed(err: impl std::fmt::Display, detail: &str) -> Response {
    ApiError::internal("harvest_store_failed", detail, err).into_response()
}

/// 证书里的租户/环境必须就是本网关的：证是同一把 CA 签的，克隆站点后也一样能验链通过。
fn site_matches(state: &ApiState, identity: &VerifiedHarvestIdentity) -> bool {
    identity.tenant_id == state.config.tenant_id
        && identity.environment_id == state.config.environment_id
}

fn site_mismatch() -> Response {
    ApiError::forbidden(
        "harvest_worker_wrong_site",
        "client certificate belongs to another site (tenant/environment mismatch)",
    )
    .into_response()
}

/// `source_code` 会进证书 URI SAN 与宿主目录名：只允许小写字母/数字/`_`/`-`。
fn source_code_is_valid(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let bytes = value.as_bytes();
    let first = bytes[0];
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// 带证书 / 票据的响应不允许缓存。
fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn worker_not_enrolled() -> Response {
    ApiError::unauthorized(
        "harvest_worker_not_enrolled",
        "this worker has no enrollment record",
    )
    .into_response()
}

fn worker_revoked() -> Response {
    ApiError::forbidden(
        "harvest_worker_revoked",
        "this worker has been revoked; re-enroll and restart",
    )
    .into_response()
}

/// worker 面三个入口的共同前置：证书 ↔ body 一致、站点一致、worker 存在且未吊销。
#[allow(clippy::result_large_err)] // 与 api/agent_ops.rs / admin_auth.rs 同一口径：错误就是 Response
async fn authorize_worker(
    state: &ApiState,
    identity: &VerifiedHarvestIdentity,
    body_worker_id: &str,
) -> Result<HarvestWorker, Response> {
    if identity.worker_id != body_worker_id {
        return Err(ApiError::forbidden(
            "harvest_worker_mismatch",
            "client certificate does not match the requested worker_id",
        )
        .into_response());
    }
    if !site_matches(state, identity) {
        return Err(site_mismatch());
    }
    let worker = match state.store.get_harvest_worker(&identity.worker_id).await {
        Ok(worker) => worker,
        Err(err) => return Err(store_failed(err, "read harvest worker")),
    };
    let Some(worker) = worker else {
        return Err(worker_not_enrolled());
    };
    if worker.status == STATUS_REVOKED {
        return Err(worker_revoked());
    }
    Ok(worker)
}

// ─────────────────────────── worker 面（mTLS） ───────────────────────────

/// `POST /api/v1/harvest/work:poll`
pub async fn poll_work(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedHarvestIdentity>>,
    Json(input): Json<PollHarvestWork>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != wist_api::harvest_work::POLL_WORK_KIND {
        return ApiError::bad_request("invalid_harvest_work_poll", "invalid work poll")
            .into_response();
    }
    let Some(Extension(identity)) = identity else {
        return ApiError::unauthorized(
            "harvest_worker_unauthenticated",
            "missing or invalid client certificate",
        )
        .into_response();
    };
    let worker = match authorize_worker(&state, &identity, &input.worker_id).await {
        Ok(worker) => worker,
        Err(response) => return response,
    };

    let now = now_rfc3339();
    if let Err(err) = state
        .store
        .touch_harvest_worker(&identity.worker_id, &now)
        .await
    {
        return store_failed(err, "touch harvest worker");
    }
    if worker.status == "pending" {
        // 目标行更新：整行回写会把并发写入的吊销擦掉。
        if let Err(err) = state
            .store
            .promote_harvest_worker(&identity.worker_id, &now)
            .await
        {
            return store_failed(err, "promote harvest worker");
        }
    }

    match build_grant(&state, &worker).await {
        Ok(grant) => Json(grant).into_response(),
        Err(response) => response,
    }
}

#[allow(clippy::result_large_err)] // 同上：这里把 Response 当作 Err
async fn build_grant(
    state: &ApiState,
    worker: &HarvestWorker,
) -> Result<HarvestWorkGrant, Response> {
    let now = now_rfc3339();
    // 惰性回收：`deadline_at` 已过却还挂着的工作不能一直出现在下发列表里
    // （客户端会遵守 deadline，但它已经不 poll 了就没人回收）。
    if let Err(err) = state.store.expire_harvest_one_shot(&now).await {
        return Err(store_failed(err, "expire harvest one-shot"));
    }
    // standing / one_shot / sequence 必须来自同一读快照，否则客户端会按旧 seq 跳过新 spec。
    let snapshot = match state.store.harvest_grant(&worker.worker_id).await {
        Ok(snapshot) => snapshot,
        Err(err) => return Err(store_failed(err, "read harvest grant")),
    };
    let standing = snapshot.standing.filter(|row| row.status != STATUS_REVOKED);
    Ok(HarvestWorkGrant {
        worker_id: worker.worker_id.clone(),
        source_code: worker.source_code.clone(),
        standing: standing.map(|stored| StandingHarvestWork {
            work_id: stored.work_id,
            family: stored.family,
            spec: stored.spec,
            catalog_version: stored.catalog_version,
            proposal_id: stored.proposal_id,
            plan_version: stored.plan_version,
            effective_from: stored.effective_from,
            status: stored.status,
            updated_by: stored.updated_by,
            updated_at: stored.updated_at,
        }),
        one_shot: snapshot
            .one_shot
            .into_iter()
            .map(|stored| stored.work)
            .collect(),
        sequence: snapshot.sequence,
        granted_at: now,
    })
}

/// `POST /api/v1/harvest/work:ack`
pub async fn ack_work(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedHarvestIdentity>>,
    Json(input): Json<AckHarvestWork>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != wist_api::harvest_work::ACK_WORK_KIND {
        return ApiError::bad_request("invalid_harvest_work_ack", "invalid work ack")
            .into_response();
    }
    let Some(Extension(identity)) = identity else {
        return ApiError::unauthorized(
            "harvest_worker_unauthenticated",
            "missing or invalid client certificate",
        )
        .into_response();
    };
    if let Err(response) = authorize_worker(&state, &identity, &input.worker_id).await {
        return response;
    }

    let standing = match state.store.harvest_standing(&identity.worker_id).await {
        Ok(standing) => standing,
        Err(err) => return store_failed(err, "read harvest standing"),
    };
    let accepted_at = now_rfc3339();
    let Some(standing) = standing else {
        return Json(HarvestWorkAccepted {
            work_id: input.work_id,
            status: "unknown".to_string(),
            accepted_at,
        })
        .into_response();
    };
    if standing.work_id != input.work_id {
        return Json(HarvestWorkAccepted {
            work_id: input.work_id,
            status: "unknown".to_string(),
            accepted_at,
        })
        .into_response();
    }
    // 落后于期望版本 = `stale`：**不落库**（否则「已确认」会把漂移盖掉）。
    if input.plan_version < standing.plan_version {
        return Json(HarvestWorkAccepted {
            work_id: input.work_id,
            status: "stale".to_string(),
            accepted_at,
        })
        .into_response();
    }
    // 比期望还新 = 网关这边落后（库被回滚 / 重建）：回 `stale` 让客户端重新拉一份，
    // 回 `unknown` 会让它以为“这件活不存在”，漂移就永远清不掉。
    if input.plan_version > standing.plan_version {
        return Json(HarvestWorkAccepted {
            work_id: input.work_id,
            status: "stale".to_string(),
            accepted_at,
        })
        .into_response();
    }

    let ack = StoredHarvestAck {
        work_id: input.work_id.clone(),
        worker_id: identity.worker_id.clone(),
        work_kind: "standing".to_string(),
        plan_version: input.plan_version,
        acknowledged_at: accepted_at.clone(),
    };
    if let Err(err) = state.store.upsert_harvest_ack(&ack).await {
        return store_failed(err, "upsert harvest ack");
    }
    Json(HarvestWorkAccepted {
        work_id: input.work_id,
        status: "accepted".to_string(),
        accepted_at,
    })
    .into_response()
}

/// `POST /api/v1/harvest/work:result` —— 一次性工作的执行结果（覆盖式，终态不覆盖）。
///
/// 为什么一次性工作**不用** `work:ack`：ack 的语义是「我收到了这份 standing 的哪一版」
/// （带 `plan_version`）；一次性工作的回执就是它的**结果**（`running` → 终态）。
pub async fn report_result(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedHarvestIdentity>>,
    Json(input): Json<ReportHarvestResult>,
) -> Response {
    if input.api_version != API_VERSION_V1
        || input.kind != wist_api::harvest_work::REPORT_WORK_RESULT_KIND
    {
        return ApiError::bad_request("invalid_harvest_work_result", "invalid work result")
            .into_response();
    }
    let Some(Extension(identity)) = identity else {
        return ApiError::unauthorized(
            "harvest_worker_unauthenticated",
            "missing or invalid client certificate",
        )
        .into_response();
    };
    if let Err(response) = authorize_worker(&state, &identity, &input.worker_id).await {
        return response;
    }
    if !REPORTABLE_STATUSES.contains(&input.status.as_str()) {
        return ApiError::bad_request(
            "invalid_harvest_result_status",
            format!(
                "status 只接受 {}，收到 {:?}",
                REPORTABLE_STATUSES.join(" / "),
                input.status
            ),
        )
        .into_response();
    }

    let result = StoredHarvestResult {
        work_id: input.work_id.clone(),
        worker_id: identity.worker_id.clone(),
        status: input.status.clone(),
        detail: input.detail.clone(),
        reported_at: if input.reported_at.trim().is_empty() {
            now_rfc3339()
        } else {
            input.reported_at.clone()
        },
    };
    let outcome = match state.store.record_harvest_result(&result).await {
        Ok(outcome) => outcome,
        Err(err) => return store_failed(err, "record harvest work result"),
    };
    let accepted_at = now_rfc3339();
    Json(HarvestResultAccepted {
        work_id: input.work_id,
        status: match outcome {
            HarvestResultOutcome::Recorded => "accepted",
            HarvestResultOutcome::Stale => "stale",
            HarvestResultOutcome::Unknown => "unknown",
        }
        .to_string(),
        accepted_at,
    })
    .into_response()
}

/// `POST /api/v1/harvest/enroll` —— 接入券换客户端证书（与 agentd 同一套纪律）。
pub async fn enroll(
    State(state): State<ApiState>,
    Json(input): Json<HarvestEnrollmentRequest>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != wist_api::harvest_work::ENROLL_KIND {
        return ApiError::bad_request("invalid_harvest_enrollment", "invalid enrollment request")
            .into_response();
    }
    let expected_worker = format!("harvest:{}", input.source_code);
    if input.worker_id != expected_worker {
        return rejected("worker_id_must_match_source_code");
    }
    if !source_code_is_valid(&input.source_code) {
        return rejected("invalid_source_code");
    }
    let Some(ca) = state.agent_ca.as_deref() else {
        return rejected("certificate_authority_not_configured");
    };
    let csr = input.certificate_signing_request.trim();
    if csr.is_empty() {
        return rejected("missing_certificate_signing_request");
    }

    // 先签证书，后消费券：CSR 坏了不能把一次性券烧掉（agentd 的 reserve/rollback 同理）。
    let identity = HarvestCertificateIdentity::new(
        state.config.tenant_id.clone(),
        state.config.environment_id.clone(),
        input.source_code.clone(),
    );
    let issued =
        match ca.issue_harvest_certificate(csr, &identity, state.config.client_cert_ttl_seconds) {
            Ok(issued) => issued,
            Err(err) => {
                // 细节只进日志：对外只给稳定 code（不把解析器文本透给未认证方）。
                log::warn!("harvest enrollment rejected: invalid CSR: {err}");
                return rejected("invalid_certificate_signing_request");
            }
        };

    let now = now_rfc3339();
    let ticket_hash = sha256_hex(input.ticket.trim());
    let consumed = match state
        .store
        .consume_harvest_ticket(&ticket_hash, &now, &input.worker_id, &input.source_code)
        .await
    {
        Ok(consumed) => consumed,
        Err(err) => return store_failed(err, "consume harvest ticket"),
    };
    if consumed.is_none() {
        // 签出的证书没有送出去，也永远不会落库（没有凭据可撤销）。
        return rejected("invalid_or_expired_ticket");
    }

    let worker = HarvestWorker {
        worker_id: input.worker_id.clone(),
        source_code: input.source_code.clone(),
        instance_id: input.instance_id.clone(),
        status: "pending".to_string(),
        enrolled_at: now.clone(),
        last_seen_at: None,
        revoked_at: None,
        revoked_by: String::new(),
    };
    if let Err(err) = state.store.upsert_harvest_worker(&worker).await {
        return store_failed(err, "enroll harvest worker");
    }
    if let Err(err) = state
        .store
        .insert_harvest_certificate(&HarvestCertificateRecord {
            credential_id: format!("hcert:{}:{}", input.worker_id, issued.serial_hex),
            worker_id: input.worker_id.clone(),
            cert_serial: issued.serial_hex.clone(),
            cert_sha256: issued.fingerprint_sha256_hex.clone(),
            issued_at: now,
            not_after: issued.not_after.clone(),
            revoked_at: None,
        })
        .await
    {
        return store_failed(err, "record harvest certificate");
    }

    let response = Json(HarvestEnrollmentEnvelope {
        result: HarvestEnrollmentOutcome::accepted(
            input.worker_id,
            input.instance_id,
            issued.certificate_pem,
            ca.ca_certificate_pem(),
            issued.not_after,
        ),
    })
    .into_response();
    no_store(response)
}

/// `POST /api/v1/harvest/credentials:renew` —— 用上一张证书续期。
pub async fn renew(
    State(state): State<ApiState>,
    identity: Option<Extension<VerifiedHarvestIdentity>>,
    Json(input): Json<HarvestCertificateRenewal>,
) -> Response {
    if input.api_version != API_VERSION_V1
        || input.kind != wist_api::harvest_work::RENEW_CERTIFICATE_KIND
    {
        return ApiError::bad_request("invalid_harvest_renewal", "invalid certificate renewal")
            .into_response();
    }
    let Some(Extension(identity)) = identity else {
        return ApiError::unauthorized(
            "harvest_worker_unauthenticated",
            "missing or invalid client certificate",
        )
        .into_response();
    };
    if let Err(response) = authorize_worker(&state, &identity, &input.worker_id).await {
        return response;
    }
    let Some(ca) = state.agent_ca.as_deref() else {
        return ApiError::unavailable(
            "certificate_authority_not_configured",
            "gateway has no client CA configured",
        )
        .into_response();
    };
    let identity_cert = HarvestCertificateIdentity::new(
        state.config.tenant_id.clone(),
        state.config.environment_id.clone(),
        identity.source_code.clone(),
    );
    let issued = match ca.issue_harvest_certificate(
        input.certificate_signing_request.trim(),
        &identity_cert,
        state.config.client_cert_ttl_seconds,
    ) {
        Ok(issued) => issued,
        Err(err) => {
            return ApiError::bad_request(
                "invalid_certificate_signing_request",
                format!("invalid certificate signing request: {err}"),
            )
            .into_response();
        }
    };
    let now = now_rfc3339();
    if let Err(err) = state
        .store
        .insert_harvest_certificate(&HarvestCertificateRecord {
            credential_id: format!("hcert:{}:{}", input.worker_id, issued.serial_hex),
            worker_id: input.worker_id,
            cert_serial: issued.serial_hex.clone(),
            cert_sha256: issued.fingerprint_sha256_hex.clone(),
            issued_at: now,
            not_after: issued.not_after.clone(),
            revoked_at: None,
        })
        .await
    {
        return store_failed(err, "record harvest certificate");
    }
    let response = Json(HarvestCertificateRenewed {
        certificate_pem: issued.certificate_pem,
        ca_certificate_pem: ca.ca_certificate_pem().to_string(),
        not_after: issued.not_after,
    })
    .into_response();
    no_store(response)
}

fn rejected(reason: impl Into<String>) -> Response {
    Json(HarvestEnrollmentEnvelope {
        result: HarvestEnrollmentOutcome::rejected(reason),
    })
    .into_response()
}

// ─────────────────────────── 管理面 ───────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateTicketRequest {
    pub source_code: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PutStandingRequest {
    pub worker_id: String,
    pub spec: HarvestSpec,
    /// `active`（默认）| `paused`
    #[serde(default)]
    pub status: Option<String>,
}

/// `POST /api/v1/admin/harvest/enroll-ticket`
pub async fn create_ticket(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<CreateTicketRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let source_code = input.source_code.trim();
    if !source_code_is_valid(source_code) {
        return ApiError::bad_request(
            "invalid_source_code",
            "source_code 只允许 1..=64 位小写字母 / 数字 / `_` / `-`（它会进证书 SAN 与目录名）",
        )
        .into_response();
    }
    let ttl = input
        .ttl_seconds
        .unwrap_or(DEFAULT_TICKET_TTL_SECONDS)
        .clamp(60, MAX_TICKET_TTL_SECONDS);
    let ticket = match new_secret_token("hwt") {
        Ok(ticket) => ticket,
        Err(err) => {
            return ApiError::internal("harvest_ticket_failed", "failed to mint ticket", err)
                .into_response();
        }
    };
    let now = Utc::now();
    let expires_at = (now + Duration::seconds(ttl)).to_rfc3339();
    let worker_id = format!("harvest:{source_code}");
    if let Err(err) = state
        .store
        .create_harvest_ticket(&StoredHarvestTicket {
            ticket_hash: sha256_hex(&ticket),
            worker_id: worker_id.clone(),
            source_code: source_code.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires_at.clone(),
            consumed_at: None,
            created_by: admin_actor(&state.config),
        })
        .await
    {
        return store_failed(err, "create harvest ticket");
    }
    let response = Json(json!({
        "ticket": ticket,
        "worker_id": worker_id,
        "source_code": source_code,
        "expires_at": expires_at,
    }))
    .into_response();
    no_store(response)
}

/// `GET /api/v1/admin/harvest/workers`
pub async fn list_workers(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match state.store.list_harvest_workers().await {
        Ok(workers) => Json(json!({ "workers": workers })).into_response(),
        Err(err) => store_failed(err, "list harvest workers"),
    }
}

/// `POST /api/v1/admin/harvest/workers/{worker_id}/revoke`
///
/// 吊销 worker：状态转 `revoked`、凭据记录标吊销。三个 worker 入口都会因此返回 403。
pub async fn revoke_worker(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(worker_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let worker = match state.store.get_harvest_worker(&worker_id).await {
        Ok(Some(worker)) => worker,
        Ok(None) => {
            return ApiError::not_found(
                "harvest_worker_not_found",
                format!("unknown harvest worker {worker_id}"),
            )
            .into_response();
        }
        Err(err) => return store_failed(err, "read harvest worker"),
    };
    let now = now_rfc3339();
    let actor = admin_actor(&state.config);
    if let Err(err) = state
        .store
        .revoke_harvest_worker(&worker_id, &actor, &now)
        .await
    {
        return store_failed(err, "revoke harvest worker");
    }
    Json(json!({ "worker_id": worker.worker_id, "status": STATUS_REVOKED, "revoked_by": actor }))
        .into_response()
}

/// `PUT /api/v1/admin/harvest/standing` —— 授权 / 改 spec（`plan_version + 1`）。
pub async fn put_standing(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<PutStandingRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Err(reason) = validate_spec(&input.spec) {
        return ApiError::bad_request("invalid_harvest_spec", reason).into_response();
    }
    if let Some(status) = input.status.as_deref()
        && status != STATUS_ACTIVE
        && status != STATUS_PAUSED
    {
        return ApiError::bad_request(
            "invalid_standing_status",
            format!("status 只接受 {STATUS_ACTIVE} / {STATUS_PAUSED}，收到 {status}"),
        )
        .into_response();
    }
    let worker = match state.store.get_harvest_worker(&input.worker_id).await {
        Ok(Some(worker)) => worker,
        Ok(None) => {
            return ApiError::not_found(
                "harvest_worker_not_found",
                format!("unknown harvest worker {}", input.worker_id),
            )
            .into_response();
        }
        Err(err) => return store_failed(err, "read harvest worker"),
    };
    if worker.status == STATUS_REVOKED {
        return ApiError::conflict(
            "harvest_worker_revoked",
            "this worker is revoked; re-enroll before granting work",
        )
        .into_response();
    }

    let existing = match state.store.harvest_standing(&input.worker_id).await {
        Ok(existing) => existing,
        Err(err) => return store_failed(err, "read harvest standing"),
    };
    let now = now_rfc3339();
    let status = input
        .status
        .clone()
        .or_else(|| existing.as_ref().map(|row| row.status.clone()))
        .unwrap_or_else(|| STATUS_ACTIVE.to_string());
    let standing = StoredHarvestStanding {
        work_id: format!("hsw:{}:{}", input.worker_id, FAMILY_INVENTORY),
        worker_id: input.worker_id.clone(),
        family: FAMILY_INVENTORY.to_string(),
        spec: input.spec,
        catalog_version: 0,
        proposal_id: None,
        // 占位：真实版本由 `save_harvest_standing_bump` 在 SQL 里 +1 并返回。
        plan_version: 0,
        effective_from: now.clone(),
        status,
        updated_by: admin_actor(&state.config),
        updated_at: now,
    };
    let plan_version = match state.store.save_harvest_standing_bump(&standing).await {
        Ok(plan_version) => plan_version,
        Err(err) => return store_failed(err, "save harvest standing"),
    };
    Json(json!({
        "worker_id": standing.worker_id,
        "work_id": standing.work_id,
        "plan_version": plan_version,
        "status": standing.status,
        "effective_from": standing.effective_from,
    }))
    .into_response()
}

/// `POST /api/v1/admin/harvest/standing/{work_id}/pause|resume|revoke`
pub async fn set_standing_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path((work_id, action)): Path<(String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let status = match action.as_str() {
        "pause" => STATUS_PAUSED,
        "resume" => STATUS_ACTIVE,
        "revoke" => STATUS_REVOKED,
        other => {
            return ApiError::bad_request(
                "unknown_standing_action",
                format!("unknown action {other}"),
            )
            .into_response();
        }
    };
    let existing = match state.store.harvest_standing_by_work_id(&work_id).await {
        Ok(Some(existing)) => existing,
        Ok(None) => {
            return ApiError::not_found(
                "harvest_standing_not_found",
                format!("unknown standing work {work_id}"),
            )
            .into_response();
        }
        Err(err) => return store_failed(err, "read harvest standing"),
    };
    if existing.status == STATUS_REVOKED {
        return ApiError::conflict(
            "harvest_standing_revoked",
            "撤销是终态：要重新采集请重新授权（plan_version 会重新从 1 开始）",
        )
        .into_response();
    }
    let now = now_rfc3339();
    let actor = admin_actor(&state.config);
    let plan_version = match state
        .store
        .set_harvest_standing_status(&work_id, status, &actor, &now)
        .await
    {
        Ok(Some(plan_version)) => plan_version,
        Ok(None) => {
            // 读与写之间被撤销（或行消失）：不假装成功。
            return ApiError::conflict(
                "harvest_standing_changed",
                "standing changed concurrently (revoked or removed); re-read and retry",
            )
            .into_response();
        }
        Err(err) => return store_failed(err, "update harvest standing status"),
    };
    Json(json!({
        "work_id": work_id,
        "worker_id": existing.worker_id,
        "status": status,
        "plan_version": plan_version,
    }))
    .into_response()
}

/// `GET /api/v1/admin/harvest/works` —— 页面只读视图：standing + 确认 + 漂移。
pub async fn list_works(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let standings = match state.store.list_harvest_standings().await {
        Ok(standings) => standings,
        Err(err) => return store_failed(err, "list harvest standings"),
    };
    let acks = match state.store.list_harvest_acks().await {
        Ok(acks) => acks,
        Err(err) => return store_failed(err, "list harvest acks"),
    };
    let ack_by_work: std::collections::HashMap<&str, &StoredHarvestAck> =
        acks.iter().map(|ack| (ack.work_id.as_str(), ack)).collect();
    let mut works = Vec::with_capacity(standings.len());
    for standing in &standings {
        let ack = ack_by_work.get(standing.work_id.as_str()).copied();
        // 三态：已同步 / 下发中（还没到宽限期）/ 漂移。"未确认" 不能一律当漂移 ——
        // 刚保存的授权在采集器下一次 poll 之前本来就是没 ack 的。
        let ack_state = if standing.status != STATUS_ACTIVE {
            "inactive"
        } else {
            match ack {
                Some(ack) if ack.plan_version == standing.plan_version => "in_sync",
                Some(_) => "drift",
                None => {
                    if within_ack_grace(&standing.updated_at) {
                        "awaiting_ack"
                    } else {
                        "drift"
                    }
                }
            }
        };
        works.push(json!({
            "worker_id": standing.worker_id,
            "work_id": standing.work_id,
            "family": standing.family,
            "spec": standing.spec,
            "plan_version": standing.plan_version,
            "status": standing.status,
            "effective_from": standing.effective_from,
            "updated_by": standing.updated_by,
            "updated_at": standing.updated_at,
            "ack": ack,
            "ack_state": ack_state,
            "drift": ack_state == "drift",
        }));
    }
    let results = match state.store.list_harvest_results().await {
        Ok(results) => results,
        Err(err) => return store_failed(err, "list harvest work results"),
    };
    // 页面刷新也是一次回收时机：没有人 poll 的站点也要能看到「早就过期了」。
    if let Err(err) = state.store.expire_harvest_one_shot(&now_rfc3339()).await {
        return store_failed(err, "expire harvest one-shot");
    }
    let one_shots = match state.store.list_harvest_one_shot_all().await {
        Ok(one_shots) => one_shots,
        Err(err) => return store_failed(err, "list harvest one-shot work"),
    };
    let result_by_work: std::collections::HashMap<&str, &StoredHarvestResult> = results
        .iter()
        .map(|row| (row.work_id.as_str(), row))
        .collect();
    let one_shot: Vec<serde_json::Value> = one_shots
        .iter()
        .map(|stored| {
            let work = &stored.work;
            json!({
                "worker_id": stored.worker_id,
                "work_id": work.work_id,
                "action": work.action,
                "spec": work.spec,
                "scheduled_at": work.scheduled_at,
                "deadline_at": work.deadline_at,
                "timeout_seconds": work.timeout_seconds,
                "status": work.status,
                "outstanding": work.is_outstanding(),
                "issued_by": work.issued_by,
                "issued_at": work.issued_at,
                // 结果单独一块："做完了吗"（status）与"做得怎么样"（detail）是两件事。
                "result": result_by_work.get(work.work_id.as_str()),
            })
        })
        .collect();
    Json(json!({ "works": works, "one_shot": one_shot })).into_response()
}

/// 一次性工作的派发请求（页面按钮）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchOneShotRequest {
    pub worker_id: String,
    /// `inventory.run` | `inventory.rescan`。
    pub action: String,
    /// 可选覆盖：不给就用数据源本机配置（与 standing 同一个口径）。
    #[serde(default)]
    pub spec: Option<OneShotHarvestSpec>,
    #[serde(default)]
    pub scheduled_at: Option<String>,
    #[serde(default)]
    pub deadline_at: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<i64>,
    #[serde(default)]
    pub interruptible: Option<bool>,
}

/// `POST /api/v1/admin/harvest/one-shot` —— 派一件一次性工作（页面「立即采集」）。
pub async fn dispatch_one_shot(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<DispatchOneShotRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if !ONE_SHOT_ACTIONS.contains(&input.action.as_str()) {
        return ApiError::bad_request(
            "invalid_harvest_action",
            format!(
                "未知动作 {:?}（可选：{}）",
                input.action,
                ONE_SHOT_ACTIONS.join(" / ")
            ),
        )
        .into_response();
    }
    let worker = match state.store.get_harvest_worker(&input.worker_id).await {
        Ok(Some(worker)) => worker,
        Ok(None) => {
            return ApiError::not_found(
                "harvest_worker_not_found",
                format!("unknown harvest worker {}", input.worker_id),
            )
            .into_response();
        }
        Err(err) => return store_failed(err, "read harvest worker"),
    };
    if worker.status == STATUS_REVOKED {
        return ApiError::conflict(
            "harvest_worker_revoked",
            "this worker is revoked; re-enroll before dispatching work",
        )
        .into_response();
    }

    let now = Utc::now();
    let timeout_seconds = input
        .timeout_seconds
        .unwrap_or(DEFAULT_ONE_SHOT_TIMEOUT_SECONDS)
        .clamp(60, MAX_ONE_SHOT_TIMEOUT_SECONDS);
    let scheduled_at = match input.scheduled_at.as_deref() {
        Some(text) => match chrono::DateTime::parse_from_rfc3339(text.trim()) {
            Ok(at) => at.with_timezone(&Utc).to_rfc3339(),
            Err(err) => {
                return ApiError::bad_request(
                    "invalid_harvest_schedule",
                    format!("scheduled_at 需要 RFC3339：{err}"),
                )
                .into_response();
            }
        },
        None => now.to_rfc3339(),
    };
    let deadline_at = match input.deadline_at.as_deref() {
        Some(text) => match chrono::DateTime::parse_from_rfc3339(text.trim()) {
            Ok(at) if at.with_timezone(&Utc) <= now => {
                return ApiError::bad_request(
                    "invalid_harvest_schedule",
                    "deadline_at 必须在将来（否则派下去就已经是过期活）",
                )
                .into_response();
            }
            Ok(at) => at.with_timezone(&Utc).to_rfc3339(),
            Err(err) => {
                return ApiError::bad_request(
                    "invalid_harvest_schedule",
                    format!("deadline_at 需要 RFC3339：{err}"),
                )
                .into_response();
            }
        },
        None => (now + Duration::seconds(timeout_seconds)).to_rfc3339(),
    };

    // `inventory.rescan` 的语义就是“忽略可续跑 spool”，不接受调用方把它设成 false。
    let mut spec = input.spec.unwrap_or_default();
    if input.action == "inventory.rescan" {
        spec.fresh = Some(true);
    }
    if let Err(reason) = validate_one_shot_spec(&spec) {
        return ApiError::bad_request("invalid_harvest_spec", reason).into_response();
    }

    let work = OneShotHarvestWork {
        work_id: one_shot_work_id(&input.worker_id, &input.action, now),
        action: input.action,
        spec,
        scheduled_at,
        deadline_at: deadline_at.clone(),
        timeout_seconds,
        interruptible: input.interruptible.unwrap_or(true),
        // 落库即 `dispatched`；采集器拿到后自己上报 `running`。
        status: "dispatched".to_string(),
        attempt: 0,
        issued_by: admin_actor(&state.config),
        issued_at: now.to_rfc3339(),
    };
    if let Err(err) = state
        .store
        .save_harvest_one_shot(&StoredHarvestOneShot {
            worker_id: input.worker_id.clone(),
            work: work.clone(),
        })
        .await
    {
        return store_failed(err, "save harvest one-shot work");
    }
    // 序号变了 = 客户端下一拍就能看见（不依赖它逐条比对）。
    if let Err(err) = state
        .store
        .bump_harvest_sequence(&input.worker_id, &now.to_rfc3339())
        .await
    {
        return store_failed(err, "bump harvest sequence");
    }
    Json(json!({
        "worker_id": input.worker_id,
        "work_id": work.work_id,
        "action": work.action,
        "status": work.status,
        "deadline_at": deadline_at,
    }))
    .into_response()
}

/// `POST /api/v1/admin/harvest/one-shot/{work_id}/cancel` —— 撤回还没跑完的一次性工作。
pub async fn cancel_one_shot(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(work_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let changed = match state
        .store
        .finish_harvest_one_shot(&work_id, "canceled")
        .await
    {
        Ok(changed) => changed,
        Err(err) => return store_failed(err, "cancel harvest one-shot work"),
    };
    Json(json!({ "work_id": work_id, "status": "canceled", "changed": changed })).into_response()
}

fn one_shot_work_id(worker_id: &str, action: &str, at: chrono::DateTime<Utc>) -> String {
    // 同一秒里连点两次也不能撞主键：尾部跟一段随机符号。
    let salt = sha256_hex(&format!(
        "{worker_id}:{action}:{}",
        at.timestamp_nanos_opt().unwrap_or_default()
    ));
    format!(
        "hos:{worker_id}:{action}:{}:{}",
        at.format("%Y%m%dT%H%M%SZ"),
        &salt[..8]
    )
}

fn validate_one_shot_spec(spec: &OneShotHarvestSpec) -> Result<(), String> {
    if let Some(assets) = spec.assets.as_ref() {
        for asset in assets {
            if !KNOWN_ASSETS.contains(&asset.as_str()) {
                return Err(format!(
                    "未知采集面 {asset}（可选：{}）",
                    KNOWN_ASSETS.join(" / ")
                ));
            }
        }
    }
    match spec.regions.as_ref() {
        None => {}
        Some(HarvestRegions::Auto(value)) if value == "auto" => {}
        Some(HarvestRegions::Auto(value)) => {
            return Err(format!(
                "regions 只接受字面量 \"auto\" 或区域数组，收到 {value:?}"
            ));
        }
        Some(HarvestRegions::List(list)) => {
            if list.is_empty() {
                return Err("regions 白名单不能为空（要全省略就写 \"auto\"）".to_string());
            }
            if list.iter().any(|region| region.trim().is_empty()) {
                return Err("regions 里有空串".to_string());
            }
        }
    }
    Ok(())
}

/// 授权刚下发时给采集器一个 poll 周期（30s × 10）的确认宽限期。
const ACK_GRACE_SECONDS: i64 = 300;

fn within_ack_grace(updated_at: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(updated_at)
        .map(|at| {
            Utc::now()
                .signed_duration_since(at.with_timezone(&Utc))
                .num_seconds()
                <= ACK_GRACE_SECONDS
        })
        .unwrap_or(false)
}

// ─────────────────────────── 校验 ───────────────────────────

fn validate_spec(spec: &HarvestSpec) -> Result<(), String> {
    if spec.credential_ref.trim().is_empty() {
        return Err("credential_ref 不能为空（它指向宿主 secret 文件里的键名）".to_string());
    }
    if spec.vendor.trim().is_empty() {
        return Err("vendor 不能为空".to_string());
    }
    for asset in &spec.assets {
        if !KNOWN_ASSETS.contains(&asset.as_str()) {
            return Err(format!(
                "未知采集面 {asset}（可选：{}）",
                KNOWN_ASSETS.join(" / ")
            ));
        }
    }
    match &spec.regions {
        HarvestRegions::Auto(value) if value == "auto" => {}
        HarvestRegions::Auto(value) => {
            return Err(format!(
                "regions 只接受字面量 \"auto\" 或区域数组，收到 {value:?}"
            ));
        }
        HarvestRegions::List(list) => {
            if list.is_empty() {
                return Err("regions 白名单不能为空（要全省略就写 \"auto\"）".to_string());
            }
            if list.iter().any(|region| region.trim().is_empty()) {
                return Err("regions 里有空串".to_string());
            }
        }
    }
    match &spec.cadence.mode[..] {
        "daily" => {
            let at = spec
                .cadence
                .at
                .as_deref()
                .ok_or_else(|| "cadence.mode=daily 需要 at（HH:MM）".to_string())?;
            NaiveTime::parse_from_str(at.trim(), "%H:%M")
                .map_err(|_| format!("cadence.at 需要 HH:MM，收到 {at:?}"))?;
        }
        "interval" => {
            let seconds = spec
                .cadence
                .seconds
                .ok_or_else(|| "cadence.mode=interval 需要 seconds".to_string())?;
            if seconds < 60 {
                return Err(format!("cadence.seconds 不能小于 60，收到 {seconds}"));
            }
        }
        "on_demand" => {}
        other => return Err(format!("未知 cadence.mode {other}")),
    }
    Ok(())
}
