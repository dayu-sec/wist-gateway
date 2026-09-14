use std::net::SocketAddr;

use axum::{
    extract::{connect_info::ConnectInfo, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use wist_contracts::enrollment::{
    CredentialBundle, EnrollmentOutcome, EnrollmentEnvelope,
    EnrollmentStatus, AgentIdentity, AgentIdentityStatus, EnrollmentRequest,
};

use crate::infra::{
    new_secret_token, sha256_hex, AdminConfig, AdminStore, StoredAgentRegistration,
    StoredCredentialStatus, StoredEnrollmentTokenStatus,
};

use super::{
    install::{recover_expired_reservation, token_hash},
    overview::record_recent_online_agent,
    rate_limit, ApiState,
};

const ENROLLMENT_AUTH_SCOPE: &str = "enrollment";
const NO_STORE: &str = "no-store";

pub async fn enroll_agent(
    State(state): State<ApiState>,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(input): Json<EnrollmentRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) = rate_limit::check_rate_limit(&state, &client_key, ENROLLMENT_AUTH_SCOPE)
    {
        return response;
    }
    let requested_at = input.requested_at.clone();
    let version = agent_version_from_capability_summary(&input.capability_summary);
    let result = agent_enrollment_result(&state.config, &state.store, input, &version);
    if result.status == EnrollmentStatus::Accepted {
        rate_limit::clear_auth_failures(&state, &client_key, ENROLLMENT_AUTH_SCOPE);
        if let (Some(agent_id), Some(instance_id)) =
            (result.agent_id.as_deref(), result.instance_id.as_deref())
        {
            record_recent_online_agent(
                &state.runtime,
                agent_id,
                instance_id,
                &version,
                &requested_at,
            );
        }
    } else {
        rate_limit::record_auth_failure(&state, &client_key, ENROLLMENT_AUTH_SCOPE);
    }
    match result.status {
        EnrollmentStatus::Accepted => eprintln!(
            "audit enrollment_accepted agent_id={} instance_id={} version={}",
            result.agent_id.as_deref().unwrap_or("unknown"),
            result.instance_id.as_deref().unwrap_or("unknown"),
            version,
        ),
        EnrollmentStatus::Rejected => eprintln!(
            "audit enrollment_rejected reason={} agent_id={}",
            result.reason_code.as_deref().unwrap_or("unknown"),
            result.agent_id.as_deref().unwrap_or("unknown"),
        ),
        EnrollmentStatus::PendingReview => {
            eprintln!("audit enrollment_pending_review");
        }
    }

    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(EnrollmentEnvelope { result }),
    )
        .into_response()
}

pub fn agent_enrollment_result(
    config: &AdminConfig,
    store: &AdminStore,
    input: EnrollmentRequest,
    version: &str,
) -> EnrollmentOutcome {
    agent_enrollment_result_with_token_issuer(config, store, input, version, new_secret_token)
}

pub(super) fn agent_enrollment_result_with_token_issuer(
    config: &AdminConfig,
    store: &AdminStore,
    input: EnrollmentRequest,
    version: &str,
    issue_secret_token: impl FnOnce(&str) -> Result<String, String>,
) -> EnrollmentOutcome {
    if let Err(reason) = validate_enrollment_message(&input) {
        return rejected_result(reason);
    }

    let instance_id = first_meaningful_identifier([
        Some(input.host_profile.node_id.as_str()),
        Some(input.host_profile.hostname.as_str()),
        Some(input.host_profile.machine_id.as_str()),
    ])
    .unwrap_or("agent-instance")
    .to_string();
    let agent_id = format!("agent-{}", stable_identifier(&instance_id));
    let reservation = match reserve_enrollment_token(config, store, &input, &agent_id) {
        Ok(reservation) => reservation,
        Err(reason) => return rejected_result(reason),
    };
    let bearer_token = match issue_secret_token("wic") {
        Ok(token) => token,
        Err(reason) => {
            let _ = rollback_enrollment_token_reservation(store, &reservation);
            return rejected_result(reason);
        }
    };
    let issued_at_time = chrono::Utc::now();
    let issued_at = issued_at_time.to_rfc3339();
    let not_after =
        (issued_at_time + chrono::Duration::seconds(config.credential_ttl_seconds)).to_rfc3339();
    let credential_id = format!("cred-{}", stable_identifier(&agent_id));
    let identity = AgentIdentity {
        agent_id: agent_id.clone(),
        instance_id: instance_id.clone(),
        tenant_id: config.tenant_id.clone(),
        environment_id: config.environment_id.clone(),
        node_id: input.host_profile.node_id.clone(),
        issued_at: issued_at.clone(),
        expires_at: None,
        status: AgentIdentityStatus::Active,
    };
    let credential_bundle = CredentialBundle {
        credential_id: credential_id.clone(),
        agent_id: agent_id.clone(),
        instance_id: instance_id.clone(),
        auth_scheme: Some("bearer".to_string()),
        bearer_token: Some(bearer_token.clone()),
        certificate: None,
        private_key_ref: None,
        ca_bundle: None,
        issued_at: issued_at.clone(),
        not_before: Some(issued_at.clone()),
        not_after: Some(not_after),
    };

    let result = EnrollmentOutcome {
        status: EnrollmentStatus::Accepted,
        reason_code: None,
        agent_id: Some(agent_id),
        instance_id: Some(instance_id),
        issued_identity: Some(identity),
        credential_bundle: Some(credential_bundle),
        initial_config: None,
        policy_binding: None,
    };
    if let Err(reason) =
        commit_reserved_registration(config, store, &input, &result, version, &bearer_token)
    {
        let _ = rollback_enrollment_token_reservation(store, &reservation);
        return rejected_result(reason);
    }
    result
}

fn validate_enrollment_message(input: &EnrollmentRequest) -> Result<(), String> {
    if input.api_version != "v1" {
        return Err("unsupported_api_version".to_string());
    }
    if input.kind != "submit_enrollment_request" {
        return Err("invalid_request_kind".to_string());
    }
    Ok(())
}

struct EnrollmentTokenReservation {
    token_hash: String,
}

fn reserve_enrollment_token(
    config: &AdminConfig,
    store: &AdminStore,
    input: &EnrollmentRequest,
    agent_id: &str,
) -> Result<EnrollmentTokenReservation, String> {
    let token_hash = token_hash(&input.token);
    let reserve_result = store
        .update_result(|snapshot| {
            let now = chrono::Utc::now();
            let Some(token) = snapshot.enrollment_tokens.get_mut(&token_hash) else {
                return Err("invalid_enrollment_token".to_string());
            };
            if token.tenant_id != config.tenant_id || token.environment_id != config.environment_id
            {
                return Err("invalid_enrollment_token".to_string());
            }
            recover_expired_reservation(token, &now);
            if token.status != StoredEnrollmentTokenStatus::Active
                || token.used_count >= token.max_uses
                || token.token_hash != token_hash
            {
                return Err("invalid_enrollment_token".to_string());
            }
            let expires_at = match chrono::DateTime::parse_from_rfc3339(&token.expires_at) {
                Ok(value) => value.with_timezone(&chrono::Utc),
                Err(_) => return Err("invalid_enrollment_token".to_string()),
            };
            if chrono::Utc::now() >= expires_at {
                return Err("invalid_enrollment_token".to_string());
            }
            if snapshot.agents.contains_key(agent_id) {
                return Err("duplicate_agent_registration".to_string());
            }

            token.used_count = token.used_count.saturating_add(1);
            token.reserved_at = Some(now.to_rfc3339());
            token.status = StoredEnrollmentTokenStatus::Reserved;
            Ok(EnrollmentTokenReservation {
                token_hash: token_hash.clone(),
            })
        })
        .map_err(|err| err.to_string())?;
    reserve_result
}

fn commit_reserved_registration(
    config: &AdminConfig,
    store: &AdminStore,
    input: &EnrollmentRequest,
    result: &EnrollmentOutcome,
    version: &str,
    bearer_token: &str,
) -> Result<(), String> {
    let token_hash = token_hash(&input.token);
    let agent_id = result
        .agent_id
        .as_deref()
        .ok_or_else(|| "accepted_result_missing_agent_id".to_string())?;
    let instance_id = result
        .instance_id
        .as_deref()
        .ok_or_else(|| "accepted_result_missing_instance_id".to_string())?;
    let now = chrono::Utc::now().to_rfc3339();
    let credential = result
        .credential_bundle
        .as_ref()
        .ok_or_else(|| "accepted_result_missing_credential_bundle".to_string())?;
    let registered_at = chrono::DateTime::parse_from_rfc3339(&input.requested_at)
        .map(|value| value.with_timezone(&chrono::Utc).to_rfc3339())
        .unwrap_or_else(|_| now.clone());

    let commit_result = store
        .update_result(|snapshot| {
            let Some(token) = snapshot.enrollment_tokens.get_mut(&token_hash) else {
                return Err("invalid_enrollment_token".to_string());
            };
            if token.status != StoredEnrollmentTokenStatus::Reserved
                || token.token_hash != token_hash
            {
                return Err("invalid_enrollment_token".to_string());
            }
            if snapshot.agents.contains_key(agent_id) {
                return Err("duplicate_agent_registration".to_string());
            }
            token.status = if token.used_count >= token.max_uses {
                StoredEnrollmentTokenStatus::Used
            } else {
                StoredEnrollmentTokenStatus::Active
            };
            token.reserved_at = None;

            snapshot.agents.insert(
                agent_id.to_string(),
                StoredAgentRegistration {
                    agent_id: agent_id.to_string(),
                    instance_id: instance_id.to_string(),
                    tenant_id: config.tenant_id.clone(),
                    environment_id: config.environment_id.clone(),
                    node_id: input.host_profile.node_id.clone(),
                    hostname: input.host_profile.hostname.clone(),
                    machine_id: input.host_profile.machine_id.clone(),
                    version: version.to_string(),
                    credential_id: credential.credential_id.clone(),
                    credential_token_hash: sha256_hex(bearer_token),
                    credential_issued_at: credential.issued_at.clone(),
                    credential_expires_at: credential.not_after.clone().unwrap_or_default(),
                    credential_status: StoredCredentialStatus::Active,
                    registered_at,
                    last_seen_at: now,
                    last_memory_bytes: None,
                    last_cpu_percent: None,
                    last_admin_latency_ms: None,
                    work_state_changes: None,
                },
            );
            Ok(())
        })
        .map_err(|err| err.to_string())?;
    commit_result
}

fn rollback_enrollment_token_reservation(
    store: &AdminStore,
    reservation: &EnrollmentTokenReservation,
) -> Result<(), String> {
    store
        .update(|snapshot| {
            let Some(token) = snapshot.enrollment_tokens.get_mut(&reservation.token_hash) else {
                return;
            };
            if token.status == StoredEnrollmentTokenStatus::Reserved {
                token.used_count = token.used_count.saturating_sub(1);
                token.reserved_at = None;
                token.status = StoredEnrollmentTokenStatus::Active;
            }
        })
        .map_err(|err| err.to_string())
}

fn rejected_result(reason_code: String) -> EnrollmentOutcome {
    EnrollmentOutcome {
        status: EnrollmentStatus::Rejected,
        reason_code: Some(reason_code),
        agent_id: None,
        instance_id: None,
        issued_identity: None,
        credential_bundle: None,
        initial_config: None,
        policy_binding: None,
    }
}

fn agent_version_from_capability_summary(summary: &str) -> String {
    summary
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("version=").map(str::trim))
        .filter(|value| !value.is_empty())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .to_string()
}

fn first_meaningful_identifier<'a>(
    values: impl IntoIterator<Item = Option<&'a str>>,
) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| is_meaningful_identifier(value))
}

fn is_meaningful_identifier(value: &str) -> bool {
    !value.is_empty() && !matches!(value, "unknown" | "local-node" | "agent-instance")
}

fn stable_identifier(value: &str) -> String {
    let normalized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let normalized = normalized.trim_matches('-');
    if normalized.is_empty() {
        "generated".to_string()
    } else {
        normalized.to_string()
    }
}
