use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use wist_contracts::enrollment::{
    AgentIdentity, AgentIdentityStatus, CredentialBundle, EnrollmentEnvelope, EnrollmentOutcome,
    EnrollmentRequest, EnrollmentStatus,
};

use crate::infra::{
    AdminConfig, CommitRegistration, ReserveEnrollmentToken, Store, new_secret_token, sha256_hex,
};

use super::{
    ApiState,
    install::{ENROLLMENT_TOKEN_RESERVATION_TTL_SECONDS, token_hash},
    overview::record_recent_online_agent,
    rate_limit,
};

const ENROLLMENT_AUTH_SCOPE: &str = "enrollment";
const NO_STORE: &str = "no-store";

pub async fn enroll_agent(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<EnrollmentRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) = rate_limit::check_rate_limit(&state, &client_key, ENROLLMENT_AUTH_SCOPE)
    {
        return response;
    }
    let requested_at = input.requested_at.clone();
    let version = agent_version_from_capability_summary(&input.capability_summary);
    let result = agent_enrollment_result(&state.config, &state.store, input, &version).await;
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

pub async fn agent_enrollment_result(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    input: EnrollmentRequest,
    version: &str,
) -> EnrollmentOutcome {
    agent_enrollment_result_with_token_issuer(config, store, input, version, new_secret_token).await
}

pub(super) async fn agent_enrollment_result_with_token_issuer(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
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
    let reservation = match reserve_enrollment_token(config, store, &input, &agent_id).await {
        Ok(reservation) => reservation,
        Err(reason) => return rejected_result(reason),
    };
    let bearer_token = match issue_secret_token("wic") {
        Ok(token) => token,
        Err(reason) => {
            let _ = rollback_enrollment_token_reservation(store, &reservation).await;
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
        commit_reserved_registration(config, store, &input, &result, version, &bearer_token).await
    {
        let _ = rollback_enrollment_token_reservation(store, &reservation).await;
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

async fn reserve_enrollment_token(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    input: &EnrollmentRequest,
    agent_id: &str,
) -> Result<EnrollmentTokenReservation, String> {
    let token_hash = token_hash(&input.token);
    let rejection = store
        .reserve_enrollment_token(&ReserveEnrollmentToken {
            token_hash: &token_hash,
            tenant_id: &config.tenant_id,
            environment_id: &config.environment_id,
            agent_id,
            reservation_ttl_seconds: ENROLLMENT_TOKEN_RESERVATION_TTL_SECONDS,
        })
        .await
        .map_err(|err| err.to_string())?
        .err();
    match rejection {
        Some(rejection) => Err(rejection.rejection_code().to_string()),
        None => Ok(EnrollmentTokenReservation { token_hash }),
    }
}

async fn commit_reserved_registration(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
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
    let credential_token_hash = sha256_hex(bearer_token);
    let credential_expires_at = credential.not_after.clone().unwrap_or_default();

    // token 状态收尾（used/reserved_at）与 agents 落库现在都在 store 单事务内完成。
    let rejection = store
        .commit_reserved_registration(&CommitRegistration {
            token_hash: &token_hash,
            agent_id,
            instance_id,
            boot_id: "",
            tenant_id: &config.tenant_id,
            environment_id: &config.environment_id,
            node_id: &input.host_profile.node_id,
            hostname: &input.host_profile.hostname,
            machine_id: &input.host_profile.machine_id,
            version,
            credential_id: &credential.credential_id,
            credential_token_hash: &credential_token_hash,
            credential_issued_at: &credential.issued_at,
            credential_expires_at: &credential_expires_at,
            registered_at: &registered_at,
            now: &now,
        })
        .await
        .map_err(|err| err.to_string())?
        .err();
    match rejection {
        Some(rejection) => Err(rejection.rejection_code().to_string()),
        None => Ok(()),
    }
}

async fn rollback_enrollment_token_reservation(
    store: &Arc<dyn Store>,
    reservation: &EnrollmentTokenReservation,
) -> Result<(), String> {
    store
        .rollback_enrollment_token_reservation(&reservation.token_hash)
        .await
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
