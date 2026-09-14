use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use crate::infra::{
    new_secret_token, sha256_hex,
    victoria_metrics::{import_lines, metric_line},
    StoredAgentRegistration, StoredCredentialStatus,
};
use insight_control::types::DateTime;
use insight_control::{
    ActionResultAccepted, AgentControlCommandsReturned, AgentHello, AgentStatusAccepted,
    PollControlCommands, ReportActionResult,
};
use wist_contracts::enrollment::{
    CredentialBundle, CredentialRenewed, CredentialRenewal,
    RENEW_AGENT_CREDENTIAL_KIND,
};
use wist_reporting::{
    ActionResultReceipt, HealthState, MetricsHealthSnapshot, RuntimeHealthSnapshot,
};

use super::ApiState;

pub async fn submit_agent_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<AgentHello>,
) -> Response {
    match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id) {
        Ok(agent) => {
            let now = DateTime::now();
            let now_utc = chrono::Utc::now();
            let last_seen_at = now_utc.to_rfc3339();
            let timestamp_ms = now_utc.timestamp_millis();
            let memory_bytes = input.memory_bytes.map(|value| value as u64);
            let cpu_percent = input.cpu_percent;
            let admin_latency_ms = input.admin_latency_ms.map(|value| value as u64);
            let update_result = state.store.update(|snapshot| {
                if let Some(stored) = snapshot.agents.get_mut(&agent.agent_id) {
                    stored.version = input.version.clone();
                    stored.last_seen_at = last_seen_at;
                    stored.last_memory_bytes = memory_bytes;
                    stored.last_cpu_percent = cpu_percent;
                    stored.last_admin_latency_ms = admin_latency_ms;
                    stored.work_state_changes = input.work_state_changes.clone();
                }
            });
            if let Err(err) = update_result {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to update agent status: {err}"),
                )
                    .into_response();
            }
            // 统一进 VM：agent 自身运行指标以时间序列写入，文件只保留最新值缓存。
            let lines: Vec<serde_json::Value> = [
                memory_bytes.map(|value| {
                    metric_line(
                        "agent.memory.bytes",
                        &agent.agent_id,
                        "agent_metrics",
                        value as f64,
                        timestamp_ms,
                    )
                }),
                cpu_percent.map(|value| {
                    metric_line(
                        "agent.cpu.percent",
                        &agent.agent_id,
                        "agent_metrics",
                        value,
                        timestamp_ms,
                    )
                }),
                admin_latency_ms.map(|value| {
                    metric_line(
                        "agent.admin_latency.ms",
                        &agent.agent_id,
                        "agent_metrics",
                        value as f64,
                        timestamp_ms,
                    )
                }),
            ]
            .into_iter()
            .flatten()
            .collect();
            if !lines.is_empty() {
                if let Err(err) = import_lines(&state.config.victoria_metrics_url, &lines).await {
                    eprintln!(
                        "warn agent metrics import failed agent_id={} instance_id={}: {err}",
                        agent.agent_id, agent.instance_id
                    );
                }
            }
            (
                StatusCode::ACCEPTED,
                Json(AgentStatusAccepted {
                    snapshot: RuntimeHealthSnapshot {
                        running_count: 0,
                        state: HealthState::Healthy,
                        queue_depth: 0,
                        metrics: MetricsHealthSnapshot {
                            sample_count: 0,
                            target_count: 0,
                            failure_count: 0,
                            active: true,
                        },
                        updated_at: now,
                        reporting_count: 0,
                        discovery: "accepted".to_string(),
                    },
                }),
            )
                .into_response()
        }
        Err(response) => response,
    }
}

pub async fn poll_control_commands(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<PollControlCommands>,
) -> Response {
    match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id) {
        Ok(_) => (
            StatusCode::OK,
            Json(AgentControlCommandsReturned {
                messages: Vec::new(),
                next_sequence: input.last_seen_sequence,
                agent_id: input.agent_id,
                returned_at: DateTime::now(),
                instance_id: input.instance_id,
            }),
        )
            .into_response(),
        Err(response) => response,
    }
}

pub async fn renew_agent_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CredentialRenewal>,
) -> Response {
    if input.api_version != "v1" || input.kind != RENEW_AGENT_CREDENTIAL_KIND {
        return (
            StatusCode::BAD_REQUEST,
            "invalid credential renewal request",
        )
            .into_response();
    }
    if input.credential_request != "bearer" {
        return (StatusCode::BAD_REQUEST, "unsupported credential request").into_response();
    }
    let Some(current_token) = bearer_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer credential").into_response();
    };
    let current_token_hash = sha256_hex(current_token);

    let agent = match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id) {
        Ok(agent) => agent,
        Err(response) => return response,
    };
    let bearer_token = match new_secret_token("wic") {
        Ok(token) => token,
        Err(reason) => return (StatusCode::INTERNAL_SERVER_ERROR, reason).into_response(),
    };
    let issued_at_time = chrono::Utc::now();
    let issued_at = issued_at_time.to_rfc3339();
    let not_after = (issued_at_time
        + chrono::Duration::seconds(state.config.credential_ttl_seconds))
    .to_rfc3339();
    let credential_id = match new_secret_token("cred") {
        Ok(id) => id,
        Err(reason) => return (StatusCode::INTERNAL_SERVER_ERROR, reason).into_response(),
    };
    let bundle = CredentialBundle {
        credential_id: credential_id.clone(),
        agent_id: agent.agent_id.clone(),
        instance_id: agent.instance_id.clone(),
        auth_scheme: Some("bearer".to_string()),
        bearer_token: Some(bearer_token.clone()),
        certificate: None,
        private_key_ref: None,
        ca_bundle: None,
        issued_at: issued_at.clone(),
        not_before: Some(issued_at.clone()),
        not_after: Some(not_after.clone()),
    };

    let update_result = state.store.update(|snapshot| {
        let Some(stored) = snapshot.agents.get_mut(&agent.agent_id) else {
            return false;
        };
        if stored.instance_id != agent.instance_id
            || stored.credential_token_hash != current_token_hash
            || stored.credential_status != StoredCredentialStatus::Active
        {
            return false;
        }
        stored.credential_id = credential_id;
        stored.credential_token_hash = sha256_hex(&bearer_token);
        stored.credential_issued_at = issued_at;
        stored.credential_expires_at = not_after;
        true
    });
    match update_result {
        Ok(true) => {
            eprintln!(
                "audit credential_renewed agent_id={} instance_id={}",
                agent.agent_id, agent.instance_id,
            );
            (
                StatusCode::OK,
                Json(CredentialRenewed {
                    credential_bundle: bundle,
                }),
            )
                .into_response()
        }
        Ok(false) => (StatusCode::UNAUTHORIZED, "invalid agent credential").into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to renew agent credential: {err}"),
        )
            .into_response(),
    }
}

pub async fn report_action_result(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ReportActionResult>,
) -> Response {
    match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id) {
        Ok(_) => (
            StatusCode::ACCEPTED,
            Json(ActionResultAccepted {
                receipt: ActionResultReceipt {
                    agent_id: input.agent_id,
                    report_id: input.report_id,
                    accepted_at: DateTime::now(),
                },
            }),
        )
            .into_response(),
        Err(response) => response,
    }
}

fn authenticate_agent(
    state: &ApiState,
    headers: &HeaderMap,
    agent_id: &str,
    instance_id: &str,
) -> Result<StoredAgentRegistration, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err((StatusCode::UNAUTHORIZED, "missing bearer credential").into_response());
    };
    let token_hash = sha256_hex(token);
    let snapshot = state.store.load().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent credential store: {err}"),
        )
            .into_response()
    })?;
    let Some(agent) = snapshot.agents.get(agent_id) else {
        return Err((StatusCode::UNAUTHORIZED, "unknown agent credential").into_response());
    };
    if agent.instance_id != instance_id
        || !constant_time_eq(
            agent.credential_token_hash.as_bytes(),
            token_hash.as_bytes(),
        )
    {
        return Err((StatusCode::UNAUTHORIZED, "invalid agent credential").into_response());
    }
    if agent.credential_status != StoredCredentialStatus::Active {
        return Err((StatusCode::UNAUTHORIZED, "agent credential is not active").into_response());
    }
    if credential_is_expired(&agent.credential_expires_at) {
        return Err((StatusCode::UNAUTHORIZED, "agent credential is expired").into_response());
    }
    Ok(agent.clone())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn credential_is_expired(expires_at: &str) -> bool {
    let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return true;
    };
    chrono::Utc::now() >= expires_at.with_timezone(&chrono::Utc)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= (left_byte ^ right_byte) as usize;
    }
    diff == 0
}
