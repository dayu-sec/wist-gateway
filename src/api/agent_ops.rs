use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::infra::{
    AgentFactSummaryMarks, AgentStatusUpdate, RenewCredential, StoredAgentFactSummary,
    StoredAgentRegistration, StoredCredentialStatus, StoredPurposeSuggestion, new_secret_token,
    sha256_hex,
    victoria_metrics::{import_lines, metric_line},
};
use wist_contracts::API_VERSION_V1;
use wist_contracts::enrollment::{
    CredentialBundle, CredentialRenewal, CredentialRenewed, RENEW_AGENT_CREDENTIAL_KIND,
};
use wist_contracts::fact_summary::FactContent;
use wist_contracts::gateway::{
    ActionResultAck, AgentStatusAck, AgentStatusReport, DiscoveryPoliciesReturned,
    FactSummaryAccepted, FactSummaryAckStatus, POLL_DISCOVERY_POLICIES_KIND, PollDiscoveryPolicies,
    REPORT_AGENT_FACT_SUMMARY_KIND, ReportActionResult, ReportAgentFactSummary,
};
use wist_control::types::DateTime;
use wist_control::{AgentControlCommandsReturned, PollControlCommands};

use super::ApiState;

pub async fn submit_agent_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<AgentStatusReport>,
) -> Response {
    match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id).await {
        Ok(agent) => {
            let now_utc = chrono::Utc::now();
            let last_seen_at = now_utc.to_rfc3339();
            let timestamp_ms = now_utc.timestamp_millis();
            let memory_bytes = input.memory_bytes;
            let cpu_percent = input.cpu_percent;
            let admin_latency_ms = input.admin_latency_ms;
            let status_result = state
                .store
                .record_agent_status(&AgentStatusUpdate {
                    agent_id: &agent.agent_id,
                    instance_id: &input.instance_id,
                    boot_id: "",
                    version: &input.version,
                    last_seen_at: &last_seen_at,
                    memory_bytes,
                    cpu_percent,
                    admin_latency_ms,
                    work_state_changes: input.work_state_changes.clone(),
                })
                .await;
            match status_result {
                Ok(true) => {}
                Ok(false) => {
                    // 未知 agent 的状态上报不再静默成功：旧实现会丢弃该次上报，
                    // 这里显式返回 404，让上报方感知身份/凭据不一致。
                    return (
                        StatusCode::NOT_FOUND,
                        format!("unknown agent {}", input.agent_id),
                    )
                        .into_response();
                }
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to update agent status: {err}"),
                    )
                        .into_response();
                }
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
            if !lines.is_empty()
                && let Err(err) = import_lines(&state.config.victoria_metrics_url, &lines).await
            {
                eprintln!(
                    "warn agent metrics import failed agent_id={} instance_id={}: {err}",
                    agent.agent_id, agent.instance_id
                );
            }
            (
                StatusCode::ACCEPTED,
                Json(AgentStatusAck {
                    agent_id: input.agent_id,
                    instance_id: input.instance_id,
                    acknowledged_at: now_utc.to_rfc3339(),
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
    match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id).await {
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

/// agentd 拉取发现方向策略表（控制面，复用 agent 凭据）。
///
/// 未配置策略表时回 **503**，而不是一份空表：空表会让「平台没发布策略」与
/// 「这台网关从未配置」变得无法区分，而 agentd 必须能分辨才能决定是应用空策略
/// 还是继续用自己的内建默认值 —— 静默发空表等于把平台的配置缺失伪装成一次成功下发。
///
/// 策略表是幂等内容：拉到的 `policy_version` 未变时由 agentd 自行跳过重算。
pub async fn poll_discovery_policies(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<PollDiscoveryPolicies>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_DISCOVERY_POLICIES_KIND {
        return (StatusCode::BAD_REQUEST, "invalid discovery policies poll").into_response();
    }
    if let Err(response) =
        authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id).await
    {
        return response;
    }
    match state.discovery_policies.as_deref() {
        Some(set) => (
            StatusCode::OK,
            Json(DiscoveryPoliciesReturned::from_set(
                set,
                chrono::Utc::now().to_rfc3339(),
            )),
        )
            .into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "discovery policy table is not configured",
        )
            .into_response(),
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

    let agent =
        match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id).await {
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

    let new_token_hash = sha256_hex(&bearer_token);
    let update_result = state
        .store
        .renew_agent_credential(&RenewCredential {
            agent_id: &agent.agent_id,
            instance_id: &agent.instance_id,
            current_token_hash: &current_token_hash,
            new_credential_id: &credential_id,
            new_token_hash: &new_token_hash,
            issued_at: &issued_at,
            expires_at: &not_after,
        })
        .await;
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
    match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id).await {
        Ok(_) => (
            StatusCode::ACCEPTED,
            Json(ActionResultAck {
                agent_id: input.agent_id,
                report_id: input.report_id,
                acknowledged_at: chrono::Utc::now().to_rfc3339(),
            }),
        )
            .into_response(),
        Err(response) => response,
    }
}

/// 接收 agentd 上报的事实**摘要**（对应模型 `ReportAgentFactSummary` / `IngestAgentFactSummary`）。
///
/// 幂等键是**网关自算**的内容摘要，不是 `input.content_digest`：
/// 用 agent 的声明判重的话，agent 侧算法一退化（比如退化成常量）就会让所有上报都命中重复，
/// 视图静默停在旧内容上，而且没有任何一层能发现。声明与自算不一致时记
/// `FactDigestMismatch` 告警（可能只是版本偏差，**不拒收**）。
///
/// 判重命中时**只刷留痕**（`revision` / `observed_at` / `process_count` / `received_at`）：
/// 内容没变就不重写、不重算、不重复计分，只记录「何时又见到同一份内容」。
pub async fn submit_agent_facts(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ReportAgentFactSummary>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != REPORT_AGENT_FACT_SUMMARY_KIND {
        return (StatusCode::BAD_REQUEST, "invalid agent fact summary report").into_response();
    }
    let agent =
        match authenticate_agent(&state, &headers, &input.agent_id, &input.instance_id).await {
            Ok(agent) => agent,
            Err(response) => return response,
        };
    // 先认证再验内容：不对未认证的请求做多余工。上限由网关自己封顶，不能指望 agent 守规矩。
    if let Err(detail) = validate_fact_summary(&input) {
        return (StatusCode::BAD_REQUEST, detail).into_response();
    }
    let received_at = chrono::Utc::now().to_rfc3339();

    let digest = gateway_digest(&input);
    if digest != input.content_digest {
        // 只作告警：不一致更可能是版本偏差（比如两侧实现不同源），不是非法输入。
        // 自己的这份才是判重依据，所以不一致时仍用 `digest` 走下去。
        eprintln!(
            "event=FactDigestMismatch agent_id={} agent={} gateway={}",
            agent.agent_id, input.content_digest, digest
        );
    }

    // 判重只读 `content_digest`：三个 JSON 列一旦损坏就不该把写路径也堵死。
    match state
        .store
        .get_agent_fact_summary_digest(&agent.agent_id)
        .await
    {
        Ok(Some(existing_digest)) if existing_digest == digest => {
            // 幂等命中：不改内容、不重算，只刷留痕 + 回带已存建议。
            // 注意「不过期自愈」是有意的：这条路径只读一个 id，不做重算；规则册换版本留下的
            // 过期建议由读取路径（`ensure_fresh_suggestion`）负责。
            let marks = AgentFactSummaryMarks {
                revision: input.revision,
                observed_at: input.observed_at.clone(),
                process_count: input.process_count,
                received_at: received_at.clone(),
            };
            match state
                .store
                .touch_agent_fact_summary_marks(&agent.agent_id, &marks)
                .await
            {
                Ok(true) => {}
                // 行在判重与刷新之间消失了（并发删除）：下次上报会走覆盖写补回来，
                // 不值得为这个竞争把 agent 卡在 500 上。
                Ok(false) => eprintln!(
                    "warn agent fact summary vanished during dedupe agent_id={}",
                    agent.agent_id
                ),
                // 留痕刷不动不该让 agent 收到 500（它会一直重试）：内容确实没变，照回 duplicate。
                Err(err) => eprintln!(
                    "warn failed to refresh agent fact marks agent_id={}: {err}",
                    agent.agent_id
                ),
            }
            let suggestion_id = match state.store.get_purpose_suggestion(&agent.agent_id).await {
                Ok(suggestion) => suggestion.map(|suggestion| suggestion.suggestion_id),
                Err(err) => {
                    // 建议读不出来不该让 agent 收到 500（它会一直重试）：当作“这次没建议”。
                    eprintln!(
                        "warn failed to load purpose suggestion agent_id={}: {err}",
                        agent.agent_id
                    );
                    None
                }
            };
            return (
                StatusCode::ACCEPTED,
                Json(FactSummaryAccepted {
                    report_id: input.report_id,
                    agent_id: agent.agent_id,
                    content_digest: digest,
                    ack_status: FactSummaryAckStatus::Duplicate,
                    suggestion_id,
                    received_at,
                }),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load agent fact summary: {err}"),
            )
                .into_response();
        }
    }

    let summary = StoredAgentFactSummary {
        agent_id: agent.agent_id.clone(),
        content_digest: digest.clone(),
        revision: input.revision,
        observed_at: input.observed_at.clone(),
        os: input.os.clone(),
        arch: input.arch.clone(),
        process_count: input.process_count,
        process_executables: input.process_executables.clone(),
        packages: input.packages.clone(),
        listen_ports: input.listen_ports.clone(),
        received_at: received_at.clone(),
    };
    // 先落事实再算建议：规则表坏了不该连带把 Agent 报上来的事实丢掉。
    if let Err(err) = state.store.upsert_agent_fact_summary(&summary).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store agent fact summary: {err}"),
        )
            .into_response();
    }

    let suggestion_id = match ensure_fresh_suggestion(&state, &summary, None, &received_at).await {
        Ok(suggestion) => suggestion.map(|suggestion| suggestion.suggestion_id),
        Err(detail) => {
            eprintln!(
                "warn purpose inference failed agent_id={}: {detail}",
                summary.agent_id
            );
            None
        }
    };

    (
        StatusCode::ACCEPTED,
        Json(FactSummaryAccepted {
            report_id: input.report_id,
            agent_id: summary.agent_id,
            content_digest: digest,
            ack_status: FactSummaryAckStatus::Accepted,
            suggestion_id,
            received_at,
        }),
    )
        .into_response()
}

/// 网关从收到的**内容字段**自算的内容摘要（判重键）。
///
/// 与 agentd 共用 `wist_contracts::fact_summary` —— 两侧只有一份规范化实现，
/// 否则「一边认为没变、另一边认为变了」无法被发现。
fn gateway_digest(input: &ReportAgentFactSummary) -> String {
    FactContent::new(
        input.os.clone(),
        input.arch.clone(),
        input.process_executables.clone(),
        input.packages.clone(),
        input.listen_ports.clone(),
    )
    .content_digest()
}

/// 上报体上限：摘要是**被管机器上报的内容**，网关必须自己封顶，不能指望 agent 守规矩。
/// 没有上限时，一台机器就能让网关写进超长单行、让管理页渲染数十万 DOM 节点。
pub(super) const MAX_FACT_SUMMARY_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROCESS_EXECUTABLES: usize = 10_000;
const MAX_PACKAGES: usize = 5_000;
const MAX_LISTEN_PORTS: usize = 1_000;
const MAX_ELEMENT_BYTES: usize = 4096;
/// `content_digest` 是固定格式的标识符（`fact-v1:sha256:<64 hex>`）。
/// 封顶是必要的：它会进告警日志，不限长就能让一条上报写出几 MB 的单行日志。
const MAX_CONTENT_DIGEST_BYTES: usize = 128;

fn validate_fact_summary(input: &ReportAgentFactSummary) -> Result<(), String> {
    if input.content_digest.len() > MAX_CONTENT_DIGEST_BYTES {
        return Err(format!(
            "content_digest is {} bytes (limit {MAX_CONTENT_DIGEST_BYTES})",
            input.content_digest.len()
        ));
    }
    if input.revision < 0 {
        return Err("revision must not be negative".to_string());
    }
    if input.process_count < 0 {
        return Err("process_count must not be negative".to_string());
    }
    check_list(
        "process_executables",
        &input.process_executables,
        MAX_PROCESS_EXECUTABLES,
    )?;
    check_list("packages", &input.packages, MAX_PACKAGES)?;
    check_list("listen_ports", &input.listen_ports, MAX_LISTEN_PORTS)?;
    Ok(())
}

fn check_list(field: &str, values: &[String], max_len: usize) -> Result<(), String> {
    if values.len() > max_len {
        return Err(format!(
            "{field} has {} entries (limit {max_len})",
            values.len()
        ));
    }
    if values.iter().any(|value| value.len() > MAX_ELEMENT_BYTES) {
        return Err(format!(
            "{field} contains an entry longer than {MAX_ELEMENT_BYTES} bytes"
        ));
    }
    Ok(())
}

/// 按规则表算建议并落库，返回生效的建议。
///
/// `current` 传 `None` = 「新内容一律重算」（收到新事实）；传已存建议 = 「仅当过期才重算」
/// （读取路径）。两种调用共用同一份判据，避免两处逻辑漂移。
///
/// 三种情况要分清：
///   - 没配规则表：不推断，也**不动**已有建议 —— 页面能看到它的 `computed_at`，人自己判；
///   - 算出建议：覆盖写入（建议可变可过期）；
///   - 确实不该有建议（平台无规则册，或既无命中又无基线）：**清掉旧建议** ——
///     旧结论是照着旧事实算的，留着比没有更误导。
pub(super) async fn ensure_fresh_suggestion(
    state: &ApiState,
    summary: &StoredAgentFactSummary,
    current: Option<StoredPurposeSuggestion>,
    computed_at: &str,
) -> Result<Option<StoredPurposeSuggestion>, String> {
    let Some(table) = state.purpose_rules.as_deref() else {
        return Ok(current);
    };
    // 过期判据：规则册换了版本（`rule_set_id` 变了）。所以**改规则必须 bump rule_set_id**，
    // 否则内容变了而版本没变，这里看不出来。
    let expected = table
        .for_platform(&summary.os)
        .map(|set| set.rule_set_id.clone());
    if let Some(suggestion) = current.as_ref()
        && suggestion.rule_set_id.as_deref() == expected.as_deref()
    {
        return Ok(current);
    }
    let suggestion_id = new_secret_token("sug")?;
    match crate::app::purpose::infer(summary, table, &suggestion_id, computed_at) {
        Some(suggestion) => {
            state
                .store
                .upsert_purpose_suggestion(&suggestion)
                .await
                .map_err(|err| format!("store purpose suggestion: {err}"))?;
            Ok(Some(suggestion))
        }
        None => {
            state
                .store
                .clear_purpose_suggestion(&summary.agent_id)
                .await
                .map_err(|err| format!("clear purpose suggestion: {err}"))?;
            Ok(None)
        }
    }
}

#[allow(clippy::result_large_err)]
async fn authenticate_agent(
    state: &ApiState,
    headers: &HeaderMap,
    agent_id: &str,
    instance_id: &str,
) -> Result<StoredAgentRegistration, Response> {
    let Some(token) = bearer_token(headers) else {
        return Err((StatusCode::UNAUTHORIZED, "missing bearer credential").into_response());
    };
    let token_hash = sha256_hex(token);
    let agent = state.store.get_agent(agent_id).await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load agent credential store: {err}"),
        )
            .into_response()
    })?;
    let Some(agent) = agent else {
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
    Ok(agent)
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
