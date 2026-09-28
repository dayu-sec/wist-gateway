use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::infra::{
    AgentFactSummaryMarks, AgentStatusUpdate, CertificateRegistration, RenewCredential,
    StoredAgentFactSummary, StoredAgentRegistration, StoredCredentialStatus,
    StoredPurposeSuggestion, StoredWorkResult, VerifiedAgentIdentity, effective_standing,
    new_secret_token, outstanding_one_shot, sha256_hex,
    victoria_metrics::{import_lines, metric_line},
};
use wist_contracts::API_VERSION_V1;
use wist_contracts::agent_uplink::{AgentUplinkGrant, POLL_AGENT_UPLINK_KIND, PollAgentUplink};
use wist_contracts::enrollment::{
    CredentialBundle, CredentialRenewal, CredentialRenewed, RENEW_AGENT_CREDENTIAL_KIND,
};
use wist_contracts::fact_summary::FactContent;
use wist_contracts::gateway::{
    ActionResultAck, AgentStatusAck, AgentStatusReport, DiscoveryPoliciesReturned,
    FactSummaryAccepted, FactSummaryAckStatus, POLL_DISCOVERY_POLICIES_KIND, PollDiscoveryPolicies,
    REPORT_AGENT_FACT_SUMMARY_KIND, ReportActionResult, ReportAgentFactSummary,
};
use wist_contracts::work::{
    ACK_WORK_KIND, AGENT_REPORTABLE_WORK_STATUSES, AckWork, POLL_WORK_KIND, PollWork,
    REPORT_WORK_RESULT_KIND, ReportWorkResult, WorkAccepted, WorkGrant, WorkResultAccepted,
};
use wist_control::types::DateTime;
use wist_control::{AgentControlCommandsReturned, PollControlCommands};

use super::ApiState;

pub async fn submit_agent_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<AgentStatusReport>,
) -> Response {
    match authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        Ok(agent) => {
            let now_utc = chrono::Utc::now();
            let last_seen_at = now_utc.to_rfc3339();
            let timestamp_ms = now_utc.timestamp_millis();
            let memory_bytes = input.memory_bytes;
            let cpu_percent = input.cpu_percent;
            let cpu_cores = input.cpu_cores;
            let admin_latency_ms = input.admin_latency_ms;
            let discovery_policy_version = input.discovery_policy_version;
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
                    cpu_cores,
                    admin_latency_ms,
                    discovery_policy_version,
                    work_state_changes: input.work_state_changes.clone(),
                    local_work: input.local_work.clone(),
                    // 与 local_work 同口径：`None`（旧版本 agentd 没带）落库时保持上一次的值。
                    uplink_state: input.uplink_state.clone(),
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
            let lines = agent_status_metric_lines(
                &agent.agent_id,
                memory_bytes,
                cpu_percent,
                cpu_cores,
                admin_latency_ms,
                discovery_policy_version,
                timestamp_ms,
            );
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

/// agent 状态上报对应的 VM 指标行（只含有值的项）。
///
/// 缺值（`None`）**不产生行、更不补 0**：把「没上报」写成 0 会在图上伪造出一段真实读数。
/// 对 `discovery_policy_version` 尤其致命 —— 0 代表确实生效了第 0 版，与「还没拉到策略表」
/// 是两回事，混为一谈正好毁掉运维要回答的那句「哪些机器还没生效」。
///
/// 注意 `agent.cpu.percent` 是**单核口径**（100% = 占满一个核，多线程进程可 >100），
/// 只统计 agent 进程自身；整机占比由管理面读投影按 `cpu_percent / cpu_cores` 派生，
/// 不在这条上报链路上另发一条线。
pub(super) fn agent_status_metric_lines(
    agent_id: &str,
    memory_bytes: Option<u64>,
    cpu_percent: Option<f64>,
    cpu_cores: Option<u32>,
    admin_latency_ms: Option<u64>,
    discovery_policy_version: Option<i64>,
    timestamp_ms: i64,
) -> Vec<serde_json::Value> {
    [
        memory_bytes.map(|value| {
            metric_line(
                "agent.memory.bytes",
                agent_id,
                "agent_metrics",
                value as f64,
                timestamp_ms,
            )
        }),
        cpu_percent.map(|value| {
            metric_line(
                "agent.cpu.percent",
                agent_id,
                "agent_metrics",
                value,
                timestamp_ms,
            )
        }),
        cpu_cores.map(|value| {
            metric_line(
                // 单位=个（逻辑核数）：gauge 型。整机占比的分母，随状态上报一起进时序。
                "agent.cpu.cores",
                agent_id,
                "agent_metrics",
                value as f64,
                timestamp_ms,
            )
        }),
        admin_latency_ms.map(|value| {
            metric_line(
                "agent.admin_latency.ms",
                agent_id,
                "agent_metrics",
                value as f64,
                timestamp_ms,
            )
        }),
        discovery_policy_version.map(|value| {
            metric_line(
                "agent.discovery_policy_version",
                agent_id,
                "agent_metrics",
                value as f64,
                timestamp_ms,
            )
        }),
    ]
    .into_iter()
    .flatten()
    .collect()
}

pub async fn poll_control_commands(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollControlCommands>,
) -> Response {
    match authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
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
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollDiscoveryPolicies>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_DISCOVERY_POLICIES_KIND {
        return (StatusCode::BAD_REQUEST, "invalid discovery policies poll").into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
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

/// agentd → 网关：拉取工作授权快照（`PollWork`）。
///
/// 幂等：同一份拉两次得到同一份（除了 `granted_at`）。不承担「指令重放」的语义 ——
/// 正因如此，agentd 断网重启后只需重新拉一次就回到期望，网关不用记「推到哪了」。
pub async fn poll_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollWork>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_WORK_KIND {
        return (StatusCode::BAD_REQUEST, "invalid work poll").into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        return response;
    }
    match build_work_grant(&state, &input.agent_id).await {
        Ok(grant) => Json(grant).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build work grant: {err}"),
        )
            .into_response(),
    }
}

/// agentd → 网关：拉取「数据面上送是否启用、目标在哪」的当前期望（`PollAgentUplink`）。
///
/// 与 [`poll_work`] 同形：同一套 agent 凭据、同一份实例标识、同一类「拉期望状态」的动作，
/// 只是期望状态的内容不同。计算规则见 [`build_agent_uplink_grant`]。
///
/// ## 为什么另开端点，不塞进 [`WorkGrant`] 的字段
///
/// `WorkGrant` 带 `#[serde(deny_unknown_fields)]`。往里加字段会让「新网关 + 旧 agentd」
/// 直接解析失败：旧 agentd 连工作授权都收不到，会停在最后一次应用的工作上 —— 这是
/// 舰队级的静默停摆。独立端点对两个方向都安全：旧 agentd 从不调它；新 agentd 遇到旧网关
/// 得到 404，按「无下发」回落本机 `[telemetry.logs.output]`。契约见 `wist_contracts::agent_uplink`。
///
/// 出错口径与 [`poll_work`] 一致，回 500 而不是「按待命处理」：待命是「关掉上送」的**实质
/// 决定**，会把一台本该上送的 Agent 悄悄停采；而一次失败的 poll 只是让 agentd 重试、
/// 沿用上一次的期望。宁可让它重试，也不要在读库失败时替它做关机决定。
pub async fn poll_agent_uplink(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollAgentUplink>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_AGENT_UPLINK_KIND {
        return (StatusCode::BAD_REQUEST, "invalid uplink poll").into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        return response;
    }
    match build_agent_uplink_grant(&state, &input.agent_id).await {
        Ok(grant) => Json(grant).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build agent uplink grant: {err}"),
        )
            .into_response(),
    }
}

/// 组装某 Agent 的授权快照（下发与查看共用同一份口径）。
///
/// 只带**当前生效**的：常驻 `active`/`paused`、一次性未了结。被取代/已撤回/已了结的
/// 留在库里供审计，但不发给 Agent —— 快照是「现在的期望」，不是历史。
pub async fn build_work_grant(
    state: &ApiState,
    agent_id: &str,
) -> Result<WorkGrant, crate::infra::StoreError> {
    let standing = effective_standing(&state.store.list_standing_work(agent_id).await?);
    let one_shot = outstanding_one_shot(&state.store.list_one_shot_work(agent_id).await?);
    let sequence = state.store.work_sequence(agent_id).await?;
    Ok(WorkGrant {
        agent_id: agent_id.to_string(),
        standing,
        one_shot,
        sequence,
        granted_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// 现算某 Agent 的数据面上送期望状态：`enabled = 有生效工作 且 已设上送地址`。
///
/// 没有新状态、没有推送通道 —— 每次被问到时从两个既有事实推出来：
///   * 「有生效工作」复用工作授权同一口径（[`effective_standing`] / [`outstanding_one_shot`]，
///     两者都空即没有工作），所以「派活即启用、撤回即待命」自动发生，无需管理面多一个动作；
///   * 「上送地址」来自管理面已设的 `StoredAgentUplinkAddress`（`store.get_agent_uplink`）。
///
/// 缺任一条都只能待命：有工作但没地址 = 没目标可指（**不猜**目标）；有地址但没工作 =
/// 地址只表示「能连到哪」，不表示「该不该连」。
pub async fn build_agent_uplink_grant(
    state: &ApiState,
    agent_id: &str,
) -> Result<AgentUplinkGrant, crate::infra::StoreError> {
    let has_work = !effective_standing(&state.store.list_standing_work(agent_id).await?).is_empty()
        || !outstanding_one_shot(&state.store.list_one_shot_work(agent_id).await?).is_empty();
    let uplink = state.store.get_agent_uplink().await?;
    let granted_at = chrono::Utc::now().to_rfc3339();
    match (has_work, uplink) {
        (true, Some(setting)) => Ok(AgentUplinkGrant::enabled_at(
            setting.host,
            setting.port,
            granted_at,
        )),
        _ => Ok(AgentUplinkGrant::standby(granted_at)),
    }
}

/// agentd → 网关：确认收到某份工作（`AckWork`）。
///
/// 三种结果**在体内**回报（`accepted` / `stale` / `unknown`），而不是全用 HTTP 状态码：
/// 对 Agent 而言这三者都是「我收到了回音、接下来该怎么做」的同一类事件，
/// 用 200+status 让它的处理分支集中在一处（而不是在 HTTP 错误码与重试策略之间拼）。
///
/// 常驻工作带 `plan_version`：对不上就是 `stale`（网关已经改过版，请重新拉快照）。
/// 一次性工作被确认时从 `dispatched` 进到 `accepted` —— 这正是那个状态存在的意义。
pub async fn ack_work(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<AckWork>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != ACK_WORK_KIND {
        return (StatusCode::BAD_REQUEST, "invalid work ack").into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        return response;
    }
    let now = chrono::Utc::now().to_rfc3339();
    let (status, work_kind) = match state.store.get_standing_work(&input.work_id).await {
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load standing work: {err}"),
            )
                .into_response();
        }
        Ok(Some(work)) if work.agent_id == input.agent_id => {
            let status = if work.plan_version == input.plan_version {
                "accepted"
            } else {
                // 版本对不上：不是错误，是「你手上那份旧了」。如实回报，不篡改期望版本。
                "stale"
            };
            (status, "Standing")
        }
        Ok(_) => match state.store.get_one_shot_work(&input.work_id).await {
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load one-shot work: {err}"),
                )
                    .into_response();
            }
            Ok(Some(stored)) if stored.work.agent_id == input.agent_id => {
                if stored.work.status == "dispatched" {
                    let mut accepted = stored;
                    accepted.work.status = "accepted".to_string();
                    accepted.work.attempt += 1;
                    if let Err(err) = state.store.save_one_shot_work(&accepted).await {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to store one-shot work: {err}"),
                        )
                            .into_response();
                    }
                }
                // 一次性工作不按 `plan_version` 比：它是命令式的，版本由网关自己推，
                // 对不上也只说明 Agent 报了另一个数，不影响「它已经收到」这个事实。
                ("accepted", "OneShot")
            }
            Ok(_) => ("unknown", "Unknown"),
        },
    };
    if status == "accepted" {
        let ack = crate::infra::StoredWorkAck {
            work_id: input.work_id.clone(),
            agent_id: input.agent_id.clone(),
            work_kind: work_kind.to_string(),
            plan_version: input.plan_version,
            acknowledged_at: now.clone(),
        };
        if let Err(err) = state.store.upsert_work_ack(&ack).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store work ack: {err}"),
            )
                .into_response();
        }
    }
    Json(WorkAccepted {
        work_id: input.work_id,
        status: status.to_string(),
        accepted_at: now,
    })
    .into_response()
}

/// Agent 上报一次性工作的**执行结果**（进度/终态）。
///
/// 为什么与确认分开一条消息：确认丢了只是页面晚一拍，结果丢了则意味着「一件改变机器状态的活
/// 已经做完/回滚，而控制面永远不知道」。两者失效的代价不同，就不该挤在一条路上。
///
/// 拒绝的边界（与 `ack_work` 同一取舍：只做**正确性**检查，不做认证以外的业务判断）：
///   * `status` 必须在 `AGENT_REPORTABLE_WORK_STATUSES` 里 —— `dispatched` 是网关写的，
///     `paused`/`canceled`/`expired` 归控制面与期限管，agent 无权写回去；
///   * 工作不存在、不属于这台 agent、或不是一次性工作 → `unknown`（不报错，也不编一个状态）；
///   * 已经到终态 → `stale`：**状态不覆盖**（一件活只能有一个终态），
///     但结果记录照存 —— 机器上确实发生过那次执行，抹掉它只会让事后无法解释。
pub async fn submit_work_result(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<ReportWorkResult>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != REPORT_WORK_RESULT_KIND {
        return (StatusCode::BAD_REQUEST, "invalid work result").into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        return response;
    }
    if !AGENT_REPORTABLE_WORK_STATUSES.contains(&input.status.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "status {:?} is not agent-reportable (one of {:?})",
                input.status, AGENT_REPORTABLE_WORK_STATUSES
            ),
        )
            .into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    let stored = match state.store.get_one_shot_work(&input.work_id).await {
        Ok(Some(stored)) if stored.work.agent_id == input.agent_id => stored,
        Ok(_) => {
            return Json(WorkResultAccepted {
                work_id: input.work_id,
                status: "unknown".to_string(),
                accepted_at: now,
            })
            .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load one-shot work: {err}"),
            )
                .into_response();
        }
    };

    let result_status = if stored.work.is_outstanding() {
        let mut updated = stored;
        updated.work.status = input.status.clone();
        if let Err(err) = state.store.save_one_shot_work(&updated).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to store one-shot work: {err}"),
            )
                .into_response();
        }
        "accepted"
    } else {
        "stale"
    };

    if let Err(err) = state
        .store
        .upsert_work_result(&StoredWorkResult {
            work_id: input.work_id.clone(),
            agent_id: input.agent_id.clone(),
            status: input.status.clone(),
            detail: input.detail.clone(),
            reported_at: input.reported_at.clone(),
        })
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store work result: {err}"),
        )
            .into_response();
    }

    // 若这份工作是某份灰度发布计划物化出来的，把结果回填到计划条目；终态结果还会触发
    // 阶段内的 batch_size 节流补批、以及 advance_rule 的自动推进。
    // 只在结果被「接受」（工作仍未了结、这次上报推进了它）时回填：stale（已了结）的结果
    // 不覆盖条目 —— 与工作自身的终态语义一致（一件活只有一个终态）。
    // 回填失败不阻塞结果上报（结果已落库，计划条目只是派生的观测）——只记一行日志。
    if result_status == "accepted"
        && let Err(err) = super::rollout_ops::reconcile_rollout_result(
            &state,
            &input.work_id,
            &input.status,
            &input.detail,
        )
        .await
    {
        eprintln!(
            "event=RolloutEntryReconcileFailed work_id={} detail=\"{err}\"",
            input.work_id
        );
    }

    Json(WorkResultAccepted {
        work_id: input.work_id,
        status: result_status.to_string(),
        accepted_at: now,
    })
    .into_response()
}

pub async fn renew_agent_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
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

    let agent = match authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
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
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<ReportActionResult>,
) -> Response {
    match authenticate_agent(
        &state,
        &headers,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
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
///
/// 事实摘要「校验 → 判重 → 入库 → 推断」的唯一实现。
///
/// **入口只有数据面订阅一条**：`POST /api/v1/ingest/agent-facts`
/// （warp-parse 转发，见 [`super::ingest`]）。原来还有一条控制面直报
/// （`POST /api/v1/agent/facts`，agent 凭据认证），已随「统一走数据面」废弃 ——
/// 见 `doc/design/center/agent-work-delivery-plan.md` §4.1。
///
/// **校验放在这里而不是调用方**：body 上限、条数上限、判重键只有一份，
/// 否则同一份摘要在不同入口会得出不同结果。
///
/// 调用方负责的只有一件事：**先把 `agent` 钉死**（身份从哪来由路径决定）。
pub(super) async fn ingest_fact_summary(
    state: &ApiState,
    agent: &StoredAgentRegistration,
    input: ReportAgentFactSummary,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != REPORT_AGENT_FACT_SUMMARY_KIND {
        return (StatusCode::BAD_REQUEST, "invalid agent fact summary report").into_response();
    }
    // 上限由网关自己封顶，不能指望 agent 守规矩。
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
                host_id: input.host_id.clone(),
                host_name: input.host_name.clone(),
                network_addresses: input.network_addresses.clone(),
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
            // L1a 清单是摘要的**投影**：内容没变就不必重建。只有「上次投影没写成」
            // （进程被杀 / 库锁）才补一次 —— 否则清单会一直空着而没人知道。
            // 常见路径只多付一次 COUNT；自愈路径才重读摘要（那时本也不在乎这点开销）。
            match state
                .store
                .agent_has_software_inventory(&agent.agent_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => match state.store.get_agent_fact_summary(&agent.agent_id).await {
                    Ok(Some(current)) => refresh_software_inventory(state, &current).await,
                    // 摘要行在判重与自愈之间消失了：下次上报会走覆盖写补回，不值得卡住 agent。
                    Ok(None) => {}
                    Err(err) => eprintln!(
                        "warn failed to reload fact summary for inventory repair agent_id={}: {err}",
                        agent.agent_id
                    ),
                },
                Err(err) => eprintln!(
                    "warn failed to check software inventory agent_id={}: {err}",
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
                    agent_id: agent.agent_id.clone(),
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
        host_id: input.host_id.clone(),
        host_name: input.host_name.clone(),
        network_addresses: input.network_addresses.clone(),
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

    // 事实变了 → 重建 L1a 清单（内容变才重建，与判重同一道门）。
    refresh_software_inventory(state, &summary).await;

    let suggestion_id = match ensure_fresh_suggestion(state, &summary, None, &received_at).await {
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

/// 重建这台机器的 L1a 机械资产清单（事实摘要的**投影**）。
///
/// 为什么失败不影响上报结果：清单是派生视图，摘要才是事实源。重建失败只是页面上少了清单，
/// 不是「事实没收到」—— 下次内容变化会重建，重复上报路径还有一次自愈机会
/// （见 `ingest_fact_summary` 的 duplicate 分支）。所以这里只记日志。
///
/// 但它**必须留日志**：清单一直空着是一个看不出来的故障（页面会显示「没有数据」，
/// 而那与「这台机器真的什么都没有」长得一样）。
async fn refresh_software_inventory(state: &ApiState, summary: &StoredAgentFactSummary) {
    let entries = crate::app::inventory::derive_inventory(
        &summary.agent_id,
        &summary.process_executables,
        &summary.received_at,
    );
    let expected = entries.len();
    match state
        .store
        .replace_agent_software_inventory(&summary.agent_id, &entries)
        .await
    {
        Ok(written) if written == expected => {}
        // 行数不符理论上不会发生（同一事务内 delete+insert）。真发生了要看得见，
        // 因为它是「清单与摘要不一致」的唯一信号。
        Ok(written) => eprintln!(
            "warn software inventory row count mismatch agent_id={}: wrote {written}, expected {expected}",
            summary.agent_id
        ),
        Err(err) => eprintln!(
            "warn failed to rebuild software inventory agent_id={}: {err}",
            summary.agent_id
        ),
    }
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
/// 单个展示字段（`host_id` / `host_name`）的字节上限。主机名按 DNS 上限（253）留余量，
/// `host_id` 还有 `hostname:<name>` 这种兜底形态，512 足够。不借 `MAX_ELEMENT_BYTES`
/// （4096）—— 那是给「列表里的一条」的，单值字段用不到那么大，只会让一条上报白写出几 KB。
const MAX_HOST_FIELD_BYTES: usize = 512;
/// 网卡条数上限：一台宿主机（含 docker 网桥 / veth / VPN）几十块网卡是常态，256 留足余量。
/// 上界存在的意义只是让一条上报撑不爆单行与页面，不是去猜机器该有几块网卡。
const MAX_NETWORK_ADDRESSES: usize = 256;

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
    check_value("host_id", &input.host_id, MAX_HOST_FIELD_BYTES)?;
    check_value("host_name", &input.host_name, MAX_HOST_FIELD_BYTES)?;
    check_list(
        "network_addresses",
        &input.network_addresses,
        MAX_NETWORK_ADDRESSES,
    )?;
    Ok(())
}

/// 单个值（不是列表）的长度上限：列表用 `check_list`，它还要额外看条数。
fn check_value(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(format!(
            "{field} is {} bytes (limit {max_bytes})",
            value.len()
        ));
    }
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
    client_identity: Option<&VerifiedAgentIdentity>,
) -> Result<StoredAgentRegistration, Response> {
    // ① bearer 双轨：迁移期的旧凭据照旧可用（docs/design/agent-identity-mtls.md §7）。
    if let Some(token) = bearer_token(headers) {
        let token_hash = sha256_hex(token);
        let agent = state
            .store
            .get_agent(agent_id)
            .await
            .map_err(store_unavailable)?;
        let Some(agent) = agent else {
            // 库里没有这条记录：可能是库丢了。不在这里下结论 —— 交给证书路径重建（§5.3），
            // 没有证书就还是普通的 401。
            return match client_identity {
                Some(identity) => {
                    certificate_authenticate(state, identity, agent_id, instance_id).await
                }
                None => Err(unauthorized_code("unknown_credential")),
            };
        };
        if agent.instance_id != instance_id
            || !constant_time_eq(
                agent.credential_token_hash.as_bytes(),
                token_hash.as_bytes(),
            )
        {
            return Err(unauthorized_code("credential_mismatch"));
        }
        if agent.credential_status != StoredCredentialStatus::Active {
            return Err(unauthorized_code("credential_inactive"));
        }
        if credential_is_expired(&agent.credential_expires_at) {
            return Err(unauthorized_code("credential_expired"));
        }
        return Ok(agent);
    }

    // ② mTLS：证书身份即权威身份（§5.2）。没配 agent CA 就是「没带凭据」。
    match client_identity {
        Some(identity) => certificate_authenticate(state, identity, agent_id, instance_id).await,
        None => Err(unauthorized_code(
            if state.config.agent_ca_files().is_some() {
                "certificate_required"
            } else {
                "missing_credential"
            },
        )),
    }
}

/// 证书路径：先把证书身份与请求体对齐，再查库；库里没有就**首触重建登记**（§5.3）。
#[allow(clippy::result_large_err)]
async fn certificate_authenticate(
    state: &ApiState,
    identity: &VerifiedAgentIdentity,
    agent_id: &str,
    _instance_id: &str,
) -> Result<StoredAgentRegistration, Response> {
    // 证书身份是权威：不接受「证书说是 A、请求体说是 B」；租户/环境也必须落在本网关上。
    if identity.agent_id != agent_id
        || identity.tenant_id != state.config.tenant_id
        || identity.environment_id != state.config.environment_id
    {
        return Err(unauthorized_code("certificate_mismatch"));
    }
    if let Some(agent) = state
        .store
        .get_agent(agent_id)
        .await
        .map_err(store_unavailable)?
    {
        return Ok(agent);
    }
    rebuild_agent_registration(state, identity).await?;
    state
        .store
        .get_agent(agent_id)
        .await
        .map_err(store_unavailable)?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "agent registration missing right after rebuild",
            )
                .into_response()
        })
}

/// 凭证书**首触重建登记**：库丢失 / 换网关后，agent 仍持有效证书 → 零人工补一条记录。
///
/// 机器画像（node_id / hostname / machine_id / instance_id）在首触时未知，留空；
/// 等 agent 后续的状态上报补齐。
#[allow(clippy::result_large_err)]
async fn rebuild_agent_registration(
    state: &ApiState,
    identity: &VerifiedAgentIdentity,
) -> Result<(), Response> {
    let now = chrono::Utc::now().to_rfc3339();
    // 凭据 id 由指纹派生：同一张证书重复首触落在同一个 id（重建本身也是幂等的）。
    let credential_id = format!(
        "cert-{}",
        identity
            .fingerprint_sha256
            .get(..16)
            .unwrap_or(&identity.fingerprint_sha256)
    );
    let created = state
        .store
        .register_agent_from_certificate(&CertificateRegistration {
            agent_id: &identity.agent_id,
            tenant_id: &identity.tenant_id,
            environment_id: &identity.environment_id,
            credential_id: &credential_id,
            credential_fingerprint: &identity.fingerprint_sha256,
            credential_issued_at: &identity.not_before,
            credential_expires_at: &identity.not_after,
            registered_at: &now,
            now: &now,
        })
        .await
        .map_err(store_unavailable)?;
    if created {
        eprintln!(
            "audit agent_rebuilt_from_certificate agent_id={} fingerprint={}",
            identity.agent_id, identity.fingerprint_sha256
        );
    }
    Ok(())
}

/// 401 的正文里带一个稳定的 `code`，agentd 按它决定要不要自愈（§5.4）。
fn unauthorized_code(code: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        format!("agent identity rejected: {code}"),
    )
        .into_response()
}

fn store_unavailable(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("failed to load agent credential store: {err}"),
    )
        .into_response()
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

/// 按明文凭据 token 校验 agent（无 `agent_id` / `instance_id` 的路径用）。
///
/// 与 [`authenticate_agent`] 同一套凭据口径（同一个 `sha256_hex` 哈希、同一种
/// active + 未过期判定），只是少了「实例必须匹配」那一步 —— 升级取包时升级器手上
/// 只有凭据 token，没有 agent_id/instance_id。查的是当前凭据（`agent_credentials.token_hash`）。
pub(crate) async fn authenticate_agent_credential_token(
    state: &ApiState,
    token: &str,
) -> Result<(), String> {
    let token_hash = sha256_hex(token);
    let agent = state
        .store
        .find_agent_by_credential_token_hash(&token_hash)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "unknown agent credential".to_string())?;
    if !constant_time_eq(
        agent.credential_token_hash.as_bytes(),
        token_hash.as_bytes(),
    ) {
        return Err("invalid agent credential".to_string());
    }
    if agent.credential_status != StoredCredentialStatus::Active {
        return Err("agent credential is not active".to_string());
    }
    if credential_is_expired(&agent.credential_expires_at) {
        return Err("agent credential is expired".to_string());
    }
    Ok(())
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
