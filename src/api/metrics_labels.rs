//! 选择类 label（`env` / `cluster` / `app` / `role` …）的下发与管理面。
//!
//! ## 为什么不复用已有报文
//!
//! 这些都是 `deny_unknown_fields` 的线格式（`AgentStatusReport` / `AgentUplinkGrant` /
//! `WorkGrant`）：加字段会让**旧 agentd** 解析整份报文失败（舰队级停摆）。所以新能力一律
//! 新开端点：旧 agentd 从不调它；新 agentd 遇旧网关得 404 后按「没有选择类 label」继续跑。
//!
//! ## 谁决定值
//!
//! 部署默认（网关配置 `[agent.metrics_labels]`）与每机手工覆盖（管理面写入）都只在控制面，
//! agentd **没有配置**也**不做推断**（见 `app::metrics_labels`）。拿不到响应就沿用本地缓存，
//! 连缓存也没有 → 指标不带选择类 label（符合规范：缺失在查询侧表现为 `{cluster=""}`，可补）。
//!
//! ## 为什么改完要让 agent 立刻拉
//!
//! 常态拉取有 5 分钟节流。改完一个值等 5 分钟才生效，运维会怀疑「是不是没改上」而反复点。
//! 写入成功后给该 agent 排一条 `refresh`（`what=["metrics-labels"]`），下一个状态上报
//! （≤3s）即送达 —— 与 `fact-refresh` 同一条命令通道，不新增推送面。

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use wist_api::metrics_labels::{
    ADMIN_METRICS_LABELS_KIND, AgentMetricsLabels, AgentMetricsLabelsView,
    POLL_AGENT_METRICS_LABELS_KIND, PollAgentMetricsLabels, SetAgentMetricsLabelsRequest,
};
use wist_api::status::{RefreshParams, command_kind, refresh_what};
use wist_contracts::API_VERSION_V1;

use crate::api::ApiState;
use crate::api::admin_auth::{admin_actor, require_admin_bearer};
use crate::api::admin_ops::agent_not_found_response;
use crate::api::agent_ops::authenticate_agent;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;
use crate::app::metrics_labels::{self, EffectiveLabels};
use crate::infra::{StoredAgentCommand, StoredAgentMetricsLabels, VerifiedAgentIdentity};

/// `POST /api/v1/agent/metrics-labels:poll`
///
/// 只读：把「这台机器现在该带哪些选择类 label」发下去。空表是合法答案，不是错误 ——
/// 一个还没人配置过 `env` / `cluster` 的部署不该让每台 agent 每拍报一次失败。
pub async fn poll_agent_metrics_labels(
    State(state): State<ApiState>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollAgentMetricsLabels>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_AGENT_METRICS_LABELS_KIND {
        return ApiError::bad_request(
            codes::INVALID_METRICS_LABELS_POLL,
            "invalid metrics labels poll",
        )
        .into_response();
    }
    if let Err(response) = authenticate_agent(
        &state,
        &input.agent_id,
        &input.instance_id,
        client_identity.as_ref().map(|identity| &identity.0),
    )
    .await
    {
        return response;
    }
    match load_effective(&state, &input.agent_id).await {
        Ok((effective, revision, updated_at)) => Json(AgentMetricsLabels::new(
            &input.agent_id,
            revision,
            effective.labels,
            effective.sources,
            &updated_at,
        ))
        .into_response(),
        Err(response) => response,
    }
}

/// `GET /api/v1/admin/agents/{agent_id}/metrics-labels`
///
/// 生效值 + 每键来源 + 只有手工覆盖的那部分（页面/脚本要能区分「谁给的」）。
pub async fn view_agent_metrics_labels(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    view_response(&state, &agent_id).await
}

/// `PUT /api/v1/admin/agents/{agent_id}/metrics-labels`
///
/// **逐键**生效：`Some(value)` = 设置 / 覆盖；`null` = 删掉该键的手工覆盖（回落到部署默认）。
/// 未出现的键保持原状，所以「只改 `cluster`」不必先把整张表抄一遍。
///
/// 非法直接 400（值文法 / `env` 闭集 / 键闭集 / `app` 依赖 / 数量上限），**不写入任何东西** ——
/// 半套生效的 label 会让序列按一半维度分段，比彻底没改更难查。
pub async fn put_agent_metrics_labels(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
    Json(input): Json<SetAgentMetricsLabelsRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    if input.api_version != API_VERSION_V1
        || input.kind != wist_api::metrics_labels::SET_AGENT_METRICS_LABELS_KIND
    {
        return ApiError::bad_request(
            codes::METRICS_LABELS_INVALID,
            "invalid set-agent-metrics-labels request",
        )
        .into_response();
    }
    if input.overrides.is_empty() {
        // 空改动不是错误，但也不该写一条新版本（每次空写都让所有 agent 白拉一次）。
        return view_response(&state, &agent_id).await;
    }
    // 只读一次：版本号与“现有覆盖”必须来自同一份快照，否则并发两次写入会各自基于
    // 同一版 +1，其中一次被静默覆盖（版本还前进了，问题更难发现）。
    let stored = match state.store.get_agent_metrics_labels(&agent_id).await {
        Ok(row) => row,
        Err(err) => {
            return ApiError::internal(
                codes::METRICS_LABELS_UNAVAILABLE,
                "failed to load agent metrics labels",
                err,
            )
            .into_response();
        }
    };
    let current = stored
        .as_ref()
        .map(|row| row.overrides.clone())
        .unwrap_or_default();
    let merged = match metrics_labels::apply_overrides(&current, &input.overrides) {
        Ok(merged) => merged,
        Err(err) => {
            return ApiError::bad_request(
                codes::METRICS_LABELS_INVALID,
                format!("{}: {err}", err.code()),
            )
            .into_response();
        }
    };
    // 组合校验必须看**三层合并后的生效值**：只判「默认 + 覆盖」会误伤 ——
    // 手工删掉 `app`、而推断层仍能给出 `app` 时，那组值完全合法。
    let inferred = infer_labels(&state, &agent_id).await;
    let effective = metrics_labels::merge(&state.config.metrics_labels, &inferred, &merged);
    if let Err(err) = wist_api::metrics_labels::rules::validate_labels(&effective.labels) {
        return ApiError::bad_request(
            codes::METRICS_LABELS_INVALID,
            format!("{}: {err}", err.code()),
        )
        .into_response();
    }
    let revision = stored.as_ref().map(|row| row.revision).unwrap_or(0) + 1;
    let now = chrono::Utc::now().to_rfc3339();
    let row = StoredAgentMetricsLabels {
        agent_id: agent_id.clone(),
        overrides: merged,
        revision,
        updated_at: now.clone(),
        updated_by: admin_actor(&state.config),
    };
    if let Err(err) = state.store.upsert_agent_metrics_labels(&row).await {
        return ApiError::internal(
            codes::METRICS_LABELS_STORE_FAILED,
            "failed to store agent metrics labels",
            err,
        )
        .into_response();
    }
    log::info!(
        "event=AgentMetricsLabelsUpdated agent_id={} revision={} labels=\"{}\" by={}",
        agent_id,
        revision,
        effective.describe(),
        row.updated_by
    );
    enqueue_labels_refresh(&state, &agent_id).await;
    // 回显走**同一条读路径**：手写一份「默认 + 覆盖」会漏掉推断层，
    // 于是响应与 agent 实际拉到的值不一致。
    view_response(&state, &agent_id).await
}

/// `DELETE /api/v1/admin/agents/{agent_id}/metrics-labels`
///
/// 清空**全部手工覆盖**，回落到部署默认。同样排一条 `refresh`，让这台机器尽快退回默认值。
pub async fn delete_agent_metrics_labels(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path(agent_id): Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let previous = match state.store.get_agent_metrics_labels(&agent_id).await {
        Ok(row) => row,
        Err(err) => {
            return ApiError::internal(
                codes::METRICS_LABELS_UNAVAILABLE,
                "failed to load agent metrics labels",
                err,
            )
            .into_response();
        }
    };
    let Some(previous) = previous else {
        // 没有手工覆盖：删除是幂等的，返回当前生效值即可（不制造一个空版本）。
        return view_response(&state, &agent_id).await;
    };
    let now = chrono::Utc::now().to_rfc3339();
    // 不删行、而是写一条**空覆盖**（版本 +1）：
    //   * agent 只看「版本或内容变了」就替换 —— 删行后版本回到 0，会让「先清空再写回
    //     同一份」在 agent 侧看起来像没变过；
    //   * 版本号因此永远单调，排障时能按 revision 复原操作序列。
    let revision = previous.revision + 1;
    let tombstone = StoredAgentMetricsLabels {
        agent_id: agent_id.clone(),
        overrides: BTreeMap::new(),
        revision,
        updated_at: now.clone(),
        updated_by: admin_actor(&state.config),
    };
    if let Err(err) = state.store.upsert_agent_metrics_labels(&tombstone).await {
        return ApiError::internal(
            codes::METRICS_LABELS_STORE_FAILED,
            "failed to store metrics labels tombstone",
            err,
        )
        .into_response();
    }
    log::info!(
        "event=AgentMetricsLabelsCleared agent_id={agent_id} revision={revision} by={}",
        tombstone.updated_by
    );
    enqueue_labels_refresh(&state, &agent_id).await;
    // 回显走**同一条读路径**：清空覆盖后生效值里还有推断层，
    // 手写一份「默认 + 空覆盖」会让响应漏掉 `app`（而 agent 拉到的却有）。
    view_response(&state, &agent_id).await
}

/// 按事实里的**高置信度证据**推断 `app` / `role`。
///
/// 三条约束：
///   * 注册表是闭集：证据必须命中已登记的 `app`，否则留空（不猜）；
///   * 一机多用途（多个 app 命中）→ 留空（规范 §3.4 规则 5：主机口径不适用）；
///   * 读不到事实 / 读不到注册表 → 留空。**推断失败不该让拉取失败** ——
///     `env` / `cluster` 仍然有用，agent 拿不到整包才是更糟的结果。
async fn infer_labels(state: &ApiState, agent_id: &str) -> BTreeMap<String, String> {
    if state.config.metrics_registry_file.is_none() {
        return BTreeMap::new();
    }
    let facts = match state.store.get_agent_fact_summary(agent_id).await {
        Ok(Some(facts)) => facts,
        Ok(None) => return BTreeMap::new(),
        Err(err) => {
            log::warn!(
                "event=MetricsLabelInferenceSkipped agent_id={agent_id} detail=\"load fact summary: {err}\""
            );
            return BTreeMap::new();
        }
    };
    let registry = state
        .metrics_registry
        .resolve(state.config.metrics_registry_file.as_deref());
    registry
        .infer(&facts.service_units, &facts.container_names)
        .as_map()
}

/// 渲染一台机器的管理面视图（生效值 + 来源 + 手工覆盖）。
async fn view_response(state: &ApiState, agent_id: &str) -> Response {
    let (effective, revision, updated_at) = match load_effective(state, agent_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let overrides = match state.store.get_agent_metrics_labels(agent_id).await {
        Ok(row) => row.map(|row| row.overrides).unwrap_or_default(),
        Err(err) => {
            return ApiError::internal(
                codes::METRICS_LABELS_UNAVAILABLE,
                "failed to load agent metrics labels",
                err,
            )
            .into_response();
        }
    };
    Json(AgentMetricsLabelsView {
        api_version: API_VERSION_V1.to_string(),
        kind: ADMIN_METRICS_LABELS_KIND.to_string(),
        agent_id: agent_id.to_string(),
        revision,
        labels: effective.labels,
        sources: effective.sources,
        overrides,
        updated_at,
    })
    .into_response()
}

/// 读一台机器的生效值。返回 `(生效值, revision, updated_at)`。
///
/// `Err` 直接就是要回给调用方的响应：三条读路径（agent 拉取 / 管理面查看 / 写入后回显）
/// 的失败投影必须一样，各写一遍就会漂出「有的 500、有的 503」这种不一致。
#[allow(clippy::result_large_err)]
async fn load_effective(
    state: &ApiState,
    agent_id: &str,
) -> Result<(EffectiveLabels, u64, String), Response> {
    let row = state
        .store
        .get_agent_metrics_labels(agent_id)
        .await
        .map_err(|err| {
            ApiError::internal(
                codes::METRICS_LABELS_UNAVAILABLE,
                "failed to load agent metrics labels",
                err,
            )
            .into_response()
        })?;
    let overrides = row
        .as_ref()
        .map(|row| row.overrides.clone())
        .unwrap_or_default();
    let inferred = infer_labels(state, agent_id).await;
    // 永不下发非法值集：agent 对选择类 label 是整包拒收的，一份坏响应会让它保留旧缓存。
    let effective =
        metrics_labels::merge_validated(&state.config.metrics_labels, &inferred, &overrides);
    let revision = row
        .as_ref()
        .map(|row| row.revision.max(0) as u64)
        .unwrap_or(0);
    let updated_at = row
        .as_ref()
        .map(|row| row.updated_at.clone())
        .unwrap_or_default();
    Ok((effective, revision, updated_at))
}

/// 给该 agent 排一条 `refresh`（只刷 `metrics-labels`）。
///
/// 排不进命令队列**不是**请求失败：值已经落库，agent 最迟 5 分钟内会自己拉到。
/// 但必须留一行日志 —— 否则「改完一直没生效」会被误判成写入失败。
async fn enqueue_labels_refresh(state: &ApiState, agent_id: &str) {
    let now = chrono::Utc::now();
    let params = RefreshParams {
        what: vec![refresh_what::METRICS_LABELS.to_string()],
    };
    let params = match serde_json::to_string(&params) {
        Ok(params) => params,
        Err(err) => {
            log::warn!("event=MetricsLabelsRefreshNotQueued agent_id={agent_id} detail={err}");
            return;
        }
    };
    let command = StoredAgentCommand {
        command_id: format!("cmd_{agent_id}_labels_{}", now.timestamp_micros()),
        agent_id: agent_id.to_string(),
        kind: command_kind::REFRESH.to_string(),
        params,
        requested_at_ms: now.timestamp_millis(),
        acked_at: None,
        claimed_at: None,
        outcome: None,
        detail: None,
        requested_by: admin_actor(&state.config),
    };
    if let Err(err) = state.store.enqueue_agent_command(&command, true).await {
        log::warn!(
            "event=MetricsLabelsRefreshNotQueued agent_id={agent_id} detail=\"{err}\" \
             （值已落库；agent 最迟 5 分钟内自动拉到）"
        );
    }
}
