//! 日志源候选的管理面 API（**人工覆盖**，仅 API、不做界面）。
//!
//! ## 为什么需要它
//!
//! 「服务在、但找不到日志」时，运维手里只有一个能让采集**立刻**跑起来的动作：告诉网关
//! 「这台机器上 PostgreSQL 的日志在 `/opt/customer-pg/log`」。自动解析（agentd 从进程证据反推）
//! 覆盖绝大多数机器，但它**看不到客户规范 / 挂载约定** —— 这条口子就是那种情况的应急锚点。
//!
//! ## 三条硬规矩
//!
//! 1. **不做界面**：这是排障用的应急口（curl / runbook），不是日常流程。运维逐台填路径
//!    既不可持续，也会把「自动解析不准」藏起来（人一填就看不到解析结果了）。
//! 2. **不能越权**：`dir` 必须落在 `[collection] allowed_source_roots` 内 —— 写入时就拒（400）。
//!    要采 roots 外的东西是**策略级变更**（改网关配置），不是单机例外。
//! 3. **按实例写**：`source_ref` 区分 `port:5432` / `port:5433`；一台机器两个实例就是两条覆盖。
//!    同一实例再写一次即覆盖（`origin = override`），删掉即回落到解析值。
//!
//! 详细设计见 `doc/design/edge/log-source-resolution.md` §6.2。

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::api::ApiState;
use crate::api::admin_auth::require_admin_bearer;
use crate::api::admin_ops::agent_not_found_response;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::rate_limit;
use crate::app::content::LOG_SERVICES;
use crate::app::log_source::{is_under_roots, normalize_dir};
use crate::infra::StoredLogSource;

/// 人工覆盖的固定 `source_ref` 之外的实例引用：`port:<n>` / `pid:<n>`。
///
/// 为什么在写入时就校验形状：`source_ref` 是主键的一半，写错一个字符就是**多出一条**
/// 永不生效的候选（页面不会报错，人以为设上了）。
pub(super) fn validate_service(service: &str) -> Result<(), String> {
    if !LOG_SERVICES.contains(&service) {
        return Err(format!(
            "service {service:?} 不在 v1 词表 {LOG_SERVICES:?} 里"
        ));
    }
    Ok(())
}

pub(super) fn validate_source_ref(source_ref: &str) -> Result<(), String> {
    let value = source_ref.trim();
    if value.is_empty() {
        return Err("source_ref 不能为空（如 port:5432）".to_string());
    }
    if value.len() > 128 {
        return Err("source_ref 过长（≤ 128）".to_string());
    }
    // `override` 由网关自己写，不接受人工指定成它 —— 否则一条「覆盖」会顶掉另一个实例。
    if value == "override" {
        return Err("source_ref 不能写成 override（它由网关生成）".to_string());
    }
    let valid = value
        .strip_prefix("port:")
        .map(|port| port.parse::<u16>().is_ok())
        .unwrap_or_else(|| {
            value
                .strip_prefix("pid:")
                .map(|pid| pid.parse::<u32>().is_ok())
                .unwrap_or(false)
        });
    if !valid {
        return Err(format!(
            "source_ref 必须是 port:<端口> 或 pid:<pid>，got {value:?}"
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct LogSourceView {
    pub agent_id: String,
    pub service: String,
    pub source_ref: String,
    pub dir: String,
    /// `human` / `cmdline_datadir` / …（见设计稿 §4.3）。
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
    /// `agent`（本机解析）| `override`（人工指定）。
    pub origin: String,
    pub observed_at: String,
    pub updated_at: String,
}

impl From<&StoredLogSource> for LogSourceView {
    fn from(source: &StoredLogSource) -> Self {
        Self {
            agent_id: source.agent_id.clone(),
            service: source.service.clone(),
            source_ref: source.source_ref.clone(),
            dir: source.dir.clone(),
            evidence: source.evidence.clone(),
            detail: source.detail.clone(),
            confidence: source.confidence,
            origin: source.origin.clone(),
            observed_at: source.observed_at.clone(),
            updated_at: source.updated_at.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LogSourceList {
    pub agent_id: String,
    /// 当前策略下允许的目录 roots —— 一并返回，省得人填了才被 400 打回来。
    pub allowed_source_roots: Vec<String>,
    pub sources: Vec<LogSourceView>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertLogSourceRequest {
    /// 实例引用：`port:5432` / `pid:1234`。
    pub source_ref: String,
    /// 日志目录（绝对路径，必须在 roots 内）。
    pub dir: String,
    /// 人给的备注（可选）：写清「为什么是这个目录」，排障时值钱。
    #[serde(default)]
    pub detail: String,
}

/// `GET /api/v1/admin/agents/{agent_id}/log-sources`
///
/// 列出这台机器**全部**候选（含覆盖与解析值）。覆盖排在最前面（`origin = override`）。
pub async fn list_agent_log_sources(
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
    match state.store.list_agent_log_sources(&agent_id).await {
        Ok(sources) => Json(LogSourceList {
            agent_id,
            allowed_source_roots: state.config.allowed_source_roots.clone(),
            sources: sources.iter().map(LogSourceView::from).collect(),
        })
        .into_response(),
        Err(err) => ApiError::internal(
            codes::LOG_SOURCE_UNAVAILABLE,
            "failed to load agent log sources",
            err,
        )
        .into_response(),
    }
}

/// `PUT /api/v1/admin/agents/{agent_id}/log-sources/{service}`
///
/// 写一条人工覆盖。**同一 `(agent, service, source_ref)` 再写即覆盖**（幂等更新）。
///
/// 拒收的情况（全部 400，且文案直接说清哪一条不成立）：
/// * `service` 不在词表 / `source_ref` 形状不对；
/// * `dir` 不是绝对路径、含 `..` 或通配；
/// * `dir` 不在 `allowed_source_roots` 内（**人也不能越权**）。
pub async fn put_agent_log_source(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path((agent_id, service)): Path<(String, String)>,
    Json(input): Json<UpsertLogSourceRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    let invalid =
        |message: String| ApiError::bad_request(codes::LOG_SOURCE_INVALID, message).into_response();
    if let Err(message) = validate_service(&service) {
        return invalid(message);
    }
    if let Err(message) = validate_source_ref(&input.source_ref) {
        return invalid(message);
    }
    let dir = match normalize_dir(&input.dir) {
        Ok(dir) => dir,
        Err(message) => return invalid(message),
    };
    // 覆盖**不能**扩大安全边界：越界就是 400，不做「人是好意就放行」。
    if !is_under_roots(&dir, &state.config.allowed_source_roots) {
        return invalid(format!(
            "目录 {dir} 不在 allowed_source_roots {:?} 内（要采这里请改网关 [collection] 配置）",
            state.config.allowed_source_roots
        ));
    }
    let detail = input.detail.trim();
    if detail.chars().count() > 512 {
        return invalid("detail 过长（≤ 512 字符）".to_string());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let source = StoredLogSource {
        agent_id: agent_id.clone(),
        service,
        source_ref: input.source_ref.trim().to_string(),
        dir,
        // `human` 是词表里最高的一档：它压过任何本机解析值。
        evidence: "human".to_string(),
        detail: if detail.is_empty() {
            "manual override".to_string()
        } else {
            detail.to_string()
        },
        confidence: 100,
        origin: "override".to_string(),
        observed_at: now.clone(),
        updated_at: now,
    };
    match state.store.upsert_agent_log_source(&source).await {
        Ok(()) => Json(LogSourceView::from(&source)).into_response(),
        Err(err) => ApiError::internal(
            codes::LOG_SOURCE_UNAVAILABLE,
            "failed to store agent log source",
            err,
        )
        .into_response(),
    }
}

/// `DELETE /api/v1/admin/agents/{agent_id}/log-sources/{service}`
///
/// 删掉该服务的**全部**候选（含解析值）：返回删除行数。
///
/// 为什么允许一次删光：服务已经卸载 / 换机器了，留着一堆解析值只会在下次误采。
pub async fn delete_agent_log_sources(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path((agent_id, service)): Path<(String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    match state
        .store
        .delete_agent_log_sources(&agent_id, &service)
        .await
    {
        Ok(deleted) => Json(serde_json::json!({
            "agent_id": agent_id,
            "service": service,
            "deleted": deleted,
        }))
        .into_response(),
        Err(err) => ApiError::internal(
            codes::LOG_SOURCE_UNAVAILABLE,
            "failed to delete agent log sources",
            err,
        )
        .into_response(),
    }
}

/// `DELETE /api/v1/admin/agents/{agent_id}/log-sources/{service}/{source_ref}`
///
/// 删一条（一个实例）。**删覆盖即回落到解析值** —— 解析值一直在表里，不需要重采。
pub async fn delete_agent_log_source(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Path((agent_id, service, source_ref)): Path<(String, String, String)>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    if let Some(response) = agent_not_found_response(&state, &agent_id).await {
        return response;
    }
    match state
        .store
        .delete_agent_log_source(&agent_id, &service, &source_ref)
        .await
    {
        Ok(true) => Json(serde_json::json!({
            "agent_id": agent_id,
            "service": service,
            "source_ref": source_ref,
            "deleted": true,
        }))
        .into_response(),
        Ok(false) => ApiError::not_found(
            codes::LOG_SOURCE_INVALID,
            format!("no log source {service}/{source_ref} for {agent_id}"),
        )
        .into_response(),
        Err(err) => ApiError::internal(
            codes::LOG_SOURCE_UNAVAILABLE,
            "failed to delete agent log source",
            err,
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_services_outside_the_vocabulary() {
        assert!(validate_service("postgresql").is_ok());
        assert!(validate_service("postgres").is_err());
        assert!(validate_service("").is_err());
    }

    #[test]
    fn source_ref_must_name_an_instance() {
        assert!(validate_source_ref("port:5432").is_ok());
        assert!(validate_source_ref("pid:1234").is_ok());
        // `override` 由网关生成：人写成它会把另一个实例顶掉。
        assert!(validate_source_ref("override").is_err());
        assert!(validate_source_ref("5432").is_err());
        assert!(validate_source_ref("port:abc").is_err());
        assert!(validate_source_ref("port:99999").is_err());
        assert!(validate_source_ref("").is_err());
    }
}
