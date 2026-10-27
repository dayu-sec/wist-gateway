//! `POST /api/v1/agent/log-sources`：agentd 上报**本机解析出来的**日志源候选。
//!
//! ## 为什么走独立端点
//!
//! 现有报文（`AgentStatusReport` / `AgentUplinkGrant` / `DiscoveryPoliciesReturned` /
//! `AgentPreflightReport`）两侧都是 `deny_unknown_fields`，加字段会让整舰队解析失败。
//! 新能力一律新开端点：旧 agentd 从不调它，新 agentd 遇旧网关得 404 后静默跳过。
//!
//! ## 判定边界
//!
//! agent 只报「**看到了什么**」（进程参数推出了哪个目录），采不采仍由网关决定：
//!
//! * `dir` 必须落在 `[collection] allowed_source_roots` 内（越界逐条丢弃，不整份拒绝）；
//! * `evidence` 必须在词表内，且 **agent 不能自称 `human`** —— 那是人工覆盖的标记；
//! * 一条坏候选不拖垮整份报告：逐条校验、逐条计数，回执里给出 `accepted` / `rejected`。

use axum::{
    Json,
    extract::{Extension, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use wist_contracts::API_VERSION_V1;

use crate::api::ApiState;
use crate::api::agent_ops::authenticate_agent;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::api::log_sources::{validate_service, validate_source_ref};
use crate::app::log_source::{LOG_SOURCE_EVIDENCE, is_under_roots, normalize_dir};
use crate::infra::{StoredLogSource, VerifiedAgentIdentity};

/// 与 agentd 约定的 `kind`（agentd 侧同名常量在 `control/log_sources.rs`）。
const REPORT_KIND: &str = "log_sources";

/// 单次最多几条（与 agentd 的上限一致）。超了整份 400：
/// 那是 agent 侧上限失灵，宁可让它重来，也别悄悄截断让人以为全报上了。
const MAX_SOURCES: usize = 64;

/// `detail` 的长度上限（字符数，不是字节）。与存储侧同一口径。
const MAX_DETAIL_CHARS: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLogSourceReport {
    pub api_version: String,
    pub kind: String,
    pub agent_id: String,
    pub instance_id: String,
    #[serde(default)]
    pub observed_at: String,
    pub sources: Vec<AgentLogSourceEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLogSourceEntry {
    pub service: String,
    pub source_ref: String,
    pub dir: String,
    pub evidence: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub confidence: i64,
}

#[derive(Debug, Default, Serialize)]
pub struct LogSourceReportAck {
    pub accepted: usize,
    pub rejected: usize,
}

pub async fn agent_log_sources(
    State(state): State<ApiState>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<AgentLogSourceReport>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != REPORT_KIND {
        return ApiError::bad_request(
            codes::INVALID_LOG_SOURCE_REPORT,
            "invalid log source report",
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
    if input.sources.len() > MAX_SOURCES {
        return ApiError::bad_request(
            codes::INVALID_LOG_SOURCE_REPORT,
            format!(
                "log source report has {} entries (max {MAX_SOURCES})",
                input.sources.len()
            ),
        )
        .into_response();
    }

    let now = chrono::Utc::now();
    let observed_at = normalize_observed_at(&input.observed_at, now);
    // 乱序到达的报告不能把更新的那份盖掉：替换语义下，旧报告会把新候选清成旧的。
    // 只比 agent 自己的 `observed_at`（两边都是 agent 的墙钟，可比）。
    if let Ok(existing) = state.store.list_agent_log_sources(&input.agent_id).await
        && let Some(latest) = existing
            .iter()
            .filter(|source| source.origin == "agent")
            .filter_map(|source| parse_rfc3339_millis(&source.observed_at))
            .max()
        && let Some(incoming) = parse_rfc3339_millis(&observed_at)
        && latest > incoming
    {
        log::info!(
            "event=LogSourceReportIgnoredStale agent_id={} incoming={} existing={}",
            input.agent_id,
            observed_at,
            existing
                .iter()
                .filter(|source| source.origin == "agent")
                .map(|source| source.observed_at.as_str())
                .max()
                .unwrap_or_default()
        );
        return Json(LogSourceReportAck::default()).into_response();
    }

    let mut accepted = Vec::with_capacity(input.sources.len());
    let mut rejected = 0usize;
    for entry in &input.sources {
        match validate_entry(&state, entry) {
            Ok(source) => accepted.push(StoredLogSource {
                agent_id: input.agent_id.clone(),
                service: source.service,
                source_ref: source.source_ref,
                dir: source.dir,
                evidence: source.evidence,
                detail: source.detail,
                confidence: source.confidence,
                // 上报路径**只能**写 agent：`override` 是人写的，不能让 agent 冒充。
                origin: "agent".to_string(),
                observed_at: observed_at.clone(),
                updated_at: now.to_rfc3339(),
            }),
            Err(reason) => {
                rejected += 1;
                // 每条都要能回答「为什么这条没被采用」，否则现场只能盯着一个数字。
                log::warn!(
                    "event=LogSourceRejected agent_id={} service={} source_ref={} detail=\"{}\"",
                    input.agent_id,
                    entry.service,
                    entry.source_ref,
                    reason
                );
            }
        }
    }
    let accepted_count = accepted.len();
    match state
        .store
        .replace_agent_log_sources(&input.agent_id, &accepted)
        .await
    {
        Ok(_) => {
            log::info!(
                "event=LogSourceReported agent_id={} accepted={accepted_count} rejected={rejected}",
                input.agent_id
            );
            Json(LogSourceReportAck {
                accepted: accepted_count,
                rejected,
            })
            .into_response()
        }
        Err(err) => ApiError::internal(
            codes::LOG_SOURCE_UNAVAILABLE,
            "failed to store agent log sources",
            err,
        )
        .into_response(),
    }
}

/// 逐条校验；返回**能入库的那一版**（目录已规范化、置信度已夹紧）。
fn validate_entry(
    state: &ApiState,
    entry: &AgentLogSourceEntry,
) -> Result<AgentLogSourceEntry, String> {
    validate_service(&entry.service)?;
    validate_source_ref(&entry.source_ref)?;
    let evidence = entry.evidence.trim();
    if !LOG_SOURCE_EVIDENCE.contains(&evidence) {
        return Err(format!(
            "evidence {evidence:?} 不在词表 {LOG_SOURCE_EVIDENCE:?} 里"
        ));
    }
    if evidence == "human" {
        // `human` 只属于人工覆盖（`PUT …/log-sources/{service}`）。
        return Err("agent 不能上报 evidence = human（那是人工覆盖的标记）".to_string());
    }
    // 「看得见实例、找不到目录」：只用于计数，不能带目录（带目录就是自相矛盾的候选）。
    if evidence == "unresolved" {
        if !entry.dir.trim().is_empty() {
            return Err("evidence = unresolved 时 dir 必须为空".to_string());
        }
        let detail: String = entry.detail.trim().chars().take(MAX_DETAIL_CHARS).collect();
        return Ok(AgentLogSourceEntry {
            service: entry.service.clone(),
            source_ref: entry.source_ref.trim().to_string(),
            dir: String::new(),
            evidence: evidence.to_string(),
            detail,
            confidence: 0,
        });
    }
    let dir = normalize_dir(&entry.dir)?;
    if dir.len() > 1024 {
        return Err("dir 过长（≤ 1024 字符）".to_string());
    }
    // **不在 roots 内的目录也存**：容器里跑的 PG 常常落在 named volume
    // （`/var/lib/docker/volumes/...`）—— 目录**找到了**，只是不在默认 roots 里。
    // 丢掉它，页面就只能说「1 个实例」，而真正的原因是 roots，不是 logging_collector。
    //
    // 安全性不靠“拒存”保证：**roots 过滤在求值时做**（`resolve_dirs`），
    // 一行越界数据永远不会变成采集目标。
    if !is_under_roots(&dir, &state.config.allowed_source_roots) {
        log::warn!(
            "event=LogSourceOutOfRoots service={} source_ref={} dir={}",
            entry.service,
            entry.source_ref,
            dir
        );
    }
    let detail: String = entry.detail.trim().chars().take(MAX_DETAIL_CHARS).collect();
    Ok(AgentLogSourceEntry {
        service: entry.service.clone(),
        source_ref: entry.source_ref.trim().to_string(),
        dir,
        evidence: evidence.to_string(),
        detail,
        confidence: entry.confidence.clamp(0, 100),
    })
}

fn normalize_observed_at(raw: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return now.to_rfc3339();
    }
    match chrono::DateTime::parse_from_rfc3339(trimmed) {
        Ok(value) => value.with_timezone(&chrono::Utc).to_rfc3339(),
        Err(_) => now.to_rfc3339(),
    }
}

fn parse_rfc3339_millis(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_at_falls_back_to_now_when_unparsable() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-26T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(normalize_observed_at("", now), now.to_rfc3339());
        assert_eq!(normalize_observed_at("not-a-time", now), now.to_rfc3339());
        assert_eq!(
            normalize_observed_at("2026-10-26T01:02:03Z", now),
            "2026-10-26T01:02:03+00:00"
        );
    }

    /// 逐字抄一份 agentd 的网络报文：两侧不共享类型，且这里是 `deny_unknown_fields` ——
    /// 字段名一旦漂移就是**整份报告**解析失败（不是逐条丢弃）。
    #[test]
    fn agentd_payload_shape_is_accepted() {
        let payload = r#"{
            "api_version": "v1",
            "kind": "log_sources",
            "agent_id": "agent-a",
            "instance_id": "instance-a",
            "observed_at": "2026-10-26T00:00:00Z",
            "sources": [
                {
                    "service": "postgresql",
                    "source_ref": "port:5432",
                    "dir": "/data/pg/log",
                    "evidence": "cmdline_datadir",
                    "detail": "-D /data/pg",
                    "confidence": 90
                },
                {
                    "service": "mysql",
                    "source_ref": "port:3306",
                    "dir": "",
                    "evidence": "unresolved",
                    "detail": "看到实例，但没有可用的日志路径",
                    "confidence": 0
                }
            ]
        }"#;
        let report: AgentLogSourceReport =
            serde_json::from_str(payload).expect("agentd 的报文形状必须能解析");
        assert_eq!(report.kind, REPORT_KIND);
        assert_eq!(report.sources.len(), 2);
        assert_eq!(report.sources[0].evidence, "cmdline_datadir");
        assert_eq!(report.sources[1].dir, "");
    }

    /// 与 agentd 的 `rules::EVIDENCE_VALUES` **同一份字面清单**：
    /// 谁改漏了另一侧，这个测试就红。
    #[test]
    fn evidence_vocabulary_covers_what_agentd_emits() {
        let agentd_emits = [
            "cmdline_datadir",
            "env_datadir",
            "cmdline_logfile",
            "config_file",
            "open_fd",
            "search_hit",
            "unresolved",
        ];
        for evidence in agentd_emits {
            assert!(
                LOG_SOURCE_EVIDENCE.contains(&evidence),
                "网关词表缺 {evidence:?}：agentd 会报它，然后被逐条丢弃"
            );
        }
    }
}
