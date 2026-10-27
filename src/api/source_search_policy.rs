//! `POST /api/v1/agent/source-search-policy:poll`：下发 L3 受限搜索的**生效 roots**。
//!
//! ## 为什么是独立端点，而不是给已有报文加字段
//!
//! `DiscoveryPoliciesReturned` 两侧都是 `deny_unknown_fields` —— 给它加字段会让
//! **旧 agentd** 解析整份报文失败（舰队级停摆）。所以新能力一律新开端点：
//! 旧 agentd 从不调它；新 agentd 遇旧网关得 404 后静默跳过（等同「不支持 L3」）。
//!
//! ## 为什么 roots 由网关算好再发
//!
//! 搜索是本系统里**唯一「遍历文件系统」**的动作，它等于允许一个 root 进程枚举客户机的
//! 目录。因此权限模型是**交集**，且每一层都不能单独放宽：
//!
//! ```text
//! 生效 roots = 知识库 [[units]] search_roots   （签名产物的舰队级上限）
//!            ∩ [collection] allowed_source_roots（部署侧的采集授权）
//! ```
//!
//! agentd 侧**没有配置**（本机任何文件都改不了范围），拿不到策略就不搜索（fail-closed）。
//!
//! ## 拿不到内容时
//!
//! 网关空载（没装知识库）不是错误：合法答案是「这个部署没有开启搜索」——
//! 回 200 + 空列表 + `catalog_version = 0`，而不是 503。503 会逼 agentd 每拍打一条告警，
//! 而这里根本没有需要人来修的东西。

use axum::{
    Json,
    extract::{Extension, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use wist_contracts::API_VERSION_V1;

use crate::api::ApiState;
use crate::api::agent_ops::authenticate_agent;
use crate::api::codes;
use crate::api::error::ApiError;
use crate::app::content::Unit;
use crate::app::log_source::{MAX_SEARCH_ROOTS, is_under_roots};
use crate::infra::VerifiedAgentIdentity;

/// 与 agentd 约定的 `kind`（agentd 侧同名常量在 `control/source_search_policy.rs`）。
const POLL_KIND: &str = "source_search_policy";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollSourceSearchPolicy {
    pub api_version: String,
    pub kind: String,
    pub agent_id: String,
    pub instance_id: String,
    /// 只是回声：与其它 `:poll` 端点保持一致（client 时间在这条路径上没有语义）。
    #[serde(default)]
    #[allow(dead_code)]
    pub requested_at: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceSearchRoots {
    pub service: String,
    pub roots: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SourceSearchPolicyReturned {
    pub api_version: String,
    pub kind: String,
    /// 这份 roots 来自知识库的哪一版（审计用）。0 = 网关空载。
    pub catalog_version: i64,
    /// **只包含生效值**：空列表 = 这个服务不做 L3 搜索（服务不会以空 roots 出现）。
    pub services: Vec<ServiceSearchRoots>,
    pub returned_at: String,
}

/// 逐服务算生效 roots：知识库上限 ∩ 部署侧的 `allowed_source_roots`。
///
/// 一个单元可能辖多个服务（`linux-db-service` 就是四个），所以按 `from_dir` 的 key 摊开：
/// **单元级的 `search_roots` 对它辖下的每个服务都生效**。
///
/// 参数是单元切片而不是 `ContentSet`：求值只跟“单元声明了什么”有关，
/// 与包/模板无关 —— 这样这条逻辑不需要一整套可装载的目录也能测。
pub fn effective_roots(units: &[&Unit], allowed: &[String]) -> Vec<ServiceSearchRoots> {
    // BTreeMap 保证输出顺序稳定（同一个 agent 每次拿到的列表不会来回跳）。
    let mut declared: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for unit in units {
        if unit.search_roots.is_empty() {
            continue;
        }
        for source in &unit.sources {
            let Some(service) = source.log_service() else {
                continue;
            };
            let entry = declared.entry(service).or_default();
            for root in &unit.search_roots {
                entry.insert(root.as_str());
            }
        }
    }

    let mut services = Vec::new();
    for (service, roots) in declared {
        let mut kept: Vec<String> = Vec::new();
        let mut dropped: Vec<&str> = Vec::new();
        for root in roots {
            if is_under_roots(root, allowed) {
                kept.push(root.to_string());
            } else {
                dropped.push(root);
            }
        }
        if !dropped.is_empty() {
            // 被部署策略裁掉这件事**必须留痕**：否则现场只会看到「搜索开了但什么都没找到」，
            // 而真正的原因是 `allowed_source_roots` 没放开（那是两份配置的交集语义）。
            log::warn!(
                "event=SourceSearchRootsNarrowed service={service} dropped={dropped:?} \
                 reason=out_of_allowed_source_roots"
            );
        }
        if kept.is_empty() {
            continue;
        }
        // 两个单元给同一服务各写了一组时可能超上限：排序后截断，保证可复现。
        kept.sort();
        kept.dedup();
        if kept.len() > MAX_SEARCH_ROOTS {
            log::warn!(
                "event=SourceSearchRootsTruncated service={service} kept={} max={MAX_SEARCH_ROOTS}",
                kept.len()
            );
            kept.truncate(MAX_SEARCH_ROOTS);
        }
        services.push(ServiceSearchRoots {
            service: service.to_string(),
            roots: kept,
        });
    }
    services
}

pub async fn poll_source_search_policy(
    State(state): State<ApiState>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollSourceSearchPolicy>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_KIND {
        return ApiError::bad_request(
            codes::INVALID_SOURCE_SEARCH_POLICY_POLL,
            "invalid source search policy poll",
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

    let knowledge = state.knowledge();
    let content = knowledge.content.as_deref();
    let units: Vec<&Unit> = content
        .map(|content| content.units().collect())
        .unwrap_or_default();
    let services = effective_roots(&units, &state.config.allowed_source_roots);
    Json(SourceSearchPolicyReturned {
        api_version: API_VERSION_V1.to_string(),
        kind: POLL_KIND.to_string(),
        catalog_version: content.map(|content| content.catalog_version).unwrap_or(0),
        services,
        returned_at: chrono::Utc::now().to_rfc3339(),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::content::UnitSource;

    fn unit(id: &str, services: &[&str], search_roots: &[&str]) -> Unit {
        Unit {
            unit_id: id.to_string(),
            family: "DatabaseService".to_string(),
            capability: "collect_logs".to_string(),
            platform: "linux".to_string(),
            service: String::new(),
            match_expr: String::new(),
            rule_ref: String::new(),
            search_roots: search_roots.iter().map(|root| root.to_string()).collect(),
            min_agentd_version: None,
            requires_privilege: "root".to_string(),
            status: "active".to_string(),
            sources: services
                .iter()
                .map(|service| UnitSource {
                    kind: "FileGlob".to_string(),
                    target: String::new(),
                    from_dir: Some(format!("log_source:{service}")),
                    pattern: "*.log".to_string(),
                    multiline: "none".to_string(),
                    exclude_globs: Vec::new(),
                    filters: Default::default(),
                    drop_if_contains: Vec::new(),
                })
                .collect(),
        }
    }

    fn roots(services: &[ServiceSearchRoots]) -> Vec<(&str, Vec<&str>)> {
        services
            .iter()
            .map(|entry| {
                (
                    entry.service.as_str(),
                    entry.roots.iter().map(String::as_str).collect(),
                )
            })
            .collect()
    }

    fn allowed(roots: &[&str]) -> Vec<String> {
        roots.iter().map(|root| root.to_string()).collect()
    }

    #[test]
    fn unit_roots_apply_to_every_service_the_unit_covers() {
        let db = unit(
            "linux-db-service",
            &["postgresql", "mysql"],
            &["/data", "/srv"],
        );

        let services = effective_roots(&[&db], &allowed(&["/data", "/srv"]));
        assert_eq!(
            roots(&services),
            vec![
                ("mysql", vec!["/data", "/srv"]),
                ("postgresql", vec!["/data", "/srv"]),
            ]
        );
    }

    #[test]
    fn roots_outside_allowed_source_roots_are_dropped_not_fatal() {
        let db = unit("linux-db-service", &["postgresql"], &["/data", "/opt"]);

        // `/opt` 不在这个部署的 allowed roots 里 → 裁掉；`/data` 留下。
        let services = effective_roots(&[&db], &allowed(&["/data"]));
        assert_eq!(roots(&services), vec![("postgresql", vec!["/data"])]);
    }

    #[test]
    fn a_service_whose_roots_are_all_narrowed_out_disappears() {
        let db = unit("linux-db-service", &["postgresql"], &["/opt"]);
        assert!(effective_roots(&[&db], &allowed(&["/data"])).is_empty());
    }

    #[test]
    fn a_unit_without_search_roots_enables_nothing() {
        let db = unit("linux-db-service", &["postgresql"], &[]);
        assert!(
            effective_roots(&[&db], &allowed(&["/data"])).is_empty(),
            "缺省 = 不搜（fail-closed）"
        );
    }

    #[test]
    fn units_that_declare_the_same_service_are_merged() {
        let first = unit("a", &["postgresql"], &["/data"]);
        let second = unit("b", &["postgresql"], &["/data", "/srv"]);

        let services = effective_roots(&[&first, &second], &allowed(&["/data", "/srv"]));
        assert_eq!(
            roots(&services),
            vec![("postgresql", vec!["/data", "/srv"])],
            "两个单元给同一服务各写一组 → 并集（已各自校验过）"
        );
    }

    #[test]
    fn a_source_without_from_dir_is_not_a_service() {
        let mut db = unit("linux-db-service", &[], &["/data"]);
        db.sources.push(UnitSource {
            kind: "FileGlob".to_string(),
            target: "/var/log/x.log".to_string(),
            from_dir: None,
            pattern: String::new(),
            multiline: "none".to_string(),
            exclude_globs: Vec::new(),
            filters: Default::default(),
            drop_if_contains: Vec::new(),
        });

        assert!(
            effective_roots(&[&db], &allowed(&["/data"])).is_empty(),
            "字面值来源不产生搜索"
        );
    }

    #[test]
    fn no_units_means_no_search() {
        assert!(effective_roots(&[], &allowed(&["/data"])).is_empty());
    }
}
