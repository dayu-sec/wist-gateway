use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};

// ─────────────────────────────────────────────────────────────────────────────
// 采集内容目录的只读视图
//
// 为什么要有它：内容目录（catalog / packs / templates）装载与校验在启动时做，
// 但「网关到底装了什么、哪些面已经能采、哪些还只能落原文」需要一个能看的地方 ——
// 这也是「部分可用/渐进启用」的可见面（见 doc/design/center/agent-work-templates.md §6.1）。
//
// **两个轴分开报**：采集（能不能派下去把原文拿回来）与解析（拿回来的能不能归类、抽字段）。
// 只报一个就会让人把「采到了但认不出是谁」当成已就绪，或反过来拿规则去卡采集。
//
// 该端点不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics / pipeline / software
// 同一模式（模型里没有这些内部视图路由）。重新生成控制面代码时需回补本模块与路由。
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TemplateView {
    template_id: String,
    machine_class: String,
    platform: String,
    /// 策展成熟度（**不是**授权闸门）。
    status: String,
    /// 派生：展开后的面集。
    family_scope: Vec<String>,
    /// 派生：展开后单元能力的并集。
    capability_scope: Vec<String>,
}

#[derive(Debug, Serialize)]
struct FamilyReadinessView {
    family: String,
    /// 采集就绪（`status = active`）的单元数。
    active_units: usize,
    /// 采集就绪**且**解析就绪（`rule_ref` 非空）的单元数。
    parse_ready_units: usize,
    total_units: usize,
    /// 采集就绪：这个面能被派下去采。
    ready: bool,
    /// 解析就绪：采下来的记录能被归类、抽字段。**不参与授权闸门**。
    parse_ready: bool,
}

#[derive(Debug, Serialize)]
struct ReadinessView {
    platform: String,
    families: Vec<FamilyReadinessView>,
}

#[derive(Debug, Serialize)]
struct ContentView {
    catalog_version: i64,
    superseded_by: Option<i64>,
    templates: Vec<TemplateView>,
    readiness: Vec<ReadinessView>,
}

/// 查看网关已装载的采集内容：模板组成 + 各平台的面就绪度。
pub async fn view_content(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let knowledge = state.knowledge();
    let Some(content) = knowledge.content.as_deref() else {
        // 不是 404：端点存在，只是这台网关**没配**内容目录 —— 与「没发布」区分开，
        // 与 discovery-policies 未配置时回 503 同一约定。
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "content catalog is not configured",
        )
            .into_response();
    };

    let templates = content
        .templates()
        .map(|template| TemplateView {
            template_id: template.template_id.clone(),
            machine_class: template.machine_class.clone(),
            platform: template.platform.clone(),
            status: template.status.clone(),
            family_scope: template.family_scope.clone(),
            capability_scope: template.capability_scope.clone(),
        })
        .collect();

    let readiness = ["macos", "linux"]
        .into_iter()
        .map(|platform| ReadinessView {
            platform: platform.to_string(),
            families: content
                .family_readiness(platform)
                .into_iter()
                .map(|entry| FamilyReadinessView {
                    ready: entry.collect_ready(),
                    parse_ready: entry.parse_ready(),
                    family: entry.family,
                    active_units: entry.active_units,
                    parse_ready_units: entry.parse_ready_units,
                    total_units: entry.total_units,
                })
                .collect(),
        })
        .collect();

    Json(ContentView {
        catalog_version: content.catalog_version,
        superseded_by: content.superseded_by,
        templates,
        readiness,
    })
    .into_response()
}
