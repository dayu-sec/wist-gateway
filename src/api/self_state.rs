// NOTE(hand-added): 网关自述面（环回；CR-003）。对应 jumo 模型 Control.GatewayApp.SelfInterface
// 的 `GatewaySelfInterface.QuerySelfState`。模型的 `bind` 未定（环回鉴权未决），故路由手加；
// 重新生成控制面代码时需回补本模块与下方路由。
//
// 用途：host 侧 **wist-gwlinkd** 拉取**进程内算得准**的网关状态，再上报 WistCenter —— 网关活着拿到准值，
// 网关不答则把「沉默」当判断（见 CR-003）。

use axum::{
    Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use wist_control::types::DateTime;

use crate::infra::AgentQuery;

use super::ApiState;

#[derive(Debug, Deserialize)]
pub struct SelfStateQuery {
    /// 调用方自报的网关 id（网关侧未必自持该值；原样回显供调用方核对）。
    pub gateway_id: Option<String>,
}

/// 网关自述状态（对应模型 `GatewaySelfState`）。
#[derive(Debug, Serialize, ::jumo_derive::Jumo)]
#[serde(rename_all = "camelCase")]
#[jumo(
    kind = "struct",
    domain = "Control",
    module = "Control.GatewayApp.SelfInterface"
)]
pub struct GatewaySelfState {
    pub gateway_id: String,
    pub version: String,
    pub collected_at: DateTime,
    pub store_healthy: bool,
    pub agent_count: i64,
    pub uplink_enabled: bool,
    pub last_error: Option<String>,
}

pub async fn query_self_state(
    State(state): State<ApiState>,
    Query(params): Query<SelfStateQuery>,
) -> Response {
    Json(self_state(&state, params.gateway_id.as_deref()).await).into_response()
}

async fn self_state(state: &ApiState, gateway_id: Option<&str>) -> GatewaySelfState {
    let mut last_error: Option<String> = None;

    // 存储健康 = 「能不能查」；同时顺手拿到机队规模。
    let (store_healthy, agent_count) = match state.store.list_agents(&AgentQuery::default()).await {
        Ok(agents) => (true, agents.len() as i64),
        Err(err) => {
            last_error = Some(err.to_string());
            (false, 0)
        }
    };

    // 上送启用 = 是否设置了 agent 数据面上送地址（无目标即不采集、不上送）。
    let uplink_enabled = match state.store.get_agent_uplink().await {
        Ok(setting) => setting.is_some(),
        Err(err) => {
            if last_error.is_none() {
                last_error = Some(err.to_string());
            }
            false
        }
    };

    GatewaySelfState {
        gateway_id: gateway_id.unwrap_or_default().to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        collected_at: DateTime::now(),
        store_healthy,
        agent_count,
        uplink_enabled,
        last_error,
    }
}
