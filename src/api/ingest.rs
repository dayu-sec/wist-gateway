//! 数据面（warp-parse）**订阅端**的内部接入端点。
//!
//! 为什么有这一层：设计上事实上报只有**一条上行通道** —— agentd 发 `OBSFACT:` 帧到数据面，
//! 网关与中心**各自订阅**（见 `doc/design/center/agent-work-delivery-plan.md` §4.1）。
//! warp-parse 把帧解析成记录后，通过 `http_sink` POST 到这里。
//!
//! ## 边界与取舍
//!
//! - 这是**内部信任边界**：监听是**明文 HTTP 且只绑环回**（数据面的 sink 连接器没有 TLS
//!   参数，而网关对外那张监听是 HTTPS 自签证书，两者接不上）。
//! - **身份校验尚未落地**（见计划 §9 风险行）。所以这里做的**不是认证**，只有两件正确性检查：
//!   ① `agent_id`/`instance_id` 必须对得上登记表（防止把不存在的机器、或重装后换了实例的
//!   记录写进库）；② 信封里的自称与正文里的自称必须一致（不一致说明中间环节出了问题）。
//! - 记录里的 `body` 是**契约对象原样透传**的 JSON 文本（WPL/OML 刻意不做字段建模），
//!   所以这里要再解析一层。
//!
//! ## 为什么整批失败就回非 2xx
//!
//! warp-parse 的 http sink 对非 2xx 会重试并最终落 rescue 文件 —— 那是**可见的**。
//! 反过来，若这里对永久性错误回 202，记录会静默消失，没人会知道。宁可让它显形。

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use wist_api::facts::ReportAgentFactSummary;
use wist_control::types::DateTime;

use super::ApiState;
use super::agent_ops::{MAX_FACT_SUMMARY_BODY_BYTES, ingest_fact_summary};

/// 内部接入端点的 body 上限。
///
/// 比摘要本身的上限（[`MAX_FACT_SUMMARY_BODY_BYTES`]）宽一倍：这里的 body 是**外层记录**，
/// 摘要以 JSON **字符串**放在 `body` 字段里（转义会把引号、反斜杠翻倍），所以同一份摘要在
/// 这一层会比在控制面那一层大。卡死在上限上会让合法上报莫名其妙地 413。
/// 倍数取 2 而不是更大：上限的用处是「一台机器不能把网关写爆」，不是精确估算。
pub const MAX_INGEST_BODY_BYTES: usize = 2 * MAX_FACT_SUMMARY_BODY_BYTES;

/// warp-parse 记录中与「事实」有关的字段（其余字段如 `biz`/`env`/`sink` 我们不消费）。
#[derive(Debug, Deserialize)]
struct DataPlaneRecord {
    /// 帧信封里的自称 agent（OML 从信封取出）。
    /// **只作交叉核对**：身份不从记录字段来（当下也不从任何地方来）。
    #[serde(default)]
    agent_id: String,
    /// 事实正文：`ReportAgentFactSummary` 的 JSON 文本。
    body: String,
}

/// 内部接入端点：接收 warp-parse 转发来的 `OBSFACT:` 记录。
///
/// 接受单个记录对象，也接受记录数组（sink 的 `batch_size` 将来若调大就会出现数组）。
pub async fn ingest_agent_facts(
    State(state): State<ApiState>,
    Json(payload): Json<Value>,
) -> Response {
    let records = match payload {
        Value::Array(items) => items,
        other => vec![other],
    };

    let mut ingested = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for (index, raw) in records.iter().enumerate() {
        match ingest_one(&state, raw).await {
            Ok(()) => ingested += 1,
            Err(detail) => failures.push(format!("record #{index}: {detail}")),
        }
    }

    // 累计计数（自述面 / 上报中心读它）：数据面吞吐的一个信号；无论成败都记「最后一次接收」。
    {
        let mut runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        runtime.ingest_accepted_total += ingested as u64;
        runtime.ingest_rejected_total += failures.len() as u64;
        runtime.last_ingest_at = Some(DateTime::now());
    }

    // 不在响应里区分 accepted / duplicate：`ingest_fact_summary` 对两者都回 202，
    // 而对数据面而言「已收到、不必重试」是同一件事（判重的意义在网关库，不在回执）。
    let body = json!({
        "ingested": ingested,
        "rejected": failures.len(),
        "failures": failures,
    });

    if failures.is_empty() {
        (StatusCode::ACCEPTED, Json(body)).into_response()
    } else {
        // 非 2xx 是故意的：让 warp-parse 重试并最终落 rescue（可见），而不是静默丢。
        // 这个 body 是**领域响应**（逐条失败明细），不是通用错误信封 —— 保留 `{ingested,rejected,failures}`。
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

/// 处理一条记录。`Err` 里的字符串会原样回给数据面并进日志，所以要写清是**哪一步**失败。
async fn ingest_one(state: &ApiState, raw: &Value) -> Result<(), String> {
    let record: DataPlaneRecord = serde_json::from_value(raw.clone()).map_err(|err| {
        // 带上原始形状：数据面的记录结构变化时，这条错误要能直接指出收到了什么。
        format!(
            "not a data-plane fact record: {err}; received {}",
            preview(raw)
        )
    })?;

    let input: ReportAgentFactSummary = serde_json::from_str(&record.body)
        .map_err(|err| format!("body is not a ReportAgentFactSummary: {err}"))?;

    if !record.agent_id.is_empty() && record.agent_id != input.agent_id {
        return Err(format!(
            "envelope agent_id {} disagrees with body agent_id {}",
            record.agent_id, input.agent_id
        ));
    }

    let agent = state
        .store
        .get_agent(&input.agent_id)
        .await
        .map_err(|err| format!("failed to load agent {}: {err}", input.agent_id))?
        .ok_or_else(|| format!("unknown agent_id {}", input.agent_id))?;

    // 实例对不上就丢掉：agentd 重装后 instance_id 会变，把记录写进旧行等于把两台机器混成一台。
    if agent.instance_id != input.instance_id {
        return Err(format!(
            "instance_id mismatch for {}: registered {}, reported {}",
            input.agent_id, agent.instance_id, input.instance_id
        ));
    }

    // 拒绝名单（§5.6）：被吊销的 agent 的数据面记录也不该进库 —— 控制面切断还不够，
    // 「业务被切断、却还能推事实/日志」同样不叫切断。
    if state
        .store
        .is_agent_revoked(&input.agent_id)
        .await
        .map_err(|err| format!("failed to check revocation for {}: {err}", input.agent_id))?
    {
        return Err(format!("agent {} is revoked", input.agent_id));
    }

    // 校验/判重/入库/推断与「控制面直报」共用同一份实现，口径只有一份。
    let response = ingest_fact_summary(state, &agent, input).await;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "gateway rejected the fact summary with HTTP {status}"
        ));
    }
    Ok(())
}

/// 截断后的原始输入预览，用于诊断「数据面记录结构变了」这类问题。
pub(super) fn preview(raw: &Value) -> String {
    const LIMIT: usize = 200;
    let text = raw.to_string();
    if text.len() <= LIMIT {
        return text;
    }
    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

// ── 主机流记录（` FLOW: ` 帧）─────────────────────────────────────────────────

/// 流记录写入的 body 上限。
///
/// 一拍最多 4096 条、单条 ~700B ≈ 2.8 MB（`host-flow-data-spec.md` §2.5）。
/// 上限存在的意义是"一台机器不能把网关写爆"，不是精确估算。
pub const MAX_FLOW_INGEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// 数据面记录里与「流记录」有关的字段。
///
/// `tenant_id` 是数据面**业务身份绑定**后的自述（当前恒为 `unbound`）：
/// 只用来交叉核对，**不**作为租户来源 —— 绑定关系的权威是网关登记表。
#[derive(Debug, Deserialize)]
struct DataPlaneFlowRecord {
    /// 帧信封里的自称 agent。数据面的 OML 输出叫 `agent`（事实帧那条老路径叫 `agent_id`），
    /// 两种都接：这条交叉校验如果读不到值就等于没有校验。
    #[serde(default, alias = "agent")]
    agent_id: String,
    #[serde(default)]
    log_type: String,
    #[serde(default)]
    tenant_id: String,
    body: String,
}

/// 数据面自述的"没绑身份"占位值（与 wparse `.env` 注入同口径）。
const FLOW_TENANT_UNBOUND: &str = "unbound";

/// 内部接入端点：接收 warp-parse 转发来的 ` FLOW: ` 记录，补 `cust_id` 后转给证据服务。
///
/// 校验顺序与事实帧一致（信封 ↔ 正文 ↔ 登记表），再多两条流记录特有的：
/// `record_schema` 闸门与数据面 `tenant_id` 的交叉核对。
pub async fn ingest_agent_flows(
    State(state): State<ApiState>,
    Json(payload): Json<Value>,
) -> Response {
    let records = match payload {
        Value::Array(items) => items,
        other => vec![other],
    };

    let mut accepted = 0usize;
    let mut failures: Vec<String> = Vec::new();
    // 按租户分组：一批理论上只属于一个客户，但分组几乎不要钱，
    // 而"跨客户混在一批里"如果直接拒，会让一次配置错误连带丢别的客户的数据。
    let mut by_tenant: std::collections::BTreeMap<
        String,
        Vec<wist_contracts::host_flow::HostFlowRecord>,
    > = std::collections::BTreeMap::new();

    for (index, raw) in records.iter().enumerate() {
        match flow_one(&state, raw).await {
            Ok((cust_id, record)) => {
                by_tenant.entry(cust_id).or_default().push(record);
                accepted += 1;
            }
            Err(detail) => failures.push(format!("record #{index}: {detail}")),
        }
    }

    if failures.is_empty() && !by_tenant.is_empty() {
        let Some(url) = state.config.evidence_flows_url.clone() else {
            // 没配写端点：明确回 503（数据面会重试并落 rescue，可见），不静默丢。
            // 记录不进 `failures`：这不是某条记录的问题，是部署没接上。
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": {
                        "code": "evidence_flows_not_configured",
                        "message": "网关未配置 ingest.evidence_flows_url：流记录无处可送",
                    }
                })),
            )
                .into_response();
        };
        for (cust_id, batch) in &by_tenant {
            if let Err(detail) =
                crate::infra::evidence_flows::post_flows(&url, cust_id, batch).await
            {
                // 转发失败按**整批**失败处理：回非 2xx 让数据面落 rescue。
                failures.push(format!("evidence cust_id={cust_id}: {detail}"));
            }
        }
    }

    {
        let mut runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        runtime.ingest_accepted_total += if failures.is_empty() {
            accepted as u64
        } else {
            0
        };
        runtime.ingest_rejected_total += failures.len() as u64;
        runtime.last_ingest_at = Some(DateTime::now());
    }

    // 计数与失败口径：与事实帧同构 —— 成功 202、有失败 400（让数据面看见）。
    let rejected = failures.len();
    let ingested = if rejected == 0 { accepted } else { 0 };
    let body = json!({
        "ingested": ingested,
        "rejected": rejected,
        "failures": failures,
    });
    if rejected == 0 {
        (StatusCode::ACCEPTED, Json(body)).into_response()
    } else {
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

/// 处理一条流记录：校验 + 解析出 `(cust_id, HostFlowRecord)`。
async fn flow_one(
    state: &ApiState,
    raw: &Value,
) -> Result<(String, wist_contracts::host_flow::HostFlowRecord), String> {
    let record: DataPlaneFlowRecord = serde_json::from_value(raw.clone()).map_err(|err| {
        format!(
            "not a data-plane flow record: {err}; received {}",
            preview(raw)
        )
    })?;

    if record.log_type != "agent_uplink_flow_frame" {
        return Err(format!(
            "not a flow record: log_type={:?} (expected agent_uplink_flow_frame)",
            record.log_type
        ));
    }

    // 正文是转义后的契约对象（数据面不拆字段），这里再解析一层。
    let flow: wist_contracts::host_flow::HostFlowRecord = serde_json::from_str(&record.body)
        .map_err(|err| format!("body is not a HostFlowRecord: {err}"))?;

    if flow.record_schema != wist_contracts::host_flow::RECORD_SCHEMA_V1 {
        return Err(format!("unsupported record_schema {}", flow.record_schema));
    }

    // 信封自述与正文自述必须一致（与事实帧同一条纪律）。
    if !record.agent_id.is_empty() && record.agent_id != flow.collector_instance_id {
        return Err(format!(
            "envelope agent {} disagrees with collector_instance_id {}",
            record.agent_id, flow.collector_instance_id
        ));
    }

    let agent = state
        .store
        .get_agent(&flow.collector_instance_id)
        .await
        .map_err(|err| format!("failed to load agent {}: {err}", flow.collector_instance_id))?
        .ok_or_else(|| format!("unknown agent_id {}", flow.collector_instance_id))?;

    if state
        .store
        .is_agent_revoked(&flow.collector_instance_id)
        .await
        .map_err(|err| format!("failed to check revocation: {err}"))?
    {
        return Err(format!("agent {} is revoked", flow.collector_instance_id));
    }

    // 数据面若已经带了绑定（非 `unbound`），必须与登记表一致：不一致说明两处配置打架，
    // 这种情况下"挑一个信"都会把数据写错客户，只能整条拒。
    if !record.tenant_id.is_empty()
        && record.tenant_id != FLOW_TENANT_UNBOUND
        && record.tenant_id != agent.tenant_id
    {
        return Err(format!(
            "tenant mismatch: data plane {}, registry {}",
            record.tenant_id, agent.tenant_id
        ));
    }

    Ok((agent.tenant_id, flow))
}
