//! Agent 面（edge seam B：gateway ↔ agentd）的 **v1** 路由表。
//!
//! 冻结基线：只做**加性**兼容不动它；需要非加性变更就新开 `v2`（另一组路由 + 另一组报文类型），
//! 本模块**只增不删**。

use axum::routing::{MethodRouter, post};

use super::super::agent_ops::{
    ack_work, poll_agent_uplink, poll_control_commands, poll_discovery_policies, poll_work,
    renew_agent_credential, report_action_result, submit_agent_status, submit_work_result,
};
use super::super::enrollment::enroll_agent;
use super::ApiState;

pub fn routes() -> Vec<(&'static str, MethodRouter<ApiState>)> {
    vec![
        ("/enroll", post(enroll_agent)),
        ("/status", post(submit_agent_status)),
        // agentd 上报事实**摘要**的原控制面路由 `POST /api/v1/agent/facts` 已删 —— 事实统一走
        // 数据面：agentd 发 `OBSFACT:` 帧 → warp-parse → 网关的**内部**端点
        // `/api/v1/ingest/agent-facts`（见 `ingest_router` 与 api/ingest.rs）。
        ("/credentials:renew", post(renew_agent_credential)),
        ("/control-commands:poll", post(poll_control_commands)),
        ("/action-results", post(report_action_result)),
        // agentd 拉取发现方向策略表。`:poll` 后缀标明它是幂等的「拉当前版本」，而不是一次汇报。
        ("/discovery-policies:poll", post(poll_discovery_policies)),
        // 工作授权快照的拉取：幂等内容、可重复拉取；断网重启后重拉一次即回期望状态。
        ("/work:poll", post(poll_work)),
        // 数据面上送启用的拉取。刻意走**独立端点**而不是给 WorkGrant 加字段 —— WorkGrant 两侧
        // 都 `deny_unknown_fields`，加字段会让「新网关 + 旧 agentd」解析失败（舰队级停摆）。
        // 旧 agentd 不调它，新 agentd 遇旧网关得 404 后回落本机配置。
        ("/uplink:poll", post(poll_agent_uplink)),
        // 确认收到某份工作（常驻工作带生效版本）。
        ("/work:ack", post(ack_work)),
        // 一次性工作的执行结果（进度/终态）。与 ack 分开：确认回答「我收到了」，结果回答
        // 「我做得怎么样」—— 失效代价不同，不挤一条路。
        ("/work:result", post(submit_work_result)),
    ]
}
