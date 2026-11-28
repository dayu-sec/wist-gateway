//! `POST /api/v1/agent/exporter-policy:poll`：下发**导出器运行参数**
//! （二进制搜索目录 + 周期 / 超时）。
//!
//! ## 为什么是独立端点
//!
//! 已有 `:poll` 报文两侧都是 `deny_unknown_fields` —— 给它们加字段会让**旧 agentd**
//! 解析整份报文失败（舰队级停摆）。新能力一律新开端点：旧 agentd 从不调它；
//! 新 agentd 遇旧网关得 404 后静默回落内置表（`telemetry::exporters::BIN_DIRS`）。
//!
//! ## 为什么这些值由网关下发
//!
//! 工具的安装位置是**纯环境信息**（发行版 / 容器镜像 / Homebrew / 自建前缀），
//! 写死在 agentd 里意味着每种新环境都要发一版 root 守护进程。数据能改「去哪找、多久跑」，
//! **不能改「跑什么」**：`id` 必须是契约 `EXPORTER_IDS` 里已登记的，参数留在 agentd 代码里
//! （校验见 `app::exporter_policy::validate`）。
//!
//! ## 空载不是错误
//!
//! 网关没装知识库 / 这一版目录没有 `exporters.toml` → 回 200 + 空目录 + 空覆盖，
//! agentd 用内置值。回 503 会逼 agentd 每拍告警，而这里没有需要人修的东西。

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
use crate::infra::VerifiedAgentIdentity;

/// 与 agentd 约定的 `kind`（agentd 侧同名常量在 `control/exporter_policy.rs`）。
const POLL_KIND: &str = "exporter_policy";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollExporterPolicy {
    pub api_version: String,
    pub kind: String,
    pub agent_id: String,
    pub instance_id: String,
    /// `linux` / `macos`：决定用哪一套搜索目录。**本机事实**，由 agent 自报。
    ///
    /// 为什么不从注册表推：注册表没有平台字段，而 agentd 自己最清楚。猜错最坏结果是
    /// 拿到另一平台的目录表（目录本身已过白名单校验，且不存在的目录会被跳过），不会越权。
    #[serde(default)]
    pub platform: String,
    /// 只是回声：与其它 `:poll` 端点保持一致（client 时间在这条路径上没有语义）。
    #[serde(default)]
    #[allow(dead_code)]
    pub requested_at: String,
}

#[derive(Debug, Serialize)]
pub struct ExporterOverrideView {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ExporterPolicyReturned {
    pub api_version: String,
    pub kind: String,
    /// 这份参数来自哪一版知识库（0 = 空载 / 没有 exporters.toml）。
    pub exporters_version: i64,
    pub platform: String,
    /// 按优先级排列的搜索目录。空 = agentd 用内置表。
    pub bin_dirs: Vec<String>,
    /// 周期 / 超时覆盖（只包含真的写了的项）。空 = 全用内置值。
    pub exporters: Vec<ExporterOverrideView>,
    pub returned_at: String,
}

pub async fn poll_exporter_policy(
    State(state): State<ApiState>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    Json(input): Json<PollExporterPolicy>,
) -> Response {
    if input.api_version != API_VERSION_V1 || input.kind != POLL_KIND {
        return ApiError::bad_request(
            codes::INVALID_EXPORTER_POLICY_POLL,
            "invalid exporter policy poll",
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

    let platform = input.platform.trim().to_ascii_lowercase();
    let knowledge = state.knowledge();
    let Some(table) = knowledge.exporters.as_deref() else {
        // 空载：合法答案就是“没有参数”，agentd 用内置值。
        return Json(ExporterPolicyReturned {
            api_version: API_VERSION_V1.to_string(),
            kind: POLL_KIND.to_string(),
            exporters_version: 0,
            platform,
            bin_dirs: Vec::new(),
            exporters: Vec::new(),
            returned_at: chrono::Utc::now().to_rfc3339(),
        })
        .into_response();
    };

    Json(ExporterPolicyReturned {
        api_version: API_VERSION_V1.to_string(),
        kind: POLL_KIND.to_string(),
        exporters_version: table.exporters_version,
        bin_dirs: table.bin_dirs_for(&platform),
        exporters: table
            .overrides()
            .into_iter()
            .map(|row| ExporterOverrideView {
                id: row.id,
                period_secs: row.period_secs,
                timeout_secs: row.timeout_secs,
            })
            .collect(),
        platform,
        returned_at: chrono::Utc::now().to_rfc3339(),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::exporter_policy::{ExporterOverride, ExporterPolicyTable, PlatformBinDirs};

    fn table() -> ExporterPolicyTable {
        ExporterPolicyTable {
            exporters_version: 3,
            published_at: String::new(),
            platform: vec![
                PlatformBinDirs {
                    platform: "linux".to_string(),
                    bin_dirs: vec!["/usr/bin".to_string(), "/bin".to_string()],
                },
                PlatformBinDirs {
                    platform: "macos".to_string(),
                    bin_dirs: vec!["/opt/homebrew/bin".to_string()],
                },
            ],
            exporter: vec![ExporterOverride {
                id: "dmesg".to_string(),
                period_secs: Some(120),
                timeout_secs: None,
            }],
        }
    }

    /// 平台决定目录：不能把 linux 的目录发给 macOS（HostFlow 那类“换载体”同理）。
    #[test]
    fn the_platform_selects_the_directory_table() {
        let table = table();
        assert_eq!(table.bin_dirs_for("linux"), vec!["/usr/bin", "/bin"]);
        assert_eq!(table.bin_dirs_for("macos"), vec!["/opt/homebrew/bin"]);
        // 未知平台：空 = 让 agentd 用内置表（不是“没目录就报错”）。
        assert!(table.bin_dirs_for("windows").is_empty());
    }

    /// 覆盖项只包含真的写了的字段（不把 None 当成“清零”下发）。
    #[test]
    fn only_declared_overrides_are_serialized() {
        let table = table();
        let overrides = table.overrides();
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].id, "dmesg");
        assert_eq!(overrides[0].period_secs, Some(120));
        assert_eq!(overrides[0].timeout_secs, None);

        let payload = ExporterOverrideView {
            id: "dmesg".to_string(),
            period_secs: Some(120),
            timeout_secs: None,
        };
        let json = serde_json::to_string(&payload).expect("serialize");
        assert!(json.contains("period_secs"));
        assert!(!json.contains("timeout_secs"), "{json}");
    }
}
