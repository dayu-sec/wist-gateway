//! VictoriaMetrics HTTP 访问助手（控制面**只读**）。
//!
//! 这台 VM 的时序只有一个写入者：数据面（warp-parse 的 `vm_metrics_sink` → `/api/v1/import`）。
//! 控制面因此只保留查询入口 `query_json`（PromQL）；**不提供写入助手** —— 曾经有一份
//! `import_lines` 让网关把 agent 自身状态也写成时序，结果与 agentd 的指标帧形成两条同义序列
//! （label 集还不一样），`count`/`sum` 类查询会双计。

use std::time::Duration;

use reqwest::Client;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

fn client() -> Client {
    Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// GET `{vm_url}{path}`（如 `/api/v1/query` / `/api/v1/query_range`），返回 JSON。
pub async fn query_json(
    vm_url: &str,
    path: &str,
    params: &[(&str, &str)],
) -> Result<serde_json::Value, String> {
    let response = client()
        .get(format!("{vm_url}{path}"))
        .query(params)
        .send()
        .await
        .map_err(|err| format!("victoria metrics request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("victoria metrics returned {}", response.status()));
    }
    response
        .json()
        .await
        .map_err(|err| format!("invalid victoria metrics response: {err}"))
}
