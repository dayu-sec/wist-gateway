//! VictoriaMetrics HTTP 访问助手（控制面读写 VM）。
//!
//! 数据面（warp-parse）经 `vm_metrics_sink` 以 NDJSON POST 到 `/api/v1/import` 写入主机/进程指标；
//! 这里提供控制面（wist-gateway）同构的读写入口：`query_json` 走 PromQL 查询、`import_lines`
//! 走 `/api/v1/import`（NDJSON + `application/json`），使 agent 自身上报的状态指标也统一进 VM。

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

/// POST 一组 VM JSON line（NDJSON）到 `/api/v1/import`。
pub async fn import_lines(vm_url: &str, lines: &[serde_json::Value]) -> Result<(), String> {
    if lines.is_empty() {
        return Ok(());
    }
    let body = lines
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let response = client()
        .post(format!("{vm_url}/api/v1/import"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|err| format!("victoria metrics import failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "victoria metrics import returned {}",
            response.status()
        ));
    }
    Ok(())
}

/// 构造一条 VM JSON line：`{"metric":{...},"values":[v],"timestamps":[ts_ms]}`。
pub fn metric_line(
    name: &str,
    agent_id: &str,
    kind: &str,
    value: f64,
    timestamp_ms: i64,
) -> serde_json::Value {
    serde_json::json!({
        "metric": {
            "__name__": name,
            "agent": agent_id,
            "kind": kind,
        },
        "values": [value],
        "timestamps": [timestamp_ms],
    })
}
