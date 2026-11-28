//! 证据服务的流记录写端点客户端（`POST /internal/flows`）。
//!
//! 为什么是网关转发而不是数据面直投：客户标识不能出现在数据面（一条 sink 配置服务所有客户），
//! 而**网关知道 agent → tenant 的绑定**（`store.get_agent().tenant_id`）。所以数据面把记录
//! 交给网关，网关补上 `cust_id` 再转给证据服务。见
//! `wist-design/doc/design/center/agent-flow-storage.md` §2/§4。
//!
//! 三条纪律：
//!
//! - **超时必须封顶**：这条路径在数据面 sink 的请求里，卡住就等于让 wparse 的重试队列堆积；
//! - **错误带状态码但不带内网细节**：上游要能区分"对面 4xx（别重试）"与"5xx（可以重试）"；
//! - **客户端进程级复用**：连接池比每次 new 一个 Client 值钱（一拍最多一次批量写）。

use std::sync::OnceLock;
use std::time::Duration;

use serde_json::json;
use wist_contracts::host_flow::HostFlowRecord;

/// 单次转发的超时。证据服务的写入是批量 upsert（一拍一次），5s 足够；
/// 超过就让它失败、让数据面落 rescue，而不是把网关的请求队列占住。
const EVIDENCE_FLOWS_TIMEOUT: Duration = Duration::from_secs(5);

/// 错误正文最多回显多少字节（只用于日志与响应里的 detail，不回内网结构）。
const MAX_ERROR_BODY: usize = 512;

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(EVIDENCE_FLOWS_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// 转发一批记录给某个客户。`Err` 里是**给人看的一句话**（含状态码），
/// 调用方负责把它放进 `failures[]` 并决定响应码。
pub async fn post_flows(
    url: &str,
    cust_id: &str,
    records: &[HostFlowRecord],
) -> Result<(), String> {
    // 正文是契约对象的规范序列化：网关已经按 `deny_unknown_fields` 解析过一遍，
    // 这里重新序列化等于顺手把"上游多塞的字段"抹掉 —— 证据服务那边的形状就只有一种。
    let body = json!({ "cust_id": cust_id, "records": records });
    let response = client()
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("evidence unreachable: {err}"))?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }

    let text = response.text().await.unwrap_or_default();
    let detail = text.chars().take(MAX_ERROR_BODY).collect::<String>();
    Err(format!(
        "evidence rejected the batch with HTTP {status}: {detail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// URL 写错（非 http/https）在这里就该失败 —— 而不是等到第一帧流记录进来才发现。
    #[tokio::test]
    async fn an_unreachable_endpoint_reports_the_reason() {
        let err = post_flows("http://127.0.0.1:9/internal/flows", "c-001", &[])
            .await
            .expect_err("no listener on port 9");
        assert!(err.contains("unreachable"), "{err}");
    }
}
