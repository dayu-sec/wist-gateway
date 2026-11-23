//! 网关管理面客户端（只用审批相关的四个端点）。
//!
//! 刻意**不**复用网关的 HTTP 栈：CLI 装在审批人的机器上，不该为了一个 POST 把
//! 整个网关依赖树拖过去。这里只依赖 `reqwest` + `wist-contracts`。
//!
//! 凭据是 **approver scope** 的 token（见设计 §12.4）；V1 暂时沿用 admin token，
//! 发布说明里必须标成「临时缺口」。

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 网关返回的错误（`{ "error": { "code", "detail" } }`）或传输层失败。
#[derive(Debug)]
pub struct GatewayError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for GatewayError {}

impl GatewayError {
    fn transport(message: impl Into<String>) -> Self {
        Self {
            code: "transport_error".to_string(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalSummary {
    pub approval_id: String,
    pub agent_id: String,
    pub plan_digest: String,
    pub risk_level: String,
    pub requested_by: String,
    pub requested_at: String,
    pub expires_at: String,
    pub required_approvers: i64,
    pub status: String,
    pub approved_at: Option<String>,
    pub issued: bool,
}

/// `/signing-payload` 的响应：只有**事实**，没有 key_id / issued_by（那些属于签名方）。
#[derive(Debug, Clone, Deserialize)]
pub struct SigningPayload {
    pub approval_id: String,
    pub agent_id: String,
    pub plan_digest: String,
    pub risk_level: String,
    pub approvers: Vec<String>,
    pub required_approvers: u8,
    pub approved_at: Option<String>,
    pub plan: Value,
    pub plan_expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssueResult {
    pub dispatched_command_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct VoteBody<'a> {
    decision: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
}

pub struct GatewayClient {
    base: String,
    token: String,
    http: reqwest::blocking::Client,
}

impl GatewayClient {
    /// `base` 形如 `https://127.0.0.1`（不带尾斜杠）。
    pub fn new(
        base: &str,
        token: &str,
        ca_file: Option<&Path>,
        insecure: bool,
    ) -> Result<Self, GatewayError> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("wist-approve/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = ca_file {
            let pem = std::fs::read(path).map_err(|err| {
                GatewayError::transport(format!("--ca-file {}: {err}", path.display()))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|err| {
                GatewayError::transport(format!("--ca-file is not a PEM cert: {err}"))
            })?;
            builder = builder.add_root_certificate(cert);
        }
        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder.build().map_err(|err| {
            GatewayError::transport(format!("failed to build HTTP client: {err}"))
        })?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http,
        })
    }

    pub fn list(&self, agent_id: Option<&str>) -> Result<Vec<ApprovalSummary>, GatewayError> {
        let path = match agent_id {
            Some(agent_id) => format!("/api/v1/admin/approvals?agent_id={agent_id}"),
            None => "/api/v1/admin/approvals".to_string(),
        };
        self.get_json(&path)
    }

    pub fn approval(&self, approval_id: &str) -> Result<Value, GatewayError> {
        self.get_json(&format!("/api/v1/admin/approvals/{approval_id}"))
    }

    pub fn signing_payload(&self, approval_id: &str) -> Result<SigningPayload, GatewayError> {
        self.get_json(&format!(
            "/api/v1/admin/approvals/{approval_id}/signing-payload"
        ))
    }

    pub fn vote(
        &self,
        approval_id: &str,
        decision: &str,
        comment: Option<&str>,
    ) -> Result<Value, GatewayError> {
        self.post_json(
            &format!("/api/v1/admin/approvals/{approval_id}/votes"),
            &VoteBody { decision, comment },
        )
    }

    pub fn issue(
        &self,
        approval_id: &str,
        attestation: &wist_contracts::action_plan::ActionPlanAttestation,
    ) -> Result<IssueResult, GatewayError> {
        let body = serde_json::json!({ "attestation": attestation });
        self.post_json(
            &format!("/api/v1/admin/approvals/{approval_id}/issue"),
            &body,
        )
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, GatewayError> {
        let response = self
            .http
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .send()
            .map_err(|err| GatewayError::transport(format!("GET {path}: {err}")))?;
        Self::decode(path, response)
    }

    fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, GatewayError> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .map_err(|err| GatewayError::transport(format!("POST {path}: {err}")))?;
        Self::decode(path, response)
    }

    fn decode<T: for<'de> Deserialize<'de>>(
        path: &str,
        response: reqwest::blocking::Response,
    ) -> Result<T, GatewayError> {
        let status = response.status();
        let text = response.text().map_err(|err| {
            GatewayError::transport(format!("{path}: failed to read body: {err}"))
        })?;
        if !status.is_success() {
            let (code, detail) = parse_error(&text);
            return Err(GatewayError {
                code,
                message: format!("HTTP {} — {detail}", status.as_u16()),
            });
        }
        serde_json::from_str(&text).map_err(|err| GatewayError {
            code: "bad_response".to_string(),
            message: format!("{path}: response does not match the contract: {err}"),
        })
    }
}

/// 从 `{ "error": { "code", "detail" } }` 里取 code/detail；取不到就原样带上文本。
fn parse_error(text: &str) -> (String, String) {
    if let Ok(value) = serde_json::from_str::<Value>(text)
        && let Some(error) = value.get("error")
    {
        let code = error
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("unknown_error")
            .to_string();
        let detail = error
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !detail.is_empty() {
            return (code, detail);
        }
        return (code.clone(), code);
    }
    (
        "unknown_error".to_string(),
        text.chars().take(300).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_gateway_error_envelope() {
        let (code, detail) =
            parse_error(r#"{"error":{"code":"plan_digest_mismatch","detail":"plan changed"}}"#);
        assert_eq!(code, "plan_digest_mismatch");
        assert_eq!(detail, "plan changed");
    }

    #[test]
    fn falls_back_to_raw_text_for_non_json_errors() {
        let (code, detail) = parse_error("502 Bad Gateway");
        assert_eq!(code, "unknown_error");
        assert!(detail.contains("502"));
    }
}
