//! 管理面 API 的错误投影（设计 `foundation/error-handling-system.md` §6）。
//!
//! 跨进程的 **wire 类型**（`ProtocolError` / `Severity` / `ProtocolErrorEnvelope`）住在
//! [`wist_shared::protocol`]，与 control / agentd 共用同一份，不在这里重复定义；本模块只放
//! **axum 侧**的 [`ApiError`]（`IntoResponse` 投影为 `(status, headers, { "error": { … } })`）。
//!
//! 安全约束（§6.1 / §9）：`detail` / source error / backtrace **不**进响应体（故投影里刻意**没有**
//! `detail` 字段）；完整因果链只进本地日志（[`ApiError::internal`] 会打 `log::error!`），由
//! `RUST_LOG` 控制。`code` 是稳定字符串码（由 reason identity 映射而来，§6.3）。

use axum::{
    Json,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
/// 重新导出共享的 wire 类型，方便 `api::error::ProtocolError` 等路径沿用。
pub use wist_shared::protocol::{ProtocolError, ProtocolErrorEnvelope, Severity};

/// 管理面 handler 的结构化错误；`IntoResponse` 投影为 `(status, headers, { "error": { … } })`。
#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: ProtocolError,
    /// 是否已经因内部错误记过日志 —— 避免 `into_response` 的 5xx 兜底重复记。
    logged: bool,
}

impl ApiError {
    /// 用一个稳定 `code` + 可暴露 `message` 构造。
    ///
    /// `severity` / `retryable` 由 `status` 推出默认值（见 [`default_severity`] /
    /// [`default_retryable`]），需要时可再用 [`ApiError::with_severity`] /
    /// [`ApiError::with_retryable`] 覆盖。
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        let mut body = ProtocolError::new(code, message);
        body.severity = Some(default_severity(status));
        body.retryable = default_retryable(status);
        Self {
            status,
            headers: Vec::new(),
            body,
            logged: false,
        }
    }

    /// 记一条单行的内部错误日志（`RUST_LOG` 可控），并标记「已记」。
    fn log_internal(&mut self, cause: impl std::fmt::Display) {
        // 折成单行：cause 可能带换行（多层 source chain），多行日志会破坏按行 grep 的口径。
        let cause = one_line(&cause.to_string());
        // 级别按状态定：4xx 也可能是 `internal_with(status, …)`（带内部 cause，如 CSR 非法）——
        // 那是客户端错误，该记 `warn`，不该按 `error` 淹没真正的服务端故障。
        if self.status.is_server_error() {
            log::error!(
                "api error: status={} code={} message={:?} cause={}",
                self.status.as_u16(),
                self.body.code,
                self.body.message,
                cause,
            );
        } else {
            log::warn!(
                "api error: status={} code={} message={:?} cause={}",
                self.status.as_u16(),
                self.body.code,
                self.body.message,
                cause,
            );
        }
        self.logged = true;
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    // ── 语义化构造器（4xx/5xx 常用档），避免各处重复写 `StatusCode::…` ──────────────

    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    pub fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn unprocessable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    pub fn unavailable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }

    pub fn bad_gateway(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, code, message)
    }

    /// 内部错误投影（500）：`cause` 只进本地日志（`RUST_LOG` 可控），对外仍只出 `code` + `message`。
    ///
    /// **`cause` 请传结构化错误的 `display_chain()`**（完整因果链）—— 直接传 `err`（`Display`）
    /// 只会得到不含 source 的一行；`message` 应是**可暴露**的短文本。
    pub fn internal(
        code: impl Into<String>,
        message: impl Into<String>,
        cause: impl std::fmt::Display,
    ) -> Self {
        Self::internal_with(StatusCode::INTERNAL_SERVER_ERROR, code, message, cause)
    }

    /// 带自定义 status 的内部错误投影（如 502）。
    pub fn internal_with(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
        cause: impl std::fmt::Display,
    ) -> Self {
        let mut error = Self::new(status, code, message);
        error.log_internal(cause);
        error
    }

    /// 用于**已在别处记过日志**（如 [`crate::error::logged_op`]）的错误：只投影，**不再记**，
    /// 也不触发 `into_response` 的 5xx 兜底（否则同一故障会记两条）。
    pub fn handled(
        status: StatusCode,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let mut error = Self::new(status, code, message);
        error.logged = true;
        error
    }

    pub fn code(&self) -> &str {
        &self.body.code
    }

    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.body.retryable = Some(retryable);
        self
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.body.severity = Some(severity);
        self
    }

    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.body.correlation_id = Some(id.into());
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.body
            .fields
            .get_or_insert_with(Default::default)
            .insert(key.into(), value.into());
        self
    }

    /// 追加一个响应头。错误响应同样可能带头（如凭据 / 配置类必须 `no-store`）。
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// 凭据 / 配置 / 一次性响应不应被缓存（对齐 `install.rs` 既有的 `Cache-Control: no-store`）。
    pub fn with_no_store(self) -> Self {
        self.with_header(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(mut self) -> Response {
        // 5xx 兜底：没经 `internal` 记过的服务端错误也留痕（否则会静默）。
        if !self.logged && self.status.is_server_error() {
            self.log_internal(format!("{} (no explicit cause)", self.body.message));
        }
        let mut response =
            (self.status, Json(ProtocolErrorEnvelope::new(self.body))).into_response();
        for (name, value) in self.headers {
            response.headers_mut().insert(name, value);
        }
        response
    }
}

/// 把可能多行的文本折成单行（供日志）。
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 默认严重度：服务端错误记 `error`，其余（客户端错误）记 `warning`。
fn default_severity(status: StatusCode) -> Severity {
    if status.is_server_error() {
        Severity::Error
    } else {
        Severity::Warning
    }
}

/// 默认可重试性：
/// - `429` / `502` / `503` / `504` 是**瞬时**故障，接收方可以重试 → `true`；
/// - 其余 `4xx` 是**永久**错误（要改请求）→ `false`；
/// - 其余 `5xx`（如 `500`）重试性**未知**，不臆断 → `None`（调用点可用
///   [`ApiError::with_retryable`] 明确）。
fn default_retryable(status: StatusCode) -> Option<bool> {
    match status.as_u16() {
        429 | 502 | 503 | 504 => Some(true),
        400..=499 => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::codes;

    /// 简单错误在线上**只**出 `code` + `message`（选填字段省略）。
    #[test]
    fn simple_error_serializes_to_code_and_message_only() {
        let envelope =
            ProtocolErrorEnvelope::new(ProtocolError::new("package_not_found", "没有这个包"));
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"error": {"code": "package_not_found", "message": "没有这个包"}})
        );
    }

    /// 选填字段只在设置后出现，且不改契约（additive）。
    #[test]
    fn optional_fields_appear_only_when_set() {
        let err = ApiError::new(StatusCode::CONFLICT, codes::AGENT_ONLINE, "agent 在线")
            .with_retryable(false)
            .with_severity(Severity::Warning)
            .with_field("agent_id", "a-1");
        let value = serde_json::to_value(ProtocolErrorEnvelope::new(err.body)).unwrap();
        assert_eq!(value["error"]["retryable"], serde_json::json!(false));
        assert_eq!(value["error"]["severity"], serde_json::json!("warning"));
        assert_eq!(value["error"]["fields"]["agent_id"], "a-1");
        assert!(value["error"].get("correlation_id").is_none());
    }

    /// 错误响应也能带响应头（凭据 / 配置类必须 `no-store`）。
    #[test]
    fn no_store_header_is_recorded() {
        let err = ApiError::new(StatusCode::UNAUTHORIZED, codes::INVALID_TOKEN, "bad token")
            .with_no_store();
        assert_eq!(err.headers.len(), 1);
        assert_eq!(err.headers[0].0, header::CACHE_CONTROL);
        assert_eq!(err.headers[0].1, "no-store");
    }

    #[test]
    fn severity_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(Severity::Warning).unwrap(),
            serde_json::json!("warning")
        );
    }

    /// 默认严重度 / 可重试性由 `status` 推出：瞬时故障可重试、客户端错误永久、其它 5xx 不臆断。
    #[test]
    fn severity_and_retryable_default_from_status() {
        let unavailable = ApiError::unavailable(codes::AGENT_STORE_UNAVAILABLE, "down");
        let value = serde_json::to_value(ProtocolErrorEnvelope::new(unavailable.body)).unwrap();
        assert_eq!(value["error"]["severity"], serde_json::json!("error"));
        assert_eq!(value["error"]["retryable"], serde_json::json!(true));

        let bad_request = ApiError::bad_request(codes::MISSING_PLATFORM, "no");
        let value = serde_json::to_value(ProtocolErrorEnvelope::new(bad_request.body)).unwrap();
        assert_eq!(value["error"]["severity"], serde_json::json!("warning"));
        assert_eq!(value["error"]["retryable"], serde_json::json!(false));

        // 普通 500：严重度是 `error`，但重试性未知 —— 不出该字段（不臆断）。
        let internal = ApiError::internal(codes::LOG_INGEST_APPEND_FAILED, "x", "cause");
        let value = serde_json::to_value(ProtocolErrorEnvelope::new(internal.body)).unwrap();
        assert_eq!(value["error"]["severity"], serde_json::json!("error"));
        assert!(value["error"].get("retryable").is_none());
    }

    /// `internal` 的 `cause` 只进日志，**不**出现在线上正文（安全约束 §6.1 / §9）。
    #[test]
    fn internal_keeps_cause_out_of_the_wire_body() {
        let secret = "/var/lib/wist/state.sqlite is locked";
        let err = ApiError::internal(codes::AGENT_STORE_UNAVAILABLE, "store unavailable", secret);
        let value = serde_json::to_value(ProtocolErrorEnvelope::new(err.body)).unwrap();
        let rendered = value.to_string();
        assert!(
            !rendered.contains("state.sqlite"),
            "cause leaked: {rendered}"
        );
        assert_eq!(value["error"]["code"], "agent_store_unavailable");
        assert_eq!(value["error"]["message"], "store unavailable");
    }

    /// `IntoResponse` 必须把构造时挂的响应头真正写进响应（如 `no-store`）。
    #[test]
    fn into_response_emits_recorded_headers() {
        let response = ApiError::unauthorized(codes::INVALID_TOKEN, "bad token")
            .with_no_store()
            .into_response();
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }
}
