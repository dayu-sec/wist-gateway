//! 低频率操作的**结构化生命周期日志**（与 `wist-gwlinkd::error::logged_op` 同一 idiom）。
//!
//! [`logged_op`] 用 orion-error 的 `AutoLogGuard` 包住一次操作：guard 在函数返回时 **drop**，
//! 恰好写一条生命周期日志 —— 成功 `suc!`（info）、失败 `fail!`（error，带 `fields` 与完整
//! `cause`）。因为它**成功也记**，只用于**低频率**操作；别包周期 tick，会刷屏。
//!
//! 与 gwlinkd 的差别：网关的下游错误多是 `String` / `StructError`，没有统一的领域 carrier，
//! 所以这里按 `E: Display` 收（日志取 `Display`），**不**把 context 附回错误（无 `OpLoggable`）。
//! 相应地，配合 [`crate::api::error::ApiError::handled`] 使用：**op 记链、边界只投影**，不重复记。

use orion_error::runtime::OperationContext;

/// 给一次**低频率**操作加结构化生命周期日志（成功 `suc!` / 失败 `fail!`）。
///
/// `mod_path` 传调用点的 `module_path!()`；`fields` 是结构化上下文（platform / url / agent_id …）。
/// 返回原 `Result`（`Ok` 透传、`Err` 透传），失败时把 `err`（折成单行）放进 `cause` 字段。
///
/// 失败已由本函数记过，边界请用 [`crate::api::error::ApiError::handled`] 投影，**不要**再用
/// `ApiError::internal*`（那会重复记一条）。
pub fn logged_op<T, E: std::fmt::Display>(
    mod_path: &str,
    action: &str,
    fields: &[(&str, String)],
    result: Result<T, E>,
) -> Result<T, E> {
    // 纯数据装配字段后武装成 guard（默认失败）：不 `mark_success` 就记 `fail!`。
    let mut guard = OperationContext::doing(action)
        .with_mod_path(mod_path)
        .with_auto_log();
    for (key, value) in fields {
        guard = guard.with_field(*key, value.clone());
    }

    match result {
        Ok(value) => {
            guard.mark_success(); // guard 于函数返回时 drop → `suc!`
            Ok(value)
        }
        Err(err) => {
            // 单行化：多层 source 会把一行日志撑成多行，破坏按行 grep。
            guard = guard.with_field("cause", one_line(&err.to_string()));
            drop(guard); // 在**失败点**立即 drop → `fail!`（含链路）
            Err(err)
        }
    }
}

/// 把可能多行的文本折成单行（供日志）。
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logged_op_passes_success_through() {
        let value = logged_op("m", "op", &[("k", "v".to_string())], Ok::<_, String>(7));
        assert_eq!(value.expect("ok"), 7);
    }

    #[test]
    fn logged_op_passes_failure_through_unchanged() {
        let err = logged_op::<(), _>("m", "op", &[], Err("boom".to_string())).unwrap_err();
        assert_eq!(err, "boom");
    }
}
