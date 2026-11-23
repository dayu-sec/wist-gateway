//! `wist-approve` 的库部分：密码学、摘要重算、计划渲染、网关客户端。
//!
//! 刻意抽成 lib 而不是全塞 `main.rs`：将来它要变成**客户侧签名服务**（见
//! `docs/design/plan-external-signing.md` §12），那时服务与 CLI 必须共用同一套
//! 「重算摘要 + 渲染 + 签名」的实现 —— 两份实现一定会漂，而这里漂的后果是
//! 「签的东西」和「机器验的东西」不是一回事。

pub mod client;
pub mod render;
pub mod signing;

pub use client::{GatewayClient, GatewayError, SigningPayload};
pub use render::{PlanSummary, render_summary};
pub use signing::ApproverKey;
