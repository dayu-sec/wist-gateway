// @jumo generated
// @jumo hash=764a69fcf1d71142

pub mod api;
pub mod app;
pub mod infra;

// NOTE(hand-added): 测试期定位跨仓数据（策展知识 `wist-knowledge`、模型仓 `wist-design`）。
// 重新生成控制面代码时需回补本模块。
#[cfg(test)]
mod test_support;

pub use wist_control::*;

pub type AppError = wist_error::AppError;
