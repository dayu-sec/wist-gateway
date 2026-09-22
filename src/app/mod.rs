// @jumo generated
// @jumo hash=40af1338bd7dce38

pub mod global_service;
pub use global_service::*;

// NOTE(hand-added): 用途推断（按规则表从事实摘要算建议）。对应 jumo 模型
// Control.Agent.Purpose 的 IngestAgentFactSummaryFlow 里那一步 InferPurpose；
// 规则表是策展数据，只读不内嵌。重新生成控制面代码时需回补本模块。
pub mod purpose;
