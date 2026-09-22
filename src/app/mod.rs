// @jumo generated
// @jumo hash=40af1338bd7dce38

pub mod global_service;
pub use global_service::*;

// NOTE(hand-added): 用途推断（按规则表从事实摘要算建议）。对应 jumo 模型
// Control.Agent.Purpose 的 IngestAgentFactSummaryFlow 里那一步 InferPurpose；
// 规则表是策展数据，只读不内嵌。重新生成控制面代码时需回补本模块。
pub mod purpose;

// NOTE(hand-added): 发现方向策略表（策展数据）。网关装载并校验后通过控制面下发给
// agentd；与 purpose 同类 —— 模型留结构、值留 content/。重新生成控制面代码时需回补本模块。
pub mod discovery_policy;

// NOTE(hand-added): L1a 机械资产清单（从事实摘要派生，见 doc/design/center/
// agent-work-delivery-plan.md §8.2）。只做机械归并，不做识别（识别在采集侧）。
// 重新生成控制面代码时需回补本模块。
pub mod inventory;
