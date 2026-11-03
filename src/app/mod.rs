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

// NOTE(hand-added): 知识库内容的装载与持有（采集目录三件套 + 用途规则 + 发现策略；
// 管理面登记生效包，运行时切换）。重生成控制面代码时需回补本模块。
pub mod knowledge;

// NOTE(hand-added): L1a 机械资产清单（从事实摘要派生，见 doc/design/center/
// agent-work-delivery-plan.md §8.2）。只做机械归并，不做识别（识别在采集侧）。
// 重新生成控制面代码时需回补本模块。
pub mod inventory;

// NOTE(hand-added): 采集内容目录（catalog / packs / templates）的装载、校验与
// 「按面展开」。对应模型 Control.Agent.Content；与 purpose/discovery_policy 同类，
// 值留 content/、只读不内嵌。重新生成控制面代码时需回补本模块。
pub mod content;

// NOTE(hand-added): 工作授权（模型 Control.Agent.Work）的校验与状态机：
// 面就绪度闸门、spec 由目录展开/逐条校验、暂停与恢复的边界。
// 重新生成控制面代码时需回补本模块。
pub mod work;

// NOTE(hand-added): 日志源定位的纯逻辑（路径规范化 / roots 判定 / 按实例展开）。
// 管理 API、目录装载期与派活物化三处共用一个口径 —— 它是安全边界，不允许各写一套。
// 重生成控制面代码时需回补本模块。
pub mod log_source;

// NOTE(hand-added): agentd 版本比较（知识库可声明「最低 agentd 版本」）。
// 只比不推：版本号回答不了“这一版在**这个环境**里真能不能采”（那是 logs_capabilities 的事），
// 但能回答“这台机器是不是旧到连该能力都没有”。重生成控制面代码时需回补本模块。
pub mod agent_version;

// NOTE(hand-added): 灰度发布计划（模型 Control.Rollout）的校验与物化：
// 推进闸门、target → OneShotWork 的物化、结果 → 条目的折算。与 Control.Agent.Work 分离，
// 物化时才落到一次性工作。重新生成控制面代码时需回补本模块。
pub mod rollout;
