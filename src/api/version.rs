//! 网关版本端点（**公开、无鉴权**）。
//!
//! 为什么单开一条公开路由：页面的左下角要一直显示「前端 + 后端」两个版本号，其中后端
//! 版本在**还没填 admin token 时**也该可见（运维一进来先想确认「我连的这个网关是哪版」）。
//! 挂到管理面 bearer 之后就答不出来了，所以这条不参与任何鉴权。
//!
//! 版本号取编译期烧入的 `CARGO_PKG_VERSION`：它与发布制品一致（是「这个二进制是哪版」，
//! 而不是「运行期读到了什么」）。
//!
//! 手工扩展说明：本模块与其路由**不在** jumo 静态模型的 `jumo/model/static/control/binding.mju`
//! 声明里 —— 与 `api/pipeline.rs` / `api/host_metrics.rs` 同一模式（模型里也没有这类运维读数）。
//! 若之后重新生成控制面代码，需要手动回补本模块与下方路由。

use axum::Json;
use serde::Serialize;

/// 版本响应体（`GET /api/v1/version`）：扁平、单字段，前端直接取 `version`。
#[derive(Debug, Serialize)]
pub struct GatewayVersion {
    pub version: String,
}

/// `GET /api/v1/version`：公开、无鉴权，返回网关（后端）版本。
pub async fn gateway_version() -> Json<GatewayVersion> {
    Json(GatewayVersion {
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
