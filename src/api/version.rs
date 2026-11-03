//! 网关版本端点（**公开、无鉴权**）。
//!
//! 为什么单开一条公开路由：页面的左下角要一直显示「前端 + 后端 + 栈」三个版本号，其中后端
//! 版本在**还没填 admin token 时**也该可见（运维一进来先想确认「我连的这个网关是哪版」）。
//! 挂到管理面 bearer 之后就答不出来了，所以这条不参与任何鉴权。
//!
//! 两个版本号的口径刻意不同：
//!
//! * `version` 取编译期烧入的 `CARGO_PKG_VERSION` —— 是「这个二进制是哪版」，与发布制品一致；
//! * `stack_version` 取运行期读到的 **stack 的 `version.txt`** —— 是「这套部署是哪版」。网关镜像
//!   与 stack 分开发版（`v0.18.0-alpha` vs `v0.1.49-alpha`），二进制自己不可能知道这一点，
//!   所以由 stack 把 `version.txt` 只读挂进容器（默认 `/config/stack-version.txt`），或直接给
//!   `WIST_GATEWAY_STACK_VERSION`。
//!
//! 读不到就**不返回该字段**（而不是编一个值）：前端据此显示 `—`。旧网关没有这个字段，新前端
//! 必须仍然能工作 —— 这是加字段而不改 `version` 形状的原因。
//!
//! 手工扩展说明：本模块与其路由**不在** jumo 静态模型的 `jumo/model/static/control/binding.mju`
//! 声明里 —— 与 `api/pipeline.rs` / `api/host_metrics.rs` 同一模式（模型里也没有这类运维读数）。
//! 若之后重新生成控制面代码，需要手动回补本模块与下方路由。

use std::path::Path;

use axum::Json;
use serde::Serialize;

/// 直接给全栈版本的环境变量（优先于文件）。
const STACK_VERSION_ENV: &str = "WIST_GATEWAY_STACK_VERSION";
/// 指定全栈版本文件路径的环境变量。
const STACK_VERSION_FILE_ENV: &str = "WIST_GATEWAY_STACK_VERSION_FILE";
/// 默认挂载点：stack 的 `version.txt` 由 compose 只读挂到这里。
const DEFAULT_STACK_VERSION_FILE: &str = "/config/stack-version.txt";

/// 版本响应体（`GET /api/v1/version`）：`version` 必有，`stack_version` 可省。
#[derive(Debug, Serialize)]
pub struct GatewayVersion {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_version: Option<String>,
}

/// `GET /api/v1/version`：公开、无鉴权，返回网关（后端）版本与部署的全栈版本。
pub async fn gateway_version() -> Json<GatewayVersion> {
    Json(GatewayVersion {
        version: env!("CARGO_PKG_VERSION").to_string(),
        stack_version: stack_version(),
    })
}

/// 运行期解析全栈版本：环境变量优先，其次读文件；空串一律当「没有」。
fn stack_version() -> Option<String> {
    let env_value = std::env::var(STACK_VERSION_ENV).ok();
    let path = std::env::var(STACK_VERSION_FILE_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_STACK_VERSION_FILE.to_string());
    let file_value = std::fs::read_to_string(Path::new(path.trim())).ok();
    resolve_stack_version(env_value.as_deref(), file_value.as_deref())
}

/// 纯函数形式的取值规则（便于测试）：先环境变量、后文件；trim 后为空则跳过。
fn resolve_stack_version(env_value: Option<&str>, file_value: Option<&str>) -> Option<String> {
    [env_value, file_value]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_version_prefers_the_explicit_environment_value() {
        assert_eq!(
            resolve_stack_version(Some(" 0.2.0 \n"), Some("0.1.49")),
            Some("0.2.0".to_string())
        );
    }

    #[test]
    fn stack_version_falls_back_to_the_file() {
        assert_eq!(
            resolve_stack_version(None, Some("0.1.49\n")),
            Some("0.1.49".to_string())
        );
    }

    #[test]
    fn stack_version_treats_blank_sources_as_absent() {
        assert_eq!(resolve_stack_version(Some("  "), Some("\n")), None);
        assert_eq!(resolve_stack_version(None, None), None);
    }
}
