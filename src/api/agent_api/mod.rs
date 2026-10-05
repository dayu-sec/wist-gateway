//! Agent 面（edge seam B：gateway ↔ agentd）的**版本化路由表**。
//!
//! 每个 API 版本一个子模块，导出该版本的 `routes()`（`(路径后缀, MethodRouter)` 列表）；
//! [`mount`] 把它们挂到 `/api/{version}/agent{suffix}`。**加 v2 = 新增 `v2` 子模块 + 往
//! [`VERSIONS`] 加一行**（版本并存约定见
//! `wist-design/doc/design/foundation/api-seam-inventory.md` §7）。
//!
//! 不在这里的：`/api/v1/agent/install/*`、`/api/v1/agent/packages/*`、`/api/v1/agent/initial-config`
//! 属**安装/bootstrap 面**（另一条 seam），仍由 `api/mod.rs` 直接挂。

use axum::{Router, routing::MethodRouter};

use super::ApiState;

pub mod v1;

pub struct AgentApiVersion {
    /// 版本号；路由前缀据它拼成 `/api/{version}/agent{suffix}`。
    pub version: &'static str,
    /// 该版本的 `(路径后缀, method-router)` 列表。
    pub routes: fn() -> Vec<(&'static str, MethodRouter<ApiState>)>,
}

/// 已上线的 agent 面版本。**加 v2 就加一行。**
pub const VERSIONS: &[AgentApiVersion] = &[AgentApiVersion {
    version: "v1",
    routes: v1::routes,
}];

/// 把 agent 面所有版本挂到 `router`。
pub fn mount(mut router: Router<ApiState>) -> Router<ApiState> {
    for version in VERSIONS {
        for (suffix, method_router) in (version.routes)() {
            let path = format!("/api/{}/agent{}", version.version, suffix);
            router = router.route(&path, method_router);
        }
    }
    router
}

#[cfg(test)]
mod tests {
    use super::VERSIONS;

    #[test]
    fn v1_is_wired_in_the_version_table() {
        assert_eq!(VERSIONS.len(), 1, "only v1 is live");
        assert_eq!(VERSIONS[0].version, "v1");

        let suffixes: Vec<&str> = (VERSIONS[0].routes)()
            .iter()
            .map(|(suffix, _)| *suffix)
            .collect();
        for expected in [
            "/enroll",
            "/status",
            "/credentials:renew",
            "/control-commands:poll",
            "/action-results",
            "/discovery-policies:poll",
            "/work:poll",
            "/uplink:poll",
            "/work:ack",
            "/work:result",
        ] {
            assert!(
                suffixes.contains(&expected),
                "missing {expected}: {suffixes:?}"
            );
        }
    }

    /// agent_api 的 v1 + `/enroll` 必须与 seam 标记（模型接口）声明的路由一致 ——
    /// 防止“表里改了版本/路径，标记没跟上”的漂移。
    #[test]
    fn v1_enroll_route_matches_the_seam_marker() {
        let (method, path) = crate::api::WistAgentdOnlineRegistrationInterface::route();
        assert_eq!(method, "POST");
        assert_eq!(path, format!("/api/{}/agent/enroll", VERSIONS[0].version));
    }
}
