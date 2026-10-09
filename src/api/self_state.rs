// NOTE(hand-added): 网关自述面（环回；CR-003）。对应 jumo 模型 Control.GatewayApp.SelfInterface
// 的 `GatewaySelfInterface.QuerySelfState`。模型的 `bind` 未定（环回鉴权未决），故路由手加；
// 重新生成控制面代码时需回补本模块与下方路由。
//
// 用途：host 侧 **wist-gwlinkd** 拉取**进程内算得准**的网关状态，再上报 WistCenter —— 网关活着拿到准值，
// 网关不答则把「沉默」当判断（见 CR-003）。
//
// 字段用 **snake_case**（与中心侧 `wist-control` 契约、gwlinkd 的 DTO 一致；网关其余管理面 DTO 用
// camelCase，属历史分歧，本接口刻意跟随契约侧）。

use super::codes;
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock};
use sysinfo::{Disks, ProcessesToUpdate, System};
use wist_control::types::DateTime;

use crate::infra::AdminConfig;
use crate::infra::AgentQuery;

use super::error::ApiError;
use super::{ApiState, rate_limit};

#[derive(Debug, Deserialize)]
pub struct SelfStateQuery {
    /// 调用方自报的网关 id（网关侧未必自持该值；原样回显供调用方核对）。
    pub gateway_id: Option<String>,
}

/// 网关自述状态（对应模型 `GatewaySelfState`；snake_case，见文件头注）。
#[derive(Debug, Serialize, ::jumo_derive::Jumo)]
#[jumo(
    kind = "struct",
    domain = "Control",
    module = "Control.GatewayApp.SelfInterface"
)]
pub struct GatewaySelfState {
    pub gateway_id: String,
    pub version: String,
    /// 网关**对外基址**（对外域名）：管理面「对外地址」优先，未设回落 `[server] public_base_url`。
    /// 供 host 侧 gwlinkd 上报中心（中心据此知道该网关对外域名）。
    pub public_base_url: String,
    pub collected_at: DateTime,
    pub store_healthy: bool,
    pub agent_count: i64,
    pub last_error: Option<String>,
    /// 网关**进程**已运行秒数（`sysinfo::Process::run_time`）。
    pub uptime_seconds: i64,
    /// 网关**进程** CPU 占比（单核口径，100% = 占满一核，可能 >100）；量不出时为 null。
    pub cpu_percent: Option<f64>,
    /// 网关**进程**常驻内存（字节，RSS）；量不出时为 null。
    pub memory_bytes: Option<u64>,
    /// 已登记 Agent 中**在线**的台数（`last_seen` 在在线窗口内）。
    pub online_agents: i64,
    /// 已登记但**离线**的台数（= `agent_count − online_agents`）。
    pub offline_agents: i64,
    /// 机队里最久没上报的那台的滞后秒数（0 = 都新鲜）。
    pub last_seen_lag_seconds: i64,
    /// 存储大小（字节；SQLite 文件大小，读不到 / 内存库为 0）。
    pub store_bytes: u64,
    /// 累计接收 / 拒收的数据面事实条数（自进程启动）。
    pub ingest_accepted_total: u64,
    pub ingest_rejected_total: u64,
    /// 最近一次接收事实的时刻（未接收过为 null）。
    pub last_ingest_at: Option<DateTime>,
    /// 主机（网关所在机器）内存总量（字节）。
    pub memory_total_bytes: Option<u64>,
    /// 主机 1 / 5 / 15 分钟负载。
    pub load_1m: Option<f64>,
    pub load_5m: Option<f64>,
    pub load_15m: Option<f64>,
    /// 主盘使用率（0..100）与总量 / 可用（字节，汇总所有挂载点，近似）。
    pub disk_usage_percent: Option<f64>,
    pub disk_total_bytes: Option<u64>,
    pub disk_available_bytes: Option<u64>,
}

pub async fn query_self_state(
    State(state): State<ApiState>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Query(params): Query<SelfStateQuery>,
) -> Response {
    // 自述面只面向**本机** host 侧常驻：非环回一律拒绝（模型里的 bind 一旦把它记成环回路由，这条手加
    // 的检查可与之合一）。
    if !client.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return ApiError::forbidden(
            codes::SELF_STATE_LOOPBACK_ONLY,
            "self-state is loopback-only",
        )
        .into_response();
    }
    let gateway_id = params.gateway_id.as_deref().unwrap_or("").trim();
    if gateway_id.is_empty() {
        return ApiError::bad_request(codes::SELF_STATE_MISSING_GATEWAY_ID, "missing gateway_id")
            .into_response();
    }
    Json(self_state(&state, gateway_id).await).into_response()
}

/// 管理面读取网关**自身**状态（页面用）：`GET /api/v1/admin/gateway/self-state`（admin bearer）。
///
/// 与环回自述面 [`query_self_state`] **同一份计算**，只是换成 admin 鉴权 —— 环回面只服务本机
/// gwlinkd，浏览器够不到；而页面又要看到「网关（容器）自己」的版本 / 健康（这正是 gwlinkd
/// 上报中心的那份值，与页面上的 gwlinkd 版本不是一回事）。
pub async fn admin_view_gateway_self_state(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Query(params): Query<SelfStateQuery>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = super::admin_auth::require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 网关未必自持 id（见 `SelfStateQuery.gateway_id`）—— 页面另有来源（linkd-status），
    // 这里原样回显调用方给的值（可缺省为空）。
    let gateway_id = params.gateway_id.as_deref().unwrap_or("").trim();
    Json(self_state(&state, gateway_id).await).into_response()
}

pub(super) async fn self_state(state: &ApiState, gateway_id: &str) -> GatewaySelfState {
    let mut last_error: Option<String> = None;

    // 存储健康 = 「能不能查」；同时一次性拿到机队，供 agent_count / 在线 / 滞后。
    let (store_healthy, agents) = match state.store.list_agents(&AgentQuery::default()).await {
        Ok(agents) => (true, agents),
        Err(err) => {
            last_error = Some(err.to_string());
            (false, Vec::new())
        }
    };
    let now = DateTime::now();
    let agent_count = agents.len() as i64;
    let online_agents = agents
        .iter()
        .filter(|agent| super::overview::agent_is_online(&agent.last_seen_at, &now))
        .count() as i64;
    // 最久没上报的那台的滞后秒数：机队「多旧」的一个信号（0 = 都新鲜）。
    let last_seen_lag_seconds = agents
        .iter()
        .filter_map(|agent| DateTime::from_rfc3339(&agent.last_seen_at))
        .map(|last_seen| last_seen.seconds_until(&now))
        .max()
        .unwrap_or(0);

    let process = process_metrics();
    let host = host_metrics();

    // 网关**对外基址**（对外域名）：本机才知道它（管理面「对外地址」优先，未设回落 `[server] public_base_url`），
    // 由 host 侧 gwlinkd 读自述面后随注册 / 状态上报转带给中心。
    let public_base_url =
        super::install::effective_advertise_base(&state.config, &state.store).await;

    // 数据面累计计数（进程内一份）；存储大小取 SQLite 文件大小。
    let store_bytes = store_file_bytes(&state.config);
    let (ingest_accepted_total, ingest_rejected_total, last_ingest_at) = {
        let runtime = state
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            runtime.ingest_accepted_total,
            runtime.ingest_rejected_total,
            runtime.last_ingest_at.clone(),
        )
    };

    GatewaySelfState {
        gateway_id: gateway_id.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        public_base_url,
        collected_at: now,
        store_healthy,
        agent_count,
        last_error,
        uptime_seconds: process.uptime_seconds,
        cpu_percent: process.cpu_percent,
        memory_bytes: process.memory_bytes,
        online_agents,
        offline_agents: agent_count - online_agents,
        last_seen_lag_seconds,
        store_bytes,
        ingest_accepted_total,
        ingest_rejected_total,
        last_ingest_at,
        memory_total_bytes: host.memory_total_bytes,
        load_1m: host.load_1m,
        load_5m: host.load_5m,
        load_15m: host.load_15m,
        disk_usage_percent: host.disk_usage_percent,
        disk_total_bytes: host.disk_total_bytes,
        disk_available_bytes: host.disk_available_bytes,
    }
}

/// 主机（网关所在机器）资源快照。
struct HostMetrics {
    memory_total_bytes: Option<u64>,
    load_1m: Option<f64>,
    load_5m: Option<f64>,
    load_15m: Option<f64>,
    disk_usage_percent: Option<f64>,
    disk_total_bytes: Option<u64>,
    disk_available_bytes: Option<u64>,
}

/// 读主机内存总量 / 负载 / 磁盘。磁盘汇总所有挂载点（容器里通常只有一处）；
/// 总量为 0 / 量不出时给 `None`，不假装 0。
fn host_metrics() -> HostMetrics {
    let mut system = System::new();
    system.refresh_memory();
    let load = System::load_average();

    let disks = Disks::new_with_refreshed_list();
    let disk_total: u64 = disks.list().iter().map(|disk| disk.total_space()).sum();
    let disk_available: u64 = disks.list().iter().map(|disk| disk.available_space()).sum();
    let (disk_total_bytes, disk_available_bytes, disk_usage_percent) = if disk_total > 0 {
        (
            Some(disk_total),
            Some(disk_available),
            Some((disk_total - disk_available) as f64 / disk_total as f64 * 100.0),
        )
    } else {
        (None, None, None)
    };

    HostMetrics {
        memory_total_bytes: Some(system.total_memory()),
        load_1m: Some(load.one),
        load_5m: Some(load.five),
        load_15m: Some(load.fifteen),
        disk_usage_percent,
        disk_total_bytes,
        disk_available_bytes,
    }
}

/// 存储文件大小（字节）：优先认数据源 URL 指向的 SQLite 文件，其次配置里的 `sqlite_path`；
/// 内存库 / 都读不到 → 0。
fn store_file_bytes(config: &AdminConfig) -> u64 {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(url) = &config.database_url
        && let Some(path) = url.strip_prefix("sqlite:")
    {
        let path = path.trim_start_matches("//");
        if !path.is_empty() && !path.contains(":memory:") {
            candidates.push(std::path::PathBuf::from(path));
        }
    }
    candidates.push(config.sqlite_path.clone());
    candidates
        .iter()
        .find_map(|path| std::fs::metadata(path).ok())
        .map(|meta| meta.len())
        .unwrap_or(0)
}

/// 网关**进程自身**的资源快照。
struct ProcessMetrics {
    uptime_seconds: i64,
    cpu_percent: Option<f64>,
    memory_bytes: Option<u64>,
}

/// 读网关进程的 CPU / 内存 / 运行时长。
///
/// **持久** `System`（静态单例）：`sysinfo` 的 `cpu_usage()` 按「两次刷新之间的增量」算，
/// 同一个实例跨调用才量得准（首次调用给 0）；`memory()` 单次刷新即可。量不出（拿不到 pid）
/// 时返回 `None`，不假装 0。
fn process_metrics() -> ProcessMetrics {
    static SYS: OnceLock<Mutex<System>> = OnceLock::new();
    let Ok(pid) = sysinfo::get_current_pid() else {
        return ProcessMetrics {
            uptime_seconds: 0,
            cpu_percent: None,
            memory_bytes: None,
        };
    };
    let mut system = SYS
        .get_or_init(|| Mutex::new(System::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    match system.process(pid) {
        Some(process) => ProcessMetrics {
            uptime_seconds: process.run_time() as i64,
            cpu_percent: Some(process.cpu_usage() as f64),
            memory_bytes: Some(process.memory()),
        },
        None => ProcessMetrics {
            uptime_seconds: 0,
            cpu_percent: None,
            memory_bytes: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// 自述面 JSON 的**键集契约**（snake_case）。
    /// gwlinkd 侧有同一份 fixture 的**解析**测试（`parses_the_gateway_self_state_contract`）——
    /// 两侧同钉一份形状，任一侧改名即爆（防三份拷贝漂移）。
    #[test]
    fn serializes_the_self_state_contract_keys() {
        let state = GatewaySelfState {
            gateway_id: "gw-1".into(),
            version: "0.1.15".into(),
            public_base_url: "https://gw.example.com".into(),
            collected_at: DateTime::now(),
            store_healthy: true,
            agent_count: 3,
            last_error: None,
            uptime_seconds: 3600,
            cpu_percent: Some(1.5),
            memory_bytes: Some(1024),
            online_agents: 2,
            offline_agents: 1,
            last_seen_lag_seconds: 30,
            store_bytes: 4096,
            ingest_accepted_total: 10,
            ingest_rejected_total: 1,
            last_ingest_at: None,
            memory_total_bytes: Some(1024),
            load_1m: Some(0.5),
            load_5m: Some(0.4),
            load_15m: Some(0.3),
            disk_usage_percent: Some(50.0),
            disk_total_bytes: Some(100),
            disk_available_bytes: Some(50),
        };
        let value: Value = serde_json::to_value(&state).expect("serialize");
        let mut keys: Vec<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "agent_count",
                "collected_at",
                "cpu_percent",
                "disk_available_bytes",
                "disk_total_bytes",
                "disk_usage_percent",
                "gateway_id",
                "ingest_accepted_total",
                "ingest_rejected_total",
                "last_error",
                "last_ingest_at",
                "last_seen_lag_seconds",
                "load_15m",
                "load_1m",
                "load_5m",
                "memory_bytes",
                "memory_total_bytes",
                "offline_agents",
                "online_agents",
                "public_base_url",
                "store_bytes",
                "store_healthy",
                "uptime_seconds",
                "version"
            ]
        );
    }
}
