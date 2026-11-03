//! 采集日志历史分卷的**周期清理**（后台 tick）。
//!
//! 轮转发生在**写入**时（见 [`crate::infra::agent_logs`]）；但网关可能长时间**空闲**
//! （Agent 都停了、没有新日志），那时没有 append 去触发轮转与清理，过期 / 超量的分卷就会一直
//! 占着盘。所以另起一个 tick，只按保留策略清**历史分卷**（不动当前卷 —— 不因定时器丢掉最近
//! 这一段窗口）。
//!
//! 与 `work_expiry` / `revocation_gc` / `self_state_history` 同一模式（自身 tick，不搭在任何
//! 请求路径上）。

use std::path::PathBuf;
use std::time::Duration;

use crate::infra::{AgentLogFile, LogRetention};

/// 清理周期。
///
/// 保留期是**天**级的，小时级扫一次绰绰有余；扫目录 + 少量 `unlink`，便宜。
pub const AGENT_LOG_PRUNE_TICK: Duration = Duration::from_secs(60 * 60);

/// 起一个后台 tick。
///
/// 首轮立即跑一次（`interval` 的第一次 tick 立即到点）：网关自己停摆期间积累的过期分卷，
/// 在重启后也会被立刻收敛，而不是等下一个整点。
pub fn spawn_agent_log_prune_tick(file: PathBuf, retention: LogRetention) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(AGENT_LOG_PRUNE_TICK);
        loop {
            ticker.tick().await;
            let file = file.clone();
            // 扫目录 + unlink 是**阻塞 IO**：丢到 blocking 池，别占着 async worker
            // （与写入路径同一取舍，见 `api/logs.rs` 的 APPEND_LOCK 注释）。
            let _ = tokio::task::spawn_blocking(move || {
                AgentLogFile::with_retention(file, retention).prune();
            })
            .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tick 周期是「天级保留期」的合理采样：不该比保留期本身还粗糙。
    #[test]
    fn prune_tick_is_sub_daily() {
        assert!(AGENT_LOG_PRUNE_TICK <= Duration::from_secs(6 * 60 * 60));
    }
}
