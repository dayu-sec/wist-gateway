//! 拒绝名单的 **GC**（后台 tick）。
//!
//! 条目只活到「被吊销的那张证书自然过期」为止（§5.6）—— 到点就该清掉。过了水位的条目虽然
//! 已经**不再拦人**、也不再出现在列表里（见 `Store::is_agent_revoked` / `list_agent_revocations`），
//! 但行还留在表里；不按时清，表会随时间无限增长。
//!
//! 为什么不只在启动时扫一次：网关会连续运行数周/数月，期间没有任何重启，启动扫就永不发生。
//! 所以让它自己走一个 tick —— 与 `work_expiry` 同一模式。

use std::sync::Arc;
use std::time::Duration;

use crate::infra::Store;

/// 扫描周期。
///
/// 水位是**天**级的（证书有效期），小时级扫一次绰绰有余；扫的是小表（每客户 10²–10³ 量级，
/// 且条目本身就在被清），完全便宜。
pub const REVOCATION_GC_TICK: Duration = Duration::from_secs(60 * 60);

/// 起一个后台 tick。`main` 只调这一行，免得把循环写进生成文件里。
///
/// 首轮立即跑一次（`interval` 的第一次 tick 立即到点）：网关自己停摆期间到期的条目，
/// 也在这里被收敛掉，而不是一直留在表里。
pub fn spawn_revocation_gc_tick(store: Arc<dyn Store>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REVOCATION_GC_TICK);
        loop {
            ticker.tick().await;
            match store.purge_expired_agent_revocations().await {
                Ok(0) => {}
                Ok(removed) => log::info!("audit agent_revocation_gc removed={removed}"),
                Err(err) => log::warn!("agent revocation gc failed: {err}"),
            }
        }
    });
}
