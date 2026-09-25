//! 一次性工作的**到期判定**（后台 tick）。
//!
//! 判定本身是纯函数（`app::work::overdue_terminal_status`），这里只做「扫库 → 判 → 落库」。
//!
//! 为什么不搭在 `work:poll` 上：`deadline_at` 是**工作**的属性，不是「agent 来问了」的属性 ——
//! agent 掉线时恰恰是这活最可能卡住的时候，那时就没有 poll 可搭。所以让它自己走一个 tick。

use std::sync::Arc;
use std::time::Duration;

use crate::app::work::overdue_terminal_status;
use crate::infra::Store;

/// 到期判定的扫描周期。
///
/// 分钟级即可：截止与预算的粒度都是分钟，晚判一分钟之内不影响处置，扫全表也很便宜
/// （未了结的一次性工作总量本来就小）。
pub const ONE_SHOT_EXPIRY_TICK: Duration = Duration::from_secs(60);

/// 起一个后台 tick。`main` 只调这一行，免得把循环写进生成文件里。
///
/// 首轮立即跑一次（`interval` 的第一次 tick 立即到点）：网关自己停摆期间到期的活，
/// 也在这里被收敛掉，而不是一直显示「执行中」。
pub fn spawn_one_shot_expiry_tick(store: Arc<dyn Store>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ONE_SHOT_EXPIRY_TICK);
        loop {
            ticker.tick().await;
            match expire_overdue_one_shot_works(store.as_ref(), now_ms()).await {
                Ok(0) => {}
                Ok(terminated) => eprintln!("event=OneShotExpirySweep terminated={terminated}"),
                Err(err) => eprintln!("one-shot expiry sweep failed: {err}"),
            }
        }
    });
}

/// 扫一遍所有未了结的一次性工作，把到期的推进终态，返回推进了几件。
///
/// 推进走的是**条件更新**（只改仍未了结的）：扫描与 agent 的结果上报会交错，
/// 不能让一次扫描把 agent 刚报进来的终态覆盖掉。
pub async fn expire_overdue_one_shot_works(
    store: &dyn Store,
    now_ms: i64,
) -> Result<usize, String> {
    let works = store
        .list_outstanding_one_shot_work()
        .await
        .map_err(|err| format!("list outstanding one-shot work: {err}"))?;
    let mut terminated = 0usize;
    for stored in works {
        let Some(status) = overdue_terminal_status(&stored.work, now_ms) else {
            continue;
        };
        let work_id = stored.work.work_id.clone();
        let agent_id = stored.work.agent_id.clone();
        match store
            .terminate_outstanding_one_shot_work(&work_id, status)
            .await
        {
            Ok(true) => {
                // 只记行日志，不落事件表：到期判定是**状态收敛**，不是「谁下了指令」那种要留审的动作；
                // 而成品（页面上那条终态）本身就可查。
                eprintln!(
                    "event=OneShotWorkOverdue work_id={work_id} agent_id={agent_id} status={status}"
                );
                terminated += 1;
            }
            // 已在扫描期间了结（agent 刚把结果报进来）：不动它 —— 那件活的终态比我们的判断新。
            Ok(false) => {}
            Err(err) => {
                // 单件失败不中断整轮：一件坏数据不该让别的活一直卡在「执行中」。
                eprintln!("event=OneShotExpirySaveFailed work_id={work_id} detail=\"{err}\"");
            }
        }
    }
    Ok(terminated)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
