//! 把「发布版本」和「目标平台」编进二进制，供 `wist-approve --version` 打印。
//!
//! 为什么不在 `Cargo.toml` 里维护版本：CLI 与网关**同仓同批发布**，但它不是网关的一部分，
//! 让它的版本号跟着网关的 `#@gxl:set(version)` 一起被 `gx adm v_*` 改写是在两处维护同一个事实。
//! 这里改成「发布流水线把 tag 传进来」（`WIST_APPROVE_VERSION`），本地构建则退回 crate 版本。
//!
//! 现场为什么需要这个：审批人是客户的人，报障时第一句话就是「你装的哪个版本」。之前它恒定
//! 打印 `0.1.0`，与 Release tag（`v0.57.0-alpha`）对不上 —— 等于没有版本信息。

fn main() {
    let version = std::env::var("WIST_APPROVE_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    // `TARGET` 是 cargo 给 build script 的目标三元组（含 musl / darwin 差异）。
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());

    println!("cargo:rustc-env=WIST_APPROVE_VERSION={version}");
    println!("cargo:rustc-env=WIST_APPROVE_TARGET={target}");
    // 传了/没传这个变量要触发重编，否则同一个 target 目录里换 tag 会继续用旧字符串。
    println!("cargo:rerun-if-env-changed=WIST_APPROVE_VERSION");
}
