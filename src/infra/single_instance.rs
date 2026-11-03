//! 单实例闸门：**一台机器（一个操作系统）上只允许一个 wist-gateway 在跑**。
//!
//! 为什么要有它：两个网关同时运行，轻则抢端口 / 同一件工作被派两次，重则**同一份 SQLite
//! 被两个进程双写** —— 那不是"多跑了一个实例"，而是把库写坏。2026-09-30 的开发机上真出现过：
//! 一个 dev 实例与一个发布态实例并存（两份 compose 项目名还相同），现场分不清是谁在应答、
//! 停的是哪一个。
//!
//! 为什么不用"端口被占用"当闸门：端口是可以配成不同的（`[server] listen_addr`），而且
//! 数据面 `[ingest]` 还能整个关掉 —— 端口冲突只是表象，拦不住真正的双写。
//!
//! 闸门本体是 `flock(LOCK_EX | LOCK_NB)`：**进程活着就持锁，进程一死（含 `kill -9`）
//! 内核自动释放**。这一点比 pidfile 强得多 —— pidfile 会把崩溃留成需要人清理的脏状态，
//! 而"看起来还在跑"正是我们最想消灭的那种错觉。
//!
//! 边界（诚实说明，不假装它管得比实际宽）：
//! - 锁文件在 `/tmp`，管的是**同一台机器上的裸进程**。容器有各自的 `/tmp`，所以容器之间
//!   那一层得靠 compose（固定 `container_name` / 固定宿主端口）兜，不是这里能解决的；
//! - 非 unix 目标（不在发布矩阵里：只发 linux-gnu ×2 与 apple-darwin）不提供锁 ——
//!   那是**已知缺口**，不是"刚好也行"。
//!
//! `WIST_GATEWAY_LOCK_FILE` 可覆盖锁文件路径：那是**故意的逃生口**（同一台机器上有意并行
//! 两套时用）。默认值不提供任何"自动让路" —— 让路意味着两个实例真的同时跑起来了。

use std::{
    env,
    ffi::OsString,
    fs::{File, OpenOptions},
    io,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// 默认锁文件。
///
/// **不能用 `env::temp_dir()`**：macOS 的 `TMPDIR` 是**按用户**的，用它等于把"一个 OS 一个
/// 实例"悄悄降级成"一个用户一个实例"。`/tmp` 才是按机器共享的那个目录。
const DEFAULT_LOCK_FILE: &str = "/tmp/wist-gateway.lock";
/// 覆盖锁文件路径的环境变量（逃生口，见模块头）。
const ENV_LOCK_FILE: &str = "WIST_GATEWAY_LOCK_FILE";

/// 单实例锁的持有句柄：**活到进程结束即持锁**，无需显式释放，也不能提前 drop。
#[derive(Debug)]
pub struct InstanceLock {
    /// 持锁的那个 fd。字段本身不读，它的存在就是锁 —— 所以带下划线前缀防 unused 告警。
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// 按默认（或 `WIST_GATEWAY_LOCK_FILE` 覆盖的）路径占位。
    ///
    /// 失败回的是**给人看的**一句话：谁的锁、怎么处置。调用方直接把它透出到启动日志。
    pub fn acquire() -> Result<Self, String> {
        Self::acquire_at(&resolve_lock_path(env::var_os(ENV_LOCK_FILE)))
    }

    /// 在指定路径占位（测试与逃生口都走它）。
    pub fn acquire_at(path: &Path) -> Result<Self, String> {
        let (mut file, writable) = open_lock_file(path)?;

        if !try_lock_exclusive(&file)
            .map_err(|err| format!("对 {} 加锁失败：{err}", path.display()))?
        {
            let holder = read_holder_pid(&mut file)
                .map(|pid| format!("pid {pid}"))
                .unwrap_or_else(|| "另一个进程".to_string());
            return Err(format!(
                "这台机器上已经有另一个 wist-gateway 在跑（{holder} 持有锁 {}）。\
                 一个操作系统上只允许一个实例：先停掉那个（注意它可能配了别的端口，\
                 光看端口会漏），或者——只在你确实要并行两套时——用 {ENV_LOCK_FILE} \
                 指到另一个锁文件。",
                path.display()
            ));
        }

        // 记下自己的 pid 只为**诊断**：出问题时"谁占着锁"要一眼看得到。
        // 只读打开的（锁文件是别人建的）就跳过 —— 拿不到写权限不影响闸门本身。
        if writable {
            let _ = file.set_len(0);
            let _ = file.seek(SeekFrom::Start(0));
            let _ = writeln!(file, "{}", std::process::id());
            let _ = file.flush();
        }

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
        })
    }

    /// 实际用的锁文件路径（启动日志里打出来，省得人猜）。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 锁文件路径：显式给了（且非空）就用它，否则回落默认。
///
/// 单独的纯函数是为了能测 —— 直接读 env 的测试在并行测试里既不稳定也会互相干扰。
fn resolve_lock_path(explicit: Option<OsString>) -> PathBuf {
    explicit
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCK_FILE))
}

/// 打开锁文件，回"句柄 + 能不能写"。
///
/// 拿不到**写**权限时退一步用只读打开：`flock` 不在乎打开模式，闸门照旧成立 ——
/// 只是记不了自己的 pid。这一条很实际：有人用 root 起过一次网关（dev 想听 443 就得 root），
/// 锁文件就归了 root，之后普通用户再起如果非要写权限，会以一句莫名其妙的
/// “Permission denied” 把人挡在门外 —— 那是**锁文件的权限**问题，不是“已有实例”。
fn open_lock_file(path: &Path) -> Result<(File, bool), String> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
    {
        Ok(file) => Ok((file, true)),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => OpenOptions::new()
            .read(true)
            .open(path)
            .map(|file| (file, false))
            .map_err(|err| {
                format!(
                    "打不开单实例锁文件 {}：{err}（锁文件在 /tmp，若它归别的用户所有，\
                         可用 {ENV_LOCK_FILE} 指到你自己可写的位置）",
                    path.display()
                )
            }),
        Err(err) => Err(format!(
            "打不开单实例锁文件 {}：{err}（锁文件在 /tmp，若它归别的用户所有，\
             可用 {ENV_LOCK_FILE} 指到你自己可写的位置）",
            path.display()
        )),
    }
}

/// 非阻塞独占锁：拿到回 `Ok(true)`，被别人持有回 `Ok(false)`，其它才是错误。
#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    // SAFETY: fd 取自仍然活着的 `file`；`flock` 只借用这个描述符，不转移所有权、不释放它。
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // EWOULDBLOCK / EAGAIN 是同一个数，但两个名字都写出来，别让读的人以为漏了一种。
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(false),
        _ => Err(err),
    }
}

/// 非 unix：**不提供锁**（发布矩阵里没有非 unix 目标）。返回"拿到了"是已知缺口，
/// 不是"这里也管得住" —— 真要支持得换 LockFileEx 那一套。
#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> io::Result<bool> {
    Ok(true)
}

/// 读出锁文件里记的持有者 pid（可能读不到：持有者刚拿到锁还没来得及写）。
fn read_holder_pid(file: &mut File) -> Option<u32> {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_to_string(&mut text).ok()?;
    text.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::unique_temp_dir;
    use std::fs;

    #[test]
    fn the_second_instance_is_refused_and_told_who_holds_the_lock() {
        let dir = unique_temp_dir("wist-gateway-lock");
        let path = dir.join("gateway.lock");

        let first = InstanceLock::acquire_at(&path).expect("第一个实例应当拿到锁");
        assert_eq!(first.path(), path.as_path());

        let err = InstanceLock::acquire_at(&path).expect_err("第二个实例必须被拒");
        assert!(err.contains("已经有另一个 wist-gateway"), "{err}");
        assert!(
            err.contains(&std::process::id().to_string()),
            "错误里要报出持有者 pid，人才知道去停谁：{err}"
        );
        assert!(
            err.contains(ENV_LOCK_FILE),
            "错误里要给出逃生口（有意并行两套时用）：{err}"
        );

        // 前一个一放，后一个就能拿到 —— 锁跟着**进程/句柄**走，不跟崩溃残留走。
        drop(first);
        InstanceLock::acquire_at(&path).expect("前一个释放后应当能再拿到");
    }

    #[test]
    fn the_lock_path_falls_back_to_the_default_when_unset_or_empty() {
        assert_eq!(resolve_lock_path(None), PathBuf::from(DEFAULT_LOCK_FILE));
        assert_eq!(
            resolve_lock_path(Some(OsString::new())),
            PathBuf::from(DEFAULT_LOCK_FILE)
        );
        assert_eq!(
            resolve_lock_path(Some(OsString::from("/tmp/other.lock"))),
            PathBuf::from("/tmp/other.lock")
        );
    }

    /// 默认锁文件必须是**按机器**共享的那个目录：`temp_dir()` 在 macOS 上按用户，
    /// 用它就等于把"一个 OS 一个实例"悄悄降级成"一个用户一个实例"。
    #[test]
    fn the_default_lock_file_is_host_wide_not_per_user() {
        assert!(
            DEFAULT_LOCK_FILE.starts_with("/tmp/"),
            "{DEFAULT_LOCK_FILE}"
        );
        let per_user = env::temp_dir();
        if per_user != Path::new("/tmp") {
            assert!(
                !DEFAULT_LOCK_FILE.starts_with(per_user.display().to_string().as_str()),
                "默认锁文件落进了按用户的临时目录（macOS 的 TMPDIR）：{DEFAULT_LOCK_FILE}"
            );
        }
    }

    #[test]
    fn the_holder_pid_is_recorded_for_diagnosis() {
        let dir = unique_temp_dir("wist-gateway-lock-pid");
        let path = dir.join("gateway.lock");
        let lock = InstanceLock::acquire_at(&path).expect("拿锁");
        let recorded = fs::read_to_string(&path).expect("读锁文件");
        assert_eq!(recorded.trim(), std::process::id().to_string());
        drop(lock);
    }

    /// 锁文件归了别人（典型：有人用 root 起过一次）也不该把人挡在门外：
    /// 只读打开也能 flock —— 闸门照旧，只是不自报 pid。
    #[cfg(unix)]
    #[test]
    fn a_lock_file_we_cannot_write_still_works() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_temp_dir("wist-gateway-lock-readonly");
        let path = dir.join("gateway.lock");
        fs::write(&path, "12345\n").expect("预置锁文件");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("只读化");

        // 只读文件仍能拿到锁；内容保持原样（没写权限就不写）。
        let lock = InstanceLock::acquire_at(&path).expect("只读的锁文件也应当能占位");
        assert_eq!(fs::read_to_string(&path).expect("读锁文件").trim(), "12345");

        // 但**互斥**一点没少：第二个照样被拒。
        let err = InstanceLock::acquire_at(&path).expect_err("第二个必须被拒");
        assert!(err.contains("已经有另一个 wist-gateway"), "{err}");

        drop(lock);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("还原权限");
    }
}
