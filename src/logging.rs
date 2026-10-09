//! 运行日志初始化：`env_logger` 走 `log` facade，级别 / 格式 / 落点由配置的 `[log]` 段决定。
//!
//! 优先级：`RUST_LOG` 环境变量 > `[log] level` > 缺省 `info`（保留“用环境变量临时加详细日志”的习惯）。
//! 落点：`[log] file` 给了就写文件（追加、自动建父目录、**写满轮转**），否则写 stderr。
//! 格式：`text`（带毫秒时间戳）或 `json`（每行一个对象，便于采集）。
//!
//! **轮转由本进程自己做**（`[log] max_bytes` / `keep_files` / `max_age_seconds`）：写满即滚成
//! `<file>.1`…`<file>.N`，并按 mtime 清超龄分卷。因此**不要再给日志文件挂 logrotate**，
//! 两套轮转会互相打架（logrotate 挪名后本进程的 fd 仍指向旧 inode）。
//!
//! 注意与 [`crate::infra::AdminConfig`] 的 `[logs]` 段区分：那是“**被采集 agent 日志**的落盘保留”，
//! 这里的 `[log]` 是**本网关进程自己**的运行日志。

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use env_logger::{Builder, Target};

/// `[log]` 段。
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct LogSection {
    /// 过滤器指令：`info`，或 `wist_gateway=debug,hyper=warn` 这种分 target 写法。缺省 `info`。
    #[serde(default)]
    pub level: Option<String>,
    /// 输出格式（`text` | `json`）。缺省 `text`。
    #[serde(default)]
    pub format: LogFormat,
    /// 写文件（追加、自动建父目录、写满轮转）。缺省写 stderr。
    #[serde(default)]
    pub file: Option<PathBuf>,
    /// 单文件上限（字节），写满就轮转成 `file.1`/`file.2`/…。缺省 64 MiB（下限 8 KiB）。
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// 保留的历史分卷个数（`0` = 不留历史，轮转即截断）。缺省 4。
    #[serde(default)]
    pub keep_files: Option<usize>,
    /// 历史分卷保留时长（秒）；`0` = 不按时间清。缺省 7 天。
    #[serde(default)]
    pub max_age_seconds: Option<i64>,
}

/// 日志输出格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// `<时间戳> <LEVEL> <target>: <message>`（缺省）。
    #[default]
    Text,
    /// 每行一个 JSON 对象：`{ts, level, target, message}`。
    Json,
}

/// 按 `[log]` 段初始化日志。**只生效一次**（`try_init`）；已初始化过不 panic。
pub fn init(section: &LogSection) {
    let mut builder = Builder::new();
    builder.parse_filters(&resolve_filter(section));

    match section.file.as_deref() {
        Some(path) => match RotatingFile::open(path, RotationPolicy::resolve(section)) {
            Ok(file) => {
                let shared = SharedWriter(Arc::new(Mutex::new(file)));
                builder.target(Target::Pipe(Box::new(shared)));
            }
            Err(err) => {
                // 落文件失败不该让网关起不来：说清一句、回落 stderr（那里通常有 journald 接着）。
                eprintln!(
                    "[warn] 打开日志文件 {} 失败：{err}（回落 stderr）",
                    path.display()
                );
                builder.target(Target::Stderr);
            }
        },
        None => {
            builder.target(Target::Stderr);
        }
    }

    match section.format {
        LogFormat::Text => {
            builder.format_timestamp_millis();
        }
        LogFormat::Json => {
            builder.format(format_json);
        }
    }

    if let Err(err) = builder.try_init() {
        // 只可能失败于「已有 logger 初始化过」（如测试 harness 或宿主先装了全局 logger）。
        // 说出来比静默好：否则使用者会以为 `[log]` 生效了，却看不到日志去了文件。
        eprintln!("[warn] 日志已被其它组件初始化，[log] 配置未生效（原因：{err}）");
    }
}

/// 解析生效的过滤器：`RUST_LOG` > `[log] level` > `info`。
fn resolve_filter(section: &LogSection) -> String {
    std::env::var("RUST_LOG")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            section
                .level
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "info".to_string())
}

/// 每行一个 JSON 对象（`ts` / `level` / `target` / `message`）。
fn format_json(
    buf: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
) -> std::io::Result<()> {
    let line = serde_json::json!({
        "ts": buf.timestamp().to_string(),
        "level": record.level().as_str().to_ascii_lowercase(),
        "target": record.target(),
        "message": record.args().to_string(),
    });
    writeln!(buf, "{line}")
}

/// 运行日志文件的轮转策略（由 `[log]` 的后三键决定）。
#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    pub max_bytes: u64,
    pub keep_files: usize,
    pub max_age_seconds: i64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            keep_files: 4,
            max_age_seconds: 7 * 24 * 60 * 60,
        }
    }
}

impl RotationPolicy {
    fn resolve(section: &LogSection) -> Self {
        let default = Self::default();
        Self {
            max_bytes: section.max_bytes.unwrap_or(default.max_bytes).max(8 * 1024),
            keep_files: section.keep_files.unwrap_or(default.keep_files),
            max_age_seconds: section.max_age_seconds.unwrap_or(default.max_age_seconds),
        }
    }
}

/// 写满 [`RotationPolicy::max_bytes`] 就轮转的日志文件：当前是 `path`，历史分卷是
/// `path.1`（最新）… `path.N`（最旧）。轮转时下移编号、丢最旧；并按 mtime 清超龄分卷。
struct RotatingFile {
    path: PathBuf,
    retention: RotationPolicy,
    file: std::fs::File,
    written: u64,
}

impl RotatingFile {
    fn open(path: &Path, retention: RotationPolicy) -> io::Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        let writer = Self {
            path: path.to_path_buf(),
            retention,
            file,
            written,
        };
        writer.prune_by_age();
        Ok(writer)
    }

    fn archive(&self, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{}", self.path.display(), index))
    }

    fn rotate(&mut self) -> io::Result<()> {
        let _ = self.file.flush();
        // `keep_files == 0`：不留历史，截断当前文件即可。
        if self.retention.keep_files == 0 {
            self.file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?;
            self.written = 0;
            return Ok(());
        }
        let keep = self.retention.keep_files;
        // 丢最旧，再逐级下移（从旧的往里挪，避免互相覆盖）。
        let _ = std::fs::remove_file(self.archive(keep));
        for index in (1..keep).rev() {
            let from = self.archive(index);
            if from.exists() {
                let _ = std::fs::rename(&from, self.archive(index + 1));
            }
        }
        let _ = std::fs::rename(&self.path, self.archive(1));
        self.file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        self.prune_by_age();
        Ok(())
    }

    fn prune_by_age(&self) {
        if self.retention.max_age_seconds <= 0 {
            return;
        }
        let cutoff = SystemTime::now() - Duration::from_secs(self.retention.max_age_seconds as u64);
        for index in 1..=self.retention.keep_files.max(1) {
            let path = self.archive(index);
            let stale = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .map(|modified| modified < cutoff)
                .unwrap_or(false);
            if stale {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // `written > 0`：空文件不反复轮转（否则上限小于一行时会转不停）。
        if self.written > 0 && self.written + buf.len() as u64 > self.retention.max_bytes {
            self.rotate()?;
        }
        let written = self.file.write(buf)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// `Target::Pipe` 收 `Box<dyn Write + Send>`；用 `Arc<Mutex<..>>` 包一层保证跨线程安全。
#[derive(Clone)]
struct SharedWriter(Arc<Mutex<RotatingFile>>);

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-gateway-log-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    #[test]
    fn filter_prefers_rust_log_then_section_then_info() {
        // 不碰进程级 RUST_LOG（测试并行），只测「无环境变量时的回落」。
        if std::env::var("RUST_LOG").is_err() {
            let level = LogSection {
                level: Some("warn".to_string()),
                ..Default::default()
            };
            assert_eq!(resolve_filter(&level), "warn");

            let empty = LogSection {
                level: Some("  ".to_string()),
                ..Default::default()
            };
            assert_eq!(resolve_filter(&empty), "info");

            assert_eq!(resolve_filter(&LogSection::default()), "info");
        }
    }

    #[test]
    fn log_section_parses_from_toml() {
        let section: LogSection = toml::from_str(
            "level = \"wist_gateway=debug\"\nformat = \"json\"\nfile = \"/tmp/g.log\"\nmax_bytes = 1048576\nkeep_files = 3\nmax_age_seconds = 86400\n",
        )
        .expect("parse");
        assert_eq!(section.level.as_deref(), Some("wist_gateway=debug"));
        assert_eq!(section.format, LogFormat::Json);
        assert_eq!(section.file.as_deref(), Some(Path::new("/tmp/g.log")));
        assert_eq!(section.max_bytes, Some(1_048_576));
        assert_eq!(section.keep_files, Some(3));
        assert_eq!(section.max_age_seconds, Some(86_400));
    }

    #[test]
    fn rotates_when_exceeding_max_bytes_and_keeps_two() {
        let dir = temp_dir("rotate");
        let path = dir.join("run.log");
        let policy = RotationPolicy {
            max_bytes: 1024,
            keep_files: 2,
            max_age_seconds: 0,
        };
        let mut writer = RotatingFile::open(&path, policy).expect("open");
        for _ in 0..40 {
            writer.write_all(&[b'x'; 100]).expect("write");
        }
        writer.flush().expect("flush");
        assert!(path.is_file(), "current file exists");
        assert!(dir.join("run.log.1").is_file(), "must have rotated");
        assert!(dir.join("run.log.2").is_file(), "keeps a second archive");
        assert!(
            !dir.join("run.log.3").exists(),
            "must not keep more than `keep_files`"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn keep_files_zero_truncates_without_archives() {
        let dir = temp_dir("truncate");
        let path = dir.join("run.log");
        let policy = RotationPolicy {
            max_bytes: 256,
            keep_files: 0,
            max_age_seconds: 0,
        };
        let mut writer = RotatingFile::open(&path, policy).expect("open");
        for _ in 0..10 {
            writer.write_all(&[b'x'; 100]).expect("write");
        }
        writer.flush().expect("flush");
        assert!(path.is_file());
        assert!(!dir.join("run.log.1").exists(), "no history kept");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn prunes_only_archives_older_than_max_age() {
        let dir = temp_dir("age");
        let path = dir.join("run.log");
        let policy = RotationPolicy {
            max_bytes: 1024,
            keep_files: 3,
            max_age_seconds: 60,
        };
        let writer = RotatingFile::open(&path, policy).expect("open");
        let stale = dir.join("run.log.1");
        let fresh = dir.join("run.log.2");
        for archive in [&stale, &fresh] {
            std::fs::write(archive, b"x").expect("write archive");
        }
        set_mtime(&stale, SystemTime::now() - Duration::from_secs(3600));
        set_mtime(&fresh, SystemTime::now());

        writer.prune_by_age();

        assert!(!stale.exists(), "超龄分卷应被清掉");
        assert!(fresh.exists(), "未超龄分卷必须保留");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn set_mtime(path: &Path, when: SystemTime) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for mtime");
        file.set_modified(when).expect("set mtime");
    }
}
