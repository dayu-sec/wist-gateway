//! 采集日志的本地落盘（append-only NDJSON）与尾部读取。
//!
//! ## 为什么是文件而不是库表
//!
//! 事实摘要是**小对象**（一台一条、覆盖式），要判重与推断，所以进库；日志是**无界的观测流**，
//! 索引键尚未定档。先落 NDJSON：可以 `tail`、可以 `grep`、不需要先定 schema。（**保留 / 轮转**
//! 已定档，见下节。）
//!
//! ## 为什么按字节窗口回看
//!
//! 文件是无界追加的。按行数回看要先整读一遍；按字节窗口回看只需要 `seek` 到文件末尾前 N 字节，
//! 代价与文件大小无关。代价是窗口起点可能落在一条记录的中间 —— 那半条会被丢掉，
//! 同时 [`LogTail::truncated`] 置位，让调用方知道「更早的这次没看到」，而不是以为「就这么多」。
//!
//! ## 为什么要有保留 / 轮转
//!
//! 只追加、不设上界，文件会一直长（曾看到单文件 52 GB）。写入前按 [`LogRetention`] 轮转：
//! 单文件写满就开新卷（`<file>.1`…），历史按**个数**与**时长**清理 —— 磁盘用量封在
//! `max_bytes × (keep_files + 1)` 量级。回看只读**当前卷**（窗口也只有 8 MiB），轮转不影响它。

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// 一次回看的字节窗口上限（8 MiB）。
pub const TAIL_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// 采集日志落盘的**保留 / 轮转**策略。
///
/// 为什么要有它：文件是 append-only 的，不设上界就会一直长（曾看到单文件 52 GB）。轮转与保留
/// 一起把磁盘用量封在 `max_bytes × (keep_files + 1)` 量级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRetention {
    /// 单个文件（含当前文件与其历史分卷）的上限（字节）：写满就轮转。
    pub max_bytes: u64,
    /// 保留的历史分卷个数（`<file>.1` … `<file>.N`）；`0` = 不留历史。
    pub keep_files: usize,
    /// 历史分卷的保留时长（秒）；`0` = 不按时间清。
    pub max_age_seconds: i64,
}

impl Default for LogRetention {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            keep_files: 4,
            max_age_seconds: 7 * 24 * 60 * 60,
        }
    }
}

/// 一条采集日志记录。
///
/// 字段来自数据面 `macos_agent_record` OML 记录及其信封（`agent_id` / `observed_at` / `seq`），
/// 外加网关自己的落盘时刻。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLogRecord {
    /// 上送该记录的 Agent（帧信封 `agent`；接入时已核对过登记表）。
    pub agent_id: String,
    /// **采集面**（闭集，如 `NetworkFirewall`）与**目录单元 id**（如 `mac-network-wifi`）。
    ///
    /// 为什么要有它：正文规则未就绪时 `category` 恒为泛化的 `agent.log`，
    /// 于是“这条来自哪个面”在数据里没有位置 —— 两个面一起跑就分不出来。
    /// 空串 = 不是平台派活来的（本机运维手工配置的输入）。
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub unit: String,
    /// Agent 侧的观测时刻（帧信封 `ts`）。
    pub observed_at: String,
    /// 该 Agent 上行帧的序号（帧信封 `seq`）。
    pub seq: u64,
    /// 采集面 / 类别（OML `log_type`，如 `agent.log`）。
    pub category: String,
    /// 人类可读的说明（OML `log_desc`）。
    pub log_desc: String,
    /// 记录**原文**（OML `raw`）。可能是多行。
    pub raw: String,
    /// 网关落盘时刻（RFC3339）。
    pub received_at: String,
}

/// 一次尾部读取的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogTail {
    /// 命中的记录，按写入顺序（旧 → 新）。
    pub records: Vec<AgentLogRecord>,
    /// 回看窗口被截断：文件比窗口大，更早的记录这次没返回。
    pub truncated: bool,
}

/// NDJSON 日志文件：追加写（按策略轮转 / 保留）+ 尾部读。
#[derive(Debug, Clone)]
pub struct AgentLogFile {
    path: PathBuf,
    retention: LogRetention,
}

impl AgentLogFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            retention: LogRetention::default(),
        }
    }

    /// 带显式保留策略构造。
    pub fn with_retention(path: PathBuf, retention: LogRetention) -> Self {
        Self { path, retention }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一批记录：一次 `write_all` 写完整批，调用方要么全落、要么拿到错误。
    ///
    /// 写前按策略轮转 / 保留（写满就开新卷，历史按数量与时长清理）。父目录不存在就建。
    pub fn append(&self, records: &[AgentLogRecord]) -> std::io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        if let Some(dir) = self.path.parent()
            && !dir.as_os_str().is_empty()
        {
            fs::create_dir_all(dir)?;
        }
        let mut buffer = String::new();
        for record in records {
            let line = serde_json::to_string(record)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            buffer.push_str(&line);
            buffer.push('\n');
        }
        self.rotate_if_needed(buffer.len() as u64)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(buffer.as_bytes())
    }

    /// 按保留策略清历史分卷（**不动当前卷**）。
    ///
    /// 轮转发生在**写入**时；但网关可能长时间空闲（没有新日志），那时没有 append 去触发清理。
    /// 后台 tick 调这个，空闲期间也能把过期/超量的分卷清掉。
    pub fn prune(&self) {
        self.prune_archives();
    }

    /// 当前文件大小；不存在 = 0。
    fn current_bytes(&self) -> std::io::Result<u64> {
        match fs::metadata(&self.path) {
            Ok(meta) => Ok(meta.len()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(err) => Err(err),
        }
    }

    /// 第 `index` 个历史分卷的路径：`<file>.<index>`。
    fn archive_path(&self, index: usize) -> PathBuf {
        let mut name = self.path.clone().into_os_string();
        name.push(format!(".{index}"));
        PathBuf::from(name)
    }

    /// 写入 `incoming` 字节前，必要的话先轮转一次。
    ///
    /// **前提**：`incoming ≤ max_bytes`（由配置下限保证 —— 单批不超过接入端点 body 上限）。
    /// 这样「文件大于 max_bytes」只可能是策略生效前的遗留，不会被误判成一批写出的正常文件。
    fn rotate_if_needed(&self, incoming: u64) -> std::io::Result<()> {
        let size = self.current_bytes()?;
        if size == 0 || size.saturating_add(incoming) <= self.retention.max_bytes {
            return Ok(());
        }
        if size > self.retention.max_bytes {
            // 策略生效前攒下的**超大遗留文件**不是合规的轮转单元：直接丢掉，
            // 而不是原样搬进历史（那样磁盘照样占满）。
            fs::remove_file(&self.path)?;
            self.prune_archives();
            return Ok(());
        }
        self.rotate()
    }

    /// 轮转：当前 → `.1`，旧卷逐个后移，超出 `keep_files` 的最老一卷丢弃；再按时间清。
    fn rotate(&self) -> std::io::Result<()> {
        let keep = self.retention.keep_files;
        if keep == 0 {
            fs::remove_file(&self.path)?;
            self.prune_archives();
            return Ok(());
        }
        // 腾位置：先去掉最老的一卷（也是 Windows 上 rename 不能覆盖目标的前提）。
        let _ = fs::remove_file(self.archive_path(keep));
        for index in (1..keep).rev() {
            let from = self.archive_path(index);
            if from.exists() {
                fs::rename(&from, self.archive_path(index + 1))?;
            }
        }
        fs::rename(&self.path, self.archive_path(1))?;
        self.prune_archives();
        Ok(())
    }

    /// 清历史分卷：**序号超出 `keep_files`** 的（含把 `keep_files` 改小后留下的残留）、
    /// 以及按 `max_age_seconds` 过期的（`0` = 不按时间清）。扫目录而不是只按序号 ——
    /// 才能收掉「曾经存在、现在不该在」的那些卷。
    fn prune_archives(&self) {
        let Some(dir) = self.path.parent() else {
            return;
        };
        let Some(base) = self.path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        let prefix = format!("{base}.");
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            // 只认 `<file>.<序号>` 形式的分卷，别误删别的文件（当前文件名没有尾 `.`，不会被命中）。
            let Ok(index) = suffix.parse::<usize>() else {
                continue;
            };
            let beyond_keep = self.retention.keep_files == 0 || index > self.retention.keep_files;
            let stale = self.retention.max_age_seconds > 0
                && entry
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| now.duration_since(modified).ok())
                    .map(|age| age.as_secs() as i64 > self.retention.max_age_seconds)
                    .unwrap_or(false);
            if beyond_keep || stale {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// 读回看窗口内最多 `limit` 条记录（旧 → 新）。`agent_id` / `family` 给了就只留命中的。
    ///
    /// 文件不存在 = 还没有日志（空结果，不是错误）。
    pub fn tail(
        &self,
        agent_id: Option<&str>,
        family: Option<&str>,
        limit: usize,
    ) -> std::io::Result<LogTail> {
        self.tail_within(agent_id, family, limit, TAIL_WINDOW_BYTES)
    }

    fn tail_within(
        &self,
        agent_id: Option<&str>,
        family: Option<&str>,
        limit: usize,
        window_bytes: u64,
    ) -> std::io::Result<LogTail> {
        let empty = LogTail {
            records: Vec::new(),
            truncated: false,
        };
        if limit == 0 {
            return Ok(empty);
        }
        let mut file = match fs::File::open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(empty),
            Err(err) => return Err(err),
        };
        let len = file.metadata()?.len();
        let window_start = len.saturating_sub(window_bytes);
        let truncated = window_start > 0;
        file.seek(SeekFrom::Start(window_start))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut kept: VecDeque<AgentLogRecord> = VecDeque::new();
        for (index, line) in buffer.split(|byte| *byte == b'\n').enumerate() {
            // 窗口起点落在记录中间时，第一段是半条：丢掉。
            if index == 0 && truncated {
                continue;
            }
            if line.is_empty() {
                continue;
            }
            // 半截行（写了一半进程被杀）或人工改过的行：跳过，不让一条坏行毁掉整次查看。
            let Ok(record) = serde_json::from_slice::<AgentLogRecord>(line) else {
                continue;
            };
            if let Some(agent_id) = agent_id
                && record.agent_id != agent_id
            {
                continue;
            }
            // 按**采集面**筛：正文规则未就绪时它是唯一能把两个面分开的字段。
            if let Some(family) = family
                && record.family != family
            {
                continue;
            }
            kept.push_back(record);
            if kept.len() > limit {
                kept.pop_front();
            }
        }
        Ok(LogTail {
            records: kept.into_iter().collect(),
            truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(label: &str) -> (PathBuf, AgentLogFile) {
        let dir = std::env::temp_dir().join(format!(
            "wist-agent-logs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        ));
        let path = dir.join("nested").join("agent-logs.ndjson");
        (dir, AgentLogFile::new(path))
    }

    fn record(agent_id: &str, seq: u64, raw: &str) -> AgentLogRecord {
        AgentLogRecord {
            agent_id: agent_id.to_string(),
            family: String::new(),
            unit: String::new(),
            observed_at: format!("2026-09-23T00:00:{seq:02}Z"),
            seq,
            category: "agent.log".to_string(),
            log_desc: "Agent 日志-原文".to_string(),
            raw: raw.to_string(),
            received_at: "2026-09-23T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn append_creates_the_parent_directory() {
        let (dir, file) = temp_file("mkdir");
        file.append(&[record("agent-a", 1, "hello")])
            .expect("append");
        assert!(file.path().is_file());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_is_a_no_op_for_an_empty_batch() {
        let (dir, file) = temp_file("empty");
        file.append(&[]).expect("append");
        assert!(
            !file.path().exists(),
            "empty batch must not create the file"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_returns_records_in_write_order() {
        let (dir, file) = temp_file("order");
        file.append(&[
            record("agent-a", 1, "first"),
            record("agent-a", 2, "second"),
        ])
        .expect("append");
        let tail = file.tail(None, None, 10).expect("tail");
        assert!(!tail.truncated);
        assert_eq!(
            tail.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_filters_by_agent() {
        let (dir, file) = temp_file("filter");
        file.append(&[
            record("agent-a", 1, "from a"),
            record("agent-b", 2, "from b"),
            record("agent-a", 3, "from a again"),
        ])
        .expect("append");
        let tail = file.tail(Some("agent-a"), None, 10).expect("tail");
        assert_eq!(
            tail.records
                .iter()
                .map(|r| r.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["from a", "from a again"]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_filters_by_family() {
        // 正文规则未就绪时，**采集面**是唯一能把两个面分开的字段 —— 它必须能筛。
        let (dir, file) = temp_file("family");
        let mut launchd = record("agent-a", 1, "from launchd");
        launchd.family = "ServiceLifecycle".to_string();
        launchd.unit = "mac-launchd-service".to_string();
        let mut wifi = record("agent-a", 2, "from wifi");
        wifi.family = "NetworkFirewall".to_string();
        wifi.unit = "mac-network-wifi".to_string();
        file.append(&[launchd, wifi]).expect("append");

        let tail = file.tail(None, Some("ServiceLifecycle"), 10).expect("tail");
        assert_eq!(tail.records.len(), 1);
        assert_eq!(tail.records[0].raw, "from launchd");
        assert_eq!(tail.records[0].unit, "mac-launchd-service");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_keeps_only_the_newest_records_for_the_limit() {
        let (dir, file) = temp_file("limit");
        file.append(&[
            record("agent-a", 1, "one"),
            record("agent-a", 2, "two"),
            record("agent-a", 3, "three"),
        ])
        .expect("append");
        let tail = file.tail(None, None, 2).expect("tail");
        assert_eq!(
            tail.records
                .iter()
                .map(|r| r.raw.as_str())
                .collect::<Vec<_>>(),
            vec!["two", "three"]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_on_a_missing_file_is_empty_not_an_error() {
        let (dir, file) = temp_file("missing");
        let tail = file.tail(None, None, 10).expect("tail");
        assert!(tail.records.is_empty());
        assert!(!tail.truncated);
        assert!(!dir.exists(), "reading must not create anything");
    }

    #[test]
    fn tail_drops_the_partial_first_record_when_the_window_starts_mid_line() {
        let (dir, file) = temp_file("window");
        file.append(&[
            record("agent-a", 1, "an old record that falls outside the window"),
            record("agent-a", 2, "a newer one"),
        ])
        .expect("append");
        // 窗口只够最后一条：起点落在上一条中间。
        // **不写死字节数** —— 记录里多一个字段就会让硬编码的数字失效（踩过一次）。
        let bytes = std::fs::read(file.path()).expect("read file");
        let last_line_len = bytes
            .iter()
            .rev()
            .skip(1)
            .take_while(|byte| **byte != b'\n')
            .count();
        let window = (last_line_len + 10) as u64;
        let tail = file.tail_within(None, None, 10, window).expect("tail");
        assert!(tail.truncated, "a clipped window must say so");
        assert_eq!(
            tail.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![2]
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tail_skips_an_unparseable_line() {
        let (dir, file) = temp_file("garbage");
        file.append(&[record("agent-a", 1, "good")])
            .expect("append");
        // 模拟「写了一半进程被杀」：往文件尾补一段不是 JSON 的内容。
        let mut handle = OpenOptions::new()
            .append(true)
            .open(file.path())
            .expect("open");
        handle
            .write_all(b"{\"agent_id\":\"agent-a\",\"raw\":")
            .expect("write");
        let tail = file.tail(None, None, 10).expect("tail");
        assert_eq!(tail.records.len(), 1);
        assert_eq!(tail.records[0].raw, "good");
        fs::remove_dir_all(&dir).ok();
    }

    fn archive(path: &Path, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{index}", path.display()))
    }

    /// 一条记录序列化后的字节数（用它推一个「写两条就超」的额度，不写死数字）。
    fn one_record_bytes() -> u64 {
        serde_json::to_string(&record("agent-a", 1, "payload"))
            .expect("serialize")
            .len() as u64
    }

    fn retention(max_bytes: u64, keep_files: usize, max_age_seconds: i64) -> LogRetention {
        LogRetention {
            max_bytes,
            keep_files,
            max_age_seconds,
        }
    }

    #[test]
    fn rotation_keeps_a_bounded_number_of_archives() {
        let (dir, file) = temp_file("rotate");
        let path = file.path().to_path_buf();
        let file =
            AgentLogFile::with_retention(path.clone(), retention(one_record_bytes() + 10, 2, 0));
        // 每次追加一条都会触发轮转（额度只够一条）。
        for seq in 1..=6 {
            file.append(&[record("agent-a", seq, "payload")])
                .expect("append");
        }
        assert!(path.is_file(), "当前卷还在");
        assert!(archive(&path, 1).is_file(), ".1 存在");
        assert!(archive(&path, 2).exists(), ".2 存在");
        assert!(
            !archive(&path, 3).exists(),
            "超出 keep_files 的最老一卷要被丢掉"
        );
        // 轮转不影响尾部读（读的是当前卷）。
        let tail = file.tail(None, None, 10).expect("tail");
        assert!(!tail.records.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_oversized_legacy_file_is_discarded_on_rotation_not_archived() {
        // 模拟「策略生效前攒下的」超大文件：直接造一个比额度大得多的文件。
        let (dir, file) = temp_file("legacy");
        let path = file.path().to_path_buf();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, vec![b'x'; 4096]).expect("seed oversized file");

        let file = AgentLogFile::with_retention(path.clone(), retention(256, 4, 0));
        file.append(&[record("agent-a", 1, "fresh")])
            .expect("append");

        assert!(
            !archive(&path, 1).exists(),
            "超大遗留文件不该被原样归档（否则磁盘照样占满）"
        );
        let tail = file.tail(None, None, 10).expect("tail");
        assert_eq!(tail.records.len(), 1, "当前卷只含新写入的记录");
        assert_eq!(tail.records[0].raw, "fresh");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn keep_files_zero_keeps_no_history() {
        let (dir, file) = temp_file("no-history");
        let path = file.path().to_path_buf();
        let file =
            AgentLogFile::with_retention(path.clone(), retention(one_record_bytes() + 10, 0, 0));
        file.append(&[record("agent-a", 1, "payload")])
            .expect("append");
        file.append(&[record("agent-a", 2, "payload")])
            .expect("append");
        assert!(!archive(&path, 1).exists(), "keep=0 不留历史卷");
        let tail = file.tail(None, None, 10).expect("tail");
        assert_eq!(tail.records.len(), 1, "只剩最近一次写入");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_archives_are_pruned_by_age() {
        let (dir, file) = temp_file("age");
        let path = file.path().to_path_buf();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        // 造一个「很久以前」的分卷：把 mtime 拨到 10 天前。
        let stale = archive(&path, 1);
        std::fs::write(&stale, b"{}\n").expect("seed stale archive");
        let old = SystemTime::now() - std::time::Duration::from_secs(10 * 24 * 60 * 60);
        OpenOptions::new()
            .write(true)
            .open(&stale)
            .expect("open stale")
            .set_modified(old)
            .expect("set mtime");

        // keep 够多（4）、只按时间清（7 天）：触发一次轮转就会把它清掉。
        let file = AgentLogFile::with_retention(
            path.clone(),
            retention(one_record_bytes() + 10, 4, 7 * 24 * 60 * 60),
        );
        file.append(&[record("agent-a", 1, "payload")])
            .expect("append"); // 首次不轮转
        file.append(&[record("agent-a", 2, "payload")])
            .expect("append"); // 这次轮转 + 按时间清

        // 陈旧分卷被移到了 .2，并在清时被删；新鲜的是 .1。
        assert!(archive(&path, 1).is_file(), "新卷在");
        assert!(!archive(&path, 2).exists(), "陈旧分卷被按时长清掉");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_removes_stale_archives_without_an_append() {
        // 空闲路径：只调 prune()（不 append），过期分卷也要被清。
        let (dir, file) = temp_file("prune-idle");
        let path = file.path().to_path_buf();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");

        let stale = archive(&path, 1);
        std::fs::write(&stale, b"{}\n").expect("seed stale");
        let old = SystemTime::now() - std::time::Duration::from_secs(10 * 24 * 60 * 60);
        OpenOptions::new()
            .write(true)
            .open(&stale)
            .expect("open stale")
            .set_modified(old)
            .expect("set mtime");

        // keep=4（不超量）、只按时间清（7 天）：只剩「按龄」一条规则。
        let file = AgentLogFile::with_retention(
            path.clone(),
            retention(one_record_bytes() + 10, 4, 7 * 24 * 60 * 60),
        );
        file.prune();
        assert!(!archive(&path, 1).exists(), "空闲时也应按时长清掉过期分卷");

        // 幂等：再清一次不报错、也不动当前卷（本用例没建当前卷）。
        file.prune();
        assert!(!path.exists(), "prune 不创建也不动当前卷");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn archives_beyond_keep_are_pruned_even_without_an_age_limit() {
        let (dir, file) = temp_file("beyond-keep");
        let path = file.path().to_path_buf();
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        // 造出 .1/.2/.3（像是曾经 keep=3 留下的），再换 keep=1 写一次触发轮转。
        for index in 1..=3 {
            std::fs::write(archive(&path, index), b"{}\n").expect("seed archive");
        }
        let file =
            AgentLogFile::with_retention(path.clone(), retention(one_record_bytes() + 10, 1, 0));
        file.append(&[record("agent-a", 1, "payload")])
            .expect("append"); // 首次不轮转
        file.append(&[record("agent-a", 2, "payload")])
            .expect("append"); // 轮转 + 清理
        assert!(archive(&path, 1).is_file(), "保留的卷在");
        assert!(!archive(&path, 2).exists(), "超出 keep 的卷被清");
        assert!(!archive(&path, 3).exists(), "超出 keep 的卷被清");
        fs::remove_dir_all(&dir).ok();
    }
}
