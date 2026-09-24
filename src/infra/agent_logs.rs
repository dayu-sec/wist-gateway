//! 采集日志的本地落盘（append-only NDJSON）与尾部读取。
//!
//! ## 为什么是文件而不是库表
//!
//! 事实摘要是**小对象**（一台一条、覆盖式），要判重与推断，所以进库；日志是**无界的观测流**，
//! 保留期与索引键尚未定档。先落 NDJSON：可以 `tail`、可以 `grep`、不需要先定 schema，
//! 等保留策略定了再考虑入库。
//!
//! ## 为什么按字节窗口回看
//!
//! 文件是无界追加的。按行数回看要先整读一遍；按字节窗口回看只需要 `seek` 到文件末尾前 N 字节，
//! 代价与文件大小无关。代价是窗口起点可能落在一条记录的中间 —— 那半条会被丢掉，
//! 同时 [`LogTail::truncated`] 置位，让调用方知道「更早的这次没看到」，而不是以为「就这么多」。

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 一次回看的字节窗口上限（8 MiB）。
pub const TAIL_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

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

/// NDJSON 日志文件：追加写 + 尾部读。
#[derive(Debug, Clone)]
pub struct AgentLogFile {
    path: PathBuf,
}

impl AgentLogFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一批记录：一次 `write_all` 写完整批，调用方要么全落、要么拿到错误。
    ///
    /// 父目录不存在就建（首次落盘）。
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
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(buffer.as_bytes())
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
}
