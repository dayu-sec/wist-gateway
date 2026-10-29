//! 数据面（wparse）的**只读浏览**：配置 / 规则，以及**输出文件 tail**。
//!
//! 两类端点共用同一个工作根（宿主 `data-plane-run/work`，compose 只读挂到
//! `/data-plane`）：
//!   - 配置树：一份目录树 + 按路径读单个文本文件。用途是「页面直接看到数据面现在
//!     吃的是哪份 conf / topology / connectors / models」，不用 SSH 到宿主；
//!   - 输出 tail：`data/out_dat` 下的文本文件（宿主 `data-plane-run/data` 由 compose
//!     只读挂到 `/data-plane/data`）。页面「采集日志」用它做 `tail -f`。
//!
//! 安全边界（这些端点能读文件，边界必须写在代码里，不能靠调用方自觉）：
//!   - 配置树只允许白名单根 [`ALLOWED_ROOTS`] 与白名单文件 [`ALLOWED_FILES`]；
//!   - 输出 tail 只允许输出目录下的**文本扩展名**（[`TEXT_EXTENSIONS`]）；
//!   - 两类都拒绝绝对路径 / `..` / 反斜杠；`canonicalize` 之后必须仍在各自根内
//!     ——挡住符号链接逃逸；目录树里**不展开**符号链接；
//!   - 单文件有返回上限，超出只返回前缀并标 `truncated`（tail 用窗口 + 偏移）；
//!   - 非 UTF-8（二进制）不返回正文，只标 `binary` / 拒收 tail；
//!   - 全部只读：本模块没有任何写路径。
//!
//! 未配置（没挂载）时回 503 —— 与 content / discovery-policies 未配置同一约定。
//!
//! 不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics / pipeline / content
//! 同一模式。重新生成控制面代码时需回补本模块与 `mod.rs` 里的四条路由。

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admin_auth::require_admin_bearer;
use super::{ApiError, ApiState, codes, rate_limit};

/// 允许浏览的顶层目录（数据面真正读的那几棵）。
const ALLOWED_ROOTS: &[&str] = &["conf", "topology", "connectors", "models"];
/// 允许单独浏览的顶层文件（工作根的管理面覆盖层）。
const ALLOWED_FILES: &[&str] = &["wparse.local.toml"];
/// 单文件返回上限：配置/规则都是文本，1 MiB 足够；超出只给前缀。
const MAX_CONTENT_BYTES: u64 = 1024 * 1024;
/// 目录树一次最多返回多少条（防止 `models/` 被塞爆时把响应拖死）。
const MAX_TREE_ENTRIES: usize = 4096;
/// 目录递归深度上限。
const MAX_TREE_DEPTH: usize = 8;

// ── 输出文件（wparse 的 file sink 落点）───────────────────────────────────────

/// 输出文件的顶层相对目录。
///
/// 模板里的 file sink 用的是 `out_dat`（少一个 `a`），但口语与部分老工程写成 `out_data`；
/// 两种都认，免得因为一个字母让页面在一版栈上找不到文件。
const OUTPUT_DIRS: &[&str] = &["data/out_dat", "data/out_data"];

/// 可 tail 的文本扩展名（小写）。
///
/// 只列文本格式：`file_arrow_sink` / `file_proto_sink` 之类的二进制输出在浏览器里
/// 没有可读性，列出来只会让人点进去看到「不是文本」。
const TEXT_EXTENSIONS: &[&str] = &[
    "log", "txt", "json", "jsonl", "ndjson", "csv", "tsv", "yaml", "yml", "xml", "pbtxt", "proto",
    "raw", "dat", "out",
];

/// 输出目录一次最多列多少条（与配置树同一思路：别让一个被塞爆的目录拖死响应）。
const MAX_OUTPUT_FILES: usize = 512;
/// 一次列目录最多**扫描**多少条（含被过滤掉的二进制文件与空目录）——
/// 防止有人往 `out_dat/` 里塞几万个空子目录时，每次轮询都把网关拖在这里。
const MAX_OUTPUT_SCAN_ENTRIES: usize = 10_000;
/// 输出目录递归深度上限。
const MAX_OUTPUT_DEPTH: usize = 4;
/// 首次 tail 的默认窗口：够看最近的几百行，又不会把整份日志塞进一次响应。
const DEFAULT_TAIL_BYTES: u64 = 256 * 1024;
/// 单次 tail 的上限。
const MAX_TAIL_BYTES: u64 = 1024 * 1024;

/// 目录树里的一个条目。
#[derive(Debug, Serialize)]
pub struct DataPlaneEntryView {
    /// 相对工作根的路径，一律 `/` 分隔。
    pub path: String,
    /// `dir` | `file`。
    pub kind: &'static str,
    /// 文件字节数；目录为 0。
    pub size: u64,
    /// RFC3339；平台/权限拿不到时为 null。
    pub modified: Option<String>,
}

/// 目录树响应。
#[derive(Debug, Serialize)]
pub struct DataPlaneTreeView {
    /// 工作根（页面用来告诉人「这是哪份目录」）。
    pub work_dir: String,
    /// 按路径排序的条目；目录在前置位（见 [`DataPlaneRoot::list`]）。
    pub entries: Vec<DataPlaneEntryView>,
    /// 条目数触顶：只列了前 [`MAX_TREE_ENTRIES`] 条。
    pub truncated: bool,
}

/// 单个文件的响应。
#[derive(Debug, Serialize)]
pub struct DataPlaneFileView {
    pub path: String,
    pub size: u64,
    pub modified: Option<String>,
    /// 超过 [`MAX_CONTENT_BYTES`]：`content` 只是前缀。
    pub truncated: bool,
    /// 不是合法 UTF-8：不返回正文（配置/规则应当是文本；二进制多半是挂错了目录）。
    pub binary: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// 读文件失败的分类（映射到不同 HTTP 状态，别把「路径非法」报成 500）。
#[derive(Debug)]
enum ReadError {
    /// 路径不合法（绝对路径 / `..` / 不在白名单 / 符号链接逃逸）。
    InvalidPath(String),
    NotFound,
    NotAFile,
    /// 不是可读文本（二进制输出，或扩展名不在文本白名单里）。
    NotText,
    Io(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(detail) => write!(f, "invalid path: {detail}"),
            Self::NotFound => write!(f, "not found"),
            Self::NotAFile => write!(f, "not a file"),
            Self::NotText => write!(f, "not a text file"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

/// 输出目录里的一个文本文件。
#[derive(Debug, Serialize)]
pub struct DataPlaneOutputFileView {
    /// 相对输出目录的路径，一律 `/` 分隔。
    pub path: String,
    pub size: u64,
    /// RFC3339；平台/权限拿不到时为 null。
    pub modified: Option<String>,
}

/// 输出目录列表。
#[derive(Debug, Serialize)]
pub struct DataPlaneOutputFilesView {
    /// 输出目录（容器内路径；页面用来告诉人「这是哪份目录」）。
    pub dir: String,
    /// 输出目录是否存在。
    ///
    /// `false` 只说明目录不在（可能数据面还没写、也可能网关没挂载输出卷），
    /// 由页面按「还没写出文件 / 没挂载」两种口径分别提示，不在这里当 404。
    pub available: bool,
    pub files: Vec<DataPlaneOutputFileView>,
    /// 条目数触顶：只列了前 [`MAX_OUTPUT_FILES`] 条。
    pub truncated: bool,
}

/// 一次 tail 的分片。
#[derive(Debug, Serialize)]
pub struct DataPlaneOutputChunkView {
    pub path: String,
    pub dir: String,
    /// 本次返回内容在文件里的起始字节偏移。
    ///
    /// 首次 tail 会从「最后 N 字节」开始，并跳到下一行的行首 —— 这里可能是非零值，
    /// 页面据此提示「更早的内容没有加载」。
    pub offset: u64,
    /// 下一次请求应带的偏移（`offset + content` 的字节数）。
    pub next_offset: u64,
    pub size: u64,
    pub modified: Option<String>,
    pub content: String,
    /// 本次分片之后还有多少字节未读（文件在读取期间继续增长时也可能非零）。
    pub pending_after: u64,
    /// 客户端给的偏移已经超过文件大小：文件被轮转/截断，已从新文件开头重读。
    pub reset: bool,
}

/// 工作根（已 canonical，所有检查都以它为准）。
struct DataPlaneRoot {
    root: PathBuf,
    /// 配置里写的路径（未 canonical）：页面展示用，与 `docker-compose` 里的挂载点对得上。
    display: String,
}

impl DataPlaneRoot {
    fn open(configured: &Path) -> io::Result<Self> {
        let root = fs::canonicalize(configured)?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                format!("{} is not a directory", configured.display()),
            ));
        }
        Ok(Self {
            root,
            display: configured.display().to_string(),
        })
    }

    /// 列出白名单根下的文件与目录（目录在前、同级按名字排序；不展开符号链接）。
    ///
    /// 返回 `(entries, truncated)`：`truncated` 表示条目数触顶（只列了前
    /// [`MAX_TREE_ENTRIES`] 条）。
    fn list(&self) -> (Vec<DataPlaneEntryView>, bool) {
        let mut entries = Vec::new();
        let mut truncated = false;
        for name in ALLOWED_ROOTS {
            let path = self.root.join(name);
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_dir() || meta.file_type().is_symlink() {
                continue;
            }
            entries.push(entry_view(name, "dir", &meta));
            self.walk(&path, 1, &mut entries, &mut truncated);
            if truncated {
                break;
            }
        }
        if !truncated {
            for name in ALLOWED_FILES {
                let path = self.root.join(name);
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.is_file() && !meta.file_type().is_symlink() {
                    entries.push(entry_view(name, "file", &meta));
                }
            }
        }
        entries.sort_by(|left, right| {
            // 目录在前：先比 kind，再比路径。名字排序用字符序即可（全是 ASCII 配置名）。
            let rank = |kind: &str| if kind == "dir" { 0 } else { 1 };
            rank(left.kind)
                .cmp(&rank(right.kind))
                .then_with(|| left.path.cmp(&right.path))
        });
        (entries, truncated)
    }

    /// 递归收集（`depth` 为当前层，根目录自己由调用方压入）。
    fn walk(
        &self,
        dir: &Path,
        depth: usize,
        out: &mut Vec<DataPlaneEntryView>,
        truncated: &mut bool,
    ) {
        if depth >= MAX_TREE_DEPTH {
            return;
        }
        let Ok(read_dir) = fs::read_dir(dir) else {
            return;
        };
        let mut children: Vec<_> = read_dir.filter_map(Result::ok).collect();
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            if out.len() >= MAX_TREE_ENTRIES {
                *truncated = true;
                return;
            }
            let Ok(file_type) = child.file_type() else {
                continue;
            };
            // 符号链接一律不进树：它可能指向工作根之外（identity/、宿主任意路径）。
            if file_type.is_symlink() {
                continue;
            }
            let path = child.path();
            let Ok(rel) = path.strip_prefix(&self.root) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            let Ok(meta) = child.metadata() else {
                continue;
            };
            if file_type.is_dir() {
                out.push(entry_view(&rel, "dir", &meta));
                self.walk(&path, depth + 1, out, truncated);
                if *truncated {
                    return;
                }
            } else if file_type.is_file() {
                out.push(entry_view(&rel, "file", &meta));
            }
        }
    }

    /// 读一个文件（路径必须先过白名单与逃逸检查）。
    fn read(&self, rel: &str) -> Result<DataPlaneFileView, ReadError> {
        let path = self.resolve(rel)?;
        let meta = fs::metadata(&path).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        if !meta.is_file() {
            return Err(ReadError::NotAFile);
        }
        let size = meta.len();
        let modified = meta.modified().ok().map(format_time);

        let mut buf = Vec::with_capacity(MAX_CONTENT_BYTES.min(size) as usize + 4);
        fs::File::open(&path)
            .and_then(|file| file.take(MAX_CONTENT_BYTES + 1).read_to_end(&mut buf))
            .map_err(ReadError::Io)?;
        let truncated = buf.len() as u64 > MAX_CONTENT_BYTES;
        if truncated {
            buf.truncate(MAX_CONTENT_BYTES as usize);
        }

        // 文本判定：合法 UTF-8 才返回正文。截断可能把多字节字符切开 —— 这时退到
        // 合法边界仍按文本返回（`error_len() == None` 表示「尾部不完整」）。
        let content = match std::str::from_utf8(&buf) {
            Ok(text) => Some(text.to_string()),
            Err(err) if truncated && err.error_len().is_none() && err.valid_up_to() > 0 => Some(
                std::str::from_utf8(&buf[..err.valid_up_to()])
                    .unwrap_or_default()
                    .to_string(),
            ),
            Err(_) => None,
        };

        Ok(DataPlaneFileView {
            path: rel.to_string(),
            size,
            modified,
            truncated,
            binary: content.is_none(),
            content,
        })
    }

    /// 把相对路径解析成工作根下的真实路径；任何一步不合规都拒绝。
    fn resolve(&self, rel: &str) -> Result<PathBuf, ReadError> {
        let rel = rel.trim();
        let candidate = validate_relative(rel)?;
        let mut first: Option<&str> = None;
        for component in candidate.components() {
            if let Component::Normal(part) = component {
                first = Some(
                    part.to_str()
                        .ok_or_else(|| ReadError::InvalidPath("non-UTF-8 path".to_string()))?,
                );
                break;
            }
        }
        let Some(first) = first else {
            return Err(ReadError::InvalidPath("empty path".to_string()));
        };
        let is_allowed = ALLOWED_ROOTS.contains(&first) || ALLOWED_FILES.contains(&rel);
        if !is_allowed {
            return Err(ReadError::InvalidPath(format!(
                "{first} is not one of the browsable entries"
            )));
        }

        let canonical = fs::canonicalize(self.root.join(rel)).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        // 逃逸检查：canonical 必须仍在工作根内，且**顶层分量**仍属白名单
        // （`conf/x -> ../../identity/...` 会通过「在根内」但顶层已不是 conf）。
        let stripped = canonical
            .strip_prefix(&self.root)
            .map_err(|_| ReadError::InvalidPath("path escapes the work dir".to_string()))?;
        let Some(Component::Normal(top)) = stripped.components().next() else {
            return Err(ReadError::InvalidPath(
                "path escapes the work dir".to_string(),
            ));
        };
        let top = top.to_str().unwrap_or_default();
        let still_allowed = ALLOWED_ROOTS.contains(&top) || ALLOWED_FILES.contains(&rel);
        if !still_allowed {
            return Err(ReadError::InvalidPath(
                "symlink escapes the browsable roots".to_string(),
            ));
        }
        Ok(canonical)
    }

    /// 当前输出目录（`data/out_dat` 优先，其次 `data/out_data`）。
    fn output_dir(&self) -> Option<PathBuf> {
        OUTPUT_DIRS.iter().find_map(|rel| {
            let path = self.root.join(rel);
            let meta = fs::symlink_metadata(&path).ok()?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return None;
            }
            let canonical = fs::canonicalize(&path).ok()?;
            if canonical.starts_with(&self.root) {
                Some(canonical)
            } else {
                None
            }
        })
    }

    /// 输出目录的展示路径（目录不存在时给出「预期位置」）。
    fn output_dir_display(&self) -> String {
        self.output_dir()
            .unwrap_or_else(|| self.root.join(OUTPUT_DIRS[0]))
            .display()
            .to_string()
    }

    /// 列出输出目录下的文本文件（递归、不展开符号链接）。
    ///
    /// 顶层目录**不可读**要当错误回：`walk_output` 会静默跳过读不动的子目录，
    /// 若顶层也吞掉，页面就会把「权限没对齐」误报成「数据面还没写出文件」。
    fn output_files(&self) -> Result<DataPlaneOutputFilesView, ReadError> {
        let Some(dir) = self.output_dir() else {
            return Ok(DataPlaneOutputFilesView {
                dir: self.output_dir_display(),
                available: false,
                files: Vec::new(),
                truncated: false,
            });
        };
        if let Err(err) = fs::read_dir(&dir) {
            // 目录在 canonicalize 之后消失：当作「还没写出文件」，不要回 500。
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(DataPlaneOutputFilesView {
                    dir: dir.display().to_string(),
                    available: false,
                    files: Vec::new(),
                    truncated: false,
                });
            }
            return Err(ReadError::Io(err));
        }
        let mut files = Vec::new();
        let mut truncated = false;
        let mut scanned = 0usize;
        walk_output(&dir, &dir, 1, &mut files, &mut truncated, &mut scanned);
        // 最近写过的排前面：页面默认选中第一个，应该是最活跃的那份输出。
        files.sort_by(|left, right| {
            right
                .modified
                .cmp(&left.modified)
                .then_with(|| left.path.cmp(&right.path))
        });
        Ok(DataPlaneOutputFilesView {
            dir: dir.display().to_string(),
            available: true,
            files,
            truncated,
        })
    }

    /// 从 `offset` 开始读一段输出文本。
    ///
    /// `offset = None` 表示「首次 tail」：从文件尾部取 `max_bytes` 窗口，并跳到下一行的
    /// 行首（不把半行、半个多字节字符当成正文）。之后调用方应把返回的 `next_offset` 带回来。
    fn tail_output(
        &self,
        rel: &str,
        offset: Option<u64>,
        max_bytes: u64,
    ) -> Result<DataPlaneOutputChunkView, ReadError> {
        let (dir, path) = self.resolve_output(rel)?;
        // 回给前端的 path 用相对输出目录的规范形状（把 `./` / 重复分隔符收掉），
        // 与文件列表里的 path 对得上，前端才能按 `?file=` 选中同一项。
        let rel = path
            .strip_prefix(&dir)
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| rel.trim().to_string());
        // 打开与取元数据都可能撞上「刚被轮转掉」：那时是 404，不是 500。
        let mut file = fs::File::open(&path).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        let meta = file.metadata().map_err(ReadError::Io)?;
        let size = meta.len();
        let modified = meta.modified().ok().map(format_time);

        let mut reset = false;
        let initial = offset.is_none();
        // 轮转检测只看大小：新文件若一上来就比旧偏移更大，这里察觉不到。栈当前没有
        // 给 file sink 配 `max_size` 滚动，所以这不是已知路径；将来启用滚动时，
        // 需要把 inode / mtime 一并带回来做判据，不能只看 size。
        let mut start = match offset {
            Some(value) if value <= size => value,
            Some(_) => {
                // 文件被截断 / 换成了更小的新文件：`tail -f` 会重新从新文件开头读，
                // 这里如实标记，页面据此清屏。
                reset = true;
                0
            }
            None => size.saturating_sub(max_bytes),
        };

        let mut bytes = read_window(&mut file, start, max_bytes)?;
        if initial && start > 0 && !is_line_start(&mut file, start) {
            if let Some(pos) = bytes.iter().position(|byte| *byte == b'\n') {
                start += (pos + 1) as u64;
                bytes.drain(..=pos);
            } else {
                // 整个窗口里没有换行：说明文件是一条超长行。从文件头读，避免把行切在中间。
                start = 0;
                bytes = read_window(&mut file, 0, max_bytes)?;
            }
        }

        let (content, consumed) = decode_text(&bytes)?;
        let next_offset = start + consumed as u64;
        Ok(DataPlaneOutputChunkView {
            path: rel,
            dir: dir.display().to_string(),
            offset: start,
            next_offset,
            size,
            modified,
            content,
            pending_after: size.saturating_sub(next_offset),
            reset,
        })
    }

    /// 只允许输出目录下的文本文件（并做与 [`DataPlaneRoot::resolve`] 同一套逃逸检查）。
    fn resolve_output(&self, rel: &str) -> Result<(PathBuf, PathBuf), ReadError> {
        let rel = rel.trim();
        validate_relative(rel)?;
        let dir = self.output_dir().ok_or(ReadError::NotFound)?;
        let name = Path::new(rel)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ReadError::InvalidPath("non-UTF-8 path".to_string()))?;
        if !is_text_output_name(name) {
            return Err(ReadError::NotText);
        }
        let canonical = fs::canonicalize(dir.join(rel)).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        if !canonical.starts_with(&dir) {
            return Err(ReadError::InvalidPath(
                "path escapes the output dir".to_string(),
            ));
        }
        // 目录也可以叫 `foo.json`：先确认是普通文件，避免把 EISDIR 报成 500。
        let meta = fs::metadata(&canonical).map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => ReadError::NotFound,
            _ => ReadError::Io(err),
        })?;
        if !meta.is_file() {
            return Err(ReadError::NotAFile);
        }
        Ok((dir, canonical))
    }
}

/// 相对路径的公共校验：拒绝绝对路径 / `..` / 反斜杠 / NUL。
fn validate_relative(rel: &str) -> Result<&Path, ReadError> {
    if rel.is_empty() {
        return Err(ReadError::InvalidPath("empty path".to_string()));
    }
    if rel.contains('\\') || rel.contains('\0') {
        return Err(ReadError::InvalidPath(
            "path must not contain backslashes or NUL".to_string(),
        ));
    }
    let candidate = Path::new(rel);
    if candidate.is_absolute() {
        return Err(ReadError::InvalidPath("absolute path".to_string()));
    }
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            // `.` 无意义但无害；`..` / 根 / 盘符一律拒。
            Component::CurDir => {}
            _ => return Err(ReadError::InvalidPath("path traversal".to_string())),
        }
    }
    Ok(candidate)
}

/// `offset` 是不是行首（文件开头，或前一个字节是 `\n`）。
///
/// 首次 tail 只有「从半行开始」时才需要往后跳到下一行；本来就从行首开始时要保留整行
/// —— 否则窗口恰好从最后一行开头时，会把唯一那一行也跳掉。
fn is_line_start(file: &mut fs::File, offset: u64) -> bool {
    if offset == 0 {
        return true;
    }
    let mut previous = [0u8; 1];
    file.seek(SeekFrom::Start(offset - 1))
        .and_then(|_| file.read_exact(&mut previous))
        .is_ok()
        && previous[0] == b'\n'
}

/// 读 `offset` 起的 `max_bytes` 字节。
fn read_window(file: &mut fs::File, offset: u64, max_bytes: u64) -> Result<Vec<u8>, ReadError> {
    file.seek(SeekFrom::Start(offset)).map_err(ReadError::Io)?;
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024) as usize);
    file.by_ref()
        .take(max_bytes)
        .read_to_end(&mut bytes)
        .map_err(ReadError::Io)?;
    Ok(bytes)
}

/// 按 UTF-8 解码一段窗口；窗口尾部可能截断一个多字节字符，只消费完整字符。
///
/// 返回 `(正文, 已消费字节数)`。中间出现非法字节 = 不是文本（二进制输出），直接拒。
fn decode_text(bytes: &[u8]) -> Result<(String, usize), ReadError> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok((text.to_string(), bytes.len())),
        // `error_len() == None` = 只是尾部不完整：返回合法前缀，下一次从断点继续。
        Err(err) if err.error_len().is_none() => {
            let valid = err.valid_up_to();
            let text = std::str::from_utf8(&bytes[..valid])
                .map_err(|_| ReadError::NotText)?
                .to_string();
            Ok((text, valid))
        }
        Err(_) => Err(ReadError::NotText),
    }
}

/// 输出文件是否属于可读文本（按扩展名判断，大小写不敏感）。
fn is_text_output_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TEXT_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// 递归收集输出目录下的文本文件；符号链接一律不进树（可能指向目录外）。
fn walk_output(
    dir: &Path,
    base: &Path,
    depth: usize,
    out: &mut Vec<DataPlaneOutputFileView>,
    truncated: &mut bool,
    scanned: &mut usize,
) {
    if depth > MAX_OUTPUT_DEPTH {
        return;
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<_> = read_dir.filter_map(Result::ok).collect();
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        if out.len() >= MAX_OUTPUT_FILES || *scanned >= MAX_OUTPUT_SCAN_ENTRIES {
            *truncated = true;
            return;
        }
        *scanned += 1;
        let Ok(file_type) = child.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = child.path();
        let Ok(rel) = path.strip_prefix(base) else {
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let Ok(meta) = child.metadata() else {
            continue;
        };
        if file_type.is_dir() {
            walk_output(&path, base, depth + 1, out, truncated, scanned);
            if *truncated {
                return;
            }
        } else if file_type.is_file() && is_text_output_name(&rel) {
            out.push(DataPlaneOutputFileView {
                path: rel,
                size: meta.len(),
                modified: meta.modified().ok().map(format_time),
            });
        }
    }
}

fn entry_view(path: &str, kind: &'static str, meta: &fs::Metadata) -> DataPlaneEntryView {
    DataPlaneEntryView {
        path: path.to_string(),
        kind,
        size: if kind == "file" { meta.len() } else { 0 },
        modified: meta.modified().ok().map(format_time),
    }
}

fn format_time(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339()
}

/// 配置里的工作根 → 可读的工作根；未配置 / 读不到统一回 503。
// 返回 ApiError 让两个处理函数共用同一条映射；`ApiError` 本身偏大，与仓内其它
// handler 一样用 allow 压掉 lint（见 agent_ops / preflight）。
#[allow(clippy::result_large_err)]
fn open_root(state: &ApiState) -> Result<DataPlaneRoot, ApiError> {
    let Some(configured) = state.config.data_plane_work_dir.as_deref() else {
        return Err(ApiError::unavailable(
            codes::DATA_PLANE_UNAVAILABLE,
            "data plane work dir is not configured",
        ));
    };
    DataPlaneRoot::open(configured).map_err(|err| {
        ApiError::unavailable(
            codes::DATA_PLANE_UNAVAILABLE,
            format!(
                "data plane work dir {} is not readable: {err}",
                configured.display()
            ),
        )
    })
}

/// `GET /api/v1/admin/data-plane/files`：白名单根下的目录树。
pub async fn list_data_plane_files(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let root = match open_root(&state) {
        Ok(root) => root,
        Err(err) => return err.into_response(),
    };
    let (entries, truncated) = root.list();
    Json(DataPlaneTreeView {
        work_dir: root.display,
        entries,
        truncated,
    })
    .into_response()
}

/// `GET /api/v1/admin/data-plane/file?path=conf/wparse.toml`：读单个文本文件。
#[derive(Debug, Deserialize)]
pub struct DataPlaneFileQuery {
    pub path: String,
}

/// `GET /api/v1/admin/data-plane/output/files`：输出目录（wparse file sink）里的文本文件。
pub async fn list_data_plane_outputs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let root = match open_root(&state) {
        Ok(root) => root,
        Err(err) => return err.into_response(),
    };
    match root.output_files() {
        Ok(view) => Json(view).into_response(),
        // 目录不存在已经由 `output_files` 折成 `available=false`；走到这里的都是
        // 「读不动」（权限 / IO），要显形，不能伪装成「还没有文件」。
        Err(err) => ApiError::internal(
            codes::DATA_PLANE_READ_FAILED,
            "failed to read data plane output directory",
            err,
        )
        .into_response(),
    }
}

/// `GET /api/v1/admin/data-plane/output/tail?path=gateway.json&offset=…&max_bytes=…`。
#[derive(Debug, Deserialize)]
pub struct DataPlaneOutputTailQuery {
    pub path: String,
    /// 上次返回的 `next_offset`；省略 = 首次 tail（取文件尾部窗口）。
    pub offset: Option<u64>,
    /// 单次最多返回多少字节（默认 256 KiB，夹到 1 KiB..1 MiB）。
    pub max_bytes: Option<u64>,
}

pub async fn tail_data_plane_output(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<DataPlaneOutputTailQuery>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let root = match open_root(&state) {
        Ok(root) => root,
        Err(err) => return err.into_response(),
    };
    let max_bytes = query
        .max_bytes
        .unwrap_or(DEFAULT_TAIL_BYTES)
        .clamp(1024, MAX_TAIL_BYTES);
    match root.tail_output(&query.path, query.offset, max_bytes) {
        Ok(view) => Json(view).into_response(),
        Err(ReadError::InvalidPath(detail)) => ApiError::bad_request(
            codes::DATA_PLANE_PATH_INVALID,
            format!("invalid output path: {detail}"),
        )
        .into_response(),
        Err(ReadError::NotFound) => ApiError::not_found(
            codes::DATA_PLANE_FILE_NOT_FOUND,
            format!("output file not found: {}", query.path),
        )
        .into_response(),
        Err(ReadError::NotAFile) => ApiError::bad_request(
            codes::DATA_PLANE_PATH_INVALID,
            format!("not a file: {}", query.path),
        )
        .into_response(),
        Err(ReadError::NotText) => ApiError::bad_request(
            codes::DATA_PLANE_FILE_NOT_TEXT,
            format!("not a readable text output: {}", query.path),
        )
        .into_response(),
        Err(ReadError::Io(err)) => ApiError::internal(
            codes::DATA_PLANE_READ_FAILED,
            "failed to read data plane output",
            err,
        )
        .into_response(),
    }
}

pub async fn read_data_plane_file(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<DataPlaneFileQuery>,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let root = match open_root(&state) {
        Ok(root) => root,
        Err(err) => return err.into_response(),
    };
    match root.read(&query.path) {
        Ok(view) => Json(view).into_response(),
        Err(ReadError::InvalidPath(detail)) => ApiError::bad_request(
            codes::DATA_PLANE_PATH_INVALID,
            format!("invalid data plane path: {detail}"),
        )
        .into_response(),
        Err(ReadError::NotFound) => ApiError::not_found(
            codes::DATA_PLANE_FILE_NOT_FOUND,
            format!("data plane file not found: {}", query.path),
        )
        .into_response(),
        Err(ReadError::NotAFile) => ApiError::bad_request(
            codes::DATA_PLANE_PATH_INVALID,
            format!("not a file: {}", query.path),
        )
        .into_response(),
        // `read` 不区分二进制（它用 `binary` 字段表达），但错误类型是共用的。
        Err(ReadError::NotText) => ApiError::bad_request(
            codes::DATA_PLANE_FILE_NOT_TEXT,
            format!("not a readable text file: {}", query.path),
        )
        .into_response(),
        Err(ReadError::Io(err)) => ApiError::internal(
            codes::DATA_PLANE_READ_FAILED,
            "failed to read data plane file",
            err,
        )
        .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::unique_temp_dir;

    fn with_root<T>(f: impl FnOnce(&DataPlaneRoot, &Path) -> T) -> T {
        let dir = unique_temp_dir("wist-data-plane");
        fs::create_dir_all(dir.join("conf")).unwrap();
        fs::create_dir_all(dir.join("topology/sinks")).unwrap();
        fs::write(dir.join("conf/wparse.toml"), "version = \"1.0\"\n").unwrap();
        fs::write(dir.join("wparse.local.toml"), "[admin_api]\n").unwrap();
        let root = DataPlaneRoot::open(&dir).expect("open root");
        f(&root, &dir)
    }

    #[test]
    fn lists_allowlisted_entries_only() {
        with_root(|root, dir| {
            fs::write(dir.join("secret.txt"), "nope").unwrap();
            let (entries, truncated) = root.list();
            assert!(!truncated);
            let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
            assert!(paths.contains(&"conf"));
            assert!(paths.contains(&"conf/wparse.toml"));
            assert!(paths.contains(&"topology"));
            assert!(paths.contains(&"topology/sinks"));
            assert!(paths.contains(&"wparse.local.toml"));
            assert!(!paths.iter().any(|p| p.contains("secret")));
        });
    }

    #[test]
    fn reads_allowlisted_text_file() {
        with_root(|root, _| {
            let file = root.read("conf/wparse.toml").expect("read");
            assert_eq!(file.content.as_deref(), Some("version = \"1.0\"\n"));
            assert!(!file.binary);
            assert!(!file.truncated);
        });
    }

    #[test]
    fn rejects_traversal_absolute_and_non_allowlisted_paths() {
        with_root(|root, _| {
            for bad in [
                "../etc/passwd",
                "/etc/passwd",
                "conf/../../etc/passwd",
                "conf\\wparse.toml",
                "secret.txt",
                "",
            ] {
                assert!(
                    matches!(root.read(bad), Err(ReadError::InvalidPath(_))),
                    "{bad:?} should be rejected"
                );
            }
            assert!(matches!(
                root.read("conf/nope.toml"),
                Err(ReadError::NotFound)
            ));
            assert!(matches!(root.read("conf"), Err(ReadError::NotAFile)));
        });
    }

    #[test]
    fn truncates_large_files_at_a_char_boundary() {
        with_root(|root, dir| {
            let mut payload = "中".repeat((MAX_CONTENT_BYTES as usize) + 8);
            payload.push_str("tail");
            fs::write(dir.join("conf/big.toml"), payload).unwrap();
            let file = root.read("conf/big.toml").expect("read");
            assert!(file.truncated);
            let content = file.content.expect("text");
            assert!(content.len() <= MAX_CONTENT_BYTES as usize);
            assert!(content.chars().all(|ch| ch == '中'));
        });
    }

    #[test]
    fn binary_files_are_flagged_without_content() {
        with_root(|root, dir| {
            fs::write(dir.join("conf/blob.toml"), [0xff, 0xfe, 0x00]).unwrap();
            let file = root.read("conf/blob.toml").expect("read");
            assert!(file.binary);
            assert!(file.content.is_none());
        });
    }

    fn with_output_root<T>(f: impl FnOnce(&DataPlaneRoot, &Path) -> T) -> T {
        with_root(|root, dir| {
            let out = dir.join("data/out_dat");
            fs::create_dir_all(&out).unwrap();
            f(root, dir)
        })
    }

    #[test]
    fn missing_output_dir_is_unavailable_not_an_error() {
        with_root(|root, _| {
            let listing = root.output_files().expect("list");
            assert!(!listing.available);
            assert!(listing.files.is_empty());
            assert!(listing.dir.ends_with("data/out_dat"), "got {}", listing.dir);
        });
    }

    #[test]
    fn lists_only_text_output_files() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            fs::write(out.join("gateway.json"), "{}\n").unwrap();
            fs::write(out.join("agent.log"), "line\n").unwrap();
            fs::write(out.join("blob.bin"), [0xff, 0x00]).unwrap();
            fs::create_dir_all(out.join("nested")).unwrap();
            fs::write(out.join("nested/host.jsonl"), "{}\n").unwrap();

            let listing = root.output_files().expect("list");
            assert!(listing.available);
            let paths: Vec<&str> = listing
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect();
            assert!(paths.contains(&"gateway.json"));
            assert!(paths.contains(&"agent.log"));
            assert!(paths.contains(&"nested/host.jsonl"));
            assert!(!paths.contains(&"blob.bin"));
        });
    }

    #[test]
    fn tail_returns_the_last_lines_then_only_new_bytes() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            let path = out.join("gateway.json");
            fs::write(&path, "one\ntwo\nthree\n").unwrap();

            let first = root
                .tail_output("gateway.json", None, 8)
                .expect("first tail");
            assert_eq!(first.content, "three\n");
            assert_eq!(first.offset, 8);
            assert_eq!(first.next_offset, 14);
            assert_eq!(first.pending_after, 0);
            assert!(!first.reset);

            let mut handle = fs::OpenOptions::new().append(true).open(&path).unwrap();
            use std::io::Write as _;
            handle.write_all(b"four\n").unwrap();

            let second = root
                .tail_output("gateway.json", Some(first.next_offset), 8)
                .expect("second tail");
            assert_eq!(second.content, "four\n");
            assert_eq!(second.offset, 14);
            assert_eq!(second.next_offset, 19);
            assert!(!second.reset);
        });
    }

    #[test]
    fn initial_tail_keeps_a_line_that_starts_at_the_window_boundary() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            fs::write(out.join("gateway.log"), "one\ntwo\n").unwrap();
            // 窗口正好从第二行行首开始：不能把唯一那一行也跳掉。
            let tail = root.tail_output("gateway.log", None, 4).expect("tail");
            assert_eq!(tail.content, "two\n");
            assert_eq!(tail.offset, 4);
        });
    }

    #[test]
    fn tail_does_not_split_a_utf8_character() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            let path = out.join("gateway.log");
            fs::write(&path, "中\n").unwrap();

            // 窗口刚好 1 字节：切在多字节字符中间。首次 tail 会跳到下一行；
            // 若从中间偏移继续，则应只返回空正文且不消费半个字符。
            let first = root.tail_output("gateway.log", None, 4).expect("tail");
            assert_eq!(first.content, "中\n");

            let partial = root
                .tail_output("gateway.log", Some(0), 1)
                .expect("partial tail");
            assert_eq!(partial.content, "");
            assert_eq!(partial.next_offset, 0);
        });
    }

    #[test]
    fn tail_resets_when_the_file_shrinks() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            let path = out.join("gateway.json");
            fs::write(&path, "0123456789\n").unwrap();
            let first = root.tail_output("gateway.json", None, 1024).expect("tail");
            assert_eq!(first.next_offset, 11);

            fs::write(&path, "abc\n").unwrap();
            let reset = root
                .tail_output("gateway.json", Some(first.next_offset), 1024)
                .expect("reset tail");
            assert!(reset.reset);
            assert_eq!(reset.offset, 0);
            assert_eq!(reset.content, "abc\n");
        });
    }

    #[test]
    fn tail_rejects_non_text_and_escaped_paths() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            fs::write(out.join("blob.bin"), [0xff, 0xfe]).unwrap();
            assert!(matches!(
                root.tail_output("blob.bin", None, 1024),
                Err(ReadError::NotText)
            ));
            // 目录也可以是 `*.json`：要回 NotAFile，而不是把 EISDIR 当 500。
            fs::create_dir_all(out.join("looks-like.json")).unwrap();
            assert!(matches!(
                root.tail_output("looks-like.json", None, 1024),
                Err(ReadError::NotAFile)
            ));
            for bad in [
                "../conf/wparse.toml",
                "/etc/passwd",
                "out_dat\\gateway.json",
            ] {
                assert!(
                    matches!(
                        root.tail_output(bad, None, 1024),
                        Err(ReadError::InvalidPath(_))
                    ),
                    "{bad:?} should be rejected"
                );
            }
        });
    }

    #[test]
    #[cfg(unix)]
    fn output_symlinks_are_not_followed_out_of_the_dir() {
        with_output_root(|root, dir| {
            let out = dir.join("data/out_dat");
            let outside = unique_temp_dir("wist-data-plane-output-outside");
            fs::write(outside.join("secret.log"), "nope").unwrap();
            std::os::unix::fs::symlink(outside.join("secret.log"), out.join("link.log")).unwrap();
            assert!(
                !root
                    .output_files()
                    .expect("list")
                    .files
                    .iter()
                    .any(|f| f.path == "link.log")
            );
            assert!(matches!(
                root.tail_output("link.log", None, 1024),
                Err(ReadError::InvalidPath(_))
            ));
        });
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_are_not_followed_out_of_the_work_dir() {
        with_root(|root, dir| {
            let outside = unique_temp_dir("wist-data-plane-outside");
            fs::write(outside.join("secret.txt"), "nope").unwrap();
            std::os::unix::fs::symlink(outside.join("secret.txt"), dir.join("conf/link.toml"))
                .unwrap();
            // 树里不出现
            assert!(!root.list().0.iter().any(|e| e.path == "conf/link.toml"));
            // 直接读也被拒（逃逸检查）
            let err = root.read("conf/link.toml").expect_err("must reject");
            assert!(matches!(err, ReadError::InvalidPath(_)));
        });
    }
}
