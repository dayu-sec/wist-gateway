//! 数据面（wparse）配置与规则的**只读浏览**。
//!
//! 数据面的工作根（宿主 `data-plane-run/work`）以只读方式挂在网关容器里
//! （compose：`- ${WPARSE_RUN_WORK}:/data-plane:ro`），这里把它开放给管理面页面：
//! 一份目录树 + 按路径读单个文本文件。用途是「页面直接看到数据面现在吃的是哪份
//! conf / topology / connectors / models」，不用 SSH 到宿主。
//!
//! 安全边界（这个端点能读文件，边界必须写在代码里，不能靠调用方自觉）：
//!   - 只允许白名单根 [`ALLOWED_ROOTS`] 与白名单文件 [`ALLOWED_FILES`]；
//!   - 拒绝绝对路径 / `..` / 反斜杠；`canonicalize` 之后必须仍在工作根内**且**第一个
//!     路径分量仍属白名单——挡住 `conf/x -> ../../identity/...` 这类符号链接逃逸；
//!   - 目录树里**不展开**符号链接；
//!   - 单文件有返回上限，超出只返回前缀并标 `truncated`；
//!   - 非 UTF-8（二进制）不返回正文，只标 `binary`；
//!   - 全部只读：本模块没有任何写路径。
//!
//! 未配置（没挂载）时回 503 —— 与 content / discovery-policies 未配置同一约定。
//!
//! 不在 jumo 静态模型 binding.mju 的声明里，与 host_metrics / pipeline / content
//! 同一模式。重新生成控制面代码时需回补本模块与 `mod.rs` 里的两条路由。

use std::fs;
use std::io::{self, Read};
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
    Io(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(detail) => write!(f, "invalid path: {detail}"),
            Self::NotFound => write!(f, "not found"),
            Self::NotAFile => write!(f, "not a file"),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
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
        let mut first: Option<&str> = None;
        for component in candidate.components() {
            match component {
                Component::Normal(part) => {
                    if first.is_none() {
                        first = part.to_str();
                        if first.is_none() {
                            return Err(ReadError::InvalidPath("non-UTF-8 path".to_string()));
                        }
                    }
                }
                // `.` 无意义但无害；`..` / 根 / 盘符一律拒。
                Component::CurDir => {}
                _ => return Err(ReadError::InvalidPath("path traversal".to_string())),
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
