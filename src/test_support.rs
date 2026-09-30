//! 测试期定位**跨仓数据**：策展知识（`wist-knowledge`）与 jumo 模型（`wist-design`）。
//!
//! 这两份数据住在别的仓，本 crate 只**读**、不在仓里留副本（留副本就是两份真相）。
//! 定位顺序：`<仓名>_DIR` 环境变量（如 `WIST_KNOWLEDGE_DIR`）优先，否则按候选位置找
//! （相对 `CARGO_MANIFEST_DIR` 起算，所以从哪个目录跑 `cargo test` 都一样）。
//!
//! **缺数据就失败**。以前这里写的是「文件不在就 `return`」，于是这些用例在 CI 里
//! 一次都没真正跑过：测试是绿的，但什么都没验（假绿）。宁可红，不要空绿。

use std::path::{Path, PathBuf};

/// 知识库仓。CI 与本地都是网关仓的同级。
const KNOWLEDGE_DIRS: &[&str] = &["../wist-knowledge"];

/// 模型仓。CI 摆成同级；本地开发仓组里它在上一级（`x-topology/wist-design`）。
const DESIGN_DIRS: &[&str] = &["../wist-design", "../../wist-design"];

/// 定位一个跨仓目录；找不到直接 panic 并列出试过哪几处。
fn locate_repo(name: &str, candidates: &[&str]) -> PathBuf {
    let key = format!("{}_DIR", name.replace('-', "_").to_uppercase());
    if let Some(value) = std::env::var_os(&key) {
        let dir = PathBuf::from(value);
        assert!(dir.is_dir(), "`{key}` 指向的目录不存在：{}", dir.display());
        return dir;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut tried = Vec::new();
    for candidate in candidates {
        let dir = root.join(candidate);
        if dir.is_dir() {
            return dir;
        }
        tried.push(dir.display().to_string());
    }
    panic!(
        "找不到同级仓 `{name}`；已试：\n  {}\n  \
         把仓 checkout 到上面任一处，或设 `{key}` 指向它。\n  \
         CI 布局见 .github/workflows/build-and-test.yml",
        tried.join("\n  ")
    );
}

fn require_file(path: PathBuf) -> PathBuf {
    assert!(path.is_file(), "数据文件缺失：{}", path.display());
    path
}

/// 知识库仓（`wist-knowledge`）里的一份策展数据。
pub(crate) fn knowledge_file(name: &str) -> PathBuf {
    require_file(locate_repo("wist-knowledge", KNOWLEDGE_DIRS).join(name))
}

/// jumo 模型仓（`wist-design`）里的一份模型文件。
pub(crate) fn model_file(relative: &str) -> PathBuf {
    require_file(locate_repo("wist-design", DESIGN_DIRS).join(relative))
}
