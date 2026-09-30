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

/// 测试专用：用知识仓里的**真实**五份数据造一个知识库制品 tar.gz。
///
/// 形状与 `wist-knowledge/scripts/package.sh` 一致（顶层一层 `<名>-<版本>/` +
/// 自描述的 `manifest.json`）—— 这样"打包侧产出的东西网关能不能吃下"就有了回归位。
/// 想验真制品本身看 `app::knowledge` 里那条 `#[ignore]` 的 e2e。
#[cfg(test)]
pub(crate) fn knowledge_package_tarball(root: &Path, tamper_catalog: bool) -> PathBuf {
    const SUFFIX: &str = "9.9.9-test";
    let package_name = format!("wist-knowledge-{SUFFIX}");
    let stage = root.join("stage").join(&package_name);
    std::fs::create_dir_all(&stage).expect("create stage");
    let mut digests = std::collections::BTreeMap::new();
    for name in crate::app::knowledge::PACKAGE_FILES {
        let bytes = std::fs::read(knowledge_file(name)).expect("read real knowledge data");
        // 摘要按**原字节**算，内容再（可选地）改 —— 模拟“打包之后被人改过”。
        digests.insert(name, crate::infra::bytes_sha256_hex(&bytes));
        let written = if tamper_catalog && name == "catalog.toml" {
            let mut tampered = bytes.clone();
            tampered.extend_from_slice(b"\n# tampered\n");
            tampered
        } else {
            bytes
        };
        std::fs::write(stage.join(name), written).expect("write package file");
    }
    let manifest = serde_json::json!({
        "name": crate::app::knowledge::PACKAGE_NAME,
        "version": SUFFIX,
        "created_at": "2026-09-30T00:00:00Z",
        "commit": "deadbee",
        "content_versions": {
            "catalog_version": 2,
            "template_version": [1],
            "policy_version": 1,
            "purpose_version": 1,
        },
        "files": digests,
    });
    std::fs::write(
        stage.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let tarball = root.join(format!("{package_name}.tar.gz"));
    let file = std::fs::File::create(&tarball).expect("create tarball");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    builder
        .append_dir_all(&package_name, &stage)
        .expect("append package dir");
    builder
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip");
    tarball
}

/// 测试专用：一把 Ed25519 签名密钥（私钥 PEM 落盘 + 裸公钥 + 公钥 PEM）。
///
/// 与发布侧同一套约定：**用私钥签 `sha256_hex` 的 ASCII 字节**（见 `wist-knowledge/scripts/package.sh`）。
#[cfg(test)]
pub(crate) fn knowledge_signing_key(root: &Path) -> TestSigningKey {
    use ring::{
        rand as ring_rand,
        signature::{Ed25519KeyPair, KeyPair},
    };

    let rng = ring_rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate signing key");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse signing key");
    let private_key = root.join("knowledge-signing.pkcs8.pem");
    std::fs::write(
        &private_key,
        crate::test_support::pem("PRIVATE KEY", pkcs8.as_ref()),
    )
    .expect("write private key");
    let public_raw = key_pair.public_key().as_ref().to_vec();
    let public_pem_path = root.join("knowledge-signing.pub.pem");
    std::fs::write(
        &public_pem_path,
        crate::infra::ed25519_public_key_pem_for_tests(&public_raw),
    )
    .expect("write public key");
    TestSigningKey {
        private_key,
        public_pem_path,
        public_raw,
    }
}

/// 测试用的签名密钥三件：私钥路径（签）、公钥 PEM 路径（配给网关）、裸公钥（断言用）。
#[cfg(test)]
pub(crate) struct TestSigningKey {
    pub private_key: PathBuf,
    pub public_pem_path: PathBuf,
    pub public_raw: Vec<u8>,
}

/// 测试专用：按发布侧同一约定，为制品写出 `<tarball>.sig`（base64 一行）。
#[cfg(test)]
pub(crate) fn sign_knowledge_package(tarball: &Path, private_key: &Path) -> PathBuf {
    use base64::Engine as _;
    use ring::signature::Ed25519KeyPair;

    let bytes = std::fs::read(tarball).expect("read tarball");
    let sha256 = crate::infra::bytes_sha256_hex(&bytes);
    let pem = std::fs::read_to_string(private_key).expect("read private key");
    let der = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let der = base64::engine::general_purpose::STANDARD
        .decode(der)
        .expect("decode private key");
    let key_pair = Ed25519KeyPair::from_pkcs8(&der).expect("parse private key");
    let signature = key_pair.sign(sha256.as_bytes());
    // 发布侧就是同名的 `.sig` 后缀。
    let sig_path = PathBuf::from(format!("{}.sig", tarball.display()));
    std::fs::write(
        &sig_path,
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
        ),
    )
    .expect("write signature");
    sig_path
}

/// 测试专用：把 DER 包成 PEM（一行 64 字符）。
#[cfg(test)]
pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

/// 测试专用：一个自增的临时目录（并行用例不会撞名）。
#[cfg(test)]
pub(crate) fn unique_temp_dir(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}
