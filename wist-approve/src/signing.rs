//! 签发私钥 / 公钥的读写与签名。
//!
//! 钥匙永远不出这台机器：`load` 只读本地文件，`sign` 只在内存里做。
//! 私钥文件必须是 **0600**（其他用户有任何权限就拒绝加载）—— 与网关自签形态
//! 对 `[plan_signing] key_file` 的要求同源（`docs/design/plan-attestation.md` §7.1）。

use std::fs;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use wist_contracts::action_plan::ActionPlanAttestation;
use zeroize::Zeroize;

/// 公钥指纹长度（hex 字符数）。与网关 `/approver-keys`、agentd 锚展示的口径一致。
const FINGERPRINT_LEN: usize = 16;

/// 一把审批钥匙：私钥 + 由公钥派生的 `key_id`。
pub struct ApproverKey {
    key_pair: Ed25519KeyPair,
    /// `ed25519-<指纹>`：确定性派生，操作员不需要手抄（手抄就会写错）。
    ///
    /// 它同时是 agentd 锚目录里的文件名、网关登记表的主键、`attestation.key_id`。
    key_id: String,
    fingerprint: String,
    public_pem: String,
}

impl std::fmt::Debug for ApproverKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 私钥永远不进 Debug：日志里顺手打一下配置是常见事故。
        f.debug_struct("ApproverKey")
            .field("key_id", &self.key_id)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl ApproverKey {
    /// 生成一把新钥匙，并把私钥以 0600 写到 `path`。
    ///
    /// 已存在就拒绝（`force = false`）：**覆盖一把正在用的钥匙**会让机器那边
    /// 的锚静默失效，必须由人明确决定。
    pub fn generate_to(path: &Path, force: bool) -> Result<Self, String> {
        if path.exists() && !force {
            return Err(format!(
                "{} already exists; refusing to overwrite a key that may be pinned on agents (use --force)",
                path.display()
            ));
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "failed to generate an Ed25519 key".to_string())?;
        let mut der = pkcs8.as_ref().to_vec();
        let key = Self::from_pkcs8_der(&der)?;
        der.zeroize();

        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        let pem = pkcs8_pem(&pkcs8.as_ref().to_vec());
        write_private(path, &pem)?;
        Ok(key)
    }

    /// 从本地文件加载（权限不合规直接拒绝）。
    pub fn load_from(path: &Path) -> Result<Self, String> {
        let metadata = fs::metadata(path)
            .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
        require_private_permissions(path, &metadata)?;
        let pem = fs::read_to_string(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        Self::from_pkcs8_pem(&pem)
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, String> {
        let der = parse_pem(pem, "PRIVATE KEY")?;
        Self::from_pkcs8_der(&der)
    }

    fn from_pkcs8_der(der: &[u8]) -> Result<Self, String> {
        let key_pair = Ed25519KeyPair::from_pkcs8(der).map_err(|err| {
            format!("not a valid Ed25519 PKCS#8 key (ring cannot parse it): {err}")
        })?;
        let public = key_pair.public_key().as_ref().to_vec();
        let fingerprint = fingerprint_of(&public);
        Ok(Self {
            key_pair,
            key_id: format!("ed25519-{fingerprint}"),
            fingerprint,
            public_pem: spki_pem(&public),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// SPKI PEM（公开信息）：登记到网关、钉到 agentd 锚的都是它。
    pub fn public_pem(&self) -> &str {
        &self.public_pem
    }

    /// 给一份（已填好除签名外全部字段的）证明签名。
    ///
    /// 只签 `signing_payload()` —— 那是 `wist-contracts` 定义的规范字节，
    /// 与 agentd 验签时重算的完全同一套规则。
    pub fn sign(&self, attestation: &mut ActionPlanAttestation) {
        let signature = self.key_pair.sign(&attestation.signing_payload());
        attestation.signature = signature
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
    }

    /// 签完自检：用**本机的公钥**验一遍。不通过就不该发出去。
    pub fn verify(&self, attestation: &ActionPlanAttestation) -> bool {
        let Ok(der) = parse_pem(&self.public_pem, "PUBLIC KEY") else {
            return false;
        };
        let Some(raw) = der.strip_prefix(ED25519_PUBLIC_KEY_SPKI_PREFIX.as_slice()) else {
            return false;
        };
        let Some(signature) = hex_decode(&attestation.signature) else {
            return false;
        };
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, raw)
            .verify(&attestation.signing_payload(), &signature)
            .is_ok()
    }
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = (bytes[index] as char).to_digit(16)?;
        let lo = (bytes[index + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        index += 2;
    }
    Some(out)
}

/// 指纹：DER(公钥) 的 sha256 前 16 位 hex。
///
/// 与网关 `/approver-keys` 返回的 `fingerprint`、agentd 文档里的口径一致；
/// 页面与 CLI 人工核对的就是这串。
pub fn fingerprint_of(public_key: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, public_key);
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(FINGERPRINT_LEN)
        .collect()
}

const ED25519_PUBLIC_KEY_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// 从公钥 PEM 算指纹（仅测试用：生产路径从裸公钥字节算，少一次解析）。
#[cfg(test)]
fn fingerprint_of_pem(pem: &str) -> Result<String, String> {
    let der = parse_pem(pem, "PUBLIC KEY")?;
    let Some(raw) = der.strip_prefix(ED25519_PUBLIC_KEY_SPKI_PREFIX.as_slice()) else {
        return Err("public key is not an Ed25519 SPKI key".to_string());
    };
    Ok(fingerprint_of(raw))
}

fn spki_pem(public_key: &[u8]) -> String {
    let mut der = Vec::with_capacity(ED25519_PUBLIC_KEY_SPKI_PREFIX.len() + public_key.len());
    der.extend_from_slice(&ED25519_PUBLIC_KEY_SPKI_PREFIX);
    der.extend_from_slice(public_key);
    encode_pem("PUBLIC KEY", &der)
}

fn pkcs8_pem(der: &[u8]) -> String {
    encode_pem("PRIVATE KEY", der)
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut wrapped = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push('\n');
    }
    format!("-----BEGIN {label}-----\n{wrapped}-----END {label}-----\n")
}

fn parse_pem(pem: &str, label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| format!("PEM is missing `{begin}`"))?;
    let rest = &pem[start + begin.len()..];
    let stop = rest
        .find(&end)
        .ok_or_else(|| format!("PEM is missing `{end}`"))?;
    let body: String = rest[..stop]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("PEM body is empty".to_string());
    }
    STANDARD
        .decode(body)
        .map_err(|err| format!("failed to decode PEM body: {err}"))
}

#[cfg(not(unix))]
fn require_private_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn require_private_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is accessible by group/other (mode {:o}); chmod 600 it before use",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, pem: &str) -> Result<(), String> {
    fs::write(path, pem).map_err(|err| format!("failed to write {}: {err}", path.display()))
}

#[cfg(unix)]
fn write_private(path: &Path, pem: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // 先以 0600 建文件再写：不给任何一瞬的 world-readable 窗口。
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    file.write_all(pem.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trips_and_key_id_is_derived_from_the_public_key() {
        let dir = std::env::temp_dir().join(format!("wist-approve-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("site.key");
        let key = ApproverKey::generate_to(&path, false).expect("generate");
        assert!(key.key_id().starts_with("ed25519-"));
        assert_eq!(key.key_id().len(), "ed25519-".len() + FINGERPRINT_LEN);
        assert_eq!(
            fingerprint_of_pem(key.public_pem()).expect("fp"),
            key.fingerprint()
        );

        let loaded = ApproverKey::load_from(&path).expect("load");
        assert_eq!(loaded.key_id(), key.key_id());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_to_overwrite_an_existing_key_without_force() {
        let dir = std::env::temp_dir().join(format!("wist-approve-force-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("site.key");
        ApproverKey::generate_to(&path, false).expect("first");
        let err = ApproverKey::generate_to(&path, false).expect_err("must refuse");
        assert!(err.contains("already exists"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn force_overwrites_an_existing_key() {
        let dir = std::env::temp_dir().join(format!("wist-approve-force2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("site.key");
        let first = ApproverKey::generate_to(&path, false).expect("first");
        let second = ApproverKey::generate_to(&path, true).expect("force");
        assert_ne!(first.key_id(), second.key_id(), "--force 会换钥匙");
        assert_eq!(
            ApproverKey::load_from(&path).expect("load").key_id(),
            second.key_id()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pem_parser_rejects_wrong_labels_and_missing_footers() {
        let key = ApproverKey::generate_to(
            &std::env::temp_dir().join(format!(
                "wist-approve-pem-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )),
            true,
        )
        .expect("generate");
        // 公钥 PEM 当私钥解析：必须报错（不然会用错钥匙签）。
        let err = ApproverKey::from_pkcs8_pem(key.public_pem()).expect_err("must refuse");
        assert!(err.contains("PRIVATE KEY"), "{err}");

        // 缺 footer。
        let broken = key.public_pem().replace("-----END PUBLIC KEY-----", "");
        let err = ApproverKey::from_pkcs8_pem(&broken).expect_err("must refuse");
        assert!(err.contains("PRIVATE KEY"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_key_file_with_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wist-approve-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("site.key");
        let key = ApproverKey::generate_to(&path, false).expect("generate");
        assert!(!key.public_pem().is_empty());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = ApproverKey::load_from(&path).expect_err("must refuse");
        assert!(err.contains("chmod 600"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
