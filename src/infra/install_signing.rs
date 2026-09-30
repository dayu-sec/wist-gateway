use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};

const PEM_BEGIN_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END_PRIVATE_KEY: &str = "-----END PRIVATE KEY-----";
const ED25519_PUBLIC_KEY_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Cache the decoded signing key pair keyed by the key file's mtime/size, so the
/// public install endpoints do not re-read and re-parse the PEM on every request.
#[allow(clippy::type_complexity)]
static SIGNING_KEY_CACHE: Mutex<Option<(PathBuf, SystemTime, u64, Arc<Ed25519KeyPair>)>> =
    Mutex::new(None);

pub fn load_install_script_public_key_pem(path: &Path) -> Result<String, String> {
    let key_pair = load_install_script_signing_key_pair(path)?;
    Ok(ed25519_public_key_pem(key_pair.public_key().as_ref()))
}

pub fn sign_install_script(path: &Path, script: &[u8]) -> Result<Vec<u8>, String> {
    let key_pair = load_install_script_signing_key_pair(path)?;
    Ok(key_pair.sign(script).as_ref().to_vec())
}

/// Generate a fresh ed25519 PKCS#8 private key PEM at `path` (mode 0600).
pub fn generate_install_script_signing_key(path: &Path) -> Result<(), String> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|err| format!("failed to generate install script signing key: {err}"))?;
    fs::write(path, private_key_pem(pkcs8.as_ref())).map_err(|err| {
        format!(
            "failed to write install script signing key {}: {err}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn private_key_pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let wrapped = wrap_base64_lines(&encoded, 64);
    format!("-----BEGIN PRIVATE KEY-----\n{wrapped}-----END PRIVATE KEY-----\n")
}

fn load_install_script_signing_key_pair(path: &Path) -> Result<Arc<Ed25519KeyPair>, String> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        format!(
            "failed to stat install script signing key {}: {err}",
            path.display()
        )
    })?;
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let len = metadata.len();
    {
        let cache = SIGNING_KEY_CACHE
            .lock()
            .map_err(|_| "install script signing key cache poisoned".to_string())?;
        if let Some((cached_path, cached_modified, cached_len, key)) = cache.as_ref()
            && cached_path == path
            && *cached_modified == modified
            && *cached_len == len
        {
            return Ok(Arc::clone(key));
        }
    }

    let pem = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read install script signing key {}: {err}",
            path.display()
        )
    })?;
    let der = decode_private_key_pem(&pem)?;
    let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|err| {
        format!(
            "invalid install script signing key {}: {err}",
            path.display()
        )
    })?;
    let key_pair = Arc::new(key_pair);
    let mut cache = SIGNING_KEY_CACHE
        .lock()
        .map_err(|_| "install script signing key cache poisoned".to_string())?;
    *cache = Some((path.to_path_buf(), modified, len, Arc::clone(&key_pair)));
    Ok(key_pair)
}

fn decode_private_key_pem(pem: &str) -> Result<Vec<u8>, String> {
    let begin = pem
        .find(PEM_BEGIN_PRIVATE_KEY)
        .ok_or_else(|| "install script signing key must be a PKCS#8 PEM private key".to_string())?;
    let pem = &pem[begin + PEM_BEGIN_PRIVATE_KEY.len()..];
    let end = pem.find(PEM_END_PRIVATE_KEY).ok_or_else(|| {
        "install script signing key must end with a PKCS#8 PEM footer".to_string()
    })?;
    let body = &pem[..end];
    let body: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
    if body.is_empty() {
        return Err("install script signing key PEM body is empty".to_string());
    }
    STANDARD
        .decode(body)
        .map_err(|err| format!("failed to decode install script signing key PEM: {err}"))
}

fn ed25519_public_key_pem(public_key: &[u8]) -> String {
    let mut der = Vec::with_capacity(ED25519_PUBLIC_KEY_SPKI_PREFIX.len() + public_key.len());
    der.extend_from_slice(&ED25519_PUBLIC_KEY_SPKI_PREFIX);
    der.extend_from_slice(public_key);
    encode_pem("PUBLIC KEY", &der)
}

/// 解析 Ed25519 **公钥** PEM（SPKI）。
///
/// 用途与安装脚本那把相反：安装签名是**网关签、目标主机验**（私钥在网关，公钥下发）；
/// 内容包签名是**发布方签、网关验**（私钥在发布 CI，公钥在网关配置里）。
/// 两边都只用一个密钥，不做多密钥共存。
pub fn parse_ed25519_public_key_pem(pem: &str) -> Result<Vec<u8>, String> {
    const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
    const END: &str = "-----END PUBLIC KEY-----";
    let begin = pem.find(BEGIN).ok_or_else(|| {
        "public key must be an SPKI PEM (`-----BEGIN PUBLIC KEY-----`)".to_string()
    })?;
    let rest = &pem[begin + BEGIN.len()..];
    let end = rest
        .find(END)
        .ok_or_else(|| "public key PEM is missing its footer".to_string())?;
    let body: String = rest[..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("public key PEM body is empty".to_string());
    }
    let der = STANDARD
        .decode(body)
        .map_err(|err| format!("failed to decode public key PEM: {err}"))?;
    let Some(raw) = der.strip_prefix(ED25519_PUBLIC_KEY_SPKI_PREFIX.as_slice()) else {
        return Err("public key is not an Ed25519 SPKI key".to_string());
    };
    if raw.len() != 32 {
        return Err(format!(
            "Ed25519 public key must be 32 bytes, found {}",
            raw.len()
        ));
    }
    Ok(raw.to_vec())
}

/// 验签（Ed25519）。签名格式错了、密钥不对、被改过一个字节，都返回 `false`。
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// 公钥指纹（sha256 前 16 位 hex）：审计里用来指认"当时信的是哪把钥匙"。
///
/// 只有一个密钥时它是个常量，但它把"这套网关当时信哪把钥匙"钉进了每一行包里 ——
/// 换钥匙后回头看旧行，能看出它们是被不同锚接受的。
pub fn public_key_fingerprint(public_key: &[u8]) -> String {
    let digest = crate::infra::bytes_sha256_hex(public_key);
    digest.chars().take(16).collect()
}

/// 测试专用：把裸公钥包成 SPKI PEM。
#[cfg(test)]
pub(crate) fn ed25519_public_key_pem_for_tests(public_key: &[u8]) -> String {
    ed25519_public_key_pem(public_key)
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let wrapped = wrap_base64_lines(&encoded, 64);
    format!("-----BEGIN {label}-----\n{wrapped}-----END {label}-----\n")
}

fn wrap_base64_lines(value: &str, width: usize) -> String {
    let mut output = String::new();
    for chunk in value.as_bytes().chunks(width) {
        output.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_pem_round_trips() {
        let raw = [7u8; 32];
        let pem = ed25519_public_key_pem(&raw);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(
            parse_ed25519_public_key_pem(&pem).expect("parse"),
            raw.to_vec()
        );
    }

    #[test]
    fn rejects_pem_that_is_not_an_ed25519_spki_key() {
        // 合法 PEM，但 DER 不是 Ed25519 SPKI（前缀不对）。
        let pem = encode_pem("PUBLIC KEY", &[0x30, 0x03, 0x02, 0x01, 0x01]);
        let err = parse_ed25519_public_key_pem(&pem).expect_err("must refuse");
        assert!(err.contains("not an Ed25519"), "{err}");

        // 连 PEM 都不是。
        let err = parse_ed25519_public_key_pem("not a pem").expect_err("must refuse");
        assert!(err.contains("SPKI PEM"), "{err}");
    }

    #[test]
    fn verifies_only_the_matching_signature() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        let public = key_pair.public_key().as_ref().to_vec();
        let message = b"deadbeef";
        let signature = key_pair.sign(message).as_ref().to_vec();
        assert!(verify_ed25519(&public, message, &signature));
        assert!(!verify_ed25519(&public, b"deadbeee", &signature));

        let mut other = public.clone();
        other[0] ^= 0x01;
        assert!(!verify_ed25519(&other, message, &signature));
    }
}
