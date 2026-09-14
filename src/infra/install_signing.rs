use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair};

const PEM_BEGIN_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END_PRIVATE_KEY: &str = "-----END PRIVATE KEY-----";
const ED25519_PUBLIC_KEY_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Cache the decoded signing key pair keyed by the key file's mtime/size, so the
/// public install endpoints do not re-read and re-parse the PEM on every request.
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
        if let Some((cached_path, cached_modified, cached_len, key)) = cache.as_ref() {
            if cached_path == path && *cached_modified == modified && *cached_len == len {
                return Ok(Arc::clone(key));
            }
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
