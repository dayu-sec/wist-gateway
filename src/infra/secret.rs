use ring::{digest, rand as ring_rand};

pub fn new_secret_token(prefix: &str) -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    let rng = ring_rand::SystemRandom::new();
    ring_rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| "failed to read system random source".to_string())?;
    Ok(format!("{prefix}_{}", hex_lower(&bytes)))
}

/// 短 admin token（10 位随机字母数字）——demo/开发便捷用，非生产安全强度（可被暴力枚举）。
pub fn new_admin_token() -> Result<String, String> {
    const CHARS: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut bytes = [0_u8; 10];
    let rng = ring_rand::SystemRandom::new();
    ring_rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| "failed to read system random source".to_string())?;
    Ok(bytes
        .iter()
        .map(|b| CHARS[*b as usize % CHARS.len()] as char)
        .collect())
}

pub fn sha256_hex(value: &str) -> String {
    bytes_sha256_hex(value.as_bytes())
}

pub fn bytes_sha256_hex(bytes: &[u8]) -> String {
    hex_lower(digest::digest(&digest::SHA256, bytes).as_ref())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
