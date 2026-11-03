use ring::rand as ring_rand;

pub fn new_secret_token(prefix: &str) -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    let rng = ring_rand::SystemRandom::new();
    ring_rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| "failed to read system random source".to_string())?;
    Ok(format!("{prefix}_{}", hex_lower(&bytes)))
}

/// 短 admin token（10 位随机字母数字）——demo/开发便捷用，非生产安全强度（可被暴力枚举）。
pub fn new_admin_token() -> Result<String, String> {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
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

/// 字节 sha256（裸 hex）。口径与中心 / 安装包**同一份**（共享 crate `wist-release`），不再各写一遍。
pub fn bytes_sha256_hex(bytes: &[u8]) -> String {
    wist_release::package::sha256_hex_bytes(bytes)
}

/// 裸 hex（小写），给随机 token 用。
fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_sha256_hex_matches_the_known_vector() {
        // 实现转发到共享 crate（`wist-release`）—— 这条就盯「转出去了、值还对」。
        assert_eq!(
            bytes_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex("abc"), bytes_sha256_hex(b"abc"));
    }

    #[test]
    fn new_secret_token_carries_the_prefix_and_32_random_bytes_of_hex() {
        let token = new_secret_token("link").expect("token");
        assert!(token.starts_with("link_"));
        assert_eq!(token.len(), "link_".len() + 64);
        assert!(
            token["link_".len()..]
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        );
        assert_ne!(token, new_secret_token("link").expect("token"));
    }
}
