use std::{fs, path::Path, sync::Arc};

use base64::Engine;
use rustls::ServerConfig;
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

use super::AdminConfig;

pub fn load_admin_tls_config(config: &AdminConfig) -> Result<ServerConfig, String> {
    load_rustls_server_config(&config.tls_cert_file, &config.tls_key_file)
}

pub fn load_rustls_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<ServerConfig, String> {
    install_crypto_provider();
    let cert_pem = fs::read_to_string(cert_path).map_err(|err| {
        format!(
            "failed to read TLS certificate {}: {err}",
            cert_path.display()
        )
    })?;
    let key_pem = fs::read_to_string(key_path).map_err(|err| {
        format!(
            "failed to read TLS private key {}: {err}",
            key_path.display()
        )
    })?;
    let certs = certificate_chain_from_pem(&cert_pem)?;
    let key = private_key_from_pem(&key_pem)?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("invalid TLS certificate or private key: {err}"))
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 用 rustls 的**客户端**校验器验证一张证书链。
///
/// 这等价于 Rust 客户端（包括 wist-agentd 经 `reqwest` + `add_root_certificate`）拿这张证书当
/// 信任锚去连本网关时的判定，**不等于 OpenSSL 的判定**：自签名证书「既当信任锚又当服务端叶证书」
/// 这类情形，二者结论可能不同。排查「客户端拒绝网关证书」时必须跑这条路径。
///
/// `cert_pem` 的第一张证书同时被当作信任锚与叶证书（这是网关 dev 自签证书的实际形态）。
pub fn verify_certificate_as_rustls_client(
    cert_pem: &str,
    server_name: &str,
) -> Result<(), String> {
    install_crypto_provider();
    let chain = certificate_chain_from_pem(cert_pem)?;
    let Some((leaf, intermediates)) = chain.split_first() else {
        return Err("certificate chain is empty".to_string());
    };

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(leaf.clone())
        .map_err(|err| format!("failed to add trust anchor: {err}"))?;
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| format!("failed to build verifier: {err}"))?;

    let name = rustls_pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|err| format!("invalid server name {server_name}: {err}"))?;

    verifier
        .verify_server_cert(
            leaf,
            intermediates,
            &name,
            &[],
            rustls_pki_types::UnixTime::now(),
        )
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn certificate_chain_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<_> = pem_sections(pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        return Err("TLS certificate file does not contain a CERTIFICATE PEM block".to_string());
    }
    Ok(certs)
}

fn private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    for (label, key) in [
        ("PRIVATE KEY", PrivateKeyKind::Pkcs8),
        ("RSA PRIVATE KEY", PrivateKeyKind::Pkcs1),
        ("EC PRIVATE KEY", PrivateKeyKind::Sec1),
    ] {
        let mut sections = pem_sections(pem, label)?;
        if let Some(der) = sections.pop() {
            return Ok(match key {
                PrivateKeyKind::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
                PrivateKeyKind::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
                PrivateKeyKind::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
            });
        }
    }
    Err("TLS private key file does not contain a supported PEM block".to_string())
}

enum PrivateKeyKind {
    Pkcs8,
    Pkcs1,
    Sec1,
}

fn pem_sections(pem: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let begin_marker = format!("-----BEGIN {label}-----");
    let end_marker = format!("-----END {label}-----");
    let mut rest = pem;
    let mut sections = Vec::new();
    while let Some(begin) = rest.find(&begin_marker) {
        let after_begin = &rest[begin + begin_marker.len()..];
        let Some(end) = after_begin.find(&end_marker) else {
            return Err(format!("unterminated {label} PEM block"));
        };
        let body = &after_begin[..end];
        let encoded: String = body.lines().map(str::trim).collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|err| format!("invalid base64 in {label} PEM block: {err}"))?;
        sections.push(der);
        rest = &after_begin[end + end_marker.len()..];
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_multiple_certificate_pem_sections() {
        let certs = certificate_chain_from_pem(
            r#"-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
BAUG
-----END CERTIFICATE-----
"#,
        )
        .expect("certs decode");

        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), &[1, 2, 3]);
        assert_eq!(certs[1].as_ref(), &[4, 5, 6]);
    }

    #[test]
    fn decodes_pkcs8_private_key_pem_section() {
        let key = private_key_from_pem(
            r#"-----BEGIN PRIVATE KEY-----
AQID
-----END PRIVATE KEY-----
"#,
        )
        .expect("key decodes");

        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
        assert_eq!(key.secret_der(), &[1, 2, 3]);
    }

    #[test]
    fn rejects_missing_certificate_pem_section() {
        let err = certificate_chain_from_pem("not a certificate").expect_err("missing cert");

        assert!(err.contains("CERTIFICATE PEM block"));
    }

    /// 诊断用：验证**正在使用的**网关证书能否被 rustls 客户端接受（agentd 走的就是这条路径）。
    ///
    /// 需要本机已生成的 dev 证书，不是 hermetic 测试，因此默认忽略。手工跑：
    ///   cargo test --offline --lib -- --ignored rustls_accepts_gateway_certificate --nocapture
    /// 可用 `WIST_GATEWAY_TLS_CERT` / `WIST_GATEWAY_TLS_SERVER_NAME` 覆盖。
    #[test]
    #[ignore = "depends on a locally generated dev certificate"]
    fn rustls_accepts_gateway_certificate() {
        let home = std::env::var("HOME").unwrap_or_default();
        let path = std::env::var("WIST_GATEWAY_TLS_CERT")
            .unwrap_or_else(|_| format!("{home}/.wist-gateway/state/admin-tls.crt.pem"));
        let server_name = std::env::var("WIST_GATEWAY_TLS_SERVER_NAME")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let pem = fs::read_to_string(&path).expect("read gateway certificate");

        match verify_certificate_as_rustls_client(&pem, &server_name) {
            Ok(()) => println!("rustls ACCEPTS {path} for {server_name}"),
            Err(err) => panic!("rustls REJECTS {path} for {server_name}: {err}"),
        }
    }
}
