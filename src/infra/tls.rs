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
    let (certs, key) = load_server_cert_and_key(cert_path, key_path)?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("invalid TLS certificate or private key: {err}"))
}

/// 构建**开启 mTLS** 的服务端 TLS 配置：以 `agent_ca_pem` 为 client 验证信任锚。
///
/// 客户端证书是**可选**的（`allow_unauthenticated`）：
///
/// - **首次注册**的 agent 还没有证书，强制要求会在握手就把它挡在外面；
/// - 「无证书」不等于「未鉴权」——注册靠 bootstrap token，其余 agent 面路由由应用层
///   `authenticate_agent` **只凭客户端证书**判定（bearer 双轨已删，见
///   `docs/design/agent-identity-mtls.md` §5.2）。
///
/// 出示了证书就一定会被验证（链 + 有效期 + `EKU=clientAuth`）；有证书但验不过，握手仍会失败。
pub fn load_agent_mtls_server_config(
    cert_path: &Path,
    key_path: &Path,
    agent_ca_pem: &str,
) -> Result<ServerConfig, String> {
    install_crypto_provider();
    let (certs, key) = load_server_cert_and_key(cert_path, key_path)?;
    let mut roots = rustls::RootCertStore::empty();
    for anchor in certificate_chain_from_pem(agent_ca_pem)? {
        roots
            .add(anchor)
            .map_err(|err| format!("failed to add agent CA trust anchor: {err}"))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|err| format!("failed to build agent client verifier: {err}"))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| format!("invalid TLS certificate or private key: {err}"))
}

/// 从**已完成握手**的服务端连接里取出已验证的客户端叶证书 DER。
///
/// `None` = 该连接没出示客户端证书（没开 mTLS 的监听上恒为 `None`）。
/// 这是「库丢失后首触重建登记」的入口：拿到证书就能从 URI SAN 认出 `agent_id`。
pub fn peer_leaf_certificate_der(conn: &rustls::server::ServerConnection) -> Option<Vec<u8>> {
    conn.peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| leaf.as_ref().to_vec())
}

fn load_server_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
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
    Ok((certs, key))
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

/// 用 rustls 的**客户端**校验器验证一条**服务端证书链**，信任锚**单独给**。
///
/// 与 [`verify_certificate_as_rustls_client`] 的区别是模拟的形态不同：
///   · 那个：信任锚就是叶证书本身（dev 自签证书的形态）；
///   · 这个：**真实部署**的形态 —— agent 的 `trust_bundle` 里是 **CA 根**，
///     网关发出去的是 CA 签的叶证书（可带中间证书）。
///
/// 判据必须走这条路径：用「自签证书当锚」的校验器去验 CA 签的叶证书会得
/// `UnknownIssuer`（叶的签发者不在信任锚里），而 OpenSSL / curl 未必这么判。
pub fn verify_chain_as_rustls_client(
    chain_pem: &str,
    anchor_pem: &str,
    server_name: &str,
) -> Result<(), String> {
    install_crypto_provider();
    let chain = certificate_chain_from_pem(chain_pem)?;
    let Some((leaf, intermediates)) = chain.split_first() else {
        return Err("certificate chain is empty".to_string());
    };

    let mut roots = rustls::RootCertStore::empty();
    for anchor in certificate_chain_from_pem(anchor_pem)? {
        roots
            .add(anchor)
            .map_err(|err| format!("failed to add trust anchor: {err}"))?;
    }
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
    ///
    /// 注意：这条只模拟「信任锚就是叶证书本身」的形态（dev 自签证书）。
    /// CA 签的叶证书要走 [`rustls_accepts_gateway_chain`]。
    #[test]
    #[ignore = "depends on a locally generated dev certificate"]
    fn rustls_accepts_gateway_certificate() {
        // dev 态网关 home：`<栈根>/dev/configs/gateway`（本 crate 的兄弟目录 `wist-gateway-stack`）。
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = std::env::var("WIST_GATEWAY_TLS_CERT").unwrap_or_else(|_| {
            format!("{manifest}/../wist-gateway-stack/dev/configs/gateway/state/admin-tls.crt.pem")
        });
        let server_name = std::env::var("WIST_GATEWAY_TLS_SERVER_NAME")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let pem = fs::read_to_string(&path).expect("read gateway certificate");

        match verify_certificate_as_rustls_client(&pem, &server_name) {
            Ok(()) => println!("rustls ACCEPTS {path} for {server_name}"),
            Err(err) => panic!("rustls REJECTS {path} for {server_name}: {err}"),
        }
    }

    /// 诊断用：模拟**真实部署**的判定 —— 信任锚是一个**单独的 CA 根**（agent 的 `trust_bundle`），
    /// 被验证的是网关发出去的那条链（`dev/setup-domain.sh` 生成的形态）。
    ///
    ///   cargo test --offline --lib -- --ignored rustls_accepts_gateway_chain --nocapture
    ///
    /// 可用 `WIST_GATEWAY_TLS_CHAIN` / `WIST_GATEWAY_TLS_ANCHOR` / `WIST_GATEWAY_TLS_SERVER_NAME`
    /// 覆盖；`WIST_GATEWAY_TLS_ANCHOR` 缺省优先取 `state/dev-ca.crt.pem`（在则用它），
    /// 否则回落成链里的第一张（等价于自签形态）。
    #[test]
    #[ignore = "depends on a locally generated dev certificate"]
    fn rustls_accepts_gateway_chain() {
        let home = std::env::var("HOME").unwrap_or_default();
        let chain_path = std::env::var("WIST_GATEWAY_TLS_CHAIN")
            .unwrap_or_else(|_| format!("{home}/.wist-gateway/state/admin-tls.crt.pem"));
        let anchor_path = std::env::var("WIST_GATEWAY_TLS_ANCHOR").unwrap_or_else(|_| {
            let ca = format!("{home}/.wist-gateway/state/dev-ca.crt.pem");
            if Path::new(&ca).exists() {
                ca
            } else {
                chain_path.clone()
            }
        });
        let server_name = std::env::var("WIST_GATEWAY_TLS_SERVER_NAME")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let chain = fs::read_to_string(&chain_path).expect("read gateway certificate chain");
        let anchor = fs::read_to_string(&anchor_path).expect("read trust anchor");

        match verify_chain_as_rustls_client(&chain, &anchor, &server_name) {
            Ok(()) => println!(
                "rustls ACCEPTS chain {chain_path} under anchor {anchor_path} for {server_name}"
            ),
            Err(err) => panic!(
                "rustls REJECTS chain {chain_path} under anchor {anchor_path} for {server_name}: {err}"
            ),
        }
    }

    // ── mTLS 链路 spike（M3 的唯一未知点：服务端能否从连接里拿到已验客户端证书）──

    use crate::infra::agent_ca::{
        AgentCa, AgentCertificateIdentity, DEFAULT_CLIENT_CERT_TTL_SECONDS,
        agent_identity_from_certificate_der,
    };
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn write_temp_pem(prefix: &str, content: &str) -> std::path::PathBuf {
        static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "wist-gateway-tls-{}-{}-{prefix}.pem",
            std::process::id(),
            NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, content).expect("write temp pem");
        path
    }

    /// 独立 agent CA + 一张用它签出的客户端证书（附客户端私钥 DER）。
    fn agent_ca_with_client_cert() -> (
        String,
        Vec<u8>,
        PrivateKeyDer<'static>,
        AgentCertificateIdentity,
    ) {
        let mut ca_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Wist Test Agent CA");
        ca_params.distinguished_name = dn;
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let ca_pem = ca_cert.pem();
        let ca = AgentCa::from_pem(&ca_pem, &ca_key.serialize_pem()).expect("load ca");

        let client_key = KeyPair::generate().expect("client key");
        let csr_pem = CertificateParams::default()
            .serialize_request(&client_key)
            .expect("csr")
            .pem()
            .expect("csr pem");
        let identity = AgentCertificateIdentity::new("tenant-default", "env-default", "agent-mtls");
        let issued = ca
            .issue_client_certificate(&csr_pem, &identity, DEFAULT_CLIENT_CERT_TTL_SECONDS)
            .expect("issue");
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));
        (ca_pem, issued.certificate_der, key_der, identity)
    }

    /// 服务端叶证书（自签，SAN=localhost）+ 一个已完成握手的监听。
    async fn spawn_mtls_server(
        ca_pem: &str,
    ) -> (
        tokio::task::JoinHandle<Result<Vec<u8>, String>>,
        std::net::SocketAddr,
        Vec<u8>,
    ) {
        let rcgen::CertifiedKey {
            cert: server_cert,
            key_pair: server_key,
        } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("server cert");
        let cert_path = write_temp_pem("server-cert", &server_cert.pem());
        let key_path = write_temp_pem("server-key", &server_key.serialize_pem());
        let server_config =
            load_agent_mtls_server_config(&cert_path, &key_path, ca_pem).expect("server config");
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let (stream, _) = listener.accept().await.map_err(|err| err.to_string())?;
            let tls = acceptor
                .accept(stream)
                .await
                .map_err(|err| format!("handshake: {err}"))?;
            peer_leaf_certificate_der(tls.get_ref().1)
                .ok_or_else(|| "server saw no client certificate".to_string())
        });
        (handle, addr, server_cert.der().to_vec())
    }

    fn client_roots(server_der: Vec<u8>) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(server_der))
            .expect("server anchor");
        roots
    }

    #[tokio::test]
    async fn mtls_server_reports_verified_client_certificate_identity() {
        install_crypto_provider();
        let (ca_pem, client_der, client_key, identity) = agent_ca_with_client_cert();
        let (server, addr, server_der) = spawn_mtls_server(&ca_pem).await;

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(client_roots(server_der))
            .with_client_auth_cert(vec![CertificateDer::from(client_der)], client_key)
            .expect("client config");
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let _tls = TlsConnector::from(Arc::new(client_config))
            .connect(
                rustls_pki_types::ServerName::try_from("localhost").expect("server name"),
                stream,
            )
            .await
            .expect("client handshake");

        let leaf = server
            .await
            .expect("join")
            .expect("server must see the client certificate");
        // 服务端从连接里读回的证书，能还原出 agent 身份 —— M3 的入口成立。
        assert_eq!(
            agent_identity_from_certificate_der(&leaf).expect("identity"),
            identity
        );
    }

    /// 没有客户端证书的连接**握手照样成**（首次注册的 agent 还没证书），
    /// 服务端只是看不到证书 —— 由应用层回 401。
    #[tokio::test]
    async fn mtls_server_accepts_client_without_certificate_but_sees_none() {
        install_crypto_provider();
        let (ca_pem, _client_der, _client_key, _identity) = agent_ca_with_client_cert();
        let (server, addr, server_der) = spawn_mtls_server(&ca_pem).await;

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(client_roots(server_der))
            .with_no_client_auth();
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let _ = TlsConnector::from(Arc::new(client_config))
            .connect(
                rustls_pki_types::ServerName::try_from("localhost").expect("server name"),
                stream,
            )
            .await;

        // 首次注册就是这条路径：还没证书。握手成、但服务端看不到客户端身份。
        let outcome = server.await.expect("join");
        assert_eq!(
            outcome,
            Err("server saw no client certificate".to_string()),
            "unauthenticated connections stay unauthenticated"
        );
    }
}
