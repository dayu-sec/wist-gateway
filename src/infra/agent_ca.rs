//! Agent 客户端证书（mTLS）的签发与解析：独立 `agent-ca`。
//!
//! 设计见 `docs/design/agent-identity-mtls.md` §4 / §4.1 / §4.2。两条边界：
//!
//! - **签发忽略 CSR 的主体，只取公钥**：主体（URI SAN）由网关按稳定哈希 `agent_id` 填，
//!   这样 agent 无法伪造他人的身份（§4.2）。
//! - **解析只认 URI SAN**（`CN` 仅供人读），与签发格式严格一致。rustls-webpki 的
//!   `EndEntityCert` 只验链、取不到主体，所以这里用 `x509-parser` 直接读扩展（§4.2）。
//!
//! 本模块只负责「签发 / 解析」这一件事；接线（enroll 流程、mTLS 监听、拒绝名单）在其上。

use std::fmt;
use std::path::Path;

use rcgen::{
    Certificate, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// 客户端证书有效期缺省：37 天 = 保底 30 天 + 提前 7 天续期（§4.2）。
pub const DEFAULT_CLIENT_CERT_TTL_SECONDS: i64 = 37 * 24 * 60 * 60;
/// `notBefore` 回拨，容忍两端时钟偏差（§4.2）。
pub const CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS: i64 = 300;

/// URI SAN 前缀；完整形态 `spiffe://<tenant_id>/<environment_id>/agent/<agent_id>`。
const AGENT_URI_PREFIX: &str = "spiffe://";
/// URI SAN 里身份段前的固定标记。
const AGENT_URI_MARKER: &str = "/agent/";
/// 证书序列号长度（字节）：128 位随机。
const SERIAL_NUMBER_BYTES: usize = 16;

/// 证书 URI SAN 里承载的 agent 身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCertificateIdentity {
    pub tenant_id: String,
    pub environment_id: String,
    pub agent_id: String,
}

impl AgentCertificateIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        environment_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            environment_id: environment_id.into(),
            agent_id: agent_id.into(),
        }
    }
}

/// 拼出证书 URI SAN。
///
/// 签发与解析共用这一个函数，避免两处格式漂移（§4.2 的取值必须无歧义）。
pub fn agent_uri(identity: &AgentCertificateIdentity) -> String {
    format!(
        "{AGENT_URI_PREFIX}{}/{}{AGENT_URI_MARKER}{}",
        identity.tenant_id, identity.environment_id, identity.agent_id
    )
}

/// 从 URI SAN 还原身份；不是本系统的 agent URI（或缺段 / 多段）即报错。
pub fn parse_agent_uri(uri: &str) -> Result<AgentCertificateIdentity, String> {
    let rest = uri
        .strip_prefix(AGENT_URI_PREFIX)
        .ok_or_else(|| format!("agent URI must start with `{AGENT_URI_PREFIX}`: {uri}"))?;
    let (tenant_id, rest) = rest
        .split_once('/')
        .ok_or_else(|| format!("agent URI missing tenant segment: {uri}"))?;
    let (environment_id, agent_id) = rest
        .split_once(AGENT_URI_MARKER)
        .ok_or_else(|| format!("agent URI missing `{AGENT_URI_MARKER}` segment: {uri}"))?;
    if tenant_id.is_empty()
        || environment_id.is_empty()
        || agent_id.is_empty()
        || agent_id.contains('/')
    {
        return Err(format!(
            "agent URI has an empty or malformed segment: {uri}"
        ));
    }
    Ok(AgentCertificateIdentity::new(
        tenant_id,
        environment_id,
        agent_id,
    ))
}

/// 一次签发的产物。字段与 `wist-contracts::CredentialBundle` 的证书字段一一对应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedAgentCertificate {
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    /// 序列号（小写 hex，无分隔符）。
    pub serial_hex: String,
    /// 证书 DER 的 SHA-256（小写 hex），用于拒绝名单 / 日志。
    pub fingerprint_sha256_hex: String,
    /// RFC3339，已含 `notBefore` 回拨。
    pub not_before: String,
    /// RFC3339。
    pub not_after: String,
    /// 证书里填的 URI SAN，便于回执/排查。
    pub agent_uri: String,
}

/// 独立的 agent CA：只用于签 agent **客户端证书**（§4.1，与服务端叶的 CA 分开）。
///
/// 私钥只留服务端；其根**不下发**给 agent。
pub struct AgentCa {
    /// 签发用的 CA 句柄。rcgen 0.13 的签名接口要一个 `Certificate`，只用它的主体 DN /
    /// key-id 方法（**不用它的 DER**），所以这里用同一把 CA 密钥自签一次得到句柄；
    /// 签出的叶证书仍能被**原始 CA 证书**验证（测试覆盖）。
    issuer: Certificate,
    issuer_key: KeyPair,
    ca_certificate_pem: String,
}

impl fmt::Debug for AgentCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rcgen::Certificate` / `KeyPair` 不实现 Debug（也不该把私钥打出来）。
        f.debug_struct("AgentCa")
            .field("ca_certificate_pem_len", &self.ca_certificate_pem.len())
            .finish_non_exhaustive()
    }
}

impl AgentCa {
    /// 从证书 PEM + 私钥 PEM 载入。
    pub fn from_pem(ca_certificate_pem: &str, ca_key_pem: &str) -> Result<Self, String> {
        let params = CertificateParams::from_ca_cert_pem(ca_certificate_pem)
            .map_err(|err| format!("failed to parse agent CA certificate: {err}"))?;
        let issuer_key = KeyPair::from_pem(ca_key_pem)
            .map_err(|err| format!("failed to parse agent CA private key: {err}"))?;
        let issuer = params
            .self_signed(&issuer_key)
            .map_err(|err| format!("failed to load agent CA as an issuer: {err}"))?;
        Ok(Self {
            issuer,
            issuer_key,
            ca_certificate_pem: ca_certificate_pem.to_string(),
        })
    }

    /// 从文件载入（证书 + 私钥）。
    pub fn load(ca_certificate_path: &Path, ca_key_path: &Path) -> Result<Self, String> {
        let ca_certificate_pem = std::fs::read_to_string(ca_certificate_path).map_err(|err| {
            format!(
                "failed to read agent CA certificate {}: {err}",
                ca_certificate_path.display()
            )
        })?;
        let ca_key_pem = std::fs::read_to_string(ca_key_path).map_err(|err| {
            format!(
                "failed to read agent CA private key {}: {err}",
                ca_key_path.display()
            )
        })?;
        Self::from_pem(&ca_certificate_pem, &ca_key_pem)
    }

    /// CA 证书 PEM（原样，用于上链 / 回执）。
    pub fn ca_certificate_pem(&self) -> &str {
        &self.ca_certificate_pem
    }

    /// 用 CSR 里的公钥签一张客户端证书。
    ///
    /// **CSR 只贡献公钥**：CSR 的 subject 与请求的扩展一律忽略，主体由网关按
    /// `identity`（稳定哈希 `agent_id`）填。约束：`CA:FALSE`、`keyUsage=digitalSignature`、
    /// `EKU=clientAuth`、URI SAN、`notBefore-5min`、`notAfter=now+ttl`。
    pub fn issue_client_certificate(
        &self,
        csr_pem: &str,
        identity: &AgentCertificateIdentity,
        ttl_seconds: i64,
    ) -> Result<IssuedAgentCertificate, String> {
        if ttl_seconds <= 0 {
            return Err(format!(
                "client certificate ttl must be positive, got {ttl_seconds}"
            ));
        }
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|err| format!("failed to parse certificate signing request: {err}"))?;

        let agent_uri = agent_uri(identity);
        let mut distinguished_name = DistinguishedName::new();
        // CN 只作人类可读标签，权威身份在 URI SAN（§4.2）。
        distinguished_name.push(DnType::CommonName, identity.agent_id.clone());

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.subject_alt_names =
            vec![SanType::URI(agent_uri.clone().try_into().map_err(
                |_| format!("agent URI is not a valid IA5 string: {agent_uri}"),
            )?)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::seconds(CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS);
        params.not_after = now + Duration::seconds(ttl_seconds);
        params.serial_number = Some(SerialNumber::from_slice(&random_serial_bytes()?));
        params.use_authority_key_identifier_extension = true;

        let certificate = params
            .signed_by(&csr.public_key, &self.issuer, &self.issuer_key)
            .map_err(|err| format!("failed to sign agent client certificate: {err}"))?;
        let certificate_der = certificate.der().to_vec();
        let serial_bytes = certificate
            .params()
            .serial_number
            .as_ref()
            .map(SerialNumber::to_bytes)
            .unwrap_or_default();

        Ok(IssuedAgentCertificate {
            certificate_pem: certificate.pem(),
            fingerprint_sha256_hex: hex_lower(digest(&SHA256, &certificate_der).as_ref()),
            certificate_der,
            serial_hex: hex_lower(&serial_bytes),
            not_before: to_rfc3339(params_not_before(certificate.params())),
            not_after: to_rfc3339(params_not_after(certificate.params())),
            agent_uri,
        })
    }
}

/// 从 DER 证书里读 URI SAN，还原 agent 身份。
///
/// 这是「库丢失 / 换网关后首触重建登记」的入口：只靠证书自证，不查库（§5.3）。
pub fn agent_identity_from_certificate_der(
    certificate_der: &[u8],
) -> Result<AgentCertificateIdentity, String> {
    let (_, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|err| format!("failed to parse client certificate: {err}"))?;
    let san = certificate
        .subject_alternative_name()
        .map_err(|err| format!("failed to read client certificate SAN: {err}"))?
        .ok_or_else(|| "client certificate has no subject alternative name".to_string())?;
    for name in &san.value.general_names {
        if let GeneralName::URI(uri) = name
            && let Ok(identity) = parse_agent_uri(uri)
        {
            return Ok(identity);
        }
    }
    Err("client certificate has no agent URI SAN".to_string())
}

fn random_serial_bytes() -> Result<Vec<u8>, String> {
    let mut serial = vec![0u8; SERIAL_NUMBER_BYTES];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| "failed to generate a certificate serial number".to_string())?;
    // DER 的 INTEGER 不允许前导 0（否则会被当成非最小编码）；首位清零仍留 127 位熵。
    serial[0] &= 0x7f;
    Ok(serial)
}

fn params_not_before(params: &CertificateParams) -> OffsetDateTime {
    params.not_before
}

fn params_not_after(params: &CertificateParams) -> OffsetDateTime {
    params.not_after
}

/// 统一走 chrono 输出 RFC3339，与仓库其余时间字段同一口径。
fn to_rfc3339(value: OffsetDateTime) -> String {
    chrono::DateTime::from_timestamp(value.unix_timestamp(), 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| value.to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rcgen::BasicConstraints;
    use rustls::RootCertStore;
    use rustls::pki_types::UnixTime;
    use rustls::server::WebPkiClientVerifier;
    use rustls_pki_types::pem::PemObject;

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn test_ca() -> (AgentCa, String) {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Wist Test Agent CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let key = KeyPair::generate().expect("ca key");
        let certificate = params.self_signed(&key).expect("self signed ca");
        let pem = certificate.pem();
        let ca = AgentCa::from_pem(&pem, &key.serialize_pem()).expect("load ca");
        (ca, pem)
    }

    /// 造一张 CSR；subject 与请求的 SAN 都是「脏」的，用来验证签发时被忽略。
    fn dirty_csr() -> String {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "evil.example");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName("evil.example".try_into().expect("ia5"))];
        params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("csr pem")
    }

    fn identity() -> AgentCertificateIdentity {
        AgentCertificateIdentity::new("tenant-default", "env-default", "agent-abc")
    }

    #[test]
    fn issues_uri_san_and_client_auth_under_the_ca() {
        install_provider();
        let (ca, _ca_pem) = test_ca();
        let issued = ca
            .issue_client_certificate(&dirty_csr(), &identity(), DEFAULT_CLIENT_CERT_TTL_SECONDS)
            .expect("issue");

        assert_eq!(
            issued.agent_uri,
            "spiffe://tenant-default/env-default/agent/agent-abc"
        );
        assert_eq!(issued.serial_hex.len(), SERIAL_NUMBER_BYTES * 2);
        assert_eq!(issued.fingerprint_sha256_hex.len(), 64);

        // 身份从证书里读回来（M3 首触重建登记的入口）。
        let parsed =
            agent_identity_from_certificate_der(&issued.certificate_der).expect("read identity");
        assert_eq!(parsed, identity());

        // CN 只是标签：CSR 的 subject 被忽略，CN = agent_id。
        let (_, certificate) =
            X509Certificate::from_der(&issued.certificate_der).expect("parse cert");
        assert_eq!(
            certificate.subject().to_string(),
            "CN=agent-abc",
            "CSR subject must be ignored"
        );

        // CA:FALSE + EKU=clientAuth（server_auth 必须为假）。
        let basic = certificate
            .basic_constraints()
            .expect("basic constraints")
            .expect("present");
        assert!(!basic.value.ca, "client certificate must not be a CA");
        let eku = certificate
            .extended_key_usage()
            .expect("extended key usage")
            .expect("present");
        assert!(eku.value.client_auth, "EKU must allow clientAuth");
        assert!(!eku.value.server_auth, "EKU must not allow serverAuth");
    }

    #[test]
    fn issued_certificate_verifies_as_a_client_certificate_under_the_original_ca() {
        install_provider();
        let (ca, ca_pem) = test_ca();
        let issued = ca
            .issue_client_certificate(&dirty_csr(), &identity(), DEFAULT_CLIENT_CERT_TTL_SECONDS)
            .expect("issue");

        let mut roots = RootCertStore::empty();
        for anchor in rustls_pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(anchor.expect("ca pem")).expect("add anchor");
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("build verifier");
        let leaf = rustls_pki_types::CertificateDer::from(issued.certificate_der.clone());
        verifier
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .expect("client certificate must verify against the original CA");
    }

    #[test]
    fn expired_client_certificate_is_rejected() {
        install_provider();
        let (ca, ca_pem) = test_ca();
        let issued = ca
            .issue_client_certificate(&dirty_csr(), &identity(), DEFAULT_CLIENT_CERT_TTL_SECONDS)
            .expect("issue");

        let mut roots = RootCertStore::empty();
        for anchor in rustls_pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(anchor.expect("ca pem")).expect("add anchor");
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("build verifier");
        let leaf = rustls_pki_types::CertificateDer::from(issued.certificate_der.clone());
        // 跳过 40 天（> 37 天寿命）后再验证 → 必须被拒。
        let later = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            UnixTime::now().as_secs() + 40 * 24 * 60 * 60,
        ));
        assert!(verifier.verify_client_cert(&leaf, &[], later).is_err());
    }

    #[test]
    fn not_before_is_backdated_for_clock_skew() {
        install_provider();
        let (ca, _) = test_ca();
        let issued = ca
            .issue_client_certificate(&dirty_csr(), &identity(), DEFAULT_CLIENT_CERT_TTL_SECONDS)
            .expect("issue");
        let not_before = chrono::DateTime::parse_from_rfc3339(&issued.not_before).expect("rfc3339");
        let not_after = chrono::DateTime::parse_from_rfc3339(&issued.not_after).expect("rfc3339");
        assert!(not_before < chrono::Utc::now());
        assert_eq!(
            (not_after - not_before).num_seconds(),
            DEFAULT_CLIENT_CERT_TTL_SECONDS + CLIENT_CERT_NOT_BEFORE_SKEW_SECONDS
        );
    }

    #[test]
    fn rejects_non_positive_ttl() {
        let (ca, _) = test_ca();
        let err = ca
            .issue_client_certificate(&dirty_csr(), &identity(), 0)
            .expect_err("zero ttl");
        assert!(err.contains("must be positive"));
    }

    #[test]
    fn agent_uri_round_trips() {
        let uri = agent_uri(&identity());
        assert_eq!(uri, "spiffe://tenant-default/env-default/agent/agent-abc");
        assert_eq!(parse_agent_uri(&uri).expect("parse"), identity());
    }

    #[test]
    fn parse_agent_uri_rejects_malformed_input() {
        for bad in [
            "",
            "https://tenant-default/env-default/agent/agent-abc",
            "spiffe://tenant-default/agent/agent-abc",
            "spiffe://tenant-default/env-default/agent/",
            "spiffe://tenant-default/env-default/agent/a/b",
            "spiffe:///env-default/agent/agent-abc",
        ] {
            assert!(parse_agent_uri(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn certificate_without_agent_uri_san_is_rejected() {
        install_provider();
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName("evil.example".try_into().unwrap())];
        let certificate = params.self_signed(&key).expect("self signed");
        let err = agent_identity_from_certificate_der(certificate.der()).expect_err("no agent uri");
        assert!(err.contains("no agent URI SAN"));
    }
}
