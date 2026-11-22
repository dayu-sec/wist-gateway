//! 计划**签发**：把审批结果变成一份可离线验证的 `ActionPlanAttestation`。
//!
//! 私钥只在这一侧（本轮是网关，后续移到 center）。被管端只拿公钥验签，两边的信任关系
//! 就是**一把钥匙**，没有别的通路。
//!
//! 三条刻意的取舍：
//!
//! 1. **签的是 attestation，不是整份 plan**（否则自引用）。attestation 里的 `plan_digest`
//!    把「签的这份证明」与「这份计划」绑死，改一个字节就验不过。
//! 2. **签发前重算摘要并比对**。调用方传进来的 digest 是审批时算的；现在重算一次，
//!    不一致 = 审批之后计划被改过，必须拒（而不是「重新签一份」——那等于绕过审批）。
//! 3. **没配私钥就不签发**。端点回 503，不做「签名可选」的降级：一份没有签名的计划
//!    在 enforced 的机器上会被拒，在未 enforced 的机器上会被静默执行 —— 后者才是最坏的。

use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use ring::signature::Ed25519KeyPair;
use wist_contracts::API_VERSION_V1;
use wist_contracts::action_plan::{
    ATTESTATION_ALGORITHM_ED25519, ActionPlan, ActionPlanApproval, ActionPlanAttestation,
    plan_digest,
};

/// 签发的默认有效期（秒）。审批单通常只该活几小时到一天。
pub const DEFAULT_ATTESTATION_TTL_SECONDS: i64 = 3600;

/// 签发的失败。
///
/// 用枚举而不是字符串：调用方要按「审批后被改」映射成 409 `plan_changed_since_approval`，
/// 靠 `err.contains("changed since approval")` 做分支，文案一改就静默变成 500。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// 审批之后计划被改过（重算摘要 ≠ 审批时的摘要）。
    PlanChanged { approved: String, current: String },
    /// 计划本身已过期（给一份活不过现在的证明没意义）。
    PlanExpired,
    /// 计划上已经挂着 attestation（不支持重签）。
    AlreadyAttested,
    /// 输入本身不合法（`approval_id` 空、`expires_at` 不是 RFC3339）。
    Invalid(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlanChanged { approved, current } => {
                write!(
                    f,
                    "plan changed since approval: approved {approved}, now {current}"
                )
            }
            Self::PlanExpired => f.write_str("plan already expired; refusing to sign"),
            Self::AlreadyAttested => f.write_str("plan already carries an attestation"),
            Self::Invalid(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for SignError {}

/// 签发器。持有私钥，**不实现 `Clone`**（靠 `Arc` 共享）。
pub struct PlanSigner {
    key_id: String,
    issued_by: String,
    ttl_seconds: i64,
    key_pair: Ed25519KeyPair,
}

impl fmt::Debug for PlanSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 私钥永远不进 `Debug`：`AdminConfig` 是 `Debug` 的，配置被顺手打进日志是常见事故。
        f.debug_struct("PlanSigner")
            .field("key_id", &self.key_id)
            .field("issued_by", &self.issued_by)
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

impl PlanSigner {
    /// 从 Ed25519 PKCS#8 PEM（`-----BEGIN PRIVATE KEY-----`）构造。
    pub fn from_pkcs8_pem(
        pem: &str,
        key_id: impl Into<String>,
        issued_by: impl Into<String>,
        ttl_seconds: i64,
    ) -> Result<Self, String> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() {
            return Err("plan signing key_id must not be empty".to_string());
        }
        if ttl_seconds <= 0 {
            return Err("plan signing ttl_seconds must be positive".to_string());
        }
        let der = parse_pkcs8_pem(pem)?;
        let key_pair = ed25519_key_pair_from_pkcs8(&der)?;
        Ok(Self {
            key_id,
            issued_by: issued_by.into(),
            ttl_seconds,
            key_pair,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn issued_by(&self) -> &str {
        &self.issued_by
    }

    pub fn ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    /// 给计划签一份证明并写回 `plan.attestation`。
    ///
    /// `expected_digest` 是**审批时**算出的摘要；这里重算后必须相等，否则返回 `Err`
    /// （调用方应把它映射成 `plan_changed_since_approval`）。
    pub fn sign(
        &self,
        plan: &mut ActionPlan,
        approval_id: &str,
        approvers: Vec<String>,
        required_approvers: u8,
        expected_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<String, SignError> {
        if approval_id.trim().is_empty() {
            return Err(SignError::Invalid(
                "approval_id must not be empty".to_string(),
            ));
        }
        // 签发时计划上不该还挂着旧证明：`plan_digest` 会排除它，但留着会让「重签」看起来
        // 像「又签了一遍同一份」，排查时误导。
        if plan.attestation.is_some() {
            return Err(SignError::AlreadyAttested);
        }
        let digest = plan_digest(plan);
        if digest != expected_digest {
            return Err(SignError::PlanChanged {
                approved: expected_digest.to_string(),
                current: digest,
            });
        }

        // 证明的有效期不晚于计划本身：计划到期了，一份还活着的证明毫无意义。
        let plan_expires = chrono::DateTime::parse_from_rfc3339(&plan.meta.expires_at)
            .map_err(|err| SignError::Invalid(format!("plan expires_at is not RFC3339: {err}")))?
            .with_timezone(&Utc);
        let issued_expires = now + chrono::Duration::seconds(self.ttl_seconds);
        let expires_at = issued_expires.min(plan_expires);
        if expires_at <= now {
            return Err(SignError::PlanExpired);
        }

        let mut attestation = ActionPlanAttestation {
            api_version: API_VERSION_V1.to_string(),
            plan_digest: digest.clone(),
            approval: ActionPlanApproval {
                approval_id: approval_id.to_string(),
                approvers,
                required_approvers,
                approved_at: format_timestamp(now),
            },
            risk_level: plan.constraints.risk_level,
            issued_by: self.issued_by.clone(),
            key_id: self.key_id.clone(),
            algorithm: ATTESTATION_ALGORITHM_ED25519.to_string(),
            signed_at: format_timestamp(now),
            expires_at: format_timestamp(expires_at),
            signature: String::new(),
        };
        let signature = self.key_pair.sign(&attestation.signing_payload());
        attestation.signature = signature
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        plan.attestation = Some(attestation);
        Ok(digest)
    }
}

/// 从 PKCS#8 DER 构造 key pair。
///
/// ring 的 `from_pkcs8` 只接受它自己生成的布局；而 **OpenSSL
/// `genpkey -algorithm ed25519` 生成的是标准 PKCS#8 v1**（私钥字段是嵌套 OCTET STRING），
/// ring 会回 `VersionNotSupported`。运维手里几乎都是 openssl 的输出，所以留一条回退：
/// 取末尾 `04 22 04 20 <32-byte seed>` 里的 seed。
fn ed25519_key_pair_from_pkcs8(der: &[u8]) -> Result<Ed25519KeyPair, String> {
    if let Ok(key_pair) = Ed25519KeyPair::from_pkcs8(der) {
        return Ok(key_pair);
    }
    let len = der.len();
    if len >= 34 && der[len - 34] == 0x04 && der[len - 33] == 0x20 {
        return Ed25519KeyPair::from_seed_unchecked(&der[len - 32..])
            .map_err(|err| format!("not a valid Ed25519 seed: {err}"));
    }
    Err("not a valid Ed25519 PKCS#8 key (neither ring nor OpenSSL layout)".to_string())
}

/// RFC3339（秒精度、UTC `Z`），与契约里的时间戳同形。
fn format_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// 解 PKCS#8 PEM 的 DER 主体。
fn parse_pkcs8_pem(pem: &str) -> Result<Vec<u8>, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let begin = pem.find(BEGIN).ok_or_else(|| {
        "private key must be a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`)".to_string()
    })?;
    let rest = &pem[begin + BEGIN.len()..];
    let end = rest
        .find(END)
        .ok_or_else(|| "private key PEM is missing its footer".to_string())?;
    let body: String = rest[..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("private key PEM body is empty".to_string());
    }
    STANDARD
        .decode(body)
        .map_err(|err| format!("failed to decode private key PEM: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wist_contracts::action_plan::{
        ActionPlanConstraints, ActionPlanMeta, ActionPlanProgram, ActionPlanStep, ActionPlanTarget,
        ApprovalMode, RiskLevel,
    };

    fn key_pair() -> (Ed25519KeyPair, String) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
        let der = pkcs8.as_ref().to_vec();
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let encoded = STANDARD.encode(&der);
        let mut wrapped = String::new();
        for chunk in encoded.as_bytes().chunks(64) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            wrapped.push('\n');
        }
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{wrapped}-----END PRIVATE KEY-----\n");
        (Ed25519KeyPair::from_pkcs8(&der).expect("parse"), pem)
    }

    fn plan() -> ActionPlan {
        ActionPlan::new(
            ActionPlanMeta {
                action_id: "act-1".to_string(),
                request_id: "req-1".to_string(),
                template_id: None,
                tenant_id: "tenant".to_string(),
                environment_id: "dev".to_string(),
                plan_version: 1,
                compiled_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2030-01-01T00:00:00Z".to_string(),
            },
            ActionPlanTarget {
                agent_id: "agent-1".to_string(),
                instance_id: None,
                node_id: "node-1".to_string(),
                host_name: None,
                platform: "linux".to_string(),
                arch: "x86_64".to_string(),
                selectors: BTreeMap::new(),
            },
            ActionPlanConstraints {
                risk_level: RiskLevel::R2,
                approval_ref: Some("apv-1".to_string()),
                approval_mode: ApprovalMode::Required,
                requested_by: "tester".to_string(),
                reason: Some("clear tmp".to_string()),
                max_total_duration_ms: 30_000,
                step_timeout_default_ms: 10_000,
                execution_profile: "agent_exec_v1".to_string(),
                required_capabilities: vec!["disk.cleanup.apply".to_string()],
                allow: None,
            },
            ActionPlanProgram {
                entry: "s1".to_string(),
                steps: vec![ActionPlanStep {
                    id: "s1".to_string(),
                    kind: "invoke".to_string(),
                    op: Some("disk.cleanup.apply".to_string()),
                    args: Some(serde_json::json!({"target": "tmp"})),
                }],
            },
        )
    }

    fn now() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .expect("parse")
            .with_timezone(&Utc)
    }

    #[test]
    fn signing_produces_a_verifiable_attestation() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let mut plan = plan();
        let digest = plan_digest(&plan);
        let signed_digest = signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect("sign");
        assert_eq!(signed_digest, digest);

        let attestation = plan.attestation.as_ref().expect("attestation");
        assert_eq!(attestation.plan_digest, digest);
        assert_eq!(attestation.key_id, "gw-k1");
        assert_eq!(attestation.approval.approval_id, "apv-1");
        assert_eq!(attestation.risk_level, RiskLevel::R2);
        assert_eq!(attestation.signed_at, "2026-06-01T00:00:00Z");
        assert_eq!(attestation.expires_at, "2026-06-01T01:00:00Z");

        // 摘要不受 attestation 影响。
        assert_eq!(plan_digest(&plan), digest);

        let public = ring::signature::KeyPair::public_key(&signer.key_pair)
            .as_ref()
            .to_vec();
        let signature = hex(&attestation.signature);
        assert!(crate::infra::verify_ed25519(
            &public,
            &attestation.signing_payload(),
            &signature
        ));
    }

    fn hex(value: &str) -> Vec<u8> {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut index = 0;
        while index + 1 < bytes.len() {
            let hi = (bytes[index] as char).to_digit(16).expect("hex");
            let lo = (bytes[index + 1] as char).to_digit(16).expect("hex");
            out.push(((hi << 4) | lo) as u8);
            index += 2;
        }
        out
    }

    #[test]
    fn signing_a_changed_plan_is_refused() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let mut plan = plan();
        let digest = plan_digest(&plan);
        plan.program.steps[0].args = Some(serde_json::json!({"target": "var_log"}));
        let err = signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect_err("digest changed");
        assert!(
            matches!(err, SignError::PlanChanged { .. }),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn refuses_to_sign_a_plan_that_already_has_an_attestation() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let mut plan = plan();
        let digest = plan_digest(&plan);
        signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect("first sign");
        let err = signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect_err("second sign");
        assert_eq!(err, SignError::AlreadyAttested);
    }

    #[test]
    fn an_expired_plan_is_not_signed() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let mut plan = plan();
        plan.meta.expires_at = "2026-05-01T00:00:00Z".to_string();
        let digest = plan_digest(&plan);
        let err = signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect_err("expired");
        assert_eq!(err, SignError::PlanExpired);
    }

    #[test]
    fn an_empty_approval_id_is_refused() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let mut plan = plan();
        let digest = plan_digest(&plan);
        let err = signer
            .sign(
                &mut plan,
                "  ",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect_err("empty approval id");
        assert!(matches!(err, SignError::Invalid(_)), "unexpected: {err:?}");
        assert!(plan.attestation.is_none(), "失败的签发不能改动计划");
    }

    /// 证明的有效期不能晚于计划本身：计划先死，一份还活着的证明毫无意义。
    #[test]
    fn the_attestation_never_outlives_the_plan() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let mut plan = plan();
        // ttl 是 1 小时（到 01:00），但计划 00:30 就过期 —— 取更早的那个。
        plan.meta.expires_at = "2026-06-01T00:30:00Z".to_string();
        let digest = plan_digest(&plan);
        signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect("sign");
        let attestation = plan.attestation.as_ref().expect("attestation");
        assert_eq!(attestation.expires_at, "2026-06-01T00:30:00Z");
    }

    /// OpenSSL `genpkey -algorithm ed25519` 的布局必须能用 —— 这是文档里写、运维实际会用的命令。
    /// 它在 PKCS#8 里把 seed 包了一层嵌套 OCTET STRING，ring 的 `from_pkcs8` 不接受。
    #[test]
    fn accepts_an_openssl_style_pkcs8_key() {
        use ring::signature::KeyPair;

        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let seed: Vec<u8> = (1u8..=32).collect();
        der.extend_from_slice(&seed);

        let pem = {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let encoded = STANDARD.encode(&der);
            let mut wrapped = String::new();
            for chunk in encoded.as_bytes().chunks(64) {
                wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
                wrapped.push('\n');
            }
            format!("-----BEGIN PRIVATE KEY-----\n{wrapped}-----END PRIVATE KEY-----\n")
        };

        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "k", "gw", 3600).expect("openssl layout is accepted");
        let mut plan = plan();
        let digest = plan_digest(&plan);
        signer
            .sign(
                &mut plan,
                "apv-1",
                vec!["user:alice".to_string()],
                1,
                &digest,
                now(),
            )
            .expect("sign");

        // 签名必须能用 seed 对应的公钥验过。
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
        let public = key_pair.public_key().as_ref().to_vec();
        let attestation = plan.attestation.as_ref().expect("attestation");
        assert!(crate::infra::verify_ed25519(
            &public,
            &attestation.signing_payload(),
            &hex(&attestation.signature)
        ));
    }

    #[test]
    fn a_bad_pem_is_refused_at_construction() {
        let err = PlanSigner::from_pkcs8_pem("not a pem", "gw-k1", "gateway:test", 3600)
            .expect_err("must refuse");
        assert!(err.contains("PKCS#8 PEM"), "{err}");
    }

    #[test]
    fn the_debug_impl_never_leaks_the_key() {
        let (_key_pair, pem) = key_pair();
        let signer =
            PlanSigner::from_pkcs8_pem(&pem, "gw-k1", "gateway:test", 3600).expect("signer");
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("gw-k1"));
        assert!(!rendered.contains("PRIVATE"));
    }
}
