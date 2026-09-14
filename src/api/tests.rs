use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
};
use ring::{
    rand as ring_rand,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use tower::ServiceExt;
use wist_contracts::enrollment::{
    AgentIdentityStatus, CredentialRenewal, CredentialRenewed, EnrollmentEnvelope,
    EnrollmentRequest, EnrollmentStatus,
};

use crate::infra::{
    AdminConfig, AdminStore, StoredEnrollmentTokenStatus, load_install_script_public_key_pem,
    sha256_hex,
};
use wist_contracts::action_result::{ActionResult, FinalStatus};
use wist_contracts::gateway::{
    AgentStatusReport, AgentWorkState, AgentWorkStateChange, ReportActionResult, ResultAttestation,
};
use wist_control::PollControlCommands;
use wist_control::types::DateTime;

use super::{
    AdminRuntimeState, ApiState,
    enrollment::{
        agent_enrollment_result, agent_enrollment_result_with_token_issuer, enroll_agent,
    },
    install::{
        agent_initial_config_toml, agent_install_code, agent_package_sha256,
        issue_agent_install_code, token_hash, validate_bootstrap_token_for_config,
    },
    overview::{RecentOnlineRegisteredAgentSource, agent_overview},
    router,
};

const TEST_ADMIN_API_TOKEN: &str = "test-admin-token";

/// Self-signed TLS cert (CN=localhost, RSA) written into each TestEnv so the
/// macOS install code can compute its `--pinnedpubkey` pin.
const TEST_TLS_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDCTCCAfGgAwIBAgIUVlBq6CYit7aQR8CpShgLhKef76gwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwODE0MzIzMFoXDTI3MDkw\nODE0MzIzMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAowBkJchsMBeZcyW2Hntz9fHbM2EYg4Phfn+S4RB2oCzc\n7hXmxB3FUMZ4VKWhF3ruhIFM7Tc6pfSUPx6AqgDJBtvkeA2v+oFR6P0Fsv2Xlczp\neBKpK0vygKjL7jGrHmbofKL5om/ytyQMVjgxhEWW5K54+bvldpa7JnBN3GAJU5KA\nxIAH/5lQSKzlvD6emuUJd62062sVkc9EX7bzM0fOWV2xMEn6JuW9Pa0sCDKZz71u\nIw4sT70inxl7djXxthq/fMekWCrjeNcoLODmMDJgiSUYki1ox1uT9YuXThgIIwHO\nERXzp3xrbO6gOeJgbX4C/aYxcMoaXQGmh89NRmK8MwIDAQABo1MwUTAdBgNVHQ4E\nFgQUDzbiNfr4kpFl2+bL6RmiPBCEgSYwHwYDVR0jBBgwFoAUDzbiNfr4kpFl2+bL\n6RmiPBCEgSYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARPZy\nXsWS0A8jnXSRbTxHCSciwic0pFDc9vo+8WyMkz1t754cbrStEhSU9Rl1hE1ZON6v\nVJpdG4Yezhdmx8zfqBbjDNhSjBlrdVRbOyC6oO5KDZHTIVI6mEqAQaRmohHY41y+\nUza+pZL6TIvol3F99ZOmPevIREmGDY9Xy6CxeaiTkSoCg/0XIO/55GeEQSix9YSM\nuvISELAaKycvD37ltjgr4DigLquxs03mCntBcKX7KvpPF6142KLvQxiHyI+VJdtK\nTapJeaMTcQ0i/jLOd47lwGDnQL2Q1RpF6Lp1uTkSDeBFjpJlRzZGnrssHX4vEA0L\nmSymA2FI5OPMsMzExQ==\n-----END CERTIFICATE-----\n";
/// Expected `sha256//` pin (base64 of the sha256 of the SPKI) of the cert above.
const TEST_TLS_CERT_PIN: &str = "uq4O4EN3e09Xmlo5euGldyHw+y27baJ+Jm/OBnFHrZc=";

#[test]
fn install_code_uses_header_bootstrap_token_without_url_token_leak() {
    let env = TestEnv::new();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);
    let install_code =
        agent_install_code(&env.config, "token-a", expires_at).expect("install code");

    assert_eq!(
        install_code.bootstrap_bundle.agent_package_url,
        "https://127.0.0.1:3000/api/v1/agent/packages/current"
    );
    assert!(
        !install_code
            .bootstrap_bundle
            .agent_package_sha256
            .is_empty()
    );
    assert!(install_code.x86_linux_install_code.contains(
        "curl -fsSLk \"https://127.0.0.1:3000/api/v1/agent/install/x86/install.sh\" -o \"$D/s\""
    ));
    assert!(install_code.arm_linux_install_code.contains(
        "curl -fsSLk \"https://127.0.0.1:3000/api/v1/agent/install/arm/install.sh\" -o \"$D/s\""
    ));
    assert!(
        install_code
            .x86_linux_install_code
            .contains("install.sh.sig")
    );
    assert!(
        install_code
            .x86_linux_install_code
            .contains("openssl pkeyutl -verify -pubin")
    );
    assert!(install_code.x86_linux_install_code.contains("sh \"$D/s\""));
    assert!(
        install_code
            .x86_linux_install_code
            .contains("-----BEGIN PUBLIC KEY-----")
    );
    let macos = &install_code.macos_install_code;
    assert!(macos.contains("\"$(uname -s)\" != \"Darwin\""));
    assert!(macos.contains("arm64) ARCH=arm ;; *) ARCH=x86"));
    assert!(macos.contains(&format!(
        "curl -fsSLk --pinnedpubkey \"sha256//{TEST_TLS_CERT_PIN}\" \"https://127.0.0.1:3000/api/v1/agent/install/$ARCH/install.sh\""
    )));
    assert!(macos.contains("sh \"$D/s\""));
    assert!(!macos.contains("openssl pkeyutl"));
    assert!(!macos.contains("install.sh.sig"));
    assert!(!macos.contains("token-a"));
    assert!(!macos.contains("?token="));
    assert_eq!(install_code.bootstrap_enrollment_token, "token-a");
    assert!(!install_code.x86_linux_install_code.contains("token-a"));
    assert!(!install_code.arm_linux_install_code.contains("token-a"));
    assert!(
        !install_code
            .x86_linux_install_code
            .contains("WARP_INSIGHT_ENROLLMENT_TOKEN=")
    );
    assert!(
        !install_code
            .arm_linux_install_code
            .contains("WARP_INSIGHT_ENROLLMENT_TOKEN=")
    );
    assert!(!install_code.x86_linux_install_code.contains("?token="));
    assert!(!install_code.arm_linux_install_code.contains("?token="));
    assert!(
        !install_code
            .bootstrap_bundle
            .install_script_url
            .contains("?token=")
    );
    assert!(
        !install_code
            .bootstrap_bundle
            .agent_package_url
            .contains("?token=")
    );
}

#[test]
fn issue_install_code_persists_one_time_enrollment_token() {
    let env = TestEnv::new();
    let install_code = issue_agent_install_code(&env.config, &env.store).expect("install code");
    let token = install_code.bootstrap_enrollment_token;

    validate_bootstrap_token_for_config(&env.config, &env.store, &token).expect("token valid");
    let snapshot = env.store.load().expect("store load");
    assert_eq!(snapshot.enrollment_tokens.len(), 1);
    assert!(snapshot.enrollment_tokens.contains_key(&token_hash(&token)));
    assert!(snapshot.enrollment_tokens.values().all(|token| {
        token.max_uses == 1
            && token.used_count == 0
            && token.status == StoredEnrollmentTokenStatus::Active
    }));
}

#[test]
fn install_script_downloads_package_verifies_sha256_and_fetches_scoped_initial_config() {
    let env = TestEnv::new();
    let script = super::install::install_script(&env.config, "x86").expect("install script");
    let sha256 = agent_package_sha256(&env.config).expect("sha256");

    assert!(script.contains("ARCH=\"x86\""));
    assert!(script.contains("AGENT_PACKAGE_SHA256=\""));
    assert!(script.contains("WARP_INSIGHT_ENROLLMENT_TOKEN"));
    assert!(script.contains("Enrollment token:"));
    assert!(script.contains("</dev/tty"));
    assert!(script.contains("umask 077"));
    assert!(script.contains("chmod 0700 \"$CONFIG_DIR\""));
    assert!(script.contains("chmod 0600 \"$CONFIG_DIR/agentd.toml\""));
    assert!(script.contains(&sha256));
    assert!(script.contains("sha256sum"));
    assert!(script.contains("shasum -a 256"));
    assert!(script.contains("WARP_INSIGHT_HOME=\"/opt/warp-insight\""));
    assert!(script.contains("WARP_INSIGHT_HOME=\"/usr/local/warp-insight\""));
    assert!(script.contains("WARP_INSIGHT_HOME=\"$HOME/.warp-insight\""));
    assert!(script.contains("CONFIG_DIR=\"$WARP_INSIGHT_HOME/.wist-agentd\""));
    assert!(script.contains("-H \"authorization: Bearer $WARP_INSIGHT_ENROLLMENT_TOKEN\""));
    assert!(script.contains("\"https://127.0.0.1:3000/api/v1/agent/packages/current\""));
    assert!(script.contains("\"https://127.0.0.1:3000/api/v1/agent/initial-config\""));
    assert!(!script.contains("?token="));
    assert!(script.contains("wist-agentd --config-dir"));
}

#[test]
fn install_script_fails_when_package_file_is_unreadable() {
    let env = TestEnv::new();
    let package_path = env.config.agent_package_file.clone();
    std::fs::remove_file(&package_path).expect("remove package");

    let err = super::install::install_script(&env.config, "x86").expect_err("unreadable package");

    assert!(!err.is_empty());
}

#[test]
fn install_command_verifies_script_signature_before_execution() {
    let env = TestEnv::new();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);
    let install_code =
        agent_install_code(&env.config, "token-a", expires_at).expect("install code");
    let command = install_code.x86_linux_install_code;

    assert!(command.contains("mktemp -d"));
    assert!(command.contains("working dir: $D"));
    assert!(command.contains(
        "curl -fsSLk \"https://127.0.0.1:3000/api/v1/agent/install/x86/install.sh.sig\" -o \"$D/sig\""
    ));
    assert!(command.contains(&env.config.install_script_signing_public_key_pem));
    assert!(command.contains(
        "openssl pkeyutl -verify -pubin -inkey \"$D/key.pem\" -rawin -in \"$D/s\" -sigfile \"$D/sig\""
    ));
    assert!(command.contains("sh \"$D/s\""));
    assert!(!command.contains("| sh"));
    assert!(!command.contains("token-a"));
}

#[test]
fn install_script_signature_matches_script_body() {
    let env = TestEnv::new();
    let script = super::install::install_script(&env.config, "x86").expect("install script");
    let signature =
        super::install::install_script_signature(&env.config, "x86").expect("sign script");

    signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(script.as_bytes(), &signature)
        .expect("signature verifies");
}

#[test]
fn install_script_signature_rejects_modified_script_body() {
    let env = TestEnv::new();
    let signature =
        super::install::install_script_signature(&env.config, "x86").expect("sign script");

    let err = signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(b"tampered install script", &signature)
        .expect_err("tampered script rejected");

    assert_eq!(format!("{err:?}"), "Unspecified");
}

#[test]
fn initial_config_is_valid_agent_config_contract_with_scoped_token() {
    let env = TestEnv::new();
    let text = agent_initial_config_toml(&env.config, "install-token-a");
    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");

    assert_eq!(parsed.schema_version, "v1");
    assert_eq!(parsed.agent.environment_id.as_deref(), Some("env-default"));
    assert!(parsed.control_plane.enabled);
    assert_eq!(
        parsed.control_plane.endpoint.as_deref(),
        Some("https://127.0.0.1:3000")
    );
    assert_eq!(
        parsed.control_plane.enrollment_token.as_deref(),
        Some("install-token-a")
    );
    assert_eq!(
        parsed.control_plane.credential_request.as_deref(),
        Some("bearer")
    );
    assert_eq!(
        parsed.control_plane.trust_bundle.as_deref(),
        Some("internal-ca-stub")
    );
    assert_eq!(parsed.paths.root_dir, "..");
}

#[test]
fn initial_config_includes_unique_instance_name_per_token() {
    let env = TestEnv::new();
    let first = agent_initial_config_toml(&env.config, "install-token-a");
    let second = agent_initial_config_toml(&env.config, "install-token-b");

    let extract = |text: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix("instance_name = \""))
            .expect("instance_name line")
            .trim_end_matches('"')
            .to_string()
    };
    let first_name = extract(&first);
    let second_name = extract(&second);
    assert!(first_name.starts_with("host-"));
    assert_ne!(first_name, second_name);
}

#[test]
fn initial_config_preserves_multiline_trust_bundle_as_valid_toml() {
    let mut env = TestEnv::new();
    let trust_bundle =
        "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n".to_string();
    env.config.trust_bundle = trust_bundle.clone();

    let text = agent_initial_config_toml(&env.config, "install-token-a");
    let trust_bundle_line = text
        .lines()
        .find(|line| line.starts_with("trust_bundle = "))
        .expect("trust_bundle line");
    assert!(trust_bundle_line.contains("\\n"));

    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    assert_eq!(parsed.control_plane.trust_bundle, Some(trust_bundle));
}

#[test]
fn enrollment_accepts_valid_token_and_issues_identity() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let result = agent_enrollment_result(
        &env.config,
        &env.store,
        enrollment_request(&token),
        "v0.1.0",
    );

    assert_eq!(result.status, EnrollmentStatus::Accepted);
    assert_eq!(result.agent_id.as_deref(), Some("agent-node-a"));
    assert_eq!(result.instance_id.as_deref(), Some("node-a"));
    let identity = result.issued_identity.expect("identity");
    assert_eq!(identity.agent_id, "agent-node-a");
    assert_eq!(identity.environment_id, "env-default");
    assert_eq!(identity.tenant_id, "tenant-default");
    assert_eq!(identity.status, AgentIdentityStatus::Active);
    let credential = result.credential_bundle.expect("credential bundle");
    assert_eq!(credential.auth_scheme.as_deref(), Some("bearer"));
    assert!(
        credential
            .bearer_token
            .as_deref()
            .is_some_and(|token| token.starts_with("wic_"))
    );
    assert!(credential.not_after.is_some());
}

#[test]
fn enrollment_rejects_invalid_token_without_identity() {
    let env = TestEnv::new();
    let result = agent_enrollment_result(
        &env.config,
        &env.store,
        enrollment_request("bad-token"),
        "v0.1.0",
    );

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
    assert!(result.agent_id.is_none());
    assert!(result.issued_identity.is_none());
}

#[test]
fn enrollment_rejects_invalid_token_before_generating_credential() {
    let env = TestEnv::new();
    let result = agent_enrollment_result_with_token_issuer(
        &env.config,
        &env.store,
        enrollment_request("bad-token"),
        "v0.1.0",
        |_| panic!("credential generation must not run for an invalid token"),
    );

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
    assert!(result.credential_bundle.is_none());
}

#[test]
fn enrollment_rolls_back_token_reservation_when_credential_generation_fails() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let result = agent_enrollment_result_with_token_issuer(
        &env.config,
        &env.store,
        enrollment_request(&token),
        "v0.1.0",
        |_| Err("injected_random_failure".to_string()),
    );

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("injected_random_failure")
    );
    validate_bootstrap_token_for_config(&env.config, &env.store, &token).expect("token active");
    let snapshot = env.store.load().expect("store load");
    let stored = snapshot
        .enrollment_tokens
        .get(&token_hash(&token))
        .expect("stored enrollment token");
    assert_eq!(stored.used_count, 0);
    assert_eq!(stored.status, StoredEnrollmentTokenStatus::Active);
}

#[test]
fn bootstrap_token_validation_recovers_expired_reservation() {
    let env = TestEnv::new();
    let token = env.issue_token();
    env.store
        .update(|snapshot| {
            let stored = snapshot
                .enrollment_tokens
                .get_mut(&token_hash(&token))
                .expect("stored token");
            stored.used_count = 1;
            stored.status = StoredEnrollmentTokenStatus::Reserved;
            stored.reserved_at =
                Some((chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339());
        })
        .expect("reserve token");

    validate_bootstrap_token_for_config(&env.config, &env.store, &token).expect("token recovered");

    let snapshot = env.store.load().expect("store load");
    let stored = snapshot
        .enrollment_tokens
        .get(&token_hash(&token))
        .expect("stored token");
    assert_eq!(stored.used_count, 0);
    assert_eq!(stored.status, StoredEnrollmentTokenStatus::Active);
    assert!(stored.reserved_at.is_none());
}

#[test]
fn enrollment_consumes_token_and_rejects_replay() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let first = agent_enrollment_result(
        &env.config,
        &env.store,
        enrollment_request(&token),
        "v0.1.0",
    );
    let second = agent_enrollment_result(
        &env.config,
        &env.store,
        enrollment_request(&token),
        "v0.1.0",
    );

    assert_eq!(first.status, EnrollmentStatus::Accepted);
    assert_eq!(second.status, EnrollmentStatus::Rejected);
    assert_eq!(
        second.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
}

#[test]
fn enrollment_rejects_duplicate_agent_registration_without_consuming_token() {
    let env = TestEnv::new();
    let first_token = env.issue_token();
    let second_token = env.issue_token();
    let first = agent_enrollment_result(
        &env.config,
        &env.store,
        enrollment_request(&first_token),
        "v0.1.0",
    );
    let duplicate = agent_enrollment_result(
        &env.config,
        &env.store,
        enrollment_request(&second_token),
        "v0.1.0",
    );

    assert_eq!(first.status, EnrollmentStatus::Accepted);
    assert_eq!(duplicate.status, EnrollmentStatus::Rejected);
    assert_eq!(
        duplicate.reason_code.as_deref(),
        Some("duplicate_agent_registration")
    );
    validate_bootstrap_token_for_config(&env.config, &env.store, &second_token)
        .expect("duplicate registration does not consume token");
}

#[test]
fn enrollment_ignores_unknown_node_id_when_issuing_identity() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let mut request = enrollment_request(&token);
    request.host_profile.node_id = "unknown".to_string();
    request.host_profile.hostname = "host-a".to_string();

    let result = agent_enrollment_result(&env.config, &env.store, request, "v0.1.0");

    assert_eq!(result.agent_id.as_deref(), Some("agent-host-a"));
    assert_eq!(result.instance_id.as_deref(), Some("host-a"));
}

#[test]
fn enrollment_response_uses_contract_wire_status() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let returned = EnrollmentEnvelope {
        result: agent_enrollment_result(
            &env.config,
            &env.store,
            enrollment_request(&token),
            "v0.1.0",
        ),
    };
    let encoded = serde_json::to_string(&returned).expect("encode");

    assert!(encoded.contains("\"status\":\"accepted\""));
    assert!(encoded.contains("\"agent_id\":\"agent-node-a\""));
}

#[tokio::test]
async fn enrollment_handler_returns_created_contract_response() {
    let state = test_state();
    let token = issue_token_for_state(&state);
    let response = enroll_agent(
        State(state),
        super::rate_limit::OptionalConnectInfo(None),
        Json(enrollment_request(&token)),
    )
    .await;
    let status = response.status();
    assert_no_store(&response);
    let returned = decode_enrollment_response(response).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(returned.result.status, EnrollmentStatus::Accepted);
    assert_eq!(returned.result.agent_id.as_deref(), Some("agent-node-a"));
}

#[tokio::test]
async fn enrollment_route_accepts_valid_contract_request() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let response = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let returned = decode_enrollment_response(response).await;
    assert_eq!(returned.result.status, EnrollmentStatus::Accepted);
    assert_eq!(returned.result.agent_id.as_deref(), Some("agent-node-a"));
    assert_eq!(returned.result.instance_id.as_deref(), Some("node-a"));
    assert!(returned.result.issued_identity.is_some());
    assert!(
        returned
            .result
            .credential_bundle
            .as_ref()
            .and_then(|credential| credential.bearer_token.as_deref())
            .is_some_and(|token| token.starts_with("wic_"))
    );
}

#[tokio::test]
async fn agent_status_route_requires_bearer_credential() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let accepted = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let rejected = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        None,
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_status_route_persists_reported_metrics() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let status = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: Some(12_345_678),
            cpu_percent: Some(7.5),
            admin_latency_ms: Some(42),
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let snapshot = env.store.load().expect("load store");
    let stored = snapshot.agents.get("agent-node-a").expect("agent");
    assert_eq!(stored.last_memory_bytes, Some(12_345_678));
    assert_eq!(stored.last_cpu_percent, Some(7.5));
    assert_eq!(stored.last_admin_latency_ms, Some(42));
}

#[tokio::test]
async fn agent_status_route_persists_work_state_changes() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let status = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            work_state_changes: Some(vec![AgentWorkStateChange {
                input_id: "app".to_string(),
                state: AgentWorkState::Paused,
                reason: "spool over limit".to_string(),
                at: "now".to_string(),
            }]),
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let snapshot = env.store.load().expect("load store");
    let stored = snapshot.agents.get("agent-node-a").expect("agent");
    let changes = stored
        .work_state_changes
        .as_deref()
        .expect("work state changes");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].input_id, "app");
    assert_eq!(changes[0].state, AgentWorkState::Paused);
    assert_eq!(changes[0].reason, "spool over limit");
}

#[tokio::test]
async fn agent_status_route_rejects_expired_bearer_credential() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");
    env.store
        .update(|snapshot| {
            let agent = snapshot
                .agents
                .get_mut("agent-node-a")
                .expect("stored agent");
            agent.credential_expires_at = "2026-07-01T00:00:00Z".to_string();
        })
        .expect("expire credential");

    let response = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            work_state_changes: None,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_credential_renewal_rotates_bearer_and_rejects_old_token() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    let returned = decode_enrollment_response(enrollment).await;
    let old_bearer = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let renewed = post_json_to_router(
        &env.config,
        "/api/v1/agent/credentials:renew",
        Some(&old_bearer),
        &CredentialRenewal::new(
            "agent-node-a".to_string(),
            "node-a".to_string(),
            "bearer".to_string(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;
    assert_eq!(renewed.status(), StatusCode::OK);
    let renewed: CredentialRenewed = decode_json_response(renewed).await;
    let new_bearer = renewed
        .credential_bundle
        .bearer_token
        .as_deref()
        .expect("renewed bearer");
    assert!(new_bearer.starts_with("wic_"));
    assert_ne!(new_bearer, old_bearer);

    let old_rejected = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        Some(&old_bearer),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(old_rejected.status(), StatusCode::UNAUTHORIZED);

    let new_accepted = post_json_to_router(
        &env.config,
        "/api/v1/agent/status",
        Some(new_bearer),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            admin_latency_ms: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(new_accepted.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn agent_credential_renewal_requires_current_bearer() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    assert_eq!(enrollment.status(), StatusCode::CREATED);

    let response = post_json_to_router(
        &env.config,
        "/api/v1/agent/credentials:renew",
        None,
        &CredentialRenewal::new(
            "agent-node-a".to_string(),
            "node-a".to_string(),
            "bearer".to_string(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_control_and_action_result_routes_accept_bearer_credential() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let enrollment = post_enrollment_to_router(&env.config, enrollment_request_json(&token)).await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let poll = post_json_to_router(
        &env.config,
        "/api/v1/agent/control-commands:poll",
        Some(&credential),
        &PollControlCommands {
            requested_at: DateTime::now(),
            last_seen_sequence: 7,
            wait_ms: 0,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
        },
    )
    .await;
    assert_eq!(poll.status(), StatusCode::OK);

    let report = post_json_to_router(
        &env.config,
        "/api/v1/agent/action-results",
        Some(&credential),
        &ReportActionResult::new(
            "report-1".to_string(),
            "action-1".to_string(),
            1,
            FinalStatus::Succeeded,
            "exec-1".to_string(),
            "sha256:plan".to_string(),
            "agent-node-a".to_string(),
            "node-a".to_string(),
            ResultAttestation {
                result_digest: "sha256:test".to_string(),
                signature: "test-signature".to_string(),
                issued_by: "agent-node-a".to_string(),
                attested_at: DateTime::now().to_chrono().to_rfc3339(),
            },
            DateTime::now().to_chrono().to_rfc3339(),
            ActionResult::new(
                "action-1".to_string(),
                "exec-1".to_string(),
                FinalStatus::Succeeded,
            ),
        ),
    )
    .await;
    assert_eq!(report.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn enrollment_route_rejects_invalid_token_as_contract_result() {
    let env = TestEnv::new();
    let response =
        post_enrollment_to_router(&env.config, enrollment_request_json("bad-token")).await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let returned = decode_enrollment_response(response).await;
    assert_eq!(returned.result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        returned.result.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
    assert!(returned.result.agent_id.is_none());
    assert!(returned.result.issued_identity.is_none());
}

#[tokio::test]
async fn enrollment_route_rejects_unknown_contract_fields() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let mut payload = serde_json::to_value(enrollment_request(&token)).expect("serialize request");
    payload["unexpected"] = serde_json::json!("not-in-contract");
    let response = post_enrollment_to_router(&env.config, payload.to_string()).await;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn install_code_route_requires_admin_bearer_token() {
    let env = TestEnv::new();
    let missing = get_to_router(&env.config, "/api/v1/agent/install-code", None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let accepted = get_to_router(
        &env.config,
        "/api/v1/agent/install-code",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_no_store(&accepted);
}

#[tokio::test]
async fn install_script_signature_route_returns_matching_signature() {
    let env = TestEnv::new();
    let script_response =
        get_to_router(&env.config, "/api/v1/agent/install/x86/install.sh", None).await;
    assert_eq!(script_response.status(), StatusCode::OK);
    assert_no_store(&script_response);
    let script = body_bytes(script_response).await;

    let signature_response = get_to_router(
        &env.config,
        "/api/v1/agent/install/x86/install.sh.sig",
        None,
    )
    .await;
    assert_eq!(signature_response.status(), StatusCode::OK);
    assert_no_store(&signature_response);
    assert_eq!(
        signature_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/octet-stream")
    );
    let signature = body_bytes(signature_response).await;

    signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(&script, &signature)
        .expect("route signature verifies script body");
}

#[tokio::test]
async fn install_script_route_rejects_unknown_or_injected_arch() {
    let env = TestEnv::new();
    let unknown = get_to_router(&env.config, "/api/v1/agent/install/mips/install.sh", None).await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_no_store(&unknown);

    let injected_script = get_to_router(
        &env.config,
        "/api/v1/agent/install/x86%22%0Aecho%20pwned%0A%23/install.sh",
        None,
    )
    .await;
    assert_eq!(injected_script.status(), StatusCode::NOT_FOUND);
    assert_no_store(&injected_script);

    let injected_signature = get_to_router(
        &env.config,
        "/api/v1/agent/install/x86%22%0Aecho%20pwned%0A%23/install.sh.sig",
        None,
    )
    .await;
    assert_eq!(injected_signature.status(), StatusCode::NOT_FOUND);
    assert_no_store(&injected_signature);
}

#[tokio::test]
async fn admin_overview_route_requires_admin_bearer_token() {
    let env = TestEnv::new();
    let missing = get_to_router(&env.config, "/api/v1/admin/agents/overview", None).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let accepted = get_to_router(
        &env.config,
        "/api/v1/admin/agents/overview",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_routes_rate_limit_failed_bearer_attempts() {
    let env = TestEnv::new();
    let app = router(env.config);

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/agent/install-code")
                    .header("x-real-ip", "192.0.2.10")
                    .header("authorization", "Bearer wrong-admin-token")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let blocked = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/install-code")
                .header("x-real-ip", "192.0.2.10")
                .header("authorization", "Bearer wrong-admin-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key(header::RETRY_AFTER));
    assert_no_store(&blocked);
}

#[tokio::test]
async fn admin_rate_limit_ignores_missing_bearer_requests() {
    let env = TestEnv::new();
    let app = router(env.config);

    // An unauthenticated client (e.g. the web UI polling the overview before a
    // token is entered) must not accumulate rate-limit failures. Send several
    // missing-token requests, then a correct token must be accepted at once
    // instead of being blocked by failures it never caused.
    for _ in 0..6 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/agent/install-code")
                    .header("x-real-ip", "192.0.2.20")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let accepted = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/install-code")
                .header("x-real-ip", "192.0.2.20")
                .header("authorization", format!("Bearer {TEST_ADMIN_API_TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_rate_limit_ignores_spoofed_forwarded_headers() {
    let env = TestEnv::new();
    let app = router(env.config);

    for index in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/agent/install-code")
                    .header("x-forwarded-for", format!("192.0.2.{index}"))
                    .header("x-real-ip", format!("198.51.100.{index}"))
                    .header("authorization", "Bearer wrong-admin-token")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let blocked = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/install-code")
                .header("x-forwarded-for", "203.0.113.99")
                .header("x-real-ip", "203.0.113.100")
                .header("authorization", "Bearer wrong-admin-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_store(&blocked);
}

#[tokio::test]
async fn admin_rate_limit_buckets_failures_per_client_ip() {
    use std::net::SocketAddr;

    use axum::extract::connect_info::MockConnectInfo;

    let env = TestEnv::new();
    let app = router(env.config);

    let request_from = |ip: [u8; 4], port: u16| {
        let mut request = Request::builder()
            .method("GET")
            .uri("/api/v1/agent/install-code")
            .header("authorization", "Bearer wrong-admin-token")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(MockConnectInfo(SocketAddr::from((ip, port))));
        request
    };

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(request_from([192, 0, 2, 1], 40001))
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // The same client is now blocked.
    let blocked = app
        .clone()
        .oneshot(request_from([192, 0, 2, 1], 40001))
        .await
        .expect("route response");
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_no_store(&blocked);

    // A different client keeps its own bucket and is not affected.
    let independent = app
        .oneshot(request_from([198, 51, 100, 1], 40002))
        .await
        .expect("route response");
    assert_eq!(independent.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn initial_config_route_requires_valid_token() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let response = router(env.config.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/initial-config")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);

    let query_token = router(env.config.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/agent/initial-config?token={token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(query_token.status(), StatusCode::UNAUTHORIZED);

    let missing = router(env.config)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/initial-config")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bootstrap_routes_rate_limit_failed_bearer_attempts() {
    let env = TestEnv::new();
    let app = router(env.config);

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/agent/initial-config")
                    .header("x-real-ip", "192.0.2.11")
                    .header("authorization", "Bearer wrong-bootstrap-token")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let blocked = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/initial-config")
                .header("x-real-ip", "192.0.2.11")
                .header("authorization", "Bearer wrong-bootstrap-token")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key(header::RETRY_AFTER));
    assert_no_store(&blocked);
}

#[tokio::test]
async fn agent_package_route_requires_valid_token() {
    let env = TestEnv::new();
    let token = env.issue_token();
    let response = router(env.config.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/packages/current")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);

    let query_token = router(env.config.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/agent/packages/current?token={token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(query_token.status(), StatusCode::UNAUTHORIZED);

    let missing = router(env.config)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/packages/current")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enrollment_route_uses_no_store_and_rate_limits_rejections() {
    let env = TestEnv::new();
    let app = router(env.config);

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/enroll")
                    .header("x-real-ip", "192.0.2.12")
                    .header("content-type", "application/json")
                    .body(Body::from(enrollment_request_json("bad-token")))
                    .expect("request"),
            )
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_no_store(&response);
    }

    let blocked = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/enroll")
                .header("x-real-ip", "192.0.2.12")
                .header("content-type", "application/json")
                .body(Body::from(enrollment_request_json("bad-token")))
                .expect("request"),
        )
        .await
        .expect("route response");

    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key(header::RETRY_AFTER));
    assert_no_store(&blocked);
}

#[tokio::test]
async fn agent_overview_is_empty_before_enrollment() {
    let state = test_state();
    let overview = agent_overview(&state).await;

    assert_eq!(overview.metrics.total_agents, 0);
    assert_eq!(overview.metrics.online_agents, 0);
    assert!(overview.recent_online_agents.is_empty());
    assert!(overview.abnormal_agents.is_empty());
}

#[tokio::test]
async fn agent_overview_reflects_successful_enrollment() {
    let state = test_state();
    let token = issue_token_for_state(&state);
    let mut request = enrollment_request(&token);
    request.capability_summary = "wist-agentd:test,version=v0.9.1".to_string();

    let _ = enroll_agent(
        State(state.clone()),
        super::rate_limit::OptionalConnectInfo(None),
        Json(request),
    )
    .await;
    let overview = agent_overview(&state).await;

    assert_eq!(overview.metrics.total_agents, 1);
    assert_eq!(overview.metrics.online_agents, 1);
    assert_eq!(overview.recent_online_agents.len(), 1);
    assert_eq!(overview.recent_online_agents[0].agent_id, "agent-node-a");
    assert_eq!(overview.recent_online_agents[0].instance_id, "node-a");
    assert_eq!(overview.recent_online_agents[0].version, "v0.9.1");
    assert_eq!(
        overview.recent_online_agents[0].source,
        RecentOnlineRegisteredAgentSource::Real
    );
}

fn enrollment_request(token: &str) -> EnrollmentRequest {
    EnrollmentRequest {
        api_version: "v1".to_string(),
        kind: "submit_enrollment_request".to_string(),
        token: token.to_string(),
        credential_request: "none".to_string(),
        host_profile: wist_contracts::enrollment::HostProfile {
            node_id: "node-a".to_string(),
            hostname: "host-a".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            machine_id: "machine-a".to_string(),
            cloud_instance_id: None,
            k8s_node_uid: None,
            ip_addresses: Vec::new(),
        },
        capability_summary: "wist-agentd:test".to_string(),
        requested_at: "2026-07-28T00:00:00Z".to_string(),
    }
}

struct TestEnv {
    config: AdminConfig,
    store: AdminStore,
    install_public_key_bytes: Vec<u8>,
    _root: std::path::PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("wist-gateway-test-{}", unique_suffix()));
        std::fs::create_dir_all(&root).expect("create root");
        let package_file = root.join("wist-agentd");
        std::fs::write(&package_file, "test-agent-package").expect("write package");
        let tls_cert_file = root.join("admin-tls.crt.pem");
        std::fs::write(&tls_cert_file, TEST_TLS_CERT_PEM).expect("write tls cert");
        let store_file = root.join("state").join("admin-store.json");
        let (install_signing_private_key_file, install_public_key_bytes) =
            write_install_signing_key(&root);
        let install_script_signing_public_key_pem =
            load_install_script_public_key_pem(&install_signing_private_key_file)
                .expect("derive install signing public key");
        let config = AdminConfig {
            listen_addr: "127.0.0.1:3000".to_string(),
            public_base_url: "https://127.0.0.1:3000".to_string(),
            tls_cert_file,
            tls_key_file: root.join("admin-tls.key.pem"),
            admin_api_token_hash: sha256_hex(TEST_ADMIN_API_TOKEN),
            agent_package_file: package_file,
            bootstrap_token_ttl_seconds: 900,
            credential_ttl_seconds: 30 * 24 * 60 * 60,
            store_file: store_file.clone(),
            trust_bundle: "internal-ca-stub".to_string(),
            install_script_signing_private_key_file: install_signing_private_key_file,
            install_script_signing_public_key_pem,
            tenant_id: "tenant-default".to_string(),
            environment_id: "env-default".to_string(),
            victoria_metrics_url: "http://127.0.0.1:18429".to_string(),
        };
        Self {
            config,
            store: AdminStore::new(store_file),
            install_public_key_bytes,
            _root: root,
        }
    }

    fn issue_token(&self) -> String {
        let install_code =
            issue_agent_install_code(&self.config, &self.store).expect("issue token");
        install_code.bootstrap_enrollment_token
    }
}

fn test_state() -> ApiState {
    let env = TestEnv::new();
    ApiState {
        config: env.config,
        store: env.store,
        runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
        rate_limits: Arc::new(Mutex::new(super::rate_limit::RateLimitState::default())),
    }
}

fn issue_token_for_state(state: &ApiState) -> String {
    let install_code =
        issue_agent_install_code(&state.config, &state.store).expect("issue state token");
    install_code.bootstrap_enrollment_token
}

fn enrollment_request_json(token: &str) -> String {
    serde_json::to_string(&enrollment_request(token)).expect("serialize request")
}

async fn get_to_router(
    config: &AdminConfig,
    uri: &str,
    admin_token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = admin_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router(config.clone())
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("route response")
}

async fn post_enrollment_to_router(config: &AdminConfig, body: String) -> axum::response::Response {
    router(config.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/enroll")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("route response")
}

fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

async fn post_json_to_router<T: serde::Serialize>(
    config: &AdminConfig,
    uri: &str,
    bearer_token: Option<&str>,
    body: &T,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router(config.clone())
        .oneshot(
            builder
                .body(Body::from(
                    serde_json::to_string(body).expect("serialize body"),
                ))
                .expect("request"),
        )
        .await
        .expect("route response")
}

async fn decode_enrollment_response(response: axum::response::Response) -> EnrollmentEnvelope {
    decode_json_response(response).await
}

async fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: axum::response::Response,
) -> T {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).expect("json response")
}

async fn body_bytes(response: axum::response::Response) -> axum::body::Bytes {
    to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body bytes")
}

fn write_install_signing_key(root: &std::path::Path) -> (std::path::PathBuf, Vec<u8>) {
    let rng = ring_rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate install signing key");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse signing key");
    let path = root.join("install-signing-ed25519.pkcs8.pem");
    std::fs::write(&path, private_key_pem(pkcs8.as_ref())).expect("write signing key");
    (path, key_pair.public_key().as_ref().to_vec())
}

fn private_key_pem(der: &[u8]) -> String {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let mut output = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(chunk).expect("base64 utf8"));
        output.push('\n');
    }
    output.push_str("-----END PRIVATE KEY-----\n");
    output
}

fn unique_suffix() -> u128 {
    static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(1);
    let seq = NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed) as u128;
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos()
        + seq
}
