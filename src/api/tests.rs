use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    response::Response,
};
use ring::{
    rand as ring_rand,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use tower::ServiceExt;
use wist_api::enrollment::{
    AgentIdentityStatus, CredentialRenewal, CredentialRenewed, EnrollmentEnvelope,
    EnrollmentRequest, EnrollmentStatus,
};
use wist_api::status::{AgentStatusReport, AgentWorkState, AgentWorkStateChange};

use crate::app::knowledge::{KnowledgeSource, LoadedKnowledge};
use crate::infra::{
    AdminConfig, AgentStatusUpdate, DEFAULT_AGENT_UPLINK_PORT, DEFAULT_AGENT_UPLINK_SETTING_ID,
    DEFAULT_INSTALL_PACKAGE_SETTING_ID, KnowledgeActivation, SqliteStore, Store,
    StoredAgentInstallPackage, StoredAgentInstallPackageAddress, StoredAgentRevocation,
    StoredAgentUplinkAddress, StoredCredentialStatus, StoredEnrollmentTokenStatus,
    StoredKnowledgePackage, VerifiedAgentIdentity, bytes_sha256_hex,
    load_install_script_public_key_pem, sha256_hex,
};
use wist_api::action_result::{ReportActionResult, ResultAttestation};
use wist_api::discovery_policies::{
    DiscoveryPoliciesReturned, POLL_DISCOVERY_POLICIES_KIND, PollDiscoveryPolicies,
};
use wist_api::facts::ReportAgentFactSummary;
use wist_api::uplink::{AgentUplinkGrant, POLL_AGENT_UPLINK_KIND};
use wist_api::work::{ACK_WORK_KIND, POLL_WORK_KIND, REPORT_WORK_RESULT_KIND};
use wist_contracts::action_result::{ActionResult, FinalStatus};
use wist_contracts::fact_summary::FactContent;
use wist_contracts::work::WorkSpec;
use wist_control::PollControlCommands;
use wist_control::types::DateTime;

use super::{
    AdminRuntimeState, ApiState,
    enrollment::{agent_enrollment_result, enroll_agent},
    install::{
        agent_initial_config_toml, agent_install_code, issue_agent_install_code, token_hash,
        validate_bootstrap_token_for_config,
    },
    install_package::{AgentPackageSource, package_id_for_sha256, read_package_identity},
    overview::{RecentOnlineRegisteredAgentSource, agent_is_online, agent_overview},
    router,
    work_expiry::expire_overdue_one_shot_works,
};

const TEST_ADMIN_API_TOKEN: &str = "test-admin-token";

/// 测试用的本地制品来源（直接从文件构造 `AgentPackageSource`，不经过库）。
fn local_package(env: &TestEnv) -> AgentPackageSource {
    AgentPackageSource::from_local_file(
        &env.config,
        &env.config.public_base_url,
        env.package_file.clone(),
    )
    .expect("local package source")
}

/// 在 TestEnv 的临时目录里放一个安装包**来源**文件，返回其绝对路径。
fn write_source_package(env: &TestEnv, name: &str, bytes: &[u8]) -> String {
    let path = env._root.join(name);
    std::fs::write(&path, bytes).expect("write source package");
    path.to_string_lossy().to_string()
}

/// 把一份来源制品设置进管理面（走真实 POST），返回（来源路径, 制品摘要）。
async fn set_install_package_source(env: &TestEnv, name: &str, bytes: &[u8]) -> (String, String) {
    let source = write_source_package(env, name, bytes);
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": source }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    (source, bytes_sha256_hex(bytes))
}

/// Self-signed TLS cert (CN=localhost, RSA) written into each TestEnv so the
/// macOS install code can compute its `--pinnedpubkey` pin.
const TEST_TLS_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIDCTCCAfGgAwIBAgIUVlBq6CYit7aQR8CpShgLhKef76gwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwODE0MzIzMFoXDTI3MDkw\nODE0MzIzMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAowBkJchsMBeZcyW2Hntz9fHbM2EYg4Phfn+S4RB2oCzc\n7hXmxB3FUMZ4VKWhF3ruhIFM7Tc6pfSUPx6AqgDJBtvkeA2v+oFR6P0Fsv2Xlczp\neBKpK0vygKjL7jGrHmbofKL5om/ytyQMVjgxhEWW5K54+bvldpa7JnBN3GAJU5KA\nxIAH/5lQSKzlvD6emuUJd62062sVkc9EX7bzM0fOWV2xMEn6JuW9Pa0sCDKZz71u\nIw4sT70inxl7djXxthq/fMekWCrjeNcoLODmMDJgiSUYki1ox1uT9YuXThgIIwHO\nERXzp3xrbO6gOeJgbX4C/aYxcMoaXQGmh89NRmK8MwIDAQABo1MwUTAdBgNVHQ4E\nFgQUDzbiNfr4kpFl2+bL6RmiPBCEgSYwHwYDVR0jBBgwFoAUDzbiNfr4kpFl2+bL\n6RmiPBCEgSYwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEARPZy\nXsWS0A8jnXSRbTxHCSciwic0pFDc9vo+8WyMkz1t754cbrStEhSU9Rl1hE1ZON6v\nVJpdG4Yezhdmx8zfqBbjDNhSjBlrdVRbOyC6oO5KDZHTIVI6mEqAQaRmohHY41y+\nUza+pZL6TIvol3F99ZOmPevIREmGDY9Xy6CxeaiTkSoCg/0XIO/55GeEQSix9YSM\nuvISELAaKycvD37ltjgr4DigLquxs03mCntBcKX7KvpPF6142KLvQxiHyI+VJdtK\nTapJeaMTcQ0i/jLOd47lwGDnQL2Q1RpF6Lp1uTkSDeBFjpJlRzZGnrssHX4vEA0L\nmSymA2FI5OPMsMzExQ==\n-----END CERTIFICATE-----\n";
/// Expected `sha256//` pin (base64 of the sha256 of the SPKI) of the cert above.
const TEST_TLS_CERT_PIN: &str = "uq4O4EN3e09Xmlo5euGldyHw+y27baJ+Jm/OBnFHrZc=";

/// 用手边的本地制品签发一份安装代码：下面几个测试关心的是安装命令/引导包的形态。
async fn local_package_install_code(env: &TestEnv) -> wist_control::types::AgentInstallCode {
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);
    agent_install_code(
        &env.config,
        "token-a",
        expires_at,
        &local_package(env),
        &env.config.public_base_url,
    )
    .expect("install code")
}

#[tokio::test]
async fn install_code_bundle_targets_gateway_package() {
    let env = TestEnv::new().await;
    let install_code = local_package_install_code(&env).await;

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
}

#[tokio::test]
async fn linux_install_code_verifies_signed_script() {
    let env = TestEnv::new().await;
    let install_code = local_package_install_code(&env).await;
    let command = &install_code.x86_linux_install_code;

    assert!(install_code.arm_linux_install_code.contains(
        "curl -fsSLk \"https://127.0.0.1:3000/api/v1/agent/install/arm/install.sh\" -o \"$D/s\""
    ));
    assert!(command.contains(
        "curl -fsSLk \"https://127.0.0.1:3000/api/v1/agent/install/x86/install.sh\" -o \"$D/s\""
    ));
    assert!(command.contains("mktemp -d"));
    // 引导命令只报「在做什么」，不把临时工作目录这种实现细节吐给运维（安装脚本自己有进度输出）。
    assert!(!command.contains("working dir"));
    assert!(command.contains("echo \"==> 校验安装脚本签名\""));
    assert!(command.contains(
        "curl -fsSLk \"https://127.0.0.1:3000/api/v1/agent/install/x86/install.sh.sig\" -o \"$D/sig\""
    ));
    assert!(command.contains("-----BEGIN PUBLIC KEY-----"));
    assert!(command.contains(&env.config.install_script_signing_public_key_pem));
    assert!(command.contains(
        "openssl pkeyutl -verify -pubin -inkey \"$D/key.pem\" -rawin -in \"$D/s\" -sigfile \"$D/sig\""
    ));
    assert!(command.contains("sh \"$D/s\""));
    // 不把脚本管进 shell：必须先验签，验过才执行。
    assert!(!command.contains("| sh"));
}

#[tokio::test]
async fn macos_install_code_pins_gateway_certificate() {
    let env = TestEnv::new().await;
    let install_code = local_package_install_code(&env).await;
    let macos = &install_code.macos_install_code;

    assert!(macos.contains("\"$(uname -s)\" != \"Darwin\""));
    assert!(macos.contains("arm64) ARCH=arm ;; *) ARCH=x86"));
    assert!(macos.contains(&format!(
        "curl -fsSLk --pinnedpubkey \"sha256//{TEST_TLS_CERT_PIN}\" \"https://127.0.0.1:3000/api/v1/agent/install/$ARCH/install.sh\""
    )));
    assert!(macos.contains("sh \"$D/s\""));
    assert!(!macos.contains("working dir"));
    // macOS 靠 curl 的证书锁定认证，不靠 Ed25519 脚本签名（系统自带的 LibreSSL 验不了）。
    assert!(!macos.contains("openssl pkeyutl"));
    assert!(!macos.contains("install.sh.sig"));
}

#[tokio::test]
async fn install_code_leaks_no_enrollment_token() {
    let env = TestEnv::new().await;
    let install_code = local_package_install_code(&env).await;

    // 令牌只能经 Authorization 头或交互输入进入脚本，不能落在命令、URL 或环境变量里。
    assert_eq!(install_code.bootstrap_enrollment_token, "token-a");
    for command in [
        &install_code.x86_linux_install_code,
        &install_code.arm_linux_install_code,
        &install_code.macos_install_code,
    ] {
        assert!(!command.contains("token-a"));
        assert!(!command.contains("?token="));
        assert!(!command.contains("WIST_ENROLLMENT_TOKEN="));
    }
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

#[tokio::test]
async fn issue_install_code_persists_one_time_token() {
    let env = TestEnv::new().await;
    let install_code = issue_agent_install_code(&env.config, &env.store_handle)
        .await
        .expect("install code");
    let token = install_code.bootstrap_enrollment_token;

    validate_bootstrap_token_for_config(&env.config, &env.store_handle, &token)
        .await
        .expect("token valid");
    // The Store trait deliberately exposes no token enumeration, so the old
    // `len() == 1` assertion is preserved with an explicit count query.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enrollment_tokens")
        .fetch_one(env.store.pool())
        .await
        .expect("count enrollment tokens");
    assert_eq!(count, 1);
    let stored = env
        .store
        .get_enrollment_token(&token_hash(&token))
        .await
        .expect("store read")
        .expect("stored enrollment token");
    assert_eq!(stored.max_uses, 1);
    assert_eq!(stored.used_count, 0);
    assert_eq!(stored.status, StoredEnrollmentTokenStatus::Active);
}

fn rendered_install_script(env: &TestEnv) -> String {
    super::install::install_script(
        &env.config,
        "x86",
        &local_package(env),
        &env.config.public_base_url,
    )
}

#[tokio::test]
async fn install_script_verifies_package_digest() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);
    let sha256 = local_package(&env).sha256;

    assert!(script.contains("ARCH=\"x86\""));
    assert!(script.contains("AGENT_PACKAGE_SHA256=\""));
    assert!(script.contains(&sha256));
    assert!(script.contains("sha256sum"));
    assert!(script.contains("shasum -a 256"));
}

#[tokio::test]
async fn install_script_handles_tarball_and_bare_package() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    // 发布产物是 tarball（内含 wist-agentd + wist-exec + wist-upgrader，三者必须同级），
    // 开发/调试时录的可能是一个裸二进制；两种形态都要装到 $BIN_DIR。
    assert!(script.contains("if tar tzf \"$PACKAGE_FILE\""));
    assert!(script.contains("for BIN_NAME in wist-agentd wist-exec wist-upgrader"));
    assert!(script.contains("install_bin \"$SRC\" \"$BIN_NAME\""));
    assert!(script.contains("install_bin \"$PACKAGE_FILE\" \"wist-agentd\""));
    // 必须先写新文件再 rename：直接 cp 到正在运行的二进制上会把该路径改坏
    // （macOS 上之后每次 exec 都被 SIGKILL），重装/升级就会卡在服务注册。
    assert!(script.contains("mv -f \"$BIN_DIR/$2.new\" \"$BIN_DIR/$2\""));
}

#[tokio::test]
async fn install_script_scopes_initial_config_to_token() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    assert!(script.contains("WIST_ENROLLMENT_TOKEN"));
    // 网关生成的安装指令导出的是旧命名，两个名字都要认，否则页面复制出来的命令会丢掉 token。
    assert!(script.contains("WARP_INSIGHT_ENROLLMENT_TOKEN"));
    assert!(script.contains("Enrollment token:"));
    assert!(script.contains("</dev/tty"));
    assert!(script.contains("-H \"authorization: Bearer $WIST_ENROLLMENT_TOKEN\""));
    assert!(script.contains("\"https://127.0.0.1:3000/api/v1/agent/packages/current\""));
    assert!(script.contains("\"https://127.0.0.1:3000/api/v1/agent/initial-config\""));
    assert!(!script.contains("?token="));
    assert!(script.contains("wist-agentd --config-dir"));
}

#[tokio::test]
async fn install_script_places_binaries() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    assert!(script.contains("CONFIG_DIR=\"$WIST_AGENTD_HOME\""));
    assert!(script.contains("BIN_DIR=\"${WIST_AGENTD_BIN_DIR:-/usr/local/bin}\""));
    assert!(script.contains("BIN_DIR=\"${WIST_AGENTD_BIN_DIR:-$HOME/bin}\""));
    assert!(script.contains("WIST_AGENTD_HOME=\"${WIST_AGENTD_HOME:-/etc/wist-agentd}\""));
    assert!(script.contains("WIST_AGENTD_HOME=\"${WIST_AGENTD_HOME:-$HOME/.wist-agentd}\""));
}

#[tokio::test]
async fn install_script_escalates_for_system_scope() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    // 作用域靠 `id -u` 猜会让页面那条普通用户粘贴的指令永远落回用户级：改成显式参数，
    // 默认系统级，并由脚本自己提权。
    assert!(script.contains("SCOPE=\"${WIST_AGENTD_SCOPE:-system}\""));
    assert!(script.contains("if [ \"$SCOPE\" = \"system\" ] && [ \"$(id -u)\" != \"0\" ]; then"));
    // 手工加 sudo 会清掉 token 所在的环境变量，所以重跑自己时把 token 作为参数带过去。
    assert!(script.contains("sh \"$0\" --enrollment-token \"$WIST_ENROLLMENT_TOKEN\""));
    // 免 sudo 的用户级安装是显式退出路径。
    assert!(script.contains("WIST_AGENTD_SCOPE=user"));
}

#[tokio::test]
async fn install_script_resolves_every_placeholder() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    // 漏替换的占位符会让安装端去请求一个字面量 URL（或写出一个叫 `{{...}}` 的文件），
    // 而且只在目标主机上才爆出来 —— 这里当门禁。
    assert!(
        !script.contains("{{"),
        "unresolved placeholder in install script"
    );
}

#[tokio::test]
async fn install_script_locks_down_config() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    assert!(script.contains("umask 077"));
    assert!(script.contains("chmod 0700 \"$CONFIG_DIR\""));
    assert!(script.contains("chmod 0600 \"$CONFIG_DIR/agentd.toml\""));
}

#[tokio::test]
async fn install_script_registers_managed_service() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    // 装完必须交常驻托管（自启 + 崩溃拉起）：root 走系统级，普通用户走用户级；
    // 注册与定义同一步完成，因此必须显式给出 bin / config-dir / 一次性 token。
    assert!(script.contains("\"$BIN_DIR/wist-agentd\" service install \"$SERVICE_SCOPE_ARG\""));
    assert!(script.contains("--bin \"$BIN_DIR/wist-agentd\""));
    assert!(script.contains("--config-dir \"$CONFIG_DIR\""));
    assert!(script.contains("--enrollment-token \"$WIST_ENROLLMENT_TOKEN\""));
    // --force 让重复执行等价于升级：换二进制后必须重建服务进程才会生效。
    assert!(script.contains("--force"));
    assert!(script.contains("SERVICE_SCOPE_ARG=\"--system\""));
    assert!(script.contains("SERVICE_SCOPE_ARG=\"--user\""));
    // 逃生口：只装二进制与配置、自行决定怎么跑。
    assert!(script.contains("WIST_AGENTD_SERVICE"));
}

#[tokio::test]
async fn install_script_reports_numbered_steps() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    // 输出要能一眼看出「现在在哪一步、卡在哪一步」，而不是一堆并列的 key=value：
    // 脚本自己的步骤行带序号，外部工具的输出统一缩进到步骤下面。
    for stage in ["[1/4]", "[2/4]", "[3/4]", "[4/4]"] {
        assert!(
            script.contains(&format!("step \"{stage}")),
            "missing {stage}"
        );
    }
    assert!(script.contains("indent_tool_output <\"$1\""));
    assert!(script.contains("show_tool_output \"$TOOL_OUT\""));
    assert!(script.contains("安装完成：wist-agentd 已交给"));
    // 颜色只在交互终端上生效，重定向到日志 / CM 时必须是纯文本。
    assert!(script.contains("if [ -t 1 ]"));
}

#[tokio::test]
async fn install_script_braces_variables_before_cjk() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);

    // macOS 的 sh 会把紧跟在 `$VAR` 后面的多字节字符吃进变量名（`$X，` 找的是变量 `X，`，
    // 报 unbound variable），而脚本里中文输出很多，极易踩到；紧邻非 ASCII 时必须写 `${X}`。
    let bytes = script.as_bytes();
    let mut offenders = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'$' || bytes.get(index + 1) == Some(&b'{') {
            continue;
        }
        let mut end = index + 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if end > index + 1 && bytes.get(end).is_some_and(|next| !next.is_ascii()) {
            offenders.push(String::from_utf8_lossy(&bytes[index..end]).into_owned());
        }
    }
    assert!(offenders.is_empty(), "needs braces: {offenders:?}");
}

#[tokio::test]
async fn local_package_requires_readable_file() {
    let env = TestEnv::new().await;
    let package_path = env.package_file.clone();
    std::fs::remove_file(&package_path).expect("remove package");

    // 从本地文件构造来源需要读制品算摘要；制品不在就必须显式失败，
    // 而不是把空摘要发下去（那会让安装端跳过校验）。
    let err =
        AgentPackageSource::from_local_file(&env.config, &env.config.public_base_url, package_path)
            .expect_err("unreadable package");

    assert!(!err.is_empty());
}

#[tokio::test]
async fn install_script_signature_matches_script_body() {
    let env = TestEnv::new().await;
    let script = super::install::install_script(
        &env.config,
        "x86",
        &local_package(&env),
        &env.config.public_base_url,
    );
    let signature = super::install::install_script_signature(
        &env.config,
        "x86",
        &local_package(&env),
        &env.config.public_base_url,
    )
    .expect("sign script");

    signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(script.as_bytes(), &signature)
        .expect("signature verifies");
}

#[tokio::test]
async fn install_script_signature_rejects_modified_body() {
    let env = TestEnv::new().await;
    let signature = super::install::install_script_signature(
        &env.config,
        "x86",
        &local_package(&env),
        &env.config.public_base_url,
    )
    .expect("sign script");

    let err = signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(b"tampered install script", &signature)
        .expect_err("tampered script rejected");

    assert_eq!(format!("{err:?}"), "Unspecified");
}

#[tokio::test]
async fn initial_config_matches_agent_config_contract() {
    let env = TestEnv::new().await;
    let text = agent_initial_config_toml(
        &env.config,
        "install-token-a",
        None,
        &env.config.public_base_url,
    );
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
        Some("csr")
    );
    assert_eq!(
        parsed.control_plane.trust_bundle.as_deref(),
        Some("internal-ca-stub")
    );
    // 模板不声明 [paths] / [telemetry.logs.output.file]：布局由 agentd 按配置目录推导，
    // 系统级（/etc/wist-agentd）才能落到 /var/lib/wist-agentd 与 /var/log/wist-agentd。
    // 一旦在此声明（即使值等于默认），agentd 就不再填默认值，系统级安装会退回配置目录下。
    // 只看真正的 section 头，模板注释里会提到这些名字。
    let has_section = |name: &str| text.lines().any(|line| line.trim() == name);
    assert!(!has_section("[paths]"));
    assert!(!has_section("[telemetry.logs.output.file]"));
    // 用户级布局不受影响：契约默认值仍是相对配置目录。
    assert_eq!(parsed.paths.root_dir, ".");
}

/// 新装 Agent 拿到初始配置时就有上送目标（同一域名 + 数据面端口），**不必先有人录入地址**；
/// 但默认仍待命（`enabled = false`）——派活后控制面才在 `uplink:poll` 上下发启用。
#[tokio::test]
async fn initial_config_route_records_the_derived_uplink_target() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let response = router(env.config.clone(), env.store_handle.clone())
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
    let text = decode_text_response(response).await;
    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    assert_eq!(parsed.telemetry.logs.output.kind, "tcp");
    assert_eq!(parsed.telemetry.logs.output.tcp.addr, "127.0.0.1");
    assert_eq!(
        parsed.telemetry.logs.output.tcp.port,
        DEFAULT_AGENT_UPLINK_PORT
    );
    assert!(!parsed.telemetry.logs.output.enabled);
}

#[tokio::test]
async fn initial_config_without_uplink_keeps_local_only_output() {
    let env = TestEnv::new().await;
    let text = agent_initial_config_toml(
        &env.config,
        "install-token-a",
        None,
        &env.config.public_base_url,
    );

    // 待命：enabled = false（不是靠 kind）。没有上送地址就没有目标，用 kind = "file" 表示。
    // `enabled = false` 下事实帧不会被上送，所以也不会再产生 fact summary uplink failed 噪声。
    assert!(text.contains("kind = \"file\""));
    assert!(text.contains("enabled = false"));
    assert!(!text.contains("file_inputs_file"));
    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    assert!(!parsed.telemetry.logs.output.enabled);
    assert_eq!(parsed.telemetry.logs.output.kind, "file");
    assert!(parsed.telemetry.logs.file_inputs.is_empty());
    assert!(parsed.telemetry.logs.file_inputs_file.is_none());
}

#[tokio::test]
async fn initial_config_records_uplink_target_stays_idle() {
    let env = TestEnv::new().await;
    let uplink = StoredAgentUplinkAddress {
        setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
        host: "10.0.1.9".to_string(),
        port: 9100,
        enabled: false,
        updated_by: "ops".to_string(),
        updated_at: "2026-09-21T00:00:00+00:00".to_string(),
    };
    let text = agent_initial_config_toml(
        &env.config,
        "install-token-a",
        Some(&uplink),
        &env.config.public_base_url,
    );

    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    // 上送目标记录下来（kind = tcp）...
    assert_eq!(parsed.telemetry.logs.output.tcp.addr, "10.0.1.9");
    assert_eq!(parsed.telemetry.logs.output.tcp.port, 9100);
    assert_eq!(parsed.telemetry.logs.output.tcp.framing, "line");
    assert_eq!(parsed.telemetry.logs.output.kind, "tcp");
    // ...但 enabled = false：设了地址也不等于开始干活。
    // 待命由 enabled 表达、与 kind 正交：目标记成 tcp，开关仍是关的。
    assert!(!parsed.telemetry.logs.output.enabled);
    assert!(parsed.telemetry.logs.file_inputs.is_empty());
    assert!(parsed.telemetry.logs.file_inputs_file.is_none());
}

#[tokio::test]
async fn initial_config_derives_instance_name_from_token() {
    let env = TestEnv::new().await;
    let first = agent_initial_config_toml(
        &env.config,
        "install-token-a",
        None,
        &env.config.public_base_url,
    );
    let second = agent_initial_config_toml(
        &env.config,
        "install-token-b",
        None,
        &env.config.public_base_url,
    );

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

#[tokio::test]
async fn initial_config_preserves_multiline_trust_bundle() {
    let mut env = TestEnv::new().await;
    let trust_bundle =
        "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n".to_string();
    env.config.trust_bundle = trust_bundle.clone();

    let text = agent_initial_config_toml(
        &env.config,
        "install-token-a",
        None,
        &env.config.public_base_url,
    );
    let trust_bundle_line = text
        .lines()
        .find(|line| line.starts_with("trust_bundle = "))
        .expect("trust_bundle line");
    assert!(trust_bundle_line.contains("\\n"));

    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    assert_eq!(parsed.control_plane.trust_bundle, Some(trust_bundle));
}

#[tokio::test]
async fn enrollment_accepts_valid_token_and_issues_identity() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        enrollment_request(&token),
        "v0.1.0",
    )
    .await;

    assert_eq!(result.status, EnrollmentStatus::Accepted);
    assert_eq!(result.agent_id.as_deref(), Some("agent-node-a"));
    assert_eq!(result.instance_id.as_deref(), Some("node-a"));
    let identity = result.issued_identity.expect("identity");
    assert_eq!(identity.agent_id, "agent-node-a");
    assert_eq!(identity.environment_id, "env-default");
    assert_eq!(identity.tenant_id, "tenant-default");
    assert_eq!(identity.status, AgentIdentityStatus::Active);
    let credential = result.credential_bundle.expect("credential bundle");
    // mTLS 是唯一凭据路径：注册必须换回一张客户端证书。
    assert!(credential.certificate.contains("BEGIN CERTIFICATE"));
    assert!(credential.not_after.is_some());
}

#[tokio::test]
async fn enrollment_rejects_invalid_token_without_identity() {
    let env = TestEnv::new().await;
    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        None,
        enrollment_request("bad-token"),
        "v0.1.0",
    )
    .await;

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
    assert!(result.agent_id.is_none());
    assert!(result.issued_identity.is_none());
}

#[tokio::test]
async fn enrollment_rejects_invalid_token_before_generating_credential() {
    let env = TestEnv::new().await;
    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        enrollment_request("bad-token"),
        "v0.1.0",
    )
    .await;

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
    assert!(result.credential_bundle.is_none());
}

#[tokio::test]
async fn enrollment_rolls_back_reservation_on_credential_failure() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    // 预留成功后才失败的时刻：CSR 坏了 → 签不出证书 → 拒绝，并回滚 token 预留。
    let mut request = enrollment_request(&token);
    request.certificate_signing_request = "not a csr".to_string();
    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        request,
        "v0.1.0",
    )
    .await;

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert!(
        result
            .reason_code
            .as_deref()
            .unwrap_or_default()
            .starts_with("invalid_certificate_signing_request"),
        "{:?}",
        result.reason_code
    );
    validate_bootstrap_token_for_config(&env.config, &env.store_handle, &token)
        .await
        .expect("token active");
    let stored = env
        .store
        .get_enrollment_token(&token_hash(&token))
        .await
        .expect("store read")
        .expect("stored enrollment token");
    assert_eq!(stored.used_count, 0);
    assert_eq!(stored.status, StoredEnrollmentTokenStatus::Active);
}

#[tokio::test]
async fn bootstrap_token_validation_recovers_expired_reservation() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let token_hash = token_hash(&token);
    // Test-only seam: the public Store API intentionally never exposes raw writes
    // to token internals, so a stale reservation is forced directly via SQL.
    let reserved_at = (chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
    sqlx::query(
        "UPDATE enrollment_tokens SET status = 'reserved', used_count = 1, reserved_at = ?1 \
         WHERE token_hash = ?2",
    )
    .bind(&reserved_at)
    .bind(&token_hash)
    .execute(env.store.pool())
    .await
    .expect("seed stale reservation");

    validate_bootstrap_token_for_config(&env.config, &env.store_handle, &token)
        .await
        .expect("token recovered");

    let stored = env
        .store
        .get_enrollment_token(&token_hash)
        .await
        .expect("store read")
        .expect("stored token");
    assert_eq!(stored.used_count, 0);
    assert_eq!(stored.status, StoredEnrollmentTokenStatus::Active);
    assert!(stored.reserved_at.is_none());
}

#[tokio::test]
async fn enrollment_consumes_token_and_rejects_replay() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let first = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        enrollment_request(&token),
        "v0.1.0",
    )
    .await;
    let second = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        enrollment_request(&token),
        "v0.1.0",
    )
    .await;

    assert_eq!(first.status, EnrollmentStatus::Accepted);
    assert_eq!(second.status, EnrollmentStatus::Rejected);
    assert_eq!(
        second.reason_code.as_deref(),
        Some("invalid_enrollment_token")
    );
}

#[tokio::test]
async fn enrollment_rejects_duplicate_agent_without_consuming_token() {
    let env = TestEnv::new().await;
    let first_token = env.issue_token().await;
    let second_token = env.issue_token().await;
    let first = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        enrollment_request(&first_token),
        "v0.1.0",
    )
    .await;
    let duplicate = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        enrollment_request(&second_token),
        "v0.1.0",
    )
    .await;

    assert_eq!(first.status, EnrollmentStatus::Accepted);
    assert_eq!(duplicate.status, EnrollmentStatus::Rejected);
    assert_eq!(
        duplicate.reason_code.as_deref(),
        Some("duplicate_agent_registration")
    );
    validate_bootstrap_token_for_config(&env.config, &env.store_handle, &second_token)
        .await
        .expect("duplicate registration does not consume token");
}

#[tokio::test]
async fn enrollment_ignores_unknown_node_id() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let mut request = enrollment_request(&token);
    request.host_profile.node_id = "unknown".to_string();
    request.host_profile.hostname = "host-a".to_string();

    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        Some(&env_agent_ca(&env)),
        request,
        "v0.1.0",
    )
    .await;

    assert_eq!(result.agent_id.as_deref(), Some("agent-host-a"));
    assert_eq!(result.instance_id.as_deref(), Some("host-a"));
}

#[tokio::test]
async fn enrollment_response_uses_contract_wire_status() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let returned = EnrollmentEnvelope {
        result: agent_enrollment_result(
            &env.config,
            &env.store_handle,
            Some(&env_agent_ca(&env)),
            enrollment_request(&token),
            "v0.1.0",
        )
        .await,
    };
    let encoded = serde_json::to_string(&returned).expect("encode");

    assert!(encoded.contains("\"status\":\"accepted\""));
    assert!(encoded.contains("\"agent_id\":\"agent-node-a\""));
}

#[tokio::test]
async fn enrollment_handler_returns_created_contract_response() {
    let state = test_state().await;
    let token = issue_token_for_state(&state).await;
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
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let response = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let returned = decode_enrollment_response(response).await;
    assert_eq!(returned.result.status, EnrollmentStatus::Accepted);
    assert_eq!(returned.result.agent_id.as_deref(), Some("agent-node-a"));
    assert_eq!(returned.result.instance_id.as_deref(), Some("node-a"));
    assert!(returned.result.issued_identity.is_some());
    let bundle = returned
        .result
        .credential_bundle
        .expect("credential bundle");
    // mTLS 是唯一凭据路径：回包里必须是一张客户端证书。
    assert!(bundle.certificate.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn agent_status_route_requires_a_client_certificate() {
    let env = TestEnv::new().await;
    let agent_id = enroll_agent_credential(&env).await;

    let accepted = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&agent_id),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let rejected = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        None,
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_status_route_persists_reported_metrics() {
    let env = TestEnv::new().await;
    let agent_id = enroll_agent_credential(&env).await;

    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&agent_id),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: Some(12_345_678),
            cpu_percent: Some(7.5),
            cpu_cores: Some(4),
            admin_latency_ms: Some(42),
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("agent");
    assert_eq!(stored.last_memory_bytes, Some(12_345_678));
    assert_eq!(stored.last_cpu_percent, Some(7.5));
    assert_eq!(stored.last_cpu_cores, Some(4));
    assert_eq!(stored.last_admin_latency_ms, Some(42));
}

/// 发一次带 CPU 字段的状态上报（只关心 `cpu_percent` / `cpu_cores`）。
async fn post_agent_status_cpu(
    env: &TestEnv,
    agent_id: &str,
    cpu_percent: Option<f64>,
    cpu_cores: Option<u32>,
) -> Response {
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(agent_id),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent,
            cpu_cores,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await
}

/// GET 管理面 Agent 列表（已带 admin token）。
async fn admin_agent_list(env: &TestEnv) -> serde_json::Value {
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

#[tokio::test]
async fn admin_agent_list_derives_machine_cpu_percent_from_cores() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_at_node(&env, "node-a").await;

    // 单核口径 50% ÷ 4 核 = 整机 12.5%。
    let accepted = post_agent_status_cpu(&env, &credential, Some(50.0), Some(4)).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let body = admin_agent_list(&env).await;
    assert_eq!(body["agents"][0]["cpu_percent"], 50.0);
    assert_eq!(body["agents"][0]["cpu_cores"], 4);
    assert_eq!(body["agents"][0]["cpu_percent_of_machine"], 12.5);

    // 老版本 agentd 没报核数（None）→ 算不出，返回 null，而不是 0。
    let accepted = post_agent_status_cpu(&env, &credential, Some(50.0), None).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let body = admin_agent_list(&env).await;
    assert!(body["agents"][0]["cpu_cores"].is_null());
    assert!(body["agents"][0]["cpu_percent_of_machine"].is_null());

    // 核数为 0（非法）→ 不除零，同样返回 null。
    let accepted = post_agent_status_cpu(&env, &credential, Some(50.0), Some(0)).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let body = admin_agent_list(&env).await;
    assert_eq!(body["agents"][0]["cpu_cores"], 0);
    assert!(body["agents"][0]["cpu_percent_of_machine"].is_null());
}

// ── 事实上报（摘要）与用途推断 ──────────────────────────────────────────

/// 精简规则表：只留推得动最小闭环的几条（完整策展数据在 jumo 模型仓）。
const TEST_PURPOSE_RULES: &str = r#"
purpose_version = 1
[[rule_set]]
rule_set_id = "macos-v1"
platform = "macos"
baseline_class = "MacDaily"
weak_score = 20

[[rule_set.rules]]
rule_id = "mac-dev-xcodebuild"
kind = "process"
pattern = "xcodebuild"
machine_class = "MacDev"
weight = 40

[[rule_set.rules]]
rule_id = "mac-dev-homebrew-arm"
kind = "process_path"
pattern = "/opt/homebrew"
machine_class = "MacDev"
weight = 30
"#;

/// 报文骨架（`content_digest` 先空着，由调用方填）。
///
/// 注意它造的是**声明**：网关会用 `wist_contracts::fact_summary` 自己重算一份，
/// 声明不一致只记告警，不影响判重。
fn raw_fact_report(processes: &[&str]) -> ReportAgentFactSummary {
    ReportAgentFactSummary::new_agent_facts(
        "report-1".to_string(),
        "agent-node-a".to_string(),
        "node-a".to_string(),
        String::new(),
        7,
        "2026-09-22T00:00:00Z".to_string(),
        "macos".to_string(),
        "arm64".to_string(),
        processes.len() as i64,
        processes.iter().map(|value| value.to_string()).collect(),
        Vec::new(),
        Vec::new(),
        "2026-09-22T00:00:01Z".to_string(),
    )
}

/// 网关会算出的内容摘要（与生产代码同一实现）。
fn digest_of(report: &ReportAgentFactSummary) -> String {
    FactContent::new(
        report.os.clone(),
        report.arch.clone(),
        report.process_executables.clone(),
        report.packages.clone(),
        report.listen_ports.clone(),
    )
    .content_digest()
}

/// 一份「声明正确」的报文：`content_digest` 与网关自算一致。
fn fact_report(processes: &[&str]) -> ReportAgentFactSummary {
    let mut report = raw_fact_report(processes);
    report.content_digest = digest_of(&report);
    report
}

/// 一份「声明被写错」的报文：用来验证判重不看声明。
fn fact_report_declaring(processes: &[&str], declared: &str) -> ReportAgentFactSummary {
    let mut report = raw_fact_report(processes);
    report.content_digest = declared.to_string();
    report
}

/// 一份带发现展示字段的报文（主机标识 / 主机名 / 网卡地址）。
///
/// 展示字段不进内容摘要，所以摘要仍按内容字段算 —— 这正是要锁住的前提。
fn fact_report_with_display(
    processes: &[&str],
    host_id: &str,
    host_name: &str,
    network_addresses: &[&str],
) -> ReportAgentFactSummary {
    fact_report(processes).with_display(
        host_id.to_string(),
        host_name.to_string(),
        network_addresses
            .iter()
            .map(|value| value.to_string())
            .collect(),
    )
}

/// 注册一个 Agent 并拿回 bearer 凭据（事实上报路径要它）。
async fn enroll_agent_credential(env: &TestEnv) -> String {
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    // 返回的是 **agent_id**（不是 bearer token）：agent 侧现在**只有证书**这一条凭据路径，
    // 测试里就用它当「握手期注入的证书身份」（`post_agent_json_to_router`）。
    decode_enrollment_response(enrollment)
        .await
        .result
        .agent_id
        .expect("agent id")
}

/// 把一份摘要当作**数据面转发来的记录**投给网关（这是事实唯一的入口）。
///
/// 控制面那条直报路由已删（`POST /api/v1/agent/facts`，见 doc/design/center/
/// agent-work-delivery-plan.md §4.1）。
/// 注意：本函数**不消费凭据** —— 数据面这条路没有身份校验（挂起中，见 §8 #17）。
/// 测试里仍需要先把 agent 注册进登记表（`enroll_agent_credential`），否则会被拒。
async fn post_facts(env: &TestEnv, report: &ReportAgentFactSummary) -> Response {
    post_to_ingest_router(env, &data_plane_record(&report.agent_id, report)).await
}

async fn get_purpose_view(env: &TestEnv, agent_id: &str) -> serde_json::Value {
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        &format!("/api/v1/admin/agents/{agent_id}/purpose"),
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

#[tokio::test]
async fn fact_summary_ingest_rejects_an_unparseable_body() {
    // 控制面那条路由删了，但「不可解析的上报必须显形」这条不能丢：数据面这条路同样要有。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;

    let rejected = post_to_ingest_router(
        &env,
        &serde_json::json!({ "agent_id": "agent-node-a", "body": "{ not json" }),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fact_summary_ingest_stores_the_summary_and_produces_a_suggestion() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let report = fact_report(&["/usr/bin/xcodebuild", "launchd"]);

    let accepted = post_facts(&env, &report).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    // 存的是**网关自算**的摘要，不是照抄声明（数据面那条回执不回转发的载荷）。
    assert_eq!(stored.content_digest, digest_of(&report));
    assert_eq!(stored.process_count, 2);
    assert_eq!(
        stored.process_executables,
        vec!["/usr/bin/xcodebuild", "launchd"]
    );

    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["agent_id"], "agent-node-a");
    // 建议确实**落库**了（不再看回执里带不带 suggestion_id：
    // 数据面的回执只报“这批记录处理结果”，不带业务字段）。
    assert!(
        env.store
            .get_purpose_suggestion("agent-node-a")
            .await
            .expect("store read")
            .is_some()
    );
    assert_eq!(view["fact_summary"]["content_digest"], digest_of(&report));
    assert_eq!(view["suggestion"]["suggested_class"], "MacDev");
    // 单类命中（无次高分）→ 100；40 >= weak_score(20) 不打折。
    assert_eq!(view["suggestion"]["confidence"], 100);
    assert_eq!(view["suggestion"]["method"], "rule");
    assert_eq!(view["suggestion"]["rule_set_id"], "macos-v1");
    assert_eq!(
        view["suggestion"]["signals"][0]["rule_id"],
        "mac-dev-xcodebuild"
    );
    assert_eq!(
        view["suggestion"]["signals"][0]["value"],
        "/usr/bin/xcodebuild"
    );
    // 没写过判定 → classification 为空（页面看到的是「还没人定」，不是默认值）。
    assert!(view["classification"].is_null());
}

#[tokio::test]
async fn fact_summary_ingest_is_idempotent_on_the_content_digest() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let report = fact_report(&["/usr/bin/xcodebuild"]);

    assert_eq!(
        post_facts(&env, &report).await.status(),
        StatusCode::ACCEPTED
    );
    let first = env
        .store
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("store read")
        .expect("suggestion");

    // 重发同一份内容：不重写、不重算，建议 id 不变（而不是被重新算成新 id）。
    assert_eq!(
        post_facts(&env, &report).await.status(),
        StatusCode::ACCEPTED
    );
    let second = env
        .store
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("store read")
        .expect("suggestion");
    assert_eq!(second.suggestion_id, first.suggestion_id);
}

#[tokio::test]
async fn fact_summary_ingest_dedupes_on_its_own_digest_not_the_declaration() {
    // 恶意/退化的 agent 声明一个**常量**摘要：若判重用声明，第二份不同内容就会被当重复，
    // 视图静默停在旧内容上。网关自算，所以必须识别出内容变了。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;

    assert_eq!(
        post_facts(
            &env,
            &fact_report_declaring(&["launchd"], "sha256:constant")
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post_facts(
            &env,
            &fact_report_declaring(&["xcodebuild"], "sha256:constant")
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    // 存的是网关自算的摘要，不是被声明的常量；且第二份内容真的覆盖进去了。
    assert_ne!(stored.content_digest, "sha256:constant");
    assert_eq!(stored.process_executables, vec!["xcodebuild"]);
}

#[tokio::test]
async fn fact_summary_ingest_refreshes_only_marks_on_duplicate() {
    // 内容没变、只是又采了一轮：只刷留痕（revision/observed_at/process_count/received_at），
    // 内容列与幂等键不动，也不重算建议。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let report = fact_report(&["/usr/bin/xcodebuild"]);

    assert_eq!(
        post_facts(&env, &report).await.status(),
        StatusCode::ACCEPTED
    );
    let first_suggestion = env
        .store
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("store read")
        .expect("suggestion");
    let digest = digest_of(&report);

    let mut rerun = report.clone();
    rerun.revision = 999;
    rerun.observed_at = "2026-09-22T01:00:00Z".to_string();
    rerun.process_count = 42;
    rerun.reported_at = "2026-09-22T01:00:01Z".to_string();
    assert_eq!(
        post_facts(&env, &rerun).await.status(),
        StatusCode::ACCEPTED
    );
    // 建议不重算（id 不变）。
    assert_eq!(
        env.store
            .get_purpose_suggestion("agent-node-a")
            .await
            .expect("store read")
            .expect("suggestion")
            .suggestion_id,
        first_suggestion.suggestion_id
    );

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    // 留痕被刷新。
    assert_eq!(stored.revision, 999);
    assert_eq!(stored.observed_at, "2026-09-22T01:00:00Z");
    assert_eq!(stored.process_count, 42);
    // 内容与幂等键不变。
    assert_eq!(stored.content_digest, digest);
    assert_eq!(stored.process_executables, vec!["/usr/bin/xcodebuild"]);
}

#[tokio::test]
async fn agent_facts_route_stores_host_and_network_discovery_fields() {
    // agentd 一直在采集发现方向的 host.id / host.name 与网卡地址，以前不上传：
    // 这三个字段是**展示用留痕**，运维要在用途页上看得见「这台到底是谁」。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let report = fact_report_with_display(
        &["/usr/bin/xcodebuild"],
        "machine-id-abc123",
        "macbook-pro",
        &["en0 192.168.1.5/24", "utun3 10.8.0.2/32"],
    );

    let accepted = post_facts(&env, &report).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    assert_eq!(stored.host_id, "machine-id-abc123");
    assert_eq!(stored.host_name, "macbook-pro");
    assert_eq!(
        stored.network_addresses,
        vec!["en0 192.168.1.5/24", "utun3 10.8.0.2/32"]
    );

    // 管理面直接序列化同一个结构：这里锁住「自动流过去」，而不是另加一个响应字段。
    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["fact_summary"]["host_id"], "machine-id-abc123");
    assert_eq!(view["fact_summary"]["host_name"], "macbook-pro");
    assert_eq!(
        view["fact_summary"]["network_addresses"],
        serde_json::json!(["en0 192.168.1.5/24", "utun3 10.8.0.2/32"])
    );
    // 展示字段没进内容摘要：摘要仍是内容字段算出来的那一份。
    assert_eq!(view["fact_summary"]["content_digest"], digest_of(&report));
}

#[tokio::test]
async fn agent_facts_route_stores_empty_display_fields_for_legacy_agents() {
    // 旧 agentd 的报文里**根本没有**这三个键：`serde(default)` 必须让上报照常成功，
    // 库里留空值（页面显示「—」并注明旧版 agentd 不带这些字段）。
    // 这里走数据面记录的 body（契约对象原样透传），所以直接把 legacy 对象序列化进 body。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let mut legacy = serde_json::to_value(fact_report(&["/usr/bin/xcodebuild"])).expect("json");
    let object = legacy.as_object_mut().expect("report object");
    object.remove("host_id");
    object.remove("host_name");
    object.remove("network_addresses");

    let accepted = post_to_ingest_router(
        &env,
        &serde_json::json!({
            "agent_id": "agent-node-a",
            "body": serde_json::to_string(&legacy).expect("legacy body"),
        }),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    assert_eq!(stored.host_id, "");
    assert_eq!(stored.host_name, "");
    assert!(stored.network_addresses.is_empty());

    // 管理面也照原样给空值（不是缺键）：页面自己决定怎么显示空。
    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["fact_summary"]["host_id"], "");
    assert_eq!(
        view["fact_summary"]["network_addresses"],
        serde_json::json!([])
    );
}

// ── 数据面订阅端点（warp-parse → 网关内部接入）────────────────────────────
//
// 与上面「控制面直报」共用同一个核心（`agent_ops::ingest_fact_summary`），所以这里
// **不**重复测入库/判重/推断语义，只测这一层独有的东西：记录形状、身份对不上、批次。

/// 把一份摘要包装成 warp-parse 记录（`agent-facts/json` sink 的落盘形状）。
/// 形状取自真实输出：`{"schema","agent_id","observed_at","seq","category","log_desc","body",…}`，
/// 其中 `body` 是契约对象的 **JSON 文本**（WPL/OML 不做字段建模）。
fn data_plane_record(envelope_agent: &str, report: &ReportAgentFactSummary) -> serde_json::Value {
    serde_json::json!({
        "schema": "v1",
        "agent_id": envelope_agent,
        "observed_at": "2026-09-22T00:00:00Z",
        "seq": 4242,
        "category": "agent.fact",
        "log_desc": "Agent 事实",
        "body": serde_json::to_string(report).expect("serialize report"),
    })
}

async fn post_to_ingest_router(env: &TestEnv, payload: &serde_json::Value) -> Response {
    post_to_ingest_uri(env, "/api/v1/ingest/agent-facts", payload).await
}

async fn post_logs_to_ingest_router(env: &TestEnv, payload: &serde_json::Value) -> Response {
    post_to_ingest_uri(env, "/api/v1/ingest/agent-logs", payload).await
}

async fn post_to_ingest_uri(env: &TestEnv, uri: &str, payload: &serde_json::Value) -> Response {
    super::ingest_router(super::build_state(
        env.config.clone(),
        Arc::clone(&env.store_handle),
    ))
    .oneshot(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(payload).expect("body")))
            .expect("request"),
    )
    .await
    .expect("route response")
}

#[tokio::test]
async fn ingest_endpoint_stores_fact_summary_forwarded_by_the_data_plane() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    // 这条路径**不带 agent 凭据**：只要 agent 在登记表里、instance 对得上就收。
    enroll_agent_credential(&env).await;
    let report = fact_report(&["/usr/bin/xcodebuild", "launchd"]);
    let record = data_plane_record("agent-node-a", &report);

    let response = post_to_ingest_router(&env, &record).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    // 判重键仍是**网关自算**的那一份，不是转发链路上那一份。
    assert_eq!(stored.content_digest, digest_of(&report));
    assert_eq!(stored.process_count, 2);

    // 入库后用途推断照常跑（与直报路径同一个核心）——这才算链路通了。
    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["suggestion"]["suggested_class"], "MacDev");
}

#[tokio::test]
async fn ingest_endpoint_accepts_a_batch_of_records() {
    // sink 的 `batch_size` 将来调大就会出现数组，这里先钉住形状。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let record = data_plane_record("agent-node-a", &fact_report(&["/usr/bin/xcodebuild"]));

    let response = post_to_ingest_router(&env, &serde_json::json!([record])).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["ingested"], 1);
    assert_eq!(body["rejected"], 0);
}

/// 数据面累计计数：接收事实后，自述面（admin 读口）的 `ingest_accepted_total` / `last_ingest_at` 要动。
#[tokio::test]
async fn ingest_bumps_self_state_data_plane_counters() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    // **同一份 state** 串内两点（接入 + 自述面），否则计数随每次 build_state 重置。
    let state = super::build_state(env.config.clone(), Arc::clone(&env.store_handle));

    let before: serde_json::Value =
        decode_json_response(get_from_state(&state, "/api/v1/admin/gateway/self-state").await)
            .await;
    assert_eq!(before["ingest_accepted_total"], 0);
    assert_eq!(before["last_ingest_at"], serde_json::Value::Null);

    let record = data_plane_record("agent-node-a", &fact_report(&["/usr/bin/xcodebuild"]));
    let response = super::ingest_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ingest/agent-facts")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&record).expect("body")))
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let after: serde_json::Value =
        decode_json_response(get_from_state(&state, "/api/v1/admin/gateway/self-state").await)
            .await;
    assert_eq!(after["ingest_accepted_total"], 1, "收到一条事实应 +1");
    assert_eq!(after["ingest_rejected_total"], 0);
    assert!(
        !after["last_ingest_at"].is_null(),
        "last_ingest_at 应被记下"
    );
}

#[tokio::test]
async fn ingest_endpoint_rejects_an_unregistered_agent() {
    // 「不存在的机器」不得被写进库：登记表是这条路径唯一的身份锚。
    let env = TestEnv::new().await;
    // 信封与正文都自称同一台**未注册**的 agent：先排除「自称不一致」那条分支。
    let mut report = fact_report(&["/usr/bin/xcodebuild"]);
    report.agent_id = "agent-ghost".to_string();
    let record = data_plane_record("agent-ghost", &report);

    let response = post_to_ingest_router(&env, &record).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["rejected"], 1);
    assert!(
        body["failures"][0]
            .as_str()
            .expect("failure text")
            .contains("unknown agent_id"),
        "got {body}"
    );
    assert!(
        env.store
            .get_agent_fact_summary("agent-ghost")
            .await
            .expect("store read")
            .is_none()
    );
}

#[tokio::test]
async fn ingest_endpoint_rejects_an_instance_id_mismatch() {
    // agentd 重装后 instance_id 会变。若照收，两台机器的观测会混进同一行。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let mut report = fact_report(&["/usr/bin/xcodebuild"]);
    report.instance_id = "node-b".to_string();

    let response = post_to_ingest_router(&env, &data_plane_record("agent-node-a", &report)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert!(
        body["failures"][0]
            .as_str()
            .expect("failure text")
            .contains("instance_id mismatch"),
        "got {body}"
    );
}

#[tokio::test]
async fn ingest_endpoint_rejects_an_envelope_body_disagreement() {
    // 信封与正文的自称不一致，说明中间环节出了问题 —— 现在两边都不是身份依据，
    // 但不一致必须显形，而不是挑一个信。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let record = data_plane_record("agent-other", &fact_report(&["/usr/bin/xcodebuild"]));

    let response = post_to_ingest_router(&env, &record).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert!(
        body["failures"][0]
            .as_str()
            .expect("failure text")
            .contains("disagrees with body agent_id"),
        "got {body}"
    );
}

#[tokio::test]
async fn ingest_endpoint_reports_the_shape_it_received_when_the_record_is_wrong() {
    // 数据面的记录结构一变，这条错误要能直接指出收到了什么（否则只能靠翻代码猜）。
    let env = TestEnv::new().await;

    let response = post_to_ingest_router(&env, &serde_json::json!({"hello": "world"})).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    let failure = body["failures"][0].as_str().expect("failure text");
    assert!(
        failure.contains("not a data-plane fact record") && failure.contains("hello"),
        "got {failure}"
    );
}

#[tokio::test]
async fn ingest_endpoint_rejects_a_body_that_is_not_a_fact_summary() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let record = serde_json::json!({
        "agent_id": "agent-node-a",
        "body": "{\"unexpected\": true}",
    });

    let response = post_to_ingest_router(&env, &record).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert!(
        body["failures"][0]
            .as_str()
            .expect("failure text")
            .contains("body is not a ReportAgentFactSummary"),
        "got {body}"
    );
}

// ── 采集日志的本地落盘（数据面 → 网关内部接入）────────────────────────────
//
// 日志与事实走同一条上行通道，但**落点不同**：事实进 SQLite，日志落本地 NDJSON 文件。
// 这里测的是「文件真的写进去了、能按台筛、读得回来」。

/// 一份日志记录的数据面落盘形状（`macos-agent/json` sink）。
/// 形状取自真实输出：`{"schema","agent_id","observed_at","seq","category","log_desc","raw",…}`。
fn data_plane_log_record(envelope_agent: &str, raw: &str) -> serde_json::Value {
    serde_json::json!({
        "schema": "v1",
        "agent_id": envelope_agent,
        "observed_at": "2026-09-23T12:24:27.734612Z",
        "seq": 292,
        "category": "agent.log",
        "log_desc": "Agent 日志-原文",
        "raw": raw,
    })
}

/// 读回落盘的日志记录（文件不存在 = 空）。
fn log_file_records(env: &TestEnv) -> Vec<crate::infra::AgentLogRecord> {
    let path = env.config.agent_log_file();
    if !path.is_file() {
        return Vec::new();
    }
    std::fs::read_to_string(&path)
        .expect("read log file")
        .lines()
        .map(|line| serde_json::from_str(line).expect("log record"))
        .collect()
}

/// 数据面记录（**新版 agentd**：信封里带 `family`/`unit`，落到记录的这两个字段）。
fn data_plane_log_record_with_family(
    envelope_agent: &str,
    family: &str,
    unit: &str,
    raw: &str,
) -> serde_json::Value {
    let mut record = data_plane_log_record(envelope_agent, raw);
    let object = record.as_object_mut().expect("record object");
    object.insert("family".to_string(), serde_json::json!(family));
    object.insert("unit".to_string(), serde_json::json!(unit));
    record
}

async fn get_admin(env: &TestEnv, uri: &str) -> Response {
    get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await
}

#[tokio::test]
async fn ingest_endpoint_appends_agent_logs_to_the_local_file() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let raw = "2026-09-23 20:24:24+08 MacBook-Pro-2 softwareupdated[565]: SUOSUPowerEventObserver: System will sleep";

    let response =
        post_logs_to_ingest_router(&env, &data_plane_log_record("agent-node-a", raw)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["ingested"], 1);
    assert_eq!(body["rejected"], 0);

    let stored = log_file_records(&env);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].agent_id, "agent-node-a");
    assert_eq!(stored[0].raw, raw);
    assert_eq!(stored[0].seq, 292);
    assert_eq!(stored[0].category, "agent.log");
    assert_eq!(stored[0].log_desc, "Agent 日志-原文");
    assert_eq!(stored[0].observed_at, "2026-09-23T12:24:27.734612Z");
    assert!(!stored[0].received_at.is_empty());
}

#[tokio::test]
async fn ingest_endpoint_keeps_a_multiline_record_on_a_single_ndjson_line() {
    // 一条多行记录在文件里仍占**一行** NDJSON：`raw` 里的换行被 JSON 转义，
    // 读回来还是多行 —— 这正是「一条记录」在落盘层的形状。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let raw = "REC-A start\n\tcontinuation A1\n\tcontinuation A2";

    let response =
        post_logs_to_ingest_router(&env, &data_plane_log_record("agent-node-a", raw)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let text = std::fs::read_to_string(env.config.agent_log_file()).expect("read log file");
    assert_eq!(text.lines().count(), 1, "one record must be one line");
    assert_eq!(log_file_records(&env)[0].raw, raw);
}

#[tokio::test]
async fn ingest_endpoint_accepts_a_batch_of_log_records() {
    // sink 的 `batch_size` 将来调大就会出现数组，这里先钉住形状。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let batch = serde_json::json!([
        data_plane_log_record("agent-node-a", "first"),
        data_plane_log_record("agent-node-a", "second"),
    ]);

    let response = post_logs_to_ingest_router(&env, &batch).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(log_file_records(&env).len(), 2);
}

#[tokio::test]
async fn ingest_endpoint_rejects_logs_from_an_unregistered_agent() {
    // 登记表是这条路径唯一的身份锚：不存在的机器不得被写进日志文件。
    let env = TestEnv::new().await;

    let response =
        post_logs_to_ingest_router(&env, &data_plane_log_record("agent-ghost", "hello")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert!(
        body["failures"][0]
            .as_str()
            .expect("failure text")
            .contains("unknown agent_id agent-ghost"),
        "got {body}"
    );
    assert!(
        log_file_records(&env).is_empty(),
        "a rejected record must not reach the file"
    );
}

#[tokio::test]
async fn ingest_endpoint_reports_the_shape_it_received_when_the_log_record_is_wrong() {
    let env = TestEnv::new().await;

    let response = post_logs_to_ingest_router(&env, &serde_json::json!({"hello": "world"})).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    let failure = body["failures"][0].as_str().expect("failure text");
    assert!(
        failure.contains("not a data-plane log record") && failure.contains("hello"),
        "got {failure}"
    );
}

#[tokio::test]
async fn ingest_endpoint_rejects_a_log_record_without_a_body() {
    // 没有 `raw` 的「日志」没有意义：宁可显形，也不要写一行空正文进去。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let record = serde_json::json!({ "agent_id": "agent-node-a", "category": "agent.log" });

    let response = post_logs_to_ingest_router(&env, &record).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert!(
        body["failures"][0]
            .as_str()
            .expect("failure text")
            .contains("not a data-plane log record"),
        "got {body}"
    );
    assert!(log_file_records(&env).is_empty());
}

#[tokio::test]
async fn admin_logs_route_requires_admin_bearer() {
    let env = TestEnv::new().await;
    let response = get_to_router(&env.config, &env.store_handle, "/api/v1/admin/logs", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_logs_route_returns_the_stored_records() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    for raw in ["first", "second", "third"] {
        let response =
            post_logs_to_ingest_router(&env, &data_plane_log_record("agent-node-a", raw)).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let body: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/logs").await).await;
    assert_eq!(body["limit"], 200);
    assert_eq!(body["truncated"], false);
    assert_eq!(
        body["logs"]
            .as_array()
            .expect("logs")
            .iter()
            .map(|log| log["raw"].as_str().expect("raw"))
            .collect::<Vec<_>>(),
        vec!["first", "second", "third"]
    );
    assert!(
        body["file"]
            .as_str()
            .expect("file")
            .ends_with("agent-logs.ndjson"),
        "ops needs to know where the file is: {body}"
    );
}

#[tokio::test]
async fn admin_logs_route_filters_by_agent_and_keeps_the_newest_limit() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    for raw in ["first", "second", "third"] {
        let response =
            post_logs_to_ingest_router(&env, &data_plane_log_record("agent-node-a", raw)).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    // 没采过的这台给空表，而不是 404：这里是筛选，不是按 id 取某一台的视图。
    let body: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/logs?agent_id=agent-other").await)
            .await;
    assert_eq!(body["logs"], serde_json::json!([]));

    // limit 取**最新** N 条，且按写入顺序回给调用方。
    let body: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/logs?limit=2").await).await;
    assert_eq!(body["limit"], 2);
    assert_eq!(
        body["logs"]
            .as_array()
            .expect("logs")
            .iter()
            .map(|log| log["raw"].as_str().expect("raw"))
            .collect::<Vec<_>>(),
        vec!["second", "third"]
    );
}

#[tokio::test]
async fn the_collection_family_travels_with_the_record_and_can_be_filtered_on() {
    // 正文规则未就绪时 `category` 恒为泛化的 `agent.log`（两个面长一模一样），
    // **面是唯一能把它们分开的字段** —— 它得一路落盘、能筛。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    for (family, unit, raw) in [
        ("ServiceLifecycle", "mac-launchd-service", "from launchd"),
        ("NetworkFirewall", "mac-network-wifi", "from wifi"),
    ] {
        let response = post_logs_to_ingest_router(
            &env,
            &data_plane_log_record_with_family("agent-node-a", family, unit, raw),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let stored = log_file_records(&env);
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].family, "ServiceLifecycle");
    assert_eq!(stored[0].unit, "mac-launchd-service");

    let body: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/logs?family=NetworkFirewall").await)
            .await;
    let logs = body["logs"].as_array().expect("logs");
    assert_eq!(logs.len(), 1, "{body}");
    assert_eq!(logs[0]["raw"], "from wifi");
    assert_eq!(logs[0]["unit"], "mac-network-wifi");
}

#[tokio::test]
async fn a_record_without_a_family_still_lands_and_matches_no_family_filter() {
    // 旧版 agentd、以及本机运维手工配置的输入都不带这两个字段：**不能因此被拒收**，
    // 但要如实留空（“不是平台派活来的”本身就是信息），并且按面筛时不该被任何面捞出来。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let response =
        post_logs_to_ingest_router(&env, &data_plane_log_record("agent-node-a", "legacy")).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(log_file_records(&env)[0].family, "");

    let body: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/logs?family=ServiceLifecycle").await)
            .await;
    assert_eq!(body["logs"], serde_json::json!([]));
}

// ── L1a 机械资产清单（从事实摘要派生）────────────────────────────

#[tokio::test]
async fn software_routes_require_admin_bearer() {
    let env = TestEnv::new().await;
    for uri in [
        "/api/v1/admin/software",
        "/api/v1/admin/agents/agent-node-a/software",
    ] {
        let response = get_to_router(&env.config, &env.store_handle, uri, None).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "uri {uri}");
    }
}

#[tokio::test]
async fn agent_software_route_differentiates_unknown_agent_from_empty_inventory() {
    // 「agent 不存在」与「存在但没上报过清单」必须能区分，否则运维分不清打错 id 与没采到。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;

    let unknown = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-nobody/software",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let empty = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/software",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(empty.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(empty).await;
    assert_eq!(body["paths"], 0);
    assert_eq!(body["apps"], 0);
    assert_eq!(body["entries"], serde_json::json!([]));
}

#[tokio::test]
async fn software_inventory_is_derived_from_the_fact_summary() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let report = fact_report(&[
        "/Applications/Firefox.app/Contents/MacOS/firefox",
        "/Applications/Firefox.app/Contents/MacOS/plugin-container",
        "/usr/bin/true",
    ]);
    let accepted = post_facts(&env, &report).await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/software",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    // 三条路径，其中两条归到同一个 `.app` 键。
    assert_eq!(body["paths"], 3);
    assert_eq!(body["apps"], 2);
    let entries = body["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3);
    // 排序：`kind` 在前，所以 app 条目先出。
    assert_eq!(entries[0]["software_key"], "/Applications/Firefox.app");
    assert_eq!(entries[0]["name"], "Firefox");
    assert_eq!(entries[0]["kind"], "app");
    assert_eq!(entries[0]["matched_rule"], "macos-app-bundle");
    assert_eq!(entries[2]["kind"], "binary");
    assert_eq!(entries[2]["matched_rule"], "unix-path");

    // 「按软件看机器」：`.app` 键持有 2 条路径，但只有 1 台机器。
    let holdings = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/software",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(holdings.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(holdings).await;
    assert_eq!(body["truncated"], false);
    let software = body["software"].as_array().expect("software");
    assert_eq!(software.len(), 2);
    let firefox = software
        .iter()
        .find(|view| view["software_key"] == "/Applications/Firefox.app")
        .expect("firefox holding");
    assert_eq!(firefox["agent_count"], 1);
    assert_eq!(firefox["holders"].as_array().expect("holders").len(), 2);
    assert_eq!(firefox["holders"][0]["agent_id"], "agent-node-a");
}

#[tokio::test]
async fn software_inventory_self_heals_on_a_duplicate_report() {
    // 内容没变时清单不重算（投影相同），但若上次重建没写成（进程被杀 / 库锁），
    // 重复上报要能补上 —— 否则清单会一直空着而没人知道。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let report = fact_report(&["/usr/bin/true"]);
    assert_eq!(
        post_facts(&env, &report).await.status(),
        StatusCode::ACCEPTED
    );

    // 模拟「上次重建没写成」：把已建好的清单删掉，内容与 digest 都不动。
    env.store
        .replace_agent_software_inventory("agent-node-a", &[])
        .await
        .expect("clear inventory");
    assert!(
        !env.store
            .agent_has_software_inventory("agent-node-a")
            .await
            .expect("has inventory")
    );

    // 同一份内容再报一次：走 duplicate 分支（不重算 digest），但清单必须回来。
    assert_eq!(
        post_facts(&env, &report).await.status(),
        StatusCode::ACCEPTED
    );
    let entries = env
        .store
        .list_agent_software("agent-node-a")
        .await
        .expect("list inventory");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "/usr/bin/true");
}

#[tokio::test]
async fn fact_summary_ingest_refreshes_display_fields_on_duplicate() {
    // 内容（可执行标识集合）没变，机器却换了网、改了名：这是 **duplicate**。
    // 展示字段必须跟着刷 —— 否则页面上的 IP 会停在几天前那一轮，而旁边「入库时间」
    // 写着刚刚，运维会以为采集坏了。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let first = fact_report_with_display(
        &["/usr/bin/xcodebuild"],
        "machine-id-abc123",
        "macbook-pro",
        &["en0 192.168.1.5/24"],
    );
    let digest = digest_of(&first);
    assert_eq!(
        post_facts(&env, &first).await.status(),
        StatusCode::ACCEPTED
    );
    let first_suggestion = env
        .store
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("store read")
        .expect("suggestion");

    let renamed = first.with_display(
        "machine-id-abc123".to_string(),
        "macbook-pro-renamed".to_string(),
        vec!["en0 10.0.0.9/24".to_string()],
    );
    assert_eq!(
        post_facts(&env, &renamed).await.status(),
        StatusCode::ACCEPTED
    );
    // 只有留痕刷新：建议不重算。
    assert_eq!(
        env.store
            .get_purpose_suggestion("agent-node-a")
            .await
            .expect("store read")
            .expect("suggestion")
            .suggestion_id,
        first_suggestion.suggestion_id
    );

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("store read")
        .expect("fact summary");
    assert_eq!(stored.host_name, "macbook-pro-renamed");
    assert_eq!(stored.network_addresses, vec!["en0 10.0.0.9/24"]);
    // 内容列与幂等键一格不动。
    assert_eq!(stored.content_digest, digest);
    assert_eq!(stored.process_executables, vec!["/usr/bin/xcodebuild"]);
}

#[tokio::test]
async fn fact_summary_ingest_recomputes_when_the_content_changes() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;

    assert_eq!(
        post_facts(&env, &fact_report(&["launchd"])).await.status(),
        StatusCode::ACCEPTED
    );
    // 只有 launchd：没命中规则 → 回落到基线 MacDaily。
    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["suggestion"]["suggested_class"], "MacDaily");
    assert_eq!(view["suggestion"]["confidence"], 0);
    let first_suggestion = env
        .store
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("store read")
        .expect("suggestion");

    // 内容变了：覆盖式入库并重算，建议 id 也应是新的。
    let changed = fact_report(&["xcodebuild"]);
    assert_eq!(
        post_facts(&env, &changed).await.status(),
        StatusCode::ACCEPTED
    );
    let second_suggestion = env
        .store
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("store read")
        .expect("suggestion");
    assert_ne!(
        second_suggestion.suggestion_id,
        first_suggestion.suggestion_id
    );

    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["fact_summary"]["content_digest"], digest_of(&changed));
    assert_eq!(view["suggestion"]["suggested_class"], "MacDev");
}

#[tokio::test]
async fn agent_facts_route_rejects_an_overlong_content_digest() {
    // 声明会进告警日志：不限长就能让一条上报写出几 MB 的单行日志。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let report = fact_report_declaring(&["xcodebuild"], &"d".repeat(1024));

    let response = post_facts(&env, &report).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn agent_facts_route_rejects_an_overlong_host_id() {
    // 上报体是**被管机器**给的内容，网关必须自己封顶，不能指望 agent 守规矩。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let report = fact_report_with_display(&["xcodebuild"], &"h".repeat(1024), "macbook-pro", &[]);

    let response = post_facts(&env, &report).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn agent_facts_route_rejects_too_many_network_addresses() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let addresses: Vec<String> = (0..300)
        .map(|index| format!("en{index} 10.0.0.1/24"))
        .collect();
    let report = fact_report(&["xcodebuild"]).with_display(
        "machine-id".to_string(),
        "macbook-pro".to_string(),
        addresses,
    );

    let response = post_facts(&env, &report).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn agent_facts_route_refuses_an_unknown_envelope() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    let mut report = fact_report(&["xcodebuild"]);
    report.kind = "something_else".to_string();

    let response = post_facts(&env, &report).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        env.store
            .get_agent_fact_summary("agent-node-a")
            .await
            .expect("store read")
            .is_none()
    );
}

#[tokio::test]
async fn fact_summary_ingest_stores_facts_even_without_a_rule_table() {
    // 未配置规则表：事实是 Agent 的数据，必须落库；只是不产出建议。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;

    assert_eq!(
        post_facts(&env, &fact_report(&["xcodebuild"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert!(
        env.store
            .get_agent_fact_summary("agent-node-a")
            .await
            .expect("store read")
            .is_some()
    );
    // 没有规则表 → 确实没有建议。
    assert!(
        env.store
            .get_purpose_suggestion("agent-node-a")
            .await
            .expect("store read")
            .is_none()
    );

    let view = get_purpose_view(&env, "agent-node-a").await;
    assert!(!view["fact_summary"].is_null());
    assert!(view["suggestion"].is_null());
}

#[tokio::test]
async fn agent_purpose_route_clears_a_stale_suggestion_when_nothing_should_be_suggested() {
    // 平台没有规则册 → 这次确实不该有建议；旧建议是照着旧事实算的，必须清掉。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    post_facts(&env, &fact_report(&["xcodebuild"])).await;
    assert!(get_purpose_view(&env, "agent-node-a").await["suggestion"].is_object());

    let mut linux_report = fact_report(&["postgres"]);
    linux_report.os = "linux".to_string();
    assert_eq!(
        post_facts(&env, &linux_report).await.status(),
        StatusCode::ACCEPTED
    );
    // 平台无规则册 → 确实不该有建议，库里必须是空的（旧建议不清掉才是错的）。
    assert!(
        env.store
            .get_purpose_suggestion("agent-node-a")
            .await
            .expect("store read")
            .is_none()
    );

    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(
        view["fact_summary"]["content_digest"],
        digest_of(&linux_report)
    );
    assert!(view["suggestion"].is_null());
}

#[tokio::test]
async fn agent_purpose_route_requires_admin_bearer() {
    let env = TestEnv::new().await;

    let rejected = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/purpose",
        None,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_purpose_view_is_empty_before_any_facts() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;

    let view = get_purpose_view(&env, "agent-node-a").await;
    // 「还没报过事实」与「这台机器不存在」是两回事：这里 200 + 空视图，不是 404。
    assert!(view["fact_summary"].is_null());
    assert!(view["suggestion"].is_null());
    assert!(view["classification"].is_null());
}

#[tokio::test]
async fn agent_purpose_route_returns_404_for_an_unknown_agent() {
    let env = TestEnv::new().await;

    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-nobody/purpose",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 用**真实策展规则表**跑通全链：上报 → 入库 → 按规则打一分 → 页面读得到依据。
///
/// 这是“用夹具数据验证计算”的那份证据；数据来自知识库仓 `wist-knowledge`（缺则失败）。
#[tokio::test]
async fn fact_summary_ingest_infers_with_the_checked_in_rule_table() {
    let rules = std::fs::read_to_string(crate::test_support::knowledge_file("purpose-rules.toml"))
        .expect("read checked-in rule table");

    let env = TestEnv::new_with_purpose_rules(Some(&rules)).await;
    enroll_agent_credential(&env).await;
    // 一台真开发机上的典型进程（含一条 Electron 应用自带的 node_modules，应当被排除）。
    let processes = [
        "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild",
        "/opt/homebrew/bin/mise",
        "/Applications/OrbStack.app/Contents/MacOS/OrbStack",
        "/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/node_modules/x",
    ];
    assert_eq!(
        post_facts(&env, &fact_report(&processes)).await.status(),
        StatusCode::ACCEPTED
    );

    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["suggestion"]["suggested_class"], "MacDev");
    assert_eq!(view["suggestion"]["rule_set_id"], "macos-v1");
    assert_eq!(view["suggestion"]["method"], "rule");
    // Xcode(40) + homebrew(30) + OrbStack(25) = 95，无次高分 → 100。
    assert_eq!(view["suggestion"]["confidence"], 100);

    let rule_ids: Vec<&str> = view["suggestion"]["signals"]
        .as_array()
        .expect("signals array")
        .iter()
        .map(|signal| signal["rule_id"].as_str().expect("rule_id"))
        .collect();
    assert!(rule_ids.contains(&"mac-dev-xcodebuild"));
    assert!(rule_ids.contains(&"mac-dev-homebrew-arm"));
    assert!(rule_ids.contains(&"mac-dev-orbstack"));
    // 排除规则在真实数据上生效：App bundle 里的 node_modules 不算开发特征。
    assert!(!rule_ids.contains(&"mac-dev-node_modules"));
}

// ── 审查发现的缺陷对应的回归测试 ──────────────────────────────────────

/// 建一份带规则表的配置副本（同一个库），用来模拟“规则表后来才配上 / 换了版本”。
fn config_with_purpose_rules(env: &TestEnv, rules: &str) -> AdminConfig {
    let path = std::env::temp_dir().join(format!("wist-gateway-purpose-{}.toml", unique_suffix()));
    std::fs::write(&path, rules).expect("write purpose rules");
    let mut config = env.config.clone();
    config.purpose_rules_file = Some(path);
    config
}

// ── 发现方向策略表（装载校验 + 下发 + 管理视图）──────────────────────

/// 精简策略表：七个方向各一条（校验要求不许缺/重）。版本号特意取 7，便于断言下发的是这一版。
const TEST_DISCOVERY_POLICIES: &str = r#"
policy_version = 7
published_at = "2026-09-22T00:00:00Z"
policies = [
  { aspect = "host", default_interval_seconds = 900, min_interval_seconds = 300, max_interval_seconds = 3600, baseline = true, enabled_by_default = true, platforms = ["macos", "linux"] },
  { aspect = "network", default_interval_seconds = 900, min_interval_seconds = 300, max_interval_seconds = 3600, baseline = false, enabled_by_default = true, platforms = ["macos", "linux"] },
  { aspect = "process", default_interval_seconds = 300, min_interval_seconds = 60, max_interval_seconds = 1800, baseline = false, enabled_by_default = true, platforms = ["macos", "linux"] },
  { aspect = "endpoint", default_interval_seconds = 300, min_interval_seconds = 60, max_interval_seconds = 1800, baseline = false, enabled_by_default = true, platforms = ["linux"] },
  { aspect = "container", default_interval_seconds = 300, min_interval_seconds = 60, max_interval_seconds = 1800, baseline = false, enabled_by_default = false, platforms = ["macos", "linux"] },
  { aspect = "k8s", default_interval_seconds = 300, min_interval_seconds = 60, max_interval_seconds = 1800, baseline = false, enabled_by_default = false, platforms = ["macos", "linux"] },
  { aspect = "package", default_interval_seconds = 1800, min_interval_seconds = 900, max_interval_seconds = 21600, baseline = false, enabled_by_default = true, platforms = ["linux"] },
]
"#;

/// 建一份带策略表的配置副本（同一个库），用来模拟“策略表后来才配上”。
fn config_with_discovery_policies(env: &TestEnv, policies: &str) -> AdminConfig {
    let path =
        std::env::temp_dir().join(format!("wist-gateway-discovery-{}.toml", unique_suffix()));
    std::fs::write(&path, policies).expect("write discovery policies");
    let mut config = env.config.clone();
    config.discovery_policies_file = Some(path);
    config
}

fn discovery_poll_request() -> PollDiscoveryPolicies {
    PollDiscoveryPolicies {
        api_version: "v1".to_string(),
        kind: POLL_DISCOVERY_POLICIES_KIND.to_string(),
        agent_id: "agent-node-a".to_string(),
        instance_id: "node-a".to_string(),
        requested_at: "2026-09-22T00:00:00Z".to_string(),
    }
}

async fn post_discovery_poll(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    credential: Option<&str>,
    request: &PollDiscoveryPolicies,
) -> Response {
    post_agent_json_to_router(
        config,
        store,
        "/api/v1/agent/discovery-policies:poll",
        credential,
        request,
    )
    .await
}

async fn get_discovery_view(env: &TestEnv, admin_token: Option<&str>) -> Response {
    get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/discovery-policies",
        admin_token,
    )
    .await
}

/// 注册一台指定 `node_id` 的 Agent 并拿回 bearer 凭据。
///
/// `agent_id` 由网关按 `node_id` 派生（`agent-<node_id>`），所以换个 node 就是一台不同的机器。
async fn enroll_agent_at_node(env: &TestEnv, node_id: &str) -> String {
    let token = env.issue_token().await;
    let mut request = enrollment_request(&token);
    request.host_profile.node_id = node_id.to_string();
    let response = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        serde_json::to_string(&request).expect("serialize enrollment"),
    )
    .await;
    // 返回 **agent_id**（agent 侧只有证书这一条凭据路径；测试里拿它当握手期注入的身份）。
    decode_enrollment_response(response)
        .await
        .result
        .credential_bundle
        .expect("credential bundle")
        .agent_id
}

/// 发一次状态上报。
///
/// `policy_version=None` 造一份**不带**该字段的报文（旧 agentd 不知道它），
/// 而不是显式建 `"discovery_policy_version": null` —— 后者是「知道字段但没值」，
/// 前者才是要验的向后兼容场景。
async fn post_agent_status(
    env: &TestEnv,
    credential: &str,
    instance_id: &str,
    policy_version: Option<i64>,
) -> Response {
    let agent_id = format!("agent-{instance_id}");
    let body = match policy_version {
        Some(version) => serde_json::to_value(AgentStatusReport {
            agent_id,
            instance_id: instance_id.to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: Some(version),
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
            certificate_status: None,
            machine_profile: None,
        })
        .expect("serialize status"),
        None => serde_json::json!({
            "agent_id": agent_id,
            "instance_id": instance_id,
            "version": "v0.1.0",
        }),
    };
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(credential),
        &body,
    )
    .await
}

#[tokio::test]
async fn discovery_policies_poll_requires_bearer_credential() {
    let env = TestEnv::new_with_discovery_policies(Some(TEST_DISCOVERY_POLICIES)).await;

    let response = post_discovery_poll(
        &env.config,
        &env.store_handle,
        None,
        &discovery_poll_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discovery_policies_poll_refuses_an_unknown_envelope() {
    let env = TestEnv::new_with_discovery_policies(Some(TEST_DISCOVERY_POLICIES)).await;
    let credential = enroll_agent_credential(&env).await;
    let mut request = discovery_poll_request();
    request.kind = "something_else".to_string();

    let response =
        post_discovery_poll(&env.config, &env.store_handle, Some(&credential), &request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn discovery_policies_poll_serves_the_configured_table() {
    let env = TestEnv::new_with_discovery_policies(Some(TEST_DISCOVERY_POLICIES)).await;
    let credential = enroll_agent_credential(&env).await;

    let response = post_discovery_poll(
        &env.config,
        &env.store_handle,
        Some(&credential),
        &discovery_poll_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let returned: DiscoveryPoliciesReturned = decode_json_response(response).await;

    assert_eq!(returned.policy_version, 7);
    assert_eq!(returned.published_at, "2026-09-22T00:00:00Z");
    assert_eq!(returned.policies.len(), 7);
    let host = returned
        .policies
        .iter()
        .find(|policy| policy.aspect == "host")
        .expect("host policy");
    assert!(host.baseline);
    assert!(host.supports("macos"));
}

#[tokio::test]
async fn discovery_policies_poll_is_unavailable_when_unconfigured() {
    // 未配置时回 503 而不是空表：空表会让「平台没发布策略」与「从未配置」无法区分。
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let response = post_discovery_poll(
        &env.config,
        &env.store_handle,
        Some(&credential),
        &discovery_poll_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = String::from_utf8(body_bytes(response).await.to_vec()).expect("utf8 body");
    assert!(body.contains("not configured"), "{body}");
}

#[tokio::test]
async fn admin_discovery_view_reports_configured() {
    let env = TestEnv::new_with_discovery_policies(Some(TEST_DISCOVERY_POLICIES)).await;

    let response = get_discovery_view(&env, Some(TEST_ADMIN_API_TOKEN)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = decode_json_response(response).await;

    assert_eq!(view["configured"], serde_json::Value::Bool(true));
    assert_eq!(view["policy"]["policy_version"], 7);
    assert_eq!(
        view["policy"]["policies"]
            .as_array()
            .expect("policies")
            .len(),
        7
    );
}

#[tokio::test]
async fn admin_discovery_view_reports_unconfigured() {
    let env = TestEnv::new().await;

    let response = get_discovery_view(&env, Some(TEST_ADMIN_API_TOKEN)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = decode_json_response(response).await;

    assert_eq!(view["configured"], serde_json::Value::Bool(false));
    assert!(view["policy"].is_null());
}

#[tokio::test]
async fn admin_discovery_view_requires_admin_bearer() {
    let env = TestEnv::new_with_discovery_policies(Some(TEST_DISCOVERY_POLICIES)).await;

    let response = get_discovery_view(&env, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_status_persists_the_applied_discovery_policy_version() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let response = post_agent_status(&env, &credential, "node-a", Some(2)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("agent");
    assert_eq!(stored.last_discovery_policy_version, Some(2));
}

#[tokio::test]
async fn agent_status_without_the_policy_version_keeps_it_null() {
    // 旧 agentd 的报文里没有这个 key：既不能因此回 400，也不能把它当成 0。
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let response = post_agent_status(&env, &credential, "node-a", None).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("agent");
    assert_eq!(stored.last_discovery_policy_version, None);
}

#[tokio::test]
async fn admin_discovery_view_lists_per_agent_applied_versions() {
    let env = TestEnv::new_with_discovery_policies(Some(TEST_DISCOVERY_POLICIES)).await;
    // a 报上生效版本 2；b 报了状态但不带版本；c 注册后从没报过 —— 三台都必须出现。
    let credential_a = enroll_agent_at_node(&env, "node-a").await;
    let credential_b = enroll_agent_at_node(&env, "node-b").await;
    let _credential_c = enroll_agent_at_node(&env, "node-c").await;
    assert_eq!(
        post_agent_status(&env, &credential_a, "node-a", Some(2))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post_agent_status(&env, &credential_b, "node-b", None)
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    let view: serde_json::Value =
        decode_json_response(get_discovery_view(&env, Some(TEST_ADMIN_API_TOKEN)).await).await;
    // 未配置/已配置两路都带上 agents；这里策略表是配了的，顺带确认旧字段语义没变。
    assert_eq!(view["configured"], serde_json::Value::Bool(true));

    let agents = view["agents"].as_array().expect("agents array");
    let ids: Vec<&str> = agents
        .iter()
        .map(|agent| agent["agent_id"].as_str().expect("agent_id"))
        .collect();
    assert_eq!(ids, vec!["agent-node-a", "agent-node-b", "agent-node-c"]);

    assert_eq!(agents[0]["applied_policy_version"], 2);
    assert_eq!(agents[0]["instance_id"], "node-a");
    assert!(
        agents[0]["last_seen_at"]
            .as_str()
            .expect("last_seen_at")
            .starts_with("20"),
        "{agents:?}"
    );

    // b 上报过但没带版本：null，不是 0，也不是缺行。
    assert!(agents[1]["applied_policy_version"].is_null());
    assert_eq!(agents[1]["instance_id"], "node-b");
    assert!(!agents[1]["last_seen_at"].as_str().unwrap().is_empty());

    // c 从没上报：仍在列表里（运维要看的正是「谁还没生效」），last_seen_at 为 null。
    assert!(agents[2]["applied_policy_version"].is_null());
    assert!(agents[2]["last_seen_at"].is_null(), "{agents:?}");
}

#[tokio::test]
async fn agent_status_metric_reports_policy_version_only_when_present() {
    // 缺值不能补 0：0 是「确实生效了第 0 版」，与「还没拉到策略表」在图上必须分开。
    let with = super::agent_ops::agent_status_metric_lines(
        "agent-node-a",
        None,
        None,
        None,
        None,
        Some(2),
        1_700_000_000_000,
    );
    let version_line = with
        .iter()
        .find(|line| line["metric"]["__name__"] == "agent.discovery_policy_version")
        .expect("discovery policy version metric line");
    assert_eq!(version_line["values"][0], 2.0);
    assert_eq!(version_line["metric"]["agent"], "agent-node-a");
    assert_eq!(with.len(), 1);

    let without = super::agent_ops::agent_status_metric_lines(
        "agent-node-a",
        None,
        None,
        None,
        None,
        None,
        1_700_000_000_000,
    );
    assert!(without.is_empty(), "{without:?}");
}

#[tokio::test]
async fn agent_status_metric_reports_cpu_cores_when_present() {
    // 核数是整机占比的分母，随状态上报一起进时序；缺值同样不发线（与 cpu.percent 同一规矩）。
    let with = super::agent_ops::agent_status_metric_lines(
        "agent-node-a",
        None,
        Some(50.0),
        Some(4),
        None,
        None,
        1_700_000_000_000,
    );
    let cores_line = with
        .iter()
        .find(|line| line["metric"]["__name__"] == "agent.cpu.cores")
        .expect("cpu cores metric line");
    assert_eq!(cores_line["values"][0], 4.0);
    assert_eq!(cores_line["metric"]["agent"], "agent-node-a");

    let without = super::agent_ops::agent_status_metric_lines(
        "agent-node-a",
        None,
        Some(50.0),
        None,
        None,
        None,
        1_700_000_000_000,
    );
    assert!(
        without
            .iter()
            .all(|line| line["metric"]["__name__"] != "agent.cpu.cores"),
        "{without:?}"
    );
}

/// 用**真实策展策略表**跑通下发：装载校验通过，且下发的是七个方向那一版。
///
/// 这是“用夹具数据验证契约”的那份证据；数据来自知识库仓 `wist-knowledge`（缺则失败）。
#[tokio::test]
async fn discovery_policies_poll_serves_the_checked_in_table() {
    let policies =
        std::fs::read_to_string(crate::test_support::knowledge_file("aspect-policies.toml"))
            .expect("read checked-in policy table");
    // 换个实现就能在这里早失败：装载校验不过不会走到端点。
    let env = TestEnv::new().await;
    let config = config_with_discovery_policies(&env, &policies);
    let credential = enroll_agent_credential(&env).await;

    let response = post_discovery_poll(
        &config,
        &env.store_handle,
        Some(&credential),
        &discovery_poll_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let returned: DiscoveryPoliciesReturned = decode_json_response(response).await;

    assert!(returned.policy_version >= 1);
    assert_eq!(returned.policies.len(), 7);
}

#[tokio::test]
async fn fact_summary_ingest_survives_a_corrupt_json_column() {
    // 判重路径若顺带反序列化三个 JSON 列，一旦某列仕掉就会把**新摘要永远挡在门外**
    // （upsert 根本走不到），坏行无法被覆盖自愈。这里把列真的写坏来验。
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    assert_eq!(
        post_facts(&env, &fact_report(&["xcodebuild"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", env.config.sqlite_path.display()))
        .await
        .expect("open raw pool");
    sqlx::query("UPDATE agent_fact_summary SET process_executables = ?1 WHERE agent_id = ?2")
        .bind("not json")
        .bind("agent-node-a")
        .execute(&pool)
        .await
        .expect("corrupt the column");
    pool.close().await;

    // 1）同一份内容再报：判重只读 digest，不该 500。
    assert_eq!(
        post_facts(&env, &fact_report(&["xcodebuild"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    // 2）换一份内容：必须能覆盖写入，坏列随之自愈。
    assert_eq!(
        post_facts(&env, &fact_report(&["/opt/homebrew/bin/mise"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    let stored = env
        .store
        .get_agent_fact_summary("agent-node-a")
        .await
        .expect("read summary")
        .expect("summary");
    assert_eq!(
        stored.process_executables,
        vec!["/opt/homebrew/bin/mise".to_string()]
    );
}

#[tokio::test]
async fn agent_facts_route_rejects_oversized_and_invalid_input() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;

    // 条数超限（被管机器可以自己控制数组长度，网关必须自己封顶）。
    let mut too_many = fact_report(&["xcodebuild"]);
    too_many.process_executables = vec!["x".to_string(); 10_001];
    assert_eq!(
        post_facts(&env, &too_many).await.status(),
        StatusCode::BAD_REQUEST
    );

    // 单元素超长。
    let mut too_long = fact_report(&["xcodebuild"]);
    too_long.process_executables = vec!["x".repeat(4097)];
    assert_eq!(
        post_facts(&env, &too_long).await.status(),
        StatusCode::BAD_REQUEST
    );

    // 负数留痕字段。
    let mut negative = fact_report(&["xcodebuild"]);
    negative.process_count = -1;
    assert_eq!(
        post_facts(&env, &negative).await.status(),
        StatusCode::BAD_REQUEST
    );

    // 被拒的上报不该落库。
    assert!(
        env.store
            .get_agent_fact_summary("agent-node-a")
            .await
            .expect("read")
            .is_none()
    );
}

#[tokio::test]
async fn agent_purpose_route_recomputes_a_missing_suggestion() {
    // 首次上报时还没配规则表：只入库、无建议。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    assert_eq!(
        post_facts(&env, &fact_report(&["xcodebuild"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    // 首次上报时还没配规则表：只入库、无建议。
    assert!(
        env.store
            .get_purpose_suggestion("agent-node-a")
            .await
            .expect("store read")
            .is_none()
    );

    // 之后配上规则表（重启生效）。事实没变、agentd 不会再报 ——
    // 读取路径必须自愈，否则「有事实、无建议」会无限期留着。
    let with_rules = config_with_purpose_rules(&env, TEST_PURPOSE_RULES);
    let response = get_to_router(
        &with_rules,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/purpose",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = decode_json_response(response).await;
    assert_eq!(view["suggestion"]["suggested_class"], "MacDev");
    assert_eq!(view["suggestion"]["rule_set_id"], "macos-v1");

    // 自愈是**落库**的，不只影响这一响；而且未配规则表的那份配置读它时
    // 不该把它清掉（不推断 ≠ 清空）。
    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["suggestion"]["rule_set_id"], "macos-v1");
}

#[tokio::test]
async fn agent_purpose_route_recomputes_when_the_rule_set_version_changes() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    post_facts(&env, &fact_report(&["xcodebuild"])).await;
    assert_eq!(
        get_purpose_view(&env, "agent-node-a").await["suggestion"]["rule_set_id"],
        "macos-v1"
    );

    // 规则册换版本：同一份事实、agentd 不会再报，只能靠读取路径看出来并重算。
    let v2 = TEST_PURPOSE_RULES.replace("macos-v1", "macos-v2");
    let with_v2 = config_with_purpose_rules(&env, &v2);
    let response = get_to_router(
        &with_v2,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/purpose",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let view: serde_json::Value = decode_json_response(response).await;
    assert_eq!(view["suggestion"]["rule_set_id"], "macos-v2");
}

#[tokio::test]
async fn agent_status_route_persists_work_state_changes() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: Some(vec![AgentWorkStateChange {
                input_id: "app".to_string(),
                state: AgentWorkState::Paused,
                reason: "spool over limit".to_string(),
                at: "now".to_string(),
            }]),
            local_work: None,
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let stored = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("agent");
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
async fn the_work_view_exposes_the_agents_local_work_report() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    // 还没上报过：`local` 是 null（不是空对象）—— 与「上报了但没东西」区分开。
    let before = get_agent_work(&env).await;
    assert!(before["local"].is_null(), "{before}");

    // 上报本机工作视图：一份常驻工作（盯一个文件）+ 一条手工输入。
    let local_work = wist_contracts::local_work::AgentLocalWork {
        recorded_at: "2026-09-26T08:00:00Z".to_string(),
        gateway_sequence: 7,
        standing: vec![wist_contracts::local_work::AgentLocalStandingWork {
            work_id: "work-1".to_string(),
            family: "SystemLogs".to_string(),
            status: "active".to_string(),
            plan_version: 3,
            acknowledged_version: Some(3),
            effective_from: "2026-09-25T00:00:00Z".to_string(),
            tasks: vec![wist_contracts::local_work::AgentLocalTask {
                input_id: "work-SystemLogs-syslog".to_string(),
                path: "/var/log/system.log".to_string(),
                startup_position: "tail".to_string(),
            }],
        }],
        one_shot: Vec::new(),
        local_inputs: vec![wist_contracts::local_work::AgentLocalTask {
            input_id: "manual-app".to_string(),
            path: "/var/log/app.log".to_string(),
            startup_position: "tail".to_string(),
        }],
        metrics_interval_seconds: Some(15),
    };
    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: Some(local_work),
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    // 工作视图（管理面）把 agent 上报的本机事实一并带出来。
    let view = get_agent_work(&env).await;
    assert_eq!(view["local"]["gateway_sequence"], 7);
    assert_eq!(
        view["local"]["standing"][0]["tasks"][0]["path"],
        "/var/log/system.log"
    );
    assert_eq!(view["local"]["local_inputs"][0]["path"], "/var/log/app.log");
    assert_eq!(view["local"]["metrics_interval_seconds"], 15);
}

/// 上报实际生效的上送状态后，运行状态响应能逐个字段读到它。
///
/// 运维问「这台为什么不上送」时查的就是运行状态响应：待命 / 本机 file 出口 / 目标是谁 /
/// 控制面下发还是本机 / 出口是否在失败，都得能在这一个响应里看到。
#[tokio::test]
async fn the_runtime_status_view_exposes_the_agents_uplink_state() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    // 还没上报过：`uplink_state` 是 null（不是全 false 的对象）。
    let before = get_agent_runtime_status(&env).await;
    assert!(before["uplink_state"].is_null(), "{before}");

    // 上报实际生效的上送状态：控制面下发的 tcp 目标，且出口正在写失败。
    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: Some(wist_contracts::agent_uplink::AgentUplinkState {
                enabled: true,
                kind: "tcp".to_string(),
                target: Some("10.0.1.9:9000".to_string()),
                source: "grant".to_string(),
                output_write_failing: true,
            }),
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let view = get_agent_runtime_status(&env).await;
    assert_eq!(view["uplink_state"]["enabled"], true);
    assert_eq!(view["uplink_state"]["kind"], "tcp");
    assert_eq!(view["uplink_state"]["target"], "10.0.1.9:9000");
    assert_eq!(view["uplink_state"]["source"], "grant");
    assert_eq!(view["uplink_state"]["output_write_failing"], true);

    // 关键语义：下一次心跳没带这个字段（旧版本 agentd）时保持上一次的值，不清空。
    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            machine_profile: None,
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
            certificate_status: None,
        },
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let view = get_agent_runtime_status(&env).await;
    assert_eq!(view["uplink_state"]["kind"], "tcp");
    assert_eq!(view["uplink_state"]["target"], "10.0.1.9:9000");
    assert_eq!(view["uplink_state"]["source"], "grant");
    assert_eq!(view["uplink_state"]["output_write_failing"], true);
}

/// 状态上报携带机器画像 → 运行状态视图能读到主机名与 IP；而且**空值不覆盖**已知画像。
#[tokio::test]
async fn a_status_report_with_a_machine_profile_backfills_the_registry() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let report = |profile: Option<wist_contracts::enrollment::HostProfile>| AgentStatusReport {
        machine_profile: profile,
        agent_id: "agent-node-a".to_string(),
        instance_id: "node-a".to_string(),
        version: "v0.3.0".to_string(),
        memory_bytes: None,
        cpu_percent: None,
        cpu_cores: None,
        admin_latency_ms: None,
        discovery_policy_version: None,
        work_state_changes: None,
        local_work: None,
        uplink_state: None,
        certificate_status: None,
    };
    let profile = wist_contracts::enrollment::HostProfile {
        node_id: "node-1".to_string(),
        hostname: "host-1".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        machine_id: "mid-1".to_string(),
        cloud_instance_id: None,
        k8s_node_uid: None,
        ip_addresses: vec!["en0 10.0.0.5/24".to_string()],
    };

    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &report(Some(profile)),
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);

    let view = get_agent_runtime_status(&env).await;
    assert_eq!(view["hostname"], "host-1");
    assert_eq!(view["node_id"], "node-1");
    assert_eq!(view["ip_addresses"], serde_json::json!(["en0 10.0.0.5/24"]));

    // 下一次心跳没带机器画像（旧版本 agentd）：保留上一次的值，不擦掉。
    let status = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &report(None),
    )
    .await;
    assert_eq!(status.status(), StatusCode::ACCEPTED);
    let view = get_agent_runtime_status(&env).await;
    assert_eq!(view["hostname"], "host-1", "空值不得擦掉已知画像");
    assert_eq!(
        view["ip_addresses"],
        serde_json::json!(["en0 10.0.0.5/24"]),
        "省略不得擦掉已知地址"
    );
}

#[tokio::test]
async fn credential_renewal_issues_a_new_certificate_and_rotates_the_stored_credential() {
    let mut env = TestEnv::new().await;
    let (_ca, ca_cert_path, ca_key_path) = test_agent_ca();
    env.config.agent_ca_cert_file = Some(ca_cert_path);
    env.config.agent_ca_key_file = Some(ca_key_path);

    let agent_id = enroll_agent_credential(&env).await;
    let before = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("stored agent");

    let renewed = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/credentials:renew",
        Some(&agent_id),
        &CredentialRenewal::new(
            "agent-node-a".to_string(),
            "node-a".to_string(),
            "csr".to_string(),
            certificate_signing_request(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;
    assert_eq!(renewed.status(), StatusCode::OK);
    let renewed: CredentialRenewed = decode_json_response(renewed).await;
    let bundle = renewed.credential_bundle;
    assert!(
        bundle.certificate.contains("BEGIN CERTIFICATE"),
        "续期应换发新证书"
    );

    // 库里当前凭据轮换到新的一行（旧行置 revoked），管理视图/吊销仍按 credential_id 定位。
    let after = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("stored agent");
    assert_ne!(after.credential_id, before.credential_id);
    assert_eq!(after.credential_status, StoredCredentialStatus::Active);

    // 续期后证书身份照常能用（续期不会把机器锁死）。
    let accepted = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&agent_id),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn agent_credential_renewal_requires_a_client_certificate() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    assert_eq!(enrollment.status(), StatusCode::CREATED);

    // 不带客户端证书 → 401（续期也不能靠 bearer / 裸奔）。
    let response = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/credentials:renew",
        None,
        &CredentialRenewal::new(
            "agent-node-a".to_string(),
            "node-a".to_string(),
            "csr".to_string(),
            certificate_signing_request(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_routes_accept_a_client_certificate() {
    let env = TestEnv::new().await;
    let agent_id = enroll_agent_credential(&env).await;

    let poll = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/control-commands:poll",
        Some(&agent_id),
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

    let report = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/action-results",
        Some(&agent_id),
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
async fn enrollment_route_rejects_invalid_token() {
    let env = TestEnv::new().await;
    let response = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json("bad-token"),
    )
    .await;

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
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let mut payload = serde_json::to_value(enrollment_request(&token)).expect("serialize request");
    payload["unexpected"] = serde_json::json!("not-in-contract");
    let response =
        post_enrollment_to_router(&env.config, &env.store_handle, payload.to_string()).await;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn install_code_route_requires_admin_bearer_token() {
    let env = TestEnv::new().await;
    let missing = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install-code",
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let accepted = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install-code",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_no_store(&accepted);
}

#[tokio::test]
async fn install_script_signature_route_matches_script() {
    let env = TestEnv::new().await;
    let script_response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install/x86/install.sh",
        None,
    )
    .await;
    assert_eq!(script_response.status(), StatusCode::OK);
    assert_no_store(&script_response);
    let script = body_bytes(script_response).await;

    let signature_response = get_to_router(
        &env.config,
        &env.store_handle,
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
async fn install_script_route_rejects_bad_arch() {
    let env = TestEnv::new().await;
    let unknown = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install/mips/install.sh",
        None,
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert_no_store(&unknown);

    let injected_script = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install/x86%22%0Aecho%20pwned%0A%23/install.sh",
        None,
    )
    .await;
    assert_eq!(injected_script.status(), StatusCode::NOT_FOUND);
    assert_no_store(&injected_script);

    let injected_signature = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install/x86%22%0Aecho%20pwned%0A%23/install.sh.sig",
        None,
    )
    .await;
    assert_eq!(injected_signature.status(), StatusCode::NOT_FOUND);
    assert_no_store(&injected_signature);
}

#[tokio::test]
async fn admin_overview_route_requires_admin_bearer_token() {
    let env = TestEnv::new().await;
    let missing = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/overview",
        None,
    )
    .await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let accepted = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/overview",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_routes_rate_limit_failed_bearer_attempts() {
    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

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
    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

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
    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

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
async fn admin_rate_limit_buckets_per_client_ip() {
    use std::net::SocketAddr;

    use axum::extract::connect_info::MockConnectInfo;

    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

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
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let response = router(env.config.clone(), env.store_handle.clone())
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

    let query_token = router(env.config.clone(), env.store_handle.clone())
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

    let missing = router(env.config.clone(), env.store_handle.clone())
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
async fn initial_config_route_401_is_uniform_across_token_failure_modes() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/agent/initial-config";
    // 与安装包分发端点同一口径：未知 / 过期 / 已消费都不区分，不暴露「存在但过期」。
    const GENERIC_BOOTSTRAP_BODY: &str = "invalid bootstrap bearer token";

    let unknown = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some("wit_does_not_exist"),
    )
    .await;
    assert_auth_rejected(unknown, GENERIC_BOOTSTRAP_BODY).await;

    let expired = env.issue_token().await;
    sqlx::query("UPDATE enrollment_tokens SET expires_at = ?1 WHERE token_hash = ?2")
        .bind("2020-01-01T00:00:00+00:00")
        .bind(token_hash(&expired))
        .execute(env.store.pool())
        .await
        .expect("expire token");
    let expired_response = get_to_router(&env.config, &env.store_handle, uri, Some(&expired)).await;
    assert_auth_rejected(expired_response, GENERIC_BOOTSTRAP_BODY).await;

    let consumed = env.issue_token().await;
    let enrolled = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&consumed),
    )
    .await;
    assert_eq!(enrolled.status(), StatusCode::CREATED);
    let consumed_response =
        get_to_router(&env.config, &env.store_handle, uri, Some(&consumed)).await;
    assert_auth_rejected(consumed_response, GENERIC_BOOTSTRAP_BODY).await;
}

#[tokio::test]
async fn bootstrap_routes_rate_limit_failed_bearer_attempts() {
    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

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
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let response = router(env.config.clone(), env.store_handle.clone())
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

    let query_token = router(env.config.clone(), env.store_handle.clone())
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

    let missing = router(env.config.clone(), env.store_handle.clone())
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

fn enrollment_attempt_request(ip: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/agent/enroll")
        .header("x-real-ip", ip)
        .header("content-type", "application/json")
        .body(Body::from(enrollment_request_json("bad-token")))
        .expect("request")
}

#[tokio::test]
async fn enrollment_route_marks_rejections_no_store() {
    let env = TestEnv::new().await;

    let response = router(env.config.clone(), env.store_handle.clone())
        .oneshot(enrollment_attempt_request("192.0.2.12"))
        .await
        .expect("route response");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_no_store(&response);
}

#[tokio::test]
async fn enrollment_route_rate_limits_repeated_rejections() {
    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

    // 前 5 次都走拒绝路径（契约上仍是 201），第 6 次被限流。
    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(enrollment_attempt_request("192.0.2.12"))
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let blocked = app
        .oneshot(enrollment_attempt_request("192.0.2.12"))
        .await
        .expect("route response");

    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key(header::RETRY_AFTER));
    assert_no_store(&blocked);
}

#[tokio::test]
async fn agent_overview_is_empty_before_enrollment() {
    let state = test_state().await;
    let overview = agent_overview(&state).await;

    assert_eq!(overview.metrics.total_agents, 0);
    assert_eq!(overview.metrics.online_agents, 0);
    assert!(overview.recent_online_agents.is_empty());
    assert!(overview.abnormal_agents.is_empty());
}

#[tokio::test]
async fn agent_overview_reflects_successful_enrollment() {
    let state = test_state().await;
    let token = issue_token_for_state(&state).await;
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

/// 注册一个 Agent 后的 TestEnv：admin Agent 列表相关测试的公共前置。
async fn env_with_enrolled_agent() -> TestEnv {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrolled = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    assert_eq!(enrolled.status(), StatusCode::CREATED);
    env
}

#[tokio::test]
async fn admin_agent_list_requires_admin_bearer() {
    let env = env_with_enrolled_agent().await;

    let unauthorized =
        get_to_router(&env.config, &env.store_handle, "/api/v1/admin/agents", None).await;

    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_agent_list_returns_enrolled_agents() {
    let env = env_with_enrolled_agent().await;

    let listed = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;

    assert_eq!(listed.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(listed).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["limit"], 100);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["agents"][0]["agent_id"], "agent-node-a");
    assert_eq!(body["agents"][0]["tenant_id"], "tenant-default");
    assert_eq!(body["agents"][0]["environment_id"], "env-default");
    assert_eq!(body["agents"][0]["credential_status"], "active");
}

/// 列表的**形状**是前端机队索引页的契约。
///
/// 为什么单列一条：升级页 / 采集工作页靠 `list_agents` 拿机队（不是“有主机指标的 Agent”
/// —— 那个口径会把待命 / 新装的机器漏掉）。前端只读 `agents[].{agent_id,instance_id,
/// hostname,version,status,health}`，所以这些键必须**存在且是字符串**，否则一次后端改名
/// 就会惄悄把页面变成空机队（比报错更难查）。
///
/// 同时钉住「注册表口径」：这台 Agent 只注册过、**没上报过任何状态或指标**，仍必须在列。
#[tokio::test]
async fn admin_agent_list_shape_is_the_registry_contract() {
    let env = env_with_enrolled_agent().await;

    let listed = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;

    assert_eq!(listed.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(listed).await;

    // 外层分页字段。
    assert!(body["total"].is_number(), "total must be a number: {body}");
    assert!(body["limit"].is_number(), "limit must be a number: {body}");
    assert!(
        body["offset"].is_number(),
        "offset must be a number: {body}"
    );

    // 注册表口径：刚注册、什么都没上报过的那台也要在。
    let agents = body["agents"].as_array().expect("agents array");
    assert_eq!(agents.len(), 1, "enrolled agent must be listed: {body}");
    assert_eq!(agents[0]["agent_id"], "agent-node-a");

    // 前端解析的字段：缺一个或类型不对，页面就读不出机队。
    for key in [
        "agent_id",
        "instance_id",
        "hostname",
        "version",
        "status",
        "health",
    ] {
        assert!(
            agents[0].get(key).is_some_and(serde_json::Value::is_string),
            "{key} must be a string in {}",
            agents[0]
        );
    }
}

/// 页大小越界必须**夹紧**，而不是回一个空页。
///
/// 前端取 `limit=500`（正好是 `MAX_AGENT_PAGE_LIMIT`）；若网关回一个空列表，页面会
/// 把它读成“机队没了”—— 比回错页数难查得多。
#[tokio::test]
async fn admin_agent_list_clamps_the_page_size() {
    let env = env_with_enrolled_agent().await;

    for (query, expected) in [
        ("/api/v1/admin/agents?limit=500", 500),  // 前端正在用的值
        ("/api/v1/admin/agents?limit=9999", 500), // 越过上限 → 夹到上限
        ("/api/v1/admin/agents?limit=0", 1),      // 非正 → 至少 1
    ] {
        let response = get_to_router(
            &env.config,
            &env.store_handle,
            query,
            Some(TEST_ADMIN_API_TOKEN),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{query}");
        let body: serde_json::Value = decode_json_response(response).await;
        assert_eq!(body["limit"], expected, "{query}");
        // 夹紧后仍能列出那台机器（不是空页）。
        assert_eq!(body["agents"].as_array().map(Vec::len), Some(1), "{query}");
    }
}

/// **离线的机器**在列表里必须被标成 `offline`，而不是一律 `online`。
///
/// 为什么：升级计划的目标列表要据此把离线机器排除掉 —— 一台几小时没上报的机器还报 "online"，
/// 页面就会把升级派给它，然后那件工作一直挂到过期（或永远等不到）。判据与总览同一处
/// （`agent_is_online`：`last_seen_at` 是否落在 300s 窗口内）。
#[tokio::test]
async fn admin_agent_list_marks_stale_agents_offline() {
    let env = env_with_enrolled_agent().await;

    // 直接写一次「很久以前」的状态上报：HTTP 路径总是把 `last_seen_at` 取当下，
    // 造不出陈旧，所以这里走存储层把水位推老。
    let stale = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    let recorded = env
        .store_handle
        .record_agent_status(&AgentStatusUpdate {
            agent_id: "agent-node-a",
            instance_id: "node-a",
            boot_id: "",
            version: "v0.2.0",
            last_seen_at: &stale,
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
        })
        .await
        .expect("record stale status");
    assert!(recorded, "the enrolled agent must exist");

    let body = admin_agent_list(&env).await;
    assert_eq!(body["agents"][0]["status"], "offline", "{body}");

    // 再来一次「刚刚」的上报：同一台机器必须回到 online —— 判据是水位，不是一次性快照。
    let fresh = chrono::Utc::now().to_rfc3339();
    env.store_handle
        .record_agent_status(&AgentStatusUpdate {
            agent_id: "agent-node-a",
            instance_id: "node-a",
            boot_id: "",
            version: "v0.2.0",
            last_seen_at: &fresh,
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
        })
        .await
        .expect("record fresh status");

    let body = admin_agent_list(&env).await;
    assert_eq!(body["agents"][0]["status"], "online", "{body}");
}

/// **单台运行态的 `status` 与列表口径一致**：同一台机器，列表说离线，详情也必须说离线。
///
/// 曾经单台接口把 `status` 写死 `"online"`，而列表是按 `last_seen_at` 现算 —— 一台几小时
/// 没上报的机器点进详情反而显示在线，运维会把活派给一台已经死掉的机器。
#[tokio::test]
async fn admin_agent_runtime_status_shares_the_online_verdict_with_the_list() {
    let env = env_with_enrolled_agent().await;

    // 直接把水位推老（HTTP 上报路径总是取当下，造不出陈旧）。
    let stale = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    assert!(
        env.store_handle
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-node-a",
                instance_id: "node-a",
                boot_id: "",
                version: "v0.2.0",
                last_seen_at: &stale,
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .expect("record stale status")
    );

    let list = admin_agent_list(&env).await;
    let detail = get_agent_runtime_status(&env).await;
    assert_eq!(list["agents"][0]["status"], "offline", "{list}");
    assert_eq!(detail["status"], "offline", "{detail}");

    // 刚上报过：两处都要回到 online。
    let fresh = chrono::Utc::now().to_rfc3339();
    env.store_handle
        .record_agent_status(&AgentStatusUpdate {
            agent_id: "agent-node-a",
            instance_id: "node-a",
            boot_id: "",
            version: "v0.2.0",
            last_seen_at: &fresh,
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
            local_work: None,
            uplink_state: None,
        })
        .await
        .expect("record fresh status");

    let list = admin_agent_list(&env).await;
    let detail = get_agent_runtime_status(&env).await;
    assert_eq!(list["agents"][0]["status"], "online", "{list}");
    assert_eq!(detail["status"], "online", "{detail}");
}

/// 删除只允许**离线**机器：在线 → 409，且机器分毫未动。
#[tokio::test]
async fn delete_agent_refuses_an_online_agent() {
    let env = env_with_enrolled_agent().await;
    // 刚注册就是 `last_seen_at = 注册时刻`（在线）；再写一条新鲜上报把它明确钉在在线。
    let fresh = chrono::Utc::now().to_rfc3339();
    assert!(
        env.store_handle
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-node-a",
                instance_id: "node-a",
                boot_id: "",
                version: "v0.2.0",
                last_seen_at: &fresh,
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .expect("record fresh status")
    );

    let response = delete_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        env.store_handle
            .get_agent("agent-node-a")
            .await
            .expect("get")
            .is_some(),
        "被拒的删除不能动到机器"
    );
}

/// 离线机器可以删：204，且注册与凭据都消失（旧 token 不能再被认出来）。
#[tokio::test]
async fn delete_agent_removes_an_offline_agent_and_its_credential() {
    let env = env_with_enrolled_agent().await;
    // 把水位推老 → 判离线（HTTP 上报路径总是取当下，造不出陈旧）。
    let stale = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    assert!(
        env.store_handle
            .record_agent_status(&AgentStatusUpdate {
                agent_id: "agent-node-a",
                instance_id: "node-a",
                boot_id: "",
                version: "v0.2.0",
                last_seen_at: &stale,
                memory_bytes: None,
                cpu_percent: None,
                cpu_cores: None,
                admin_latency_ms: None,
                discovery_policy_version: None,
                work_state_changes: None,
                local_work: None,
                uplink_state: None,
            })
            .await
            .expect("record stale status")
    );
    let credential_hash = env
        .store_handle
        .get_agent("agent-node-a")
        .await
        .expect("get")
        .expect("enrolled")
        .credential_token_hash;

    let response = delete_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["agent_id"], "agent-node-a", "{body}");
    assert!(body["deleted_at"].is_string(), "{body}");

    assert!(
        env.store_handle
            .get_agent("agent-node-a")
            .await
            .expect("get")
            .is_none()
    );
    // 凭据行必须一并删掉，否则旧凭据还能被利用。
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_credentials WHERE token_hash = ?1")
            .bind(&credential_hash)
            .fetch_one(env.store.pool())
            .await
            .expect("count credentials");
    assert_eq!(remaining, 0, "凭据必须一并删掉，否则旧凭据还能用");
}

#[tokio::test]
async fn delete_agent_is_not_found_for_an_unknown_agent() {
    let env = env_with_enrolled_agent().await;
    let response = delete_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-nope",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 删除是管理动作（会连凭据一起拿走）：没有 admin token 一律 401。
#[tokio::test]
async fn delete_agent_requires_admin_bearer() {
    let env = env_with_enrolled_agent().await;
    let response = delete_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 在线窗口的**边界**：`last_seen_at` 落在 `0..=300s` 内算在线。
///
/// 注意 `DateTime::seconds_until` 把负差**夹到 0**（`max(0)`）：所以「上报时间在未来」
/// （机器时钟偏快 / 回拨）按 0 秒处理 = **在线**。这是刻意的 —— 一台刚上报、只是时钟
/// 偏快的机器不该被当成离线排掉。
#[test]
fn agent_online_window_is_a_closed_three_hundred_second_boundary() {
    let base = chrono::Utc::now();
    let now = DateTime::from_rfc3339(&base.to_rfc3339()).expect("parse now");
    // 同一时间源推差，避免 `Utc::now()` 与 `DateTime::now()` 的秒级偏差把边界测试弄成偶发。
    let at = |secs_ago: i64| (base - chrono::Duration::seconds(secs_ago)).to_rfc3339();

    assert!(agent_is_online(&at(0), &now), "刚上报：在线");
    assert!(agent_is_online(&at(300), &now), "恰好在窗口上沿：仍算在线");
    assert!(!agent_is_online(&at(301), &now), "越过窗口：离线");
    assert!(
        agent_is_online(&at(-30), &now),
        "未来时间戳被夹到 0 秒 ⇒ 在线（时钟偏快的机器不该被当成离线）"
    );
    assert!(!agent_is_online("not-a-timestamp", &now), "坏时间戳：离线");
}

#[tokio::test]
async fn admin_agent_list_filters_by_tenant() {
    let env = env_with_enrolled_agent().await;

    let filtered = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents?tenant_id=tenant-other",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;

    let body: serde_json::Value = decode_json_response(filtered).await;
    assert_eq!(body["total"], 0);
    assert_eq!(body["agents"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn admin_agent_list_paginates() {
    let env = env_with_enrolled_agent().await;

    // offset 越过末尾：列表为空，但 total 仍反映整体数量。
    let paged = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents?limit=1&offset=1",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;

    let body: serde_json::Value = decode_json_response(paged).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["agents"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn admin_revoke_agent_credential_locks_agent_out() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrolled = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    assert_eq!(enrolled.status(), StatusCode::CREATED);

    let agent = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("load agent")
        .expect("agent exists");
    let credential_id = agent.credential_id.clone();
    assert_eq!(agent.credential_status, StoredCredentialStatus::Active);
    let uri = "/api/v1/admin/agents/agent-node-a/credentials:revoke";

    // 缺 admin 凭据：拒绝。
    let unauthorized = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        None,
        &serde_json::json!({ "credential_id": credential_id }),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 未知凭据：404。
    let unknown = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "credential_id": "cred-unknown" }),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    // 当前凭据：吊销成功。
    let revoked = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "credential_id": credential_id }),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(revoked).await;
    assert_eq!(body["status"], "revoked");
    assert_eq!(body["credential_id"], credential_id);

    // 已吊销：认证路径不再放行，且重复吊销返回 404。
    let agent = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("load agent")
        .expect("agent exists");
    assert_eq!(agent.credential_status, StoredCredentialStatus::Revoked);
    let again = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "credential_id": credential_id }),
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uplink_view_reports_the_target_derived_from_the_deployment_config() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/uplink";

    let unauthorized = get_to_router(&env.config, &env.store_handle, uri, None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 管理面没设过：生效值是**部署配置派生**的 —— 与 Agent 拿到的控制面地址同域 + 数据面端口
    // （「一台机器、一个域名」的部署不必再录一遍）。`updated_at == null` 即「不是管理面录入的值」，
    // 页面据此显示「来自部署配置」。
    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(view.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["host"], "127.0.0.1"); // 取 public_base_url 的主机名
    assert_eq!(body["port"], 9000);
    assert_eq!(body["updated_by"], "");
    assert_eq!(body["updated_at"], serde_json::Value::Null);
    // 派生只说明「能连到哪」，不说明「该不该连」：开关恒为关，
    // 而且必须标出它是**派生的**（页面据此区分「没录入」与「录入过一次不开」）。
    assert_eq!(body["enabled"], false);
    assert_eq!(body["enabled_configured"], false);
}

/// 连派生都派不出（对外基址里取不出主机名）才是真的「未设置」：页面据此提示「没有上送目标」。
#[tokio::test]
async fn uplink_view_is_unset_when_the_base_url_yields_no_host() {
    let mut env = TestEnv::new().await;
    // 真实部署里配置校验挡得住这种基址，这里只钉住「派生不出就返回未设置」的兜底分支。
    env.config.public_base_url = "https://".to_string();

    let view = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/uplink",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(view.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["host"], "");
    assert_eq!(body["port"], 9000);
    assert_eq!(body["updated_at"], serde_json::Value::Null);
}

/// 生效上送目标的两级来源：管理面设置优先，没设过用部署配置派生的。
#[tokio::test]
async fn effective_uplink_prefers_the_admin_setting_over_the_derived_target() {
    let env = TestEnv::new().await;

    let derived = super::install::effective_agent_uplink(&env.config, &env.store_handle)
        .await
        .expect("resolve")
        .expect("derived target");
    assert_eq!(derived.host, "127.0.0.1");
    assert_eq!(derived.port, DEFAULT_AGENT_UPLINK_PORT);
    // 派生值的 `updated_at` 为空 —— 它是「不是管理面录入的」的判据。
    assert_eq!(derived.updated_at, "");

    set_agent_uplink_address(&env, "10.0.1.9", 9100, false).await;
    let chosen = super::install::effective_agent_uplink(&env.config, &env.store_handle)
        .await
        .expect("resolve")
        .expect("admin setting");
    assert_eq!(chosen.host, "10.0.1.9");
    assert_eq!(chosen.port, 9100);
    assert_eq!(chosen.updated_by, "ops");
}

/// 派生只取主机名：丢 scheme、丢端口、丢路径；IPv6 字面量拼不出 `host:port`，判为派生不出。
#[tokio::test]
async fn derived_uplink_target_takes_only_the_host_name() {
    let mut env = TestEnv::new().await;
    for (base, expected) in [
        ("https://gw.example.com", Some("gw.example.com")),
        ("https://gw.example.com/", Some("gw.example.com")),
        ("https://gw.example.com:8443/admin", Some("gw.example.com")),
        (
            "https://gw.example.com:8443/a/b?x=1#f",
            Some("gw.example.com"),
        ),
        ("  https://gw.example.com  ", Some("gw.example.com")),
        ("https://10.0.0.1", Some("10.0.0.1")),
        ("https://gw-ex_1.example.com", Some("gw-ex_1.example.com")),
        // 取不出**干净**的主机名就不猜（比派生错一个地址好）：
        ("https://[::1]:8443", None),
        ("https://::1", None),
        ("https://user@gw.example.com", None),
        ("https://gw example.com", None),
        ("https://", None),
        ("", None),
    ] {
        env.config.public_base_url = base.to_string();
        let derived = super::install::derived_agent_uplink(&env.config, &env.store_handle).await;
        match expected {
            Some(host) => {
                let setting = derived.expect("derived target");
                assert_eq!(setting.host, host, "base {base}");
                assert_eq!(setting.port, DEFAULT_AGENT_UPLINK_PORT, "base {base}");
                // 派生值的判据：不是管理面录入的。
                assert_eq!(setting.updated_at, "", "base {base}");
                assert_eq!(setting.updated_by, "", "base {base}");
            }
            None => assert!(derived.is_none(), "base {base}"),
        }
    }
}

/// 读上送设置失败时的口径（三条路径各不相同，都是刻意的）：
///   * 管理面看得到 —— 查看端点 500，不把「读不到」伪装成「未设置」；
///   * 授权端点 500 让 agentd 重试 —— 待命是**实质决定**，不在读库失败时替它做；
///   * 安装链路不因此中断 —— 按「没设过」用派生目标，只留告警。
#[tokio::test]
async fn uplink_store_failure_is_reported_but_does_not_break_install() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let credential = enroll_agent_credential(&env).await;
    // 直接撤掉这张表：等价于读设置时出错。
    sqlx::query("DROP TABLE agent_uplink")
        .execute(env.store.pool())
        .await
        .expect("drop uplink table");

    let view = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/uplink",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(view.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let poll = poll_uplink(&env, Some(&credential)).await;
    assert_eq!(poll.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let response = router(env.config.clone(), env.store_handle.clone())
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
    let text = decode_text_response(response).await;
    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    assert_eq!(parsed.telemetry.logs.output.tcp.addr, "127.0.0.1");
    assert!(!parsed.telemetry.logs.output.enabled);
}

#[tokio::test]
async fn uplink_set_validates_and_round_trips() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/uplink";

    // 带 scheme / 自带端口 / 空主机 / 端口越界的写法一律 400：agentd 是把
    // `addr` 与 `port` 分开拼成 `addr:port` 的，收下这些值只会拼出连不上的地址。
    for bad in [
        serde_json::json!({ "host": "", "port": 9000 }),
        serde_json::json!({ "host": "https://10.0.1.9", "port": 9000 }),
        serde_json::json!({ "host": "10.0.1.9:9000", "port": 9000 }),
        serde_json::json!({ "host": "10.0.1.9", "port": 0 }),
        serde_json::json!({ "host": "10.0.1.9", "port": 70000 }),
    ] {
        let response = post_json_to_router(
            &env.config,
            &env.store_handle,
            uri,
            Some(TEST_ADMIN_API_TOKEN),
            &bad,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "input {bad}");
    }
    // 被拒的输入不落库。
    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["updated_at"], serde_json::Value::Null);

    let ok = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        // 故意**不带** `enabled`：老前端 / 老脚本只发地址，不得顺手把全队打开。
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100, "requested_by": "ops" }),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let stored: serde_json::Value = decode_json_response(ok).await;
    assert_eq!(stored["host"], "10.0.1.9");
    assert_eq!(stored["port"], 9100);
    assert_eq!(stored["updated_by"], "ops");
    assert_eq!(stored["enabled"], false, "缺省必须落在「不启用」这侧");

    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["host"], "10.0.1.9");
    assert_eq!(body["port"], 9100);
    assert_eq!(body["updated_at"], stored["updated_at"]);
    assert_eq!(body["enabled"], false);
    // 录入过一次（哪怕是 false）——「已配置」看的是**有没有录入**，不是那个布尔值本身。
    assert_eq!(body["enabled_configured"], true);
}

/// 部署级启用开关：录入 → 立即被响应回带；再录一次能关上。
#[tokio::test]
async fn uplink_switch_round_trips_through_the_admin_route() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/uplink";

    let on = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100, "enabled": true }),
    )
    .await;
    assert_eq!(on.status(), StatusCode::OK);
    let stored: serde_json::Value = decode_json_response(on).await;
    assert_eq!(stored["enabled"], true);
    assert_eq!(stored["enabled_configured"], true);

    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["enabled"], true);

    // 关回去：开关是可逆的，不需要删设置（删了会回落到派生目标，那又是另一回事）。
    let off = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100, "enabled": false }),
    )
    .await;
    let stored: serde_json::Value = decode_json_response(off).await;
    assert_eq!(stored["enabled"], false);
    assert_eq!(stored["enabled_configured"], true);
}

/// **缺省 `enabled` = 保持已存值**，不是「关掉」。
///
/// 两个方向都得是这个形状：
///   * 已存值是 `true` → 老客户端/脚本只改地址，**不能**把全队的上送静默掉；
///   * 从未录入过 → `false`，**不能**顺手把全队打开。
/// 不钉住第二条就会出现「一台 curl 把整个机队掐了」这种没人能一眼看出的故障。
#[tokio::test]
async fn omitting_the_switch_keeps_the_stored_value_instead_of_turning_it_off() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/uplink";

    // ① 从未录入过：不带 `enabled` 的旧式请求落 `false`。
    let first = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100 }),
    )
    .await;
    let stored: serde_json::Value = decode_json_response(first).await;
    assert_eq!(stored["enabled"], false, "缺省绝不可能把全队打开");

    // ② 显式打开。
    let on = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100, "enabled": true }),
    )
    .await;
    let stored: serde_json::Value = decode_json_response(on).await;
    assert_eq!(stored["enabled"], true);

    // ③ 再发一次**不带 `enabled`** 的旧式请求（典型：老客户端只改端口）→ 开关必须留着。
    let legacy = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "host": "10.0.1.9", "port": 9200 }),
    )
    .await;
    let stored: serde_json::Value = decode_json_response(legacy).await;
    assert_eq!(stored["port"], 9200, "地址要按请求改掉");
    assert_eq!(
        stored["enabled"], true,
        "缺省必须保留已打开的开关 —— 否则一次地址变更就静默掐掉全队上送"
    );
}

#[tokio::test]
async fn advertise_url_view_reports_config_fallback() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/advertise-url";

    let unauthorized = get_to_router(&env.config, &env.store_handle, uri, None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 未设置过：url 为空，但 fallback 要给出网关当前**实际**用的基址 ——
    // 否则页面只能显示一个空值，答不出「不设置的话 agent 会连到哪里」。
    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(view.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["url"], "");
    assert_eq!(body["fallback_url"], env.config.public_base_url);
    assert_eq!(body["updated_by"], "");
    assert_eq!(body["updated_at"], serde_json::Value::Null);
}

#[tokio::test]
async fn advertise_url_set_validates_and_round_trips() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/advertise-url";

    // 只收 https 基址：它会被拼进安装命令与 install.sh 的 URL，还会写成 Agent 的控制面
    // endpoint。http、裸主机、只有 scheme、带 shell 元字符的写法一律 400。
    for bad in [
        serde_json::json!({ "url": "" }),
        serde_json::json!({ "url": "http://gw.example.com" }),
        serde_json::json!({ "url": "gw.example.com" }),
        serde_json::json!({ "url": "https://" }),
        serde_json::json!({ "url": "https://gw.example.com; touch /tmp/pwned" }),
        serde_json::json!({ "url": "https://gw.example.com/$(id)" }),
        serde_json::json!({ "url": "https://gw.example.com/a b" }),
    ] {
        let response = post_json_to_router(
            &env.config,
            &env.store_handle,
            uri,
            Some(TEST_ADMIN_API_TOKEN),
            &bad,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "input {bad}");
    }
    // 被拒的输入不落库。
    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["updated_at"], serde_json::Value::Null);

    // 尾斜杠允许，保存时裁掉 —— 拼路径时不会再出现双斜杠。
    let ok = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "url": "https://gw.example.com/", "requested_by": "ops" }),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let stored: serde_json::Value = decode_json_response(ok).await;
    assert_eq!(stored["url"], "https://gw.example.com");
    assert_eq!(stored["updated_by"], "ops");

    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["url"], "https://gw.example.com");
    assert_eq!(body["updated_at"], stored["updated_at"]);
}

#[tokio::test]
async fn advertise_url_drives_install_code_and_initial_config() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/advertise-url";

    // 未设置时，安装命令 / 分发地址 / Agent 控制面 endpoint 全部来自配置里的
    // server.public_base_url —— 既有行为不变。
    let before = issue_agent_install_code(&env.config, &env.store_handle)
        .await
        .unwrap();
    assert_eq!(
        before.bootstrap_bundle.control_endpoint,
        env.config.public_base_url
    );
    assert!(
        before
            .bootstrap_bundle
            .agent_package_url
            .starts_with(&env.config.public_base_url)
    );

    let ok = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "url": "https://gw.example.com" }),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);

    // 设置之后，同一批产物全部改用设置值 —— 这就是这个设置项的全部意义：
    // agent 拿到的必须是它对目标主机可见的地址。
    let after = issue_agent_install_code(&env.config, &env.store_handle)
        .await
        .unwrap();
    assert_eq!(
        after.bootstrap_bundle.control_endpoint,
        "https://gw.example.com"
    );
    assert!(
        after
            .bootstrap_bundle
            .install_script_url
            .starts_with("https://gw.example.com/api/v1/agent/install/")
    );
    assert!(
        after
            .bootstrap_bundle
            .agent_package_url
            .starts_with("https://gw.example.com/api/v1/agent/packages/current")
    );
    assert!(
        after
            .x86_linux_install_code
            .contains("https://gw.example.com/api/v1/agent/install/x86/install.sh")
    );
    assert!(
        after
            .macos_install_code
            .contains("https://gw.example.com/api/v1/agent/install/")
    );
    assert!(
        !after
            .x86_linux_install_code
            .contains(&env.config.public_base_url)
    );

    // 初始配置里的控制面 endpoint 与 tls_mode 同源派生自它。
    let text = agent_initial_config_toml(
        &env.config,
        "install-token-a",
        None,
        "https://gw.example.com",
    );
    assert!(text.contains("endpoint = \"https://gw.example.com\""));
    assert!(text.contains("tls_mode = \"https\""));
    assert!(!text.contains(&env.config.public_base_url));
}

#[tokio::test]
async fn install_package_view_starts_unset() {
    let env = TestEnv::new_without_package().await;
    let uri = "/api/v1/admin/agent/install-package";

    let unauthorized = get_to_router(&env.config, &env.store_handle, uri, None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 未设置过：来源地址为空。安装端始终从网关取包，此处报的是网关的取包来源，
    // 回填分发端点会误导操作者（那样存进去会让网关去请求它自己）。
    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(view.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["package_url"], "");
    assert_eq!(body["package_sha256"], serde_json::Value::Null);
    assert_eq!(body["updated_by"], "");
    assert_eq!(body["updated_at"], serde_json::Value::Null);
}

#[tokio::test]
async fn install_package_set_rejects_bad_input() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/install-package";

    // 明文 http：安装包是 Agent 启动来源，不允许明文分发。
    let insecure = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": "http://example.com/agentd.tar.gz" }),
    )
    .await;
    assert_eq!(insecure.status(), StatusCode::BAD_REQUEST);

    let bad_digest = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "package_url": "https://example.com/agentd.tar.gz",
            "package_sha256": "not-a-digest",
        }),
    )
    .await;
    assert_eq!(bad_digest.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn install_package_set_rejects_unfetchable_source() {
    let env = TestEnv::new_without_package().await;
    let missing = write_source_package(&env, "gone", b"x");
    std::fs::remove_file(&missing).expect("remove source");

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": missing }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        env.store
            .get_agent_install_package()
            .await
            .unwrap()
            .is_none(),
        "a failed set must not persist"
    );
}

#[tokio::test]
async fn install_package_set_rejects_mismatched_digest() {
    let env = TestEnv::new_without_package().await;
    let source = write_source_package(&env, "source", b"cached-package-bytes-v1");

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "package_url": source,
            "package_sha256": "b".repeat(64),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        env.store
            .get_agent_install_package()
            .await
            .unwrap()
            .is_none(),
        "a mismatched digest must not persist"
    );
}

#[tokio::test]
async fn install_package_set_stores_computed_digest() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/install-package";
    let bytes = b"cached-package-bytes-v1";
    let source = write_source_package(&env, "source", bytes);
    let digest = bytes_sha256_hex(bytes);

    // 期望摘要可带前缀与大写；落库的是网关按实际内容算出的小写 sha256:<hex>。
    let set = post_json_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "package_url": source,
            "package_sha256": format!("sha256:{}", digest.to_uppercase()),
            "requested_by": "platform-eng",
        }),
    )
    .await;
    assert_eq!(set.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(set).await;
    assert_eq!(body["package_url"], source);
    assert_eq!(body["package_sha256"], format!("sha256:{digest}"));
    assert_eq!(body["updated_by"], "platform-eng");
    assert!(body["updated_at"].is_string());

    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["package_url"], source);
    assert_eq!(body["updated_by"], "platform-eng");
}

#[tokio::test]
async fn install_package_set_caches_artifact_locally() {
    let env = TestEnv::new().await;
    let bytes = b"cached-package-bytes-v2";
    set_install_package_source(&env, "mirror", bytes).await;

    let cached = env.config.install_package_cache_path();
    assert!(cached.is_file(), "artifact should be cached locally");
    assert_eq!(std::fs::read(&cached).expect("read cache"), bytes.to_vec());
}

#[tokio::test]
async fn install_code_distributes_gateway_endpoint() {
    let env = TestEnv::new().await;
    let bytes = b"cached-package-bytes-v2";
    let (_, digest) = set_install_package_source(&env, "mirror", bytes).await;

    let install_code = issue_agent_install_code(&env.config, &env.store_handle)
        .await
        .expect("install code");

    // 分发地址恒为网关端点，摘要取自本地缓存：两者同源，安装端不会 mismatch。
    assert_eq!(
        install_code.bootstrap_bundle.agent_package_url,
        env.config.agent_package_url()
    );
    assert_eq!(install_code.bootstrap_bundle.agent_package_sha256, digest);
}

#[tokio::test]
async fn install_script_hides_source_address() {
    let env = TestEnv::new().await;
    let bytes = b"cached-package-bytes-v2";
    let (source, digest) = set_install_package_source(&env, "mirror", bytes).await;

    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install/x86/install.sh",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let script = String::from_utf8(body_bytes(response).await.to_vec()).expect("utf8 script");

    assert!(script.contains(&env.config.agent_package_url()));
    assert!(script.contains(&digest));
    assert!(
        !script.contains(&source),
        "install.sh must not expose the source address"
    );
}

#[tokio::test]
async fn package_download_serves_cached_artifact() {
    let env = TestEnv::new().await;
    let bytes = b"cached-package-bytes-v2";
    set_install_package_source(&env, "mirror", bytes).await;
    let token = env.issue_token().await;

    let response = router(env.config.clone(), Arc::clone(&env.store_handle))
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
    assert_eq!(body_bytes(response).await.to_vec(), bytes.to_vec());
}

/// 构造一个最小可解析的 tar.gz：单个条目 `path_in_archive` → `contents`。
fn tar_gz_with_entry(path_in_archive: &str, contents: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut builder = tar::Builder::new(&mut encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, path_in_archive, contents)
            .expect("append tar entry");
        builder.finish().expect("finish tar");
    }
    encoder.finish().expect("finish gzip")
}

#[test]
fn read_package_identity_parses_version_and_triple() {
    let bytes = tar_gz_with_entry(
        "wist-agentd-1.2.3-x86_64-unknown-linux-gnu/wist-agentd",
        b"agentd-binary",
    );
    assert_eq!(
        read_package_identity(&bytes),
        ("1.2.3".to_string(), "x86_64-unknown-linux-gnu".to_string())
    );
}

#[test]
fn read_package_identity_tolerates_non_packages() {
    // 裸二进制/非 gzip/空字节：读不出身份但不 panic，留空串（行照记）。
    for bytes in [b"not-a-package".as_slice(), &[], b"\x1f\x8b\x00".as_slice()] {
        assert_eq!(read_package_identity(bytes), (String::new(), String::new()));
    }
    // 是合法 tar.gz、但顶层目录不是 wist-agentd-<version>-<triple>：同样留空。
    let odd = tar_gz_with_entry("some-other-dir/file", b"x");
    assert_eq!(read_package_identity(&odd), (String::new(), String::new()));
}

#[tokio::test]
async fn install_package_history_lists_recorded_packages() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/install-packages";

    // 无凭据 → 401。
    let unauthorized = get_to_router(&env.config, &env.store_handle, uri, None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-aarch64-apple-darwin/wist-agentd",
        b"agentd-v0.1.9",
    );
    let (source, digest) = set_install_package_source(&env, "history", &pkg).await;
    let package_id = package_id_for_sha256(&digest);

    // 网关为这个包单独存了一份副本（升级按条目取包要用）。
    let cached = env.config.install_package_history_path(&package_id);
    assert_eq!(
        std::fs::read(&cached).expect("per-package copy"),
        pkg,
        "each recorded package gets its own cached copy"
    );

    let response = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    let packages = body["packages"].as_array().expect("packages array");
    assert_eq!(packages.len(), 1);
    let entry = &packages[0];
    assert_eq!(entry["package_id"], package_id);
    assert_eq!(entry["source"], source);
    assert_eq!(entry["package_sha256"], format!("sha256:{digest}"));
    assert_eq!(entry["version"], "0.1.9");
    assert_eq!(entry["arch"], "aarch64-apple-darwin");
    assert_eq!(entry["created_by"], "platform-maintenance-engineer");
    assert!(entry["created_at"].is_string());
}

#[tokio::test]
async fn install_package_history_entry_carries_derived_download_url() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/install-packages";
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.2.0-aarch64-apple-darwin/wist-agentd",
        b"agentd-v0.2.0",
    );
    let (_, digest) = set_install_package_source(&env, "url-derive", &pkg).await;
    let package_id = package_id_for_sha256(&digest);

    // 未设 advertise-url：基址取 server.public_base_url。
    let body: serde_json::Value = decode_json_response(
        get_to_router(
            &env.config,
            &env.store_handle,
            uri,
            Some(TEST_ADMIN_API_TOKEN),
        )
        .await,
    )
    .await;
    assert_eq!(
        body["packages"][0]["agent_package_url"],
        format!(
            "{}/api/v1/agent/packages/{package_id}",
            env.config.public_base_url
        )
    );

    // 设置网关对外地址后，该字段跟随生效基址（与安装命令同一口径）。
    let ok = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/advertise-url",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "url": "https://gw.example.com" }),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);

    let body: serde_json::Value = decode_json_response(
        get_to_router(
            &env.config,
            &env.store_handle,
            uri,
            Some(TEST_ADMIN_API_TOKEN),
        )
        .await,
    )
    .await;
    assert_eq!(
        body["packages"][0]["agent_package_url"],
        format!("https://gw.example.com/api/v1/agent/packages/{package_id}")
    );
}

#[tokio::test]
async fn package_download_by_id_accepts_bootstrap_token_or_client_certificate() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-x86_64-unknown-linux-gnu/wist-agentd",
        b"agentd-upgrade-bytes",
    );
    let (_, digest) = set_install_package_source(&env, "byid", &pkg).await;
    let package_id = package_id_for_sha256(&digest);
    let uri = format!("/api/v1/agent/packages/{package_id}");

    // 无凭据（也没证书）→ 401。
    let unauthorized = get_agent_package(&env, &uri, None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // bootstrap（注册）token → 200 + 字节。
    let bootstrap = env.issue_token().await;
    let response = get_to_router(&env.config, &env.store_handle, &uri, Some(&bootstrap)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await.to_vec(), pkg);

    // 客户端证书（升级路径，没 enrollment token）→ 200 + 字节。
    let agent_id = enroll_agent_credential(&env).await;
    let response = get_agent_package(&env, &uri, Some(&agent_id)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await.to_vec(), pkg);

    // 未知 id → 404（证书有效）。
    let unknown = get_agent_package(
        &env,
        "/api/v1/agent/packages/pkg-0000000000000000",
        Some(&agent_id),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn current_package_download_accepts_a_client_certificate() {
    let env = TestEnv::new().await;
    let bytes = b"cached-package-current";
    set_install_package_source(&env, "current", bytes).await;
    let agent_id = enroll_agent_credential(&env).await;

    let response = get_agent_package(&env, "/api/v1/agent/packages/current", Some(&agent_id)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await.to_vec(), bytes.to_vec());
}

/// 安装包分发端点「没带凭据」的对外口径（无 bootstrap token、也没客户端证书）。
const PACKAGE_NO_CREDENTIAL_BODY: &str =
    "agent package download requires a bootstrap token or a client certificate";
/// 「带了 bootstrap token 但不合法」的统一口径：未知 / 过期 / 已消费 / 已吊销，
/// 一律回这一句 —— 不区分「token 存在但过期」这类可被用来枚举的信息。
const PACKAGE_INVALID_BOOTSTRAP_BODY: &str = "invalid bootstrap token";

/// 用**原始** Authorization 头值发一次取包 GET（`get_to_router` 只能给合法 Bearer）。
async fn get_package_with_raw_authorization(
    env: &TestEnv,
    uri: &str,
    authorization: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(value) = authorization {
        builder = builder.header("authorization", value);
    }
    router(env.config.clone(), Arc::clone(&env.store_handle))
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("route response")
}

/// 断言一次取包鉴权失败：401 + `no-store` + 统一口径的响应体（不泄露细节）。
async fn assert_auth_rejected(response: axum::response::Response, expected_body: &str) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_store(&response);
    let body = String::from_utf8_lossy(&body_bytes(response).await).to_string();
    assert_eq!(body, expected_body);
}

#[tokio::test]
async fn package_download_rejects_missing_and_malformed_credentials_uniformly() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-x86_64-unknown-linux-gnu/wist-agentd",
        b"credential-shape-bytes",
    );
    let (_, digest) = set_install_package_source(&env, "credential-shape", &pkg).await;
    let package_id = package_id_for_sha256(&digest);
    let uri = format!("/api/v1/agent/packages/{package_id}");

    // 根本没带 Authorization 头，也没客户端证书。
    assert_auth_rejected(
        get_package_with_raw_authorization(&env, &uri, None).await,
        PACKAGE_NO_CREDENTIAL_BODY,
    )
    .await;
    // `Bearer ` 后面是空 token：被当成「没带 token」（trim + filter 空串）。
    assert_auth_rejected(
        get_package_with_raw_authorization(&env, &uri, Some("Bearer ")).await,
        PACKAGE_NO_CREDENTIAL_BODY,
    )
    .await;
    // 非 Bearer 方案（Basic）：同样按「没带 token」处理，不解析。
    assert_auth_rejected(
        get_package_with_raw_authorization(&env, &uri, Some("Basic dXNlcjpwYXNz")).await,
        PACKAGE_NO_CREDENTIAL_BODY,
    )
    .await;
    // 未知的 bootstrap token：统一口径（不暴露「不存在」）。
    assert_auth_rejected(
        get_package_with_raw_authorization(&env, &uri, Some("Bearer wit_does_not_exist")).await,
        PACKAGE_INVALID_BOOTSTRAP_BODY,
    )
    .await;
    // 长得像 agent 凭据的 token（旧双轨遗留）：现在没有任何效力，按 bootstrap 校验失败统一口径。
    assert_auth_rejected(
        get_package_with_raw_authorization(&env, &uri, Some("Bearer wic_does_not_exist")).await,
        PACKAGE_INVALID_BOOTSTRAP_BODY,
    )
    .await;
}

/// 拒绝名单同样拦升级取包：被吊销的 agent 连包也不该能取（§5.6）。
#[tokio::test]
async fn package_download_rejects_a_revoked_agent() {
    let env = TestEnv::new().await;
    set_install_package_source(&env, "revoked-agent", b"revoked-agent-bytes").await;
    let agent_id = enroll_agent_credential(&env).await;

    let before = get_agent_package(&env, "/api/v1/agent/packages/current", Some(&agent_id)).await;
    assert_eq!(before.status(), StatusCode::OK);

    assert_eq!(
        revoke_agent_via_admin(&env, "agent-node-a", "cut off")
            .await
            .status(),
        StatusCode::OK
    );

    let after = get_agent_package(&env, "/api/v1/agent/packages/current", Some(&agent_id)).await;
    assert_auth_rejected(after, "invalid agent client certificate").await;
}

#[tokio::test]
async fn any_registered_agent_credential_can_fetch_any_package_by_id() {
    let env = TestEnv::new().await;
    let pkg_one = tar_gz_with_entry(
        "wist-agentd-0.1.9-x86_64-unknown-linux-gnu/wist-agentd",
        b"package-one-bytes",
    );
    let (_, digest_one) = set_install_package_source(&env, "any-agent-one", &pkg_one).await;
    let id_one = package_id_for_sha256(&digest_one);
    let pkg_two = tar_gz_with_entry(
        "wist-agentd-0.2.0-x86_64-unknown-linux-gnu/wist-agentd",
        b"package-two-bytes",
    );
    let (_, digest_two) = set_install_package_source(&env, "any-agent-two", &pkg_two).await;
    let id_two = package_id_for_sha256(&digest_two);

    // 单个 agent 凭据能取**任意**已录入的包：两个包都不是它录入的，也没有归属表。
    // 这是当前**设计**：网关按配置单租户，安装包本身不是秘密（install.sh 内嵌地址与摘要），
    // 端点上刻意不做按 agent 的归属/租户校验。本测试钉住现状，改语义前必须先改这里。
    let credential = enroll_agent_credential(&env).await;
    for (package_id, bytes) in [(&id_one, &pkg_one), (&id_two, &pkg_two)] {
        let response = get_agent_package(
            &env,
            &format!("/api/v1/agent/packages/{package_id}"),
            Some(&credential),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.to_vec(), bytes.to_vec());
    }
}

#[tokio::test]
async fn package_download_by_id_rejects_path_traversal_ids_without_reading_disk() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-x86_64-unknown-linux-gnu/wist-agentd",
        b"traversal-guard-bytes",
    );
    let (_, digest) = set_install_package_source(&env, "traversal", &pkg).await;
    let package_id = package_id_for_sha256(&digest);
    let credential = enroll_agent_credential(&env).await;

    // 在 history 目录的**上一级**放一个哨兵文件：若 handler 拿 package_id 去 join 磁盘路径，
    // `..%2Fwist-sentinel` 会顺着目录穿越读到它。这里断言永远读不到、也不吐任何缓存字节。
    let history_dir = env.config.install_package_history_path("pkg-placeholder");
    let history_dir = history_dir.parent().expect("history dir");
    let sentinel = history_dir
        .parent()
        .expect("install-package dir")
        .join("wist-sentinel");
    std::fs::write(&sentinel, b"sentinel-must-not-be-served").expect("write sentinel");

    let variants = [
        "..%2F..%2Fetc%2Fpasswd",
        "..%2Fwist-sentinel",
        "..%2Fagent-package",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "a%00b",
    ];
    for variant in variants {
        let uri = format!("/api/v1/agent/packages/{variant}");
        let response = get_agent_package(&env, &uri, Some(&credential)).await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "traversal id {variant} must not resolve"
        );
        assert_no_store(&response);
        let body = body_bytes(response).await.to_vec();
        assert_ne!(
            body, pkg,
            "traversal id {variant} must not serve the cached package"
        );
        assert_ne!(
            body,
            b"sentinel-must-not-be-served".to_vec(),
            "traversal id {variant} must not read the sentinel file"
        );
        assert_eq!(body, b"unknown agent package".to_vec());
    }

    // 超长 id（>1KB）：不 panic、不读盘，按「库里没有」处理。
    let long_uri = format!("/api/v1/agent/packages/{}", "a".repeat(2_000));
    let long = get_agent_package(&env, &long_uri, Some(&credential)).await;
    assert_eq!(long.status(), StatusCode::NOT_FOUND);

    // 空 package_id（尾斜杠）：路由层没有可匹配的动态段，同样不是 200。
    let empty = get_agent_package(&env, "/api/v1/agent/packages/", Some(&credential)).await;
    assert_eq!(empty.status(), StatusCode::NOT_FOUND);

    // 正常 id 仍能取到原字节（确认上面的 404 不是「整个端点坏了」）。
    let ok = get_agent_package(
        &env,
        &format!("/api/v1/agent/packages/{package_id}"),
        Some(&credential),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(body_bytes(ok).await.to_vec(), pkg);
}

/// 复用同一个 router 实例发一次取包 GET：限流状态挂在 state 上，必须共享才会累积。
async fn package_get_with_bearer(app: &axum::Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/packages/current")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response")
}

#[tokio::test]
async fn package_routes_rate_limit_repeated_failed_auth_attempts() {
    let env = TestEnv::new().await;
    set_install_package_source(&env, "rate-limit", b"rate-limit-bytes").await;
    let app = router(env.config.clone(), env.store_handle.clone());

    // 前 5 次失败都以 401 回应（沿用 BOOTSTRAP_AUTH_SCOPE 的失败计数）。
    for _ in 0..5 {
        let response = package_get_with_bearer(&app, "wit_not-a-real-token").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // 第 6 次在同一桶上被限流：不能靠反复试错绕过。
    let blocked = package_get_with_bearer(&app, "wit_not-a-real-token").await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(blocked.headers().contains_key(header::RETRY_AFTER));
    assert_no_store(&blocked);
}

#[tokio::test]
async fn recorded_package_with_a_missing_copy_is_unavailable() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;
    // 录入过，但网关那份副本丢了：没有可用包（不会回落到别的来源）。
    std::fs::remove_file(env.config.install_package_cache_path()).expect("remove cached copy");

    let current =
        get_agent_package(&env, "/api/v1/agent/packages/current", Some(&credential)).await;
    assert_eq!(current.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&current);

    // 安装脚本要嵌摘要，没有包就必须明确失败（而不是发一份空摘要的脚本下去）。
    let script = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/install/x86/install.sh",
        None,
    )
    .await;
    assert_eq!(script.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = decode_text_response(script).await;
    assert!(body.contains("没有可用的 agent 安装包"), "{body}");
}

#[tokio::test]
async fn package_download_success_clears_the_failure_count() {
    let env = TestEnv::new().await;
    set_install_package_source(&env, "rate-limit-clear", b"rate-limit-clear-bytes").await;
    let app = router(env.config.clone(), env.store_handle.clone());
    let valid = env.issue_token().await;

    for _ in 0..4 {
        let response = package_get_with_bearer(&app, "wit_not-a-real-token").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // 一次成功必须清零失败计数：否则一次失败就会把客户端推向永久封禁。
    let ok = package_get_with_bearer(&app, &valid).await;
    assert_eq!(ok.status(), StatusCode::OK);

    // 清零后重新计：再失败 5 次都还是 401（若没清零，这里第二次就该 429）。
    for _ in 0..5 {
        let response = package_get_with_bearer(&app, "wit_not-a-real-token").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let blocked = package_get_with_bearer(&app, "wit_not-a-real-token").await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn package_download_without_a_recorded_package_is_no_store() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    // 抹掉「已录入的安装包」这一行：缓存副本还在，但没有来源就是**没有可用包**
    // （已删的 `agent.package_file` 不再是退路）→ 503，而且必须 no-store。
    sqlx::query("DELETE FROM agent_install_package")
        .execute(env.store.pool())
        .await
        .expect("clear recorded package");
    let current =
        get_agent_package(&env, "/api/v1/agent/packages/current", Some(&credential)).await;
    assert_eq!(current.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&current);
    let body = decode_text_response(current).await;
    assert!(body.contains("not configured"), "{body}");

    // by-id 的库读失败（直接撤掉历史表）→ 500，也必须 no-store。
    sqlx::query("DROP TABLE agent_install_package_history")
        .execute(env.store.pool())
        .await
        .expect("drop history table");
    let by_id = get_agent_package(
        &env,
        "/api/v1/agent/packages/pkg-0000000000000000",
        Some(&credential),
    )
    .await;
    assert_eq!(by_id.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_no_store(&by_id);
}

#[tokio::test]
async fn current_package_download_still_enforces_one_time_bootstrap_tokens() {
    let env = TestEnv::new().await;
    set_install_package_source(&env, "one-time", b"one-time-bytes").await;

    // 取包端点同时接受客户端证书，没有放松 bootstrap token 的既有语义：
    // 1) 首次可用。
    let token = env.issue_token().await;
    let first = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/packages/current",
        Some(&token),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // 2) 被 enroll 消费后（一次性）不能再取包。
    let enrolled = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    assert_eq!(enrolled.status(), StatusCode::CREATED);
    let replay = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/packages/current",
        Some(&token),
    )
    .await;
    assert_auth_rejected(replay, PACKAGE_INVALID_BOOTSTRAP_BODY).await;

    // 3) 过期 token 同样被拒。
    let expired = env.issue_token().await;
    sqlx::query("UPDATE enrollment_tokens SET expires_at = ?1 WHERE token_hash = ?2")
        .bind("2020-01-01T00:00:00+00:00")
        .bind(token_hash(&expired))
        .execute(env.store.pool())
        .await
        .expect("expire bootstrap token");
    let after = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/packages/current",
        Some(&expired),
    )
    .await;
    assert_auth_rejected(after, PACKAGE_INVALID_BOOTSTRAP_BODY).await;
}

#[tokio::test]
async fn install_package_history_url_is_admin_only_and_never_leaked_unauthenticated() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-x86_64-unknown-linux-gnu/wist-agentd",
        b"url-secret-bytes",
    );
    let (_, digest) = set_install_package_source(&env, "url-secret", &pkg).await;
    let package_id = package_id_for_sha256(&digest);
    let expected_url = format!(
        "{}/api/v1/agent/packages/{package_id}",
        env.config.public_base_url
    );

    // 管理面历史列表无凭据：401，且响应体里不得出现字段名或派生地址。
    let unauthorized = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-packages",
        None,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let body = String::from_utf8_lossy(&body_bytes(unauthorized).await).to_string();
    assert!(!body.contains("agent_package_url"));
    assert!(!body.contains(&expected_url));

    // 安装包分发端点无凭据：同样 401，不泄露地址。
    let pkg_unauth = get_to_router(
        &env.config,
        &env.store_handle,
        &format!("/api/v1/agent/packages/{package_id}"),
        None,
    )
    .await;
    assert_eq!(pkg_unauth.status(), StatusCode::UNAUTHORIZED);
    let body = String::from_utf8_lossy(&body_bytes(pkg_unauth).await).to_string();
    assert!(!body.contains("agent_package_url"));
    assert!(!body.contains(&expected_url));

    // 正例：带上 admin bearer 才出现该字段（防止上面的断言是假阴性）。
    let authorized = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-packages",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(authorized.status(), StatusCode::OK);
    let body = String::from_utf8_lossy(&body_bytes(authorized).await).to_string();
    assert!(body.contains(&expected_url));
}

#[tokio::test]
async fn install_package_history_absent_when_source_unreadable() {
    let env = TestEnv::new().await;
    let missing = write_source_package(&env, "gone-history", b"x");
    std::fs::remove_file(&missing).expect("remove source");

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": missing }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        env.store
            .list_agent_install_packages()
            .await
            .unwrap()
            .is_empty(),
        "a failed set must not leave a history row"
    );
}

#[tokio::test]
async fn install_package_history_empty_lists_as_empty_array() {
    let env = TestEnv::new().await;
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-packages",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    // 空历史是一个成功的空列表，不是 404 / null。
    assert_eq!(body, serde_json::json!({ "packages": [] }));
}

#[tokio::test]
async fn install_package_set_records_setting_and_history_together() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.3.1-x86_64-unknown-linux-gnu/wist-agentd",
        b"agentd-0.3.1",
    );
    let (source, digest) = set_install_package_source(&env, "together", &pkg).await;
    let package_id = package_id_for_sha256(&digest);

    // 成功录入：单行设置（当前生效来源）与历史行**都在**，且摘要同源。
    let setting = env
        .store
        .get_agent_install_package()
        .await
        .unwrap()
        .expect("setting");
    assert_eq!(setting.package_url, source);
    assert_eq!(
        setting.package_sha256.as_deref(),
        Some(format!("sha256:{digest}").as_str())
    );

    let history = env.store.list_agent_install_packages().await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].package_id, package_id);
    assert_eq!(history[0].source, source);
    assert_eq!(history[0].package_sha256, format!("sha256:{digest}"));
    assert_eq!(history[0].version, "0.3.1");
    assert_eq!(history[0].arch, "x86_64-unknown-linux-gnu");
}

#[tokio::test]
async fn install_package_history_is_idempotent_for_the_same_package() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.4.0-aarch64-apple-darwin/wist-agentd",
        b"agentd-0.4.0",
    );
    let (first_source, digest) = set_install_package_source(&env, "idem-first", &pkg).await;
    let package_id = package_id_for_sha256(&digest);

    // 同一份字节从**另一个来源路径**再录一次：内容寻址 id 不变。
    let (second_source, second_digest) = set_install_package_source(&env, "idem-copy", &pkg).await;
    assert_eq!(
        second_digest, digest,
        "identical bytes must yield the same digest"
    );
    assert_eq!(package_id_for_sha256(&second_digest), package_id);
    assert_ne!(second_source, first_source);

    // 历史只有一行；留痕来源被覆盖为最近一次录入的地址。
    let history = env.store.list_agent_install_packages().await.unwrap();
    assert_eq!(history.len(), 1, "same package must stay one history row");
    assert_eq!(history[0].source, second_source);

    // 按条副本只有一份，内容正确。
    let cached = env.config.install_package_history_path(&package_id);
    assert!(cached.is_file(), "per-package copy must exist");
    assert_eq!(std::fs::read(&cached).expect("copy"), pkg);
}

#[tokio::test]
async fn install_package_failed_set_keeps_previous_setting_and_history() {
    let env = TestEnv::new().await;
    let good = tar_gz_with_entry(
        "wist-agentd-0.5.0-x86_64-unknown-linux-gnu/wist-agentd",
        b"agentd-0.5.0",
    );
    let (good_source, good_digest) = set_install_package_source(&env, "good-set", &good).await;

    // 期望摘要不符：整次操作失败，既不留历史行也不覆盖已有单行设置。
    let bad_source = write_source_package(&env, "bad-digest", b"agentd-0.6.0");
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "package_url": bad_source,
            "package_sha256": "c".repeat(64),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let setting = env
        .store
        .get_agent_install_package()
        .await
        .unwrap()
        .expect("setting");
    assert_eq!(
        setting.package_url, good_source,
        "failed set must not overwrite"
    );
    assert_eq!(
        setting.package_sha256.as_deref(),
        Some(format!("sha256:{good_digest}").as_str())
    );

    let history = env.store.list_agent_install_packages().await.unwrap();
    assert_eq!(history.len(), 1, "failed set must not append history");
    assert_eq!(history[0].source, good_source);
}

#[tokio::test]
async fn install_package_history_orders_newest_first() {
    let env = TestEnv::new().await;
    // 直接落库两条（带受控 created_at），验证列表按 created_at DESC 且派生地址逐条成立。
    let older = StoredAgentInstallPackage {
        package_id: "pkg-00000000000000aa".to_string(),
        source: "/packages/older.tar.gz".to_string(),
        package_sha256: "sha256:older".to_string(),
        version: "0.1.0".to_string(),
        arch: "aarch64-apple-darwin".to_string(),
        cached_path: "/state/older".to_string(),
        created_by: "eng".to_string(),
        created_at: "2026-01-01T00:00:00+00:00".to_string(),
    };
    let newer = StoredAgentInstallPackage {
        package_id: "pkg-00000000000000bb".to_string(),
        created_at: "2026-02-01T00:00:00+00:00".to_string(),
        ..older.clone()
    };
    env.store
        .upsert_agent_install_package_by_id(&older)
        .await
        .unwrap();
    env.store
        .upsert_agent_install_package_by_id(&newer)
        .await
        .unwrap();

    let body: serde_json::Value = decode_json_response(
        get_to_router(
            &env.config,
            &env.store_handle,
            "/api/v1/admin/agent/install-packages",
            Some(TEST_ADMIN_API_TOKEN),
        )
        .await,
    )
    .await;
    let packages = body["packages"].as_array().expect("packages array");
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0]["package_id"], "pkg-00000000000000bb");
    assert_eq!(packages[1]["package_id"], "pkg-00000000000000aa");
    for (entry, id) in packages
        .iter()
        .zip(["pkg-00000000000000bb", "pkg-00000000000000aa"])
    {
        assert_eq!(
            entry["agent_package_url"],
            format!("{}/api/v1/agent/packages/{id}", env.config.public_base_url)
        );
    }
}

#[tokio::test]
async fn agent_package_url_by_id_trims_trailing_slash_base() {
    let env = TestEnv::new().await;
    // 基址带/不带尾斜杠都拼出同一条地址（不出现 `//api/...`）。
    assert_eq!(
        env.config
            .agent_package_url_by_id_at("https://gw.example.com/", "pkg-abc"),
        "https://gw.example.com/api/v1/agent/packages/pkg-abc"
    );
    assert_eq!(
        env.config
            .agent_package_url_by_id_at("https://gw.example.com", "pkg-abc"),
        "https://gw.example.com/api/v1/agent/packages/pkg-abc"
    );
}

#[tokio::test]
async fn package_download_by_id_requires_bootstrap_token_or_certificate() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-x86_64-unknown-linux-gnu/wist-agentd",
        b"agentd",
    );
    let (_, digest) = set_install_package_source(&env, "auth-byid", &pkg).await;
    let uri = format!("/api/v1/agent/packages/{}", package_id_for_sha256(&digest));

    // 无凭据（也没证书）→ 401。
    assert_eq!(
        get_agent_package(&env, &uri, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // 带了但不合法的 bootstrap token → 401。
    assert_eq!(
        get_to_router(
            &env.config,
            &env.store_handle,
            &uri,
            Some("not-a-real-token"),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // 客户端证书 → 200。
    let agent_id = enroll_agent_credential(&env).await;
    assert_eq!(
        get_agent_package(&env, &uri, Some(&agent_id))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn package_download_by_id_returns_404_when_cached_copy_is_missing() {
    let env = TestEnv::new().await;
    let pkg = tar_gz_with_entry(
        "wist-agentd-0.1.9-aarch64-apple-darwin/wist-agentd",
        b"upgrade-bytes",
    );
    let (_, digest) = set_install_package_source(&env, "missing-copy", &pkg).await;
    let package_id = package_id_for_sha256(&digest);
    let uri = format!("/api/v1/agent/packages/{package_id}");
    let credential = enroll_agent_credential(&env).await;

    // 行在、副本在 → 200。
    let ok = get_agent_package(&env, &uri, Some(&credential)).await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(body_bytes(ok).await.to_vec(), pkg);

    // 磁盘上的副本被清掉（行还在）：当前实现按「这个包不在了」处理 —— 404、非空体，不 panic。
    std::fs::remove_file(env.config.install_package_history_path(&package_id))
        .expect("remove cached copy");
    let response = get_agent_package(&env, &uri, Some(&credential)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_bytes(response).await;
    assert!(
        !body.is_empty(),
        "must not return an empty body on a missing copy"
    );
}

#[tokio::test]
async fn package_download_by_id_rejects_path_traversal() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    // path 参数只用于**查库**（不是去拼文件路径）：穿越串查不到行 → 404，绝不读到任意文件。
    for uri in [
        "/api/v1/agent/packages/..%2F..%2Fetc%2Fpasswd",
        "/api/v1/agent/packages/pkg-..%2F..%2Fetc%2Fpasswd",
        "/api/v1/agent/packages/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ] {
        let response = get_agent_package(&env, uri, Some(&credential)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "uri {uri}");
    }
}

/// 历史行写入失败时：单行设置已存（请求 500），随后重试同一来源可幂等补齐历史。
///
/// 用一条临时 SQLite 触发器把「历史表的 INSERT」打失败来制造这个中间态 ——
/// 这正是 `set_agent_install_package` 里「先 upsert 单行、再 upsert 历史」的顺序所暴露的分界。
#[tokio::test]
async fn install_package_set_heals_history_after_a_history_write_failure() {
    let env = TestEnv::new().await;
    sqlx::query(
        "CREATE TRIGGER fail_history_insert BEFORE INSERT ON agent_install_package_history \
         BEGIN SELECT RAISE(ABORT, 'injected history failure'); END",
    )
    .execute(env.store.pool())
    .await
    .expect("install failing trigger");

    let pkg = tar_gz_with_entry(
        "wist-agentd-0.7.0-x86_64-unknown-linux-gnu/wist-agentd",
        b"agentd-0.7.0",
    );
    let source = write_source_package(&env, "heal", &pkg);
    let digest = bytes_sha256_hex(&pkg);

    // 第一次：历史写失败 → 500，但单行设置已落库（与实现顺序一致）。
    let failed = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": source }),
    )
    .await;
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let setting = env
        .store
        .get_agent_install_package()
        .await
        .unwrap()
        .expect("setting stored despite failed history write");
    assert_eq!(setting.package_url, source);
    assert!(
        env.store
            .list_agent_install_packages()
            .await
            .unwrap()
            .is_empty(),
        "history write failed, so no history row yet"
    );

    // 去掉故障、重试同一来源：幂等补齐（设置不变，历史补上）。
    sqlx::query("DROP TRIGGER fail_history_insert")
        .execute(env.store.pool())
        .await
        .expect("drop trigger");
    let retried = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": source }),
    )
    .await;
    assert_eq!(retried.status(), StatusCode::OK);
    let history = env.store.list_agent_install_packages().await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].package_id, package_id_for_sha256(&digest));
    assert_eq!(history[0].source, source);
}

#[tokio::test]
async fn install_package_set_rejects_unreachable_url() {
    let env = TestEnv::new().await;
    // https URL 分支的失败：URL 不可请求（无 host）→ 502，且不留历史。
    // （本机路径分支的失败已由 `install_package_set_rejects_unfetchable_source` 覆盖。）
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/install-package",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "package_url": "https://" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        env.store
            .list_agent_install_packages()
            .await
            .unwrap()
            .is_empty(),
        "an unreachable URL must not leave a history row"
    );
}

#[tokio::test]
async fn install_package_history_records_non_tar_package_without_identity() {
    let env = TestEnv::new().await;
    // 裸二进制（非 gzip/tar）仍可录入与分发，只是历史里 version/arch 留空。
    let raw = b"raw-binary-agentd-v0";
    let (_, digest) = set_install_package_source(&env, "raw-package", raw).await;
    let package_id = package_id_for_sha256(&digest);

    let history = env.store.list_agent_install_packages().await.unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].package_id, package_id);
    assert_eq!(history[0].version, "", "non-tar package has no identity");
    assert_eq!(history[0].arch, "");

    // 而且能按 id 取回原字节（不因“没身份”而阻断升级）。
    let credential = enroll_agent_credential(&env).await;
    let response = get_agent_package(
        &env,
        &format!("/api/v1/agent/packages/{package_id}"),
        Some(&credential),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await.to_vec(), raw.to_vec());
}

fn enrollment_request(token: &str) -> EnrollmentRequest {
    EnrollmentRequest {
        api_version: "v1".to_string(),
        kind: "submit_enrollment_request".to_string(),
        token: token.to_string(),
        credential_request: "csr".to_string(),
        certificate_signing_request: certificate_signing_request(),
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

const TEST_CONTENT_CATALOG: &str = r#"
catalog_version = 1
origin = "Gateway"
published_at = "2026-09-22T00:00:00Z"

[[units]]
unit_id = "mac-metrics"
family = "HostMetrics"
capability = "collect_metrics"
platform = "macos"
match = ""
rule_ref = "agent_uplink"
requires_privilege = "none"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"

[[units]]
unit_id = "linux-metrics"
family = "HostMetrics"
capability = "collect_metrics"
platform = "linux"
match = ""
rule_ref = "agent_uplink"
requires_privilege = "root"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"
"#;

const TEST_CONTENT_PACKS: &str = r#"
[[pack]]
pack_id = "macos-base"
platform = "macos"
kind = "Baseline"
families = ["HostMetrics"]
unit_refs = ["mac-metrics"]
catalog_version = 1
status = "active"

[[pack]]
pack_id = "linux-base"
platform = "linux"
kind = "Baseline"
families = ["HostMetrics"]
unit_refs = ["linux-metrics"]
catalog_version = 1
status = "active"
"#;

const TEST_CONTENT_TEMPLATES: &str = r#"
[[template]]
template_id = "macos-daily"
machine_class = "MacDaily"
platform = "macos"
pack_refs = ["macos-base"]
catalog_version = 1
template_version = 1
status = "active"

[[template]]
template_id = "linux-compute"
machine_class = "LinuxCompute"
platform = "linux"
pack_refs = ["linux-base"]
catalog_version = 1
template_version = 1
status = "active"
"#;

struct TestEnv {
    config: AdminConfig,
    store: SqliteStore,
    store_handle: Arc<dyn Store>,
    install_public_key_bytes: Vec<u8>,
    /// 就绪的本地安装包**制品**（测试夹具）。它不再是配置项 —— 运行时网关只认
    /// 管理面录入的那份；这里只给「从本地文件构造来源」这类单测提供一个可读文件。
    package_file: std::path::PathBuf,
    _root: std::path::PathBuf,
}

impl TestEnv {
    async fn new() -> Self {
        Self::new_with_policy_files(None, None, true).await
    }

    /// 不装载内容目录的用例用这个（`/api/v1/admin/content` 回 503）。
    async fn new_without_content() -> Self {
        Self::new_with_policy_files(None, None, false).await
    }

    /// **未录入任何安装包**的环境：用于「来源为空 / 没有可用包 → 503」这类用例
    /// （默认的 `new()` 已录入一份本地制品，让安装链路开箱可用）。
    async fn new_without_package() -> Self {
        Self::new_with_policy_files_and_package(None, None, true, false).await
    }

    /// 需要用途推断的用例用这个：把规则表写进 temp 目录并挂到配置上。
    /// `None` = 模拟「尚未配置规则表」 （事实照常入库，但不产出建议）。
    async fn new_with_purpose_rules(purpose_rules_toml: Option<&str>) -> Self {
        Self::new_with_policy_files(purpose_rules_toml, None, true).await
    }

    /// 需要发现方向策略表的用例用这个：把策略表写进 temp 目录并挂到配置上。
    /// `None` = 模拟「尚未配置策略表」（poll 回 503，agentd 回落内建默认值）。
    async fn new_with_discovery_policies(discovery_policies_toml: Option<&str>) -> Self {
        Self::new_with_policy_files(None, discovery_policies_toml, true).await
    }

    async fn new_with_policy_files(
        purpose_rules_toml: Option<&str>,
        discovery_policies_toml: Option<&str>,
        content: bool,
    ) -> Self {
        Self::new_with_policy_files_and_package(
            purpose_rules_toml,
            discovery_policies_toml,
            content,
            true,
        )
        .await
    }

    async fn new_with_policy_files_and_package(
        purpose_rules_toml: Option<&str>,
        discovery_policies_toml: Option<&str>,
        content: bool,
        record_package: bool,
    ) -> Self {
        let root = std::env::temp_dir().join(format!("wist-gateway-test-{}", unique_suffix()));
        std::fs::create_dir_all(&root).expect("create root");
        let package_file = root.join("wist-agentd");
        std::fs::write(&package_file, "test-agent-package").expect("write package");
        let tls_cert_file = root.join("admin-tls.crt.pem");
        std::fs::write(&tls_cert_file, TEST_TLS_CERT_PEM).expect("write tls cert");
        let store_file = root.join("state").join("admin-store.json");
        let db_path = root.join("state").join("wist-gateway.db");
        let (install_signing_private_key_file, install_public_key_bytes) =
            write_install_signing_key(&root);
        let install_script_signing_public_key_pem =
            load_install_script_public_key_pem(&install_signing_private_key_file)
                .expect("derive install signing public key");
        let (content_catalog_file, content_packs_file, content_templates_file) = if content {
            let content_dir = root.join("content");
            std::fs::create_dir_all(&content_dir).expect("create content dir");
            let catalog = content_dir.join("catalog.toml");
            std::fs::write(&catalog, TEST_CONTENT_CATALOG).expect("write catalog");
            let packs = content_dir.join("packs.toml");
            std::fs::write(&packs, TEST_CONTENT_PACKS).expect("write packs");
            let templates = content_dir.join("templates.toml");
            std::fs::write(&templates, TEST_CONTENT_TEMPLATES).expect("write templates");
            (Some(catalog), Some(packs), Some(templates))
        } else {
            (None, None, None)
        };
        let config = AdminConfig {
            listen_addr: "127.0.0.1:3000".to_string(),
            public_base_url: "https://127.0.0.1:3000".to_string(),
            tls_cert_file,
            tls_key_file: root.join("admin-tls.key.pem"),
            admin_api_token_hash: sha256_hex(TEST_ADMIN_API_TOKEN),
            bootstrap_token_ttl_seconds: 900,
            credential_ttl_seconds: 30 * 24 * 60 * 60,
            store_file,
            database_url: None,
            sqlite_path: db_path.clone(),
            trust_bundle: "internal-ca-stub".to_string(),
            agent_ca_cert_file: Some(shared_test_agent_ca_paths().0),
            agent_ca_key_file: Some(shared_test_agent_ca_paths().1),
            client_cert_ttl_seconds: crate::infra::agent_ca::DEFAULT_CLIENT_CERT_TTL_SECONDS,
            install_script_signing_private_key_file: install_signing_private_key_file,
            install_script_signing_public_key_pem,
            tenant_id: "tenant-default".to_string(),
            environment_id: "env-default".to_string(),
            victoria_metrics_url: "http://127.0.0.1:18429".to_string(),
            purpose_rules_file: purpose_rules_toml.map(|text| {
                let path = root.join("purpose-rules.toml");
                std::fs::write(&path, text).expect("write purpose rules");
                path
            }),
            discovery_policies_file: discovery_policies_toml.map(|text| {
                let path = root.join("aspect-policies.toml");
                std::fs::write(&path, text).expect("write discovery policies");
                path
            }),
            content_catalog_file,
            content_packs_file,
            content_templates_file,
            // 内部接入端点默认关：测试走 `router()`，明文监听由 main.rs 单独起。
            ingest_listen_addr: None,
            // 知识库包默认不验签（要验签的用例自己把公钥填上）。
            knowledge_source_dir: None,
            knowledge_signing_public_key_file: None,
            knowledge_signing_public_key: None,
        };
        // A temp-file DB (not `:memory:`) because the router may use several
        // pooled connections; `SqliteStore` is `Clone` and shares the same pool.
        let store = SqliteStore::connect_path(&db_path)
            .await
            .expect("open store");
        let store_handle: Arc<dyn Store> = Arc::new(store.clone());
        // 安装包只有「管理面录入」一个来源（`agent.package_file` 已删）：默认给测试环境录一份本地
        // 制品，等价于真实部署里先在「安装包」页录入 —— 否则签发安装代码/分发端点会直接 503。
        if record_package {
            let cached = config.install_package_cache_path();
            std::fs::create_dir_all(cached.parent().expect("cache dir")).expect("create cache dir");
            std::fs::copy(&package_file, &cached).expect("seed package cache");
            store_handle
                .upsert_agent_install_package(&StoredAgentInstallPackageAddress {
                    address_id: DEFAULT_INSTALL_PACKAGE_SETTING_ID.to_string(),
                    package_url: package_file.to_string_lossy().to_string(),
                    package_sha256: None,
                    updated_by: "test-ops".to_string(),
                    updated_at: "2026-09-01T00:00:00+00:00".to_string(),
                })
                .await
                .expect("record install package");
        }
        Self {
            config,
            store,
            store_handle,
            install_public_key_bytes,
            package_file,
            _root: root,
        }
    }

    async fn issue_token(&self) -> String {
        let install_code = issue_agent_install_code(&self.config, &self.store_handle)
            .await
            .expect("issue token");
        install_code.bootstrap_enrollment_token
    }
}

async fn test_state() -> ApiState {
    let env = TestEnv::new().await;
    let knowledge = LoadedKnowledge::from_config(&env.config);
    ApiState {
        agent_ca: super::load_agent_ca(&env.config),
        config: env.config.clone(),
        store: Arc::clone(&env.store_handle),
        runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
        rate_limits: Arc::new(Mutex::new(super::rate_limit::RateLimitState::default())),
        knowledge: Arc::new(RwLock::new(Arc::new(knowledge))),
    }
}

async fn issue_token_for_state(state: &ApiState) -> String {
    let install_code = issue_agent_install_code(&state.config, &state.store)
        .await
        .expect("issue state token");
    install_code.bootstrap_enrollment_token
}

fn enrollment_request_json(token: &str) -> String {
    serde_json::to_string(&enrollment_request(token)).expect("serialize request")
}

/// 共享一份**测试用 agent CA**（证书 + 私钥），只在首次调用时生成。
///
/// mTLS 是 agent 唯一的凭据路径，注册/续期都必须有 CA 可签；每个 `TestEnv` 现造一份会白白
/// 重复做密钥生成，所以就共享一份（文件落在系统临时目录，进程退出即随 `TestEnv` 一起被忽略）。
fn shared_test_agent_ca_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    static PATHS: std::sync::OnceLock<(std::path::PathBuf, std::path::PathBuf)> =
        std::sync::OnceLock::new();
    PATHS
        .get_or_init(|| {
            let (_ca, cert_path, key_path) = test_agent_ca();
            (cert_path, key_path)
        })
        .clone()
}

/// 采集内容只读视图：模板组成 + 各平台的面就绪度（“部分可用”的可见面）。
#[tokio::test]
async fn admin_content_view_lists_readiness_and_templates() {
    let env = TestEnv::new().await;
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/content",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = decode_json_response(response).await;
    assert_eq!(view["catalog_version"], 1);
    let templates = view["templates"].as_array().expect("templates array");
    assert!(
        templates
            .iter()
            .any(|template| template["template_id"] == "macos-daily")
    );

    let readiness = view["readiness"].as_array().expect("readiness array");
    let macos = readiness
        .iter()
        .find(|entry| entry["platform"] == "macos")
        .expect("macos readiness");
    let host_metrics = macos["families"]
        .as_array()
        .expect("families array")
        .iter()
        .find(|family| family["family"] == "HostMetrics")
        .expect("HostMetrics readiness");
    assert_eq!(host_metrics["ready"], serde_json::Value::Bool(true));
    assert_eq!(host_metrics["active_units"], 1);
    // 两个轴都要出得来：只报一个会让「采到了但认不出是谁」看着像已就绪。
    assert_eq!(host_metrics["parse_ready"], serde_json::Value::Bool(true));
    assert_eq!(host_metrics["parse_ready_units"], 1);
    assert_eq!(host_metrics["total_units"], 1);
}

#[tokio::test]
async fn admin_content_view_requires_admin_bearer() {
    let env = TestEnv::new().await;
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/content",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_content_view_reports_not_configured() {
    // 端点存在、但这台网关没配内容目录 —— 与“没发布”区分开，回 503。
    let env = TestEnv::new_without_content().await;
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/content",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// 人工判定：写入后落到用途视图里（采集范围变更的前置）。
#[tokio::test]
async fn admin_classify_agent_stores_the_decision() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    assert_eq!(
        post_facts(&env, &fact_report(&["/usr/bin/xcodebuild"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "machine_class": "MacDev", "note": "人看过" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["machine_class"], "MacDev");
    assert_eq!(body["decided_by"], "admin");

    let view = get_purpose_view(&env, "agent-node-a").await;
    assert_eq!(view["classification"]["machine_class"], "MacDev");
    assert_eq!(view["classification"]["note"], "人看过");
}

#[tokio::test]
async fn admin_classify_agent_rejects_a_platform_mismatch() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    // 事实摘要是 macOS 的：Linux 类别必须被拒（分类必须与机器平台一致）。
    post_facts(&env, &fact_report(&["xcodebuild"])).await;

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "machine_class": "LinuxData" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_classify_agent_accepts_a_generic_linux_host() {
    // 通用 Linux 服务器（`LinuxHost`）：平台对得上（linux 事实 + linux 类别）就应当被接受。
    // 没有它，普通 Linux 机器在闭集里就没有可归档的类别，采集链就断在第一步。
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let mut report = fact_report(&["dockerd", "nginx"]);
    report.os = "linux".to_string();
    report.content_digest = digest_of(&report);
    post_facts(&env, &report).await;

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "machine_class": "LinuxHost" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["machine_class"], "LinuxHost");
    assert_eq!(body["decided_by"], "admin");
}

#[tokio::test]
async fn admin_classify_agent_rejects_an_unobserved_agent() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    // 没有事实摘要 → 平台未知 → 拒（不是默认通过）。
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "machine_class": "MacDaily" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_classify_agent_requires_admin_bearer() {
    let env = TestEnv::new().await;
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        None,
        &serde_json::json!({ "machine_class": "MacDev" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_purpose_coverage_counts_classified_and_unclassified() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    post_facts(&env, &fact_report(&["xcodebuild"])).await;
    post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "machine_class": "MacDev" }),
    )
    .await;

    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/purpose-coverage",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = decode_json_response(response).await;
    assert_eq!(view["total_agents"], 1);
    assert_eq!(view["classified_agents"], 1);
    assert_eq!(view["unclassified_agents"], 0);
    assert_eq!(view["by_class"][0]["machine_class"], "MacDev");
    assert_eq!(view["by_class"][0]["agent_count"], 1);
}

async fn get_to_router(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    uri: &str,
    admin_token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = admin_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router(config.clone(), Arc::clone(store))
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("route response")
}

/// agent 取包路由的 GET：第 4 个参数是 **agent_id**，注入「握手期验过的客户端证书身份」。
///
/// 与 [`get_to_router`]（管理面 admin token）分开，理由同 [`post_agent_json_to_router`]：
/// agent 只有一条凭据路径 —— 客户端证书。
async fn get_agent_package(
    env: &TestEnv,
    uri: &str,
    agent_id: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    if let Some(agent_id) = agent_id {
        request.extensions_mut().insert(client_identity(agent_id));
    }
    router(env.config.clone(), Arc::clone(&env.store_handle))
        .oneshot(request)
        .await
        .expect("route response")
}

async fn delete_to_router(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    uri: &str,
    admin_token: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().method("DELETE").uri(uri);
    if let Some(token) = admin_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    router(config.clone(), Arc::clone(store))
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("route response")
}

async fn post_enrollment_to_router(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    body: String,
) -> axum::response::Response {
    router(config.clone(), Arc::clone(store))
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
    store: &Arc<dyn Store>,
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
    router(config.clone(), Arc::clone(store))
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

/// agent 路由的请求：第 4 个参数是 **agent_id**，注入「握手期验过的客户端证书身份」。
///
/// 为什么和管理面那个助手分开：管理面走的是 **admin token**（bearer 头，人的凭据），而 agent
/// **只有一条凭据路径 —— 客户端证书**（§5.2，2026-09-30 起删掉了 bearer 双轨）。两者靠 header
/// 与否已经分不开了，所以在测试里就用两个助手区分，别让「同一个 helper 既能当人又能当机器」。
async fn post_agent_json_to_router<T: serde::Serialize>(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    uri: &str,
    agent_id: Option<&str>,
    body: &T,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(body).expect("serialize body"),
        ))
        .expect("request");
    if let Some(agent_id) = agent_id {
        request.extensions_mut().insert(client_identity(agent_id));
    }
    router(config.clone(), Arc::clone(store))
        .oneshot(request)
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

// ─────────────────────────────────────────────────────────────────────────────
// 工作授权（Control.Agent.Work）：授权 → 拉快照 → 确认 → 暂停/恢复/撤回
// ─────────────────────────────────────────────────────────────────────────────

/// 让 agent-node-a 成为一台「有事实、已判定 MacDaily」的机器（派活的两条前置），
/// 返回它的通讯凭据（Agent 侧拉快照要用）。
async fn a_classified_macos_agent(env: &TestEnv) -> String {
    let credential = enroll_agent_credential(env).await;
    assert_eq!(
        post_facts(env, &fact_report(&["/usr/bin/xcodebuild"]))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/classification",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "machine_class": "MacDaily" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    credential
}

async fn grant_work(env: &TestEnv, body: serde_json::Value) -> Response {
    post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/work",
        Some(TEST_ADMIN_API_TOKEN),
        &body,
    )
    .await
}

async fn post_work_route(env: &TestEnv, path: &str) -> Response {
    post_json_to_router(
        &env.config,
        &env.store_handle,
        path,
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "reason_code": "测试" }),
    )
    .await
}

/// 拒结类的断言用得上正文文本（理由写在那里，不在日志里）。
async fn decode_text_response(response: Response) -> String {
    String::from_utf8(body_bytes(response).await.to_vec()).expect("utf8 body")
}

async fn get_agent_work(env: &TestEnv) -> serde_json::Value {
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/work",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

async fn get_agent_runtime_status(env: &TestEnv) -> serde_json::Value {
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/runtime-status",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

async fn poll_work(env: &TestEnv, credential: Option<&str>) -> Response {
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/work:poll",
        credential,
        &serde_json::json!({
            "api_version": "v1",
            "kind": POLL_WORK_KIND,
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "last_seen_sequence": 0,
            "wait_ms": 0,
            "requested_at": "2026-09-23T00:00:00Z",
        }),
    )
    .await
}

async fn poll_uplink(env: &TestEnv, credential: Option<&str>) -> Response {
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/uplink:poll",
        credential,
        &serde_json::json!({
            "api_version": "v1",
            "kind": POLL_AGENT_UPLINK_KIND,
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "requested_at": "2026-09-26T00:00:00Z",
        }),
    )
    .await
}

/// 带自定义 envelope 的 uplink poll（用于验 `api_version` / `kind` 被拒）。
async fn poll_uplink_with(
    env: &TestEnv,
    credential: Option<&str>,
    api_version: &str,
    kind: &str,
) -> Response {
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/uplink:poll",
        credential,
        &serde_json::json!({
            "api_version": api_version,
            "kind": kind,
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "requested_at": "2026-09-26T00:00:00Z",
        }),
    )
    .await
}

/// envelope 字段与 `work:poll` 同一口径：`api_version` / `kind` 任一不对就是 400。
#[tokio::test]
async fn the_uplink_poll_rejects_a_wrong_envelope() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    for (api_version, kind) in [
        ("v2", POLL_AGENT_UPLINK_KIND),
        ("v1", "poll_something_else"),
    ] {
        let response = poll_uplink_with(&env, Some(&credential), api_version, kind).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "api_version={api_version} kind={kind}"
        );
    }
}

/// 「授权前不上送」的回归护栏：网关签发的初始配置**永远**是待命 ——
/// 无论管理面有没有设上送地址、有没有打开部署级开关。启用只能来自运行期的
/// `uplink:poll`（`（有生效工作 或 开关打开）且 有地址`）。
/// 有人把模板改成 `enabled = true`，就会让新装 Agent 在授权前外发；这条测试要拦住它。
#[tokio::test]
async fn initial_config_never_enables_the_uplink() {
    let env = TestEnv::new().await;
    for switch in [false, true] {
        let uplink = StoredAgentUplinkAddress {
            setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
            host: "10.0.1.9".to_string(),
            port: 9100,
            // 关键：连「开关已打开」也不得写进安装期配置 —— 安装脚本是死数据，
            // 开关是运行期的（改了开关不需要重装）。
            enabled: switch,
            updated_by: "ops".to_string(),
            updated_at: "2026-09-21T00:00:00+00:00".to_string(),
        };
        for with_target in [false, true] {
            let text = agent_initial_config_toml(
                &env.config,
                "install-token-a",
                with_target.then_some(&uplink),
                &env.config.public_base_url,
            );
            // 只信解析结果，不做文本匹配：模板里 `[control_plane] enabled = true` 也会命中
            // 子串/行匹配（`enabled` 这个键名不止一处），而解析后看的是**输出那一段**的真值。
            let parsed: wist_contracts::agent_config::AgentConfig =
                toml::from_str(&text).expect("valid agent config toml");
            assert!(
                !parsed.telemetry.logs.output.enabled,
                "网关签发的初始配置必须待命（switch={switch} with_target={with_target}）:\n{text}"
            );
        }
    }
}

async fn ack_work(
    env: &TestEnv,
    credential: Option<&str>,
    work_id: &str,
    version: i64,
) -> Response {
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/work:ack",
        credential,
        &serde_json::json!({
            "api_version": "v1",
            "kind": ACK_WORK_KIND,
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "work_id": work_id,
            "plan_version": version,
            "acknowledged_at": "2026-09-23T00:00:00Z",
        }),
    )
    .await
}

/// 没有用途判定就没法派活：判定决定取哪份模板，跳过它就是跳过采集范围的审定。
#[tokio::test]
async fn granting_work_without_a_classification_is_rejected() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = decode_text_response(response).await;
    assert!(message.contains("先归档用途判定"), "{message}");
}

/// 常驻工作留空的 spec 由网关**按事实从采集目录展开** —— 这就是「网关决定采什么」。
#[tokio::test]
async fn granting_standing_work_derives_the_spec_from_catalog_and_facts() {
    let env = TestEnv::new().await;
    a_classified_macos_agent(&env).await;

    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: serde_json::Value = decode_json_response(response).await;
    assert_eq!(receipt["work_kind"], "Standing");
    assert_eq!(receipt["status"], "accepted");
    assert_eq!(receipt["plan_version"], 1);
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    let view = get_agent_work(&env).await;
    assert_eq!(view["sequence"], 1);
    // 断言落库/下发的是**物化过**的工作参数：agentd 拿着它就能直接采。
    let spec = WorkSpec::parse(
        view["standing"][0]["spec"]
            .as_str()
            .expect("spec is a string"),
    )
    .expect("spec 是可解析的工作参数");
    assert_eq!(spec.units[0].unit_id, "mac-metrics");
    assert_eq!(spec.units[0].capability, "collect_metrics");
    assert_eq!(spec.units[0].sources[0].kind, "MetricInterval");
    assert_eq!(view["standing"][0]["family"], "HostMetrics");
    assert_eq!(view["standing"][0]["catalog_version"], 1);
    assert_eq!(view["standing"][0]["status"], "active");
    assert!(view["standing"][0]["ack"].is_null());

    // 同一面再授一次 = 改这一份（同一个 work_id，版本 +1），不是多出一份。
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let again: serde_json::Value = decode_json_response(response).await;
    assert_eq!(again["work_id"], work_id.as_str());
    assert_eq!(again["plan_version"], 2);
    let view = get_agent_work(&env).await;
    assert_eq!(view["standing"].as_array().expect("standing").len(), 1);
    assert_eq!(view["sequence"], 2);
}

#[tokio::test]
async fn granting_a_family_that_is_not_ready_is_a_conflict() {
    let env = TestEnv::new().await;
    a_classified_macos_agent(&env).await;
    // 测试目录里只有 HostMetrics 的单元；LoginSession 这个面还没有采集就绪的单元
    // （它的来源是导出器/导出式采集，不是 agentd 现在能执行的东西）。
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "LoginSession" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let message = decode_text_response(response).await;
    assert!(message.contains("collect_not_ready"), "{message}");
}

#[tokio::test]
async fn a_hand_written_spec_must_name_units_of_that_family() {
    let env = TestEnv::new().await;
    a_classified_macos_agent(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({
            "work_kind": "Standing", "family": "HostMetrics", "spec": "not-a-unit"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = decode_text_response(response).await;
    assert!(
        message.contains("not in the collection catalog"),
        "{message}"
    );
}

/// 授权快照是「现在的期望」：幂等、可重复拉，且只有生效中的才下发。
#[tokio::test]
async fn agent_polls_the_work_grant_and_acks_the_plan_version() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;

    let response = grant_work(
        &env,
        serde_json::json!({
            "work_kind": "OneShot", "action": "upgrade", "spec": "0.1.4",
            "deadline_at": "2026-09-24T00:00:00Z", "timeout_seconds": 600
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: serde_json::Value = decode_json_response(response).await;
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    // 拉快照：一次性工作在，状态是 dispatched（还没被确认）。
    let grant: serde_json::Value =
        decode_json_response(poll_work(&env, Some(&credential)).await).await;
    assert_eq!(grant["one_shot"][0]["work_id"], work_id.as_str());
    assert_eq!(grant["one_shot"][0]["status"], "dispatched");

    // 确认：dispatched → accepted，并留下回执。
    let acked: serde_json::Value =
        decode_json_response(ack_work(&env, Some(&credential), &work_id, 1).await).await;
    assert_eq!(acked["status"], "accepted");
    let view = get_agent_work(&env).await;
    assert_eq!(view["one_shot"][0]["status"], "accepted");
    assert_eq!(view["one_shot"][0]["ack"]["plan_version"], 1);
}

#[tokio::test]
async fn acking_a_stale_plan_version_is_reported_in_band_and_not_recorded() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    let receipt: serde_json::Value = decode_json_response(response).await;
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    let acked: serde_json::Value =
        decode_json_response(ack_work(&env, Some(&credential), &work_id, 99).await).await;
    assert_eq!(acked["status"], "stale");

    // 陈旧确认不写回执：否则「Agent 手上是哪一版」会被一个错的数盖掉。
    let view = get_agent_work(&env).await;
    assert!(view["standing"][0]["ack"].is_null());
}

// ─────────────────────────────────────────────────────────────────────────────
// 一次性工作的执行结果（Control.Agent.Work）：上报 → 推进 / 迟到 → 不覆盖
// ─────────────────────────────────────────────────────────────────────────────

/// 派一件一次性升级给已判定的 agent-node-a，返回 work_id。
async fn grant_one_shot_upgrade(env: &TestEnv) -> String {
    let receipt: serde_json::Value = decode_json_response(
        grant_work(
            env,
            serde_json::json!({
                "work_kind": "OneShot", "action": "upgrade", "spec": "0.1.4",
                "deadline_at": "2026-09-24T00:00:00Z", "timeout_seconds": 600
            }),
        )
        .await,
    )
    .await;
    receipt["work_id"].as_str().expect("work id").to_string()
}

/// 派一件带**指定**截止与预算的一次性升级（到期判定要看的是相对时间，不能写死）。
async fn grant_one_shot_upgrade_until(
    env: &TestEnv,
    deadline_at: &str,
    timeout_seconds: i64,
) -> String {
    let receipt: serde_json::Value = decode_json_response(
        grant_work(
            env,
            serde_json::json!({
                "work_kind": "OneShot", "action": "upgrade", "spec": "0.1.4",
                "deadline_at": deadline_at, "timeout_seconds": timeout_seconds
            }),
        )
        .await,
    )
    .await;
    receipt["work_id"].as_str().expect("work id").to_string()
}

async fn submit_work_result_as(
    env: &TestEnv,
    credential: Option<&str>,
    agent_id: &str,
    instance_id: &str,
    work_id: &str,
    status: &str,
    detail: &str,
) -> Response {
    post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/work:result",
        credential,
        &serde_json::json!({
            "api_version": "v1",
            "kind": REPORT_WORK_RESULT_KIND,
            "agent_id": agent_id,
            "instance_id": instance_id,
            "work_id": work_id,
            "status": status,
            "detail": detail,
            "reported_at": "2026-09-23T00:05:00Z",
        }),
    )
    .await
}

async fn submit_work_result(
    env: &TestEnv,
    credential: Option<&str>,
    work_id: &str,
    status: &str,
    detail: &str,
) -> Response {
    submit_work_result_as(
        env,
        credential,
        "agent-node-a",
        "node-a",
        work_id,
        status,
        detail,
    )
    .await
}

/// 结果上报回答「我做得怎么样了」：进度把工作从 dispatched 推到 running，页面上随工作一起可见。
#[tokio::test]
async fn an_agent_reports_the_result_of_a_one_shot_work() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let work_id = grant_one_shot_upgrade(&env).await;

    let accepted: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), &work_id, "running", "正在换件").await,
    )
    .await;
    assert_eq!(accepted["status"], "accepted");

    let view = get_agent_work(&env).await;
    assert_eq!(view["one_shot"][0]["status"], "running");
    assert_eq!(view["one_shot"][0]["result"]["status"], "running");
    assert_eq!(view["one_shot"][0]["result"]["detail"], "正在换件");
}

/// 终态让工作**了结**：离开「在办」清单，进历史留痕。
#[tokio::test]
async fn a_terminal_result_settles_the_work() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let work_id = grant_one_shot_upgrade(&env).await;

    let accepted: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), &work_id, "failed", "摘要不符").await,
    )
    .await;
    assert_eq!(accepted["status"], "accepted");

    let view = get_agent_work(&env).await;
    assert!(view["one_shot"].as_array().expect("one_shot").is_empty());
    assert_eq!(view["settled_one_shot"][0]["work_id"], work_id.as_str());
    assert_eq!(view["settled_one_shot"][0]["status"], "failed");
    // 了结之后**仍看得到原因**：失败说明正是这活做完才最需要看的东西。
    assert_eq!(view["settled_one_shot"][0]["result"]["status"], "failed");
    assert_eq!(view["settled_one_shot"][0]["result"]["detail"], "摘要不符");
}

/// 一件活只能有一个终态：迟到的结果回 `stale`、**不覆盖**状态，但结果记录照存
/// —— 机器上确实发生过那次上报，抹掉它只会让事后无法解释。
#[tokio::test]
async fn a_late_result_is_stale_and_never_overwrites_the_terminal_state() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let work_id = grant_one_shot_upgrade(&env).await;

    let accepted: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), &work_id, "failed", "摘要不符").await,
    )
    .await;
    assert_eq!(accepted["status"], "accepted");

    let late: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), &work_id, "succeeded", "迟到的成功").await,
    )
    .await;
    assert_eq!(late["status"], "stale");

    let stored = env
        .store_handle
        .get_one_shot_work(&work_id)
        .await
        .expect("load work")
        .expect("work exists");
    assert_eq!(stored.work.status, "failed");

    let result = env
        .store_handle
        .get_work_result(&work_id)
        .await
        .expect("load result")
        .expect("result exists");
    assert_eq!(result.status, "succeeded");
    assert_eq!(result.detail, "迟到的成功");
}

/// agent 无权写回**控制面与期限**拥有的状态：那些要么是网关自己写的（dispatched），
/// 要么归运维暂停/撤回或过了截止。
#[tokio::test]
async fn an_agent_cannot_report_a_status_the_control_plane_owns() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let work_id = grant_one_shot_upgrade(&env).await;

    for status in [
        "dispatched",
        "accepted",
        "paused",
        "canceled",
        "expired",
        "timed_out",
        "rolled_back",
    ] {
        let response = submit_work_result(&env, Some(&credential), &work_id, status, "").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{status}");
    }
}

/// 报一件**不属于自己**或**根本不存在**的活回 `unknown`：不报错，也不替它编一个状态。
#[tokio::test]
async fn a_result_for_an_unknown_or_someone_elses_work_is_unknown() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let work_id = grant_one_shot_upgrade(&env).await;

    // 不存在的活。
    let unknown: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), "work-nope", "succeeded", "").await,
    )
    .await;
    assert_eq!(unknown["status"], "unknown");

    // 别人的活：换一台机器（agent-node-b）拿自己的凭据去报 agent-node-a 的活。
    let other = enroll_agent_at_node(&env, "node-b").await;
    let unknown: serde_json::Value = decode_json_response(
        submit_work_result_as(
            &env,
            Some(&other),
            "agent-node-b",
            "node-b",
            &work_id,
            "succeeded",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(unknown["status"], "unknown");

    // 别人的上报没动这台机器的活：还是派下去那一刻的状态。
    let stored = env
        .store_handle
        .get_one_shot_work(&work_id)
        .await
        .expect("load work")
        .expect("work exists");
    assert_eq!(stored.work.status, "dispatched");
}

#[tokio::test]
async fn reporting_a_result_needs_an_agent_credential() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let work_id = grant_one_shot_upgrade(&env).await;

    assert_eq!(
        submit_work_result(&env, None, &work_id, "running", "")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        submit_work_result(&env, Some("forged"), &work_id, "running", "")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // 凭据是真的、但报的是**别人**报的身份：同样拒绝（身份与凭据必须对得上）。
    assert_eq!(
        submit_work_result_as(
            &env,
            Some(&credential),
            "agent-node-b",
            "node-b",
            &work_id,
            "running",
            "",
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 一次性工作的到期判定（后台 tick）：截止 → expired，预算尽 → timed_out
// ─────────────────────────────────────────────────────────────────────────────

/// 过了绝对截止的活由**网关**收敛掉，不等 agent 来报 —— 掉线的 agent 恰恰是这活最可能
/// 卡住的时候，那时没有 poll 可搭。
#[tokio::test]
async fn the_gateway_expires_a_one_shot_work_that_passed_its_deadline() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    // 截止设在 1 小时后、预算给足 24 小时：两条约束里只会碰``截止``那一条。
    let deadline = chrono::Utc::now() + chrono::Duration::hours(1);
    let work_id = grant_one_shot_upgrade_until(&env, &deadline.to_rfc3339(), 86_400).await;

    // 还没到期：一件都不动。（扫描用显式传入的“现在”，测试不靠抢时间。）
    assert_eq!(
        expire_overdue_one_shot_works(
            env.store_handle.as_ref(),
            chrono::Utc::now().timestamp_millis()
        )
        .await
        .expect("sweep"),
        0
    );

    // 越过截止：记 expired，并离开未了结清单与下发的快照。
    let after = (deadline + chrono::Duration::minutes(1)).timestamp_millis();
    assert_eq!(
        expire_overdue_one_shot_works(env.store_handle.as_ref(), after)
            .await
            .expect("sweep"),
        1
    );
    let view = get_agent_work(&env).await;
    assert!(view["one_shot"].as_array().expect("one_shot").is_empty());
    assert_eq!(view["settled_one_shot"][0]["work_id"], work_id.as_str());
    assert_eq!(view["settled_one_shot"][0]["status"], "expired");

    let grant: serde_json::Value =
        decode_json_response(poll_work(&env, Some(&credential)).await).await;
    assert!(grant["one_shot"].as_array().expect("one_shot").is_empty());

    // 到期是终态：再扫一遍不会重复推进。
    assert_eq!(
        expire_overdue_one_shot_works(env.store_handle.as_ref(), after)
            .await
            .expect("sweep"),
        0
    );
}

/// 截止还没到但执行预算尽了 → `timed_out`（两条约束各自独立，不以截止为唯一时钟）。
#[tokio::test]
async fn the_gateway_times_out_a_one_shot_work_that_blew_its_budget() {
    let env = TestEnv::new().await;
    a_classified_macos_agent(&env).await;
    // 截止给足 10 天，预算只有 600s：只有预算这条会先到。
    let deadline = chrono::Utc::now() + chrono::Duration::days(10);
    let work_id = grant_one_shot_upgrade_until(&env, &deadline.to_rfc3339(), 600).await;

    let after = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp_millis();
    assert_eq!(
        expire_overdue_one_shot_works(env.store_handle.as_ref(), after)
            .await
            .expect("sweep"),
        1
    );
    let view = get_agent_work(&env).await;
    assert_eq!(view["settled_one_shot"][0]["work_id"], work_id.as_str());
    assert_eq!(view["settled_one_shot"][0]["status"], "timed_out");
}

#[tokio::test]
async fn the_work_grant_needs_an_agent_credential() {
    let env = TestEnv::new().await;
    assert_eq!(
        poll_work(&env, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        poll_work(&env, Some("forged")).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 数据面上送启用（Control.Agent.Work）：现算 → 无工作 / 无地址即待命
// ─────────────────────────────────────────────────────────────────────────────

/// 直接经 store 设上送地址（比走管理面路由少一层，测试只关心授权计算结果）。
///
/// `enabled` 就是那个部署级开关；绝大多数用例需要的是「只按派工启用」，所以走这个偏门写法。
async fn set_agent_uplink_address(env: &TestEnv, host: &str, port: u16, enabled: bool) {
    env.store
        .upsert_agent_uplink(&StoredAgentUplinkAddress {
            setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
            host: host.to_string(),
            port,
            enabled,
            updated_by: "ops".to_string(),
            updated_at: "2026-09-26T00:00:00+00:00".to_string(),
        })
        .await
        .expect("store uplink address");
}

#[tokio::test]
async fn the_uplink_grant_needs_an_agent_credential() {
    let env = TestEnv::new().await;
    assert_eq!(
        poll_uplink(&env, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        poll_uplink(&env, Some("forged")).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_uplink_poll_rejects_a_wrong_kind() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;
    let response = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/uplink:poll",
        Some(&credential),
        &serde_json::json!({
            "api_version": "v1",
            "kind": "poll_something_else",
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "requested_at": "2026-09-26T00:00:00Z",
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(decode_text_response(response).await, "invalid uplink poll");
}

/// 没有生效工作就必须待命 —— 只要**开关也关着**：
/// 地址只回答「能连到哪」，不回答「该不该连」。
#[tokio::test]
async fn uplink_poll_is_standby_without_any_work() {
    let env = TestEnv::new().await;
    set_agent_uplink_address(&env, "10.0.1.9", 9000, false).await;
    let credential = enroll_agent_credential(&env).await;

    let grant: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!grant.enabled);
    assert_eq!(grant.target(), None);
}

/// 部署级开关打开 → **没有派任何活也启用**（新装机不再需要人工派工才能开始上送）。
///
/// 这是 §4.1 的核心行为：开关回答「这套网关收不收数据」，与「这台干什么活」正交。
#[tokio::test]
async fn the_deployment_switch_opens_the_uplink_without_any_work() {
    let env = TestEnv::new().await;
    set_agent_uplink_address(&env, "10.0.1.9", 9100, true).await;
    let credential = enroll_agent_credential(&env).await;

    let grant: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(grant.enabled, "开关打开时不必先派工");
    assert_eq!(grant.target(), Some(("10.0.1.9", 9100)));
}

/// 开关**不能凭空造出去处**：取不到目标（对外基址里没有主机名）时照样待命。
#[tokio::test]
async fn the_deployment_switch_alone_cannot_open_the_uplink_without_a_target() {
    let mut env = TestEnv::new().await;
    env.config.public_base_url = "https://".to_string();
    // 管理面也没设过 → 两条来源都取不出目标。
    let credential = enroll_agent_credential(&env).await;

    // 先把开关打开（用一份能存下的设置：开关与地址同在一行，所以得带个地址）。
    set_agent_uplink_address(&env, "10.0.1.9", 9100, true).await;
    let with_address: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(with_address.enabled);

    // 删掉那一行 → 只剩派生，而派生不出主机名 → 待命（不猜目标）。
    sqlx::query("DELETE FROM agent_uplink")
        .execute(env.store.pool())
        .await
        .expect("clear uplink setting");
    let standby: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!standby.enabled, "没有目标可指时必须待命（开关也不例外）");
    assert_eq!(standby.target(), None);
}

/// 开关是**并集**不是替代：关掉开关不影响「有工作即启用」这条原有路径。
#[tokio::test]
async fn turning_the_switch_off_still_leaves_worked_agents_enabled() {
    let env = TestEnv::new().await;
    set_agent_uplink_address(&env, "10.0.1.9", 9100, false).await;
    let credential = a_classified_macos_agent(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let grant: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(grant.enabled, "开关关着时，派工这条路径必须原样生效");
}

/// 开关打开时的**粒度代价**，钉住它是刻意的：撤回工作不再能把这一台单独关掉。
///
/// 要单独停只有两条路：关掉部署级开关（会连带停掉其他「没有工作」的机器），或吊销这台 agent。
/// 写下来是因为它会让人意外 —— 但反过来（让撤回压过开关）会使开关对**新装机**完全失效，
/// 而「新装机不必先派工就能开始上送」正是这个开关存在的理由（设计 §4.1）。
#[tokio::test]
async fn with_the_switch_on_revoking_work_no_longer_stops_a_single_agent() {
    let env = TestEnv::new().await;
    set_agent_uplink_address(&env, "10.0.1.9", 9100, true).await;
    let credential = a_classified_macos_agent(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let view = get_agent_work(&env).await;
    let work_id = view["standing"][0]["work_id"].as_str().expect("work id");
    let revoked = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/revoke"),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let grant: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(
        grant.enabled,
        "开关打开时，撤回工作不再单独关掉这一台（刻意的粒度取舍）"
    );

    // 而关掉开关就会回到待命 —— 这才是「停一台」的代价：粒度是部署级。
    let off = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent/uplink",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100, "enabled": false }),
    )
    .await;
    assert_eq!(off.status(), StatusCode::OK);
    let standby: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!standby.enabled, "关掉开关后这台才回到待命");
}

/// 派活即启用 —— **不必先有人在管理面录入上送地址**：没设过时目标派生自部署配置
/// （同一个域名 + 数据面端口），于是「装完 + 派活」就能开始上送。
#[tokio::test]
async fn uplink_poll_derives_the_target_from_the_deployment_config() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let grant: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(grant.enabled);
    assert_eq!(
        grant.target(),
        Some(("127.0.0.1", DEFAULT_AGENT_UPLINK_PORT))
    );
}

/// 派生不出目标（对外基址里取不出主机名）时**仍然不猜**：有工作也只能待命。
#[tokio::test]
async fn uplink_poll_with_work_but_no_target_stays_standby() {
    let mut env = TestEnv::new().await;
    env.config.public_base_url = "https://".to_string();
    let credential = a_classified_macos_agent(&env).await;
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let grant: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!grant.enabled);
    assert_eq!(grant.target(), None);
}

/// 授权层「暂停」≠ 撤回：暂停的工作仍在下发的快照里，所以上送授权**保持启用**。
///
/// 这是刻意的语义（暂停 = 暂不做这项采集，日志/指标停），不是 bug。钉住它，
/// 免得有人顺手把 `effective_standing` 改成只认 `active` —— 那会把「暂停」变成「断连」。
#[tokio::test]
async fn a_paused_standing_work_still_authorizes_uplink() {
    let env = TestEnv::new().await;
    set_agent_uplink_address(&env, "10.0.1.9", 9000, false).await;
    let credential = a_classified_macos_agent(&env).await;
    let receipt: serde_json::Value = decode_json_response(
        grant_work(
            &env,
            serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
        )
        .await,
    )
    .await;
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    let enabled: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(enabled.enabled);

    // 暂停之后仍启用。
    let paused = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/pause"),
    )
    .await;
    assert_eq!(paused.status(), StatusCode::OK);
    let still_enabled: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(
        still_enabled.enabled,
        "暂停不是撤回：授权层暂停不该把上送也关掉"
    );

    // 撤回之后 → 回到待命。
    let revoked = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/revoke"),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let standby: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!standby.enabled, "撤回后必须回到待命");
}

/// 派活即启用、撤回即待命：不需要管理面多一个动作，同一份拉取自动反映。
#[tokio::test]
async fn uplink_poll_enables_on_effective_work_and_target_then_returns_to_standby() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    set_agent_uplink_address(&env, "10.0.1.9", 9100, false).await;

    // 还没派活：待命。
    let standby: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!standby.enabled);
    assert_eq!(standby.target(), None);

    // 派常驻工作：同一份拉取立刻变 enabled，且目标与设置一致。
    let response = grant_work(
        &env,
        serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let enabled: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(enabled.enabled);
    assert_eq!(enabled.target(), Some(("10.0.1.9", 9100)));

    // 撤回：自动变回待命。
    let view = get_agent_work(&env).await;
    let work_id = view["standing"][0]["work_id"].as_str().expect("work id");
    let revoked = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/revoke"),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let standby_again: AgentUplinkGrant =
        decode_json_response(poll_uplink(&env, Some(&credential)).await).await;
    assert!(!standby_again.enabled);
    assert_eq!(standby_again.target(), None);
}

#[tokio::test]
async fn standing_work_pauses_resumes_and_leaves_the_grant_only_when_revoked() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let receipt: serde_json::Value = decode_json_response(
        grant_work(
            &env,
            serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
        )
        .await,
    )
    .await;
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    // 暂停：仍在下发的快照里（期望就是「暂不做」），但状态变了。
    let paused = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/pause"),
    )
    .await;
    assert_eq!(paused.status(), StatusCode::OK);
    let grant: serde_json::Value =
        decode_json_response(poll_work(&env, Some(&credential)).await).await;
    assert_eq!(grant["standing"][0]["status"], "paused");

    // 恢复不重新审定：版本不动。
    let before = get_agent_work(&env).await;
    let version_before = before["standing"][0]["plan_version"].clone();
    let resumed = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/resume"),
    )
    .await;
    assert_eq!(resumed.status(), StatusCode::OK);
    let after = get_agent_work(&env).await;
    assert_eq!(after["standing"][0]["status"], "active");
    assert_eq!(after["standing"][0]["plan_version"], version_before);

    // 撤回：不再下发，但留在 retired_standing 里供审计。
    let revoked = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/revoke"),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::OK);
    let grant: serde_json::Value =
        decode_json_response(poll_work(&env, Some(&credential)).await).await;
    assert!(grant["standing"].as_array().expect("standing").is_empty());
    let view = get_agent_work(&env).await;
    assert_eq!(view["retired_standing"][0]["status"], "revoked");
}

/// 不可中断的一次性工作**拒绝**暂停（而不是「尽力暂停」）。
#[tokio::test]
async fn an_uninterruptible_one_shot_work_refuses_to_pause() {
    let env = TestEnv::new().await;
    a_classified_macos_agent(&env).await;
    let receipt: serde_json::Value = decode_json_response(
        grant_work(
            &env,
            serde_json::json!({
                "work_kind": "OneShot", "action": "upgrade", "spec": "0.1.4",
                "deadline_at": "2026-09-24T00:00:00Z", "timeout_seconds": 600
            }),
        )
        .await,
    )
    .await;
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    let response = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/pause"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let message = decode_text_response(response).await;
    assert!(message.contains("not interruptible"), "{message}");

    // 撤回未了结的一次性工作 = 取消（不是 revoked）：它本来就还没做完。
    let canceled = post_work_route(
        &env,
        &format!("/api/v1/admin/agents/agent-node-a/work/{work_id}/revoke"),
    )
    .await;
    assert_eq!(canceled.status(), StatusCode::OK);
    let view = get_agent_work(&env).await;
    assert_eq!(view["settled_one_shot"][0]["status"], "canceled");
}

#[tokio::test]
async fn work_routes_need_the_admin_token_and_the_right_agent() {
    let env = TestEnv::new().await;
    a_classified_macos_agent(&env).await;
    let receipt: serde_json::Value = decode_json_response(
        grant_work(
            &env,
            serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
        )
        .await,
    )
    .await;
    let work_id = receipt["work_id"].as_str().expect("work id").to_string();

    // 无 token：401。
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/work",
        None,
        &serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 未知 agent：404。
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-nope/work",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "work_kind": "Standing", "family": "HostMetrics" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // work_id 属于别的 agent：不能拿 A 的路径去改 B 的工作。
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        &format!("/api/v1/admin/agents/agent-other/work/{work_id}/revoke"),
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "reason_code": "x" }),
    )
    .await;
    assert!(matches!(response.status(), StatusCode::NOT_FOUND));
}

// ─────────────────────────────────────────────────────────────────────────────
// 灰度发布计划（Control.Rollout）：创建 → 批准（物化第一阶段）→ 推进 → 完成 + 结果回填
// ─────────────────────────────────────────────────────────────────────────────

async fn create_rollout_plan(env: &TestEnv, phases: serde_json::Value) -> serde_json::Value {
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/rollout-plans",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "action": "upgrade",
            "spec": "{\"target_version\":\"0.1.4\",\"package_url\":\"/tmp/pkg\",\"package_sha256\":\"sha256:abc\"}",
            "phases": phases,
            "deadline_at": "2026-10-01T00:00:00Z",
            "timeout_seconds": 600,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    decode_json_response(response).await
}

async fn approve_plan(env: &TestEnv, plan_id: &str) -> serde_json::Value {
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/rollout-plans/approve",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "plan_id": plan_id }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

async fn advance_plan(env: &TestEnv, plan_id: &str) -> serde_json::Value {
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/rollout-plans/advance",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "plan_id": plan_id }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

async fn view_plan(env: &TestEnv, plan_id: &str) -> serde_json::Value {
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        &format!("/api/v1/admin/rollout-plans/{plan_id}"),
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    decode_json_response(response).await
}

#[tokio::test]
async fn rollout_plan_routes_require_admin_bearer() {
    let env = TestEnv::new().await;
    let body = serde_json::json!({
        "action": "upgrade", "spec": "x",
        "phases": [{ "target_ids": ["agent-node-a"], "advance_rule": "manual" }],
        "deadline_at": "2026-10-01T00:00:00Z", "timeout_seconds": 600,
    });
    assert_eq!(
        post_json_to_router(
            &env.config,
            &env.store_handle,
            "/api/v1/admin/rollout-plans",
            None,
            &body,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_to_router(
            &env.config,
            &env.store_handle,
            "/api/v1/admin/rollout-plans",
            None,
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn creating_a_plan_validates_phases_and_returns_draft() {
    let env = TestEnv::new().await;
    enroll_fleet(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([
            { "target_ids": ["agent-node-a"], "advance_rule": "manual" },
            { "target_ids": ["agent-node-b"], "advance_rule": "all_succeeded" },
        ]),
    )
    .await;
    assert_eq!(plan["status"], "draft");
    assert_eq!(plan["current_phase"], 0);
    assert_eq!(plan["action"], "upgrade");
    assert_eq!(plan["phases"].as_array().expect("phases").len(), 2);
    assert_eq!(plan["phases"][0]["phase_index"], 1);
    assert_eq!(plan["phases"][0]["status"], "pending");
    assert_eq!(plan["phases"][1]["phase_index"], 2);

    // 阶段数/闸门/重复 target 都要响，不能当自由文本收下。
    for (bad, reason) in [
        (serde_json::json!([]), "at least one phase"),
        (
            serde_json::json!([{ "target_ids": ["agent-node-a"], "advance_rule": "auto" }]),
            "advance_rule",
        ),
        (
            serde_json::json!([
                { "target_ids": ["agent-node-a"], "advance_rule": "manual" },
                { "target_ids": ["agent-node-a"], "advance_rule": "manual" },
            ]),
            "more than one phase",
        ),
    ] {
        let response = post_json_to_router(
            &env.config,
            &env.store_handle,
            "/api/v1/admin/rollout-plans",
            Some(TEST_ADMIN_API_TOKEN),
            &serde_json::json!({
                "action": "upgrade", "spec": "x", "phases": bad,
                "deadline_at": "2026-10-01T00:00:00Z", "timeout_seconds": 600,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{reason}");
    }
}

#[tokio::test]
async fn creating_a_plan_rejects_unknown_targets() {
    let env = TestEnv::new().await;
    // 只注册 node-a：agent-node-a 存在，agent-ghost 不存在。
    enroll_agent_at_node(&env, "node-a").await;
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/rollout-plans",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "action": "upgrade",
            "spec": "x",
            "phases": [{
                "target_ids": ["agent-node-a", "agent-ghost"],
                "advance_rule": "manual"
            }],
            "deadline_at": "2026-10-01T00:00:00Z",
            "timeout_seconds": 600,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_bytes(response).await;
    let text = String::from_utf8(body.to_vec()).expect("utf8");
    // 报错要能直接指出是哪个 target 不存在（否则运维只能翻代码猜）。
    assert!(text.contains("agent-ghost"), "{text}");
}

#[tokio::test]
async fn approving_a_plan_materializes_the_first_phase_and_advancing_completes_it() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([{ "target_ids": ["agent-node-a"], "advance_rule": "manual" }]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();

    // 批准 → 进入第一阶段：物化出的 upgrade 工作应能被 agent 拉到。
    let approved = approve_plan(&env, &plan_id).await;
    assert_eq!(approved["status"], "rolling");
    assert_eq!(approved["current_phase"], 1);
    assert_eq!(approved["phases"][0]["status"], "rolling");
    let grant: serde_json::Value =
        decode_json_response(poll_work(&env, Some(&credential)).await).await;
    let one_shot = grant["one_shot"].as_array().expect("one_shot");
    assert_eq!(one_shot.len(), 1);
    assert_eq!(one_shot[0]["action"], "upgrade");
    assert_eq!(one_shot[0]["agent_id"], "agent-node-a");

    // 推进（单阶段 = 最后阶段）→ 计划收敛为 completed。
    let completed = advance_plan(&env, &plan_id).await;
    assert_eq!(completed["status"], "completed");
    assert_eq!(completed["phases"][0]["status"], "completed");
}

#[tokio::test]
async fn advancing_materializes_the_next_phase() {
    let env = TestEnv::new().await;
    enroll_fleet(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([
            { "target_ids": ["agent-node-a"], "advance_rule": "manual" },
            { "target_ids": ["agent-node-b"], "advance_rule": "manual" },
        ]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    let advanced = advance_plan(&env, &plan_id).await;
    assert_eq!(advanced["status"], "rolling");
    assert_eq!(advanced["current_phase"], 2);
    assert_eq!(advanced["phases"][0]["status"], "completed");
    assert_eq!(advanced["phases"][1]["status"], "rolling");

    // 第二阶段的 target 也被物化成了工作（与第一阶段同一计划）。
    let work_id = crate::app::rollout::rollout_work_id(&plan_id, "agent-node-b");
    let work = env
        .store_handle
        .get_one_shot_work(&work_id)
        .await
        .expect("load work")
        .expect("work exists");
    assert_eq!(work.work.agent_id, "agent-node-b");
    assert_eq!(work.work.issued_by, format!("rollout:{plan_id}"));
}

#[tokio::test]
async fn a_work_result_fills_the_rollout_entry() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([{ "target_ids": ["agent-node-a"], "advance_rule": "manual" }]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    let detail = view_plan(&env, &plan_id).await;
    let work_id = detail["entries"][0]["work_id"]
        .as_str()
        .expect("work id")
        .to_string();
    assert_eq!(detail["entries"][0]["status"], "dispatched");

    // 结果回填：成功 → 条目 succeeded。
    let accepted: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), &work_id, "succeeded", "").await,
    )
    .await;
    assert_eq!(accepted["status"], "accepted");
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["entries"][0]["status"], "succeeded");

    // 迟到的失败是 stale：不覆盖已落成的终态（与工作自身的终态语义一致）。
    let stale: serde_json::Value = decode_json_response(
        submit_work_result(&env, Some(&credential), &work_id, "failed", "迟到的失败").await,
    )
    .await;
    assert_eq!(stale["status"], "stale");
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["entries"][0]["status"], "succeeded");
}

#[tokio::test]
async fn a_failed_work_result_fills_the_entry_with_the_detail() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([{ "target_ids": ["agent-node-a"], "advance_rule": "manual" }]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;
    let detail = view_plan(&env, &plan_id).await;
    let work_id = detail["entries"][0]["work_id"]
        .as_str()
        .expect("work id")
        .to_string();

    submit_work_result(&env, Some(&credential), &work_id, "failed", "摘要不符").await;
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["entries"][0]["status"], "failed");
    assert_eq!(detail["entries"][0]["detail"], "摘要不符");
}

#[tokio::test]
async fn a_settled_last_phase_finishes_the_plan_without_a_manual_advance() {
    let env = TestEnv::new().await;
    let credential = a_classified_macos_agent(&env).await;
    // 单阶段 + manual：末阶段不需要人工闸门 —— 全部了结就应收敛为 completed，
    // 而不是让计划永远停在 rolling 等人去点那个什么都不启动的「推进」。
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([{ "target_ids": ["agent-node-a"], "advance_rule": "manual" }]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["plan"]["status"], "rolling");
    let work_id = detail["entries"][0]["work_id"]
        .as_str()
        .expect("work id")
        .to_string();

    submit_work_result(&env, Some(&credential), &work_id, "succeeded", "").await;

    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["plan"]["status"], "completed", "{detail}");
    assert_eq!(
        detail["plan"]["phases"][0]["status"], "completed",
        "{detail}"
    );

    // 已收敛之后再点推进会被拒（不是 rolling）—— 证明它是自己收尾的，不是靠人点。
    let advance = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/rollout-plans/advance",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "plan_id": plan_id }),
    )
    .await;
    assert_ne!(advance.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_settled_last_phase_is_reconciled_when_the_plan_is_read() {
    // 模拟「结果回填时网关没接上」留下的 rolling：条目已终态，但计划没收敛。
    let env = TestEnv::new().await;
    let _credential = a_classified_macos_agent(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([{ "target_ids": ["agent-node-a"], "advance_rule": "manual" }]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    // 直接把条目改成终态（绕过结果回填，模拟那条没触发收敛的路径）。
    let mut entries = env
        .store
        .list_rollout_plan_entries(&plan_id)
        .await
        .expect("entries");
    assert_eq!(entries.len(), 1);
    entries[0].status = "succeeded".to_string();
    entries[0].detail = String::new();
    env.store
        .upsert_rollout_plan_entry(&entries[0])
        .await
        .expect("upsert entry");

    let stored = env
        .store
        .get_rollout_plan(&plan_id)
        .await
        .expect("load plan")
        .expect("plan");
    assert_eq!(stored.status, "rolling", "这一步计划确实还挂着");

    // 读详情顺手对账 → 收敛为 completed（幂等）。
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["plan"]["status"], "completed", "{detail}");
    assert_eq!(
        detail["plan"]["phases"][0]["status"], "completed",
        "{detail}"
    );
}

fn entry_work_id(detail: &serde_json::Value, target: &str) -> String {
    detail["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["target_id"] == target)
        .and_then(|entry| entry["work_id"].as_str())
        .expect("work id")
        .to_string()
}

fn entry_status(detail: &serde_json::Value, target: &str) -> String {
    detail["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["target_id"] == target)
        .and_then(|entry| entry["status"].as_str())
        .expect("entry status")
        .to_string()
}

/// 注册 node-a（拿凭据）+ node-b + node-c，让计划里的 target 都真实存在。
/// 返回 agent-node-a 的凭据（提交结果要用）。
async fn enroll_fleet(env: &TestEnv) -> String {
    let credential = enroll_agent_at_node(env, "node-a").await;
    enroll_agent_at_node(env, "node-b").await;
    enroll_agent_at_node(env, "node-c").await;
    credential
}

#[tokio::test]
async fn a_phase_with_all_succeeded_advances_automatically() {
    let env = TestEnv::new().await;
    let credential = enroll_fleet(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([
            { "target_ids": ["agent-node-a"], "advance_rule": "all_succeeded" },
            { "target_ids": ["agent-node-b"], "advance_rule": "manual" },
        ]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    let detail = view_plan(&env, &plan_id).await;
    let work_id = entry_work_id(&detail, "agent-node-a");
    submit_work_result(&env, Some(&credential), &work_id, "succeeded", "").await;

    // 阶段 1 全部成功 → 自动推进到阶段 2。
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["plan"]["status"], "rolling");
    assert_eq!(detail["plan"]["current_phase"], 2);
    assert_eq!(detail["plan"]["phases"][0]["status"], "completed");
    assert_eq!(detail["plan"]["phases"][1]["status"], "rolling");
    assert_eq!(entry_status(&detail, "agent-node-b"), "dispatched");
}

#[tokio::test]
async fn a_manual_phase_never_auto_advances() {
    let env = TestEnv::new().await;
    let credential = enroll_fleet(&env).await;
    let plan = create_rollout_plan(
        &env,
        serde_json::json!([
            { "target_ids": ["agent-node-a"], "advance_rule": "manual" },
            { "target_ids": ["agent-node-b"], "advance_rule": "manual" },
        ]),
    )
    .await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    let detail = view_plan(&env, &plan_id).await;
    let work_id = entry_work_id(&detail, "agent-node-a");
    submit_work_result(&env, Some(&credential), &work_id, "succeeded", "").await;

    // manual：即便阶段 1 全部成功，也不自动推进，要人工 advance 确认。
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["plan"]["current_phase"], 1);
    assert_eq!(detail["plan"]["phases"][0]["status"], "rolling");

    advance_plan(&env, &plan_id).await;
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(detail["plan"]["current_phase"], 2);
}

#[tokio::test]
async fn batch_size_throttles_materialization_and_refills_on_terminal_results() {
    let env = TestEnv::new().await;
    let credential = enroll_fleet(&env).await;
    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/rollout-plans",
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({
            "action": "upgrade",
            "spec": "{\"target_version\":\"0.1.4\"}",
            "phases": [{
                "target_ids": ["agent-node-a", "agent-node-b", "agent-node-c"],
                "advance_rule": "manual"
            }],
            "deadline_at": "2026-10-01T00:00:00Z",
            "timeout_seconds": 600,
            "batch_size": 2,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let plan: serde_json::Value = decode_json_response(response).await;
    let plan_id = plan["plan_id"].as_str().expect("plan id").to_string();
    approve_plan(&env, &plan_id).await;

    // batch_size=2：只物化前 2 台，第 3 台 pending。
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(entry_status(&detail, "agent-node-a"), "dispatched");
    assert_eq!(entry_status(&detail, "agent-node-b"), "dispatched");
    assert_eq!(entry_status(&detail, "agent-node-c"), "pending");

    // 一台成功（释放一个在飞槽位）→ 补物化第 3 台。
    let work_id = entry_work_id(&detail, "agent-node-a");
    submit_work_result(&env, Some(&credential), &work_id, "succeeded", "").await;
    let detail = view_plan(&env, &plan_id).await;
    assert_eq!(entry_status(&detail, "agent-node-c"), "dispatched");
    assert!(entry_work_id(&detail, "agent-node-c").starts_with("work-"));
}

// ── mTLS 客户端证书鉴权（docs/design/agent-identity-mtls.md §5.2 / §5.3 / §5.4）──

/// 造一个「已由 agent CA 验链通过」的客户端身份，等价于 TLS 握手后注入的请求扩展。
fn client_identity(agent_id: &str) -> VerifiedAgentIdentity {
    VerifiedAgentIdentity {
        agent_id: agent_id.to_string(),
        tenant_id: "tenant-default".to_string(),
        environment_id: "env-default".to_string(),
        fingerprint_sha256: "ab".repeat(32),
        not_before: "2026-09-01T00:00:00+00:00".to_string(),
        not_after: "2026-10-08T00:00:00+00:00".to_string(),
    }
}

/// 发一次 agent 请求，并可选地把证书身份塞进请求扩展（模拟握手注入）。
async fn post_agent_with_client_identity(
    env: &TestEnv,
    uri: &str,
    bearer_token: Option<&str>,
    identity: Option<VerifiedAgentIdentity>,
    body: &serde_json::Value,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = bearer_token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let mut request = builder
        .body(Body::from(
            serde_json::to_string(body).expect("serialize body"),
        ))
        .expect("request");
    if let Some(identity) = identity {
        request.extensions_mut().insert(identity);
    }
    super::router_with_state(super::build_state(
        env.config.clone(),
        Arc::clone(&env.store_handle),
    ))
    .oneshot(request)
    .await
    .expect("route response")
}

async fn response_text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8_lossy(&bytes).to_string()
}

fn status_body(agent_id: &str, instance_id: &str) -> serde_json::Value {
    serde_json::json!({
        "agent_id": agent_id,
        "instance_id": instance_id,
        "version": "v0.2.0",
    })
}

/// 核心验收：库丢了（没有该 agent 记录），但 agent 持有效证书 → 首触重建登记，零人工。
#[tokio::test]
async fn mtls_certificate_rebuilds_unknown_agent_on_first_touch() {
    let env = TestEnv::new().await;
    assert!(
        env.store
            .get_agent("agent-rebuilt")
            .await
            .expect("read")
            .is_none()
    );

    let response = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None, // 库丢了，旧 bearer 凭据也没了 —— 只有证书
        Some(client_identity("agent-rebuilt")),
        &status_body("agent-rebuilt", "rebuilt-host"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let rebuilt = env
        .store
        .get_agent("agent-rebuilt")
        .await
        .expect("read")
        .expect("agent must be rebuilt from the certificate");
    assert_eq!(rebuilt.tenant_id, "tenant-default");
    assert_eq!(rebuilt.environment_id, "env-default");
    assert_eq!(rebuilt.credential_status, StoredCredentialStatus::Active);
}

/// §5.3 只保证**第一次**心跳能自愈 —— 除非「证书 + 陈旧 bearer」也按证书放行。
///
/// 重建出来的那行**不可能**知道这台机器的 bearer token（重建只读证书），而双轨期的 agent
/// （§7）照旧会把 token 一起带上。若 bearer 先判，第二次心跳就是「行在、token 对不上」→
/// 401 `credential_mismatch`（对 agentd 是**终态**：停重试、只能人工重注册）。
/// 现象就是「自愈一次就死」。2026-09-30 实撞，所以这条测试锁死：证书已验证且未吊销时，
/// 陈旧的 bearer 不该把请求判死。
#[tokio::test]
async fn a_certificate_authenticated_agent_survives_a_stale_bearer_token() {
    let env = TestEnv::new().await;

    // ① 库是空的：只有证书 → 凭证书首触重建（§5.3）。
    let first = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None, // 库丢了，旧 bearer 凭据也没了 —— 只有证书
        Some(client_identity("agent-rehydrated")),
        &status_body("agent-rehydrated", "host-a"),
    )
    .await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    // ② 同一个 agent 的**下一次**心跳：它照旧带上自己那份 bearer（重建后库里并没这条 token）。
    let second = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        Some("wic_stale_bearer_from_before_the_rebuild"),
        Some(client_identity("agent-rehydrated")),
        &status_body("agent-rehydrated", "host-a"),
    )
    .await;
    let second_status = second.status();
    let second_body = response_text(second).await;
    assert_eq!(
        second_status,
        StatusCode::ACCEPTED,
        "证书已验、未吊销时，陈旧的 bearer 不该把请求判死（正文：{second_body}）"
    );
}

/// 证书身份与请求体不一致必须被拒：不能拿 A 的证书代表 B。
#[tokio::test]
async fn mtls_certificate_identity_mismatch_is_rejected() {
    let env = TestEnv::new().await;
    let response = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None,
        Some(client_identity("agent-other")),
        &status_body("agent-victim", "victim-host"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(response).await;
    assert!(body.contains("certificate_mismatch"), "{body}");
    assert!(
        env.store
            .get_agent("agent-victim")
            .await
            .expect("read")
            .is_none()
    );
}

/// 既没凭据也没证书：拒绝，并给出可辨识的 code。
///
/// `TestEnv` 配了 agent CA（mTLS 开启）⇒ 该带而没带 → `certificate_required`；
/// 没配 CA 的网关则回 `missing_credential`（两者都可自愈/可重装，都不是终态）。
#[tokio::test]
async fn agent_request_without_credential_or_certificate_is_rejected() {
    let env = TestEnv::new().await;
    let response = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None,
        None,
        &status_body("agent-nobody", "nobody-host"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(response).await;
    assert!(body.contains("certificate_required"), "{body}");
}

/// 凭据路径只有一条 —— **客户端证书**：有证书（哪怕不带 Authorization 头）就放行；
/// 只有 bearer token、没有证书一律拒绝（双轨已删）。
#[tokio::test]
async fn certificate_is_the_only_credential_path() {
    let env = TestEnv::new().await;
    let agent_id = enroll_agent_credential(&env).await;

    // 有证书、**不带任何 Authorization 头** → 放行（证明 bearer 已彻底删除）。
    let accepted = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&agent_id),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    // 只有 bearer token、没有证书 → 拒绝（token 不再有任何效力）。
    let rejected = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        Some("wic_some_old_bearer"),
        None,
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

/// **核心回归**：库丢 / 换网关后，agent 凭证书**自愈重建** → **续期也必须能成**。
///
/// 重建登记的 `current_instance_id` 是 NULL（首触时实例本就未知），而网关续期时取的是库里
/// 的 instance_id（投影退化为 `''`）。若续期按「实例必须相等」硬卡，自愈后的第一次续期会
/// 白撞 401 —— 而身份明明已由证书验明。
#[tokio::test]
async fn a_rebuilt_agent_can_renew_its_certificate() {
    let env = TestEnv::new().await;
    let agent_id = "agent-rebuilt";

    // ① 空库 + 只有证书 → 首触重建（§5.3）。
    let first = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(agent_id),
        &status_body(agent_id, "host-a"),
    )
    .await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert!(
        env.store.get_agent(agent_id).await.expect("read").is_some(),
        "凭证书首触应重建登记"
    );

    // ② 续期：带 CSR，必须换回一张新证书（而不是 401）。
    let renewed = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/credentials:renew",
        Some(agent_id),
        &CredentialRenewal::new(
            agent_id.to_string(),
            "host-a".to_string(),
            "csr".to_string(),
            certificate_signing_request(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;
    let status = renewed.status();
    let body = response_text(renewed).await;
    assert_eq!(status, StatusCode::OK, "自愈后的续期不该被拒：{body}");
    assert!(body.contains("BEGIN CERTIFICATE"), "{body}");
}

/// 续期**必须**带 CSR：空 CSR 直接 400（mTLS 是唯一凭据路径，不签 token）。
#[tokio::test]
async fn renewal_without_a_csr_is_rejected() {
    let env = TestEnv::new().await;
    let agent_id = enroll_agent_credential(&env).await;

    let response = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/credentials:renew",
        Some(&agent_id),
        &CredentialRenewal::new(
            "agent-node-a".to_string(),
            "node-a".to_string(),
            "csr".to_string(),
            String::new(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// 证书只证明「CA 签过它」，不证明「它现在还是本网关的成员」：没登记过的 agent 不能取包。
///
/// 取包路径与状态上报不同，**不重建**登记 —— 比照「被删掉的登记不该还能拉包」。
#[tokio::test]
async fn package_download_rejects_a_certificate_for_an_unknown_agent() {
    let env = TestEnv::new().await;
    set_install_package_source(&env, "unknown-agent", b"unknown-agent-bytes").await;

    let rejected =
        get_agent_package(&env, "/api/v1/agent/packages/current", Some("agent-ghost")).await;
    assert_auth_rejected(rejected, "invalid agent client certificate").await;

    // 登记一台后放行（证明拒绝来自「未知」，不是端点坏了）。
    let agent_id = enroll_agent_credential(&env).await;
    let ok = get_agent_package(&env, "/api/v1/agent/packages/current", Some(&agent_id)).await;
    assert_eq!(ok.status(), StatusCode::OK);
}

// ── 注册时拿 CSR 换客户端证书（docs/design/agent-identity-mtls.md §5.1）──

/// 临时 agent CA：返回 `(CA, 证书文件, 私钥文件)`。
///
/// 文件用于给 `AdminConfig` 指路 —— `build_state` 是从配置**装载** CA 的，不是从内存对象。
fn test_agent_ca() -> (
    crate::infra::AgentCa,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Wist Test Agent CA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let key = KeyPair::generate().expect("ca key");
    let certificate = params.self_signed(&key).expect("ca cert");
    let cert_path = write_temp_pem("agent-ca.crt.pem", &certificate.pem());
    let key_path = write_temp_pem("agent-ca.key.pem", &key.serialize_pem());
    let ca =
        crate::infra::AgentCa::from_pem(&certificate.pem(), &key.serialize_pem()).expect("load ca");
    (ca, cert_path, key_path)
}

fn write_temp_pem(suffix: &str, body: &str) -> std::path::PathBuf {
    static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(1);
    let path = std::env::temp_dir().join(format!(
        "wist-gateway-test-{}-{}-{suffix}",
        std::process::id(),
        NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, body).expect("write temp pem");
    path
}

fn certificate_signing_request() -> String {
    let key = rcgen::KeyPair::generate().expect("client key");
    rcgen::CertificateParams::default()
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("csr pem")
}

/// `TestEnv` 里配置的那份测试 agent CA（`load_agent_ca` 从配置装载）。
///
/// mTLS 是 agent 唯一凭据路径，所以注册 / 续期都需要真 CA 可签；测试直接用它。
fn env_agent_ca(env: &TestEnv) -> std::sync::Arc<crate::infra::AgentCa> {
    super::load_agent_ca(&env.config).expect("test agent CA is configured")
}

/// 核心：带 CSR + 配了 agent CA → 回包里带客户端证书，且证书身份就是刚注册的 agent。
#[tokio::test]
async fn enrollment_with_a_csr_issues_a_client_certificate() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let (ca, _, _) = test_agent_ca();
    let request = enrollment_request(&token);

    let result =
        agent_enrollment_result(&env.config, &env.store_handle, Some(&ca), request, "v0.1.0").await;
    assert_eq!(result.status, EnrollmentStatus::Accepted);

    let bundle = result.credential_bundle.clone().expect("credential bundle");
    let certificate_pem = bundle.certificate;

    // 证书里的身份 = 刚注册的 agent，且能被 agent CA 验链接受。
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).expect("pem");
    let identity =
        crate::infra::agent_identity_from_certificate_der(&pem.contents).expect("identity");
    assert_eq!(
        identity.agent_id,
        result.agent_id.clone().expect("agent id")
    );
    assert_eq!(identity.environment_id, "env-default");
}

/// 开了 agent CA 但 CSR 是坏的：**拒绍**，不静默降级。
#[tokio::test]
async fn enrollment_with_a_broken_csr_is_rejected_not_downgraded() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let (ca, _, _) = test_agent_ca();
    let mut request = enrollment_request(&token);
    request.certificate_signing_request = "not a csr".to_string();

    let result =
        agent_enrollment_result(&env.config, &env.store_handle, Some(&ca), request, "v0.1.0").await;
    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert!(
        result
            .reason_code
            .as_deref()
            .unwrap_or_default()
            .contains("invalid_certificate_signing_request"),
        "{:?}",
        result.reason_code
    );
}

/// 没配 agent CA = 这台网关没开 mTLS：注册**直接拒**（没有 bearer 可以回落）。
#[tokio::test]
async fn enrollment_without_an_agent_ca_is_rejected() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;

    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
        None,
        enrollment_request(&token),
        "v0.1.0",
    )
    .await;
    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("agent_certificate_authority_not_configured")
    );
    assert!(result.credential_bundle.is_none());
}

/// 续期也能换发新证书：agent 重新交 CSR，网关用 agent CA 签一张新的（§4.2）。
#[tokio::test]
async fn credential_renewal_with_a_csr_issues_a_new_client_certificate() {
    let mut env = TestEnv::new().await;
    let (_ca, ca_cert_path, ca_key_path) = test_agent_ca();
    env.config.agent_ca_cert_file = Some(ca_cert_path);
    env.config.agent_ca_key_file = Some(ca_key_path);

    let credential = enroll_agent_credential(&env).await;
    let body = serde_json::json!({
        "api_version": "v1",
        "kind": "renew_agent_credential",
        "agent_id": "agent-node-a",
        "instance_id": "node-a",
        "credential_request": "csr",
        "certificate_signing_request": certificate_signing_request(),
        "requested_at": "2026-09-28T00:00:00Z",
    });

    let response = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/credentials:renew",
        Some(&credential),
        &body,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let renewed: CredentialRenewed = decode_json_response(response).await;
    let bundle = renewed.credential_bundle;
    let certificate_pem = bundle.certificate;
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).expect("pem");
    let identity =
        crate::infra::agent_identity_from_certificate_der(&pem.contents).expect("identity");
    assert_eq!(identity.agent_id, "agent-node-a");
}

/// 客户端证书状态：agent 报上来 → 入库 → 管理面运行态里看得到（§5.5），连最近一次续签判定一起。
#[tokio::test]
async fn agent_certificate_status_is_stored_and_exposed_to_admins() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let response = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &serde_json::json!({
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "version": "v0.2.0",
            "certificate_status": {
                "not_after": "2026-11-04T00:00:00+00:00",
                "remaining_seconds": 1_234_567,
                "state": "renew_due",
                "last_renewal": {
                    "outcome": "renewed",
                    "checked_at": "2026-10-08T00:00:00+00:00",
                    "detail": "credential renewed",
                    "not_after": "2026-11-04T00:00:00+00:00",
                },
            },
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let runtime = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/runtime-status",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(runtime.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(runtime).await;
    assert_eq!(body["certificate_status"]["state"], "renew_due");
    assert_eq!(body["certificate_status"]["remaining_seconds"], 1_234_567);
    assert_eq!(
        body["certificate_status"]["not_after"],
        "2026-11-04T00:00:00+00:00"
    );
    // 续签上报（§5.5）：原样透出，网关不重算。
    assert_eq!(
        body["certificate_status"]["last_renewal"]["outcome"],
        "renewed"
    );
    assert_eq!(
        body["certificate_status"]["last_renewal"]["checked_at"],
        "2026-10-08T00:00:00+00:00"
    );

    // 旧版本 agentd（不带 last_renewal）：**保留**上一次的续签记录，必填子字段照常覆盖。
    let legacy = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &serde_json::json!({
            "agent_id": "agent-node-a",
            "instance_id": "node-a",
            "version": "v0.2.0",
            "certificate_status": {
                "not_after": "2026-11-04T00:00:00+00:00",
                "remaining_seconds": 1_200_000,
                "state": "valid",
            },
        }),
    )
    .await;
    assert_eq!(legacy.status(), StatusCode::ACCEPTED);
    let runtime = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/runtime-status",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(runtime).await;
    assert_eq!(body["certificate_status"]["state"], "valid");
    assert_eq!(
        body["certificate_status"]["last_renewal"]["outcome"],
        "renewed"
    );
}

// ── 拒绝名单 / 吊销（docs/design/agent-identity-mtls.md §5.6）──

async fn revoke_agent_via_admin(env: &TestEnv, agent_id: &str, reason: &str) -> Response {
    post_json_to_router(
        &env.config,
        &env.store_handle,
        &format!("/api/v1/admin/agents/{agent_id}/revocation"),
        Some(TEST_ADMIN_API_TOKEN),
        &serde_json::json!({ "reason_code": reason }),
    )
    .await
}

/// 吊销后 **bearer 路径**立即被拒，且 code 明确为 `certificate_revoked`（agentd 据此停重试）。
#[tokio::test]
async fn a_revoked_agent_is_rejected_on_the_bearer_path() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    let ok = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::ACCEPTED);

    let revoked = revoke_agent_via_admin(&env, "agent-node-a", "compromised").await;
    assert_eq!(revoked.status(), StatusCode::OK);

    let blocked = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(blocked).await;
    assert!(body.contains("certificate_revoked"), "{body}");
}

/// 吊销也拦 **证书路径**：同一张此前可用的证书，之后一律 401（续签也过不来）。
#[tokio::test]
async fn a_revoked_agent_is_rejected_on_the_certificate_path() {
    let env = TestEnv::new().await;
    let first = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None,
        Some(client_identity("agent-revoked")),
        &status_body("agent-revoked", "host"),
    )
    .await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    assert_eq!(
        revoke_agent_via_admin(&env, "agent-revoked", "stolen key")
            .await
            .status(),
        StatusCode::OK
    );

    let blocked = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None,
        Some(client_identity("agent-revoked")),
        &status_body("agent-revoked", "host"),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(blocked).await.contains("certificate_revoked"));
}

/// 列表能看到「谁在名单里」；解除后恢复访问（且再解除返回 404）。
#[tokio::test]
async fn lifting_a_revocation_restores_access_and_the_list_shows_entries() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    assert_eq!(
        revoke_agent_via_admin(&env, "agent-node-a", "bye")
            .await
            .status(),
        StatusCode::OK
    );

    let list = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent-revocations",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(list).await;
    assert_eq!(body["revocations"][0]["agent_id"], "agent-node-a");
    assert_eq!(body["revocations"][0]["reason_code"], "bye");

    let lifted = delete_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/revocation",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(lifted.status(), StatusCode::OK);

    let ok = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::ACCEPTED);

    // 已经不在名单里：再解除一次是 404，不把空操作当成功。
    let again = delete_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/revocation",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
}

/// 运行态里能看出「被吊销」——与「离线」区分开（离线会自己回来，被吊销不会）。
#[tokio::test]
async fn runtime_status_exposes_the_revocation_flag() {
    let env = TestEnv::new().await;
    let _credential = enroll_agent_credential(&env).await;

    let before = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/runtime-status",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(before).await;
    assert_eq!(body["revoked"], false);

    assert_eq!(
        revoke_agent_via_admin(&env, "agent-node-a", "retired")
            .await
            .status(),
        StatusCode::OK
    );

    let after = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/runtime-status",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(after).await;
    assert_eq!(body["revoked"], true);
}

/// 吊销一台不存在的 agent：404（不静默建一条无主条目）。
#[tokio::test]
async fn revoking_an_unknown_agent_is_rejected() {
    let env = TestEnv::new().await;
    let response = revoke_agent_via_admin(&env, "agent-ghost", "n/a").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// **续签也过不来**：这是「拒绝名单」相对「停止续签」的核心补口 —— 续签的凭据就是旧证书本身，
/// 若不在这条路径上拦，持钥者能自己续命。走的就是 `authenticate_agent`，与上报同一条闸门。
#[tokio::test]
async fn a_revoked_agent_cannot_renew_its_credential() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    assert_eq!(
        revoke_agent_via_admin(&env, "agent-node-a", "stolen key or retired")
            .await
            .status(),
        StatusCode::OK
    );

    let renew = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/credentials:renew",
        Some(&credential),
        &CredentialRenewal::new(
            "agent-node-a".to_string(),
            "node-a".to_string(),
            "csr".to_string(),
            certificate_signing_request(),
            "2026-07-29T00:00:00Z".to_string(),
        ),
    )
    .await;
    assert_eq!(renew.status(), StatusCode::UNAUTHORIZED);
    assert!(response_text(renew).await.contains("certificate_revoked"));
}

/// 过了 GC 水位就不再拦（即便行还没被清）：那时被吊销的证书早已过期，agent 只能带 token 重装。
/// 用注入 `retain_until` 在过去的条目来验证，不必真的等 30 天。
#[tokio::test]
async fn a_revocation_past_its_retention_no_longer_blocks() {
    let env = TestEnv::new().await;
    let credential = enroll_agent_credential(&env).await;

    env.store
        .revoke_agent(&StoredAgentRevocation {
            entry_id: "denylist-agent-node-a".to_string(),
            agent_id: "agent-node-a".to_string(),
            reason_code: "retired long ago".to_string(),
            denied_by: "admin".to_string(),
            denied_at: "2026-01-01T00:00:00+00:00".to_string(),
            // 已过水位（“很久以前吊销的那张证书”早已过期）。
            retain_until: "2026-02-01T00:00:00+00:00".to_string(),
        })
        .await
        .expect("inject a stale revocation");

    let ok = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::ACCEPTED);
}

/// 重复吊销同一台：列表里仍是一条（`agent_id` 一条），不是两条。
#[tokio::test]
async fn revoking_twice_keeps_one_entry() {
    let env = TestEnv::new().await;
    let _credential = enroll_agent_credential(&env).await;

    for reason in ["first", "again"] {
        assert_eq!(
            revoke_agent_via_admin(&env, "agent-node-a", reason)
                .await
                .status(),
            StatusCode::OK
        );
    }

    let list = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent-revocations",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let body: serde_json::Value = decode_json_response(list).await;
    let entries = body["revocations"].as_array().expect("array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["reason_code"], "again");
}

/// 拒绝名单视图是管理面接口：没有 admin 凭据一律 401。
#[tokio::test]
async fn listing_revocations_requires_admin_credentials() {
    let env = TestEnv::new().await;
    let response = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/agent-revocations",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 不带**任何**凭据的请求不该探出「某 agent 已被吊销」：名单判定在凭据验明之后，
/// 所以这里拿到的是与其它未鉴权请求同口径的 401，而不是 `certificate_revoked`。
#[tokio::test]
async fn an_unauthenticated_probe_cannot_reveal_revocation() {
    let env = TestEnv::new().await;
    let _credential = enroll_agent_credential(&env).await;
    assert_eq!(
        revoke_agent_via_admin(&env, "agent-node-a", "x")
            .await
            .status(),
        StatusCode::OK
    );

    // 既没 bearer 也没证书。
    let probe = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None,
        None,
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(probe.status(), StatusCode::UNAUTHORIZED);
    let body = response_text(probe).await;
    assert!(
        !body.contains("certificate_revoked"),
        "must not leak revocation to an unauthenticated probe: {body}"
    );

    // 凭据没验明（错的 bearer）同样不泄露。
    let wrong = post_agent_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some("wic_not_the_real_token"),
        &status_body("agent-node-a", "node-a"),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(!response_text(wrong).await.contains("certificate_revoked"));
}

/// 被吊销 + 库丢了 + 手持有效证书：**不能**走首触重建把自己登记回来。
///
/// 这是「名单判定放在重建之前」的保护（见 `certificate_authenticate`）：若顺序反了，
/// 被吊销的 agent 一接触网关就把自己重新登记回来，拒绝名单形同虚设。
#[tokio::test]
async fn a_revoked_agent_is_not_rebuilt_from_its_certificate() {
    let env = TestEnv::new().await;
    // 库里有吊销条目，但没有这台 agent 的注册记录（模拟「库丢了」）。
    env.store
        .revoke_agent(&StoredAgentRevocation {
            entry_id: "denylist-agent-rebuilt".to_string(),
            agent_id: "agent-rebuilt".to_string(),
            reason_code: "compromised".to_string(),
            denied_by: "admin".to_string(),
            denied_at: "2026-09-01T00:00:00+00:00".to_string(),
            retain_until: "2027-01-01T00:00:00+00:00".to_string(),
        })
        .await
        .expect("inject revocation");

    let response = post_agent_with_client_identity(
        &env,
        "/api/v1/agent/status",
        None,
        Some(client_identity("agent-rebuilt")),
        &status_body("agent-rebuilt", "rebuilt-host"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response_text(response)
            .await
            .contains("certificate_revoked")
    );
    assert!(
        env.store
            .get_agent("agent-rebuilt")
            .await
            .expect("read")
            .is_none(),
        "a revoked agent must not be rebuilt from its certificate"
    );
}

/// 被吊销的 agent 的数据面记录也不进库（§5.6）：控制面切断之外，数据面同样是「它还能联系网关」的途径。
#[tokio::test]
async fn ingest_endpoint_rejects_a_revoked_agent() {
    let env = TestEnv::new().await;
    enroll_agent_credential(&env).await;
    let record = data_plane_record("agent-node-a", &fact_report(&["/usr/bin/xcodebuild"]));

    // 吊销前正常收下。
    let ok = post_to_ingest_router(&env, &record).await;
    assert_eq!(ok.status(), StatusCode::ACCEPTED);

    assert_eq!(
        revoke_agent_via_admin(&env, "agent-node-a", "cut off")
            .await
            .status(),
        StatusCode::OK
    );

    let rejected = post_to_ingest_router(&env, &record).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(rejected).await;
    assert!(
        body["failures"][0]
            .as_str()
            .unwrap_or_default()
            .contains("is revoked"),
        "{body}"
    );
}

// ── 知识库：从管理面登记的生效包装载 + 运行时整体换版（设计 §6 / §8）──────────────

/// 在环境的状态目录里造一个包目录，并写入五份**真实**策展数据。
fn stage_knowledge_package(env: &TestEnv, package_id: &str) -> std::path::PathBuf {
    stage_knowledge_dir(&env.config.knowledge_package_dir(package_id))
}

/// 把五份**真实**数据铺到任意目录 —— 包目录与 `[knowledge] source_dir`（启动期知识源）共用这一手。
/// 用真数据而不是内联夹具：这里要验的正是“策展数据能被装载器吃下”。
fn stage_knowledge_dir(dir: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(dir).expect("create knowledge dir");
    for name in crate::app::knowledge::PACKAGE_FILES {
        std::fs::copy(crate::test_support::knowledge_file(name), dir.join(name))
            .unwrap_or_else(|err| panic!("copy {name}: {err}"));
    }
    dir.to_path_buf()
}

fn knowledge_package_row(package_id: &str, dir: &std::path::Path) -> StoredKnowledgePackage {
    StoredKnowledgePackage {
        package_id: package_id.to_string(),
        source: dir.display().to_string(),
        package_sha256: format!("sha256:{package_id}"),
        version: "0.1.0".to_string(),
        catalog_version: Some(crate::test_support::real_catalog_version()),
        template_version: Some(1),
        policy_version: Some(1),
        purpose_version: Some(2),
        parser_abi: 1,
        signed_by: String::new(),
        cached_path: dir.display().to_string(),
        created_by: "admin".to_string(),
        created_at: "2026-09-30T00:00:00Z".to_string(),
    }
}

async fn record_and_activate_knowledge(env: &TestEnv, package_id: &str) {
    let dir = stage_knowledge_package(env, package_id);
    env.store_handle
        .upsert_knowledge_package(&knowledge_package_row(package_id, &dir))
        .await
        .expect("record knowledge package");
    env.store_handle
        .activate_knowledge(&KnowledgeActivation {
            package_id,
            reason: "activate",
            requested_by: "admin",
            created_at: "2026-09-30T00:00:00Z",
        })
        .await
        .expect("activate knowledge");
}

/// 生效包优先于配置里的 `*_file`：管理面切过的网关，不再看卡器里写了什么。
#[tokio::test]
async fn knowledge_loads_from_the_active_package_in_the_store() {
    // `TestEnv::new()` 的配置里本来就有内容（夹具那版是 `catalog_version = 1`），用来证明**优先级**。
    let env = TestEnv::new().await;
    record_and_activate_knowledge(&env, "kbp-test").await;

    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("load from store");
    assert_eq!(
        loaded.source,
        KnowledgeSource::Package {
            package_id: "kbp-test".to_string()
        }
    );
    assert_eq!(loaded.generation, 1);
    assert_eq!(
        loaded.content.as_deref().map(|set| set.catalog_version),
        Some(crate::test_support::real_catalog_version())
    );
    assert_eq!(
        loaded
            .purpose_rules
            .as_deref()
            .map(|table| table.purpose_version),
        Some(2)
    );
    assert!(loaded.discovery_policies.is_some());
}

/// **生效包优先于启动期知识源**：管理面切过的包，不能被出厂初始包顶掉。
#[tokio::test]
async fn an_active_package_wins_over_the_startup_source_dir() {
    let mut env = TestEnv::new().await;
    env.config.knowledge_source_dir = Some(stage_knowledge_dir(&env._root.join("initial")));
    record_and_activate_knowledge(&env, "kbp-test").await;

    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("resolve");
    assert_eq!(
        loaded.source,
        KnowledgeSource::Package {
            package_id: "kbp-test".to_string()
        }
    );
}

/// 启动期知识源（出厂初始包）：管理面还没激活过任何包时，用它而不是空载/配置态。
#[tokio::test]
async fn knowledge_uses_the_startup_source_dir_before_any_package_is_activated() {
    let mut env = TestEnv::new().await;
    let dir = stage_knowledge_dir(&env._root.join("initial"));
    env.config.knowledge_source_dir = Some(dir.clone());

    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("resolve");
    assert_eq!(
        loaded.source,
        KnowledgeSource::Dir {
            path: dir.display().to_string()
        }
    );
    assert_eq!(loaded.generation, 0);
    assert!(loaded.content.is_some());
    assert!(loaded.purpose_rules.is_some());
    assert!(loaded.discovery_policies.is_some());
}

/// 从未录入过 = 空载：回落配置文件（今天的部署就是这样跑起来的）。
#[tokio::test]
async fn knowledge_falls_back_to_config_files_before_anything_is_activated() {
    let env = TestEnv::new().await;
    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("load from config");
    assert_eq!(loaded.source, KnowledgeSource::ConfigFiles);
    assert_eq!(loaded.generation, 0);
    assert!(loaded.content.is_some());
}

/// **悬空的生效包不再拒启**（曾经是“生效包损坏 = 拒绝启动”）：
/// 搬了库没搬盘时会撞上，拒启等于把处置入口（管理面）一起关掉 —— 回落并告警就行。
#[tokio::test]
async fn a_dangling_active_package_no_longer_refuses_startup() {
    let env = TestEnv::new().await;
    activate_missing_package(&env, "kbp-broken").await;

    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("a missing package copy must not refuse startup");
    // 没有启动期知识源 → 落到配置文件那份（`TestEnv` 配了内容）。
    assert_eq!(loaded.source, KnowledgeSource::ConfigFiles);
    assert!(loaded.content.is_some());
}

/// 悬空的生效包 + 有启动期知识源 → 用后者（“搬库没搬盘”现场的实际回归）。
#[tokio::test]
async fn a_dangling_active_package_falls_back_to_the_startup_source_dir() {
    let mut env = TestEnv::new().await;
    let dir = stage_knowledge_dir(&env._root.join("initial"));
    env.config.knowledge_source_dir = Some(dir.clone());
    activate_missing_package(&env, "kbp-broken").await;

    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("resolve");
    assert_eq!(
        loaded.source,
        KnowledgeSource::Dir {
            path: dir.display().to_string()
        }
    );
}

/// 启动期知识源配错/没铺 → 告警回落，不当启动失败。
#[tokio::test]
async fn a_broken_startup_source_dir_falls_back_without_refusing() {
    let mut env = TestEnv::new().await;
    env.config.knowledge_source_dir = Some(env._root.join("no-such-knowledge"));

    let loaded = LoadedKnowledge::resolve(&env.config, &env.store_handle)
        .await
        .expect("a broken source_dir must not refuse startup");
    assert_eq!(loaded.source, KnowledgeSource::ConfigFiles);
}

/// 登记并激活一个**目录不存在**的包（模拟“搬库没搬盘”）。
async fn activate_missing_package(env: &TestEnv, package_id: &str) {
    env.store_handle
        .upsert_knowledge_package(&knowledge_package_row(
            package_id,
            &env.config.knowledge_package_dir(package_id),
        ))
        .await
        .expect("record broken package");
    env.store_handle
        .activate_knowledge(&KnowledgeActivation {
            package_id,
            reason: "activate",
            requested_by: "admin",
            created_at: "2026-09-30T00:00:00Z",
        })
        .await
        .expect("activate broken package");
}

/// 换版**不需要重启**：换掉的是 `ApiState` 里那一份 `Arc`，同一个 router 立刻跟着变。
#[tokio::test]
async fn admin_content_view_follows_a_knowledge_swap_without_a_restart() {
    let env = TestEnv::new().await;
    let state = super::build_state(env.config.clone(), Arc::clone(&env.store_handle));

    // 起始：`TestEnv` 配置里的那份内容（`TEST_CONTENT_CATALOG`，catalog_version = 1）。
    let view = get_view(&state, "/api/v1/admin/content").await;
    assert_eq!(view["catalog_version"], 1);

    // 不重启、不换 router：只把装载着的内容整体换成"空载"。
    state.replace_knowledge(Arc::new(LoadedKnowledge::none()));

    let response = get_from_state(&state, "/api/v1/admin/content").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

async fn get_from_state(state: &ApiState, uri: &str) -> axum::response::Response {
    super::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {TEST_ADMIN_API_TOKEN}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response")
}

async fn get_view(state: &ApiState, uri: &str) -> serde_json::Value {
    decode_json_response(get_from_state(state, uri).await).await
}

async fn post_to_state(state: &ApiState, uri: &str, body: &serde_json::Value) -> Response {
    super::router_with_state(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {TEST_ADMIN_API_TOKEN}"))
                .body(Body::from(
                    serde_json::to_string(body).expect("serialize body"),
                ))
                .expect("request"),
        )
        .await
        .expect("route response")
}

// ── 知识库管理面：录入 → 激活 → 换版（设计 §7）────────────────────────────

/// 整条链走一遍：录入不生效 → 激活当场换版（同一个 router，**不重启**）→ 回滚留痕。
///
/// 这是"没有设置入口"那个问题的闭环回归：包从哪来（tar.gz）、怎么录、怎么切、切完谁能看见。
#[tokio::test]
async fn knowledge_endpoints_record_then_activate_without_a_restart() {
    let env = TestEnv::new().await;
    let state = super::build_state(env.config.clone(), Arc::clone(&env.store_handle));
    let root = crate::test_support::unique_temp_dir("wist-knowledge-api");
    let tarball = crate::test_support::knowledge_package_tarball(&root, false);

    // ① 录入：**不生效**（录入 ≠ 生效，设计 I2）
    let response = post_to_state(
        &state,
        "/api/v1/admin/knowledge/packages",
        &serde_json::json!({ "source": tarball.to_string_lossy() }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let recorded: serde_json::Value = decode_json_response(response).await;
    let package_id = recorded["package_id"]
        .as_str()
        .expect("package_id")
        .to_string();
    assert!(package_id.starts_with("kbp-"), "{package_id}");
    assert_eq!(recorded["active"], false);
    assert_eq!(recorded["available"], true);
    assert_eq!(
        recorded["catalog_version"],
        serde_json::json!(crate::test_support::real_catalog_version())
    );

    // 内容照旧：还是测试夹具那一版（catalog_version = 1）。
    let view = get_view(&state, "/api/v1/admin/content").await;
    assert_eq!(view["catalog_version"], 1);

    // ② 激活 → 内容**当场**变，同一个 state 不重启。
    let activate_uri = format!("/api/v1/admin/knowledge/packages/{package_id}/activate");
    let response = post_to_state(
        &state,
        &activate_uri,
        &serde_json::json!({ "requested_by": "tester" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let view = get_view(&state, "/api/v1/admin/content").await;
    assert_eq!(
        view["catalog_version"],
        serde_json::json!(crate::test_support::real_catalog_version())
    );

    // ③ 生效视图：来源是包、世代 1、留痕一条（首次激活 `from_package` 为空）。
    let knowledge = get_view(&state, "/api/v1/admin/knowledge").await;
    assert_eq!(knowledge["source"], "package");
    assert_eq!(knowledge["generation"], 1);
    assert_eq!(knowledge["package_id"], package_id);
    assert_eq!(knowledge["purpose_version"], 2);
    assert_eq!(knowledge["policy_version"], 1);
    assert!(knowledge["hint"].is_null(), "有内容时不该再提示空载");
    assert_eq!(knowledge["activations"][0]["reason"], "activate");
    assert!(knowledge["activations"][0]["from_package"].is_null());

    // ④ 回滚（这里指回同一版）：世代继续前进，**不是**回到 1 —— 否则“哪一代算的”会重复。
    let response = post_to_state(
        &state,
        &activate_uri,
        &serde_json::json!({ "reason": "rollback", "requested_by": "tester" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let knowledge = get_view(&state, "/api/v1/admin/knowledge").await;
    assert_eq!(knowledge["generation"], 2);
    assert_eq!(knowledge["activations"][0]["reason"], "rollback");
    assert_eq!(knowledge["activations"][0]["from_package"], package_id);

    // ⑤ “谁还锁在旧版目录”可读（换版不追改在跑的工作）。
    let locks = get_view(&state, "/api/v1/admin/knowledge/locks").await;
    assert_eq!(
        locks["active_catalog_version"],
        serde_json::json!(crate::test_support::real_catalog_version())
    );
    assert!(locks["locks"].is_array());
}

/// `activate: true` 的一次性路径：录入与切换一趟做完（页面上的「立即激活」）。
///
/// 回归的是这条路径曾经 **100% 失败**：`record_package` 交出的 `LoadedKnowledge.source` 还是默认的
/// `None`，而 `activate_loaded` 只认 `KnowledgeSource::Package`，于是它回 HTTP 500
/// `{"code":"package_store_failed","message":"内部错误：切的是未登记的包"}`。
/// 两条激活路径（本接口 / 单独的 `/activate`）的输入必须同形，所以这里把两种情形都钉住：
/// 全新录入，以及重复录入同一份（幂等 upsert）后的一次性激活。
#[tokio::test]
async fn knowledge_record_can_activate_in_one_shot() {
    let env = TestEnv::new().await;
    let state = super::build_state(env.config.clone(), Arc::clone(&env.store_handle));
    let root = crate::test_support::unique_temp_dir("wist-knowledge-one-shot");
    let tarball = crate::test_support::knowledge_package_tarball(&root, false);
    let body = serde_json::json!({
        "source": tarball.to_string_lossy(),
        "activate": true,
        "requested_by": "tester",
    });

    // ① 录完即生效：同一个请求里既登记又切换。
    let response = post_to_state(&state, "/api/v1/admin/knowledge/packages", &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let recorded: serde_json::Value = decode_json_response(response).await;
    assert_eq!(recorded["active"], true, "一次性路径应当录完就生效");
    let package_id = recorded["package_id"]
        .as_str()
        .expect("package_id")
        .to_string();

    // 内容当场就是包里的那一版（不重启），且留痕是 activate。
    let content = get_view(&state, "/api/v1/admin/content").await;
    assert_eq!(
        content["catalog_version"],
        serde_json::json!(crate::test_support::real_catalog_version())
    );
    let knowledge = get_view(&state, "/api/v1/admin/knowledge").await;
    assert_eq!(knowledge["source"], "package");
    assert_eq!(knowledge["generation"], 1);
    assert_eq!(knowledge["package_id"], package_id);
    assert_eq!(knowledge["activations"][0]["reason"], "activate");

    // ② 同一份再录一次（幂等 upsert）也仍然能一次性激活 —— 这半边盖的是
    //    「记录已存在，但交出去的 `loaded` 仍要带上 `Package` 标签」。
    let response = post_to_state(&state, "/api/v1/admin/knowledge/packages", &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let knowledge = get_view(&state, "/api/v1/admin/knowledge").await;
    assert_eq!(knowledge["generation"], 2);
    assert_eq!(knowledge["activations"][0]["from_package"], package_id);
}

/// 空载：`configured: false` + 一句"怎么办"（I5：空载要看得见，不能是 503 哑谜）。
#[tokio::test]
async fn knowledge_view_reports_the_unconfigured_state_with_a_hint() {
    let env = TestEnv::new_without_content().await;
    let state = super::build_state(env.config.clone(), Arc::clone(&env.store_handle));
    let view = get_view(&state, "/api/v1/admin/knowledge").await;
    assert_eq!(view["configured"], false);
    assert_eq!(view["source"], "none");
    assert_eq!(view["generation"], 0);
    let hint = view["hint"].as_str().expect("空载必须给出怎么办");
    assert!(hint.contains("录入一个包"), "{hint}");
}

/// 错误要能被机器分支：正文带 `code`，状态码按"谁能修"分。
#[tokio::test]
async fn knowledge_endpoints_report_actionable_error_codes() {
    let env = TestEnv::new().await;
    let state = super::build_state(env.config.clone(), Arc::clone(&env.store_handle));

    let response = post_to_state(
        &state,
        "/api/v1/admin/knowledge/packages",
        &serde_json::json!({ "source": "relative/path.tar.gz" }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["code"], "package_source_invalid");

    let response = post_to_state(
        &state,
        "/api/v1/admin/knowledge/packages/kbp-nope/activate",
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["code"], "package_not_found");

    let response = get_from_state(&state, "/api/v1/admin/knowledge/packages/kbp-nope").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// 只抬**整表版本**、分册 id 一字不改 —— 这正是"改了内容却忘了改分册 id"那条路。
/// 断言落库的建议真的重算了（而不是靠时间戳之类的旁证）。
#[tokio::test]
async fn agent_purpose_route_recomputes_when_only_the_purpose_version_changes() {
    let env = TestEnv::new_with_purpose_rules(Some(TEST_PURPOSE_RULES)).await;
    enroll_agent_credential(&env).await;
    post_facts(&env, &fact_report(&["xcodebuild"])).await;
    assert_eq!(
        get_purpose_view(&env, "agent-node-a").await["suggestion"]["rule_set_id"],
        "macos-v1"
    );
    let recorded = env
        .store_handle
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("read suggestion")
        .expect("suggestion");
    assert_eq!(recorded.purpose_version, Some(1));

    // 内容改了、版本抬了、分册 id 没动：旧行必须被判成过期并重算。
    let v2 = TEST_PURPOSE_RULES.replace("purpose_version = 1", "purpose_version = 2");
    assert_ne!(v2, TEST_PURPOSE_RULES, "夹具里应当有 purpose_version");
    let with_v2 = config_with_purpose_rules(&env, &v2);
    let response = get_to_router(
        &with_v2,
        &env.store_handle,
        "/api/v1/admin/agents/agent-node-a/purpose",
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    let view: serde_json::Value = decode_json_response(response).await;
    assert_eq!(view["suggestion"]["rule_set_id"], "macos-v1");

    let recomputed = env
        .store_handle
        .get_purpose_suggestion("agent-node-a")
        .await
        .expect("read suggestion")
        .expect("suggestion");
    assert_eq!(
        recomputed.purpose_version,
        Some(2),
        "版本抬了就必须重算并把新版本记下来"
    );
}

/// 接入请求通道：admin 提交 → gwlinkd 环回拉取 → 回报结果 → 终态；环回限定。
#[tokio::test]
async fn gateway_link_request_flow_round_trips() {
    use std::net::SocketAddr;

    use axum::extract::connect_info::MockConnectInfo;

    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());
    let loopback = || MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000)));

    // 1. admin 提交（含地址 + 券 + CA）。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/gateway/link-request")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {TEST_ADMIN_API_TOKEN}"))
                .body(Body::from(
                    serde_json::json!({
                        "gateway_id": "gw-1",
                        "center_endpoint": "https://center.example",
                        "link_token": "link_abc",
                        "trust_bundle_pem": "-----BEGIN CERTIFICATE-----\n",
                        "requested_by": "admin",
                    })
                    .to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let view: serde_json::Value = decode_json_response(response).await;
    assert_eq!(view["has_request"], true);
    assert_eq!(view["status"], "Pending");
    // admin 视图**不得**回传券与 CA。
    assert!(view.get("link_token").is_none());
    assert!(view.get("trust_bundle_pem").is_none());

    // 2. gwlinkd 环回拉取：拿到券与 CA，Pending → Connecting。
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/gateway/link-request")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(loopback());
    let response = app.clone().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["has_request"], true);
    assert_eq!(body["link_token"], "link_abc");
    assert_eq!(body["status"], "Connecting");

    // 3. 非环回拒绝。
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/gateway/link-request")
        .body(Body::empty())
        .expect("request");
    request
        .extensions_mut()
        .insert(MockConnectInfo(SocketAddr::from(([192, 0, 2, 1], 40_001))));
    let response = app.clone().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 4. 回报 Connected → 清掉明文券。
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/gateway/link-result")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "gateway_id": "gw-1", "status": "Connected", "detail": "" })
                .to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(loopback());
    let response = app.clone().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::OK);

    // 5. 终态：环回不再派发待办，页面看到 Connected。
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/gateway/link-request")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(loopback());
    let response = app.clone().oneshot(request).await.expect("route response");
    let body: serde_json::Value = decode_json_response(response).await;
    assert_eq!(body["has_request"], false);

    let stored = env
        .store_handle
        .get_gateway_link_request()
        .await
        .expect("read")
        .expect("request");
    assert_eq!(stored.status, "Connected");
    assert!(stored.link_token.is_empty(), "消费后必须清掉明文券");

    let view: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/gateway/link-request").await).await;
    assert_eq!(view["status"], "Connected");
}

/// CA 信任锚仅对 **https** 中心必需：http 明文可省；https 无 CA 则 400（不得静默回落）。
#[tokio::test]
async fn link_request_ca_is_required_only_for_https_centers() {
    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());

    async fn post(app: axum::Router, body: serde_json::Value) -> StatusCode {
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/gateway/link-request")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {TEST_ADMIN_API_TOKEN}"))
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("route response")
        .status()
    }

    // http 明文中心 + 无 CA → 接受。
    let http = post(
        app.clone(),
        serde_json::json!({
            "gateway_id": "gw-http",
            "center_endpoint": "http://center.local:3100",
            "link_token": "link_http",
            "trust_bundle_pem": "",
        }),
    )
    .await;
    assert_eq!(http, StatusCode::OK, "http 明文中心无需 CA");

    // https 中心 + 无 CA → 拒绝（不允许静默回落到系统根）。
    let https = post(
        app.clone(),
        serde_json::json!({
            "gateway_id": "gw-https",
            "center_endpoint": "https://center.example",
            "link_token": "link_https",
            "trust_bundle_pem": "",
        }),
    )
    .await;
    assert_eq!(https, StatusCode::BAD_REQUEST, "https 中心必须带 CA");
}

/// 终态 `Failed` 不再派发（避免 gwlinkd 用同一张已消费的券反复重试）。
#[tokio::test]
async fn gateway_link_request_failed_is_not_reserved() {
    use std::net::SocketAddr;

    use axum::extract::connect_info::MockConnectInfo;

    let env = TestEnv::new().await;
    // 直接落一条 Pending 请求（绕过 admin 面，聚焦状态机）。
    env.store_handle
        .upsert_gateway_link_request(&crate::infra::StoredGatewayLinkRequest {
            setting_id: crate::infra::DEFAULT_GATEWAY_LINK_REQUEST_SETTING_ID.to_string(),
            gateway_id: "gw-1".to_string(),
            center_endpoint: "https://center.example".to_string(),
            link_token: "link_abc".to_string(),
            trust_bundle_pem: "CA".to_string(),
            status: "Pending".to_string(),
            result_detail: String::new(),
            requested_by: "admin".to_string(),
            requested_at: "t".to_string(),
            updated_at: "t".to_string(),
        })
        .await
        .expect("seed");

    let app = router(env.config.clone(), env.store_handle.clone());
    let loopback = || MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000)));

    // gwlinkd 拉一次 → Connecting。
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/gateway/link-request")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(loopback());
    let body: serde_json::Value =
        decode_json_response(app.clone().oneshot(request).await.expect("route response")).await;
    assert_eq!(body["has_request"], true);

    // 回报 Failed → 变终态。
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/gateway/link-result")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "gateway_id": "gw-1", "status": "Failed", "detail": "bad token" })
                .to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(loopback());
    let response = app.clone().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::OK);

    // 再拉：不再派发。
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/gateway/link-request")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(loopback());
    let body: serde_json::Value =
        decode_json_response(app.clone().oneshot(request).await.expect("route response")).await;
    assert_eq!(body["has_request"], false, "Failed 不应再被派发");
}

/// gwlinkd 状态通道：环回心跳 → 网关存储 → admin 视图（含 `age_seconds` / `stale`）；环回限定。
#[tokio::test]
async fn gateway_linkd_status_heartbeat_round_trips() {
    use std::net::SocketAddr;

    use axum::extract::connect_info::MockConnectInfo;

    let env = TestEnv::new().await;
    let app = router(env.config.clone(), env.store_handle.clone());
    let loopback = || MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000)));

    // 1. 从未上报 → has_status=false（页面显示「未检测到 gwlinkd」）：空态也是全字段契约。
    let view: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/gateway/linkd-status").await).await;
    assert_eq!(view["has_status"], false);
    assert_eq!(view["stale"], false, "从未有过 ≠ 失联");
    assert_eq!(view["age_seconds"], 0);

    // 2. gwlinkd 环回心跳（无密钥载荷）。
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/gateway/linkd-status")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "gateway_id": "GX01",
                "instance_id": "GX01/inst-1",
                "version": "0.4.0",
                "center_endpoint": "https://center.example",
                "state": "Linked",
                "credential_expires_at": "2026-12-01T00:00:00Z",
                "last_center_report_at": "2026-10-05T00:00:00Z",
                "reported_at": "2026-10-05T00:00:00Z",
            })
            .to_string(),
        ))
        .expect("request");
    request.extensions_mut().insert(loopback());
    let response = app.clone().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::OK);
    let accepted: serde_json::Value = decode_json_response(response).await;
    assert_eq!(accepted["gateway_id"], "GX01");
    assert!(
        accepted["received_at"].is_string(),
        "受理回执要给网关收讫时刻"
    );

    // 3. admin 读回：新鲜 → stale=false（失联判定走**网关时钟**的 received_at）。
    let view: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/gateway/linkd-status").await).await;
    assert_eq!(view["has_status"], true);
    assert_eq!(view["state"], "Linked");
    assert_eq!(view["gateway_id"], "GX01");
    assert_eq!(view["center_endpoint"], "https://center.example");
    assert_eq!(view["stale"], false, "刚心跳不算失联");
    let age = view["age_seconds"].as_i64().expect("i64");
    assert!((0..=5).contains(&age), "刚写进去，age 应在 [0,5]：{age}");

    // 3b. 心跳轨迹（页面「最近 1 小时稳不稳」）：刚那一拍应出现在窗口内。
    let history: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/gateway/linkd-status/history").await)
            .await;
    assert_eq!(history["window_seconds"], 3600, "缺省窗口 = 1h：{history}");
    let samples = history["samples"].as_array().expect("samples");
    assert_eq!(samples.len(), 1, "刚报了一拍，轨迹应有一条：{history}");
    assert_eq!(samples[0]["state"], "Linked");
    assert!(samples[0]["at"].is_i64(), "时刻是 unix 秒：{history}");

    // 3c. 窗口可调且被夹到 [60, 保留窗口]。
    let tiny: serde_json::Value = decode_json_response(
        get_admin(
            &env,
            "/api/v1/admin/gateway/linkd-status/history?window_seconds=1",
        )
        .await,
    )
    .await;
    assert_eq!(tiny["window_seconds"], 60, "过小的窗口应夹到 60s：{tiny}");

    // 4. 非环回拒绝（与 link-request / self-state 同口径）。
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/gateway/linkd-status")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "gateway_id": "GX01" }).to_string(),
        ))
        .expect("request");
    request
        .extensions_mut()
        .insert(MockConnectInfo(SocketAddr::from(([192, 0, 2, 1], 40_001))));
    let response = app.clone().oneshot(request).await.expect("route response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 5. admin 面要 bearer：没带 token → 401（状态不可匿名读）。
    let unauthorized = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/gateway/linkd-status",
        None,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 6. **错误**的 bearer 同样 401（不是只认「有没有带」）。
    let wrong = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/gateway/linkd-status",
        Some("adm_wrong_token"),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    // 7. 轨迹口同样要 bearer（没带 → 401）。
    let unauthorized_history = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/gateway/linkd-status/history",
        None,
    )
    .await;
    assert_eq!(unauthorized_history.status(), StatusCode::UNAUTHORIZED);
}

/// 网关**自身**状态读口（页面）：admin bearer → 200 且全键契约；无 token → 401；
/// 环回自述面（`/api/v1/gateway/self-state`）非环回仍 403（不被 admin 读口放宽）。
#[tokio::test]
async fn admin_reads_gateway_self_state_but_loopback_face_stays_private() {
    let env = TestEnv::new().await;

    let view: serde_json::Value = decode_json_response(
        get_admin(&env, "/api/v1/admin/gateway/self-state?gateway_id=gw-1").await,
    )
    .await;
    for key in [
        "gateway_id",
        "version",
        "collected_at",
        "store_healthy",
        "agent_count",
        "uplink_enabled",
        "last_error",
    ] {
        assert!(view.get(key).is_some(), "缺 {key}: {view}");
    }
    assert_eq!(view["gateway_id"], "gw-1", "原样回显调用方给的 id");
    assert_eq!(view["store_healthy"], true, "空库应可查（健康）");

    // 无 token → 401。
    let unauthorized = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/gateway/self-state",
        None,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 环回面：不带环回连接信息的请求仍被拒（admin 读口不影响它的私密性）。
    let response = router(env.config.clone(), env.store_handle.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/gateway/self-state?gateway_id=gw-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// 网关自述状态**轨迹**读口：采样落表后能读回（值原样，量不出的是 `null`）；窗口被夹；无 token → 401。
#[tokio::test]
async fn admin_reads_gateway_self_state_history() {
    let env = TestEnv::new().await;
    let now = chrono::Utc::now().timestamp();
    env.store_handle
        .append_gateway_self_state_sample(
            &crate::infra::StoredGatewaySelfStateSample {
                at_seconds: now,
                cpu_percent: Some(1.5),
                memory_bytes: Some(64 * 1024 * 1024),
                load_1m: Some(0.42),
                online_agents: 3,
                disk_usage_percent: None,
            },
            // 写入时裁旧：保留窗口（2h），刚采的这条不会把自己裁掉。
            now - 7200,
        )
        .await
        .expect("append sample");

    let view: serde_json::Value =
        decode_json_response(get_admin(&env, "/api/v1/admin/gateway/self-state/history").await)
            .await;
    assert_eq!(view["window_seconds"], 3600, "缺省窗口 = 1h：{view}");
    let samples = view["samples"].as_array().expect("samples");
    assert_eq!(samples.len(), 1, "刚采的一拍应读回：{view}");
    assert_eq!(samples[0]["cpu_percent"], 1.5);
    assert_eq!(samples[0]["online_agents"], 3);
    assert!(
        samples[0]["disk_usage_percent"].is_null(),
        "量不出应是 null（不是缺键、也不是 0）：{view}"
    );
    assert!(samples[0]["at"].is_i64(), "时刻是 unix 秒：{view}");

    // 窗口可调且被夹到 [60s, 2h]。
    let tiny: serde_json::Value = decode_json_response(
        get_admin(
            &env,
            "/api/v1/admin/gateway/self-state/history?window_seconds=1",
        )
        .await,
    )
    .await;
    assert_eq!(tiny["window_seconds"], 60, "过小的窗口应夹到 60s：{tiny}");

    // admin 面要 bearer（状态轨迹不可匿名读）。
    let unauthorized = get_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/admin/gateway/self-state/history",
        None,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
}
