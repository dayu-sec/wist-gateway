use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
use wist_contracts::enrollment::{
    AgentIdentityStatus, CredentialRenewal, CredentialRenewed, EnrollmentEnvelope,
    EnrollmentRequest, EnrollmentStatus,
};

use crate::infra::{
    AdminConfig, DEFAULT_AGENT_UPLINK_SETTING_ID, SqliteStore, Store, StoredAgentUplinkAddress,
    StoredCredentialStatus, StoredEnrollmentTokenStatus, bytes_sha256_hex,
    load_install_script_public_key_pem, sha256_hex,
};
use wist_contracts::action_result::{ActionResult, FinalStatus};
use wist_contracts::fact_summary::FactContent;
use wist_contracts::gateway::{
    AgentStatusReport, AgentWorkState, AgentWorkStateChange, DiscoveryPoliciesReturned,
    POLL_DISCOVERY_POLICIES_KIND, PollDiscoveryPolicies, ReportActionResult,
    ReportAgentFactSummary, ResultAttestation,
};
use wist_contracts::work::{ACK_WORK_KIND, POLL_WORK_KIND, REPORT_WORK_RESULT_KIND, WorkSpec};
use wist_control::PollControlCommands;
use wist_control::types::DateTime;

use super::{
    AdminRuntimeState, ApiState,
    enrollment::{
        agent_enrollment_result, agent_enrollment_result_with_token_issuer, enroll_agent,
    },
    install::{
        agent_initial_config_toml, agent_install_code, issue_agent_install_code, token_hash,
        validate_bootstrap_token_for_config,
    },
    install_package::AgentPackageSource,
    overview::{RecentOnlineRegisteredAgentSource, agent_overview},
    router,
    work_expiry::expire_overdue_one_shot_works,
};

const TEST_ADMIN_API_TOKEN: &str = "test-admin-token";

/// 测试用的内置安装包来源（未在管理面设置来源地址时的生效值）。
fn builtin_package(env: &TestEnv) -> AgentPackageSource {
    AgentPackageSource::from_local_file(&env.config, env.config.agent_package_file.clone())
        .expect("builtin package source")
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

/// 用内置安装包签发一份安装代码：下面几个测试关心的是安装命令/引导包的形态。
async fn builtin_install_code(env: &TestEnv) -> wist_control::types::AgentInstallCode {
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(900);
    agent_install_code(&env.config, "token-a", expires_at, &builtin_package(env))
        .expect("install code")
}

#[tokio::test]
async fn install_code_bundle_targets_gateway_package() {
    let env = TestEnv::new().await;
    let install_code = builtin_install_code(&env).await;

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
    let install_code = builtin_install_code(&env).await;
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
    let install_code = builtin_install_code(&env).await;
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
    let install_code = builtin_install_code(&env).await;

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
    super::install::install_script(&env.config, "x86", &builtin_package(env))
}

#[tokio::test]
async fn install_script_verifies_package_digest() {
    let env = TestEnv::new().await;
    let script = rendered_install_script(&env);
    let sha256 = builtin_package(&env).sha256;

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
    // 网关内置包则是裸二进制；两种形态都要装到 $BIN_DIR。
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
async fn builtin_package_requires_readable_file() {
    let env = TestEnv::new().await;
    let package_path = env.config.agent_package_file.clone();
    std::fs::remove_file(&package_path).expect("remove package");

    // 解析内置来源需要读制品算摘要；制品不在就必须显式失败，
    // 而不是把空摘要发下去（那会让安装端跳过校验）。
    let err = AgentPackageSource::from_local_file(&env.config, package_path)
        .expect_err("unreadable package");

    assert!(!err.is_empty());
}

#[tokio::test]
async fn install_script_signature_matches_script_body() {
    let env = TestEnv::new().await;
    let script = super::install::install_script(&env.config, "x86", &builtin_package(&env));
    let signature =
        super::install::install_script_signature(&env.config, "x86", &builtin_package(&env))
            .expect("sign script");

    signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(script.as_bytes(), &signature)
        .expect("signature verifies");
}

#[tokio::test]
async fn install_script_signature_rejects_modified_body() {
    let env = TestEnv::new().await;
    let signature =
        super::install::install_script_signature(&env.config, "x86", &builtin_package(&env))
            .expect("sign script");

    let err = signature::UnparsedPublicKey::new(&signature::ED25519, &env.install_public_key_bytes)
        .verify(b"tampered install script", &signature)
        .expect_err("tampered script rejected");

    assert_eq!(format!("{err:?}"), "Unspecified");
}

#[tokio::test]
async fn initial_config_matches_agent_config_contract() {
    let env = TestEnv::new().await;
    let text = agent_initial_config_toml(&env.config, "install-token-a", None);
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

#[tokio::test]
async fn initial_config_without_uplink_keeps_local_only_output() {
    let env = TestEnv::new().await;
    let text = agent_initial_config_toml(&env.config, "install-token-a", None);

    // 待命语义：kind 恒为 file，不下发任何采集配置。
    // file sink 没有 inputs 时什么都不写，而“静”本身就是要求。
    assert!(text.contains("kind = \"file\""));
    assert!(!text.contains("file_inputs_file"));
    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
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
        updated_by: "ops".to_string(),
        updated_at: "2026-09-21T00:00:00+00:00".to_string(),
    };
    let text = agent_initial_config_toml(&env.config, "install-token-a", Some(&uplink));

    let parsed: wist_contracts::agent_config::AgentConfig =
        toml::from_str(&text).expect("valid agent config toml");
    // 上送目标记录下来...
    assert_eq!(parsed.telemetry.logs.output.tcp.addr, "10.0.1.9");
    assert_eq!(parsed.telemetry.logs.output.tcp.port, 9100);
    assert_eq!(parsed.telemetry.logs.output.tcp.framing, "line");
    // ...但 kind 仍是 file：设了地址也不等于开始干活（指标也不会被上送）。
    // 靠 kind 而不是“没有任务”来保证静 —— 指标帧走的是同一个 sink。
    assert_eq!(parsed.telemetry.logs.output.kind, "file");
    assert!(parsed.telemetry.logs.file_inputs.is_empty());
    assert!(parsed.telemetry.logs.file_inputs_file.is_none());
}

#[tokio::test]
async fn initial_config_derives_instance_name_from_token() {
    let env = TestEnv::new().await;
    let first = agent_initial_config_toml(&env.config, "install-token-a", None);
    let second = agent_initial_config_toml(&env.config, "install-token-b", None);

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

    let text = agent_initial_config_toml(&env.config, "install-token-a", None);
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
    assert_eq!(credential.auth_scheme.as_deref(), Some("bearer"));
    assert!(
        credential
            .bearer_token
            .as_deref()
            .is_some_and(|token| token.starts_with("wic_"))
    );
    assert!(credential.not_after.is_some());
}

#[tokio::test]
async fn enrollment_rejects_invalid_token_without_identity() {
    let env = TestEnv::new().await;
    let result = agent_enrollment_result(
        &env.config,
        &env.store_handle,
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
    let result = agent_enrollment_result_with_token_issuer(
        &env.config,
        &env.store_handle,
        enrollment_request("bad-token"),
        "v0.1.0",
        |_| panic!("credential generation must not run for an invalid token"),
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
    let result = agent_enrollment_result_with_token_issuer(
        &env.config,
        &env.store_handle,
        enrollment_request(&token),
        "v0.1.0",
        |_| Err("injected_random_failure".to_string()),
    )
    .await;

    assert_eq!(result.status, EnrollmentStatus::Rejected);
    assert_eq!(
        result.reason_code.as_deref(),
        Some("injected_random_failure")
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
        enrollment_request(&token),
        "v0.1.0",
    )
    .await;
    let second = agent_enrollment_result(
        &env.config,
        &env.store_handle,
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
        enrollment_request(&first_token),
        "v0.1.0",
    )
    .await;
    let duplicate = agent_enrollment_result(
        &env.config,
        &env.store_handle,
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

    let result = agent_enrollment_result(&env.config, &env.store_handle, request, "v0.1.0").await;

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
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let accepted = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);

    let rejected = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        None,
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_status_route_persists_reported_metrics() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let status = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: Some(12_345_678),
            cpu_percent: Some(7.5),
            cpu_cores: Some(4),
            admin_latency_ms: Some(42),
            discovery_policy_version: None,
            work_state_changes: None,
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
    credential: &str,
    cpu_percent: Option<f64>,
    cpu_cores: Option<u32>,
) -> Response {
    post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent,
            cpu_cores,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
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
    decode_enrollment_response(enrollment)
        .await
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token")
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
/// 这是“用夹具数据验证计算”的那份证据；规则表文件缺失（如单独拷本仓）时跳过。
#[tokio::test]
async fn fact_summary_ingest_infers_with_the_checked_in_rule_table() {
    // 相对本 crate 根：../../wist-design/jumo/model/content/purpose-rules.toml
    let path = std::path::Path::new("../../wist-design/jumo/model/content/purpose-rules.toml");
    let Ok(rules) = std::fs::read_to_string(path) else {
        return;
    };

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
    post_json_to_router(
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
    decode_enrollment_response(response)
        .await
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token")
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
        })
        .expect("serialize status"),
        None => serde_json::json!({
            "agent_id": agent_id,
            "instance_id": instance_id,
            "version": "v0.1.0",
        }),
    };
    post_json_to_router(
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
/// 这是“用夹具数据验证契约”的那份证据；策略表文件缺失（如单独拷本仓）时跳过。
#[tokio::test]
async fn discovery_policies_poll_serves_the_checked_in_table() {
    // 相对本 crate 根：../../wist-design/jumo/model/content/aspect-policies.toml
    let path = std::path::Path::new("../../wist-design/jumo/model/content/aspect-policies.toml");
    let Ok(policies) = std::fs::read_to_string(path) else {
        return;
    };
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
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let status = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
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
async fn agent_status_route_rejects_expired_bearer_credential() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");
    let stored = env
        .store
        .get_agent("agent-node-a")
        .await
        .expect("store read")
        .expect("stored agent");
    // Test-only seam: the public Store API does not expose arbitrary credential
    // mutation, so the current credential's expiry is forced directly via SQL.
    sqlx::query("UPDATE agent_credentials SET expires_at = ?1 WHERE credential_id = ?2")
        .bind("2026-07-01T00:00:00Z")
        .bind(&stored.credential_id)
        .execute(env.store.pool())
        .await
        .expect("expire credential");

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&credential),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_renewal_replaces_previous_credential() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    let returned = decode_enrollment_response(enrollment).await;
    let old_bearer = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let renewed = post_json_to_router(
        &env.config,
        &env.store_handle,
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
        &env.store_handle,
        "/api/v1/agent/status",
        Some(&old_bearer),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(old_rejected.status(), StatusCode::UNAUTHORIZED);

    let new_accepted = post_json_to_router(
        &env.config,
        &env.store_handle,
        "/api/v1/agent/status",
        Some(new_bearer),
        &AgentStatusReport {
            agent_id: "agent-node-a".to_string(),
            instance_id: "node-a".to_string(),
            version: "v0.2.0".to_string(),
            memory_bytes: None,
            cpu_percent: None,
            cpu_cores: None,
            admin_latency_ms: None,
            discovery_policy_version: None,
            work_state_changes: None,
        },
    )
    .await;
    assert_eq!(new_accepted.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn agent_credential_renewal_requires_current_bearer() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    assert_eq!(enrollment.status(), StatusCode::CREATED);

    let response = post_json_to_router(
        &env.config,
        &env.store_handle,
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
async fn agent_routes_accept_issued_bearer_credential() {
    let env = TestEnv::new().await;
    let token = env.issue_token().await;
    let enrollment = post_enrollment_to_router(
        &env.config,
        &env.store_handle,
        enrollment_request_json(&token),
    )
    .await;
    let returned = decode_enrollment_response(enrollment).await;
    let credential = returned
        .result
        .credential_bundle
        .expect("credential bundle")
        .bearer_token
        .expect("bearer token");

    let poll = post_json_to_router(
        &env.config,
        &env.store_handle,
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
        &env.store_handle,
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
    let unauthorized = post_json_to_router(
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
async fn uplink_view_starts_unset() {
    let env = TestEnv::new().await;
    let uri = "/api/v1/admin/agent/uplink";

    let unauthorized = get_to_router(&env.config, &env.store_handle, uri, None).await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // 未设置过：host 空、updated_at 为 null。端口回约定默认值，但那只是给页面预填的提示，
    // 不落库 —— `updated_at == null` 才是「未设置」的判据。
    let view = get_to_router(
        &env.config,
        &env.store_handle,
        uri,
        Some(TEST_ADMIN_API_TOKEN),
    )
    .await;
    assert_eq!(view.status(), StatusCode::OK);
    let body: serde_json::Value = decode_json_response(view).await;
    assert_eq!(body["host"], "");
    assert_eq!(body["port"], 9000);
    assert_eq!(body["updated_by"], "");
    assert_eq!(body["updated_at"], serde_json::Value::Null);
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
        &serde_json::json!({ "host": "10.0.1.9", "port": 9100, "requested_by": "ops" }),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let stored: serde_json::Value = decode_json_response(ok).await;
    assert_eq!(stored["host"], "10.0.1.9");
    assert_eq!(stored["port"], 9100);
    assert_eq!(stored["updated_by"], "ops");

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
}

#[tokio::test]
async fn install_package_view_starts_unset() {
    let env = TestEnv::new().await;
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
    let env = TestEnv::new().await;
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
    let env = TestEnv::new().await;
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
            agent_package_file: package_file,
            bootstrap_token_ttl_seconds: 900,
            credential_ttl_seconds: 30 * 24 * 60 * 60,
            store_file,
            database_url: None,
            sqlite_path: db_path.clone(),
            trust_bundle: "internal-ca-stub".to_string(),
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
        };
        // A temp-file DB (not `:memory:`) because the router may use several
        // pooled connections; `SqliteStore` is `Clone` and shares the same pool.
        let store = SqliteStore::connect_path(&db_path)
            .await
            .expect("open store");
        let store_handle: Arc<dyn Store> = Arc::new(store.clone());
        Self {
            config,
            store,
            store_handle,
            install_public_key_bytes,
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
    ApiState {
        purpose_rules: super::load_purpose_rules(&env.config),
        discovery_policies: super::load_discovery_policies(&env.config),
        content: super::load_content(&env.config),
        config: env.config.clone(),
        store: Arc::clone(&env.store_handle),
        runtime: Arc::new(Mutex::new(AdminRuntimeState::default())),
        rate_limits: Arc::new(Mutex::new(super::rate_limit::RateLimitState::default())),
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

async fn poll_work(env: &TestEnv, credential: Option<&str>) -> Response {
    post_json_to_router(
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

async fn ack_work(
    env: &TestEnv,
    credential: Option<&str>,
    work_id: &str,
    version: i64,
) -> Response {
    post_json_to_router(
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
    post_json_to_router(
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
