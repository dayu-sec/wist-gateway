use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::infra::{
    AdminConfig, BootstrapTokenCheck, Store, StoredAgentUplinkAddress, StoredEnrollmentToken,
    StoredEnrollmentTokenStatus, new_secret_token, sha256_hex, sign_install_script,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ring::digest::{SHA256, digest};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use webpki::EndEntityCert;
use wist_control::types::{AgentBootstrapBundle, AgentInstallCode, DateTime};

use super::ApiState;
use super::install_package::{AgentPackageSource, effective_package_path, resolve_agent_package};
use super::{admin_auth::require_admin_bearer, rate_limit};

const INSTALL_SCRIPT_TEMPLATE: &str = include_str!("install.sh");
pub(crate) const ENROLLMENT_TOKEN_RESERVATION_TTL_SECONDS: i64 = 60;
const BOOTSTRAP_AUTH_SCOPE: &str = "bootstrap";
const NO_STORE: &str = "no-store";

pub async fn get_agent_install_code(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    match issue_agent_install_code(&state.config, &state.store).await {
        Ok(install_code) => {
            eprintln!(
                "audit install_code_issued tenant={} environment={} bundle={}",
                state.config.tenant_id,
                state.config.environment_id,
                install_code.bootstrap_bundle.bundle_id,
            );
            ([(header::CACHE_CONTROL, NO_STORE)], Json(install_code)).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to issue install code: {err}"),
        )
            .into_response(),
    }
}

pub async fn get_agent_install_script(
    State(state): State<ApiState>,
    Path(arch): Path<String>,
) -> Response {
    let Ok(arch) = supported_agent_arch(&arch) else {
        return unknown_arch_response();
    };
    match resolve_agent_package(&state.config, &state.store).await {
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to resolve agent package: {err}"),
        )
            .into_response(),
        Ok(package) => (
            [
                (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
                (header::CACHE_CONTROL, NO_STORE),
            ],
            install_script(&state.config, arch, &package),
        )
            .into_response(),
    }
}

pub async fn get_agent_install_script_signature(
    State(state): State<ApiState>,
    Path(arch): Path<String>,
) -> Response {
    let Ok(arch) = supported_agent_arch(&arch) else {
        return unknown_arch_response();
    };
    let package = match resolve_agent_package(&state.config, &state.store).await {
        Ok(package) => package,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to resolve agent package: {err}"),
            )
                .into_response();
        }
    };
    match install_script_signature(&state.config, arch, &package) {
        Ok(signature) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, NO_STORE),
            ],
            signature,
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to sign install script: {err}"),
        )
            .into_response(),
    }
}

fn supported_agent_arch(arch: &str) -> Result<&'static str, ()> {
    match arch {
        "x86" => Ok("x86"),
        "arm" => Ok("arm"),
        _ => Err(()),
    }
}

fn unknown_arch_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CACHE_CONTROL, NO_STORE)],
        "unknown agent architecture",
    )
        .into_response()
}

pub async fn get_agent_initial_config_with_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) = rate_limit::check_rate_limit(&state, &client_key, BOOTSTRAP_AUTH_SCOPE)
    {
        return response;
    }
    let Some(token) = bootstrap_bearer_token(&headers) else {
        rate_limit::record_auth_failure(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
        return unauthorized_no_store("agent initial config requires a bootstrap bearer token");
    };

    match validate_bootstrap_token_for_config(&state.config, &state.store, token).await {
        Ok(()) => {
            rate_limit::clear_auth_failures(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
            // 管理面未设置数据面上送地址时不下发上送段；读设置失败不阻断安装，
            // 按「未设置」处理并留下告警。
            let uplink = match state.store.get_agent_uplink().await {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("warning: failed to read agent uplink address: {err}");
                    None
                }
            };
            (
                [
                    (header::CONTENT_TYPE, "application/toml; charset=utf-8"),
                    (header::CACHE_CONTROL, NO_STORE),
                ],
                agent_initial_config_toml(&state.config, token, uplink.as_ref()),
            )
                .into_response()
        }
        Err(reason) => {
            rate_limit::record_auth_failure(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
            unauthorized_no_store(reason)
        }
    }
}

pub async fn download_agent_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Some(response) = rate_limit::check_rate_limit(&state, &client_key, BOOTSTRAP_AUTH_SCOPE)
    {
        return response;
    }
    let Some(token) = bootstrap_bearer_token(&headers) else {
        rate_limit::record_auth_failure(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
        return unauthorized_no_store("agent package download requires a bootstrap bearer token");
    };
    if let Err(reason) =
        validate_bootstrap_token_for_config(&state.config, &state.store, token).await
    {
        rate_limit::record_auth_failure(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
        return unauthorized_no_store(reason);
    }
    rate_limit::clear_auth_failures(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
    let package_path = effective_package_path(&state.config, &state.store).await;
    match std::fs::read(&package_path) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, NO_STORE),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"wist-agentd\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to read agent package",
        )
            .into_response(),
    }
}

fn unauthorized_no_store(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CACHE_CONTROL, NO_STORE)],
        message.into(),
    )
        .into_response()
}

pub async fn issue_agent_install_code(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
) -> Result<AgentInstallCode, String> {
    let token = new_enrollment_token()?;
    let token_hash = token_hash(&token);
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::seconds(config.bootstrap_token_ttl_seconds);
    let stored = StoredEnrollmentToken {
        token_id: format!("install-{}", short_token_id(&token)),
        token_hash,
        tenant_id: config.tenant_id.clone(),
        environment_id: config.environment_id.clone(),
        issued_by: "admin-api".to_string(),
        allowed_node_selector: None,
        max_uses: 1,
        used_count: 0,
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        reserved_at: None,
        revoked_at: None,
        status: StoredEnrollmentTokenStatus::Active,
    };
    store
        .insert_enrollment_token(&stored)
        .await
        .map_err(|err| err.to_string())?;
    // 分发地址恒为网关自身端点；管理面设置的是来源地址，制品已缓存到网关本地。
    let package = resolve_agent_package(config, store).await?;
    agent_install_code(config, &token, expires_at, &package)
}

pub fn agent_install_code(
    config: &AdminConfig,
    token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    package: &AgentPackageSource,
) -> Result<AgentInstallCode, String> {
    let x86_install_script_url = config.install_script_url("x86");
    let arm_install_script_url = config.install_script_url("arm");
    let macos_install_code = macos_install_command(config)?;
    Ok(AgentInstallCode {
        x86_linux_install_code: install_command(config, &x86_install_script_url),
        bootstrap_enrollment_token: token.to_string(),
        arm_linux_install_code: install_command(config, &arm_install_script_url),
        macos_install_code,
        bootstrap_bundle: AgentBootstrapBundle {
            bundle_id: format!("agent-bootstrap-{}", short_token_id(token)),
            install_script_url: x86_install_script_url,
            agent_package_url: package.url.clone(),
            agent_package_sha256: package.sha256.clone(),
            control_endpoint: config.public_base_url.clone(),
            trust_bundle: config.trust_bundle.clone(),
            tenant_id: config.tenant_id.clone(),
            environment_id: config.environment_id.clone(),
            expires_at: DateTime::from_rfc3339(&expires_at.to_rfc3339())
                .unwrap_or_else(DateTime::now),
        },
    })
}

/// 渲染 install.sh，并把生效的安装包地址与校验摘要写进模板。
///
/// 调用方必须与 [`install_script_signature`] 传入同一个 [`AgentPackageSource`]，
/// 否则客户端下载到的脚本与其签名会不一致。
pub fn install_script(config: &AdminConfig, arch: &str, package: &AgentPackageSource) -> String {
    INSTALL_SCRIPT_TEMPLATE
        .replace("{{ARCH}}", arch)
        .replace("{{AGENT_PACKAGE_URL}}", &package.url)
        .replace(
            "{{AGENT_INITIAL_CONFIG_URL}}",
            &config.agent_initial_config_url(),
        )
        .replace("{{AGENT_PACKAGE_SHA256}}", &package.sha256)
        .replace("{{TRUST_BUNDLE}}", &config.trust_bundle)
}

fn install_command(config: &AdminConfig, script_url: &str) -> String {
    let signature_url = install_script_signature_url(script_url);
    // The two downloads use -k (skip cert verification) because the admin runs
    // a self-signed CA that a fresh host cannot yet trust. This is safe: the
    // script's integrity/authenticity is verified by the embedded public key
    // below (openssl pkeyutl -verify), so TLS is just transport here.
    format!(
        r#"set -eu; D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT INT TERM
curl -fsSLk "{script_url}" -o "$D/s"
curl -fsSLk "{signature_url}" -o "$D/sig"
echo "==> 校验安装脚本签名"
cat >"$D/key.pem" <<'EOF'
{public_key_pem}EOF
openssl pkeyutl -verify -pubin -inkey "$D/key.pem" -rawin -in "$D/s" -sigfile "$D/sig" && sh "$D/s""#,
        script_url = script_url,
        signature_url = signature_url,
        public_key_pem = config.install_script_signing_public_key_pem,
    )
}

/// sha256 of the TLS serving certificate's SubjectPublicKeyInfo (DER), base64.
/// curl's `--pinnedpubkey sha256//<pin>` uses the same value, so the macOS
/// install command can authenticate the gateway with the built-in curl even
/// though macOS ships LibreSSL (which cannot verify the Ed25519 script
/// signature the Linux command relies on).
fn server_tls_spki_pin(config: &AdminConfig) -> Result<String, String> {
    let cert = CertificateDer::from_pem_file(&config.tls_cert_file).map_err(|err| {
        format!(
            "failed to read tls certificate {}: {err}",
            config.tls_cert_file.display()
        )
    })?;
    let end_entity = EndEntityCert::try_from(&cert)
        .map_err(|err| format!("failed to parse tls certificate: {err}"))?;
    let spki = end_entity.subject_public_key_info();
    Ok(BASE64_STANDARD.encode(digest(&SHA256, spki.as_ref()).as_ref()))
}

/// macOS install command: the built-in curl authenticates the TLS channel by
/// pinning the gateway's serving certificate, so the target host needs no
/// external OpenSSL 3 / Ed25519 CLI support. The host architecture is picked
/// at runtime (arm64 -> arm, everything else -> x86).
fn macos_install_command(config: &AdminConfig) -> Result<String, String> {
    let pin = server_tls_spki_pin(config)?;
    let install_base = format!(
        "{}/api/v1/agent/install",
        config.public_base_url.trim_end_matches('/')
    );
    Ok(format!(
        r#"set -eu; D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT INT TERM
if [ "$(uname -s)" != "Darwin" ]; then echo "this install command is for macOS only" >&2; exit 2; fi
case "$(uname -m)" in arm64) ARCH=arm ;; *) ARCH=x86 ;; esac
curl -fsSLk --pinnedpubkey "sha256//{pin}" "{install_base}/$ARCH/install.sh" -o "$D/s"
sh "$D/s""#,
        pin = pin,
        install_base = install_base,
    ))
}

fn install_script_signature_url(script_url: &str) -> String {
    format!("{script_url}.sig")
}

pub(crate) fn install_script_signature(
    config: &AdminConfig,
    arch: &str,
    package: &AgentPackageSource,
) -> Result<Vec<u8>, String> {
    let script = install_script(config, arch, package);
    sign_install_script(
        &config.install_script_signing_private_key_file,
        script.as_bytes(),
    )
}

pub fn agent_initial_config_toml(
    config: &AdminConfig,
    enrollment_token: &str,
    uplink: Option<&StoredAgentUplinkAddress>,
) -> String {
    // Give each install a unique instance_name derived from its bootstrap token so
    // cloned machines (shared machine-id) still derive distinct agent identities.
    let instance_name = format!("host-{}", short_token_id(enrollment_token));
    // 默认**待命**：Agent 不做任何数据面工作 —— 不采集日志，也不上送（指标同样不上送）。
    //
    // 靠 `kind = "file"` 实现：没有 inputs 时 file sink 什么都不会写，而 agentd 的指标帧
    // 走的是同一个 sink（`write_metrics` 对 file 分支直接跳过）。所以“静”是靠 kind 保证的，
    // 不是靠“没有任务”。上送目标只记录下来，等控制面派活时再改成 tcp。
    let telemetry = match uplink {
        Some(setting) => format!(
            r#"# 待命：Agent 不采集日志、也不上送（指标同样不上送）。
# 上送目标已由管理面的「数据面上送地址」设置好，此处只记录 ——
# 真正开始上送要等控制面派活（下发任务清单）时把 kind 改成 "tcp"。
[telemetry.logs]
in_memory_buffer_bytes = 1048576
spool_dir = "state/spool/logs"

[telemetry.logs.output]
kind = "file"

[telemetry.logs.output.tcp]
addr = "{addr}"
port = {port}
framing = "line"
"#,
            addr = toml_escape(&setting.host),
            port = setting.port,
        ),
        None => r#"# 待命：Agent 不采集日志、也不上送（指标同样不上送）。
# 管理面还没设置「数据面上送地址」，所以这里连上送目标都没有。
[telemetry.logs]
in_memory_buffer_bytes = 1048576
spool_dir = "state/spool/logs"

[telemetry.logs.output]
kind = "file"
"#
        .to_string(),
    };
    format!(
        r#"schema_version = "v1"

[agent]
environment_id = "{environment_id}"
instance_name = "{instance_name}"

[control_plane]
enabled = true
endpoint = "{endpoint}"
enrollment_token = "{enrollment_token}"
credential_request = "bearer"
tls_mode = "{tls_mode}"
trust_bundle = "{trust_bundle}"
auth_mode = "enrollment_token"

# 路径布局由 agentd 按**配置目录**推导，此处不声明 [paths]：
#   /etc/wist-agentd（系统级安装）→ 数据 /var/lib/wist-agentd、日志 /var/log/wist-agentd
#   其它位置（用户级安装）→ 数据与日志留在配置目录下
# 一旦在此声明（即使值等于默认），agentd 就不再填默认值，系统级安装会退回配置目录下。
{telemetry}
[discovery]
host_enabled = true
network_enabled = true
endpoint_enabled = true
process_enabled = true
container_enabled = false
"#,
        environment_id = toml_escape(&config.environment_id),
        instance_name = toml_escape(&instance_name),
        endpoint = toml_escape(&config.public_base_url),
        enrollment_token = toml_escape(enrollment_token),
        tls_mode = toml_escape(tls_mode_for_endpoint(&config.public_base_url)),
        trust_bundle = toml_escape(&config.trust_bundle),
        telemetry = telemetry,
    )
}

pub async fn validate_bootstrap_token_for_config(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
    token: &str,
) -> Result<(), String> {
    let token_hash = token_hash(token);
    // The store persists its own state transitions (marking an expired token,
    // recovering a stale reservation) even when it rejects, so here we only map
    // the semantic rejection back to the existing outward error strings.
    let rejection = store
        .validate_bootstrap_token(&BootstrapTokenCheck {
            token_hash: &token_hash,
            tenant_id: &config.tenant_id,
            environment_id: &config.environment_id,
            reservation_ttl_seconds: ENROLLMENT_TOKEN_RESERVATION_TTL_SECONDS,
        })
        .await
        .map_err(|err| err.to_string())?
        .err();
    match rejection {
        Some(rejection) => Err(rejection.to_string()),
        None => Ok(()),
    }
}

fn tls_mode_for_endpoint(endpoint: &str) -> &'static str {
    if endpoint.starts_with("https://") {
        "https"
    } else {
        "http"
    }
}

fn toml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\u{:04X}", ch as u32));
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn new_enrollment_token() -> Result<String, String> {
    new_secret_token("wit")
}

pub fn token_hash(token: &str) -> String {
    sha256_hex(token)
}

fn short_token_id(token: &str) -> String {
    token_hash(token).chars().take(12).collect()
}

fn bootstrap_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
