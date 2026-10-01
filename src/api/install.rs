use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::infra::{
    AdminConfig, BootstrapTokenCheck, DEFAULT_AGENT_UPLINK_PORT, DEFAULT_AGENT_UPLINK_SETTING_ID,
    Store, StoreResult, StoredAgentUplinkAddress, StoredEnrollmentToken,
    StoredEnrollmentTokenStatus, VerifiedAgentIdentity, new_secret_token, sha256_hex,
    sign_install_script,
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
    let base = effective_advertise_base(&state.config, &state.store).await;
    match resolve_agent_package(&state.config, &state.store, &base).await {
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
            install_script(&state.config, arch, &package, &base),
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
    let base = effective_advertise_base(&state.config, &state.store).await;
    let package = match resolve_agent_package(&state.config, &state.store, &base).await {
        Ok(package) => package,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to resolve agent package: {err}"),
            )
                .into_response();
        }
    };
    match install_script_signature(&state.config, arch, &package, &base) {
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
            // 控制面 endpoint 取「网关对外地址」（未设置回落配置值）：agent 拿到的
            // 必须是它对目标主机可见的地址，否则装完连不上。
            let base = effective_advertise_base(&state.config, &state.store).await;
            // 上送目标：管理面设置 → 部署配置派生（与上面同一个域名 + 数据面端口）。
            // 读设置失败不阻断安装：按「没设过」处理，用派生值兜底并留下告警。
            let uplink = match effective_agent_uplink(&state.config, &state.store).await {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("warning: failed to read agent uplink address: {err}");
                    derived_agent_uplink(&state.config, &state.store).await
                }
            };
            (
                [
                    (header::CONTENT_TYPE, "application/toml; charset=utf-8"),
                    (header::CACHE_CONTROL, NO_STORE),
                ],
                agent_initial_config_toml(&state.config, token, uplink.as_ref(), &base),
            )
                .into_response()
        }
        Err(reason) => {
            rate_limit::record_auth_failure(&state, &client_key, BOOTSTRAP_AUTH_SCOPE);
            // 对外只回一句不可区分的口径：不暴露「token 存在但过期/已消费」这类可枚举细节
            // （与安装包分发端点、enroll 路径的对外口径一致）。具体原因只进服务端审计日志，
            // 保留运维可诊断性。
            eprintln!("audit bootstrap_token_rejected endpoint=initial-config reason={reason}");
            unauthorized_no_store("invalid bootstrap bearer token")
        }
    }
}

pub async fn download_agent_package(
    State(state): State<ApiState>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = authorize_package_download(
        &state,
        client_identity.as_ref().map(|identity| &identity.0),
        &headers,
        &client_key,
    )
    .await
    {
        return response;
    }
    let Some(package_path) = effective_package_path(&state.config, &state.store).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CACHE_CONTROL, NO_STORE)],
            "agent package is not configured on this gateway",
        )
            .into_response();
    };
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
            [(header::CACHE_CONTROL, NO_STORE)],
            "failed to read agent package",
        )
            .into_response(),
    }
}

/// 按内容寻址 id 取某个录入过的安装包（升级路径）。
///
/// 与 `/current` 不同：这里取的是历史里**这个包自己**的那份副本，而不是单例缓存。
/// 鉴权与 `/current` 一致（bootstrap token 或 agent 凭据二者其一）。
pub async fn download_agent_package_by_id(
    State(state): State<ApiState>,
    Path(package_id): Path<String>,
    client_identity: Option<Extension<VerifiedAgentIdentity>>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = authorize_package_download(
        &state,
        client_identity.as_ref().map(|identity| &identity.0),
        &headers,
        &client_key,
    )
    .await
    {
        return response;
    }
    let entry = match state
        .store
        .get_agent_install_package_by_id(&package_id)
        .await
    {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                [(header::CACHE_CONTROL, NO_STORE)],
                "unknown agent package",
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CACHE_CONTROL, NO_STORE)],
                format!("failed to load agent package history: {err}"),
            )
                .into_response();
        }
    };
    match std::fs::read(&entry.cached_path) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, NO_STORE),
            ],
            bytes,
        )
            .into_response(),
        // 行在但副本丢了（磁盘被清/被移）：按不存在处理，别把 500 当作“网关挂了”。
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(header::CACHE_CONTROL, NO_STORE)],
            "agent package copy is missing",
        )
            .into_response(),
    }
}

/// 安装包分发端点的鉴权：接受 **bootstrap（注册）token 或 agent 客户端证书** 二者其一。
///
/// 为什么要两个入口：新装场景手上是注册 token（agent 还没证书）；而升级场景的机器没有
/// enrollment token，靠 mTLS 出示自己的客户端证书（升级器 `/current` 或按 id 取包）。
/// 两者都是「可信的舰队成员」，且包本身不是秘密（install.sh 会内嵌下载地址与摘要）。
///
/// **bearer 凭据路径已随双轨一起删除**（§7 收口）：机器一方的身份只有客户端证书这一条。
///
/// 限流沿用现有 `BOOTSTRAP_AUTH_SCOPE`：这是同一个端点上的**一次**鉴权决策，
/// 桶按客户端 IP 分；沿用旧 scope 能保持 `/current` 现有行为不变（不新立 scope）。
#[allow(clippy::result_large_err)]
async fn authorize_package_download(
    state: &ApiState,
    client_identity: Option<&VerifiedAgentIdentity>,
    headers: &HeaderMap,
    client_key: &str,
) -> Result<(), Response> {
    if let Some(response) = rate_limit::check_rate_limit(state, client_key, BOOTSTRAP_AUTH_SCOPE) {
        return Err(response);
    }
    // 先按 mTLS 客户端证书（升级路径），再按引导 token（新装路径）。
    if client_identity.is_some() {
        return match super::agent_ops::authorize_agent_certificate(state, client_identity).await {
            Ok(()) => {
                rate_limit::clear_auth_failures(state, client_key, BOOTSTRAP_AUTH_SCOPE);
                Ok(())
            }
            Err(reason) => {
                rate_limit::record_auth_failure(state, client_key, BOOTSTRAP_AUTH_SCOPE);
                eprintln!(
                    "audit package_download_rejected reason=invalid_certificate detail={reason}"
                );
                Err(unauthorized_no_store("invalid agent client certificate"))
            }
        };
    }
    let Some(token) = bootstrap_bearer_token(headers) else {
        rate_limit::record_auth_failure(state, client_key, BOOTSTRAP_AUTH_SCOPE);
        // 对外仍是一句不可区分的口径；具体原因只进服务端审计日志（**不记 token 本身**）。
        eprintln!("audit package_download_rejected reason=missing_credential");
        return Err(unauthorized_no_store(
            "agent package download requires a bootstrap token or a client certificate",
        ));
    };
    match validate_bootstrap_token_for_config(&state.config, &state.store, token).await {
        Ok(()) => {
            rate_limit::clear_auth_failures(state, client_key, BOOTSTRAP_AUTH_SCOPE);
            Ok(())
        }
        Err(reason) => {
            rate_limit::record_auth_failure(state, client_key, BOOTSTRAP_AUTH_SCOPE);
            eprintln!(
                "audit package_download_rejected reason=invalid_bootstrap_token detail={reason}"
            );
            Err(unauthorized_no_store("invalid bootstrap token"))
        }
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
    // 基址取「网关对外地址」：安装命令、脚本与安装包的分发地址、以及 Agent 的控制面
    // endpoint 全部由它派生，必须同源。
    let base = effective_advertise_base(config, store).await;
    let package = resolve_agent_package(config, store, &base).await?;
    agent_install_code(config, &token, expires_at, &package, &base)
}

/// 生效的对外基址：管理面设置过就用它（去掉尾斜杠），否则回落 `server.public_base_url`。
///
/// 读设置失败不阻断安装链路，只回落并留下告警 —— 与 [`effective_package_path`] 同一个
/// 取舍：安装端点不该因为管理面的一次读失败而整体不可用。
pub async fn effective_advertise_base(config: &AdminConfig, store: &Arc<dyn Store>) -> String {
    match store.get_agent_advertise_url().await {
        Ok(Some(setting)) => setting.url.trim_end_matches('/').to_string(),
        Ok(None) => config.public_base_url.clone(),
        Err(err) => {
            eprintln!("warning: failed to read gateway advertise url: {err}");
            config.public_base_url.clone()
        }
    }
}

/// 生效的数据面上送目标：**管理面设置 → 部署配置派生 → 都没有**。
///
/// 「一台机器、一个域名」的部署不该再录一遍地址：录进来的域名（[`effective_advertise_base`]）
/// 就是唯一来源 —— 派生规则是「与 Agent 拿到的控制面地址**同域**，端口取数据面约定的入口端口
/// [`DEFAULT_AGENT_UPLINK_PORT`]」。要指到别处（另一台机器的数据面、非约定端口）才需要管理面录入。
///
/// 派生的那条 `updated_at` 留空，管理面据此把「来自部署配置」与「管理面设置过」区分开
/// （见 `admin_ops::uplink_response`）。
pub async fn effective_agent_uplink(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
) -> StoreResult<Option<StoredAgentUplinkAddress>> {
    Ok(match store.get_agent_uplink().await? {
        Some(setting) => Some(setting),
        None => derived_agent_uplink(config, store).await,
    })
}

/// 部署配置派生的上送目标（管理面没设过时的回落）。
///
/// `None` = 连基址里都取不出主机名 —— 这时才是真的「没有上送目标」，调用方按未设置处理。
///
/// `enabled` 恒为 `false`：派生只说明「能连到哪」（同一域名 + 数据面端口），不说明「该不该连」。
/// 把 `true` 当成默认就等于「升级即开始上送」，与「默认零行为变化」相冲。
pub async fn derived_agent_uplink(
    config: &AdminConfig,
    store: &Arc<dyn Store>,
) -> Option<StoredAgentUplinkAddress> {
    let base = effective_advertise_base(config, store).await;
    uplink_host_from_base_url(&base).map(|host| StoredAgentUplinkAddress {
        setting_id: DEFAULT_AGENT_UPLINK_SETTING_ID.to_string(),
        host,
        port: DEFAULT_AGENT_UPLINK_PORT,
        enabled: false,
        updated_by: String::new(),
        updated_at: String::new(),
    })
}

/// 从基址取「裸主机名」：`https://gw.example.com:8443/x` → `gw.example.com`。
///
/// 端口一律丢掉：上送端口是**数据面**端口，与基址里那个（网关自己的监听端口）无关。
///
/// **只接受裸主机名 / IPv4 字面量**（白名单），其余一律判为派生不出：
///   * IPv6 字面量（`[::1]`）拼不出 agentd 要的 `host:port`；
///   * 带 userinfo（`https://user@gw`）、带空白或其它符号的写法：宁可判「无目标」也不猜 ——
///     派生错了会让整队 agent 去连一个不存在的地址（**比没有目标更糟**）。
fn uplink_host_from_base_url(base: &str) -> Option<String> {
    // scheme 按大小写不敏感地切（固定小写是在上游校验里保证的，这里不靠它做正确性）。
    let after_scheme = base.find("://").map_or(base, |index| &base[index + 3..]);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    let host = authority.split(':').next().unwrap_or_default();
    let is_bare_host = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    is_bare_host.then(|| host.to_string())
}

pub fn agent_install_code(
    config: &AdminConfig,
    token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    package: &AgentPackageSource,
    base: &str,
) -> Result<AgentInstallCode, String> {
    let x86_install_script_url = config.install_script_url_at(base, "x86");
    let arm_install_script_url = config.install_script_url_at(base, "arm");
    let macos_install_code = macos_install_command(config, base)?;
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
            control_endpoint: base.to_string(),
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
pub fn install_script(
    config: &AdminConfig,
    arch: &str,
    package: &AgentPackageSource,
    base: &str,
) -> String {
    INSTALL_SCRIPT_TEMPLATE
        .replace("{{ARCH}}", arch)
        .replace("{{AGENT_PACKAGE_URL}}", &package.url)
        .replace(
            "{{AGENT_INITIAL_CONFIG_URL}}",
            &config.agent_initial_config_url_at(base),
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
fn macos_install_command(config: &AdminConfig, base: &str) -> Result<String, String> {
    let pin = server_tls_spki_pin(config)?;
    let install_base = format!("{}/api/v1/agent/install", base.trim_end_matches('/'));
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
    base: &str,
) -> Result<Vec<u8>, String> {
    let script = install_script(config, arch, package, base);
    sign_install_script(
        &config.install_script_signing_private_key_file,
        script.as_bytes(),
    )
}

pub fn agent_initial_config_toml(
    config: &AdminConfig,
    enrollment_token: &str,
    uplink: Option<&StoredAgentUplinkAddress>,
    base: &str,
) -> String {
    // Give each install a unique instance_name derived from its bootstrap token so
    // cloned machines (shared machine-id) still derive distinct agent identities.
    let instance_name = format!("host-{}", short_token_id(enrollment_token));
    // 默认**待命**：Agent 不采集日志、也不上送（指标同样不上送）。
    //
    // 待命由 `[telemetry.logs.output] enabled = false` 表达 —— 它与 `kind` **正交**：
    // `kind` 回答「写到哪」（file / tcp），`enabled` 回答「要不要写」。待命是开关状态，
    // 不该由「写到哪」来表达：
    //   * 有上送地址 → 记下真实目标（`kind = "tcp"`），但 `enabled = false` 先关掉；
    //   * 没有上送地址 → 没有目标可指，用 `kind = "file"` 表示，避免记一个会连错的
    //     tcp 默认值（旧默认是 127.0.0.1:9000）。
    //
    // 控制面派活后会在 `uplink:poll` 上下发 `enabled = true` + 目标，Agent 自动开始上送，
    // **无需人工改这份配置**、也无需重装。这也是相对旧实现（用 `kind = "file"` 表达待命）
    // 的修复：旧写法让事实帧走 file 分支返回 Err，默认配置持续打印 `fact summary uplink failed`；
    // `enabled = false` 时事实帧根本不会被上送，噪声自然消失。
    let telemetry = match uplink {
        Some(setting) => format!(
            r#"# 待命：不采集日志、也不上送（指标同样不上送）。
# 待命由 enabled = false 表达，与 kind 正交：目标记成 tcp，但开关先关掉。
# 控制面派活后会在 uplink:poll 上下发 enabled = true + 目标，Agent 自动开始上送 ——
# 不需要人工改这份配置。
[telemetry.logs]
in_memory_buffer_bytes = 1048576
spool_dir = "state/spool/logs"

[telemetry.logs.output]
enabled = false
kind = "tcp"

[telemetry.logs.output.tcp]
addr = "{addr}"
port = {port}
framing = "line"
"#,
            addr = toml_escape(&setting.host),
            port = setting.port,
        ),
        None => r#"# 待命：不采集日志、也不上送（指标同样不上送）。
# 待命由 enabled = false 表达，与 kind 正交。
# 管理面还没设置「数据面上送地址」，所以这里连上送目标都没有，用 kind = "file" 表示
# 「没有目标」（不记一个会连错的 tcp 默认值）。派活后控制面会在 uplink:poll 上下发目标。
[telemetry.logs]
in_memory_buffer_bytes = 1048576
spool_dir = "state/spool/logs"

[telemetry.logs.output]
enabled = false
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
credential_request = "csr"
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
        endpoint = toml_escape(base),
        enrollment_token = toml_escape(enrollment_token),
        tls_mode = toml_escape(tls_mode_for_endpoint(base)),
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
