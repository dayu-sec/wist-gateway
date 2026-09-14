use std::{
    env, fs,
    path::{Path, PathBuf},
};

use orion_error::conversion::ToStructError;
use serde::Deserialize;

use super::{load_install_script_public_key_pem, sha256_hex};
use wist_error::ConfigReason;

const DEFAULT_CONFIG_PATH: &str = "wist-gateway.toml";
const CONFIG_ENV: &str = "WIST_GATEWAY_CONFIG";
// Lower bound on the admin token length; the actual strength gate is the
// entropy check in require_non_weak_admin_token (>= 8 alphanumeric chars).
const MIN_ADMIN_API_TOKEN_BYTES: usize = 8;
const MAX_BOOTSTRAP_TOKEN_TTL_SECONDS: i64 = 60 * 60;
/// Well-known weak values that must never be used as the admin API token.
const WEAK_ADMIN_API_TOKENS: &[&str] = &[
    "admin",
    "password",
    "changeme",
    "letmein",
    "secret",
    "1234567890123456",
    "install-test-admin-token",
];

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub listen_addr: String,
    pub public_base_url: String,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    pub admin_api_token_hash: String,
    pub agent_package_file: PathBuf,
    pub bootstrap_token_ttl_seconds: i64,
    pub credential_ttl_seconds: i64,
    pub store_file: PathBuf,
    pub trust_bundle: String,
    pub install_script_signing_private_key_file: PathBuf,
    pub install_script_signing_public_key_pem: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub victoria_metrics_url: String,
}

pub use wist_error::ConfigError;

fn config_validation(message: impl Into<String>) -> ConfigError {
    ConfigReason::Validation.to_err().with_detail(message)
}

fn config_io(message: impl Into<String>) -> ConfigError {
    ConfigReason::Io.to_err().with_detail(message)
}

fn config_parse(message: impl Into<String>) -> ConfigError {
    ConfigReason::Parse.to_err().with_detail(message)
}

#[derive(Debug, Deserialize)]
struct RawAdminConfig {
    server: RawServerConfig,
    agent: RawAgentConfig,
}

#[derive(Debug, Deserialize)]
struct RawServerConfig {
    listen_addr: String,
    public_base_url: String,
    tls_cert_file: String,
    tls_key_file: String,
    admin_api_token: String,
    #[serde(default = "default_victoria_metrics_url")]
    victoria_metrics_url: String,
}

#[derive(Debug, Deserialize)]
struct RawAgentConfig {
    package_file: String,
    #[serde(default = "default_bootstrap_token_ttl_seconds")]
    bootstrap_token_ttl_seconds: i64,
    #[serde(default = "default_credential_ttl_seconds")]
    credential_ttl_seconds: i64,
    #[serde(default = "default_store_file")]
    store_file: String,
    trust_bundle: String,
    install_script_signing_private_key_file: String,
    tenant_id: String,
    environment_id: String,
}

pub fn default_config_path() -> String {
    DEFAULT_CONFIG_PATH.to_string()
}

/// Default admin config loaded from the `wist-gateway.toml` template with
/// the admin API token placeholder replaced by a freshly random value. Used by
/// the `init-config` command so a newly generated config never ships with a
/// predictable or shared default token, and editing the template file is the
/// single place to change the generated config shape.
pub fn default_config_text(admin_api_token: &str) -> String {
    include_str!("../../wist-gateway.toml").replace("${WARP_INSIGHT_ADMIN_TOKEN}", admin_api_token)
}

impl AdminConfig {
    pub fn load_from_env() -> Result<Self, ConfigError> {
        let path = env::var(CONFIG_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());
        Self::load_from_path(path)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config_path = absolutize_config_path(path.as_ref())?;
        let raw_content = fs::read_to_string(&config_path).map_err(|err| {
            config_io(format!(
                "failed to read config {}: {err}",
                config_path.display()
            ))
        })?;
        let raw: RawAdminConfig = toml::from_str(&raw_content).map_err(|err| {
            config_parse(format!(
                "failed to parse config {}: {err}",
                config_path.display()
            ))
        })?;
        let config_dir = config_path.parent().ok_or_else(|| {
            config_validation(format!(
                "failed to resolve config dir for {}",
                config_path.display()
            ))
        })?;
        let config = AdminConfig::from_raw(raw, config_dir)?;
        config.validate()?;
        Ok(config)
    }

    fn from_raw(raw: RawAdminConfig, config_dir: &Path) -> Result<Self, ConfigError> {
        let package_file = expand_env(&raw.agent.package_file)?;
        let tls_cert_file = expand_env(&raw.server.tls_cert_file)?;
        let tls_key_file = expand_env(&raw.server.tls_key_file)?;
        let admin_api_token = expand_env(&raw.server.admin_api_token)?;
        let install_script_signing_private_key_file = absolutize_path(
            config_dir,
            Path::new(&expand_env(
                &raw.agent.install_script_signing_private_key_file,
            )?),
        );
        require_non_empty("server.admin_api_token", &admin_api_token)?;
        require_min_secret_length(
            "server.admin_api_token",
            &admin_api_token,
            MIN_ADMIN_API_TOKEN_BYTES,
        )?;
        require_non_weak_admin_token(&admin_api_token)?;
        Ok(Self {
            listen_addr: expand_env(&raw.server.listen_addr)?,
            public_base_url: trim_trailing_slash(expand_env(&raw.server.public_base_url)?),
            tls_cert_file: absolutize_path(config_dir, Path::new(&tls_cert_file)),
            tls_key_file: absolutize_path(config_dir, Path::new(&tls_key_file)),
            admin_api_token_hash: sha256_hex(&admin_api_token),
            agent_package_file: absolutize_path(config_dir, Path::new(&package_file)),
            bootstrap_token_ttl_seconds: raw.agent.bootstrap_token_ttl_seconds,
            credential_ttl_seconds: raw.agent.credential_ttl_seconds,
            store_file: absolutize_path(config_dir, Path::new(&expand_env(&raw.agent.store_file)?)),
            trust_bundle: expand_env(&raw.agent.trust_bundle)?,
            install_script_signing_private_key_file: install_script_signing_private_key_file
                .clone(),
            install_script_signing_public_key_pem: load_install_script_public_key_pem(
                &install_script_signing_private_key_file,
            )
            .map_err(config_validation)?,
            tenant_id: expand_env(&raw.agent.tenant_id)?,
            environment_id: expand_env(&raw.agent.environment_id)?,
            victoria_metrics_url: trim_trailing_slash(expand_env(
                &raw.server.victoria_metrics_url,
            )?),
        })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        require_non_empty("server.listen_addr", &self.listen_addr)?;
        require_https_url("server.public_base_url", &self.public_base_url)?;
        require_existing_file("server.tls_cert_file", &self.tls_cert_file)?;
        require_existing_file("server.tls_key_file", &self.tls_key_file)?;
        require_existing_file("agent.package_file", &self.agent_package_file)?;
        require_positive_seconds(
            "agent.bootstrap_token_ttl_seconds",
            self.bootstrap_token_ttl_seconds,
        )?;
        require_seconds_at_most(
            "agent.bootstrap_token_ttl_seconds",
            self.bootstrap_token_ttl_seconds,
            MAX_BOOTSTRAP_TOKEN_TTL_SECONDS,
        )?;
        require_positive_seconds("agent.credential_ttl_seconds", self.credential_ttl_seconds)?;
        require_non_empty("agent.trust_bundle", &self.trust_bundle)?;
        require_existing_file(
            "agent.install_script_signing_private_key_file",
            &self.install_script_signing_private_key_file,
        )?;
        require_non_empty(
            "agent.install_script_signing_public_key_pem",
            &self.install_script_signing_public_key_pem,
        )?;
        require_non_empty("agent.tenant_id", &self.tenant_id)?;
        require_non_empty("agent.environment_id", &self.environment_id)?;
        require_non_empty("server.victoria_metrics_url", &self.victoria_metrics_url)?;
        Ok(())
    }

    pub fn install_script_url(&self, arch: &str) -> String {
        format!(
            "{}/api/v1/agent/install/{arch}/install.sh",
            self.public_base_url
        )
    }

    pub fn agent_package_url(&self) -> String {
        format!("{}/api/v1/agent/packages/current", self.public_base_url)
    }

    pub fn agent_initial_config_url(&self) -> String {
        format!("{}/api/v1/agent/initial-config", self.public_base_url)
    }
}

fn default_bootstrap_token_ttl_seconds() -> i64 {
    900
}

fn default_credential_ttl_seconds() -> i64 {
    30 * 24 * 60 * 60
}

fn default_victoria_metrics_url() -> String {
    "http://127.0.0.1:18429".to_string()
}

fn default_store_file() -> String {
    "state/wist-gateway-store.json".to_string()
}

fn absolutize_config_path(path: &Path) -> Result<PathBuf, ConfigError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = env::current_dir()
        .map_err(|err| config_io(format!("failed to resolve current dir: {err}")))?;
    Ok(cwd.join(path))
}

fn absolutize_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    base_dir.join(path)
}

fn expand_env(value: &str) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        output.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(config_validation(format!(
                "invalid environment placeholder in {value:?}"
            )));
        };
        let key = &after_start[..end];
        if key.is_empty() {
            return Err(config_validation("empty environment placeholder"));
        }
        let replacement = env::var(key)
            .map_err(|_| config_validation(format!("missing environment variable {key}")))?;
        output.push_str(&replacement);
        rest = &after_start[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

fn trim_trailing_slash(value: String) -> String {
    value.trim_end_matches('/').to_string()
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(config_validation(format!("{field} must not be empty")));
    }
    Ok(())
}

fn require_https_url(field: &str, value: &str) -> Result<(), ConfigError> {
    require_non_empty(field, value)?;
    if !value.starts_with("https://") {
        return Err(config_validation(format!(
            "{field} must start with https://"
        )));
    }
    if contains_shell_metacharacters(value) {
        return Err(config_validation(format!(
            "{field} contains characters that are unsafe in generated install scripts"
        )));
    }
    Ok(())
}

/// The value is embedded verbatim into install scripts that run under `sh` on
/// target hosts (inside double-quoted URLs). Reject characters that would break
/// out of that context or that are never valid in a control-plane base URL.
fn contains_shell_metacharacters(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '"' | '\\'
                | '$'
                | '`'
                | ';'
                | '|'
                | '&'
                | '<'
                | '>'
                | '('
                | ')'
                | ' '
                | '\''
                | '!'
                | '\n'
                | '\r'
                | '\t'
        )
    })
}

fn require_positive_seconds(field: &str, value: i64) -> Result<(), ConfigError> {
    if value > 0 {
        return Ok(());
    }
    Err(config_validation(format!("{field} must be greater than 0")))
}

fn require_seconds_at_most(field: &str, value: i64, max: i64) -> Result<(), ConfigError> {
    if value <= max {
        return Ok(());
    }
    Err(config_validation(format!(
        "{field} must be less than or equal to {max}"
    )))
}

fn require_min_secret_length(field: &str, value: &str, min: usize) -> Result<(), ConfigError> {
    if value.as_bytes().len() >= min {
        return Ok(());
    }
    Err(config_validation(format!(
        "{field} must be at least {min} bytes"
    )))
}

/// Minimum accepted admin token entropy in bits. 40 bits admits an 8-character
/// alphanumeric token while rejecting short digit/hex tokens (~20-32 bits).
const MIN_ADMIN_TOKEN_ENTROPY_BITS: f64 = 40.0;

fn require_non_weak_admin_token(value: &str) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    let normalized = trimmed.to_ascii_lowercase();
    if WEAK_ADMIN_API_TOKENS.iter().any(|weak| *weak == normalized) {
        return Err(config_validation(
            "server.admin_api_token uses a known weak value; use a randomly generated token",
        ));
    }
    if estimate_token_entropy_bits(trimmed) < MIN_ADMIN_TOKEN_ENTROPY_BITS {
        return Err(config_validation(format!(
            "server.admin_api_token is too weak: use a mixed-case alphanumeric token with at least \
             {MIN_ADMIN_TOKEN_ENTROPY_BITS} bits of entropy (an 8-character alphanumeric token qualifies)"
        )));
    }
    let distinct = trimmed.chars().collect::<std::collections::HashSet<char>>();
    if distinct.len() < 3 {
        return Err(config_validation(
            "server.admin_api_token is too weak: too few distinct characters",
        ));
    }
    Ok(())
}

/// Conservative entropy estimate (bits) based on the character classes present:
/// each class contributes its alphabet size, symbols are counted as a small
/// set, and the result is `length * log2(alphabet)`. This rejects short
/// digit/hex tokens while leaving strong single-case values (e.g. a long hex
/// key) accepted.
fn estimate_token_entropy_bits(value: &str) -> f64 {
    let has_upper = value.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = value.chars().any(|ch| ch.is_ascii_lowercase());
    let has_digit = value.chars().any(|ch| ch.is_ascii_digit());
    let has_symbol = value.chars().any(|ch| !ch.is_ascii_alphanumeric());
    let mut alphabet = 0.0f64;
    if has_upper {
        alphabet += 26.0;
    }
    if has_lower {
        alphabet += 26.0;
    }
    if has_digit {
        alphabet += 10.0;
    }
    if has_symbol {
        alphabet += 10.0; // conservative guess for a small symbol set
    }
    let alphabet = alphabet.max(2.0);
    value.chars().count() as f64 * alphabet.log2()
}

fn require_existing_file(field: &str, path: &Path) -> Result<(), ConfigError> {
    if !path.exists() {
        return Err(config_validation(format!(
            "{field} does not exist: {}",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(config_validation(format!(
            "{field} is not a file: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand as ring_rand,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_short_admin_token() {
        assert!(require_non_weak_admin_token("1234567").is_err()); // 7 chars < minimum
    }

    #[test]
    fn rejects_low_entropy_admin_tokens() {
        assert!(require_non_weak_admin_token("12345678").is_err()); // 8 digits ~27 bits
        assert!(require_non_weak_admin_token("abcdefgh").is_err()); // 8 lowercase ~37 bits
        assert!(require_non_weak_admin_token("0123456789").is_err()); // 10 digits ~33 bits
    }

    #[test]
    fn rejects_known_weak_admin_token() {
        assert!(require_non_weak_admin_token("password").is_err());
        assert!(require_non_weak_admin_token("install-test-admin-token").is_err());
    }

    #[test]
    fn accepts_strong_admin_tokens() {
        assert!(require_non_weak_admin_token("aB3kQ9x2Zz").is_ok()); // 10 alphanumeric ~60 bits
        assert!(require_non_weak_admin_token("test-admin-token").is_ok()); // existing test fixture
    }

    #[test]
    fn loads_config_with_environment_expansion() {
        let package_file = write_temp_file("wist-agentd");
        unsafe {
            env::set_var("WARP_INSIGHT_TEST_AGENT_PACKAGE_FILE", &package_file);
            env::set_var("WARP_INSIGHT_TEST_ADMIN_API_TOKEN", "test-admin-token");
        }
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000/"
admin_api_token = "${WARP_INSIGHT_TEST_ADMIN_API_TOKEN}"

[agent]
package_file = "${WARP_INSIGHT_TEST_AGENT_PACKAGE_FILE}"
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let config = AdminConfig::load_from_path(&path).expect("config loads");

        assert_eq!(config.agent_package_file, package_file);
        assert_eq!(config.admin_api_token_hash, sha256_hex("test-admin-token"));
        assert_eq!(config.public_base_url, "https://127.0.0.1:3000");
        assert_eq!(
            config.install_script_url("x86"),
            "https://127.0.0.1:3000/api/v1/agent/install/x86/install.sh"
        );
        assert_eq!(
            config.agent_package_url(),
            "https://127.0.0.1:3000/api/v1/agent/packages/current"
        );
        assert!(config.install_script_signing_private_key_file.is_absolute());
        assert!(
            config
                .install_script_signing_public_key_pem
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    #[test]
    fn relative_config_path_is_absolutized_against_current_dir() {
        let cwd = env::current_dir().expect("current dir");
        let path = absolutize_config_path(Path::new("wist-gateway.toml")).expect("path");

        assert!(path.is_absolute());
        assert_eq!(path, cwd.join("wist-gateway.toml"));
    }

    #[test]
    fn relative_package_file_is_absolutized_against_config_dir() {
        let dir = env::temp_dir().join(format!("wist-gateway-dir-{}", unique_suffix()));
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(dir.join("wist-agent.tar.gz"), "package").expect("write package");
        write_install_signing_key(&dir.join("install-signing-ed25519.pkcs8.pem"));
        let config_path = dir.join("admin.toml");
        fs::write(
            &config_path,
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
tls_cert_file = "admin-tls.crt.pem"
tls_key_file = "admin-tls.key.pem"
admin_api_token = "test-admin-token"

[agent]
package_file = "wist-agent.tar.gz"
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
install_script_signing_private_key_file = "install-signing-ed25519.pkcs8.pem"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        )
        .expect("write config");
        fs::write(dir.join("admin-tls.crt.pem"), "cert").expect("write cert");
        fs::write(dir.join("admin-tls.key.pem"), "key").expect("write key");

        let config = AdminConfig::load_from_path(&config_path).expect("config loads");

        assert_eq!(config.agent_package_file, dir.join("wist-agent.tar.gz"));
        assert_eq!(config.tls_cert_file, dir.join("admin-tls.crt.pem"));
        assert_eq!(config.tls_key_file, dir.join("admin-tls.key.pem"));
        assert_eq!(
            config.install_script_signing_private_key_file,
            dir.join("install-signing-ed25519.pkcs8.pem")
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_missing_tls_certificate_file() {
        let package_file = write_temp_file("wist-agentd");
        let key_file = write_temp_file("key");
        let missing_cert = env::temp_dir().join(format!(
            "warp-insight-missing-admin-tls-{}.crt.pem",
            unique_suffix()
        ));
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
tls_cert_file = "{}"
tls_key_file = "{}"
admin_api_token = "test-admin-token"

[agent]
package_file = "{}"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            missing_cert.display(),
            key_file.display(),
            package_file.display()
        ));

        let err = AdminConfig::load_from_path(&path).expect_err("missing TLS cert rejected");

        assert!(err.to_string().contains("server.tls_cert_file"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
        let _ = fs::remove_file(key_file);
    }

    #[test]
    fn rejects_missing_agent_package_file() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
admin_api_token = "test-admin-token"

[agent]
package_file = "/tmp/warp-insight-missing-agent-package.tar.gz"
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let err = AdminConfig::load_from_path(&path).expect_err("invalid URL rejected");

        assert!(err.to_string().contains("agent.package_file"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_short_admin_api_token() {
        let package_file = write_temp_file("wist-agentd");
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
admin_api_token = "short"

[agent]
package_file = "{}"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            package_file.display()
        ));

        let err = AdminConfig::load_from_path(&path).expect_err("short token rejected");

        assert!(err.to_string().contains("server.admin_api_token"));
        assert!(err.to_string().contains("at least 8 bytes"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    #[test]
    fn rejects_long_bootstrap_token_ttl() {
        let package_file = write_temp_file("wist-agentd");
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
admin_api_token = "test-admin-token"

[agent]
package_file = "{}"
bootstrap_token_ttl_seconds = 7200
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            package_file.display()
        ));

        let err = AdminConfig::load_from_path(&path).expect_err("long ttl rejected");

        assert!(
            err.to_string()
                .contains("agent.bootstrap_token_ttl_seconds")
        );
        assert!(err.to_string().contains("less than or equal to 3600"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    #[test]
    fn rejects_http_public_base_url() {
        let package_file = write_temp_file("wist-agentd");
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "0.0.0.0:3000"
public_base_url = "http://127.0.0.1:3000"
admin_api_token = "test-admin-token"

[agent]
package_file = "{}"
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            package_file.display()
        ));

        let err = AdminConfig::load_from_path(&path).expect_err("insecure URL rejected");

        assert!(err.to_string().contains("must start with https://"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    #[test]
    fn accepts_https_public_base_url() {
        let package_file = write_temp_file("wist-agentd");
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://localhost:3000/"
admin_api_token = "test-admin-token"

[agent]
package_file = "{}"
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            package_file.display()
        ));

        let config = AdminConfig::load_from_path(&path).expect("https config loads");

        assert_eq!(config.public_base_url, "https://localhost:3000");
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    #[test]
    fn rejects_public_base_url_with_shell_metacharacters() {
        let package_file = write_temp_file("wist-agentd");
        let text = r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000\"; touch /tmp/pwned"
admin_api_token = "test-admin-token"

[agent]
package_file = "__PACKAGE__"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#
        .replace("__PACKAGE__", &package_file.display().to_string());
        let path = write_temp_config(&text);

        let err = AdminConfig::load_from_path(&path).expect_err("injected URL rejected");

        assert!(
            err.to_string()
                .contains("unsafe in generated install scripts")
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    #[test]
    fn loads_multiline_trust_bundle() {
        let package_file = write_temp_file("wist-agentd");
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://localhost:3000/"
admin_api_token = "test-admin-token"

[agent]
package_file = "{}"
trust_bundle = '''-----BEGIN CERTIFICATE-----
MIIBtest
-----END CERTIFICATE-----
'''
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            package_file.display()
        ));

        let config = AdminConfig::load_from_path(&path).expect("config loads");

        assert_eq!(
            config.trust_bundle,
            "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n"
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(package_file);
    }

    fn write_temp_config(content: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("wist-gateway-{}.toml", unique_suffix()));
        let key_path = path.with_extension("ed25519.pkcs8.pem");
        let tls_cert_path = path.with_extension("tls.crt.pem");
        let tls_key_path = path.with_extension("tls.key.pem");
        write_install_signing_key(&key_path);
        fs::write(&tls_cert_path, "cert").expect("write TLS cert");
        fs::write(&tls_key_path, "key").expect("write TLS key");
        let content = if content.contains("install_script_signing_private_key_file") {
            content.to_string()
        } else {
            format!(
                "{content}\ninstall_script_signing_private_key_file = \"{}\"\n",
                key_path.display()
            )
        };
        let content = if content.contains("tls_cert_file") {
            content
        } else {
            inject_server_field(
                &content,
                "tls_cert_file",
                &tls_cert_path.display().to_string(),
            )
        };
        let content = if content.contains("tls_key_file") {
            content
        } else {
            inject_server_field(
                &content,
                "tls_key_file",
                &tls_key_path.display().to_string(),
            )
        };
        fs::write(&path, content).expect("write config");
        path
    }

    fn inject_server_field(content: &str, key: &str, value: &str) -> String {
        let mut output = Vec::new();
        let mut inserted = false;
        for line in content.lines() {
            output.push(line.to_string());
            if !inserted && line.trim() == "[server]" {
                output.push(format!("{key} = \"{value}\""));
                inserted = true;
            }
        }
        assert!(inserted, "test config must include [server]");
        format!("{}\n", output.join("\n"))
    }

    fn write_temp_file(content: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("warp-insight-agent-package-{}", unique_suffix()));
        fs::write(&path, content).expect("write file");
        path
    }

    fn unique_suffix() -> u128 {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        suffix
    }

    fn write_install_signing_key(path: &Path) {
        let rng = ring_rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate signing key");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse signing key");
        assert_eq!(key_pair.public_key().as_ref().len(), 32);
        fs::write(path, private_key_pem(pkcs8.as_ref())).expect("write signing key");
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
}
