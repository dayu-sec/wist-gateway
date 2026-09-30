use std::{
    env, fs,
    path::{Path, PathBuf},
};

use orion_error::conversion::ToStructError;
use serde::Deserialize;

use super::{load_install_script_public_key_pem, sha256_hex};
use wist_error::ConfigReason;

const DEFAULT_CONFIG_PATH: &str = "wist-gateway.toml";
/// `[ingest]` 段缺省时的内部接入端点：只绑环回，避免明文监听被动暴露到网卡上。
const DEFAULT_INGEST_LISTEN_ADDR: &str = "127.0.0.1:3001";
const CONFIG_ENV: &str = "WIST_GATEWAY_CONFIG";
/// 显式设置即覆盖文件值；显式置空 = 回到默认 SQLite 文件存储。
const ENV_DATABASE_URL: &str = "WIST_GATEWAY_DATABASE_URL";
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
    pub bootstrap_token_ttl_seconds: i64,
    pub credential_ttl_seconds: i64,
    /// 旧版单文件 JSON 存储路径：现在只作为「首次启动一次性导入」的来源。
    pub store_file: PathBuf,
    /// SQLite DSN（显式配置时），留空则由 [`AdminConfig::sqlite_path`] 决定。
    pub database_url: Option<String>,
    /// 默认 SQLite 数据库文件（DSN 未配置时使用）。
    pub sqlite_path: PathBuf,
    pub trust_bundle: String,
    /// agent 客户端证书签发 CA（证书 + 私钥，PEM）。这是与「服务端叶证书的 CA」**分开**的
    /// 一把 CA（见 `docs/design/agent-identity-mtls.md` §4.1）。两者**要么都给、要么都不给**：
    /// 都缺 = 关闭 mTLS 签发（双轨期，bearer 路径照常）。
    pub agent_ca_cert_file: Option<PathBuf>,
    pub agent_ca_key_file: Option<PathBuf>,
    /// 签发的 agent 客户端证书有效期（秒）。缺省 37 天 = 保底 30 天 + 提前 7 天续期（§4.2）。
    pub client_cert_ttl_seconds: i64,
    pub install_script_signing_private_key_file: PathBuf,
    pub install_script_signing_public_key_pem: String,
    pub tenant_id: String,
    pub environment_id: String,
    pub victoria_metrics_url: String,
    /// 用途推断规则表（策展数据）。未配置时：事实照常入库，但不产出建议。
    pub purpose_rules_file: Option<PathBuf>,
    /// 发现方向策略表（策展数据）。未配置时：不下发该端点，Agent 回落到自己的内建默认值。
    pub discovery_policies_file: Option<PathBuf>,
    /// 采集内容三件套（catalog / packs / templates，策展数据）。
    /// 三者**要么都给、要么都不给** —— 内容集内部互相引用，缺一不可。
    pub content_catalog_file: Option<PathBuf>,
    pub content_packs_file: Option<PathBuf>,
    pub content_templates_file: Option<PathBuf>,
    /// 数据面订阅端的内部接入端点（明文 HTTP，只应绑环回）。
    /// `None` = 关闭订阅（见 [`RawIngestConfig`]）。
    pub ingest_listen_addr: Option<String>,
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
    #[serde(default)]
    store: RawStoreConfig,
    #[serde(default)]
    purpose: RawPurposeConfig,
    #[serde(default)]
    discovery: RawDiscoveryConfig,
    #[serde(default)]
    content: RawContentConfig,
    #[serde(default)]
    ingest: RawIngestConfig,
}

/// `[ingest]` 段：数据面（warp-parse）**订阅端**的内部接入端点。
///
/// 为什么不复用 `server.listen_addr`：那张监听是 HTTPS（自签证书），而数据面的 sink
/// 连接器**没有 TLS 参数**，打不进来。按设计这就是「数据面 → 网关的**内部信任边界**」
/// （见 doc/design/center/agent-work-delivery-plan.md §4），所以是**明文 HTTP 且只绑环回**。
///
/// 缺省（无此段）→ **默认开启**，否则数据面上报落地无处可去；
/// 显式置空（`listen_addr = ""`）→ 关闭，即网关不订阅数据面。
#[derive(Debug, Default, Deserialize)]
struct RawIngestConfig {
    #[serde(default)]
    listen_addr: Option<String>,
}

/// `[purpose]` 段。缺省时不装载规则表：摘要照常入库，但不产出建议。
#[derive(Debug, Default, Deserialize)]
struct RawPurposeConfig {
    /// 源头是知识库仓 `wist-knowledge/purpose-rules.toml`，由部署侧提供给网关。
    /// 为什么不做内嵌默认副本：那会有两份真相，改规则时必然漂移。
    #[serde(default)]
    rules_file: Option<String>,
}

/// `[discovery]` 段。缺省时不装载策略表：不提供下发端点，Agent 用自己的内建默认值。
#[derive(Debug, Default, Deserialize)]
struct RawDiscoveryConfig {
    /// 源头是知识库仓 `wist-knowledge/aspect-policies.toml`，由部署侧提供给网关。
    /// 为什么不做内嵌默认副本：那会有两份真相，改策略时必然漂移。
    #[serde(default)]
    policies_file: Option<String>,
}

/// `[content]` 段。缺省时不装载内容目录（不影响事实 / 用途 / 清单）。
/// 三份文件互相引用，**要么都给、要么都不给**（校验在 `validate` 里）。
#[derive(Debug, Default, Deserialize)]
struct RawContentConfig {
    /// 源头是知识库仓 `wist-knowledge/catalog.toml`。
    #[serde(default)]
    catalog_file: Option<String>,
    /// `wist-knowledge/packs.toml`。
    #[serde(default)]
    packs_file: Option<String>,
    /// `wist-knowledge/templates.toml`。
    #[serde(default)]
    templates_file: Option<String>,
}

/// `[store]` 段。缺省（旧配置无此段）时回退到本地 SQLite 文件。
#[derive(Debug, Default, Deserialize)]
struct RawStoreConfig {
    /// 持久化 DSN，目前支持 `sqlite:` 前缀（如 `sqlite:state/wist-gateway.db`）。
    /// 留空 → 使用 `agent.store_file` 同目录下的 `wist-gateway.db`。
    #[serde(default)]
    database_url: Option<String>,
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
    #[serde(default = "default_bootstrap_token_ttl_seconds")]
    bootstrap_token_ttl_seconds: i64,
    #[serde(default = "default_credential_ttl_seconds")]
    credential_ttl_seconds: i64,
    #[serde(default = "default_store_file")]
    store_file: String,
    /// 外部信任锚文件（相对 config 目录的 PEM）。信任锚**只走文件**：证书不内联进本配置，
    /// 便于轮换（换证书只换文件），也免去把多行 PEM 塞进 TOML。
    trust_bundle_file: String,
    /// agent 客户端证书签发 CA（相对 config 目录的 PEM）。两者同给同缺，见 [`AdminConfig`]。
    #[serde(default)]
    agent_ca_cert_file: Option<String>,
    #[serde(default)]
    agent_ca_key_file: Option<String>,
    #[serde(default = "default_client_cert_ttl_seconds")]
    client_cert_ttl_seconds: i64,
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
        let trust_bundle = read_trust_bundle_file(config_dir, &raw.agent.trust_bundle_file)?;
        Ok(Self {
            listen_addr: expand_env(&raw.server.listen_addr)?,
            public_base_url: trim_trailing_slash(expand_env(&raw.server.public_base_url)?),
            tls_cert_file: absolutize_path(config_dir, Path::new(&tls_cert_file)),
            tls_key_file: absolutize_path(config_dir, Path::new(&tls_key_file)),
            admin_api_token_hash: sha256_hex(&admin_api_token),
            bootstrap_token_ttl_seconds: raw.agent.bootstrap_token_ttl_seconds,
            credential_ttl_seconds: raw.agent.credential_ttl_seconds,
            store_file: absolutize_path(config_dir, Path::new(&expand_env(&raw.agent.store_file)?)),
            database_url: resolved_database_url(&raw.store)?,
            sqlite_path: default_sqlite_path(config_dir, &raw.agent.store_file)?,
            trust_bundle,
            agent_ca_cert_file: resolve_optional_agent_ca_path(
                config_dir,
                raw.agent.agent_ca_cert_file.as_deref(),
            )?,
            agent_ca_key_file: resolve_optional_agent_ca_path(
                config_dir,
                raw.agent.agent_ca_key_file.as_deref(),
            )?,
            client_cert_ttl_seconds: raw.agent.client_cert_ttl_seconds,
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
            purpose_rules_file: normalize_optional(
                raw.purpose
                    .rules_file
                    .as_deref()
                    .map(expand_env)
                    .transpose()?,
            )
            .map(|value| absolutize_path(config_dir, Path::new(&value))),
            discovery_policies_file: normalize_optional(
                raw.discovery
                    .policies_file
                    .as_deref()
                    .map(expand_env)
                    .transpose()?,
            )
            .map(|value| absolutize_path(config_dir, Path::new(&value))),
            content_catalog_file: normalize_optional(
                raw.content
                    .catalog_file
                    .as_deref()
                    .map(expand_env)
                    .transpose()?,
            )
            .map(|value| absolutize_path(config_dir, Path::new(&value))),
            content_packs_file: normalize_optional(
                raw.content
                    .packs_file
                    .as_deref()
                    .map(expand_env)
                    .transpose()?,
            )
            .map(|value| absolutize_path(config_dir, Path::new(&value))),
            content_templates_file: normalize_optional(
                raw.content
                    .templates_file
                    .as_deref()
                    .map(expand_env)
                    .transpose()?,
            )
            .map(|value| absolutize_path(config_dir, Path::new(&value))),
            ingest_listen_addr: match raw.ingest.listen_addr.as_deref() {
                // 缺省（无 `[ingest]` 段）= 开，默认只绑环回；显式置空 = 关。
                None => Some(DEFAULT_INGEST_LISTEN_ADDR.to_string()),
                Some(value) => normalize_optional(Some(expand_env(value)?)),
            },
        })
    }

    /// agent CA 的（证书文件, 私钥文件）。两者都配了才返回 `Some` —— 也就是这台网关启用了
    /// agent 客户端证书签发/验证（mTLS）。见 `docs/design/agent-identity-mtls.md` §4.1。
    pub fn agent_ca_files(&self) -> Option<(&Path, &Path)> {
        match (
            self.agent_ca_cert_file.as_deref(),
            self.agent_ca_key_file.as_deref(),
        ) {
            (Some(cert), Some(key)) => Some((cert, key)),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        require_non_empty("server.listen_addr", &self.listen_addr)?;
        require_https_url("server.public_base_url", &self.public_base_url)?;
        require_existing_file("server.tls_cert_file", &self.tls_cert_file)?;
        require_existing_file("server.tls_key_file", &self.tls_key_file)?;
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
        require_positive_seconds(
            "agent.client_cert_ttl_seconds",
            self.client_cert_ttl_seconds,
        )?;
        require_agent_ca_together(
            self.agent_ca_cert_file.as_deref(),
            self.agent_ca_key_file.as_deref(),
        )?;
        // 启动时就把 CA 读一遍：文件坏了/不是 PEM，现在就报出来，而不是等第一次签发或握手才炸。
        if let Some((cert_file, key_file)) = self.agent_ca_files() {
            crate::infra::agent_ca::AgentCa::load(cert_file, key_file)
                .map_err(config_validation)?;
        }
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
        if let Some(rules_file) = self.purpose_rules_file.as_deref() {
            require_existing_file("purpose.rules_file", rules_file)?;
            // 用**真实的装载器**做结构化校验（不只是 TOML 语法）：规则表写错必须在启动时
            // 就被拒，而不是静默降级成「不推断」。
            //
            // 取舍：这是 infra 调 app（同 crate 内允许，非硬循环）。要彻底消掉这层反向引用，
            // 得把 PurposeRule* 的类型与装载器从 `app/purpose.rs` 挪到 `infra/`，
            // 只把 `infer` 留在 app —— 当下换来的是 fail-fast，值得。
            crate::app::purpose::load_rule_table(rules_file).map_err(|err| {
                config_validation(format!(
                    "purpose.rules_file {}: {err}",
                    rules_file.display()
                ))
            })?;
        }
        if let Some(policies_file) = self.discovery_policies_file.as_deref() {
            require_existing_file("discovery.policies_file", policies_file)?;
            // 同 purpose：用**真实的装载器**做结构化校验，策略表写错必须在启动时被拒，
            // 而不是静默降级成「不下发」（那会让 agentd 悄悄回落内建默认值）。
            crate::app::discovery_policy::load_policy_table(policies_file).map_err(|err| {
                config_validation(format!(
                    "discovery.policies_file {}: {err}",
                    policies_file.display()
                ))
            })?;
        }
        // 内容三件套：要么都给、要么都不给；给了就逐一存在 + 用**真实装载器**校验
        // （模板引用写错必须在启动时被拒，而不是等到展开时才发现）。
        let content_provided = [
            self.content_catalog_file.is_some(),
            self.content_packs_file.is_some(),
            self.content_templates_file.is_some(),
        ]
        .iter()
        .filter(|present| **present)
        .count();
        if content_provided != 0 && content_provided != 3 {
            return Err(config_validation(
                "content.*: catalog_file / packs_file / templates_file 必须同时提供（缺一不可）",
            ));
        }
        if let (Some(catalog), Some(packs), Some(templates)) = (
            self.content_catalog_file.as_deref(),
            self.content_packs_file.as_deref(),
            self.content_templates_file.as_deref(),
        ) {
            require_existing_file("content.catalog_file", catalog)?;
            require_existing_file("content.packs_file", packs)?;
            require_existing_file("content.templates_file", templates)?;
            crate::app::content::load_content(catalog, packs, templates)
                .map_err(|err| config_validation(format!("content: {err}")))?;
        }
        if let Some(database_url) = self.database_url.as_deref()
            && !database_url.starts_with("sqlite:")
        {
            return Err(config_validation(format!(
                "unsupported store.database_url scheme (this build implements SQLite only): {database_url}"
            )));
        }
        if let Some(ingest_addr) = self.ingest_listen_addr.as_deref() {
            // 这个监听器是**明文 HTTP**：地址写错必须在启动时被拒，而不是等到第一个
            // 数据面帧打进来才发现。也不允许与 TLS 监听撞端口（两者语义完全不同）。
            if ingest_addr.parse::<std::net::SocketAddr>().is_err() {
                return Err(config_validation(format!(
                    "ingest.listen_addr must be host:port, got {ingest_addr}"
                )));
            }
            if ingest_addr == self.listen_addr {
                return Err(config_validation(format!(
                    "ingest.listen_addr must differ from server.listen_addr ({ingest_addr}): \
                     the ingest endpoint is plain HTTP and must not share the TLS listener"
                )));
            }
        }
        Ok(())
    }

    /// 安装脚本分发地址（基址取配置里的 `server.public_base_url`）。
    ///
    /// **运行期分发不要用这个**：基址应取「网关对外地址」（管理面设置，未设置时回落
    /// 配置值），见 [`Self::install_script_url_at`]。
    pub fn install_script_url(&self, arch: &str) -> String {
        self.install_script_url_at(&self.public_base_url, arch)
    }

    /// 同 [`Self::install_script_url`]，但基址由调用方给出（网关对外地址）。
    pub fn install_script_url_at(&self, base: &str, arch: &str) -> String {
        format!(
            "{}/api/v1/agent/install/{arch}/install.sh",
            trim_base_url(base)
        )
    }

    /// 安装包分发地址（基址取配置里的 `server.public_base_url`）；运行期见
    /// [`Self::agent_package_url_at`]。
    pub fn agent_package_url(&self) -> String {
        self.agent_package_url_at(&self.public_base_url)
    }

    /// 同 [`Self::agent_package_url`]，但基址由调用方给出。
    pub fn agent_package_url_at(&self, base: &str) -> String {
        format!("{}/api/v1/agent/packages/current", trim_base_url(base))
    }

    /// 某个内容寻址 id 的安装包下载地址（基址由调用方给出，通常取
    /// `effective_advertise_base`）。
    ///
    /// 与 [`Self::agent_package_url_at`] 同一口径，只是路径尾部是 `package_id` 而非
    /// `current`；由网关派生，避免前端自己拼。
    pub fn agent_package_url_by_id_at(&self, base: &str, package_id: &str) -> String {
        format!("{}/api/v1/agent/packages/{package_id}", trim_base_url(base))
    }

    /// Agent 初始配置地址（基址取配置里的 `server.public_base_url`）；运行期见
    /// [`Self::agent_initial_config_url_at`]。
    pub fn agent_initial_config_url(&self) -> String {
        self.agent_initial_config_url_at(&self.public_base_url)
    }

    /// 同 [`Self::agent_initial_config_url`]，但基址由调用方给出。
    pub fn agent_initial_config_url_at(&self, base: &str) -> String {
        format!("{}/api/v1/agent/initial-config", trim_base_url(base))
    }

    /// 管理面设置的安装包**本地缓存**路径（单例）。
    ///
    /// 设置来源地址时网关会把制品拉到这里，之后所有安装都从这份缓存分发；
    /// 放在 SQLite 库同目录（`state/`）下，便于随 `state/` 一起备份或清理。
    pub fn install_package_cache_path(&self) -> PathBuf {
        let state_dir = self.sqlite_path.parent().unwrap_or(Path::new("."));
        state_dir.join("install-package").join("agent-package")
    }

    /// 内容寻址的安装包**按条副本**路径：每个录入过的包单独存一份（升级要按条目取包）。
    ///
    /// 与单例 [`Self::install_package_cache_path`] 是两回事：那个 `agent-package` 是
    /// 「当前生效来源」的单文件缓存（安装仍用它），这里 `history/<package_id>` 是历史里
    /// 每个包各自的副本。调用方写入前会确保 parent 目录存在（见 `install_package::write_cache_to`）。
    pub fn install_package_history_path(&self, package_id: &str) -> PathBuf {
        let state_dir = self.sqlite_path.parent().unwrap_or(Path::new("."));
        state_dir
            .join("install-package")
            .join("history")
            .join(package_id)
    }

    /// 知识库内容包副本的**根目录**：`<state>/knowledge/`。
    ///
    /// 与安装包缓存同一约定：放在 SQLite 库同目录（`state/`）下，随 `state/` 一起备份或清理。
    /// 目录下每个包一份（`<package_id>/`）；与安装包不同的是，这里是**目录**（解开的五份
    /// 数据加 `manifest.json`），而且**每版都要留着**：在跑的常驻工作锁在它展开时那一版
    /// 目录上（见 `docs/design/knowledge-content-management.md` §4）。
    pub fn knowledge_dir(&self) -> PathBuf {
        let state_dir = self.sqlite_path.parent().unwrap_or(Path::new("."));
        state_dir.join("knowledge")
    }

    /// 某一个知识库内容包的目录。
    pub fn knowledge_package_dir(&self, package_id: &str) -> PathBuf {
        self.knowledge_dir().join(package_id)
    }

    /// 采集日志（数据面转发的 `LOGRAW:` 记录）的本地落盘文件。
    ///
    /// 与安装包缓存同一约定：放在 SQLite 库同目录（`state/`）下，随 `state/` 一起备份或清理。
    /// 为什么先落文件而不是入库：日志是无界的观测流，保留期与索引键尚未定档 ——
    /// 先落 NDJSON（可以 `tail`、可以 `grep`），等保留策略定了再考虑入库。
    pub fn agent_log_file(&self) -> PathBuf {
        let state_dir = self.sqlite_path.parent().unwrap_or(Path::new("."));
        state_dir.join("logs").join("agent-logs.ndjson")
    }
}

fn default_bootstrap_token_ttl_seconds() -> i64 {
    900
}

fn default_credential_ttl_seconds() -> i64 {
    30 * 24 * 60 * 60
}

fn default_client_cert_ttl_seconds() -> i64 {
    crate::infra::agent_ca::DEFAULT_CLIENT_CERT_TTL_SECONDS
}

fn default_victoria_metrics_url() -> String {
    "http://127.0.0.1:18429".to_string()
}

fn default_store_file() -> String {
    "state/wist-gateway-store.json".to_string()
}

/// 未配置 `database_url` 时的默认 SQLite 库：与旧存储文件同目录。
fn default_sqlite_path(config_dir: &Path, store_file: &str) -> Result<PathBuf, ConfigError> {
    let store_file = absolutize_path(config_dir, Path::new(&expand_env(store_file)?));
    let file_name = store_file
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("wist-gateway-store.json")
        .replace(".json", ".db");
    Ok(store_file.with_file_name(file_name))
}

/// `database_url` 的解析：文件值 → 环境变量覆盖（显式置空等于「回到默认 SQLite 文件」）。
fn resolved_database_url(raw: &RawStoreConfig) -> Result<Option<String>, ConfigError> {
    let file_value = match raw.database_url.as_deref() {
        Some(value) => Some(expand_env(value)?),
        None => None,
    };
    let value = match env::var(ENV_DATABASE_URL) {
        Ok(value) => Some(value),
        Err(_) => file_value,
    };
    Ok(normalize_optional(value))
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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

/// 读 agent 的信任锚文件（相对 config 目录的 PEM）。
fn read_trust_bundle_file(config_dir: &Path, file: &str) -> Result<String, ConfigError> {
    let resolved = absolutize_path(config_dir, Path::new(&expand_env(file)?));
    fs::read_to_string(&resolved).map_err(|err| {
        config_io(format!(
            "failed to read agent.trust_bundle_file {}: {err}",
            resolved.display()
        ))
    })
}

/// 拼路径前把基址的尾斜杠裁掉：管理面设置的对外地址允许带 `/` 收尾。
fn trim_base_url(base: &str) -> &str {
    base.trim_end_matches('/')
}

/// 解析可选的 agent CA 路径（相对 config 目录）。
fn resolve_optional_agent_ca_path(
    config_dir: &Path,
    value: Option<&str>,
) -> Result<Option<PathBuf>, ConfigError> {
    let value = match value {
        Some(value) => normalize_optional(Some(expand_env(value)?)),
        None => None,
    };
    Ok(value.map(|value| absolutize_path(config_dir, Path::new(&value))))
}

/// agent CA 的证书与私钥必须**同给同缺**：只有一半是配置错误，宁可起不来也不静默降级。
fn require_agent_ca_together(
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
) -> Result<(), ConfigError> {
    match (cert_file, key_file) {
        (None, None) => Ok(()),
        (Some(cert), Some(key)) => {
            require_existing_file("agent.agent_ca_cert_file", cert)?;
            require_existing_file("agent.agent_ca_key_file", key)
        }
        (Some(_), None) => Err(config_validation(
            "agent.agent_ca_cert_file is set but agent.agent_ca_key_file is missing",
        )),
        (None, Some(_)) => Err(config_validation(
            "agent.agent_ca_key_file is set but agent.agent_ca_cert_file is missing",
        )),
    }
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
///
/// `pub(crate)`：管理面设置「网关对外地址」时要按同一口径校验（它同样会被拼进
/// 安装命令），两处绝不能各写一份。
pub(crate) fn contains_shell_metacharacters(value: &str) -> bool {
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
    if value.len() >= min {
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
    use std::sync::atomic::{AtomicU64, Ordering};
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
        unsafe {
            env::set_var("WARP_INSIGHT_TEST_ADMIN_API_TOKEN", "test-admin-token");
        }
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000/"
admin_api_token = "${WARP_INSIGHT_TEST_ADMIN_API_TOKEN}"

[agent]
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let config = AdminConfig::load_from_path(&path).expect("config loads");

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
    }

    #[test]
    fn relative_config_path_is_absolutized_against_current_dir() {
        let cwd = env::current_dir().expect("current dir");
        let path = absolutize_config_path(Path::new("wist-gateway.toml")).expect("path");

        assert!(path.is_absolute());
        assert_eq!(path, cwd.join("wist-gateway.toml"));
    }

    #[test]
    fn relative_paths_are_absolutized_against_config_dir() {
        let dir = env::temp_dir().join(format!("wist-gateway-dir-{}", unique_suffix()));
        fs::create_dir_all(&dir).expect("create dir");
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
enrollment_token = "test-token"
trust_bundle_file = "trust-bundle.pem"
install_script_signing_private_key_file = "install-signing-ed25519.pkcs8.pem"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        )
        .expect("write config");
        fs::write(dir.join("admin-tls.crt.pem"), "cert").expect("write cert");
        fs::write(dir.join("admin-tls.key.pem"), "key").expect("write key");
        fs::write(dir.join("trust-bundle.pem"), "bundle").expect("write trust bundle");

        let config = AdminConfig::load_from_path(&config_path).expect("config loads");

        assert_eq!(config.tls_cert_file, dir.join("admin-tls.crt.pem"));
        assert_eq!(config.tls_key_file, dir.join("admin-tls.key.pem"));
        assert_eq!(
            config.install_script_signing_private_key_file,
            dir.join("install-signing-ed25519.pkcs8.pem")
        );
        let _ = fs::remove_dir_all(dir);
    }

    const RULES_TOML: &str = r#"
purpose_version = 1
[[rule_set]]
rule_set_id = "macos-v1"
platform = "macos"
baseline_class = "MacDaily"
weak_score = 20
"#;

    /// 一份合法的发现策略表：七个方向各一条（校验要求不许缺/重）。
    const DISCOVERY_POLICIES: &str = r#"
policy_version = 1
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

    /// 生成一份最小可用配置，其中 `[purpose]` 表体由调用方给出（可为空）。
    /// `[purpose]` 放在最前面：`write_temp_config` 会在文末补签名私钥行，
    /// 那行应落在 `[agent]` 里而不是 `[purpose]` 里。
    fn config_with_purpose(purpose_body: &str) -> String {
        format!(
            "[purpose]\n{purpose_body}\n\n[server]\nlisten_addr = \"127.0.0.1:3000\"\npublic_base_url = \"https://127.0.0.1:3000\"\nadmin_api_token = \"test-admin-token\"\n\n[agent]\ntrust_bundle = \"internal-ca-stub\"\ntenant_id = \"tenant-default\"\nenvironment_id = \"env-default\"\n",
        )
    }

    /// 同 `config_with_purpose`，但给出的是 `[discovery]` 表体。
    fn config_with_discovery(discovery_body: &str) -> String {
        format!(
            "[discovery]\n{discovery_body}\n\n[server]\nlisten_addr = \"127.0.0.1:3000\"\npublic_base_url = \"https://127.0.0.1:3000\"\nadmin_api_token = \"test-admin-token\"\n\n[agent]\ntrust_bundle = \"internal-ca-stub\"\ntenant_id = \"tenant-default\"\nenvironment_id = \"env-default\"\n",
        )
    }

    #[test]
    fn purpose_rules_file_is_none_when_unset_or_blank() {
        let unset = write_temp_config(&config_with_purpose(""));
        let config = AdminConfig::load_from_path(&unset).expect("config loads");
        assert_eq!(config.purpose_rules_file, None);

        // 空串必须归成 None；否则会变成 config 目录本身，校验时报“不是文件”。
        let blank = write_temp_config(&config_with_purpose("rules_file = \"\""));
        let config = AdminConfig::load_from_path(&blank).expect("config loads");
        assert_eq!(config.purpose_rules_file, None);
    }

    #[test]
    fn purpose_rules_file_is_absolutized_and_must_load() {
        // 规则表写进 temp_dir（与 write_temp_config 同目录），所以相对路径可解析。
        let rules = write_temp_file(RULES_TOML);
        let name = rules
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string();
        let path = write_temp_config(&config_with_purpose(&format!("rules_file = \"{name}\"")));
        let config = AdminConfig::load_from_path(&path).expect("config loads");
        assert_eq!(config.purpose_rules_file.as_deref(), Some(rules.as_path()));

        // 配了就必须能读到：不存在的文件在启动时就被拒。
        let missing =
            write_temp_config(&config_with_purpose("rules_file = \"no-such-rules.toml\""));
        assert!(AdminConfig::load_from_path(&missing).is_err());

        // 语法坏掉同样在启动时被拒，不拖到“收到第一份事实才报错”。
        let broken = write_temp_file("[[rule_set]\nbroken");
        let broken_name = broken
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string();
        let path = write_temp_config(&config_with_purpose(&format!(
            "rules_file = \"{broken_name}\""
        )));
        assert!(AdminConfig::load_from_path(&path).is_err());
    }

    #[test]
    fn discovery_policies_file_is_none_when_unset_or_blank() {
        let unset = write_temp_config(&config_with_discovery(""));
        let config = AdminConfig::load_from_path(&unset).expect("config loads");
        assert_eq!(config.discovery_policies_file, None);

        // 空串必须归成 None；否则会变成 config 目录本身，校验时报“不是文件”。
        let blank = write_temp_config(&config_with_discovery("policies_file = \"\""));
        let config = AdminConfig::load_from_path(&blank).expect("config loads");
        assert_eq!(config.discovery_policies_file, None);
    }

    #[test]
    fn discovery_policies_file_is_absolutized_and_must_load() {
        // 策略表写进 temp_dir（与 write_temp_config 同目录），所以相对路径可解析。
        let policies = write_temp_file(DISCOVERY_POLICIES);
        let name = policies
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string();
        let path = write_temp_config(&config_with_discovery(&format!(
            "policies_file = \"{name}\""
        )));
        let config = AdminConfig::load_from_path(&path).expect("config loads");
        assert_eq!(
            config.discovery_policies_file.as_deref(),
            Some(policies.as_path())
        );

        // 配了就必须能读到：不存在的文件在启动时就被拒。
        let missing = write_temp_config(&config_with_discovery(
            "policies_file = \"no-such-policies.toml\"",
        ));
        assert!(AdminConfig::load_from_path(&missing).is_err());

        // 语法坏掉同样在启动时被拒，不拖到“Agent 来拉表才发现”。
        let broken = write_temp_file("policy_version = 1\n[[policies]\nbroken");
        let broken_name = broken
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string();
        let path = write_temp_config(&config_with_discovery(&format!(
            "policies_file = \"{broken_name}\""
        )));
        assert!(AdminConfig::load_from_path(&path).is_err());

        // 语法合法但**内容非法**（缺方向）也要在启动时被拒 —— 这正是把真实装载器
        // 接进 validate 的意义：否则一份半截表会被当成配好了而下发。
        let incomplete = write_temp_file(
            "policy_version = 1\npublished_at = \"x\"\n[[policies]]\naspect = \"host\"\ndefault_interval_seconds = 900\nmin_interval_seconds = 300\nmax_interval_seconds = 3600\nbaseline = true\nenabled_by_default = true\nplatforms = [\"linux\"]\n",
        );
        let incomplete_name = incomplete
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string();
        let path = write_temp_config(&config_with_discovery(&format!(
            "policies_file = \"{incomplete_name}\""
        )));
        let err = AdminConfig::load_from_path(&path).expect_err("incomplete table rejected");
        assert!(err.to_string().contains("discovery.policies_file"), "{err}");
    }

    #[test]
    fn rejects_missing_tls_certificate_file() {
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
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            missing_cert.display(),
            key_file.display(),
        ));

        let err = AdminConfig::load_from_path(&path).expect_err("missing TLS cert rejected");

        assert!(err.to_string().contains("server.tls_cert_file"));
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(key_file);
    }

    #[test]
    fn rejects_short_admin_api_token() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
admin_api_token = "short"

[agent]
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let err = AdminConfig::load_from_path(&path).expect_err("short token rejected");

        assert!(err.to_string().contains("server.admin_api_token"));
        assert!(err.to_string().contains("at least 8 bytes"));
        let _ = fs::remove_file(path);
    }

    /// `init-config` 直接把仓库里的 `wist-gateway.toml` 模板写出去（`default_config_text`），
    /// 所以模板里的键名必须仍是当前配置结构认的 —— 否则现场 `wist-gateway init-config`
    /// 生成的配置一启动就报 missing field。改模板/改结构时这条会当场报。
    #[test]
    fn generated_config_template_parses() {
        let text = default_config_text("test-admin-token");
        let parsed: RawAdminConfig = toml::from_str(&text).expect("config template parses");

        assert_eq!(parsed.server.listen_addr, "127.0.0.1:3000");
        assert_eq!(parsed.server.public_base_url, "https://127.0.0.1:3000");
        assert_eq!(parsed.agent.tenant_id, "tenant-default");
        assert_eq!(parsed.agent.environment_id, "env-default");
        // 安装包不是配置项（`agent.package_file` 已删）：模板里不该再有这个键。
        assert!(!text.contains("package_file"));
    }

    /// 0.1.8 起 `agent.package_file` 已删。既有部署渲染出的配置里还留着这一行，
    /// 把镜像升上去后必须照常启动 —— 所以 `RawAgentConfig` **有意不**给 deny_unknown_fields。
    #[test]
    fn legacy_agent_package_file_key_does_not_block_startup() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
admin_api_token = "test-admin-token"

[agent]
package_file = "/config/wist-agentd.tar.gz"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let config = AdminConfig::load_from_path(&path).expect("legacy key must not block startup");

        assert_eq!(config.public_base_url, "https://127.0.0.1:3000");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_long_bootstrap_token_ttl() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000"
admin_api_token = "test-admin-token"

[agent]
bootstrap_token_ttl_seconds = 7200
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let err = AdminConfig::load_from_path(&path).expect_err("long ttl rejected");

        assert!(
            err.to_string()
                .contains("agent.bootstrap_token_ttl_seconds")
        );
        assert!(err.to_string().contains("less than or equal to 3600"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_http_public_base_url() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "0.0.0.0:3000"
public_base_url = "http://127.0.0.1:3000"
admin_api_token = "test-admin-token"

[agent]
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let err = AdminConfig::load_from_path(&path).expect_err("insecure URL rejected");

        assert!(err.to_string().contains("must start with https://"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn accepts_https_public_base_url() {
        let path = write_temp_config(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://localhost:3000/"
admin_api_token = "test-admin-token"

[agent]
enrollment_token = "test-token"
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
        );

        let config = AdminConfig::load_from_path(&path).expect("https config loads");

        assert_eq!(config.public_base_url, "https://localhost:3000");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_public_base_url_with_shell_metacharacters() {
        let text = r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://127.0.0.1:3000\"; touch /tmp/pwned"
admin_api_token = "test-admin-token"

[agent]
trust_bundle = "internal-ca-stub"
tenant_id = "tenant-default"
environment_id = "env-default"
"#;
        let path = write_temp_config(text);

        let err = AdminConfig::load_from_path(&path).expect_err("injected URL rejected");

        assert!(
            err.to_string()
                .contains("unsafe in generated install scripts")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn loads_trust_bundle_from_file() {
        let bundle_path = env::temp_dir().join(format!("trust-bundle-{}.pem", unique_suffix()));
        fs::write(
            &bundle_path,
            "-----BEGIN CERTIFICATE-----\nMIIBfromfile\n-----END CERTIFICATE-----\n",
        )
        .expect("write trust bundle");
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://localhost:3000/"
admin_api_token = "test-admin-token"

[agent]
trust_bundle_file = "{}"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            bundle_path.display()
        ));

        let config = AdminConfig::load_from_path(&path).expect("config loads");

        assert_eq!(
            config.trust_bundle,
            "-----BEGIN CERTIFICATE-----\nMIIBfromfile\n-----END CERTIFICATE-----\n"
        );
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(bundle_path);
    }

    #[test]
    fn missing_trust_bundle_file_is_an_error() {
        let missing = env::temp_dir().join(format!("does-not-exist-{}.pem", unique_suffix()));
        let path = write_temp_config(&format!(
            r#"
[server]
listen_addr = "127.0.0.1:3000"
public_base_url = "https://localhost:3000/"
admin_api_token = "test-admin-token"

[agent]
trust_bundle_file = "{}"
tenant_id = "tenant-default"
environment_id = "env-default"
"#,
            missing.display()
        ));

        assert!(AdminConfig::load_from_path(&path).is_err());
        let _ = fs::remove_file(path);
    }

    // ── `[content]` 三件套 ────────────────────────────────────────────

    /// 把三份内容写进 temp 目录（与 `write_temp_config` 同目录），再用相对路径引用。
    fn config_with_content(catalog: &str, packs: &str, templates: &str) -> String {
        let catalog_file = write_temp_file(catalog);
        let packs_file = write_temp_file(packs);
        let templates_file = write_temp_file(templates);
        let rel = |path: &PathBuf| {
            path.file_name()
                .expect("name")
                .to_string_lossy()
                .to_string()
        };
        format!(
            "[content]\ncatalog_file = \"{}\"\npacks_file = \"{}\"\ntemplates_file = \"{}\"\n\n[server]\nlisten_addr = \"127.0.0.1:3000\"\npublic_base_url = \"https://127.0.0.1:3000\"\nadmin_api_token = \"test-admin-token\"\n\n[agent]\ntrust_bundle = \"internal-ca-stub\"\ntenant_id = \"tenant-default\"\nenvironment_id = \"env-default\"\n",
            rel(&catalog_file),
            rel(&packs_file),
            rel(&templates_file),
        )
    }

    #[test]
    fn content_files_are_none_when_unset_or_blank() {
        let unset = write_temp_config(&config_with_purpose(""));
        let config = AdminConfig::load_from_path(&unset).expect("config loads");
        assert_eq!(config.content_catalog_file, None);
        assert_eq!(config.content_packs_file, None);
        assert_eq!(config.content_templates_file, None);

        let blank = write_temp_config(
            "[content]\ncatalog_file = \"\"\npacks_file = \"\"\ntemplates_file = \"\"\n\n[server]\nlisten_addr = \"127.0.0.1:3000\"\npublic_base_url = \"https://127.0.0.1:3000\"\nadmin_api_token = \"test-admin-token\"\n\n[agent]\ntrust_bundle = \"internal-ca-stub\"\ntenant_id = \"tenant-default\"\nenvironment_id = \"env-default\"\n",
        );
        let config = AdminConfig::load_from_path(&blank).expect("blank content loads as unset");
        assert_eq!(config.content_catalog_file, None);
    }

    #[test]
    fn content_files_must_all_be_provided() {
        // 只给一份：内容集内部互相引用（模板 → 包 → 单元），缺一不可。
        let catalog_file = write_temp_file("catalog_version = 1\nunits = []\n");
        let body = format!(
            "[content]\ncatalog_file = \"{}\"\n\n[server]\nlisten_addr = \"127.0.0.1:3000\"\npublic_base_url = \"https://127.0.0.1:3000\"\nadmin_api_token = \"test-admin-token\"\n\n[agent]\ntrust_bundle = \"internal-ca-stub\"\ntenant_id = \"tenant-default\"\nenvironment_id = \"env-default\"\n",
            catalog_file.file_name().expect("name").to_string_lossy(),
        );
        let path = write_temp_config(&body);
        let err = AdminConfig::load_from_path(&path).expect_err("partial content must be rejected");
        assert!(err.to_string().contains("同时提供"), "{err}");
    }

    #[test]
    fn content_files_are_validated_at_load() {
        // 三份都在，但内容不合法（这里 catalog 无单元）→ 启动就被拒，而不是静默不装载。
        let body = config_with_content("catalog_version = 1\nunits = []\n", "", "");
        let path = write_temp_config(&body);
        let err = AdminConfig::load_from_path(&path).expect_err("invalid content must be rejected");
        assert!(err.to_string().contains("content"), "{err}");
    }

    fn write_temp_config(content: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("wist-gateway-{}.toml", unique_suffix()));
        let key_path = path.with_extension("ed25519.pkcs8.pem");
        let tls_cert_path = path.with_extension("tls.crt.pem");
        let tls_key_path = path.with_extension("tls.key.pem");
        let bundle_path = path.with_extension("trust-bundle.pem");
        write_install_signing_key(&key_path);
        fs::write(&tls_cert_path, "cert").expect("write TLS cert");
        fs::write(&tls_key_path, "key").expect("write TLS key");
        fs::write(
            &bundle_path,
            "-----BEGIN CERTIFICATE-----\ntest-bundle\n-----END CERTIFICATE-----\n",
        )
        .expect("write trust bundle");
        // 信任锚只走文件：把内联 `trust_bundle = ...` 改写成 `trust_bundle_file = "<...>"`；
        // 原配置若没有锚字段，再注入一行（见下方 inject_agent_field）。
        let mut has_bundle = false;
        let content = content
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                if trimmed.starts_with("trust_bundle =") {
                    has_bundle = true;
                    let indent = &line[..line.len() - trimmed.len()];
                    format!("{indent}trust_bundle_file = \"{}\"", bundle_path.display())
                } else {
                    if trimmed.starts_with("trust_bundle_file =") {
                        has_bundle = true;
                    }
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let content = if content.contains("install_script_signing_private_key_file") {
            content
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
        let content = if has_bundle {
            content
        } else {
            inject_agent_field(
                &content,
                "trust_bundle_file",
                &bundle_path.display().to_string(),
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

    fn inject_agent_field(content: &str, key: &str, value: &str) -> String {
        let mut output = Vec::new();
        let mut inserted = false;
        for line in content.lines() {
            output.push(line.to_string());
            if !inserted && line.trim() == "[agent]" {
                output.push(format!("{key} = \"{value}\""));
                inserted = true;
            }
        }
        assert!(inserted, "test config must include [agent]");
        format!("{}\n", output.join("\n"))
    }

    fn write_temp_file(content: &str) -> PathBuf {
        let path = env::temp_dir().join(format!("warp-insight-agent-package-{}", unique_suffix()));
        fs::write(&path, content).expect("write file");
        path
    }

    fn unique_suffix() -> u128 {
        // 加一个自增序号：只用纳秒时，并行跑的测试有几率拿到同一个后缀从而互相覆写
        // 临时配置文件（曾表现为「不存在的策略表竟然装载成功」这种偶发失败）。
        // `src/api/tests.rs` 的同名函数早就踩过并这么修了，这里补上。
        static NEXT_SUFFIX: AtomicU64 = AtomicU64::new(1);
        let seq = NEXT_SUFFIX.fetch_add(1, Ordering::Relaxed) as u128;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
            + seq
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

    /// 只给一半的 agent CA 是配置错误：宁可起不来，也不静默降级成「没有 mTLS」。
    #[test]
    fn agent_ca_requires_certificate_and_key_together() {
        let (ca_cert_name, _) = write_agent_ca_files();
        let only_cert = write_temp_config(&agent_config_toml(&format!(
            "agent_ca_cert_file = \"{ca_cert_name}\"\n"
        )));
        let err = AdminConfig::load_from_path(&only_cert).expect_err("cert without key");
        assert!(err.to_string().contains("agent_ca_key_file"), "{err}");
        let _ = fs::remove_file(only_cert);

        let (_, ca_key_name) = write_agent_ca_files();
        let only_key = write_temp_config(&agent_config_toml(&format!(
            "agent_ca_key_file = \"{ca_key_name}\"\n"
        )));
        let err = AdminConfig::load_from_path(&only_key).expect_err("key without cert");
        assert!(err.to_string().contains("agent_ca_cert_file"), "{err}");
        let _ = fs::remove_file(only_key);
    }

    /// 文件不是可解析的 CA 时，配置加载就应失败（fail fast），而不是等签发/握手才炸。
    #[test]
    fn agent_ca_with_unparsable_certificate_fails_at_load() {
        let cert = write_temp_file("not a certificate");
        let key = write_temp_file("not a key");
        let path = write_temp_config(&agent_config_toml(&format!(
            "agent_ca_cert_file = \"{}\"\nagent_ca_key_file = \"{}\"\n",
            file_name(&cert),
            file_name(&key),
        )));
        let err = AdminConfig::load_from_path(&path).expect_err("unparsable CA");
        assert!(err.to_string().contains("agent CA certificate"), "{err}");
        let _ = fs::remove_file(path);
    }

    /// 两个都不给 = 关闭 mTLS 签发（双轨期），且签发有效期缺省 37 天（= 保底 30 + 提前 7）。
    #[test]
    fn agent_ca_absent_disables_mtls_and_defaults_ttl_to_37_days() {
        let path = write_temp_config(&agent_config_toml(""));
        let config = AdminConfig::load_from_path(&path).expect("config loads");

        assert!(config.agent_ca_cert_file.is_none());
        assert!(config.agent_ca_key_file.is_none());
        assert_eq!(
            config.client_cert_ttl_seconds,
            crate::infra::agent_ca::DEFAULT_CLIENT_CERT_TTL_SECONDS
        );
        assert_eq!(config.client_cert_ttl_seconds, 37 * 24 * 60 * 60);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn agent_ca_paths_are_absolutized_and_ttl_override_is_honored() {
        let (ca_cert_name, ca_key_name) = write_agent_ca_files();
        let path = write_temp_config(&agent_config_toml(&format!(
            "agent_ca_cert_file = \"{ca_cert_name}\"\nagent_ca_key_file = \"{ca_key_name}\"\nclient_cert_ttl_seconds = 1000\n",
        )));
        let config = AdminConfig::load_from_path(&path).expect("config loads");

        assert_eq!(
            config.agent_ca_cert_file,
            Some(env::temp_dir().join(&ca_cert_name))
        );
        assert_eq!(
            config.agent_ca_key_file,
            Some(env::temp_dir().join(&ca_key_name))
        );
        assert_eq!(config.client_cert_ttl_seconds, 1000);
        assert!(config.agent_ca_files().is_some(), "both paths = mTLS on");
        let _ = fs::remove_file(path);
    }

    /// 一份可用的 agent CA（证书 + 私钥）PEM，落到临时目录，返回**文件名**（相对临时目录）。
    fn write_agent_ca_files() -> (String, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        };
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Wist Test Agent CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let key = KeyPair::generate().expect("ca key");
        let certificate = params.self_signed(&key).expect("ca cert");
        let cert_path = write_temp_file(&certificate.pem());
        let key_path = write_temp_file(&key.serialize_pem());
        (file_name(&cert_path), file_name(&key_path))
    }

    fn file_name(path: &Path) -> String {
        path.file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string()
    }

    /// 最小的可加载配置：`[server]` + `[agent]`，其余交给 `write_temp_config` 注入。
    fn agent_config_toml(extra_agent_lines: &str) -> String {
        format!(
            "[server]\nlisten_addr = \"127.0.0.1:3000\"\npublic_base_url = \"https://127.0.0.1:3000\"\nadmin_api_token = \"test-admin-token\"\n\n[agent]\ntenant_id = \"tenant-default\"\nenvironment_id = \"env-default\"\n{extra_agent_lines}",
        )
    }
}
