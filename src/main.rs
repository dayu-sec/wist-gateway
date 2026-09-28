// @jumo generated
// @jumo hash=46ea6f5515c8cd4b

use std::{
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Router,
    extract::{Request, State, connect_info::ConnectInfo},
    middleware::{Next, from_fn_with_state},
    response::Response,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wist_gateway::infra::VerifiedAgentIdentity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("init-config") {
        return init_config_command(args.get(1).map(String::as_str));
    }
    let config =
        wist_gateway::infra::AdminConfig::load_from_env().map_err(|err| err.into_boxed_std())?;
    let addr = config.listen_addr.clone();
    let ingest_addr = config.ingest_listen_addr.clone();
    let store = build_store(&config).await?;
    // 配了 agent CA = 启用 mTLS（客户端证书验证）。双轨期没配就保持原来的「只要服务端证书」。
    let mtls_enabled = config.agent_ca_files().is_some();
    let tls_config = if let Some((agent_ca_file, _)) = config.agent_ca_files() {
        let agent_ca_pem = std::fs::read_to_string(agent_ca_file).map_err(|err| {
            format!(
                "failed to read agent CA certificate {}: {err}",
                agent_ca_file.display()
            )
        })?;
        wist_gateway::infra::load_agent_mtls_server_config(
            &config.tls_cert_file,
            &config.tls_key_file,
            &agent_ca_pem,
        )?
    } else {
        wist_gateway::infra::load_admin_tls_config(&config)?
    };
    // 两个监听共用一份状态：规则表、策略表、会话运行态与限流器都只能有一份。
    let state = wist_gateway::api::build_state(config, store);

    // 一次性工作的到期判定：过了截止的标 expired、预算尽的标 timed_out。
    // 与 agent 在不在线无关 —— 掉线的 agent 恰恰是活最容易卡住的时候。
    wist_gateway::api::spawn_one_shot_expiry_tick(state.store.clone());

    // 拒绝名单的周期 GC：条目只活到被吊销证书自然过期（§5.6），到点清掉。
    // 为什么不在启动扫一次就完：网关可能连续跑数周不重启，那只会在重启时扫。
    wist_gateway::api::spawn_revocation_gc_tick(state.store.clone());

    if let Some(ingest_addr) = ingest_addr {
        // 数据面（warp-parse）订阅端的**内部**接入端点：明文 HTTP，默认只绑环回。
        // 为什么不能复用下面的 HTTPS 监听：数据面的 sink 连接器没有 TLS 参数（见 api/ingest.rs）。
        let ingest_listener = TcpListener::bind(&ingest_addr).await?;
        println!("wist-gateway ingest listening on http://{ingest_addr} (data plane only)");
        let ingest_app = wist_gateway::api::ingest_router(state.clone());
        tokio::spawn(async move {
            if let Err(err) = axum::serve(ingest_listener, ingest_app).await {
                // 内部端点挂了不让整个网关跟着退：控制面还能用，只是不再订阅数据面。
                eprintln!("ingest listener stopped: {err}");
            }
        });
    } else {
        println!("wist-gateway ingest endpoint disabled ([ingest] listen_addr is empty)");
    }

    let listener = TcpListener::bind(&addr).await?;
    println!("wist-gateway listening on https://{addr}");
    serve_tls(
        listener,
        wist_gateway::api::router_with_state(state),
        tls_config,
        mtls_enabled,
    )
    .await?;
    Ok(())
}

/// 打开持久化后端（当前实现：SQLite），并在库为空时一次性导入旧版 JSON 存储。
async fn build_store(
    config: &wist_gateway::infra::AdminConfig,
) -> Result<Arc<dyn wist_gateway::infra::Store>, Box<dyn std::error::Error + Send + Sync>> {
    let store = match config.database_url.as_deref() {
        Some(database_url) => wist_gateway::infra::SqliteStore::connect(database_url)
            .await
            .map_err(|err| err.into_boxed_std())?,
        None => wist_gateway::infra::SqliteStore::connect_path(&config.sqlite_path)
            .await
            .map_err(|err| err.into_boxed_std())?,
    };
    match store.import_legacy_json(&config.store_file).await {
        Ok(true) => println!(
            "imported legacy store {} into the database",
            config.store_file.display()
        ),
        Ok(false) => {}
        // 导入失败不阻断启动：库本身可用，旧注册表可由 Agent 重新注册恢复。
        Err(err) => eprintln!(
            "warning: failed to import legacy store {}: {err}",
            config.store_file.display()
        ),
    }
    Ok(Arc::new(store))
}

/// Generate a wist-gateway.toml with a freshly random admin API token
/// (and the install-script signing key it references), so a newly initialized
/// admin never runs with a predictable or shared default token.
fn init_config_command(
    out_arg: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let token = wist_gateway::infra::new_admin_token()
        .map_err(|err| format!("failed to generate admin api token: {err}"))?;
    let out_path = out_arg
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(wist_gateway::infra::default_config_path()));
    let parent = out_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let state_dir = parent.join("state");
    let key_path = state_dir.join("install-script-signing-ed25519.pkcs8.pem");
    if !key_path.exists() {
        std::fs::create_dir_all(&state_dir)?;
        wist_gateway::infra::generate_install_script_signing_key(&key_path)?;
    }
    std::fs::write(&out_path, wist_gateway::infra::default_config_text(&token))?;
    println!("generated admin config: {}", out_path.display());
    println!("admin api token: {}", token);
    println!("install script signing key: {}", key_path.display());
    println!(
        "note: create a TLS certificate/key pair at {}/admin-tls.crt.pem and {}/admin-tls.key.pem before starting",
        state_dir.display(),
        state_dir.display(),
    );
    Ok(())
}

async fn serve_tls(
    listener: TcpListener,
    app: Router,
    tls_config: rustls::ServerConfig,
    mtls_enabled: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = app.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("failed TLS handshake from {peer_addr}: {err}");
                    return;
                }
            };
            // mTLS 开启时，从**已完成握手**的连接里取已验的客户端证书并解出 agent 身份。
            // 链验过了但认不出身份（缺 URI SAN / 段非法）就不当作已认证 ——
            // 交给应用层回 401，而不是静默落回未认证的 bearer 路径。
            let client_identity = if mtls_enabled {
                match wist_gateway::infra::peer_leaf_certificate_der(tls_stream.get_ref().1) {
                    Some(der) => match VerifiedAgentIdentity::from_certificate_der(&der) {
                        Ok(identity) => Some(identity),
                        Err(err) => {
                            eprintln!(
                                "mTLS client certificate from {peer_addr} has no usable agent identity: {err}"
                            );
                            None
                        }
                    },
                    None => None,
                }
            } else {
                None
            };
            let io = TokioIo::new(tls_stream);
            // Inject the real peer address so rate limiting can bucket per client and
            // cannot be bypassed with spoofed x-real-ip / x-forwarded-for headers.
            let context = ConnectionContext {
                peer: peer_addr,
                client_identity,
            };
            let service = service.layer(from_fn_with_state(context, inject_connection_context));
            let service = TowerToHyperService::new(service);
            let builder = Builder::new(TokioExecutor::new());
            if let Err(err) = builder.serve_connection(io, service).await {
                eprintln!("failed to serve HTTPS connection from {peer_addr}: {err}");
            }
        });
    }
}

/// 每条连接注入请求扩展的东西：对端地址（限流）与 mTLS 证书身份（鉴权）。
///
/// `client_identity` 只能由本进程在握手后写入 —— 它走 `request.extensions_mut()`，
/// 客户端无法通过 HTTP 头伪造。
#[derive(Clone)]
struct ConnectionContext {
    peer: SocketAddr,
    client_identity: Option<VerifiedAgentIdentity>,
}

async fn inject_connection_context(
    State(context): State<ConnectionContext>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(ConnectInfo::<SocketAddr>(context.peer));
    if let Some(identity) = context.client_identity {
        request.extensions_mut().insert(identity);
    }
    next.run(request).await
}
