// @jumo generated
// @jumo hash=46ea6f5515c8cd4b

use std::{
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    extract::{connect_info::ConnectInfo, Request, State},
    middleware::{from_fn_with_state, Next},
    response::Response,
    Router,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("init-config") {
        return init_config_command(args.get(1).map(String::as_str));
    }
    let config =
        wist_gateway::infra::AdminConfig::load_from_env().map_err(|err| err.into_boxed_std())?;
    let addr = config.listen_addr.clone();
    let tls_config = wist_gateway::infra::load_admin_tls_config(&config)?;
    let listener = TcpListener::bind(&addr).await?;
    println!("wist-gateway listening on https://{addr}");
    serve_tls(listener, wist_gateway::api::router(config), tls_config).await?;
    Ok(())
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
            let io = TokioIo::new(tls_stream);
            // Inject the real peer address so rate limiting can bucket per client and
            // cannot be bypassed with spoofed x-real-ip / x-forwarded-for headers.
            let service = service.layer(from_fn_with_state(peer_addr, inject_connect_info));
            let service = TowerToHyperService::new(service);
            let builder = Builder::new(TokioExecutor::new());
            if let Err(err) = builder.serve_connection(io, service).await {
                eprintln!("failed to serve HTTPS connection from {peer_addr}: {err}");
            }
        });
    }
}

async fn inject_connect_info(
    State(peer): State<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(ConnectInfo::<SocketAddr>(peer));
    next.run(request).await
}
