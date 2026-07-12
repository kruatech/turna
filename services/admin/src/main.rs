//! turna-admin — admin panel bridge.
//!
//! Stage 1 (read-only): GET /api/status /metrics /health /ready /cluster
//! Stage 2 (mutate):    POST /api/manage → gRPC to control-plane
//!
//! TLS modes for --grpc-addr:
//!   https://turna.krutilin.pro:5350  → TLS, system roots (Let's Encrypt)
//!   https://host:5350 + --tls-*      → mTLS with custom CA + client cert
//!   http://127.0.0.1:5350            → plaintext (loopback dev only)

mod grpc_client;
mod prometheus;
mod proxy;

use std::{net::SocketAddr, path::Path, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{info, warn};

use grpc_client::AdminTlsConfig;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "turna-admin",
    version,
    about = "turna admin panel bridge — read-only monitoring + gRPC management"
)]
struct Config {
    /// Address turna-admin listens on.
    #[arg(long, env = "TURNA_ADMIN_LISTEN", default_value = "127.0.0.1:8080")]
    listen: String,

    /// Node health/metrics address (:9090).
    #[arg(
        long,
        env = "TURNA_ADMIN_TURNA_ADDR",
        default_value = "http://127.0.0.1:9090"
    )]
    turna_addr: String,

    /// Control-plane gRPC address.
    /// Use https:// for TLS/mTLS (Let's Encrypt works automatically),
    /// http:// for plaintext loopback dev.
    /// Example: https://turna.krutilin.pro:5350
    #[arg(
        long,
        env = "TURNA_ADMIN_GRPC_ADDR",
        default_value = "http://127.0.0.1:5350"
    )]
    grpc_addr: String,

    /// Static assets directory (dist/).
    #[arg(long, env = "TURNA_ADMIN_STATIC_DIR", default_value = "./dist")]
    static_dir: String,

    /// Upstream health-server timeout, seconds.
    #[arg(long, env = "TURNA_ADMIN_UPSTREAM_TIMEOUT", default_value_t = 5)]
    upstream_timeout: u64,

    // ── mTLS (optional — only needed when control-plane requires client cert) ─
    /// CA cert PEM to verify control-plane server certificate.
    /// Not needed for Let's Encrypt (system roots are used automatically).
    #[arg(long, env = "TURNA_ADMIN_TLS_CA")]
    tls_ca: Option<PathBuf>,

    /// Client certificate PEM (only for mTLS mode).
    #[arg(long, env = "TURNA_ADMIN_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    /// Client private key PEM (only for mTLS mode).
    #[arg(long, env = "TURNA_ADMIN_TLS_KEY")]
    tls_key: Option<PathBuf>,

    // ── Operator auth (browser → admin) ───────────────────────────────────────
    /// Static token required in X-Admin-Token header for mutating requests.
    /// Unset = open access (safe only on loopback or trusted network).
    #[arg(long, env = "TURNA_ADMIN_AUTH_TOKEN")]
    auth_token: Option<String>,
}

impl Config {
    /// Resolve TLS config:
    /// - all three --tls-* set → mTLS
    /// - none set              → None (TLS with system roots for https://, plaintext for http://)
    /// - partial               → error
    fn tls_config(&self) -> anyhow::Result<Option<AdminTlsConfig>> {
        match (&self.tls_ca, &self.tls_cert, &self.tls_key) {
            (Some(ca), Some(cert), Some(key)) =>
                Ok(Some(AdminTlsConfig { ca_cert: ca.clone(), client_cert: cert.clone(), client_key: key.clone() })),
            (None, None, None) => Ok(None),
            _ => anyhow::bail!(
                "Incomplete mTLS config: set all three of --tls-ca, --tls-cert, --tls-key together, \
                 or none of them (for TLS with system roots or plaintext)."
            ),
        }
    }
}

#[derive(Clone)]
struct AppState {
    turna_addr: String,
    http: reqwest::Client,
    grpc_channel: tonic::transport::Channel,
    auth_token: Option<String>,
}

fn node_unreachable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "node_unreachable"})),
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "unauthorized",
         "hint": "Set X-Admin-Token header."})),
    )
        .into_response()
}

fn check_auth(headers: &HeaderMap, token: &Option<String>) -> bool {
    let Some(expected) = token else { return true };
    headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == expected)
        .unwrap_or(false)
}

// ── read-only handlers ────────────────────────────────────────────────────────

async fn api_status(State(st): State<Arc<AppState>>) -> Response {
    match proxy::fetch_json(&st.http, &format!("{}/status", st.turna_addr)).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/status");
            node_unreachable()
        }
    }
}
async fn api_metrics(State(st): State<Arc<AppState>>) -> Response {
    match proxy::fetch_text(&st.http, &format!("{}/metrics", st.turna_addr)).await {
        Ok(t) => (StatusCode::OK, Json(prometheus::parse(&t))).into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/metrics");
            node_unreachable()
        }
    }
}
async fn api_health(State(st): State<Arc<AppState>>) -> Response {
    match proxy::fetch_status_code(&st.http, &format!("{}/health", st.turna_addr)).await {
        Ok(code) => StatusCode::from_u16(code)
            .unwrap_or(StatusCode::OK)
            .into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/health");
            node_unreachable()
        }
    }
}
async fn api_ready(State(st): State<Arc<AppState>>) -> Response {
    match proxy::fetch_status_code(&st.http, &format!("{}/ready", st.turna_addr)).await {
        Ok(code) => StatusCode::from_u16(code)
            .unwrap_or(StatusCode::OK)
            .into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/ready");
            node_unreachable()
        }
    }
}
async fn api_cluster(State(st): State<Arc<AppState>>) -> Response {
    match proxy::fetch_json(&st.http, &format!("{}/cluster", st.turna_addr)).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(_) => (StatusCode::OK, Json(serde_json::json!([]))).into_response(),
    }
}

// ── mutate via gRPC ───────────────────────────────────────────────────────────

async fn api_manage(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if !check_auth(&headers, &st.auth_token) {
        return unauthorized();
    }
    let command = body["command"].as_str().unwrap_or("?");
    let params = body.get("params").cloned().unwrap_or(serde_json::json!({}));
    match grpc_client::dispatch(st.grpc_channel.clone(), command, &params).await {
        Ok(v) => {
            info!(command, "POST /api/manage ok");
            (StatusCode::OK, Json(v)).into_response()
        }
        Err(e) => {
            tracing::warn!(error=%e, command, "POST /api/manage failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string(), "command": command})),
            )
                .into_response()
        }
    }
}

async fn api_actions_not_implemented() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({"error": "not_implemented", "stage": 2})),
    )
        .into_response()
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::parse();
    let tls = cfg.tls_config()?;

    // Fail-closed: non-loopback without TLS → refuse.
    // (https:// is fine — TLS with system roots; http:// non-loopback → error)
    if !cfg.grpc_addr.starts_with("https://") {
        let host = cfg
            .grpc_addr
            .trim_start_matches("http://")
            .split(':')
            .next()
            .unwrap_or("");
        let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
        if !is_loopback {
            anyhow::bail!(
                "Refusing to connect to control-plane at {:?} without TLS. \
                 Use https:// for a remote address (e.g. https://turna.krutilin.pro:5350).",
                cfg.grpc_addr
            );
        }
    }

    // Fail-closed (symmetric with gRPC check above):
    // non-loopback listen + no auth token → refuse to start.
    // An admin exposed beyond localhost with unauthenticated mutations is a
    // security hole. Loopback-only is fine without a token (trusted dev setup).
    {
        let host = cfg.listen.split(':').next().unwrap_or("127.0.0.1");
        let listen_loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
        if !listen_loopback && cfg.auth_token.is_none() {
            anyhow::bail!(
                "Refusing to start: --listen {:?} is non-loopback but --auth-token is not set. \
                 Anyone who can reach port {} can execute mutating operations without \
                 authentication. Set --auth-token / TURNA_ADMIN_AUTH_TOKEN, or bind to \
                 127.0.0.1 for local-only access.",
                cfg.listen,
                cfg.listen.split(':').next_back().unwrap_or("8080"),
            );
        }
    }

    let grpc_channel = grpc_client::build_channel(&cfg.grpc_addr, tls.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!("gRPC channel to {}: {}", cfg.grpc_addr, e))?;

    let tls_desc = if tls.is_some() {
        "mTLS"
    } else if cfg.grpc_addr.starts_with("https://") {
        "TLS (system roots)"
    } else {
        "plaintext"
    };
    info!(grpc_addr = %cfg.grpc_addr, tls = tls_desc, "gRPC channel ready");

    if cfg.auth_token.is_some() {
        info!("operator auth: X-Admin-Token required for mutations");
    } else {
        // loopback only — WARN is sufficient, no bail
        warn!("no auth token — mutations unauthenticated (loopback-only, acceptable for dev)");
    }

    let turna_addr = cfg.turna_addr.trim_end_matches('/').to_string();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.upstream_timeout))
        .build()?;

    let state = Arc::new(AppState {
        turna_addr: turna_addr.clone(),
        http,
        grpc_channel,
        auth_token: cfg.auth_token.clone(),
    });

    let index = Path::new(&cfg.static_dir).join("index.html");
    let static_service = ServeDir::new(&cfg.static_dir).fallback(ServeFile::new(index));

    let api = Router::new()
        .route("/status", get(api_status))
        .route("/metrics", get(api_metrics))
        .route("/health", get(api_health))
        .route("/ready", get(api_ready))
        .route("/cluster", get(api_cluster))
        .route("/manage", post(api_manage))
        .route(
            "/actions/*rest",
            post(api_actions_not_implemented).get(api_actions_not_implemented),
        );

    let app = Router::new()
        .nest("/api", api)
        .fallback_service(static_service)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cfg.listen.parse()?;
    info!(%addr, turna_addr=%turna_addr, grpc_addr=%cfg.grpc_addr, "turna-admin listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
