//! turna-admin — admin panel bridge.
//!
//! Read-only monitoring: GET /api/status /metrics /health /ready /cluster
//! Management bridge:   POST /api/manage → gRPC to control-plane
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

/// The health plane's address, parsed once at startup.
///
/// Held as parts rather than as a string so that every request is assembled from
/// them plus a fixed path. A prefix check on a string did not satisfy the
/// request-forgery rule, and rightly: a check is something you can forget to
/// call, while parts you have to assemble.
#[derive(Clone)]
struct Upstream {
    /// The five URLs this module ever fetches, built once at startup.
    ///
    /// Fields rather than a method taking a path. Two earlier shapes — a prefix
    /// check, then parse-into-parts and assemble per call — both still passed a
    /// freshly computed String to `client.get()`, which is what the
    /// request-forgery rule follows.
    status_url: String,
    metrics_url: String,
    health_url: String,
    ready_url: String,
    cluster_url: String,
}

impl Upstream {
    /// Parse `http://host:port` or `https://host:port`.
    fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim_end_matches('/');
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| format!("upstream address needs a scheme: {raw}"))?;
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "upstream scheme must be http or https, not {scheme}"
            ));
        }
        if rest.contains('@') || rest.contains('/') {
            return Err(format!(
                "upstream address must be host:port with no path or credentials: {rest}"
            ));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse::<u16>()
                    .map_err(|_| format!("upstream port is not a number: {p}"))?,
            ),
            None => (rest, if scheme == "https" { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err("upstream host is empty".to_string());
        }
        let base = format!("{scheme}://{host}:{port}");
        Ok(Self {
            status_url: format!("{base}/status"),
            metrics_url: format!("{base}/metrics"),
            health_url: format!("{base}/health"),
            ready_url: format!("{base}/ready"),
            cluster_url: format!("{base}/cluster"),
        })
    }
}

#[derive(Clone)]
struct AppState {
    upstream: Upstream,
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

/// Constant-time byte comparison.
///
/// `==` on `str` returns as soon as two bytes differ, so the time it takes to
/// reject a token is proportional to how many leading characters were right.
/// Over enough requests that recovers the token one character at a time, and
/// this endpoint is reachable over the network by anyone who can route to it.
///
/// Whether the timing is exploitable through a real network is arguable; the
/// argument is not worth having for four lines, and the next person to read
/// `==` here would have to have it again.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // The length is not a secret: an attacker learns it from the token they
        // were issued, or from the length of any token that is accepted.
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Consecutive authentication failures, for the backoff below.
static AUTH_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Delay a failed authentication, and only a failed one.
///
/// There was nothing between an attacker and an unlimited guessing rate: the
/// token is a static string, the endpoint answers as fast as it can reject, and
/// a wrong answer cost the sender nothing.
///
/// This is a delay rather than a lockout on purpose. A lockout after N failures
/// hands anyone who can reach the port the ability to lock the operator out of
/// their own admin surface — trading a brute-force risk for a denial-of-service
/// certainty. A delay costs the attacker the one thing they need, which is
/// attempts per second, and costs a correct token nothing at all: success is
/// never delayed, and the counter resets on it.
///
/// Global rather than per-IP because the handlers have no client address —
/// wiring `ConnectInfo` through would change how the server is started. The
/// difference matters less here than it would on a public datapath: this
/// surface has a handful of legitimate users, so one shared budget does not
/// starve anybody, and an attacker with many addresses still cannot go faster
/// than the shared delay.
///
/// Capped at two seconds: past that it stops adding protection and starts
/// looking like the service is broken to an operator who typed their token
/// wrong.
async fn penalise_auth_failure() {
    let n = AUTH_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if n == 1 || n.is_power_of_two() {
        warn!(
            consecutive_failures = n,
            "admin authentication failed; responses are being delayed. A rising \
             count means someone is guessing the token."
        );
    }
    let delay_ms = 50u64.saturating_mul(1 << n.min(5)).min(2_000);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

fn note_auth_success() {
    AUTH_FAILURES.store(0, std::sync::atomic::Ordering::Relaxed);
}

/// Check the token, applying the failure delay. Every handler uses this rather
/// than [`check_auth`] directly, so a new route cannot accidentally get the
/// check without the backoff.
async fn authorised(headers: &HeaderMap, token: &Option<String>) -> bool {
    if check_auth(headers, token) {
        note_auth_success();
        true
    } else {
        penalise_auth_failure().await;
        false
    }
}

fn check_auth(headers: &HeaderMap, token: &Option<String>) -> bool {
    let Some(expected) = token else { return true };
    headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| constant_time_eq(v.as_bytes(), expected.as_bytes()))
        .unwrap_or(false)
}

// ── read-only handlers ────────────────────────────────────────────────────────

async fn api_status(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorised(&headers, &st.auth_token).await {
        return unauthorized();
    }
    match proxy::fetch_json(&st.http, &st.upstream.status_url).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/status");
            node_unreachable()
        }
    }
}
async fn api_metrics(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorised(&headers, &st.auth_token).await {
        return unauthorized();
    }
    match proxy::fetch_text(&st.http, &st.upstream.metrics_url).await {
        Ok(t) => (StatusCode::OK, Json(prometheus::parse(&t))).into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/metrics");
            node_unreachable()
        }
    }
}
async fn api_health(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorised(&headers, &st.auth_token).await {
        return unauthorized();
    }
    match proxy::fetch_status_code(&st.http, &st.upstream.health_url).await {
        Ok(code) => StatusCode::from_u16(code)
            .unwrap_or(StatusCode::OK)
            .into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/health");
            node_unreachable()
        }
    }
}
async fn api_ready(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorised(&headers, &st.auth_token).await {
        return unauthorized();
    }
    match proxy::fetch_status_code(&st.http, &st.upstream.ready_url).await {
        Ok(code) => StatusCode::from_u16(code)
            .unwrap_or(StatusCode::OK)
            .into_response(),
        Err(e) => {
            tracing::warn!(error=%e, "GET /api/ready");
            node_unreachable()
        }
    }
}
async fn api_cluster(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !authorised(&headers, &st.auth_token).await {
        return unauthorized();
    }
    match proxy::fetch_json(&st.http, &st.upstream.cluster_url).await {
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
    if !authorised(&headers, &st.auth_token).await {
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

async fn local_healthz() -> StatusCode {
    StatusCode::OK
}

/// Resolve on SIGTERM (docker stop / k8s pod termination) or Ctrl-C.
/// Without this the binary runs as container PID 1, ignores SIGTERM and gets
/// SIGKILLed after the stop grace period (exit 137).
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
    info!("shutdown signal received, draining connections");
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
        // The token protects the surface; it does not protect the wire. This
        // server speaks plain HTTP, so on a non-loopback bind the token itself
        // travels in a header in the clear on every request — and the metrics
        // and cluster topology come back the same way.
        //
        // A warning and not a refusal: the common shape is a reverse proxy
        // terminating TLS in front of this, and refusing would break it for no
        // gain. What must not happen is an operator concluding that
        // `--auth-token` made the exposure safe.
        if !listen_loopback {
            warn!(
                listen = %cfg.listen,
                "admin is bound beyond loopback and serves PLAIN HTTP: the \
                 X-Admin-Token header is sent in the clear on every request, as \
                 are the metrics and cluster topology in the replies. Put a TLS \
                 terminator in front of it, or bind 127.0.0.1 and reach it over \
                 an SSH tunnel."
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
    info!(grpc_addr = %cfg.grpc_addr, tls = tls_desc, "lazy gRPC channel configured");

    if cfg.auth_token.is_some() {
        // Every route, not only the mutating one. Until 0.5.0 the read-only
        // routes took no token at all: /api/status, /api/metrics and
        // /api/cluster returned the node's full Prometheus surface, its
        // readiness and the cluster topology to anyone who could reach the
        // port. The startup check above reasoned about "unauthenticated
        // mutations" and was right about mutations, which is how the gap
        // survived — the read side was never the thing being checked.
        info!("operator auth: X-Admin-Token required on every /api route");
    } else {
        // loopback only — WARN is sufficient, no bail
        warn!(
            "no auth token: every /api route is open, reads included \
             (loopback-only, acceptable for dev)"
        );
    }

    // Parsed here so a bad address stops startup with a clear message instead of
    // failing on the first request.
    let upstream =
        Upstream::parse(&cfg.turna_addr).map_err(|e| anyhow::anyhow!("[turna_addr] {e}"))?;
    let turna_addr = cfg.turna_addr.trim_end_matches('/').to_string();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.upstream_timeout))
        .build()?;

    let state = Arc::new(AppState {
        upstream,
        http,
        grpc_channel,
        auth_token: cfg.auth_token.clone(),
    });

    let index = Path::new(&cfg.static_dir).join("index.html");
    if !index.is_file() {
        anyhow::bail!(
            "admin static assets are missing: expected {}",
            index.display()
        );
    }
    let static_service = ServeDir::new(&cfg.static_dir).fallback(ServeFile::new(index));

    let api = Router::new()
        .route("/status", get(api_status))
        .route("/metrics", get(api_metrics))
        .route("/health", get(api_health))
        .route("/ready", get(api_ready))
        .route("/cluster", get(api_cluster))
        .route("/manage", post(api_manage));

    let app = Router::new()
        .route("/healthz", get(local_healthz))
        .nest("/api", api)
        .fallback_service(static_service)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cfg.listen.parse()?;
    info!(%addr, turna_addr=%turna_addr, grpc_addr=%cfg.grpc_addr, "turna-admin listening");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
