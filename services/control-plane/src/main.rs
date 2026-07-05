//! Control plane service — gRPC management server.
//!
//! Runs alongside `turna-node`. Provides ops API for turnactl, dashboards, etc.
//!
//! # Configuration
//!
//! The control-plane reads its configuration from a TOML file (the same
//! `turn.toml` consumed by `turna-node`). The path is taken from:
//!
//! 1. First CLI argument: `turna-control-plane /etc/turna/turn.toml`, or
//! 2. `TURNA_CONFIG` env var, or
//! 3. If neither is set, the process runs in env-only mode using
//!    sensible defaults — useful for `cargo run` and for old-style
//!    deployments that pre-date this change.
//!
//! Whatever the file says, the following env vars OVERRIDE the file
//! when set to a non-empty value. This matches the pattern used by
//! Postgres / Grafana stack / Traefik — file is the artifact in git,
//! env carries the per-environment overrides:
//!
//! - `TURNA_GRPC_ADDR`     — bind address
//! - `TURNA_EXTERNAL_IP`   — IP to advertise to TURN clients
//! - `TURNA_GRPC_TLS_MODE` — `disabled` | `tls` | `mtls`
//! - `TURNA_GRPC_TLS_CERT` — path to server cert PEM file
//! - `TURNA_GRPC_TLS_KEY`  — path to server private-key PEM file
//! - `TURNA_GRPC_TLS_CA`   — path to CA cert PEM file (required for mtls)
//!
//! # Graceful shutdown
//!
//! The process listens for SIGTERM and SIGINT.  On signal:
//! 1. The gRPC server stops accepting new connections.
//! 2. Active streaming RPCs are cancelled via CancellationToken —
//!    clients receive a clean EOF, not a reset.
//! 3. The server waits up to `drain_timeout` seconds for streams to
//!    close, then exits.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{info, warn};

use turna_config::TurnaConfig;
use turna_control::{start_grpc_server, GrpcConfig, GrpcTlsConfig, TurnCoreImpl};
use turna_state_backend::{create_backend, Backend, BackendConfig};

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    turna_observability::init();

    // ── Load configuration ────────────────────────────────────────────────────
    // Resolution order: CLI arg → TURNA_CONFIG env → no file (env-only mode).
    let cfg_path: Option<String> = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("TURNA_CONFIG").ok());

    let file_cfg = match cfg_path.as_deref() {
        Some(p) => {
            info!(path = %p, "loading control-plane config from file");
            Some(
                TurnaConfig::load(p)
                    .map_err(|e| -> AnyError { format!("failed to load {p}: {e}").into() })?,
            )
        }
        None => {
            warn!(
                "no config file given (pass a path as the first argument or set \
                   TURNA_CONFIG); falling back to env-only mode with defaults"
            );
            None
        }
    };

    // ── Resolve effective settings (file → env override) ──────────────────────
    let grpc_addr = resolve_grpc_addr(&file_cfg)?;
    let external_ip = resolve_external_ip(&file_cfg);
    let tls = resolve_tls(&file_cfg)?;

    let tls_state = match tls.as_ref() {
        Some(_) => "enabled",
        None => "disabled",
    };
    info!(%grpc_addr, %external_ip, tls = tls_state,
          "turna control plane starting");

    // ── Wire dependencies ────────────────────────────────────────────────────
    let store = Arc::new(turna_session::AllocationStore::new(49152, 65535, 10000));
    let metrics = Arc::new(turna_health::Metrics::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let realm = resolve_realm(&file_cfg);
    let user_backend = build_user_backend(&file_cfg).await?;

    let mut core_impl = TurnCoreImpl::new(
        Arc::clone(&store),
        Arc::clone(&metrics),
        shutdown_tx.clone(),
    )
    .with_config(
        realm.clone(),
        external_ip,
        vec!["0.0.0.0:3478".into()],
        49152,
        65535,
        600,
        3600,
    );
    if let Some(backend) = user_backend {
        info!(%realm, "runtime user management enabled (state backend attached)");
        core_impl = core_impl.with_user_backend(backend);
    }
    let core = Arc::new(core_impl);

    // ── Signal handler ────────────────────────────────────────────────────────
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm =
                signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c           => info!("SIGINT received — shutting down"),
                _ = sigterm.recv()   => info!("SIGTERM received — shutting down"),
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            info!("SIGINT received — shutting down");
        }
        let _ = signal_tx.send(true);
    });

    let mut rx = shutdown_rx;
    let shutdown_fut = async move {
        rx.changed().await.ok();
    };

    let config = GrpcConfig {
        listen_addr: grpc_addr,
        tls,
        ..Default::default()
    };

    if let Err(e) = start_grpc_server(config, core, metrics, shutdown_fut).await {
        tracing::error!(%e, "gRPC server error");
    }

    info!("control plane stopped");
    Ok(())
}

/// Resolve the realm advertised to TURN clients. MUST match the nodes' realm,
/// or the long-term keys this control-plane derives will not verify on a node.
fn resolve_realm(file_cfg: &Option<TurnaConfig>) -> String {
    file_cfg
        .as_ref()
        .map(|c| c.turn.realm.clone())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "turna".into())
}

/// Build the shared state backend used for runtime user CRUD (R8). Only a
/// Tarantool backend is useful here: the control-plane is a separate process,
/// so an in-memory store would never reach the nodes. Returns `None` (user
/// management stays Unimplemented) when no usable backend is configured.
async fn build_user_backend(
    file_cfg: &Option<TurnaConfig>,
) -> Result<Option<Arc<Backend>>, AnyError> {
    let Some(cfg) = file_cfg else {
        warn!("no config file — runtime user management (AddUser) disabled (no state backend)");
        return Ok(None);
    };
    let b = &cfg.cluster.backend;
    let backend_cfg = match b.r#type.as_str() {
        "tarantool" => BackendConfig::Tarantool {
            uri: b.uri.clone(),
            user: if b.user.is_empty() {
                None
            } else {
                Some(b.user.clone())
            },
            password: if b.password.is_empty() {
                None
            } else {
                Some(b.password.clone())
            },
            pool_size: if b.pool_size == 0 {
                None
            } else {
                Some(b.pool_size)
            },
        },
        "memory" | "" => {
            warn!(
                "[cluster.backend].type is memory/empty — a control-plane user store would be                  process-local and NOT reach nodes; set type = \"tarantool\" for a cluster.                  Runtime user management disabled."
            );
            return Ok(None);
        }
        other => {
            warn!(backend = %other,
                  "unknown [cluster.backend].type; runtime user management disabled");
            return Ok(None);
        }
    };
    let backend = create_backend(&backend_cfg)
        .await
        .map_err(|e| -> AnyError { format!("state backend init failed: {e}").into() })?;
    Ok(Some(Arc::new(backend)))
}

/// Resolve the gRPC bind address from (in priority order):
/// 1. `TURNA_GRPC_ADDR` env (highest)
/// 2. `[management].listen` in the loaded config
/// 3. `127.0.0.1:5350` (default)
fn resolve_grpc_addr(file_cfg: &Option<TurnaConfig>) -> Result<SocketAddr, AnyError> {
    if let Ok(s) = std::env::var("TURNA_GRPC_ADDR") {
        if !s.is_empty() {
            return s.parse().map_err(|e| -> AnyError {
                format!("TURNA_GRPC_ADDR {s:?} is not a valid socket address: {e}").into()
            });
        }
    }
    if let Some(cfg) = file_cfg {
        return Ok(cfg.management.listen);
    }
    Ok("127.0.0.1:5350".parse().unwrap())
}

/// Resolve the externally-visible IP from (in priority order):
/// 1. `TURNA_EXTERNAL_IP` env
/// 2. `[turn].external_ip` in the loaded config
/// 3. `0.0.0.0` (best-effort, but warn — this should usually be set)
fn resolve_external_ip(file_cfg: &Option<TurnaConfig>) -> String {
    if let Ok(s) = std::env::var("TURNA_EXTERNAL_IP") {
        if !s.is_empty() {
            return s;
        }
    }
    if let Some(cfg) = file_cfg {
        if !cfg.turn.external_ip.is_empty() {
            return cfg.turn.external_ip.clone();
        }
    }
    warn!("external_ip is not configured (neither TURNA_EXTERNAL_IP nor [turn].external_ip)");
    "0.0.0.0".into()
}

/// Resolve TLS configuration. Same precedence as the other resolvers:
/// env wins when non-empty, otherwise the file's `[grpc]` section, otherwise
/// disabled.
///
/// We don't *just* read env here — we merge: if the file says `mtls` and
/// only `TURNA_GRPC_TLS_CERT` is overridden via env, the merged config has
/// the file's mode + ca and the env's cert. This lets operators ship a
/// committed file with the "shape" of the TLS config and supply only the
/// paths that differ per host (the usual pattern for cert rotation
/// drivers).
fn resolve_tls(file_cfg: &Option<TurnaConfig>) -> Result<Option<GrpcTlsConfig>, AnyError> {
    // Start with whatever the file says (or all-defaults if no file).
    let mut base = file_cfg
        .as_ref()
        .map(|c| c.grpc.clone())
        .unwrap_or_default();

    // Layer env overrides where the env value is non-empty.
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_MODE") {
        if !v.is_empty() {
            base.tls_mode = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_CERT") {
        if !v.is_empty() {
            base.tls_cert = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_KEY") {
        if !v.is_empty() {
            base.tls_key = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_CA") {
        if !v.is_empty() {
            base.tls_ca = v;
        }
    }

    match base.normalised_mode() {
        "disabled" => {
            warn!(
                "gRPC TLS is disabled — only safe when management.listen is bound \
                   to 127.0.0.1 / ::1. Set tls_mode = \"tls\" or \"mtls\" before exposing \
                   the control plane beyond localhost."
            );
            // If the operator wrote a typo (e.g. "Tls" with a capital), surface it.
            if !matches!(
                base.tls_mode.trim().to_ascii_lowercase().as_str(),
                "" | "disabled" | "tls" | "mtls"
            ) {
                return Err(format!(
                    "grpc.tls_mode = {:?} is invalid; use \"disabled\", \"tls\", or \"mtls\"",
                    base.tls_mode
                )
                .into());
            }
            Ok(None)
        }
        mode @ ("tls" | "mtls") => {
            if base.tls_cert.is_empty() {
                return Err(format!(
                    "grpc.tls_mode = {mode:?} but tls_cert is empty; set TURNA_GRPC_TLS_CERT \
                     or grpc.tls_cert in turn.toml"
                )
                .into());
            }
            if base.tls_key.is_empty() {
                return Err(format!(
                    "grpc.tls_mode = {mode:?} but tls_key is empty; set TURNA_GRPC_TLS_KEY \
                     or grpc.tls_key in turn.toml"
                )
                .into());
            }
            if mode == "mtls" && base.tls_ca.is_empty() {
                return Err(
                    "grpc.tls_mode = \"mtls\" but tls_ca is empty; mTLS requires a CA \
                     file to verify client certificates. Set TURNA_GRPC_TLS_CA or \
                     grpc.tls_ca in turn.toml"
                        .into(),
                );
            }
            info!(mode,
                  cert = %base.tls_cert,
                  key  = %base.tls_key,
                  ca   = %base.tls_ca,
                  "gRPC TLS enabled");

            // Sanity-check that the files exist now, not at first connection.
            // Better error story: fail at startup, not on the first client.
            for (name, path) in [("tls_cert", &base.tls_cert), ("tls_key", &base.tls_key)] {
                if !std::path::Path::new(path).exists() {
                    return Err(
                        format!("grpc.{name} = {path:?} but the file does not exist").into(),
                    );
                }
            }
            if mode == "mtls" && !std::path::Path::new(&base.tls_ca).exists() {
                return Err(format!(
                    "grpc.tls_ca = {:?} but the file does not exist",
                    base.tls_ca
                )
                .into());
            }

            Ok(Some(GrpcTlsConfig {
                server_cert: PathBuf::from(&base.tls_cert),
                server_key: PathBuf::from(&base.tls_key),
                client_ca_cert: PathBuf::from(&base.tls_ca),
            }))
        }
        _ => unreachable!("normalised_mode returns one of disabled|tls|mtls"),
    }
}
