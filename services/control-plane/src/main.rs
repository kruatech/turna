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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use turna_config::TurnaConfig;
use turna_control::{
    start_grpc_server, GrpcConfig, GrpcTlsConfig, RbacPolicy, RevocationList, TurnCoreImpl,
};
use turna_state_backend::{create_backend, now_ms, Backend, BackendConfig, CommandLogRetention};

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

    // ── Build the single effective configuration and validate it ──────────────
    // P0 #5: fold env overrides into one config, then run the FULL validator
    // BEFORE any listener binds — so an env override (e.g. TURNA_GRPC_ADDR to a
    // non-loopback address with TLS disabled) cannot bypass a production guard
    // that file-only validation would have caught.
    let cfg = build_effective_config(&file_cfg)?;
    let grpc_addr = cfg.management.listen;
    let external_ip = effective_external_ip(&cfg);
    let tls = build_tls(&cfg.grpc)?;

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
        // Advance the versioned legacy command-log migration in bounded,
        // resumable batches. The backend persists cursor/completion state, so a
        // process restart never restarts a whole-log Lua scan.
        let clog = cfg.cluster.command_log.clone();
        tokio::spawn(run_command_log_migration(
            Arc::clone(&backend),
            clog.batch_size.max(1),
            Arc::clone(&metrics),
            shutdown_tx.subscribe(),
        ));

        // Run command-log GC from the control-plane on the shared backend,
        // gated on a configured sweep interval. It runs in its own task and is
        // best-effort — GC never stalls the control-plane, only degrading
        // readiness on a sustained growing backlog or repeated backend errors.
        if clog.gc_enabled() {
            info!(
                interval_secs = clog.sweep_interval_secs,
                batch = clog.batch_size,
                "command-log GC enabled"
            );
            tokio::spawn(run_command_log_gc(
                Arc::clone(&backend),
                clog,
                Arc::clone(&metrics),
                shutdown_tx.subscribe(),
            ));
        }
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

    // Built before the server so a policy that would lock everyone out is
    // refused at startup rather than on the first request. `validate()` returns
    // warnings and errors separately: a typo in a role name is a warning because
    // a fleet mid-upgrade legitimately has configs naming permissions the older
    // binary does not check, while an enabled policy with no bindings is an error
    // because there is no reading of it that anybody meant.
    let rbac = {
        let r = &cfg.grpc.rbac;
        let roles = r
            .roles
            .iter()
            .map(|(name, perms)| (name.clone(), perms.iter().cloned().collect()))
            .collect();
        let policy = RbacPolicy::new(r.enabled, roles, r.bindings.clone());
        let (warnings, errors) = policy.validate();
        for w in &warnings {
            warn!("rbac: {w}");
        }
        if !errors.is_empty() {
            for e in &errors {
                tracing::error!("rbac: {e}");
            }
            return Err(format!("rbac configuration is unusable: {}", errors.join("; ")).into());
        }
        if policy.is_enabled() {
            info!(
                identities = r.bindings.len(),
                roles = r.roles.len() + 3,
                "RBAC enforcing"
            );
        } else {
            // Said out loud, because the alternative is an operator believing
            // roles are being enforced when the section is present but disabled.
            warn!(
                "RBAC is not enabled: every client with a valid certificate has \
                 full management access"
            );
        }
        Arc::new(policy)
    };

    let revoked = {
        let path = &cfg.grpc.revocation_list;
        if path.is_empty() {
            Arc::new(RevocationList::empty())
        } else {
            match RevocationList::load(path) {
                Ok(list) => {
                    info!(path = %path, revoked = list.len(),
                          "certificate revocation list loaded");
                    Arc::new(list)
                }
                // Refusing at deploy time is loud and happens when somebody is
                // looking. A list that is configured and silently empty looks
                // like protection and is not.
                Err(e) => return Err(format!("{e}").into()),
            }
        }
    };

    let config = GrpcConfig {
        listen_addr: grpc_addr,
        tls,
        ..Default::default()
    };

    if let Err(e) = start_grpc_server(config, core, metrics, rbac, revoked, shutdown_fut).await {
        tracing::error!(%e, "gRPC server error");
    }

    info!("control plane stopped");
    Ok(())
}

/// Advance the command-log schema migration one bounded backend batch at a
/// time. Tarantool owns the durable cursor and completion marker; this task is
/// only a retry/scheduling loop and never keeps migration state in process.
async fn run_command_log_migration(
    backend: Arc<Backend>,
    batch_size: usize,
    metrics: Arc<turna_health::Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    use std::sync::atomic::Ordering;

    const ERROR_DEGRADE_THRESHOLD: u32 = 3;
    let mut consecutive_errors = 0_u32;

    // #4 (B): stable per-process lease owner for the command-log migration.
    let migration_owner = format!("control-plane-{}", std::process::id());
    loop {
        if *shutdown.borrow() {
            info!("command-log migration stopping (shutdown)");
            return;
        }

        match backend
            .migrate_command_log_batch(batch_size, &migration_owner)
            .await
        {
            Ok(progress) => {
                consecutive_errors = 0;
                metrics
                    .command_log_migration_processed_total
                    .fetch_add(progress.processed_in_batch, Ordering::Relaxed);
                metrics
                    .command_log_migration_completed
                    .store(u64::from(progress.completed), Ordering::Relaxed);

                debug!(
                    processed_in_batch = progress.processed_in_batch,
                    total_processed = progress.total_processed,
                    cursor = %progress.cursor,
                    completed = progress.completed,
                    "command-log migration batch complete"
                );

                if progress.completed {
                    info!(
                        total_processed = progress.total_processed,
                        "command-log migration complete"
                    );
                    return;
                }

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    _ = shutdown.changed() => {
                        info!("command-log migration stopping (shutdown)");
                        return;
                    }
                }
            }
            Err(error) => {
                metrics
                    .command_log_migration_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                consecutive_errors = consecutive_errors.saturating_add(1);
                warn!(
                    %error,
                    consecutive_errors,
                    "command-log migration batch failed"
                );
                if consecutive_errors >= ERROR_DEGRADE_THRESHOLD {
                    metrics.set_readiness(turna_health::Readiness::Degraded);
                }

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = shutdown.changed() => {
                        info!("command-log migration stopping (shutdown)");
                        return;
                    }
                }
            }
        }
    }
}

/// Command-log GC sweep. Periodically prunes terminal commands + aged
/// idempotency records on the shared backend, exports counts/gauges, and
/// degrades readiness on a sustained growing backlog or repeated backend errors.
/// Best-effort: it never propagates failures. The degrade is sticky (no
/// auto-recovery) so a cleared backlog does not silently mask another
/// subsystem's degradation via the shared readiness gauge.
async fn run_command_log_gc(
    backend: Arc<Backend>,
    cfg: turna_config::CommandLogConfig,
    metrics: Arc<turna_health::Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    use std::sync::atomic::Ordering;

    let retention = CommandLogRetention {
        done_ms: cfg.retain_done_secs.saturating_mul(1000),
        failed_ms: cfg.retain_failed_secs.saturating_mul(1000),
        superseded_ms: cfg.retain_superseded_secs.saturating_mul(1000),
        expired_ms: cfg.retain_expired_secs.saturating_mul(1000),
        idempotency_ms: cfg.retain_idempotency_secs.saturating_mul(1000),
        batch: cfg.batch_size,
        max_batches: cfg.max_batches_per_sweep,
    };
    let base = Duration::from_secs(cfg.sweep_interval_secs.max(1));
    // Fixed per-process jitter (no rand dep): distinct pids desynchronise
    // multiple control-plane instances so they do not sweep in lockstep.
    let jitter = if cfg.sweep_jitter_secs > 0 {
        Duration::from_secs((std::process::id() as u64) % (cfg.sweep_jitter_secs + 1))
    } else {
        Duration::ZERO
    };

    const ERROR_DEGRADE_THRESHOLD: u32 = 3;
    const BACKLOG_GROWTH_THRESHOLD: u32 = 3;
    let mut consecutive_errors: u32 = 0;
    let mut backlog_growth_streak: u32 = 0;
    let mut prev_backlog: u64 = 0;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(base + jitter) => {}
            _ = shutdown.changed() => {
                info!("command-log GC sweep stopping (shutdown)");
                return;
            }
        }

        let stats = backend.gc_command_log(retention, now_ms()).await;

        metrics
            .command_log_gc_deleted_commands_total
            .fetch_add(stats.deleted_commands, Ordering::Relaxed);
        metrics
            .command_log_gc_deleted_idempotency_total
            .fetch_add(stats.deleted_idempotency, Ordering::Relaxed);
        metrics
            .command_log_terminal_remaining
            .store(stats.terminal_remaining, Ordering::Relaxed);
        metrics
            .command_log_oldest_unfinished_ms
            .store(stats.oldest_unfinished_age_ms, Ordering::Relaxed);

        if stats.errors > 0 {
            metrics
                .command_log_gc_errors_total
                .fetch_add(stats.errors, Ordering::Relaxed);
            consecutive_errors = consecutive_errors.saturating_add(1);
        } else {
            consecutive_errors = 0;
        }

        if stats.terminal_remaining > prev_backlog {
            backlog_growth_streak = backlog_growth_streak.saturating_add(1);
        } else {
            backlog_growth_streak = 0;
        }
        prev_backlog = stats.terminal_remaining;

        if consecutive_errors >= ERROR_DEGRADE_THRESHOLD
            || backlog_growth_streak >= BACKLOG_GROWTH_THRESHOLD
        {
            warn!(
                consecutive_errors,
                backlog_growth_streak,
                terminal_remaining = stats.terminal_remaining,
                "command-log GC unhealthy; marking control-plane Degraded"
            );
            metrics.set_readiness(turna_health::Readiness::Degraded);
        }

        debug!(
            deleted_commands = stats.deleted_commands,
            deleted_idempotency = stats.deleted_idempotency,
            terminal_remaining = stats.terminal_remaining,
            oldest_unfinished_ms = stats.oldest_unfinished_age_ms,
            errors = stats.errors,
            "command-log GC sweep complete"
        );
    }
}

/// Build the single effective configuration: start from the file (or all
/// defaults in env-only mode), fold in the env overrides, then run the FULL
/// validator. Nothing binds until this returns Ok. This is the P0 #5 guard —
/// env overrides can no longer disable a production check that file-based
/// validation would enforce.
fn build_effective_config(file_cfg: &Option<TurnaConfig>) -> Result<TurnaConfig, AnyError> {
    let mut cfg = file_cfg.clone().unwrap_or_default();

    // Preserve the historical env-only bind (127.0.0.1:5350) when neither a
    // file nor an explicit TURNA_GRPC_ADDR is given, instead of the config
    // struct's [management].listen default. Keeps `cargo run` behaviour stable.
    let grpc_addr_env_set = std::env::var("TURNA_GRPC_ADDR")
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if file_cfg.is_none() && !grpc_addr_env_set {
        cfg.management.listen = "127.0.0.1:5350".parse().expect("valid default addr");
    }

    if let Ok(v) = std::env::var("TURNA_GRPC_ADDR") {
        if !v.is_empty() {
            cfg.management.listen = v.parse().map_err(|e| -> AnyError {
                format!("TURNA_GRPC_ADDR {v:?} is not a valid socket address: {e}").into()
            })?;
        }
    }
    if let Ok(v) = std::env::var("TURNA_EXTERNAL_IP") {
        if !v.is_empty() {
            cfg.turn.external_ip = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_MODE") {
        if !v.is_empty() {
            cfg.grpc.tls_mode = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_CERT") {
        if !v.is_empty() {
            cfg.grpc.tls_cert = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_KEY") {
        if !v.is_empty() {
            cfg.grpc.tls_key = v;
        }
    }
    if let Ok(v) = std::env::var("TURNA_GRPC_TLS_CA") {
        if !v.is_empty() {
            cfg.grpc.tls_ca = v;
        }
    }

    cfg.validate().map_err(|e| -> AnyError {
        format!("effective configuration invalid after env overrides: {e}").into()
    })?;
    Ok(cfg)
}

/// Externally-visible IP: the effective config's `[turn].external_ip`, or a
/// best-effort `0.0.0.0` with a warning when unset (production validation
/// already requires it to be set when `production = true`).
fn effective_external_ip(cfg: &TurnaConfig) -> String {
    if cfg.turn.external_ip.is_empty() {
        warn!("external_ip is not configured (neither TURNA_EXTERNAL_IP nor [turn].external_ip)");
        "0.0.0.0".into()
    } else {
        cfg.turn.external_ip.clone()
    }
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

/// Translate the (already-validated, env-folded) `[grpc]` section into a
/// runtime `GrpcTlsConfig`. `build_effective_config` has already merged env
/// overrides and validated the whole config, so no env reading or mode
/// validation happens here — we only add a startup file-existence check
/// (a nicer error than a first-client failure).
fn build_tls(grpc: &turna_config::GrpcConfigSection) -> Result<Option<GrpcTlsConfig>, AnyError> {
    let base = grpc.clone();

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
                // "tls" => server-only; "mtls" => require & verify client cert.
                require_client_auth: mode == "mtls",
            }))
        }
        _ => unreachable!("normalised_mode returns one of disabled|tls|mtls"),
    }
}
