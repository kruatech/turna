//! Turna TURN server entry point
//!
//! Modes:
//! - tokio (default): multi-threaded async, works everywhere
//! - io_uring (--features io-uring): io_uring for main socket + tokio for relay sockets

mod af_xdp_listener;
mod bulk_load;
mod dtls_listener;
mod failover;
mod heartbeat;
mod quic_listener;
mod runtime_management;
mod writer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use turna_auth::{AuthMode, AuthRegistry, UserKeys};
use turna_cluster::gossip::{run_gossip, GossipConfig};
use turna_cluster::{ClusterNode, HashRing};
use turna_config::{
    ClusterConfig, RuntimeSnapshot as ConfigRuntimeSnapshot, RuntimeValidationCtx, TurnConfig,
    TurnaConfig,
};
use turna_health::Metrics;
use turna_observability::{SamplingConfig, TelemetryConfig};
use turna_relay::processor::ClusterRouting;
use turna_session::AllocationStore;
use turna_state_backend::{create_backend, BackendConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }
    let dump_mode = if let Some(pos) = args.iter().position(|a| a == "--dump-config") {
        args.remove(pos);
        Some(DumpMode::Masked)
    } else if let Some(pos) = args.iter().position(|a| a == "--dump-config-raw") {
        args.remove(pos);
        Some(DumpMode::Raw)
    } else {
        None
    };
    let config_path: Option<String> = args.get(1).cloned();

    if let Some(mode) = dump_mode {
        turna_observability::init();
        let path = config_path.ok_or_else(|| -> Box<dyn std::error::Error> {
            "--dump-config requires a config file path".into()
        })?;
        let cfg = TurnaConfig::load(&path)?;
        print_dumped_config(&cfg, mode);
        return Ok(());
    }

    let (
        config,
        cluster,
        health_listen,
        tls_cfg,
        tenants,
        runtime_validation_ctx,
        bootstrap_runtime,
    ) = match config_path {
        Some(path) => {
            let root = TurnaConfig::load(&path)?;
            let runtime_validation_ctx = RuntimeValidationCtx::from_config(&root);
            let bootstrap_runtime = ConfigRuntimeSnapshot::from_config(&root);
            let health_listen = root.health.listen;
            let tls_cfg = root.tls.clone();
            (
                root.turn,
                root.cluster,
                health_listen,
                tls_cfg,
                root.tenants,
                runtime_validation_ctx,
                bootstrap_runtime,
            )
        }
        None => {
            turna_observability::init();
            info!("no config file, using defaults");
            let root = TurnaConfig::default();
            let runtime_validation_ctx = RuntimeValidationCtx::from_config(&root);
            let bootstrap_runtime = ConfigRuntimeSnapshot::from_config(&root);
            (
                root.turn,
                root.cluster,
                "0.0.0.0:9090".parse().unwrap(),
                root.tls,
                root.tenants,
                runtime_validation_ctx,
                bootstrap_runtime,
            )
        }
    };

    let obs = &config.observability;
    let telemetry_config = TelemetryConfig {
        service_name: "turna".into(),
        service_version: env!("CARGO_PKG_VERSION").into(),
        instance_id: hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into()),
        otlp_endpoint: obs.otlp_endpoint.clone(),
        json_logs: obs.json_logs,
        sampling: SamplingConfig {
            base_ratio: obs.trace_sample_rate,
            max_spans_per_second: obs.max_spans_per_second,
            always_sample_errors: true,
            latency_threshold_us: 10_000,
            always_sample_methods: vec!["Allocate".into(), "Refresh".into()],
        },
        ..Default::default()
    };

    let _telemetry_guard =
        turna_observability::init_with_config(telemetry_config).unwrap_or_else(|e| {
            eprintln!("telemetry init failed: {e} — falling back to basic logging");
            turna_observability::init();
            turna_observability::init_with_config(Default::default())
                .expect("fallback telemetry init")
        });

    info!(listen = %config.listen, realm = %config.realm, "starting turna");

    // #3 (audit-2 §9.1): fail fast if DTLS is requested in config but this
    // binary was built without the `dtls` feature. Otherwise `spawn_dtls`
    // launches a task whose `DtlsServer::run` immediately returns
    // `NotSupported`; the error is swallowed in the task and the node keeps
    // serving without DTLS while the operator believes it is enabled.
    if config.dtls.enabled && !turna_transport::dtls::DTLS_AVAILABLE {
        return Err(
            "[turn.dtls] is enabled in the configuration, but this binary \
                    was built without DTLS support; rebuild with `--features dtls` \
                    or disable [turn.dtls]"
                .into(),
        );
    }

    // Same fail-fast for QUIC. `quic_listener::spawn_quic` is a no-op stub on a
    // build without the `quic` feature (it only logs), so `[turn.quic] enabled`
    // would otherwise leave the listener silently unstarted. WebTransport needs
    // the additional `web-transport` feature; `web_transport = true` is the
    // config default, so a `--features quic`-only build must say so explicitly
    // rather than fall back to raw QUIC the operator did not ask for.
    if config.quic.enabled && !turna_transport::quic::QUIC_AVAILABLE {
        return Err(
            "[turn.quic] is enabled in the configuration, but this binary \
                    was built without QUIC support; rebuild with `--features quic` \
                    (or `--features web-transport` for the browser H3 path) \
                    or disable [turn.quic]"
                .into(),
        );
    }
    if config.quic.enabled
        && config.quic.web_transport
        && !turna_transport::quic::WEB_TRANSPORT_AVAILABLE
    {
        return Err(
            "[turn.quic] web_transport = true, but this binary was built \
                    without WebTransport support; rebuild with \
                    `--features web-transport`, or set \
                    [turn.quic] web_transport = false to serve raw QUIC only"
                .into(),
        );
    }

    let external_ip: std::net::IpAddr = if config.external_ip.is_empty() {
        let ip = config.listen.ip();
        if ip.is_unspecified() {
            "127.0.0.1".parse().unwrap()
        } else {
            ip
        }
    } else {
        config.external_ip.parse().unwrap_or_else(|_| {
            let ip = config.listen.ip();
            if ip.is_unspecified() {
                "127.0.0.1".parse().unwrap()
            } else {
                ip
            }
        })
    };

    // Base ([turn]) auth backend.
    let base_auth = if config.auth.oauth.enabled {
        // RFC 7635 third-party auth on the base realm. Keys are validated as hex
        // (16/32 B) in config::validate, so decoding here does not fail.
        let as_rs_keys: Vec<Vec<u8>> = config
            .auth
            .oauth
            .as_rs_keys
            .iter()
            .filter_map(|h| decode_hex(h))
            .collect();
        // RFC 7635 kid-tagged keys (each `key` validated as hex in config::validate).
        let kid_keys: Vec<(String, Vec<u8>)> = config
            .auth
            .oauth
            .keys
            .iter()
            .filter_map(|k| decode_hex(&k.key).map(|bytes| (k.kid.clone(), bytes)))
            .collect();
        info!(
            realm = %config.realm,
            keys = as_rs_keys.len(),
            kid_keys = kid_keys.len(),
            server_name = %config.auth.oauth.server_name,
            "OAuth (RFC 7635) auth enabled on base realm"
        );
        AuthMode::oauth_full(
            config.realm.clone(),
            as_rs_keys,
            kid_keys,
            config.auth.oauth.strict_kid,
            config.auth.oauth.server_name.clone(),
            config.auth.oauth.as_identity.clone(),
        )
    } else if config.auth.static_users.is_empty() {
        AuthMode::SharedSecret {
            realm: config.realm.clone(),
            secret: config.auth.shared_secret.as_bytes().to_vec(),
        }
    } else {
        AuthMode::long_term(
            config.realm.clone(),
            config
                .auth
                .static_users
                .iter()
                .map(|u| (&u.username, &u.password)),
        )
    };
    // Multi-tenancy: register each [[tenants]] entry under its own realm. Tenant
    // identity is resolved from the authenticated realm at request time (see
    // turna_auth::AuthRegistry); the listener never selects the tenant.
    let auth: Arc<AuthRegistry> = {
        let mut registry = AuthRegistry::new(base_auth);
        for t in &tenants {
            let tenant_auth = if t.static_users.is_empty() {
                AuthMode::SharedSecret {
                    realm: t.realm.clone(),
                    secret: t.shared_secret.as_bytes().to_vec(),
                }
            } else {
                AuthMode::long_term(
                    t.realm.clone(),
                    t.static_users.iter().map(|u| (&u.username, &u.password)),
                )
            };
            info!(tenant = %t.id, realm = %t.realm, ports = ?t.relay_port_range,
                  "tenant registered");
            registry = registry.with_tenant(t.id.clone(), tenant_auth);
        }
        Arc::new(registry)
    };

    let store = Arc::new({
        let mut s = AllocationStore::new(
            config.relay.min_port,
            config.relay.max_port,
            config.relay.max_allocations,
        );
        // Publish the complete boot snapshot once. Config values never live in
        // independent atomics; runtime updates replace this whole value.
        s.publish_runtime(turna_session::RuntimeLimits {
            version: bootstrap_runtime.version,
            max_bytes_per_sec_per_allocation: bootstrap_runtime
                .limits
                .max_bytes_per_sec_per_allocation,
            max_per_user: bootstrap_runtime.limits.max_per_user,
            max_allocations: bootstrap_runtime.limits.max_allocations,
        });
        s.set_bootstrap_max_lifetime(turna_proto_turn::MAX_LIFETIME);
        // Multi-tenancy: isolated relay-port pool per tenant (disjoint ranges).
        for t in &tenants {
            s = s.with_tenant_pool(
                t.id.clone(),
                t.relay_port_range[0],
                t.relay_port_range[1],
                t.max_allocations,
                turna_session::BandwidthQuota {
                    max_bytes_per_sec_per_allocation: t.quota.max_bytes_per_sec_per_allocation,
                    max_per_user: t.quota.max_per_user,
                },
            );
        }
        s
    });

    let metrics = Arc::new(Metrics::new());

    // The node's own audit ring is NOT constructed here yet, deliberately.
    //
    // `AuditLog` is an in-memory ring, not a file, so it cannot hold start or stop
    // events — those describe the restart that erases it, and they go to syslog
    // instead. What belongs in it is what happens while the process lives: drain
    // transitions, certificate rotations, a listener that failed to bind.
    //
    // Those call sites are not wired, so constructing the ring here would leave a
    // documented, dead object that reads as plumbing. Construct it at the same
    // time as the first real caller:
    //
    //   let node_audit = Arc::new(turna_control::audit::AuditLog::new(
    //       config.observability.node_audit_entries));
    //
    // The config key exists and is documented.

    // Security-event export. Constructed here so it exists before anything can
    // refuse a request: an exporter created later would miss exactly the events
    // that happen during startup, which is when a misconfigured listener refuses
    // things.
    //
    // Disabled unless an endpoint is configured, and a disabled exporter is a
    // no-op rather than a branch at every call site.
    let _syslog = Arc::new(turna_observability::syslog::SyslogExporter::new(
        turna_observability::syslog::SyslogConfig {
            endpoint: config.observability.syslog_endpoint.clone(),
            app_name: "turna".to_string(),
            redact_addresses: config.observability.syslog_redact_addresses,
            non_blocking: true,
        },
    ));
    // Mirror the exporter's counters on the same ticker as the rest. Without
    // this the two documented series read zero forever, and a dashboard panel
    // showing no drops is indistinguishable from one showing no export.
    {
        let syslog = _syslog.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                metrics
                    .syslog_sent
                    .store(syslog.sent.load(Relaxed), Relaxed);
                metrics
                    .syslog_dropped
                    .store(syslog.dropped.load(Relaxed), Relaxed);
            }
        });
    }

    // Startup goes to syslog, not to the ring.
    //
    // The ring is in memory and does not survive a restart, so a start event
    // recorded there is one nobody can ever read — it describes the very
    // discontinuity that erases it. Putting it in the ring anyway would look like
    // coverage and provide none, which is the worse kind of nothing.
    //
    // Version and config path because the first question after any incident is
    // which build was running.
    _syslog.emit(
        // ReadinessChanged, not ControlFailed: nothing failed. Using the failure
        // kind for a normal start would put successes and failures under one
        // MSGID, and a SIEM rule cannot separate them again.
        turna_observability::syslog::EventKind::ReadinessChanged,
        &[
            ("state", "started"),
            ("version", env!("CARGO_PKG_VERSION")),
            ("pid", &std::process::id().to_string()),
        ],
    );

    if _syslog.is_enabled() {
        info!(
            endpoint = %config.observability.syslog_endpoint,
            "security events exporting to syslog"
        );
    }

    // Publish the node's own ceiling so `/capacity` has something to reason
    // about. Until this runs, that endpoint reports UNAVAILABLE — a node that
    // does not know its limit must not advertise headroom, because an unset
    // limit read as "unlimited" is how a node gets sent work it cannot take.
    //
    // The thresholds are percentages of `max_allocations`, which is the only
    // ceiling this process actually enforces. A deployment's real constraint is
    // often something else — uplink bandwidth, a licence count — which is why
    // `/capacity` returns the raw numbers next to the state rather than only a
    // verdict.
    metrics.set_capacity_limits(config.relay.max_allocations as u64, 75, 95);

    // M1: install the configured peer-filter policy before serving.
    // Default profile is internet-facing (denies RFC1918/ULA); opt into
    // LAN relaying via [turn.peer_filter] profile = "lan".
    turna_relay::peer_filter::init_peer_policy(turna_relay::peer_filter::PeerPolicy::from_config(
        &config.peer_filter.profile,
        config.peer_filter.allow_loopback_peers,
        &config.peer_filter.denied_peer_ranges,
        &config.peer_filter.allowed_peer_ranges,
    ));

    run_tokio(
        config,
        cluster,
        store,
        auth,
        external_ip,
        metrics,
        health_listen,
        tls_cfg,
        runtime_validation_ctx,
        bootstrap_runtime,
    )
}

/// Map the config-layer [`turna_config::TlsConfig`] to the transport-layer
/// `TlsTransportConfig`. Kept in the node binary so the `config` crate stays
/// free of a `turna-transport` dependency.
#[cfg(feature = "tls")]
fn build_tls_transport_config(
    c: &turna_config::TlsConfig,
) -> turna_transport::tcp_tls::TlsTransportConfig {
    turna_transport::tcp_tls::TlsTransportConfig {
        listen_addr: c.listen,
        cert_path: c.cert_path.clone(),
        key_path: c.key_path.clone(),
        max_frame_size: c.max_frame_size,
        handshake_timeout: std::time::Duration::from_secs(c.handshake_timeout_secs),
        read_timeout: std::time::Duration::from_secs(c.read_timeout_secs),
        max_connections: c.max_connections,
        max_connections_per_ip: c.max_connections_per_ip,
        cert_reload_interval: std::time::Duration::from_secs(c.cert_reload_secs),
        enable_alpn: c.enable_alpn,
        max_handshakes_per_sec_per_ip: c.max_handshakes_per_sec_per_ip,
        handshake_burst_per_ip: c.handshake_burst_per_ip,
        alpn_required: c.alpn_required,
        client_ca_path: c.client_ca.clone(),
        require_client_cert: c.require_client_cert,
    }
}

/// Map `[turn.tcp_relay]` config to the relay-layer `TcpRelayConfig`.
fn build_tcp_relay_config(
    c: &turna_config::TcpRelaySection,
) -> turna_relay::tcp_relay::TcpRelayConfig {
    turna_relay::tcp_relay::TcpRelayConfig {
        connect_timeout: std::time::Duration::from_secs(c.connect_timeout_secs),
        idle_timeout: std::time::Duration::from_secs(c.idle_timeout_secs),
        max_per_allocation: c.max_per_allocation,
        max_total: c.max_total,
        buffer_size: c.buffer_size,
    }
}

/// Map the config-layer [`turna_config::SctpSection`] to the transport-layer
/// `SctpTransportConfig`. Experimental TURN-over-SCTP control transport.
#[cfg(feature = "sctp")]
fn build_sctp_transport_config(
    c: &turna_config::SctpSection,
) -> turna_transport::sctp::SctpTransportConfig {
    turna_transport::sctp::SctpTransportConfig {
        listen_addr: c.listen,
        max_frame_size: c.max_frame_size,
        read_timeout: std::time::Duration::from_secs(c.read_timeout_secs),
        max_connections: c.max_connections,
        max_connections_per_ip: c.max_connections_per_ip,
        max_associations_per_sec_per_ip: c.max_associations_per_sec_per_ip,
        association_burst_per_ip: c.association_burst_per_ip,
        backlog: c.backlog,
    }
}

#[allow(clippy::too_many_arguments)]
/// P0 #8: upper bound on how long shutdown waits for the write-behind
/// persistence writer to flush its queue before the process exits. Part of
/// the total shutdown budget that `terminationGracePeriodSeconds` must
/// exceed. Conservative default; revisit with batch sizing / backend latency.
const PERSISTENCE_FLUSH_TIMEOUT_SECS: u64 = 10;

/// P0 #8/#11: per-task join budget on shutdown for supervised background tasks
/// other than the persistence writer (heartbeat, failover). They only need to
/// observe the shutdown signal and stop; the writer gets the larger flush budget.
const TASK_JOIN_TIMEOUT_SECS: u64 = 5;
/// P0.2: how long a claimed command's lease is held before another claim may
/// reclaim it (the claimant is expected to complete well within this window).
const COMMAND_LEASE_MS: u64 = 30_000;

/// P0.1: how long the readiness monitor waits for the writer to flush a
/// reconcile barrier to the backend before giving up and staying Degraded.
/// Must comfortably exceed a batch flush; the monitor ticks every 5s.
const RECONCILE_BARRIER_WAIT_SECS: u64 = 10;

/// #5: which optional workers each deployment profile runs. Centralizes the
/// gate decisions so the profile matrix (management / allocation-persistence /
/// cluster-failover) lives — and is tested — in one place instead of scattered
/// inline conditions that can drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfileGates {
    /// Durable management plane: command log, runtime/limits restore, migration,
    /// command worker, and the presence/incarnation heartbeat used for command
    /// targeting. Enabled by ANY durable backend, independent of allocation
    /// write-behind.
    management: bool,
    /// Rehydrate persisted allocations at startup — allocation-persistence only.
    bulk_load: bool,
    /// Write-behind allocation writer + reconcile — allocation-persistence only.
    writer: bool,
    /// Ownership adoption / failover sweep — CLUSTER profile only. Gated on the
    /// explicit `cluster_mode`, never inferred from persistence being enabled: a
    /// standalone (or management-only) persistent node must not adopt ownership
    /// or run failover for peers.
    failover: bool,
    /// Gossip membership / redirects — cluster profile only.
    gossip: bool,
}

/// Resolve the deployment-profile worker gates from cluster config. Pure and
/// side-effect free so the profile matrix (see the `profile_gates_matrix` test)
/// is verifiable without booting a node.
fn profile_gates(cluster: &turna_config::ClusterConfig) -> ProfileGates {
    let persistence = cluster.persistence.is_enabled();
    let durable_backend = cluster.backend.r#type.as_str() == "tarantool";
    ProfileGates {
        management: persistence || durable_backend,
        bulk_load: persistence,
        writer: persistence,
        failover: cluster.cluster_mode,
        gossip: cluster.cluster_mode,
    }
}

/// P0.1: await the writer publishing `target` (a reconcile barrier's
/// generation) to `ack` — i.e. every op enqueued before the barrier has been
/// flushed to the backend. Returns `false` on timeout or shutdown so the caller
/// stays Degraded rather than declaring Ready over an unconfirmed resync.
async fn await_reconcile_barrier(
    ack: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    target: u64,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    use std::sync::atomic::Ordering;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(RECONCILE_BARRIER_WAIT_SECS);
    loop {
        if ack.load(Ordering::Acquire) >= target {
            return true;
        }
        if *shutdown.borrow() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            _ = shutdown.changed() => return false,
        }
    }
}

/// Decode an even-length hex string into bytes. `None` on invalid hex. Used for
/// OAuth AS-RS keys (validated as hex in config::validate before we reach here).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// P0 #11: spawn a MANDATORY background task under supervision. If the task's
/// future completes while the node is NOT shutting down, that is an unexpected
/// exit (a panic surfaces here as task completion too): mark the node Degraded
/// so a load balancer / failover controller stops trusting it, and initiate an
/// orderly shutdown so the orchestrator restarts the pod. Returns the handle so
/// shutdown can join it within the budget.
fn spawn_supervised<F>(
    name: &'static str,
    metrics: Arc<Metrics>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    fut: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let shutting_down = shutdown_tx.subscribe();
    tokio::spawn(async move {
        fut.await;
        if *shutting_down.borrow() {
            info!(task = name, "background task stopped (shutdown)");
        } else {
            tracing::error!(
                task = name,
                "mandatory background task exited unexpectedly; marking node \
                 Degraded and initiating shutdown"
            );
            metrics.set_readiness(turna_health::Readiness::Degraded);
            let _ = shutdown_tx.send(true);
        }
    })
}

/// P0 #8/#11: join a supervised task within a bounded budget on shutdown, so a
/// mandatory task is never left detached to be aborted by the runtime drop.
async fn join_within_budget(
    name: &'static str,
    handle: Option<tokio::task::JoinHandle<()>>,
    budget: Duration,
) {
    let Some(handle) = handle else { return };
    match tokio::time::timeout(budget, handle).await {
        Ok(Ok(())) => info!(task = name, "task stopped cleanly during shutdown"),
        Ok(Err(e)) => warn!(task = name, error = %e, "task panicked during shutdown"),
        Err(_) => warn!(
            task = name,
            budget_secs = budget.as_secs(),
            "task did not stop within the shutdown budget"
        ),
    }
}

/// P0 #4: apply one claimed command to this node's real runtime state and
/// return (status, result) for the command log. Only node-local mutations
/// are handled; unknown ops fail explicitly so the control-plane learns the
/// command was not honoured (never a silent success).
fn apply_command(
    cmd: &turna_state_backend::PendingCommand,
    store: &Arc<AllocationStore>,
    metrics: &Arc<Metrics>,
) -> (&'static str, String) {
    match cmd.op.as_str() {
        "delete_allocation" => {
            let Some(relay_id) = cmd.args.first() else {
                return (
                    "failed",
                    "delete_allocation: missing relay id arg".to_string(),
                );
            };
            // Find the live allocation by its relay address and remove it from
            // the real store. Persistence propagates via the write-behind path.
            match store
                .iter_all()
                .find(|a| a.relay_addr.to_string() == *relay_id)
            {
                Some(a) => {
                    store.force_remove(&a.client_addr);
                    metrics
                        .active_allocations
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    ("done", String::new())
                }
                // Already gone => idempotent success.
                None => (
                    "done",
                    "allocation not present (already removed)".to_string(),
                ),
            }
        }
        other => ("failed", format!("unknown command op: {other}")),
    }
}

/// RFC 6156 IPv6 relayed transport: resolve `[turn] external_ip6` into the address
/// to advertise for IPv6-family allocations, or `None` to keep IPv4-only relaying
/// (where an explicit IPv6 Allocate answers 440).
///
/// `validate()` already rejected a non-IPv6 literal, so a parse failure here can
/// only mean the key was left empty — but it is reported rather than swallowed,
/// because silently relaying IPv4-only after an operator set the key would be the
/// worst outcome.
fn resolve_external_ip6(cfg: &TurnConfig) -> Option<std::net::Ipv6Addr> {
    if cfg.external_ip6.is_empty() {
        return None;
    }
    match cfg.external_ip6.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => {
            info!(%v6, "IPv6 relayed transport enabled (RFC 6156)");
            Some(v6)
        }
        Err(e) => {
            warn!(
                value = %cfg.external_ip6, %e,
                "turn.external_ip6 is not a valid IPv6 address; IPv6 relaying stays disabled"
            );
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_tokio(
    config: TurnConfig,
    cluster: ClusterConfig,
    store: Arc<AllocationStore>,
    auth: Arc<AuthRegistry>,
    external_ip: std::net::IpAddr,
    metrics: Arc<Metrics>,
    health_listen: std::net::SocketAddr,
    tls_cfg: turna_config::TlsConfig,
    runtime_validation_ctx: RuntimeValidationCtx,
    bootstrap_runtime: ConfigRuntimeSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    // `tls_cfg` is only consumed when the `tls` feature is enabled.
    #[cfg(not(feature = "tls"))]
    let _ = &tls_cfg;
    let external_ip6 = resolve_external_ip6(&config);
    let num_threads = std::env::var("TURNA_WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        // TURNA_WORKERS=0 means "auto" (the Helm chart's default). tokio's
        // worker_threads(0) panics, so treat 0 (and unset/unparseable) as a
        // request to size the pool from available parallelism.
        .filter(|&n| n != 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_threads)
        .enable_all()
        .build()?;

    rt.block_on(async {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        // #5: resolve the deployment-profile worker gates once, up front.
        let gates = profile_gates(&cluster);
        let node_incarnation = format!(
            "{}:{}:{}",
            cluster.node_id,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        // #6: shared drain signal for the cluster hash ring. Set when this node
        // enters drain so the gossip loop advertises `leaving` immediately (not
        // only at final shutdown), evicting this node from peers' routing so new
        // clients stop being redirected here mid-drain (no redirect loop).
        let gossip_draining =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // #6: edge signal pulsed the instant drain begins so gossip sends the
        // leaving frame immediately, not on the next periodic tick.
        let gossip_drain_notify = std::sync::Arc::new(tokio::sync::Notify::new());

        // Health check server is started below, after cluster_routing is built,
        // so it can also expose GET /cluster (gossip ring membership).

        let cluster_routing = if gates.gossip {
            // node_id MUST be unique per host. The default placeholder collides
            // across nodes; identical ids are deduped into a single ring entry,
            // so every node serves locally and no redirect/balancing happens.
            if cluster.node_id == "node-1" {
                warn!(
                    "cluster.node_id is the default \"node-1\"; set a unique id per host \
                     (e.g. TURNA_NODE_ID=node-$(hostname)) or balancing will silently no-op"
                );
            }
            let turn_announce_addr = resolve_turn_announce_addr(&cluster, &config, external_ip);
            let initial_nodes = vec![ClusterNode {
                node_id: cluster.node_id.clone(),
                turn_addr: turn_announce_addr,
            }];
            let hash_ring = Arc::new(parking_lot::RwLock::new(HashRing::new(initial_nodes)));
            let routing = ClusterRouting::new(cluster.node_id.clone(), hash_ring.clone());

            let gossip_cfg = GossipConfig {
                node_id: cluster.node_id.clone(),
                turn_addr: turn_announce_addr,
                bind_addr: cluster.effective_gossip_bind(),
                seeds: cluster.effective_gossip_seeds(),
                interval: Duration::from_secs(cluster.gossip_interval_secs.max(1)),
                timeout: Duration::from_secs(cluster.gossip_timeout_secs.max(1)),
                cluster_name: cluster.cluster_name.clone(),
                advertise_addr: cluster.gossip_advertise_addr,
                secret: if cluster.cluster_secret.is_empty() {
                    None
                } else {
                    Some(cluster.cluster_secret.clone().into_bytes())
                },
            };
            let gossip_shutdown = shutdown_rx.clone();
            let ring_for_gossip = hash_ring.clone();
            let metrics_for_gossip = metrics.clone();
            let gossip_draining_g = gossip_draining.clone();
            let gossip_drain_notify_g = gossip_drain_notify.clone();
            // P0 #11: gossip is a mandatory cluster task. Supervise it so an
            // unexpected exit marks the node Degraded and initiates shutdown,
            // instead of silently leaving a stale hash ring while /ready stays
            // 200 and routing keeps trusting dead membership.
            spawn_supervised(
                "cluster-gossip",
                metrics.clone(),
                shutdown_tx.clone(),
                async move {
                    if let Err(e) = run_gossip(
                        gossip_cfg,
                        move |nodes| {
                            metrics_for_gossip
                                .cluster_nodes
                                .store(nodes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            ring_for_gossip.write().update_nodes(nodes);
                        },
                        gossip_draining_g,
                        gossip_drain_notify_g,
                        gossip_shutdown,
                    )
                    .await
                    {
                        warn!(%e, "cluster gossip stopped with error");
                    }
                },
            );

            info!(
                node_id = %cluster.node_id,
                turn_announce_addr = %turn_announce_addr,
                gossip_bind = %cluster.effective_gossip_bind(),
                gossip_seeds = ?cluster.effective_gossip_seeds(),
                "cluster redirect mode enabled"
            );
            Some(routing)
        } else {
            None
        };

        // RFC 8016 sharded-ownership route table (io_uring datapath only).
        // Created here, before the health server starts, so the *same* instance
        // feeds both the worker pool (later, in the IoUring transport arm) and
        // the health server's relay-route metrics. On builds without the
        // io_uring datapath the table does not exist and the metric block is
        // simply omitted.
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        let relay_routes = turna_transport::relay_route::RelayRoutes::new();
        // Lame-duck window for the io_uring worker pool on shutdown (Fix 4).
        #[cfg(all(target_os = "linux", feature = "io-uring"))]
        let worker_drain_grace = std::time::Duration::from_secs(cluster.drain_grace_secs);

        // Health check server (also serves GET /cluster). The cluster view
        // returns the gossip ring when clustered, or just this node otherwise —
        // so `turnactl cluster nodes` works the same on one node or many.
        {
            let health_metrics = metrics.clone();
            let cluster_view: Arc<dyn turna_health::ClusterView> = Arc::new(ClusterStatusView {
                local_node_id: cluster.node_id.clone(),
                local_addr: resolve_turn_announce_addr(&cluster, &config, external_ip).to_string(),
                ring: cluster_routing.as_ref().map(|r| r.hash_ring.clone()),
            });

            // Relay-route metrics provider: snapshot the shared route table on
            // each scrape and map it into the health crate's feature-neutral
            // metric struct. `None` on non-io_uring builds.
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            let relay_route_metrics: Option<turna_health::RelayRouteMetricsProvider> = {
                let routes = relay_routes.clone();
                Some(Arc::new(move || {
                    let s = routes.snapshot();
                    turna_health::RelayRouteMetrics {
                        send_local: s.send_local,
                        send_forwarded: s.send_forwarded,
                        send_forward_failed: s.send_forward_failed,
                        send_stale: s.send_stale,
                        route_miss: s.route_miss,
                        owner_cleanup_stale: s.owner_cleanup_stale,
                    }
                }))
            };
            #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
            let relay_route_metrics: Option<turna_health::RelayRouteMetricsProvider> = None;

            // Host CPU and memory, every five seconds.
            //
            // A single long-lived `System`, refreshed in place. CPU usage in
            // sysinfo is a delta between refreshes, so a persistent instance
            // reports the load over the whole interval; building a fresh one each
            // tick — which `heartbeat::sample_resources` did — measures only the
            // library's internal ~100 ms settling window, and a node busy in
            // bursts reads low if the sample falls between them.
            //
            // Runs regardless of whether a cluster backend is configured. The
            // previous arrangement collected this only inside the heartbeat loop,
            // so a standalone node had no CPU or memory reading at all — the two
            // signals a capacity decision most wants, missing exactly where there
            // is no cluster to ask instead.
            {
                let metrics = metrics.clone();
                tokio::task::spawn_blocking(move || {
                    use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
                    let mut sys = System::new_with_specifics(
                        RefreshKind::nothing()
                            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                            .with_memory(MemoryRefreshKind::nothing().with_ram()),
                    );
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        sys.refresh_cpu_usage();
                        sys.refresh_memory();
                        let cpu = sys.global_cpu_usage().round() as u64;
                        let mem = if sys.total_memory() > 0 {
                            ((sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0)
                                .round() as u64
                        } else {
                            0
                        };
                        metrics.set_host_load(cpu, mem);
                    }
                });
            }

            // Relayed traffic rate, sampled once a second.
            //
            // Its own task rather than a branch of the five-second port ticker
            // below: `RateSampler`'s window is ten one-second buckets, so ticking
            // it every five seconds would put a five-second delta into a bucket
            // meant to hold one second and leave eight buckets stale. The mean
            // would be wrong by roughly a factor of five while still looking like
            // a plausible number — the failure mode worth avoiding, since nothing
            // would flag it.
            //
            // The cost is two loads, two swaps and two stores per second.
            {
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    use std::sync::atomic::Ordering::Relaxed;
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(1));
                    // Skip rather than Burst: after a stall, catching up would
                    // write several buckets from one counter reading and report a
                    // rate that never happened.
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        let bytes = metrics.bytes_received.load(Relaxed)
                            + metrics.bytes_sent.load(Relaxed);
                        let packets = metrics.packets_received.load(Relaxed)
                            + metrics.packets_sent.load(Relaxed);
                        metrics.rates.tick(bytes, packets);
                    }
                });
            }

            // Relay-port occupancy, mirrored on a ticker.
            //
            // A ticker rather than a scrape-time provider like the two below: a
            // provider would need another parameter on `serve_*`, whose signature
            // has already grown twice this week, and the cost of the ticker is up
            // to five seconds of staleness. A port range does not fill in five
            // seconds, so an alert firing one interval late is not a worse alert.
            //
            // Tenant pools are summed into the global gauges rather than exported
            // per tenant. `port_pool_usage()` keeps the per-pool detail for
            // anything that wants it without every scrape paying for the labels.
            {
                let store = store.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    use std::sync::atomic::Ordering::Relaxed;
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(5));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        let (used, total) = store
                            .port_pool_usage()
                            .iter()
                            .fold((0usize, 0usize), |(u, t), (_, in_use, cap)| {
                                (u + in_use, t + cap)
                            });
                        metrics.relay_ports_in_use.store(used as u64, Relaxed);
                        metrics.relay_ports_total.store(total as u64, Relaxed);
                    }
                });
            }

            // Per-tenant traffic provider: snapshot the store's cumulative
            // per-tenant counters (accrued at allocation teardown) on each
            // scrape. Empty until tenant-scoped allocations have closed, so
            // single-tenant deployments see no extra output.
            let tenant_traffic: Option<turna_health::TenantTrafficProvider> = {
                let store = store.clone();
                Some(Arc::new(move || store.tenant_traffic_snapshot()))
            };

            // Bound here rather than inside the task: the same reasoning as the
            // DTLS check above. A bind failure inside a spawned task is
            // swallowed, the node carries on, and the operator believes the
            // configured port is being scraped. We ran into exactly that — the
            // port was held by an unrelated process and a whole scrape window
            // read that process's metrics as if they were this node's.
            let health_listener = turna_health::bind(health_listen).await.map_err(|e| {
                format!(
                    "[health] listen = \"{health_listen}\" could not be bound: {e}. \
                     Free the port or change [health].listen; the node will not start \
                     without the health endpoint it was told to serve"
                )
            })?;
            tokio::spawn(async move {
                if let Err(e) = turna_health::serve_on(
                    health_listener,
                    health_listen,
                    health_metrics,
                    Some(cluster_view),
                    relay_route_metrics,
                    tenant_traffic,
                )
                .await
                {
                    tracing::error!(error = %e, "health server stopped");
                }
            });
        }

        // P0 #8: keep the writer's JoinHandle so shutdown can wait for its
        // final flush instead of the runtime drop aborting it mid-write.
        let mut writer_handle: Option<tokio::task::JoinHandle<()>> = None;
        let mut heartbeat_handle: Option<tokio::task::JoinHandle<()>> = None;
        let mut failover_handle: Option<tokio::task::JoinHandle<()>> = None;
        let mut command_log_handle: Option<tokio::task::JoinHandle<()>> = None;

        // ── PR2: write-behind writer task ─────────────────────────────────────
        // P0 #16: hoisted so the readiness monitor (spawned below, outside this
        // block) can run reconciliation against the backend after write-drops.
        let mut reconcile_backend: Option<Arc<turna_state_backend::Backend>> = None;
        // P0.1: hoisted so the readiness monitor (below, outside the writer
        // block) can await the writer flushing a reconcile barrier to the
        // backend (`reconcile_ack`) and detect backend write failures during the
        // drain (`reconcile_counters`) before returning the node to Ready.
        let reconcile_ack = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut reconcile_counters: Option<Arc<writer::WriterCounters>> = None;
        // #6: the management backend (durable command log, runtime/limits
        // restore, migration, command worker, and the heartbeat that publishes
        // this node's incarnation for command targeting) is enabled whenever a
        // durable backend is configured — independent of allocation write-behind.
        // Allocation persistence (writer, reconcile) is gated on persistence and
        // ownership/failover on cluster_mode — see `profile_gates`.
        let management_enabled = gates.management;
        if !management_enabled {
            // No management plane on this node → nothing to gate; mark the
            // management-readiness sub-signal Ready so it never sticks at Starting.
            metrics.set_management_readiness(turna_health::Readiness::Ready);
        }
        if management_enabled {
            let backend_cfg = match cluster.backend.r#type.as_str() {
                "memory" => BackendConfig::Memory,
                "tarantool" => BackendConfig::Tarantool {
                    uri: cluster.backend.uri.clone(),
                    user: if cluster.backend.user.is_empty() {
                        None
                    } else {
                        Some(cluster.backend.user.clone())
                    },
                    password: if cluster.backend.password.is_empty() {
                        None
                    } else {
                        Some(cluster.backend.password.clone())
                    },
                    pool_size: if cluster.backend.pool_size == 0 {
                        None
                    } else {
                        Some(cluster.backend.pool_size)
                    },
                },
                other => {
                    // P0 #10: refuse to silently fall back to a process-local
                    // in-memory store. TurnaConfig::validate already rejects
                    // unknown backend types at load; this is defence in depth.
                    return Err(format!(
                        "unknown [cluster.backend].type = {other:?}; use \"memory\" or \
                         \"tarantool\" (refusing to fall back to in-memory)"
                    )
                    .into());
                }
            };

            let backend =
                create_backend(&backend_cfg)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error> {
                        format!("state backend init failed: {e}").into()
                    })?;
            let backend = Arc::new(backend);
            reconcile_backend = Some(backend.clone());

            // Durable runtime state is restored before allocation rehydration
            // and before readiness. A backend outage is fatal here: silently
            // falling back to bootstrap/unlimited values would violate the
            // management-plane desired state.
            let runtime_management = runtime_management::RuntimeManagement::new(
                cluster.node_id.clone(),
                node_incarnation.clone(),
                store.clone(),
                backend.clone(),
                metrics.clone(),
                runtime_validation_ctx,
            );
            runtime_management
                .restore(&bootstrap_runtime)
                .await
                .map_err(|error| -> Box<dyn std::error::Error> {
                    format!("runtime state restore failed: {error}").into()
                })?;

            // #6 (4.4): rehydrate persisted allocations ONLY under allocation
            // persistence. A management-only node (durable backend, persistence
            // disabled) must NOT load old allocations — that is an allocation
            // persistence concern, not a management-plane one.
            if gates.bulk_load {
                let bulk_stats = bulk_load::bulk_load(&backend, &store, &cluster.node_id).await;
                metrics.active_allocations.fetch_add(
                    bulk_stats.rehydrated as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }

            // R8: rehydrate runtime long-term users from the shared backend into
            // the in-memory AuthRegistry. Variant B — the backend holds two
            // pre-derived keys (hex); the password is never persisted.
            fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
                if !s.len().is_multiple_of(2) {
                    return None;
                }
                (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                    .collect()
            }
            // I5: track (realm, username) pairs we sync from the backend so the
            // refresh loop can propagate *deletions* too — without ever touching
            // config static_users (which this task never adds here).
            let mut synced_users: std::collections::HashSet<(String, String)> =
                std::collections::HashSet::new();
            match backend.list_users().await {
                Ok(users) => {
                    let mut loaded = 0usize;
                    for u in users {
                        match (hex_to_bytes(&u.key_md5_hex), hex_to_bytes(&u.key_sha256_hex)) {
                            (Some(key_md5), Some(key_sha256)) => {
                                if auth.add_user_with_keys(
                                    &u.realm,
                                    &u.username,
                                    UserKeys { key_md5, key_sha256 },
                                ) {
                                    loaded += 1;
                                    synced_users.insert((u.realm.clone(), u.username.clone()));
                                }
                            }
                            _ => warn!(username = %u.username, realm = %u.realm,
                                       "skipping backend user with malformed key hex"),
                        }
                    }
                    info!(loaded, "rehydrated runtime users from state backend");
                }
                Err(e) => warn!(%e, "failed to load users from state backend (continuing)"),
            }

            // R8 live propagation: periodically re-read users from the backend so
            // AddUser on the control-plane reaches a running node without a
            // restart. Insert/overwrite is idempotent. (Deletion is not
            // propagated here — see remove_user with force, or a node restart.)
            let refresh_secs = cluster.persistence.user_refresh_secs;
            if refresh_secs > 0 {
                let refresh_backend = backend.clone();
                let refresh_auth = auth.clone();
                let mut refresh_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
                        if !s.len().is_multiple_of(2) {
                            return None;
                        }
                        (0..s.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                            .collect()
                    }
                    let mut synced_users = synced_users;
                    let mut tick = tokio::time::interval(Duration::from_secs(refresh_secs));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    // First tick fires immediately; skip it (startup already loaded).
                    tick.tick().await;
                    loop {
                        tokio::select! {
                            _ = tick.tick() => {
                                match refresh_backend.list_users().await {
                                    Ok(users) => {
                                        let mut current: std::collections::HashSet<(String, String)> =
                                            std::collections::HashSet::new();
                                        let mut n = 0usize;
                                        for u in users {
                                            if let (Some(key_md5), Some(key_sha256)) = (
                                                hex_to_bytes(&u.key_md5_hex),
                                                hex_to_bytes(&u.key_sha256_hex),
                                            ) {
                                                current.insert((u.realm.clone(), u.username.clone()));
                                                if refresh_auth.add_user_with_keys(
                                                    &u.realm,
                                                    &u.username,
                                                    UserKeys { key_md5, key_sha256 },
                                                ) {
                                                    n += 1;
                                                }
                                            }
                                        }
                                        // I5: propagate revocation without a restart. Remove only
                                        // users THIS task previously synced from the backend that the
                                        // backend no longer lists; config static_users are never in
                                        // `synced_users`, so they are never touched.
                                        let mut removed = 0usize;
                                        for (realm, username) in synced_users.difference(&current) {
                                            if refresh_auth.remove_user_for_realm(realm, username) {
                                                removed += 1;
                                            }
                                        }
                                        synced_users = current;
                                        tracing::debug!(refreshed = n, removed, "user refresh from backend");
                                    }
                                    Err(e) => tracing::warn!(%e, "user refresh from backend failed"),
                                }
                            }
                            _ = refresh_shutdown.changed() => break,
                        }
                    }
                });
            }

            // #6: allocation write-behind persistence — gated independently of
            // the management backend above.
            if gates.writer {
            let (tx, rx) = tokio::sync::mpsc::channel::<turna_session::WriteOp>(
                cluster.persistence.channel_capacity,
            );
            store.attach_writer(tx);

            let writer_cfg = writer::WriterConfig {
                channel_capacity: cluster.persistence.channel_capacity,
                batch_max_size: cluster.persistence.batch_max_size,
                batch_max_delay: Duration::from_millis(cluster.persistence.batch_max_delay_ms),
                node_id: cluster.node_id.clone(),
            };
            let counters = Arc::new(writer::WriterCounters::default());
            reconcile_counters = Some(counters.clone());
            let realm = config.realm.clone();
            let writer_shutdown = shutdown_rx.clone();

            info!(
                mode             = %cluster.persistence.mode,
                node_id          = %writer_cfg.node_id,
                channel_capacity = writer_cfg.channel_capacity,
                batch_max_size   = writer_cfg.batch_max_size,
                batch_max_delay  = ?writer_cfg.batch_max_delay,
                "allocation-store persistence: writer attached"
            );

            let writer_backend = backend.clone();
            let writer_store = store.clone();
            let writer_metrics = metrics.clone();
            let writer_ack = reconcile_ack.clone();
            writer_handle = Some(spawn_supervised(
                "persistence-writer",
                metrics.clone(),
                shutdown_tx.clone(),
                async move {
                    writer::run_writer(
                        writer_backend,
                        writer_store,
                        realm,
                        writer_cfg,
                        writer_metrics,
                        counters,
                        writer_ack,
                        rx,
                        writer_shutdown,
                    )
                    .await;
                },
            ));
            } // #6: end allocation write-behind persistence

            // ── PR4: heartbeat task ───────────────────────────────────────
            let hb_backend = backend.clone();
            let hb_metrics = metrics.clone();
            let hb_shutdown = shutdown_rx.clone();
            let hb_cfg = heartbeat::HeartbeatConfig {
                node_id: cluster.node_id.clone(),
                incarnation: node_incarnation.clone(),
                addr: std::net::SocketAddr::new(external_ip, config.listen.port()).to_string(),
                version: env!("CARGO_PKG_VERSION").into(),
                interval: std::time::Duration::from_secs(
                    cluster.failure_detection.heartbeat_interval_secs.max(1),
                ),
            };
            info!(
                node_id  = %hb_cfg.node_id,
                addr     = %hb_cfg.addr,
                interval = ?hb_cfg.interval,
                "heartbeat task starting"
            );
            heartbeat_handle = Some(spawn_supervised(
                "heartbeat",
                metrics.clone(),
                shutdown_tx.clone(),
                async move {
                    heartbeat::run_heartbeat(hb_backend, hb_metrics, hb_cfg, hb_shutdown).await;
                },
            ));

            // ── PR5: failover claim task ──────────────────────────────────
            // #5 (§5.2/§5.3): ownership adoption / failover is a CLUSTER concern
            // gated on the explicit `cluster_mode`, NOT on persistence. A
            // standalone or management-only persistent node must never adopt
            // peers' allocations or run the failover sweep.
            if gates.failover {
            let fo_backend = backend.clone();
            let fo_store = store.clone();
            let fo_metrics = metrics.clone(); // PR A: pass metrics for counters
            let fo_shutdown = shutdown_rx.clone();
            let fo_cfg = failover::FailoverConfig {
                node_id: cluster.node_id.clone(),
                sweep_interval: std::time::Duration::from_secs(
                    cluster.failure_detection.sweep_interval_secs.max(1),
                ),
                live_window: std::time::Duration::from_secs(
                    cluster.failure_detection.live_window_secs.max(1),
                ),
                suspicion_ticks: cluster.failure_detection.suspicion_ticks.max(1),
            };
            info!(
                node_id        = %fo_cfg.node_id,
                sweep_interval = ?fo_cfg.sweep_interval,
                live_window    = ?fo_cfg.live_window,
                "failover task starting"
            );
            failover_handle = Some(spawn_supervised(
                "failover",
                metrics.clone(),
                shutdown_tx.clone(),
                async move {
                    let _ = failover::run_failover(
                        fo_backend, fo_store, fo_cfg, fo_metrics, fo_shutdown,
                    )
                    .await;
                },
            ));
            } // #5: end ownership adoption / failover (cluster profile only)

            // ── P0 #4: command-log apply loop ─────────────────────────────
            // Claim commands the control-plane targeted at THIS node and apply
            // them to the real runtime state, then confirm. This is the node
            // half of the control-plane→node command channel.
            // ── §3: command-log backfill migration (one-shot, resumable) ──
            // Drain the bounded/resumable idem+status backfill in the background.
            // Idempotent and safe on every node: once complete each call returns
            // immediately; an interrupted run resumes on the next startup. A plain
            // task (not spawn_supervised) because completion is the goal — its exit
            // must NOT be treated as a failed mandatory task.
            {
                let mig_backend = backend.clone();
                let mig_owner = cluster.node_id.clone();
                let mig_metrics = metrics.clone();
                let mut mig_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    use std::sync::atomic::Ordering;
                    loop {
                        if *mig_shutdown.borrow() {
                            break;
                        }
                        match mig_backend.migrate_command_log_batch(500, &mig_owner).await {
                            Ok(progress) => {
                                mig_metrics
                                    .command_log_migration_processed_total
                                    .store(progress.total_processed, Ordering::Relaxed);
                                if progress.completed {
                                    mig_metrics
                                        .command_log_migration_completed
                                        .store(1, Ordering::Relaxed);
                                    // #6/#4.5: the management plane is fully ready
                                    // only once the mandatory migration phases
                                    // complete — a signal distinct from the
                                    // dataplane readiness flag, so TURN keeps
                                    // serving while the backfill runs.
                                    mig_metrics
                                        .set_management_readiness(turna_health::Readiness::Ready);
                                    if progress.total_processed > 0 {
                                        info!(
                                            total = progress.total_processed,
                                            "command-log backfill migration complete"
                                        );
                                    }
                                    break;
                                }
                                debug!(
                                    phase = %progress.phase,
                                    processed = progress.total_processed,
                                    "command-log backfill migration progress"
                                );
                            }
                            Err(error) => {
                                mig_metrics
                                    .command_log_migration_errors_total
                                    .fetch_add(1, Ordering::Relaxed);
                                warn!(%error,
                                      "command-log backfill migration batch failed; retrying");
                                tokio::select! {
                                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                                    _ = mig_shutdown.changed() => break,
                                }
                                continue;
                            }
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                            _ = mig_shutdown.changed() => break,
                        }
                    }
                });
            }

            {
                let cmd_backend = backend.clone();
                let cmd_store = store.clone();
                let cmd_metrics = metrics.clone();
                let cmd_node_id = cluster.node_id.clone();
                let cmd_incarnation = node_incarnation.clone();
                let cmd_runtime_management = runtime_management.clone();
                let cmd_routing = cluster_routing.clone();
                let cmd_gossip_draining = gossip_draining.clone();
                let cmd_gossip_notify = gossip_drain_notify.clone();
                let cmd_shutdown_tx = shutdown_tx.clone();
                let mut cmd_shutdown = shutdown_rx.clone();
                // P0.7: the command-log apply loop is a mandatory cluster task —
                // supervise it like writer/heartbeat/failover so an unexpected
                // exit marks the node Degraded and triggers shutdown instead of
                // leaving it Ready while commands silently stop being applied.
                command_log_handle = Some(spawn_supervised(
                    "command-log",
                    cmd_metrics.clone(),
                    shutdown_tx.clone(),
                    async move {
                    let mut ticker = tokio::time::interval(Duration::from_secs(1));
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = ticker.tick() => {}
                            _ = cmd_shutdown.changed() => break,
                        }
                        if *cmd_shutdown.borrow() {
                            break;
                        }
                        let claimed = match cmd_backend
                            .claim_commands(&cmd_node_id, &cmd_incarnation, 32, COMMAND_LEASE_MS)
                            .await
                        {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(%e, "command-log claim failed");
                                continue;
                            }
                        };
                        for cmd in claimed {
                            // claim_commands fences by incarnation: every claimed
                            // command targets this incarnation (or is unversioned).
                            // Stale-incarnation commands are never claimed here — the
                            // §2.4 sweeper resolves them to `done` + superseded.
                            let (status, result): (&'static str, String) =
                                match cmd.op.as_str() {
                                "update_config" => {
                                    cmd_runtime_management.apply_update_config(&cmd).await
                                }
                                "set_user_limits" => {
                                    cmd_runtime_management.apply_set_user_limits(&cmd).await
                                }
                                // Drain / undrain this node's real readiness + routing.
                                "set_draining" => {
                                    let on =
                                        cmd.args.first().map(|s| s == "true").unwrap_or(false);
                                    cmd_metrics.set_draining(on);
                                    if on {
                                        cmd_metrics.refresh_readiness();
                                        if let Some(r) = &cmd_routing {
                                            r.begin_drain();
                                        }
                                        // #6: advertise leaving via gossip now.
                                        cmd_gossip_draining.store(true, std::sync::atomic::Ordering::Relaxed);
                                        cmd_gossip_notify.notify_one();
                                    } else {
                                        // Undrain (P0.5 derived readiness): drop the
                                        // routing lame-duck flag and recompute readiness
                                        // from inputs. Divergence is a separate input
                                        // (backend_diverged), so an undrain returns to
                                        // Ready only when no divergence is active — it can
                                        // no longer clobber a real Degraded.
                                        if let Some(r) = &cmd_routing {
                                            r.end_drain();
                                        }
                                        // #6: stop advertising leaving; peers re-admit
                                        // after the tombstone grace expires.
                                        cmd_gossip_draining.store(false, std::sync::atomic::Ordering::Relaxed);
                                        cmd_metrics.refresh_readiness();
                                    }
                                    // #8: report the node's live active-allocation count
                                    // (same wire format as shutdown) so the control-plane
                                    // returns a real number, not a fabricated 0.
                                    let remaining = cmd_metrics
                                        .active_allocations
                                        .load(std::sync::atomic::Ordering::Relaxed);
                                    ("done", format!("remaining_allocations={remaining}"))
                                }
                                // Begin draining and signal this node's own shutdown.
                                "shutdown" => {
                                    // P0.6: honour graceful/timeout args — reject new
                                    // allocations + lame-duck redirect, then drain active
                                    // allocations (up to the timeout) before signalling
                                    // shutdown, reporting the real remaining count.
                                    let graceful = cmd
                                        .args
                                        .first()
                                        .map(|s| s != "false")
                                        .unwrap_or(true);
                                    let timeout_secs = cmd
                                        .args
                                        .get(1)
                                        .and_then(|s| s.parse::<u64>().ok())
                                        .unwrap_or(0);
                                    cmd_metrics.set_draining(true);
                                    cmd_metrics.refresh_readiness();
                                    if let Some(r) = &cmd_routing {
                                        r.begin_drain();
                                    }
                                    // #6: advertise leaving via gossip at drain start.
                                    cmd_gossip_draining.store(true, std::sync::atomic::Ordering::Relaxed);
                                    cmd_gossip_notify.notify_one();
                                    // Graceful: wait for allocations to drain, finishing
                                    // early once empty and never past the timeout.
                                    if graceful && timeout_secs > 0 {
                                        let deadline = tokio::time::Instant::now()
                                            + Duration::from_secs(timeout_secs);
                                        loop {
                                            let n = cmd_metrics
                                                .active_allocations
                                                .load(std::sync::atomic::Ordering::Relaxed);
                                            if n == 0 || tokio::time::Instant::now() >= deadline {
                                                break;
                                            }
                                            tokio::time::sleep(Duration::from_millis(500)).await;
                                        }
                                    }
                                    let remaining = cmd_metrics
                                        .active_allocations
                                        .load(std::sync::atomic::Ordering::Relaxed);
                                    info!(graceful, timeout_secs, remaining,
                                          "shutdown command drained");
                                    let _ = cmd_shutdown_tx.send(true);
                                    ("done", format!("remaining_allocations={remaining}"))
                                }
                                // delete_allocation (and unknown ops) handled here.
                                _ => apply_command(&cmd, &cmd_store, &cmd_metrics),
                                };
                            if status == runtime_management::RETRY_LATER_STATUS {
                                // #4: the terminal outcome could not be made durable.
                                // Do NOT complete — leave the command claimed so its
                                // lease expires and it is reclaimed + re-applied,
                                // rather than completing with an un-journaled outcome
                                // a lost completion could later re-validate.
                                warn!(request_id = %cmd.request_id, op = %cmd.op,
                                      "command outcome not durably recorded; \
                                       leaving claimed for reclaim");
                            } else {
                            info!(request_id = %cmd.request_id, op = %cmd.op, status,
                                  "applied control-plane command");
                            match cmd_backend
                                .complete_command(
                                    &cmd.request_id,
                                    &cmd_node_id,
                                    &cmd.claim_token,
                                    status,
                                    &result,
                                )
                                .await
                            {
                                Ok(true) => {}
                                Ok(false) => {
                                    // Fencing rejected us (P0.4): our lease was lost
                                    // and the claim superseded. Do NOT assume success
                                    // — the command will be reclaimed or dead-lettered.
                                    warn!(request_id = %cmd.request_id,
                                          "command completion rejected as stale (lease lost)");
                                }
                                Err(e) => {
                                    warn!(%e, request_id = %cmd.request_id,
                                          "failed to record command completion");
                                }
                            }
                            }
                        }
                        // §2.4: finalize stale-incarnation commands targeting this
                        // node that a prior incarnation left non-terminal — claim
                        // fences them out, so nothing else resolves them. Bounded
                        // per tick; a backlog drains over subsequent ticks.
                        let swept = cmd_runtime_management.sweep_stale_commands().await;
                        if swept > 0 {
                            info!(swept, "finalized stale-incarnation commands");
                        }
                    }
                }));
            }

            let _ = backend;
        }

        // Resolve the transport backend from config + a runtime io_uring probe.
        // `auto` uses io_uring when available, else tokio; `io_uring` forces it
        // (error if unavailable); `tokio` forces tokio.
        let transport_pref = match config.transport {
            turna_config::TransportSelection::Auto => turna_transport::TransportPreference::Auto,
            turna_config::TransportSelection::IoUring => {
                turna_transport::TransportPreference::IoUring
            }
            turna_config::TransportSelection::Tokio => turna_transport::TransportPreference::Tokio,
            turna_config::TransportSelection::AfXdp => turna_transport::TransportPreference::AfXdp,
        };
        let transport_decision = turna_transport::resolve(transport_pref)
            .map_err(std::io::Error::other)?;
        info!(
            backend = ?transport_decision.backend,
            reason  = %transport_decision.reason,
            "transport backend selected"
        );

        let mode = match transport_decision.backend {
            turna_transport::TransportBackend::Tokio => "tokio",
            turna_transport::TransportBackend::IoUring => "io_uring",
            turna_transport::TransportBackend::AfXdp => "af_xdp",
        };

        info!(
            %external_ip,
            relay_ports = ?(config.relay.min_port, config.relay.max_port),
            max_alloc   = config.relay.max_allocations,
            threads     = num_threads,
            health      = %format!("http://{health_listen}/health"),
            mode,
            "turna ready"
        );
        // 2.4: startup validation passed. The supported Tokio datapath marks
        // Ready only AFTER its listener is actually bound (see the Tokio arm
        // below), closing the P2 window where `/ready` returned 200 before
        // TokioTransport::bind. The opt-in AfXdp/io_uring datapaths bind inside
        // the datapath loop with no observable post-bind hook here, so they are
        // marked Ready at this point (behaviour unchanged for them).
        if !matches!(
            transport_decision.backend,
            turna_transport::TransportBackend::Tokio
        ) {
            metrics.set_readiness(turna_health::Readiness::Ready);
        }

        // I6: in cluster mode, persistence write-drops mean in-memory state has
        // diverged from the backend. Surface that as `Degraded` (/ready → 503) so
        // a load balancer / failover controller stops trusting this node instead
        // of leaving it Ready; recover to Ready when drops stop. Drain always wins
        // (once Draining, stop touching readiness). Single-node stays Ready — the
        // drop counter + alert are enough there (R6).
        if cluster.cluster_mode {
            let mon_metrics = metrics.clone();
            let mut mon_shutdown = shutdown_rx.clone();
            let mon_store = store.clone();
            let mon_backend = reconcile_backend.clone();
            let mon_counters = reconcile_counters.clone();
            let mon_ack = reconcile_ack.clone();
            let mon_node_id = cluster.node_id.clone();
            tokio::spawn(async move {
                let mut last = mon_metrics
                    .tarantool_writes_dropped
                    .load(std::sync::atomic::Ordering::Relaxed);
                let mut ticker = tokio::time::interval(Duration::from_secs(5));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        _ = mon_shutdown.changed() => break,
                    }
                    if *mon_shutdown.borrow() {
                        break;
                    }
                    // Drain is terminal — never override it.
                    if mon_metrics.is_draining() {
                        break;
                    }
                    let now = mon_metrics
                        .tarantool_writes_dropped
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if now > last {
                        // In-memory state has diverged from the backend. Go
                        // Degraded and attempt a reconcile pass now (P0 #16).
                        mon_metrics.set_backend_diverged(true);
                        mon_metrics.refresh_readiness();
                        if let Some(be) = &mon_backend {
                            match writer::reconcile(&mon_store, be, &mon_node_id).await {
                                Ok(s) => info!(
                                    zombies_deleted = s.zombies_deleted,
                                    live_resynced = s.live_resynced,
                                    "reconcile pass while drops active"
                                ),
                                Err(e) => warn!(%e, "reconcile failed"),
                            }
                        }
                    } else if mon_metrics.backend_diverged() {
                        // Drops have stopped. Only return to Ready once a reconcile
                        // pass confirms the backend is consistent with live state —
                        // not merely because drops paused (P0 #16).
                        match (&mon_backend, &mon_counters) {
                            (Some(be), Some(cnt)) => {
                                // Snapshot backend write errors BEFORE the pass so
                                // failures during this reconcile's flush are seen.
                                let errors_before = cnt
                                    .backend_errors
                                    .load(std::sync::atomic::Ordering::Relaxed);
                                match writer::reconcile(&mon_store, be, &mon_node_id).await {
                                    Ok(s) if s.resync_complete && s.barrier_enqueued => {
                                        // Queue accepted the full resync AND the
                                        // barrier. Wait for the writer to actually
                                        // flush everything up to the barrier into the
                                        // backend, and confirm no backend write failed
                                        // meanwhile — only then is the backend truly
                                        // consistent with live state (P0.1). Mere queue
                                        // acceptance is NOT enough to declare Ready.
                                        let acked = await_reconcile_barrier(
                                            &mon_ack,
                                            s.barrier_generation,
                                            &mut mon_shutdown,
                                        )
                                        .await;
                                        let errors_after = cnt
                                            .backend_errors
                                            .load(std::sync::atomic::Ordering::Relaxed);
                                        if acked && errors_after == errors_before {
                                            info!(
                                                zombies_deleted = s.zombies_deleted,
                                                live_resynced = s.live_resynced,
                                                generation = s.barrier_generation,
                                                "reconcile flushed to backend — returning to Ready"
                                            );
                                            mon_metrics.set_backend_diverged(false);
                                            mon_metrics.refresh_readiness();
                                        } else {
                                            warn!(
                                                barrier_acked = acked,
                                                backend_write_errors =
                                                    errors_after.saturating_sub(errors_before),
                                                "reconcile barrier not confirmed — staying Degraded"
                                            );
                                        }
                                    }
                                    Ok(s) => {
                                        // Resync re-dropped, or the barrier itself was
                                        // dropped under backpressure: backend is not
                                        // known-consistent, so stay Degraded and retry
                                        // on a later tick (P0.1).
                                        warn!(
                                            resync_complete = s.resync_complete,
                                            barrier_enqueued = s.barrier_enqueued,
                                            "reconcile could not enqueue full resync — staying Degraded"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(%e, "reconcile failed — staying Degraded")
                                    }
                                }
                            }
                            // No backend/counters to reconcile against (cluster
                            // without persistence): fall back to prior behaviour.
                            _ => {
                                mon_metrics.set_backend_diverged(false);
                                mon_metrics.refresh_readiness();
                            }
                        }
                    }
                    last = now;
                }
            });
        }

        // P0 #8: surface the shutdown budget so operators can size
        // terminationGracePeriodSeconds >= this. Budget = lame-duck drain
        // grace + persistence flush budget + a small safety margin.
        let shutdown_budget_secs =
            cluster.drain_grace_secs + PERSISTENCE_FLUSH_TIMEOUT_SECS
                + 2 * TASK_JOIN_TIMEOUT_SECS
                + 2;
        info!(
            drain_grace_secs = cluster.drain_grace_secs,
            persistence_flush_secs = PERSISTENCE_FLUSH_TIMEOUT_SECS,
            shutdown_budget_secs,
            "shutdown budget computed — set terminationGracePeriodSeconds >= \
             shutdown_budget_secs"
        );

        // Signal handler → shutdown (shared by both backends).
        let drain_routing = cluster_routing.clone();
        let drain_gossip_draining = gossip_draining.clone();
        let drain_gossip_notify = gossip_drain_notify.clone();
        let drain_metrics = metrics.clone();
        let drain_grace = cluster.drain_grace_secs;
        tokio::spawn(async move {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).unwrap();
                tokio::select! {
                    _ = ctrl_c => info!("SIGINT received"),
                    _ = sigterm.recv() => info!("SIGTERM received"),
                }
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
                info!("SIGINT received");
            }
            // Reject new allocations immediately on every node (508 Server
            // Draining via the processor). On a cluster also flip the routing
            // lame-duck so new clients are redirected (300 Try Alternate) to
            // another node during the grace window. Existing sessions keep
            // running until they expire / the worker drain tears them down.
            drain_metrics.set_draining(true);
            drain_metrics.refresh_readiness();
            if drain_grace > 0 {
                if let Some(routing) = &drain_routing {
                    // Cluster: lame-duck redirect (300 Try Alternate) new clients.
                    routing.begin_drain();
                    // #6: advertise leaving via gossip at drain start (k8s/systemd
                    // rolling upgrade path) so peers stop redirecting new clients here.
                    drain_gossip_draining.store(true, std::sync::atomic::Ordering::Relaxed);
                    drain_gossip_notify.notify_one();
                }
                info!(grace_secs = drain_grace, "draining active allocations before shutdown");
                // P0.6: poll for allocations to drain instead of sleeping the full grace
                // unconditionally — finish as soon as the node is empty, but never wait
                // past the deadline (keeps shutdown within the computed budget).
                let deadline = tokio::time::Instant::now() + Duration::from_secs(drain_grace);
                loop {
                    let remaining = drain_metrics
                        .active_allocations
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if remaining == 0 {
                        info!("drain complete — no active allocations remaining");
                        // A syslog emit belongs here — an outage window is bounded
                        // by the drain entries and by nothing else the system
                        // records. Not wired: this runs inside a spawned task whose
                        // captures I have not traced, and the exporter lives in
                        // main. Threading it in is a small change; guessing at the
                        // capture list and having it compile would be worse than
                        // leaving the note.
                        //
                        // Until then the transition is visible through
                        // turna_backend_readiness and the log line above.
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        warn!(remaining, "drain grace elapsed with allocations still active");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
            let _ = shutdown_tx.send(true);
        });

        let datapath_result: Result<(), Box<dyn std::error::Error>> =
            match transport_decision.backend {
            // AF_XDP ring datapath (Linux + af-xdp feature). Opt-in backend;
            // handles the main TURN socket via the xsk-rs datapath.
            turna_transport::TransportBackend::AfXdp => {
                let processor = Arc::new(
                    turna_relay::PacketProcessor::new_with_cluster(
                        store,
                        auth,
                        external_ip,
                        metrics.clone(),
                        cluster_routing.clone(),
                    )
                    .with_external_ip6(external_ip6),
                );
                let af_cfg = config.af_xdp.clone();
                let listen = config.listen;
                let af_shutdown = shutdown_rx.clone();
                let af_metrics = metrics.clone();
                match tokio::task::spawn_blocking(move || {
                    af_xdp_listener::run_af_xdp(af_cfg, processor, listen, af_shutdown, af_metrics)
                })
                .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(format!("af_xdp datapath: {e}").into()),
                    Err(join) => Err(Box::new(join) as Box<dyn std::error::Error>),
                }
            }

            // epoll + recvmmsg/sendmmsg — all platforms.
            turna_transport::TransportBackend::Tokio => {
                // With multiple workers the first socket must also join the
                // SO_REUSEPORT group (option set before bind).
                let transport = if turna_relay::server::recv_workers() > 1 {
                    turna_transport::TokioTransport::bind_reuseport(config.listen).await?
                } else {
                    turna_transport::TokioTransport::bind(config.listen).await?
                };
                // #8: the TURN listener is now bound — only now is it honest to
                // report Ready, so `/ready=200` implies the socket is accepting.
                metrics.set_readiness(turna_health::Readiness::Ready);
                let migration = build_migration_manager(&config.migration);
                let tcp_relay = if config.tcp_relay.enabled {
                    info!("RFC 6062 TCP relay enabled");
                    Some(std::sync::Arc::new(turna_relay::tcp_relay::TcpRelayManager::new(
                        build_tcp_relay_config(&config.tcp_relay),
                    )))
                } else {
                    None
                };
                let server = turna_relay::RelayServer::new_full(
                    transport,
                    store,
                    auth,
                    external_ip,
                    metrics.clone(),
                    cluster_routing.clone(),
                    migration,
                    tcp_relay,
                )
                .with_external_ip6(external_ip6)
                .with_drain_timeout_secs(config.relay.drain_timeout_secs);
                #[cfg(feature = "tls")]
                let server = if tls_cfg.enabled {
                    info!(listen = %tls_cfg.listen, cert = %tls_cfg.cert_path.display(), "TURNS (TLS) enabled");
                    server.with_tls(build_tls_transport_config(&tls_cfg))
                } else {
                    server
                };
                #[cfg(feature = "sctp")]
                let server = if config.sctp.enabled {
                    info!(listen = %config.sctp.listen, "TURN-over-SCTP (experimental) enabled");
                    server.with_sctp(build_sctp_transport_config(&config.sctp))
                } else {
                    server
                };
                // QUIC/DTLS get a dedicated relay egress (sharing this server's
                // processor + client_sinks) so their relay-plane actions
                // (RegisterRelay/Forward/CloseRelay) reach a peer→client return
                // path. Without it the listeners would drop those actions.
                if config.quic.enabled || config.dtls.enabled {
                    let egress_out =
                        turna_transport::TokioTransport::bind("0.0.0.0:0".parse().unwrap()).await?;
                    let (egress, _egress_task) = turna_relay::start_relay_egress(
                        server.processor().clone(),
                        server.client_sinks(),
                        egress_out,
                        external_ip,
                    );
                    if config.quic.enabled {
                        quic_listener::spawn_quic(
                            &config.quic,
                            server.processor().clone(),
                            server.client_sinks(),
                            metrics.clone(),
                            egress.clone(),
                            shutdown_rx.clone(),
                        );
                    }
                    if config.dtls.enabled {
                        dtls_listener::spawn_dtls(
                            &config.dtls,
                            server.processor().clone(),
                            server.client_sinks(),
                            metrics.clone(),
                            egress.clone(),
                            shutdown_rx.clone(),
                        )?;
                    }
                }
                server.run(shutdown_rx).await
            }

            // io_uring thread-per-core datapath (Linux + io-uring feature only).
            // resolve() cannot pick this backend without that cfg.
            turna_transport::TransportBackend::IoUring => {
                #[cfg(all(target_os = "linux", feature = "io-uring"))]
                {
                    use turna_relay::handler::RelayHandler;
                    use turna_transport::worker::{spawn_worker_pool, WorkerPoolConfig};

                    // Multi-worker thread-per-core. Each io_uring engine binds
                    // the listen address with SO_REUSEPORT (set in
                    // UringEngine::new), so the kernel shards inbound datagrams
                    // by client 4-tuple: a given client always lands on the same
                    // worker — which is exactly where its allocation and relay
                    // socket live. Peer->relay traffic lands on the worker that
                    // bound that relay port. The AllocationStore is DashMap-backed
                    // (lock-free reads on the media path) and shared across
                    // workers; only the rare PortAllocator path takes a mutex.
                    //
                    // Worker count defaults to the CPU count; override with
                    // TURNA_IOURING_WORKERS=<n>.
                    //
                    // Limitation: a client that changes its source 5-tuple (NAT
                    // rebind) may rehash to another worker with no allocation for
                    // it and must re-Allocate (zero-downtime migration is P2).
                    let num_workers = std::env::var("TURNA_IOURING_WORKERS")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .filter(|&n| n >= 1)
                        .unwrap_or_else(|| {
                            std::thread::available_parallelism()
                                .map(|n| n.get())
                                .unwrap_or(1)
                        });
                    info!(num_workers, "io_uring multi-worker pool");

                    // Same gap the tokio path had: `turna_transport_readiness` is
                    // exported and documented as the primary UDP datapath's
                    // readiness, but nothing set it here either — a soak on this
                    // backend read `0` (starting) for its whole run while serving
                    // traffic. Found by comparing the two soak verdicts: tokio said
                    // "ready throughout", io_uring said "values seen: [0.0]".
                    metrics.set_transport_readiness(turna_health::Readiness::Ready);

                    // QUIC/DTLS coexist with the io_uring datapath: they run as
                    // independent tokio transports (separate ports) served by a
                    // dedicated PacketProcessor sharing the same store/auth, plus
                    // a tokio relay-egress for the peer→client return path. The
                    // io_uring workers own the main :3478 socket; QUIC/DTLS
                    // clients are reached via the egress' client_sinks.
                    if config.quic.enabled || config.dtls.enabled {
                        let qd_processor = Arc::new(
                            turna_relay::PacketProcessor::new_with_cluster(
                                store.clone(),
                                auth.clone(),
                                external_ip,
                                metrics.clone(),
                                cluster_routing.clone(),
                            )
                            .with_external_ip6(external_ip6),
                        );
                        let qd_sinks = turna_relay::new_client_sinks();
                        // Ephemeral fallback socket (bound off :3478 so it never
                        // joins the io_uring reuseport group); QUIC/DTLS clients
                        // are always reached via client_sinks, so it is unused.
                        let egress_out =
                            turna_transport::TokioTransport::bind("0.0.0.0:0".parse().unwrap())
                                .await?;
                        let (egress, _egress_task) = turna_relay::start_relay_egress(
                            qd_processor.clone(),
                            qd_sinks.clone(),
                            egress_out,
                            external_ip,
                        );
                        if config.quic.enabled {
                            quic_listener::spawn_quic(
                                &config.quic,
                                qd_processor.clone(),
                                qd_sinks.clone(),
                                metrics.clone(),
                                egress.clone(),
                                shutdown_rx.clone(),
                            );
                        }
                        if config.dtls.enabled {
                            dtls_listener::spawn_dtls(
                                &config.dtls,
                                qd_processor.clone(),
                                qd_sinks.clone(),
                                metrics.clone(),
                                egress.clone(),
                                shutdown_rx.clone(),
                            )?;
                        }
                        info!("QUIC/DTLS listeners started alongside io_uring datapath");
                    }
                    // RFC 8016 sharded ownership: reuse the single route table
                    // created above (also wired into the health server's
                    // relay-route metrics), so what the workers update is
                    // exactly what `/metrics` reports.
                    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let ring_agg = Arc::new(
                        turna_transport::uring::RingStatsAggregate::new(num_workers),
                    );
                    let relay_cap = config.io_uring.relay_socket_capacity_per_worker;
                    if relay_cap == 0 || relay_cap > 1024 {
                        return Err(format!(
                            "[turn.io_uring] relay_socket_capacity_per_worker must be 1..=1024 \
                             (16-bit msghdr index limit), got {relay_cap}"
                        )
                        .into());
                    }
                    let pool_cfg = WorkerPoolConfig {
                        listen_addr: config.listen,
                        num_workers,
                        relay_capacity_per_worker: relay_cap,
                        buffers_per_worker: 2048,
                        external_ip,
                        relay_routes,
                        cmd_poll_timeout: std::time::Duration::from_micros(500),
                        shutdown: shutdown.clone(),
                        drain_grace: worker_drain_grace,
                        ring_stats: Some(ring_agg.clone()),
                    };
                    let store_f = store.clone();
                    let auth_f = auth.clone();
                    let metrics_f = metrics.clone();
                    let cluster_f = cluster_routing.clone();
                    let handles = spawn_worker_pool(pool_cfg, move |_worker_id| {
                        RelayHandler::new_with_cluster(
                            store_f.clone(),
                            auth_f.clone(),
                            external_ip,
                            metrics_f.clone(),
                            cluster_f.clone(),
                        )
                    });

                    // io_uring mode does not run RelayServer::run, so nothing
                    // else reaps expired allocations — without this the store and
                    // port allocator grow unbounded. (Relay sockets are closed by
                    // the worker engine on expiry; the DTLS/QUIC egress reaps its
                    // own sockets in start_relay_egress.)
                    {
                        let store = store.clone();
                        let metrics = metrics.clone();
                        tokio::spawn(async move {
                            let mut ticker =
                                tokio::time::interval(std::time::Duration::from_secs(5));
                            loop {
                                ticker.tick().await;
                                let removed = store.cleanup_expired();
                                if removed > 0 {
                                    metrics.active_allocations.fetch_sub(
                                        removed as u64,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    info!(
                                        removed,
                                        active = store.len(),
                                        "expired allocations cleaned (io_uring)"
                                    );
                                }
                            }
                        });
                    }

                    // Mirror summed io_uring ring stats into Prometheus Metrics
                    // every 5s (workers publish their slots on a 30s tick, so the
                    // gauges refresh at worker cadence). Runs until process exit.
                    {
                        let ring_agg = ring_agg.clone();
                        let metrics = metrics.clone();
                        tokio::spawn(async move {
                            use std::sync::atomic::Ordering::Relaxed;
                            let mut tick =
                                tokio::time::interval(std::time::Duration::from_secs(5));
                            loop {
                                tick.tick().await;
                                let t = ring_agg.totals();
                                metrics.uring_workers.store(t.workers, Relaxed);
                                metrics.uring_cqe_drained_total.store(t.cqe_drained, Relaxed);
                                metrics.uring_cqe_batches_total.store(t.cqe_batches, Relaxed);
                                metrics.uring_cqe_max_batch.store(t.cqe_max_batch, Relaxed);
                                metrics
                                    .uring_sq_push_failed_total
                                    .store(t.sq_push_failed, Relaxed);
                                metrics.uring_sq_len.store(t.sq_len, Relaxed);
                                metrics.uring_sq_capacity.store(t.sq_capacity, Relaxed);
                                metrics.uring_cq_len.store(t.cq_len, Relaxed);
                                metrics
                                    .uring_buffers_available
                                    .store(t.buffers_available, Relaxed);
                                metrics
                                    .uring_relay_capacity_exhausted_total
                                    .store(t.relay_capacity_exhausted, Relaxed);
                                metrics
                                    .uring_inflight_send_slots
                                    .store(t.send_slots_inflight, Relaxed);
                                metrics
                                    .uring_send_slot_stalled_total
                                    .store(t.send_slot_stalled, Relaxed);
                            }
                        });
                    }
                    // pool's drain flag — each worker stops taking new traffic
                    // on its main socket, lets established relay flows finish
                    // for the grace window, unregisters its routes, and exits
                    // its loop. We then join the threads (they return within the
                    // grace window) instead of abandoning them on process exit.
                    let mut rx = shutdown_rx;
                    let _ = rx.changed().await;
                    info!(
                        grace_secs = worker_drain_grace.as_secs(),
                        "shutdown signalled; draining io_uring worker pool"
                    );
                    shutdown.store(true, std::sync::atomic::Ordering::Release);
                    let _ = tokio::task::spawn_blocking(move || {
                        for h in handles {
                            let _ = h.join();
                        }
                    })
                    .await;
                    info!("io_uring worker pool drained");
                    Ok(())
                }
                #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
                {
                    unreachable!(
                        "resolve() cannot select io_uring without linux + io-uring feature"
                    )
                }
            }
        };

        // ── P0 #8: bounded shutdown — flush persistence deterministically ─────
        // The datapath has returned (shutdown observed). Wait for the
        // write-behind writer to flush its queue and exit within the budget,
        // rather than letting the runtime drop abort it mid-flush. This is the
        // difference between "persistence queue flushed" and "detached task
        // killed on exit".
        // The writer flush is correctness-critical (persistence queue must be
        // drained); heartbeat/failover only need to observe shutdown and stop.
        join_within_budget(
            "persistence-writer",
            writer_handle,
            Duration::from_secs(PERSISTENCE_FLUSH_TIMEOUT_SECS),
        )
        .await;
        join_within_budget(
            "heartbeat",
            heartbeat_handle,
            Duration::from_secs(TASK_JOIN_TIMEOUT_SECS),
        )
        .await;
        join_within_budget(
            "failover",
            failover_handle,
            Duration::from_secs(TASK_JOIN_TIMEOUT_SECS),
        )
        .await;
        join_within_budget(
            "command-log",
            command_log_handle,
            Duration::from_secs(TASK_JOIN_TIMEOUT_SECS),
        )
        .await;

        datapath_result
    })
}

/// Exposes cluster membership to the health server's GET /cluster endpoint.
/// Returns the gossip ring when clustered, or just this node otherwise.
struct ClusterStatusView {
    local_node_id: String,
    local_addr: String,
    ring: Option<Arc<parking_lot::RwLock<HashRing>>>,
}

impl turna_health::ClusterView for ClusterStatusView {
    fn nodes(&self) -> Vec<turna_health::ClusterNodeInfo> {
        match &self.ring {
            Some(ring) => ring
                .read()
                .snapshot()
                .into_iter()
                .map(|n| turna_health::ClusterNodeInfo {
                    is_self: n.node_id == self.local_node_id,
                    node_id: n.node_id,
                    turn_addr: n.turn_addr.to_string(),
                })
                .collect(),
            None => vec![turna_health::ClusterNodeInfo {
                node_id: self.local_node_id.clone(),
                turn_addr: self.local_addr.clone(),
                is_self: true,
            }],
        }
    }
}

fn resolve_turn_announce_addr(
    cluster: &ClusterConfig,
    turn: &TurnConfig,
    external_ip: std::net::IpAddr,
) -> SocketAddr {
    let configured = cluster.turn_announce_addr;
    let ip = if configured.ip().is_unspecified() {
        external_ip
    } else {
        configured.ip()
    };
    let port = if configured.port() == 0 {
        turn.listen.port()
    } else {
        configured.port()
    };
    SocketAddr::new(ip, port)
}

#[derive(Copy, Clone)]
enum DumpMode {
    Masked,
    Raw,
}

/// Build the optional RFC 8016 migration ticket manager from config.
/// Returns `None` when `turn.migration.enabled = false`.
fn build_migration_manager(
    cfg: &turna_config::MigrationConfig,
) -> Option<turna_transport::migration::MigrationManager> {
    use turna_transport::migration::MigrationManager;
    if !cfg.enabled {
        return None;
    }
    let secret = if cfg.ticket_secret.is_empty() {
        // We only reach the random fallback on a single, non-production node:
        // config validation now hard-errors on an empty ticket_secret whenever
        // clustering is enabled (cross-node tickets would silently fail) or in
        // production. So this warning is the dev-single-node case only.
        warn!(
            "turn.migration enabled with no ticket_secret — using a random \
             per-process key (single-node/dev only); mobility tickets will not \
             survive a restart. Set a stable ticket_secret before deploying."
        );
        random_secret()
    } else {
        cfg.ticket_secret.clone().into_bytes()
    };
    info!(
        ttl_secs = cfg.ticket_ttl_secs,
        "RFC 8016 connection migration enabled"
    );
    Some(MigrationManager::with_ttl(
        secret,
        std::time::Duration::from_secs(cfg.ticket_ttl_secs),
    ))
}

/// 32 random bytes from the OS CSPRNG. Falls back to a (weak, dev-only)
/// time seed if `/dev/urandom` is unavailable — acceptable because an empty
/// secret is already rejected in production by config validation.
fn random_secret() -> Vec<u8> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.to_vec();
        }
    }
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    n.to_le_bytes().to_vec()
}

fn print_usage() {
    eprintln!(
        "turna-node — Turna TURN/STUN server

USAGE:
    turna-node [OPTIONS] [CONFIG_PATH]

OPTIONS:
    --dump-config <PATH>      Load config, print with secrets masked, exit.
    --dump-config-raw <PATH>  Like --dump-config but shows secrets verbatim.
    -h, --help                Print this help and exit.

EXAMPLES:
    turna-node /etc/turna/turn.toml
    turna-node --dump-config /etc/turna/turn.toml
"
    );
}

fn print_dumped_config(cfg: &TurnaConfig, mode: DumpMode) {
    let mask = |s: &str| -> String {
        match mode {
            DumpMode::Raw => s.to_string(),
            DumpMode::Masked => {
                if s.is_empty() {
                    String::new()
                } else {
                    let prefix: String = s.chars().take(4).collect();
                    format!("***{prefix}…[{} chars]", s.chars().count())
                }
            }
        }
    };

    let header = match mode {
        DumpMode::Raw => "# turna-node --dump-config-raw output — CONTAINS SECRETS",
        DumpMode::Masked => "# turna-node --dump-config output — secrets masked",
    };
    println!("{header}");
    println!("# Fully-resolved config. ${{VAR}} and file:// already expanded.");
    println!();
    println!("production = {}", cfg.production);
    println!();

    let t = &cfg.turn;
    println!("[turn]");
    println!("listen      = \"{}\"", t.listen);
    println!("external_ip = \"{}\"", t.external_ip);
    println!("external_ip6 = \"{}\"", t.external_ip6);
    println!("realm       = \"{}\"", t.realm);
    println!();
    println!("[turn.auth]");
    println!("shared_secret = \"{}\"", mask(&t.auth.shared_secret));
    println!("token_ttl     = {}", t.auth.token_ttl);
    for u in &t.auth.static_users {
        println!();
        println!("[[turn.auth.static_users]]");
        println!("username = \"{}\"", u.username);
        println!("password = \"{}\"", mask(&u.password));
    }
    println!();
    println!("[turn.relay]");
    println!("min_port        = {}", t.relay.min_port);
    println!("max_port        = {}", t.relay.max_port);
    println!("max_allocations = {}", t.relay.max_allocations);
    println!();
    println!("[turn.relay.quota]");
    println!(
        "max_bytes_per_sec_per_allocation = {}",
        t.relay.quota.max_bytes_per_sec_per_allocation
    );
    println!("max_per_user      = {}", t.relay.quota.max_per_user);
    println!();
    println!("[turn.migration]");
    println!("enabled         = {}", t.migration.enabled);
    println!("ticket_secret   = \"{}\"", mask(&t.migration.ticket_secret));
    println!("ticket_ttl_secs = {}", t.migration.ticket_ttl_secs);
    println!();
    println!("[turn.observability]");
    println!(
        "otlp_endpoint        = \"{}\"",
        t.observability.otlp_endpoint
    );
    println!(
        "trace_sample_rate    = {}",
        t.observability.trace_sample_rate
    );
    println!("json_logs            = {}", t.observability.json_logs);
    println!(
        "max_spans_per_second = {}",
        t.observability.max_spans_per_second
    );
    println!();

    let s = &cfg.signaling;
    println!("[signaling]");
    println!("listen             = \"{}\"", s.listen);
    println!("turn_url           = \"{}\"", s.turn_url);
    println!("turn_shared_secret = \"{}\"", mask(&s.turn_shared_secret));
    println!();
    println!("[health]");
    println!("listen = \"{}\"", cfg.health.listen);
    println!();

    let c = &cfg.cluster;
    println!("[cluster]");
    println!("node_id              = \"{}\"", c.node_id);
    println!("cluster_mode         = {}", c.cluster_mode);
    println!("gossip_port          = {}", c.gossip_port);
    println!("seeds                = {:?}", c.seeds);
    println!("gossip_bind          = \"{}\"", c.gossip_bind);
    println!("gossip_seeds         = {:?}", c.gossip_seeds);
    println!("gossip_interval_secs = {}", c.gossip_interval_secs);
    println!("gossip_timeout_secs  = {}", c.gossip_timeout_secs);
    println!("turn_announce_addr   = \"{}\"", c.turn_announce_addr);
    println!("cluster_name         = \"{}\"", c.cluster_name);
    println!("gossip_advertise_addr= \"{}\"", c.gossip_advertise_addr);
    println!("cluster_secret       = \"{}\"", mask(&c.cluster_secret));
    println!("drain_grace_secs     = {}", c.drain_grace_secs);
    println!();
    println!("[cluster.backend]");
    println!("type      = \"{}\"", c.backend.r#type);
    println!("uri       = \"{}\"", c.backend.uri);
    println!("user      = \"{}\"", c.backend.user);
    println!("password  = \"{}\"", mask(&c.backend.password));
    println!("pool_size = {}", c.backend.pool_size);
    println!();
    println!("[cluster.persistence]");
    println!("mode               = \"{}\"", c.persistence.mode);
    println!("channel_capacity   = {}", c.persistence.channel_capacity);
    println!("batch_max_size     = {}", c.persistence.batch_max_size);
    println!("batch_max_delay_ms = {}", c.persistence.batch_max_delay_ms);
    println!("user_refresh_secs  = {}", c.persistence.user_refresh_secs);
    println!();
    println!("[management]");
    println!("listen = \"{}\"", cfg.management.listen);
    println!();

    let g = &cfg.grpc;
    println!("[grpc]");
    println!("tls_mode = \"{}\"", g.tls_mode);
    println!("tls_cert = \"{}\"", g.tls_cert);
    println!("tls_key  = \"{}\"", g.tls_key);
    println!("tls_ca   = \"{}\"", g.tls_ca);
    println!();

    let t = &cfg.tls;
    println!("[tls]");
    println!("enabled               = {}", t.enabled);
    println!("listen                = \"{}\"", t.listen);
    println!("cert_path             = \"{}\"", t.cert_path.display());
    println!("key_path              = \"{}\"", t.key_path.display());
    println!("max_frame_size        = {}", t.max_frame_size);
    println!("handshake_timeout_secs= {}", t.handshake_timeout_secs);
    println!("read_timeout_secs     = {}", t.read_timeout_secs);
    println!("max_connections       = {}", t.max_connections);
    println!("enable_alpn           = {}", t.enable_alpn);
}

#[cfg(test)]
mod profile_tests {
    use super::{profile_gates, ProfileGates};
    use turna_config::ClusterConfig;

    fn cfg(backend_type: &str, persistence_mode: &str, cluster_mode: bool) -> ClusterConfig {
        let mut c = ClusterConfig::default();
        c.backend.r#type = backend_type.into();
        c.persistence.mode = persistence_mode.into();
        c.cluster_mode = cluster_mode;
        c
    }

    // §5.6: deployment-profile worker matrix.
    #[test]
    fn profile_gates_matrix() {
        // Standalone, no durable backend → nothing optional runs.
        assert_eq!(
            profile_gates(&cfg("memory", "disabled", false)),
            ProfileGates {
                management: false,
                bulk_load: false,
                writer: false,
                failover: false,
                gossip: false,
            }
        );
        // Management-only (durable backend, persistence off) → management plane
        // only; no bulk load, writer, failover, or gossip.
        assert_eq!(
            profile_gates(&cfg("tarantool", "disabled", false)),
            ProfileGates {
                management: true,
                bulk_load: false,
                writer: false,
                failover: false,
                gossip: false,
            }
        );
        // Management + persistence → adds allocation load + writer; still NO
        // failover/gossip.
        assert_eq!(
            profile_gates(&cfg("tarantool", "write_behind", false)),
            ProfileGates {
                management: true,
                bulk_load: true,
                writer: true,
                failover: false,
                gossip: false,
            }
        );
        // Cluster + persistence + failover → everything.
        assert_eq!(
            profile_gates(&cfg("tarantool", "write_behind", true)),
            ProfileGates {
                management: true,
                bulk_load: true,
                writer: true,
                failover: true,
                gossip: true,
            }
        );
    }

    // The core #5 invariant: allocation persistence (even "scaffold") must NOT
    // enable failover — only cluster_mode does.
    #[test]
    fn failover_never_follows_persistence_alone() {
        assert!(!profile_gates(&cfg("tarantool", "write_behind", false)).failover);
        assert!(!profile_gates(&cfg("tarantool", "scaffold", false)).failover);
        assert!(profile_gates(&cfg("tarantool", "write_behind", true)).failover);
    }
}
