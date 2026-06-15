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
mod writer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use turna_auth::{AuthMode, AuthRegistry};
use turna_cluster::gossip::{run_gossip, GossipConfig};
use turna_cluster::{ClusterNode, HashRing};
use turna_config::{ClusterConfig, TurnConfig, TurnaConfig};
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

    let (config, cluster, health_listen, tls_cfg, tenants) = match config_path {
        Some(path) => {
            let root = TurnaConfig::load(&path)?;
            let health_listen = root.health.listen;
            let tls_cfg = root.tls.clone();
            (
                root.turn,
                root.cluster,
                health_listen,
                tls_cfg,
                root.tenants,
            )
        }
        None => {
            turna_observability::init();
            info!("no config file, using defaults");
            (
                TurnConfig::default(),
                ClusterConfig::default(),
                "0.0.0.0:9090".parse().unwrap(),
                turna_config::TlsConfig::default(),
                Vec::new(),
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
    let base_auth = if config.auth.static_users.is_empty() {
        AuthMode::SharedSecret {
            realm: config.realm.clone(),
            secret: config.auth.shared_secret.as_bytes().to_vec(),
        }
    } else {
        AuthMode::LongTerm {
            realm: config.realm.clone(),
            users: config
                .auth
                .static_users
                .iter()
                .map(|u| (u.username.clone(), u.password.clone()))
                .collect(),
        }
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
                AuthMode::LongTerm {
                    realm: t.realm.clone(),
                    users: t
                        .static_users
                        .iter()
                        .map(|u| (u.username.clone(), u.password.clone()))
                        .collect(),
                }
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
        s.quota = turna_session::BandwidthQuota {
            max_bytes_per_sec: config.relay.quota.max_bytes_per_sec,
            max_per_user: config.relay.quota.max_per_user,
        };
        // Multi-tenancy: isolated relay-port pool per tenant (disjoint ranges).
        for t in &tenants {
            s = s.with_tenant_pool(
                t.id.clone(),
                t.relay_port_range[0],
                t.relay_port_range[1],
                t.max_allocations,
                turna_session::BandwidthQuota {
                    max_bytes_per_sec: t.quota.max_bytes_per_sec,
                    max_per_user: t.quota.max_per_user,
                },
            );
        }
        s
    });

    let metrics = Arc::new(Metrics::new());

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
        enable_alpn: c.enable_alpn,
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
) -> Result<(), Box<dyn std::error::Error>> {
    // `tls_cfg` is only consumed when the `tls` feature is enabled.
    #[cfg(not(feature = "tls"))]
    let _ = &tls_cfg;
    let num_threads = std::env::var("TURNA_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
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

        // Health check server is started below, after cluster_routing is built,
        // so it can also expose GET /cluster (gossip ring membership).

        let cluster_routing = if cluster.cluster_mode {
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
            tokio::spawn(async move {
                if let Err(e) = run_gossip(
                    gossip_cfg,
                    move |nodes| {
                        metrics_for_gossip
                            .cluster_nodes
                            .store(nodes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        ring_for_gossip.write().update_nodes(nodes);
                    },
                    gossip_shutdown,
                )
                .await
                {
                    warn!(%e, "cluster gossip stopped with error");
                }
            });

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

            // Per-tenant traffic provider: snapshot the store's cumulative
            // per-tenant counters (accrued at allocation teardown) on each
            // scrape. Empty until tenant-scoped allocations have closed, so
            // single-tenant deployments see no extra output.
            let tenant_traffic: Option<turna_health::TenantTrafficProvider> = {
                let store = store.clone();
                Some(Arc::new(move || store.tenant_traffic_snapshot()))
            };

            tokio::spawn(async move {
                let _ = turna_health::serve_with_cluster_routes(
                    health_listen,
                    health_metrics,
                    Some(cluster_view),
                    relay_route_metrics,
                    tenant_traffic,
                )
                .await;
            });
        }

        // ── PR2: write-behind writer task ─────────────────────────────────────
        if cluster.persistence.is_enabled() {
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
                    warn!(backend = %other,
                          "unknown [cluster.backend.type]; falling back to memory");
                    BackendConfig::Memory
                }
            };

            let backend =
                create_backend(&backend_cfg)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error> {
                        format!("state backend init failed: {e}").into()
                    })?;
            let backend = Arc::new(backend);

            let bulk_stats = bulk_load::bulk_load(&backend, &store, &cluster.node_id).await;
            metrics.active_allocations.fetch_add(
                bulk_stats.rehydrated as u64,
                std::sync::atomic::Ordering::Relaxed,
            );

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
            tokio::spawn(async move {
                writer::run_writer(
                    writer_backend,
                    writer_store,
                    realm,
                    writer_cfg,
                    writer_metrics,
                    counters,
                    rx,
                    writer_shutdown,
                )
                .await;
            });

            // ── PR4: heartbeat task ───────────────────────────────────────
            let hb_backend = backend.clone();
            let hb_metrics = metrics.clone();
            let hb_shutdown = shutdown_rx.clone();
            let hb_cfg = heartbeat::HeartbeatConfig {
                node_id: cluster.node_id.clone(),
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
            tokio::spawn(async move {
                heartbeat::run_heartbeat(hb_backend, hb_metrics, hb_cfg, hb_shutdown).await;
            });

            // ── PR5: failover claim task ──────────────────────────────────
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
            tokio::spawn(async move {
                let _ =
                    failover::run_failover(fo_backend, fo_store, fo_cfg, fo_metrics, fo_shutdown)
                        .await;
            });

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
        // 2.4: startup validation passed and listeners are coming up -> mark
        // the node ready so `/ready` returns 200 (flips to 503 on drain).
        metrics.set_readiness(turna_health::Readiness::Ready);

        // Signal handler → shutdown (shared by both backends).
        let drain_routing = cluster_routing.clone();
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
            drain_metrics.set_readiness(turna_health::Readiness::Draining);
            if let Some(routing) = &drain_routing {
                if drain_grace > 0 {
                    routing.begin_drain();
                    info!(grace_secs = drain_grace, "lame-duck: draining new clients before shutdown");
                    tokio::time::sleep(Duration::from_secs(drain_grace)).await;
                }
            }
            let _ = shutdown_tx.send(true);
        });

        match transport_decision.backend {
            // AF_XDP ring datapath (Linux + af-xdp feature). Opt-in backend;
            // handles the main TURN socket via the xsk-rs datapath.
            turna_transport::TransportBackend::AfXdp => {
                let processor = Arc::new(turna_relay::PacketProcessor::new_with_cluster(
                    store,
                    auth,
                    external_ip,
                    metrics.clone(),
                    cluster_routing.clone(),
                ));
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
                let migration = build_migration_manager(&config.migration);
                let server = turna_relay::RelayServer::new_full(
                    transport,
                    store,
                    auth,
                    external_ip,
                    metrics.clone(),
                    cluster_routing.clone(),
                    migration,
                );
                #[cfg(feature = "tls")]
                let server = if tls_cfg.enabled {
                    info!(listen = %tls_cfg.listen, cert = %tls_cfg.cert_path.display(), "TURNS (TLS) enabled");
                    server.with_tls(build_tls_transport_config(&tls_cfg))
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

                    // QUIC/DTLS coexist with the io_uring datapath: they run as
                    // independent tokio transports (separate ports) served by a
                    // dedicated PacketProcessor sharing the same store/auth, plus
                    // a tokio relay-egress for the peer→client return path. The
                    // io_uring workers own the main :3478 socket; QUIC/DTLS
                    // clients are reached via the egress' client_sinks.
                    if config.quic.enabled || config.dtls.enabled {
                        let qd_processor = Arc::new(turna_relay::PacketProcessor::new_with_cluster(
                            store.clone(),
                            auth.clone(),
                            external_ip,
                            metrics.clone(),
                            cluster_routing.clone(),
                        ));
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
        }
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
    println!("max_bytes_per_sec = {}", t.relay.quota.max_bytes_per_sec);
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
