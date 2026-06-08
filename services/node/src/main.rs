//! Turna TURN server entry point
//!
//! Modes:
//! - tokio (default): multi-threaded async, works everywhere
//! - io_uring (--features io-uring): io_uring for main socket + tokio for relay sockets

mod bulk_load;
mod failover;
mod heartbeat;
mod writer;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use turna_auth::AuthMode;
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
        let _ = turna_observability::init();
        let path = config_path.ok_or_else(|| -> Box<dyn std::error::Error> {
            "--dump-config requires a config file path".into()
        })?;
        let cfg = TurnaConfig::load(&path)?;
        print_dumped_config(&cfg, mode);
        return Ok(());
    }

    let (config, cluster, health_listen, tls_cfg) = match config_path {
        Some(path) => {
            let root = TurnaConfig::load(&path)?;
            let health_listen = root.health.listen;
            let tls_cfg = root.tls.clone();
            (root.turn, root.cluster, health_listen, tls_cfg)
        }
        None => {
            turna_observability::init();
            info!("no config file, using defaults");
            (
                TurnConfig::default(),
                ClusterConfig::default(),
                "0.0.0.0:9090".parse().unwrap(),
                turna_config::TlsConfig::default(),
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
            let _ = turna_observability::init();
            turna_observability::init_with_config(Default::default())
                .expect("fallback telemetry init")
        });

    info!(listen = %config.listen, realm = %config.realm, "starting turna");

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

    let auth: Arc<AuthMode> = if config.auth.static_users.is_empty() {
        Arc::new(AuthMode::SharedSecret {
            realm: config.realm.clone(),
            secret: config.auth.shared_secret.as_bytes().to_vec(),
        })
    } else {
        Arc::new(AuthMode::LongTerm {
            realm: config.realm.clone(),
            users: config
                .auth
                .static_users
                .iter()
                .map(|u| (u.username.clone(), u.password.clone()))
                .collect(),
        })
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
        s
    });

    let metrics = Arc::new(Metrics::new());

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

fn run_tokio(
    config: TurnConfig,
    cluster: ClusterConfig,
    store: Arc<AllocationStore>,
    auth: Arc<AuthMode>,
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
            tokio::spawn(async move {
                let _ = turna_health::serve_with_cluster(health_listen, health_metrics, Some(cluster_view))
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
        };
        let transport_decision = turna_transport::resolve(transport_pref)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        info!(
            backend = ?transport_decision.backend,
            reason  = %transport_decision.reason,
            "transport backend selected"
        );

        let mode = match transport_decision.backend {
            turna_transport::TransportBackend::Tokio => "tokio",
            turna_transport::TransportBackend::IoUring => "io_uring",
        };

        info!(
            %external_ip,
            relay_ports = ?(config.relay.min_port, config.relay.max_port),
            max_alloc   = config.relay.max_allocations,
            threads     = num_threads,
            health      = "http://0.0.0.0:9090/health",
            mode,
            "turna ready"
        );

        // Signal handler → shutdown (shared by both backends).
        let drain_routing = cluster_routing.clone();
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
            // Lame-duck: stop taking new clients, let the ring learn we're going,
            // then exit. Existing sessions keep running until they expire.
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
            // epoll + recvmmsg/sendmmsg — all platforms.
            turna_transport::TransportBackend::Tokio => {
                // With multiple workers the first socket must also join the
                // SO_REUSEPORT group (option set before bind).
                let transport = if turna_relay::server::recv_workers() > 1 {
                    turna_transport::TokioTransport::bind_reuseport(config.listen).await?
                } else {
                    turna_transport::TokioTransport::bind(config.listen).await?
                };
                let server = turna_relay::RelayServer::new_with_cluster(
                    transport,
                    store,
                    auth,
                    external_ip,
                    metrics.clone(),
                    cluster_routing.clone(),
                );
                #[cfg(feature = "tls")]
                let server = if tls_cfg.enabled {
                    info!(listen = %tls_cfg.listen, cert = %tls_cfg.cert_path.display(), "TURNS (TLS) enabled");
                    server.with_tls(build_tls_transport_config(&tls_cfg))
                } else {
                    server
                };
                server.run(shutdown_rx).await
            }

            // io_uring thread-per-core datapath (Linux + io-uring feature only).
            // resolve() cannot pick this backend without that cfg.
            turna_transport::TransportBackend::IoUring => {
                #[cfg(all(target_os = "linux", feature = "io-uring"))]
                {
                    use turna_relay::handler::RelayHandler;
                    use turna_transport::worker::{spawn_worker_pool, WorkerPoolConfig};

                    // Single worker for now: each io_uring engine owns its own
                    // relay sockets, and there is no cross-worker relay routing
                    // for the shared allocation store yet — with >1 worker, media
                    // landing on a worker that didn't bind that relay port would
                    // be dropped. Multi-worker sharding is future work.
                    let pool_cfg = WorkerPoolConfig {
                        listen_addr: config.listen,
                        num_workers: 1,
                        buffers_per_worker: 2048,
                        external_ip,
                    };
                    let store_f = store.clone();
                    let auth_f = auth.clone();
                    let metrics_f = metrics.clone();
                    let cluster_f = cluster_routing.clone();
                    let _handles = spawn_worker_pool(pool_cfg, move |_worker_id| {
                        RelayHandler::new_with_cluster(
                            store_f.clone(),
                            auth_f.clone(),
                            external_ip,
                            metrics_f.clone(),
                            cluster_f.clone(),
                        )
                    });

                    // Worker threads run blocking io_uring loops with no shutdown
                    // hook yet: wait for the signal, then let the process exit
                    // (threads are torn down on exit). Graceful drain is TODO.
                    let mut rx = shutdown_rx;
                    let _ = rx.changed().await;
                    info!("shutdown signalled; io_uring workers are not gracefully drained yet");
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
