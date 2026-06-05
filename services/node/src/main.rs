//! Turna TURN server entry point
//!
//! Modes:
//! - tokio (default): multi-threaded async, works everywhere
//! - io_uring (--features io-uring): io_uring for main socket + tokio for relay sockets

mod writer;
mod bulk_load;
mod heartbeat;
mod failover;

use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use turna_auth::AuthMode;
use turna_config::{ClusterConfig, TurnConfig, TurnaConfig};
use turna_health::Metrics;
use turna_observability::{TelemetryConfig, SamplingConfig};
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

    let (config, cluster) = match config_path {
        Some(path) => {
            let root = TurnaConfig::load(&path)?;
            (root.turn, root.cluster)
        }
        None => {
            turna_observability::init();
            info!("no config file, using defaults");
            (TurnConfig::default(), ClusterConfig::default())
        }
    };

    let obs = &config.observability;
    let telemetry_config = TelemetryConfig {
        service_name:    "turna".into(),
        service_version: env!("CARGO_PKG_VERSION").into(),
        instance_id:     hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into()),
        otlp_endpoint:   obs.otlp_endpoint.clone(),
        json_logs:       obs.json_logs,
        sampling: SamplingConfig {
            base_ratio:            obs.trace_sample_rate,
            max_spans_per_second:  obs.max_spans_per_second,
            always_sample_errors:  true,
            latency_threshold_us:  10_000,
            always_sample_methods: vec!["Allocate".into(), "Refresh".into()],
        },
        ..Default::default()
    };

    let _telemetry_guard = turna_observability::init_with_config(telemetry_config)
        .unwrap_or_else(|e| {
            eprintln!("telemetry init failed: {e} — falling back to basic logging");
            let _ = turna_observability::init();
            turna_observability::init_with_config(Default::default())
                .expect("fallback telemetry init")
        });

    info!(listen = %config.listen, realm = %config.realm, "starting turna");

    let external_ip: std::net::IpAddr = if config.external_ip.is_empty() {
        let ip = config.listen.ip();
        if ip.is_unspecified() { "127.0.0.1".parse().unwrap() } else { ip }
    } else {
        config.external_ip.parse().unwrap_or_else(|_| {
            let ip = config.listen.ip();
            if ip.is_unspecified() { "127.0.0.1".parse().unwrap() } else { ip }
        })
    };

    let auth: Arc<AuthMode> = if config.auth.static_users.is_empty() {
        Arc::new(AuthMode::SharedSecret {
            realm:  config.realm.clone(),
            secret: config.auth.shared_secret.as_bytes().to_vec(),
        })
    } else {
        Arc::new(AuthMode::LongTerm {
            realm: config.realm.clone(),
            users: config.auth.static_users.iter()
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
            max_per_user:      config.relay.quota.max_per_user,
        };
        s
    });

    let metrics = Arc::new(Metrics::new());

    run_tokio(config, cluster, store, auth, external_ip, metrics)
}

fn run_tokio(
    config:      TurnConfig,
    cluster:     ClusterConfig,
    store:       Arc<AllocationStore>,
    auth:        Arc<AuthMode>,
    external_ip: std::net::IpAddr,
    metrics:     Arc<Metrics>,
) -> Result<(), Box<dyn std::error::Error>> {
    let num_threads = std::env::var("TURNA_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
        });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_threads)
        .enable_all()
        .build()?;

    rt.block_on(async {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Health check server
        let health_metrics = metrics.clone();
        tokio::spawn(async move {
            let addr = "0.0.0.0:9090".parse().unwrap();
            let _ = turna_health::serve(addr, health_metrics).await;
        });

        // ── PR2: write-behind writer task ─────────────────────────────────────
        if cluster.persistence.is_enabled() {
            let backend_cfg = match cluster.backend.r#type.as_str() {
                "memory" => BackendConfig::Memory,
                "tarantool" => BackendConfig::Tarantool {
                    uri:       cluster.backend.uri.clone(),
                    user:      if cluster.backend.user.is_empty() {
                                   None
                               } else {
                                   Some(cluster.backend.user.clone())
                               },
                    password:  if cluster.backend.password.is_empty() {
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

            let backend = create_backend(&backend_cfg).await
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("state backend init failed: {e}").into()
                })?;
            let backend = Arc::new(backend);

            let bulk_stats = bulk_load::bulk_load(
                &backend, &store, &cluster.node_id
            ).await;
            metrics.active_allocations
                .fetch_add(bulk_stats.rehydrated as u64,
                           std::sync::atomic::Ordering::Relaxed);

            let (tx, rx) = tokio::sync::mpsc::channel::<turna_session::WriteOp>(
                cluster.persistence.channel_capacity
            );
            store.attach_writer(tx);

            let writer_cfg = writer::WriterConfig {
                channel_capacity: cluster.persistence.channel_capacity,
                batch_max_size:   cluster.persistence.batch_max_size,
                batch_max_delay:  Duration::from_millis(cluster.persistence.batch_max_delay_ms),
                node_id:          cluster.node_id.clone(),
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
            let writer_store   = store.clone();
            let writer_metrics = metrics.clone();
            tokio::spawn(async move {
                writer::run_writer(
                    writer_backend, writer_store, realm,
                    writer_cfg, writer_metrics, counters,
                    rx, writer_shutdown,
                ).await;
            });

            // ── PR4: heartbeat task ───────────────────────────────────────
            let hb_backend  = backend.clone();
            let hb_metrics  = metrics.clone();
            let hb_shutdown = shutdown_rx.clone();
            let hb_cfg = heartbeat::HeartbeatConfig {
                node_id:  cluster.node_id.clone(),
                addr:     std::net::SocketAddr::new(external_ip, config.listen.port())
                              .to_string(),
                version:  env!("CARGO_PKG_VERSION").into(),
                interval: heartbeat::DEFAULT_INTERVAL,
            };
            info!(
                node_id  = %hb_cfg.node_id,
                addr     = %hb_cfg.addr,
                interval = ?hb_cfg.interval,
                "heartbeat task starting"
            );
            tokio::spawn(async move {
                heartbeat::run_heartbeat(
                    hb_backend, hb_metrics, hb_cfg, hb_shutdown,
                ).await;
            });

            // ── PR5: failover claim task ──────────────────────────────────
            let fo_backend  = backend.clone();
            let fo_store    = store.clone();
            let fo_metrics  = metrics.clone();  // PR A: pass metrics for counters
            let fo_shutdown = shutdown_rx.clone();
            let fo_cfg = failover::FailoverConfig {
                node_id:        cluster.node_id.clone(),
                sweep_interval: failover::DEFAULT_SWEEP_INTERVAL,
                live_window:    failover::DEFAULT_LIVE_WINDOW,
            };
            info!(
                node_id        = %fo_cfg.node_id,
                sweep_interval = ?fo_cfg.sweep_interval,
                live_window    = ?fo_cfg.live_window,
                "failover task starting"
            );
            tokio::spawn(async move {
                let _ = failover::run_failover(
                    fo_backend, fo_store, fo_cfg, fo_metrics, fo_shutdown,
                ).await;
            });

            let _ = backend;
        }

        // TURN server. С несколькими воркерами первый сокет тоже должен
        // быть в SO_REUSEPORT-группе (опция ставится до bind).
        let transport = if turna_relay::server::recv_workers() > 1 {
            turna_transport::TokioTransport::bind_reuseport(config.listen).await?
        } else {
            turna_transport::TokioTransport::bind(config.listen).await?
        };
        let server = turna_relay::RelayServer::new(
            transport, store, auth, external_ip, metrics.clone(),
        );

        let mode = if cfg!(all(target_os = "linux", feature = "io-uring")) {
            "tokio+io_uring_ready"
        } else {
            "tokio"
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
            let _ = shutdown_tx.send(true);
        });

        server.run(shutdown_rx).await
    })
}

#[derive(Copy, Clone)]
enum DumpMode { Masked, Raw }

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
            DumpMode::Raw    => s.to_string(),
            DumpMode::Masked => {
                if s.is_empty() { String::new() } else {
                    let prefix: String = s.chars().take(4).collect();
                    format!("***{prefix}…[{} chars]", s.chars().count())
                }
            }
        }
    };

    let header = match mode {
        DumpMode::Raw    => "# turna-node --dump-config-raw output — CONTAINS SECRETS",
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
    println!("otlp_endpoint        = \"{}\"", t.observability.otlp_endpoint);
    println!("trace_sample_rate    = {}",     t.observability.trace_sample_rate);
    println!("json_logs            = {}",     t.observability.json_logs);
    println!("max_spans_per_second = {}",     t.observability.max_spans_per_second);
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
    println!("node_id     = \"{}\"", c.node_id);
    println!("gossip_port = {}",     c.gossip_port);
    println!("seeds       = {:?}",   c.seeds);
    println!();
    println!("[cluster.backend]");
    println!("type      = \"{}\"", c.backend.r#type);
    println!("uri       = \"{}\"", c.backend.uri);
    println!("user      = \"{}\"", c.backend.user);
    println!("password  = \"{}\"", mask(&c.backend.password));
    println!("pool_size = {}",     c.backend.pool_size);
    println!();
    println!("[cluster.persistence]");
    println!("mode               = \"{}\"", c.persistence.mode);
    println!("channel_capacity   = {}",     c.persistence.channel_capacity);
    println!("batch_max_size     = {}",     c.persistence.batch_max_size);
    println!("batch_max_delay_ms = {}",     c.persistence.batch_max_delay_ms);
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
}
