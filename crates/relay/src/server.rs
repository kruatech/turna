//! Async relay server — multi-threaded tokio with decoupled recv/send.
//!
//! # Zero-copy recv loop
//!
//! The old code allocated a `Vec<u8>` on every packet AND copied again for
//! `ZeroCopyForward` (the name was misleading — it still called `.to_vec()`).
//!
//! New approach:
//! 1. `recv_from` fills a per-worker `BytesMut`.
//! 2. `BytesMut::freeze()` produces a `Bytes` — an Arc-backed slice,
//!    zero allocation cost after the initial recv.
//! 3. `Action::Forward` carries a `Bytes::slice()` of that buffer —
//!    pointer arithmetic + AtomicAdd, no memcpy.
//! 4. `OutMsg` fields are all `Bytes`, so the send task also avoids copies.
//!
//! Result: **1 allocation per packet** (per-worker recv buffer) instead of
//! the previous **2-3 allocations + 2 memcpy** for ChannelData.

use bytes::Bytes;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use turna_auth::AuthRegistry;
use turna_health::Metrics;
use turna_session::AllocationStore;
use turna_transport::buffer::MAX_UDP_PACKET;
use turna_transport::migration::MigrationManager;
use turna_transport::{TokioTransport, Transport};

use crate::processor::{Action, ClusterRouting, PacketProcessor};
use crate::tcp_relay::TcpRelayManager;

// ── Internal message types ────────────────────────────────────────────────────

/// Sink that delivers bytes to a non-UDP (TLS/TCP) client, keyed by the
/// client's source address. Empty unless the TURNS bridge is running, so the
/// pure-UDP path pays only a single (missed) map lookup on the relay return
/// path — and nothing at all on the recv hot path.
pub type ClientSink = mpsc::Sender<Vec<u8>>;
pub type ClientSinks = Arc<DashMap<SocketAddr, ClientSink>>;

/// Outbound message ready for the send task.
///
/// All data fields are `Bytes` — sending to the channel is an AtomicAdd,
/// not a memcpy. STUN-ответы сюда больше не попадают — каждый recv-воркер
/// отвечает send_to со своего SO_REUSEPORT-сокета.
pub(crate) enum OutMsg {
    Relay {
        port: u16,
        data: Bytes,
        target: SocketAddr,
    },
    RegisterRelay {
        port: u16,
        socket: std::net::UdpSocket,
    },
    CloseRelay {
        port: u16,
    },
}

/// Число SO_REUSEPORT recv-воркеров: TURNA_RECV_WORKERS,
/// иначе число доступных ядер (taskset учитывается), максимум 16.
pub fn recv_workers() -> usize {
    let default = if cfg!(target_os = "linux") {
        std::thread::available_parallelism()
            .map(|n| n.get() * 2)
            .unwrap_or(8)
            .min(32)
    } else {
        1
    };
    std::env::var("TURNA_RECV_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(default)
}

// ── Relay egress task ─────────────────────────────────────────────────────────

/// Spawn the relay-egress task. It owns the relay sockets and:
///   * `RegisterRelay` — adopts a newly-bound relay socket into tokio and
///     spawns a per-socket peer→client recv pump (`process_relay_recv` →
///     route via `client_sinks` for TLS/DTLS/QUIC clients, else `main_out`
///     over UDP);
///   * `Relay` — sends peer-bound data on the owning relay socket;
///   * `CloseRelay` — drops the socket and aborts its pump.
///
/// Extracted from `RelayServer::run` so the io_uring backend can stand up the
/// same egress for a dedicated QUIC/DTLS processor (the io_uring datapath owns
/// the main socket, but QUIC/DTLS allocations still need this tokio-driven
/// relay return path). Behaviour is identical to the previous inline task.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_relay_egress(
    mut send_rx: mpsc::Receiver<OutMsg>,
    processor: Arc<PacketProcessor>,
    relay_sockets: Arc<DashMap<u16, TokioTransport>>,
    relay_tasks: Arc<DashMap<u16, tokio::task::AbortHandle>>,
    client_sinks: ClientSinks,
    main_out: TokioTransport,
    external_ip: std::net::IpAddr,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(msg) = send_rx.recv().await {
            match msg {
                OutMsg::Relay { port, data, target } => {
                    if let Some(relay) = relay_sockets.get(&port) {
                        let _ = relay.send_to(&data, target).await;
                    }
                }
                OutMsg::CloseRelay { port } => {
                    relay_sockets.remove(&port);
                    if let Some((_, h)) = relay_tasks.remove(&port) {
                        h.abort();
                    }
                }
                OutMsg::RegisterRelay { port, socket } => {
                    // Socket is already bound (in handle_allocate). Adopt it
                    // into the tokio runtime — this cannot fail to bind.
                    let socket = match tokio::net::UdpSocket::from_std(socket) {
                        Ok(s) => TokioTransport::from_socket(s),
                        Err(e) => {
                            error!(port, %e, "failed to adopt relay socket");
                            continue;
                        }
                    };
                    relay_sockets.insert(port, socket.clone());

                    // Spawn relay recv task (peer → client).
                    let proc = processor.clone();
                    let main_out = main_out.clone();
                    let sockets = relay_sockets.clone();
                    let ext_ip = external_ip;
                    let client_sinks_relay = client_sinks.clone();

                    let handle = tokio::spawn(async move {
                        // Relay packets are at most MTU bytes; fixed buf is fine here
                        // (relay_recv is not the hot path — ChannelData client→server is).
                        let mut buf = [0u8; MAX_UDP_PACKET];
                        loop {
                            let (n, peer_addr) = match socket.recv_from(&mut buf).await {
                                Ok(r) => r,
                                Err(_) => break,
                            };
                            let relay_addr = SocketAddr::new(ext_ip, port);
                            let actions = proc.process_relay_recv(&buf[..n], peer_addr, relay_addr);
                            for action in actions {
                                if let Action::Send { data, target } = action {
                                    // Route to a TURNS/DTLS/QUIC client if a sink is
                                    // registered, otherwise send_to over UDP.
                                    if let Some(sink) = client_sinks_relay.get(&target) {
                                        let _ = sink.try_send(data.to_vec());
                                    } else {
                                        let _ = main_out.send_to(&data, target).await;
                                    }
                                }
                            }
                        }
                        sockets.remove(&port);
                    });
                    relay_tasks.insert(port, handle.abort_handle());
                }
            }
        }
    })
}

/// Create an empty cross-transport client-sink registry. Shared between a
/// [`start_relay_egress`] task and the DTLS/QUIC listeners that register their
/// established client addresses into it (so peer→client relay data is delivered
/// over the right transport).
pub fn new_client_sinks() -> ClientSinks {
    Arc::new(DashMap::new())
}

/// Public handle to a relay-egress task (see [`start_relay_egress`]). A non-UDP
/// listener (DTLS/QUIC) routes the relay-plane actions a packet produced into
/// the egress while keeping the control `Send` for delivery over its own
/// transport.
#[derive(Clone)]
pub struct RelayEgress {
    tx: mpsc::Sender<OutMsg>,
}

impl RelayEgress {
    /// Dispatch one processor [`Action`]. `RegisterRelay` / `Forward` /
    /// `SendViaRelay` / `CloseRelay` are forwarded to the egress task; a control
    /// `Send` is returned to the caller to deliver over its own transport
    /// (DTLS/QUIC). Returns `None` when handled internally or `Action::None`.
    pub async fn dispatch(&self, action: Action) -> Option<(Bytes, SocketAddr)> {
        match action {
            Action::Send { data, target } => return Some((data, target)),
            Action::Forward {
                data,
                target,
                relay_port,
            }
            | Action::SendViaRelay {
                data,
                target,
                relay_port,
            } => {
                // Media path: drop on a full queue rather than stall the session.
                let _ = self.tx.try_send(OutMsg::Relay {
                    port: relay_port,
                    data,
                    target,
                });
            }
            Action::RegisterRelay { port, socket, .. } => {
                // Control-plane: must not be dropped — await for queue capacity.
                let _ = self.tx.send(OutMsg::RegisterRelay { port, socket }).await;
            }
            Action::CloseRelay { port } => {
                let _ = self.tx.send(OutMsg::CloseRelay { port }).await;
            }
            Action::RegisterTcpListener { .. } => {
                // Unreachable on the UDP path: a TCP allocation over non-TCP ingress
                // is now rejected (400) in `handle_allocate` before any listener is
                // bound. Kept for match exhaustiveness; drop defensively, no panic.
                tracing::debug!(
                    "unexpected RegisterTcpListener on the UDP dispatch path; dropping"
                );
            }
            // The tokio path never produces ForwardZeroCopy — `process()` emits
            // `Forward { data: Bytes }`. It is an io_uring / AF_XDP-only action.
            // Handle it defensively so the match stays exhaustive.
            Action::ForwardZeroCopy { .. } => {
                debug_assert!(false, "ForwardZeroCopy reached the tokio dispatch path");
            }
            Action::None => {}
        }
        None
    }
}

/// Stand up a standalone relay-egress task (its own relay-socket map + the
/// peer→client pump) and return a [`RelayEgress`] handle for it. Used by the
/// io_uring backend to give QUIC/DTLS allocations a tokio-driven relay return
/// path even though the main TURN socket is owned by the io_uring datapath.
///
/// `main_out` is the UDP fallback for peer→client when the target is not in
/// `client_sinks`; for QUIC/DTLS-only egress those clients are always in
/// `client_sinks`, so an ephemeral socket (`0.0.0.0:0`) is fine here.
pub fn start_relay_egress(
    processor: Arc<PacketProcessor>,
    client_sinks: ClientSinks,
    main_out: TokioTransport,
    external_ip: std::net::IpAddr,
) -> (RelayEgress, tokio::task::JoinHandle<()>) {
    let relay_sockets: Arc<DashMap<u16, TokioTransport>> = Arc::new(DashMap::new());
    let relay_tasks: Arc<DashMap<u16, tokio::task::AbortHandle>> = Arc::new(DashMap::new());
    let (tx, rx) = mpsc::channel::<OutMsg>(8192);

    // Orphan-reconciliation for this egress's OWN socket maps. DTLS/QUIC
    // listeners register relay sockets here (separate from RelayServer's
    // `relay_sockets`), so without this task they would leak on idle-expiry;
    // explicit release is still handled promptly via OutMsg::CloseRelay. Mirrors
    // the reconciliation loop in RelayServer::run.
    {
        let store = processor.store().clone();
        let relay_sockets_cl = relay_sockets.clone();
        let relay_tasks_cl = relay_tasks.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let orphans: Vec<u16> = relay_sockets_cl
                    .iter()
                    .map(|e| *e.key())
                    .filter(|p| !store.ports.is_allocated(*p))
                    .collect();
                for port in orphans {
                    relay_sockets_cl.remove(&port);
                    if let Some((_, h)) = relay_tasks_cl.remove(&port) {
                        h.abort();
                    }
                }
            }
        });
    }

    let handle = spawn_relay_egress(
        rx,
        processor,
        relay_sockets,
        relay_tasks,
        client_sinks,
        main_out,
        external_ip,
    );
    (RelayEgress { tx }, handle)
}

// ── RelayServer ───────────────────────────────────────────────────────────────

/// Async TURN relay server.
pub struct RelayServer {
    transport: TokioTransport,
    processor: Arc<PacketProcessor>,
    relay_sockets: Arc<DashMap<u16, TokioTransport>>,
    external_ip: std::net::IpAddr,
    /// Registry of TLS/TCP client sinks (addr → writer channel). Shared with the
    /// relay return path so peer→client data reaches TURNS clients over TLS.
    client_sinks: ClientSinks,
    /// RFC 6062 TCP relay engine; `None` disables TCP allocations. Read by the
    /// TURNS bridge (CONNECT executor); unused when built without `tls`.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    tcp_relay: Option<Arc<TcpRelayManager>>,
    /// TURNS (TLS) listener config; `None` disables it.
    #[cfg(feature = "tls")]
    tls_config: Option<turna_transport::tcp_tls::TlsTransportConfig>,
    /// TURN-over-SCTP listener config; `None` disables it.
    #[cfg(feature = "sctp")]
    sctp_config: Option<turna_transport::sctp::SctpTransportConfig>,
    /// Seconds to wait for allocations to end on shutdown. Set by the node from
    /// `[turn.relay] drain_timeout_secs`; 30 when nothing sets it, which is what
    /// this was hard-coded to.
    drain_timeout_secs: u64,
}

impl RelayServer {
    pub fn new(
        transport: TokioTransport,
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::new_with_cluster(transport, store, auth, external_ip, metrics, None)
    }

    pub fn new_with_cluster(
        transport: TokioTransport,
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
        cluster: Option<ClusterRouting>,
    ) -> Self {
        Self::new_full(
            transport,
            store,
            auth,
            external_ip,
            metrics,
            cluster,
            None,
            None,
        )
    }

    /// Full constructor including the optional RFC 8016 migration ticket
    /// manager. `migration = None` is identical to `new_with_cluster`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_full(
        transport: TokioTransport,
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
        cluster: Option<ClusterRouting>,
        migration: Option<MigrationManager>,
        tcp_relay: Option<Arc<TcpRelayManager>>,
    ) -> Self {
        let processor = Arc::new(
            PacketProcessor::new_with_cluster(store, auth, external_ip, metrics, cluster)
                .with_migration(migration)
                .with_tcp_relay(tcp_relay.clone()),
        );
        Self {
            transport,
            processor,
            relay_sockets: Arc::new(DashMap::new()),
            external_ip,
            client_sinks: Arc::new(DashMap::new()),
            tcp_relay,
            #[cfg(feature = "tls")]
            tls_config: None,
            #[cfg(feature = "sctp")]
            sctp_config: None,
            drain_timeout_secs: 30,
        }
    }

    /// Override how long shutdown waits for allocations to end.
    ///
    /// A builder setter rather than a constructor argument: there are three
    /// constructors and this concerns none of them.
    pub fn with_drain_timeout_secs(mut self, secs: u64) -> Self {
        self.drain_timeout_secs = secs;
        self
    }

    /// Enable the TURNS (TLS-over-TCP) listener. No-op unless built with the
    /// `tls` feature.
    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, cfg: turna_transport::tcp_tls::TlsTransportConfig) -> Self {
        self.tls_config = Some(cfg);
        self
    }

    /// Enable the TURN-over-SCTP listener. No-op unless built with the
    /// `sctp` feature.
    #[cfg(feature = "sctp")]
    pub fn with_sctp(mut self, cfg: turna_transport::sctp::SctpTransportConfig) -> Self {
        self.sctp_config = Some(cfg);
        self
    }

    pub fn processor(&self) -> &Arc<PacketProcessor> {
        &self.processor
    }

    /// Enable RFC 6156 IPv6 relayed transport on this server's processor.
    ///
    /// Reaches the processor through `Arc::get_mut`, which succeeds because this
    /// is called immediately after construction while the refcount is still 1 (the
    /// same pattern the QUIC listener uses for `quinn::ServerConfig::transport`).
    /// If it ever fails, IPv6 stays off and says so rather than silently
    /// advertising a v6 candidate the datapath will not bind.
    pub fn with_external_ip6(mut self, ip6: Option<std::net::Ipv6Addr>) -> Self {
        if ip6.is_none() {
            return self;
        }
        match Arc::get_mut(&mut self.processor) {
            Some(p) => p.set_external_ip6(ip6),
            None => error!(
                "cannot enable IPv6 relayed transport: the processor is already \
                 shared. IPv6 stays disabled (an explicit IPv6 Allocate keeps \
                 answering 440)."
            ),
        }
        self
    }

    /// Shared cross-transport client-sink registry (addr -> writer).
    /// DTLS/QUIC listeners register established client addresses here so
    /// peer->client relay data is delivered over the right transport.
    pub fn client_sinks(&self) -> ClientSinks {
        self.client_sinks.clone()
    }

    pub async fn run(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!(addr = %self.transport.local_addr()?, "relay server started (tokio)");

        // `turna_transport_readiness` was exported, documented as the primary UDP
        // backend's readiness, and listed as shipped — but `set_transport_readiness`
        // was never called anywhere, so it read `0` (starting) for the life of every
        // process, including one actively serving traffic. Found by a browser interop
        // run against a healthy node. Set it here, where the datapath is actually up.
        self.processor
            .metrics()
            .set_transport_readiness(turna_health::Readiness::Ready);

        // Per-port relay recv-task handles, so a released/expired relay can be
        // stopped (its socket closed, fd freed, port reusable).
        let relay_tasks: Arc<DashMap<u16, tokio::task::AbortHandle>> = Arc::new(DashMap::new());

        // ── Cleanup + metrics task ────────────────────────────────────────────
        let cleanup_handle = {
            let store = self.processor.store().clone();
            let metrics = self.processor.metrics().clone();
            let rtp = self.processor.rtp_analyzer().clone();
            let processor_cl = self.processor.clone();
            let relay_sockets_cl = self.relay_sockets.clone();
            let relay_tasks_cl = relay_tasks.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
                loop {
                    ticker.tick().await;
                    // I2: reclaim rate-limiter buckets idle > 10 min (bounded by
                    // max_entries anyway, but don't let them linger until restart).
                    processor_cl.cleanup_rate_limiter(600.0);
                    let removed = store.cleanup_expired();
                    if removed > 0 {
                        metrics
                            .active_allocations
                            .fetch_sub(removed as u64, std::sync::atomic::Ordering::Relaxed);
                        info!(removed, active = store.len(), "expired allocations cleaned");
                    }
                    // Reconcile: close relay sockets whose port is no longer a
                    // live allocation (covers the expiry path; explicit release
                    // is handled promptly via OutMsg::CloseRelay).
                    let orphans: Vec<u16> = relay_sockets_cl
                        .iter()
                        .map(|e| *e.key())
                        .filter(|p| !store.ports.is_allocated(*p))
                        .collect();
                    for port in orphans {
                        relay_sockets_cl.remove(&port);
                        if let Some((_, h)) = relay_tasks_cl.remove(&port) {
                            h.abort();
                        }
                    }
                    let agg = rtp.aggregate();
                    metrics
                        .rtp_streams
                        .store(agg.total_streams, std::sync::atomic::Ordering::Relaxed);
                    metrics.rtp_avg_loss_pct_x100.store(
                        (agg.avg_loss_percent * 100.0) as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    metrics.rtp_max_loss_pct_x100.store(
                        (agg.max_loss_percent * 100.0) as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    metrics.rtp_avg_jitter_us.store(
                        (agg.avg_jitter_ms * 1000.0) as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    metrics.rtp_max_jitter_us.store(
                        (agg.max_jitter_ms * 1000.0) as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    metrics.rtp_total_bitrate_kbps.store(
                        agg.total_bitrate_bps / 1000,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    rtp.cleanup_stale();
                }
            })
        };

        // ── Send channel: recv task → send task (backpressure) ───────────────
        let (send_tx, send_rx) = mpsc::channel::<OutMsg>(8192);

        // ── Send task ─────────────────────────────────────────────────────────
        // Relay egress (RegisterRelay/Relay/CloseRelay + the peer→client pump)
        // now lives in spawn_relay_egress so the io_uring backend can stand up
        // the same return path for a dedicated QUIC/DTLS processor.
        let sender_task = spawn_relay_egress(
            send_rx,
            self.processor.clone(),
            self.relay_sockets.clone(),
            relay_tasks.clone(),
            self.client_sinks.clone(),
            self.transport.clone(),
            self.external_ip,
        );

        // A configured listener must not die silently. We retain its handle so
        // shutdown can abort it (previously it was leaked), and on an unexpected
        // exit we cut this node from routing (Degraded) so a load balancer stops
        // sending it new clients. The node is NOT force-killed — other transports
        // may still be serving.
        #[cfg(feature = "tls")]
        let mut tls_handle: Option<tokio::task::JoinHandle<()>> = None;
        #[cfg(feature = "sctp")]
        let mut sctp_handle: Option<tokio::task::JoinHandle<()>> = None;

        // ── TURNS (TLS-over-TCP) bridge ──────────────────────────────────────
        // Shares the relay send channel and the client-sink registry with the
        // UDP path: control responses go back over TLS, peer→client relay data
        // is routed to the TLS connection via `client_sinks`.
        #[cfg(feature = "tls")]
        if let Some(tls_cfg) = self.tls_config.clone() {
            let proc = self.processor.clone();
            let relay_tx = send_tx.clone();
            let sinks = self.client_sinks.clone();
            let tcp_relay = self.tcp_relay.clone();
            let listener_metrics = self.processor.metrics().clone();
            let listener_shutdown = shutdown.clone();
            // Cooperative drain for the TURNS listener: it stops accepting and
            // winds established connections down itself, so the `abort()` at the
            // end of `run` is only a backstop.
            let bridge_shutdown = shutdown.clone();
            tls_handle = Some(tokio::spawn(async move {
                let res = crate::tls_bridge::run_tls_bridge(
                    tls_cfg,
                    proc,
                    relay_tx,
                    sinks,
                    tcp_relay,
                    bridge_shutdown,
                )
                .await;
                if !*listener_shutdown.borrow() {
                    match res {
                        Ok(()) => error!("TURNS bridge exited unexpectedly"),
                        Err(e) => error!(error = %e, "TURNS bridge failed"),
                    }
                    listener_metrics.set_readiness(turna_health::Readiness::Degraded);
                }
            }));
        }

        // ── TURN-over-SCTP bridge ────────────────────────────────────────────
        // Same sharing model as the TURNS bridge: control over SCTP, relay UDP.
        #[cfg(feature = "sctp")]
        if let Some(sctp_cfg) = self.sctp_config.clone() {
            let proc = self.processor.clone();
            let relay_tx = send_tx.clone();
            let sinks = self.client_sinks.clone();
            let listener_metrics = self.processor.metrics().clone();
            let listener_shutdown = shutdown.clone();
            // A second receiver: the first is consumed by the post-exit check
            // below, which distinguishes a deliberate drain from a crash. The
            // bridge needs its own so it can stop accepting on the same signal.
            let sctp_bridge_shutdown = shutdown.clone();
            let sctp_bridge_metrics = listener_metrics.clone();
            sctp_handle = Some(tokio::spawn(async move {
                let res = crate::sctp_bridge::run_sctp_bridge(
                    sctp_cfg,
                    proc,
                    relay_tx,
                    sinks,
                    sctp_bridge_metrics,
                    sctp_bridge_shutdown,
                )
                .await;
                if !*listener_shutdown.borrow() {
                    match res {
                        Ok(()) => error!("TURN-over-SCTP bridge exited unexpectedly"),
                        Err(e) => error!(error = %e, "TURN-over-SCTP bridge failed"),
                    }
                    listener_metrics.set_readiness(turna_health::Readiness::Degraded);
                }
            }));
        }

        // ── Recv workers (hot path) ──────────────────────────────────────
        // N сокетов SO_REUSEPORT на одном порту, по recv-задаче на сокет.
        // STUN-ответы (Action::Send) уходят send_to прямо из воркера, без mpsc.
        // В бенче с одного IP отключай TURNA_RATE_LIMIT_* и TURNA_PREFIX_*.
        let n_workers = recv_workers();
        let listen_addr = self.transport.local_addr()?;
        let mut workers = Vec::with_capacity(n_workers);

        for i in 0..n_workers {
            let transport = if i == 0 {
                self.transport.clone()
            } else {
                match TokioTransport::bind_reuseport(listen_addr).await {
                    Ok(t) => t,
                    Err(e) => {
                        error!(worker = i, %e, "SO_REUSEPORT bind failed, continuing with fewer workers");
                        break;
                    }
                }
            };

            let processor = self.processor.clone();
            let send_tx = send_tx.clone();

            workers.push(tokio::spawn(async move {
                // До BATCH датаграмм на один recvmmsg; ответы — одним sendmmsg.
                const BATCH: usize = 32;
                let zero: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 0));
                let mut metas = [(0usize, zero); BATCH];
                loop {
                    // Одна арена на батч: 1 malloc на 32 пакета; каждый пакет —
                    // Bytes-слайс арены без копирования (zero-copy Forward жив).
                    let mut arena = bytes::BytesMut::with_capacity(BATCH * MAX_UDP_PACKET);
                    // SAFETY: capacity == BATCH*MAX_UDP_PACKET; recvmmsg пишет
                    // первые len байт каждого слота, slice(..len) ниже не даёт
                    // прочитать неинициализированный хвост.
                    unsafe {
                        arena.set_len(BATCH * MAX_UDP_PACKET);
                    }

                    let n = {
                        let mut slots: Vec<&mut [u8]> = arena.chunks_mut(MAX_UDP_PACKET).collect();
                        match transport.recv_mmsg(&mut slots, &mut metas).await {
                            Ok(n) => n,
                            Err(e) => {
                                error!(worker = i, %e, "recv error, worker stopping");
                                break;
                            }
                        }
                    };

                    let mut replies: Vec<(Bytes, SocketAddr)> = Vec::with_capacity(n);
                    #[allow(clippy::needless_range_loop)]
                    for k in 0..n {
                        let (len, src) = metas[k];
                        let chunk = arena.split_to(MAX_UDP_PACKET);
                        let raw: Bytes = chunk.freeze().slice(..len);
                        // A3-O1: isolate per-packet panics so a single bad packet
                        // can't take down the whole worker task. `processor` is
                        // &self over Arc/lock-free state (DashMap + atomics +
                        // parking_lot, which has no poisoning), so dropping the
                        // offending packet and continuing leaves no torn state.
                        let actions =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                processor.process(raw, src)
                            }))
                            .unwrap_or_else(|_| {
                                processor
                                    .metrics()
                                    .processor_panics
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                Vec::new()
                            });
                        for action in actions {
                            match action {
                                Action::Send { data, target } => {
                                    replies.push((data, target));
                                }
                                Action::Forward {
                                    data,
                                    target,
                                    relay_port,
                                }
                                | Action::SendViaRelay {
                                    data,
                                    target,
                                    relay_port,
                                } => {
                                    if send_tx
                                        .try_send(OutMsg::Relay {
                                            port: relay_port,
                                            data,
                                            target,
                                        })
                                        .is_err()
                                    {
                                        processor
                                            .metrics()
                                            .send_queue_dropped
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                }
                                // Control-plane: не дропаем при полной очереди.
                                Action::RegisterRelay { port, socket, .. } => {
                                    if send_tx
                                        .send(OutMsg::RegisterRelay { port, socket })
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Action::CloseRelay { port } => {
                                    if send_tx.send(OutMsg::CloseRelay { port }).await.is_err() {
                                        break;
                                    }
                                }
                                Action::RegisterTcpListener { .. } => {
                                    // Unreachable (see dispatch path): TCP-allocate over
                                    // non-TCP ingress is rejected at handle_allocate.
                                    tracing::debug!(
                                        "unexpected RegisterTcpListener on the UDP recvmmsg path; dropping"
                                    );
                                }
                                // io_uring / AF_XDP-only; never produced by the
                                // tokio `process()` path. Defensive, keeps the
                                // match exhaustive.
                                Action::ForwardZeroCopy { .. } => {
                                    debug_assert!(
                                        false,
                                        "ForwardZeroCopy reached the tokio recvmmsg path"
                                    );
                                }
                                Action::None => {}
                            }
                        }
                    }

                    if !replies.is_empty() {
                        if let Err(e) = transport.send_mmsg(&replies).await {
                            error!(worker = i, %e, "send_mmsg failed");
                        }
                    }
                }
            }));
        }

        info!(workers = workers.len(), %listen_addr, "recv workers started");

        // Wait for shutdown, but also watch the datapath. If every recv worker
        // has exited, or the relay egress / cleanup task has died while we are NOT
        // shutting down, the node can no longer serve — mark it Degraded so a load
        // balancer stops trusting it and stop waiting so shutdown/restart proceeds.
        // One dead worker is tolerated (SO_REUSEPORT leaves the others receiving);
        // all-dead is fatal.
        loop {
            tokio::select! {
                res = shutdown.changed() => {
                    if res.is_err() {
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }
            if *shutdown.borrow() {
                break;
            }
            if !workers.is_empty() && workers.iter().all(|w| w.is_finished()) {
                error!("all recv workers exited — datapath is dead");
                self.processor
                    .metrics()
                    .set_readiness(turna_health::Readiness::Degraded);
                break;
            }
            if sender_task.is_finished() {
                error!("relay egress task exited — datapath is dead");
                self.processor
                    .metrics()
                    .set_readiness(turna_health::Readiness::Degraded);
                break;
            }
            if cleanup_handle.is_finished() {
                error!("cleanup/metrics task exited unexpectedly");
                self.processor
                    .metrics()
                    .set_readiness(turna_health::Readiness::Degraded);
                break;
            }
            // Watch the listener bridges directly. Their own tasks set Degraded on
            // a normal unexpected exit, but a *panic* aborts before that runs — so
            // check the JoinHandle here, which flips to finished on panic too.
            #[cfg(feature = "tls")]
            if tls_handle.as_ref().is_some_and(|h| h.is_finished()) {
                error!("TURNS/TLS listener task exited unexpectedly (possible panic) — degraded");
                self.processor
                    .metrics()
                    .set_readiness(turna_health::Readiness::Degraded);
                break;
            }
            #[cfg(feature = "sctp")]
            if sctp_handle.as_ref().is_some_and(|h| h.is_finished()) {
                error!("SCTP listener task exited unexpectedly (possible panic) — degraded");
                self.processor
                    .metrics()
                    .set_readiness(turna_health::Readiness::Degraded);
                break;
            }
        }
        info!("shutdown signal received, draining...");
        self.processor.metrics().set_draining(true);
        self.processor
            .metrics()
            .set_transport_readiness(turna_health::Readiness::Draining);
        self.drain().await;
        for w in &workers {
            w.abort();
        }
        sender_task.abort();
        cleanup_handle.abort();
        #[cfg(feature = "tls")]
        if let Some(h) = tls_handle {
            h.abort();
        }
        #[cfg(feature = "sctp")]
        if let Some(h) = sctp_handle {
            h.abort();
        }
        Ok(())
    }

    async fn drain(&self) {
        let store = self.processor.store();
        let drain_secs = self.drain_timeout_secs;
        let timeout = tokio::time::Instant::now() + std::time::Duration::from_secs(drain_secs);

        // Stall detection. An allocation whose client vanished without a
        // Refresh(0) will not expire inside a 30-second window — its lifetime is
        // ten minutes — so the loop below would poll until the timeout with
        // nothing to wait for. Measured at 36 seconds for a node holding 300 of
        // them.
        //
        // If nothing has been removed and the count has not moved for three
        // consecutive polls (~6 s), the rest are not going anywhere. Three rather
        // than one because a brief gap between expiries is ordinary, and exiting
        // on the first would cut short a node that is draining real traffic —
        // exactly the case the timeout exists to protect.
        let mut last_len = store.len();
        let mut stalled_polls = 0u32;
        const STALL_POLLS: u32 = 3;

        while !store.is_empty() && tokio::time::Instant::now() < timeout {
            let removed = store.cleanup_expired();

            let len_now = store.len();
            if removed == 0 && len_now == last_len {
                stalled_polls += 1;
                if stalled_polls >= STALL_POLLS {
                    info!(
                        remaining = len_now,
                        waited_polls = stalled_polls,
                        "drain: no allocations ended in the last few polls; the rest hold \
                         lifetimes longer than this window and will not expire here. \
                         Exiting rather than waiting out the timeout — their clients are \
                         gone, and their relay ports are released with the process."
                    );
                    break;
                }
            } else {
                stalled_polls = 0;
            }
            last_len = len_now;

            if removed > 0 {
                self.processor
                    .metrics()
                    .active_allocations
                    .fetch_sub(removed as u64, std::sync::atomic::Ordering::Relaxed);
            }
            info!(remaining = store.len(), "draining...");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        if !store.is_empty() {
            info!(remaining = store.len(), "drain timeout — forcing shutdown");
        } else {
            info!("all allocations drained");
        }
    }
}
