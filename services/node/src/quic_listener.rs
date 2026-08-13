//! QUIC / WebTransport listener wiring (QUIC Phase 4 + Phase 2 egress).
//!
//! Self-contained so it can be dropped into `main` with a single call and a
//! `mod quic_listener;` -- it owns the event channel, the relay bridge, the
//! outbound registry, and the two long-lived tasks (listener + consumer).
//!
//! Data flow:
//! ```text
//!   wtransport --QuicEvent--> QuicBridge --Action--> outbound registry
//!        ^                                               |
//!        +-------------- QuicOutbound <------------------+
//! ```
//! Outbound classification follows the bridge's framing contract: ChannelData
//! (first byte 0x40..=0x7F) is media -> unreliable datagram; STUN/TURN
//! (top two bits 00) is control -> reliable bidi stream.
//!
//! Phase 2 egress (peer -> client): like the DTLS listener, each established
//! session registers a byte sink in `RelayServer`'s shared `client_sinks` so
//! relayed peer data reaches QUIC clients over QUIC instead of raw UDP. The
//! per-session pump resolves the session's QuicOutbound sender at send time, so
//! it is robust to the registry entry appearing just after `NewSession`.

#[cfg(feature = "quic")]
use std::sync::Arc;

#[cfg(feature = "quic")]
use turna_relay::quic_bridge::QuicBridge;
#[cfg(feature = "quic")]
use turna_relay::PacketProcessor;
#[cfg(feature = "quic")]
use turna_transport::quic::{
    OutboundRegistry, QuicConfig, QuicEvent, QuicOutbound, QuicServer, QuicStats,
};

/// Start the QUIC/WebTransport listener and its bridge consumer. Returns once
/// both tasks are spawned; the consumer runs until the listener task ends
/// (i.e. the event channel closes).
///
/// `client_sinks` is `RelayServer`'s shared cross-transport egress registry
/// (`server.client_sinks()`); established QUIC clients register here so the
/// relay return path reaches them over QUIC.
#[cfg(feature = "quic")]
pub fn spawn_quic(
    cfg: &turna_config::QuicConfigSection,
    processor: Arc<PacketProcessor>,
    client_sinks: turna_relay::ClientSinks,
    metrics: Arc<turna_health::Metrics>,
    egress: turna_relay::RelayEgress,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let qcfg = QuicConfig {
        listen_addr: cfg.listen,
        cert_path: cfg.cert_path.to_string_lossy().into_owned(),
        key_path: cfg.key_path.to_string_lossy().into_owned(),
        max_bi_streams: cfg.max_bi_streams,
        max_uni_streams: cfg.max_uni_streams,
        enable_datagrams: cfg.enable_datagrams,
        max_datagram_size: cfg.max_datagram_size,
        idle_timeout: std::time::Duration::from_secs(cfg.idle_timeout_secs),
        keep_alive: std::time::Duration::from_secs(cfg.keep_alive_secs),
        alpn: cfg.alpn.clone(),
        max_sessions: cfg.max_sessions,
        max_sessions_per_ip: cfg.max_sessions_per_ip,
        cert_reload_interval: std::time::Duration::from_secs(cfg.cert_reload_secs),
        max_handshakes_per_sec_per_ip: cfg.max_handshakes_per_sec_per_ip,
        handshake_burst_per_ip: cfg.handshake_burst_per_ip,
        allow_migration: true,
    };

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<QuicEvent>(1024);
    let outbound: OutboundRegistry =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let stats: Arc<QuicStats> = Arc::new(QuicStats::default());

    // Mirror QuicStats into the shared Prometheus Metrics every few seconds
    // (the transport crate is leaf-level and cannot depend on turna-health, so
    // the copy lives here in the node where both crates are visible).
    {
        let stats = stats.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                let s = stats.snapshot();
                metrics.quic_active.store(s.active as u64, Relaxed);
                metrics.quic_sessions_total.store(s.accepted, Relaxed);
                metrics.quic_closed_total.store(s.closed, Relaxed);
                metrics.quic_datagrams_rx.store(s.datagrams_rx, Relaxed);
                metrics.quic_datagrams_tx.store(s.datagrams_tx, Relaxed);
                metrics.quic_streams_opened.store(s.streams_opened, Relaxed);
                metrics.quic_control_bytes_tx.store(s.control_bytes_tx, Relaxed);
                metrics.quic_send_errors.store(s.send_errors, Relaxed);
                metrics
                    .quic_handshake_failures
                    .store(s.handshake_failures, Relaxed);
                metrics
                    .quic_control_dropped_no_stream
                    .store(s.control_dropped_no_stream, Relaxed);
                metrics
                    .quic_rejected_over_cap
                    .store(s.rejected_over_cap, Relaxed);
                metrics.quic_rejected_per_ip.store(s.rejected_per_ip, Relaxed);
                metrics.quic_cert_reloads.store(s.cert_reloads, Relaxed);
                metrics
                    .quic_cert_reload_failures
                    .store(s.cert_reload_failures, Relaxed);
                metrics
                    .quic_rejected_rate_limit
                    .store(s.rejected_rate_limit, Relaxed);
                metrics.quic_migrations.store(s.migrations, Relaxed);
                metrics.set_quic_readiness(if s.listening {
                    turna_health::Readiness::Ready
                } else {
                    turna_health::Readiness::Degraded
                });
            }
        });
    }

    // -- listener task --
    let server = QuicServer::new(qcfg);
    let reg = outbound.clone();
    let st = stats.clone();
    let web_transport = cfg.web_transport;
    let listener_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let result =
            run_listener(server, web_transport, event_tx, reg, st, listener_shutdown).await;
        if let Err(e) = result {
            tracing::error!(%e, "QUIC listener exited");
        }
    });

    // -- consumer task: bridge events into the processor, route responses back --
    // `QuicBridge` takes ownership of the processor handle; keep a clone for the
    // session-close release path below.
    let released = processor.clone();
    let mut bridge = QuicBridge::new(processor);
    let stats_out = stats.clone();
    tokio::spawn(async move {
        // session_id -> client addr, so SessionClosed (which carries no addr)
        // can drop the right client_sink. Egress mirrors the DTLS path.
        let mut session_addr: std::collections::HashMap<String, std::net::SocketAddr> =
            std::collections::HashMap::new();

        while let Some(ev) = event_rx.recv().await {
            // Peek session lifecycle to maintain the cross-transport egress
            // registry (client_sinks), then hand the event to the bridge.
            match &ev {
                QuicEvent::NewSession(s) => {
                    let session_id = s.session_id.clone();
                    let addr = s.remote_addr;
                    session_addr.insert(session_id.clone(), addr);

                    let (sink_tx, mut sink_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                    client_sinks.insert(addr, sink_tx);

                    let reg = outbound.clone();
                    let st_pump = stats_out.clone();
                    tokio::spawn(async move {
                        while let Some(bytes) = sink_rx.recv().await {
                            // ChannelData (0x40..=0x7f) -> unreliable datagram;
                            // STUN/TURN control -> reliable stream.
                            let via_datagram = bytes
                                .first()
                                .map(|b| (0x40..=0x7f).contains(b))
                                .unwrap_or(false);
                            // Resolve the session writer at send time (robust to
                            // the registry entry landing just after NewSession).
                            let sender = reg.lock().ok().and_then(|g| g.get(&session_id).cloned());
                            if let Some(tx) = sender {
                                // B6: non-blocking enqueue; a full per-session queue
                                // sheds this outbound instead of stalling the pump.
                                if tx
                                    .try_send(QuicOutbound {
                                        session_id: session_id.clone(),
                                        data: bytes,
                                        via_datagram,
                                        // Relay return path: no originating
                                        // request stream, so answer on whichever
                                        // bidi stream the client has open.
                                        stream_id: None,
                                    })
                                    .is_err()
                                {
                                    st_pump
                                        .send_errors
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    });
                    tracing::debug!(%addr, "QUIC session established (egress registered)");
                }
                QuicEvent::ConnectionMigrated {
                    session_id,
                    old_addr,
                    new_addr,
                } => {
                    // Re-key the egress sink to the client's new address, and the
                    // bridge's addr -> session index with it: without the latter
                    // `session_for_addr` would still answer on the old address
                    // and peer->client traffic would be lost after a migration.
                    if let Some((_, sink)) = client_sinks.remove(old_addr) {
                        client_sinks.insert(*new_addr, sink);
                    }
                    session_addr.insert(session_id.clone(), *new_addr);
                    bridge.migrate(session_id, *old_addr, *new_addr);
                    tracing::debug!(%old_addr, %new_addr, "QUIC connection migrated (egress re-keyed)");
                }
                QuicEvent::SessionClosed { session_id, .. } => {
                    if let Some(addr) = session_addr.remove(session_id) {
                        client_sinks.remove(&addr);
                        // The session is the client's transport identity here, so
                        // its allocation can never be used again — release it now
                        // instead of pinning a relay port until the TTL expires.
                        for action in released.release_for_closed_connection(addr) {
                            let _ = egress.dispatch(action).await;
                        }
                    }
                    tracing::debug!(session = %session_id, "QUIC session closed (egress unregistered)");
                }
                _ => {}
            }

            for action in bridge.on_event(ev) {
                // Relay-plane actions go into the shared relay egress; a control
                // Send comes back here for delivery over this QUIC session.
                let Some((data, target)) = egress.dispatch(action).await else {
                    continue;
                };
                let Some(session_id) = bridge.session_for_addr(target) else {
                    continue; // client gone
                };
                let via_datagram = data
                    .first()
                    .map(|b| (0x40..=0x7f).contains(b))
                    .unwrap_or(false);
                // Control responses go back on the stream the request came in on.
                let stream_id = if via_datagram {
                    None
                } else {
                    bridge.control_stream_for(&session_id)
                };
                // Clone the per-session sender out of the registry without
                // holding the lock across the send.
                let sender = outbound
                    .lock()
                    .ok()
                    .and_then(|g| g.get(&session_id).cloned());
                if let Some(tx) = sender {
                    // B6: non-blocking enqueue; drop + count on a full queue.
                    if tx
                        .try_send(QuicOutbound {
                            session_id,
                            data: data.to_vec(),
                            via_datagram,
                            stream_id,
                        })
                        .is_err()
                    {
                        stats_out
                            .send_errors
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }
        tracing::info!("QUIC bridge consumer stopped (listener closed)");
    });
}

/// Drive the configured listener. With the `web-transport` feature the
/// WebTransport-over-H3 path is available; without it only raw QUIC is, and
/// `web_transport = true` has already been rejected at startup in `main`
/// (`WEB_TRANSPORT_AVAILABLE`), so this cannot be reached with it set.
#[cfg(feature = "web-transport")]
async fn run_listener(
    server: QuicServer,
    web_transport: bool,
    event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
    outbound: OutboundRegistry,
    stats: Arc<QuicStats>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> turna_transport::quic::Result<()> {
    if web_transport {
        server
            .run_web_transport(event_tx, outbound, stats, shutdown)
            .await
    } else {
        server.run(event_tx, outbound, stats, shutdown).await
    }
}

/// Raw-QUIC-only build (`--features quic` without `web-transport`).
#[cfg(all(feature = "quic", not(feature = "web-transport")))]
async fn run_listener(
    server: QuicServer,
    web_transport: bool,
    event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
    outbound: OutboundRegistry,
    stats: Arc<QuicStats>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> turna_transport::quic::Result<()> {
    debug_assert!(
        !web_transport,
        "web_transport must be rejected at startup on a build without the \
         `web-transport` feature"
    );
    let _ = web_transport;
    server.run(event_tx, outbound, stats, shutdown).await
}

/// No-op when the binary is built without QUIC support.
#[cfg(not(feature = "quic"))]
pub fn spawn_quic(
    _cfg: &turna_config::QuicConfigSection,
    _processor: std::sync::Arc<turna_relay::PacketProcessor>,
    _client_sinks: turna_relay::ClientSinks,
    _metrics: std::sync::Arc<turna_health::Metrics>,
    _egress: turna_relay::RelayEgress,
    _shutdown: tokio::sync::watch::Receiver<bool>,
) {
    tracing::warn!("[quic] enabled in config but binary built without the `quic` feature");
}
