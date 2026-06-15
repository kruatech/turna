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

#[cfg(feature = "web-transport")]
use std::sync::Arc;

#[cfg(feature = "web-transport")]
use turna_relay::quic_bridge::QuicBridge;
#[cfg(feature = "web-transport")]
use turna_relay::PacketProcessor;
#[cfg(feature = "web-transport")]
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
#[cfg(feature = "web-transport")]
pub fn spawn_quic(
    cfg: &turna_config::QuicConfigSection,
    processor: Arc<PacketProcessor>,
    client_sinks: turna_relay::ClientSinks,
    metrics: Arc<turna_health::Metrics>,
    egress: turna_relay::RelayEgress,
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
        enable_0rtt: false,
        alpn: cfg.alpn.clone(),
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
                metrics.quic_active.store(s.0 as u64, Relaxed);
                metrics.quic_sessions_total.store(s.1, Relaxed);
                metrics.quic_closed_total.store(s.2, Relaxed);
                metrics.quic_datagrams_rx.store(s.3, Relaxed);
                metrics.quic_datagrams_tx.store(s.4, Relaxed);
                metrics.quic_streams_opened.store(s.5, Relaxed);
                metrics.quic_control_bytes_tx.store(s.6, Relaxed);
                metrics.quic_send_errors.store(s.7, Relaxed);
            }
        });
    }

    // -- listener task --
    let server = QuicServer::new(qcfg);
    let reg = outbound.clone();
    let st = stats.clone();
    let web_transport = cfg.web_transport;
    tokio::spawn(async move {
        let result = if web_transport {
            server.run_web_transport(event_tx, reg, st).await
        } else {
            // Raw-QUIC path: now bidirectional too (outbound registry wired into
            // `run`). Control delivery is still limited by the draft per-stream
            // buffering loop; datagram (media) egress is fully functional.
            server.run(event_tx, reg, st).await
        };
        if let Err(e) = result {
            tracing::error!(%e, "QUIC listener exited");
        }
    });

    // -- consumer task: bridge events into the processor, route responses back --
    let mut bridge = QuicBridge::new(processor);
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
                                let _ = tx.send(QuicOutbound {
                                    session_id: session_id.clone(),
                                    data: bytes,
                                    via_datagram,
                                });
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
                    // Re-key the egress sink to the client's new address.
                    if let Some((_, sink)) = client_sinks.remove(old_addr) {
                        client_sinks.insert(*new_addr, sink);
                    }
                    session_addr.insert(session_id.clone(), *new_addr);
                    tracing::debug!(%old_addr, %new_addr, "QUIC connection migrated (egress re-keyed)");
                }
                QuicEvent::SessionClosed { session_id, .. } => {
                    if let Some(addr) = session_addr.remove(session_id) {
                        client_sinks.remove(&addr);
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
                // Clone the per-session sender out of the registry without
                // holding the lock across the send.
                let sender = outbound
                    .lock()
                    .ok()
                    .and_then(|g| g.get(&session_id).cloned());
                if let Some(tx) = sender {
                    let _ = tx.send(QuicOutbound {
                        session_id,
                        data: data.to_vec(),
                        via_datagram,
                    });
                }
            }
        }
        tracing::info!("QUIC bridge consumer stopped (listener closed)");
    });
}

/// No-op when the binary is built without WebTransport support.
#[cfg(not(feature = "web-transport"))]
pub fn spawn_quic(
    _cfg: &turna_config::QuicConfigSection,
    _processor: std::sync::Arc<turna_relay::PacketProcessor>,
    _client_sinks: turna_relay::ClientSinks,
    _metrics: std::sync::Arc<turna_health::Metrics>,
    _egress: turna_relay::RelayEgress,
) {
    tracing::warn!("[quic] enabled in config but binary built without the `web-transport` feature");
}
