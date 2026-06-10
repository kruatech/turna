//! TURN-over-DTLS listener wiring (Phase 1 bridge + Phase 2 egress).
//!
//! Self-contained like `quic_listener`: owns the event channel, the DTLS
//! outbound registry, and the two tasks (DTLS listener + bridge consumer).
//!
//! Two directions, both ending at the per-session DTLS writer (`conn.send`):
//!
//!   * **client -> server -> client** (requests/responses, client-originated
//!     ChannelData/Send): the bridge runs `process_slice` on each decrypted
//!     record and routes the resulting `Action::Send { target }` straight to
//!     the originating session via the DTLS `OutboundRegistry`.
//!
//!   * **peer -> client** (relayed data arriving on an allocation's relay
//!     socket): handled by `RelayServer`'s relay-recv task, which dispatches
//!     `Action::Send { target }` through the shared `client_sinks` registry.
//!     We register each established DTLS client there (addr -> byte sink) so
//!     that path encrypts the relayed datagram into the DTLS session instead
//!     of emitting raw UDP. This mirrors exactly how the TURNS (TLS) bridge
//!     hooks into `client_sinks`.
//!
//! Sessions are keyed by client address, so an `Action::Send { target }` maps
//! to a session via `target.to_string()` -- a direct registry lookup, no map.

#[cfg(feature = "dtls")]
use std::sync::Arc;

#[cfg(feature = "dtls")]
use turna_relay::PacketProcessor;
#[cfg(feature = "dtls")]
use turna_transport::dtls::{
    DtlsConfig, DtlsEvent, DtlsOutbound, DtlsServer, DtlsStats, OutboundRegistry,
};

/// Start the DTLS listener and its bridge consumer.
///
/// `client_sinks` is `RelayServer`'s shared cross-transport egress registry
/// (`server.client_sinks()`); established DTLS clients register here so the
/// relay return path reaches them over DTLS.
#[cfg(feature = "dtls")]
pub fn spawn_dtls(
    cfg: &turna_config::DtlsSection,
    processor: Arc<PacketProcessor>,
    client_sinks: turna_relay::ClientSinks,
    metrics: Arc<turna_health::Metrics>,
    egress: turna_relay::RelayEgress,
) {
    // Phase 3: preflight validation at startup (spawn_dtls runs before
    // RelayServer::run). On a fatal misconfiguration we log loudly and decline
    // to start the listener instead of failing silently inside the spawned
    // task. The rest of the server keeps running (DTLS is an optional
    // transport). For hard fail-fast, have `main` treat a disabled-but-enabled
    // DTLS as fatal.
    if let Err(problems) = validate_dtls(cfg) {
        for p in &problems {
            tracing::error!(problem = %p, "[turn.dtls] invalid configuration");
        }
        tracing::error!(
            count = problems.len(),
            "[turn.dtls] enabled but misconfigured -> DTLS listener NOT started"
        );
        return;
    }

    let dcfg = DtlsConfig {
        listen_addr: cfg.listen,
        cert_path: cfg.cert_path.to_string_lossy().into_owned(),
        key_path: cfg.key_path.to_string_lossy().into_owned(),
        mtu: cfg.mtu,
        max_sessions: cfg.max_sessions,
        idle_timeout: std::time::Duration::from_secs(cfg.idle_timeout_secs),
    };

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<DtlsEvent>(1024);
    let outbound: OutboundRegistry =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let stats: Arc<DtlsStats> = Arc::new(DtlsStats::default());

    // Mirror DtlsStats into the shared Prometheus Metrics every few seconds
    // (transport crate is leaf-level and cannot depend on turna-health; the
    // copy lives here in the node where both crates are visible).
    {
        let stats = stats.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                let s = stats.snapshot();
                metrics.dtls_active.store(s.0 as u64, Relaxed);
                metrics.dtls_sessions_total.store(s.1, Relaxed);
                metrics.dtls_rejected_over_cap.store(s.2, Relaxed);
                metrics.dtls_closed_total.store(s.3, Relaxed);
                metrics.dtls_idle_timeouts.store(s.4, Relaxed);
                metrics.dtls_bytes_rx.store(s.5, Relaxed);
                metrics.dtls_bytes_tx.store(s.6, Relaxed);
            }
        });
    }

    // -- listener task --
    let server = DtlsServer::new(dcfg);
    let reg = outbound.clone();
    let st = stats.clone();
    tokio::spawn(async move {
        if let Err(e) = server.run(event_tx, reg, st).await {
            tracing::error!(%e, "DTLS listener exited");
        }
    });

    // -- bridge consumer --
    //   * Datagram      -> process_slice -> encrypt response back (client<->server)
    //   * NewSession    -> register a client_sink (enables peer->client egress)
    //   * SessionClosed -> drop the client_sink
    tokio::spawn(async move {
        while let Some(ev) = event_rx.recv().await {
            match ev {
                DtlsEvent::NewSession { session_id, remote } => {
                    // Clone this session's DTLS writer-sender (already inserted
                    // into the registry before NewSession was emitted) and wire
                    // a byte sink into it. The relay return path pushes raw TURN
                    // bytes into `sink_tx`; this pump wraps them as DtlsOutbound
                    // so the session task encrypts + sends them over `conn`.
                    let out_tx = outbound
                        .lock()
                        .ok()
                        .and_then(|g| g.get(&session_id).cloned());
                    if let Some(out_tx) = out_tx {
                        let (sink_tx, mut sink_rx) =
                            tokio::sync::mpsc::channel::<Vec<u8>>(256);
                        client_sinks.insert(remote, sink_tx);
                        let sid = session_id.clone();
                        tokio::spawn(async move {
                            while let Some(bytes) = sink_rx.recv().await {
                                if out_tx
                                    .send(DtlsOutbound {
                                        session_id: sid.clone(),
                                        data: bytes,
                                    })
                                    .is_err()
                                {
                                    break; // session writer gone
                                }
                            }
                        });
                        tracing::debug!(%remote, "DTLS session established (egress registered)");
                    } else {
                        tracing::warn!(%remote, "DTLS NewSession without outbound entry; peer->client egress disabled for this session");
                    }
                }
                DtlsEvent::SessionClosed { session_id } => {
                    // session_id == remote.to_string(); recover the addr to drop
                    // the client_sink (dropping the sender ends the pump task).
                    if let Ok(addr) = session_id.parse::<std::net::SocketAddr>() {
                        client_sinks.remove(&addr);
                    }
                    tracing::debug!(session = %session_id, "DTLS session closed (egress unregistered)");
                }
                DtlsEvent::Datagram { remote, data, .. } => {
                    for action in processor.process_slice(&data, remote) {
                        // Relay-plane actions (RegisterRelay/Forward/CloseRelay)
                        // go into the shared relay egress; a control Send comes
                        // back here for delivery over this DTLS session.
                        let Some((data, target)) = egress.dispatch(action).await else {
                            continue;
                        };
                        let sender = outbound
                            .lock()
                            .ok()
                            .and_then(|g| g.get(&target.to_string()).cloned());
                        match sender {
                            Some(tx) => {
                                let _ = tx.send(DtlsOutbound {
                                    session_id: target.to_string(),
                                    data: data.to_vec(),
                                });
                            }
                            None => {
                                // Not a DTLS session: a cross-transport send the
                                // relay data-plane owns. Nothing to do here.
                                tracing::trace!(%target, "DTLS bridge: no session for target (cross-transport)");
                            }
                        }
                    }
                }
            }
        }
        tracing::info!("DTLS bridge consumer stopped (listener closed)");
    });
}

/// Phase 3 preflight checks for `[turn.dtls]`. Returns the list of problems
/// (empty = OK). Kept pure/synchronous so it can run before any task spawns and
/// so it is unit-testable without a runtime.
#[cfg(feature = "dtls")]
fn validate_dtls(cfg: &turna_config::DtlsSection) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();

    if cfg.listen.port() == 0 {
        problems.push("listen port must be non-zero".to_string());
    }

    // cert/key must exist and be regular files (best-effort; the listener would
    // otherwise fail later with a less obvious error).
    for (label, path) in [("cert_path", &cfg.cert_path), ("key_path", &cfg.key_path)] {
        match std::fs::metadata(path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => problems.push(format!("{label} is not a regular file: {}", path.display())),
            Err(e) => problems.push(format!("{label} unreadable ({}): {e}", path.display())),
        }
    }

    // idle_timeout == 0 would close every session immediately (sleep(0) fires
    // at once); reject it outright.
    if cfg.idle_timeout_secs == 0 {
        problems.push("idle_timeout_secs must be > 0".to_string());
    }

    // MTU sanity: below the IPv4 minimum-reassembly floor nothing useful fits;
    // above a UDP datagram is impossible. (max_sessions == 0 is allowed and
    // means "unlimited".)
    if cfg.mtu < 576 {
        problems.push(format!("mtu too small ({}, minimum 576)", cfg.mtu));
    } else if cfg.mtu > 65535 {
        problems.push(format!("mtu too large ({}, maximum 65535)", cfg.mtu));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// No-op when built without the `dtls` feature.
#[cfg(not(feature = "dtls"))]
pub fn spawn_dtls(
    _cfg: &turna_config::DtlsSection,
    _processor: std::sync::Arc<turna_relay::PacketProcessor>,
    _client_sinks: turna_relay::ClientSinks,
    _metrics: std::sync::Arc<turna_health::Metrics>,
    _egress: turna_relay::RelayEgress,
) {
    tracing::warn!("[turn.dtls] enabled in config but binary built without the `dtls` feature");
}
