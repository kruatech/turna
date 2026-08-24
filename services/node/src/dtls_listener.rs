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

/// Fatal DTLS startup error (DTL-1). Returned by [`spawn_dtls`] when
/// `[turn.dtls]` is enabled but the configuration is invalid; the caller
/// turns this into a non-zero process exit instead of starting partially.
#[derive(Debug)]
pub struct DtlsStartupError {
    pub problems: Vec<String>,
}

impl std::fmt::Display for DtlsStartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[turn.dtls] invalid configuration ({} problem(s)): {}",
            self.problems.len(),
            self.problems.join("; ")
        )
    }
}

impl std::error::Error for DtlsStartupError {}

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
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), DtlsStartupError> {
    // DTL-1 fail-fast: spawn_dtls runs before RelayServer::run. When
    // [turn.dtls].enabled is set, any invalid configuration aborts startup
    // (the caller propagates this error and the process exits non-zero)
    // instead of logging and letting the server run without the requested
    // DTLS transport -- "enabled but not started" is exactly the trap we remove.
    if let Err(problems) = validate_dtls(cfg) {
        for p in &problems {
            tracing::error!(problem = %p, "[turn.dtls] invalid configuration");
        }
        tracing::error!(
            count = problems.len(),
            "[turn.dtls] enabled but misconfigured -> aborting startup"
        );
        return Err(DtlsStartupError { problems });
    }

    let dcfg = DtlsConfig {
        listen_addr: cfg.listen,
        cert_path: cfg.cert_path.to_string_lossy().into_owned(),
        key_path: cfg.key_path.to_string_lossy().into_owned(),
        mtu: cfg.mtu,
        max_sessions: cfg.max_sessions,
        idle_timeout: std::time::Duration::from_secs(cfg.idle_timeout_secs),
        outbound_queue_capacity: cfg.outbound_queue_capacity,
        max_sessions_per_ip: cfg.max_sessions_per_ip,
        accept_timeout: std::time::Duration::from_secs(cfg.accept_timeout_secs),
        demux: cfg.demux,
        max_handshakes_per_sec_per_ip: cfg.max_handshakes_per_sec_per_ip,
        handshake_burst_per_ip: cfg.handshake_burst_per_ip,
        cert_reload_interval: std::time::Duration::from_secs(cfg.cert_reload_secs),
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
            // Report Degraded until the first tick observes a bound listener, so
            // `turna_dtls_readiness` cannot sit at "starting" forever (it never
            // used to be written at all).
            loop {
                tick.tick().await;
                let s = stats.snapshot();
                metrics.dtls_active.store(s.active as u64, Relaxed);
                metrics.dtls_sessions_total.store(s.accepted, Relaxed);
                metrics
                    .dtls_rejected_over_cap
                    .store(s.rejected_over_cap, Relaxed);
                metrics.dtls_closed_total.store(s.closed, Relaxed);
                metrics.dtls_idle_timeouts.store(s.idle_timeouts, Relaxed);
                metrics.dtls_bytes_rx.store(s.bytes_rx, Relaxed);
                metrics.dtls_bytes_tx.store(s.bytes_tx, Relaxed);
                metrics
                    .dtls_outbound_dropped
                    .store(s.outbound_dropped, Relaxed);
                metrics
                    .dtls_rejected_per_ip
                    .store(s.rejected_per_ip, Relaxed);
                metrics
                    .dtls_outbound_oversize
                    .store(s.outbound_oversize, Relaxed);
                metrics
                    .dtls_accept_timeouts
                    .store(s.accept_timeouts, Relaxed);
                metrics
                    .dtls_handshake_failures
                    .store(s.handshake_failures, Relaxed);
                metrics
                    .dtls_inbound_dropped
                    .store(s.inbound_dropped, Relaxed);
                metrics
                    .dtls_rejected_rate_limit
                    .store(s.rejected_rate_limit, Relaxed);
                metrics.dtls_cert_reloads.store(s.cert_reloads, Relaxed);
                metrics
                    .dtls_cert_reload_failures
                    .store(s.cert_reload_failures, Relaxed);
                metrics.set_dtls_readiness(if s.listening {
                    turna_health::Readiness::Ready
                } else {
                    turna_health::Readiness::Degraded
                });
            }
        });
    }

    // DTLS has no certificate hot-reload: webrtc-dtls takes its `Config` at
    // `listen()`, and swapping material would mean rebinding the UDP socket and
    // dropping every live session. The operator trap is that rotating the cert
    // (ACME renewal) then does *nothing* with no signal at all — the listener
    // keeps serving the old certificate until the process restarts. Watch the
    // files and say so loudly; TURNS (tcp_tls) does reload, DTLS cannot.
    if !cfg.cert_path.as_os_str().is_empty() && !cfg.key_path.as_os_str().is_empty() {
        let cert_path = cfg.cert_path.clone();
        let key_path = cfg.key_path.clone();
        tokio::spawn(async move {
            let mtime =
                |p: &std::path::Path| std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
            let mut cert_mt = mtime(&cert_path);
            let mut key_mt = mtime(&key_path);
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let new_cert = mtime(&cert_path);
                let new_key = mtime(&key_path);
                if new_cert != cert_mt || new_key != key_mt {
                    cert_mt = new_cert;
                    key_mt = new_key;
                    tracing::warn!(
                        cert = %cert_path.display(),
                        key = %key_path.display(),
                        "DTLS certificate material changed on disk but DTLS cannot \
                         hot-reload it (webrtc-dtls fixes its config at listen time). \
                         The listener is still serving the OLD certificate — restart \
                         the node to pick up the new one."
                    );
                }
            }
        });
    }

    // -- listener task --
    let server = DtlsServer::new(dcfg);
    let reg = outbound.clone();
    let st = stats.clone();
    tokio::spawn(async move {
        if let Err(e) = server.run(event_tx, reg, st, shutdown).await {
            tracing::error!(%e, "DTLS listener exited");
        }
    });

    // -- bridge consumer --
    //   * Datagram      -> process_slice -> encrypt response back (client<->server)
    //   * NewSession    -> register a client_sink (enables peer->client egress)
    //   * SessionClosed -> drop the client_sink
    let bridge_stats = stats.clone();
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
                        let (sink_tx, mut sink_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                        client_sinks.insert(remote, sink_tx);
                        let sid = session_id.clone();
                        let pump_stats = bridge_stats.clone();
                        tokio::spawn(async move {
                            while let Some(bytes) = sink_rx.recv().await {
                                match out_tx.try_send(DtlsOutbound {
                                    session_id: sid.clone(),
                                    data: bytes,
                                }) {
                                    Ok(()) => {}
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        pump_stats
                                            .outbound_dropped
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                        break; // session writer gone
                                    }
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
                        // The DTLS session *is* the client's 5-tuple: once it is
                        // gone the allocation can never be refreshed or used
                        // again, so release it now instead of holding its relay
                        // port for the rest of the lifetime.
                        for action in processor.release_for_closed_connection(addr) {
                            let _ = egress.dispatch(action).await;
                        }
                    }
                    tracing::debug!(session = %session_id, "DTLS session closed (egress unregistered)");
                }
                DtlsEvent::Datagram { remote, data, .. } => {
                    // `process_owned`, NOT `process_slice`: the latter emits
                    // `ForwardZeroCopy { offset, len }` for ChannelData, and
                    // `RelayEgress::dispatch` cannot turn an offset/len back
                    // into bytes — so every client→peer media record was
                    // silently dropped (and tripped a debug_assert in debug
                    // builds). The decrypted record is already owned here, so
                    // handing it over by value costs nothing.
                    for action in processor.process_owned(data, remote) {
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
                                match tx.try_send(DtlsOutbound {
                                    session_id: target.to_string(),
                                    data: data.to_vec(),
                                }) {
                                    Ok(()) => {}
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        bridge_stats
                                            .outbound_dropped
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
                                }
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

    Ok(())
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

    // Both paths empty = explicit opt-in to the ephemeral self-signed cert that
    // `dtls::load_certificate` generates (dev/test only). Previously this branch
    // was unreachable: the defaults are non-empty paths and this loop required
    // the files to exist, so the documented fallback could never be selected.
    // A partially-configured pair is still an error.
    let cert_empty = cfg.cert_path.as_os_str().is_empty();
    let key_empty = cfg.key_path.as_os_str().is_empty();
    match (cert_empty, key_empty) {
        (true, true) => {
            tracing::warn!(
                "[turn.dtls] cert_path/key_path are empty: using an ephemeral \
                 self-signed certificate. Do not do this in production."
            );
        }
        (false, false) => {
            // cert/key must exist and be regular files (best-effort; the listener
            // would otherwise fail later with a less obvious error).
            for (label, path) in [("cert_path", &cfg.cert_path), ("key_path", &cfg.key_path)] {
                match std::fs::metadata(path) {
                    Ok(m) if m.is_file() => {}
                    Ok(_) => {
                        problems.push(format!("{label} is not a regular file: {}", path.display()))
                    }
                    Err(e) => {
                        problems.push(format!("{label} unreadable ({}): {e}", path.display()))
                    }
                }
            }
        }
        _ => problems.push(
            "cert_path and key_path must both be set, or both be empty \
             (empty = ephemeral self-signed, dev only)"
                .to_string(),
        ),
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

#[cfg(all(test, feature = "dtls"))]
mod tests {
    use super::validate_dtls;
    use turna_config::DtlsSection;

    fn base() -> DtlsSection {
        // Defaults are sane except that cert_path/key_path point at files that do
        // not exist in a test environment; each case sets what it needs.
        DtlsSection {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn both_cert_paths_empty_is_the_dev_self_signed_opt_in() {
        // Previously unreachable: the defaults are non-empty paths and validation
        // demanded the files exist, so `load_certificate`'s documented ephemeral
        // self-signed fallback could never be selected from config.
        let cfg = DtlsSection {
            cert_path: "".into(),
            key_path: "".into(),
            ..base()
        };
        assert!(
            validate_dtls(&cfg).is_ok(),
            "empty cert+key must be accepted as the dev self-signed opt-in"
        );
    }

    #[test]
    fn half_configured_cert_pair_is_rejected() {
        let only_cert = DtlsSection {
            cert_path: "/nonexistent/cert.pem".into(),
            key_path: "".into(),
            ..base()
        };
        let problems = validate_dtls(&only_cert).expect_err("half-set pair must fail");
        assert!(
            problems.iter().any(|p| p.contains("both")),
            "error should explain the both-or-neither rule, got {problems:?}"
        );

        let only_key = DtlsSection {
            cert_path: "".into(),
            key_path: "/nonexistent/key.pem".into(),
            ..base()
        };
        assert!(validate_dtls(&only_key).is_err());
    }

    #[test]
    fn missing_cert_files_are_rejected() {
        let cfg = DtlsSection {
            cert_path: "/nonexistent/cert.pem".into(),
            key_path: "/nonexistent/key.pem".into(),
            ..base()
        };
        let problems = validate_dtls(&cfg).expect_err("unreadable cert/key must fail");
        assert_eq!(
            problems.len(),
            2,
            "one problem per unreadable file: {problems:?}"
        );
    }

    #[test]
    fn zero_idle_timeout_is_rejected() {
        // sleep(0) fires immediately, closing every session as soon as it opens.
        let cfg = DtlsSection {
            cert_path: "".into(),
            key_path: "".into(),
            idle_timeout_secs: 0,
            ..base()
        };
        assert!(validate_dtls(&cfg).is_err());
    }

    #[test]
    fn mtu_bounds_are_enforced() {
        let too_small = DtlsSection {
            cert_path: "".into(),
            key_path: "".into(),
            mtu: 500,
            ..base()
        };
        assert!(
            validate_dtls(&too_small).is_err(),
            "below the IPv4 576 floor"
        );

        let too_large = DtlsSection {
            cert_path: "".into(),
            key_path: "".into(),
            mtu: 70_000,
            ..base()
        };
        assert!(validate_dtls(&too_large).is_err(), "above a UDP datagram");

        let ok = DtlsSection {
            cert_path: "".into(),
            key_path: "".into(),
            mtu: 1200,
            ..base()
        };
        assert!(validate_dtls(&ok).is_ok());
    }

    #[test]
    fn zero_listen_port_is_rejected() {
        let cfg = DtlsSection {
            cert_path: "".into(),
            key_path: "".into(),
            listen: "0.0.0.0:0".parse().unwrap(),
            ..base()
        };
        assert!(validate_dtls(&cfg).is_err());
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
    _shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), DtlsStartupError> {
    tracing::warn!("[turn.dtls] enabled in config but binary built without the `dtls` feature");
    Ok(())
}
