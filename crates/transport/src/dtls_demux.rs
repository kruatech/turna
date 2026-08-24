//! Owned UDP demultiplexer for the DTLS listener (opt-in).
//!
//! # Why this exists
//!
//! `webrtc_dtls::listener::listen()` + `accept()` runs the entire handshake
//! inline inside `accept()`, serially, with no timeout of its own
//! (webrtc-rs/webrtc#614). Three consequences follow from that one design, and
//! all three are closed here rather than separately:
//!
//! 1. **Liveness.** A peer that begins a handshake and goes silent parks
//!    `accept()`, so the listener stops serving *everyone* while the process
//!    still looks healthy. `[turn.dtls].accept_timeout_secs` bounds that on the
//!    stock path, but it only converts an outage into degraded throughput: the
//!    accepts are still serial, so each stalled peer costs one whole timeout
//!    window. Here handshakes run in their own tasks, so a stalled peer costs
//!    one task.
//! 2. **Admission control.** On the stock path the session and per-IP caps can
//!    only be applied *after* a completed handshake — we pay for the crypto
//!    first and refuse afterwards. Here the first datagram from an unknown
//!    address is admitted or refused before any handshake state exists, which is
//!    also where a per-IP handshake **rate** limit can finally live (the stock
//!    path has none; `iptables hashlimit` was the only mitigation).
//! 3. **Certificate hot-reload.** `listen()` fixes its `Config` at bind time, so
//!    a rotated certificate needed a process restart. Here the config is
//!    consulted per new peer, so a reload applies to new sessions and leaves
//!    live ones alone — the same model TURNS and both QUIC paths already use.
//!
//! # What is unchanged
//!
//! The HelloVerifyRequest cookie exchange still happens: it is part of the
//! server-side handshake inside `DTLSConn`, not part of the listener we replaced.
//! Established sessions are still serviced by
//! [`super::handle_dtls_session`], so the record pump, MTU enforcement, idle
//! reaper and egress queue are shared with the stock path and cannot drift.
//!
//! # Status
//!
//! Opt-in via `[turn.dtls] demux = true`, default **off**. The stock path has
//! recorded transport-level verification (`docs/dtls/`); this one has none yet.
//! Until it does, the proven path stays the default — see
//! `docs/verification/encrypted-transports.md`.
//!
//! # Pinned upstream API (verified against the vendored sources, not inferred)
//!
//! * `webrtc_util::conn::Conn` (0.9) requires nine items. `connect`, `recv`,
//!   `recv_from`, `send`, `send_to` and `close` are `async fn`; `local_addr`,
//!   `remote_addr` and `as_any` are **plain `fn`** — writing the latter three as
//!   `async` fails with E0195 (lifetimes do not match), and omitting `as_any`
//!   fails with E0046.
//! * `webrtc_util::Error::from_std<T>(T) -> Self where T: std::error::Error +
//!   Send + Sync + 'static`.
//! * `webrtc_dtls::conn::DTLSConn::new(conn: Arc<dyn Conn + Send + Sync>,
//!   config: Config, is_client: bool, initial_state: Option<State>)`.
//!
//! Re-check these if either crate is bumped; they are the only places this module
//! depends on shapes it does not own.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::dtls::{
    handle_dtls_session, load_certificate, DtlsConfig, DtlsError, DtlsEvent, DtlsStats,
    OutboundRegistry, Result, MAX_DTLS_PLAINTEXT,
};

/// Per-peer inbound queue depth. A DTLS handshake is a handful of flights and a
/// live session is paced by the relay, so this only needs to absorb a burst;
/// overflow is dropped and counted rather than blocking the demux loop, because
/// one slow peer must never stall every other peer's datagrams.
const PEER_QUEUE: usize = 64;

/// A virtual connection for one remote address.
///
/// Reads come from the demux loop through an mpsc queue; writes go straight out
/// of the shared socket with `send_to`. This is the same shape as
/// `webrtc_util`'s own `UdpConn`, which is what `listen()` hands to `DTLSConn` —
/// we build it ourselves only so that admission and concurrency are under our
/// control.
struct PeerConn {
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    local: SocketAddr,
    /// `Mutex` because the `Conn` trait takes `&self`; the receiver still has a
    /// single logical reader (the DTLS state machine for this peer).
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

fn closed_err(what: &str) -> webrtc_util::Error {
    webrtc_util::Error::from_std(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        what.to_string(),
    ))
}

#[async_trait::async_trait]
impl webrtc_util::conn::Conn for PeerConn {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        // Server side: the peer address is fixed at construction.
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(closed_err("dtls peer queue closed")),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let n = self.recv(buf).await?;
        Ok((n, self.remote))
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.socket
            .send_to(buf, self.remote)
            .await
            .map_err(webrtc_util::Error::from_std)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        self.socket
            .send_to(buf, target)
            .await
            .map_err(webrtc_util::Error::from_std)
    }

    // NOT async in webrtc-util 0.9: the trait declares these two as plain `fn`,
    // so `#[async_trait]` leaves them alone and an `async fn` here fails to match.
    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        // The socket is shared and outlives this peer; closing the queue is the
        // caller's job (dropping the sender in the demux map).
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Build the DTLS `Config` from the current certificate material on disk.
fn build_config(cfg: &DtlsConfig) -> Result<webrtc_dtls::config::Config> {
    let certificate = load_certificate(&cfg.cert_path, &cfg.key_path)?;
    Ok(webrtc_dtls::config::Config {
        certificates: vec![certificate],
        insecure_skip_verify: false,
        ..Default::default()
    })
}

fn mtime(path: &str) -> Option<std::time::SystemTime> {
    if path.is_empty() {
        return None;
    }
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Run the demultiplexing DTLS listener. Returns when `shutdown` flips or the
/// socket fails unrecoverably.
pub(crate) async fn run_demux(
    cfg: DtlsConfig,
    event_tx: mpsc::Sender<DtlsEvent>,
    outbound: OutboundRegistry,
    stats: Arc<DtlsStats>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(cfg.listen_addr)
            .await
            .map_err(|e| DtlsError::Other(format!("bind {}: {e}", cfg.listen_addr)))?,
    );
    let local = socket
        .local_addr()
        .map_err(|e| DtlsError::Other(format!("local_addr: {e}")))?;
    tracing::info!(
        addr = %local,
        "DTLS endpoint listening (owned demultiplexer: concurrent handshakes, \
         pre-handshake admission, certificate hot-reload)"
    );

    let mut dtls_cfg = build_config(&cfg)?;
    let mut cert_mt = mtime(&cfg.cert_path);
    let mut key_mt = mtime(&cfg.key_path);
    stats.listening.store(true, Relaxed);

    // addr -> inbound queue for that peer's DTLS state machine.
    let peers: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Concurrent sessions per source IP, held from admission (pre-handshake) to
    // session teardown — unlike the stock path, where it starts post-handshake.
    let per_ip: Arc<std::sync::Mutex<HashMap<IpAddr, u32>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    let limiter = crate::ratelimit::HandshakeLimiter::new(
        cfg.max_handshakes_per_sec_per_ip,
        cfg.handshake_burst_per_ip,
    );
    if limiter.enabled() {
        tracing::info!(
            rate = cfg.max_handshakes_per_sec_per_ip,
            burst = cfg.handshake_burst_per_ip,
            "DTLS per-IP handshake rate limit active (demux path only)"
        );
    }

    let mut housekeeping = tokio::time::interval(Duration::from_secs(30));
    housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let reload_enabled = !cfg.cert_reload_interval.is_zero();
    let mut reload_tick = tokio::time::interval(if reload_enabled {
        cfg.cert_reload_interval
    } else {
        Duration::from_secs(3600)
    });
    reload_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    reload_tick.tick().await; // the first tick fires immediately
    if !reload_enabled {
        tracing::info!("DTLS certificate hot-reload disabled (cert_reload_secs = 0)");
    }

    let mut buf = vec![0u8; MAX_DTLS_PLAINTEXT];

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = housekeeping.tick() => {
                limiter.sweep();
                continue;
            }
            _ = reload_tick.tick() => {
                if reload_enabled {
                    let (nc, nk) = (mtime(&cfg.cert_path), mtime(&cfg.key_path));
                    if nc != cert_mt || nk != key_mt {
                        cert_mt = nc;
                        key_mt = nk;
                        match build_config(&cfg) {
                            Ok(new_cfg) => {
                                dtls_cfg = new_cfg;
                                stats.cert_reloads.fetch_add(1, Relaxed);
                                tracing::info!(
                                    "DTLS certificate reloaded; new sessions use it, live \
                                     sessions are untouched"
                                );
                            }
                            Err(e) => {
                                stats.cert_reload_failures.fetch_add(1, Relaxed);
                                tracing::warn!(
                                    %e,
                                    "DTLS certificate reload failed; keeping the previous \
                                     certificate in service"
                                );
                            }
                        }
                    }
                }
                continue;
            }
            r = socket.recv_from(&mut buf) => {
                let (n, remote) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        // A UDP recv error is per-datagram (ICMP port-unreachable
                        // surfaces here on some platforms), not fatal to the socket.
                        tracing::debug!(%e, "DTLS demux: recv_from error, continuing");
                        continue;
                    }
                };
                if n == 0 {
                    continue;
                }

                // Known peer: hand the datagram to its state machine.
                {
                    let map = peers.lock().await;
                    if let Some(tx) = map.get(&remote) {
                        if tx.try_send(buf[..n].to_vec()).is_err() {
                            // Queue full or peer gone. Dropping is correct: DTLS
                            // retransmits during the handshake, and a live session
                            // that cannot keep up must not stall the loop.
                            stats.inbound_dropped.fetch_add(1, Relaxed);
                        }
                        continue;
                    }
                }

                // ── New address: admission BEFORE any handshake work. ──
                if cfg.max_sessions != 0 && stats.active.load(Relaxed) >= cfg.max_sessions {
                    stats.rejected_over_cap.fetch_add(1, Relaxed);
                    continue;
                }
                if !limiter.allow(remote.ip()) {
                    stats.rejected_rate_limit.fetch_add(1, Relaxed);
                    continue;
                }
                {
                    let mut m = match per_ip.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    let cur = *m.get(&remote.ip()).unwrap_or(&0);
                    if cfg.max_sessions_per_ip != 0 && cur as usize >= cfg.max_sessions_per_ip {
                        stats.rejected_per_ip.fetch_add(1, Relaxed);
                        continue;
                    }
                    *m.entry(remote.ip()).or_insert(0) += 1;
                }

                let (ptx, prx) = mpsc::channel::<Vec<u8>>(PEER_QUEUE);
                // The first datagram is the ClientHello; it must not be lost.
                if ptx.try_send(buf[..n].to_vec()).is_err() {
                    release_ip(&per_ip, remote.ip());
                    continue;
                }
                peers.lock().await.insert(remote, ptx);

                let conn: Arc<dyn webrtc_util::conn::Conn + Send + Sync> = Arc::new(PeerConn {
                    socket: socket.clone(),
                    remote,
                    local,
                    rx: Mutex::new(prx),
                });

                let handshake_cfg = dtls_cfg.clone();
                let handshake_timeout = cfg.accept_timeout;
                let peers_c = peers.clone();
                let per_ip_c = per_ip.clone();
                let stats_c = stats.clone();
                let tx_c = event_tx.clone();
                let out_c = outbound.clone();
                let sd = shutdown.clone();
                let mtu = cfg.mtu;
                let idle = cfg.idle_timeout;
                let cap = cfg.outbound_queue_capacity;

                tokio::spawn(async move {
                    // One task per peer: a stalled handshake costs this task, not
                    // the listener. `is_client = false`, no resumption state —
                    // the same arguments the stock listener passes.
                    let established = if handshake_timeout.is_zero() {
                        webrtc_dtls::conn::DTLSConn::new(conn, handshake_cfg, false, None)
                            .await
                            .map_err(|e| e.to_string())
                    } else {
                        match tokio::time::timeout(
                            handshake_timeout,
                            webrtc_dtls::conn::DTLSConn::new(conn, handshake_cfg, false, None),
                        )
                        .await
                        {
                            Ok(r) => r.map_err(|e| e.to_string()),
                            Err(_) => {
                                stats_c.accept_timeouts.fetch_add(1, Relaxed);
                                Err("handshake exceeded accept_timeout_secs".to_string())
                            }
                        }
                    };

                    match established {
                        Ok(dtls_conn) => {
                            stats_c.active.fetch_add(1, Relaxed);
                            stats_c.accepted.fetch_add(1, Relaxed);
                            handle_dtls_session(
                                Arc::new(dtls_conn),
                                remote,
                                tx_c,
                                out_c,
                                mtu,
                                idle,
                                cap,
                                stats_c.clone(),
                                per_ip_c.clone(),
                                sd,
                            )
                            .await;
                            // `handle_dtls_session` owns the per-IP release for a
                            // session it actually serviced.
                        }
                        Err(reason) => {
                            // Unlike the stock path, a failed handshake IS
                            // observable here — it fails in our task, not below
                            // `accept()`. This is what makes the counter honest.
                            stats_c.handshake_failures.fetch_add(1, Relaxed);
                            tracing::debug!(%remote, %reason, "DTLS handshake failed");
                            release_ip(&per_ip_c, remote.ip());
                        }
                    }
                    peers_c.lock().await.remove(&remote);
                });
            }
        }
    }

    stats.listening.store(false, Relaxed);
    peers.lock().await.clear();
    tracing::info!("DTLS demux draining: shutdown signalled, no new handshakes");
    Ok(())
}

fn release_ip(per_ip: &Arc<std::sync::Mutex<HashMap<IpAddr, u32>>>, ip: IpAddr) {
    let mut m = match per_ip.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(n) = m.get_mut(&ip) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            m.remove(&ip);
        }
    }
}
