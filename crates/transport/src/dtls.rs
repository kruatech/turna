//! TURN over DTLS (RFC 7350) — DTLS 1.2 transport via the pure-Rust
//! `webrtc-dtls` stack. See `docs/design/dtls-turn.md`.
//!
//! Shape mirrors `quic.rs`: a listener emits `DtlsEvent`s (NewSession /
//! Datagram / SessionClosed) onto a channel, and an `OutboundRegistry` carries
//! encrypted responses back into the originating session. Each DTLS record is
//! exactly one TURN message (datagram-bounded), so — unlike TURNS over TCP —
//! no stream de-framing is needed; the relay bridge feeds each record straight
//! to `PacketProcessor::process_slice`.
//!
//! Cookie exchange + per-address demux + handshake are handled *inside*
//! `webrtc-dtls`' listener: `accept()` only yields a `Conn` after a completed
//! handshake (HelloVerifyRequest round-trip included), so spoofed/garbage UDP
//! never reaches the TURN layer. (The amplification surface of the listener's
//! pre-handshake per-address buffer is a Phase-1 security-review item — see the
//! design doc §5/§8.)
//!
//! Phase 4 hardening lives here too: post-handshake admission control
//! (`max_sessions`), per-session idle timeout, and lightweight atomic stats
//! that a periodic task logs (no dependency on the metrics crate — the
//! transport layer stays leaf-level; richer metrics can be wired from the node
//! bridge later).

use std::net::SocketAddr;
use std::time::Duration;

/// Maximum plaintext a single DTLS 1.2 record can carry: 2^14 bytes
/// (RFC 6347 §4.1 inherits RFC 5246 §6.2.1). The per-session receive buffer is
/// sized to at least this so a large client record is never truncated.
pub const MAX_DTLS_PLAINTEXT: usize = 16 * 1024;

/// DTLS listener parameters (mapped from the `[turn.dtls]` config section).
#[derive(Clone)]
pub struct DtlsConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    /// Max application record size; also caps outbound TURN responses to avoid
    /// IP fragmentation. Default ~1200 (matches the QUIC datagram default).
    pub mtu: usize,
    pub max_sessions: usize,
    pub idle_timeout: Duration,
    /// DTL-3: bounded per-session outbound queue; full => drop newest.
    pub outbound_queue_capacity: usize,
    /// DTL-9: max concurrent sessions per source IP (0 = unlimited).
    pub max_sessions_per_ip: usize,
    /// Upper bound on how long one `accept()` may sit in a handshake before the
    /// listener gives up on it. 0 disables the bound (the previous behaviour).
    ///
    /// This exists because of an upstream liveness bug, not as tuning: see the
    /// comment on the accept loop in [`DtlsServer::run`]. On the demux path it is
    /// the per-task handshake timeout, which is the same intent without the
    /// serialisation.
    pub accept_timeout: Duration,
    /// Use the owned UDP demultiplexer ([`crate::dtls_demux`]) instead of
    /// `webrtc_dtls::listener::listen()`. Off by default: the stock path is the
    /// one with recorded verification. The demux path makes handshakes
    /// concurrent, moves admission control ahead of the handshake, and enables
    /// certificate hot-reload and a per-IP handshake rate limit.
    pub demux: bool,
    /// Per-source-IP handshake **rate** limit (handshakes/second, 0 = unlimited).
    /// **Demux path only** — on the stock path the handshake runs below
    /// `accept()`, so there is nowhere to enforce it.
    pub max_handshakes_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate.
    pub handshake_burst_per_ip: u32,
    /// Poll interval for certificate hot-reload. 0 disables it. **Demux path
    /// only** — `listen()` fixes its config at bind time.
    pub cert_reload_interval: Duration,
}

/// Events surfaced from established DTLS sessions. `session_id` is the client's
/// socket address as a string (sessions are keyed by 5-tuple), so outbound
/// routing by `Action::Send { target }` is a direct lookup with no extra map.
pub enum DtlsEvent {
    NewSession {
        session_id: String,
        remote: SocketAddr,
    },
    /// One decrypted TURN message (STUN / ChannelData), datagram-bounded.
    Datagram {
        session_id: String,
        remote: SocketAddr,
        data: Vec<u8>,
    },
    SessionClosed {
        session_id: String,
    },
}

/// An encrypted-on-send response for a specific session.
#[derive(Debug, Clone)]
pub struct DtlsOutbound {
    pub session_id: String,
    pub data: Vec<u8>,
}

/// `session_id` → sender into that session's writer task; the relay-bridge
/// consumer pushes `DtlsOutbound`s here and the session task encrypts + sends.
#[cfg(feature = "dtls")]
pub type OutboundRegistry = std::sync::Arc<
    std::sync::Mutex<std::collections::HashMap<String, tokio::sync::mpsc::Sender<DtlsOutbound>>>,
>;

/// Process-wide counters for the DTLS transport. Cheap atomics, snapshotted by
/// a periodic logger; the node side can also read these to publish real metrics.
#[cfg(feature = "dtls")]
#[derive(Default)]
pub struct DtlsStats {
    /// Sessions currently alive (handshake done, task running).
    pub active: std::sync::atomic::AtomicUsize,
    /// Sessions admitted since start.
    pub accepted: std::sync::atomic::AtomicU64,
    /// Sessions refused post-handshake because `max_sessions` was hit.
    pub rejected_over_cap: std::sync::atomic::AtomicU64,
    /// Sessions closed (idle timeout, peer close, or error).
    pub closed: std::sync::atomic::AtomicU64,
    /// Sessions closed specifically due to idle timeout.
    pub idle_timeouts: std::sync::atomic::AtomicU64,
    pub bytes_rx: std::sync::atomic::AtomicU64,
    pub bytes_tx: std::sync::atomic::AtomicU64,
    /// DTL-3: outbound datagrams dropped (session egress queue full).
    pub outbound_dropped: std::sync::atomic::AtomicU64,
    /// DTL-9: sessions refused because the source IP hit max_sessions_per_ip.
    pub rejected_per_ip: std::sync::atomic::AtomicU64,
    /// Outbound datagrams dropped because they exceeded the configured record
    /// MTU. A DTLS record cannot be fragmented at the record layer, so sending
    /// one anyway would rely on IP fragmentation (commonly dropped on the
    /// public Internet) — the datagram is dropped and counted instead.
    pub outbound_oversize: std::sync::atomic::AtomicU64,
    /// Handshakes that failed (bad cert, unsupported suite, malformed flight).
    ///
    /// **Demux path only, and only there is it honest.** On the stock path a
    /// failed handshake never surfaces above `webrtc-dtls::accept()`, which is
    /// why no such counter existed; on the demux path the handshake fails inside
    /// our own task, so this is a real observation rather than a guess.
    pub handshake_failures: std::sync::atomic::AtomicU64,
    /// Datagrams dropped because a peer's inbound queue was full (demux path).
    /// The handshake retransmits, and a live session that cannot keep up must not
    /// stall the demux loop for everyone else.
    pub inbound_dropped: std::sync::atomic::AtomicU64,
    /// Handshakes refused by the per-IP rate limiter, before any DTLS state was
    /// created (demux path).
    pub rejected_rate_limit: std::sync::atomic::AtomicU64,
    /// Successful certificate hot-reloads (demux path).
    pub cert_reloads: std::sync::atomic::AtomicU64,
    /// Failed certificate hot-reloads; the previous material stays in service.
    pub cert_reload_failures: std::sync::atomic::AtomicU64,
    /// Handshakes abandoned because they exceeded `accept_timeout`.
    ///
    /// NOTE the precise meaning: this counts accepts *we* gave up on, not DTLS
    /// handshake failures observed by the stack (those happen below `accept()`
    /// and are not observable — see docs/roadmap/IMPLEMENTATION_STATUS.md). A
    /// non-zero value means either a peer that started a handshake and stopped,
    /// or a legitimate client too slow for the configured bound.
    pub accept_timeouts: std::sync::atomic::AtomicU64,
    /// True once the UDP listener is bound and accepting handshakes; cleared on
    /// drain/exit. Mirrored into `turna_dtls_readiness` by the node.
    pub listening: std::sync::atomic::AtomicBool,
}

/// Point-in-time copy of [`DtlsStats`]. A named struct rather than a tuple so
/// adding a counter cannot silently shift the node's metric mirror.
#[cfg(feature = "dtls")]
#[derive(Debug, Clone, Copy, Default)]
pub struct DtlsStatsSnapshot {
    pub active: usize,
    pub accepted: u64,
    pub rejected_over_cap: u64,
    pub closed: u64,
    pub idle_timeouts: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub outbound_dropped: u64,
    pub rejected_per_ip: u64,
    pub outbound_oversize: u64,
    pub accept_timeouts: u64,
    pub handshake_failures: u64,
    pub inbound_dropped: u64,
    pub rejected_rate_limit: u64,
    pub cert_reloads: u64,
    pub cert_reload_failures: u64,
    pub listening: bool,
}

#[cfg(feature = "dtls")]
impl DtlsStats {
    pub fn snapshot(&self) -> DtlsStatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        DtlsStatsSnapshot {
            active: self.active.load(Relaxed),
            accepted: self.accepted.load(Relaxed),
            rejected_over_cap: self.rejected_over_cap.load(Relaxed),
            closed: self.closed.load(Relaxed),
            idle_timeouts: self.idle_timeouts.load(Relaxed),
            bytes_rx: self.bytes_rx.load(Relaxed),
            bytes_tx: self.bytes_tx.load(Relaxed),
            outbound_dropped: self.outbound_dropped.load(Relaxed),
            rejected_per_ip: self.rejected_per_ip.load(Relaxed),
            outbound_oversize: self.outbound_oversize.load(Relaxed),
            accept_timeouts: self.accept_timeouts.load(Relaxed),
            handshake_failures: self.handshake_failures.load(Relaxed),
            inbound_dropped: self.inbound_dropped.load(Relaxed),
            rejected_rate_limit: self.rejected_rate_limit.load(Relaxed),
            cert_reloads: self.cert_reloads.load(Relaxed),
            cert_reload_failures: self.cert_reload_failures.load(Relaxed),
            listening: self.listening.load(Relaxed),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DtlsError {
    #[error("DTLS requested but built without the `dtls` feature")]
    NotSupported,
    #[error("dtls: {0}")]
    Other(String),
}

pub(crate) type Result<T> = std::result::Result<T, DtlsError>;

/// Whether this build actually supports DTLS, i.e. was compiled with the
/// `dtls` feature.
///
/// Used by the node for a startup fail-fast: enabling `[turn.dtls]` in config
/// on a binary built **without** the feature would otherwise make
/// `DtlsServer::run` return [`DtlsError::NotSupported`] inside a spawned task
/// and the listener would silently never start, while the operator believes
/// TURN-over-DTLS is being served. The const lives here (not in the node) so
/// the `cfg!` is evaluated in the crate that actually declares the `dtls`
/// feature — keeping the node free of an unexpected-`cfg` lint.
pub const DTLS_AVAILABLE: bool = cfg!(feature = "dtls");

pub struct DtlsServer {
    config: DtlsConfig,
}

impl DtlsServer {
    pub fn new(config: DtlsConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &DtlsConfig {
        &self.config
    }

    /// Without the `dtls` feature, a no-op stub returning `NotSupported`.
    #[cfg(not(feature = "dtls"))]
    pub async fn run(
        &self,
        _event_tx: tokio::sync::mpsc::Sender<DtlsEvent>,
        _outbound: std::sync::Arc<
            std::sync::Mutex<
                std::collections::HashMap<String, tokio::sync::mpsc::Sender<DtlsOutbound>>,
            >,
        >,
        _shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        Err(DtlsError::NotSupported)
    }

    /// Real DTLS listener: accept handshakes, then per session pump decrypted
    /// records out as `Datagram`s and encrypt queued `DtlsOutbound`s back.
    ///
    /// Admission control: `accept()` only returns after a completed handshake,
    /// so the `max_sessions` check below is *post-handshake* — it caps how many
    /// sessions we will service concurrently, dropping (closing) the freshly
    /// established connection if we are already at the cap. (Pre-handshake
    /// flood protection is the listener/cookie layer's job — design doc §5.)
    #[cfg(feature = "dtls")]
    pub async fn run(
        &self,
        event_tx: tokio::sync::mpsc::Sender<DtlsEvent>,
        outbound: OutboundRegistry,
        stats: std::sync::Arc<DtlsStats>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        use std::sync::atomic::Ordering::Relaxed;
        use webrtc_dtls::config::Config;
        use webrtc_dtls::listener::listen;
        use webrtc_util::conn::Listener;

        // Opt-in: own the UDP socket instead of letting `listen()` own it. See
        // `crate::dtls_demux` for why (concurrent handshakes, pre-handshake
        // admission, certificate hot-reload). Default off — the stock path below
        // is the one with recorded verification.
        if self.config.demux {
            let _ = rustls::crypto::ring::default_provider().install_default();
            return crate::dtls_demux::run_demux(
                self.config.clone(),
                event_tx,
                outbound,
                stats,
                shutdown,
            )
            .await;
        }

        // rustls 0.23 in this dependency tree unifies both the `ring` and
        // `aws-lc-rs` crypto features (pulled by quinn + webrtc), which disables
        // automatic crypto-provider selection. quinn passes its provider
        // explicitly, but webrtc-dtls relies on the *process-default* provider —
        // so install one here, once. `install_default` returns Err if a provider
        // is already set (e.g. on a listener restart); that is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();

        tracing::info!(addr = %self.config.listen_addr, "DTLS (TURN over DTLS) server starting");

        let certificate = load_certificate(&self.config.cert_path, &self.config.key_path)?;
        let cfg = Config {
            certificates: vec![certificate],
            insecure_skip_verify: false,
            ..Default::default()
        };

        // `listen` builds a UDP listener that demultiplexes by remote address
        // and drives DTLS handshakes (cookie exchange included). `accept()`
        // only completes for fully-handshaked peers.
        let listener = listen(self.config.listen_addr, cfg)
            .await
            .map_err(|e| DtlsError::Other(format!("listen: {e}")))?;
        tracing::info!(addr = %self.config.listen_addr, "DTLS endpoint listening");
        // The socket is bound and cookie exchange is live — only now is it
        // honest to report the DTLS listener ready.
        stats.listening.store(true, Relaxed);

        spawn_stats_logger(stats.clone());

        let mtu = self.config.mtu;
        let max_sessions = self.config.max_sessions;
        let max_per_ip = self.config.max_sessions_per_ip;
        let accept_timeout = self.config.accept_timeout;
        let per_ip: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        loop {
            // DTL-4: stop accepting new handshakes on shutdown. accept() is
            // cancel-safe (dropped if shutdown wins); the listener is released
            // when this function returns.
            if *shutdown.borrow() {
                break;
            }
            // UPSTREAM LIVENESS BUG (webrtc-rs/webrtc#614). `DtlsListener::accept()`
            // runs `DTLSConn::new()` — the whole handshake — inline, with no
            // timeout of its own:
            //
            //     let (conn, raddr) = self.parent.accept().await?;
            //     let dtls_conn = DTLSConn::new(conn, self.config.clone(), false, None).await?;
            //
            // So a peer that begins a handshake and then goes silent parks
            // `accept()` forever, and this loop never reaches the next peer. One
            // unfinished handshake takes the entire DTLS listener out of service
            // while the process stays healthy, the socket stays bound, and
            // `turna_dtls_readiness` still reads Ready — a silent outage from a
            // single packet. The HelloVerifyRequest cookie exchange does not help:
            // it defends against spoofed source addresses, not against a real peer
            // that simply stops.
            //
            // Bounding the accept gives the loop back its liveness: on timeout the
            // in-flight future is dropped (webrtc-dtls tears its handshake state
            // down) and we move on. This is a mitigation, not a fix — an attacker
            // can still consume one timeout window at a time, so new-session
            // throughput degrades under a deliberate flood. The real fix is owning
            // the UDP demultiplexer so handshakes run concurrently instead of
            // serially inside accept(); see docs/design/dtls-turn.md.
            let accept_fut = listener.accept();
            let accepted = if accept_timeout.is_zero() {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    r = accept_fut => Some(r),
                }
            } else {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    r = tokio::time::timeout(accept_timeout, accept_fut) => r.ok(),
                }
            };
            let (conn, remote) = match accepted {
                Some(r) => r.map_err(|e| DtlsError::Other(format!("accept: {e}")))?,
                None => {
                    stats.accept_timeouts.fetch_add(1, Relaxed);
                    tracing::warn!(
                        timeout = ?accept_timeout,
                        "DTLS handshake abandoned: accept() exceeded the bound. The \
                         listener stays live; see turna_dtls_accept_timeouts_total."
                    );
                    continue;
                }
            };

            // Post-handshake admission control. `max_sessions == 0` = unlimited.
            if max_sessions != 0 && stats.active.load(Relaxed) >= max_sessions {
                stats.rejected_over_cap.fetch_add(1, Relaxed);
                tracing::warn!(
                    %remote,
                    max_sessions,
                    "DTLS session refused: max_sessions reached (dropping connection)"
                );
                // Drop the Conn without servicing it; webrtc-dtls tears the
                // handshake state down on drop. We intentionally do not call a
                // method on the trait object here (keeps trait scope minimal).
                drop(conn);
                continue;
            }

            // DTL-9: per-source-IP concurrent session cap (anti slot-exhaustion).
            {
                let ip = remote.ip();
                let mut m = per_ip.lock().unwrap();
                let n = *m.get(&ip).unwrap_or(&0);
                if max_per_ip != 0 && n as usize >= max_per_ip {
                    drop(m);
                    stats.rejected_per_ip.fetch_add(1, Relaxed);
                    tracing::warn!(%remote, max_per_ip, "DTLS session refused: per-IP cap reached");
                    drop(conn);
                    continue;
                }
                *m.entry(ip).or_insert(0) += 1;
            }
            stats.active.fetch_add(1, Relaxed);
            stats.accepted.fetch_add(1, Relaxed);
            let tx = event_tx.clone();
            let reg = outbound.clone();
            let st = stats.clone();
            let idle = self.config.idle_timeout;
            let cap = self.config.outbound_queue_capacity;
            let sd = shutdown.clone();
            let pip = per_ip.clone();
            tokio::spawn(async move {
                handle_dtls_session(conn, remote, tx, reg, mtu, idle, cap, st, pip, sd).await;
            });
        }

        stats.listening.store(false, Relaxed);
        tracing::info!("DTLS listener draining: shutdown signalled, no new handshakes");
        Ok(())
    }
}

/// Periodic stats line so operators can see DTLS health without scraping.
#[cfg(feature = "dtls")]
fn spawn_stats_logger(stats: std::sync::Arc<DtlsStats>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let s = stats.snapshot();
            tracing::info!(
                active = s.active,
                accepted = s.accepted,
                rejected_over_cap = s.rejected_over_cap,
                closed = s.closed,
                idle_timeouts = s.idle_timeouts,
                bytes_rx = s.bytes_rx,
                bytes_tx = s.bytes_tx,
                outbound_dropped = s.outbound_dropped,
                rejected_per_ip = s.rejected_per_ip,
                outbound_oversize = s.outbound_oversize,
                listening = s.listening,
                "DTLS stats"
            );
        }
    });
}

/// Per-session task: register the outbound channel, announce the session, then
/// pump decrypted records → `Datagram` and queued responses → `conn.send`.
///
/// Idle timeout: if no record is received within `idle_timeout`, the session is
/// closed (RFC 7350 leaves lifetime to the TURN allocation, but a transport
/// idle reaper bounds half-open sessions left by clients that vanish).
#[cfg(feature = "dtls")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_dtls_session(
    conn: std::sync::Arc<dyn webrtc_util::conn::Conn + Send + Sync>,
    remote: SocketAddr,
    tx: tokio::sync::mpsc::Sender<DtlsEvent>,
    outbound: OutboundRegistry,
    mtu: usize,
    idle_timeout: Duration,
    capacity: usize,
    stats: std::sync::Arc<DtlsStats>,
    per_ip: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    use std::sync::atomic::Ordering::Relaxed;

    let session_id = remote.to_string();

    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<DtlsOutbound>(capacity.max(1));
    if let Ok(mut g) = outbound.lock() {
        g.insert(session_id.clone(), out_tx);
    }
    let _ = tx
        .send(DtlsEvent::NewSession {
            session_id: session_id.clone(),
            remote,
        })
        .await;

    // Receive buffer: a DTLS 1.2 record carries up to 2^14 bytes of plaintext
    // (RFC 6347 §4.1 → RFC 5246 §6.2.1), independent of the *send*-side MTU we
    // impose on ourselves. Sizing this at `mtu.max(2048)` truncated or errored
    // out any larger client record (e.g. a Send indication with a big payload)
    // and killed the session.
    let mut buf = vec![0u8; mtu.max(MAX_DTLS_PLAINTEXT)];

    // Resettable idle deadline.
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);

    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::debug!(%remote, "DTLS session draining on shutdown");
                break;
            }
            _ = &mut idle => {
                stats.idle_timeouts.fetch_add(1, Relaxed);
                tracing::debug!(%remote, ?idle_timeout, "DTLS session idle timeout");
                break;
            }
            r = conn.recv(&mut buf) => match r {
                Ok(0) => break,
                Ok(n) => {
                    stats.bytes_rx.fetch_add(n as u64, Relaxed);
                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    let _ = tx
                        .send(DtlsEvent::Datagram {
                            session_id: session_id.clone(),
                            remote,
                            data: buf[..n].to_vec(),
                        })
                        .await;
                }
                Err(_) => break,
            },
            out = out_rx.recv() => match out {
                // conn.send encrypts the TURN response into this DTLS session.
                Some(msg) => {
                    // A single DTLS record cannot be fragmented at the record
                    // layer, so an oversized datagram would depend on IP
                    // fragmentation — widely dropped on the public Internet, and
                    // a silent one-way media failure for the client. Drop and
                    // count it instead of pretending it was delivered. TURN
                    // control responses are tiny; relayed ChannelData larger
                    // than the configured MTU means the operator's `mtu` is
                    // below the media path MTU in use, which the counter surfaces.
                    if msg.data.len() > mtu {
                        stats.outbound_oversize.fetch_add(1, Relaxed);
                        tracing::warn!(
                            %remote, len = msg.data.len(), mtu,
                            "DTLS outbound exceeds record MTU; dropped (raise [turn.dtls].mtu)"
                        );
                        continue;
                    }
                    match conn.send(&msg.data).await {
                        Ok(_) => {
                            stats.bytes_tx.fetch_add(msg.data.len() as u64, Relaxed);
                            idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        }
                        Err(_) => break,
                    }
                }
                None => break,
            },
        }
    }

    if let Ok(mut g) = outbound.lock() {
        g.remove(&session_id);
    }
    let _ = conn.close().await;
    stats.active.fetch_sub(1, Relaxed);
    stats.closed.fetch_add(1, Relaxed);
    {
        let ip = remote.ip();
        let mut m = per_ip.lock().unwrap();
        if let Some(n) = m.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&ip);
            }
        }
    }
    let _ = tx.send(DtlsEvent::SessionClosed { session_id }).await;
}

/// Build a `webrtc-dtls` certificate from PEM cert + key files.
///
/// `webrtc_dtls::crypto::Certificate::from_pem` (behind webrtc-dtls' `pem`
/// feature) expects a single PEM string with the **private key first** (PKCS#8,
/// tag `PRIVATE_KEY`) followed by the certificate chain. PKCS#1 (`RSA PRIVATE
/// KEY`) / SEC1 (`EC PRIVATE KEY`) keys are not accepted — convert with
/// `openssl pkcs8 -topk8 -nocrypt` if needed.
#[cfg(feature = "dtls")]
pub(crate) fn load_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<webrtc_dtls::crypto::Certificate> {
    // If the operator did not configure a cert/key, use an ephemeral
    // self-signed cert (dev/test convenience — DTLS-TURN has no CA trust needs
    // for a throwaway handshake). But if a cert/key WAS configured and fails to
    // load, fail closed: do NOT silently downgrade to self-signed, or the
    // operator would believe DTLS is serving their cert when it is not.
    if cert_path.is_empty() || key_path.is_empty() {
        tracing::info!("DTLS: no operator cert configured; using ephemeral self-signed cert");
        return webrtc_dtls::crypto::Certificate::generate_self_signed(vec![
            "turn.local".to_owned()
        ])
        .map_err(|e| DtlsError::Other(format!("dtls self-signed certificate: {e}")));
    }
    match load_operator_certificate(cert_path, key_path) {
        Ok(cert) => {
            tracing::info!(cert = %cert_path, key = %key_path, "DTLS using operator certificate");
            Ok(cert)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                cert = %cert_path,
                key = %key_path,
                "DTLS operator certificate configured but failed to load; refusing to start. \
                 The key must be PKCS#8 ECDSA P-256 (`PRIVATE KEY`, not `EC PRIVATE KEY`); \
                 convert with `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem`."
            );
            Err(e)
        }
    }
}

/// Load an operator-supplied PEM cert + key into a `webrtc-dtls` certificate.
///
/// `Certificate::from_pem` parses via the `pem` crate and needs the private-key
/// block tagged `PRIVATE_KEY` (underscore) with PKCS#8 DER — not the openssl
/// `PRIVATE KEY` (space). We re-tag the key block and concatenate key-first +
/// cert chain. Non-PKCS#8 keys (`RSA`/`EC PRIVATE KEY`) must be converted first:
/// `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem`.
///
/// IMPORTANT: the key MUST be ECDSA P-256. webrtc-dtls negotiates only
/// `ECDHE-ECDSA-*` cipher suites, so an RSA cert loads cleanly but every
/// DTLS handshake then aborts with an `internal_error` alert (no shared
/// cipher). Generate with `openssl ecparam -name prime256v1 -genkey`.
#[cfg(feature = "dtls")]
fn load_operator_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<webrtc_dtls::crypto::Certificate> {
    if cert_path.is_empty() || key_path.is_empty() {
        return Err(DtlsError::Other(
            "no DTLS cert_path/key_path configured".to_owned(),
        ));
    }
    let cert_pem = std::fs::read_to_string(cert_path)
        .map_err(|e| DtlsError::Other(format!("read cert {cert_path}: {e}")))?;
    let key_pem = std::fs::read_to_string(key_path)
        .map_err(|e| DtlsError::Other(format!("read key {key_path}: {e}")))?;
    // Re-tag the PKCS#8 header/footer to webrtc's expected `PRIVATE_KEY` tag,
    // then place the key block first, followed by the certificate chain.
    let retagged_key = key_pem
        .replace("-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE_KEY-----")
        .replace("-----END PRIVATE KEY-----", "-----END PRIVATE_KEY-----");
    let combined = format!("{}\n{}", retagged_key.trim_end(), cert_pem.trim_start());
    // `from_pem` may panic on unexpected key DER; contain it so a bad operator
    // cert degrades to the self-signed fallback instead of crashing the node.
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        webrtc_dtls::crypto::Certificate::from_pem(&combined)
    }));
    match parsed {
        Ok(Ok(cert)) => Ok(cert),
        Ok(Err(e)) => Err(DtlsError::Other(format!("from_pem: {e}"))),
        Err(_) => Err(DtlsError::Other(
            "from_pem panicked (key likely not PKCS#8; convert with `openssl pkcs8 -topk8`)"
                .to_owned(),
        )),
    }
}
