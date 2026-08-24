//! QUIC / WebTransport transport (RFC 9000, RFC 9220).
//!
//! WebTransport over HTTP/3: browser connects via QUIC, opens
//! bidirectional streams for signaling and unidirectional/datagrams for media.
//!
//! Advantages over WebSocket + UDP:
//! - Single connection for signaling + media
//! - Built-in encryption (TLS 1.3)
//! - Connection migration (IP change without reconnect)
//! - Head-of-line blocking only per-stream (not per-connection)
//! - Datagrams for low-latency media (no HoL blocking at all)
//!
//! Backend: quinn crate (pure Rust QUIC).
//!
//! This module provides the abstraction — quinn integration is behind
//! a feature flag to avoid pulling the dependency unconditionally.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tracing::info;
// `warn!` is only used inside the feature-gated listener/admission code
// below, so importing it unconditionally warns on a default build.
#[cfg(any(feature = "quic", feature = "web-transport"))]
use tracing::warn;

#[derive(Debug, Error)]
pub enum QuicError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("datagram error: {0}")]
    Datagram(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("not supported")]
    NotSupported,
}

pub type Result<T> = std::result::Result<T, QuicError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct QuicConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    /// Max concurrent bidirectional streams per connection.
    pub max_bi_streams: u64,
    /// Max concurrent unidirectional streams.
    pub max_uni_streams: u64,
    /// Enable QUIC datagrams (RFC 9221) — for low-latency media.
    pub enable_datagrams: bool,
    /// Max datagram size.
    pub max_datagram_size: usize,
    /// Idle timeout.
    pub idle_timeout: Duration,
    /// Keep-alive interval.
    pub keep_alive: Duration,
    /// ALPN protocols.
    pub alpn: Vec<String>,
    /// Max concurrent sessions serviced at once. 0 = unlimited.
    pub max_sessions: usize,
    /// Max concurrent sessions per source IP. 0 = unlimited.
    pub max_sessions_per_ip: usize,
    /// Certificate hot-reload interval (WebTransport path). Zero disables it.
    pub cert_reload_interval: Duration,
    /// Max new handshakes per second per source IP. Zero disables the limit.
    pub max_handshakes_per_sec_per_ip: u32,
    /// Burst allowance for the handshake rate limit.
    pub handshake_burst_per_ip: u32,
    /// Allow QUIC connection migration (client address changes). WebTransport
    /// path only — the builder exposes it; the raw-QUIC path keeps quinn's
    /// default.
    pub allow_migration: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            cert_path: "/etc/turna/tls/cert.pem".into(),
            key_path: "/etc/turna/tls/key.pem".into(),
            max_bi_streams: 100,
            max_uni_streams: 100,
            enable_datagrams: true,
            max_datagram_size: 1200,
            idle_timeout: Duration::from_secs(30),
            keep_alive: Duration::from_secs(10),
            alpn: vec![
                "h3".into(),           // HTTP/3
                "webtransport".into(), // WebTransport
            ],
            max_sessions: 10_000,
            max_sessions_per_ip: 0,
            cert_reload_interval: Duration::from_secs(30),
            max_handshakes_per_sec_per_ip: 0,
            handshake_burst_per_ip: 0,
            allow_migration: true,
        }
    }
}

// ---------------------------------------------------------------------------
// WebTransport Session
// ---------------------------------------------------------------------------

/// A WebTransport session over QUIC.
///
/// Provides:
/// - Bidirectional streams (for signaling, reliable data)
/// - Unidirectional streams (for server push)
/// - Datagrams (for low-latency media, unreliable)
pub struct WebTransportSession {
    pub session_id: String,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    /// Connection ID (for migration tracking).
    pub connection_id: Vec<u8>,
    /// Whether datagrams are available.
    pub datagrams_available: bool,
    /// ALPN negotiated.
    pub alpn: String,
    /// Creation time.
    pub created_at: std::time::Instant,
}

// NOTE: `WebTransportSession` is a *descriptor* of an established session, not
// a handle: the connection itself is owned by the per-session task in this
// module, and outbound data is delivered through `OutboundRegistry` /
// `QuicOutbound`. The previous `send_datagram` / `open_bi_stream` /
// `open_uni_stream` methods and the `BiStream` / `UniStream` types were
// unimplemented placeholders that returned `Ok(())` / `Ok(0)` without touching
// the network — a silent no-op for any caller outside this crate. They are
// removed rather than left to look functional.

// ---------------------------------------------------------------------------
// QUIC Server (trait for quinn backend)
// ---------------------------------------------------------------------------

/// QUIC server events.
pub enum QuicEvent {
    /// New WebTransport session established.
    NewSession(WebTransportSession),
    /// Datagram received on a session.
    Datagram { session_id: String, data: Vec<u8> },
    /// Bidirectional stream opened by client.
    BiStreamOpened { session_id: String, stream_id: u64 },
    /// Stream data received.
    StreamData {
        session_id: String,
        stream_id: u64,
        data: Vec<u8>,
    },
    /// Session closed.
    SessionClosed { session_id: String, reason: String },
    /// Connection migrated to new address.
    ConnectionMigrated {
        session_id: String,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    },
}

/// An outbound packet to deliver back over a WebTransport session (Phase 4).
/// `via_datagram` selects the unreliable datagram path (media) over the
/// reliable control stream (STUN/TURN responses) — see the bridge's framing
/// contract ("control on the bidi stream, media as a datagram").
#[derive(Debug, Clone)]
pub struct QuicOutbound {
    pub session_id: String,
    pub data: Vec<u8>,
    pub via_datagram: bool,
    /// Which bidi stream to answer on (ignored when `via_datagram`).
    ///
    /// A control response belongs on the stream the request arrived on. The
    /// previous code pinned the *first* stream a client ever opened as the only
    /// writer, so a client that opens a stream per request (or re-opens after
    /// closing one) never received an answer. `None` = no preference; the most
    /// recently opened stream is used.
    pub stream_id: Option<u64>,
}

/// B6: per-session outbound queue depth. A bounded channel means a slow or
/// stalled session sheds excess outbound (media/control) instead of growing
/// memory without limit; the producer drops on full (try_send) and counts it.
#[cfg(any(feature = "quic", feature = "web-transport"))]
pub const QUIC_OUTBOUND_CAP: usize = 1024;

/// `session_id` → sender into that session's writer task. The relay-bridge
/// consumer pushes `QuicOutbound`s here; each session task drains its own
/// receiver and writes to the wtransport connection. A cheap `std::Mutex` is
/// fine — no `.await` is held across the lock and the non-blocking `try_send`
/// never awaits.
#[cfg(any(feature = "quic", feature = "web-transport"))]
pub type OutboundRegistry = std::sync::Arc<
    std::sync::Mutex<std::collections::HashMap<String, tokio::sync::mpsc::Sender<QuicOutbound>>>,
>;

/// Process-wide counters for the WebTransport/QUIC path (parity with the DTLS
/// transport's `DtlsStats`). Cheap atomics, snapshotted by a periodic logger;
/// the node side can also read these to publish real metrics.
#[cfg(any(feature = "quic", feature = "web-transport"))]
#[derive(Default)]
pub struct QuicStats {
    /// Sessions currently alive (handshake done, task running).
    pub active: std::sync::atomic::AtomicUsize,
    /// Sessions admitted since start.
    pub accepted: std::sync::atomic::AtomicU64,
    /// Sessions closed (peer close or error).
    pub closed: std::sync::atomic::AtomicU64,
    /// Inbound datagrams (media path).
    pub datagrams_rx: std::sync::atomic::AtomicU64,
    /// Outbound datagrams (media path).
    pub datagrams_tx: std::sync::atomic::AtomicU64,
    /// Client-opened bidi streams (control path).
    pub streams_opened: std::sync::atomic::AtomicU64,
    /// Bytes written on the control (bidi) stream.
    pub control_bytes_tx: std::sync::atomic::AtomicU64,
    /// Outbound send failures (datagram or stream).
    pub send_errors: std::sync::atomic::AtomicU64,
    /// Inbound connections/sessions that failed before becoming usable
    /// (handshake error, rejected CONNECT).
    pub handshake_failures: std::sync::atomic::AtomicU64,
    /// Control responses dropped because the session had no open bidi stream.
    pub control_dropped_no_stream: std::sync::atomic::AtomicU64,
    /// Sessions refused because `max_sessions` was reached.
    pub rejected_over_cap: std::sync::atomic::AtomicU64,
    /// Sessions refused because the source IP hit `max_sessions_per_ip`.
    pub rejected_per_ip: std::sync::atomic::AtomicU64,
    /// Successful certificate hot-reloads (WebTransport path).
    pub cert_reloads: std::sync::atomic::AtomicU64,
    /// Failed certificate hot-reloads; the previous material stays in service.
    pub cert_reload_failures: std::sync::atomic::AtomicU64,
    /// Handshakes refused by the per-IP handshake rate limiter.
    pub rejected_rate_limit: std::sync::atomic::AtomicU64,
    /// Observed client address changes (QUIC connection migration).
    pub migrations: std::sync::atomic::AtomicU64,
    /// True once the QUIC endpoint is bound and accepting; cleared on drain.
    pub listening: std::sync::atomic::AtomicBool,
}

/// Point-in-time copy of [`QuicStats`] (named struct so adding a counter cannot
/// shift the node's positional metric mirror).
#[cfg(any(feature = "quic", feature = "web-transport"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct QuicStatsSnapshot {
    pub active: usize,
    pub accepted: u64,
    pub closed: u64,
    pub datagrams_rx: u64,
    pub datagrams_tx: u64,
    pub streams_opened: u64,
    pub control_bytes_tx: u64,
    pub send_errors: u64,
    pub handshake_failures: u64,
    pub control_dropped_no_stream: u64,
    pub rejected_over_cap: u64,
    pub rejected_per_ip: u64,
    pub cert_reloads: u64,
    pub cert_reload_failures: u64,
    pub rejected_rate_limit: u64,
    pub migrations: u64,
    pub listening: bool,
}

#[cfg(any(feature = "quic", feature = "web-transport"))]
impl QuicStats {
    pub fn snapshot(&self) -> QuicStatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        QuicStatsSnapshot {
            active: self.active.load(Relaxed),
            accepted: self.accepted.load(Relaxed),
            closed: self.closed.load(Relaxed),
            datagrams_rx: self.datagrams_rx.load(Relaxed),
            datagrams_tx: self.datagrams_tx.load(Relaxed),
            streams_opened: self.streams_opened.load(Relaxed),
            control_bytes_tx: self.control_bytes_tx.load(Relaxed),
            send_errors: self.send_errors.load(Relaxed),
            handshake_failures: self.handshake_failures.load(Relaxed),
            control_dropped_no_stream: self.control_dropped_no_stream.load(Relaxed),
            rejected_over_cap: self.rejected_over_cap.load(Relaxed),
            rejected_per_ip: self.rejected_per_ip.load(Relaxed),
            cert_reloads: self.cert_reloads.load(Relaxed),
            cert_reload_failures: self.cert_reload_failures.load(Relaxed),
            rejected_rate_limit: self.rejected_rate_limit.load(Relaxed),
            migrations: self.migrations.load(Relaxed),
            listening: self.listening.load(Relaxed),
        }
    }
}

/// Periodic stats line so operators can see QUIC/WebTransport health.
#[cfg(any(feature = "quic", feature = "web-transport"))]
fn spawn_quic_stats_logger(stats: std::sync::Arc<QuicStats>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let s = stats.snapshot();
            info!(
                active = s.active,
                accepted = s.accepted,
                closed = s.closed,
                datagrams_rx = s.datagrams_rx,
                datagrams_tx = s.datagrams_tx,
                streams_opened = s.streams_opened,
                control_bytes_tx = s.control_bytes_tx,
                send_errors = s.send_errors,
                handshake_failures = s.handshake_failures,
                control_dropped_no_stream = s.control_dropped_no_stream,
                rejected_over_cap = s.rejected_over_cap,
                rejected_per_ip = s.rejected_per_ip,
                cert_reloads = s.cert_reloads,
                cert_reload_failures = s.cert_reload_failures,
                rejected_rate_limit = s.rejected_rate_limit,
                migrations = s.migrations,
                listening = s.listening,
                "QUIC stats"
            );
        }
    });
}

// The per-source-IP handshake rate limiter now lives in `crate::ratelimit`
// so the TURNS listener (feature `tls`, no quic) can use it too. Re-exported
// here because both QUIC paths and their docs refer to it as
// `quic::HandshakeLimiter`.
pub use crate::ratelimit::HandshakeLimiter;

/// Last-modified time of a certificate/key file, or `None` if unreadable.
/// Used by the WebTransport hot-reload poll; an unreadable file compares equal
/// to itself, so a missing file does not trigger a reload storm.
#[cfg(any(feature = "quic", feature = "web-transport"))]
fn file_mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Per-source-IP live session counts, shared by a listener and its session
/// tasks (parity with the DTLS listener's DTL-9 cap).
#[cfg(any(feature = "quic", feature = "web-transport"))]
pub type PerIpSessions =
    std::sync::Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, u32>>>;

/// Post-handshake admission control shared by the raw-QUIC and WebTransport
/// session tasks. Returns `false` when the session must be refused (the caller
/// drops the connection); on `true` the per-IP counter has been incremented and
/// the caller must call [`release_admission`] when the session ends.
///
/// Both caps were previously absent on the QUIC path entirely: a single source
/// could open unlimited sessions, each with its own task, buffers and outbound
/// queue.
#[cfg(any(feature = "quic", feature = "web-transport"))]
fn admit_session(
    remote: SocketAddr,
    max_sessions: usize,
    max_per_ip: usize,
    per_ip: &PerIpSessions,
    stats: &QuicStats,
) -> bool {
    use std::sync::atomic::Ordering::Relaxed;
    if max_sessions != 0 && stats.active.load(Relaxed) >= max_sessions {
        stats.rejected_over_cap.fetch_add(1, Relaxed);
        warn!(%remote, max_sessions, "QUIC session refused: max_sessions reached");
        return false;
    }
    let ip = remote.ip();
    let mut m = match per_ip.lock() {
        Ok(g) => g,
        Err(_) => return true, // poisoned lock must not deny service
    };
    if max_per_ip != 0 && *m.get(&ip).unwrap_or(&0) as usize >= max_per_ip {
        drop(m);
        stats.rejected_per_ip.fetch_add(1, Relaxed);
        warn!(%remote, max_per_ip, "QUIC session refused: per-IP cap reached");
        return false;
    }
    *m.entry(ip).or_insert(0) += 1;
    true
}

/// Interval at which a session task re-reads its peer address to notice a QUIC
/// connection migration. QUIC only surfaces a migrated address after path
/// validation, so polling `remote_address()` is how a server observes it — there
/// is no event for it in either backend.
#[cfg(any(feature = "quic", feature = "web-transport"))]
pub const MIGRATION_POLL: Duration = Duration::from_secs(2);

/// Compare the session's current peer address with the last known one and, if it
/// changed, emit `ConnectionMigrated` and hand the per-IP admission slot over to
/// the new address.
///
/// Without this the event was defined and handled (the bridge re-keys its address
/// index, the listener re-keys `client_sinks`) but never emitted, so a client
/// whose address changed kept its session while all peer→client traffic went to
/// the stale address.
#[cfg(any(feature = "quic", feature = "web-transport"))]
async fn note_migration(
    current: SocketAddr,
    known: &mut SocketAddr,
    session_id: &str,
    tx: &tokio::sync::mpsc::Sender<QuicEvent>,
    stats: &QuicStats,
    per_ip: &PerIpSessions,
) {
    if current == *known {
        return;
    }
    let old = *known;
    *known = current;
    // Move the admission slot with the client, or the old IP would stay charged
    // for a session it no longer owns and the new IP would be uncounted.
    if old.ip() != current.ip() {
        release_admission(old, per_ip);
        if let Ok(mut m) = per_ip.lock() {
            *m.entry(current.ip()).or_insert(0) += 1;
        }
    }
    stats
        .migrations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    info!(%old, new = %current, session = %session_id, "QUIC connection migrated");
    let _ = tx
        .send(QuicEvent::ConnectionMigrated {
            session_id: session_id.to_string(),
            old_addr: old,
            new_addr: current,
        })
        .await;
}

/// Release the per-IP slot taken by [`admit_session`].
#[cfg(any(feature = "quic", feature = "web-transport"))]
fn release_admission(remote: SocketAddr, per_ip: &PerIpSessions) {
    if let Ok(mut m) = per_ip.lock() {
        let ip = remote.ip();
        if let Some(n) = m.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&ip);
            }
        }
    }
}

/// Whether this build supports the raw-QUIC datapath, i.e. was compiled with
/// the `quic` feature.
///
/// Used by the node for a startup fail-fast (same reasoning as
/// [`crate::dtls::DTLS_AVAILABLE`]): enabling `[turn.quic]` on a binary built
/// without the feature would otherwise leave the listener silently unstarted
/// while the operator believes QUIC is being served. The const lives here so
/// the `cfg!` is evaluated in the crate that declares the feature.
pub const QUIC_AVAILABLE: bool = cfg!(feature = "quic");

/// Whether this build supports WebTransport-over-HTTP/3 (the browser CONNECT
/// handshake), i.e. was compiled with the `web-transport` feature.
///
/// `[turn.quic] web_transport = true` (the default) needs this; the raw-QUIC
/// datapath alone only needs [`QUIC_AVAILABLE`].
pub const WEB_TRANSPORT_AVAILABLE: bool = cfg!(feature = "web-transport");

/// QUIC server handle.
pub struct QuicServer {
    config: QuicConfig,
}

impl QuicServer {
    pub fn new(config: QuicConfig) -> Self {
        info!(addr = %config.listen_addr, "QUIC/WebTransport server configured");
        Self { config }
    }

    /// Start the QUIC server.
    ///
    /// Without the `quic` feature this is a no-op stub returning
    /// `NotSupported` (no quinn dependency is compiled in). With the feature it
    /// runs a real quinn endpoint; see the `#[cfg(feature = "quic")]` impl.
    #[cfg(not(feature = "quic"))]
    pub async fn run(&self, _event_tx: tokio::sync::mpsc::Sender<QuicEvent>) -> Result<()> {
        info!("QUIC server requested but built without the `quic` feature");
        Err(QuicError::NotSupported)
    }

    /// Raw-QUIC server: quinn endpoint + accept loop, surfacing streams and
    /// datagrams as `QuicEvent`s. Selected with `[turn.quic] web_transport =
    /// false`; the browser HTTP/3 path is [`run_web_transport`].
    ///
    /// Unlike the WebTransport path, this one applies the full `[turn.quic]`
    /// transport config (stream limits, datagram buffer, idle timeout) because it
    /// owns the `quinn::ServerConfig` directly. Admission control is
    /// post-handshake here (quinn's `Incoming` is refused before the handshake
    /// only for the rate limit), whereas WebTransport can refuse on the session
    /// request itself.
    ///
    /// Verified against quinn 0.11 + rustls 0.23.
    #[cfg(feature = "quic")]
    pub async fn run(
        &self,
        event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
        outbound: OutboundRegistry,
        stats: std::sync::Arc<QuicStats>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        info!(
            addr = %self.config.listen_addr,
            alpn = ?self.config.alpn,
            datagrams = self.config.enable_datagrams,
            "QUIC server starting"
        );

        let endpoint = quinn::Endpoint::server(self.build_quic_config()?, self.config.listen_addr)
            .map_err(|e| QuicError::Connection(e.to_string()))?;
        info!(addr = %self.config.listen_addr, "QUIC endpoint listening");
        stats
            .listening
            .store(true, std::sync::atomic::Ordering::Relaxed);

        spawn_quic_stats_logger(stats.clone());

        let per_ip: PerIpSessions =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let limiter = std::sync::Arc::new(HandshakeLimiter::new(
            self.config.max_handshakes_per_sec_per_ip,
            self.config.handshake_burst_per_ip,
        ));
        if limiter.enabled() {
            info!(
                rate = self.config.max_handshakes_per_sec_per_ip,
                burst = self.config.handshake_burst_per_ip,
                "QUIC per-IP handshake rate limit active"
            );
        }
        let mut sweep = tokio::time::interval(Duration::from_secs(30));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Certificate hot-reload. `quinn::Endpoint::set_server_config` swaps the
        // material for *new* connections without touching live ones, so the raw
        // path reloads like the WebTransport one (and like TURNS) instead of
        // needing a restart.
        let reload_enabled = !self.config.cert_reload_interval.is_zero();
        let mut reload_tick = tokio::time::interval(if reload_enabled {
            self.config.cert_reload_interval
        } else {
            Duration::from_secs(3600)
        });
        reload_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        reload_tick.tick().await; // the first tick completes immediately
        let mut cert_mt = file_mtime(&self.config.cert_path);
        let mut key_mt = file_mtime(&self.config.key_path);
        if !reload_enabled {
            info!("QUIC certificate hot-reload disabled (cert_reload_interval = 0)");
        }

        // Accept loop: one task per connection, each translating quinn events
        // into `QuicEvent`s on the shared channel. Stops on the shutdown watch
        // (previously there was no shutdown path at all, so a drain could only
        // `abort()` the task mid-write).
        loop {
            if *shutdown.borrow() {
                break;
            }
            let incoming = tokio::select! {
                _ = shutdown.changed() => break,
                _ = sweep.tick() => {
                    limiter.sweep();
                    continue;
                }
                _ = reload_tick.tick() => {
                    if reload_enabled {
                        let nc = file_mtime(&self.config.cert_path);
                        let nk = file_mtime(&self.config.key_path);
                        if nc != cert_mt || nk != key_mt {
                            cert_mt = nc;
                            key_mt = nk;
                            match self.build_quic_config() {
                                Ok(cfg) => {
                                    // Infallible on the quinn side; only building
                                    // the config can fail.
                                    endpoint.set_server_config(Some(cfg));
                                    stats
                                        .cert_reloads
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    info!("QUIC certificate reloaded");
                                }
                                Err(e) => {
                                    stats
                                        .cert_reload_failures
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    warn!(%e, "QUIC certificate reload failed; keeping previous certificate");
                                }
                            }
                        }
                    }
                    continue;
                }
                acc = endpoint.accept() => match acc {
                    Some(i) => i,
                    None => break, // endpoint closed
                },
            };

            // Rate-limit BEFORE awaiting the handshake: `quinn::Incoming` has not
            // cost us a handshake yet, and dropping it declines the attempt.
            let peer = incoming.remote_address();
            if !limiter.allow(peer.ip()) {
                stats
                    .rejected_rate_limit
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!(%peer, "QUIC handshake refused: per-IP rate limit");
                drop(incoming);
                continue;
            }

            let tx = event_tx.clone();
            let reg = outbound.clone();
            let st = stats.clone();
            let pip = per_ip.clone();
            let max_sessions = self.config.max_sessions;
            let max_per_ip = self.config.max_sessions_per_ip;
            tokio::spawn(async move {
                if let Err(e) =
                    handle_quic_connection(incoming, tx, reg, st, pip, max_sessions, max_per_ip)
                        .await
                {
                    tracing::warn!(%e, "QUIC connection ended with error");
                }
            });
        }
        stats
            .listening
            .store(false, std::sync::atomic::Ordering::Relaxed);
        info!("QUIC listener draining: shutdown signalled, no new connections");
        Ok(())
    }

    /// WebTransport-over-HTTP/3 server. Performs the browser CONNECT handshake
    /// via `wtransport`, then surfaces each session's datagrams and bidi streams
    /// as the same `QuicEvent`s the raw-QUIC path emits — so the relay bridge
    /// (`turna_relay::quic_bridge`) consumes both identically.
    ///
    /// Verified against the wtransport 0.7 API. What `[turn.quic]` reaches here:
    ///   * listen address, cert/key identity and `keep_alive` via the builder;
    ///   * `max_sessions` / `max_sessions_per_ip` enforced **pre**-handshake on
    ///     `IncomingSession` (cheaper than the raw path's post-handshake check);
    ///   * `cert_reload_secs` via `Endpoint::reload_config`.
    ///
    ///   * the transport limits (stream counts, datagram buffer, idle timeout)
    ///     via `ServerConfig::quic_config_mut()`, reachable since the wtransport
    ///     dependency enables its `quinn` re-export — so this path now enforces
    ///     the same `[turn.quic]` limits as the raw-QUIC one.
    ///
    /// NOT reached: `alpn`, inert by design — wtransport negotiates "h3" itself.
    ///
    /// Certificate hot-reload uses `Endpoint::reload_config(cfg, rebind=false)`,
    /// which swaps the material for new sessions without disturbing live ones.
    #[cfg(feature = "web-transport")]
    pub async fn run_web_transport(
        &self,
        event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
        outbound: OutboundRegistry,
        stats: std::sync::Arc<QuicStats>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        use wtransport::Endpoint;

        info!(addr = %self.config.listen_addr, "WebTransport (H3) server starting");

        let endpoint = Endpoint::server(self.build_wt_config().await?)
            .map_err(|e| QuicError::Connection(e.to_string()))?;
        let local_addr = endpoint.local_addr().unwrap_or(self.config.listen_addr);
        info!(addr = %local_addr, "WebTransport endpoint listening");
        stats
            .listening
            .store(true, std::sync::atomic::Ordering::Relaxed);

        spawn_quic_stats_logger(stats.clone());

        let per_ip: PerIpSessions =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let limiter = std::sync::Arc::new(HandshakeLimiter::new(
            self.config.max_handshakes_per_sec_per_ip,
            self.config.handshake_burst_per_ip,
        ));
        if limiter.enabled() {
            info!(
                rate = self.config.max_handshakes_per_sec_per_ip,
                burst = self.config.handshake_burst_per_ip,
                "WebTransport per-IP handshake rate limit active"
            );
        }

        // Certificate hot-reload poll. The accept loop owns the endpoint, so the
        // check lives in its `select!` rather than a separate task (no need for
        // the endpoint to be cloneable).
        let reload_enabled = !self.config.cert_reload_interval.is_zero();
        let mut reload_tick = tokio::time::interval(if reload_enabled {
            self.config.cert_reload_interval
        } else {
            Duration::from_secs(3600)
        });
        reload_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        reload_tick.tick().await; // the first tick completes immediately
        let mut cert_mt = file_mtime(&self.config.cert_path);
        let mut key_mt = file_mtime(&self.config.key_path);
        if !reload_enabled {
            info!("WebTransport certificate hot-reload disabled (cert_reload_interval = 0)");
        }

        loop {
            if *shutdown.borrow() {
                break;
            }
            let incoming = tokio::select! {
                _ = shutdown.changed() => break,
                _ = reload_tick.tick() => {
                    if reload_enabled {
                        let nc = file_mtime(&self.config.cert_path);
                        let nk = file_mtime(&self.config.key_path);
                        if nc != cert_mt || nk != key_mt {
                            cert_mt = nc;
                            key_mt = nk;
                            match self.build_wt_config().await {
                                // rebind = false: keep the same socket and every
                                // live session; only new handshakes see the new
                                // certificate.
                                Ok(cfg) => match endpoint.reload_config(cfg, false) {
                                    Ok(()) => {
                                        stats
                                            .cert_reloads
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        info!("WebTransport certificate reloaded");
                                    }
                                    Err(e) => {
                                        stats
                                            .cert_reload_failures
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        warn!(%e, "WebTransport certificate reload rejected; keeping previous certificate");
                                    }
                                },
                                Err(e) => {
                                    stats
                                        .cert_reload_failures
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    warn!(%e, "WebTransport certificate reload failed to build; keeping previous certificate");
                                }
                            }
                        }
                    }
                    limiter.sweep();
                    continue;
                }
                inc = endpoint.accept() => inc,
            };

            // PRE-handshake admission control: `IncomingSession` exposes the peer
            // address and can be refused outright, so an over-cap or abusive
            // source never costs us a QUIC/H3 handshake. (The raw-QUIC path can
            // only check post-handshake.)
            let remote = incoming.remote_address();
            if !limiter.allow(remote.ip()) {
                stats
                    .rejected_rate_limit
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!(%remote, "WebTransport handshake refused: per-IP rate limit");
                incoming.refuse();
                continue;
            }
            if !admit_session(
                remote,
                self.config.max_sessions,
                self.config.max_sessions_per_ip,
                &per_ip,
                &stats,
            ) {
                incoming.refuse();
                continue;
            }

            let tx = event_tx.clone();
            let reg = outbound.clone();
            let st = stats.clone();
            let pip = per_ip.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_wt_session(incoming, tx, reg, st, pip, local_addr).await {
                    tracing::warn!(%e, "WebTransport session ended with error");
                }
            });
        }
        stats
            .listening
            .store(false, std::sync::atomic::Ordering::Relaxed);
        info!("WebTransport listener draining: shutdown signalled, no new sessions");
        Ok(())
    }

    /// Build the quinn `ServerConfig` for the raw-QUIC path from `[turn.quic]`.
    /// Used at startup and on certificate hot-reload, so the two can never drift.
    #[cfg(feature = "quic")]
    fn build_quic_config(&self) -> Result<quinn::ServerConfig> {
        use std::sync::Arc;

        // rustls server config from cert/key (the same PEM material the `tls`
        // transport uses).
        //
        // The provider is pinned explicitly rather than left to
        // `ServerConfig::builder()`, which resolves a *process-global* default and
        // has none when more than one provider is in the dependency graph. That is
        // not hypothetical: with `--features "tls,quic"` both ring and aws-lc-rs are
        // present, and this call took the listener down between "QUIC server
        // starting" and "QUIC endpoint listening" — no error line, just a dead
        // listener and `turna_quic_readiness` stuck at 2. `tcp_tls.rs` already pins
        // ring for exactly this reason; raw QUIC was the one path that did not, so
        // it worked under `--features quic` alone and failed the moment `tls` was
        // enabled alongside it.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certs = load_certs(&self.config.cert_path)?;
        let key = load_key(&self.config.key_path)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| QuicError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        tls.alpn_protocols = self
            .config
            .alpn
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        // quinn server config + transport tuning.
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        {
            let tp = Arc::get_mut(&mut server_config.transport)
                .expect("fresh ServerConfig has a unique transport");
            tp.max_concurrent_bidi_streams((self.config.max_bi_streams as u32).into());
            tp.max_concurrent_uni_streams((self.config.max_uni_streams as u32).into());
            tp.max_idle_timeout(Some(
                self.config
                    .idle_timeout
                    .try_into()
                    .map_err(|_| QuicError::Connection("idle_timeout too large".into()))?,
            ));
            tp.keep_alive_interval(Some(self.config.keep_alive));
            if self.config.enable_datagrams {
                tp.datagram_receive_buffer_size(Some(self.config.max_datagram_size * 16));
            } else {
                tp.datagram_receive_buffer_size(None);
            }
        }
        Ok(server_config)
    }

    /// Build a wtransport `ServerConfig` from `[turn.quic]`, applying the knobs
    /// the builder does not expose through the underlying `quinn::ServerConfig`.
    /// Used both at startup and on certificate hot-reload.
    #[cfg(feature = "web-transport")]
    async fn build_wt_config(&self) -> Result<wtransport::ServerConfig> {
        use wtransport::{Identity, ServerConfig};

        let identity = Identity::load_pemfiles(&self.config.cert_path, &self.config.key_path)
            .await
            .map_err(|e| QuicError::Tls(format!("wtransport identity: {e}")))?;

        let mut config = ServerConfig::builder()
            .with_bind_address(self.config.listen_addr)
            .with_identity(identity)
            .keep_alive_interval(Some(self.config.keep_alive))
            .allow_migration(self.config.allow_migration)
            .build();

        // [turn.quic] transport limits, applied through wtransport's quinn
        // re-export (dependency feature "quinn"). Previously unreachable, so
        // these keys silently did nothing on this path; now the WebTransport and
        // raw-QUIC paths enforce the same limits. `alpn` stays inert by design —
        // wtransport negotiates "h3".
        {
            let mut tp = wtransport::quinn::TransportConfig::default();
            tp.max_concurrent_bidi_streams((self.config.max_bi_streams as u32).into());
            tp.max_concurrent_uni_streams((self.config.max_uni_streams as u32).into());
            tp.max_idle_timeout(Some(
                self.config
                    .idle_timeout
                    .try_into()
                    .map_err(|_| QuicError::Connection("idle_timeout too large".into()))?,
            ));
            tp.keep_alive_interval(Some(self.config.keep_alive));
            if self.config.enable_datagrams {
                tp.datagram_receive_buffer_size(Some(self.config.max_datagram_size * 16));
            } else {
                tp.datagram_receive_buffer_size(None);
            }
            config.quic_config_mut().transport = std::sync::Arc::new(tp);
        }

        Ok(config)
    }

    pub fn config(&self) -> &QuicConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// quinn-backed helpers (feature = "quic", draft — verify the quinn 0.11 /
// rustls 0.23 / rustls-pki-types PEM APIs with `cargo build --features quic`)
// ---------------------------------------------------------------------------

#[cfg(feature = "quic")]
fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| QuicError::Tls(format!("read cert {path}: {e}")))?;
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    CertificateDer::pem_slice_iter(&data[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| QuicError::Tls(e.to_string()))
}

#[cfg(feature = "quic")]
fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| QuicError::Tls(format!("read key {path}: {e}")))?;
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    PrivateKeyDer::from_pem_slice(&data[..])
        .map_err(|e| QuicError::Tls(format!("no private key in {path}: {e}")))
}

/// Per-connection task for the raw-QUIC path: emit `NewSession`, then surface
/// inbound datagrams and bidi-stream chunks as events until the connection
/// closes, and write outbound responses back.
///
/// Two things this used to get wrong:
///   * it called `recv.read_to_end(1 MiB)` on an accepted bidi stream, so a
///     control stream that stays open for the session's lifetime never yielded
///     a single message — and while it waited, the same `select!` arm blocked
///     datagram reception;
///   * it kept only the *first* stream's send half, so a client that opens a
///     stream per request never received an answer.
///
/// Now each accepted stream's recv half is pumped per chunk in its own task
/// (matching `StreamFramer`'s incremental reassembly), and every send half is
/// retained so a response can go back on the stream its request arrived on.
#[cfg(feature = "quic")]
#[allow(clippy::too_many_arguments)]
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    outbound: OutboundRegistry,
    stats: std::sync::Arc<QuicStats>,
    per_ip: PerIpSessions,
    max_sessions: usize,
    max_sessions_per_ip: usize,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            stats.handshake_failures.fetch_add(1, Relaxed);
            return Err(QuicError::Connection(e.to_string()));
        }
    };
    let remote = conn.remote_address();

    // Admission control (post-handshake, like the DTLS listener): refuse rather
    // than service an unbounded number of sessions. Dropping the `Connection`
    // closes it.
    if !admit_session(remote, max_sessions, max_sessions_per_ip, &per_ip, &stats) {
        drop(conn);
        return Ok(());
    }
    let session_id = format!("quic-{}", conn.stable_id());
    let alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol.clone())
        .map(|p| String::from_utf8_lossy(&p).into_owned())
        .unwrap_or_default();

    // Register the outbound channel before announcing the session, so the
    // bridge can route responses as soon as it processes NewSession.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<QuicOutbound>(QUIC_OUTBOUND_CAP);
    if let Ok(mut g) = outbound.lock() {
        g.insert(session_id.clone(), out_tx);
    }

    let session = WebTransportSession {
        session_id: session_id.clone(),
        remote_addr: remote,
        // NOTE: quinn's Connection does not expose the local socket address;
        // the field is filled with the remote as a placeholder (the bridge keys
        // sessions on the remote, so nothing reads this today).
        local_addr: remote,
        connection_id: (conn.stable_id() as u64).to_le_bytes().to_vec(),
        datagrams_available: conn.max_datagram_size().is_some(),
        alpn,
        created_at: std::time::Instant::now(),
    };
    let _ = tx.send(QuicEvent::NewSession(session)).await;
    stats.active.fetch_add(1, Relaxed);
    stats.accepted.fetch_add(1, Relaxed);

    // Every client-opened bidi stream's send half, keyed by stream id, plus the
    // id of the most recently opened one (the default reply target when an
    // outbound carries no explicit `stream_id`).
    let mut writers: std::collections::HashMap<u64, quinn::SendStream> =
        std::collections::HashMap::new();
    let mut newest_stream: Option<u64> = None;

    // Last address we told the rest of the system about, for migration detection.
    let mut known_addr = remote;
    let mut migration_poll = tokio::time::interval(MIGRATION_POLL);
    migration_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = migration_poll.tick() => {
                note_migration(
                    conn.remote_address(),
                    &mut known_addr,
                    &session_id,
                    &tx,
                    &stats,
                    &per_ip,
                )
                .await;
            }
            dgram = conn.read_datagram() => match dgram {
                Ok(bytes) => {
                    stats.datagrams_rx.fetch_add(1, Relaxed);
                    let _ = tx
                        .send(QuicEvent::Datagram {
                            session_id: session_id.clone(),
                            data: bytes.to_vec(),
                        })
                        .await;
                }
                Err(_) => break,
            },
            bi = conn.accept_bi() => match bi {
                Ok((send, recv)) => {
                    stats.streams_opened.fetch_add(1, Relaxed);
                    let stream_id = recv.id().index();
                    writers.insert(stream_id, send);
                    newest_stream = Some(stream_id);
                    // Pump this stream's recv half incrementally in its own task
                    // so one stream cannot starve datagrams or other streams.
                    let tx2 = tx.clone();
                    let sid = session_id.clone();
                    tokio::spawn(async move { pump_quic_stream(recv, tx2, sid, stream_id).await });
                }
                Err(_) => break,
            },
            out = out_rx.recv() => match out {
                Some(msg) if msg.via_datagram => {
                    // Unreliable media path.
                    match conn.send_datagram(bytes::Bytes::from(msg.data)) {
                        Ok(_) => {
                            stats.datagrams_tx.fetch_add(1, Relaxed);
                        }
                        Err(_) => {
                            stats.send_errors.fetch_add(1, Relaxed);
                        }
                    }
                }
                Some(msg) => {
                    // Reliable control path: answer on the requested stream, else
                    // on the newest one the client opened.
                    let target = msg.stream_id.or(newest_stream);
                    match target.and_then(|id| writers.get_mut(&id)) {
                        Some(w) => {
                            let len = msg.data.len();
                            match w.write_all(&msg.data).await {
                                Ok(_) => {
                                    stats.control_bytes_tx.fetch_add(len as u64, Relaxed);
                                }
                                Err(_) => {
                                    stats.send_errors.fetch_add(1, Relaxed);
                                }
                            }
                        }
                        None => {
                            stats.control_dropped_no_stream.fetch_add(1, Relaxed);
                            tracing::debug!(
                                session = %session_id,
                                stream = ?msg.stream_id,
                                "raw-QUIC control response dropped: no open bidi stream"
                            );
                        }
                    }
                }
                None => break,
            },
        }
    }

    if let Ok(mut g) = outbound.lock() {
        g.remove(&session_id);
    }
    stats.active.fetch_sub(1, Relaxed);
    stats.closed.fetch_add(1, Relaxed);
    // `known_addr`, not `remote`: after a migration the slot was moved to the
    // client's new IP, so releasing the original address would leak a slot on the
    // new one and under-count the old.
    release_admission(known_addr, &per_ip);
    let _ = tx
        .send(QuicEvent::SessionClosed {
            session_id,
            reason: "connection closed".into(),
        })
        .await;
    Ok(())
}

/// Pump one raw-QUIC bidi `RecvStream`, emitting `BiStreamOpened` then
/// `StreamData` per read chunk so `StreamFramer` can reassemble messages
/// incrementally. A control stream stays open for the whole session, so
/// `read_to_end` must never be used here.
#[cfg(feature = "quic")]
async fn pump_quic_stream(
    mut recv: quinn::RecvStream,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    session_id: String,
    stream_id: u64,
) {
    let _ = tx
        .send(QuicEvent::BiStreamOpened {
            session_id: session_id.clone(),
            stream_id,
        })
        .await;

    let mut chunk = [0u8; 8192];
    loop {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) if n > 0 => {
                if tx
                    .send(QuicEvent::StreamData {
                        session_id: session_id.clone(),
                        stream_id,
                        data: chunk[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Some(_)) | Ok(None) => break,
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// wtransport-backed helpers (feature = "web-transport", draft — verify the
// wtransport 0.6 API with `cargo build --features web-transport`)
// ---------------------------------------------------------------------------

/// Per-WebTransport-session task: complete the CONNECT handshake, emit
/// `NewSession`, then surface datagrams and (per-chunk) bidi-stream data as
/// `QuicEvent`s until the session closes, writing outbound responses back.
///
/// Admission control already happened pre-handshake in `run_web_transport`
/// (`IncomingSession` exposes the peer address and can be refused), so this
/// function owns the per-IP slot and must release it on every exit path.
#[cfg(feature = "web-transport")]
async fn handle_wt_session(
    incoming: wtransport::endpoint::IncomingSession,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    outbound: OutboundRegistry,
    stats: std::sync::Arc<QuicStats>,
    per_ip: PerIpSessions,
    local_addr: SocketAddr,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    let remote = incoming.remote_address();

    // CONNECT: IncomingSession → SessionRequest → accept() → Connection.
    let session_request = match incoming.await {
        Ok(r) => r,
        Err(e) => {
            stats.handshake_failures.fetch_add(1, Relaxed);
            release_admission(remote, &per_ip);
            return Err(QuicError::Connection(format!("wt incoming: {e}")));
        }
    };
    let conn = match session_request.accept().await {
        Ok(c) => c,
        Err(e) => {
            stats.handshake_failures.fetch_add(1, Relaxed);
            release_admission(remote, &per_ip);
            return Err(QuicError::Connection(format!("wt accept: {e}")));
        }
    };

    let session_id = format!("wt-{}", conn.stable_id());

    // Register the outbound channel *before* announcing the session, so the
    // bridge can route responses as soon as it processes NewSession.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<QuicOutbound>(QUIC_OUTBOUND_CAP);
    if let Ok(mut g) = outbound.lock() {
        g.insert(session_id.clone(), out_tx);
    }

    let session = WebTransportSession {
        session_id: session_id.clone(),
        remote_addr: conn.remote_address(),
        local_addr,
        connection_id: (conn.stable_id() as u64).to_le_bytes().to_vec(),
        // Ask the connection instead of assuming: a peer that negotiated no
        // datagram support would otherwise look datagram-capable and media
        // sends would fail silently.
        datagrams_available: conn.max_datagram_size().is_some(),
        alpn: "h3".into(),
        created_at: std::time::Instant::now(),
    };
    let _ = tx.send(QuicEvent::NewSession(session)).await;
    stats.active.fetch_add(1, Relaxed);
    stats.accepted.fetch_add(1, Relaxed);

    // Every client-opened bidi stream's send half, keyed by a per-session stream
    // key, plus the newest one as the default reply target. Earlier this path
    // kept only the FIRST stream's send half and reported stream_id = 0 for
    // every stream, so a client opening a stream per request never got answers.
    let mut writers: std::collections::HashMap<u64, wtransport::SendStream> =
        std::collections::HashMap::new();
    let mut newest_stream: Option<u64> = None;
    // Per-session stream counter. The real quinn stream index IS reachable now
    // (the wtransport `quinn` dependency feature is enabled), but it is
    // deliberately not used: the id is purely an opaque routing key: the transport hands it to the bridge in `StreamData`
    // and the bridge hands it back in `QuicOutbound.stream_id`. A monotonic
    // per-session counter is therefore sufficient AND stable, which is all the
    // routing needs. (It is NOT the on-wire QUIC stream id; do not log it as one.)
    let mut next_stream_key: u64 = 0;

    // Last address reported downstream, for migration detection.
    let mut known_addr = conn.remote_address();
    let mut migration_poll = tokio::time::interval(MIGRATION_POLL);
    migration_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = migration_poll.tick() => {
                note_migration(
                    conn.remote_address(),
                    &mut known_addr,
                    &session_id,
                    &tx,
                    &stats,
                    &per_ip,
                )
                .await;
            }
            dgram = conn.receive_datagram() => match dgram {
                Ok(d) => {
                    stats.datagrams_rx.fetch_add(1, Relaxed);
                    let _ = tx
                        .send(QuicEvent::Datagram {
                            session_id: session_id.clone(),
                            data: d.payload().to_vec(),
                        })
                        .await;
                }
                Err(_) => break,
            },
            bi = conn.accept_bi() => match bi {
                Ok((send, recv)) => {
                    stats.streams_opened.fetch_add(1, Relaxed);
                    let stream_id = next_stream_key;
                    next_stream_key += 1;
                    writers.insert(stream_id, send);
                    newest_stream = Some(stream_id);
                    let tx2 = tx.clone();
                    let sid = session_id.clone();
                    tokio::spawn(async move { pump_wt_stream(recv, tx2, sid, stream_id).await });
                }
                Err(_) => break,
            },
            out = out_rx.recv() => match out {
                Some(msg) if msg.via_datagram => {
                    // Unreliable media path.
                    match conn.send_datagram(msg.data) {
                        Ok(_) => {
                            stats.datagrams_tx.fetch_add(1, Relaxed);
                        }
                        Err(_) => {
                            stats.send_errors.fetch_add(1, Relaxed);
                        }
                    }
                }
                Some(msg) => {
                    // Reliable control path: answer on the stream the request
                    // arrived on, else on the newest stream the client opened.
                    let target = msg.stream_id.or(newest_stream);
                    match target.and_then(|id| writers.get_mut(&id)) {
                        Some(w) => {
                            let len = msg.data.len();
                            match w.write_all(&msg.data).await {
                                Ok(_) => {
                                    stats.control_bytes_tx.fetch_add(len as u64, Relaxed);
                                }
                                Err(_) => {
                                    stats.send_errors.fetch_add(1, Relaxed);
                                }
                            }
                        }
                        None => {
                            stats.control_dropped_no_stream.fetch_add(1, Relaxed);
                            tracing::debug!(
                                session = %session_id,
                                stream = ?msg.stream_id,
                                "WebTransport control response dropped: no open bidi stream"
                            );
                        }
                    }
                }
                None => break, // registry dropped the sender
            },
        }
    }

    if let Ok(mut g) = outbound.lock() {
        g.remove(&session_id);
    }
    stats.active.fetch_sub(1, Relaxed);
    stats.closed.fetch_add(1, Relaxed);
    // `known_addr`, not the pre-handshake `remote`: a migration moved the slot.
    release_admission(known_addr, &per_ip);
    let _ = tx
        .send(QuicEvent::SessionClosed {
            session_id,
            reason: "session closed".into(),
        })
        .await;
    Ok(())
}

/// Pump one bidi WebTransport `RecvStream`, emitting `BiStreamOpened` then
/// `StreamData` per read chunk so the bridge's `StreamFramer` can reassemble
/// messages incrementally (a control stream stays open for the whole session,
/// so it must never be read to end).
#[cfg(feature = "web-transport")]
async fn pump_wt_stream(
    mut recv: wtransport::RecvStream,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    session_id: String,
    stream_id: u64,
) {
    let _ = tx
        .send(QuicEvent::BiStreamOpened {
            session_id: session_id.clone(),
            stream_id,
        })
        .await;

    let mut chunk = [0u8; 8192];
    loop {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) if n > 0 => {
                if tx
                    .send(QuicEvent::StreamData {
                        session_id: session_id.clone(),
                        stream_id,
                        data: chunk[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Some(_)) | Ok(None) => break,
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let c = QuicConfig::default();
        assert!(c.enable_datagrams);
        assert_eq!(c.max_datagram_size, 1200);
        assert!(c.alpn.contains(&"h3".to_string()));
    }

    #[test]
    fn config_alpn_is_configurable() {
        let c = QuicConfig {
            alpn: vec!["stun.turn".into()],
            ..Default::default()
        };
        assert_eq!(c.alpn, vec!["stun.turn".to_string()]);
    }
}
