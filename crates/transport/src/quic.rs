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
    /// Enable 0-RTT (faster reconnects, less secure).
    pub enable_0rtt: bool,
    /// ALPN protocols.
    pub alpn: Vec<String>,
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
            enable_0rtt: false,
            alpn: vec![
                "h3".into(),           // HTTP/3
                "webtransport".into(), // WebTransport
            ],
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

impl WebTransportSession {
    /// Send a datagram (unreliable, low-latency).
    /// Ideal for forwarding RTP-like media without HoL blocking.
    pub fn send_datagram(&self, _data: &[u8]) -> Result<()> {
        if !self.datagrams_available {
            return Err(QuicError::Datagram("datagrams not enabled".into()));
        }
        // In production: self.connection.send_datagram(data)
        Ok(())
    }

    /// Open a bidirectional stream (reliable, ordered).
    /// For signaling messages, data channel messages.
    pub fn open_bi_stream(&self) -> Result<BiStream> {
        Ok(BiStream {
            stream_id: rand::random(),
            session_id: self.session_id.clone(),
        })
    }

    /// Send on a unidirectional stream (reliable, server → client).
    pub fn open_uni_stream(&self) -> Result<UniStream> {
        Ok(UniStream {
            stream_id: rand::random(),
            session_id: self.session_id.clone(),
        })
    }
}

/// Bidirectional QUIC stream.
pub struct BiStream {
    pub stream_id: u64,
    pub session_id: String,
}

impl BiStream {
    pub fn send(&self, _data: &[u8]) -> Result<()> {
        // quinn: stream.write_all(data).await
        Ok(())
    }

    pub fn recv(&self, _buf: &mut [u8]) -> Result<usize> {
        // quinn: stream.read(buf).await
        Ok(0)
    }
}

/// Unidirectional QUIC stream (send only).
pub struct UniStream {
    pub stream_id: u64,
    pub session_id: String,
}

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
}

#[cfg(any(feature = "quic", feature = "web-transport"))]
impl QuicStats {
    #[allow(clippy::type_complexity)]
    pub fn snapshot(&self) -> (usize, u64, u64, u64, u64, u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.active.load(Relaxed),
            self.accepted.load(Relaxed),
            self.closed.load(Relaxed),
            self.datagrams_rx.load(Relaxed),
            self.datagrams_tx.load(Relaxed),
            self.streams_opened.load(Relaxed),
            self.control_bytes_tx.load(Relaxed),
            self.send_errors.load(Relaxed),
        )
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
            let (active, accepted, closed, drx, dtx, streams, ctl, errs) = stats.snapshot();
            info!(
                active,
                accepted,
                closed,
                datagrams_rx = drx,
                datagrams_tx = dtx,
                streams_opened = streams,
                control_bytes_tx = ctl,
                send_errors = errs,
                "QUIC stats"
            );
        }
    });
}

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

    /// Real quinn-backed QUIC server (Phase 1: endpoint + accept loop + inbound
    /// events). WebTransport-over-HTTP/3 negotiation (the browser handshake) is
    /// Phase 2 — see `docs/design/quic-webtransport.md`; this loop currently
    /// surfaces raw QUIC streams/datagrams as `QuicEvent`s.
    ///
    /// NOTE (draft): written against quinn 0.11 + rustls 0.23. The endpoint /
    /// `ServerConfig` / `Incoming` / stream APIs are the version-sensitive
    /// calls — verify with `cargo build --features quic`.
    #[cfg(feature = "quic")]
    pub async fn run(
        &self,
        event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
        outbound: OutboundRegistry,
        stats: std::sync::Arc<QuicStats>,
    ) -> Result<()> {
        use std::sync::Arc;

        info!(
            addr = %self.config.listen_addr,
            alpn = ?self.config.alpn,
            datagrams = self.config.enable_datagrams,
            "QUIC server starting"
        );

        // ── rustls server config from cert/key (reuse the PEM material the
        // `tls` transport already uses). ──
        let certs = load_certs(&self.config.cert_path)?;
        let key = load_key(&self.config.key_path)?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| QuicError::Tls(e.to_string()))?;
        tls.alpn_protocols = self
            .config
            .alpn
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        // ── quinn server config + transport tuning. ──
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

        let endpoint = quinn::Endpoint::server(server_config, self.config.listen_addr)
            .map_err(|e| QuicError::Connection(e.to_string()))?;
        info!(addr = %self.config.listen_addr, "QUIC endpoint listening");

        spawn_quic_stats_logger(stats.clone());

        // Accept loop: one task per connection, each translating quinn events
        // into `QuicEvent`s on the shared channel.
        while let Some(incoming) = endpoint.accept().await {
            let tx = event_tx.clone();
            let reg = outbound.clone();
            let st = stats.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_quic_connection(incoming, tx, reg, st).await {
                    tracing::warn!(%e, "QUIC connection ended with error");
                }
            });
        }
        Ok(())
    }

    /// WebTransport-over-HTTP/3 server (Phase 2). Performs the browser CONNECT
    /// handshake via `wtransport`, then surfaces each session's datagrams and
    /// bidi streams as the same `QuicEvent`s the raw-QUIC path emits — so the
    /// relay bridge (`turna_relay::quic_bridge`) consumes both identically.
    ///
    /// Unlike the quinn Phase-1 path (which buffers a whole bidi stream before
    /// surfacing it), this pumps `StreamData` per read chunk: a WebTransport
    /// session keeps one control bidi stream open for its whole lifetime, so
    /// `read_to_end` would block forever and starve the framer. Per-chunk
    /// delivery matches `StreamFramer`'s incremental reassembly.
    ///
    /// NOTE (draft): written against the wtransport 0.6 API. `Endpoint::server`,
    /// `ServerConfig::builder`, `Identity::load_pemfiles`, `accept()` →
    /// `IncomingSession` → `SessionRequest::accept()` → `Connection`, and the
    /// `Connection` stream/datagram accessors are the version-sensitive calls —
    /// verify with `cargo build --features web-transport`.
    #[cfg(feature = "web-transport")]
    pub async fn run_web_transport(
        &self,
        event_tx: tokio::sync::mpsc::Sender<QuicEvent>,
        outbound: OutboundRegistry,
        stats: std::sync::Arc<QuicStats>,
    ) -> Result<()> {
        use wtransport::{Endpoint, Identity, ServerConfig};

        info!(addr = %self.config.listen_addr, "WebTransport (H3) server starting");

        // wtransport loads cert+key as an Identity (PEM) and negotiates the "h3"
        // ALPN itself, so QuicConfig.alpn is unused on this path.
        let identity = Identity::load_pemfiles(&self.config.cert_path, &self.config.key_path)
            .await
            .map_err(|e| QuicError::Tls(format!("wtransport identity: {e}")))?;

        // Builder: bind addr + identity + keep-alive. Additional transport tuning
        // (idle timeout, datagram buffer) maps onto the wtransport builder —
        // verify method names/return types against 0.6.
        let config = ServerConfig::builder()
            .with_bind_address(self.config.listen_addr)
            .with_identity(identity)
            .keep_alive_interval(Some(self.config.keep_alive))
            .build();

        let endpoint =
            Endpoint::server(config).map_err(|e| QuicError::Connection(e.to_string()))?;
        info!(addr = %self.config.listen_addr, "WebTransport endpoint listening");

        spawn_quic_stats_logger(stats.clone());

        // wtransport's accept() yields an IncomingSession each iteration (never
        // None), so this is an unbounded loop rather than `while let Some`.
        loop {
            let incoming = endpoint.accept().await;
            let tx = event_tx.clone();
            let reg = outbound.clone();
            let st = stats.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_wt_session(incoming, tx, reg, st).await {
                    tracing::warn!(%e, "WebTransport session ended with error");
                }
            });
        }
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

/// Per-connection task: emit `NewSession`, then surface inbound datagrams and
/// bidi streams as events until the connection closes. Phase 1 draft — it does
/// not yet perform the WebTransport CONNECT handshake (Phase 2) and buffers
/// whole bidi streams rather than streaming them.
#[cfg(feature = "quic")]
async fn handle_quic_connection(
    incoming: quinn::Incoming,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    outbound: OutboundRegistry,
    stats: std::sync::Arc<QuicStats>,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    let conn = incoming
        .await
        .map_err(|e| QuicError::Connection(e.to_string()))?;
    let remote = conn.remote_address();
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
        local_addr: remote, // local addr not exposed on Connection; bridge can fill it
        connection_id: (conn.stable_id() as u64).to_le_bytes().to_vec(),
        datagrams_available: conn.max_datagram_size().is_some(),
        alpn,
        created_at: std::time::Instant::now(),
    };
    let _ = tx.send(QuicEvent::NewSession(session)).await;
    stats.active.fetch_add(1, Relaxed);
    stats.accepted.fetch_add(1, Relaxed);

    // Reliable control writer = send half of the first client-opened bidi
    // stream (STUN/TURN responses go on the bidi stream; media as datagrams).
    let mut control_writer: Option<quinn::SendStream> = None;

    loop {
        tokio::select! {
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
                Ok((send, mut recv)) => {
                    stats.streams_opened.fetch_add(1, Relaxed);
                    if control_writer.is_none() {
                        control_writer = Some(send);
                    }
                    let stream_id = recv.id().index();
                    let _ = tx
                        .send(QuicEvent::BiStreamOpened {
                            session_id: session_id.clone(),
                            stream_id,
                        })
                        .await;
                    // Draft: buffer the whole stream (cap 1 MiB) before surfacing.
                    if let Ok(data) = recv.read_to_end(1024 * 1024).await {
                        let _ = tx
                            .send(QuicEvent::StreamData {
                                session_id: session_id.clone(),
                                stream_id,
                                data,
                            })
                            .await;
                    }
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
                    // Reliable control path on the first bidi stream's send half.
                    if let Some(w) = control_writer.as_mut() {
                        let len = msg.data.len();
                        match w.write_all(&msg.data).await {
                            Ok(_) => {
                                stats.control_bytes_tx.fetch_add(len as u64, Relaxed);
                            }
                            Err(_) => {
                                stats.send_errors.fetch_add(1, Relaxed);
                            }
                        }
                    } else {
                        tracing::debug!(
                            session = %session_id,
                            "raw-QUIC control response dropped: no bidi stream open yet"
                        );
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
    let _ = tx
        .send(QuicEvent::SessionClosed {
            session_id,
            reason: "connection closed".into(),
        })
        .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// wtransport-backed helpers (feature = "web-transport", draft — verify the
// wtransport 0.6 API with `cargo build --features web-transport`)
// ---------------------------------------------------------------------------

/// Per-WebTransport-session task: complete the CONNECT handshake, emit
/// `NewSession`, then surface datagrams and (per-chunk) bidi-stream data as
/// `QuicEvent`s until the session closes. Inbound only — retaining the send
/// half for outbound `Action::Send` delivery is Phase 4.
#[cfg(feature = "web-transport")]
async fn handle_wt_session(
    incoming: wtransport::endpoint::IncomingSession,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    outbound: OutboundRegistry,
    stats: std::sync::Arc<QuicStats>,
) -> Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    // CONNECT: IncomingSession → SessionRequest → accept() → Connection.
    let session_request = incoming
        .await
        .map_err(|e| QuicError::Connection(format!("wt incoming: {e}")))?;
    let conn = session_request
        .accept()
        .await
        .map_err(|e| QuicError::Connection(format!("wt accept: {e}")))?;

    let remote = conn.remote_address();
    let session_id = format!("wt-{}", conn.stable_id());

    // Register the outbound channel *before* announcing the session, so the
    // bridge can route responses as soon as it processes NewSession.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<QuicOutbound>(QUIC_OUTBOUND_CAP);
    if let Ok(mut g) = outbound.lock() {
        g.insert(session_id.clone(), out_tx);
    }

    let session = WebTransportSession {
        session_id: session_id.clone(),
        remote_addr: remote,
        local_addr: remote, // not exposed on Connection; bridge can fill it
        connection_id: (conn.stable_id() as u64).to_le_bytes().to_vec(),
        datagrams_available: true, // WebTransport datagrams negotiated by wtransport
        alpn: "h3".into(),
        created_at: std::time::Instant::now(),
    };
    let _ = tx.send(QuicEvent::NewSession(session)).await;
    stats.active.fetch_add(1, Relaxed);
    stats.accepted.fetch_add(1, Relaxed);

    // Reliable control writer = send half of the first client-opened bidi
    // stream (the contract puts STUN/TURN responses on the bidi stream; media
    // goes out as datagrams).
    let mut control_writer: Option<wtransport::SendStream> = None;

    loop {
        tokio::select! {
            dgram = conn.receive_datagram() => match dgram {
                // wtransport Datagram exposes its bytes via `payload()` — verify.
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
                    // Keep the first stream's send half as the control writer;
                    // pump every stream's recv half incrementally.
                    if control_writer.is_none() {
                        control_writer = Some(send);
                    }
                    let tx2 = tx.clone();
                    let sid = session_id.clone();
                    tokio::spawn(async move { pump_wt_stream(recv, tx2, sid).await });
                }
                Err(_) => break,
            },
            out = out_rx.recv() => match out {
                Some(msg) if msg.via_datagram => {
                    // Unreliable media path. wtransport: send_datagram(payload).
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
                    // Reliable control path. Requires the client to have opened a
                    // bidi stream first (it does — that's how it sends the
                    // request). If none is open yet, drop and log.
                    if let Some(w) = control_writer.as_mut() {
                        let len = msg.data.len();
                        match w.write_all(&msg.data).await {
                            Ok(_) => {
                                stats.control_bytes_tx.fetch_add(len as u64, Relaxed);
                            }
                            Err(_) => {
                                stats.send_errors.fetch_add(1, Relaxed);
                            }
                        }
                    } else {
                        tracing::debug!(
                            session = %session_id,
                            "control response dropped: no bidi stream open yet"
                        );
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
    let _ = tx
        .send(QuicEvent::SessionClosed {
            session_id,
            reason: "session closed".into(),
        })
        .await;
    Ok(())
}

/// Pump one bidi RecvStream, emitting `StreamData` per read chunk so the relay
/// bridge's `StreamFramer` can reassemble messages incrementally (a control
/// stream stays open for the whole session — never `read_to_end`).
#[cfg(feature = "web-transport")]
async fn pump_wt_stream(
    mut recv: wtransport::RecvStream,
    tx: tokio::sync::mpsc::Sender<QuicEvent>,
    session_id: String,
) {
    // wtransport does not expose a stable per-stream index here; 0 is a
    // placeholder (the bridge keys on session_id, not stream_id). Replace with
    // the real accessor if/when StreamData needs to disambiguate streams.
    let stream_id = 0u64;
    let _ = tx
        .send(QuicEvent::BiStreamOpened {
            session_id: session_id.clone(),
            stream_id,
        })
        .await;

    // RecvStream::read(&mut buf) → Result<Option<usize>>: Some(n) bytes,
    // None on EOF. Verify against the wtransport 0.6 RecvStream API.
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
    fn session_datagram_disabled() {
        let session = WebTransportSession {
            session_id: "test".into(),
            remote_addr: "1.2.3.4:5000".parse().unwrap(),
            local_addr: "0.0.0.0:443".parse().unwrap(),
            connection_id: vec![1, 2, 3],
            datagrams_available: false,
            alpn: "h3".into(),
            created_at: std::time::Instant::now(),
        };
        assert!(session.send_datagram(b"test").is_err());
    }
}
