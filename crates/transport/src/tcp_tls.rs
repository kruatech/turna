//! TLS/TCP Transport (TURNS — RFC 5766/8656 over TLS, порт 5349/443)
//!
//! - TLS acceptor на rustls с ALPN "stun.turn"
//! - STUN/TURN-over-TCP framing: сообщения самоописываются.
//!   * STUN — длина в заголовке (байты 2..4) + 20-байтовый заголовок
//!     (RFC 5389/8489 §7.2.2 / §6.2.2; тело уже кратно 4).
//!   * ChannelData — длина (байты 2..4) + 4-байтовый заголовок, с паддингом
//!     до кратности 4 поверх TCP/TLS (RFC 5766/8656 §11.5).
//!     НЕ RFC 4571 (тот — про RTP-over-TCP): стандартные TURN-клиенты
//!     (браузерный WebRTC, coturn) не добавляют 2-байтовый префикс длины.
//! - Certificate hot-reload по mtime
//! - Connection limit, idle timeout
//! - События совместимы с UDP-транспортом (PacketProcessor не знает о типе)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("TLS config: {0}")]
    TlsConfig(#[from] rustls::Error),
    #[error("cert load {path}: {source}")]
    CertLoad {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("key load {path}: {source}")]
    KeyLoad {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("no private key in {0}")]
    NoKey(PathBuf),
    #[error("frame too large: {size} (max {max})")]
    FrameTooLarge { size: usize, max: usize },
    #[error("invalid TURN-over-TCP framing: leading byte 0x{0:02x}")]
    InvalidFraming(u8),
    #[error("connection closed")]
    Closed,
    #[error("TLS handshake timeout ({0:?})")]
    HandshakeTimeout(Duration),
}

pub type Result<T> = std::result::Result<T, TlsError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TlsTransportConfig {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub max_frame_size: usize,
    pub handshake_timeout: Duration,
    pub read_timeout: Duration,
    pub max_connections: usize,
    /// Max concurrent connections from a single source IP. 0 = unlimited.
    pub max_connections_per_ip: usize,
    /// Interval for the mtime-based certificate reload. 0 disables it.
    pub cert_reload_interval: Duration,
    pub enable_alpn: bool,
}

impl Default for TlsTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:5349".parse().unwrap(),
            cert_path: PathBuf::from("/etc/turna/tls/cert.pem"),
            key_path: PathBuf::from("/etc/turna/tls/key.pem"),
            max_frame_size: 64 * 1024,
            handshake_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(300),
            max_connections: 10_000,
            max_connections_per_ip: 0,
            cert_reload_interval: Duration::from_secs(30),
            enable_alpn: true,
        }
    }
}

// ---------------------------------------------------------------------------
// STUN/TURN-over-TCP Frame Codec
//
// Messages are self-delimiting; there is NO 2-byte length prefix. The first
// two bits select the demultiplexing type (RFC 5389 §7.2.2):
//   * 0b00 → STUN message: total length = 20-byte header + length@[2..4]
//            (the length field already excludes the header and is a multiple of 4).
//   * 0b01 → ChannelData: total length = 4-byte header + length@[2..4], padded
//            up to a multiple of 4 over TCP/TLS (RFC 5766/8656 §11.5).
// Anything else is not valid TURN-over-TCP and is treated as a framing error.
// ---------------------------------------------------------------------------

pub struct TcpFrameCodec {
    max_frame_size: usize,
}

impl TcpFrameCodec {
    pub fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    /// Compute the total on-wire length of the message starting at `buf`, or
    /// `None` if fewer than 4 bytes are buffered (need the length field first).
    fn frame_len(&self, buf: &[u8]) -> Result<Option<usize>> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let total = match buf[0] & 0xC0 {
            // STUN: 20-byte header + body (body already padded to 4 by sender).
            0x00 => 20 + body_len,
            // ChannelData: 4-byte header + data, padded to a multiple of 4 over TCP.
            0x40 => 4 + ((body_len + 3) & !3),
            // 0b10 / 0b11 are not STUN nor ChannelData — not valid TURN framing.
            _ => return Err(TlsError::InvalidFraming(buf[0])),
        };
        if total > self.max_frame_size {
            return Err(TlsError::FrameTooLarge {
                size: total,
                max: self.max_frame_size,
            });
        }
        Ok(Some(total))
    }

    /// Try to split one complete message off the front of `buf`. Returns
    /// `Ok(None)` if the buffer does not yet hold a full message.
    pub fn decode(&self, buf: &mut BytesMut) -> Result<Option<BytesMut>> {
        let total = match self.frame_len(buf)? {
            Some(t) => t,
            None => return Ok(None),
        };
        if buf.len() < total {
            return Ok(None);
        }
        Ok(Some(buf.split_to(total)))
    }

    /// Append `payload` to `buf` for sending. The payload is already a complete,
    /// self-framed STUN or ChannelData message, so it is written verbatim — no
    /// length prefix. ChannelData is padded up to a multiple of 4 (TCP/TLS only).
    pub fn encode(&self, payload: &[u8], buf: &mut BytesMut) -> Result<()> {
        if payload.len() > self.max_frame_size {
            return Err(TlsError::FrameTooLarge {
                size: payload.len(),
                max: self.max_frame_size,
            });
        }
        let pad = if !payload.is_empty() && (payload[0] & 0xC0) == 0x40 {
            (4 - (payload.len() & 3)) & 3
        } else {
            0
        };
        buf.reserve(payload.len() + pad);
        buf.put_slice(payload);
        for _ in 0..pad {
            buf.put_u8(0);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Stats
//
// The TURNS listener previously exported nothing at all (DTLS and QUIC both
// had counters), so there was no way to alert on handshake failures, connection
// caps being hit, or framing errors. Same shape as `DtlsStats`: cheap atomics
// here in the leaf transport crate, mirrored into the Prometheus `Metrics` by
// the bridge (which can see `turna-health`).
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TlsStats {
    /// Connections currently established (post-handshake, pre-close).
    pub active: std::sync::atomic::AtomicUsize,
    /// Connections accepted (TCP accept succeeded) since start.
    pub accepted: std::sync::atomic::AtomicU64,
    /// Connections closed for any reason.
    pub closed: std::sync::atomic::AtomicU64,
    /// TLS handshakes that failed (bad client cert/version/cipher, RST, ...).
    pub handshake_failures: std::sync::atomic::AtomicU64,
    /// TLS handshakes that exceeded `handshake_timeout`.
    pub handshake_timeouts: std::sync::atomic::AtomicU64,
    /// Connections refused because `max_connections` was reached.
    pub rejected_over_cap: std::sync::atomic::AtomicU64,
    /// Connections refused because the source IP hit `max_connections_per_ip`.
    pub rejected_per_ip: std::sync::atomic::AtomicU64,
    /// Connections closed by the per-connection idle read timeout.
    pub idle_timeouts: std::sync::atomic::AtomicU64,
    /// Connections closed because the peer sent invalid TURN-over-TCP framing
    /// or an over-sized frame.
    pub framing_errors: std::sync::atomic::AtomicU64,
    /// `accept()` errors that did NOT stop the listener (EMFILE, ECONNABORTED).
    pub accept_errors: std::sync::atomic::AtomicU64,
    /// Decrypted bytes read from clients.
    pub bytes_rx: std::sync::atomic::AtomicU64,
    /// Bytes written to clients (pre-encryption).
    pub bytes_tx: std::sync::atomic::AtomicU64,
    /// Successful certificate hot-reloads.
    pub cert_reloads: std::sync::atomic::AtomicU64,
    /// Failed certificate hot-reloads (old material kept in service).
    pub cert_reload_failures: std::sync::atomic::AtomicU64,
    /// True once the TCP listener is bound; cleared on drain/exit.
    pub listening: std::sync::atomic::AtomicBool,
}

/// Point-in-time copy of [`TlsStats`] (named struct so adding a counter cannot
/// shift a positional mirror).
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsStatsSnapshot {
    pub active: usize,
    pub accepted: u64,
    pub closed: u64,
    pub handshake_failures: u64,
    pub handshake_timeouts: u64,
    pub rejected_over_cap: u64,
    pub rejected_per_ip: u64,
    pub idle_timeouts: u64,
    pub framing_errors: u64,
    pub accept_errors: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub cert_reloads: u64,
    pub cert_reload_failures: u64,
    pub listening: bool,
}

impl TlsStats {
    pub fn snapshot(&self) -> TlsStatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        TlsStatsSnapshot {
            active: self.active.load(Relaxed),
            accepted: self.accepted.load(Relaxed),
            closed: self.closed.load(Relaxed),
            handshake_failures: self.handshake_failures.load(Relaxed),
            handshake_timeouts: self.handshake_timeouts.load(Relaxed),
            rejected_over_cap: self.rejected_over_cap.load(Relaxed),
            rejected_per_ip: self.rejected_per_ip.load(Relaxed),
            idle_timeouts: self.idle_timeouts.load(Relaxed),
            framing_errors: self.framing_errors.load(Relaxed),
            accept_errors: self.accept_errors.load(Relaxed),
            bytes_rx: self.bytes_rx.load(Relaxed),
            bytes_tx: self.bytes_tx.load(Relaxed),
            cert_reloads: self.cert_reloads.load(Relaxed),
            cert_reload_failures: self.cert_reload_failures.load(Relaxed),
            listening: self.listening.load(Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection ID
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpConnectionId(u64);

impl TcpConnectionId {
    pub(crate) fn next(counter: &std::sync::atomic::AtomicU64) -> Self {
        Self(counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

impl std::fmt::Display for TcpConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tcp-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum TcpTransportEvent {
    PacketReceived {
        conn_id: TcpConnectionId,
        peer_addr: SocketAddr,
        data: BytesMut,
    },
    ConnectionOpened {
        conn_id: TcpConnectionId,
        peer_addr: SocketAddr,
    },
    ConnectionClosed {
        conn_id: TcpConnectionId,
        peer_addr: SocketAddr,
        reason: String,
    },
}

#[derive(Debug)]
pub struct TcpSendCommand {
    pub conn_id: TcpConnectionId,
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// RFC 6062 connection role transition (framed control -> raw data)
// ---------------------------------------------------------------------------

/// A connection detached from framed TURN mode after a successful RFC 6062
/// ConnectionBind. `AsyncRead` yields any bytes buffered past the ConnectionBind
/// frame first (`prebuffer`) and then the live decrypted stream, so consumers
/// see one uninterrupted application byte stream; `AsyncWrite` passes straight
/// through. This lets the (generic) TCP relay splice a TLS client stream to the
/// plaintext peer stream without losing the unread prebuffer.
pub struct DetachedConn {
    pub connection_id: u32,
    pub peer_addr: SocketAddr,
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    prebuffer: BytesMut,
}

impl AsyncRead for DetachedConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.prebuffer.is_empty() {
            let n = std::cmp::min(me.prebuffer.len(), buf.remaining());
            let chunk = me.prebuffer.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DetachedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Request (from the relay bridge, after a validated ConnectionBind) to detach a
/// framed connection into raw relay mode. `success` is the ConnectionBind success
/// response, written before the switch (RFC 6062 Â§4.4: success precedes raw mode).
pub struct DetachRequest {
    pub conn_id: TcpConnectionId,
    pub connection_id: u32,
    pub success: Vec<u8>,
}

/// Internal per-connection control message.
enum ConnCtl {
    Send(Vec<u8>),
    Detach {
        connection_id: u32,
        success: Vec<u8>,
    },
}

/// Outcome of `handle_conn`: a normal close (emit ConnectionClosed) vs a detach
/// (ownership moved to the raw relay; not a close).
enum HandleOutcome {
    Closed(String),
    Detached,
}

// ---------------------------------------------------------------------------
// TLS Server
// ---------------------------------------------------------------------------

pub struct TlsTransportServer {
    config: TlsTransportConfig,
    tls_acceptor: TlsAcceptor,
    conn_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl TlsTransportServer {
    pub fn new(config: TlsTransportConfig) -> Result<Self> {
        let tls_config = build_tls_config(&config)?;
        Ok(Self {
            config,
            tls_acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            conn_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    pub async fn run(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        send_rx: mpsc::Receiver<TcpSendCommand>,
    ) -> Result<()> {
        // No RFC 6062 detach: a detach-request channel that never fires and a
        // handoff sink that is never read.
        let (_never_tx, never_rx) = mpsc::channel::<DetachRequest>(1);
        let (out_tx, _out_rx) = mpsc::channel::<DetachedConn>(1);
        self.run_with_detach(event_tx, send_rx, never_rx, out_tx)
            .await
    }

    /// Like [`run`], plus RFC 6062 connection role transition: a `DetachRequest`
    /// (sent after a validated ConnectionBind) makes the owning connection write
    /// the success response, stop framing, and hand its raw stream (plus any
    /// unread bytes) to `detach_out_tx` for raw relaying.
    ///
    /// Kept for compatibility: no shutdown signal (runs until the listener
    /// errors) and throw-away stats. New callers should use [`run_full`].
    pub async fn run_with_detach(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        send_rx: mpsc::Receiver<TcpSendCommand>,
        detach_req_rx: mpsc::Receiver<DetachRequest>,
        detach_out_tx: mpsc::Sender<DetachedConn>,
    ) -> Result<()> {
        let (_never_tx, never_shutdown) = tokio::sync::watch::channel(false);
        self.run_full(
            event_tx,
            send_rx,
            detach_req_rx,
            detach_out_tx,
            Arc::new(TlsStats::default()),
            never_shutdown,
        )
        .await
    }

    /// Full listener: RFC 6062 detach, shared [`TlsStats`], and a cooperative
    /// shutdown signal.
    ///
    /// Shutdown (parity with the DTLS listener's DTL-4): once `shutdown` flips,
    /// the accept loop stops taking new connections and established ones are
    /// asked to close, instead of the whole task being `abort()`ed mid-write.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_full(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        mut send_rx: mpsc::Receiver<TcpSendCommand>,
        mut detach_req_rx: mpsc::Receiver<DetachRequest>,
        detach_out_tx: mpsc::Sender<DetachedConn>,
        stats: Arc<TlsStats>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(
            addr = %self.config.listen_addr,
            max = self.config.max_connections,
            max_per_ip = self.config.max_connections_per_ip,
            "TURNS listening"
        );
        stats.listening.store(true, std::sync::atomic::Ordering::Relaxed);

        // Certificate hot-reload. `CertReloader` existed but was wired to
        // nothing: the acceptor was built once in `new()`, so a rotated cert
        // (ACME renewal) needed a process restart. Each accepted connection now
        // takes the current `ServerConfig` out of this watch channel, so a
        // reload applies to new connections without touching established ones.
        let cert_rx: Option<tokio::sync::watch::Receiver<Arc<ServerConfig>>> =
            if self.config.cert_reload_interval.is_zero() {
                info!("TURNS certificate hot-reload disabled (cert_reload_interval = 0)");
                None
            } else {
                match CertReloader::new(&self.config, self.config.cert_reload_interval)
                    .spawn(stats.clone())
                    .await
                {
                    Ok(rx) => Some(rx),
                    Err(e) => {
                        // Non-fatal: `new()` already validated this material, so
                        // keep serving with the static acceptor.
                        error!(%e, "TURNS certificate hot-reload unavailable; using static cert");
                        None
                    }
                }
            };

        // Per-source-IP connection counts for `max_connections_per_ip`.
        let per_ip: Arc<tokio::sync::RwLock<HashMap<std::net::IpAddr, u32>>> =
            Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let conns: Arc<tokio::sync::RwLock<HashMap<TcpConnectionId, mpsc::Sender<ConnCtl>>>> =
            Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        // Route outbound sends AND detach requests to the owning connection over
        // the same per-connection queue, so a ConnectionBind success is always
        // written before the detach that follows it.
        let conns_route = conns.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = send_rx.recv() => match cmd {
                        Some(cmd) => {
                            let c = conns_route.read().await;
                            if let Some(tx) = c.get(&cmd.conn_id) {
                                let _ = tx.try_send(ConnCtl::Send(cmd.data));
                            }
                        }
                        None => break,
                    },
                    req = detach_req_rx.recv() => match req {
                        Some(req) => {
                            // Clone the owning conn's sender and release the map lock
                            // before delivering, then hand off on a task so a slow or
                            // blocked connection cannot stall routing for every other
                            // connection.
                            let conn_id = req.conn_id;
                            let tx = conns_route.read().await.get(&conn_id).cloned();
                            match tx {
                                Some(tx) => {
                                    let ctl = ConnCtl::Detach {
                                        connection_id: req.connection_id,
                                        success: req.success,
                                    };
                                    tokio::spawn(async move {
                                        // Bounded send, NOT try_send: a transiently full
                                        // per-conn queue must not silently drop the
                                        // detach (which would strand the client framed).
                                        // On error the conn has closed (ctl_rx dropped) —
                                        // surface it; the relay side already released its
                                        // claim on its own send failure.
                                        if tx.send(ctl).await.is_err() {
                                            warn!(conn_id = %conn_id, "RFC 6062 detach not delivered; connection closed");
                                        }
                                    });
                                }
                                None => warn!(conn_id = %conn_id, "RFC 6062 detach for unknown/closed connection"),
                            }
                        }
                        None => break,
                    },
                }
            }
        });

        // Consecutive accept failures, for the EMFILE backoff below.
        let mut accept_failures: u32 = 0;

        loop {
            if *shutdown.borrow() {
                break;
            }
            let accepted = tokio::select! {
                _ = shutdown.changed() => break,
                r = listener.accept() => r,
            };
            let (stream, peer) = match accepted {
                Ok(pair) => {
                    accept_failures = 0;
                    pair
                }
                Err(e) => {
                    // Previously `accept().await?` returned, killing the whole
                    // TURNS listener on the first transient error — a single
                    // EMFILE (fd exhaustion) or ECONNABORTED took TURNS down
                    // until the process restarted. Log, count, back off on
                    // repeats, and keep listening.
                    stats
                        .accept_errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    accept_failures = accept_failures.saturating_add(1);
                    let backoff = std::cmp::min(1000, 10u64 * u64::from(accept_failures));
                    warn!(
                        %e,
                        consecutive = accept_failures,
                        backoff_ms = backoff,
                        "TURNS accept failed; listener staying up"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    continue;
                }
            };
            {
                let c = conns.read().await;
                if c.len() >= self.config.max_connections {
                    stats
                        .rejected_over_cap
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(%peer, max = self.config.max_connections, "connection limit reached");
                    continue;
                }
            }

            // Per-source-IP cap (parity with the DTLS listener's DTL-9): without
            // it a single source could hold every one of `max_connections`.
            let max_per_ip = self.config.max_connections_per_ip;
            if max_per_ip != 0 {
                let ip = peer.ip();
                let mut m = per_ip.write().await;
                if *m.get(&ip).unwrap_or(&0) as usize >= max_per_ip {
                    drop(m);
                    stats
                        .rejected_per_ip
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(%peer, max_per_ip, "TURNS connection refused: per-IP cap reached");
                    continue;
                }
                *m.entry(ip).or_insert(0) += 1;
            } else {
                *per_ip.write().await.entry(peer.ip()).or_insert(0) += 1;
            }

            let conn_id = TcpConnectionId::next(&self.conn_counter);
            let (conn_tx, conn_rx) = mpsc::channel::<ConnCtl>(256);
            conns.write().await.insert(conn_id, conn_tx);
            stats
                .accepted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // Current certificate material: the reloader's latest, else the
            // acceptor built at construction time.
            let tls = match cert_rx.as_ref() {
                Some(rx) => TlsAcceptor::from(rx.borrow().clone()),
                None => self.tls_acceptor.clone(),
            };
            let etx = event_tx.clone();
            let cfg = self.config.clone();
            let conns = conns.clone();
            let dout = detach_out_tx.clone();
            let st = stats.clone();
            let pip = per_ip.clone();
            let conn_shutdown = shutdown.clone();

            tokio::spawn(async move {
                let outcome = handle_conn(
                    conn_id,
                    stream,
                    peer,
                    tls,
                    &cfg,
                    etx.clone(),
                    conn_rx,
                    dout,
                    st.clone(),
                    conn_shutdown,
                )
                .await;
                conns.write().await.remove(&conn_id);
                {
                    let mut m = pip.write().await;
                    if let Some(n) = m.get_mut(&peer.ip()) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            m.remove(&peer.ip());
                        }
                    }
                }
                st.closed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                match outcome {
                    Ok(HandleOutcome::Detached) => { /* moved to raw relay; not a close */ }
                    Ok(HandleOutcome::Closed(reason)) => {
                        let _ = etx
                            .send(TcpTransportEvent::ConnectionClosed {
                                conn_id,
                                peer_addr: peer,
                                reason,
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = etx
                            .send(TcpTransportEvent::ConnectionClosed {
                                conn_id,
                                peer_addr: peer,
                                reason: format!("{e}"),
                            })
                            .await;
                    }
                }
            });
        }

        stats
            .listening
            .store(false, std::sync::atomic::Ordering::Relaxed);
        info!("TURNS listener draining: shutdown signalled, no new connections");
        Ok(())
    }
}

/// Decrements `TlsStats::active` on every exit path of `handle_conn`
/// (including `?` and the RFC 6062 detach), so the gauge cannot drift upward.
struct ActiveGuard {
    stats: Arc<TlsStats>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.stats
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
#[instrument(skip_all, fields(conn = %id, peer = %peer))]
async fn handle_conn(
    id: TcpConnectionId,
    stream: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    cfg: &TlsTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut ctl_rx: mpsc::Receiver<ConnCtl>,
    detach_out_tx: mpsc::Sender<DetachedConn>,
    stats: Arc<TlsStats>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<HandleOutcome> {
    use std::sync::atomic::Ordering::Relaxed;

    let tls_stream = match timeout(cfg.handshake_timeout, tls.accept(stream)).await {
        Err(_) => {
            stats.handshake_timeouts.fetch_add(1, Relaxed);
            return Err(TlsError::HandshakeTimeout(cfg.handshake_timeout));
        }
        Ok(Err(e)) => {
            stats.handshake_failures.fetch_add(1, Relaxed);
            return Err(TlsError::Io(io::Error::other(e)));
        }
        Ok(Ok(s)) => s,
    };
    stats.active.fetch_add(1, Relaxed);
    // Every exit below goes through `finish`, so `active` cannot leak.
    let _guard = ActiveGuard {
        stats: stats.clone(),
    };

    let _ = etx
        .send(TcpTransportEvent::ConnectionOpened {
            conn_id: id,
            peer_addr: peer,
        })
        .await;

    let (mut rd, mut wr) = tokio::io::split(tls_stream);
    let codec = TcpFrameCodec::new(cfg.max_frame_size);
    let mut buf = BytesMut::with_capacity(8192);

    loop {
        tokio::select! {
            // Cooperative drain: stop serving this connection when the process
            // is shutting down instead of being aborted mid-write. An `Err`
            // means the watch sender is gone (the server is going away), which
            // is treated as shutdown — otherwise `changed()` would return
            // immediately forever and spin this loop.
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    let _ = wr.shutdown().await;
                    return Ok(HandleOutcome::Closed("server draining".into()));
                }
            }
            res = timeout(cfg.read_timeout, rd.read_buf(&mut buf)) => {
                match res {
                    Ok(Ok(0)) => return Ok(HandleOutcome::Closed("clean close".into())),
                    Ok(Ok(n)) => {
                        stats.bytes_rx.fetch_add(n as u64, Relaxed);
                        loop {
                            match codec.decode(&mut buf) {
                                Ok(Some(frame)) => {
                                    etx.send(TcpTransportEvent::PacketReceived { conn_id: id, peer_addr: peer, data: frame })
                                        .await.map_err(|_| TlsError::Closed)?;
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    // Invalid framing / over-sized frame: the
                                    // stream can no longer be resynchronised, so
                                    // the connection still dies — but count it so
                                    // a client sending garbage is visible instead
                                    // of looking like a normal disconnect.
                                    stats.framing_errors.fetch_add(1, Relaxed);
                                    return Err(e);
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => return Err(TlsError::Io(e)),
                    Err(_) => {
                        stats.idle_timeouts.fetch_add(1, Relaxed);
                        return Ok(HandleOutcome::Closed("idle timeout".into()));
                    }
                }
            }
            Some(ctl) = ctl_rx.recv() => {
                match ctl {
                    ConnCtl::Send(data) => {
                        // `data` is already a complete self-framed message; encode
                        // only appends ChannelData padding (no length prefix).
                        let mut out = BytesMut::with_capacity(data.len() + 3);
                        codec.encode(&data, &mut out)?;
                        wr.write_all(&out).await?;
                        wr.flush().await?;
                        stats.bytes_tx.fetch_add(out.len() as u64, Relaxed);
                    }
                    ConnCtl::Detach { connection_id, success } => {
                        // RFC 6062 4.4: write the ConnectionBind success, then the
                        // connection stops being a framed control connection and
                        // becomes a raw data connection.
                        let mut out = BytesMut::with_capacity(success.len() + 3);
                        codec.encode(&success, &mut out)?;
                        wr.write_all(&out).await?;
                        wr.flush().await?;
                        stats.bytes_tx.fetch_add(out.len() as u64, Relaxed);
                        let stream = rd.unsplit(wr);
                        let prebuffer = std::mem::take(&mut buf);
                        if detach_out_tx
                            .send(DetachedConn { connection_id, peer_addr: peer, inner: stream, prebuffer })
                            .await
                            .is_err()
                        {
                            // The raw-relay receiver is gone; the detached stream is
                            // dropped here (closing the TCP connection). Report a close
                            // so the session layer tears the claim down instead of
                            // believing the hand-off succeeded.
                            warn!(conn = %id, "RFC 6062 detach hand-off failed; closing connection");
                            return Ok(HandleOutcome::Closed("detach hand-off failed".into()));
                        }
                        return Ok(HandleOutcome::Detached);
                    }
                }
            }
            else => break,
        }
    }
    Ok(HandleOutcome::Closed("clean close".into()))
}

// ---------------------------------------------------------------------------
// TLS Helpers
// ---------------------------------------------------------------------------

/// Build a `ServerConfig` pinned to the `ring` crypto provider.
///
/// rustls 0.23's `ServerConfig::builder()` derives the crypto provider from the
/// process-level default and panics if it cannot pick one — which happens when
/// both `ring` and `aws-lc-rs` end up in the dependency graph via feature
/// unification. Selecting the provider explicitly removes that ambiguity and
/// needs no process-global `install_default()`.
fn ring_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}

fn build_tls_config(cfg: &TlsTransportConfig) -> Result<ServerConfig> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_key(&cfg.key_path)?;
    let mut tls = ring_server_config(certs, key)?;
    if cfg.enable_alpn {
        tls.alpn_protocols = vec![b"stun.turn".to_vec(), b"stun.nat-discovery".to_vec()];
    }
    Ok(tls)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| TlsError::CertLoad {
        path: path.into(),
        source: e,
    })?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(data.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertLoad {
            path: path.into(),
            source: io::Error::new(io::ErrorKind::InvalidData, e),
        })?;
    if certs.is_empty() {
        return Err(TlsError::CertLoad {
            path: path.into(),
            source: io::Error::new(io::ErrorKind::InvalidData, "empty"),
        });
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| TlsError::KeyLoad {
        path: path.into(),
        source: e,
    })?;
    match PrivateKeyDer::from_pem_slice(data.as_slice()) {
        Ok(key) => Ok(key),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => Err(TlsError::NoKey(path.into())),
        Err(e) => Err(TlsError::KeyLoad {
            path: path.into(),
            source: io::Error::new(io::ErrorKind::InvalidData, e),
        }),
    }
}

// ---------------------------------------------------------------------------
// Certificate Hot-Reload
// ---------------------------------------------------------------------------

pub struct CertReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    interval: Duration,
    enable_alpn: bool,
}

impl CertReloader {
    pub fn new(cfg: &TlsTransportConfig, interval: Duration) -> Self {
        Self {
            cert_path: cfg.cert_path.clone(),
            key_path: cfg.key_path.clone(),
            interval,
            enable_alpn: cfg.enable_alpn,
        }
    }

    /// Spawn the watcher and return a channel carrying the newest
    /// `ServerConfig`. The listener reads this per accepted connection, so a
    /// rotated certificate applies without a restart.
    pub async fn spawn(
        self,
        stats: Arc<TlsStats>,
    ) -> Result<tokio::sync::watch::Receiver<Arc<ServerConfig>>> {
        use std::sync::atomic::Ordering::Relaxed;
        let initial = self.reload()?;
        let (tx, rx) = tokio::sync::watch::channel(Arc::new(initial));
        tokio::spawn(async move {
            let mut cert_mt = mtime(&self.cert_path);
            let mut key_mt = mtime(&self.key_path);
            loop {
                tokio::time::sleep(self.interval).await;
                let new_cert = mtime(&self.cert_path);
                let new_key = mtime(&self.key_path);
                if new_cert != cert_mt || new_key != key_mt {
                    match self.reload() {
                        Ok(c) => {
                            let _ = tx.send(Arc::new(c));
                            cert_mt = new_cert;
                            key_mt = new_key;
                            stats.cert_reloads.fetch_add(1, Relaxed);
                            info!("TLS cert reloaded");
                        }
                        Err(e) => {
                            // Keep serving the previous material rather than
                            // dropping TLS because of a half-written PEM.
                            stats.cert_reload_failures.fetch_add(1, Relaxed);
                            error!(%e, "cert reload failed; keeping previous certificate");
                        }
                    }
                }
            }
        });
        Ok(rx)
    }

    fn reload(&self) -> Result<ServerConfig> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;
        let mut tls = ring_server_config(certs, key)?;
        if self.enable_alpn {
            tls.alpn_protocols = vec![b"stun.turn".to_vec(), b"stun.nat-discovery".to_vec()];
        }
        Ok(tls)
    }
}

fn mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal STUN message: type(2) + length(2) + magic cookie(4) + txid(12) = 20
    // header bytes, plus `body` bytes (body must already be 4-aligned).
    fn stun_msg(body: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(20 + body.len());
        m.extend_from_slice(&0x0001u16.to_be_bytes()); // Binding request (top 2 bits = 00)
        m.extend_from_slice(&(body.len() as u16).to_be_bytes());
        m.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
        m.extend_from_slice(&[0u8; 12]); // txid
        m.extend_from_slice(body);
        m
    }

    // ChannelData: channel(2, 0x4000..=0x7FFF) + length(2) + data + pad-to-4.
    fn channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(4 + data.len());
        m.extend_from_slice(&channel.to_be_bytes());
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(data);
        while m.len() % 4 != 0 {
            m.push(0);
        }
        m
    }

    #[test]
    fn stun_roundtrip_no_prefix() {
        let codec = TcpFrameCodec::new(65535);
        let msg = stun_msg(&[]); // 20-byte header, empty body
        let mut buf = BytesMut::new();
        codec.encode(&msg, &mut buf).unwrap();
        assert_eq!(buf.len(), 20, "no length prefix must be added");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(&frame[..], &msg[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn stun_with_body() {
        let codec = TcpFrameCodec::new(65535);
        let msg = stun_msg(&[1, 2, 3, 4]); // 24 bytes total
        let mut buf = BytesMut::from(&msg[..]);
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.len(), 24);
    }

    #[test]
    fn channeldata_padded() {
        let codec = TcpFrameCodec::new(65535);
        // 3 data bytes → padded to 4 → total 8.
        let cd = channel_data(0x4000, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(cd.len(), 8);
        let mut buf = BytesMut::from(&cd[..]);
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame.len(), 8);
        assert!(buf.is_empty());
    }

    #[test]
    fn channeldata_encode_pads() {
        let codec = TcpFrameCodec::new(65535);
        // Unpadded ChannelData (as produced for UDP): 4 hdr + 3 data = 7 bytes.
        let mut unpadded = vec![0x40, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        assert_eq!(unpadded.len(), 7);
        let mut buf = BytesMut::new();
        codec.encode(&unpadded, &mut buf).unwrap();
        assert_eq!(buf.len(), 8, "ChannelData must be padded to 4 over TCP");
        unpadded.clear();
    }

    #[test]
    fn partial_header_returns_none() {
        let codec = TcpFrameCodec::new(65535);
        // Only the channel number, no length yet.
        let mut buf = BytesMut::from(&[0x40, 0x00][..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn partial_body_returns_none() {
        let codec = TcpFrameCodec::new(65535);
        // STUN header claims 8-byte body but only 4 present.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn frame_too_large() {
        let codec = TcpFrameCodec::new(64); // max 64 bytes
                                            // STUN claiming a 1000-byte body.
        let mut buf = BytesMut::from(&[0x00, 0x01, 0x03, 0xE8, 0x21, 0x12, 0xA4, 0x42][..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(TlsError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn invalid_leading_bits_rejected() {
        let codec = TcpFrameCodec::new(65535);
        // 0b11xxxxxx leading byte is neither STUN nor ChannelData.
        let mut buf = BytesMut::from(&[0xC0, 0x00, 0x00, 0x00][..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(TlsError::InvalidFraming(0xC0))
        ));
    }

    #[test]
    fn multi_frame_back_to_back() {
        let codec = TcpFrameCodec::new(65535);
        let a = stun_msg(&[]); // 20
        let b = channel_data(0x4001, &[1, 2, 3, 4]); // 8
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().len(), 20);
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap().len(), 8);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }
}
