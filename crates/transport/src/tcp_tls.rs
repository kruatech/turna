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
//! - The same listener without TLS serves plain TURN over TCP
//!   ([`TlsTransportServer::new_plain`]), and either one can take the client
//!   address from a HAProxy PROXY header ([`crate::proxy_protocol`]).
//! - TLS policy: minimum version and a cipher-suite allowlist, both checked
//!   against what rustls implements ([`supported_cipher_suite_names`]).

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

use crate::proxy_protocol::PrefixedStream;

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
    #[error("ALPN required but the client negotiated none")]
    AlpnMissing,
    #[error("client CA bundle {0} has no usable certificate")]
    ClientCaEmpty(PathBuf),
    #[error("client certificate verifier rejected the CA bundle: {0}")]
    ClientCaInvalid(String),
    #[error("require_client_cert = true needs client_ca_path")]
    ClientCertConfig,
    #[error("alpn_required = true needs enable_alpn = true")]
    AlpnConfig,
    #[error("cipher suite {0:?} is not implemented by this TLS stack")]
    UnknownCipherSuite(String),
    #[error(
        "no cipher suite in the allowlist can be used with this {key:?} certificate key: \
         TLS 1.2 suites must match the key type (ECDSA vs RSA), and the list has no \
         usable TLS 1.3 suite"
    )]
    NoSuiteForKey { key: rustls::SignatureAlgorithm },
    #[error("proxy_protocol = true needs at least one trusted CIDR")]
    ProxyConfig,
    #[error("PROXY protocol: {0}")]
    Proxy(#[from] crate::proxy_protocol::ProxyError),
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
    /// Per-source-IP handshake **rate** limit (handshakes/second). 0 = unlimited.
    /// Complements `max_connections_per_ip`, which bounds only how many
    /// connections a source holds at once.
    pub max_handshakes_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate.
    pub handshake_burst_per_ip: u32,
    /// RFC 7443 strict mode: refuse a client that negotiated no ALPN protocol.
    /// Requires `enable_alpn`. Default false (compatible mode).
    pub alpn_required: bool,
    /// PEM bundle of CA certificates that may sign a TURNS **client** certificate.
    /// Empty (the default) disables client-certificate verification entirely, which
    /// is what a public TURN server wants.
    pub client_ca_path: String,
    /// With a `client_ca_path` set: refuse a client that presents no certificate.
    /// `false` allows unauthenticated clients through TLS and leaves them to the
    /// normal TURN long-term credential check — useful while rolling certificates
    /// out to an existing fleet.
    pub require_client_cert: bool,
    /// Offer TLS 1.3 only. `false` (the default) offers 1.2 and 1.3, which is
    /// rustls's safe default and what this listener always did.
    pub tls13_only: bool,
    /// Cipher-suite allowlist by rustls name. Empty = the provider's defaults.
    pub cipher_suites: Vec<String>,
    /// Expect a HAProxy PROXY header (v1/v2) on every connection and take the
    /// client address from it. Connections from outside `proxy_trusted_cidrs`
    /// are closed without being read.
    pub proxy_protocol: bool,
    /// Load-balancer CIDRs allowed to send the header.
    pub proxy_trusted_cidrs: Vec<String>,
    /// Deadline for the header to arrive.
    pub proxy_header_timeout: Duration,
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
            max_handshakes_per_sec_per_ip: 0,
            handshake_burst_per_ip: 0,
            alpn_required: false,
            client_ca_path: String::new(),
            require_client_cert: false,
            tls13_only: false,
            cipher_suites: Vec::new(),
            proxy_protocol: false,
            proxy_trusted_cidrs: Vec::new(),
            proxy_header_timeout: Duration::from_secs(5),
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
    /// Connections refused by the per-IP handshake rate limiter, before any
    /// TLS work was done.
    pub rejected_rate_limit: std::sync::atomic::AtomicU64,
    /// Connections closed after the handshake because `alpn_required` was set
    /// and the client negotiated no ALPN protocol.
    pub alpn_rejected: std::sync::atomic::AtomicU64,
    /// Connections refused by the PROXY protocol: a source outside the trusted
    /// CIDRs, or a missing, malformed, unsupported or late header.
    pub proxy_rejected: std::sync::atomic::AtomicU64,
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
    pub rejected_rate_limit: u64,
    pub alpn_rejected: u64,
    pub proxy_rejected: u64,
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
            rejected_rate_limit: self.rejected_rate_limit.load(Relaxed),
            alpn_rejected: self.alpn_rejected.load(Relaxed),
            proxy_rejected: self.proxy_rejected.load(Relaxed),
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

/// Any byte stream a detached connection can sit on: a TLS stream for TURNS,
/// the TCP socket itself for plain TURN over TCP, either behind the PROXY
/// header's prefix buffer.
pub trait ConnStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ConnStream for T {}

/// A connection detached from framed TURN mode after a successful RFC 6062
/// ConnectionBind. `AsyncRead` yields any bytes buffered past the ConnectionBind
/// frame first (`prebuffer`) and then the live stream, so consumers see one
/// uninterrupted application byte stream; `AsyncWrite` passes straight through.
/// This lets the (generic) TCP relay splice a TLS or plain client stream to the
/// plaintext peer stream without losing the unread prebuffer.
pub struct DetachedConn {
    pub connection_id: u32,
    pub peer_addr: SocketAddr,
    inner: Box<dyn ConnStream>,
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

/// The TURNS listener, or — built with [`TlsTransportServer::new_plain`] — the
/// plain TURN-over-TCP one. The two differ only in whether a TLS handshake
/// runs before the framed TURN stream; caps, rate limits, framing, idle
/// timeout, drain, RFC 6062 detach and the PROXY protocol are shared.
pub struct TlsTransportServer {
    config: TlsTransportConfig,
    /// `None` for the plain TCP listener.
    tls_acceptor: Option<TlsAcceptor>,
    /// Parsed `proxy_trusted_cidrs`; only read when `proxy_protocol` is set.
    proxy_trusted: crate::proxy_protocol::TrustedSources,
    conn_counter: Arc<std::sync::atomic::AtomicU64>,
}

/// Per-connection admission state shared between the accept loop and, on a
/// PROXY-protocol listener, the task that reads the header.
struct Admission {
    config: TlsTransportConfig,
    limiter: crate::ratelimit::HandshakeLimiter,
    per_ip: tokio::sync::RwLock<HashMap<std::net::IpAddr, u32>>,
    conns: tokio::sync::RwLock<HashMap<TcpConnectionId, mpsc::Sender<ConnCtl>>>,
    conn_counter: Arc<std::sync::atomic::AtomicU64>,
    stats: Arc<TlsStats>,
    label: &'static str,
    /// PROXY-protocol listeners only: one permit per connection that has been
    /// accepted and not yet closed, *including* those still waiting for their
    /// header. Sized from `max_connections` and taken in the accept loop
    /// before the header read is spawned, so a trusted source that opens
    /// connections and sends nothing holds at most `max_connections` tasks and
    /// descriptors for `proxy_header_timeout`, not an unbounded number. The
    /// permit then moves into the admitted connection and is released when it
    /// closes.
    slots: Arc<tokio::sync::Semaphore>,
}

impl Admission {
    /// The rate limiter, the global cap and the per-IP cap, in that order, for
    /// the client address `peer`. On success the connection is registered and
    /// its control queue returned; on refusal the matching counter is bumped.
    async fn admit(&self, peer: SocketAddr) -> Option<(TcpConnectionId, mpsc::Receiver<ConnCtl>)> {
        use std::sync::atomic::Ordering::Relaxed;
        let label = self.label;
        // Refused before any TLS work, so a flood costs a map lookup instead
        // of a handshake.
        if !self.limiter.allow(peer.ip()) {
            self.stats.rejected_rate_limit.fetch_add(1, Relaxed);
            warn!(event = "peer_refused_rate_limit", %peer, "{label} connection refused: per-IP handshake rate limit");
            return None;
        }
        // Check and insert under ONE write lock. On a PROXY-protocol listener
        // `admit` runs concurrently on every connection's own task, and a
        // read-locked check followed by a separately locked insert let any
        // number of them pass the check together and overshoot the cap.
        // Lock order is `conns` then `per_ip`; `release` takes them one after
        // the other, never nested, so the order cannot invert.
        let mut conns = self.conns.write().await;
        if conns.len() >= self.config.max_connections {
            drop(conns);
            self.stats.rejected_over_cap.fetch_add(1, Relaxed);
            warn!(event = "peer_refused_max_connections", %peer, max = self.config.max_connections, "connection limit reached");
            return None;
        }
        // Per-source-IP cap (parity with the DTLS listener's DTL-9): without
        // it a single source could hold every one of `max_connections`.
        let max_per_ip = self.config.max_connections_per_ip;
        {
            let ip = peer.ip();
            let mut m = self.per_ip.write().await;
            if max_per_ip != 0 && *m.get(&ip).unwrap_or(&0) as usize >= max_per_ip {
                drop(m);
                drop(conns);
                self.stats.rejected_per_ip.fetch_add(1, Relaxed);
                warn!(event = "peer_refused_per_ip_cap", %peer, max_per_ip, "{label} connection refused: per-IP cap reached");
                return None;
            }
            *m.entry(ip).or_insert(0) += 1;
        }

        let conn_id = TcpConnectionId::next(&self.conn_counter);
        let (conn_tx, conn_rx) = mpsc::channel::<ConnCtl>(256);
        conns.insert(conn_id, conn_tx);
        drop(conns);
        self.stats.accepted.fetch_add(1, Relaxed);
        Some((conn_id, conn_rx))
    }

    /// Undo `admit` once the connection is gone.
    async fn release(&self, conn_id: TcpConnectionId, peer: SocketAddr) {
        self.conns.write().await.remove(&conn_id);
        let mut m = self.per_ip.write().await;
        if let Some(n) = m.get_mut(&peer.ip()) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&peer.ip());
            }
        }
    }
}

impl TlsTransportServer {
    pub fn new(config: TlsTransportConfig) -> Result<Self> {
        // Strict ALPN with nothing advertised would refuse every client, since no
        // protocol can be negotiated. Fail at construction rather than at the
        // first connection.
        if config.alpn_required && !config.enable_alpn {
            return Err(TlsError::AlpnConfig);
        }
        // `require_client_cert` with no CA would demand a certificate that nothing
        // can validate, refusing every client.
        if config.require_client_cert && config.client_ca_path.is_empty() {
            return Err(TlsError::ClientCertConfig);
        }
        let tls_config = build_tls_config(&config)?;
        let proxy_trusted = parse_proxy_trusted(&config)?;
        Ok(Self {
            config,
            tls_acceptor: Some(TlsAcceptor::from(Arc::new(tls_config))),
            proxy_trusted,
            conn_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Plain TURN over TCP: the same listener with no TLS layer. The
    /// certificate, ALPN, client-CA and TLS policy fields of `config` are
    /// ignored; `max_handshakes_per_sec_per_ip` limits new connections.
    pub fn new_plain(config: TlsTransportConfig) -> Result<Self> {
        let proxy_trusted = parse_proxy_trusted(&config)?;
        Ok(Self {
            config,
            tls_acceptor: None,
            proxy_trusted,
            conn_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    fn label(&self) -> &'static str {
        if self.tls_acceptor.is_some() {
            "TURNS"
        } else {
            "TURN-over-TCP"
        }
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
        let label = self.label();
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(
            addr = %self.config.listen_addr,
            max = self.config.max_connections,
            max_per_ip = self.config.max_connections_per_ip,
            proxy_protocol = self.config.proxy_protocol,
            "{label} listening"
        );
        stats
            .listening
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Certificate hot-reload. `CertReloader` existed but was wired to
        // nothing: the acceptor was built once in `new()`, so a rotated cert
        // (ACME renewal) needed a process restart. Each accepted connection now
        // takes the current `ServerConfig` out of this watch channel, so a
        // reload applies to new connections without touching established ones.
        let cert_rx: Option<tokio::sync::watch::Receiver<Arc<ServerConfig>>> = if self
            .tls_acceptor
            .is_none()
        {
            // Plain TCP: no certificate to reload.
            None
        } else if self.config.cert_reload_interval.is_zero() {
            info!(
                event = "cert_reload_disabled",
                "TURNS certificate hot-reload disabled (cert_reload_interval = 0)"
            );
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
                    error!(event = "cert_reload_unavailable", %e, "TURNS certificate hot-reload unavailable; using static cert");
                    None
                }
            }
        };

        // Per-source-IP handshake RATE limit, shared implementation with the
        // QUIC listeners (`crate::ratelimit`). `max_connections_per_ip` bounds
        // concurrency only: a source that connects and drops in a loop never
        // trips it while still making us pay for a TLS handshake each time.
        let limiter = crate::ratelimit::HandshakeLimiter::new(
            self.config.max_handshakes_per_sec_per_ip,
            self.config.handshake_burst_per_ip,
        );
        if limiter.enabled() {
            info!(
                rate = self.config.max_handshakes_per_sec_per_ip,
                burst = self.config.handshake_burst_per_ip,
                "{label} per-IP handshake rate limit active"
            );
        }
        let adm = Arc::new(Admission {
            config: self.config.clone(),
            limiter,
            per_ip: tokio::sync::RwLock::new(HashMap::new()),
            conns: tokio::sync::RwLock::new(HashMap::new()),
            conn_counter: self.conn_counter.clone(),
            stats: stats.clone(),
            label,
            slots: Arc::new(tokio::sync::Semaphore::new(self.config.max_connections)),
        });

        // Route outbound sends AND detach requests to the owning connection over
        // the same per-connection queue, so a ConnectionBind success is always
        // written before the detach that follows it.
        let adm_route = adm.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    cmd = send_rx.recv() => match cmd {
                        Some(cmd) => {
                            let c = adm_route.conns.read().await;
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
                            let tx = adm_route.conns.read().await.get(&conn_id).cloned();
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

        let mut limiter_sweep = tokio::time::interval(Duration::from_secs(30));
        limiter_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Consecutive accept failures, for the EMFILE backoff below.
        let mut accept_failures: u32 = 0;

        loop {
            if *shutdown.borrow() {
                break;
            }
            let accepted = tokio::select! {
                _ = shutdown.changed() => break,
                _ = limiter_sweep.tick() => {
                    adm.limiter.sweep();
                    continue;
                }
                r = listener.accept() => r,
            };
            let (stream, socket_peer) = match accepted {
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
                        "{label} accept failed; listener staying up"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    continue;
                }
            };

            // Current certificate material: the reloader's latest, else the
            // acceptor built at construction time.
            let tls = match (cert_rx.as_ref(), self.tls_acceptor.as_ref()) {
                (Some(rx), Some(_)) => Some(TlsAcceptor::from(rx.borrow().clone())),
                (_, acceptor) => acceptor.cloned(),
            };
            let conn = ConnCtx {
                event_tx: event_tx.clone(),
                detach_out_tx: detach_out_tx.clone(),
                shutdown: shutdown.clone(),
                tls,
            };

            if !self.config.proxy_protocol {
                // Admission in the accept loop, as it always was: the checks
                // run before the next connection is taken.
                let Some((conn_id, conn_rx)) = adm.admit(socket_peer).await else {
                    continue;
                };
                let adm = adm.clone();
                tokio::spawn(async move {
                    serve_admitted(
                        adm,
                        conn,
                        conn_id,
                        conn_rx,
                        PrefixedStream::new(BytesMut::new(), stream),
                        socket_peer,
                    )
                    .await;
                });
                continue;
            }

            // PROXY protocol. The allowlist is checked on the socket address
            // before a byte is read: an untrusted source never gets to present
            // a header, and never gets served without one either.
            if !self.proxy_trusted.contains(socket_peer.ip()) {
                stats
                    .proxy_rejected
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!(event = "proxy_untrusted_source", peer = %socket_peer, "{label} connection refused: source is not in proxy_protocol_trusted_cidrs");
                continue;
            }
            // Bound the connections still waiting for a header (see
            // `Admission::slots`). Refused here, before a task exists.
            let Ok(slot) = adm.slots.clone().try_acquire_owned() else {
                stats
                    .rejected_over_cap
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!(event = "peer_refused_max_connections", peer = %socket_peer, max = self.config.max_connections, "{label} connection refused: max_connections reached (including connections awaiting a PROXY header)");
                continue;
            };
            // Reading the header waits on the network, so it runs on the
            // connection's own task; admission follows, keyed on the address
            // the header carries.
            let adm = adm.clone();
            let header_timeout = self.config.proxy_header_timeout;
            tokio::spawn(async move {
                // Held until this task ends: on a refused header, on a refused
                // admission, or when the admitted connection closes.
                let _slot = slot;
                let mut stream = stream;
                let read = timeout(
                    header_timeout,
                    crate::proxy_protocol::read_header(&mut stream),
                )
                .await
                .unwrap_or(Err(crate::proxy_protocol::ProxyError::Timeout));
                let (header, rest) = match read {
                    Ok(v) => v,
                    Err(e) => {
                        adm.stats
                            .proxy_rejected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!(event = "proxy_header_rejected", peer = %socket_peer, error = %e, "{} connection refused: bad PROXY header", adm.label);
                        return;
                    }
                };
                let client = header.client_addr(socket_peer);
                tracing::debug!(%socket_peer, %client, "PROXY header accepted");
                let Some((conn_id, conn_rx)) = adm.admit(client).await else {
                    return;
                };
                serve_admitted(
                    adm.clone(),
                    conn,
                    conn_id,
                    conn_rx,
                    PrefixedStream::new(rest, stream),
                    client,
                )
                .await;
            });
        }

        stats
            .listening
            .store(false, std::sync::atomic::Ordering::Relaxed);
        info!(
            event = "listener_draining",
            "{label} listener draining: shutdown signalled, no new connections"
        );
        Ok(())
    }
}

fn parse_proxy_trusted(cfg: &TlsTransportConfig) -> Result<crate::proxy_protocol::TrustedSources> {
    let t = crate::proxy_protocol::TrustedSources::parse(&cfg.proxy_trusted_cidrs)?;
    // Same rule as config validation, restated at the layer that enforces it:
    // an empty allowlist would refuse every connection.
    if cfg.proxy_protocol && t.is_empty() {
        return Err(TlsError::ProxyConfig);
    }
    Ok(t)
}

/// What every connection task needs from the listener, bundled so the PROXY
/// path and the direct path hand over the same thing.
struct ConnCtx {
    event_tx: mpsc::Sender<TcpTransportEvent>,
    detach_out_tx: mpsc::Sender<DetachedConn>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// `None` on the plain TCP listener.
    tls: Option<TlsAcceptor>,
}

/// Serve one admitted connection to completion, then release its slot and
/// report the close. `peer` is the client address — the PROXY header's source
/// when there was one — and is what the relay sees for this connection.
async fn serve_admitted(
    adm: Arc<Admission>,
    conn: ConnCtx,
    conn_id: TcpConnectionId,
    conn_rx: mpsc::Receiver<ConnCtl>,
    stream: PrefixedStream<TcpStream>,
    peer: SocketAddr,
) {
    let etx = conn.event_tx.clone();
    let outcome = handle_conn(
        conn_id,
        stream,
        peer,
        conn.tls,
        &adm.config,
        etx.clone(),
        conn_rx,
        conn.detach_out_tx,
        adm.stats.clone(),
        conn.shutdown,
    )
    .await;
    adm.release(conn_id, peer).await;
    adm.stats
        .closed
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
    stream: PrefixedStream<TcpStream>,
    peer: SocketAddr,
    tls: Option<TlsAcceptor>,
    cfg: &TlsTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    ctl_rx: mpsc::Receiver<ConnCtl>,
    detach_out_tx: mpsc::Sender<DetachedConn>,
    stats: Arc<TlsStats>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<HandleOutcome> {
    use std::sync::atomic::Ordering::Relaxed;

    let Some(tls) = tls else {
        // Plain TURN over TCP: the byte stream is the framed TURN stream.
        return serve_framed(
            id,
            stream,
            peer,
            cfg,
            etx,
            ctl_rx,
            detach_out_tx,
            stats,
            shutdown,
        )
        .await;
    };

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
    // RFC 7443 strict mode. rustls already fails the handshake when the client
    // offers ALPN with no overlap, but a client offering NO ALPN is accepted —
    // that is the case this refuses. Checked after the handshake because that is
    // the earliest point the negotiated protocol is known.
    if cfg.alpn_required && tls_stream.get_ref().1.alpn_protocol().is_none() {
        stats.alpn_rejected.fetch_add(1, Relaxed);
        return Err(TlsError::AlpnMissing);
    }
    serve_framed(
        id,
        tls_stream,
        peer,
        cfg,
        etx,
        ctl_rx,
        detach_out_tx,
        stats,
        shutdown,
    )
    .await
}

/// The framed TURN stream of one connection, after any TLS handshake: STUN and
/// ChannelData in, control responses and relayed data out, until close, idle
/// timeout, drain or an RFC 6062 detach.
#[allow(clippy::too_many_arguments)]
async fn serve_framed<S>(
    id: TcpConnectionId,
    stream: S,
    peer: SocketAddr,
    cfg: &TlsTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut ctl_rx: mpsc::Receiver<ConnCtl>,
    detach_out_tx: mpsc::Sender<DetachedConn>,
    stats: Arc<TlsStats>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<HandleOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use std::sync::atomic::Ordering::Relaxed;

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

    let (mut rd, mut wr) = tokio::io::split(stream);
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
                            .send(DetachedConn { connection_id, peer_addr: peer, inner: Box::new(stream), prebuffer })
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
/// Build the client-certificate verifier from a CA bundle.
///
/// `require` selects mandatory vs optional presentation:
/// `allow_unauthenticated()` lets a client with no certificate complete the
/// handshake (it is then only as authenticated as its TURN long-term credentials
/// make it), which is what makes a staged rollout possible on a live fleet.
///
/// **No CRL or OCSP**, deliberately, and for the same reason the management plane
/// does not have them (`docs/MTLS.md` → Revocation): correct revocation means CRL
/// download and caching or OCSP stapling, and it is solved better by the PKI
/// (Vault, cloud CA) than by a bespoke path inside turna. To revoke here, rotate
/// the CA — the procedure in `docs/MTLS.md` applies unchanged.
fn client_cert_verifier(
    ca_path: &Path,
    require: bool,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let cas = load_certs(ca_path)?;
    let mut roots = rustls::RootCertStore::empty();
    for ca in cas {
        roots
            .add(ca)
            .map_err(|e| TlsError::ClientCaInvalid(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(TlsError::ClientCaEmpty(ca_path.into()));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    let builder = if require {
        builder
    } else {
        builder.allow_unauthenticated()
    };
    builder
        .build()
        .map_err(|e| TlsError::ClientCaInvalid(e.to_string()))
}

/// Names of every cipher suite the `ring` provider implements, as rustls
/// spells them. The `[tls] cipher_suites` allowlist is checked against this.
pub fn supported_cipher_suite_names() -> Vec<&'static str> {
    rustls::crypto::ring::ALL_CIPHER_SUITES
        .iter()
        .filter_map(|s| s.suite().as_str())
        .collect()
}

/// Minimum version + cipher allowlist. Carried separately from the rest of the
/// config so the certificate reloader rebuilds with exactly the same policy —
/// the same reason it carries the client verifier.
#[derive(Debug, Clone, Default)]
struct TlsPolicy {
    tls13_only: bool,
    cipher_suites: Vec<String>,
}

impl TlsPolicy {
    fn from_config(cfg: &TlsTransportConfig) -> Self {
        Self {
            tls13_only: cfg.tls13_only,
            cipher_suites: cfg.cipher_suites.clone(),
        }
    }

    /// The `ring` provider narrowed to the allowlist, in the operator's order
    /// (rustls prefers the server's order). Empty allowlist = the provider
    /// unchanged, which is the pre-policy behaviour byte for byte.
    fn provider(&self) -> Result<rustls::crypto::CryptoProvider> {
        let mut provider = rustls::crypto::ring::default_provider();
        if !self.cipher_suites.is_empty() {
            let mut picked = Vec::with_capacity(self.cipher_suites.len());
            for name in &self.cipher_suites {
                let suite = rustls::crypto::ring::ALL_CIPHER_SUITES
                    .iter()
                    .find(|s| s.suite().as_str() == Some(name.as_str()))
                    .ok_or_else(|| TlsError::UnknownCipherSuite(name.clone()))?;
                picked.push(*suite);
            }
            provider.cipher_suites = picked;
        }
        Ok(provider)
    }

    /// An allowlist can be valid by name and still refuse every client: TLS 1.2
    /// suites name their signature algorithm, so a list of only ECDSA suites
    /// with an RSA certificate negotiates nothing. The key type is known here,
    /// at certificate load, not at config validation. Nothing usable at all is
    /// an error (the listener does not start); TLS 1.2 suites that are all
    /// unusable while TLS 1.3 ones remain is a warning, because TLS 1.3
    /// clients are still served. Default (empty) allowlists are not checked:
    /// the provider's full set covers every key type rustls loads.
    fn check_key(
        &self,
        provider: &rustls::crypto::CryptoProvider,
        key: &PrivateKeyDer<'static>,
    ) -> Result<()> {
        if self.cipher_suites.is_empty() {
            return Ok(());
        }
        let alg = provider
            .key_provider
            .load_private_key(key.clone_key())?
            .algorithm();
        let tls13 = provider
            .cipher_suites
            .iter()
            .any(|s| s.version() == &rustls::version::TLS13);
        let tls12: Vec<_> = provider
            .cipher_suites
            .iter()
            .filter(|s| s.version() == &rustls::version::TLS12)
            .collect();
        let tls12_usable =
            !self.tls13_only && tls12.iter().any(|s| s.usable_for_signature_algorithm(alg));
        if !tls13 && !tls12_usable {
            return Err(TlsError::NoSuiteForKey { key: alg });
        }
        if !self.tls13_only && !tls12.is_empty() && !tls12_usable {
            warn!(
                key = ?alg,
                "[tls] cipher_suites: none of the TLS 1.2 suites matches the certificate \
                 key type, so TLS 1.2 clients will be refused; only TLS 1.3 is usable"
            );
        }
        Ok(())
    }

    fn versions(&self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        if self.tls13_only {
            TLS13_ONLY
        } else {
            rustls::DEFAULT_VERSIONS
        }
    }
}

fn ring_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_auth: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    policy: &TlsPolicy,
) -> Result<ServerConfig> {
    let provider = Arc::new(policy.provider()?);
    policy.check_key(&provider, &key)?;
    // `with_protocol_versions` refuses a version set the allowlist leaves with
    // no suite ("no usable cipher suites configured"), so a TLS 1.2-only list
    // with `tls13_only` fails here, at startup.
    let base =
        ServerConfig::builder_with_provider(provider).with_protocol_versions(policy.versions())?;
    let cfg = match client_auth {
        Some(v) => base.with_client_cert_verifier(v),
        None => base.with_no_client_auth(),
    };
    Ok(cfg.with_single_cert(certs, key)?)
}

fn build_tls_config(cfg: &TlsTransportConfig) -> Result<ServerConfig> {
    let certs = load_certs(&cfg.cert_path)?;
    let key = load_key(&cfg.key_path)?;
    let client_auth = if cfg.client_ca_path.is_empty() {
        None
    } else {
        Some(client_cert_verifier(
            Path::new(&cfg.client_ca_path),
            cfg.require_client_cert,
        )?)
    };
    let mut tls = ring_server_config(certs, key, client_auth, &TlsPolicy::from_config(cfg))?;
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
    /// Carried so a server-certificate rotation rebuilds the config *with* the
    /// client verifier. Dropping it here would silently turn mTLS off at the first
    /// reload, which is the worst possible failure mode for this feature.
    client_ca_path: String,
    require_client_cert: bool,
    /// Carried for the same reason: a reload must not quietly widen the
    /// version or cipher policy back to the defaults.
    policy: TlsPolicy,
}

impl CertReloader {
    pub fn new(cfg: &TlsTransportConfig, interval: Duration) -> Self {
        Self {
            cert_path: cfg.cert_path.clone(),
            key_path: cfg.key_path.clone(),
            interval,
            enable_alpn: cfg.enable_alpn,
            client_ca_path: cfg.client_ca_path.clone(),
            require_client_cert: cfg.require_client_cert,
            policy: TlsPolicy::from_config(cfg),
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
                            info!(event = "cert_rotated", "TLS cert reloaded");
                        }
                        Err(e) => {
                            // Keep serving the previous material rather than
                            // dropping TLS because of a half-written PEM.
                            stats.cert_reload_failures.fetch_add(1, Relaxed);
                            error!(event = "cert_rotate_failed", %e, "cert reload failed; keeping previous certificate");
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
        let client_auth = if self.client_ca_path.is_empty() {
            None
        } else {
            Some(client_cert_verifier(
                Path::new(&self.client_ca_path),
                self.require_client_cert,
            )?)
        };
        let mut tls = ring_server_config(certs, key, client_auth, &self.policy)?;
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

    // ── TLS policy ───────────────────────────────────────────────────────────

    /// A self-signed `localhost` certificate in a fresh temp dir.
    fn test_cert(tag: &str) -> (PathBuf, PathBuf, CertificateDer<'static>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "turna-tls-policy-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        (cert, key, ck.cert.der().clone())
    }

    fn server_cfg(tag: &str) -> (TlsTransportConfig, CertificateDer<'static>) {
        let (cert_path, key_path, der) = test_cert(tag);
        (
            TlsTransportConfig {
                cert_path,
                key_path,
                ..Default::default()
            },
            der,
        )
    }

    /// Handshake a client limited to `versions` against `server`, in memory.
    /// Returns the negotiated suite name, or the handshake error.
    async fn handshake(
        server: ServerConfig,
        root: CertificateDer<'static>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> std::result::Result<String, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let (c, s) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let srv = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let res = connector.connect(name, c).await;
        let _ = srv.await;
        match res {
            Ok(stream) => Ok(stream
                .get_ref()
                .1
                .negotiated_cipher_suite()
                .and_then(|s| s.suite().as_str())
                .unwrap_or("?")
                .to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    #[test]
    fn supported_names_cover_both_versions() {
        let names = supported_cipher_suite_names();
        assert!(names.contains(&"TLS13_AES_128_GCM_SHA256"));
        assert!(names.contains(&"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    }

    #[test]
    fn unknown_suite_and_empty_version_set_are_errors() {
        let (mut cfg, _) = server_cfg("unknown");
        cfg.cipher_suites = vec!["TLS_RSA_WITH_RC4_128_MD5".into()];
        assert!(matches!(
            build_tls_config(&cfg),
            Err(TlsError::UnknownCipherSuite(_))
        ));
        // TLS 1.3 only with nothing but a TLS 1.2 suite: refused at
        // construction. The key check sees it first (no TLS 1.3 suite, TLS 1.2
        // off); rustls's own "no usable cipher suites" would follow otherwise.
        cfg.cipher_suites = vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into()];
        cfg.tls13_only = true;
        assert!(matches!(
            build_tls_config(&cfg),
            Err(TlsError::NoSuiteForKey { .. } | TlsError::TlsConfig(_))
        ));
    }

    #[test]
    fn allowlist_unusable_with_the_key_type_is_refused() {
        // rcgen's default key is ECDSA P-256, so RSA-only TLS 1.2 suites
        // cannot be used with it.
        let (mut cfg, _) = server_cfg("keytype");
        cfg.cipher_suites = vec!["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into()];
        assert!(matches!(
            build_tls_config(&cfg),
            Err(TlsError::NoSuiteForKey { .. })
        ));
        // A matching TLS 1.2 suite, or any TLS 1.3 suite alongside, is fine.
        cfg.cipher_suites = vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into()];
        assert!(build_tls_config(&cfg).is_ok());
        cfg.cipher_suites = vec![
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
            "TLS13_AES_128_GCM_SHA256".into(),
        ];
        assert!(build_tls_config(&cfg).is_ok());
    }

    #[tokio::test]
    async fn default_policy_still_accepts_tls12() {
        // The default must stay what it was: TLS 1.2 clients are served.
        let (cfg, root) = server_cfg("default12");
        let got = handshake(
            build_tls_config(&cfg).unwrap(),
            root,
            &[&rustls::version::TLS12],
        )
        .await;
        assert!(got.is_ok(), "{got:?}");
    }

    #[tokio::test]
    async fn tls13_only_refuses_a_tls12_client() {
        let (mut cfg, root) = server_cfg("min13");
        cfg.tls13_only = true;
        let server = build_tls_config(&cfg).unwrap();
        let got = handshake(server.clone(), root.clone(), &[&rustls::version::TLS12]).await;
        assert!(
            got.is_err(),
            "a TLS 1.2-only client must be refused: {got:?}"
        );
        let ok = handshake(server, root, &[&rustls::version::TLS13]).await;
        assert!(ok.unwrap().starts_with("TLS13_"));
    }

    #[tokio::test]
    async fn cipher_allowlist_is_what_gets_negotiated() {
        let (mut cfg, root) = server_cfg("allow");
        cfg.cipher_suites = vec!["TLS13_CHACHA20_POLY1305_SHA256".into()];
        let server = build_tls_config(&cfg).unwrap();
        let got = handshake(server, root, &[&rustls::version::TLS13]).await;
        assert_eq!(got.unwrap(), "TLS13_CHACHA20_POLY1305_SHA256");
    }

    #[tokio::test]
    async fn policy_survives_a_certificate_reload() {
        let (mut cfg, root) = server_cfg("reload");
        cfg.tls13_only = true;
        let reloaded = CertReloader::new(&cfg, Duration::from_secs(1))
            .reload()
            .unwrap();
        let got = handshake(reloaded, root, &[&rustls::version::TLS12]).await;
        assert!(got.is_err(), "reload widened the version policy: {got:?}");
    }

    // ── Plain TCP listener and PROXY protocol ────────────────────────────────

    fn free_tcp_addr() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    struct Running {
        addr: SocketAddr,
        events: mpsc::Receiver<TcpTransportEvent>,
        stats: Arc<TlsStats>,
        _send: mpsc::Sender<TcpSendCommand>,
        _detach: mpsc::Sender<DetachRequest>,
        _shutdown: tokio::sync::watch::Sender<bool>,
    }

    async fn start_plain(cfg: TlsTransportConfig) -> Running {
        let addr = cfg.listen_addr;
        start(TlsTransportServer::new_plain(cfg).unwrap(), addr).await
    }

    async fn start(server: TlsTransportServer, addr: SocketAddr) -> Running {
        let (etx, events) = mpsc::channel(64);
        let (send_tx, send_rx) = mpsc::channel(64);
        let (dtx, drx) = mpsc::channel(1);
        let (otx, _orx) = mpsc::channel(1);
        let stats = Arc::new(TlsStats::default());
        let (sd_tx, sd_rx) = tokio::sync::watch::channel(false);
        let st = stats.clone();
        tokio::spawn(async move {
            let _ = server.run_full(etx, send_rx, drx, otx, st, sd_rx).await;
        });
        // Wait for the bind.
        for _ in 0..100 {
            if stats.listening.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Running {
            addr,
            events,
            stats,
            _send: send_tx,
            _detach: dtx,
            _shutdown: sd_tx,
        }
    }

    /// First PacketReceived's peer address, skipping ConnectionOpened.
    async fn first_packet_peer(events: &mut mpsc::Receiver<TcpTransportEvent>) -> SocketAddr {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("event within 5 s")
                .expect("channel open")
            {
                TcpTransportEvent::PacketReceived {
                    peer_addr, data, ..
                } => {
                    assert_eq!(data.len(), 20, "one bare STUN header");
                    return peer_addr;
                }
                TcpTransportEvent::ConnectionOpened { .. } => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// The peer closed (or reset) the connection within five seconds.
    async fn assert_closed(c: &mut TcpStream) {
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut b))
            .await
            .expect("closed promptly");
        assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
    }

    #[tokio::test]
    async fn plain_listener_frames_without_tls() {
        let mut r = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            ..Default::default()
        })
        .await;
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        c.write_all(&stun_msg(&[])).await.unwrap();
        let peer = first_packet_peer(&mut r.events).await;
        assert_eq!(peer, c.local_addr().unwrap());
    }

    #[tokio::test]
    async fn proxy_header_sets_the_client_address() {
        let mut r = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            proxy_protocol: true,
            proxy_trusted_cidrs: vec!["127.0.0.0/8".into()],
            ..Default::default()
        })
        .await;
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        // Header and the first STUN message in one write, as a balancer that
        // forwards the client's first segment immediately would send them.
        let mut wire = b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 3478\r\n".to_vec();
        wire.extend_from_slice(&stun_msg(&[]));
        c.write_all(&wire).await.unwrap();
        let peer = first_packet_peer(&mut r.events).await;
        assert_eq!(peer, "203.0.113.7:51000".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn proxy_listener_refuses_untrusted_and_headerless() {
        use std::sync::atomic::Ordering::Relaxed;
        let mut r = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            proxy_protocol: true,
            proxy_trusted_cidrs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        })
        .await;
        // Untrusted source: closed before anything is read, header or not.
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        let _ = c
            .write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 3478\r\n")
            .await;
        assert_closed(&mut c).await;
        assert_eq!(r.stats.proxy_rejected.load(Relaxed), 1);

        // Trusted source that sends no header: also refused.
        let mut r2 = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            proxy_protocol: true,
            proxy_trusted_cidrs: vec!["127.0.0.1/32".into()],
            ..Default::default()
        })
        .await;
        let mut c = TcpStream::connect(r2.addr).await.unwrap();
        c.write_all(&stun_msg(&[])).await.unwrap();
        assert_closed(&mut c).await;
        assert_eq!(r2.stats.proxy_rejected.load(Relaxed), 1);
        assert_eq!(r2.stats.accepted.load(Relaxed), 0);
        assert!(r.events.try_recv().is_err() && r2.events.try_recv().is_err());
    }

    #[tokio::test]
    async fn proxy_header_timeout_is_enforced() {
        use std::sync::atomic::Ordering::Relaxed;
        let r = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            proxy_protocol: true,
            proxy_trusted_cidrs: vec!["127.0.0.1/32".into()],
            proxy_header_timeout: Duration::from_millis(200),
            ..Default::default()
        })
        .await;
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        c.write_all(b"PROXY TCP4 1.2").await.unwrap();
        assert_closed(&mut c).await;
        assert_eq!(r.stats.proxy_rejected.load(Relaxed), 1);
    }

    /// TURNS behind a balancer: the PROXY header, then the TLS handshake on
    /// the same stream. The bytes after the header must reach rustls intact.
    #[tokio::test]
    async fn proxy_header_then_tls_handshake() {
        let (mut cfg, root) = server_cfg("proxy-tls");
        cfg.listen_addr = free_tcp_addr();
        cfg.proxy_protocol = true;
        cfg.proxy_trusted_cidrs = vec!["127.0.0.0/8".into()];
        cfg.cert_reload_interval = Duration::ZERO;
        let addr = cfg.listen_addr;
        let mut r = start(TlsTransportServer::new(cfg).unwrap(), addr).await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        // v2 this time: TCP over IPv4, 198.51.100.4:6000 -> 10.0.0.1:5349.
        let mut hdr = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x0C, 198, 51, 100, 4, 10, 0, 0, 1,
        ];
        hdr.extend_from_slice(&6000u16.to_be_bytes());
        hdr.extend_from_slice(&5349u16.to_be_bytes());
        tcp.write_all(&hdr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(name, tcp)
            .await
            .expect("TLS handshake after the PROXY header");
        tls.write_all(&stun_msg(&[])).await.unwrap();
        tls.flush().await.unwrap();
        let peer = first_packet_peer(&mut r.events).await;
        assert_eq!(peer, "198.51.100.4:6000".parse::<SocketAddr>().unwrap());
    }

    /// `admit` is atomic: fifty concurrent admissions against a cap of three
    /// admit exactly three. With the old read-check / separate-insert shape
    /// they could all pass the check before any of them inserted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_admit_never_exceeds_max_connections() {
        let stats = Arc::new(TlsStats::default());
        let adm = Arc::new(Admission {
            config: TlsTransportConfig {
                max_connections: 3,
                max_connections_per_ip: 0,
                ..Default::default()
            },
            limiter: crate::ratelimit::HandshakeLimiter::new(0, 0),
            per_ip: tokio::sync::RwLock::new(HashMap::new()),
            conns: tokio::sync::RwLock::new(HashMap::new()),
            conn_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            stats: stats.clone(),
            label: "test",
            slots: Arc::new(tokio::sync::Semaphore::new(3)),
        });
        let barrier = Arc::new(tokio::sync::Barrier::new(50));
        let mut tasks = Vec::new();
        for i in 0..50u16 {
            let adm = adm.clone();
            let b = barrier.clone();
            tasks.push(tokio::spawn(async move {
                b.wait().await;
                let peer = SocketAddr::from(([198, 51, 100, (i % 250) as u8], 1000 + i));
                adm.admit(peer).await.map(|(id, rx)| (id, rx, peer))
            }));
        }
        let mut admitted = Vec::new();
        for t in tasks {
            if let Some(a) = t.await.unwrap() {
                admitted.push(a);
            }
        }
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(admitted.len(), 3);
        assert_eq!(adm.conns.read().await.len(), 3);
        assert_eq!(stats.accepted.load(Relaxed), 3);
        assert_eq!(stats.rejected_over_cap.load(Relaxed), 47);
        // Releasing one frees exactly one slot.
        let (id, _rx, peer) = admitted.pop().unwrap();
        adm.release(id, peer).await;
        assert!(adm.admit("203.0.113.9:1".parse().unwrap()).await.is_some());
        assert!(adm.admit("203.0.113.9:2".parse().unwrap()).await.is_none());
    }

    /// Connections still waiting for their PROXY header count against
    /// `max_connections`: a trusted source that opens many and sends nothing
    /// has the excess refused at once instead of holding a task and a
    /// descriptor each for the header timeout.
    #[tokio::test]
    async fn pending_proxy_headers_are_bounded_by_max_connections() {
        use std::sync::atomic::Ordering::Relaxed;
        let r = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            proxy_protocol: true,
            proxy_trusted_cidrs: vec!["127.0.0.1/32".into()],
            proxy_header_timeout: Duration::from_secs(60),
            max_connections: 2,
            max_connections_per_ip: 0,
            ..Default::default()
        })
        .await;
        let mut silent = Vec::new();
        for _ in 0..2 {
            silent.push(TcpStream::connect(r.addr).await.unwrap());
        }
        // Give the accept loop time to take both permits.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = std::time::Instant::now();
        let mut extra = TcpStream::connect(r.addr).await.unwrap();
        assert_closed(&mut extra).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the over-cap connection waited for the header timeout"
        );
        assert_eq!(r.stats.rejected_over_cap.load(Relaxed), 1);
        // A slot frees up when a pending connection goes away.
        drop(silent.pop());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        let mut wire = b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 3478\r\n".to_vec();
        wire.extend_from_slice(&stun_msg(&[]));
        c.write_all(&wire).await.unwrap();
        let mut r = r;
        let peer = first_packet_peer(&mut r.events).await;
        assert_eq!(peer, "203.0.113.7:51000".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn proxy_without_trusted_sources_is_refused_at_construction() {
        let cfg = TlsTransportConfig {
            proxy_protocol: true,
            ..Default::default()
        };
        assert!(matches!(
            TlsTransportServer::new_plain(cfg),
            Err(TlsError::ProxyConfig)
        ));
    }

    #[tokio::test]
    async fn per_ip_cap_applies_to_the_proxied_address() {
        use std::sync::atomic::Ordering::Relaxed;
        let mut r = start_plain(TlsTransportConfig {
            listen_addr: free_tcp_addr(),
            proxy_protocol: true,
            proxy_trusted_cidrs: vec!["127.0.0.1/32".into()],
            max_connections_per_ip: 1,
            ..Default::default()
        })
        .await;
        // Two clients behind the same balancer address: different proxied
        // sources, both admitted even though the socket peer is the same.
        let mut held = Vec::new();
        for src in ["203.0.113.1", "203.0.113.2"] {
            let mut c = TcpStream::connect(r.addr).await.unwrap();
            let mut wire = format!("PROXY TCP4 {src} 10.0.0.1 4000 3478\r\n").into_bytes();
            wire.extend_from_slice(&stun_msg(&[]));
            c.write_all(&wire).await.unwrap();
            let _ = first_packet_peer(&mut r.events).await;
            held.push(c);
        }
        // A second connection from an already-present proxied source hits
        // the per-IP cap of 1.
        let mut c = TcpStream::connect(r.addr).await.unwrap();
        c.write_all(b"PROXY TCP4 203.0.113.1 10.0.0.1 4001 3478\r\n")
            .await
            .unwrap();
        assert_closed(&mut c).await;
        assert_eq!(r.stats.rejected_per_ip.load(Relaxed), 1);
        assert_eq!(r.stats.accepted.load(Relaxed), 2);
    }
}
