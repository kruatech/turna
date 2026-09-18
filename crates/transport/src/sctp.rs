//! TURN-over-SCTP transport server (client CONTROL transport).
//!
//! SCOPE / HONESTY: no TURN RFC defines SCTP as a *relayed* transport. This is a
//! client↔server **control** transport only — STUN/TURN messages carried over an
//! SCTP association, framed with the exact same self-delimiting codec as
//! TURN-over-TCP ([`crate::tcp_tls::TcpFrameCodec`]). The relay socket to the peer
//! stays UDP (handled by the relay bridge/egress, not here).
//!
//! DESIGN: uses **one-to-one SCTP** (`SOCK_STREAM` + `IPPROTO_SCTP`), whose
//! `listen`/`accept`/`recv`/`send` semantics mirror TCP — so this module is a
//! faithful structural mirror of [`crate::tcp_tls`], minus the TLS layer (the SCTP
//! control channel here is plaintext; TLS-over-SCTP / DTLS is out of scope).
//!
//! It reuses the transport-agnostic types from `tcp_tls`
//! ([`TcpConnectionId`], [`TcpTransportEvent`], [`TcpSendCommand`],
//! [`TcpFrameCodec`]), so the relay-side `sctp_bridge` needs no new event types.
//! Therefore `feature = "sctp"` must also enable `feature = "tls"` (for those
//! shared types) — see Cargo notes in the delivery.
//!
//! REQUIREMENTS: Linux with the `sctp` kernel module (lksctp) loaded; the
//! `socket2` crate. Non-Linux targets have no SCTP here.
//!
//! Uses independently polled reads and bounded writes. SCTP has no TCP-style
//! half-close (RFC 6458 section 4.1.7); clients await replies before shutdown.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{info, instrument, warn};

use crate::tcp_tls::{TcpConnectionId, TcpFrameCodec, TcpSendCommand, TcpTransportEvent, TlsError};

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// IANA protocol number for SCTP (RFC 4960). socket2 may also expose
/// `Protocol::SCTP` on some versions; the numeric form is used to avoid a
/// version dependency.
const IPPROTO_SCTP: i32 = 132;

#[derive(Debug, Error)]
pub enum SctpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Framing errors bubble up from the shared TURN-over-stream codec.
    #[error("framing: {0}")]
    Framing(#[from] TlsError),
    #[error("connection closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, SctpError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SctpTransportConfig {
    pub listen_addr: SocketAddr,
    pub max_frame_size: usize,
    pub read_timeout: Duration,
    pub max_connections: usize,
    /// Per-source-IP association cap. 0 = unlimited.
    ///
    /// Without it a single source can hold every one of `max_connections`, which
    /// is the same gap the DTLS and TURNS listeners closed (DTL-9).
    pub max_connections_per_ip: usize,
    /// Per-source-IP association **rate** limit (associations/second).
    /// 0 = unlimited.
    ///
    /// Complements `max_connections_per_ip`, which bounds concurrency only: a
    /// source that associates and drops in a loop never trips a concurrency cap
    /// while still making the server pay for association setup each time.
    pub max_associations_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate.
    pub association_burst_per_ip: u32,
    /// listen(2) backlog for the SCTP one-to-one listener.
    pub backlog: i32,
}

impl Default for SctpTransportConfig {
    fn default() -> Self {
        Self {
            // No standardized TURN-over-SCTP port; operator-configured. 3478 is the
            // STUN/TURN default and is reused here for familiarity only.
            listen_addr: "0.0.0.0:3478".parse().unwrap(),
            max_frame_size: 64 * 1024,
            read_timeout: Duration::from_secs(300),
            max_connections: 10_000,
            // Both default to off, matching TURNS: a limit that surprises an
            // operator on upgrade is worse than one they had to opt into.
            max_connections_per_ip: 0,
            max_associations_per_sec_per_ip: 0,
            association_burst_per_ip: 0,
            backlog: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Counters for the SCTP listener, mirrored into Prometheus by the bridge.
///
/// This transport shipped with none, so there was no way to alert on refused
/// associations, framing errors or a listener that had stopped accepting — the
/// socket stayed bound and the process stayed healthy either way. The fields
/// mirror `TlsStats` where the concept carries over and stop where it does not:
/// there is no handshake, no certificate and no ALPN here, and a counter that
/// can only ever read zero is worse than an absent one.
#[derive(Default)]
pub struct SctpStats {
    /// Associations currently established.
    pub active: AtomicUsize,
    /// Associations accepted since start.
    pub accepted: AtomicU64,
    /// Associations closed for any reason.
    pub closed: AtomicU64,
    /// Refused because `max_connections` was reached.
    pub rejected_over_cap: AtomicU64,
    /// Refused because the source IP hit `max_connections_per_ip`.
    pub rejected_per_ip: AtomicU64,
    /// Refused by the per-IP association rate limiter.
    pub rejected_rate_limit: AtomicU64,
    /// Closed by the per-association idle read timeout.
    pub idle_timeouts: AtomicU64,
    /// Closed because the peer sent invalid TURN-over-stream framing or an
    /// over-sized frame.
    pub framing_errors: AtomicU64,
    /// `accept()` errors that did NOT stop the listener (EMFILE, ECONNABORTED).
    pub accept_errors: AtomicU64,
    /// Outbound frames dropped because the per-association channel was full or
    /// gone. Previously discarded with `let _`, so a client could lose relayed
    /// data with nothing recording it.
    pub send_dropped: AtomicU64,
    /// Bytes read from clients.
    pub bytes_rx: AtomicU64,
    /// Bytes written to clients.
    pub bytes_tx: AtomicU64,
    /// True once the listener is bound; cleared on drain or exit.
    pub listening: AtomicBool,
}

/// Point-in-time copy of [`SctpStats`] (named struct so adding a counter cannot
/// shift a positional mirror).
#[derive(Debug, Clone, Copy, Default)]
pub struct SctpStatsSnapshot {
    pub active: usize,
    pub accepted: u64,
    pub closed: u64,
    pub rejected_over_cap: u64,
    pub rejected_per_ip: u64,
    pub rejected_rate_limit: u64,
    pub idle_timeouts: u64,
    pub framing_errors: u64,
    pub accept_errors: u64,
    pub send_dropped: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub listening: bool,
}

impl SctpStats {
    pub fn snapshot(&self) -> SctpStatsSnapshot {
        SctpStatsSnapshot {
            active: self.active.load(Relaxed),
            accepted: self.accepted.load(Relaxed),
            closed: self.closed.load(Relaxed),
            rejected_over_cap: self.rejected_over_cap.load(Relaxed),
            rejected_per_ip: self.rejected_per_ip.load(Relaxed),
            rejected_rate_limit: self.rejected_rate_limit.load(Relaxed),
            idle_timeouts: self.idle_timeouts.load(Relaxed),
            framing_errors: self.framing_errors.load(Relaxed),
            accept_errors: self.accept_errors.load(Relaxed),
            send_dropped: self.send_dropped.load(Relaxed),
            bytes_rx: self.bytes_rx.load(Relaxed),
            bytes_tx: self.bytes_tx.load(Relaxed),
            listening: self.listening.load(Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub struct SctpTransportServer {
    config: SctpTransportConfig,
    conn_counter: Arc<AtomicU64>,
}

impl SctpTransportServer {
    pub fn new(config: SctpTransportConfig) -> Result<Self> {
        Ok(Self {
            config,
            conn_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Bind the SCTP one-to-one listener. Mirrors `TcpListener::bind` but built
    /// from a raw `socket2` socket with `IPPROTO_SCTP`.
    fn bind_listener(&self) -> Result<AsyncFd<Socket>> {
        let domain = if self.config.listen_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        // Native SCTP one-to-one socket.
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            // Linux accepted SCTP sockets inherit this setting from the listener.
            // Avoid Nagle/delayed-SACK latency for small control and media frames.
            let enabled: libc::c_int = 1;
            // SAFETY: live SCTP socket, valid integer pointer and matching length.
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    IPPROTO_SCTP,
                    libc::SCTP_NODELAY,
                    &enabled as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // This wire profile carries one ordered TURN byte stream. Negotiate
            // one SCTP stream so records from different streams cannot interleave.
            let init = libc::sctp_initmsg {
                sinit_num_ostreams: 1,
                sinit_max_instreams: 1,
                sinit_max_attempts: 0,
                sinit_max_init_timeo: 0,
            };
            // SAFETY: valid socket and correctly sized Linux SCTP_INITMSG value.
            let rc = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    IPPROTO_SCTP,
                    libc::SCTP_INITMSG,
                    &init as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&init) as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind(&SockAddr::from(self.config.listen_addr))?;
        sock.listen(self.config.backlog)?;
        Ok(AsyncFd::new(sock)?)
    }

    /// Kept for compatibility: no shutdown signal, no counters. Runs until the
    /// listener itself fails.
    pub async fn run(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        send_rx: mpsc::Receiver<TcpSendCommand>,
    ) -> Result<()> {
        let (_never_tx, never_shutdown) = tokio::sync::watch::channel(false);
        self.run_with_shutdown(
            event_tx,
            send_rx,
            Arc::new(SctpStats::default()),
            never_shutdown,
        )
        .await
    }

    /// Serve with counters and a cooperative drain.
    ///
    /// `shutdown` flipping true stops accepting and returns; established
    /// associations are left to their own tasks, matching how TURNS drains. The
    /// `listening` flag is cleared on the way out so readiness stops reporting a
    /// listener that is no longer taking work.
    pub async fn run_with_shutdown(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        mut send_rx: mpsc::Receiver<TcpSendCommand>,
        stats: Arc<SctpStats>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(SctpError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native SCTP requires Linux kernel SCTP support",
            )));
        }
        let listener = self.bind_listener()?;
        stats.listening.store(true, Relaxed);
        info!(
            addr = %self.config.listen_addr,
            max = self.config.max_connections,
            "TURN-over-SCTP listening"
        );

        // conn_id -> per-connection writer channel (same pattern as tcp_tls).
        let conns: Arc<tokio::sync::RwLock<HashMap<TcpConnectionId, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        let conns_send = conns.clone();
        let send_stats = stats.clone();
        tokio::spawn(async move {
            while let Some(cmd) = send_rx.recv().await {
                let mut c = conns_send.write().await;
                // Empty data is the bridge's explicit close command; it is not
                // a valid TURN message and is never written on the wire.
                if cmd.data.is_empty() {
                    c.remove(&cmd.conn_id);
                    continue;
                }
                match c.get(&cmd.conn_id) {
                    // `try_send` rather than `send` on purpose: a blocked writer
                    // must not stall the shared command loop for every other
                    // association. But the failure is now counted — it was
                    // discarded with `let _`, so a full channel meant a client
                    // silently lost relayed data with nothing to show for it.
                    Some(tx) => {
                        if tx.try_send(cmd.data).is_err() {
                            send_stats.send_dropped.fetch_add(1, Relaxed);
                            // A dropped control reply/FIN cannot be recovered by
                            // continuing this byte stream. Close only this association.
                            c.remove(&cmd.conn_id);
                        }
                    }
                    None => {
                        send_stats.send_dropped.fetch_add(1, Relaxed);
                    }
                }
            }
        });

        // Per-source-IP association count, decremented when a task ends.
        let per_ip: Arc<tokio::sync::RwLock<HashMap<IpAddr, u32>>> =
            Arc::new(tokio::sync::RwLock::new(HashMap::new()));

        // Shared implementation with the TURNS and QUIC listeners.
        let limiter = crate::ratelimit::HandshakeLimiter::new(
            self.config.max_associations_per_sec_per_ip,
            self.config.association_burst_per_ip,
        );
        if limiter.enabled() {
            info!(
                rate = self.config.max_associations_per_sec_per_ip,
                burst = self.config.association_burst_per_ip,
                "TURN-over-SCTP per-IP association rate limit active"
            );
        }
        let mut limiter_sweep = tokio::time::interval(Duration::from_secs(30));
        limiter_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Consecutive accept failures, for the backoff below.
        let mut accept_failures: u32 = 0;

        loop {
            if *shutdown.borrow() {
                break;
            }

            // Async accept over the raw fd. `try_io` returning WouldBlock clears
            // readiness and we loop to await the next readable edge.
            let accepted = tokio::select! {
                _ = shutdown.changed() => break,
                _ = limiter_sweep.tick() => {
                    limiter.sweep();
                    continue;
                }
                readable = listener.readable() => {
                    match readable {
                        Ok(mut guard) => match guard.try_io(|inner| inner.get_ref().accept()) {
                            Ok(r) => Some(r),
                            Err(_would_block) => continue,
                        },
                        Err(e) => Some(Err(e)),
                    }
                }
            };

            let (stream, sockaddr) = match accepted {
                Some(Ok(pair)) => {
                    accept_failures = 0;
                    pair
                }
                Some(Err(e)) => {
                    // Previously `return Err(SctpError::Io(e))`, which killed the
                    // whole SCTP listener on the first transient error: a single
                    // EMFILE (fd exhaustion) or ECONNABORTED took the transport
                    // down until the process restarted, with the socket still
                    // bound and the process still healthy. tcp_tls had the
                    // identical bug and fixed it the same way. Log, count, back
                    // off on repeats, keep listening.
                    stats.accept_errors.fetch_add(1, Relaxed);
                    accept_failures = accept_failures.saturating_add(1);
                    let backoff = std::cmp::min(1000, 10u64 * u64::from(accept_failures));
                    warn!(
                        %e,
                        consecutive = accept_failures,
                        backoff_ms = backoff,
                        "SCTP accept failed; listener staying up"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    continue;
                }
                None => break,
            };

            let peer: SocketAddr = match sockaddr.as_socket() {
                Some(a) => a,
                None => {
                    warn!("SCTP accept: non-IP peer address; dropping");
                    continue;
                }
            };

            // Refused before any per-association work is done, so a flood costs
            // a map lookup.
            if !limiter.allow(peer.ip()) {
                stats.rejected_rate_limit.fetch_add(1, Relaxed);
                warn!(event = "peer_refused_rate_limit", %peer, "SCTP association refused: per-IP rate limit");
                continue;
            }

            {
                let c = conns.read().await;
                if self.config.max_connections != 0 && c.len() >= self.config.max_connections {
                    stats.rejected_over_cap.fetch_add(1, Relaxed);
                    warn!(event = "peer_refused_max_connections", %peer, max = self.config.max_connections, "SCTP connection limit reached");
                    continue;
                }
            }

            // Per-source-IP cap: without it one source can hold every slot.
            let max_per_ip = self.config.max_connections_per_ip;
            {
                let ip = peer.ip();
                let mut m = per_ip.write().await;
                if max_per_ip != 0 && *m.get(&ip).unwrap_or(&0) as usize >= max_per_ip {
                    drop(m);
                    stats.rejected_per_ip.fetch_add(1, Relaxed);
                    warn!(event = "peer_refused_per_ip_cap", %peer, max_per_ip, "SCTP association refused: per-IP cap reached");
                    continue;
                }
                *m.entry(ip).or_insert(0) += 1;
            }

            let conn_id = TcpConnectionId::next(&self.conn_counter);
            let (conn_tx, conn_rx) = mpsc::channel::<Vec<u8>>(256);
            conns.write().await.insert(conn_id, conn_tx);
            stats.accepted.fetch_add(1, Relaxed);
            stats.active.fetch_add(1, Relaxed);

            let etx = event_tx.clone();
            let cfg = self.config.clone();
            let conns2 = conns.clone();
            let per_ip2 = per_ip.clone();
            let conn_stats = stats.clone();

            tokio::spawn(async move {
                let outcome = handle_conn(
                    conn_id,
                    stream,
                    peer,
                    &cfg,
                    etx.clone(),
                    conn_rx,
                    &conn_stats,
                )
                .await;
                let reason = match outcome {
                    Ok(()) => "clean close".to_string(),
                    Err(e) => {
                        // Framing errors are the peer's fault and worth their own
                        // counter: they distinguish a malformed or hostile client
                        // from an ordinary disconnect.
                        if matches!(e, SctpError::Framing(_)) {
                            conn_stats.framing_errors.fetch_add(1, Relaxed);
                        }
                        format!("{e}")
                    }
                };
                conns2.write().await.remove(&conn_id);
                conn_stats.active.fetch_sub(1, Relaxed);
                conn_stats.closed.fetch_add(1, Relaxed);
                {
                    let mut m = per_ip2.write().await;
                    if let Some(n) = m.get_mut(&peer.ip()) {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            m.remove(&peer.ip());
                        }
                    }
                }
                let _ = etx
                    .send(TcpTransportEvent::ConnectionClosed {
                        conn_id,
                        peer_addr: peer,
                        reason,
                    })
                    .await;
            });
        }

        conns.write().await.clear();
        stats.listening.store(false, Relaxed);
        info!(
            event = "listener_draining",
            "TURN-over-SCTP listener draining: shutdown signalled, no new associations"
        );
        Ok(())
    }
}

/// Async recv one chunk into `buf`. Returns bytes read (0 = peer closed).
async fn recv_chunk(afd: &AsyncFd<Socket>, buf: &mut BytesMut) -> std::io::Result<usize> {
    loop {
        let mut guard = afd.readable().await?;
        let mut tmp: [MaybeUninit<u8>; 65536] = [MaybeUninit::uninit(); 65536];
        match guard.try_io(|inner| inner.get_ref().recv(&mut tmp)) {
            Ok(Ok(0)) => return Ok(0),
            Ok(Ok(n)) => {
                // SAFETY: `recv` reported `n` initialized bytes at the front.
                let filled = unsafe { std::slice::from_raw_parts(tmp.as_ptr() as *const u8, n) };
                buf.extend_from_slice(filled);
                return Ok(n);
            }
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

/// Async write all of `data` (already framed) to the SCTP association.
async fn send_all(afd: &AsyncFd<Socket>, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send(data)) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "SCTP send returned 0",
                ))
            }
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

#[instrument(skip_all, fields(conn = %id, peer = %peer))]
async fn handle_conn(
    id: TcpConnectionId,
    stream: Socket,
    peer: SocketAddr,
    cfg: &SctpTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut send_rx: mpsc::Receiver<Vec<u8>>,
    stats: &SctpStats,
) -> Result<()> {
    stream.set_nonblocking(true)?;
    let afd = AsyncFd::new(stream)?;

    let _ = etx
        .send(TcpTransportEvent::ConnectionOpened {
            conn_id: id,
            peer_addr: peer,
        })
        .await;

    let codec = TcpFrameCodec::new(cfg.max_frame_size);
    let mut buf = BytesMut::with_capacity(8192);

    let reader = async {
        loop {
            match timeout(cfg.read_timeout, recv_chunk(&afd, &mut buf)).await {
                Ok(Ok(0)) => {
                    if !buf.is_empty() {
                        return Err(SctpError::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "truncated SCTP TURN frame",
                        )));
                    }
                    return Ok(());
                }
                Ok(Ok(n)) => {
                    stats.bytes_rx.fetch_add(n as u64, Relaxed);
                    while let Some(frame) = codec.decode(&mut buf)? {
                        etx.send(TcpTransportEvent::PacketReceived {
                            conn_id: id,
                            peer_addr: peer,
                            data: frame,
                        })
                        .await
                        .map_err(|_| SctpError::Closed)?;
                    }
                }
                Ok(Err(e)) => return Err(SctpError::Io(e)),
                Err(_) => {
                    stats.idle_timeouts.fetch_add(1, Relaxed);
                    return Err(SctpError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "SCTP read idle timeout",
                    )));
                }
            }
        }
    };
    let writer = async {
        while let Some(data) = send_rx.recv().await {
            let mut out = BytesMut::with_capacity(data.len() + 3);
            codec.encode(&data, &mut out)?;
            timeout(WRITE_TIMEOUT, send_all(&afd, &out))
                .await
                .map_err(|_| {
                    SctpError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "SCTP write timeout",
                    ))
                })??;
            stats.bytes_tx.fetch_add(out.len() as u64, Relaxed);
        }
        Ok::<(), SctpError>(())
    };
    tokio::pin!(reader, writer);
    tokio::select! {
        // SCTP shutdown closes the association, not a TCP-style half-close.
        result = &mut reader => result,
        result = &mut writer => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Exercise the socket IO/framing machinery without requiring the SCTP kernel
    // module in unit-test containers. Native SCTP is checked by sctp-check.
    async fn pair() -> (tokio::net::TcpStream, Socket, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let (server, peer) = server.unwrap();
        (
            client.unwrap(),
            Socket::from(server.into_std().unwrap()),
            peer,
        )
    }
    fn request() -> Vec<u8> {
        let mut b = vec![0; 20];
        b[1] = 1;
        b[4..8].copy_from_slice(&0x2112a442u32.to_be_bytes());
        b
    }
    #[tokio::test]
    async fn fragmented_frames_and_padded_reply() {
        let (mut client, socket, peer) = pair().await;
        let (events, mut rx) = mpsc::channel(8);
        let (commands, send_rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            handle_conn(
                TcpConnectionId::next(&AtomicU64::new(0)),
                socket,
                peer,
                &SctpTransportConfig::default(),
                events,
                send_rx,
                &SctpStats::default(),
            )
            .await
        });
        assert!(matches!(
            rx.recv().await,
            Some(TcpTransportEvent::ConnectionOpened { .. })
        ));
        let req = request();
        client.write_all(&req[..9]).await.unwrap();
        assert!(timeout(Duration::from_millis(20), rx.recv()).await.is_err());
        client.write_all(&req[9..]).await.unwrap();
        match timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            TcpTransportEvent::PacketReceived { data, .. } => assert_eq!(&data[..], &req),
            other => panic!("unexpected event {other:?}"),
        }
        commands.send(vec![0x40, 0, 0, 1, 7]).await.unwrap();
        let mut reply = [0; 8];
        timeout(Duration::from_secs(1), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, [0x40, 0, 0, 1, 7, 0, 0, 0]);
        drop(client);
        assert!(task.await.unwrap().is_ok());
    }
    #[tokio::test]
    async fn outgoing_traffic_does_not_reset_read_idle_timeout() {
        let (_client, socket, peer) = pair().await;
        let (events, _rx) = mpsc::channel(8);
        let (commands, send_rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            let cfg = SctpTransportConfig {
                read_timeout: Duration::from_millis(80),
                ..Default::default()
            };
            let stats = SctpStats::default();
            let _ = handle_conn(
                TcpConnectionId::next(&AtomicU64::new(0)),
                socket,
                peer,
                &cfg,
                events,
                send_rx,
                &stats,
            )
            .await;
            stats.idle_timeouts.load(Relaxed)
        });
        for _ in 0..3 {
            commands.send(request()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            timeout(Duration::from_millis(80), task)
                .await
                .unwrap()
                .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn malformed_frame_closes_only_its_connection() {
        let (mut client, socket, peer) = pair().await;
        let (events, _rx) = mpsc::channel(8);
        let (_commands, send_rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            handle_conn(
                TcpConnectionId::next(&AtomicU64::new(0)),
                socket,
                peer,
                &SctpTransportConfig::default(),
                events,
                send_rx,
                &SctpStats::default(),
            )
            .await
        });
        client.write_all(&[0xff, 0, 0, 0]).await.unwrap();
        assert!(matches!(
            timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap(),
            Err(SctpError::Framing(_))
        ));
    }
}
