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
//! Several socket-level specifics are marked `// VERIFY (on-repo):` — this is the
//! highest-uncertainty module written without a compiler; expect to iterate.

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

/// IANA protocol number for SCTP (RFC 4960). socket2 may also expose
/// `Protocol::SCTP` on some versions; the numeric form is used to avoid a
/// version dependency. VERIFY (on-repo): `Protocol::from(IPPROTO_SCTP)` compiles
/// with the pinned socket2; if not, use `Protocol::SCTP`.
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
        // VERIFY (on-repo): SCTP one-to-one is SOCK_STREAM + IPPROTO_SCTP.
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::from(IPPROTO_SCTP)))?;
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
                let c = conns_send.read().await;
                match c.get(&cmd.conn_id) {
                    // `try_send` rather than `send` on purpose: a blocked writer
                    // must not stall the shared command loop for every other
                    // association. But the failure is now counted — it was
                    // discarded with `let _`, so a full channel meant a client
                    // silently lost relayed data with nothing to show for it.
                    Some(tx) => {
                        if tx.try_send(cmd.data).is_err() {
                            send_stats.send_dropped.fetch_add(1, Relaxed);
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
                warn!(%peer, "SCTP association refused: per-IP rate limit");
                continue;
            }

            {
                let c = conns.read().await;
                if c.len() >= self.config.max_connections {
                    stats.rejected_over_cap.fetch_add(1, Relaxed);
                    warn!(%peer, max = self.config.max_connections, "SCTP connection limit reached");
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
                    warn!(%peer, max_per_ip, "SCTP association refused: per-IP cap reached");
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

        stats.listening.store(false, Relaxed);
        info!("TURN-over-SCTP listener draining: shutdown signalled, no new associations");
        Ok(())
    }
}

/// Async recv one chunk into `buf`. Returns bytes read (0 = peer closed).
async fn recv_chunk(afd: &AsyncFd<Socket>, buf: &mut BytesMut) -> std::io::Result<usize> {
    loop {
        let mut guard = afd.readable().await?;
        // VERIFY (on-repo): socket2 `recv` takes `&mut [MaybeUninit<u8>]`.
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

    loop {
        tokio::select! {
            res = timeout(cfg.read_timeout, recv_chunk(&afd, &mut buf)) => {
                match res {
                    Ok(Ok(0)) => return Ok(()),
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
                        // Idle timeout. Counted rather than silent: a deployment
                        // closing associations it thinks are alive should be able
                        // to see it without reading logs.
                        stats.idle_timeouts.fetch_add(1, Relaxed);
                        return Ok(());
                    }
                }
            }
            Some(data) = send_rx.recv() => {
                let mut out = BytesMut::with_capacity(data.len());
                codec.encode(&data, &mut out)?;
                send_all(&afd, &out).await?;
                stats.bytes_tx.fetch_add(out.len() as u64, Relaxed);
            }
            else => break,
        }
    }
    Ok(())
}
