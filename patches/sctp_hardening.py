#!/usr/bin/env python3
"""
Pass 1 of the SCTP work: bring the transport up to the same operational footing
as TURNS, so `production = true` can stop refusing it for a reason other than
"nobody looked at it".

What this adds, all patterned on crates/transport/src/tcp_tls.rs:

  * SctpStats / SctpStatsSnapshot            — there were no counters at all
  * max_connections_per_ip                   — one source could hold every slot
  * per-IP association rate limit             — concurrency caps do not stop a
                                                connect/drop loop
  * accept-error resilience with backoff      — see below, this was a real bug
  * cooperative drain via a shutdown channel  — run() looped forever
  * a `listening` flag for readiness          — nothing could tell if it was up
  * send-drop counter                         — `let _ = try_send` lost writes
                                                silently

The accept-error fix is not cosmetic. The loop did:

    Ok(Err(e)) => return Err(SctpError::Io(e))

so one EMFILE or ECONNABORTED returned from run() and took the whole SCTP
listener down until the process restarted. tcp_tls had the identical bug and
already fixed it; the comment there explains it in the same words. Fixing it
here is the single most valuable line in this patch.

Run from the repository root. Idempotent: refuses to apply twice.
"""

import sys
import pathlib

SCTP = pathlib.Path("crates/transport/src/sctp.rs")


def die(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        die(f"{label}: found {n} occurrences, expected exactly 1")
    print(f"  ok  {label}")
    return text.replace(old, new)


if not SCTP.exists():
    die(f"{SCTP} not found — run from the repository root")

s = SCTP.read_text()

if "pub struct SctpStats" in s:
    die("already applied (SctpStats exists)")

# ---------------------------------------------------------------------------
# 1. Imports the new code needs.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;""",
    """use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;""",
    "imports",
)

# ---------------------------------------------------------------------------
# 2. Config: the two limits that were missing.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """    pub max_connections: usize,
    /// listen(2) backlog for the SCTP one-to-one listener.
    pub backlog: i32,
}""",
    """    pub max_connections: usize,
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
}""",
    "config fields",
)

s = replace_once(
    s,
    """            max_connections: 10_000,
            backlog: 1024,""",
    """            max_connections: 10_000,
            // Both default to off, matching TURNS: a limit that surprises an
            // operator on upgrade is worse than one they had to opt into.
            max_connections_per_ip: 0,
            max_associations_per_sec_per_ip: 0,
            association_burst_per_ip: 0,
            backlog: 1024,""",
    "config defaults",
)

# ---------------------------------------------------------------------------
# 3. Stats. Deliberately not a copy of TlsStats: no handshake, certificate or
#    ALPN counters, because this transport has none of those. Inventing them
#    would leave four series permanently at zero and an operator wondering
#    which of them means something.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub struct SctpTransportServer {""",
    """// ---------------------------------------------------------------------------
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

pub struct SctpTransportServer {""",
    "stats structs",
)

# ---------------------------------------------------------------------------
# 4. run(): keep the old signature working, add the hardened variant.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """    pub async fn run(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        mut send_rx: mpsc::Receiver<TcpSendCommand>,
    ) -> Result<()> {
        let listener = self.bind_listener()?;""",
    """    /// Kept for compatibility: no shutdown signal, no counters. Runs until the
    /// listener itself fails.
    pub async fn run(
        self,
        event_tx: mpsc::Sender<TcpTransportEvent>,
        send_rx: mpsc::Receiver<TcpSendCommand>,
    ) -> Result<()> {
        let (_never_tx, never_shutdown) = tokio::sync::watch::channel(false);
        self.run_with_shutdown(event_tx, send_rx, Arc::new(SctpStats::default()), never_shutdown)
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
        stats.listening.store(true, Relaxed);""",
    "run signature",
)

# ---------------------------------------------------------------------------
# 5. The writer task: count drops instead of discarding them.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """        let conns_send = conns.clone();
        tokio::spawn(async move {
            while let Some(cmd) = send_rx.recv().await {
                let c = conns_send.read().await;
                if let Some(tx) = c.get(&cmd.conn_id) {
                    let _ = tx.try_send(cmd.data);
                }
            }
        });""",
    """        let conns_send = conns.clone();
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
        });""",
    "writer task",
)

# ---------------------------------------------------------------------------
# 6. The accept loop. This is the substance of the patch.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """        loop {
            // Async accept over the raw fd. `try_io` returning Err clears readiness
            // and we loop to await the next readable edge.
            let (stream, sockaddr) = {
                let mut guard = listener.readable().await?;
                match guard.try_io(|inner| inner.get_ref().accept()) {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(e)) => return Err(SctpError::Io(e)),
                    Err(_would_block) => continue,
                }
            };
            let peer: SocketAddr = match sockaddr.as_socket() {
                Some(a) => a,
                None => {
                    warn!("SCTP accept: non-IP peer address; dropping");
                    continue;
                }
            };

            {
                let c = conns.read().await;
                if c.len() >= self.config.max_connections {
                    warn!(%peer, "SCTP connection limit reached");
                    continue;
                }
            }

            let conn_id = TcpConnectionId::next(&self.conn_counter);
            let (conn_tx, conn_rx) = mpsc::channel::<Vec<u8>>(256);
            conns.write().await.insert(conn_id, conn_tx);

            let etx = event_tx.clone();
            let cfg = self.config.clone();
            let conns2 = conns.clone();

            tokio::spawn(async move {
                let reason =
                    match handle_conn(conn_id, stream, peer, &cfg, etx.clone(), conn_rx).await {
                        Ok(()) => "clean close".to_string(),
                        Err(e) => format!("{e}"),
                    };
                conns2.write().await.remove(&conn_id);
                let _ = etx
                    .send(TcpTransportEvent::ConnectionClosed {
                        conn_id,
                        peer_addr: peer,
                        reason,
                    })
                    .await;
            });
        }
    }
}""",
    """        // Per-source-IP association count, decremented when a task ends.
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
                let outcome =
                    handle_conn(conn_id, stream, peer, &cfg, etx.clone(), conn_rx, &conn_stats)
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
}""",
    "accept loop",
)

# ---------------------------------------------------------------------------
# 7. handle_conn takes stats: byte counters and the idle-timeout counter.
# ---------------------------------------------------------------------------
s = replace_once(
    s,
    """async fn handle_conn(
    id: TcpConnectionId,
    stream: Socket,
    peer: SocketAddr,
    cfg: &SctpTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut send_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {""",
    """async fn handle_conn(
    id: TcpConnectionId,
    stream: Socket,
    peer: SocketAddr,
    cfg: &SctpTransportConfig,
    etx: mpsc::Sender<TcpTransportEvent>,
    mut send_rx: mpsc::Receiver<Vec<u8>>,
    stats: &SctpStats,
) -> Result<()> {""",
    "handle_conn signature",
)

s = replace_once(
    s,
    """                    Ok(Err(e)) => return Err(SctpError::Io(e)),
                    Err(_) => return Ok(()), // idle timeout""",
    """                    Ok(Err(e)) => return Err(SctpError::Io(e)),
                    Err(_) => {
                        // Idle timeout. Counted rather than silent: a deployment
                        // closing associations it thinks are alive should be able
                        // to see it without reading logs.
                        stats.idle_timeouts.fetch_add(1, Relaxed);
                        return Ok(());
                    }""",
    "idle timeout counter",
)

s = replace_once(
    s,
    """                    Ok(Ok(_)) => {
                        while let Some(frame) = codec.decode(&mut buf)? {""",
    """                    Ok(Ok(n)) => {
                        stats.bytes_rx.fetch_add(n as u64, Relaxed);
                        while let Some(frame) = codec.decode(&mut buf)? {""",
    "bytes_rx",
)

s = replace_once(
    s,
    """                let mut out = BytesMut::with_capacity(data.len());
                codec.encode(&data, &mut out)?;
                send_all(&afd, &out).await?;""",
    """                let mut out = BytesMut::with_capacity(data.len());
                codec.encode(&data, &mut out)?;
                send_all(&afd, &out).await?;
                stats.bytes_tx.fetch_add(out.len() as u64, Relaxed);""",
    "bytes_tx",
)

SCTP.write_text(s)

print()
print("applied. Next:")
print()
print("  cargo clippy -p turna-transport --features sctp --all-targets -- -D warnings")
print()
print("Two things this patch does NOT do, deliberately:")
print("  * the bridge does not mirror SctpStats into Prometheus yet — the counters")
print("    exist but nothing scrapes them, so that is the next edit")
print("  * run_with_shutdown is not wired in services/node, so nothing passes a")
print("    shutdown channel or the stats Arc yet")
