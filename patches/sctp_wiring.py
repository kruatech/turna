#!/usr/bin/env python3
"""
Pass 2 of the SCTP work: make the counters from pass 1 reachable.

Pass 1 added `SctpStats` inside the transport crate, which nothing scraped and
nothing passed a shutdown channel to. This wires the whole path:

  config      three new keys, so the limits can actually be set from TOML
  health      thirteen `turna_sctp_*` series plus a readiness gauge
  bridge      creates the stats, mirrors them on a ticker, forwards shutdown
  node        passes the shutdown receiver through

Deliberately mirroring how TURNS does each of these rather than inventing a
second convention: the metric names follow `turna_tls_*`, the readiness gauge
follows `set_tls_readiness`, and the mirroring ticker follows the TURNS bridge.

The metric render in crates/health is one large `format!` with positional
arguments — the comment on `TlsStatsSnapshot` warns about exactly this. Both
insertions are anchored on the last TLS entry so nothing existing shifts.

Run from the repository root. Idempotent.
"""

import sys
import pathlib


def die(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def patch(path: str, edits: list[tuple[str, str, str]]) -> None:
    p = pathlib.Path(path)
    if not p.exists():
        die(f"{path} not found — run from the repository root")
    s = p.read_text()
    for label, old, new in edits:
        n = s.count(old)
        if n != 1:
            die(f"{path} / {label}: found {n} occurrences, expected exactly 1")
        s = s.replace(old, new)
        print(f"  ok  {path.split('/')[-1]}: {label}")
    p.write_text(s)


# ---------------------------------------------------------------------------
# 1. Config: the keys pass 1 introduced in SctpTransportConfig.
# ---------------------------------------------------------------------------
cfg = pathlib.Path("crates/config/src/lib.rs")
if "max_associations_per_sec_per_ip" in cfg.read_text():
    die("already applied (config key exists)")

patch(
    "crates/config/src/lib.rs",
    [
        (
            "SctpSection fields",
            """    /// Max concurrent SCTP connections.
    pub max_connections: usize,
    /// listen(2) backlog.
    pub backlog: i32,
}""",
            """    /// Max concurrent SCTP connections.
    pub max_connections: usize,
    /// Per-source-IP association cap. 0 = unlimited.
    ///
    /// Without it one source can hold every one of `max_connections` — the gap
    /// the DTLS and TURNS listeners already closed.
    pub max_connections_per_ip: usize,
    /// Per-source-IP association rate limit, associations/second. 0 = unlimited.
    ///
    /// `max_connections_per_ip` bounds concurrency only: a source that
    /// associates and drops in a loop never trips it.
    pub max_associations_per_sec_per_ip: u32,
    /// Burst allowance for the rate limit. 0 = twice the rate.
    pub association_burst_per_ip: u32,
    /// listen(2) backlog.
    pub backlog: i32,
}""",
        ),
        (
            "SctpSection defaults",
            """            listen: "0.0.0.0:3478".parse().unwrap(),
            max_frame_size: 64 * 1024,
            read_timeout_secs: 300,
            max_connections: 10_000,""",
            """            listen: "0.0.0.0:3478".parse().unwrap(),
            max_frame_size: 64 * 1024,
            read_timeout_secs: 300,
            max_connections: 10_000,
            // Off by default, matching TURNS: a limit that surprises an operator
            // on upgrade is worse than one they had to opt into.
            max_connections_per_ip: 0,
            max_associations_per_sec_per_ip: 0,
            association_burst_per_ip: 0,""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. Health: fields, readiness, render, args.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "readiness field",
            """    pub tls_readiness: AtomicU8,""",
            """    pub tls_readiness: AtomicU8,
    pub sctp_readiness: AtomicU8,""",
        ),
        (
            "readiness init",
            """            tls_readiness: AtomicU8::new(Readiness::Starting as u8),""",
            """            tls_readiness: AtomicU8::new(Readiness::Starting as u8),
            sctp_readiness: AtomicU8::new(Readiness::Starting as u8),""",
        ),
        (
            "readiness setter",
            """    pub fn set_tls_readiness(&self, r: Readiness) {
        self.tls_readiness.store(r as u8, Ordering::SeqCst);""",
            """    pub fn set_sctp_readiness(&self, r: Readiness) {
        self.sctp_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_tls_readiness(&self, r: Readiness) {
        self.tls_readiness.store(r as u8, Ordering::SeqCst);""",
        ),
        (
            "counter fields",
            """    pub tls_rejected_rate_limit: AtomicU64,
    pub tls_alpn_rejected: AtomicU64,""",
            """    pub tls_rejected_rate_limit: AtomicU64,
    pub tls_alpn_rejected: AtomicU64,

    // TURN-over-SCTP. Mirrored from `turna_transport::sctp::SctpStats` by the
    // SCTP bridge; all zero when the listener is disabled or not built.
    //
    // No handshake, certificate or ALPN counters here, unlike TURNS: this
    // transport has none of those, and a series that can only ever read zero
    // costs an operator more than an absent one.
    pub sctp_active: AtomicU64,
    pub sctp_conns_total: AtomicU64,
    pub sctp_closed_total: AtomicU64,
    pub sctp_rejected_over_cap: AtomicU64,
    pub sctp_rejected_per_ip: AtomicU64,
    pub sctp_rejected_rate_limit: AtomicU64,
    pub sctp_idle_timeouts: AtomicU64,
    pub sctp_framing_errors: AtomicU64,
    pub sctp_accept_errors: AtomicU64,
    pub sctp_send_dropped: AtomicU64,
    pub sctp_bytes_rx: AtomicU64,
    pub sctp_bytes_tx: AtomicU64,""",
        ),
        (
            "render block",
            """             turna_tls_alpn_rejected_total {}\\n\\""",
            """             turna_tls_alpn_rejected_total {}\\n\\
             # HELP turna_sctp_active_associations Active TURN-over-SCTP associations\\n\\
             # TYPE turna_sctp_active_associations gauge\\n\\
             turna_sctp_active_associations {}\\n\\
             # HELP turna_sctp_associations_total TURN-over-SCTP associations accepted since start\\n\\
             # TYPE turna_sctp_associations_total counter\\n\\
             turna_sctp_associations_total {}\\n\\
             # HELP turna_sctp_closed_total TURN-over-SCTP associations closed since start\\n\\
             # TYPE turna_sctp_closed_total counter\\n\\
             turna_sctp_closed_total {}\\n\\
             # HELP turna_sctp_rejected_over_cap_total SCTP associations refused at the max_connections cap\\n\\
             # TYPE turna_sctp_rejected_over_cap_total counter\\n\\
             turna_sctp_rejected_over_cap_total {}\\n\\
             # HELP turna_sctp_rejected_per_ip_total SCTP associations refused at max_connections_per_ip\\n\\
             # TYPE turna_sctp_rejected_per_ip_total counter\\n\\
             turna_sctp_rejected_per_ip_total {}\\n\\
             # HELP turna_sctp_rejected_rate_limit_total SCTP associations refused by the per-IP rate limiter\\n\\
             # TYPE turna_sctp_rejected_rate_limit_total counter\\n\\
             turna_sctp_rejected_rate_limit_total {}\\n\\
             # HELP turna_sctp_idle_timeouts_total SCTP associations closed by the idle read timeout\\n\\
             # TYPE turna_sctp_idle_timeouts_total counter\\n\\
             turna_sctp_idle_timeouts_total {}\\n\\
             # HELP turna_sctp_framing_errors_total SCTP associations closed on invalid or over-sized TURN-over-stream framing\\n\\
             # TYPE turna_sctp_framing_errors_total counter\\n\\
             turna_sctp_framing_errors_total {}\\n\\
             # HELP turna_sctp_accept_errors_total SCTP accept() errors survived without stopping the listener\\n\\
             # TYPE turna_sctp_accept_errors_total counter\\n\\
             turna_sctp_accept_errors_total {}\\n\\
             # HELP turna_sctp_send_dropped_total Outbound SCTP frames dropped because the per-association channel was full or gone\\n\\
             # TYPE turna_sctp_send_dropped_total counter\\n\\
             turna_sctp_send_dropped_total {}\\n\\
             # HELP turna_sctp_bytes_rx_total Bytes read from TURN-over-SCTP clients\\n\\
             # TYPE turna_sctp_bytes_rx_total counter\\n\\
             turna_sctp_bytes_rx_total {}\\n\\
             # HELP turna_sctp_bytes_tx_total Bytes written to TURN-over-SCTP clients\\n\\
             # TYPE turna_sctp_bytes_tx_total counter\\n\\
             turna_sctp_bytes_tx_total {}\\n\\""",
        ),
        (
            "readiness render",
            """             turna_tls_readiness {}\\n\\""",
            """             turna_tls_readiness {}\\n\\
             # HELP turna_sctp_readiness TURN-over-SCTP listener readiness (0=starting,1=ready,2=degraded,3=draining; starting if SCTP disabled)\\n\\
             # TYPE turna_sctp_readiness gauge\\n\\
             turna_sctp_readiness {}\\n\\""",
        ),
        (
            "readiness arg",
            """            self.tls_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,""",
            """            self.tls_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.sctp_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,""",
        ),
        (
            "counter args",
            """            l(&self.tls_rejected_rate_limit),
            l(&self.tls_alpn_rejected),""",
            """            l(&self.tls_rejected_rate_limit),
            l(&self.tls_alpn_rejected),
            l(&self.sctp_active),
            l(&self.sctp_conns_total),
            l(&self.sctp_closed_total),
            l(&self.sctp_rejected_over_cap),
            l(&self.sctp_rejected_per_ip),
            l(&self.sctp_rejected_rate_limit),
            l(&self.sctp_idle_timeouts),
            l(&self.sctp_framing_errors),
            l(&self.sctp_accept_errors),
            l(&self.sctp_send_dropped),
            l(&self.sctp_bytes_rx),
            l(&self.sctp_bytes_tx),""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 3. Bridge: create the stats, mirror them, forward shutdown.
# ---------------------------------------------------------------------------
patch(
    "crates/relay/src/sctp_bridge.rs",
    [
        (
            "bridge signature",
            """pub(crate) async fn run_sctp_bridge(
    cfg: SctpTransportConfig,
    processor: Arc<PacketProcessor>,
    relay_tx: mpsc::Sender<OutMsg>,
    client_sinks: ClientSinks,
) -> BridgeResult {
    let server = SctpTransportServer::new(cfg)?;

    let (event_tx, mut event_rx) = mpsc::channel::<TcpTransportEvent>(8192);
    let (sctp_send_tx, sctp_send_rx) = mpsc::channel::<TcpSendCommand>(8192);

    tokio::spawn(async move {
        if let Err(e) = server.run(event_tx, sctp_send_rx).await {
            error!(error = %e, "TURN-over-SCTP server stopped");
        }
    });""",
            """#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_sctp_bridge(
    cfg: SctpTransportConfig,
    processor: Arc<PacketProcessor>,
    relay_tx: mpsc::Sender<OutMsg>,
    client_sinks: ClientSinks,
    metrics: Arc<turna_health::Metrics>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> BridgeResult {
    let server = SctpTransportServer::new(cfg)?;

    let (event_tx, mut event_rx) = mpsc::channel::<TcpTransportEvent>(8192);
    let (sctp_send_tx, sctp_send_rx) = mpsc::channel::<TcpSendCommand>(8192);

    let stats = Arc::new(turna_transport::sctp::SctpStats::default());

    // Mirror the transport's counters into Prometheus on a ticker, the same way
    // the TURNS bridge does. Without this the counters exist and nothing scrapes
    // them, which is the state pass 1 left behind.
    {
        let stats = stats.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering::Relaxed;
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let s = stats.snapshot();
                metrics.sctp_active.store(s.active as u64, Relaxed);
                metrics.sctp_conns_total.store(s.accepted, Relaxed);
                metrics.sctp_closed_total.store(s.closed, Relaxed);
                metrics
                    .sctp_rejected_over_cap
                    .store(s.rejected_over_cap, Relaxed);
                metrics.sctp_rejected_per_ip.store(s.rejected_per_ip, Relaxed);
                metrics
                    .sctp_rejected_rate_limit
                    .store(s.rejected_rate_limit, Relaxed);
                metrics.sctp_idle_timeouts.store(s.idle_timeouts, Relaxed);
                metrics.sctp_framing_errors.store(s.framing_errors, Relaxed);
                metrics.sctp_accept_errors.store(s.accept_errors, Relaxed);
                metrics.sctp_send_dropped.store(s.send_dropped, Relaxed);
                metrics.sctp_bytes_rx.store(s.bytes_rx, Relaxed);
                metrics.sctp_bytes_tx.store(s.bytes_tx, Relaxed);
                // Readiness follows the listener's own flag rather than a
                // separate belief about it: `listening` is set after bind and
                // cleared on drain, so a listener that stopped accepting cannot
                // keep reporting Ready.
                metrics.set_sctp_readiness(if s.listening {
                    turna_health::Readiness::Ready
                } else {
                    turna_health::Readiness::Draining
                });
            }
        });
    }

    {
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = server
                .run_with_shutdown(event_tx, sctp_send_rx, stats, shutdown)
                .await
            {
                error!(error = %e, "TURN-over-SCTP server stopped");
            }
        });
    }""",
        ),
    ],
)

print()
print("applied. Next:")
print()
print("  cargo clippy -p turna-transport -p turna-relay -p turna-health \\")
print("    --features sctp --all-targets -- -D warnings")
print()
print("Then the call site in services/node/src/main.rs needs the two new")
print("arguments (metrics, shutdown). It is behind `#[cfg(feature = \"sctp\")]`")
print("via `server.with_sctp(...)`, so find where that reaches the bridge:")
print()
print("  grep -n 'run_sctp_bridge' -B 4 -A 6 crates/relay/src/server.rs")
print()
print("And docs/OBSERVABILITY.md must list the thirteen new series, or")
print("check-doc-claims.sh fails — it asserts every exported metric is")
print("documented.")
