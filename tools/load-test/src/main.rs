//! turna-bench — TURN server load testing
//!
//!   turna-bench --server 10.0.0.1:3478 binding -c 100 -d 60
//!   turna-bench --server 10.0.0.1:3478 --json binding -c 100 -d 60   # machine-readable
//!
//! The `--json` switch emits a single line of JSON to stdout once the
//! run completes (the progress reporter on stderr is unchanged). This
//! is what `bench/run.sh` consumes when comparing turna to coturn.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use tokio::net::UdpSocket;
use tokio::sync::Barrier;

mod turn_client;
// Framing and the test certificate verifier, shared by the stream transports.
// Gated together with them: the TCP relay client used to keep the framer alive
// without any feature, then moved under `tls` itself, leaving the module dead in a
// featureless build.
// Two independent pieces live here with different users: the certificate verifier
// (tls, quic, dtls) and the stream framer (tls, quic, web-transport). The module gate
// is the union; each piece carries its own inside.
#[cfg(any(
    feature = "tls",
    feature = "quic",
    feature = "dtls",
    feature = "web-transport"
))]
mod stream_common;
// RFC 6062 runs over TURNS, so this needs the TLS stack like the others.
#[cfg(feature = "dtls")]
mod dtls_client;
#[cfg(feature = "quic")]
mod quic_client;
#[cfg(feature = "tls")]
mod tcp_relay_client;
#[cfg(feature = "tls")]
mod tls_client;
#[cfg(feature = "web-transport")]
mod wt_client;
use turn_client::{Creds, FAMILY_V4, FAMILY_V6};

const STUN_MAGIC: u32 = 0x2112A442;

#[derive(Parser)]
#[command(name = "turna-bench", about = "TURN load testing")]
struct Cli {
    #[arg(short, long, default_value = "127.0.0.1:3478")]
    server: SocketAddr,
    #[command(subcommand)]
    mode: Mode,
    #[arg(short, long, default_value = "30")]
    duration: u64,
    /// P0 #14: steady-state warmup in seconds. Traffic runs this long first,
    /// then stats are RESET and the reported window is the next `--duration`
    /// seconds only (excludes connection/allocation ramp-up). 0 = disabled.
    #[arg(long, default_value = "0")]
    warmup: u64,
    /// Emit a single JSON object to stdout instead of the human report.
    /// Use for `bench/run.sh` and other automation.
    #[arg(long)]
    json: bool,
    /// Optional label included in the JSON output. Lets `run.sh`
    /// distinguish e.g. "turna-with-bpf" vs "turna-no-bpf" vs "coturn".
    #[arg(long, default_value = "")]
    label: String,
    /// TURN REST shared secret (turna SharedSecret / coturn
    /// use-auth-secret / eturnal secret). Used by `allocate` and
    /// `channeldata`; ignored by `binding`.
    #[arg(long, default_value = "")]
    secret: String,
    /// User id embedded into REST credentials ("<expiry>:<uid>").
    #[arg(long, default_value = "bench")]
    uid: String,
    /// Static long-term username (alternative to --secret).
    #[arg(long, default_value = "")]
    user: String,
    /// Static long-term password (used with --user).
    #[arg(long, default_value = "")]
    pass: String,
    /// Per-request response timeout in milliseconds.
    #[arg(long, default_value = "2000")]
    rtt_timeout_ms: u64,
    /// Local IP to bind every socket on. Default: loopback.
    ///
    /// Needed whenever the server is not on loopback — the AF_XDP lab, for one, puts
    /// the node on `10.123.0.1` across a veth pair, so the client must send from
    /// `10.123.0.2`. `0.0.0.0` is not a substitute: `local_addr()` would return
    /// `0.0.0.0` and that is the address that goes into CreatePermission, where it
    /// means nothing.
    #[arg(long)]
    bind_ip: Option<String>,
}

#[derive(Subcommand, Clone)]
enum Mode {
    Binding {
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
    },
    Allocate {
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
    },
    ChannelData {
        #[arg(short = 'n', long, default_value = "100")]
        channels: usize,
        #[arg(long, default_value = "1000")]
        pps: u64,
        #[arg(long, default_value = "160")]
        payload: usize,
        /// Relayed address family: `v4` (default) or `v6`.
        ///
        /// `v6` sends REQUESTED-ADDRESS-FAMILY = IPv6 on Allocate and binds the peer
        /// socket on `[::1]`, so the whole path — v6 relay socket, v6 peer
        /// permission, v6 channel — is exercised. The server must have
        /// `[turn] external_ip6` set, or the Allocate is refused with 440.
        ///
        /// This is the only way to put load on IPv6 relaying: a browser cannot send
        /// the attribute, and the `conformance` mode only checks the control plane.
        #[arg(long, default_value = "v4")]
        family: String,
    },
    /// TURN over WebTransport (HTTP/3): session, control stream, allocation and
    /// relayed media both ways.
    ///
    /// Requires `--features web-transport` here and `[turn.quic] enabled = true`
    /// with `web_transport = true` on the server.
    ///
    /// Not a substitute for a browser: this client and the server share the
    /// `wtransport` library and one reading of the spec, so a shared misreading
    /// stays invisible. It catches server-side faults ahead of a browser test.
    /// Sustained load over WebTransport. What an endurance run needs — `wt-check` is
    /// one session for a few seconds.
    #[cfg(feature = "web-transport")]
    Wt {
        #[arg(long, default_value = "https://localhost:3479/")]
        url: String,
        #[arg(short = 'c', long, default_value = "20")]
        concurrency: usize,
        #[arg(long, default_value = "25")]
        pps: u64,
        #[arg(long, default_value = "160")]
        payload: usize,
    },
    #[cfg(feature = "web-transport")]
    WtCheck {
        /// Full URL, e.g. `https://localhost:3479/turn`. WebTransport is an HTTP/3
        /// CONNECT, so it needs a URL rather than a host:port.
        #[arg(long, default_value = "https://localhost:3479/")]
        url: String,
    },
    /// Sustained load over DTLS.
    #[cfg(feature = "dtls")]
    Dtls {
        #[arg(short = 'c', long, default_value = "20")]
        concurrency: usize,
        #[arg(long, default_value = "25")]
        pps: u64,
        #[arg(long, default_value = "160")]
        payload: usize,
    },
    /// Sustained load over raw QUIC.
    #[cfg(feature = "quic")]
    Quic {
        #[arg(short = 'c', long, default_value = "20")]
        concurrency: usize,
        #[arg(long, default_value = "25")]
        pps: u64,
        #[arg(long, default_value = "160")]
        payload: usize,
        #[arg(long, default_value = "localhost")]
        server_name: String,
        #[arg(long, default_value = "stun.turn")]
        alpn: String,
    },
    /// TURN over DTLS: handshake, allocation, and relayed media both ways.
    ///
    /// Requires `--features dtls` here and `[turn.dtls] enabled = true` on the
    /// server. Point `--server` at the DTLS port, not 3478.
    ///
    /// Run it against both server paths: `[turn.dtls] demux = false` (the default,
    /// `webrtc_dtls::listen()`) and `demux = true` (the owned demultiplexer). They
    /// accept handshakes differently, so one result does not stand for the other.
    #[cfg(feature = "dtls")]
    DtlsCheck,
    /// RFC 6062 TCP relay: Allocate(TCP) → CreatePermission → Connect →
    /// ConnectionBind, then data in both directions.
    ///
    /// Requires `[turn.tcp_relay] enabled = true` and `production = false` — the
    /// feature is refused in production precisely for want of this evidence.
    #[cfg(feature = "tls")]
    TcpRelayCheck {
        /// SNI presented in the TURNS handshake. RFC 6062 runs over TURNS here —
        /// turna has no plain-TCP TURN listener — so `--server` must be the TURNS
        /// port, not 3478.
        #[arg(long, default_value = "localhost")]
        server_name: String,
        /// Send the first application bytes in the SAME write as ConnectionBind.
        ///
        /// This is the case RFC 6062 §5.4 permits and the one the server's detach
        /// prebuffer exists to handle: a server that stops parsing STUN and starts a
        /// fresh read loses whatever shared the segment. Run it both ways — the
        /// non-pipelined form passing tells you little on its own.
        #[arg(long)]
        pipelined: bool,
    },
    /// TURN over TLS (TURNS): one session end to end, including relayed media in
    /// both directions.
    ///
    /// Requires `--features tls` here and `[tls] enabled = true` on the server.
    /// Point `--server` at the TURNS port (5349 by convention), not 3478.
    #[cfg(feature = "tls")]
    TlsCheck {
        /// SNI presented in the handshake. Any syntactically valid name works — the
        /// certificate is not verified.
        #[arg(long, default_value = "localhost")]
        server_name: String,
        /// ALPN to offer. Empty offers none, which is what tests `alpn_required`.
        #[arg(long, default_value = "stun.turn")]
        alpn: String,
        /// PEM chain to present for client authentication (mTLS).
        ///
        /// Needs a **private** CA: public issuers hand out server certificates only.
        /// The server side is `[tls] client_ca` plus `require_client_cert`. Omit both
        /// flags to test the negative case — with `require_client_cert = true` a
        /// client without a certificate must be refused.
        #[arg(long)]
        client_cert: Option<String>,
        /// Private key for `--client-cert`.
        #[arg(long)]
        client_key: Option<String>,
    },
    /// Sustained load over TURNS. This is the mode a TURNS soak needs: the UDP
    /// modes cannot place any load on the TLS path.
    #[cfg(feature = "tls")]
    Tls {
        #[arg(short = 'c', long, default_value = "100")]
        concurrency: usize,
        /// Pump ChannelData over long-lived sessions instead of churning
        /// allocations. Allocation churn measures the handshake + Allocate cost;
        /// channel-data measures the relay under sustained traffic. Both matter and
        /// they stress different things.
        #[arg(long)]
        channel_data: bool,
        #[arg(long, default_value = "50")]
        pps: u64,
        #[arg(long, default_value = "160")]
        payload: usize,
        #[arg(long, default_value = "localhost")]
        server_name: String,
        #[arg(long, default_value = "stun.turn")]
        alpn: String,
        /// PEM chain to present for client authentication (mTLS); see `tls-check`.
        #[arg(long)]
        client_cert: Option<String>,
        /// Private key for `--client-cert`.
        #[arg(long)]
        client_key: Option<String>,
    },
    /// TURN over raw QUIC: full authenticated Allocate + CreatePermission on a
    /// bidi control stream. Requires `--features quic` on this tool and
    /// `[turn.quic] enabled = true` with `web_transport = false` on the server.
    ///
    /// This is the interop evidence `[turn.quic]` has never had. It accepts any
    /// server certificate — a verification client, not a library.
    #[cfg(feature = "quic")]
    QuicCheck {
        /// SNI presented in the handshake; any value works with a self-signed cert.
        #[arg(long, default_value = "localhost")]
        server_name: String,
        /// Must match `[turn.quic].alpn`.
        #[arg(long, default_value = "stun.turn")]
        alpn: String,
        /// Peer used for the CreatePermission step.
        #[arg(long, default_value = "192.0.2.10:9999")]
        peer: String,
    },
    /// Address-family and peer-filter conformance probes. Seconds, not minutes,
    /// and no browser — this is what can be checked on a dev machine before
    /// committing to a stand.
    ///
    /// It reports what the server actually answered rather than asserting one
    /// expected outcome, because several answers are legitimate: an IPv6 Allocate
    /// is `440` when `[turn] external_ip6` is unset and succeeds when it is set,
    /// and both are correct behaviour for their configuration.
    Conformance {
        /// IPv6 peer for the family-mismatch probe. Must be **globally routable**:
        /// `is_forbidden_peer` is checked before the family test, so a loopback or
        /// link-local address answers 403 and the probe never reaches the 443 it is
        /// looking for. (This defaulted to `[::1]` and produced exactly that
        /// misleading result.) No traffic is sent to it — only a permission is
        /// attempted.
        #[arg(long, default_value = "[2606:4700::1111]:9999")]
        v6_peer: String,
        /// IPv4 peer used for the family-mismatch probe.
        #[arg(long, default_value = "192.0.2.10:9999")]
        v4_peer: String,
    },
}

impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::Binding { .. } => "binding",
            Mode::Allocate { .. } => "allocate",
            Mode::ChannelData { .. } => "channeldata",
            Mode::Conformance { .. } => "conformance",
            #[cfg(feature = "quic")]
            Mode::QuicCheck { .. } => "quic-check",
            #[cfg(feature = "tls")]
            Mode::TcpRelayCheck { .. } => "tcp-relay-check",
            #[cfg(feature = "dtls")]
            Mode::DtlsCheck => "dtls-check",
            #[cfg(feature = "dtls")]
            Mode::Dtls { .. } => "dtls",
            #[cfg(feature = "quic")]
            Mode::Quic { .. } => "quic",
            #[cfg(feature = "web-transport")]
            Mode::WtCheck { .. } => "wt-check",
            #[cfg(feature = "web-transport")]
            Mode::Wt { .. } => "wt",
            #[cfg(feature = "tls")]
            Mode::TlsCheck { .. } => "tls-check",
            #[cfg(feature = "tls")]
            Mode::Tls { .. } => "tls",
        }
    }
}

// ---------------------------------------------------------------------------
// Stats (lock-free)
// ---------------------------------------------------------------------------

struct Stats {
    sent: AtomicU64,
    recv: AtomicU64,
    errs: AtomicU64,
    bytes_out: AtomicU64,
    bytes_in: AtomicU64,
    lat_buckets: [AtomicU64; 10],
    lat_sum: AtomicU64,
    lat_min: AtomicU64,
    lat_max: AtomicU64,
    /// P0 #14: elapsed-ns from `start` when the steady-state measurement
    /// window began (after warmup). 0 = measure from construction.
    measure_start_ns: AtomicU64,
    start: Instant,
    running: AtomicBool,
}

impl Stats {
    fn new() -> Self {
        Self {
            sent: 0.into(),
            recv: 0.into(),
            errs: 0.into(),
            bytes_out: 0.into(),
            bytes_in: 0.into(),
            lat_buckets: Default::default(),
            lat_sum: 0.into(),
            lat_min: AtomicU64::new(u64::MAX),
            measure_start_ns: AtomicU64::new(0),
            lat_max: 0.into(),
            start: Instant::now(),
            running: true.into(),
        }
    }

    fn record_latency(&self, d: Duration) {
        let us = d.as_micros() as u64;
        self.lat_sum.fetch_add(us, Ordering::Relaxed);
        loop {
            let c = self.lat_min.load(Ordering::Relaxed);
            if us >= c
                || self
                    .lat_min
                    .compare_exchange_weak(c, us, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
        }
        loop {
            let c = self.lat_max.load(Ordering::Relaxed);
            if us <= c
                || self
                    .lat_max
                    .compare_exchange_weak(c, us, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
        }
        let b = match us {
            0..=99 => 0,
            100..=499 => 1,
            500..=999 => 2,
            1_000..=4_999 => 3,
            5_000..=9_999 => 4,
            10_000..=49_999 => 5,
            50_000..=99_999 => 6,
            100_000..=499_999 => 7,
            500_000..=999_999 => 8,
            _ => 9,
        };
        self.lat_buckets[b].fetch_add(1, Ordering::Relaxed);
    }

    fn reset(&self) {
        // P0 #14: begin the steady-state window. Discard everything collected
        // during warmup so the report reflects steady state only, not
        // connection setup / allocation handshakes / ramp-up.
        self.sent.store(0, Ordering::Relaxed);
        self.recv.store(0, Ordering::Relaxed);
        self.errs.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.lat_sum.store(0, Ordering::Relaxed);
        self.lat_min.store(u64::MAX, Ordering::Relaxed);
        self.lat_max.store(0, Ordering::Relaxed);
        for b in &self.lat_buckets {
            b.store(0, Ordering::Relaxed);
        }
        self.measure_start_ns
            .store(self.start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Compute approximate percentile from the bucket histogram.
    ///
    /// Resolution is the bucket boundary; for cross-implementation
    /// comparisons (turna vs coturn) this is more than adequate.
    ///
    /// `target` uses `ceil()`, not `as u64` truncation: at low sample
    /// counts (a few hundred), p99 of `1` sample would otherwise give
    /// `target = 0` and the algorithm would return the first bucket
    /// (often empty) — wrong. `ceil()` keeps "p99 of 1 sample" = "the
    /// bucket of that one sample", which is what callers expect.
    fn percentile(&self, p: f64) -> u64 {
        let buckets: Vec<u64> = self
            .lat_buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();
        let total: u64 = buckets.iter().sum();
        if total == 0 {
            return 0;
        }
        let target = ((total as f64) * p).ceil() as u64;
        let target = target.max(1); // guard against p == 0.0
        const BOUNDS: [u64; 10] = [
            100,
            500,
            1000,
            5000,
            10000,
            50000,
            100000,
            500000,
            1000000,
            u64::MAX,
        ];
        let mut cum = 0u64;
        for (i, &c) in buckets.iter().enumerate() {
            cum += c;
            if cum >= target {
                return BOUNDS[i];
            }
        }
        BOUNDS[9]
    }

    fn snapshot(&self, label: &str, mode: &str) -> Snapshot {
        // P0 #14: measure only the steady-state window (total minus warmup).
        let total = self.start.elapsed().as_secs_f64();
        let win_start = self.measure_start_ns.load(Ordering::Relaxed) as f64 / 1e9;
        let el = (total - win_start).max(0.0);
        let sent = self.sent.load(Ordering::Relaxed);
        let recv = self.recv.load(Ordering::Relaxed);
        let errs = self.errs.load(Ordering::Relaxed);
        Snapshot {
            label: label.into(),
            mode: mode.into(),
            duration_s: el,
            sent,
            recv,
            errs,
            // P0 #14: sends that got neither a response nor a counted error.
            // Closed-loop (binding/allocate): ~0 after join = convergence.
            // Open-loop (channeldata): the real relay drop count.
            loss: sent.saturating_sub(recv + errs),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            rps: if el > 0.0 { recv as f64 / el } else { 0.0 },
            lat_min_us: {
                let v = self.lat_min.load(Ordering::Relaxed);
                if v == u64::MAX {
                    0
                } else {
                    v
                }
            },
            lat_max_us: self.lat_max.load(Ordering::Relaxed),
            #[allow(clippy::manual_checked_ops)]
            lat_avg_us: if recv > 0 {
                self.lat_sum.load(Ordering::Relaxed) / recv
            } else {
                0
            },
            lat_p50_us: self.percentile(0.50),
            lat_p95_us: self.percentile(0.95),
            lat_p99_us: self.percentile(0.99),
            lat_buckets: self
                .lat_buckets
                .iter()
                .map(|b| b.load(Ordering::Relaxed))
                .collect(),
        }
    }
}

/// Snapshot of a completed run. Owns its data so we can format it
/// either as a human report or as JSON without touching the live Stats.
#[derive(Debug)]
struct Snapshot {
    label: String,
    mode: String,
    duration_s: f64,
    sent: u64,
    recv: u64,
    errs: u64,
    loss: u64,
    bytes_out: u64,
    bytes_in: u64,
    rps: f64,
    lat_min_us: u64,
    lat_max_us: u64,
    lat_avg_us: u64,
    lat_p50_us: u64,
    lat_p95_us: u64,
    lat_p99_us: u64,
    lat_buckets: Vec<u64>,
}

impl Snapshot {
    /// Human-readable report to stdout.
    fn print_report(&self) {
        println!("═══════════════════════════════════════════");
        println!("  Turna TURN Benchmark Results");
        if !self.label.is_empty() {
            println!("  Label:       {}", self.label);
        }
        println!("  Mode:        {}", self.mode);
        println!("═══════════════════════════════════════════");
        println!("  Duration:    {:.1}s", self.duration_s);
        println!("  Sent:        {}", self.sent);
        println!("  Received:    {}", self.recv);
        let err_pct = if self.sent > 0 {
            self.errs as f64 / self.sent as f64 * 100.0
        } else {
            0.0
        };
        println!("  Errors:      {} ({:.2}%)", self.errs, err_pct);
        let loss_pct = if self.sent > 0 {
            self.loss as f64 / self.sent as f64 * 100.0
        } else {
            0.0
        };
        println!("  Loss:        {} ({:.2}%)", self.loss, loss_pct);
        println!("  RPS:         {:.0}", self.rps);
        println!(
            "  Throughput:  {} out / {} in",
            fmt_bytes(self.bytes_out),
            fmt_bytes(self.bytes_in)
        );
        println!("───────────────────────────────────────────");
        println!("  Latency:");
        println!("    Min:  {} µs", self.lat_min_us);
        println!("    Avg:  {} µs", self.lat_avg_us);
        println!("    P50:  {} µs", self.lat_p50_us);
        println!("    P95:  {} µs", self.lat_p95_us);
        println!("    P99:  {} µs", self.lat_p99_us);
        println!("    Max:  {} µs", self.lat_max_us);
        println!("───────────────────────────────────────────");
        let labels = [
            "<100µs", "<500µs", "<1ms", "<5ms", "<10ms", "<50ms", "<100ms", "<500ms", "<1s", "≥1s",
        ];
        let mx_b = self.lat_buckets.iter().max().copied().unwrap_or(1);
        for (l, &c) in labels.iter().zip(self.lat_buckets.iter()) {
            #[allow(clippy::manual_checked_ops)]
            let bar = "█".repeat(if mx_b > 0 {
                (c * 40 / mx_b) as usize
            } else {
                0
            });
            println!("    {l:>8} │ {c:>8} │ {bar}");
        }
        println!("═══════════════════════════════════════════");
    }

    /// Single-line JSON to stdout. We don't pull in serde just for
    /// this — hand-rolled format is sufficient and avoids a build-time
    /// cost. Field names are stable; treat as machine contract.
    fn print_json(&self) {
        // Helper to format the bucket vector as a JSON array.
        let buckets = self
            .lat_buckets
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\
\"label\":\"{label}\",\
\"mode\":\"{mode}\",\
\"duration_s\":{duration_s:.3},\
\"sent\":{sent},\
\"recv\":{recv},\
\"errs\":{errs},\
\"loss\":{loss},\
\"bytes_out\":{bytes_out},\
\"bytes_in\":{bytes_in},\
\"rps\":{rps:.3},\
\"lat_min_us\":{lat_min},\
\"lat_avg_us\":{lat_avg},\
\"lat_p50_us\":{lat_p50},\
\"lat_p95_us\":{lat_p95},\
\"lat_p99_us\":{lat_p99},\
\"lat_max_us\":{lat_max},\
\"lat_buckets_us\":[100,500,1000,5000,10000,50000,100000,500000,1000000,-1],\
\"lat_bucket_counts\":[{buckets}]\
}}",
            label = json_escape(&self.label),
            mode = self.mode,
            duration_s = self.duration_s,
            sent = self.sent,
            recv = self.recv,
            errs = self.errs,
            loss = self.loss,
            bytes_out = self.bytes_out,
            bytes_in = self.bytes_in,
            rps = self.rps,
            lat_min = self.lat_min_us,
            lat_avg = self.lat_avg_us,
            lat_p50 = self.lat_p50_us,
            lat_p95 = self.lat_p95_us,
            lat_p99 = self.lat_p99_us,
            lat_max = self.lat_max_us,
        );
    }
}

/// Minimal JSON-escape for our label string. Quote, backslash, control
/// chars. We don't accept anything that would need unicode escapes.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.2} GiB", b as f64 / (1 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.2} MiB", b as f64 / (1 << 20) as f64)
    } else if b >= 1024 {
        format!("{:.2} KiB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

fn binding_request() -> [u8; 20] {
    let mut p = [0u8; 20];
    p[0] = 0x00;
    p[1] = 0x01;
    p[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    for b in &mut p[8..20] {
        *b = rand::random();
    }
    p
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async fn run_binding(
    server: SocketAddr,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let stats = stats.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            sock.connect(server).await.unwrap();
            let mut buf = [0u8; 1500];
            barrier.wait().await;
            while stats.is_running() {
                let pkt = binding_request();
                let t = Instant::now();
                if sock.send(&pkt).await.is_ok() {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_out
                        .fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
                        Ok(Ok(n)) => {
                            stats.recv.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                            stats.record_latency(t.elapsed());
                        }
                        _ => {
                            stats.errs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    barrier.wait().await;

    // progress reporter — only when not in --json mode. JSON consumers
    // don't want the carriage-return line on stderr poking through.
    if !json {
        let stats2 = stats.clone();
        tokio::spawn(async move {
            let mut prev = 0u64;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if !stats2.is_running() {
                    break;
                }
                let cur = stats2.recv.load(Ordering::Relaxed);
                eprint!(
                    "\r  [{:>3}s] {:>8} resp | {:>6} rps | {:>4} err",
                    stats2.start.elapsed().as_secs(),
                    cur,
                    cur.saturating_sub(prev),
                    stats2.errs.load(Ordering::Relaxed)
                );
                prev = cur;
            }
            eprintln!();
        });
    }

    // P0 #14: run warmup, then reset to measure only steady state.
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
        stats.reset();
    }
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles {
        let _ = h.await;
    }
    stats
}

/// Closed-loop authenticated Allocate benchmark.
///
/// Each task repeats: full Allocate handshake (401 challenge →
/// MESSAGE-INTEGRITY request) → Refresh(0) to release. `recv` counts
/// successful allocations; latency is the full two-round-trip
/// handshake as a client experiences it.
async fn run_allocate(
    server: SocketAddr,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
    creds: Creds,
    rtt_ms: u64,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let stats = stats.clone();
        let barrier = barrier.clone();
        let creds = creds.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            while stats.is_running() {
                let t = Instant::now();
                stats.sent.fetch_add(1, Ordering::Relaxed);
                match turn_client::allocate(server, &creds, rtt_ms).await {
                    Ok(mut sess) => {
                        stats.recv.fetch_add(1, Ordering::Relaxed);
                        stats.record_latency(t.elapsed());
                        sess.release().await;
                    }
                    Err(_) => {
                        stats.errs.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    barrier.wait().await;
    progress_reporter(&stats, json);
    // P0 #14: run warmup, then reset to measure only steady state.
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
        stats.reset();
    }
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles {
        let _ = h.await;
    }
    stats
}

/// Relay throughput benchmark.
///
/// Per channel: Allocate → CreatePermission → ChannelBind to a local
/// "peer" socket, then pump ChannelData client→relay→peer at `pps`
/// per channel. The peer stamps one-way relay latency from a counter
/// embedded in the payload (same host ⇒ same clock). `recv`/`bytes_in`
/// are what actually came out of the relay, so loss% = 1 - recv/sent.
#[allow(clippy::too_many_arguments)]
async fn run_channeldata(
    server: SocketAddr,
    channels: usize,
    pps: u64,
    payload: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
    creds: Creds,
    rtt_ms: u64,
    v6: bool,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(channels + 1));
    let payload = payload.max(16); // room for seq + timestamp
    let epoch = Arc::new(Instant::now());
    let mut handles = Vec::new();

    for i in 0..channels {
        let stats = stats.clone();
        let barrier = barrier.clone();
        let creds = creds.clone();
        let epoch = epoch.clone();
        handles.push(tokio::spawn(async move {
            // Local peer socket: the relay's other side. It must match the
            // relayed family — RFC 6156 §4.2 refuses a cross-family peer with 443,
            // so a v4 peer on a v6 allocation would fail at CreatePermission.
            let bind_addr = turn_client::peer_bind_addr(v6);
            let peer = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(_) => {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    barrier.wait().await;
                    return;
                }
            };
            let peer_addr = peer.local_addr().unwrap();

            let family = if v6 {
                Some(turn_client::FAMILY_V6)
            } else {
                None
            };
            let mut sess = match turn_client::allocate_family(server, &creds, rtt_ms, family).await
            {
                Ok(s) => s,
                Err(e) => {
                    // 440 here means the server has no `[turn] external_ip6`, which is
                    // a configuration answer rather than a fault — but the phase still
                    // has nothing to measure, so it is counted as an error and the
                    // reason is printed once.
                    if v6 && e.1 == Some(440) && i == 0 {
                        eprintln!(
                            "IPv6 Allocate refused with 440: the server has no \
                             [turn] external_ip6 configured, so there is no IPv6 relay \
                             to test against."
                        );
                    }
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    barrier.wait().await;
                    return;
                }
            };
            let ch: u16 = 0x4000 + (i as u16 & 0x3FFF);
            if sess.create_permission(peer_addr).await.is_err()
                || sess.channel_bind(ch, peer_addr).await.is_err()
            {
                stats.errs.fetch_add(1, Ordering::Relaxed);
                sess.release().await;
                barrier.wait().await;
                return;
            }

            // Peer receiver: counts what made it through the relay and
            // computes one-way latency from the embedded timestamp.
            let recv_stats = stats.clone();
            let recv_epoch = epoch.clone();
            let recv_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    match tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buf))
                        .await
                    {
                        Ok(Ok((n, _))) => {
                            recv_stats.recv.fetch_add(1, Ordering::Relaxed);
                            recv_stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                            if n >= 16 {
                                let mut ts = [0u8; 8];
                                ts.copy_from_slice(&buf[8..16]);
                                let sent_ns = u64::from_be_bytes(ts);
                                let now_ns = recv_epoch.elapsed().as_nanos() as u64;
                                if now_ns >= sent_ns {
                                    recv_stats
                                        .record_latency(Duration::from_nanos(now_ns - sent_ns));
                                }
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {
                            // recv timeout — exit once the run is over so
                            // the task doesn't linger forever.
                            if !recv_stats.is_running() {
                                break;
                            }
                        }
                    }
                }
            });

            barrier.wait().await;

            // Sender: paced ChannelData stream.
            let mut body = vec![0u8; payload];
            let mut seq: u64 = 0;
            let mut tick = tokio::time::interval(Duration::from_nanos(1_000_000_000 / pps.max(1)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            // Inside the 300 s permission deadline, the shortest of the three.
            let mut next_refresh = Instant::now() + Duration::from_secs(240);
            while stats.is_running() {
                tick.tick().await;
                if Instant::now() >= next_refresh {
                    if sess.refresh(ch, peer_addr).await.is_err() {
                        stats.errs.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    next_refresh = Instant::now() + Duration::from_secs(240);
                }
                seq += 1;
                body[0..8].copy_from_slice(&seq.to_be_bytes());
                let now_ns = epoch.elapsed().as_nanos() as u64;
                body[8..16].copy_from_slice(&now_ns.to_be_bytes());
                let frame = turn_client::channel_data_frame(ch, &body);
                if sess.sock.send_to(&frame, server).await.is_ok() {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_out
                        .fetch_add(frame.len() as u64, Ordering::Relaxed);
                } else {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                }
            }

            sess.release().await;
            let _ = recv_task.await;
        }));
    }

    barrier.wait().await;
    progress_reporter(&stats, json);
    // P0 #14: run warmup, then reset to measure only steady state.
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
        stats.reset();
    }
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles {
        let _ = h.await;
    }
    stats
}

/// Shared 1-second progress line on stderr (skipped in --json mode).
fn progress_reporter(stats: &Arc<Stats>, json: bool) {
    if json {
        return;
    }
    let stats2 = stats.clone();
    tokio::spawn(async move {
        let mut prev = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if !stats2.is_running() {
                break;
            }
            let cur = stats2.recv.load(Ordering::Relaxed);
            eprint!(
                "\r  [{:>3}s] {:>8} resp | {:>6} rps | {:>4} err",
                stats2.start.elapsed().as_secs(),
                cur,
                cur.saturating_sub(prev),
                stats2.errs.load(Ordering::Relaxed)
            );
            prev = cur;
        }
        eprintln!();
    });
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Set before any client runs: `peer_bind_addr` reads it for every socket.
    if let Some(ref ip) = cli.bind_ip {
        match ip.parse::<std::net::IpAddr>() {
            Ok(addr) => {
                let _ = turn_client::BIND_IP.set(addr);
            }
            Err(e) => {
                eprintln!("--bind-ip {ip:?} is not an IP address: {e}");
                std::process::exit(2);
            }
        }
    }
    let dur = Duration::from_secs(cli.duration);
    let wu = Duration::from_secs(cli.warmup);
    let mode_name = cli.mode.name();

    if !cli.json {
        eprintln!(
            "Turna TURN Benchmark — server: {}, duration: {}s",
            cli.server, cli.duration
        );
    }

    let creds = if !cli.user.is_empty() {
        Creds::Static {
            user: cli.user.clone(),
            pass: cli.pass.clone(),
        }
    } else {
        Creds::Rest {
            secret: cli.secret.clone(),
            uid: cli.uid.clone(),
            ttl_s: 3600,
        }
    };

    #[cfg(feature = "web-transport")]
    if let Mode::WtCheck { url } = &cli.mode {
        println!("TURN over WebTransport against {url}\n");
        match wt_client::webtransport_check(url, &creds, cli.rtt_timeout_ms).await {
            Ok(steps) => {
                for s in steps {
                    println!("  ok   {s}");
                }
                println!(
                    "\nwt-check: OK — the H3 path carries a full allocation and relays media."
                );
                println!("Not a browser test: same library on both sides (see the module docs).");
                std::process::exit(0);
            }
            Err(e) => {
                println!("  FAIL {e}");
                println!("\nwt-check: FAIL");
                std::process::exit(1);
            }
        }
    }

    #[cfg(feature = "dtls")]
    if matches!(cli.mode, Mode::DtlsCheck) {
        println!("TURN over DTLS against {}\n", cli.server);
        match dtls_client::dtls_check(cli.server, &creds, cli.rtt_timeout_ms).await {
            Ok(steps) => {
                for s in steps {
                    println!("  ok   {s}");
                }
                println!(
                    "\ndtls-check: OK — DTLS carries a full allocation and relays media both ways."
                );
                std::process::exit(0);
            }
            Err(e) => {
                println!("  FAIL {e}");
                println!("\ndtls-check: FAIL");
                std::process::exit(1);
            }
        }
    }

    #[cfg(feature = "tls")]
    if let Mode::TcpRelayCheck {
        server_name,
        pipelined,
    } = &cli.mode
    {
        println!(
            "RFC 6062 TCP relay against {} ({})\n",
            cli.server,
            if *pipelined {
                "payload pipelined with ConnectionBind"
            } else {
                "payload sent after ConnectionBind"
            }
        );
        match tcp_relay_client::tcp_relay_check(
            cli.server,
            server_name,
            &creds,
            cli.rtt_timeout_ms,
            *pipelined,
        )
        .await
        {
            Ok(steps) => {
                for s in steps {
                    println!("  ok   {s}");
                }
                println!("\ntcp-relay-check: OK");
                std::process::exit(0);
            }
            Err(e) => {
                println!("  FAIL {e}");
                println!("\ntcp-relay-check: FAIL");
                std::process::exit(1);
            }
        }
    }

    #[cfg(feature = "tls")]
    if let Mode::TlsCheck {
        server_name,
        alpn,
        client_cert,
        client_key,
    } = &cli.mode
    {
        let alpns: Vec<String> = if alpn.is_empty() {
            Vec::new()
        } else {
            vec![alpn.clone()]
        };
        println!("TURN over TLS against {}\n", cli.server);
        let auth = match (client_cert.as_deref(), client_key.as_deref()) {
            (Some(c), Some(k)) => Some((c, k)),
            (None, None) => None,
            _ => {
                eprintln!("--client-cert and --client-key must be given together");
                std::process::exit(2);
            }
        };
        match tls_client::tls_probe(
            cli.server,
            server_name,
            &alpns,
            &creds,
            cli.rtt_timeout_ms,
            auth,
        )
        .await
        {
            Ok(steps) => {
                for s in steps {
                    println!("  ok   {s}");
                }
                println!(
                    "\ntls-check: OK — TURNS carries a full allocation and relays media both ways."
                );
                std::process::exit(0);
            }
            Err(e) => {
                println!("  FAIL {e}");
                println!("\ntls-check: FAIL");
                std::process::exit(1);
            }
        }
    }

    #[cfg(feature = "quic")]
    if let Mode::QuicCheck {
        server_name,
        alpn,
        peer,
    } = &cli.mode
    {
        let peer: std::net::SocketAddr = match peer.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("bad --peer: {e}");
                std::process::exit(2);
            }
        };
        println!("TURN over raw QUIC against {}\n", cli.server);
        match quic_client::quic_allocate_check(
            cli.server,
            server_name,
            alpn,
            &creds,
            cli.rtt_timeout_ms,
            peer,
        )
        .await
        {
            Ok(steps) => {
                for s in steps {
                    println!("  ok   {s}");
                }
                println!("\nquic-check: OK — the QUIC ingress carries a full TURN allocation.");
                println!("Control plane only: relayed media over QUIC is not exercised here");
                println!("(docs/verification/interop-plan.md, Tier 2).");
                std::process::exit(0);
            }
            Err(e) => {
                println!("  FAIL {e}");
                println!("\nquic-check: FAIL");
                std::process::exit(1);
            }
        }
    }

    // Conformance is a probe sequence, not a load run: it has no throughput or
    // latency to report, so it exits here rather than being forced through the
    // stats/JSON path that the three load modes share.
    if let Mode::Conformance { v6_peer, v4_peer } = &cli.mode {
        let rc = run_conformance(cli.server, &creds, cli.rtt_timeout_ms, v6_peer, v4_peer).await;
        std::process::exit(rc);
    }

    let stats = match cli.mode {
        Mode::Binding { concurrency } => {
            if !cli.json {
                eprintln!("Mode: STUN Binding (c={concurrency})");
            }
            run_binding(cli.server, concurrency, dur, wu, cli.json).await
        }
        Mode::Allocate { concurrency } => {
            if !cli.json {
                eprintln!("Mode: Allocate (c={concurrency}, authed full handshake)");
            }
            run_allocate(
                cli.server,
                concurrency,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
            )
            .await
        }
        Mode::Conformance { .. } => unreachable!("handled above"),
        #[cfg(feature = "quic")]
        Mode::QuicCheck { .. } => unreachable!("handled above"),
        #[cfg(feature = "tls")]
        Mode::TcpRelayCheck { .. } => unreachable!("handled above"),
        #[cfg(feature = "dtls")]
        Mode::DtlsCheck => unreachable!("handled above"),
        #[cfg(feature = "dtls")]
        Mode::Dtls {
            concurrency,
            pps,
            payload,
        } => {
            if !cli.json {
                eprintln!("Mode: DTLS load (c={concurrency}, {pps} pps/session, {payload} B)");
            }
            dtls_client::run_dtls_load(
                cli.server,
                concurrency,
                pps,
                payload,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
            )
            .await
        }
        #[cfg(feature = "quic")]
        Mode::Quic {
            concurrency,
            pps,
            payload,
            ref server_name,
            ref alpn,
        } => {
            if !cli.json {
                eprintln!("Mode: QUIC load (c={concurrency}, {pps} pps/session, {payload} B)");
            }
            quic_client::run_quic_load(
                cli.server,
                server_name.clone(),
                alpn.clone(),
                concurrency,
                pps,
                payload,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
            )
            .await
        }
        #[cfg(feature = "web-transport")]
        Mode::WtCheck { .. } => unreachable!("handled above"),
        #[cfg(feature = "web-transport")]
        Mode::Wt {
            ref url,
            concurrency,
            pps,
            payload,
        } => {
            if !cli.json {
                eprintln!(
                    "Mode: WebTransport load (c={concurrency}, {pps} pps/session, {payload} B)"
                );
            }
            wt_client::run_wt_load(
                url.clone(),
                concurrency,
                pps,
                payload,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
            )
            .await
        }
        #[cfg(feature = "tls")]
        Mode::TlsCheck { .. } => unreachable!("handled above"),
        #[cfg(feature = "tls")]
        Mode::Tls {
            concurrency,
            channel_data,
            pps,
            payload,
            ref server_name,
            ref alpn,
            ref client_cert,
            ref client_key,
        } => {
            let alpns: Vec<String> = if alpn.is_empty() {
                Vec::new()
            } else {
                vec![alpn.clone()]
            };
            if !cli.json {
                eprintln!(
                    "Mode: TURNS load (c={concurrency}, {})",
                    if channel_data {
                        format!("channel-data {pps} pps/session, {payload} B")
                    } else {
                        "allocation churn".to_string()
                    }
                );
            }
            tls_client::run_tls_load(
                cli.server,
                server_name.clone(),
                alpns,
                client_cert.clone(),
                client_key.clone(),
                concurrency,
                channel_data,
                pps,
                payload,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
            )
            .await
        }
        Mode::ChannelData {
            channels,
            pps,
            payload,
            ref family,
        } => {
            let v6 = match family.as_str() {
                "v4" => false,
                "v6" => true,
                other => {
                    eprintln!("--family must be v4 or v6, got {other:?}");
                    std::process::exit(2);
                }
            };
            if !cli.json {
                eprintln!(
                    "Mode: ChannelData relay (n={channels}, {pps} pps/ch, {payload} B, \
                     relayed family {})",
                    if v6 { "IPv6" } else { "IPv4" }
                );
            }
            run_channeldata(
                cli.server,
                channels,
                pps,
                payload,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
                v6,
            )
            .await
        }
    };

    let snap = stats.snapshot(&cli.label, mode_name);
    if cli.json {
        snap.print_json();
    } else {
        snap.print_report();
    }
}

// ---------------------------------------------------------------------------
// Conformance probes (address family + peer filter)
// ---------------------------------------------------------------------------

/// Print one probe result. `verdict` is the interpretation, not just the raw
/// answer — a reader should not have to know the RFC to see whether a line is
/// good news.
fn probe(name: &str, answer: &str, verdict: &str) {
    println!("  {name:<44} {answer:<28} {verdict}");
}

fn code_str(c: Option<u16>) -> String {
    match c {
        Some(c) => format!("{c}"),
        None => "no response".to_string(),
    }
}

/// Address-family and peer-filter conformance. Returns a process exit code.
///
/// Deliberately reports rather than asserts where more than one answer is
/// correct: an IPv6 Allocate is `440` with `[turn] external_ip6` unset and
/// succeeds when it is set. Only genuinely wrong answers fail the run.
async fn run_conformance(
    server: std::net::SocketAddr,
    creds: &Creds,
    rtt: u64,
    v6_peer: &str,
    v4_peer: &str,
) -> i32 {
    let v6_peer: std::net::SocketAddr = match v6_peer.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bad --v6-peer: {e}");
            return 2;
        }
    };
    let v4_peer: std::net::SocketAddr = match v4_peer.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("bad --v4-peer: {e}");
            return 2;
        }
    };

    let mut failures = 0;
    println!("conformance probes against {server}\n");

    // ── 1. baseline: no family requested ──
    let mut v4_session = match turn_client::allocate_family(server, creds, rtt, None).await {
        Ok(s) => {
            let fam = if s.relayed.is_ipv4() { "IPv4" } else { "IPv6" };
            probe(
                "Allocate, no REQUESTED-ADDRESS-FAMILY",
                &format!("ok, relayed {fam}"),
                if s.relayed.is_ipv4() {
                    "as expected"
                } else {
                    "UNEXPECTED: default must be IPv4"
                },
            );
            if !s.relayed.is_ipv4() {
                failures += 1;
            }
            Some(s)
        }
        Err(e) => {
            probe(
                "Allocate, no REQUESTED-ADDRESS-FAMILY",
                &format!("{} ({})", e.0, code_str(e.1)),
                "FAIL: the baseline path is broken",
            );
            failures += 1;
            None
        }
    };

    // ── 2. explicit IPv4 must be indistinguishable from absent ──
    match turn_client::allocate_family(server, creds, rtt, Some(FAMILY_V4)).await {
        Ok(mut s) => {
            let ok = s.relayed.is_ipv4();
            probe(
                "Allocate, RAF = IPv4",
                "ok",
                if ok {
                    "as expected"
                } else {
                    "UNEXPECTED family"
                },
            );
            if !ok {
                failures += 1;
            }
            s.release().await;
        }
        Err(e) => {
            probe(
                "Allocate, RAF = IPv4",
                &code_str(e.1),
                "FAIL: explicit IPv4 must behave like absent",
            );
            failures += 1;
        }
    }

    // ── 3. IPv6: both outcomes legitimate, depending on external_ip6 ──
    let mut v6_session =
        match turn_client::allocate_family(server, creds, rtt, Some(FAMILY_V6)).await {
            Ok(s) => {
                let ok = s.relayed.is_ipv6();
                probe(
                    "Allocate, RAF = IPv6",
                    &format!("ok, relayed {}", if ok { "IPv6" } else { "IPv4" }),
                    if ok {
                        "IPv6 relaying is ENABLED (external_ip6 is set)"
                    } else {
                        "FAIL: accepted an IPv6 request but relayed IPv4"
                    },
                );
                if !ok {
                    failures += 1;
                    None
                } else {
                    Some(s)
                }
            }
            Err(e) if e.1 == Some(440) => {
                probe(
                    "Allocate, RAF = IPv6",
                    "440",
                    "IPv6 relaying is DISABLED (external_ip6 unset) — correct refusal",
                );
                None
            }
            Err(e) => {
                probe(
                    "Allocate, RAF = IPv6",
                    &code_str(e.1),
                    "FAIL: expected success or 440",
                );
                failures += 1;
                None
            }
        };

    // ── 4. ADDITIONAL-ADDRESS-FAMILY (RFC 8656 §7.2). Not implemented, and the
    //       attribute is comprehension-optional, so being ignored is RFC-legal —
    //       the probe records which of the three possible behaviours this build
    //       has, so the doc claim and the wire agree. ──
    let aaf = turn_client::probe_additional_address_family(server, rtt, FAMILY_V6, false).await;
    match aaf {
        Some(401) | Some(turn_client::PROBE_SUCCESS) => probe(
            "ADDITIONAL-ADDRESS-FAMILY = IPv6",
            "ignored",
            "not implemented; ignoring is RFC-legal for a comprehension-optional attribute",
        ),
        Some(400) => probe(
            "ADDITIONAL-ADDRESS-FAMILY = IPv6",
            "400",
            "the attribute is being validated — docs say it is not implemented, so one of them is wrong",
        ),
        c => probe(
            "ADDITIONAL-ADDRESS-FAMILY = IPv6",
            &code_str(c),
            "unexpected; investigate before trusting the family docs",
        ),
    }
    // The illegal combination: both family attributes at once must be 400 once the
    // feature lands. Until then it is ignored, and recording that is the point.
    let both = turn_client::probe_additional_address_family(server, rtt, FAMILY_V6, true).await;
    match both {
        Some(400) => probe(
            "RAF + ADDITIONAL-ADDRESS-FAMILY",
            "400",
            "as the RFC requires",
        ),
        Some(401) | Some(turn_client::PROBE_SUCCESS) => probe(
            "RAF + ADDITIONAL-ADDRESS-FAMILY",
            "accepted",
            "expected while AAF is unimplemented; must become 400 with the feature",
        ),
        c => probe(
            "RAF + ADDITIONAL-ADDRESS-FAMILY",
            &code_str(c),
            "unexpected",
        ),
    }

    // ── 5. family mismatch: RFC 6156 §4.2 -> 443 ──
    if let Some(s) = v4_session.as_mut() {
        match s.create_permission_code(v6_peer).await {
            Err(Some(443)) => probe(
                "v6 peer on a v4 allocation",
                "443",
                "as expected (RFC 6156 §4.2)",
            ),
            Err(c) => {
                probe(
                    "v6 peer on a v4 allocation",
                    &code_str(c),
                    "FAIL: expected 443",
                );
                failures += 1;
            }
            Ok(()) => {
                probe(
                    "v6 peer on a v4 allocation",
                    "success",
                    "FAIL: a cross-family permission was installed",
                );
                failures += 1;
            }
        }
    }
    if let Some(s) = v6_session.as_mut() {
        match s.create_permission_code(v4_peer).await {
            Err(Some(443)) => probe(
                "v4 peer on a v6 allocation",
                "443",
                "as expected (RFC 6156 §4.2)",
            ),
            Err(c) => {
                probe(
                    "v4 peer on a v6 allocation",
                    &code_str(c),
                    "FAIL: expected 443",
                );
                failures += 1;
            }
            Ok(()) => {
                probe(
                    "v4 peer on a v6 allocation",
                    "success",
                    "FAIL: a cross-family permission was installed",
                );
                failures += 1;
            }
        }
    }

    // ── 6. peer filter: the v4-embedding v6 transition prefixes must be 403.
    //       This is the SSRF check — each of these smuggles an arbitrary IPv4
    //       address inside a v6 literal, so without them every v4 deny rule is
    //       bypassable. Run on the v4 allocation: `is_forbidden_peer` is checked
    //       before the family test, so a forbidden peer answers 403 even though
    //       it is also cross-family. ──
    let bypass: [(&str, &str); 4] = [
        ("64:ff9b::a9fe:a9fe", "NAT64 form of 169.254.169.254"),
        ("2002:c000:0204::1", "6to4"),
        ("2001::1", "Teredo"),
        ("::203.0.113.1", "IPv4-compatible"),
    ];
    if let Some(s) = v4_session.as_mut() {
        for (addr, what) in bypass {
            let peer: std::net::SocketAddr = format!("[{addr}]:9999").parse().expect("literal");
            match s.create_permission_code(peer).await {
                Err(Some(403)) => probe(
                    &format!("peer filter: {what}"),
                    "403",
                    "denied, as it must be",
                ),
                Err(c) => {
                    probe(
                        &format!("peer filter: {what}"),
                        &code_str(c),
                        "FAIL: expected 403 Forbidden",
                    );
                    failures += 1;
                }
                Ok(()) => {
                    probe(
                        &format!("peer filter: {what}"),
                        "success",
                        "FAIL: this smuggles an IPv4 target past the v4 deny rules",
                    );
                    failures += 1;
                }
            }
        }
    }

    if let Some(s) = v4_session.as_mut() {
        s.release().await;
    }
    if let Some(s) = v6_session.as_mut() {
        s.release().await;
    }

    println!();
    if failures == 0 {
        println!("conformance: OK — every probe answered as the RFC and the config require.");
        println!("This covers address-family handling and the peer filter. It does not cover");
        println!("relayed media: an allocation that answers correctly can still fail to pass");
        println!("packets (see docs/verification/interop-plan.md, Tier 2).");
        0
    } else {
        println!("conformance: FAIL — {failures} probe(s) wrong. Details above.");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_pkt() {
        let p = binding_request();
        assert_eq!(p.len(), 20); // fixed array
        assert_eq!(u32::from_be_bytes([p[4], p[5], p[6], p[7]]), STUN_MAGIC);
    }

    #[test]
    fn fmt() {
        assert_eq!(fmt_bytes(500), "500 B");
        assert!(fmt_bytes(2_000_000).contains("MiB"));
    }

    #[test]
    fn stats_latency() {
        let s = Stats::new();
        s.record_latency(Duration::from_micros(50));
        s.record_latency(Duration::from_micros(5000));
        assert_eq!(s.lat_buckets[0].load(Ordering::Relaxed), 1);
        assert_eq!(s.lat_min.load(Ordering::Relaxed), 50);
        assert_eq!(s.lat_max.load(Ordering::Relaxed), 5000);
    }

    #[test]
    fn json_escape_basic() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
    }

    #[test]
    fn snapshot_json_is_valid_one_liner() {
        let s = Stats::new();
        s.record_latency(Duration::from_micros(120));
        s.sent.store(10, Ordering::Relaxed);
        s.recv.store(10, Ordering::Relaxed);
        // We can't call print_json() in a test (it goes to stdout); just
        // verify that the snapshot fields we'd format are sensible.
        let snap = s.snapshot("test-label", "binding");
        assert_eq!(snap.mode, "binding");
        assert_eq!(snap.label, "test-label");
        // 1 sample at 120 µs → bucket 1 (<500 µs); every percentile of
        // a single-sample histogram must land in that bucket = 500.
        assert_eq!(snap.lat_p50_us, 500);
        assert_eq!(snap.lat_p95_us, 500);
        assert_eq!(snap.lat_p99_us, 500);
    }

    /// Regression test for the percentile-at-low-counts bug: with
    /// `total=1, p=0.99`, the old `as u64` truncation gave target=0
    /// and the loop returned the first (empty) bucket = 100.
    #[test]
    fn percentile_handles_low_sample_count() {
        let s = Stats::new();
        s.record_latency(Duration::from_micros(120)); // bucket 1 (<500)
        assert_eq!(s.percentile(0.50), 500, "p50 of 1 sample → its bucket");
        assert_eq!(
            s.percentile(0.99),
            500,
            "p99 must not return empty bucket 0"
        );

        // Two samples in different buckets: 120 (bucket 1) and 600
        // (bucket 2, <1ms). p50 = first half = bucket 1 = 500.
        // p99 = second half = bucket 2 = 1000.
        let s = Stats::new();
        s.record_latency(Duration::from_micros(120));
        s.record_latency(Duration::from_micros(600));
        assert_eq!(s.percentile(0.50), 500);
        assert_eq!(s.percentile(0.99), 1000);
    }

    /// P0 #14: `reset()` starts the steady-state window — everything from the
    /// warmup phase (counters, latency histogram, loss) is discarded.
    #[test]
    fn reset_clears_warmup_window() {
        let s = Stats::new();
        s.sent.fetch_add(100, Ordering::Relaxed);
        s.recv.fetch_add(90, Ordering::Relaxed);
        s.errs.fetch_add(5, Ordering::Relaxed);
        s.record_latency(Duration::from_micros(500));

        s.reset();

        // Only post-reset activity is measured.
        s.sent.fetch_add(10, Ordering::Relaxed);
        s.recv.fetch_add(10, Ordering::Relaxed);
        let snap = s.snapshot("x", "binding");
        assert_eq!(snap.sent, 10, "warmup sends discarded");
        assert_eq!(snap.recv, 10, "warmup recvs discarded");
        assert_eq!(snap.errs, 0, "warmup errors discarded");
        assert_eq!(snap.loss, 0, "sent == recv + errs → no loss");
        assert_eq!(snap.lat_min_us, 0, "latency histogram cleared");
    }
}
