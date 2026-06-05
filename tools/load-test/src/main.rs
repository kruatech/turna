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
use turn_client::Creds;

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
}

#[derive(Subcommand, Clone)]
enum Mode {
    Binding { #[arg(short, long, default_value = "10")] concurrency: usize },
    Allocate { #[arg(short, long, default_value = "100")] concurrency: usize },
    ChannelData {
        #[arg(short = 'n', long, default_value = "100")] channels: usize,
        #[arg(long, default_value = "1000")] pps: u64,
        #[arg(long, default_value = "160")] payload: usize,
    },
}

impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::Binding { .. }     => "binding",
            Mode::Allocate { .. }    => "allocate",
            Mode::ChannelData { .. } => "channeldata",
        }
    }
}

// ---------------------------------------------------------------------------
// Stats (lock-free)
// ---------------------------------------------------------------------------

struct Stats {
    sent: AtomicU64, recv: AtomicU64, errs: AtomicU64,
    bytes_out: AtomicU64, bytes_in: AtomicU64,
    lat_buckets: [AtomicU64; 10],
    lat_sum: AtomicU64, lat_min: AtomicU64, lat_max: AtomicU64,
    start: Instant, running: AtomicBool,
}

impl Stats {
    fn new() -> Self {
        Self {
            sent: 0.into(), recv: 0.into(), errs: 0.into(),
            bytes_out: 0.into(), bytes_in: 0.into(),
            lat_buckets: Default::default(), lat_sum: 0.into(),
            lat_min: AtomicU64::new(u64::MAX), lat_max: 0.into(),
            start: Instant::now(), running: true.into(),
        }
    }

    fn record_latency(&self, d: Duration) {
        let us = d.as_micros() as u64;
        self.lat_sum.fetch_add(us, Ordering::Relaxed);
        loop {
            let c = self.lat_min.load(Ordering::Relaxed);
            if us >= c
               || self.lat_min.compare_exchange_weak(c, us, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                break;
            }
        }
        loop {
            let c = self.lat_max.load(Ordering::Relaxed);
            if us <= c
               || self.lat_max.compare_exchange_weak(c, us, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                break;
            }
        }
        let b = match us {
            0..=99            => 0,
            100..=499         => 1,
            500..=999         => 2,
            1_000..=4_999     => 3,
            5_000..=9_999     => 4,
            10_000..=49_999   => 5,
            50_000..=99_999   => 6,
            100_000..=499_999 => 7,
            500_000..=999_999 => 8,
            _                 => 9,
        };
        self.lat_buckets[b].fetch_add(1, Ordering::Relaxed);
    }

    fn is_running(&self) -> bool { self.running.load(Ordering::Relaxed) }
    fn stop(&self) { self.running.store(false, Ordering::Relaxed); }

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
        let buckets: Vec<u64> = self.lat_buckets.iter()
            .map(|b| b.load(Ordering::Relaxed)).collect();
        let total: u64 = buckets.iter().sum();
        if total == 0 { return 0; }
        let target = ((total as f64) * p).ceil() as u64;
        let target = target.max(1); // guard against p == 0.0
        const BOUNDS: [u64; 10] = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, u64::MAX];
        let mut cum = 0u64;
        for (i, &c) in buckets.iter().enumerate() {
            cum += c;
            if cum >= target { return BOUNDS[i]; }
        }
        BOUNDS[9]
    }

    fn snapshot(&self, label: &str, mode: &str) -> Snapshot {
        let el = self.start.elapsed().as_secs_f64();
        let recv = self.recv.load(Ordering::Relaxed);
        Snapshot {
            label:        label.into(),
            mode:         mode.into(),
            duration_s:   el,
            sent:         self.sent.load(Ordering::Relaxed),
            recv,
            errs:         self.errs.load(Ordering::Relaxed),
            bytes_out:    self.bytes_out.load(Ordering::Relaxed),
            bytes_in:     self.bytes_in.load(Ordering::Relaxed),
            rps:          if el > 0.0 { recv as f64 / el } else { 0.0 },
            lat_min_us:   { let v = self.lat_min.load(Ordering::Relaxed); if v == u64::MAX { 0 } else { v } },
            lat_max_us:   self.lat_max.load(Ordering::Relaxed),
            lat_avg_us:   if recv > 0 { self.lat_sum.load(Ordering::Relaxed) / recv } else { 0 },
            lat_p50_us:   self.percentile(0.50),
            lat_p95_us:   self.percentile(0.95),
            lat_p99_us:   self.percentile(0.99),
            lat_buckets:  self.lat_buckets.iter()
                              .map(|b| b.load(Ordering::Relaxed)).collect(),
        }
    }
}

/// Snapshot of a completed run. Owns its data so we can format it
/// either as a human report or as JSON without touching the live Stats.
#[derive(Debug)]
struct Snapshot {
    label:       String,
    mode:        String,
    duration_s:  f64,
    sent:        u64,
    recv:        u64,
    errs:        u64,
    bytes_out:   u64,
    bytes_in:    u64,
    rps:         f64,
    lat_min_us:  u64,
    lat_max_us:  u64,
    lat_avg_us:  u64,
    lat_p50_us:  u64,
    lat_p95_us:  u64,
    lat_p99_us:  u64,
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
        let err_pct = if self.sent > 0 { self.errs as f64 / self.sent as f64 * 100.0 } else { 0.0 };
        println!("  Errors:      {} ({:.2}%)", self.errs, err_pct);
        println!("  RPS:         {:.0}", self.rps);
        println!("  Throughput:  {} out / {} in",
                 fmt_bytes(self.bytes_out), fmt_bytes(self.bytes_in));
        println!("───────────────────────────────────────────");
        println!("  Latency:");
        println!("    Min:  {} µs", self.lat_min_us);
        println!("    Avg:  {} µs", self.lat_avg_us);
        println!("    P50:  {} µs", self.lat_p50_us);
        println!("    P95:  {} µs", self.lat_p95_us);
        println!("    P99:  {} µs", self.lat_p99_us);
        println!("    Max:  {} µs", self.lat_max_us);
        println!("───────────────────────────────────────────");
        let labels = ["<100µs","<500µs","<1ms","<5ms","<10ms",
                      "<50ms","<100ms","<500ms","<1s","≥1s"];
        let mx_b = self.lat_buckets.iter().max().copied().unwrap_or(1);
        for (l, &c) in labels.iter().zip(self.lat_buckets.iter()) {
            let bar = "█".repeat(if mx_b > 0 { (c * 40 / mx_b) as usize } else { 0 });
            println!("    {l:>8} │ {c:>8} │ {bar}");
        }
        println!("═══════════════════════════════════════════");
    }

    /// Single-line JSON to stdout. We don't pull in serde just for
    /// this — hand-rolled format is sufficient and avoids a build-time
    /// cost. Field names are stable; treat as machine contract.
    fn print_json(&self) {
        // Helper to format the bucket vector as a JSON array.
        let buckets = self.lat_buckets.iter()
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
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c    => out.push(c),
        }
    }
    out
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 { format!("{:.2} GiB", b as f64 / (1 << 30) as f64) }
    else if b >= 1 << 20 { format!("{:.2} MiB", b as f64 / (1 << 20) as f64) }
    else if b >= 1024 { format!("{:.2} KiB", b as f64 / 1024.0) }
    else { format!("{b} B") }
}

fn binding_request() -> [u8; 20] {
    let mut p = [0u8; 20];
    p[0] = 0x00; p[1] = 0x01;
    p[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    for b in &mut p[8..20] { *b = rand::random(); }
    p
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async fn run_binding(server: SocketAddr, concurrency: usize, duration: Duration, json: bool) -> Arc<Stats> {
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
                    stats.bytes_out.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
                        Ok(Ok(n)) => {
                            stats.recv.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                            stats.record_latency(t.elapsed());
                        }
                        _ => { stats.errs.fetch_add(1, Ordering::Relaxed); }
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
                if !stats2.is_running() { break; }
                let cur = stats2.recv.load(Ordering::Relaxed);
                eprint!("\r  [{:>3}s] {:>8} resp | {:>6} rps | {:>4} err",
                    stats2.start.elapsed().as_secs(), cur, cur - prev,
                    stats2.errs.load(Ordering::Relaxed));
                prev = cur;
            }
            eprintln!();
        });
    }

    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles { let _ = h.await; }
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
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles { let _ = h.await; }
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
    json: bool,
    creds: Creds,
    rtt_ms: u64,
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
            // Local peer socket: the relay's other side.
            let peer = match UdpSocket::bind("127.0.0.1:0").await {
                Ok(s) => s,
                Err(_) => { stats.errs.fetch_add(1, Ordering::Relaxed); barrier.wait().await; return; }
            };
            let peer_addr = peer.local_addr().unwrap();

            let mut sess = match turn_client::allocate(server, &creds, rtt_ms).await {
                Ok(s) => s,
                Err(_) => { stats.errs.fetch_add(1, Ordering::Relaxed); barrier.wait().await; return; }
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
                    match tokio::time::timeout(Duration::from_secs(1), peer.recv_from(&mut buf)).await {
                        Ok(Ok((n, _))) => {
                            recv_stats.recv.fetch_add(1, Ordering::Relaxed);
                            recv_stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                            if n >= 16 {
                                let mut ts = [0u8; 8];
                                ts.copy_from_slice(&buf[8..16]);
                                let sent_ns = u64::from_be_bytes(ts);
                                let now_ns = recv_epoch.elapsed().as_nanos() as u64;
                                if now_ns >= sent_ns {
                                    recv_stats.record_latency(Duration::from_nanos(now_ns - sent_ns));
                                }
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {
                            // recv timeout — exit once the run is over so
                            // the task doesn't linger forever.
                            if !recv_stats.is_running() { break; }
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
            while stats.is_running() {
                tick.tick().await;
                seq += 1;
                body[0..8].copy_from_slice(&seq.to_be_bytes());
                let now_ns = epoch.elapsed().as_nanos() as u64;
                body[8..16].copy_from_slice(&now_ns.to_be_bytes());
                let frame = turn_client::channel_data_frame(ch, &body);
                if sess.sock.send_to(&frame, server).await.is_ok() {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_out.fetch_add(frame.len() as u64, Ordering::Relaxed);
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
    tokio::time::sleep(duration).await;
    stats.stop();
    for h in handles { let _ = h.await; }
    stats
}

/// Shared 1-second progress line on stderr (skipped in --json mode).
fn progress_reporter(stats: &Arc<Stats>, json: bool) {
    if json { return; }
    let stats2 = stats.clone();
    tokio::spawn(async move {
        let mut prev = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if !stats2.is_running() { break; }
            let cur = stats2.recv.load(Ordering::Relaxed);
            eprint!("\r  [{:>3}s] {:>8} resp | {:>6} rps | {:>4} err",
                stats2.start.elapsed().as_secs(), cur, cur - prev,
                stats2.errs.load(Ordering::Relaxed));
            prev = cur;
        }
        eprintln!();
    });
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let dur = Duration::from_secs(cli.duration);
    let mode_name = cli.mode.name();

    if !cli.json {
        eprintln!("Turna TURN Benchmark — server: {}, duration: {}s", cli.server, cli.duration);
    }

    let creds = if !cli.user.is_empty() {
        Creds::Static { user: cli.user.clone(), pass: cli.pass.clone() }
    } else {
        Creds::Rest { secret: cli.secret.clone(), uid: cli.uid.clone(), ttl_s: 3600 }
    };

    let stats = match cli.mode {
        Mode::Binding { concurrency } => {
            if !cli.json { eprintln!("Mode: STUN Binding (c={concurrency})"); }
            run_binding(cli.server, concurrency, dur, cli.json).await
        }
        Mode::Allocate { concurrency } => {
            if !cli.json {
                eprintln!("Mode: Allocate (c={concurrency}, authed full handshake)");
            }
            run_allocate(cli.server, concurrency, dur, cli.json, creds, cli.rtt_timeout_ms).await
        }
        Mode::ChannelData { channels, pps, payload } => {
            if !cli.json {
                eprintln!("Mode: ChannelData relay (n={channels}, {pps} pps/ch, {payload} B)");
            }
            run_channeldata(cli.server, channels, pps, payload, dur, cli.json, creds, cli.rtt_timeout_ms).await
        }
    };

    let snap = stats.snapshot(&cli.label, mode_name);
    if cli.json {
        snap.print_json();
    } else {
        snap.print_report();
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
        assert_eq!(s.percentile(0.99), 500, "p99 must not return empty bucket 0");

        // Two samples in different buckets: 120 (bucket 1) and 600
        // (bucket 2, <1ms). p50 = first half = bucket 1 = 500.
        // p99 = second half = bucket 2 = 1000.
        let s = Stats::new();
        s.record_latency(Duration::from_micros(120));
        s.record_latency(Duration::from_micros(600));
        assert_eq!(s.percentile(0.50), 500);
        assert_eq!(s.percentile(0.99), 1000);
    }
}
