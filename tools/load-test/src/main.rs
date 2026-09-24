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

mod hold;
mod procfs;
#[cfg(all(feature = "sctp", target_os = "linux"))]
mod sctp_client;
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
    feature = "web-transport",
    all(feature = "sctp", target_os = "linux")
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
#[cfg(any(
    feature = "quic",
    feature = "web-transport",
    all(feature = "sctp", target_os = "linux")
))]
mod transport_probe;
#[cfg(feature = "web-transport")]
mod wt_client;
use hold::{run_hold, HoldParams};
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

    /// Spread client control sockets over N addresses in 127.0.0.0/8
    /// (127.0.0.1 upwards, at most 65 534 — see `turn_client::SPREAD_MAX`).
    ///
    /// Defaults to 1 — every client from 127.0.0.1, as before. Raise it when a
    /// run is meant to measure the server rather than turna's per-source-IP
    /// limits: the Allocate limiter (burst 32, 16/s by default — 38 channels from
    /// one address produced 122 refusals against 59 allocations) and the
    /// unauthenticated-reply budget (burst 64, 8/s, not configurable), which
    /// every Binding response and every 401 challenge draws on.
    ///
    /// Linux only. The whole of 127.0.0.0/8 is local there; macOS needs
    /// `ifconfig lo0 alias 127.0.0.2` for each address and will otherwise bind
    /// them all to the same place without saying so.
    ///
    /// Ignored when --bind-ip is given, and for IPv6 servers.
    #[arg(long, default_value_t = 1)]
    source_ips: u32,

    /// PID of the server under test, for server-side resource figures.
    ///
    /// When set (Linux, same host), every load mode samples `/proc/<pid>` at the
    /// start and end of the *measured* window — after allocation setup and
    /// `--warmup` — and the JSON gains `server_cpu_pct`, `server_rss_kb_start` and
    /// `server_rss_kb_end`; the `hold` mode needs it for its per-allocation memory
    /// figure. Sampled here rather than by the calling script because only this
    /// process knows where the window starts. See `procfs.rs` for exactly what the
    /// numbers include.
    #[arg(long)]
    server_pid: Option<u32>,

    /// Clock ticks per second for `/proc/<pid>/stat` (USER_HZ). 100 on every
    /// mainstream Linux ABI; pass `$(getconf CLK_TCK)` to be exact.
    #[arg(long, default_value_t = 100)]
    clk_tck: u64,
}

#[derive(Subcommand, Clone)]
enum Mode {
    #[cfg(any(
        feature = "quic",
        feature = "web-transport",
        all(feature = "sctp", target_os = "linux")
    ))]
    TransportNetwork {
        #[arg(long)]
        transport: String,
        #[arg(long, default_value = "127.0.0.1:39001")]
        peer: SocketAddr,
        #[arg(long, default_value_t = 10)]
        pps: u64,
    },
    #[cfg(any(
        feature = "quic",
        feature = "web-transport",
        all(feature = "sctp", target_os = "linux")
    ))]
    TransportProbe {
        #[arg(long)]
        transport: String,
        #[arg(long, default_value = "hold")]
        action: String,
        #[arg(long, default_value_t = 0)]
        hold_secs: u64,
    },
    /// Establish N allocations, drop them all at once, and re-establish them
    /// simultaneously — a link flap or a node loss, from the server's side.
    ///
    /// Reports how many came back, how long the slowest took, and what the
    /// server refused along the way. Pair it with `--source-ips`: from a single
    /// source this measures the per-IP allocate limiter (32/s, burst 16) rather
    /// than the server, which is a different and much smaller question.
    ReconnectStorm {
        /// Clients in the storm.
        #[arg(long, default_value_t = 100)]
        clients: usize,
        /// Storms to run. More than one shows whether recovery degrades as
        /// limiter budgets deplete — the first storm is always the kindest.
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        /// Seconds to hold allocations before dropping them.
        #[arg(long, default_value_t = 5)]
        settle: u64,
        /// Seconds to wait for reconnection before calling a client lost.
        #[arg(long, default_value_t = 30)]
        recover_timeout: u64,
    },
    Binding {
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
        /// Sockets each task rotates through, one request per socket in turn.
        ///
        /// With `--source-ips`, each socket is bound on the next spread address,
        /// so the load arrives from `concurrency × sockets-per-task` sources.
        /// That is what a Binding benchmark against turna needs: the node
        /// answers at most 8 unauthenticated replies per second per source
        /// address (burst 64), so a few sources measure that budget, not the
        /// server. 1 (the default) keeps one socket per task, as before.
        #[arg(long, default_value_t = 1)]
        sockets_per_task: usize,
    },
    Allocate {
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
        /// Run every cycle as a brand-new client: fresh socket (new 5-tuple),
        /// unauthenticated Allocate → 401 challenge → authenticated Allocate →
        /// Refresh(lifetime=0) confirmed. Without it each worker takes the 401
        /// once and then reuses its socket and nonce, which measures allocation
        /// bookkeeping but not the challenge round-trip every real client pays.
        #[arg(long)]
        fresh: bool,
    },
    /// Establish N allocations, hold them, release them — and report the
    /// server's resident memory before, while held and after release.
    ///
    /// This is the per-allocation memory figure: `(rss_held - rss_before) / N`.
    /// Needs `--server-pid` for the memory fields (they are `null` without it).
    /// One JSON object on stdout with `--json`, a short report otherwise.
    Hold {
        /// Allocations to establish.
        #[arg(short = 'n', long, default_value_t = 1000)]
        allocations: usize,
        /// Allocations set up concurrently. Bounded so the setup does not become
        /// a flood the server's own rate limiter answers instead of its allocator.
        #[arg(long, default_value_t = 32)]
        parallel: usize,
        /// Seconds to wait after the last allocation before sampling, and again
        /// after release. Must stay well inside the 300 s permission lifetime:
        /// nothing is refreshed while held.
        #[arg(long, default_value_t = 3)]
        settle: u64,
        /// Also install one permission and one channel per allocation, which is
        /// what an allocation carrying a call looks like. Without it the figure
        /// is for the bare allocation.
        #[arg(long)]
        channel: bool,
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
    #[cfg(all(feature = "sctp", target_os = "linux"))]
    SctpCheck,
    #[cfg(all(feature = "sctp", target_os = "linux"))]
    Sctp {
        #[arg(short = 'c', long, default_value = "10")]
        concurrency: usize,
        #[arg(long, default_value = "10")]
        pps: u64,
        #[arg(long, default_value = "160")]
        payload: usize,
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
    /// Requires `[turn.tcp_relay] enabled = true` and `[tls]` enabled. (It was
    /// also refused under `production = true` until 2026-08-25, for want of the
    /// interop evidence this check and coturn's client then provided.)
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
            #[cfg(any(
                feature = "quic",
                feature = "web-transport",
                all(feature = "sctp", target_os = "linux")
            ))]
            Mode::TransportProbe { .. } | Mode::TransportNetwork { .. } => "transport-probe",
            #[cfg(all(feature = "sctp", target_os = "linux"))]
            Mode::SctpCheck => "sctp-check",
            #[cfg(all(feature = "sctp", target_os = "linux"))]
            Mode::Sctp { .. } => "sctp",
            Mode::Binding { .. } => "binding",
            Mode::Allocate { .. } => "allocate",
            Mode::Hold { .. } => "hold",
            Mode::ReconnectStorm { .. } => "reconnect-storm",
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
    /// Elapsed-ns from `start` when the measured window closed (`stop()`).
    /// 0 = still open. Without it the window ran on through teardown — the
    /// channel-data mode's peer drain and Refresh(0) of every allocation — so
    /// rates read a few percent low and covered a different span from the
    /// server CPU sample, which is taken at `stop()`.
    measure_end_ns: AtomicU64,
    start: Instant,
    running: AtomicBool,
    /// Server process samples bracketing the measured window (`--server-pid`).
    /// `srv_start` is re-taken by `begin_window()` — when the warm-up is
    /// discarded, or right before the measured phase when there is none;
    /// `srv_end` at `stop()`. Same instants as `measure_{start,end}_ns`, so CPU
    /// and throughput describe one window.
    srv_start: std::sync::Mutex<Option<procfs::ProcSample>>,
    srv_end: std::sync::Mutex<Option<procfs::ProcSample>>,
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
            measure_end_ns: AtomicU64::new(0),
            lat_max: 0.into(),
            start: Instant::now(),
            running: true.into(),
            srv_start: std::sync::Mutex::new(procfs::sample()),
            srv_end: std::sync::Mutex::new(None),
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
        self.errs.store(0, Ordering::Relaxed);
        self.reset_preserving_errors();
    }

    fn reset_preserving_errors(&self) {
        // P0 #14: begin the steady-state window. Discard everything collected
        // during warmup so the report reflects steady state only, not
        // connection setup / allocation handshakes / ramp-up.
        self.sent.store(0, Ordering::Relaxed);
        self.recv.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.lat_sum.store(0, Ordering::Relaxed);
        self.lat_min.store(u64::MAX, Ordering::Relaxed);
        self.lat_max.store(0, Ordering::Relaxed);
        for b in &self.lat_buckets {
            b.store(0, Ordering::Relaxed);
        }
        self.begin_window();
    }

    /// Open the measured window now, without touching the counters.
    ///
    /// Called by `reset_preserving_errors()` after a warm-up, and directly by
    /// the load modes right before their measured phase when there is no
    /// warm-up — otherwise the window (and the server CPU baseline) would start
    /// at construction and include allocation setup.
    fn begin_window(&self) {
        self.measure_start_ns
            .store(self.start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        *self
            .srv_start
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = procfs::sample();
    }

    /// Length of the measured window, seconds: from `begin_window()` (or
    /// construction) to `stop()`, or to now while still running.
    fn window_secs(&self) -> f64 {
        let start = self.measure_start_ns.load(Ordering::Relaxed);
        let end = match self.measure_end_ns.load(Ordering::Relaxed) {
            0 => self.start.elapsed().as_nanos() as u64,
            e => e,
        };
        end.saturating_sub(start) as f64 / 1e9
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    fn stop(&self) {
        // Close the server-side window at the first stop only; a second call
        // (none today) must not stretch it over teardown.
        if self.running.swap(false, Ordering::Relaxed) {
            // `max(1)`: 0 means "open", and a stop in the first nanosecond
            // must still close the window.
            self.measure_end_ns.store(
                (self.start.elapsed().as_nanos() as u64).max(1),
                Ordering::Relaxed,
            );
            *self
                .srv_end
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = procfs::sample();
        }
    }

    /// `(cpu %, rss start KiB, rss end KiB)` over the measured window, each
    /// `None` without `--server-pid` or off Linux.
    fn server_window(&self) -> (Option<f64>, Option<u64>, Option<u64>) {
        let start = *self
            .srv_start
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = *self
            .srv_end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let clk = procfs::TARGET.get().map_or(100, |t| t.clk_tck);
        let cpu = match (&start, &end) {
            (Some(a), Some(b)) => procfs::cpu_percent(a, b, clk),
            _ => None,
        };
        (cpu, start.map(|s| s.rss_kb), end.map(|s| s.rss_kb))
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
        // P0 #14: measure only the steady-state window — after the warm-up (or
        // setup) and ending at stop(), not at the end of teardown.
        let el = self.window_secs();
        let sent = self.sent.load(Ordering::Relaxed);
        let recv = self.recv.load(Ordering::Relaxed);
        let errs = self.errs.load(Ordering::Relaxed);
        let (server_cpu_pct, server_rss_kb_start, server_rss_kb_end) = self.server_window();
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
            server_cpu_pct,
            server_rss_kb_start,
            server_rss_kb_end,
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
    /// Server CPU over the measured window, percent of one core (`--server-pid`).
    server_cpu_pct: Option<f64>,
    /// Server `VmRSS` at the start / end of the measured window, KiB.
    server_rss_kb_start: Option<u64>,
    server_rss_kb_end: Option<u64>,
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
        if let Some(cpu) = self.server_cpu_pct {
            println!("  Server CPU:  {cpu:.1} % of one core (measured window)");
        }
        if let (Some(a), Some(b)) = (self.server_rss_kb_start, self.server_rss_kb_end) {
            println!("  Server RSS:  {a} KiB → {b} KiB");
        }
        println!("═══════════════════════════════════════════");
    }

    /// Single-line JSON to stdout. We don't pull in serde just for
    /// this — hand-rolled format is sufficient and avoids a build-time
    /// cost. Field names are stable; treat as machine contract.
    fn print_json(&self) {
        println!("{}", self.to_json());
    }

    /// The JSON line [`print_json`](Self::print_json) prints. Separate so the
    /// contract can be tested without capturing stdout.
    fn to_json(&self) -> String {
        // Helper to format the bucket vector as a JSON array.
        let buckets = self
            .lat_buckets
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
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
\"lat_bucket_counts\":[{buckets}],\
\"server_cpu_pct\":{cpu},\
\"server_rss_kb_start\":{rss0},\
\"server_rss_kb_end\":{rss1}\
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
            cpu = procfs::json_opt_f(self.server_cpu_pct, 1),
            rss0 = procfs::json_opt(self.server_rss_kb_start),
            rss1 = procfs::json_opt(self.server_rss_kb_end),
        )
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
    sockets_per_task: usize,
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
            // Without a spread or --bind-ip, keep the historical wildcard bind:
            // it is what lets this mode reach a server that is not on loopback.
            let spread = turn_client::SOURCE_SPREAD.get().copied().unwrap_or(1) > 1
                || turn_client::BIND_IP.get().is_some();
            let mut socks = Vec::with_capacity(sockets_per_task.max(1));
            for _ in 0..sockets_per_task.max(1) {
                let local = if spread {
                    turn_client::control_bind_addr(server)
                } else {
                    "0.0.0.0:0".to_string()
                };
                let sock = UdpSocket::bind(local).await.unwrap();
                sock.connect(server).await.unwrap();
                socks.push(sock);
            }
            let mut buf = [0u8; 1500];
            let mut next = 0usize;
            barrier.wait().await;
            while stats.is_running() {
                let sock = &socks[next % socks.len()];
                next = next.wrapping_add(1);
                let pkt = binding_request();
                let t = Instant::now();
                if sock.send(&pkt).await.is_ok() {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_out
                        .fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    // Match the transaction id: with rotation, a late answer to an
                    // earlier (timed-out) request can be waiting on this socket,
                    // and counting it would pair a response with the wrong request.
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
                    let got = loop {
                        match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                            Ok(Ok(n)) if n >= 20 && buf[8..20] == pkt[8..20] => break Some(n),
                            Ok(Ok(_)) => continue,
                            _ => break None,
                        }
                    };
                    match got {
                        Some(n) => {
                            stats.recv.fetch_add(1, Ordering::Relaxed);
                            stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                            stats.record_latency(t.elapsed());
                        }
                        None => {
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
    } else {
        stats.begin_window();
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
/// Each worker obtains a challenge once, retains its UDP socket and repeats
/// authenticated Allocate -> confirmed Refresh(0). With `fresh`, every cycle is a
/// new client instead: new socket, 401 challenge, authenticated Allocate,
/// confirmed Refresh(0). `recv` counts complete
/// create/delete cycles; latency includes both operations. Nonce expiry retries
/// are bounded. Warmup failures remain visible in the final error count.
#[allow(clippy::too_many_arguments)]
async fn run_allocate(
    server: SocketAddr,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    json: bool,
    creds: Creds,
    rtt_ms: u64,
    fresh: bool,
) -> Arc<Stats> {
    let stats = Arc::new(Stats::new());
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::new();
    let measuring = Arc::new(AtomicBool::new(false));

    for worker in 0..concurrency {
        let stats = stats.clone();
        let barrier = barrier.clone();
        let creds = creds.clone();
        let measuring = measuring.clone();
        handles.push(tokio::spawn(async move {
            let mut session: Option<turn_client::Session> = None;
            let mut failures = 0u64;
            barrier.wait().await;
            while stats.is_running() {
                let measured = measuring.load(Ordering::Acquire);
                let t = Instant::now();
                let result = async {
                    if let Some(current) = session.as_mut().filter(|_| !fresh) {
                        current.churn_request(true).await?;
                    } else {
                        session =
                            Some(turn_client::allocate_family(server, &creds, rtt_ms, None).await?);
                    }
                    // Count success only after the server confirms deletion.
                    session.as_mut().unwrap().churn_request(false).await
                }
                .await;
                if fresh && result.is_ok() {
                    // Deleted and confirmed; the next cycle is a new client.
                    session = None;
                }
                if measured {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    match &result {
                        Ok(()) => {
                            stats.recv.fetch_add(1, Ordering::Relaxed);
                            stats.record_latency(t.elapsed());
                        }
                        Err(_) => {
                            stats.errs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if let Err(error) = result {
                    failures += 1;
                    if failures <= 8 || failures.is_power_of_two() {
                        eprintln!(
                            "allocate worker={worker} failure={failures} stage={} stun_code={:?}",
                            error.0, error.1
                        );
                    }
                    // A timed-out operation has uncertain state. Do not reuse it.
                    if let Some(mut sess) = session.take() {
                        sess.release().await;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            // Include warmup failures in the final error count; never erase them.
            failures
        }));
    }

    barrier.wait().await;
    progress_reporter(&stats, json);
    // Mark operations at their start so warmup cannot split accounting.
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
    }
    stats.reset_preserving_errors();
    measuring.store(true, Ordering::Release);
    tokio::time::sleep(duration).await;
    stats.stop();
    let mut failures = 0;
    for h in handles {
        failures += match h.await {
            Ok(n) => n,
            Err(error) => {
                eprintln!("allocate worker failed: {error}");
                1
            }
        };
    }
    stats.errs.store(failures, Ordering::Relaxed);
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
            // Inside RFC 8656 §12's 0x4000-0x4FFF. The old mask (0x3FFF) reached
            // 0x7FFF, which RFC 8656 reserves and current coturn refuses unless
            // `rfc5766-channel-numbers` is set; numbers are per allocation, so
            // wrapping at 4096 costs nothing.
            let ch: u16 = 0x4000 + (i as u16 & 0x0FFF);
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
                if !stats.is_running() {
                    break;
                }
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

            // Drain the peer before deleting the allocation. Bound teardown
            // even if unrelated traffic keeps its receive loop alive.
            let mut recv_task = recv_task;
            match tokio::time::timeout(Duration::from_secs(2), &mut recv_task).await {
                Ok(Ok(())) => {}
                _ => {
                    stats.errs.fetch_add(1, Ordering::Relaxed);
                    recv_task.abort();
                    let _ = recv_task.await;
                }
            }
            sess.release().await;
        }));
    }

    barrier.wait().await;
    progress_reporter(&stats, json);
    // P0 #14: run warmup, then reset to measure only steady state.
    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
        stats.reset();
    } else {
        stats.begin_window();
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

/// One round: establish `clients` allocations, drop them, re-establish.
///
/// Returns `(established, recovered, slowest_recovery_ms)`.
///
/// Establishment and recovery are both concurrent — a storm is defined by
/// everyone arriving at once, and staggering them would measure something else.
/// Each client is timed individually so the reported figure is the slowest
/// client's recovery rather than the wall time of the round, which would be the
/// same number only by coincidence.
async fn storm_round(
    server: SocketAddr,
    creds: &turn_client::Creds,
    clients: usize,
    settle: u64,
    recover_timeout: u64,
    round: usize,
    rtt_ms: u64,
) -> (usize, usize, u128) {
    // ── establish ──────────────────────────────────────────────────────────
    let mut sessions = Vec::with_capacity(clients);
    let mut handles = Vec::with_capacity(clients);
    for _ in 0..clients {
        let creds = creds.clone();
        handles.push(tokio::spawn(async move {
            turn_client::allocate_family(server, &creds, rtt_ms, None)
                .await
                .ok()
        }));
    }
    for h in handles {
        if let Ok(Some(sess)) = h.await {
            sessions.push(sess);
        }
    }
    let established = sessions.len();
    if established == 0 {
        eprintln!("  round {round}: nothing established — check credentials and --source-ips");
        return (0, 0, 0);
    }

    tokio::time::sleep(Duration::from_secs(settle)).await;

    // ── the drop ───────────────────────────────────────────────────────────
    //
    // Sockets dropped without a Refresh(lifetime=0). A client that sends the
    // Refresh is a client shutting down politely, and the server frees the
    // allocation immediately; a client whose network vanished sends nothing and
    // the allocation lingers until its lifetime expires. The second is the case
    // a storm is about, and it is harder on the server: the returning clients
    // ask for new allocations while the old ones still hold relay ports.
    drop(sessions);

    // ── the storm ──────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(established);
    for _ in 0..established {
        let creds = creds.clone();
        let deadline = Duration::from_secs(recover_timeout);
        handles.push(tokio::spawn(async move {
            let started = Instant::now();
            match tokio::time::timeout(
                deadline,
                turn_client::allocate_family(server, &creds, rtt_ms, None),
            )
            .await
            {
                Ok(Ok(_sess)) => Some(started.elapsed().as_millis()),
                _ => None,
            }
        }));
    }

    let mut recovered = 0usize;
    let mut slowest = 0u128;
    for h in handles {
        if let Ok(Some(ms)) = h.await {
            recovered += 1;
            slowest = slowest.max(ms);
        }
    }

    println!(
        "  round {round}: {recovered}/{established} recovered, slowest {slowest} ms, \
         round took {} ms",
        t0.elapsed().as_millis()
    );
    (established, recovered, slowest)
}

/// Knobs for the reconnect storm, bundled so a caller cannot transpose two of
/// the four consecutive integers without noticing.
#[derive(Clone, Copy)]
struct StormParams {
    clients: usize,
    rounds: usize,
    settle: u64,
    recover_timeout: u64,
    /// Response timeout per STUN exchange, ms. A 0 here makes every client give
    /// up before the server answers.
    rtt_ms: u64,
}

async fn run_reconnect_storm(
    server: SocketAddr,
    creds: turn_client::Creds,
    p: StormParams,
    json: bool,
) {
    let StormParams {
        clients,
        rounds,
        settle,
        recover_timeout,
        rtt_ms,
    } = p;
    if !json {
        println!("Reconnect storm: {clients} clients, {rounds} rounds, {settle}s settle");
        println!("Drop is ungraceful — no Refresh(0) — so old allocations still hold");
        println!("relay ports while the returning clients ask for new ones.");
        println!("═══════════════════════════════════════════");
    }

    let mut worst_recovery = 0u128;
    let mut total_established = 0usize;
    let mut total_recovered = 0usize;

    for round in 1..=rounds {
        let (est, rec, slow) = storm_round(
            server,
            &creds,
            clients,
            settle,
            recover_timeout,
            round,
            rtt_ms,
        )
        .await;
        total_established += est;
        total_recovered += rec;
        worst_recovery = worst_recovery.max(slow);
        // Between rounds: long enough for a token bucket to refill, short enough
        // that the run stays useful. Without a gap, later rounds would measure
        // depletion from earlier ones rather than the storm itself — which is
        // worth measuring, but as a separate question.
        if round < rounds {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    let lost = total_established.saturating_sub(total_recovered);
    if json {
        println!(
            "{{\"mode\":\"reconnect_storm\",\"clients\":{clients},\"rounds\":{rounds},\
             \"established\":{total_established},\"recovered\":{total_recovered},\
             \"lost\":{lost},\"worst_recovery_ms\":{worst_recovery}}}"
        );
    } else {
        println!("═══════════════════════════════════════════");
        println!("  Established:  {total_established}");
        println!("  Recovered:    {total_recovered}");
        println!("  Lost:         {lost}");
        println!("  Worst client: {worst_recovery} ms");
        println!("───────────────────────────────────────────");
        if lost > 0 {
            println!("  A client that did not come back is one whose call stays down.");
            println!("  Check the server's rate_limited and quota_exceeded counters");
            println!("  before concluding the server was overloaded — a refusal and");
            println!("  an overload look identical from here.");
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Set before any client runs: `control_bind_addr_indexed` reads it.
    if cli.source_ips > 1 {
        let _ = turn_client::SOURCE_SPREAD.set(cli.source_ips);
        eprintln!(
            "source spread: clients bound across 127.0.0.1-{} \
             (Linux only; on macOS these need lo0 aliases)",
            turn_client::spread_addr(cli.source_ips.min(turn_client::SPREAD_MAX))
        );
    }

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
    if let Some(pid) = cli.server_pid {
        let _ = procfs::TARGET.set(procfs::Target {
            pid,
            clk_tck: cli.clk_tck,
        });
        if procfs::sample().is_none() {
            eprintln!(
                "--server-pid {pid}: /proc/{pid} is not readable here (not Linux, wrong PID, \
                 or another PID namespace); server CPU/RSS fields will be null"
            );
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
            // Credentials must outlive warmup, the measured run and teardown.
            ttl_s: cli.duration.saturating_add(cli.warmup).saturating_add(3600),
        }
    };

    #[cfg(any(
        feature = "quic",
        feature = "web-transport",
        all(feature = "sctp", target_os = "linux")
    ))]
    if let Mode::TransportNetwork {
        transport,
        peer,
        pps,
    } = &cli.mode
    {
        let result = tokio::time::timeout(
            Duration::from_secs(cli.duration.saturating_add(30)),
            transport_probe::network(transport, cli.server, &creds, *peer, cli.duration, *pps),
        )
        .await;
        match result {
            Ok(Ok(())) => std::process::exit(0),
            other => {
                eprintln!("transport-network failed: {other:?}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(any(
        feature = "quic",
        feature = "web-transport",
        all(feature = "sctp", target_os = "linux")
    ))]
    if let Mode::TransportProbe {
        transport,
        action,
        hold_secs,
    } = &cli.mode
    {
        let result = tokio::time::timeout(
            Duration::from_secs(hold_secs.saturating_add(25)),
            transport_probe::run(transport, cli.server, &creds, action, *hold_secs),
        )
        .await;
        match result {
            Ok(Ok(())) => std::process::exit(0),
            other => {
                eprintln!("transport-probe failed: {other:?}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(all(feature = "sctp", target_os = "linux"))]
    if let Mode::SctpCheck = &cli.mode {
        match sctp_client::check(cli.server, &creds, cli.rtt_timeout_ms).await {
            Ok(steps) => {
                for s in steps {
                    println!("  ok   {s}");
                }
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("sctp-check: FAIL: {e}");
                std::process::exit(1);
            }
        }
    }

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
                println!(
                    "Relayed media verified in both directions; this is not an endurance test."
                );
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

    if let Mode::Hold {
        allocations,
        parallel,
        settle,
        channel,
    } = cli.mode
    {
        let report = run_hold(
            cli.server,
            &creds,
            HoldParams {
                allocations,
                parallel,
                settle: Duration::from_secs(settle.min(200)),
                channel,
                rtt_ms: cli.rtt_timeout_ms,
            },
        )
        .await;
        if cli.json {
            println!("{}", report.to_json(&cli.label));
        } else {
            report.print_report();
        }
        std::process::exit(if report.established == 0 { 1 } else { 0 });
    }

    let stats = match cli.mode {
        Mode::Binding {
            concurrency,
            sockets_per_task,
        } => {
            if !cli.json {
                eprintln!(
                    "Mode: STUN Binding (c={concurrency}, {sockets_per_task} socket(s)/task)"
                );
            }
            run_binding(cli.server, concurrency, sockets_per_task, dur, wu, cli.json).await
        }
        Mode::ReconnectStorm {
            clients,
            rounds,
            settle,
            recover_timeout,
        } => {
            if !cli.json && turn_client::SOURCE_SPREAD.get().is_none() {
                eprintln!(
                    "warning: no --source-ips, so every client shares 127.0.0.1 and this                      measures the per-IP allocate limiter (32/s, burst 16) rather than the                      server. Deliberate? Then this is the everyone-behind-one-NAT case."
                );
            }
            run_reconnect_storm(
                cli.server,
                creds,
                StormParams {
                    clients,
                    rounds,
                    settle,
                    recover_timeout,
                    rtt_ms: cli.rtt_timeout_ms,
                },
                cli.json,
            )
            .await;
            // Exit here rather than returning an empty Stats: the summary printer
            // below would render a table of zeros under the storm's own report,
            // and a reader would have to know that "Errors: 0" refers to frames
            // this mode never sends. A report that has to be explained away is
            // worse than no report.
            std::process::exit(0);
        }
        Mode::Allocate { concurrency, fresh } => {
            if !cli.json {
                eprintln!(
                    "Mode: Allocate (c={concurrency}, {})",
                    if fresh {
                        "fresh client per cycle: 401 → Allocate → Refresh(0)"
                    } else {
                        "challenge once per worker, then Allocate → Refresh(0)"
                    }
                );
            }
            run_allocate(
                cli.server,
                concurrency,
                dur,
                wu,
                cli.json,
                creds,
                cli.rtt_timeout_ms,
                fresh,
            )
            .await
        }
        Mode::Hold { .. } => unreachable!("handled above"),
        #[cfg(any(
            feature = "quic",
            feature = "web-transport",
            all(feature = "sctp", target_os = "linux")
        ))]
        Mode::TransportProbe { .. } | Mode::TransportNetwork { .. } => {
            unreachable!("handled above")
        }
        #[cfg(all(feature = "sctp", target_os = "linux"))]
        Mode::SctpCheck => unreachable!("handled above"),
        #[cfg(all(feature = "sctp", target_os = "linux"))]
        Mode::Sctp {
            concurrency,
            pps,
            payload,
        } => {
            sctp_client::load(
                cli.server,
                creds,
                cli.rtt_timeout_ms,
                concurrency,
                pps,
                payload,
                dur,
                wu,
                cli.json,
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

    /// The window ends at `stop()`, not when the snapshot is taken after
    /// teardown, and starts at `begin_window()`, not at construction.
    #[test]
    fn window_runs_from_begin_to_stop_not_to_snapshot() {
        let s = Stats::new();
        std::thread::sleep(Duration::from_millis(60)); // "setup" — excluded
        s.begin_window();
        std::thread::sleep(Duration::from_millis(100)); // measured
        s.sent.store(1000, Ordering::Relaxed);
        s.recv.store(1000, Ordering::Relaxed);
        s.stop();
        std::thread::sleep(Duration::from_millis(150)); // "teardown" — excluded
        let snap = s.snapshot("x", "channeldata");
        assert!(
            (0.09..0.15).contains(&snap.duration_s),
            "window {} s should be ~0.1 s",
            snap.duration_s
        );
        // Rate over the window, not over window + teardown.
        assert!(snap.rps > 6_000.0, "rps {}", snap.rps);
        // A second stop must not move the end.
        let before = s.window_secs();
        std::thread::sleep(Duration::from_millis(20));
        s.stop();
        assert_eq!(s.window_secs(), before);
    }

    #[test]
    fn open_window_reads_up_to_now() {
        let s = Stats::new();
        s.begin_window();
        std::thread::sleep(Duration::from_millis(30));
        let a = s.window_secs();
        std::thread::sleep(Duration::from_millis(30));
        assert!(s.window_secs() > a, "an open window keeps growing");
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
