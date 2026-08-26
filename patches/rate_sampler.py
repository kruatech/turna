#!/usr/bin/env python3
"""
Rate sampler — the piece three separate requirements were waiting on.

`/capacity` reports `bandwidth_rate: false` and `packet_rate: false`; §4 asks for
bandwidth and pps saturation alerts; capacity-aware admission control needs load,
not counts. All three want the same thing: bytes and packets *per second*, inside
the process.

Prometheus computes `rate()` from the cumulative counters already, so this is not
for dashboards. It is for decisions the node makes about itself, which cannot
wait for a scrape.

WINDOW: 10 SECONDS, SAMPLED EVERY SECOND

Short enough to notice real saturation before the egress queue starts dropping,
long enough that one burst does not flip a node to SATURATED and send its callers
elsewhere. A single-sample rate would do the latter: relayed media is bursty by
nature, and a node that reports saturation on every keyframe is worse than one
that reports nothing.

Ten one-second buckets in a ring, so the reported rate is the mean over the last
ten seconds. No allocation after construction, no lock on the read path — the
capacity endpoint calls it and must stay cheap enough for per-placement use.

WHAT IT DOES NOT SOLVE

CPU and memory pressure, also asked for by §4, are not here: they need a host
source, and the heartbeat path already has `sysinfo` wired for exactly that.
Bringing it into `Metrics` is a separate, smaller change — kept separate so this
one can be reviewed on its own.

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


health = pathlib.Path("crates/health/src/lib.rs")
if not health.exists():
    die("crates/health/src/lib.rs not found — run from the repository root")
if "RateSampler" in health.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. The sampler itself, next to the capacity types that consume it.
# ---------------------------------------------------------------------------
s = health.read_text()
anchor = "/// Capacity state, in the vocabulary the enterprise spec asks for."
if s.count(anchor) != 1:
    die("could not find the capacity types to anchor the sampler")

sampler = '''/// Bytes and packets per second, averaged over a sliding ten-second window.
///
/// The cumulative counters answer "how much since start"; a node deciding
/// whether it is saturated needs "how much right now", and cannot wait for a
/// Prometheus scrape to tell it.
///
/// Ten one-second buckets in a fixed ring. `tick()` is called once a second by a
/// task in the node; the read path is three atomic loads and no lock, because
/// `/capacity` calls it and is meant to be cheap enough to call before every
/// session placement.
///
/// **Why ten seconds.** Short enough to catch saturation before the egress queue
/// begins dropping; long enough that one burst does not flip the node to
/// SATURATED and divert its callers. Relayed media is bursty — a rate computed
/// from a single sample would report saturation on every keyframe, which is a
/// worse failure than reporting nothing at all.
pub struct RateSampler {
    /// Per-bucket deltas. Index `pos % WINDOW` is the bucket being filled.
    bytes_buckets: [AtomicU64; Self::WINDOW],
    packets_buckets: [AtomicU64; Self::WINDOW],
    /// Counter values at the last tick, for computing the delta.
    last_bytes: AtomicU64,
    last_packets: AtomicU64,
    /// Ticks since start. Doubles as the ring position and as the "have we
    /// filled the window yet" test — before `WINDOW` ticks the mean would be
    /// divided by buckets that were never written.
    ticks: AtomicU64,
}

impl Default for RateSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl RateSampler {
    const WINDOW: usize = 10;

    pub fn new() -> Self {
        Self {
            bytes_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            packets_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            last_bytes: AtomicU64::new(0),
            last_packets: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
        }
    }

    /// Record one second's worth of traffic. Called once a second.
    ///
    /// `total_bytes` and `total_packets` are the cumulative counters; the delta
    /// against the previous tick becomes this bucket. `saturating_sub` because a
    /// counter that appears to go backwards (it should not, but a reordered
    /// relaxed load could) must produce zero rather than a vast number that
    /// reads as saturation.
    pub fn tick(&self, total_bytes: u64, total_packets: u64) {
        let n = self.ticks.fetch_add(1, Ordering::Relaxed) as usize;
        let slot = n % Self::WINDOW;

        let prev_b = self.last_bytes.swap(total_bytes, Ordering::Relaxed);
        let prev_p = self.last_packets.swap(total_packets, Ordering::Relaxed);

        self.bytes_buckets[slot].store(total_bytes.saturating_sub(prev_b), Ordering::Relaxed);
        self.packets_buckets[slot].store(total_packets.saturating_sub(prev_p), Ordering::Relaxed);
    }

    /// Mean bytes/second over the window, or `None` until the window has filled.
    ///
    /// `None` rather than a partial mean on purpose: a rate averaged over three
    /// buckets when ten are expected understates by more than two thirds, and a
    /// node that under-reports its load during the first ten seconds after start
    /// is a node that accepts work it cannot serve. The caller decides what to do
    /// with "not yet known" — `/capacity` reports the signal as unavailable
    /// rather than guessing.
    pub fn bytes_per_sec(&self) -> Option<u64> {
        self.mean(&self.bytes_buckets)
    }

    /// Mean packets/second over the window, or `None` until it has filled.
    pub fn packets_per_sec(&self) -> Option<u64> {
        self.mean(&self.packets_buckets)
    }

    fn mean(&self, buckets: &[AtomicU64; Self::WINDOW]) -> Option<u64> {
        if (self.ticks.load(Ordering::Relaxed) as usize) < Self::WINDOW {
            return None;
        }
        let sum: u64 = buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .fold(0u64, |a, b| a.saturating_add(b));
        Some(sum / Self::WINDOW as u64)
    }

    /// Seconds of history collected, capped at the window size. For diagnostics
    /// and for a caller wanting to know how much to trust a fresh reading.
    pub fn samples(&self) -> usize {
        (self.ticks.load(Ordering::Relaxed) as usize).min(Self::WINDOW)
    }
}

'''

health.write_text(s.replace(anchor, sampler + anchor, 1))
print("  ok  lib.rs: RateSampler")

# ---------------------------------------------------------------------------
# 2. Hang one off Metrics and expose the rates.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "sampler field",
            """    pub relay_ports_in_use: AtomicU64,""",
            """    /// Relayed traffic rate over the last ten seconds. Fed by a one-second
            /// ticker in the node; read by `/capacity` and, later, by admission
            /// control.
    pub rates: RateSampler,

    pub relay_ports_in_use: AtomicU64,""",
        ),
        (
            "sampler init",
            """            relay_ports_in_use: AtomicU64::new(0),""",
            """            rates: RateSampler::new(),
            relay_ports_in_use: AtomicU64::new(0),""",
        ),
        (
            "capacity signals",
            """                bandwidth_rate: false,
                packet_rate: false,""",
            """                bandwidth_rate: self.rates.bytes_per_sec().is_some(),
                packet_rate: self.rates.packets_per_sec().is_some(),""",
        ),
        (
            "capacity response fields",
            """    ready: bool,
    draining: bool,""",
            """    ready: bool,
    draining: bool,
    /// Relayed bytes/second over the last ten seconds. `null` until the window
    /// has filled — a partial mean would understate the load, and a node that
    /// under-reports during its first ten seconds accepts work it cannot serve.
    bytes_per_sec: Option<u64>,
    /// Relayed packets/second over the last ten seconds. `null` on the same terms.
    packets_per_sec: Option<u64>,""",
        ),
        (
            "capacity response construction",
            """            ready,
            draining,
            signals: CapacitySignals {""",
            """            ready,
            draining,
            bytes_per_sec: self.rates.bytes_per_sec(),
            packets_per_sec: self.rates.packets_per_sec(),
            signals: CapacitySignals {""",
        ),
    ],
)

print()
print("applied to crates/health. The ticker goes in services/node, beside the")
print("relay-port one already there. Send its surroundings:")
print()
print("  grep -n 'relay_ports_in_use.store' -B 12 services/node/src/main.rs")
print()
print("Note the state machine does NOT use the rates yet — the signals and the")
print("numbers are exposed, the verdict still weighs allocations only. Turning a")
print("rate into a threshold needs a capacity figure to compare against, which is")
print("the hardware-profile item, so wiring it now would mean inventing a limit.")
