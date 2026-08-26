#!/usr/bin/env python3
"""
CPU and memory pressure in `/capacity` — the last two `false` entries in its
`signals` object.

TWO PROBLEMS WITH WHERE THIS DATA LIVES TODAY

First, it is only collected when a cluster backend is configured: `sample_resources`
runs inside the heartbeat loop, and a standalone node never calls it. So the two
signals a capacity decision most wants are absent exactly when there is no cluster
to ask instead.

Second, `sample_resources` builds a fresh `System` on every tick. CPU usage in
sysinfo is a delta between two refreshes, so a newly-created instance has nothing
to compare against and relies on the library's internal minimum-interval sleep —
which the existing comment acknowledges ("sleeps for MINIMUM_CPU_UPDATE_INTERVAL").
That yields a reading over ~100 ms rather than over the interval, which is a
different measurement: a node busy in bursts reads low if the sample lands between
them.

WHAT THIS DOES

One long-lived `System` in a sampler task that always runs, refreshed every five
seconds, storing into `Metrics`. CPU usage then covers the whole five seconds
rather than a 100 ms sliver.

Heartbeat reads the stored values instead of sampling again — one sampler, two
consumers, and no second `/proc` reader on a node whose job is to measure its own
load.

Percentages are stored as whole numbers. Thresholds do not need decimals, and an
integer avoids a float in an atomic.

STILL NOT A THRESHOLD

`/capacity` will report CPU and memory and set the signals true; the state
continues to weigh allocations only. Same reason as the rate sampler: a threshold
needs a figure to compare against, and what counts as "too busy" for this
workload has not been measured. Reporting an input is honest; acting on an
invented limit is not.

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
if "host_cpu_percent" in health.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. Somewhere to put them.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "host fields",
            """    pub rates: RateSampler,""",
            """    pub rates: RateSampler,

    /// Host CPU and memory, whole percent, refreshed every five seconds by a
    /// sampler task in the node.
    ///
    /// `u64::MAX` means "never sampled" — distinct from 0, which is a real and
    /// unremarkable reading. Without that distinction a node whose sampler had
    /// died would look idle, which is the worst possible way to be wrong about
    /// load.
    pub host_cpu_percent: AtomicU64,
    pub host_memory_percent: AtomicU64,""",
        ),
        (
            "host init",
            """            rates: RateSampler::new(),""",
            """            rates: RateSampler::new(),
            host_cpu_percent: AtomicU64::new(u64::MAX),
            host_memory_percent: AtomicU64::new(u64::MAX),""",
        ),
        (
            "host accessors",
            """    /// Publish the node's capacity limits. Called once at startup.""",
            """    /// Store a host CPU and memory sample, whole percent.
    pub fn set_host_load(&self, cpu_percent: u64, memory_percent: u64) {
        self.host_cpu_percent
            .store(cpu_percent.min(100), Ordering::Relaxed);
        self.host_memory_percent
            .store(memory_percent.min(100), Ordering::Relaxed);
    }

    /// Host CPU percent, or `None` if no sample has been taken yet.
    pub fn host_cpu(&self) -> Option<u64> {
        match self.host_cpu_percent.load(Ordering::Relaxed) {
            u64::MAX => None,
            v => Some(v),
        }
    }

    /// Host memory percent, or `None` if no sample has been taken yet.
    pub fn host_memory(&self) -> Option<u64> {
        match self.host_memory_percent.load(Ordering::Relaxed) {
            u64::MAX => None,
            v => Some(v),
        }
    }

    /// Publish the node's capacity limits. Called once at startup.""",
        ),
        (
            "capacity fields",
            """    /// Relayed packets/second over the last ten seconds. `null` on the same terms.
    packets_per_sec: Option<u64>,""",
            """    /// Relayed packets/second over the last ten seconds. `null` on the same terms.
    packets_per_sec: Option<u64>,
    /// Host CPU, whole percent. `null` until the first sample.
    cpu_percent: Option<u64>,
    /// Host memory in use, whole percent. `null` until the first sample.
    memory_percent: Option<u64>,""",
        ),
        (
            "capacity construction",
            """            bytes_per_sec: self.rates.bytes_per_sec(),
            packets_per_sec: self.rates.packets_per_sec(),""",
            """            bytes_per_sec: self.rates.bytes_per_sec(),
            packets_per_sec: self.rates.packets_per_sec(),
            cpu_percent: self.host_cpu(),
            memory_percent: self.host_memory(),""",
        ),
        (
            "capacity signals",
            """                cpu: false,
                memory: false,""",
            """                cpu: self.host_cpu().is_some(),
                memory: self.host_memory().is_some(),""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. One sampler, in the node, always running.
# ---------------------------------------------------------------------------
patch(
    "services/node/src/main.rs",
    [
        (
            "host sampler",
            """            // Relayed traffic rate, sampled once a second.""",
            """            // Host CPU and memory, every five seconds.
            //
            // A single long-lived `System`, refreshed in place. CPU usage in
            // sysinfo is a delta between refreshes, so a persistent instance
            // reports the load over the whole interval; building a fresh one each
            // tick — which `heartbeat::sample_resources` did — measures only the
            // library's internal ~100 ms settling window, and a node busy in
            // bursts reads low if the sample falls between them.
            //
            // Runs regardless of whether a cluster backend is configured. The
            // previous arrangement collected this only inside the heartbeat loop,
            // so a standalone node had no CPU or memory reading at all — the two
            // signals a capacity decision most wants, missing exactly where there
            // is no cluster to ask instead.
            {
                let metrics = metrics.clone();
                tokio::task::spawn_blocking(move || {
                    use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
                    let mut sys = System::new_with_specifics(
                        RefreshKind::nothing()
                            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                            .with_memory(MemoryRefreshKind::nothing().with_ram()),
                    );
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(5));
                        sys.refresh_cpu_usage();
                        sys.refresh_memory();
                        let cpu = sys.global_cpu_usage().round() as u64;
                        let mem = if sys.total_memory() > 0 {
                            ((sys.used_memory() as f64 / sys.total_memory() as f64) * 100.0)
                                .round() as u64
                        } else {
                            0
                        };
                        metrics.set_host_load(cpu, mem);
                    }
                });
            }

            // Relayed traffic rate, sampled once a second.""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 3. Heartbeat reads the sample instead of taking its own.
# ---------------------------------------------------------------------------
patch(
    "services/node/src/heartbeat.rs",
    [
        (
            "read the shared sample",
            """                // ── CPU + memory (blocking, runs in a short thread) ──────────
                // sample_resources sleeps for MINIMUM_CPU_UPDATE_INTERVAL
                // (~100ms) — spawn_blocking so we don't block the async runtime.
                let (cpu_pct, mem_pct) = tokio::task::spawn_blocking(sample_resources)
                    .await
                    .unwrap_or((0.0, 0.0));""",
            """                // ── CPU + memory ─────────────────────────────────────────────
                // Read from the shared sampler rather than taking our own: it
                // keeps a persistent `System` and so measures CPU over its whole
                // interval, where a fresh instance per tick only sees the
                // library's ~100 ms settling window. It also means one /proc
                // reader on a node whose job includes measuring its own load.
                //
                // 0.0 before the first sample lands. The heartbeat is periodic and
                // the next one will carry a real figure; reporting 0 once is
                // better than blocking a heartbeat on a resource read.
                let cpu_pct = metrics.host_cpu().unwrap_or(0) as f32;
                let mem_pct = metrics.host_memory().unwrap_or(0) as f32;""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 4. Remove what now has no callers.
#
# Deleted rather than left with an #[allow(dead_code)]: a suppression here would
# hide the next function that genuinely stops being used, which is the trade this
# project already made once and regretted.
# ---------------------------------------------------------------------------
patch(
    "services/node/src/heartbeat.rs",
    [
        (
            "drop sample_resources",
            """/// Collect current CPU and memory usage via sysinfo.
/// Creates a fresh `System` each tick — lightweight enough at 5s interval.
fn sample_resources() -> (f32, f32) {
    let sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
            .with_memory(MemoryRefreshKind::nothing().with_ram()),
    );

    let cpu_pct = sys.global_cpu_usage();
    let mem_pct = if sys.total_memory() > 0 {
        (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0
    } else {
        0.0f32
    };
    (cpu_pct, mem_pct)
}
""",
            "",
        ),
        (
            "drop the sysinfo import",
            """use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
""",
            "",
        ),
    ],
)

print()
print("applied. Verify:")
print("  cargo clippy -p turna-health -p turna-node --all-targets -- -D warnings")
print()
print("If clippy reports sysinfo as an unused dependency of services/node, leave")
print("it: the sampler in main.rs uses it now, just from a different module.")
