#!/usr/bin/env python3
"""
Capacity API, first version — §4 and §13 of the enterprise spec.

The spec asks for a versioned endpoint returning current and maximum capacity,
load state, and reasons for unavailability, with at least the states AVAILABLE,
DEGRADED, DRAINING, SATURATED and UNAVAILABLE. This adds `GET /capacity`.

WHO IT IS FOR
-------------
The upper Conference product, asking "can this node take a call" before placing
one. That choice of consumer shapes everything: the response is per-node, cheap
enough to call per placement, and returns the raw numbers alongside the state so
the caller can apply its own policy instead of trusting ours. Cluster-wide
selection stays with `/cluster`, which already returns the ring.

If the real consumer turns out to be a load balancer polling on an interval, or
the cluster distributing internally, this is the wrong shape and should be
changed before anything binds to it. The decision is recorded rather than
implied so it can be argued with.

WHAT THE STATE IS ACTUALLY BASED ON
-----------------------------------
Only signals this process can observe right now:

  active allocations vs `[turn.relay] max_allocations`   — a count
  send-queue drops                                        — back-pressure
  readiness and drain flags                               — lifecycle

The spec also asks admission to weigh bps, pps, CPU and memory pressure. Those
are deliberately absent here, and the response says so in a `signals` field
rather than leaving a caller to assume a richer state than exists. Byte and
packet counters exist but are cumulative; turning them into a rate needs a
background sampler, and CPU and memory need a source this crate does not have.
A state label that implied it had weighed CPU while it had not would be the same
class of untruth as the health port that reported Ready while bound to nothing.

Capacity-aware *admission* — actually refusing an Allocate — is a separate item
in §4 and lives on the relay path, not here. This endpoint reports; it does not
enforce.

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
if "CapacityResponse" in health.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. Limits live on Metrics so the endpoint needs no new constructor argument.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "capacity limit fields",
            """    pub active_allocations: AtomicU64,
    pub total_allocations: AtomicU64,""",
            """    pub active_allocations: AtomicU64,
    pub total_allocations: AtomicU64,

    // Capacity limits, published by the node at startup rather than read from
    // config here: this crate has no view of config, and threading it in would
    // mean changing `serve_*`'s signature for the third time this week.
    //
    // `capacity_max_allocations == 0` means "not published", which is reported as
    // UNAVAILABLE rather than as unlimited headroom. An unset limit read as
    // infinite capacity is exactly the kind of default that puts a node into
    // service claiming room it does not have.
    pub capacity_max_allocations: AtomicU64,
    pub capacity_soft_percent: AtomicU64,
    pub capacity_hard_percent: AtomicU64,""",
        ),
        (
            "capacity limit init",
            """            active_allocations: AtomicU64::new(0),
            total_allocations: AtomicU64::new(0),""",
            """            active_allocations: AtomicU64::new(0),
            total_allocations: AtomicU64::new(0),
            capacity_max_allocations: AtomicU64::new(0),
            capacity_soft_percent: AtomicU64::new(75),
            capacity_hard_percent: AtomicU64::new(95),""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. The response type and the state machine.
# ---------------------------------------------------------------------------
s = health.read_text()
anchor = "struct StatusResponse {"
if s.count(anchor) != 1:
    die("could not find StatusResponse to anchor the capacity types")

capacity = '''/// Capacity state, in the vocabulary the enterprise spec asks for.
///
/// Ordered by decreasing willingness to take work, which is also the order the
/// checks run in: the first that matches wins, so DRAINING beats SATURATED and a
/// node that is both reports the one that will not change on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CapacityState {
    /// Accepting work with headroom.
    Available,
    /// Accepting work, but past the soft threshold or with a degraded
    /// dependency. A caller with a choice should choose elsewhere.
    Degraded,
    /// Shutting down. Will not take new work and existing work is being wound
    /// down. Distinct from SATURATED because it does not recover.
    Draining,
    /// At or past the hard threshold, or shedding. New work will suffer.
    Saturated,
    /// Not able to serve: startup incomplete, or no capacity limit published so
    /// there is nothing to reason about.
    Unavailable,
}

/// `GET /capacity` — per-node capacity, for a caller deciding where to place a
/// session.
///
/// Both the state and the numbers behind it are returned. The state is our
/// opinion; the numbers let a caller form its own, which matters because the
/// thresholds here are generic and a deployment's real limit is usually
/// something else — bandwidth on a shared uplink, or a licence count.
#[derive(Debug, serde::Serialize)]
struct CapacityResponse {
    /// Response schema version. Increment on any change that is not additive.
    version: u32,
    state: CapacityState,
    /// Why, in a form worth logging. Empty when AVAILABLE.
    reasons: Vec<&'static str>,
    active_allocations: u64,
    max_allocations: u64,
    /// Percent of `max_allocations` in use. 100 when the limit is unpublished,
    /// pairing with UNAVAILABLE rather than reading as empty.
    utilization_percent: u64,
    soft_threshold_percent: u64,
    hard_threshold_percent: u64,
    ready: bool,
    draining: bool,
    /// Which inputs this state actually weighed.
    ///
    /// Present so a caller is not left to assume the state considered load it
    /// could not see. The spec asks for bps, pps, CPU and memory pressure in
    /// admission decisions; none of those is here yet, and saying so in the
    /// response is cheaper than a caller discovering it during an incident.
    signals: CapacitySignals,
}

#[derive(Debug, serde::Serialize)]
struct CapacitySignals {
    allocations: bool,
    send_queue_pressure: bool,
    readiness: bool,
    /// Rate of bytes relayed. Counters exist; a rate needs a sampler.
    bandwidth_rate: bool,
    /// Rate of packets relayed. Same.
    packet_rate: bool,
    /// Host CPU load. No source in this crate.
    cpu: bool,
    /// Host memory pressure. No source in this crate.
    memory: bool,
}

impl Metrics {
    /// Publish the node's capacity limits. Called once at startup.
    ///
    /// Until this is called, `/capacity` reports UNAVAILABLE: a node that does
    /// not know its own ceiling cannot honestly claim headroom.
    pub fn set_capacity_limits(&self, max_allocations: u64, soft_percent: u64, hard_percent: u64) {
        self.capacity_max_allocations
            .store(max_allocations, Ordering::SeqCst);
        self.capacity_soft_percent
            .store(soft_percent.min(100), Ordering::SeqCst);
        self.capacity_hard_percent
            .store(hard_percent.min(100), Ordering::SeqCst);
    }

    fn capacity(&self) -> CapacityResponse {
        let max = self.capacity_max_allocations.load(Ordering::Relaxed);
        let active = self.active_allocations.load(Ordering::Relaxed);
        let soft = self.capacity_soft_percent.load(Ordering::Relaxed);
        let hard = self.capacity_hard_percent.load(Ordering::Relaxed);
        let draining = self.is_draining();
        let ready = self.is_ready();
        // Any drop means the egress queue has already overflowed at least once.
        // Treated as saturation rather than degradation: by the time a frame is
        // dropped the damage is done, and a caller placing more work on this
        // node makes it worse.
        let shedding = self.send_queue_dropped.load(Ordering::Relaxed) > 0;

        let utilization = if max == 0 {
            100
        } else {
            (active.saturating_mul(100) / max).min(100)
        };

        let mut reasons: Vec<&'static str> = Vec::new();
        let state = if draining {
            reasons.push("node is draining");
            CapacityState::Draining
        } else if !ready {
            reasons.push("node is not ready");
            CapacityState::Unavailable
        } else if max == 0 {
            reasons.push("no capacity limit published; cannot reason about headroom");
            CapacityState::Unavailable
        } else if utilization >= hard {
            reasons.push("allocations at or above the hard threshold");
            CapacityState::Saturated
        } else if shedding {
            reasons.push("send queue has dropped frames");
            CapacityState::Saturated
        } else if utilization >= soft {
            reasons.push("allocations at or above the soft threshold");
            CapacityState::Degraded
        } else if self.readiness() == Readiness::Degraded {
            reasons.push("a listener or backend reports degraded");
            CapacityState::Degraded
        } else {
            CapacityState::Available
        };

        CapacityResponse {
            version: 1,
            state,
            reasons,
            active_allocations: active,
            max_allocations: max,
            utilization_percent: utilization,
            soft_threshold_percent: soft,
            hard_threshold_percent: hard,
            ready,
            draining,
            signals: CapacitySignals {
                allocations: true,
                send_queue_pressure: true,
                readiness: true,
                bandwidth_rate: false,
                packet_rate: false,
                cpu: false,
                memory: false,
            },
        }
    }
}

'''

health.write_text(s.replace(anchor, capacity + anchor, 1))
print("  ok  lib.rs: capacity types and state machine")

# ---------------------------------------------------------------------------
# 3. Route it.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "capacity route",
            """                "/health" => {
                    if metrics.is_draining() {""",
            """                "/capacity" => {
                    // 200 in every state, including SATURATED and UNAVAILABLE:
                    // the body carries the state, and a caller asking "can you
                    // take this" needs an answer rather than an error it has to
                    // interpret. `/ready` remains the endpoint that speaks in
                    // status codes for load balancers.
                    let cap = metrics.capacity();
                    (
                        "200 OK",
                        serde_json::to_string(&cap).unwrap_or_else(|_| "{}".into()),
                        "application/json",
                    )
                }
                "/health" => {
                    if metrics.is_draining() {""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 4. Publish the limits at startup.
#
# Placed immediately after Metrics is constructed rather than later: between the
# two, /capacity answers UNAVAILABLE, and the shorter that window the better.
# ---------------------------------------------------------------------------
patch(
    "services/node/src/main.rs",
    [
        (
            "publish capacity limits",
            """    let metrics = Arc::new(Metrics::new());""",
            """    let metrics = Arc::new(Metrics::new());

    // Publish the node's own ceiling so `/capacity` has something to reason
    // about. Until this runs, that endpoint reports UNAVAILABLE — a node that
    // does not know its limit must not advertise headroom, because an unset
    // limit read as "unlimited" is how a node gets sent work it cannot take.
    //
    // The thresholds are percentages of `max_allocations`, which is the only
    // ceiling this process actually enforces. A deployment's real constraint is
    // often something else — uplink bandwidth, a licence count — which is why
    // `/capacity` returns the raw numbers next to the state rather than only a
    // verdict.
    metrics.set_capacity_limits(config.relay.max_allocations as u64, 75, 95);"""
        ),
    ],
)

print()
print("applied. Remaining, and worth doing in the same change:")
print()
print("  docs/MANAGEMENT_API.md — document GET /capacity and its five states")
print("  docs/roadmap/enterprise-gap-2026-08-26.md — Capacity API moves from")
print("    'build' to 'partial': the endpoint exists, the load signals do not")
print()
print("Verify:")
print("  cargo clippy -p turna-health -p turna-node --all-targets -- -D warnings")
print("  cargo build -p turna-node && target/debug/turna-node --dump-config <cfg>")
print()
print("Then see it answer, which is the part that matters:")
print("  curl -s localhost:9090/capacity | python3 -m json.tool")
