#!/usr/bin/env python3
"""
Relay port exhaustion — a §4 P0, and currently a blind spot.

The relay range is bounded by `[turn.relay] min_port`/`max_port`, and
`config::validate()` warns when `max_allocations` exceeds half the usable ports.
But nothing reports how full the range is at runtime: it fills silently, and the
first sign is `Allocate` starting to fail with 508. On a range sized for the
allocation cap that is fine; on one shared with the ephemeral range, or with
EVEN-PORT reservations in play, it is not.

The gap was found while looking for `turna_relay_ports_in_use` during a 24-hour
soak and discovering the series did not exist.

WHAT THIS ADDS

  PortAllocator::in_use() / capacity()   — the numbers, from the HashSet that
                                           already tracks them
  AllocationStore::port_pool_usage()     — global plus per-tenant, following
                                           the shape of tenant_traffic_snapshot
  turna_relay_ports_in_use / _total      — gauges
  turna_relay_ports_utilization_percent  — the number an alert actually wants

Per-tenant pools are summed into the global gauges rather than exported with a
tenant label. Labels are how a Prometheus instance dies when a customer has ten
thousand tenants, and §10 asks for cardinality protection in the same
specification that asks for this metric. The per-tenant detail is available from
`port_pool_usage()` for anything that needs it — the management API, a support
bundle — without every scrape paying for it.

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


sess = pathlib.Path("crates/session/src/lib.rs")
if not sess.exists():
    die("crates/session/src/lib.rs not found — run from the repository root")
if "port_pool_usage" in sess.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. The numbers, on the allocator that already has them.
# ---------------------------------------------------------------------------
patch(
    "crates/session/src/lib.rs",
    [
        (
            "allocator accessors",
            """    /// True if the port is currently held by a live allocation.
    pub fn is_allocated(&self, port: u16) -> bool {
        self.used.lock().contains(&port)
    }""",
            """    /// True if the port is currently held by a live allocation.
    pub fn is_allocated(&self, port: u16) -> bool {
        self.used.lock().contains(&port)
    }

    /// Ports currently held, including those held by an unclaimed EVEN-PORT
    /// reservation — a reserved port is unavailable to anyone else, so counting
    /// it as free would understate how full the pool is.
    pub fn in_use(&self) -> usize {
        self.used.lock().len()
    }

    /// Total ports in this pool's range, inclusive of both bounds.
    pub fn capacity(&self) -> usize {
        (self.max_port as usize).saturating_sub(self.min_port as usize) + 1
    }""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. A snapshot across the global pool and any tenant pools.
# ---------------------------------------------------------------------------
s = sess.read_text()
anchor = "    pub fn tenant_traffic_snapshot(&self)"
if s.count(anchor) != 1:
    die("could not find tenant_traffic_snapshot to anchor the new snapshot")

snapshot = '''    /// Relay port usage: `(pool_name, in_use, capacity)` for the global pool and
    /// each tenant pool.
    ///
    /// Shaped like [`Self::tenant_traffic_snapshot`] deliberately — a second
    /// snapshot method with a different convention is how a codebase acquires
    /// two ways to ask the same question.
    ///
    /// The global pool is named `"global"`; tenant pools carry their tenant id.
    /// Ranges are disjoint by config validation, so the sums do not double-count.
    pub fn port_pool_usage(&self) -> Vec<(String, usize, usize)> {
        let mut out = Vec::with_capacity(1 + self.tenant_pools.len());
        out.push((
            "global".to_string(),
            self.ports.in_use(),
            self.ports.capacity(),
        ));
        for t in &self.tenant_pools {
            out.push((t.id.clone(), t.ports.in_use(), t.ports.capacity()));
        }
        out
    }

'''
sess.write_text(s.replace(anchor, snapshot + anchor, 1))
print("  ok  lib.rs: port_pool_usage snapshot")

# ---------------------------------------------------------------------------
# 3. Metrics fields.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "relay port fields",
            """    pub capacity_max_allocations: AtomicU64,""",
            """    // Relay port pool occupancy, summed across the global pool and any
    // tenant pools. Summed rather than labelled per tenant: labels are how a
    // Prometheus instance dies when a customer has ten thousand tenants, and
    // §10 asks for cardinality protection in the same specification that asks
    // for this metric. Per-tenant detail: AllocationStore::port_pool_usage().
    pub relay_ports_in_use: AtomicU64,
    pub relay_ports_total: AtomicU64,

    pub capacity_max_allocations: AtomicU64,""",
        ),
        (
            "relay port init",
            """            capacity_max_allocations: AtomicU64::new(0),""",
            """            relay_ports_in_use: AtomicU64::new(0),
            relay_ports_total: AtomicU64::new(0),
            capacity_max_allocations: AtomicU64::new(0),""",
        ),
        (
            "relay port render",
            """             turna_sctp_readiness {}\\n\\""",
            """             turna_sctp_readiness {}\\n\\
             # HELP turna_relay_ports_in_use Relay ports currently held by an allocation or an unclaimed EVEN-PORT reservation\\n\\
             # TYPE turna_relay_ports_in_use gauge\\n\\
             turna_relay_ports_in_use {}\\n\\
             # HELP turna_relay_ports_total Relay ports configured across the global pool and any tenant pools\\n\\
             # TYPE turna_relay_ports_total gauge\\n\\
             turna_relay_ports_total {}\\n\\
             # HELP turna_relay_ports_utilization_percent Percent of the relay port range in use\\n\\
             # TYPE turna_relay_ports_utilization_percent gauge\\n\\
             turna_relay_ports_utilization_percent {}\\n\\""",
        ),
        (
            "relay port args",
            """            self.sctp_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,""",
            """            self.sctp_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            l(&self.relay_ports_in_use),
            l(&self.relay_ports_total),
            {
                let total = self.relay_ports_total.load(std::sync::atomic::Ordering::Relaxed);
                let used = self.relay_ports_in_use.load(std::sync::atomic::Ordering::Relaxed);
                // 0 rather than 100 when no range is published: unlike capacity
                // state, an unreported port range is not a reason to call the node
                // full — it means the sampler has not run yet.
                if total == 0 { 0 } else { (used.saturating_mul(100) / total).min(100) }
            },""",
        ),
    ],
)

print()
print("applied to session and health. One piece remains, in services/node: a")
print("ticker that calls store.port_pool_usage() and stores the sums into the two")
print("gauges. It follows the SCTP mirroring already there. Send:")
print()
print("  grep -n 'tenant_traffic_snapshot' -B 6 services/node/src/main.rs")
print()
print("Also needed before the doc-claims gate passes: three rows in")
print("docs/OBSERVABILITY.md for the new series. That gate asserts every exported")
print("metric is documented, which is the reason the SCTP series arrived")
print("documented rather than not.")
