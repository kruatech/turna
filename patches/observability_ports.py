#!/usr/bin/env python3
"""
Document the three relay-port series and `/capacity`.

Required, not cosmetic: `check-doc-claims.sh` asserts every exported metric
appears in OBSERVABILITY.md and fails the build otherwise. That check exists
because eight metrics once shipped undocumented — nothing was wrong with them,
they were simply unfindable, and a metric nobody can find is a metric nobody
builds a dashboard on.

Run from the repository root. Idempotent.
"""

import sys
import pathlib


def die(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


p = pathlib.Path("docs/OBSERVABILITY.md")
if not p.exists():
    die("docs/OBSERVABILITY.md not found — run from the repository root")

s = p.read_text()
if "turna_relay_ports_in_use" in s:
    die("already applied")

# ---------------------------------------------------------------------------
# The three series, in the core table next to the allocation gauges they relate
# to. Not a section of their own: a reader looking at allocation counts is the
# reader who needs to know whether the port range behind them is filling.
# ---------------------------------------------------------------------------
old = """| `turna_active_allocations` | gauge | Current allocation count. |
| `turna_total_allocations` | counter | Total successful allocations since start. |"""

new = """| `turna_active_allocations` | gauge | Current allocation count. |
| `turna_total_allocations` | counter | Total successful allocations since start. |
| `turna_relay_ports_in_use` | gauge | Relay ports held by an allocation **or** by an unclaimed EVEN-PORT reservation — a reserved port is unavailable to anyone else, so counting it free would understate how full the pool is. Summed across the global pool and any tenant pools. |
| `turna_relay_ports_total` | gauge | Relay ports configured, summed the same way: `max_port - min_port + 1` per pool. |
| `turna_relay_ports_utilization_percent` | gauge | Percent of the range in use. **The one to alert on.** Reads 0 rather than 100 before the first sample, so an alert on a high value cannot fire during startup. |"""

n = s.count(old)
if n != 1:
    die(f"core table anchor: found {n} occurrences, expected exactly 1")
s = s.replace(old, new)
print("  ok  OBSERVABILITY.md: three relay-port series")

# ---------------------------------------------------------------------------
# Why they exist, and the cardinality decision, which is not obvious from a
# table row and is the kind of thing someone will otherwise "fix" by adding a
# tenant label.
# ---------------------------------------------------------------------------
anchor = "#### TURNS — TLS over TCP (`[tls]`)"
if s.count(anchor) != 1:
    die("could not find the TURNS section to anchor the note")

note = """#### Relay port exhaustion

`turna_relay_ports_utilization_percent` is the series to alert on, and it was
absent until 2026-08-26. The range is bounded by `[turn.relay] min_port`/`max_port`
and config validation warns when `max_allocations` exceeds half of it, but nothing
reported occupancy at runtime: the range filled silently and the first symptom was
`Allocate` beginning to fail. The gap surfaced while looking for this metric during
a 24-hour soak and finding it did not exist.

Two things make a range fill faster than the allocation count suggests. EVEN-PORT
reservations hold a port without an allocation behind it, and a range overlapping
the host's ephemeral range loses ports to processes that have nothing to do with
turna — which has bitten this project: a peer socket landed inside the relay range
and the relay forwarded to itself.

**Tenant pools are summed, not labelled.** Per-tenant series are how a Prometheus
instance dies when a customer has ten thousand tenants, and §10 of the enterprise
specification asks for cardinality protection in the same document that asks for
this metric. `AllocationStore::port_pool_usage()` returns `(pool, in_use, capacity)`
per pool for anything that needs the detail — the management API, a support bundle —
without every scrape paying for it. Resist adding the label.

"""
s = s.replace(anchor, note + anchor, 1)
print("  ok  OBSERVABILITY.md: exhaustion note with the cardinality decision")

# ---------------------------------------------------------------------------
# /capacity belongs here too: it is served by the same listener as /metrics and
# an operator looking for "how loaded is this node" will look in this file.
# ---------------------------------------------------------------------------
cap_note = """#### `GET /capacity`

Served on the health listener beside `/metrics`. Returns the node's capacity state
in the vocabulary the enterprise specification asks for — `AVAILABLE`, `DEGRADED`,
`DRAINING`, `SATURATED`, `UNAVAILABLE` — with the raw numbers beside the verdict so
a caller can apply its own policy.

Always answers `200`, including when saturated: a caller asking "can you take this"
needs an answer rather than an error to interpret. `/ready` remains the endpoint
that speaks in status codes.

The response carries a `signals` object naming which inputs the state actually
weighed. Allocations, send-queue pressure and readiness are in; bps, pps, CPU and
memory are not, and saying so in the response is cheaper than a caller discovering
it during an incident. Design and rationale: `docs/design/capacity-api.md`.

"""
s = s.replace(note + anchor, note + cap_note + anchor, 1)
print("  ok  OBSERVABILITY.md: /capacity endpoint")

p.write_text(s)

print()
print("Verify — this is the gate that made the work necessary:")
print()
print("  bash scripts/check-doc-claims.sh")
