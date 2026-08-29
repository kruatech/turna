# Capacity API — `GET /capacity`

Per-node capacity, for a caller deciding where to place a session. Added
2026-08-26 against §4 and §13 of the enterprise specification, which ask for a
versioned endpoint returning current and maximum capacity, load state and
reasons for unavailability, with at least the states `AVAILABLE`, `DEGRADED`,
`DRAINING`, `SATURATED` and `UNAVAILABLE`.

Served on the health listener, alongside `/health`, `/ready`, `/status`,
`/cluster` and `/metrics`.

## The assumption this is built on

**The consumer is the upper Conference product, asking "can this node take a
call" immediately before placing one.**

The specification does not say who calls this, and the shape depends entirely on
the answer, so the assumption is written here to be argued with rather than left
implicit in the code.

What follows from it:

- **Per node, not per cluster.** Cluster-wide selection stays with `/cluster`,
  which already returns the ring. Two endpoints with overlapping purposes would
  be worse than one of each.
- **Cheap enough to call per placement.** No sampling, no locks held, no
  allocation beyond the response itself. It reads atomics.
- **Always `200 OK`.** Including `SATURATED` and `UNAVAILABLE`: a caller asking
  "can you take this" needs an answer, not an error to interpret. `/ready` remains
  the endpoint that speaks in status codes, for load balancers.
- **Raw numbers next to the verdict.** `active_allocations`, `max_allocations`
  and `utilization_percent` are returned alongside `state`, so a caller can apply
  its own policy. This matters because the thresholds here are generic and a
  deployment's real constraint is usually something else — uplink bandwidth on a
  shared link, or a licence count.

**If the real consumer is different, this is the wrong shape.** A load balancer
polling on a timer would want something closer to `/ready`. The cluster
distributing work internally would not want an HTTP endpoint at all — that
belongs in gossip. Change it before anything binds to it; after that the shape is
a contract.

## Response

```json
{
  "version": 1,
  "state": "AVAILABLE",
  "reasons": [],
  "active_allocations": 128,
  "max_allocations": 10000,
  "utilization_percent": 1,
  "soft_threshold_percent": 75,
  "hard_threshold_percent": 95,
  "ready": true,
  "draining": false,
  "signals": {
    "allocations": true,
    "send_queue_pressure": true,
    "readiness": true,
    "bandwidth_rate": false,
    "packet_rate": false,
    "cpu": false,
    "memory": false
  }
}
```

`version` increments on any non-additive change. Adding a field does not bump it;
removing or reinterpreting one does.

`reasons` is empty when `AVAILABLE` and otherwise carries short strings worth
logging. They are for a human reading an incident timeline, not for a caller to
branch on — branch on `state`.

## How the state is decided

In order; the first match wins.

| state | condition |
|---|---|
| `DRAINING` | the node is shutting down |
| `UNAVAILABLE` | not ready, **or** no capacity limit published |
| `SATURATED` | allocations at or above the hard threshold, **or** the send queue has dropped frames |
| `DEGRADED` | allocations at or above the soft threshold, **or** a listener or backend reports degraded |
| `AVAILABLE` | none of the above |

Three of these orderings are deliberate.

**`DRAINING` beats `SATURATED`.** A node that is both reports the condition that
will not resolve on its own. A caller that sees `SATURATED` may reasonably retry
in a minute; one that sees `DRAINING` should not.

**An unpublished limit is `UNAVAILABLE`, not unlimited.** `max_allocations`
reaches this crate through `set_capacity_limits()` at startup; until that call it
is zero. Treating zero as "no ceiling" would put a node into service advertising
headroom it has never measured — the same shape as a health endpoint reporting
Ready while bound to nothing, which this project has already shipped once.

**Any send-queue drop is saturation, not degradation.** By the time a frame is
dropped the egress queue has already overflowed and a client has already lost
data. Placing more work on that node makes it worse, so there is no gentler state
to report.

## What the state does not weigh

The specification asks admission decisions to consider bps, pps, CPU and memory
pressure. **None of those is in this version**, and the `signals` object says so
in every response.

That field exists because the alternative is worse. A state label that implied it
had weighed CPU while it had not would be indistinguishable, to a caller, from
one that had — and would be discovered during an incident rather than during
integration.

Why each is absent:

- **`bandwidth_rate`, `packet_rate`** — the byte and packet counters are
  cumulative. A rate needs deltas over an interval, which needs a background
  sampler. That sampler is worth building; it is not built.
- **`cpu`, `memory`** — no source in this crate. The node reports its own load via
  `sysinfo` in the heartbeat path; wiring that here is a small change that has not
  been made.

Until then the state is honest about being a count-based judgement with a
back-pressure signal attached.

## What this is not

**This endpoint reports; it does not enforce.** Capacity-aware *admission* —
actually refusing an `Allocate` before the node is overloaded — is a separate §4
requirement and lives on the relay path. A caller that ignores `SATURATED` and
allocates anyway will still be served, subject to `max_allocations` and the
per-user quotas, exactly as before.

Building the report first is deliberate: it forces the states to be defined, and
admission control then has something to act on rather than inventing its own
vocabulary.

## Thresholds

Percentages of `max_allocations`, defaulting to 75 and 95. They are set at
startup and not currently configurable — a `[capacity]` config section is the
obvious next step, and was left out of the first version so the endpoint could be
reviewed before its configuration surface was fixed.
