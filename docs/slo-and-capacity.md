# Turna — SLO & Capacity Planning (§31)

This is a **framework**, not a set of promises. Concrete target numbers (SLO
objectives, per-node capacity limits) depend on your hardware, network, and
business requirements and must be established by measurement — they are marked
`TODO(operator)` below and should be filled in from a steady-state benchmark run
(see "Establishing the baseline"). Everything **not** marked as a placeholder is a
hard property of the system derived from the code/config.

## 1. Hard capacity constraint — relay ports (grounded)

The relay UDP port range is `49152–65535` = **16384 ports** (defaults; confirm
against your `[turn.relay] min_port/max_port`).

Each active allocation consumes at least one relay port. Therefore:

> **The per-node concurrent-allocation ceiling cannot exceed the relay port
> count (~16384 with the default range).**

`RESERVE`/even-port allocations can consume an extra port, lowering the effective
ceiling further.

**Resolved** (P0 review item A): the per-node allocation cap is **8192** — the
conservative ceiling for the default relay range (49152–65535 = 16384 ports)
under EVEN-PORT worst-case, where one allocation can consume a second (reserved)
port. All artifacts agree: `deploy/turn.toml`, the Helm chart default
(`values.yaml`), and the production example (`values-production.example.yaml`).
Capacity scales **horizontally** — N nodes ≈ N×8192 (1→8192, 2→16384,
4→32768, 8→65536) — rather than by raising the per-node cap or widening the
range: a wider range complicates firewall / Kubernetes / operations, and a single
IP's UDP range cannot realistically host 50000 live allocations anyway. Real
capacity is additionally bounded by PPS, bandwidth, file descriptors, and CPU
(see §2). Config `validate()` rejects `max_allocations > usable ports` and warns
above half, so a mis-set cap fails fast.

## 2. Capacity dimensions to plan for

A node is bounded by whichever of these is hit first:

| Dimension | Bound | Where to observe |
|---|---|---|
| Concurrent allocations | relay port count (hard, ~16384) | `active_allocations`, `allocated_ports` / `available_ports` on `/metrics` |
| Relay throughput | NIC / CPU / transport backend | `bytes_*`, `pps` on `/metrics` |
| Allocation churn (create/refresh/remove rate) | write-behind backend throughput | `tarantool_writes_dropped_total` (non-zero ⇒ backend can't keep up) |
| Management/auth load | control-plane + backend | control-plane latency |

Rule of thumb: if `tarantool_writes_dropped_total` is ever non-zero under expected
load, you are backend-write-capacity bound before you are port bound — size the
write-behind channel and backend accordingly (runbook RB-1/RB-3).

## 3. SLO framework (targets are placeholders)

Define SLIs first (these map to signals the system actually exposes), then set
objectives by measurement.

### Suggested SLIs (measurable today)
- **Node readiness ratio** — fraction of time a *node* reports Ready on `/ready`
  (Draining and Degraded both fail readiness by design). This is a per-node
  operational metric, **not** service availability: a planned drain of one node
  in a cluster is not a service outage.
- **Service TURN availability** — fraction of successful STUN/TURN operations for
  clients across the whole deployment. This is the user-facing availability SLI.
- **Service Allocate success rate** — successful `Allocate` handshakes ÷ attempts,
  deployment-wide.
- **Synthetic relay availability / delivery** — `1 − loss` where
  `loss = sent − received`, from the load generator's `channeldata` mode or a
  synthetic probe. Note: this is a benchmark/probe SLI. True production end-to-end
  loss needs client telemetry or a dedicated measurement flow — internal server
  counters alone are not a full end-to-end SLI.
- **Latency** — STUN Binding RTT and Allocate handshake latency percentiles
  (p50/p95/p99), and one-way relay latency (`channeldata` mode).
- **Persistence health** — `tarantool_writes_dropped_total` rate (should be 0 in
  steady state).

### Objectives — `TODO(operator)`
Fill these in from your measured baseline and business need. Do **not** copy
generic numbers; they must reflect your environment.

| SLI | Objective | Window |
|---|---|---|
| Service TURN availability | `TODO` (e.g. 99.9%) | `TODO` (e.g. 30d) |
| Service Allocate success rate | `TODO` | `TODO` |
| Node readiness ratio (per node) | `TODO` | `TODO` |
| Synthetic relay availability (1 − loss) | `TODO` | `TODO` |
| Binding RTT p99 | `TODO` µs | `TODO` |
| Allocate handshake p99 | `TODO` µs | `TODO` |
| Relay one-way latency p99 | `TODO` µs | `TODO` |

### Error budget & alerting — `TODO(operator)`
Derive from the objectives above. Suggested paging signals (thresholds are yours to
set): sustained Degraded, `tarantool_writes_dropped_total` rate > 0, allocation
success rate below objective, `available_ports` approaching 0.

## 4. Establishing the baseline (ties to the load generator)

Use the load generator in **steady state** so setup/ramp does not skew results:

```
# warm up 10s, then measure 60s; JSON for automation
turna-bench --warmup 10 --duration 60 --json binding    -c 50
turna-bench --warmup 10 --duration 60 --json allocate   -c 100
turna-bench --warmup 10 --duration 60 --json channeldata -n 200 --pps 1000
```

- The `--warmup` window is discarded; reported `rps`, latency percentiles, and
  `loss` reflect steady state only.
- For `channeldata`, `loss` is the real relay drop rate — the primary relay-
  delivery SLI. For `binding`/`allocate` (closed-loop), `loss` should be ~0; a
  non-zero value indicates a measurement or convergence problem.
- Ramp concurrency/pps until a capacity dimension (§2) saturates. The last healthy
  point is your per-node capacity; set operating limits below it with headroom.

`TODO(operator)`: record the measured baseline (hardware, config, numbers) here so
capacity decisions are reproducible.
