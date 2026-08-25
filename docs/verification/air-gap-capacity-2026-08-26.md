# Air-gap and capacity verification — 2026-08-26

Ubuntu 24.04, kernel 6.8.0-87, on the host referred to as `cloud`. Both checks run
against the release build.

## Air-gap — 7 of 7

`sudo scripts/verify/air-gap.sh`. The node runs in a network namespace containing
only loopback: no default route, no resolver, nowhere to go.

| check | result |
|---|---|
| Namespace has no route off-host | pass — `ip route show default` empty |
| Starts air-gapped | pass — ready with only loopback |
| Relays media air-gapped | pass — **404 of 404 frames** returned to the peer, 0 errors |
| Opens nothing outbound | pass — `ss -tanp` shows only loopback and listeners |
| Zero outbound telemetry by default | pass — logged `distributed tracing disabled (no OTLP endpoint configured)` |
| No mandatory external DNS | pass — no nameserver in the namespace, node unaffected |
| Local observability air-gapped | pass — 215 `turna_` series on `/metrics` |

Closes four §6 P0 requirements that were previously architectural arguments
rather than observations: air-gapped mode, zero outbound telemetry by default, no
mandatory cloud dependencies, no mandatory external DNS.

A namespace rather than a firewall rule, deliberately. A `DROP` rule leaves an
attempted connection visible only in a counter nobody reads; an empty namespace
makes "it opened nothing" an observation instead of an inference.

The relay check matters as much as the start check. A node that starts but cannot
relay is not air-gap capable, only quiet — and "it started" is precisely the
assertion that let a three-hour soak report PASS on every signal while the
datapath forwarded nothing.

### What it does not establish

That no code path *can* reach outward — only that none is taken during startup
and a relayed session. A path behind a config flag (`otlp_endpoint`, a Tarantool
backend, a cluster peer) or one taken on a rare error would not appear. Those are
opt-in by construction, which is an argument, not a measurement.

Offline *installation* is packaging and is not covered here.

## Capacity API

Three of the five states observed live. Each was sampled three times, four
seconds apart, and returned the same result — a steady state, not a transient.
`turna_relay_ports_in_use` agreed with the allocation count throughout.

| `max_allocations` | live allocations | state | reason returned |
|---|---|---|---|
| 8 | 0 | `AVAILABLE` | — |
| 10 | 8 (80 %) | `DEGRADED` | allocations at or above the soft threshold |
| 8 | 8 (100 %) | `SATURATED` | allocations at or above the hard threshold |

The two thresholds are distinct and not confused with each other, which is the
thing worth checking: a soft threshold that reports `SATURATED` would tell a
caller to stop using a node with 20 % headroom left.

`DRAINING` and `UNAVAILABLE` are not covered here. `DRAINING` follows the same
flag the drain check already exercises; `UNAVAILABLE` needs either a node that
has not finished starting or one with no published limit, neither of which this
harness produces.

The useful finding is not that `SATURATED` appeared. It is that **the endpoint
reported reality the whole way through the debugging below** — when it said eight
allocations, there were eight, and the number that looked wrong was the one I
expected, not the one it returned.

## Rate sampler

Ten one-second buckets, mean over the window. Fed by a one-second ticker in the
node; read by `/capacity`.

Predicted before running, then observed:

| phase | expected | observed |
|---|---|---|
| first 3 s after start | `null` — window not filled | `null` |
| after 12 s, no traffic | `0` | `0` |
| 8 channels x 10 pps, 200 B payload | ~160 pkt/s, ~32 kB/s | **160 pkt/s, 32 320 B/s** |

Three samples five seconds apart under load returned the same numbers.

Two things the arithmetic confirms. 160 packets for 80 sent means the counters
total both directions — a relayed frame is received and then sent, so the figure
is the load on the node rather than the traffic of one direction, which is what an
admission decision wants. And 32 320 / 160 = 202 bytes per packet: the 200-byte
payload plus a 4-byte ChannelData header, less rounding on the window.

`null` and `0` are deliberately different answers. "No traffic" and "not yet
known" are different states, and a partial mean over three of ten buckets would
understate the load by two thirds — a node that under-reports during its first ten
seconds accepts work it cannot serve.

### What the rates are not used for

The capacity state still weighs allocations and send-queue pressure only. The
rates are reported, not acted on, because a threshold needs a capacity figure to
compare against and this node's throughput ceiling has never been measured — that
is the hardware-profile item. Wiring a threshold now would mean inventing a limit
and then declaring nodes saturated against it.

So of the three requirements that were waiting on this sampler, two are closed
honestly (`/capacity`'s bandwidth and packet-rate signals) and the third,
capacity-aware admission control, still needs hardware rather than code.

## Two things found while verifying

### A log line that had never been logged

`telemetry.rs` emitted `"OTLP endpoint not configured — distributed tracing
disabled"` on the line *above* `try_init_with_fmt!`, so it was written before the
tracing subscriber existed and discarded. That message had never appeared in any
log.

An operator confirming that a deployment sends nothing outward found no statement
either way — they had to infer it from an empty `otlp=` field on a different line.
Moved after initialisation, where its neighbour already lives.

It surfaced because the air-gap check looked for the sentence and failed on a node
that was behaving correctly. A check asserting on intended output rather than
observed output finds this; one asserting on the code does not.

### A rate limiter that obstructs measurement, and a wrong conclusion about it

Driving 38 concurrent allocations from one host does not work: every client
arrives from loopback and `TieredRateLimiter` refuses most of them —
`rate_limited: 122` against `total_allocations: 59`, with `quota_exceeded: 0`
confirming the limiter rather than a quota. Eight allocations is what this host
sustains. The limiter is doing its job; it is the measurement it obstructs.

I first concluded from this that the soft threshold could not be verified without
multiple source addresses or making `TieredLimits` configurable, and wrote that
down. It was wrong. The threshold does not need many allocations, only allocations
that land inside the band: with `max_allocations = 10`, the eight this host
sustains are 80 %, which is between the two thresholds. `DEGRADED` followed.

Recorded because the mistake is instructive. The obstacle was real and the
inference from it was not — "I cannot generate enough load" became "this cannot be
measured", when the measurement never needed the load. Worth suspecting the next
time a limit looks like it blocks a test.

## Scope

One host, one kernel, functional. No endurance: the air-gap namespace was up for
about twenty seconds of relayed traffic, which is enough to show the path works
and nothing about whether it stays working. The capacity endpoint has no load
history behind it either — it was sampled, not soaked.
