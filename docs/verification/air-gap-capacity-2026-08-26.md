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

`GET /capacity` on a node with `max_allocations = 8`:

```
idle:            AVAILABLE   0 of 8
under load:      SATURATED   8 of 8   100%   ['allocations at or above the hard threshold']
```

Three consecutive samples four seconds apart returned the same result, so this is
a steady state rather than a transient. `turna_relay_ports_in_use` agreed with the
allocation count throughout.

The useful finding is not that `SATURATED` appeared. It is that **the endpoint
reported reality the whole way through the debugging below** — when it said eight
allocations, there were eight, and the number that looked wrong was the one I
expected, not the one it returned.

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

### The soft threshold is not verified, and cannot be from this host

The 95 % hard threshold is confirmed above. The 75 % soft threshold is **not**,
and the reason is worth recording rather than leaving as a gap someone assumes
was covered.

Driving 38 concurrent allocations from one host does not work: every client
arrives from loopback and `TieredRateLimiter` refuses most of them —
`rate_limited: 122` against `total_allocations: 59`, with `quota_exceeded: 0`
confirming it was the rate limiter and not a quota. The limiter is doing its job;
it is the measurement it obstructs.

The threshold was reached instead by lowering `max_allocations` to 8, which the
host can sustain. That proves the hard threshold and leaves the soft one
untested, because there is no configuration where 8 allocations sit between 75 %
and 95 % of 8.

Testing the soft threshold needs either a load source with multiple source
addresses, or `TieredLimits` becoming configurable — it is currently constructed
in `processor.rs` rather than read from config. Neither is difficult; both are
more than this run.

## Scope

One host, one kernel, functional. No endurance: the air-gap namespace was up for
about twenty seconds of relayed traffic, which is enough to show the path works
and nothing about whether it stays working. The capacity endpoint has no load
history behind it either — it was sampled, not soaked.
