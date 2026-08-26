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

### Host CPU and memory

Collected by a persistent `System` refreshed every five seconds, in a task that
runs whether or not a cluster backend is configured.

Two things were wrong with where this lived before. It ran only inside the
heartbeat loop, so a standalone node collected nothing — the two signals a
capacity decision most wants, absent exactly where there is no cluster to ask
instead. And it built a fresh `System` each tick; CPU usage in sysinfo is a delta
between refreshes, so a new instance has nothing to compare against and falls back
on the library's ~100 ms settling window. A node busy in bursts reads low if the
sample lands between them.

`u64::MAX` marks "never sampled", distinct from a genuine 0. A node whose sampler
had died would otherwise look idle, which is the worst available way to be wrong
about load.

### What the rates are not used for

The capacity state still weighs allocations and send-queue pressure only. The
rates are reported, not acted on, because a threshold needs a capacity figure to
compare against and this node's throughput ceiling has never been measured — that
is the hardware-profile item. Wiring a threshold now would mean inventing a limit
and then declaring nodes saturated against it.

So of the three requirements that were waiting on this sampler, two are closed
honestly (`/capacity`'s bandwidth and packet-rate signals) and the third,
capacity-aware admission control, still needs hardware rather than code.

## Reconnect storm

50 clients establish allocations, all vanish at once without a `Refresh(0)` —
what a link flap looks like from the server — and all return simultaneously.
Three rounds, sources spread across `127.0.0.0/8`.

```
round 1: 50/50 recovered, slowest 2 ms
round 2: 50/50 recovered, slowest 2 ms
round 3: 50/50 recovered, slowest 3 ms
rate_limited: 0   quota_exceeded: 0
```

150 of 150, no loss, no degradation across rounds, and neither the rate limiter
nor the quotas were touched. On this host, at this size, a reconnect storm is not
a problem.

The ungraceful drop matters to the result: a client that sends `Refresh(0)` frees
its allocation immediately, while one whose network vanished leaves it holding a
relay port until the lifetime expires. The returning clients therefore ask for new
allocations while the old ones are still held — the harder of the two cases, and
the realistic one.

### Two findings that were mine, not the server's

The first run of this reported slot exhaustion and failed recovery. Both were
artefacts: `allocate_family`'s third parameter is the response timeout in
milliseconds and I passed 0, so every client gave up before the server could
answer. Rounds "completed" in 1 ms with most allocations failing and nothing on
the server side to show for it.

What caught it was the 1 ms, not the failures — a round establishing fifty
allocations cannot take a millisecond. Had the number been merely bad rather than
impossible, two non-existent server defects would now be written here as measured
facts.

The lesson is not "check your parameters". It is that a result which is *wrong*
often looks plausible, while a result which is *impossible* does not, so the
impossible one is the gift.

### What the storm did find: drain waits when there is nothing to wait for

Shutting down a node holding 300 abandoned allocations took **36 seconds**. The
drain loop is `while !store.is_empty() && now < timeout` with a hard-coded 30
seconds, polling `cleanup_expired()`. Allocations with a 600-second lifetime do
not expire inside a 30-second window, so the loop polls until the timeout with
nothing to wait for.

That is a fixed cost, not a load-dependent one: a node whose clients disappeared
always pays it in full. Rolling ten nodes sequentially spends five minutes there.

Both halves are now addressed — `[turn.relay] drain_timeout_secs` makes the wait
an operator's decision rather than a constant, and the loop exits early when three
consecutive polls remove nothing and the count has not moved. A node draining live
traffic is unaffected: its allocations end, the count moves, the loop keeps
waiting. The two cases were previously indistinguishable despite wanting opposite
handling.

Not yet measured after the change. The number to check is both directions —
abandoned allocations should now exit in seconds, and live traffic should still
take as long as its clients need. A change that makes shutdown fast by cutting
calls short would be a regression wearing a fix's clothes.

### Two drain settings, and why the names mislead

Adding `[turn.relay] drain_timeout_secs` produced a second knob next to an
existing one, and they are not duplicates:

| key | waits for | applies to |
|---|---|---|
| `[turn.relay] drain_timeout_secs` | **allocations** to end | the tokio datapath's `RelayServer::drain` |
| `[cluster] drain_grace_secs` | **io_uring worker threads** to finish | the io_uring worker pool's lame-duck window |

One is about clients, the other about threads. Both are needed.

Two things about this are worth fixing eventually, and neither is fixed here
because renaming a key breaks existing configuration and that is not a decision
to make in passing:

`drain_grace_secs` lives in `[cluster]` but has nothing to do with clustering —
io_uring worker threads exist on a single node too. An operator looking for it
will not look there.

And an operator reading two similarly-named drain settings in different sections
will reasonably conclude one is redundant, set the wrong one, and get a shutdown
that behaves differently from the one they configured. The names describe their
implementations rather than their effects.

## Three false alarms about io_uring, recorded because the pattern repeated

While tracing the drain path I concluded three times that the io_uring datapath
lacked something, and was wrong each time:

- "io_uring builds no `RelayServer`, so it has no drain" — it has one, a worker
  pool lame-duck window at a different call site.
- "that window is a hard-coded constant" — it reads `cluster.drain_grace_secs`.
- "so `drain_timeout_secs` silently does not apply there" — correct, but not a
  defect: the two settings wait for different things.

Each conclusion came from a grep that found nothing, and each grep searched for a
word I had guessed. **Not finding something is not the same as its absence**, and
the difference is invisible from inside the search. The tell, in hindsight, was
that every one of these was an assertion about what does *not* exist — the class
of claim a keyword search is worst at supporting.

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

### The harness was measuring the rate limiter, not the server

Every load client bound its control socket to `127.0.0.1`, and
`TieredLimits::allocate` is 32 allocations/second per source IP with a burst of
16. So 38 requested channels produced `rate_limited: 122` against
`total_allocations: 59`, `quota_exceeded: 0` confirming the limiter rather than a
quota.

Fixed by spreading control sockets across `127.0.0.0/8`, which is entirely local
on Linux and needs no interface configuration. `--source-ips N` in the load tool.
Measured back-to-back against the same node:

| | frames received | errors | allocations | `rate_limited` delta |
|---|---|---|---|---|
| 38 channels, one source | 205 | 33 | 5 | +33 |
| 38 channels, 40 sources | **1558** | **0** | **38** | **0** |

The limiter was never touched in the second run. Seven and a half times the
traffic, and every channel established.

**This invalidates a statement made earlier in this document and now corrected:**
"eight allocations is what this host sustains" was wrong. Eight was what leaked
through a per-source-IP limit. The host sustains at least 38, and the ceiling is
still unmeasured.

It also means the single-source case is not a capacity measurement at all — it is
the everyone-behind-one-NAT case. Worth testing deliberately, and worth not
confusing with the other.

### A wrong inference about the soft threshold, kept here because it is instructive

Before the above was understood, I concluded the 75 % soft threshold could not be
verified without multiple source addresses or making `TieredLimits` configurable,
and wrote that into this file as a finding. It was wrong twice over.

Wrong first because the threshold never needed many allocations, only allocations
landing inside the band: with `max_allocations = 10`, the eight then available are
80 %, and `DEGRADED` followed immediately. Wrong again because the obstacle itself
turned out to be removable in an afternoon.

"I cannot generate enough load" became "this cannot be measured". The obstacle was
real; the inference was not. Worth suspecting the next time a limit looks like it
blocks a test.

## Scope

One host, one kernel, functional. No endurance: the air-gap namespace was up for
about twenty seconds of relayed traffic, which is enough to show the path works
and nothing about whether it stays working. The capacity endpoint has no load
history behind it either — it was sampled, not soaked.
