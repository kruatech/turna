# Conformance and QUIC interop — 2026-08-18

Two runs, on a developer machine (macOS, Apple silicon), against a loopback node.
Recorded because both cover things that previously had **no** evidence of any kind.

Read the scope lines carefully: neither run exercises relayed media. An allocation
that answers correctly can still fail to pass packets, and that gap is what Tier 2
of [../verification/interop-plan.md](../verification/interop-plan.md) is for.

---

## 1. Address family and peer filter (`turna-load-test conformance`)

**Build:** `cargo build --release -p turna-node --features tls`,
`cargo build --release -p turna-load-test`
**Config:** loopback, `production = false`, relay ports 49152–49999,
`max_allocations = 800`.
**Run twice**, once with `[turn] external_ip6` unset and once set to `::1`, because
the two configurations must behave differently and both behaviours are correct.

| probe | `external_ip6` unset | `external_ip6 = "::1"` |
|---|---|---|
| Allocate, no `REQUESTED-ADDRESS-FAMILY` | ok, relayed IPv4 | ok, relayed IPv4 |
| Allocate, `RAF = IPv4` | ok | ok |
| Allocate, `RAF = IPv6` | **440** | **ok, relayed IPv6** |
| `ADDITIONAL-ADDRESS-FAMILY = IPv6` | ignored | ignored |
| `RAF` + `ADDITIONAL-ADDRESS-FAMILY` | accepted | accepted |
| v6 peer on a v4 allocation | **443** | **443** |
| v4 peer on a v6 allocation | n/a | **443** |
| peer filter, NAT64 `64:ff9b::a9fe:a9fe` | **403** | **403** |
| peer filter, 6to4 `2002:c000:0204::1` | **403** | **403** |
| peer filter, Teredo `2001::1` | **403** | **403** |
| peer filter, IPv4-compatible `::203.0.113.1` | **403** | **403** |

**Verdict: pass, both configurations.**

What this establishes:

- IPv6 relaying is genuinely opt-in. Unset, an IPv6 Allocate is refused; set, it
  yields an IPv6 relayed address. Both are correct for their configuration, which is
  why the probe reports rather than asserting one outcome.
- RFC 6156 §4.2 family separation holds in **both** directions.
- The v4-embedding v6 transition prefixes are denied. This is the check that matters
  most on this list: each of those four smuggles an arbitrary IPv4 address inside a
  v6 literal, so without them every v4 deny rule — including the cloud metadata
  address — was reachable by asking for the v6 spelling of the same target.

Two notes on things that look like failures and are not:

- `ADDITIONAL-ADDRESS-FAMILY` is **ignored**, and that is RFC-legal: the attribute is
  comprehension-optional and the feature is not implemented
  ([../design/additional-address-family.md](../design/additional-address-family.md)).
  The illegal `RAF` + `AAF` combination is likewise accepted today; it must become
  `400` when the feature lands, and this row is the record of the current behaviour
  so that change is visible.
- The probe originally reported `403` instead of `443` for "v6 peer on a v4
  allocation". That was the harness, not the server: it defaulted to `[::1]`, and
  loopback is refused by the peer filter *before* the family check runs. Fixed by
  defaulting to a globally routable address. Worth recording because the same
  mistake would make a future reader think family separation was broken.

## 2. TURN over raw QUIC (`turna-load-test quic-check`)

**Build:** `--features quic` on both the node and the tool.
**Config:** `[turn.quic] enabled = true`, `listen = 0.0.0.0:3479`,
`web_transport = false`, self-signed P-256 certificate.

| step | result |
|---|---|
| QUIC handshake, ALPN `stun.turn` | ok |
| 401 challenge over the control stream | ok |
| Authenticated Allocate | ok, relayed `127.0.0.1:49152` |
| CreatePermission | ok |
| Session close | clean |

Metrics after the session, scraped once the 5-second mirror had ticked:

| series | value | what it confirms |
|---|---|---|
| `turna_quic_sessions_total` | 1 | the session was admitted |
| `turna_quic_closed_total` | 1 | and closed |
| `turna_quic_active_sessions` | 0 | back to baseline — **no session leak** |
| `turna_quic_streams_opened_total` | 1 | the client's bidi control stream was seen |
| `turna_quic_control_bytes_tx_total` | 228 | three control responses went back over that stream (401, Allocate success, CreatePermission success) |
| `turna_quic_handshake_failures_total` | 0 | clean handshake |
| `turna_quic_control_dropped_no_stream_total` | 0 | every response found a stream to answer on |
| `turna_quic_readiness` | 1 | ready |

This half matters as much as the pass/fail: the counters agree with what the client
observed, so the QUIC path is not just working but *legible* — a dashboard built on
these series would have shown this session accurately.

**Verdict: pass.**

This is the first interop evidence `[turn.quic]` has ever had. It exercises the QUIC
ingress, the stream framer, the per-stream reply routing and the processor together —
a passing Allocate means all four agree on the framing, which is the part most likely
to be subtly wrong.

The reason no such run existed before was that no off-the-shelf TURN-over-QUIC client
exists. That was true and it was not a reason: the wire format inside a bidi stream is
the same length-delimited STUN that TURN-over-TCP uses, so the client
(`tools/load-test/src/quic_client.rs`) is a few hundred lines. It accepts any server
certificate — a verification client, not a library.

**Not covered:** relayed media over QUIC (needs a peer), the WebTransport/H3 path, and
whether the `[turn.quic]` transport limits are enforced. That last one is worth doing
next and is cheap: set small stream counts and confirm both paths refuse to exceed
them — it is the check that would have caught the silent no-op on H3 that this release
fixed.

## 3. Production gates

With `production = true`, each of `[turn.tcp_relay]`, `[turn.sctp]` and
`[turn.auth.oauth]` set to `enabled = true` was refused by config validation, with a
message naming the key. **Pass** — the refusal documented in `README.md`,
`docs/feature-support.md` and `docs/PRODUCTION_READINESS.md` (R9) is real, not just
asserted.

## Observability note

`turna_quic_readiness` read `2` (degraded) when scraped roughly two seconds after
startup, then `1` on every later scrape. The `QuicStats` → Prometheus mirror runs
on a 5-second interval whose first tick fires immediately, before the endpoint has
bound. Not a defect, but worth knowing before writing an alert with a short `for:`
window — `TurnaQuicListenerDegraded` uses `for: 1m`, which is comfortably clear of it.
