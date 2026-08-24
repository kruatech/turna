# TURNS browser interop — 2026-08-18

Three engines against one node over `turns:` (TLS-over-TCP). This supersedes
`v0.3.0-rc.1.md` for TURNS: that run predates the transport hardening pass, so it did
not cover the code that ships now.

Harness: `turn-relay-probe.html` — a standalone page, four checks, run from the
machine under test. Each check answers a different question, and they are recorded
separately because passing one does not imply the others.

**Environment**

| | |
|---|---|
| Host | macOS, Apple silicon (Mac Studio) |
| Node | `turna-node --features tls`, loopback, `production = false` |
| Certificate | `mkcert localhost 127.0.0.1` — a locally-trusted CA, required because browsers validate the `turns:` certificate |
| TURN URL | `turns:localhost:5349?transport=tcp` |
| Credentials | static long-term user |
| Peer policy | `profile = "lan"`, `allow_loopback_peers = true` — see "Stand quirks" |

## Results

| Check | Chrome 151 | Firefox 153 | Safari 26.5 |
|---|---|---|---|
| **Relay** — a relay candidate is offered | pass, 2 candidates | pass, 1 candidate | pass, 2 candidates |
| **Auth** — bad credentials get nothing | pass, 401 on both probes | pass, 401 | pass (no error code surfaced) |
| **Media** — data flows both ways | pass, 5/5 echoed | pass, 5/5 echoed | pass, 5/5 echoed |
| **Stats** — the path really was the relay | pass, `relayProtocol: tls` | pass, `relayProtocol: tls` | pass, `relayProtocol` not exposed |

`relayProtocol: tls` is the decisive field: it is the client→server transport, so it
distinguishes TURNS from plain TURN directly rather than by inference. Two of three
engines report it; Safari does not expose it at all.

**Safari's Stats row, and a correction worth keeping.** Safari first reported `FAIL`
here, and the first explanation written down was that Safari exposes none of the byte
counters. **That was wrong.** The real cause was in the harness: it closed the remote
peer before reading `getStats()`, which tears down the data channel and freezes the
pair's inbound counter. With that fixed, Safari reports all three sources and both
directions — `data-channel` 5/5, `transport` 1788/1672, `candidate-pair` 1788/1672 —
and passes.

The correction matters beyond Safari: it was the same harness bug that made Chrome
report `2692/0`, and blaming the browser would have left a false limitation on record
and a real defect in the instrument. The only thing Safari genuinely does not expose is
`relayProtocol`, so on Safari the relay path is confirmed by candidate type and byte
flow rather than by naming the transport.

## Server-side corroboration

Metrics after the runs, which is the half a browser cannot show:

| series | value | reading |
|---|---|---|
| `turna_tls_connections_total` | 24 | one per gathering and per peer; matches the number of runs |
| `turna_tls_closed_total` | 24 | all closed — **no connection leak** |
| `turna_tls_active_connections` | 0 | back to baseline |
| `turna_tls_handshake_failures_total` | 0 | every TLS handshake completed |
| `turna_tls_framing_errors_total` | 0 | no TURN-over-TCP framing rejected |
| `turna_total_allocations` | 18 | with `active_allocations` 0 — **no allocation leak** |
| `turna_zero_copy_forwards` | 69 | relayed ChannelData actually forwarded |
| `turna_relay_forward_duration_seconds` | 69 samples, median ≈5 µs | the relay hot path |
| `turna_stun_request_duration_seconds` | 146 samples, 55 under 5 µs | request processing |
| `turna_peer_rejected_total` | 0 | with loopback peers permitted, nothing was filtered |

**Both authentication rejection paths were exercised**, which the wire cannot show:
the two negative probes moved `turna_auth_failures_by_reason_total{reason="integrity_failed"}`
and `{reason="invalid_credentials"}` by 2 each. A wrong password fails
MESSAGE-INTEGRITY; an unknown username is an unknown user. Both answer `401` — which
is correct, since telling a client which of the two happened would leak whether an
account exists — but they are different code paths, and only running both makes those
counters meaningful. Note for alerting: credential-guessing shows up in
`integrity_failed`, not `invalid_credentials`.

## Stand quirks — not server behaviour

Recorded because each one looks like a server defect and is not. Two of the three cost
real time to diagnose, and one of them was originally written down wrongly — that entry
is left visible rather than quietly amended, because a reader deciding whether to trust
this file should see how it was corrected.

**Firefox discards loopback relay candidates.** With the default
`media.peerconnection.ice.loopback = false`, Firefox gathered nothing with valid
credentials and reported no error — while the same run got a `401` with invalid ones,
proving it had reached the server. Setting the pref to `true` produced a clean 4/4.
On a routable address this does not arise.

**Peer filtering blocks a loopback-only relay test.** Two browser peers on `127.0.0.1`
relaying to each other need `allow_loopback_peers = true`; without it the relay
correctly refuses to permit a loopback peer and Media cannot connect. That default is
protection against SSRF, and it should not be relaxed in a production config — the
schema says as much.

**Safari exposes no `relayProtocol` and no `onicecandidateerror`.** Those two are real
gaps: the transport cannot be named from stats, and a credential rejection is visible
only as the absence of a candidate — which is why the Auth check is gated on Relay
having just succeeded against the same server. Everything else is present: Safari
reports `RTCTransportStats`, `data-channel` stats and both directions on the candidate
pair. An earlier draft of this file claimed otherwise; see the Stats note above.

**Chrome's candidate-pair inbound counter lags.** Chrome reported `2668/0` on the pair
while its `transport` and `data-channel` counters showed both directions. Safari's pair
counter did not lag. So a check that relies on the pair alone will misread Chrome —
prefer `transport`, or corroborate across sources.

## What this does not cover

- **IPv6 relaying** — a browser cannot request `REQUESTED-ADDRESS-FAMILY`. Covered
  separately by `turna-load-test conformance` (`conformance-2026-08-18.md`).
- **Sustained load or duration.** Four checks per browser is a functional pass, not a
  soak. Endurance is `scripts/soak/soak.sh`.
- **RFC 6062 TCP relay, DTLS, QUIC/WebTransport.** No browser drives any of them;
  QUIC has its own recorded run in `conformance-2026-08-18.md`.
- **A real certificate chain.** `mkcert` installs a local CA, so this exercises
  certificate *validation* but not a public chain, OCSP, or an intermediate.

## Found by these runs

Two exported, documented readiness gauges never left "starting" because nothing ever
set them:

- `turna_transport_readiness` — the primary UDP datapath, read `0` on a node that had
  just served 146 STUN requests. `set_transport_readiness()` was not called anywhere.
- `turna_afxdp_readiness` — AF_XDP shared the process-level gauge instead of having
  its own.

Both now set Ready at bind and Draining on shutdown; `turna_transport_readiness` reads
`1` on the rebuilt node. Worth noting how they surfaced: not from a test suite, but
from reading a metrics dump taken during an unrelated interop run.
