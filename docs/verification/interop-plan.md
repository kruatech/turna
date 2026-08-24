# Interop and soak plan — what to run, in what order, and what it unblocks

`docs/verification/encrypted-transports.md` lists *what to check*. This file is the
other half: **which runs are worth doing first**, what each one unblocks, and what
counts as evidence rather than a green feeling.

Written after a code pass that changed wire behaviour in two places, so the first
section is not new features — it is confirming that nothing regressed.

## Harnesses already in the repo

Reuse these rather than building new ones; the earlier recorded runs used them.

**`turna-load-test` now speaks every transport the server does.** It used to be
UDP-only, which is why so much of this plan read "needs a client". One binary, one
set of credentials, one JSON output shape:

| Mode | Feature | What it does |
|---|---|---|
| `binding` / `allocate` / `channel-data` | — | UDP load; `channel-data --family v6` puts real traffic through an IPv6 relay |
| `conformance` | — | address-family and peer-filter probes, seconds, no stand |
| `tcp-relay-check [--pipelined]` | — | RFC 6062 end to end; the pipelined form is the case the server's detach prebuffer exists for |
| `tls-check` / `tls` | `tls` | TURNS functionally, and TURNS **under load** — the missing piece for a TURNS soak |
| `dtls-check` | `dtls` | the first TURN allocation over DTLS |
| `quic-check` | `quic` | raw QUIC including relayed media |
| `wt-check` | `web-transport` | the H3 path; not a browser substitute |

Every check ends at a byte arriving somewhere, not at a success response — see
`docs/soak/endurance-2026-08-19.md` for why that distinction earned its own rule.

| Path | Use |
|---|---|
| `bench/pion-turn/` | Go TURN client — scriptable, good for negative cases and for anything a browser will not let you send |
| `tools/load-test/` | Allocation churn and concurrent-session load |
| `tools/benchmark/` | Throughput, for soak baselines |
| `scripts/e2e/backend_diff.sh`, `backend_diff_bytes.sh` | Byte-level datapath comparison between backends |
| `bench/coturn.conf`, `bench/eturnal.yml` | Reference servers, for differential testing when a client disagrees with us |
| `docs/interop/v0.3.0-rc.1.md` | Format to follow; the TURNS browser matrix already lives there |
| `scripts/soak/soak.sh` + `analyze.py` | 6h endurance harness: alternating load/idle phases, metric sampling to CSV, per-signal leak verdict |

**On the soak harness specifically.** It answers one question — does the node
degrade over time under steady load — and the idle phases are the point: under
continuous load a leak and a working cache look identical, and it is the failure to
return to baseline during idle that separates them. `analyze.py` gives a verdict per
signal rather than one green light, because "did not crash", "did not leak" and "no
errors" are three different claims. Load comes from `turna-load-test`,
rotated across its three modes because they stress different paths: `allocate`
(allocation churn → port recycling and release on close), `channeldata` (sustained
relayed media → egress queues, byte counters, the datapath), `binding` (bare STUN →
a leak visible here is in the parser or socket layer, not in allocations). Two
`allocate` phases per `channeldata` phase, because allocation churn is where this
codebase has actually had leaks. `TURNA_LOAD_CMD` overrides the rotation if you want
one specific command.

**Run Tier 0 first.** A green soak on a broken redirect path is still a broken
redirect path.

Record every run in `docs/interop/`, `docs/soak/` or `docs/dtls/` following the
existing file shape. **A run that is not written down did not happen** — that is
exactly how the repo ended up with a documented RFC 5780 codec that never existed.

---

## Tier 0 — regression confirmation (do this before anything else)

Two changes altered observable behaviour. Neither is a new feature, so neither
appears as a gate below, but both can break a working deployment.

1. **`300 Try Alternate` redirect.** The `ALTERNATE-SERVER` attribute type was
   wrong (`0x0003`, which is `CHANGE-REQUEST`) and is now `0x8023`. Drive a cluster
   redirect and a lame-duck drain with a client that actually follows redirects —
   pion is the reliable one here, browsers are inconsistent about it.
   *Evidence:* the client connects to the alternate node. Capture the 300 and
   confirm attribute type `0x8023` on the wire; a passing test that only checks
   "client eventually worked" does not distinguish this from a retry.

2. **IPv6 peer filter.** NAT64 / 6to4 / Teredo / IPv4-compatible peers are now
   refused. If any real client population relays through NAT64, this is a
   regression for them.
   *Evidence:* CreatePermission for `64:ff9b::a9fe:a9fe`, `2002:c000:0204::1`,
   `2001::1`, `::203.0.113.1` each answer `403`, and a normal global v6 peer
   (`2606:4700::1111`) still succeeds. `turna_peer_rejected_total` moves for the
   first four only.

3. **DTLS accept liveness.** Start a handshake and go silent (ClientHello, answer
   the HelloVerifyRequest, then stop). *Evidence:* within
   `accept_timeout_secs`, `turna_dtls_accept_timeouts_total` increments **and a
   second normal client completes a handshake**. Before the bound existed the
   second client never connected and nothing said why.

---

## Tier 1 — lifts a production gate

These are the runs that change what an operator is allowed to ship. Ordered by
value per hour of work.

### 1. RFC 6062 TCP relay → lift `production = true` refusal

Highest value: the code looks complete (`CONNECT` / `ConnectionBind` /
peer-initiated listener, ownership-bound binds, pipelined bytes preserved across
the detach), so this is plausibly a documentation-and-evidence gap rather than a
work gap.

- Client: pion (browsers do not expose RFC 6062).
- Cases: full `CONNECT` → `ConnectionBind` → bidirectional data; a second
  `ConnectionBind` from a *different* client for the same connection id must be
  refused; peer-initiated connection arriving before the client binds; allocation
  released when the control connection closes (the relay port must be reusable
  immediately, not after the TTL).
- One case deserves specific attention because it is the one that motivated the
  detach prebuffer: a client that **pipelines** application bytes immediately after
  `ConnectionBind` in the same TCP segment. Those bytes must arrive, in order.
- *Then:* remove the refusal in `config::validate()` and the "refused in
  production" wording in `README.md`, `docs/feature-support.md`,
  `docs/PRODUCTION_READINESS.md` (R9), `docs/compatibility/transport-backends.md`.
  `scripts/check-doc-claims.sh` fails if the code and docs disagree, so do both.

### 2. RFC 7635 OAuth → lift gate

- Needs a real authorization server issuing AEAD access tokens, not a hand-rolled
  token — the point is interop with someone else's encoder.
- Cases: valid token; expired token inside and outside the clock-skew grace;
  `kid`-tagged key selection with `strict_kid` both on and off; a token whose
  remaining lifetime is shorter than the requested allocation lifetime (the granted
  lifetime must be capped, §6.1); zero-remaining lifetime → `401`.

### 3. TURNS and DTLS: beta → supported

The recorded browser interop (Chrome 150 / Firefox 152 / Safari 26.5, 5/5 each) and
the 12h relay soak **predate the hardening pass**, so they do not cover the current
code. Re-run rather than cite.

- TURNS: repeat the existing matrix, plus the two new knobs —
  `max_handshakes_per_sec_per_ip` (flood one source, confirm normal clients still
  connect and `turna_tls_rejected_rate_limit_total` moves) and `alpn_required`
  (a client offering no ALPN is refused; confirm your real clients *do* offer it
  before enabling this in production).
- DTLS: the gap here is not the transport handshake — that is on record in
  `docs/dtls/` — it is that **no live TURN client has ever completed an allocation
  over DTLS**. No common client does it, so this needs a pion-based client speaking
  TURN over DTLS. Until that exists, DTLS cannot honestly move past beta no matter
  how much hardening lands.
- Soak: 12h minimum, watching RSS and fd count. The earlier run is the baseline to
  compare against.

---

## Tier 2 — makes an opt-in feature trustworthy

### 4. IPv6 relayed transport

Set `[turn] external_ip6` to a routable address. The decisive case is
**bidirectional media to a real external v6 peer, not loopback** — everything else
only proves the 440-vs-success branch.

Also: `443` in both directions (v4 peer on a v6 allocation and the reverse), Send
indication with a mismatched peer dropped but the relay still usable afterwards,
`EVEN-PORT` on a v6 allocation, and the Tier-0 peer-filter cases above.

### 5. DTLS demux path (`[turn.dtls] demux = true`)

Currently off by default *because* this section is empty. Filling it in is what
allows the default to flip.

- Match whatever the stock path achieved, first. A better design that is less
  verified is not an improvement.
- Then the properties the stock path cannot have: several silent handshakes held
  open while a normal client connects **immediately** (not after a timeout window);
  `max_handshakes_per_sec_per_ip` refusing before any DTLS state exists;
  `cert_reload_secs` rotating for new sessions while live ones continue;
  `turna_dtls_handshake_failures_total` moving for a client with no shared cipher.
- **Verify the cookie exchange is still there** — capture the handshake and confirm
  the HelloVerifyRequest round-trip. The whole change rests on the assumption that
  it lives in `DTLSConn` rather than the replaced listener. Confirm it; do not
  reason about it.

### 6. QUIC / WebTransport

No interop test had ever been recorded for either path, and the stated reason was
that no off-the-shelf TURN-over-QUIC client exists. True, and not a reason to stop:
the wire format inside a QUIC bidi stream is the same length-delimited STUN that
TURN-over-TCP uses, so a client is a few hundred lines. It now exists:

```
cargo build --release -p turna-load-test --features quic
target/release/turna-load-test --server 127.0.0.1:3479 --secret "$SECRET" quic-check
```

`quic-check` does a full authenticated Allocate plus CreatePermission over a bidi
control stream, which exercises the ingress, the stream framer, the per-stream reply
routing and the processor together. It accepts any server certificate — a
verification client, not a library. **Runs on a dev machine**, no stand needed.

`quic-check` now covers **relayed media too**: it binds a peer socket, channel-binds
it, pushes ChannelData down the QUIC stream and requires the frames to arrive at the
peer, then requires the peer's reply back as ChannelData on the same stream. That
check exists because a datapath can answer every control request and forward nothing
— the io_uring backend did exactly that for three hours at 10 800 allocations/s.

What it does not cover: the WebTransport/H3 path (needs either a browser page writing
framed STUN over `new WebTransport()`, or a `wtransport` client — same shape as this
one).

Also now testable, and the check that would have caught the previous silent no-op on
H3: set small stream counts and a small datagram buffer in `[turn.quic]` and confirm
**both** paths enforce them.

---

## Tier 3 — hardware, and only worth it with a decision behind it

`io_uring` and `AF_XDP` need the target NIC and kernel; `AF_XDP` also needs an
external XDP program on the bound queue. Neither is a production recommendation
today, so treat these as capacity experiments rather than release gates.

SCTP is deliberately excluded: it stays refused under `production = true` and is not
being matured, so spending a stand slot on it would be work for a feature with no
RFC and no users. If the decision is ever to keep it, it needs the hardening every
other listener already has first (per-IP cap, rate limit, metrics, readiness gauge,
cooperative drain) — not an interop run.

---

## What "evidence" means here

For each run, record: date, build (`git rev-parse HEAD` and the feature flags),
client and version, the case list with pass/fail, **and the metric or capture that
proved each pass**. A checkbox with no artifact behind it is the failure mode this
repo already has history with.
