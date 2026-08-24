# Verification plan — encrypted transports

The evidence gate for the encrypted transports. The hardening work is in source
(limits, metrics, readiness, drain, fail-fast); this document says what has to be
**run** on top of it.

**Much of it has now been run.** Results live in `docs/interop/` and `docs/soak/`
rather than inline here, so this stays a checklist rather than a log:

| Transport | Where it stands |
|---|---|
| TURNS | **supported** — three-engine browser interop, a public certificate chain validated by a verifying client, coturn interop, 24 h under load |
| DTLS | beta with interop — both listener paths, 20 min under load, agreement with coturn's client |
| WebTransport | beta with interop — a browser drives it end to end |
| QUIC | beta, and structurally stuck there — no RFC defines TURN over raw QUIC, so no independent implementation exists to test against |

What remains open per transport is stated in each record and in
`docs/OPEN-DECISIONS.md`.

Status labels match `docs/feature-support.md`.

## 0. Build matrix (blocking, cheap)

Run first — everything else depends on it.

```bash
cargo build --workspace --locked
cargo build -p turna-node --features tls
cargo build -p turna-node --features dtls
cargo build -p turna-node --features quic
cargo build -p turna-node --features web-transport
cargo build -p turna-node --features tls,dtls
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p turna-config
cargo test -p turna-relay
cargo test -p turna-node --features dtls    # validate_dtls unit tests
```

Note: `--all-features` may fail on the QUIC pair alone — `web-transport` pulls
wtransport's bundled quinn, which can conflict with the standalone `quinn`
dependency. Build the two QUIC features separately; a failure there is not a
transport-backend regression.

| check | result | date | notes |
|---|---|---|---|
| `--workspace` | | | |
| `--features tls` | | | |
| `--features dtls` | | | |
| `--features quic` | | | |
| `--features web-transport` | | | |
| clippy `-D warnings` | | | |

> **Order of work:** this file is the case list. Which runs to do first, what each
> one unblocks, and what counts as evidence is in
> [interop-plan.md](interop-plan.md). Start there — two of the runs are regression
> confirmation for wire-behaviour changes and come before any new-feature testing.

## 1. Interop — the part that actually decides beta → supported

**Some of this already exists — do not redo it blindly.** `docs/interop/` records
TURNS against Chrome 150 / Firefox 152 / Safari 26.5 (5/5 each: allocate,
auth-negative 401, end-to-end relay data, TLS transport, RAF), `docs/soak/` a 12h
relay soak, and `docs/dtls/` a DTLS 1.2 handshake with an operator certificate.
What none of it covers is the code *after* the transport hardening pass — new
limits, drain paths, cert reload and the repaired media path. Treat the rows below
as a re-run against the current build, and reuse the earlier harnesses.

One row per client stack you intend to support. "Allocate + relay" means a full
allocation and **bidirectional media**, not just a STUN Binding: the
client→peer media path is the one that regressed unnoticed before, because the
only existing DTLS test covers Binding alone.

| client | transport | Binding | Allocate | ChannelData both ways | result |
|---|---|---|---|---|---|
| coturn `turnutils_uclient` | TURNS (`-S`) | | | | |
| coturn `turnutils_uclient` | TCP relay (RFC 6062, `-T`) | | | | |
| browser WebRTC (Chrome) | `turns:` TCP | | | | |
| browser WebRTC (Firefox) | `turns:` TCP | | | | |
| pion/turn client | DTLS | | | | |
| libwebrtc / mobile SDK | DTLS | | | | |
| browser WebTransport | QUIC H3 | | | | |
| raw QUIC test client | QUIC (`web_transport = false`) | | | | |

Minimum bar to call a transport supported: two independent client stacks
completing bidirectional media, plus §2 and §3 below.

## 2. Behavioural checks

Each of these exercises a code path that has no automated coverage. Record
pass/fail and the metric that proved it.

### TURNS

- [ ] **Cert hot-reload.** Replace `cert_path`/`key_path` with a new pair while
      connections are live. Expect: `turna_tls_cert_reloads_total` increments
      within `cert_reload_secs`; existing connections keep working; a *new*
      connection presents the new certificate (`openssl s_client`).
- [ ] **Failed reload keeps serving.** Write a truncated PEM. Expect
      `turna_tls_cert_reload_failures_total` increments and TLS keeps working on
      the old material.
- [ ] **Per-IP cap.** Set `max_connections_per_ip = 2`, open 3 connections from
      one host. Expect the third refused and
      `turna_tls_rejected_per_ip_total` = 1.
- [ ] **Accept resilience.** Lower `ulimit -n` until `accept()` fails. Expect
      `turna_tls_accept_errors_total` climbing, log lines saying the listener is
      staying up, and recovery once fds free — **not** a dead listener.
- [ ] **Framing error.** Send garbage to 5349 after the handshake. Expect the
      connection closed and `turna_tls_framing_errors_total` = 1.
- [ ] **Allocation released on close.** Allocate over TURNS, note the relay port,
      kill the TCP connection. Expect `turna_active_allocations` to drop
      immediately (not after the lifetime) and the port reusable.
- [ ] **Drain.** `SIGTERM` with live connections. Expect
      `turna_tls_readiness = 3`, no new connections accepted, existing ones
      closed cleanly within `drain_grace_secs` — no truncated writes.

### DTLS

- [ ] **Large client record.** Send a Send-indication with a payload of ~8 KiB.
      Expect it to be processed, not a dropped session. (This is the buffer that
      used to be 2 KiB.)
- [ ] **Oversize egress.** Set `mtu = 600`, relay a 1200-byte peer packet.
      Expect `turna_dtls_outbound_oversize_total` incrementing and no IP
      fragments on the wire.
- [ ] **Per-IP cap** — as TURNS, with `max_sessions_per_ip`.
- [ ] **Empty cert opt-in.** Set both `cert_path` and `key_path` to `""`. Expect
      startup with the self-signed warning. Then set only one — expect a startup
      error naming the both-or-neither rule.
- [ ] **Cert rotation warning.** Touch the cert files. Expect the
      `cannot hot-reload` warning and *no* change in served certificate.
- [ ] **Readiness.** `turna_dtls_readiness` = 1 while listening, 3 on drain.

### QUIC / WebTransport

- [ ] **Media path.** Bidirectional ChannelData over a session (the regression
      that made this whole pass necessary).
- [ ] **Per-stream control replies** (both paths now): client opens a new bidi
      stream per request. Expect every request answered and
      `turna_quic_control_dropped_no_stream_total` = 0.
- [ ] **Session caps** — `max_sessions`, `max_sessions_per_ip`.
- [ ] **Transport limits (raw QUIC).** With `web_transport = false` and
      `max_bi_streams = 2`, have a client open 3 bidi streams; expect the third
      refused by QUIC flow control. On the WebTransport path expect the startup
      warning naming the unapplied keys instead — that path does not enforce them.
- [ ] **Pre-handshake refusal (WebTransport).** With `max_sessions_per_ip = 1`,
      open a second session from the same host. Expect
      `turna_quic_rejected_per_ip_total` = 1 and, in a capture, no completed H3
      CONNECT for the refused attempt.
- [ ] **Certificate hot-reload (WebTransport).** Replace the pair with sessions
      live. Expect `turna_quic_cert_reloads_total` to increment, live sessions
      unaffected, and a new session presenting the new certificate. Repeat with
      a truncated PEM and expect
      `turna_quic_cert_reload_failures_total` plus continued service on the old
      material. Repeat with `web_transport = false` — the raw path reloads too, via
      a different quinn call, so it needs its own run.
- [ ] **Drain.** `SIGTERM`; expect the accept loop to stop and readiness = 3.
- [ ] **Connection migration.** Change the client's source address mid-session
      (NAT rebind, or move a mobile client between networks). Expect
      `turna_quic_migrations_total` to increment within ~2s, peer→client media to
      keep flowing, and — with `max_sessions_per_ip` set — the per-IP count to
      move from the old IP to the new one rather than leaking on both.
- [ ] **Handshake rate limit.** Set `max_handshakes_per_sec_per_ip = 2`, open
      sessions in a tight loop from one host. Expect
      `turna_quic_rejected_rate_limit_total` climbing while established sessions
      stay serviceable, and no CPU spike (the refusal is pre-handshake). Then
      confirm a normal client still connects.

### Production gate (policy, not a bug)

- [ ] With `production = true`, each of `[turn.tcp_relay].enabled`,
      `[turn.sctp].enabled` and `[turn.auth.oauth].enabled` must make config
      validation **fail** with a message naming the key. Confirm all three, so a
      production cutover cannot silently enable an unverified datapath.
- [ ] With `production = false` the same configs must start normally — the gate is
      policy, not brokenness.

### Relayed address family

**Most of this section is now a single command.** `turna-load-test conformance`
probes the address-family and peer-filter cases below and prints the interpretation
of each answer, in seconds, with no browser and no stand:

```
cargo build --release -p turna-load-test
target/release/turna-load-test --server 127.0.0.1:3478 --secret "$SECRET" conformance
```

It reports rather than asserts where more than one answer is correct — an IPv6
Allocate is `440` with `external_ip6` unset and succeeds when it is set, and both are
right for their configuration. Only genuinely wrong answers fail the run. What it
does **not** cover is relayed media: an allocation that answers correctly can still
fail to pass packets, which is Tier 2.

With `[turn] external_ip6` **unset** (the default):

- [ ] An Allocate with `REQUESTED-ADDRESS-FAMILY = IPv6` is answered
      `440 Address Family not Supported`. Intended behaviour for a node with no v6
      address to hand out — record it so the limitation is evidenced.
- [ ] An Allocate carrying both `REQUESTED-ADDRESS-FAMILY` and
      `RESERVATION-TOKEN` is answered `400` (RFC 8656 §7.2 mutual exclusion).

With `[turn] external_ip6` **set** to a routable IPv6 address. Recorded
2026-08-23 on two routable global addresses, and independently by coturn's client
(`docs/interop/relayed-media-2026-08-19.md`, `docs/interop/coturn-2026-08-23.md`);
the boxes below stay as the checklist to repeat in your own environment:

- [ ] An Allocate with `REQUESTED-ADDRESS-FAMILY = IPv6` succeeds and
      `XOR-RELAYED-ADDRESS` carries `external_ip6`, not `external_ip`.
- [ ] Bidirectional media over that v6 allocation to a **real external** v6 peer
      (not loopback). This is the check that decides whether the feature works at
      all; the 440-vs-success path alone proves nothing.
      Loopback and ULA are testable today with
      `turna-load-test channel-data --family v6`, which allocates with
      REQUESTED-ADDRESS-FAMILY = IPv6, binds its peer on `[::1]`, and relays real
      traffic through it. That exercises the v6 relay socket, the v6 permission and
      the v6 channel — everything except routing off-host.
- [ ] CreatePermission for an IPv4 peer on a v6 allocation → `443 Peer Address
      Family Mismatch`, and no permission installed. Same for ChannelBind.
- [ ] A Send indication naming a cross-family peer is dropped and counted (no
      error response — indications have none), with the relay still usable after.
- [ ] The reverse: an IPv4 allocation with an IPv6 peer → `443`.
- [ ] EVEN-PORT (`R=1`) on a v6 allocation binds an even v6 port and the echoed
      RESERVATION-TOKEN claims its pair.
- [ ] A v4 literal in `external_ip6` fails validation at startup.
- [ ] RFC 6062: with `[turn.tcp_relay]` enabled and `external_ip6` set, an IPv6
      family TCP Allocate is still refused `440` (the TCP relay datapath has no v6
      path).
- [ ] Peer-filter bypass check. On a v6 allocation, CreatePermission for each of
      `64:ff9b::a9fe:a9fe` (NAT64 form of the cloud metadata address),
      `2002:c000:0204::1` (6to4), `2001::1` (Teredo) and `::203.0.113.1`
      (IPv4-compatible) must be answered `403 Forbidden`. These are the forms that
      would otherwise smuggle a v4 target past the v4 deny rules; a pass here is
      the evidence that enabling IPv6 did not open an SSRF path.
- [ ] DONT-FRAGMENT on a v6 allocation: a Send payload above the path MTU is
      dropped rather than fragmented (confirms `IPV6_MTU_DISCOVER` took effect —
      the v4 option silently does nothing on an `AF_INET6` socket).

### DTLS accept liveness (regression test for webrtc-rs/webrtc#614)

- [ ] Start a DTLS handshake and stop (send a ClientHello, answer the
      HelloVerifyRequest, then go silent). Within `accept_timeout_secs`,
      `turna_dtls_accept_timeouts_total` increments and **a second, normal client
      still completes a handshake**. Before the bound existed the second client
      never connected and nothing indicated why — this is the check that proves the
      listener is not parked.
- [ ] Repeat with several such peers in a loop and record how far new-session
      throughput drops. That number is the residual exposure until handshakes are
      made concurrent; write it down rather than assuming it is small.

### DTLS demux path (`[turn.dtls] demux = true`) — no evidence recorded yet

This path is off by default precisely because this section is empty. Filling it in
is what allows the default to flip.

- [ ] Full allocation + **bidirectional media** over DTLS with `demux = true`,
      matching whatever the stock path achieved in `docs/dtls/`. Until this passes,
      the demux path is strictly less trustworthy than the default, however much
      better its properties look on paper.
- [ ] Concurrency: hold several handshakes open and silent, then confirm a normal
      client still completes **immediately** (not after a timeout window). This is
      the difference from the stock path, so measure it rather than assume it.
- [ ] `max_handshakes_per_sec_per_ip` refuses over the limit with
      `turna_dtls_rejected_rate_limit_total` rising and no DTLS state created.
- [ ] `cert_reload_secs`: rotate the PEM files; a new session presents the new
      certificate, live sessions are untouched, `turna_dtls_cert_reloads_total`
      increments. Repeat with a truncated PEM and expect
      `turna_dtls_cert_reload_failures_total` plus continued service on the old
      material.
- [ ] `turna_dtls_handshake_failures_total` moves for a client with a bad cipher
      suite — the counter that is structurally impossible on the stock path.
- [ ] Cookie exchange still happens: capture the handshake and confirm the
      HelloVerifyRequest round-trip. It should be unaffected (it lives in
      `DTLSConn`, not the listener), but that is the assumption this whole change
      rests on, so verify it rather than reason about it.
- [ ] Setting `max_handshakes_per_sec_per_ip` or `cert_reload_secs` **without**
      `demux = true` must fail validation at startup.

### Fail-fast

- [ ] `[turn.dtls] enabled = true` on a build without `--features dtls` → startup
      error naming the flag.
- [ ] `[turn.quic] enabled = true` without `--features quic` → startup error.
- [ ] `[turn.quic] web_transport = true` without `--features web-transport` →
      startup error suggesting `web_transport = false`.

## 3. Soak

One run per transport, minimum 24h, on the profile you intend to operate.
Record start/end values, not just "no crash".

| transport | duration | sessions | offered load | RSS start/end | fds start/end | allocations leaked | verdict |
|---|---|---|---|---|---|---|---|
| TURNS | | | | | | | |
| DTLS | | | | | | | |
| QUIC | | | | | | | |

Watch for, specifically:

- **fd growth** — a leak here means connections are not being reaped.
- **`turna_active_allocations` not returning to baseline** after clients leave —
  the release-on-close path failing.
- **`*_active` gauges drifting upward** while sessions are actually closing — a
  counter bug (the TLS path uses an RAII guard to make this impossible; the
  others decrement explicitly).
- **`turna_*_readiness` flapping** — a listener restarting silently.

## 4. Missing automated coverage (known)

These are gaps in the test suite, not in the implementation. Closing them is the
cheapest way to stop re-running §2 by hand:

- `tests/integration` has exactly one encrypted-transport test
  (`stun_binding_over_dtls`) and it covers **STUN Binding only** — no media.
- No TURNS integration test. Adding one needs a TLS client dependency
  (`tokio-rustls`) in `tests/integration/Cargo.toml`.
- No RFC 6062 round-trip test (allocate TCP → CONNECT → ConnectionBind → relay).
- No QUIC/WebTransport loopback test, although both are loopback-testable
  in-process (see `docs/design/quic-webtransport.md` §5).
- Fuzzing covers the STUN/TURN decoders, which are shared by every transport, but
  not the TURNS stream framer or the QUIC `StreamFramer` reassembly.

## Sign-off

| area | owner | evidence | status |
|---|---|---|---|
| Build matrix | | | |
| TURNS interop | | | |
| DTLS interop | | | |
| QUIC interop | | | |
| Behavioural checks | | | |
| Soak | | | |

A row is signed off against a linked run or capture, not a source review.
