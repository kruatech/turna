# Verification plan — encrypted transports

What must be **run** before TURNS/DTLS move from beta to supported, and before
QUIC/WebTransport moves from experimental to beta. The hardening work is in
source (limits, metrics, readiness, drain, fail-fast); this document is the
evidence gate, and it is deliberately empty of results until someone runs it.

Status labels used here match `docs/feature-support.md`: **beta** = hardened in
source, no soak/interop evidence; **supported** = evidence recorded below.

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

## 1. Interop — the part that actually decides beta → supported

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
      material. With `web_transport = false` expect **no** reload at all.
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
