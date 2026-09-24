# Production readiness and known limitations

This document is the operational risk register for Turna: what is safe to run
today, what is experimental, and which configuration keeps you on the most
verified path.

## Recommended production profile


The canonical GA topology is one TURN dataplane process/pod per public IP and
relay range. Use `transport = "tokio"`, keep gossip cluster mode disabled, and
run control-plane/admin separately. Runtime management persistence requires a
shared Tarantool backend even in standalone dataplane mode:

Use this profile unless you are deliberately testing an experimental datapath:

```toml
production = true

[turn]
external_ip = "203.0.113.10"
transport = "tokio"

[turn.auth]
shared_secret = "file:///etc/turna/secrets/shared_secret"

[turn.relay.quota]
max_per_user = 100
# Finite per-user byte/s cap. Under production = true the validator REJECTS an
# unlimited cap (max_bytes_per_sec_per_allocation = 0) unless you also set
# allow_unlimited_bandwidth = true to explicitly accept that risk.
max_bytes_per_sec_per_allocation = 12500000   # ~100 Mbit/s per user; set to your ceiling

[health]
# Loopback. This endpoint serves the entire Prometheus surface, not just
# /health, so give it a PRIVATE address if a remote Prometheus scrapes it —
# never 0.0.0.0.
listen = "127.0.0.1:9090"

[management]
listen = "127.0.0.1:5350"


[cluster]
node_id = "turna-prod-1"
cluster_mode = false

[cluster.backend]
type = "tarantool"
uri = "tarantool.internal:3301"
user = "turna"
password = "file:///run/secrets/tarantool-password"
pool_size = 8

[cluster.persistence]
mode = "write_behind"
```

Production checklist:

- Generate `turn.auth.shared_secret` with `openssl rand -hex 32`.
- Set `turn.external_ip` to a concrete IPv4/IPv6 address. Empty values are
  refused in production, and invalid strings are rejected at config validation.
- Prefer `transport = "tokio"` for the public production path.
- Keep `/health`, `/status`, `/metrics`, and the gRPC management port off the
  public Internet.
- Use mTLS when the gRPC control plane is reachable from anywhere except
  loopback.
- In cluster mode, set a unique `cluster.node_id` per host and the same
  `cluster.cluster_name`, `cluster.cluster_secret`, shared TURN secret, and
  migration ticket secret on every node.
- For Tarantool persistence, set `[cluster.backend] user/password` and monitor
  writer drops.

## Support tiers

| Area | Status | Production guidance |
|---|---|---|
| UDP TURN/STUN over tokio | Mainline | Recommended baseline. Endurance re-recorded against this release (`docs/soak/endurance-2026-08-19.md`): 3 h, 13.7 M allocations, 441 M packets, RSS +0.2 %, no fd or thread growth, no dropped packets, no panics, clean drain. |
| TURNS / TLS-over-TCP | **Supported** | Metrics (`turna_tls_*`), `max_connections_per_ip`, per-IP handshake rate limit, mTLS (verified incl. the refusal case) and ALPN strict mode, certificate hot-reload, cooperative drain. Three lines of evidence: browser interop across three engines (`docs/interop/turns-browsers-2026-08-18.md`), a Let's Encrypt chain validated by a verifying client against a public deployment, and **24 h under load** — 9.6 h of relayed media at zero loss plus 4.8 h of allocation churn at 441/s, no leak on any signal (`docs/soak/endurance-24h-2026-08-22.md`). |
| RFC 6062 TCP relay allocations | Beta, allowed in production | The `production = true` refusal was lifted on 2026-08-25: interop is recorded against our own client and against coturn's (`docs/interop/coturn-2026-08-23.md`), including the pipelined `ConnectionBind` case that no independent client had exercised before. What the gate used to stand in for — a sizing decision, since each relayed peer costs a listener and a connection — is now yours to make. Still IPv4-only. |
| TURN-over-SCTP | **Supported on Linux/tokio** | Opt-in native SCTP, allowed in production; requires kernel support and IP protocol 132 reachability. Plaintext, UDP peer-side relay. [Evidence](verification/sctp-supported-2026-09-18.md). |
| Third-party auth (RFC 7635 OAuth) | **Refused in production** | Same gate on `[turn.auth.oauth].enabled`. |
| IPv6 relayed transport | Opt-in, verified | Set `[turn] external_ip6` to a routable IPv6 address. Unset (default) keeps the old behaviour: IPv6 Allocate → `440`. Relayed media verified between two **routable** global v6 addresses with the peer filter in its `lan` profile and no loopback concession (`docs/interop/relayed-media-2026-08-19.md`), plus interop against coturn's client (`docs/interop/coturn-2026-08-23.md`). Not covered: routing between different hosts, and `ADDITIONAL-ADDRESS-FAMILY`. |
| DTLS | **Supported**, optional feature | Verified on the shipped stack (`crates/dtls`): interop with OpenSSL and coturn's client, a 300 000-packet spoofed-source flood that allocates no state, and 24 h under load with zero packet loss (`docs/interop/dtls-stack-2026-09-16.md`, `docs/soak/soak-24h-dtls-2026-09-15.md`). The default path is `[turn.dtls] demux = true` (since 0.5.0): concurrent handshakes, pre-handshake admission, per-IP handshake rate limit, certificate hot-reload. `demux = false` selects the stock listener, which has neither the rate limit nor hot reload. Session and per-IP caps, idle reaper, bounded egress, MTU enforcement, metrics. |
| QUIC / WebTransport | Optional features; supported on Linux/macOS with tokio | Project-specific TURN mappings. Functional, lifecycle/limits, 20-minute load and WAN checks recorded; WebTransport also has Chrome browser evidence. DATAGRAM delivery is unreliable. No multi-day endurance or independent raw-QUIC TURN interoperability claim. See [support record](verification/quic-webtransport-supported-2026-09-18.md). |
| io_uring | Supported on Linux, opt-in | Explicit `transport = "io_uring"`, built with `io-uring`. Tested kernels 6.8.0-87 and 6.14.0-33; 134 MiB and 1073 MiB RSS respectively in different worker/host configurations, not a kernel-only comparison. [Evidence and deployment scope](verification/io-uring-supported-2026-09-19.md). |
| AF_XDP | Supported within verified Linux IPv4 UDP copy-mode scope | Opt-in; SKB/native copy on Linux 6.8.0-87 / `virtio_net`, two queues. Zero-copy unverified; prior WAN churn timeouts unexplained. [Evidence](verification/af-xdp-supported-2026-09-22.md). |
| Cluster redirect/gossip | Implemented path | Useful for new-client distribution; secure gossip with `cluster_secret`. |
| Tarantool allocation persistence/failover | Implemented path | Monitor writer drops/errors; validate failover in your environment. |
| Runtime user CRUD over gRPC | Implemented (requires Tarantool backend) | `AddUser`/`RemoveUser` via the control-plane gRPC; users persist in the shared backend and nodes pick them up at startup and via periodic refresh. Needs `[cluster.backend] type = "tarantool"`. |

## Risk register

### R1 — `transport = "auto"` can select a backend you did not intend

The config enum supports `auto`, `tokio`, `io_uring`, and `af_xdp`. `auto` is
convenient for development and benchmark hosts, but production should be
explicit so a kernel/build capability does not silently change the datapath.

- **Severity:** Medium
- **Mitigation:** set `transport = "tokio"` in production configs and Helm
  values unless you are intentionally validating another backend.

### R2 — io_uring kernel and memory requirements

The supported UDP datapath requires kernel io_uring access and sufficient memory
for each worker's buffers and rings. Worker count defaults to available parallelism;
`TURNA_IOURING_WORKERS` overrides it. Support does not imply a fixed memory cost
or verified behaviour on every kernel and security policy.

- **Severity:** Medium
- **Mitigation:** select the backend explicitly, size workers and relay capacity,
  and run recovery/drain, functional and load checks after deployment changes.
  See the [support record](verification/io-uring-supported-2026-09-19.md) and
  [operator runbook](runbooks/io-uring.md). Tokio remains the default.

### R3 — AF_XDP support is scoped to a verified deployment

AF_XDP is supported for the documented Linux IPv4 UDP copy-mode deployment:
6.8.0-87, `virtio_net`, two queues, SKB/copy and native/copy. The active path is
`turna_transport::af_xdp::xsk::XskDatapath`; the node owns its embedded selective
XDP program. It is never auto-selected. [Evidence](verification/af-xdp-supported-2026-09-22.md).

The native four-hour media run met the agreed 99.99% delivery threshold, with
37 missing echoes recorded rather than hidden. The final 15-minute native churn
completed 49,647/49,647 operations with zero errors and full cleanup. Previous
WAN churn timeouts still have no established cause; a passing run is not a fix.

Fixed geometry is validated at startup: frames 4096 bytes, rings 2048 entries,
frame_count at most 4096. Inert geometry overrides are refused. All RX queues
must be configured. Native attach is independent of copy/zero-copy selection.

- Revalidate after kernel, NIC, driver or topology changes. Zero-copy, IPv6 WAN,
  cold-neighbor and route-change behavior are outside this evidence.
- XDP redirect bypasses ordinary UDP INPUT filtering. The selective destination
  IP/port filter is not a source-IP ACL; retain application auth, limits and peer policy.
- Capability-only setup needs privileges for XSK/BPF/XDP, not just CAP_NET_RAW.
  A support label does not certify an unsafe-code audit or every listener combination.

### R4 — Optional encrypted transports are less exercised than UDP

TURNS, DTLS, QUIC and WebTransport are valuable for blocked networks, but their
coverage is thinner than the core UDP TURN path.

- **Severity:** Low–Medium depending on client population.
- **Mitigation:** run explicit interop tests for every client stack you support,
  and keep UDP/tokio as the fallback path.

Known residual gaps, per transport:

- **DTLS:** the listener's `accept()` runs the whole handshake inline in
  `webrtc-dtls` with no timeout of its own
  ([webrtc-rs/webrtc#614](https://github.com/webrtc-rs/webrtc/issues/614)), so a
  peer that starts a handshake and goes silent used to park the accept loop
  **forever** — a one-packet, silent DTLS outage: socket bound, process healthy,
  `turna_dtls_readiness` still Ready. `[turn.dtls].accept_timeout_secs` (default
  10) now bounds it and counts abandonments
  (`turna_dtls_accept_timeouts_total`). That restores liveness but is a
  mitigation, not a fix: an attacker still consumes one timeout window at a time,
  so new-session throughput degrades under a deliberate flood. The fix is owning
  the UDP demultiplexer so handshakes run concurrently instead of serially inside
  `accept()` — implemented as `[turn.dtls] demux = true`, which is the default
  and brings pre-handshake admission, a per-IP handshake rate limit, certificate
  hot-reload and observable handshake failures. (Earlier revisions of this
  paragraph said "off by default"; demux is the default since 0.5.0.) DTLS 1.2 only.

  **Re-verified against the shipped stack on 2026-09-16** —
  `docs/interop/dtls-stack-2026-09-16.md`. A spoofed flood of 300 000 valid
  ClientHellos allocates no state while a real client still completes a
  handshake; 24 hours under load with zero packet loss; 20 of 20 handshakes at
  3 % path loss; interop with OpenSSL and with coturn's client; certificate
  rotation takes a new pair and keeps the old one when the new is unusable.
  Untested: end-to-end relay across two hosts, and the cause of two failed
  handshake attempts before each success.

  Since 0.5.0 the demux path also performs **stateless address validation**
  before allocating anything: a ClientHello without a cookie this node issued is
  answered with a HelloVerifyRequest (RFC 6347 §4.2.1) and no state is kept.
  Without it, one spoofed ~100-byte ClientHello bought a channel, a map entry, a
  connection and a task for `accept_timeout_secs` — and nothing bounded that,
  because `max_sessions` counts handshakes that already succeeded. A flood was an
  out-of-memory kill in seconds, from any address, with no credentials. A
  `max_pending_handshakes` cap (512) remains as the backstop behind the cookie.

  One caveat on that: `webrtc-dtls` performs its own HelloVerifyRequest inside
  the connection. If it still does after this gate, a client pays two cookie
  round trips — slower, not broken. Watch handshake latency when you enable
  DTLS.
- **QUIC/WebTransport:** the `[turn.quic]` transport limits (stream counts,
  datagram buffer, idle timeout) now apply on **both** paths. `alpn` is inert
  under WebTransport (wtransport forces `h3`).
  `max_handshakes_per_sec_per_ip` and `max_sessions_per_ip` default to 8 and 16
  since 0.5.0; both were 0 (unlimited), which left `max_sessions` — a global
  number — as the only bound, and a global bound is exhausted by one host.

  Since 0.5.0 an Initial from an address quinn has not validated is answered
  with a Retry (RFC 9000 §8.1) rather than a handshake. Without it every spoofed
  Initial bought a full TLS 1.3 handshake, ECDHE and a certificate signature
  included — a cryptographic denial of service that needs no amplification to
  work. The WebTransport path does the same: `wtransport` 0.7 exposes
  `remote_address_validated()` and `retry()` on its `IncomingSession`, and there
  the check runs **before** the per-IP tables are touched — admitting an
  unvalidated Initial would otherwise let a spoofed source consume a slot
  belonging to an address that never sent anything.
- **Evidence status differs, and the difference is what to read.** All four
  transports now have recorded runs against the current code, but they are not
  equally strong:
  - **TURNS — supported.** Browser interop across three engines, a Let's Encrypt
    chain validated by a verifying client, coturn interop, and 24 h under load
    with zero relayed-frame loss.
  - **DTLS — supported.** Allocation and media on both listener paths, interop
    with OpenSSL and coturn's client (`docs/interop/coturn-2026-08-23.md`,
    `docs/interop/dtls-stack-2026-09-16.md`), and 24 h under load on the shipped
    stack (`docs/soak/soak-24h-dtls-2026-09-15.md`).
  - **WebTransport — supported.** Browser and transport verification within the
    scope in [the support record](verification/quic-webtransport-supported-2026-09-18.md).
  - **QUIC — supported.** Maintained project-specific TURN mapping. Independent
    raw-QUIC TURN interoperability is not established; this is an explicit scope
    limitation, not a claim that another implementation cannot be written.

  The gate is `docs/verification/encrypted-transports.md`; operator response for
  the alerts is `docs/runbooks/encrypted-transports.md`.

### R9 — RFC 7635 OAuth remains refused in production

`config::validate()` rejects `production = true` with `turn.auth.oauth.enabled`.
OAuth still needs verification against a real authorization server. Do not
bypass normal production checks just to enable it.

The RFC 6062 gate was lifted on 2026-08-25. The SCTP gate is now lifted for
Linux/tokio after native functional, lifecycle/limits and WAN verification;
see [SCTP support evidence](verification/sctp-supported-2026-09-18.md).
Platform, backend, feature availability and framing validation remain enforced.

### R10 — IPv6 relayed transport is opt-in

`[turn] external_ip6` enables IPv6 relaying: the relay socket is bound in the
family the client requested and the matching address is advertised. Left empty
(the default) the node behaves exactly as before — an explicit IPv6 Allocate is
answered `440 Address Family not Supported`.

- **Severity:** Low-to-Medium. Unset, an IPv6-only client cannot obtain a relayed
  candidate. Set, the path has relayed-media evidence between two routable global
  addresses and interop with coturn's client
  (`docs/interop/relayed-media-2026-08-19.md`,
  `docs/interop/coturn-2026-08-23.md`) — what it lacks is a run across *different
  hosts*, since both addresses in the recorded run belong to one machine.
- **Mitigation:** if you leave it unset, ensure clients can reach the server over
  IPv4 and do not advertise an IPv6-only TURN URI. If you set it, confirm your own
  clients get a routable v6 candidate — the checks are in
  `docs/verification/encrypted-transports.md` → relayed address family.
- **Known limits:** one family per allocation (cross-family peers get `443`);
  `ADDITIONAL-ADDRESS-FAMILY` not implemented (storage decision pending —
  `docs/design/additional-address-family.md`); RFC 6062 TCP relay stays IPv4-only.
  The relay socket *is* bound `IPV6_V6ONLY`, so the family separation is enforced
  at the socket as well as by the 443 check.

### R11 — enabling a transport without its Cargo feature

`[turn.dtls]`, `[turn.quic]` and `[turn.quic] web_transport` fail startup if the
binary lacks the matching feature (`dtls`, `quic`, `web-transport`), instead of
running without the listener the operator asked for. `[tls]` follows the same
model via the `tls` feature. This is distinct from R9: R9 is a *policy* refusal of
a finished-but-unverified feature; this is a *build* mismatch.

- **Severity:** Low (fails closed).
- **Mitigation:** build with the features you configure; the error message names
  the required flag.

### R12 — the node did not exit on `SIGTERM` (fixed 2026-08-28)

**Every restart on every node, in every configuration.** `Runtime::drop` waits for
each spawned task, and four metric tickers loop forever by design — one says "Runs
until process exit" in its own comment. So the drop blocked and the process stayed
alive until something killed it.

Measured before: alive past 45 s after `SIGTERM`, two threads remaining, one a
worker in `hrtimer_nanosleep`. After `rt.shutdown_timeout(5s)`: exits in ~12 s with
status 0.

*Impact while it existed:* an orchestrator waited out its termination grace period
on every rollout and then killed hard. Drain itself was correct — allocations were
released and `all allocations drained` appears in the log within milliseconds — so
the symptom looked like a slow shutdown rather than a failure.

*Why it survived:* the wait came after the last line anything writes, so logs ended
looking clean. And every verification script finished by killing the node with
`SIGKILL`, so none of them could observe it. `scripts/verify/dtls-demux.sh` was the
first to *assert* that the node exits on its own, and found it on its first clean
run.

*Generalisable:* a check that observes a process is weaker than one that requires a
result. Nine scripts watched shutdown happen; the tenth demanded it complete, and
only that one worked.

*Action for operators:* if your termination grace period was lengthened because
turna "took a while to stop", it can be shortened.

### R5 — Cluster gossip must be authenticated on any shared network

An empty `cluster.cluster_secret` leaves gossip unauthenticated. That is useful
for local development but unsafe on any network where untrusted hosts can reach
the gossip port.

- **Severity:** High in shared networks.
- **Mitigation:** set the same strong `cluster_secret` on every node and limit
  UDP 7946 to the private cluster network.

### R6 — Tarantool write-behind can drop events under overload

Persistence is write-behind: the datapath does not block on every backend write.
If the bounded writer channel fills, events are dropped and the metric
`tarantool_writes_dropped_total` increases.

- **Severity:** High for HA/failover correctness.
- **Mitigation:** alert on any non-zero write drops, monitor
  `tarantool_writer_errors_total`, and size Tarantool/pool/batches for your
  allocation churn.

### R7 — Cross-node migration requires identical ticket secrets

When `[turn.migration] enabled = true`, mobility tickets are signed by
`ticket_secret`. A cluster where nodes use different values cannot validate one
another's tickets.

- **Severity:** High if mobility is required.
- **Mitigation:** set the same non-empty `turn.migration.ticket_secret` on every
  node. Empty is a hard validation error when migration and cluster mode are
  both enabled.

### R8 — runtime user management requires the Tarantool backend

`AddUser`/`RemoveUser` on the control-plane gRPC persist long-term users to the
shared state backend. No plaintext password is stored — only the two
pre-derived long-term keys (RFC 5389 MD5 key and RFC 8489 SHA-256 key). Nodes
load users from the backend at startup and re-read them every
`cluster.persistence.user_refresh_secs` seconds, so additions apply without a
restart. Because the control-plane is a separate process, this only works with
`[cluster.backend] type = "tarantool"`; an in-memory backend is process-local
and never reaches the nodes.

- **Severity:** Low–Medium. Without a Tarantool backend, runtime user
  management is unavailable (the RPC returns an explicit unimplemented error)
  and you fall back to config/static users or shared-secret credentials.
- **Mitigation:** for runtime management, run the Tarantool backend with the
  **same `[turn] realm` on the control-plane and every node** (long-term keys
  are realm-bound, so a realm mismatch makes them fail to verify). Add users
  with `turnactl user add <u> <p>` or grpcurl. Note: user *deletion* reaches a
  running node on its next restart (or use `remove --force` to drop the user's
  active allocations on the serving node); periodic refresh propagates
  additions/updates, not deletions.

### R13 — shared-secret rotation — RESOLVED

**Superseded.** This entry recorded, from a 2026-08-28 measurement, that `SIGHUP`
was not handled and that `UpdateConfig` carried allocation limits rather than the
secret, so `[turn.auth] shared_secret` changed only with a restart.

`SIGHUP` is now handled: the node re-reads its config file and republishes the
SharedSecret backends without restarting. A rotation is: new secret into
`shared_secret`, old one into `previous_shared_secret`, SIGHUP each node, wait for
`turna_auth_previous_secret_total` to flatten, remove the old secret, SIGHUP
again. `UpdateConfig` still does not carry the secret, deliberately — see
`docs/OPEN-DECISIONS.md` §0 for why the management API was the wrong channel.

*Action:* none. Rotation is a config reload, not a rolling upgrade. On a non-unix
target there is no SIGHUP and the restart still applies.

## Metrics to watch first

| Metric | Why it matters |
|---|---|
| `turna_active_allocations` | Capacity and load. |
| `turna_total_allocations` | Allocation creation rate. |
| `turna_auth_failures` / `turna_auth_failures_by_reason_total` | Bad credentials, brute force, clock/secret mismatch. |
| `turna_peer_rejected_total` | Peer-filter blocks; useful for SSRF/private-address probing. |
| `turna_quota_exceeded_total` | Abuse or too-tight quota. |
| `turna_send_queue_dropped_total` | Internal backpressure. |
| `turna_recv_workers_alive` | Partial datapath failure. The node keeps reporting Ready while a fraction of clients go unserved, and it does not recover. Alert on any decrease. |
| `turna_unauth_replies_suppressed_total` | Reflection: spoofed requests naming a victim as the source, or clients looping on authentication. |
| `turna_rate_limiter_evictions_total` | Table churn — a spoofed-source flood, or a client population larger than `max_entries`. |
| `turna_dtls_cookie_challenges_total` / `turna_dtls_rejected_pending_cap_total` | Spoofed DTLS handshakes turned away at the door, and the backstop behind them. |
| `turna_quic_retries_sent_total` | Spoofed QUIC Initials. One per real client per first connection; far above that is a flood. |
| `tarantool_writer_errors_total` | Backend write failures. |
| `tarantool_writes_dropped_total` | HA correctness risk; page on any sustained increase. |
| `failover_errors_total` | Failover sweeps failing. |
| `failover_sweep_duration_us` | Slow failover scans. |
| `turna_relay_route_forwarded_ratio` | io_uring migration forwarding cost; should be zero on tokio. |
| `turna_tls_handshake_failures_total` / `turna_tls_handshake_timeouts_total` | TURNS client/cert mismatch, or a scanner hitting 5349. |
| `turna_tls_rejected_over_cap_total` / `turna_tls_rejected_per_ip_total` | TURNS connection caps being hit. |
| `turna_tls_accept_errors_total` | fd exhaustion (EMFILE); the listener survives but is degraded. |
| `turna_tls_cert_reload_failures_total` | a rotated certificate failed to load; the previous one is still in service. |
| `turna_dtls_outbound_oversize_total` | relayed datagrams exceed `[turn.dtls].mtu` and are being dropped. |
| `turna_quic_rejected_over_cap_total` / `turna_quic_rejected_per_ip_total` | QUIC session caps being hit. |
| `turna_quic_control_dropped_no_stream_total` | QUIC control responses with no stream to answer on (client framing problem). |
| `turna_quic_rejected_rate_limit_total` | Handshake flood being shed; check whether it is abuse or a NAT. |
| `turna_tls_readiness` / `turna_dtls_readiness` / `turna_quic_readiness` | per-listener readiness; 2 = the listener died while the process lives. |

See [OBSERVABILITY.md](OBSERVABILITY.md) and `docs/alerts/turna.yml` for the
starter alert set.

## Verification status

### 2026-08-28 — measured, not argued

| what | result |
|---|---|
| Packet-rate ceiling, 32-thread Threadripper 1950X | **112 000 pps**, 120 s, zero loss, zero egress drops. Measured twice, identically. |
| Shape above the ceiling | **A cliff, not a slope.** 120 000 fails; 128 000 sheds a million frames in two minutes. There is no warning band. |
| DTLS demux path | 9 of 9. Both §7 P0 requirements confirmed: certificate hot-reload, and the per-IP handshake limiter refusing 15 handshakes before any DTLS state existed. |
| Mixed UDP + TURNS | No node interference. Zero loss on both transports in both phases, no egress drops. |
| Air-gap | 7 of 7, re-verified after all of the above. |
| Reproducible builds | 3 of 3 binaries byte-identical from different build directories. |
| Certificate rotation under load | 0 → 1, no failures, media uninterrupted. |
| Drain with abandoned allocations | 1 s, down from the full 30 s timeout. |
| Node exits on `SIGTERM` | Now yes — see R12. It did not before. |

**A node at 110 000 pps looks perfectly healthy and is one traffic bump from losing
6 % of media.** That is the operationally important part, more than the number
itself: run at a fraction of the measured ceiling, and watch
`turna_send_queue_dropped_total`, which is the counter that sees what a
client-side loss measurement cannot.

### What the same runs did not establish

**The mixed-load result held the wrong thing constant.** Loss was zero throughout,
and the TLS *generator* sent 17 % fewer frames in the mixed phase (72 012 → 60 010)
while UDP sent the same (180 060 → 180 059). The node delivered everything it was
given; the two generators were competing for the cores they share. Generators on
separate hosts would settle it.

**The demux path has no 24-hour run.** Nine checks over five minutes say it is
correct. The stock path holds the default on the strength of a recorded 24 hours,
and correctness is a different claim from stability.

**`turna_dtls_handshake_failures_total` did not move** on malformed input.
Possibly correct — the datagram may be discarded before the DTLS state machine
engages — but that check did not exercise the counter.

Full record: `docs/verification/runs-2026-08-28.md`, including three conclusions of
mine that the runs overturned.

### Earlier

| Area | Current verification expectation |
|---|---|
| Config schema and deploy template | `cargo test -p turna-config`; render Helm and parse extracted config. |
| UDP TURN/STUN path | Unit/integration/fuzz tests plus local `stunclient`/TURN allocation tests. |
| Docker/Helm packaging | `docker build -f deploy/Dockerfile .`, `helm lint`, `helm template`. |
| Tarantool cluster path | Run the smoke config and an induced node-death/failover test. |
| Experimental datapaths | Require host-specific Linux tests; do not infer production readiness from static compilation alone. |

When in doubt, choose the explicit `tokio` transport and prove every additional
feature before enabling it in front of users.

## Runtime management invariants

- `update_config` accepts only allocation count, default per-user allocation
  count, and `max_bytes_per_sec_per_allocation`. Listener addresses, external IP, relay range,
  worker/backend/identity/secrets, safety flags, and drain are immutable or have
  dedicated operations.
- The target node checks `expected_version` inside a serialized apply section,
  persists desired state, publishes one immutable snapshot, then confirms
  observed state. A no-op succeeds without increasing the version.
- `set_user_limits` takes the **userid without the TURN REST expiry prefix** —
  `alice`, not `1758012345:alice`. Before 0.5.0 it keyed on the raw USERNAME, so
  an override set for a user matched nothing and `max_per_user` counted each
  minted credential as a separate person, capping one pair of credentials rather
  than one user. Existing `max_per_user` values are therefore too low now that
  the field means what it says.
- `set_user_limits` resolves each field independently in this order: user,
  tenant, node runtime default, bootstrap default. Lowering a limit below usage
  does not destroy allocations; it rejects new allocations until usage falls.
- Startup loads the last confirmed observed config and limits before readiness.
  A backend/load/validation failure does not silently enable unlimited defaults.
- `max_bytes_per_sec_per_allocation` is bytes/second. `TopTalker.bandwidth_bps` and load metrics
  are telemetry in bits/second and are intentionally separate.

## Opt-in transports and datapaths — the short list

Everything below is opt-in; each row states its own support scope. The
authoritative per-feature register is `docs/protocol-gap.md`.

| Area | State |
|---|---|
| `io_uring` datapath | **Supported on Linux**, opt-in; tested on 6.8.0-87 and 6.14.0-33. Kernel and resource configuration still require deployment validation (R2). |
| `AF_XDP` datapath | Supported within verified Linux IPv4 UDP copy-mode scope (R3). Embedded filter, queue coverage, four-hour native media and 15-minute churn. [Limits and evidence](verification/af-xdp-supported-2026-09-22.md). |
| QUIC (`quic`) | **supported (Linux/macOS, tokio)** — Opt-in, project-specific TURN over raw QUIC; UDP peer relay. No independent raw-QUIC TURN client interoperability claim. Functional, lifecycle/limits, 20-minute load and WAN evidence recorded. See `docs/verification/quic-webtransport-supported-2026-09-18.md`. |
| WebTransport (`web-transport`) | **supported (Linux/macOS, tokio)** — Opt-in, project-specific TURN over WebTransport/H3; UDP peer relay. Browser interoperability recorded for tested Chrome versions; custom JavaScript client, not a WebRTC ICE TURN URI. H3 uses `h3` ALPN. See `docs/verification/quic-webtransport-supported-2026-09-18.md`. |
| TURNS | **Supported** — three-engine interop, public certificate chain, coturn interop, 24 h under load (R4) |
| DTLS | **Supported** — interop with OpenSSL and coturn's client, spoofed-source flood resistance, 24 h under load on the shipped stack (R4) |
| DTLS demux (`demux = true`) | Default since 0.5.0 — concurrent handshakes, pre-handshake admission, rate limit, cert reload; `scripts/verify/dtls-demux.sh` 9/9 and a 24 h soak (`docs/soak/soak-24h-dtls-2026-09-01.md`) |
| mTLS for TURNS clients | Opt-in (`[tls] client_ca`), verified incl. the refusal case; no CRL/OCSP by design |
| SCTP | Supported on Linux/tokio; plaintext, native SCTP (R9) |
| OAuth | Refused in production (R9) |
| RFC 6062 TCP relay | Beta, no longer refused — gate lifted 2026-08-25 (R9) |
| IPv6 relayed transport | Opt-in; conformance **and relayed media** recorded, loopback only (R10) |
| Mobility (RFC 8016) | Partial — same-node only; cross-node migration is not implemented (the placeholder module was removed) |
| NAT discovery (RFC 5780) | Not implemented — no codec; would also need a 2×IP/2×port topology |
| ALPN (RFC 7443) | Partial — no strict/compatible mode, unverified over DTLS |
| Multi-node cluster / failover | Experimental — see the HA boundary below |
| Transparent active-session HA | Out of GA scope |

## HA boundary

The multi-node chart/profile is experimental. Durable allocation metadata and
mobility tooling do not recreate a dead owner's relay socket or guarantee media
continuity. The GA claim is standalone recovery of management state, not
transparent active-session failover.

## Desired/observed convergence gate

Before promoting a managed node, confirm on every managed node:

- `desired_version == observed_version` (via `GetConfig`).
- No node is stuck `applying` / with an unconfirmed `pending_desired`.
- No unresolved rollback states (`failed` with `rolled_back`); a failed desired
  state is retained for diagnosis and is not auto-applied on restart.
- Stale-incarnation commands are not accumulating (they are finalized as
  `superseded` by the sweeper; a growing backlog is a signal to investigate).

## Sign-off

| Area             | Owner | Evidence | Status |
| ---------------- | ----- | -------- | ------ |
| Config           |       |          |        |
| Security         |       |          |        |
| Management state |       |          |        |
| Migration        |       |          |        |
| Admin            |       |          |        |
| Dataplane        |       |          |        |
| Backup/rollback  |       |          |        |
| Documentation    |       |          |        |

Each row is signed off against concrete evidence (a verification run, drill, or
audit reference), not a source-review assertion.
