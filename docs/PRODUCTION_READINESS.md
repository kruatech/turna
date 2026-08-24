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
listen = "0.0.0.0:9090"

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
| RFC 6062 TCP relay allocations | **Refused in production** | `production = true` rejects `[turn.tcp_relay].enabled` — config validation fails, the node does not start. Test it with `production = false`; the gate lifts when interop and pipelined-client hardening are done. |
| TURN-over-SCTP | **Refused in production** | Same gate on `[turn.sctp].enabled`. No RFC defines SCTP for TURN; control channel only. Needs the host `sctp` kernel module. |
| Third-party auth (RFC 7635 OAuth) | **Refused in production** | Same gate on `[turn.auth.oauth].enabled`. |
| IPv6 relayed transport | Opt-in, verified | Set `[turn] external_ip6` to a routable IPv6 address. Unset (default) keeps the old behaviour: IPv6 Allocate → `440`. Relayed media verified between two **routable** global v6 addresses with the peer filter in its `lan` profile and no loopback concession (`docs/interop/relayed-media-2026-08-19.md`), plus interop against coturn's client (`docs/interop/coturn-2026-08-23.md`). Not covered: routing between different hosts, and `ADDITIONAL-ADDRESS-FAMILY`. |
| DTLS | Beta, optional feature | Session and per-IP caps, idle reaper, bounded egress, MTU enforcement, metrics, bounded accept (`accept_timeout_secs`). On the **default** path pre-handshake rate limiting is still missing — do not expose to an untrusted internet without upstream rate limiting. `[turn.dtls] demux = true` adds it, plus concurrent handshakes and certificate hot-reload, but is itself unverified. |
| QUIC / WebTransport | Optional feature | Both **beta**. Raw QUIC: allocation, relayed media both directions and 20 min under load at zero loss — but **no independent implementation exists**, because no RFC defines TURN over raw QUIC, so interop cannot be obtained from anyone. WebTransport: browser interop on record (Chrome 151 against a real certificate, `docs/interop/webtransport-browser-2026-08-20.md`) plus 20 min under load. The full `[turn.quic]` config applies on both paths. WebTransport residual — no client has exercised it. Neither has relayed-media evidence. |
| io_uring | Optional backend | Usable in production when explicitly enabled, on a kernel you have tested. Endurance and relaying are both on record (`docs/soak/endurance-2026-08-19.md`, Ubuntu 24.04 / 6.14): no leak over 3 h, ~4× tokio's Allocate throughput, ChannelData relayed at ~17 000 rps with zero errors. Costs ~1 GiB resident (pre-registered buffers). Not the default recommendation: io_uring behaviour is kernel-version-sensitive, so verify on yours before relying on it. |
| AF_XDP | Explicit opt-in backend | Never auto-selected. Correctness verified on a veth lab (`docs/interop/af-xdp-2026-08-19.md`): relayed media at three rates with zero loss after fixing an RX frame leak. Still needs a run on the target NIC — the lab attaches in SKB mode, which copies every frame and reproduces none of the kernel-bypass behaviour that AF_XDP is for. |
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

### R2 — io_uring is experimental

The io_uring datapath contains sharded ownership and drain logic, but it needs
runtime verification on the same kernel/NIC/load profile you plan to operate.
It is not the recommended default for a first production rollout.

- **Severity:** Medium
- **Mitigation:** use `tokio`; validate io_uring separately with
  `cargo test --features io-uring` and a drain-under-load run.

### R3 — AF_XDP is opt-in and environment-sensitive

`transport = "af_xdp"` is wired as an explicit backend when built on Linux with
`--features af-xdp`. The active path uses the XSK datapath from
`turna_transport::af_xdp::xsk`. The older `AfXdpTransport` wrapper in
`crates/transport/src/af_xdp.rs` remains a loud non-functional stub and is not
the runtime path.

AF_XDP requires privileges, NIC/queue setup and correct source/destination MAC
configuration. IPv4-only is no longer true — the v6 frame path and ICMPv6 ND are
implemented — and the XDP program is embedded and attached by the node itself, so no
external redirect plumbing is needed.

The veth lab step is done (`docs/interop/af-xdp-2026-08-19.md`), and it is worth
knowing what it cost: three separate lab faults masked the datapath entirely before
anything could be measured. Both ends of the veth in one namespace short-circuits
through `lo`; `frame_count` above twice the ring size kills RX silently; and the
`fill_ring_size`/`rx_ring_size`/`comp_ring_size`/`tx_ring_size` keys in
`[turn.af_xdp]` are accepted and ignored.

- **Severity:** High if enabled without a hardware-specific validation run.
- **Mitigation:** keep it disabled for normal production. The lab run is on record;
  repeat it on the target NIC, where the attach is native rather than SKB, before
  exposing traffic.

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
  `accept()` — and that is now implemented as `[turn.dtls] demux = true`, which
  also brings pre-handshake admission, a per-IP handshake rate limit, certificate
  hot-reload and observable handshake failures. It is **off by default** because
  it displaces the only DTLS path with recorded verification, so on a default
  deployment the residual gaps still stand: no pre-handshake rate limiting and no
  certificate hot-reload (a rotated cert needs a restart). DTLS 1.2 only.
- **QUIC/WebTransport:** the `[turn.quic]` transport limits (stream counts,
  datagram buffer, idle timeout) now apply on **both** paths. `alpn` is inert
  under WebTransport (wtransport forces `h3`).
  `max_handshakes_per_sec_per_ip` is **off by default**; set it on any
  internet-facing listener.
- **Evidence status differs, and the difference is what to read.** All four
  transports now have recorded runs against the current code, but they are not
  equally strong:
  - **TURNS — supported.** Browser interop across three engines, a Let's Encrypt
    chain validated by a verifying client, coturn interop, and 24 h under load
    with zero relayed-frame loss.
  - **DTLS — beta with interop.** Allocation and media on both listener paths,
    20 min under load, and agreement with coturn's client
    (`docs/interop/coturn-2026-08-23.md`) — an implementation nobody here wrote.
  - **WebTransport — beta with interop.** A browser drives it, with its own H3
    stack and hand-written STUN.
  - **QUIC — beta, and it stops there.** Correctness and endurance are recorded,
    but no RFC defines TURN over raw QUIC, so no second implementation exists and
    none can be written. This is not a testing gap.

  The gate is `docs/verification/encrypted-transports.md`; operator response for
  the alerts is `docs/runbooks/encrypted-transports.md`.

### R9 — experimental features are refused in production, and that is deliberate

`config::validate()` hard-fails when `production = true` and any of
`turn.tcp_relay.enabled`, `turn.sctp.enabled`, or `turn.auth.oauth.enabled` is
set. The node does not start with a diagnostic naming the key.

- **Severity:** none if understood; an outage if discovered during a production
  cutover.
- **Mitigation:** decide before the cutover whether you need any of them. If you
  do, the honest options are to run that deployment with `production = false`
  (which also disables the placeholder-secret and missing-`external_ip` checks —
  usually the wrong trade) or to keep the feature out of the production profile
  and finish its verification first.

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

## Metrics to watch first

| Metric | Why it matters |
|---|---|
| `turna_active_allocations` | Capacity and load. |
| `turna_total_allocations` | Allocation creation rate. |
| `turna_auth_failures` / `turna_auth_failures_by_reason_total` | Bad credentials, brute force, clock/secret mismatch. |
| `turna_peer_rejected_total` | Peer-filter blocks; useful for SSRF/private-address probing. |
| `turna_quota_exceeded_total` | Abuse or too-tight quota. |
| `turna_send_queue_dropped_total` | Internal backpressure. |
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
- `set_user_limits` resolves each field independently in this order: user,
  tenant, node runtime default, bootstrap default. Lowering a limit below usage
  does not destroy allocations; it rejects new allocations until usage falls.
- Startup loads the last confirmed observed config and limits before readiness.
  A backend/load/validation failure does not silently enable unlimited defaults.
- `max_bytes_per_sec_per_allocation` is bytes/second. `TopTalker.bandwidth_bps` and load metrics
  are telemetry in bits/second and are intentionally separate.

## Still experimental / partial — the short list

Everything below is opt-in and none of it is on the supported path. The
authoritative per-feature register is `docs/protocol-gap.md`.

| Area | State |
|---|---|
| `io_uring` datapath | Beta — endurance and relaying recorded on kernels **6.8 and 6.14**; version-sensitive, verify on yours (R2) |
| `AF_XDP` datapath | Beta (lab-verified) (R3) — correctness on a veth lab: relayed media at three rates with zero loss, ARP/NDP answered by the datapath itself. The XDP program is embedded and attached by the node (no external program), and the v6 frame path is implemented. **Not a capacity result**: veth attaches in SKB mode, which copies every frame. Validate on your NIC. |
| QUIC (raw) | Beta — interop recorded including relayed media both directions (R4) |
| WebTransport (H3) | Beta — browser interop (Chrome 151, real certificate) **and** 20 min under load at zero loss (R4) |
| TURNS | **Supported** — three-engine interop, public certificate chain, coturn interop, 24 h under load (R4) |
| DTLS | Beta — allocation and media on both listener paths, 20 min under load, **and interop against coturn's client** (R4) |
| DTLS demux (`demux = true`) | Opt-in, no evidence yet — concurrent handshakes, pre-handshake admission, rate limit, cert reload |
| mTLS for TURNS clients | Opt-in (`[tls] client_ca`), verified incl. the refusal case; no CRL/OCSP by design |
| RFC 6062 TCP relay, SCTP, OAuth | Refused in production (R9) |
| IPv6 relayed transport | Opt-in; conformance **and relayed media** recorded, loopback only (R10) |
| Mobility (RFC 8016) | Partial — same-node only; cross-node migration is unwired (`node_migration.rs` has no callers) |
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
