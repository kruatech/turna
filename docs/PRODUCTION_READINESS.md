# Production readiness and known limitations

This document is the operational risk register for Turna: what is safe to run
today, what is experimental, and which configuration keeps you on the most
verified path.

## Recommended production profile

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
max_bytes_per_sec = 0

[health]
listen = "0.0.0.0:9090"

[management]
listen = "127.0.0.1:5350"
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
| UDP TURN/STUN over tokio | Mainline | Recommended baseline. |
| TURNS / TLS-over-TCP | Implemented, feature-dependent | Test with your clients and certificates before relying on it. |
| RFC 6062 TCP relay allocations | Implemented path exists | Treat as less exercised than UDP until covered by your interop tests. |
| DTLS | Optional feature | Experimental; enable only after local load and interop tests. |
| QUIC / WebTransport | Optional feature | Experimental; product semantics are still evolving. |
| io_uring | Optional backend | Experimental; not the default production recommendation. |
| AF_XDP | Explicit opt-in backend | Experimental Linux/NIC-specific path; never auto-selected. |
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

AF_XDP requires privileges, NIC/queue setup, XDP redirect plumbing, IPv4-only
Phase-1 assumptions, and correct source/destination MAC configuration.

- **Severity:** High if enabled without a hardware-specific validation run.
- **Mitigation:** keep it disabled for normal production. Validate in a lab with
  veth/copy-mode and then the target NIC before exposing traffic.

### R4 — Optional encrypted transports are less exercised than UDP

TURNS, DTLS, QUIC and WebTransport are valuable for blocked networks, but their
coverage is thinner than the core UDP TURN path.

- **Severity:** Low–Medium depending on client population.
- **Mitigation:** run explicit interop tests for every client stack you support,
  and keep UDP/tokio as the fallback path.

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
