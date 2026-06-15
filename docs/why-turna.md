# Why turna

Turna is a TURN/STUN relay focused on the common WebRTC path: authenticated TURN
over UDP, strong peer filtering, cloud-native observability, and cluster-aware
operation. It is written in Rust and keeps the high-risk datapath code isolated
and audited.

Turna is **not** trying to be a flag-for-flag coturn clone. coturn remains the
safe choice when you need the broadest legacy compatibility today. Turna is for
operators who want a smaller, stricter, more observable TURN stack and are
willing to validate it against their own clients before production rollout.

Status legend: ✅ shipped · 🚧 implemented/experimental · 📋 planned.

## Design goals

1. **Secure defaults.** Reject placeholder secrets in production, require a real
   advertised IP, deny unsafe peer ranges by default, and fail on unknown config
   fields.
2. **Operational clarity.** `/health`, `/status`, `/metrics`, structured logs,
   OTLP traces, and explicit counters for auth failures, quota, parser rejects,
   peer-filter rejects and backend health.
3. **High-performance path without hiding risk.** Tokio UDP is the recommended
   baseline. io_uring, AF_XDP, QUIC/WebTransport and DTLS are available as
   explicit/feature-gated paths and are documented as experimental until proven
   in a given deployment.
4. **Cluster-aware deployment.** Gossip-based node discovery/redirects,
   Tarantool-backed allocation persistence, failover counters and drain mode are
   first-class concerns instead of external-only glue.
5. **Multi-tenant direction.** Tenant ids, realm isolation, disjoint relay-port
   pools and per-tenant quotas are represented in the config model.

## Current capability map

| Area | Turna status | Notes |
|---|---|---|
| STUN Binding | ✅ | Core parser and response path. |
| TURN Allocate / Refresh | ✅ | Authenticated allocation lifecycle. |
| CreatePermission / ChannelBind | ✅ | Permission and channel state are allocation-scoped. |
| Send Indication / ChannelData | ✅ | ChannelData fast path exists. |
| Long-term static users | ✅ | Config-driven static users. |
| Shared-secret time-limited credentials | ✅ | Coturn-compatible username/password formula for common WebRTC credential services. |
| Peer filtering | ✅ | Default `internet-facing` profile denies private/special-use targets. |
| Prometheus metrics / health | ✅ | See `OBSERVABILITY.md`. |
| gRPC management / `turnactl` | 🚧 | Status/drain/allocation/failover operations exist; runtime user CRUD is not implemented. |
| Tarantool backend | 🚧 | Implemented; production requires backend auth and monitoring writer drops. |
| Cluster redirect/gossip | 🚧 | Implemented path; secure gossip with `cluster_secret`. |
| TURNS / TCP/TLS | 🚧 | Feature-dependent and less exercised than UDP. |
| DTLS | 🚧 | Optional feature; validate with your clients. |
| QUIC/WebTransport | 🚧 | Optional/experimental. |
| io_uring | 🚧 | Experimental datapath; not recommended as default production path. |
| AF_XDP | 🚧 | Explicit opt-in Linux/NIC-specific backend. |
| OAuth RFC 7635 | 📋 | Not implemented. |
| SQL/Redis/Mongo user DB backends | 📋 | Not implemented. |
| Full coturn flag parity | 📋 | Not a near-term goal. |

## Why not just use coturn?

Use coturn when you need maximum maturity, broad DB/backend support, OAuth,
legacy flags, packaged distro defaults, or a well-known operational baseline.

Use Turna when these are more important for your deployment:

- a Rust codebase with unsafe code isolated mostly to transport/datapath layers;
- strict configuration parsing and validation;
- peer filtering that is secure by default for public TURN;
- first-class Prometheus/OTel/journald-friendly operation;
- a built-in cluster/failover model rather than only external load balancing;
- a smaller scope focused on WebRTC-style TURN credentials and relay semantics.

## What Turna deliberately does not promise yet

- It does not claim to outperform coturn until `bench/RESULTS.md` contains real
  reproducible numbers for a specific hardware/kernel/config combination.
- It does not claim full coturn compatibility until `tools/diff-test` covers the
  relevant STUN/TURN behaviours.
- It does not ship a built-in signaling server, browser demo, SFU, OAuth server,
  SQL/Redis/Mongo user DB, or runtime user CRUD.
- It does not make experimental datapaths production-safe just because they
  compile. See `PRODUCTION_READINESS.md` before enabling them.

## Drop-in expectations

For the common WebRTC setup, Turna aims to be operationally familiar:

- TURN URI and credentials are issued by your application/credential service.
- Shared-secret time-limited credentials use the coturn-style
  `<unix_expiry>:<userid>` username and HMAC password formula.
- UDP TURN relay semantics should match coturn on the wire; differences found by
  `tools/diff-test` should be treated as bugs or explicitly documented scope
  gaps.

## Security posture summary

- Placeholder secrets fail validation in production.
- `external_ip` is required in production and should be a concrete IPv4/IPv6
  address.
- Peer relay targets are filtered by default.
- Config typos and stale sections fail loudly via `deny_unknown_fields`.
- gRPC management is loopback by default and requires mTLS for non-loopback
  production exposure.
- Parser fuzzing, unsafe inventory and threat-model docs live under `docs/`.

See `docs/security/threat-model.md`, `docs/security/invariants.md`,
`docs/SECURITY.md`, and `docs/PRODUCTION_READINESS.md` for details.
