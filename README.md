# turna

High-performance TURN/STUN server written in Rust (RFC 5389, RFC 5766, RFC 8656).

[![CI](https://github.com/kruatech/turna/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/turna/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)

> Turna is the Turkish name of the crane — a migratory bird that relays itself
> across continents. This server does the same for your packets.

## Status

**Production GA (`0.3.0`).** The default **Tokio datapath** is the primary supported path:
STUN binding, the TURN allocation lifecycle, long-term-credential and JWT auth,
Prometheus/OpenTelemetry, config validation, durable runtime configuration,
per-subject limits, and graceful drain.

The new GA management changes are implemented in source but are **not considered
verified by this document** until the exact release commit passes the workspace,
Tarantool, frontend, container, Helm, migration, restart, and live relay gates in
[RELEASE.md](RELEASE.md).

The alternative transports are **not** on the same footing as the default path,
and they differ from each other:

- **Beta** — TLS-over-TCP (`tls`, TURNS), RFC 6062 TCP relay allocations, and
  DTLS (`dtls`). Hardened in source: connection/session limits including per-IP
  caps, Prometheus counters, per-listener readiness, cooperative drain,
  fail-fast startup, and prompt allocation release when a control connection
  closes. What they lack is *evidence* — no soak or interop run is recorded yet
  ([docs/verification/encrypted-transports.md](docs/verification/encrypted-transports.md)
  is the gate).
- **Experimental** — QUIC (`quic`) and WebTransport (`web-transport`), plus the
  `io-uring` and `af-xdp` datapaths. These still have functional gaps, not just
  missing tests: notably several `[turn.quic]` limits do not apply on the
  WebTransport path (the listener warns about this at startup) and QUIC
  connection migration is not detected.

Enabling a transport in config on a binary built without its Cargo feature is a
startup error, not a warning, so a configured listener is never silently absent.
For the authoritative per-feature state see
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) and
[docs/feature-support.md](docs/feature-support.md).

## Why turna


### GA management contract

`update_config` dynamically changes only `max_allocations`,
`max_allocations_per_user`, and `max_bytes_per_sec_per_allocation` (bytes/second). Changes are
published as one immutable versioned snapshot on the target node. `set_user_limits`
supports global, tenant, and realm/tenant/user overrides for allocation count,
bytes/second, and lifetime. Every field independently supports inherit, a finite
value, unlimited, or disabled where valid. Both RPCs require a target node,
expected version, and idempotency key; their responses come from the node's
durable terminal result rather than control-plane-local state.

- **Memory-safe core in Rust** with continuously fuzzed STUN/TURN parsers
  (`fuzz/`) and an [audited `unsafe` inventory](docs/unsafe-audit.md) confined to
  the transport/relay datapaths.
- **Batched UDP I/O** — `SO_REUSEPORT` recv workers with `recvmmsg`/`sendmmsg`
  and per-batch arena buffers; optional `io_uring` and `AF_XDP` datapaths behind
  features for kernel-bypass throughput.
- **Standalone-first management** — node-targeted, idempotent runtime config
  and user-limit commands with desired/observed versions and Tarantool-backed
  restart restore.
- **Experimental clustering** — gossip discovery, a hash ring, TURN redirects,
  and allocation-state tooling. It does **not** guarantee transparent survival
  of active allocations, relay-socket rehydration, or zero-gap rolling upgrades.
- **Operable** — gRPC control plane + `turnactl` CLI, Prometheus metrics and
  OpenTelemetry tracing, graceful drain and RFC 8016 session migration.

For a longer comparison and the design rationale, see
[docs/why-turna.md](docs/why-turna.md). Reproducible benchmarks against coturn
live in [bench/README.md](bench/README.md).

### Guarantees and limitations

| Guarantee                                     | Status                                        |
| --------------------------------------------- | --------------------------------------------- |
| Idempotent retry of management commands       | Supported                                     |
| Runtime config restore after restart          | Supported (management-backend profile)        |
| User-limits restore after restart             | Supported                                     |
| Existing allocation survives process crash    | Not guaranteed                                |
| Existing media path migrates to another node  | Not guaranteed                                |
| Drain waits indefinitely                       | No — bounded by `drain_grace_secs`            |
| Allocation released when its TCP/DTLS/QUIC connection closes | Supported (not left to TTL)     |
| Certificate rotation without restart           | TURNS only; DTLS and QUIC need a restart      |
| Multi-node ownership/state failover            | Experimental / limited scope                  |
| Transparent active-session (media) failover    | Out of GA scope                               |

"Supported" is a source-level statement pending the release verification gates
in [RELEASE.md](RELEASE.md); see [docs/feature-support.md](docs/feature-support.md)
for the full matrix and [docs/MANAGEMENT_API.md](docs/MANAGEMENT_API.md) for the
RPC contract.

## Features

- STUN binding and full TURN allocation lifecycle (Allocate / Refresh /
  CreatePermission / ChannelBind / Send & Data indications)
- UDP relay on the default path; TCP relay (RFC 6062) behind the `tls` feature,
  since RFC 6062 requires a TCP/TLS control connection
- Long-term credential mechanism, JWT-based auth, rate limiting and credential
  rotation; multi-tenant realms with per-tenant relay port pools and limits
- Pluggable state backend (in-memory, Tarantool) for clustered deployments
- gRPC control plane + CLI (`turnactl`) for live management
- OpenTelemetry tracing and Prometheus metrics out of the box
- Graceful drain and RFC 8016 session migration on the default (tokio) datapath
- Continuously fuzzed STUN/TURN parsers (cargo-fuzz)

## Quick start

### Binary

```bash
cargo build --release
./target/release/turna-node deploy/turn.toml
```

### Docker

```bash
docker build -f deploy/Dockerfile -t turna:local .
docker run --rm \
  -p 3478:3478/udp -p 3478:3478/tcp -p 9090:9090/tcp \
  -v "$PWD/deploy/turn.toml:/etc/turna/turn.toml:ro" \
  turna:local
```

### Kubernetes (Helm)

```bash
helm install turna deploy/helm/turna \
  --set turn.externalIP=203.0.113.10 \
  --set turn.auth.sharedSecret="$(openssl rand -hex 32)"
```

The chart keeps the TURN secret in a Kubernetes Secret, runs as a hardened
non-root pod, and separates the public TURN service from an internal
health/metrics service. See [docs/DEPLOY.md](docs/DEPLOY.md).

## Configuration

Minimal `turn.toml`:

```toml
production = false

[turn]
listen      = "0.0.0.0:3478"
external_ip = "203.0.113.10"   # your real public IP
realm       = "turna"

[turn.auth]
shared_secret = "use: openssl rand -hex 32"

[health]
listen = "0.0.0.0:9090"
```

`deploy/turn.toml` is a complete annotated example; every option is documented
in [docs/CONFIGURATION.md](docs/CONFIGURATION.md). With `production = true`,
config validation rejects placeholder secrets and a missing `external_ip`.

## Architecture

The workspace is split by domain so each concern is isolated:

- **Protocol** — `proto-stun`, `proto-turn`, `proto-rtp`, `packet`
- **Datapath** — `transport` (tokio / io_uring / AF_XDP / DTLS / QUIC),
  `relay`, `session`, `qos`
- **Auth & crypto** — `auth`, `crypto`
- **State & cluster** — `state-backend` (in-memory / Tarantool), `cluster`,
  `common`
- **Control & ops** — `control` (gRPC), `management`, `observability`,
  `health`, `rtp-analyzer`
- **Binaries** — `services/node` (`turna-node`),
  `services/control-plane` (`turna-control-plane`)
- **Tools** — `turnactl`, `benchmark`, `load-test`, `diff-test`, `garbage-gen`

Design notes (AF_XDP datapath, DTLS, QUIC/WebTransport, RFC 6062 TCP
allocations, allocation-store persistence) are under
[docs/design/](docs/design/); clustering is covered in
[docs/CLUSTER.md](docs/CLUSTER.md).

## Standards & feature support

`turna` implements STUN (RFC 5389) and TURN (RFC 5766, RFC 8656). The table
below summarises standards and transport maturity. For the authoritative,
per-feature production maturity always check
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) and
[docs/feature-support.md](docs/feature-support.md).

| Standard / capability | RFC | Status |
| --- | --- | --- |
| STUN Binding | RFC 5389 | Supported (default tokio datapath) |
| Message integrity, SHA-256 (`MESSAGE-INTEGRITY-SHA256`) | RFC 8489 | Supported |
| TURN allocation lifecycle, UDP relay | RFC 5766 / RFC 8656 | Supported (default tokio datapath) |
| TURN over TCP (TCP relay allocations) | RFC 6062 | Beta (requires the `tls` listener) |
| Session migration | RFC 8016 | Supported (tokio datapath) |
| TLS-over-TCP transport (`tls`) | — | Beta |
| DTLS transport (`dtls`) | RFC 7350 | Beta |
| QUIC transport (`quic`) | — | Experimental |
| WebTransport (`web-transport`) | — | Experimental |
| `io_uring` datapath | — | Experimental |
| `AF_XDP` datapath | — | Experimental |

Status legend: **Supported** — exercised on the primary path and intended for
production use. **Beta** — gated behind a Cargo feature, hardened in source
(limits, metrics, readiness, graceful drain) but without recorded soak/interop
evidence; test it with your own client stack first. **Experimental** — gated
behind a Cargo feature with known functional gaps; not for production.

## Observability

`turna-node` exposes Prometheus metrics and a health endpoint, and emits
OpenTelemetry traces. Each listener has its own readiness gauge
(`turna_transport_readiness`, `turna_tls_readiness`, `turna_dtls_readiness`,
`turna_quic_readiness`) plus per-transport counters, so a listener that dies
while the process survives is visible; operator response for the shipped alert
rules is in
[docs/runbooks/encrypted-transports.md](docs/runbooks/encrypted-transports.md). Bind health/metrics to an internal interface only — see
[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md). The management API and gRPC
control plane can be secured with mTLS ([docs/MTLS.md](docs/MTLS.md)).

## Using turna as a library

Workspace crates can be consumed via a git dependency:

```toml
[dependencies]
turna-relay = { git = "https://github.com/kruatech/turna", tag = "v0.3.0" }
```

## Development

```bash
cargo build --workspace --locked
cargo test  --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check
```

Fuzz targets (nightly) live in `fuzz/`. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the full workflow, including the `unsafe` audit process.

## Community

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test and submit changes
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [SUPPORT.md](SUPPORT.md) — where to get help
- [ROADMAP.md](ROADMAP.md)

## Security

Parsers are fuzz-tested continuously; the threat model, production checklist and
security invariants live in [docs/SECURITY.md](docs/SECURITY.md) and
[docs/security/](docs/security/). To report a vulnerability privately, see
[SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution. The name "turna" and the logo are trademarks — see
[TRADEMARKS.md](TRADEMARKS.md).