# turna

High-performance TURN/STUN server written in Rust (RFC 5389, RFC 5766, RFC 8656).

[![CI](https://github.com/kruatech/turna/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/turna/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

> Turna is the Turkish name of the crane — a migratory bird that relays itself
> across continents. This server does the same for your packets.

## Status

**Beta (`0.3.0-beta.1`).** The default **tokio UDP datapath** is the
primary supported path: STUN binding, the full TURN allocation lifecycle,
long-term-credential and JWT auth, Prometheus/OpenTelemetry, config validation,
and graceful drain / RFC 8016 migration are exercised here.

The high-performance and alternative-transport backends are **experimental**,
gated behind Cargo features, and not yet runtime-verified for production: the
`io-uring` and `af-xdp` datapaths, and the `dtls`, `quic`, `web-transport` and
TLS-over-TCP (`tls`) transports. Treat them as preview until further validation
— see [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md).

## Why turna

- **Memory-safe core in Rust** with continuously fuzzed STUN/TURN parsers
  (`fuzz/`) and an [audited `unsafe` inventory](docs/unsafe-audit.md) confined to
  the transport/relay datapaths.
- **Batched UDP I/O** — `SO_REUSEPORT` recv workers with `recvmmsg`/`sendmmsg`
  and per-batch arena buffers; optional `io_uring` and `AF_XDP` datapaths behind
  features for kernel-bypass throughput.
- **Clustering** — gossip discovery, a hash ring, and TURN-redirect load
  balancing, with a pluggable state backend (in-memory or Tarantool) for shared
  allocation state.
- **Operable** — gRPC control plane + `turnactl` CLI, Prometheus metrics and
  OpenTelemetry tracing, graceful drain and RFC 8016 session migration.

For a longer comparison and the design rationale, see
[docs/why-turna.md](docs/why-turna.md). Reproducible benchmarks against coturn
live in [bench/README.md](bench/README.md).

## Features

- STUN binding and full TURN allocation lifecycle (Allocate / Refresh /
  CreatePermission / ChannelBind / Send & Data indications)
- UDP and TCP relay transports
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
| TURN over TCP (TCP relay allocations) | RFC 6062 | Implemented, less exercised (preview) |
| Session migration | RFC 8016 | Supported (tokio datapath) |
| TLS-over-TCP transport (`tls`) | — | Experimental (preview) |
| DTLS transport (`dtls`) | — | Experimental (preview) |
| QUIC transport (`quic`) | — | Experimental (preview) |
| WebTransport (`web-transport`) | — | Experimental (preview) |
| `io_uring` datapath | — | Experimental (preview) |
| `AF_XDP` datapath | — | Experimental (preview) |

Status legend: **Supported** — exercised on the primary path and intended for
production use; **Preview** — gated behind a Cargo feature and not yet
runtime-verified for production.

## Observability

`turna-node` exposes Prometheus metrics and a health endpoint, and emits
OpenTelemetry traces. Bind health/metrics to an internal interface only — see
[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md). The management API and gRPC
control plane can be secured with mTLS ([docs/MTLS.md](docs/MTLS.md)).

## Using turna as a library

Workspace crates can be consumed via a git dependency:

```toml
[dependencies]
turna-relay = { git = "https://github.com/kruatech/turna", tag = "v0.3.0-beta.1" }
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