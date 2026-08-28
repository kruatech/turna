# turna

High-performance TURN/STUN server written in Rust (RFC 5389, RFC 5766, RFC 8656).

[![CI](https://github.com/kruatech/turna/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/turna/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14223/badge)](https://www.bestpractices.dev/projects/14223)

> Turna is the Turkish name of the crane — a migratory bird that relays itself
> across continents. This server does the same for your packets.

## Status

**Production GA (`0.3.1`).** The default **Tokio datapath** is the primary supported path:
STUN binding, the TURN allocation lifecycle, long-term-credential and JWT auth,
Prometheus/OpenTelemetry, config validation, durable runtime configuration,
per-subject limits, and graceful drain.

The new GA management changes are implemented in source but are **not considered
verified by this document** until the exact release commit passes the workspace,
Tarantool, frontend, container, Helm, migration, restart, and live relay gates in
[RELEASE.md](RELEASE.md).

## Status legend

This is software other people install on machines we have never seen, so a status has
to say what was verified and where — a bare "supported" would promise something no
project in this position can deliver.

- **Supported** — verified end to end, and its behaviour does not depend on the
  kernel or the hardware underneath. UDP TURN/STUN on the tokio datapath, long-term
  credentials and the Tarantool backend are here: three hours under load with no
  leak, 13.7 M allocations, 441 M packets
  ([docs/soak/endurance-2026-08-19.md](docs/soak/endurance-2026-08-19.md)).

  **TURNS is here too**, on three independent pieces of evidence: interop across three
  browser engines, a Let's Encrypt chain validated by a verifying client against a
  public address, and 24 hours under load with zero relayed-frame loss and no leak on
  any signal ([docs/soak/endurance-24h-2026-08-22.md](docs/soak/endurance-24h-2026-08-22.md)).

- **Beta, verified on listed configurations** — correctness is on record, but the
  behaviour depends on your environment in a way we cannot test for you. The
  `io-uring` datapath is the clearest case: it is verified on Linux **6.8** and
  **6.14** — 9.6 h of relayed media at 0.006 % loss on the former, no leak on either —
  and io_uring semantics are version-sensitive, so that is evidence about those two
  kernels and no others. `af-xdp` is the same with a NIC driver added —
  the lab attaches in SKB (generic) mode, which copies every frame and reproduces
  none of the kernel-bypass behaviour the feature exists for.

  Verify on your kernel and your NIC before enabling either. What is on record is in
  [docs/interop/](docs/interop/) and [docs/soak/](docs/soak/), with the exact
  configurations named.

- **Beta, no independent implementation** — **QUIC only.** It carries a TURN
  allocation and relays media in both directions, but the client that proved it was
  written here, against the same reading of the spec as the server, so a shared
  misreading stays invisible. That is correctness evidence, not interop evidence.

  QUIC is alone here for a structural reason: no RFC defines TURN over raw QUIC, so
  there is no second implementation to test against and none can be written from a
  specification that does not exist. The path out is a draft and someone else's
  implementation, not more testing — see
  [docs/OPEN-DECISIONS.md](docs/OPEN-DECISIONS.md).

  Everything else has left this group. TURNS: three browser engines. WebTransport: a
  TURN client written in browser JavaScript, assembling every STUN byte and its own MD5
  and HMAC. DTLS, UDP, IPv6 and RFC 6062: coturn's `turnutils_uclient`, another
  language and another reading of the RFC
  ([docs/interop/coturn-2026-08-23.md](docs/interop/coturn-2026-08-23.md)).

- **Refused in production** — TURN-over-SCTP (`[turn.sctp]`) and RFC 7635 OAuth
  (`[turn.auth.oauth]`). Implemented and usable for testing; `production = true` makes
  config validation **reject** them, so they cannot ship by accident. Two are refused in
  production for different reasons: SCTP has none of the hardening the other listeners
  received and no users, and OAuth has never run against a real authorization server.

  RFC 6062 TCP relay was on this list until 2026-08-25. It came off because the evidence
  the gate was waiting for arrived — interop against coturn's own client
  ([docs/interop/coturn-2026-08-23.md](docs/interop/coturn-2026-08-23.md)) — not because
  the risk changed. Size for it before enabling: each relayed peer costs a listener and
  a connection, which the gate used to decide on your behalf.

Two known functional gaps, independent of testing: several `[turn.quic]` limits do not
apply on the WebTransport path (the listener warns at startup), and QUIC connection
migration is not detected.

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
| mTLS for TURNS clients                         | Opt-in (`[tls] client_ca`); no CRL/OCSP by design |
| IPv6 relayed transport                         | Opt-in via `[turn] external_ip6`; 440 when unset. Relayed media and coturn interop verified on routable addresses |
| Certificate rotation without restart           | TURNS and QUIC (both paths); DTLS only with `[turn.dtls] demux = true`. Verified under load: 0 → 1, no failures, 36 021 frames relayed with zero errors across the swap |
| Shared-secret rotation without restart         | **Not supported.** `SIGHUP` is not handled and `UpdateConfig` carries allocation limits, not the secret — `[turn.auth] shared_secret` changes only with a restart. Ephemeral credentials derived from it expire on their own; the secret does not. See R13 in [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) |
| Multi-node ownership/state failover            | Experimental / limited scope                  |
| Transparent active-session (media) failover    | Out of GA scope                               |

"Supported" is a source-level statement pending the release verification gates
in [RELEASE.md](RELEASE.md); see [docs/feature-support.md](docs/feature-support.md)
for the full matrix and [docs/MANAGEMENT_API.md](docs/MANAGEMENT_API.md) for the
RPC contract.

## Features

- STUN binding and full TURN allocation lifecycle (Allocate / Refresh /
  CreatePermission / ChannelBind / Send & Data indications)
- UDP relay on the default path (IPv4, plus IPv6 when `external_ip6` is set); TCP relay (RFC 6062)
  behind the `tls` feature, since RFC 6062 requires a TCP/TLS control connection
  — and refused under `production = true`
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
| Relayed transport family | RFC 6156 / 8656 | IPv4 by default; IPv6 opt-in via `[turn] external_ip6` (unset → `440`). One family per allocation, cross-family peers get `443`. `ADDITIONAL-ADDRESS-FAMILY` not implemented |
| TURN over TCP (TCP relay allocations) | RFC 6062 | Implemented; allowed in production since 2026-08-25. Requires the `tls` listener. IPv4 only — an IPv6 TCP allocation answers 440 |
| Session migration | RFC 8016 | Partial — tickets are issued and re-issued on the tokio datapath; cross-node migration is **unwired** (no allocation is transferred between nodes), treat as same-node |
| TLS-over-TCP transport (`tls`) | — | **Supported** — three-engine browser interop, a public certificate chain validated by a verifying client, coturn interop, and 24 h under load ([docs/soak/endurance-24h-2026-08-22.md](docs/soak/endurance-24h-2026-08-22.md)) |
| DTLS transport (`dtls`) | RFC 7350 | Beta — both listener paths, 20 min under load, and interop against coturn's client ([docs/interop/coturn-2026-08-23.md](docs/interop/coturn-2026-08-23.md)) |
| QUIC transport (`quic`) | — | Beta — allocation, relayed media both directions and 20 min under load, but **no independent implementation exists** (no RFC defines TURN over raw QUIC), so interop cannot be obtained |
| WebTransport (`web-transport`) | — | Beta — browser interop recorded ([docs/interop/webtransport-browser-2026-08-20.md](docs/interop/webtransport-browser-2026-08-20.md)) plus 20 min under load |
| TURN-over-SCTP transport (`sctp`) | none — no RFC defines it | Experimental; **refused under `production = true`**. Control channel only, the relay stays UDP |
| Third-party auth (`oauth`) | RFC 7635 | Implemented; **refused under `production = true`** |
| NAT behaviour discovery | RFC 5780 | Not implemented (no codec; would also need a 2×IP/2×port topology) |
| ALPN | RFC 7443 | Partial — labels advertised, no strict/compatible mode |
| Shared-secret ("REST") credentials | none — expired draft | Compatibility extension, coturn-compatible. Not an RFC |
| `io_uring` datapath | — | Beta — endurance and relaying recorded on Linux **6.8 and 6.14** ([docs/soak/endurance-2026-08-19.md](docs/soak/endurance-2026-08-19.md), [docs/soak/endurance-24h-2026-08-22.md](docs/soak/endurance-24h-2026-08-22.md)); io_uring is version-sensitive — verify on your own kernel |
| `AF_XDP` datapath | — | Beta — correctness verified on a veth lab ([docs/interop/af-xdp-2026-08-19.md](docs/interop/af-xdp-2026-08-19.md)); validate on your NIC, the lab attaches in SKB mode |

Status legend: **Supported** — exercised on the primary path and intended for
production use. **Beta** — gated behind a Cargo feature, hardened in source
(limits, metrics, readiness, graceful drain) but without recorded soak/interop
evidence; test it with your own client stack first. **Experimental** — gated
behind a Cargo feature with known functional gaps; not for production. **Partial**
— the protocol element is present but not the whole feature; the notes say what
is missing. Anything marked *refused under `production = true`* is rejected by
config validation in that mode, which is the authoritative signal.

The full per-feature register, with what each `partial` needs to become stable,
is [docs/protocol-gap.md](docs/protocol-gap.md).

## Observability

`turna-node` exposes Prometheus metrics and a health endpoint, and emits
OpenTelemetry traces. Each listener has its own readiness gauge
(`turna_transport_readiness`, `turna_tls_readiness`, `turna_dtls_readiness`,
`turna_quic_readiness`) plus per-transport counters, so a listener that dies
while the process survives is visible; operator response for the shipped alert
rules is in
[docs/runbooks/encrypted-transports.md](docs/runbooks/encrypted-transports.md). Bind health/metrics to an internal interface only — see
[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md). The management API and gRPC
control plane can be secured with mTLS, and TURNS clients can be required to
present a certificate too (`[tls] client_ca` / `require_client_cert`) — see
[docs/MTLS.md](docs/MTLS.md), which covers both planes and states the deliberate
no-CRL/OCSP position.

## Using turna as a library

Workspace crates can be consumed via a git dependency:

```toml
[dependencies]
turna-relay = { git = "https://github.com/kruatech/turna", tag = "v0.3.1" }
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