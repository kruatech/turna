# turna

High-performance TURN/STUN server written in Rust (RFC 5389, RFC 5766, RFC 8656).

[![CI](https://github.com/kruatech/turna/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/turna/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14223/badge)](https://www.bestpractices.dev/projects/14223)

> Turna is the Turkish name of the crane — a migratory bird that relays itself
> across continents. This server does the same for your packets.

## Status

**Production GA (`0.4.0`).** The default **Tokio datapath** is the primary supported path:
STUN binding, the TURN allocation lifecycle, long-term-credential and TURN REST
(coturn-compatible) auth, Prometheus/OpenTelemetry, config validation, durable runtime configuration,
per-subject limits, and graceful drain.

The new GA management changes are implemented in source but are **not considered
verified by this document** until the exact release commit passes the workspace,
Tarantool, frontend, container, Helm, migration, restart, and live relay gates in
[RELEASE.md](RELEASE.md).

## Status legend

This is software other people install on machines we have never seen, so a status has
to say what was verified and where — a bare "supported" would promise something no
project in this position can deliver.

- **Supported** — maintained and verified end to end within the documented
  platform, backend and protocol scope. UDP TURN/STUN on the tokio datapath, long-term
  credentials and the Tarantool backend are here: three hours under load with no
  leak, 13.7 M allocations, 441 M packets
  ([docs/soak/endurance-2026-08-19.md](docs/soak/endurance-2026-08-19.md)).

  **TURNS is here too**, on three independent pieces of evidence: interop across three
  browser engines, a Let's Encrypt chain validated by a verifying client against a
  public address, and 24 hours under load with zero relayed-frame loss and no leak on
  any signal ([docs/soak/endurance-24h-2026-08-22.md](docs/soak/endurance-24h-2026-08-22.md)).

- **io_uring — supported on Linux, opt-in.** Recovery/drain checks, live TURN
  behaviour and load are recorded on Linux 6.8.0-87 and 6.14.0-33. The support
  scope, resource costs and exact evidence are in the
  [verification record](docs/verification/io-uring-supported-2026-09-19.md).
  Revalidate after kernel or deployment changes; tokio remains the default.

- **AF_XDP — supported within the verified Linux IPv4 UDP copy-mode scope.**
  SKB/copy and native/copy are verified on Linux 6.8.0-87 with `virtio_net`,
  two RX queues. Native evidence includes four-hour WAN media and 15-minute churn.
  Zero-copy and other NIC/kernel combinations need separate validation.
  [Evidence and known limitations](docs/verification/af-xdp-supported-2026-09-22.md).

- **Supported QUIC and WebTransport** — opt-in on Linux/macOS with the tokio backend.
  These are project-specific TURN mappings, not standardized TURN transport URIs.
  Raw QUIC has no independent TURN-client interoperability evidence; WebTransport
  has browser evidence for tested Chrome versions. DATAGRAM media remains
  unreliable. [Support scope and verification](docs/verification/quic-webtransport-supported-2026-09-18.md).

- **Supported on Linux — TURN-over-SCTP (`sctp`).** Opt-in native SCTP on the
  tokio backend, allowed with `production = true`. Carries TURN control and
  ChannelData; the peer-side relay remains UDP. Requires kernel SCTP support and
  a network permitting IP protocol 132. This project-specific transport is
  plaintext, not WebRTC DataChannel or SCTP-over-DTLS. Functional, lifecycle,
  limits and 30-minute WAN verification are recorded in
  [SCTP support evidence](docs/verification/sctp-supported-2026-09-18.md).

- **Refused in production** — RFC 7635 OAuth (`[turn.auth.oauth]`). Implemented
  and usable for testing, but has not been verified with a real authorization
  server; `production = true` rejects it. The verification kit and procedure for
  doing that with your AS: [docs/runbooks/oauth-verification.md](docs/runbooks/oauth-verification.md).

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
  features for reduced syscall overhead (io_uring) or kernel bypass (AF_XDP).
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
| Certificate rotation without restart           | TURNS and QUIC (both paths); DTLS on the demux path, which is the default since 0.4.1 (`demux = false` gives the stock listener and no hot reload). Verified under load, and again on 2026-09-16 for the current DTLS stack: a new pair reaches the next client, an unusable one leaves the previous certificate in service and is counted as a failure rather than reported as success |
| Shared-secret rotation without restart         | Supported via `SIGHUP`. The handler re-reads the same config file and republishes `shared_secret` / `previous_shared_secret` without dropping calls; a changed realm is refused. `UpdateConfig` still carries allocation limits only, not the secret. Overlap window: set the new secret, keep the old one in `previous_shared_secret`, `SIGHUP`, wait for `turna_auth_previous_secret_total` to flatten, drop the old one, `SIGHUP` again |
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
  requires `[tls]`, since RFC 6062 carries the control connection over TCP/TLS
- Long-term credentials, TURN REST (coturn-compatible) time-limited credentials,
  rate limiting, and shared-secret rotation via `SIGHUP`; multi-tenant realms with
  per-tenant relay port pools and limits
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

Running one node on your own hardware: [docs/SELFHOSTED.md](docs/SELFHOSTED.md)
is the start-to-finish version, with the host tuning and the client ICE config.

### Docker

```bash
docker build -f deploy/Dockerfile -t turna:local .
docker run --rm --network host \
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

**Scope:** the chart configures **plain UDP TURN only**. Its ConfigMap has no
`[tls]`, `[turn.dtls]` or `[turn.quic]` section and no override hook, so TURNS,
DTLS and QUIC/WebTransport — which the node supports and CI exercises end to end
— are not reachable through it. Certificate material needs Secret mounting and a
rotation story the chart does not have yet. Use your own ConfigMap for those.

**No ops API in the chart either.** It deploys `turna-node` and nothing else:
there is no `turna-control-plane` workload, no Service for the management port,
and the ConfigMap sets `[management] enabled = false` on loopback. `turnactl` and
the admin console therefore cannot reach a chart deployment — they assume the
single-host topology in [docs/admin/README.md](docs/admin/README.md), with the
control plane on `127.0.0.1:5350`. `deploy/docker-compose.yml` runs the node
alone for the same reason.

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

### Client ICE configuration

Two URLs are served, and a third one that browser examples commonly carry is not:

```js
iceServers: [
  { urls: "turn:turn.example.net:3478?transport=udp", username, credential },
  { urls: "turns:turn.example.net:5349?transport=tcp", username, credential },
  // NOT served: turn:turn.example.net:3478?transport=tcp
]
```

`transport=tcp` without TLS has no listener — by design, not by omission. TCP
clients are served over TURNS, which is also what gets through a firewall that
inspects traffic on 443 (point `[tls] listen` there if 5349 is filtered). A
client config that keeps the plain-TCP URL spends its ICE-gathering budget on a
connection refused before falling through to the URL that works.

TURNS therefore is not optional infrastructure here: it is the only TCP entry
point, which is why `tls` is a default Cargo feature and why a binary built with
`--no-default-features` refuses to start when `[tls]` is enabled.

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
| DTLS transport (`dtls`) | RFC 7350 | Supported — 24 h under load with zero packet loss, a 300 000-packet spoofed-source flood that allocates no state, 20/20 handshakes at 3 % path loss, and interop with OpenSSL and coturn's client ([docs/interop/dtls-stack-2026-09-16.md](docs/interop/dtls-stack-2026-09-16.md)). Not reachable from a browser: WebRTC has no DTLS transport for TURN |
| QUIC (`quic`) | — | **supported (Linux/macOS, tokio)** — Opt-in, project-specific TURN over raw QUIC; UDP peer relay. No independent raw-QUIC TURN client interoperability claim. Functional, lifecycle/limits, 20-minute load and WAN evidence recorded. See [docs/verification/quic-webtransport-supported-2026-09-18.md](docs/verification/quic-webtransport-supported-2026-09-18.md). |
| WebTransport (`web-transport`) | — | **supported (Linux/macOS, tokio)** — Opt-in, project-specific TURN over WebTransport/H3; UDP peer relay. Browser interoperability recorded for tested Chrome versions; custom JavaScript client, not a WebRTC ICE TURN URI. H3 uses `h3` ALPN. See [docs/verification/quic-webtransport-supported-2026-09-18.md](docs/verification/quic-webtransport-supported-2026-09-18.md). |
| TURN-over-SCTP transport (`sctp`) | Project-specific TURN mapping | **Supported on Linux/tokio**, opt-in, allowed in production. Native SCTP without TLS; control and ChannelData, UDP relay. [Evidence](docs/verification/sctp-supported-2026-09-18.md) |
| Third-party auth (`oauth`) | RFC 7635 | Implemented; **refused under `production = true`** until verified with a real AS — [verification kit](docs/runbooks/oauth-verification.md) |
| NAT behaviour discovery | RFC 5780 | Not implemented (no codec; would also need a 2×IP/2×port topology) |
| ALPN | RFC 7443 | Partial — labels advertised, no strict/compatible mode |
| Shared-secret ("REST") credentials | none — expired draft | Compatibility extension, coturn-compatible. Not an RFC |
| `io_uring` datapath | — | **Supported on Linux**, opt-in UDP datapath. Verified on **6.8.0-87 / 6.14.0-33**: recovery/drain, live TURN checks, 30-minute media and four-hour authenticated allocation churn on 6.8; functional checks and short churn on 6.14. [Scope and evidence](docs/verification/io-uring-supported-2026-09-19.md). |
| `AF_XDP` datapath | — | **Supported within verified Linux IPv4 UDP copy-mode scope** — SKB/native on 6.8.0-87, `virtio_net`, two queues. Zero-copy unverified; historical WAN churn timeouts remain unexplained. [Evidence and limits](docs/verification/af-xdp-supported-2026-09-22.md). |

Status legend: **Supported** — maintained and verified within its stated scope;
platform, interoperability and endurance limits remain explicit. **Beta** —
verification or operational gaps remain for the intended scope. **Experimental** — gated
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
turna-relay = { git = "https://github.com/kruatech/turna", tag = "v0.5.0" }
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
