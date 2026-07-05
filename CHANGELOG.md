# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0-beta.1]

Production-hardening of the core UDP/IPv4 TURN path. No new features; this
release closes the concurrency, resource-bound, protocol-strictness and
fail-closed-config gaps that kept `0.2.0-alpha.1` at alpha. See
[docs/COMPLIANCE.md](docs/COMPLIANCE.md) for the supported/not-supported scope.

### Fixed
- Atomic allocation create: a lost create race now returns `437 Allocation
  Mismatch` instead of silently overwriting an existing allocation.
- Global and per-tenant allocation quotas enforced with atomic reserve/rollback
  accounting (no quota race); per-user tracking is tenant-scoped.
- EVEN-PORT reservations released immediately on create failure instead of
  leaking until the sweep.

### Security
- Bounded per-allocation resources: 256 permissions, 256 channels, 32 peers per
  CreatePermission.
- Bandwidth quota enforced on all relay paths (channel data, Send-indication
  egress, peer -> client), not only ChannelData.
- Bounded internal QUIC/AF_XDP outbound and neighbour queues (experimental).
- Fail-closed production config: placeholder/empty shared or cluster secrets,
  unlimited bandwidth without explicit opt-in, and non-loopback plaintext
  management binds are refused at startup.

### Changed
- Strict STUN/TURN parsing: exact attribute lengths; MESSAGE-INTEGRITY /
  MESSAGE-INTEGRITY-SHA256 strictness; `420 UNKNOWN-ATTRIBUTES` for unknown
  comprehension-required attributes (symmetric encode/parse); reserved/unknown
  message types rejected.
- Runtime user revocation now propagates to live nodes via the backend refresh
  loop (config static users are never affected).
- Readiness degrades to `503` when backend writes are dropped, and recovers.

### CI
- New `msrv` job builds + tests on the pinned 1.95.0 toolchain (`--locked`) on
  every PR/push.
- The remaining tag-pinned action (`ossf/scorecard-action`) pinned by commit SHA.

## [0.2.0-alpha.1] - 2026-06-15

First public pre-release. Builds on the internal `v0.1.0` tag with multi-node
clustering, multi-tenant auth, and the QUIC/DTLS/AF_XDP transport foundation.
The default tokio UDP datapath is the supported path; the alternative transports
are experimental — see [README](README.md#status) and
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md).

### Added
- **Multi-node clustering (`turna-cluster`).** Gossip-based discovery, a hash
  ring, and TURN-redirect load balancing. Cluster config covers the gossip
  bind/seeds, announce address, shared HMAC secret, and drain grace; heartbeat
  and failure-detection settings control failover timing. Redirect-mode settings
  are validated against the TURN external address, and cluster redirect /
  live-node counts are exported as metrics.
- **Multi-tenant authentication.** `AuthRegistry`-based realm resolution with
  per-tenant results, multi-tenant config validation (unique ids, realms, and
  disjoint relay port ranges), tenant-isolated relay port pools with per-tenant
  limits, and per-tenant allocation counters in Prometheus.
- **QUIC, DTLS and WebTransport transports** with their listeners, plus relay
  node migration, relay routing primitives, and transport-layer certificate
  management. All are behind Cargo features and experimental.
- **AF_XDP transport backend — selective XDP filter.** Embedded XDP program
  attached to the configured interface that redirects only UDP datagrams whose
  destination port is in the BPF `ports` map into the AF_XDP socket
  (`xsks_map`); everything else is passed to the kernel (`XDP_PASS`). Attach
  mode follows `zero_copy` (SKB/copy vs native). Relay ports are registered into
  the map dynamically as allocations are created.
- **AF_XDP neighbour resolution.** Per-destination next-hop MAC resolution via
  ARP/NDP with a TTL cache, active resolution kick on cache miss, serve-stale
  while refreshing, and TTL-based eviction. New metric
  `turna_afxdp_neighbor_cache_entries`.
- **TURN-over-TLS (TURNS) listener** configuration defaults.
- **`MESSAGE-INTEGRITY-SHA256` support (RFC 8489)**, preserving the legacy
  `MESSAGE-INTEGRITY` path for long-term-credential compatibility.
- **`turnactl failover status`** subcommand exposing `claimed_total`,
  `lost_race_total`, `errors_total`, `last_sweep_us`, and draining counters.

### Changed
- **gRPC stack upgraded to tonic 0.14 / prost 0.14** (`turna-control`).
  Build-time codegen moved to `tonic-prost-build`; runtime uses `tonic-prost`.
  TLS feature switched from `tls` to `tls-ring`.
- **OpenTelemetry stack upgraded to 0.32** (`turna-observability`):
  `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` (grpc-tonic) to
  `0.32`, and `tracing-opentelemetry` to `0.33`. This moves OTLP export onto
  `tonic 0.14` / `prost 0.14` / `http 1` / `hyper 1`, eliminating the duplicate
  `tonic 0.11` / `http 0.2` / `hyper 0.14` generation that the old
  `opentelemetry-otlp 0.16` had pulled in.
- **Relay wiring switched from `AuthMode` to `AuthRegistry`** across the relay
  processor, server, and node.
- **STUN encode APIs are now fallible.** `encode`, `encode_with_integrity`, and
  `encode_channel_data` return `Result`; callers propagate `BufferTooSmall`
  instead of panicking on an undersized output buffer.
- **io_uring worker count is configurable** via `TURNA_IOURING_WORKERS`.

### Fixed
- **io_uring graceful shutdown.** On `SIGTERM`, workers now wait for all relays
  to be reclaimed *and* all in-flight send slots to complete (bounded by the
  drain grace window) before tearing down, so in-flight sends are no longer
  dropped during lame-duck shutdown.
- **io_uring send-slot handling.** Send-slot accounting/reuse so submitted sends
  are tracked to completion (including cancellations) rather than leaked.
- **io_uring relay lifecycle.** `CloseRelay` actions are mapped into a
  `ForwardAction` instead of being dropped; in-flight ops are cancelled with
  `AsyncCancel2` before reclaiming closing relays; recv slots are re-armed on
  transient recv errors to avoid slot starvation.
- **`pin_to_core` bounds check.** Worker core pinning now validates the core id
  against the `cpu_set_t` capacity and runs unpinned (with a warning) instead of
  risking undefined behaviour when the id is out of range.
- **AF_XDP build.** `build.rs` resolves the architecture UAPI include path
  (`asm/types.h`) so the embedded XDP program compiles with `clang -target bpf`.
- Assorted Clippy lints; the workspace builds clean under `clippy --workspace -D warnings`.
- Audited `#[allow(dead_code)]`: removed stale annotations and two dead helper functions, kept and documented the genuinely-reserved ones.

### Security
- **`rustls-pemfile` (unmaintained, RUSTSEC-2025-0134) removed from the default
  build.** PEM parsing in `turna-transport` (the `tls` and `quic` features) was
  migrated to `rustls-pki-types`, so `rustls-pemfile` is no longer a direct
  dependency. The only remaining occurrence is transitive, via `wtransport`
  under the experimental `web-transport` feature (`wtransport 0.6.1`, the
  latest release, still depends on it), and is absent from default/production
  builds. `cargo deny check advisories` is clean — the advisory is not
  surfaced because the default graph does not enable `web-transport` — so no
  `deny.toml` ignore is carried. Tracked as RISK-001 in
  `docs/security/accepted-risks.md`.
- **Hardened HS256 JWT secrets.** A minimum secret length (>= 32 bytes) is
  enforced at both the sign and verify boundaries, and placeholder secrets are
  rejected at startup.
- **Stricter STUN auth.** Requests carrying an unknown or inconsistent
  `PASSWORD-ALGORITHM` declaration are rejected as `400 Bad Request`.

### Dependency hygiene (cargo-deny)
- `turna-benchmark` marked `publish = false` so license checks skip it.
- Trimmed unused entries from the license `allow` list.
- Removed the `bans.skip-tree` for `opentelemetry-otlp`: upgrading the
  OpenTelemetry stack to 0.32 (tonic 0.14 / http 1 / hyper 1) eliminated the
  older `tonic 0.11` generation it had pulled in, so the skip-tree is no longer
  needed. `skip` entries for the `getrandom` / `hashbrown` multi-version
  transitives remain. The full picture is tracked in
  `docs/security/dependency-dedup.md`.

[Unreleased]: https://github.com/kruatech/turna/compare/v0.3.0-beta.1...HEAD
[0.3.0-beta.1]: https://github.com/kruatech/turna/compare/v0.2.0-alpha.1...v0.3.0-beta.1
[0.2.0-alpha.1]: https://github.com/kruatech/turna/compare/v0.1.0...v0.2.0-alpha.1
