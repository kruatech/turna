# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-14

Production GA — all production blockers flagged in the `0.3.0-rc.2` external
audit are closed; the management subsystem is code-verified (full Rust workspace
suite with `--all-features`, plus the Tarantool stored-procedure TAP suites).
Optional high-performance / alternative-transport datapaths and multi-node
cluster mode remain feature-gated and **experimental**.

### GA Highlights
- Runtime config management: versioned updates, immutable snapshot, CAS, rollback.
- User limits: global / tenant / user scopes, inheritance, reservations, exact replay.
- Durable command log v2 with idempotency and lost-completion recovery.
- Three-phase resumable migration: page-CAS, monotonic fencing generation, canonical hash.
- Exact-u64 versioning (runtime, user-limits, fencing token); overflow refused.
- Atomic observed confirmation (journal write + observed bump in one `box.atomic`).
- Management / persistence / cluster profile separation; failover gated on `cluster_mode`.
- Admin control-plane API and Admin UI.


### Added
- End-to-end node-targeted `update_config` with optional proto presence,
  expected-version conflict detection, typed deterministic command payloads,
  one-shot immutable snapshot publication, no-op semantics, rollback reporting,
  and responses decoded from the target node's terminal result.
- End-to-end `set_user_limits` for global, tenant, and realm/tenant/user scopes,
  including independent inherit/value/unlimited/disabled modes, effective-limit
  reporting, lower-than-current-usage behavior, and restart restore.
- Durable desired/observed runtime and limits state for memory and Tarantool
  backends, process-incarnation fencing, startup adoption/restore before
  readiness, and a bounded, resumable, leased three-phase command-log migration
  (`commands` → `idempotency` → `complete`) that recomputes legacy payload
  hashes with the canonical Rust hash and terminally closes orphaned idempotency
  rows. The idempotency phase is a fetch/apply pair guarded by a monotonic lease
  fencing generation: apply commits under a full compare-and-swap (version,
  phase, cursor, owner, token, unexpired lease) in a single `box.atomic`
  transaction, so a stale page cannot land, partial-terminal rows are enriched
  by consulting the linked command's status, and a GC'd-then-reused idempotency
  key is never clobbered.
- Concurrency-safe user/tenant/global allocation reservations with rollback and
  local immutable limit lookup on allocation, refresh, and packet paths.
- Node-scoped admin forms, desired/observed status, version conflict handling,
  retry-stable idempotency keys, session-only admin token storage, and admin
  container smoke coverage.
- Socket-level gossip drain/leaving/rejoin integration coverage.

### Changed
- Runtime quota APIs consistently use `max_bytes_per_sec_per_allocation`; telemetry fields that
  measure traffic remain explicitly named `bandwidth_bps` (bits/second).
- The canonical Helm production example is standalone-first: one TURN pod per
  public IP/relay range, Tokio transport, finite resources/bandwidth, and a
  separately managed Tarantool backend for durable management state.
- The Helm multi-node StatefulSet is explicitly experimental and no longer
  presented as the canonical GA topology.
- `UserLimitScope` numbering changed: `UNSPECIFIED = 0` (required-but-unset
  guard), `GLOBAL = 1`, `TENANT = 2`, `USER = 3`. Numeric `0` is no longer
  `GLOBAL`; an unset scope is rejected instead of silently treated as global.
- `SetUserLimits` usage fields renamed for unambiguous meaning:
  `current_usage` → `max_user_allocations_in_scope`,
  `usage_above_limit` → `max_user_allocations_above_limit` (highest single-user
  allocation count in the scope, not an aggregate total).
- Command `done` now denotes completed transport processing, not necessarily
  `applied`; the business outcome (`applied` / `no_op` / `conflict` / `failed` /
  `superseded`) is carried in the typed result.
- Management-plane persistence (command-log, runtime config, limits state) is
  decoupled from allocation write-behind: the management backend is enabled
  whenever a durable (Tarantool) backend is configured, independent of whether
  allocation write-behind persistence is on.
- Durable operation outcomes are persisted at the observed-version confirmation
  — atomically with the observed bump and before command completion — keyed by
  idempotency key, so a lost completion still recovers the original result even
  after a later operation overwrites the single most-recent-applied slot; every
  later journal write (completion, dead-letter, stale finalize) is guarded so a
  terminal outcome is never downgraded. Non-mutating terminal outcomes (`no_op`,
  version `conflict`, validation `failed`) are recorded into the same journal via
  `record_command_outcome` before completion under the identical contract, and
  the handler consults the journal before re-validating, so a replay after the
  state has changed returns the original outcome rather than re-deriving a
  different one.
- Runtime and user-limits versions are exact unsigned 64-bit throughout the
  Tarantool path: a single parser normalizes string/number/cdata to a u64,
  comparisons and CAS never route a version through a float (exact above 2^53),
  and an increment at `u64::MAX` is refused with an error rather than wrapping.
- Management-plane readiness is surfaced on a distinct `turna_management_readiness`
  gauge that reaches `ready` only after the mandatory migration phases complete;
  the TURN dataplane readiness is independent. Allocation rehydrate and the
  write-behind writer run only under an allocation-persistence profile, and
  ownership adoption/failover only under the cluster profile.
- Drain publishes `leaving` at the start of drain.
- The local user-limits cache carries a monotonic generation independent of the
  durable subject version; a no-op publish neither stores nor advances it.

### Fixed
- Proto/field drift between the wire contract and the Rust/TypeScript surfaces.
- Optimistic-concurrency (expected-version) drift on runtime-config updates.
- Helm allocation-cap value that could exceed the usable relay-port range.
- Post-GC idempotency replay: a retry after the command row was collected now
  resolves from the retained idempotency record instead of polling to timeout.
- Lost-completion recovery: an applied operation whose completion was lost is
  recovered from durable operation metadata and returns its original outcome
  without re-applying the side effect.
- Stale-incarnation command recovery: commands targeting a dead incarnation are
  finalized as `superseded` and no longer accumulate as non-terminal rows.
- Legacy idempotency migration for pre-existing Tarantool command rows.
- Per-user allocation reservation race under concurrent Allocate.
- Mixed runtime snapshot: readers now observe one atomic versioned snapshot.
- Unsafe global default scope (`GLOBAL = 0`) removed.
- Front-end/back-end field-name mismatch on the admin surface.
- User-limits cache generation overflow now returns an explicit error instead of
  panicking, leaving the current snapshot unpublished.

### Compatibility
- Protobuf field numbers are preserved; retired pre-GA fields are marked
  `reserved` (numbers and names) rather than reused.
- Source/JSON rename of the bandwidth quota field to
  `max_bytes_per_sec_per_allocation`. Durable command/state JSON written with the
  old `max_bytes_per_sec` key is still read (deserialization alias); telemetry
  `bandwidth_bps` (bits/second) is unchanged.
- `UserLimitScope` enum numeric change (`UNSPECIFIED = 0`); clients relying on
  `GLOBAL = 0` must update.
- Old Tarantool schema requires the bounded/resumable migration
  (commands → idempotency → complete). See `RELEASE.md`.
- Management API semantics: accepted is not applied; callers must inspect the
  terminal business outcome, not only the gRPC status.
- New mandatory mutation fields: `node_id`, `idempotency_key`,
  `expected_version` (where applicable), and `reason`. Older clients may require
  updates.

### Known limitations
- No transparent active-session failover; an existing media path does not
  migrate to another node.
- No general multi-replica shared-IP Helm topology; standalone-first is the
  canonical GA profile.
- Experimental transport backends (AF_XDP; io_uring/QUIC/DTLS per their stated
  scope).
- Admin token model: session-only bearer token; not a full RBAC/identity system.
- Bandwidth enforcement is per-allocation (independent budget per allocation),
  not an aggregate per-user limiter.
- Limits atomicity is guaranteed within the limits domain, not necessarily
  jointly with the runtime-config domain.

### Verification boundary
- These entries describe source changes only. Build, tests, Tarantool runtime,
  frontend, Docker, Helm, migration upgrades, and live TURN scenarios must be
  run on the exact release commit before assigning GA status.

## [0.3.0-rc.2] - 2026-07-12
Second release candidate on top of `0.3.0-rc.1`. Lands the admin control-plane
stage 2 (gRPC mutations) and DTLS fail-closed hardening, and records the
verification finished since rc.1 (multi-day endurance, mobile/multi-OS interop).
NOT GA: an external code audit flagged production blockers that are still open —
notably the control-plane's management model (mutations must be proven to reach
a live node, not a control-plane-local store), the gRPC TLS env-override /
`tls` vs `mtls` gap, Helm/K8s production topology, unknown-backend fallback,
task supervision, and Tarantool operation timeouts. See docs/verification/
pre-GA-status.md and the audit follow-up before promoting to a stable release.

Verification completed (see `docs/`):
- Endurance: a continuous relay run of more than 5 full days (uptime 434,908 s,
  ~130M packets, 21.4 GB) with flat memory (RSS below start), stable fds, and
  zero error counters across the soak window — no leak at a multi-day horizon
  (`docs/soak/endurance-v0.3.0-rc.1.md`), extending the 12-hour soak.
- Browser interop broadened to mobile and multi-OS: iPhone (Safari/Chrome),
  Android (Chrome/Firefox), iPad, Windows, Linux, macOS — each 5/5 over TURNS
  (TCP/TLS) from the external network, including mobile 4G/5G
  (`docs/interop/v0.3.0-rc.1.md`).
- DTLS: transport + DTLS 1.2 handshake + allocate confirmed against a live node
  with `turnutils_uclient` and `openssl s_client -dtls` (`docs/dtls/`).
- A consolidated pre-GA verification map, honest about what is and is not
  covered (`docs/verification/pre-GA-status.md`).

### Added
- Admin console stage 2: mutating operations via a gRPC bridge to the
  control-plane (`SetDraining`, `DeleteAllocation`, `AddUser`/`RemoveUser`,
  plus reads). Operator mutations are gated by an `X-Admin-Token`; the
  HTTP-to-node mutation path was removed in favour of gRPC only. Verified live
  end-to-end (drain/undrain/stats/auth) (`docs/admin/`).
  - `SetUserLimits` and `UpdateConfig` are defined in the proto/surface but
    still return `Unimplemented` — the live runtime-config snapshot (S4) and
    limit enforcement (S5) that back them are in progress. They are NOT part of
    the working mutation surface yet and must not be advertised as such.

### Security
- Admin fail-closed hardening: a plaintext (`http://`) non-loopback gRPC address
  is refused, and — symmetrically — a non-loopback `--listen` with no
  `--auth-token` is refused, so an exposed console cannot serve unauthenticated
  mutations. The config checks run before any network dial.
- DTLS transport now fails closed when a configured operator certificate cannot
  be loaded, instead of silently falling back to an ephemeral self-signed cert
  (`crates/transport/src/dtls.rs`).

## [0.3.0-rc.1] - 2026-07-06

Release-candidate hardening on top of `0.3.0-beta.1`: interop, cluster
failover, and deploy-artifact fixes surfaced by live verification on Linux
(fuzz, coturn interop, soak, multi-node failover drill, Helm/Docker).

Verification highlights (see `docs/`): a 12-hour relay soak with no memory/fd
leak (518M packets, 0 panics, 0 drops, P99 500 us — `docs/soak/`); a live
multi-node failover drill that found and fixed the list-truncation P1
(`docs/failover/`); and real-browser WebRTC interop over TURNS with a trusted
Let's Encrypt cert — allocate, auth-negative (401), end-to-end relay data
transfer, and the RAF fix all confirmed with Chrome (`docs/interop/`).

### Fixed
- REQUESTED-ADDRESS-FAMILY (0x0017): the Allocate flow now parses this base
  RFC 8656 attribute. An explicit IPv4 request is honoured; an IPv6 request is
  refused with `440 Address Family not Supported`. Previously the strict
  unknown-attribute handling answered `420` to any client sending it
  (e.g. `turnutils_uclient -X`, dual-stack browsers), breaking allocation.
- Cluster failover on the Tarantool backend: list-returning stored functions
  used `return unpack(res)`, a flat multiple-return that the iproto CALL parser
  truncated to a single row. This silently broke `find_by_node`,
  `get_live_nodes`, `list_allocations`, and the other list reads, so the
  failover sweep saw at most one node/orphan and adoption never completed in a
  real cluster. Fixed to `return res`; a live drill now shows a killed owner's
  allocations claimed by the survivor (`failover_claimed_total` increments,
  owner reassigned in the backend, no split-brain).
- `TURNA_WORKERS=0` no longer panics on startup. Zero (the Helm chart's default
  meaning "auto") now maps to CPU-count autodetection, matching unset/invalid.
- Config parse tests isolate the `TURNA_PRODUCTION` env var so a concurrent
  production-validation test can't leak into an unrelated parse test.
- `/metrics` output: several counters were emitted with leading indentation
  that broke Prometheus parsing; all counter lines are now flush-left.
- Strict STUN parser: enforce 4-byte body alignment up front and treat a
  declared length past the packet as `BufferTooShort`; padding value is ignored
  per RFC (non-zero padding tolerated).

### Changed
- Malformed REQUESTED-ADDRESS-FAMILY (bad length or unknown family) is dropped
  silently with `parser_rejections` incremented, like any malformed STUN
  attribute — intentional anti-amplification, not a `400` response.

### Migration
- The Tarantool stored-function fix changes `deploy/tarantool/init.lua`. Because
  functions are created with `if_not_exists = true`, an existing Tarantool
  instance will NOT pick up the new bodies on restart: drop and recreate the
  affected functions (or reload the schema) when upgrading a live cluster.
  Fresh installs are unaffected.

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

[Unreleased]: https://github.com/kruatech/turna/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kruatech/turna/compare/v0.3.0-rc.2...v0.3.0
[0.3.0-rc.2]: https://github.com/kruatech/turna/compare/v0.3.0-rc.1...v0.3.0-rc.2
[0.3.0-rc.1]: https://github.com/kruatech/turna/compare/v0.3.0-beta.1...v0.3.0-rc.1
[0.3.0-beta.1]: https://github.com/kruatech/turna/compare/v0.2.0-alpha.1...v0.3.0-beta.1
[0.2.0-alpha.1]: https://github.com/kruatech/turna/compare/v0.1.0...v0.2.0-alpha.1
