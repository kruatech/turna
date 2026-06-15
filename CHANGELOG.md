# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
  NOTE: the entries below cover the transport/datapath and dependency work that
  was verified in this cycle. Other 0.1.0 -> 0.2.0 changes are NOT yet listed —
  fill them in from `git log <0.1.0-tag>..HEAD` (or the PR history). Replace the
  TBD date and the compare links before tagging the release.
-->

## [Unreleased]

## [0.2.0] - TBD

### Added
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

### Changed
- **gRPC stack upgraded to tonic 0.14 / prost 0.14** (`turna-control`).
  Build-time codegen moved to `tonic-prost-build`; runtime uses `tonic-prost`.
  TLS feature switched from `tls` to `tls-ring`.

### Fixed
- **io_uring graceful shutdown.** On `SIGTERM`, workers now wait for all relays
  to be reclaimed *and* all in-flight send slots to complete (bounded by the
  drain grace window) before tearing down, so in-flight sends are no longer
  dropped during lame-duck shutdown.
- **io_uring send-slot handling.** Send-slot accounting/reuse so submitted sends
  are tracked to completion (including cancellations) rather than leaked.
- **`pin_to_core` bounds check.** Worker core pinning now validates the core id
  against the `cpu_set_t` capacity and runs unpinned (with a warning) instead of
  risking undefined behaviour when the id is out of range.
- **AF_XDP build.** `build.rs` resolves the architecture UAPI include path
  (`asm/types.h`) so the embedded XDP program compiles with `clang -target bpf`.
- Assorted Clippy lints; the workspace builds clean under `clippy --workspace -D warnings`.
- Audited `#[allow(dead_code)]`: removed stale annotations and two dead helper functions, kept and documented the genuinely-reserved ones.

### Security
- **Removed the unmaintained `rustls-pemfile` crate from the dependency tree**
  by upgrading tonic to 0.14, resolving **RUSTSEC-2025-0134**. The temporary
  `cargo-deny` advisory ignore was removed. Stale ignore entries for
  RUSTSEC-2026-0098/0099/0104 (no longer present in the tree) were also dropped.

### Dependency hygiene (cargo-deny)
- `turna-benchmark` marked `publish = false` so license checks skip it.
- Trimmed unused entries from the license `allow` list.
- Acknowledged the older transport stack pulled by `opentelemetry-otlp 0.16`
  (tonic 0.11 / http 0.2 / hyper 0.14 …) via `bans.skip-tree`, plus `skip` for
  the `getrandom` / `hashbrown` multi-version transitives. <!-- TODO: replace
  with a real fix by bumping the opentelemetry stack to a tonic 0.14 / http 1
  release. -->

<!-- Compare links — fill in the real tags:
[Unreleased]: https://<repo>/compare/v0.2.0...HEAD
[0.2.0]: https://<repo>/compare/v0.1.0...v0.2.0
-->
