# Roadmap

`turna` is alpha (`0.2.0-alpha.x`). This roadmap is intentionally
direction-only — no committed dates — and points to the living documents that
track detail.

See first:

- [Feature status matrix](README.md#status) — supported vs experimental today.
- [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) — maturity and
  known limitations.
- [docs/roadmap/IMPLEMENTATION_STATUS.md](docs/roadmap/IMPLEMENTATION_STATUS.md)
  and [docs/roadmap/af-xdp-phase2.md](docs/roadmap/af-xdp-phase2.md) — the
  detailed, per-area plans.

## Themes toward a stable 0.x → 1.0

These are the areas we want to harden, in rough priority order:

1. **Stabilize the core path.** The tokio UDP datapath, TURN allocation
   lifecycle, long-term/shared-secret and JWT auth, config validation, and
   graceful drain are the supported surface; keep them well-tested and stable.
2. **Mature the experimental transports.** `io-uring`, `af-xdp`, `dtls`,
   `quic`, and `web-transport` are behind Cargo features and not yet
   runtime-verified for production. Move them toward "supported" one at a time,
   with soak and integration coverage.
3. **Control plane completeness.** Round out the gRPC management surface
   (including runtime user management) and document what is and is not
   implemented.
4. **Supply-chain hardening for releases.** SBOM, artifact checksums, signed
   images/provenance, and pinned CI actions.
5. **Operability.** Clustering ergonomics, runbooks, and dashboards.

## Contributing to the roadmap

Open a GitHub issue (feature request template) to propose or discuss an item.
Larger changes are best raised as a discussion first so the design can be agreed
before implementation.

## Concurrency model checking (loom)

<!-- loom-nonce-stateless -->
The `turna-qos` token-bucket invariant is verified under `loom`. The
nonce issuer in `turna-relay` was redesigned to be **stateless** (a per-client
HMAC over client + ephemeral key + timestamp, with no shared mutable state), so
the originally planned `loom_nonce` test (audit §3) no longer maps to any
in-process synchronization primitive and was removed from CI. Reintroduce a
loom test if a stateful, concurrently-rotated key is ever added.
