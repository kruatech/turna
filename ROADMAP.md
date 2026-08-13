# Roadmap

`turna` is Production GA (`0.3.0`). This roadmap is intentionally
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
2. **Mature the alternative transports.** All are behind Cargo features. They
   are no longer one undifferentiated bucket:
   - `tls` (TURNS, incl. RFC 6062 TCP relay) and `dtls` are **beta** — the
     hardening is in source (per-IP and global limits, metrics, per-listener
     readiness, cooperative drain, fail-fast startup, allocation release on
     connection close). The remaining work is *evidence*: run
     [docs/verification/encrypted-transports.md](docs/verification/encrypted-transports.md)
     and record it, then they can be called supported.
   - `quic` / `web-transport` are **experimental** with known functional gaps —
     most `[turn.quic]` limits are not applied on the WebTransport path, there is
     no per-stream reply routing there, and QUIC connection migration is not
     detected. See
     [docs/design/quic-webtransport.md](docs/design/quic-webtransport.md) §7.
   - `io-uring` and `af-xdp` remain **experimental** and hardware/kernel
     dependent; see [docs/roadmap/af-xdp-phase2.md](docs/roadmap/af-xdp-phase2.md).

   Cross-cutting gaps that block *all* of the encrypted transports from
   "supported": no certificate hot-reload for DTLS or QUIC (TURNS has it), no
   pre-handshake rate limiting anywhere, and no integration test covering
   bidirectional media on any encrypted transport — only a STUN Binding test on
   DTLS today.
3. **Control plane completeness.** Runtime user management (AddUser/RemoveUser
   over the control-plane gRPC, backed by Tarantool) is implemented; the
   remaining work is rounding out the rest of the gRPC management surface and
   keeping the implemented-vs-not documentation current.
4. **Supply-chain hardening for releases.** The release workflow already
   produces SBOMs, artifact checksums, cosign-signed images and SLSA
   provenance, with its actions pinned by commit SHA. Remaining: extend the
   same SHA-pinning and hardening discipline to the rest of the CI workflows.
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
