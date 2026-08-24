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
     `io-uring` is now **beta**: endurance and ChannelData relaying are both on record
     (`docs/soak/endurance-2026-08-19.md`) on Ubuntu 24.04 / kernel 6.14. Getting there
     found and fixed a relay-slot leak that made the datapath forward nothing at all
     while its control plane ran at 10 800 Allocate/s. What remains before `supported`
     is a run on the kernel you actually deploy — io_uring behaviour is
     version-sensitive, and one kernel is not evidence for another.
   - `sctp` is **experimental and refused under `production = true`**, and unlike
     the others it has had none of the hardening pass: no per-IP cap, no metrics,
     no readiness gauge, no cooperative drain, and a plaintext control channel.
     [docs/protocol-gap.md](docs/protocol-gap.md) rates it lowest priority. The
     current position is **keep it refused and do not invest**: the production gate
     already makes it unshippable, so hardening it would be work for a feature with
     no RFC and no users. The open decision is whether to delete it outright; until
     then it stays test-only and the feature-powerset CI keeps it compiling.
     (One real bug was fixed in passing: `sctp_bridge` never released an
     allocation when the association closed, so every closed connection leaked its
     relay port until the TTL expired — `tls_bridge` had that release, SCTP did
     not.)

   Cross-cutting gaps that block *all* of the encrypted transports from
   "supported": on the **default** DTLS path there is still no certificate
   hot-reload and no handshake **rate** limit — both need to sit above
   `webrtc-dtls`'s `accept()`, which is exactly what `[turn.dtls] demux = true`
   does; that path has both, and is off by default only because it displaces the
   one DTLS path with recorded verification. And no integration test covers
   bidirectional media on any encrypted transport — only a STUN Binding test on
   DTLS today.

3. **Decide the production gate for the three refused features.**
   `config::validate()` hard-rejects `turn.tcp_relay.enabled`,
   `turn.sctp.enabled` and `turn.auth.oauth.enabled` when `production = true`.
   Each needs an explicit exit condition rather than staying refused
   indefinitely: RFC 6062 needs interop plus pipelined-client hardening, OAuth
   needs an interop pass against a real authorization server, and SCTP needs the
   keep-or-drop decision above.

4. **Finish the relayed transport family.** IPv6 relaying is now opt-in via
   `[turn] external_ip6`, with RFC 6156 §4.2 family separation (443 on a
   cross-family peer), `IPV6_V6ONLY` on the relay socket, and IPv6-specific
   peer-filter classes (the v4-embedding transition prefixes are denied). What is
   left, in order:
   - **Evidence** — no test exercises a v6 allocation end to end. This comes first;
     it is the prerequisite for the next item, not a parallel track.
   - **`ADDITIONAL-ADDRESS-FAMILY`** — one Allocate, both families. Blocked on a
     storage decision, not on protocol work: `turna_allocations` is keyed by
     `relay_port`, so one allocation cannot hold two ports without choosing between
     an unindexed second port, two tuples, or a composite key. Three options with
     costs, edit lists and tests:
     [docs/design/additional-address-family.md](docs/design/additional-address-family.md).
   - **IPv6 for RFC 6062 TCP relay** — still `440`; the TCP relay datapath has no v6
     path.
5. **Control plane completeness.** Runtime user management (AddUser/RemoveUser
   over the control-plane gRPC, backed by Tarantool) is implemented; the
   remaining work is rounding out the rest of the gRPC management surface and
   keeping the implemented-vs-not documentation current.
6. **Supply-chain hardening for releases.** The release workflow already
   produces SBOMs, artifact checksums, cosign-signed images and SLSA
   provenance, with its actions pinned by commit SHA. Remaining: extend the
   same SHA-pinning and hardening discipline to the rest of the CI workflows.
7. **Operability.** Clustering ergonomics, runbooks, and dashboards.

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
