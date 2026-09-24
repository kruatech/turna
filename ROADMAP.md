# Roadmap

`turna` is Production GA (`0.5.0`). This roadmap is intentionally
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
   lifecycle, long-term/shared-secret auth, config validation, and
   graceful drain are the supported surface; keep them well-tested and stable.
2. **Mature the alternative transports.** All are behind Cargo features. They
   are no longer one undifferentiated bucket:
   - `tls` (TURNS) and `dtls` are **supported**: TURNS on three-engine browser
     interop, a public certificate chain and a 24 h soak
     ([docs/soak/endurance-24h-2026-08-22.md](docs/soak/endurance-24h-2026-08-22.md));
     DTLS on OpenSSL/coturn interop and a 24 h soak of the shipped stack
     ([docs/interop/dtls-stack-2026-09-16.md](docs/interop/dtls-stack-2026-09-16.md)).
     RFC 6062 TCP relay remains **beta**, allowed in production, IPv4 only.
   - `quic` / `web-transport` are **supported** on Linux/macOS with tokio.
     Limits, per-stream replies and migration handling are implemented.
     Scope and evidence: [support record](docs/verification/quic-webtransport-supported-2026-09-18.md).
   - `io-uring` is **supported on Linux**, opt-in; tokio remains the default.
     Recovery, buffer/cancellation handling, functional checks and clean shutdown
     are verified. Load evidence includes 30-minute media and four-hour authenticated
     churn on 6.8.0-87, plus functional checks and short churn on 6.14.0-33.
     [Scope and evidence](docs/verification/io-uring-supported-2026-09-19.md).
   - `af-xdp` is **supported within the verified Linux IPv4 UDP copy-mode scope**.
     SKB/native copy-mode evidence is recorded on 6.8.0-87 / `virtio_net`;
     zero-copy, additional hardware and cold-neighbor/route-change validation remain.
     Earlier WAN control timeouts remain unexplained despite later passing runs.
     [Scope and evidence](docs/verification/af-xdp-supported-2026-09-22.md).
   - `sctp` is **supported on Linux/tokio**, opt-in and allowed in production.
     Native functional, lifecycle/limits and 30-minute WAN checks passed.
     [Evidence and scope](docs/verification/sctp-supported-2026-09-18.md):
     plaintext, UDP peer-side relay, kernel SCTP/IP protocol 132 required.
     Independent-client interoperability and multi-day endurance are not claimed.

   Remaining cross-cutting gaps: the stock DTLS listener (`demux = false`) has
   no certificate hot-reload and no handshake rate limit by construction — the
   default path since 0.5.0 (`demux = true`) has both. DTLS end-to-end relay
   across two hosts is untested. And no Rust integration test covers
   bidirectional media on an encrypted transport — `tests/integration` has only
   a STUN Binding test over DTLS; media coverage lives in the
   `scripts/verify/` runs.

3. **Finish OAuth verification before lifting its production gate.**
   RFC 7635 needs a real authorization-server interoperability run. RFC 6062
   and Linux/tokio SCTP are no longer refused merely by `production = true`.

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
   provenance. Every workflow's actions are pinned by commit SHA. Remaining:
   container image scanning and a declared MSRV.
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
