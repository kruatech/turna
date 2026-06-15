# Feature & RFC support

What turna implements today and at what maturity. The goal is to set accurate
expectations rather than imply everything is production-grade.

> Maturity labels below are derived from the project's Status notes, the Cargo
> feature set, and the implemented data paths. **Maintainer: confirm/adjust the
> labels** — extend the table for any RFC/feature not yet listed rather than
> leaving a guess in place.

| Feature / RFC                              | Status                  | Notes |
| ------------------------------------------ | ----------------------- | ----- |
| STUN Binding (RFC 5389)                    | stable                  | Core protocol. |
| TURN relay over UDP (RFC 5766 / RFC 8656)  | stable                  | Default tokio data path. |
| Long-term credentials (RFC 5389/5766)      | stable                  | HMAC-SHA1; realm/nonce. |
| Shared-secret auth                         | stable                  | HMAC; secret via env/Secret. |
| Connection migration / mobility (RFC 8016) | stable                  | ReKey + migration epoch, persisted across failover. |
| TLS over TCP (`tls`)                        | experimental            | Feature-gated. |
| DTLS (`dtls`)                               | experimental            | Feature-gated. |
| QUIC (`quic`)                               | experimental            | Feature-gated; pulls `wtransport`. |
| WebTransport (`web-transport`)             | experimental            | Feature-gated. |
| io_uring data path (`io-uring`)            | experimental, Linux-only | Compile-gated; hardware-dependent. |
| AF_XDP data path (`af-xdp`)                | experimental, Linux-only | Kernel-bypass; requires NIC/kernel support. |
| Runtime user CRUD (management API)         | not implemented / partial | See `docs/PRODUCTION_READINESS.md`. |

Default builds use the tokio UDP data path; everything marked *experimental* is
opt-in via Cargo features and is not yet covered by the same testing/hardening
bar as the core path. The Linux-only data paths do not build on macOS (see the
`af-xdp`/`io-uring` notes in `CONTRIBUTING.md`).
