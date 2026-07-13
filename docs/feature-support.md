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
| Runtime user CRUD (`AddUser`/`RemoveUser`) | supported (needs mgmt backend) | Requires the Tarantool management backend; unavailable on an in-memory backend. |

Default builds use the tokio UDP data path; everything marked *experimental* is
opt-in via Cargo features and is not yet covered by the same testing/hardening
bar as the core path. The Linux-only data paths do not build on macOS (see the
`af-xdp`/`io-uring` notes in `CONTRIBUTING.md`).

## GA management feature matrix

| Capability | Source status | Verification required before GA |
|---|---|---|
| Node-targeted `update_config` | implemented | workspace + live update/restart |
| Durable desired/observed config | memory + Tarantool implemented | clean/upgrade/outage tests |
| Global/tenant/user limits | implemented | concurrency + restart + packet tests |
| Atomic allocation reservations | implemented | race/rollback/rehydrate tests |
| Admin config/limits UI | implemented | npm build + container smoke + live CP |
| Standalone Helm profile | implemented | lint/render/kubeconform + live deploy |
| `SetDraining` (drain/undrain) | implemented | drain/leaving + grace deadline tests |
| `DeleteAllocation` | implemented | idempotent not-found retry test |
| Idempotent management retry | implemented + covered by tests | lost-completion + replay tests |
| Restart restore (config + limits) | implemented + covered by tests | clean/upgrade/outage runs |
| Per-allocation bandwidth enforcement | implemented + covered by tests | two-allocation independence test |
| Audit log (tamper-evident) | implemented | fail-closed on unhealthy audit |
| Transparent active-session HA | not GA | future milestone; media path does not migrate |

“Implemented” here is a source-level statement, not a claim that the current
working tree has passed the release verification commands.
