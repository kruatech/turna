# Accepted risks

Security/maintenance risks consciously accepted for the current release, with
their compensating controls and a review point. This is a living register;
each entry is revisited at the version named under "Review by".

## RISK-001 — `rustls-pemfile` reachable only via the experimental `web-transport` feature

- **Status:** **resolved** — `rustls-pemfile` is no longer in the dependency graph
  at all, including with `--features web-transport`
  (`cargo tree -p turna-transport --features web-transport -i rustls-pemfile`
  reports no matching package). `wtransport 0.7.1` dropped it.
- **Description:** `rustls-pemfile` is flagged unmaintained
  (RUSTSEC-2025-0134; the upstream repository was archived in August 2025).
- **Why it stays:** the direct dependency was removed — `turna-transport` now
  parses PEM via `rustls-pki-types` under the `tls`/`quic` features. The only
  remaining occurrence is transitive, through `wtransport` under the
  experimental `web-transport` feature. `wtransport 0.6.1` still depended on it, so
  no dependency bump removed it at the time; the workspace has since moved to
  `wtransport 0.7.1`, which does not.
- **Compensating controls:** `cargo deny check advisories` is green because the
  default graph does not enable `web-transport`, so the crate is not in release
  builds; the PEM surface only touches operator-supplied certificate files at
  startup; the advisory is tracked here rather than ignored silently.
- **Planned remediation:** done — `wtransport` migrated off `rustls-pemfile`
  upstream. If `web-transport` is ever pinned back to a 0.6.x release the risk
  returns; the `Cargo.lock` check above is what to re-run.
- **Review by:** closed.

## RISK-002 — duplicate dependency versions (previous gRPC/HTTP generation)

- **Status:** resolved in `0.2.0-alpha.1`.
- **Description:** the workspace previously shipped two generations of the
  gRPC/HTTP stack (`tonic` 0.11 + 0.14, `axum` 0.6 + 0.8, `hyper` 0.14 + 1,
  `http` 0.2 + 1, `prost` 0.12 + 0.14, `thiserror` 1 + 2, …), with the old
  generation pulled entirely through `opentelemetry-otlp 0.16 → tonic 0.11`.
- **Resolution:** the OpenTelemetry crates were upgraded to `0.32`
  (`opentelemetry-otlp` on `grpc-tonic` → `tonic 0.14`, `prost 0.14`, `http 1`,
  `hyper 1`; `tracing-opentelemetry 0.33`), collapsing the previous generation.
  `tonic` now resolves to a single major (`0.14.x`), and the
  `opentelemetry-otlp` `skip-tree` has been removed from `deny.toml`.
- **Residual:** only benign minor-version multiplicity remains (`socket2`
  0.5/0.6, `hashbrown`, `getrandom`, plus dev-only `proptest`/`criterion`
  trees); tracked in `docs/security/dependency-dedup.md`.
- **Review by:** closed; residuals tracked in the dedup roadmap.

## RISK-003 — LGPL branch in the `af-xdp` dependency graph

- **Status:** accepted, mitigated by licence election.
- **Description:** `libxdp-sys` and the C libraries it binds (`libxdp`, `libbpf`)
  are offered under `LGPL-2.1 OR BSD-2-Clause`. It is the only crate in the
  workspace that brings an LGPL branch into the graph, and it arrives solely
  through the `af-xdp` feature.
- **Aggravating factor found 2026-08-13:** the declared SPDX string uses the
  **deprecated** identifier `LGPL-2.1`, which cargo-deny cannot parse — it
  degraded to a warning, so this crate's licence was effectively **not being
  checked** at all. It only became visible once `deny.toml` moved to
  `all-features = true`.
- **Mitigation:** Turna elects the permissive branch, `BSD-2-Clause`, pinned
  explicitly via `[[licenses.clarify]]` in `deny.toml` so the check is real and
  the election is machine-readable. Recorded for audit in `docs/COMPLIANCE.md` §6.
  `af-xdp` is absent from default and production builds and is Linux-only.
- **Planned remediation:** none needed while the election holds. If a binary is
  shipped with `--features af-xdp`, add the BSD-2-Clause notice for
  `libxdp`/`libbpf` to `NOTICE`.
- **Review by:** whenever `af-xdp` graduates from experimental.

## RISK — active-session HA remains experimental

**Scope:** multi-node gossip/redirect/failover tooling.
**Accepted boundary:** GA does not promise relay-socket rehydration, preservation
of the old relay IP, conflict-free relay-port adoption, or media continuity after
owner death. Durable metadata is not equivalent to a live socket.
**Mitigation:** canonical production deployment is standalone-first, one public
IP/range per node; use drain for planned maintenance, monitor remaining
allocations, and treat cluster StatefulSet mode as experimental.
**Exit condition:** a separately verified socket/port ownership protocol and
end-to-end media continuity tests across process/node death.
