# Dependency duplication roadmap

Tracking record for duplicate dependency versions in the workspace, derived
from `cargo tree -d` against `Cargo.lock`. None of these are release blockers;
this document records what the `0.2.0-alpha.1` cleanup removed and what is left
for beta.

`deny.toml` keeps `multiple-versions = "warn"`, so `cargo deny check` stays
green while the remaining multiplicity is tracked here rather than ignored
silently.

## Resolved in 0.2.0-alpha.1: the previous gRPC/HTTP generation

The workspace is on the current generation of the gRPC/HTTP stack — `tonic
0.14`, `axum 0.8`, `hyper 1`, `http 1`, `prost 0.14`, `tower 0.5`,
`thiserror 2`. Until this release a *second*, older generation was pulled in
through a single transitive path:

```
opentelemetry-otlp 0.16  ->  tonic 0.11  ->  axum 0.6 / hyper 0.14 / http 0.2
                                              h2 0.3 / prost 0.12 / tower 0.4
                                              base64 0.21 / bitflags 1.x ...
opentelemetry* 0.23      ->  thiserror 1.0
```

That single blocker was removed by upgrading the OpenTelemetry crates to
`0.32` — `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` (with
`grpc-tonic`), and `tracing-opentelemetry 0.33`. `opentelemetry-otlp 0.32`
builds on `tonic 0.14` / `prost 0.14` / `http 1` / `hyper 1` and `thiserror 2`,
so the entire `tonic 0.11` / `axum 0.6` generation is gone. `tonic` now
resolves to a single major (`0.14.x`), and the `opentelemetry-otlp` `skip-tree`
entry has been removed from `deny.toml`.

> Verify after the upgrade with `cargo tree -d`: the output should no longer
> contain `tonic 0.11`, `axum 0.6`, `hyper 0.14`, `http 0.2`, `h2 0.3`,
> `prost 0.12`, `tower 0.4`, or the `base64 0.21` / `bitflags 1` leaves.

## Remaining minor-version multiplicity — accept

Unrelated leaf crates resolving their own minor versions; chasing them has no
security or size payoff:

- `socket2` 0.5 / 0.6 — `turna-transport` pins `0.5`, while `tokio` and
  `tonic 0.14` are on `0.6`. Optional cleanup: bump `turna-transport` to
  `socket2 0.6`.
- `hashbrown` (multiple minors) and `getrandom` 0.2 / 0.3 — ubiquitous
  transitive splits; covered by the `deny.toml` `skip` list.
- `regex` / `regex-automata` / `regex-syntax` — same version reachable through
  multiple build/normal paths.

## Dev-only duplicates — accept, not shipped

These live only under `dev-dependencies` / `build-dependencies` and never reach
a release binary:

- `getrandom 0.3` — via `proptest`. (`rand` 0.8/0.9 is *not* dev-only:
  `opentelemetry_sdk 0.32` pulls `rand 0.9` at runtime alongside the workspace's
  pinned `rand 0.8`; that split, with its `rand_chacha`/`rand_core` leaves, is
  benign and suppressed via the `deny.toml` `skip` list.)
- `itertools 0.10` — via `criterion` (benchmarks).
- `getrandom 0.4` — via `tempfile` (test/build).

## `rustls-pemfile` — web-transport only

`rustls-pemfile` (RUSTSEC-2025-0134, unmaintained) is no longer a direct
dependency: PEM parsing in `turna-transport` moved to `rustls-pki-types`. It
remains only transitively via `wtransport` under the experimental
`web-transport` feature, and is absent from default/production builds. See
RISK-001 in `accepted-risks.md`.

## Summary

- Removed in alpha: the entire `opentelemetry-otlp 0.16` / `tonic 0.11` /
  `axum 0.6` generation, via the OpenTelemetry 0.32 upgrade.
- Accept: benign minor multiplicity (`socket2`, `hashbrown`, `getrandom`),
  dev-only trees (`proptest`, `criterion`), and `rustls-pemfile` under the
  preview `web-transport` feature.
