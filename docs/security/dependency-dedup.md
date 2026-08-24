# Dependency duplication roadmap

Tracking record for duplicate dependency versions in the workspace, derived
from `cargo tree -d` against `Cargo.lock`. None of these are release blockers;
this document records what the `0.2.0-alpha.1` cleanup removed and what is left
for beta.

`deny.toml` keeps `multiple-versions = "warn"`, so `cargo deny check` stays
green while the remaining multiplicity is tracked here rather than ignored
silently.

> **Scope change (2026-08-13).** `deny.toml` now sets `all-features = true`.
> Previously cargo-deny resolved only the *default* feature graph, which is why
> both `[advisories] ignore` entries reported `advisory-not-detected` — the crates
> they cover (`bincode` via `dtls`, `paste` via `af-xdp`) were not in the graph
> being checked, so the checks were not covering the builds the ignores exist for.
> With the full graph the advisories are correctly matched, and the duplicate list
> grew from a handful to ~24 because the feature-only subtrees are now visible.
> **This is disclosure, not regression** — those duplicates were always in
> feature builds; they were simply unexamined. See "Feature-only duplicates".

## Feature-only duplicates — surfaced by `all-features`

Two generations of the certificate/ASN.1 parsing stack coexist because
`webrtc-dtls` (feature `dtls`) and `wtransport` (feature `web-transport`) pin
different majors:

`asn1-rs`, `asn1-rs-derive`, `asn1-rs-impl`, `der-parser`, `oid-registry`,
`x509-parser`, `yasna`, `rcgen`, `synstructure`, plus the RustCrypto leaves they
drag along (`digest`, `block-buffer`, `crypto-common`, `sha2`, `const-oid`,
`cpufeatures`) and unrelated splits (`bitflags` 1/2, `nix`, `foldhash`, `shlex`,
`itertools`, `syn`, `thiserror`, `untrusted`).

None of these reach a default or production binary. Cleaning them up means
waiting for `webrtc-dtls` and `wtransport` to converge on one `rcgen` /
`x509-parser` generation, which is upstream work, not ours.

**Deliberately not suppressed yet.** Adding `skip`/`skip-tree` entries would
silence them, but a blanket `skip-tree` on `webrtc-dtls` or `wtransport` would
also hide a *new* duplicate appearing under those roots. Decide from
`cargo tree -d` output which roots are worth a targeted `skip-tree`, and record
each here with the root and the reason — the same discipline the existing `skip`
list follows.

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

`rustls-pemfile` (RUSTSEC-2025-0134, unmaintained) is **gone from the graph
entirely**. It was removed as a direct dependency when PEM parsing in
`turna-transport` moved to `rustls-pki-types`, and the last transitive path —
`wtransport` under the experimental `web-transport` feature — disappeared with
`wtransport 0.7.1`. Verified against `Cargo.lock`:
`cargo tree -p turna-transport --features web-transport -i rustls-pemfile`
reports no matching package. RISK-001 in `accepted-risks.md` is closed.

## Summary

- Removed in alpha: the entire `opentelemetry-otlp 0.16` / `tonic 0.11` /
  `axum 0.6` generation, via the OpenTelemetry 0.32 upgrade.
- Accept: benign minor multiplicity (`socket2`, `hashbrown`, `getrandom`),
  dev-only trees (`proptest`, `criterion`), and the feature-only certificate/ASN.1
  duplication under `dtls` / `web-transport`.
- Closed: `rustls-pemfile` is no longer in the graph at all (RISK-001).
