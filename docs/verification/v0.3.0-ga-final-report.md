# turna GA verification — v0.3.0

Release: **v0.3.0 — Production GA**, dated 2026-07-14.

Scope: the GA-hardening effort on the command-log / management-plane path,
promoted from `0.3.0-rc.2`. All production blockers flagged in the rc.2 external
audit are closed.

## Verification results

Run on Linux (x86_64), Tarantool 2.11.5, full-features Rust build
(`io-uring, af-xdp, dtls, web-transport`):

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | passed |
| `cargo test --workspace --all-features` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| Tarantool TAP `migration_cas_test` | 12/12 |
| Tarantool TAP `u64_parser_test` | 22/22 |
| Tarantool TAP `version_cas_roundtrip_test` | 5/5 |

Deployment / live gates still owned by `RELEASE.md` and **not** covered by this
report: admin frontend build, node/admin container builds + admin container
smoke, Helm lint/template, and the cluster failover smoke.
## Closed work

### Migration page-CAS + fencing (idempotency phase)
The legacy command-log upgrade is a bounded, resumable, three-phase migration
(`commands` → `idempotency` → `complete`). The `idempotency` phase is a
Rust-driven fetch/apply pair so each restorable record's hash is recomputed by
the canonical Rust `command_payload_hash`, never a Lua copy. `fetch` returns a
bounded page plus its CAS context (version, phase, expected cursor, owner,
fencing token) without mutating; `apply` re-checks the FULL CAS (version, phase,
cursor, owner, token, unexpired lease) and, only if all match, writes the page
and advances the cursor as ONE `box.atomic` transaction. A mismatch is a no-op
that leaves the cursor untouched. Apply also refuses to overwrite a terminal
outcome that appeared between fetch and apply, or to clobber a GC'd-then-reused
idempotency key.

### Partial-terminal & orphan rows
A row is migrated unless already fully modern — a full terminal row, or a genuine
pending row whose linked command is still non-terminal. A row that only *looks*
pending but whose command is already terminal is enriched from that command
across the full terminal set (`done`/`failed`/`expired`/`superseded`/
`dead_letter`); if the command is gone, an explicit terminal
`legacy_outcome_unavailable` result is persisted so the record still participates
in retention/GC and never replays as a silent conflict.

### Exact u64 (versions + fencing token)
Runtime and user-limits versions are exact unsigned 64-bit throughout the
Tarantool path: a single `turna_parse_u64_exact` normalizes string/number/cdata,
rejecting any value that does not round-trip; an increment at `u64::MAX` returns
an error rather than wrapping. The migration lease `lease_generation` (the
fencing token) is parsed/compared/incremented as an exact `uint64` in all three
migration functions (`migrate`, `fetch`, `apply`) — a lossy Lua double could
otherwise equate two distinct tokens above 2^53 and let a stale page pass the
CAS.

### Durable outcome for every terminal business result
Applied outcomes are journaled at the observed-version confirmation (atomically
with the observed bump, before completion). Non-mutating terminal outcomes
(`no_op`, version `conflict`, validation `failed`) are recorded into the same
journal via `record_command_outcome` before completion, under the identical
contract (existing canonical record only, matched by `request_id` +
`payload_hash`, never downgraded). Recovery consults the journal before
re-validating, so a replay after the observed state has changed returns the
original outcome verbatim.

### Fail-closed outcome recording (final tail)
`record_terminal_outcome` no longer collapses "no record" and "backend read
failed" into one best-effort branch. `Ok(None)` (record confirmed absent — an
invariant violation) and `Err(read_err)` (write AND read-back both failed, e.g. a
backend outage) both fail closed to `RetryLater`: the command is not completed
and is left for reclaim, so a simultaneous write+read outage can no longer reopen
the exactly-once crash window.

### Failover gate + profile matrix
Optional workers are a pure function of a node's profile (`profile_gates`):
management plane on any durable backend; allocation rehydrate + write-behind on
an allocation-persistence profile; ownership adoption / failover and gossip only
on `cluster_mode` — never inferred from persistence being enabled. Readiness has
matching dataplane / management / cluster tiers.

### Documentation reconciliation
`command-log-lease.md`, `operations-overview.md`, `MANAGEMENT_API.md`,
`CONFIGURATION.md`, `PRODUCTION_READINESS.md`, `feature-support.md`,
`admin/README.md`, `README.md`, `CHANGELOG.md`, and `RELEASE.md` were reconciled
with the final code (page-CAS, fencing, partial/orphan, outcome-before-completion
for all outcomes, profile-worker matrix, exact-u64, no transparent media failover
as GA).

## Tests added
- `crates/state-backend/src/memory.rs`: record-outcome semantics (record/replay/
  no-downgrade/conflict), u64 boundary CAS (runtime exact across the boundary;
  user-limits counter exact + refuses overflow), and an idempotency
  fault-injection hook (`set_idempotency_fault`, compiled in, test-only).
- `services/node/src/runtime_management.rs`: lost-completion recovery for
  `no_op` / `conflict` / `failed`, replay across an incarnation change, retry when
  an outcome cannot be journaled against an existing record, and a fault-injection
  test (write + read-back both fail → `RETRY_LATER`, command not completed).
- `deploy/tarantool/tests/migration_cas_test.lua` (12 cases): phase/cursor/owner/
  token CAS, `box.atomic`, partial-terminal enrichment, orphan, and exact-u64
  fencing (2^53+1 ≠ 2^53, MAX-1 → MAX, refuse overflow at MAX).
- `deploy/tarantool/tests/u64_parser_test.lua`: parser round-trip / rejection at
  the u64 boundaries.
- `deploy/tarantool/tests/version_cas_roundtrip_test.lua`: real stored-proc CAS
  round-trip for runtime + user-limits at 2^53+1 and u64::MAX.

## Commands run

```
cargo fmt --all -- --check
cargo test --workspace --all-features -- --skip dtls --skip full_soak
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Tarantool TAP (throwaway instance per suite, isolated datadir):

```
tarantool -e "dofile('deploy/tarantool/init.lua'); dofile('deploy/tarantool/tests/migration_cas_test.lua')"
tarantool -e "dofile('deploy/tarantool/init.lua'); dofile('deploy/tarantool/tests/u64_parser_test.lua')"
tarantool -e "dofile('deploy/tarantool/init.lua'); dofile('deploy/tarantool/tests/version_cas_roundtrip_test.lua')"
```

## Remaining deployment gates (per RELEASE.md)

Not part of this code-level verification; owned by `RELEASE.md`:

- admin frontend build (`npm ci && npm run build`);
- node + admin container builds, and the admin container smoke;
- Helm lint / template;
- cluster failover smoke — induced node-death / ownership failover.

Optional feature-gated subsystems remain **experimental** and are intentionally
not promoted by this report: `io-uring`, `af-xdp`, `dtls`, `quic`,
`web-transport`, TLS-over-TCP, RFC 6062 TCP relay, and multi-node cluster /
gossip mode.
