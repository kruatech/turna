# Release Guide


## Stable/GA scope

The stable target is a **standalone-first TURN platform**: one Tokio dataplane
node owns one public IP and relay range; control-plane and admin are separate;
Tarantool stores command-log plus runtime desired/observed state. The published
admin image is part of the release and must pass its container smoke test.

Multi-node gossip/redirect mode remains experimental. A release must not claim
transparent continuation of an active allocation after owner death, relay
socket rehydration on another node, preservation of the old relay IP, automatic
cross-node relay-port conflict resolution, or zero-gap rolling upgrades.

`update_config` and `set_user_limits` are GA-scoped APIs. A release is blocked
unless node-side expected-version checks, idempotent replay, restart restore,
allocation reservation races, command GC replay, legacy migration, and admin
token behavior pass on the exact commit.

How to build, verify, and (optionally) publish a turna release.

> Verify the exact Cargo feature names against each crate's `Cargo.toml` before
> tagging — the sets below are the intended configuration, not a guarantee that
> every name is exposed by the target crate.

## Prerequisites

- **Rust toolchain 1.95+** (workspace builds and lints were verified on 1.95).
- For the **`af-xdp`** feature (the embedded XDP program is compiled at build time
  via `clang -target bpf`):
  - `clang` and `llvm`
  - `linux-libc-dev` — arch UAPI headers (e.g. `asm/types.h`)
  - `libelf` and `zlib` development headers (vendored libbpf build)
  - Debian/Ubuntu: `sudo apt-get install -y clang llvm linux-libc-dev libelf-dev zlib1g-dev`
- **Kernel minimums at runtime** (see `docs/transport-backends.md`):
  io_uring NODROP ≥ 5.5; AF_XDP copy mode ≥ 5.10; AF_XDP zero-copy / multi-queue ≥ 5.15.

## Feature flags

Optional/high-performance backends are behind Cargo features:

- `io-uring` — io_uring datapath (Linux; no extra privileges)
- `af-xdp` — AF_XDP datapath (Linux; needs the clang/libxdp toolchain above; `CAP_NET_RAW` at runtime)
- `dtls`, `web-transport`, `quic`, `tls` — signalling / transport options

## Building a release

```bash
cargo build --release -p turna-node --features io-uring,af-xdp,dtls,web-transport
```

**Caveat:** enabling `quic` together with `web-transport` can hit the
`wtransport` bundled-quinn vs standalone quinn conflict. If a build with both
fails to compile, that combination is the cause — not the datapath features.
For a focused datapath build use `--features io-uring,af-xdp`.

## Checks before tagging

```bash
cargo deny check                              # advisories / bans / licenses / sources
cargo clippy --workspace -- -D warnings       # lib + bins + tests
cargo test  --workspace --all-features -- --skip dtls --skip full_soak
```

- `cargo deny check` is expected green (advisories clean; the older
  `opentelemetry-otlp 0.16` transport stack is acknowledged via `bans.skip-tree`
  rather than deduplicated — see CHANGELOG).
- On `--all-features`, see the quic/web-transport caveat above. A narrower run
  is `cargo clippy -p turna-transport --features io-uring,af-xdp -- -D warnings`.
- Tests that require an external server (e.g. Tarantool) or long soak runs are
  expected to be skipped/ignored in CI.

## Runtime notes

- Transport backend is selected in config: `[turn] transport = "tokio" | "io_uring" | "af_xdp"`.
  `io_uring` and `af_xdp` are never auto-selected — request them explicitly.
- **AF_XDP** requires a concrete `listen` IP (not `0.0.0.0`) and `CAP_NET_RAW`/root,
  and attaches an XDP program to the configured interface (removed on clean
  shutdown; after `SIGKILL` clear with `ip link set dev <iface> xdpgeneric off`).
- Metrics are served at `/metrics` (Prometheus); the health server port is set
  via `[health].listen` (default `0.0.0.0:8080`).
- Full backend reference: `docs/transport-backends.md`.

## Publishing to crates.io (optional — not yet configured)

If/when publishing library crates:

- Keep `publish = false` on internal/binary crates and tools.
- For publishable libraries, remove `publish = false` and add `description`,
  `readme`, and `license` fields. Candidate set per maintainers: `proto-stun`,
  `proto-turn`, `packet`, `crypto`, `common`, `rtp-analyzer`, `health`,
  `observability`. Confirm each is actually self-contained and license-clean
  before flipping it publishable.

## GA management verification order

Run the repository's existing CI/feature matrix first, then Tarantool clean and
legacy-schema upgrade scenarios, frontend build, both container builds, admin
container smoke, deploy consistency/Helm render, fuzz/mutation/soak commands,
and finally the live scenarios listed in `docs/verification/v0.3.0-ga-verification.md`.
Do not infer GA readiness from source review alone.

## Upgrade procedure (from a previous RC/release)

Do not promise a zero-gap rolling upgrade of an active media dataplane; it is
not a guaranteed operation.

1. Back up Tarantool.
2. Check the current schema version.
3. Deploy the backend/migration-capable code.
4. Run the bounded, resumable command-log migration.
5. Wait for the `commands → idempotency → complete` phases to finish.
6. Update the control-plane.
7. Update the TURN nodes.
8. Update the admin image.
9. Verify desired/observed convergence (see the readiness gate below).

## Migration

The legacy command-log upgrade is a versioned, bounded, resumable migration:

- **Phases:** `commands` (upgrade legacy rows to the typed/fenced form) →
  `idempotency` (backfill idempotency records for legacy keys) → `complete`
  (completion marker).
- **Cursor / batch / resume:** each sweep runs at most one configured batch; a
  durable cursor and cumulative processed count are exposed via migration
  progress/error metrics. On process stop, the next sweep resumes from the
  cursor.
- **Lease / fencing:** a per-migration lease carries a monotonic fencing
  generation (bumped on every new acquisition, kept on refresh). The idempotency
  phase is a fetch/apply pair; apply commits only under a full compare-and-swap
  (version, phase, cursor, owner, token, unexpired lease) in a single
  transaction, so a page issued under a since-superseded lease cannot land and
  never rewinds the cursor.
- **Legacy / partial / orphan policy:** a row is migrated unless it is fully
  modern — a full terminal row, or a genuine pending row whose linked command is
  still non-terminal. A row that only *looks* pending but whose command is
  already terminal is enriched from that command across the full terminal set
  (`done`/`failed`/`expired`/`superseded`/`dead_letter`). An idempotency record
  whose linked command is gone is finalized with an explicit terminal
  `legacy_outcome_unavailable` result, so it participates in retention/GC and
  never replays as a silent conflict. Apply never overwrites a terminal outcome
  that appeared concurrently, nor a GC'd-then-reused key.
- **Completion:** the migration is done when the completion marker is set and no
  batches remain. It is additive (row upgrade + idempotency backfill); a binary
  rollback after conversion must be verified against the specific prior release
  rather than assumed safe.

## Rollback

- **Application rollback.** Revert to the prior binary. Verify it tolerates the
  migrated (additive) schema and the field-number-preserving proto contract; old
  clients relying on retired field layouts or `GLOBAL = 0` need updating either
  way.
- **Runtime-operation rollback.** A failed observed confirmation rolls the local
  publication back: the business outcome is `failed` with `rolled_back = true`,
  the observed snapshot stays at the previous confirmed version, and a failed
  desired state is **not** auto-applied after restart — it is retained as
  failed/mismatched for diagnosis.
- **Deployment rollback.** Revert the main image, the admin image, and Helm
  values independently. Tarantool schema rollback is the riskiest step and
  requires restoring from the backup taken in the upgrade procedure.

## Release blockers

A release is blocked by any of:

- Version mismatch across Cargo workspace, git tag, Helm chart/appVersion,
  Docker image tag/OCI label, README install example, and CHANGELOG entry.
- An incomplete migration.
- A desired/observed mismatch on any managed node.
- A missing admin artifact when the release workflow publishes it.
- An unsupported topology (e.g. multi-replica shared relay IP without an
  external routing architecture).
- An invalid production config (unlimited bandwidth without accepted risk,
  allocation cap above relay capacity, in-memory backend in cluster mode, etc.).
- Release docs that do not match the actual shipped scope.
