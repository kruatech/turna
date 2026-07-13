# Command-log lease & fencing contract (P0.2 / P0.4)

The control-plane routes node-targeted commands (drain, undrain, shutdown,
delete_allocation) through a durable command log. The node half claims commands,
applies them, and marks them done/failed.

Two reliability invariants are enforced by the backend, **not** by the callers:

- **P0.2 — no stuck `in_progress`.** A node may die after claiming a command but
  before completing it. Without a lease, that command is `in_progress` forever
  and never re-applied. Claims therefore carry a lease; an `in_progress` command
  whose lease has expired is reclaimable on the next claim.
- **P0.4 — fenced completion.** Only the current claimant may complete a command,
  and only from `in_progress`. Fencing is by a **per-claim `claim_token`**, not
  just `claimed_by`: a stale worker whose lease expired and was reclaimed holds an
  old token and must be rejected even when the reclaiming worker shares the same
  node id. Completion reports whether it was applied (so a rejected, stale caller
  does not assume success).
- **P0.2 bound — dead-letter.** After `MAX_COMMAND_ATTEMPTS` (5) claims a command
  is moved to terminal `failed` (`result = "dead_letter: ..."`) instead of being
  reclaimed again, so a repeatedly-failing command cannot loop forever.

The **reference implementation is `crates/state-backend/src/memory.rs`**
(`InMemoryBackend::claim_commands` / `complete_command`). The Tarantool backend
must match its observable behaviour. The Rust wrappers in
`crates/state-backend/src/tarantool.rs` call the stored procedures with the
signatures below; the matching Lua procedures are now implemented in
`deploy/tarantool/init.lua` (`turna_enqueue_command` / `turna_claim_commands` /
`turna_complete_command`, plus the `turna_command_idem` space for P0.3). They
**still require live stand verification** — the CI here cannot run a Tarantool
instance, so lease/reclaim/token-fencing/dead-letter/idempotency must be checked
against a real node before the cluster P0 items are signed off.

## Row shape (`PendingCommand`)

Fields relevant to leasing (see `crates/state-backend/src/lib.rs`):

| field            | type   | meaning                                             |
|------------------|--------|-----------------------------------------------------|
| `request_id`     | string | primary key; enqueue dedups on it                   |
| `target_node_id` | string | which node may claim/apply this command             |
| `status`         | string | `pending` \| `in_progress` \| `done` \| `failed`    |
| `claimed_by`     | string | node holding the current claim (empty when pending) |
| `lease_until_ms` | u64    | epoch-ms deadline of the current claim's lease      |
| `attempts`       | u32    | incremented on every claim, including reclaims      |
| `claim_token`    | string | unique token minted on each claim (P0.4 fence)      |
| `idempotency_key`| string | client-supplied dedup key (P0.3); empty = none       |
| `updated_at_ms`  | u64    | last mutation time                                  |

`claimed_by`, `lease_until_ms`, `attempts`, and `claim_token` are new. They are
`#[serde(default)]`, so existing rows without them deserialize fine (defaults:
empty / 0 / 0 / empty).

## `turna_enqueue_command(request_id, target_node_id, data, payload_hash)` — durable idempotency (P0.3)

`data` is the full serialized `PendingCommand` (it carries `idempotency_key`).
`payload_hash` is the canonical FNV-1a/64 computed by the Rust
`command_payload_hash(op, args, payload_json)` — over `(op, payload_json)` when a
typed payload is present, else over `(op, args)`. The command-log migration
recomputes a legacy record's hash with this same Rust function (never a Lua
copy), so the value is identical however it was produced.
Enqueue returns **`(canonical_request_id, conflict)`**: the caller polls the
canonical id; `conflict = true` means the same key was reused with a *different*
payload (rejected → `BackendError::Conflict`, not a dedup hit).

- If `idempotency_key` is empty → insert keyed by `request_id` (dedup on
  `request_id` only) and return `(request_id, false)`.
- If `idempotency_key` is non-empty → atomically resolve it against the
  `turna_command_idem` record (primary key = `idempotency_key`). The first
  caller wins and its command is inserted; a later retry carrying the **same
  key + same payload_hash** resolves to the winner, does **not** insert a second
  command, and gets `(winner_request_id, false)`. The **same key with a
  different payload_hash** returns `(request_id, true)` (conflict). A legacy
  pre-2b record with no stored hash never triggers a false conflict.

A dedup hit resolves whatever the command's status
(`pending`/`in_progress`/terminal). Crucially, the idempotency record is
**self-sufficient and retained independently** of the command (see “Durable idempotency and GC”):
it stores the terminal outcome and its own `completed_at_ms`, so it can
**outlive** the command row under GC. A replay arriving after the command has
been pruned recovers the original outcome via `turna_get_idempotency(key)` — the
control-plane's `enqueue_and_await` falls back to it — instead of polling a
`get_command` row that will never reappear. The in-memory backend (`memory.rs`)
is the reference; the Tarantool procs must match.

## `turna_claim_commands(node_id, max, lease_ms, now_ms)`

All four arguments arrive as strings (iproto CALL args). Parse `max`, `lease_ms`,
`now_ms` as integers.

Atomically (single transaction, so two claimants cannot both take the same row),
select up to `max` rows where `target_node_id == node_id` **and**

```
status == "pending"
  OR (status == "in_progress" AND lease_until_ms <= now_ms)
```

For each selected row, **first apply the retry bound**: if `attempts >= 5`
(`MAX_COMMAND_ATTEMPTS`), set `status = "failed"`,
`result = "dead_letter: exceeded 5 claim attempts"`, `updated_at_ms = now_ms`, and
do **not** return the row. Otherwise claim it:

```
status         = "in_progress"
claimed_by     = node_id
claim_token    = <fresh unique token>   -- unique per claim; see below
lease_until_ms = now_ms + lease_ms
attempts       = attempts + 1
updated_at_ms  = now_ms
```

The `claim_token` must be unique for every claim (including reclaims of the same
row), e.g. a UUID or `node_id .. ":" .. box.info.uuid .. ":" .. attempts .. ":" ..
clock.realtime`. The Rust reference uses pid + nanoseconds + a monotonic counter.

Return the claimed rows (same serialization `turna_get_command` uses, so
`call_list` deserializes them into `PendingCommand`). Return an empty list when
nothing is claimable.

Reclaiming an expired `in_progress` row is how P0.2 is closed: no separate reaper
task is required — expiry (and dead-lettering) are handled inside the claim.

## `turna_complete_command(request_id, claimed_by, claim_token, status, result)`

Look up the row by `request_id`. Apply the write **only if**

```
row.status == "in_progress"
  AND row.claimed_by == claimed_by
  AND row.claim_token == claim_token
```

then set `status = status`, `result = result`, `updated_at_ms = <now>`.

The procedure **must return a boolean**: `true` if the write was applied, `false`
otherwise. The Rust wrapper decodes msgpack `true` (`0xc3`). If the guard fails
(row missing, not `in_progress`, wrong claimant, or a superseded/old
`claim_token`), it must be a **no-op returning `false`** — the command is left to
be reclaimed on lease expiry rather than being marked done by a caller that no
longer owns the claim. The whole check must be inside the same transaction as the
write.

## Notes / follow-ups

- The stricter fence is now implemented via `claim_token` (above): a stale
  claimant sharing the new claimant's `node_id` is rejected because it presents a
  superseded token. `attempts` additionally bounds retries via dead-lettering.
- Lease length is `COMMAND_LEASE_MS` in `services/node/src/main.rs` (30s). It must
  comfortably exceed the worst-case apply time of any single command.
- Verify on the stand: kill a node mid-apply and confirm the command is reclaimed
  and re-applied; attempt a foreign completion and confirm it is ignored.

## Durable idempotency and GC

The command log can be garbage-collected without weakening idempotency,
and idempotency-key reuse with a different payload is detectable.

### Self-sufficient idempotency records

`turna_command_idem` no longer maps a key to just a `request_id`. Each record
now carries the payload hash and the terminal outcome:

| field             | meaning                                                        |
|-------------------|----------------------------------------------------------------|
| `idempotency_key` | primary key                                                    |
| `request_id`      | canonical command this key first created                       |
| `payload_hash`    | canonical Rust FNV-1a/64 of `(op, payload)` or `(op, args)` — conflict detection  |
| `final_status`    | terminal status once known (`""` while pending)                |
| `result`          | terminal result once known                                     |
| `created_at_ms`   | when the record was created                                    |
| `completed_at_ms` | when the guarded command reached a terminal state, or `0`      |

Because the record stores the outcome, it can **outlive the command row** under
GC: a replay that arrives after the command has been pruned still resolves to
the original `request_id` and prior result instead of re-running the operation.

### Conflict on key reuse

`turna_enqueue_command(request_id, target_node_id, data, payload_hash)` returns
`(canonical_request_id, conflict)`:

- same key + **same** `payload_hash` → dedup: returns the canonical id;
- same key + **different** `payload_hash` → `conflict = true`, surfaced by the
  Rust wrapper as `BackendError::Conflict` (the key was reused for a different
  operation — not a retry).

The Rust side computes `payload_hash` (`command_payload_hash`) and passes it in,
so both backends hash identically. Legacy records without a stored hash
never trigger a false conflict.

### Indexed status for GC (no full scan)

`turna_commands` promotes `status` and `updated_at_ms` to top-level, nullable,
indexed columns (`by_status`); the `data` blob stays authoritative for content
(claim/get still deserialize from it). GC scans only terminal rows via the
index instead of the whole space. Command mutations use `replace` (not a
non-contiguous `update`) so a legacy row is upgraded in place.

### Garbage collection

`turna_gc_command_log(now_ms, done_ms, failed_ms, superseded_ms, expired_ms,
idem_ms, batch)` prunes one bounded batch (≤ `batch` command deletes and
≤ `batch` idempotency deletes per CALL, keeping the transaction small) and
returns `(deleted_commands, deleted_idempotency, terminal_remaining,
oldest_unfinished_age_ms, more)`. The control-plane sweep
(`run_command_log_gc` in `services/control-plane/src/main.rs`) loops up to
`max_batches_per_sweep` while `more`, on the cadence + jitter from
`[cluster.command_log]`, exports the counts/gauges as `turna_command_log_*`
metrics, and degrades control-plane readiness on a sustained growing backlog or
repeated backend errors. GC is best-effort and never stalls the dataplane.

Retention defaults and the
`retain_idempotency_secs >= max(retain_done, retain_failed, retain_superseded,
retain_expired)` invariant (so an idempotency record outlives EVERY command it
can guard — the longest terminal window, not just `failed`) are in
`[cluster.command_log]`;
`InMemoryBackend` remains the reference and is unit-tested, while the Tarantool
procedures still require **live stand verification**.

## Versioned typed commands

New management operations store a deterministic typed JSON payload in
`payload_json`; legacy operations retain `args`. Payload DTOs deny unknown fields
and carry an explicit schema version. The idempotency hash includes the exact
normalized typed payload, so the same key/same payload replays while the same
key/different payload conflicts.

Commands are targeted to both `node_id` and the process `incarnation` observed
in heartbeat. The backend's atomic claim filters on both values; the node handler
checks them again before apply. A restarted process adopts durable state before
readiness but cannot claim its predecessor's commands.

Legacy command rows are upgraded by a versioned, bounded, resumable Tarantool
migration that runs in three phases: `commands` (normalize each command's
extracted status/timestamp columns) → `idempotency` (upgrade legacy/partial
idempotency rows) → `complete`. Each sweep runs at most one configured batch;
phase, cursor, cumulative processed count, error count, and completion are
durable.

A per-migration lease serializes concurrent runners. Beyond the owner id the
lease carries a monotonic **fencing generation**, bumped on every new
acquisition (first grab or a takeover after expiry) and kept on a same-owner
refresh, so a stale page issued under a since-superseded lease cannot land even
under the same owner. The `commands` and `complete` phases run wholly in Lua.
The `idempotency` phase is a Rust-driven fetch/apply pair so each restorable
record's hash is recomputed by the canonical Rust `command_payload_hash`, never a
divergent Lua copy: `turna_migration_idem_fetch` returns a bounded page plus its
CAS context (migration version, phase, expected cursor, owner, fencing token)
without mutating; Rust computes the hashes; `turna_migration_idem_apply` then
re-checks the FULL CAS (version, phase, cursor, owner, token, and an unexpired
lease) and, only if all match, writes the page and advances the cursor as ONE
transaction (`box.atomic`). A mismatch is a no-op that leaves the cursor
untouched, and the driver simply re-fetches on the next tick. Apply also re-reads
each row and refuses to overwrite a terminal outcome that appeared between fetch
and apply, or to clobber a row whose idempotency key was GC'd and reused by a
different command.

A row is migrated unless it is already fully modern — a full terminal row
(hash + status + result + created + completed) or a genuine full pending row
(hash set, no outcome, **and** its linked command still non-terminal). A row that
merely *looks* pending but whose command is already terminal is a partial row and
is enriched: the outcome is restored from the linked command across the full
terminal set (`done` / `failed` / `expired` / `superseded` / `dead_letter` and
any other non-empty terminal status), or — if the command is gone — an explicit
terminal `legacy_outcome_unavailable` result is persisted so the record still
participates in retention/GC and never replays as a silent conflict.

GC remains separately bounded, and durable idempotency records preserve terminal
replay after command deletion.

## Command status vs business outcome

Two distinct fields must not be conflated:

- **Transport command status** (the row's `status`): `pending` → `in_progress`
  → `done`, plus the terminal side-states `failed`, `expired`, `superseded`,
  and `dead_letter`. `done` means the handler ran and stored a typed result; it
  does **not** by itself mean the change was applied.
- **Business outcome** (inside the typed result JSON): one of `applied`,
  `no_op`, `conflict`, `superseded`, `failed`. A command can be transport-`done`
  while the business outcome is `conflict` or `no_op`.

Audit success is derived from the business outcome (`applied` / `no_op`), not
from the transport status.

## Lost-completion recovery

A command may apply its side effect and then lose its completion write (crash,
lease expiry, or a lost response). Recovery makes the effect exactly-once from
the caller's perspective:

1. The handler applies the side effect (e.g. publishes the runtime snapshot or
   the user-limits cache).
2. The operation identity and its typed result are recorded **durably at the
   observed-version confirmation** — in the **same explicit Tarantool transaction
   (`box.atomic`)** as the observed-version bump and its CAS re-read, and
   **before** the completion write — into the durable idempotency journal
   (`turna_command_idem`), keyed by `idempotency_key` and retained at least as
   long as every command window. Because memtx does not make a stored procedure
   atomic on its own, the journal write and the observed-state write are wrapped
   in one transaction: either both land or neither does, so the journal can never
   record `applied` while the observed state was left un-bumped. The node also
   keeps the most-recent applied operation as a fast path. Every later journal
   write (completion, dead-letter,
   stale finalize) is guarded, so a record that already reached a terminal
   outcome is never downgraded.
3. The completion write is lost; the row stays non-terminal.
4. A later worker (reclaim or post-restart) re-examines the command and matches
   its identity — by `request_id`, or by `idempotency_key` + `payload_hash`.
   The match consults the durable idempotency journal, not only the node-local
   most-recent slot, so an **older, interleaved** command still recovers its
   result rather than being re-applied or finalized as `superseded`.
5. It returns the **stored** outcome as the result.
6. The side effect is **not** re-applied.

The same guard turns a genuine replay (same key + same normalized payload) into
a stored-result return rather than a spurious version `conflict`.

Terminal outcomes that do **not** mutate observed state — `no_op`, version
`conflict`, and validation `failed` — are recorded into the same journal via
`record_command_outcome` **before** the command is completed, using the identical
contract (only the existing canonical record, matched by `request_id` and
`payload_hash`, never downgraded). The handler consults this journal *before*
re-validating, so a replay after the observed state has since changed returns the
original outcome verbatim rather than re-deriving a different `conflict` / `no_op`
against the new state. If a fresh recording is rejected because a terminal outcome
is already stored, that durable outcome wins — the caller never sees a divergent
recomputation.

## Incarnation changes and stale recovery

Commands are fenced to a target `incarnation`. When a node restarts under a new
incarnation, commands aimed at the old one cannot be claimed or applied by the
new process. A bounded stale sweeper finalizes them so they never linger
non-terminal:

- The sweeper acts on a command only when it is **non-terminal**, its
  `target_incarnation` is non-empty, and it differs from the current
  incarnation (fencing invariant).
- If the operation was already applied (recognized via the applied-operation
  metadata), its stored outcome is returned; otherwise it is finalized as a
  typed `superseded` result.
- Terminal rows are never reclaimed or dead-lettered by the sweeper.

This guarantees no command remains permanently non-terminal across incarnation
changes, while preserving exactly-once side effects for already-applied
operations.
