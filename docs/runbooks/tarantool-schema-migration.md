# Runbook — Tarantool schema migration and upgrades

Two different things wear the word "migration" here, and confusing them is the
main way this goes wrong:

1. **Schema provisioning** — `deploy/tarantool/init.lua`, which creates spaces,
   indexes, stored functions and the `turna_app` role. Idempotent by
   construction. Re-run it on every upgrade.
2. **The command-log backfill** — a bounded background task inside the node that
   normalises legacy rows in `turna_commands`. It runs itself, gates the
   management plane while it works, and needs nothing from you except a metric to
   watch.

This runbook covers both. Backup and restore are in
`docs/runbooks/tarantool-backup.md`; deployment order under Kubernetes is in
`docs/runbooks/kubernetes-tarantool.md`.

## 1. Schema provisioning is idempotent, and that is the whole design

Every `box.schema.space.create` and every `create_index` in `init.lua` uses
`if_not_exists = true`, and every grant likewise. There is no version number, no
migration table, and no ordered list of steps to apply — re-running the script
converges the schema and leaves existing data alone.

That means the upgrade procedure is: **run `init.lua` again**.

    TURNA_PASSWORD=<from your secret store> tarantool /path/to/init.lua

Supply `TURNA_PASSWORD`. Without it the script generates one and prints it once;
with it, the password is refreshed on every run, which is what makes re-running
safe in automation.

There is exactly one definition of the schema — that file. Nothing on the Rust
side carries a second copy to keep in step.

### What idempotence does not cover

`if_not_exists` creates what is missing. It does **not** alter what exists. So:

- a new **space** or a new **index** appears on re-run — safe, and the common case;
- a changed **field type** or a changed **index part** does not. The old shape
  stays, silently, and the node then reads or writes something the code no longer
  expects.

Nothing in the current schema needs that kind of change, and the one candidate on
the horizon — the composite primary key discussed for
`ADDITIONAL-ADDRESS-FAMILY` — is called out in
`docs/design/additional-address-family.md` as needing "a documented procedure and
a rollback that does not strand rows" precisely because `if_not_exists` will not
do it for you. If that day comes, this section is where the procedure goes.

### Verify after every run

Three checks, and they cost seconds:

    tt connect <host>:3301 -f - <<'EOF'
    print(box.space.turna_allocations ~= nil)
    print(box.func['turna_init_schema'] ~= nil)
    print(box.schema.user.exists('turna_app'))
    EOF

All three must print `true`. A node connecting to an unprovisioned Tarantool
fails on its first call rather than degrading, so catching it here is much
cheaper than catching it in a pod log.

## 2. The stored functions are the contract, and they are tested

The node does not read and write spaces directly for the operations that matter.
It calls stored functions, and those carry the compare-and-swap semantics that
failover and runtime config depend on — `turna_cas_runtime_desired`,
`turna_migration_idem_apply`, `turna_parse_u64_exact`, the claim primitives.

Three Lua suites pin that behaviour:

| Suite | What it pins |
|---|---|
| `deploy/tarantool/tests/migration_cas_test.lua` | Migration idempotency: phase, cursor and owner transitions, 12 cases. |
| `deploy/tarantool/tests/u64_parser_test.lua` | The exact-u64 parser — versions cross the wire as decimal strings and are stored `unsigned`; a lossy parse would silently corrupt a version compare. |
| `deploy/tarantool/tests/version_cas_roundtrip_test.lua` | Real stored-procedure CAS round-trip, including rollback when a write is made to fail. |

They run in CI (`failover-integration`). To run them by hand against a throwaway
instance — not against production, they write:

    docker run --rm -e TURNA_PASSWORD=turna \
      -v "$PWD/deploy/tarantool:/opt/turna:ro" \
      tarantool/tarantool:2 \
      tarantool -e "dofile('/opt/turna/init.lua'); dofile('/opt/turna/tests/migration_cas_test.lua')"

Each suite ends with `os.exit(check() and 0 or 1)`, so the exit status is the
result.

**If you change a stored function, run these first.** Getting CAS wrong here does
not throw — it loses allocations quietly, which is the failure this whole layer
exists to prevent.

## 3. The command-log backfill

Separate machinery, and the only "migration" that runs on its own. On startup the
node walks `turna_commands` in batches of 500, normalising legacy rows, and
**holds the management plane not-ready until it finishes**. The TURN dataplane is
unaffected and keeps serving throughout — that separation is deliberate.

Watch three metrics, all described in `docs/OBSERVABILITY.md`:

| Metric | Meaning |
|---|---|
| `turna_command_log_migration_processed_total` | Rows normalised so far. Should climb, then stop. |
| `turna_command_log_migration_completed` | `1` when done. |
| `turna_management_readiness` | `1` once the backfill completes. Deliberately its own gauge, separate from `turna_transport_readiness` and `turna_backend_readiness`, so a node mid-backfill is not mistaken for one that cannot relay. There is no single `turna_readiness` series — readiness is reported per subsystem. |

`turna_command_log_migration_errors_total` climbing instead means backend errors
during the walk. Look at the Tarantool side; the node retries.

On a fresh deployment there is nothing to migrate and all of this completes
immediately. `processed_total` staying at `0` with `completed = 1` is the normal
result, not a stall.

## 4. Rolling upgrade order

1. Back up Tarantool (`docs/runbooks/tarantool-backup.md`). Do this even though
   provisioning is idempotent — the backup is for the node upgrade, not the
   schema one.
2. Run `init.lua` against the instance. New spaces and indexes appear; nothing
   existing changes.
3. Verify with the three checks in §1.
4. Roll the turna nodes one at a time. Wait for `turna_management_readiness = 1`
   on each before moving to the next, so two nodes are never mid-backfill
   together.
5. Watch `tarantool_writes_dropped_total` across the roll. Any increase is
   allocation state that did not reach the backend.

Order matters in one direction only: the schema must not be *behind* the code. A
schema ahead of the code is harmless — spaces and functions the old binary does
not call cost nothing.

## 5. Rollback

Rolling the node binaries back is safe as long as the schema stays. Old nodes
ignore spaces and functions they do not know.

Rolling the *schema* back is not a supported operation and there is no script for
it: `if_not_exists` has no inverse, and dropping a space discards its rows. If you
need to undo a schema change, restore from the backup taken in step 1 — which is
the reason step 1 is there.
