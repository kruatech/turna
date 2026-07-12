# Runbook — Tarantool backup, restart, and recovery

Applies when turna runs in cluster / persistence mode (`[state.persistence]`
with the Tarantool backend). Single-node turna without Tarantool has no external
state to back up — a restart simply loses active allocations and clients
re-Allocate (see docs/design/allocation-store-persistence.md).

## 0. Persistence is the operator's responsibility

The shipped `deploy/docker-compose.yml` runs turna standalone — it does NOT
include a Tarantool service. When you enable the Tarantool backend you deploy
Tarantool yourself, and you MUST give it a persistent data directory. Tarantool
stores snapshots (`*.snap`) and the write-ahead log (`*.xlog`) under its
`work_dir` (default `/var/lib/tarantool`, override `TURNA_WORK_DIR`).

- In Docker, mount a volume at `/var/lib/tarantool`. Without it, a container
  restart discards all snap/wal — the entire cluster allocation view is lost.
  (A throwaway test container with no volume is fine for testing; production is
  not.)
- Confirm: `docker inspect <tarantool> --format '{{json .Mounts}}'` shows a
  volume at `/var/lib/tarantool`.

## 1. What to back up

Everything under `work_dir` (`/var/lib/tarantool`): the latest `*.snap` plus all
`*.xlog` newer than that snapshot. Together they reconstruct full state on start.

## 2. Taking a backup (online)

Tarantool checkpoints are consistent and online — no downtime.

1. Trigger a fresh snapshot:
   `box.snapshot()` (via `tarantoolctl connect <sock>` or the admin console).
   This writes a new `*.snap` capturing current memtx state.
2. Copy `work_dir` — at least the newest `*.snap` and every `*.xlog` after it —
   to backup storage. `tar czf turna-tnt-$(date +%F).tgz -C /var/lib/tarantool .`
   is sufficient; snapshots are point-in-time consistent.
3. Rotate: keep enough history for your RPO. Old `*.xlog` before the retained
   snapshot can be pruned (Tarantool's own checkpoint GC also handles this).

Automate via cron: periodic `box.snapshot()` + copy. Frequency sets your RPO;
between snapshots the `*.xlog` still lets you recover to the last committed write.

## 3. Restore

1. Stop the Tarantool instance (`docker stop`, or the process).
2. Restore the backed-up `*.snap` + `*.xlog` into `work_dir`.
3. Start Tarantool. It replays the latest snapshot + subsequent xlogs and comes
   up with that state. No turna-side action is needed for the restore itself.
4. turna nodes reconnect automatically: `turna_backend_readiness` moves
   2 (degraded) → 1 (ready) once the pool reconnects (I6). Each node re-hydrates
   its own allocations on the next `bulk_load` / failover sweep.

## 4. Safe restart of Tarantool under a running cluster

turna tolerates a brief backend outage:

- While Tarantool is down, nodes go `degraded` (readiness 2) but keep serving
  from local state; cluster reads (failover, user management) pause.
- Alerts `TarantoolConnectionNotConnected` / `TurnaBackendDegraded` fire — this
  is expected during a planned restart.
- On reconnect, readiness returns to ready. No data loss for already-local
  allocations; only write-behind updates in flight at the moment of a crash can
  be lost (R6 — clients recover via TURN retransmit).

## 5. Schema / upgrade caveat (learned from the failover P1)

`deploy/tarantool/init.lua` creates spaces, indexes, and stored functions with
`if_not_exists = true`. On a restart against existing data, the function BODIES
are NOT refreshed. So when you upgrade turna with a changed `init.lua` (e.g. the
`return unpack` → `return res` fix), an existing Tarantool will keep the OLD
function bodies unless you explicitly drop and recreate them (or reload the
schema). Fresh installs are unaffected. See docs/failover/v0.3.0-rc.1.md
(Migration).

- Upgrade procedure: after deploying new `init.lua`, drop the affected functions
  and re-run schema init so the new bodies load, then verify with the
  `integration_list_functions_return_all_rows_not_truncated` test against the
  live instance.

## 6. What is NOT covered / accepted loss

- **Write-behind backlog on crash.** A node crash within ~100–500 ms of
  accepting an Allocate/Refresh can lose that not-yet-flushed write (R6). The
  affected client re-Allocates on retransmit. This is accepted, not a bug.
- **Point-in-time to the exact millisecond.** Backups restore to the last
  checkpoint + xlog; the newest un-flushed writes at crash time are not
  guaranteed.
- **Automated failover of Tarantool itself** (replication/HA) is out of scope
  here — this runbook covers single-instance backup/restore. For HA, use
  Tarantool replication and adapt §3–4 accordingly.
