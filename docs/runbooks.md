# Turna — Operational Runbooks (§23)

Incident procedures for operators. Each runbook is **symptom → diagnosis → remediation**.

Scope note: this document describes only mechanisms that exist in the codebase.
Anything an operator must decide (thresholds, target numbers, alert routing) is
marked `TODO(operator)` rather than guessed. Port/endpoint defaults below reflect
`deploy/turn.toml` and the Helm values; confirm against your own config.

## Reference: ports & endpoints (defaults)

- TURN/STUN listener: `3478` (UDP/TCP), TLS `5349` (TCP)
- Health / metrics: `9090` — `/health` (liveness), `/ready` (readiness), `/metrics` (Prometheus)
- gRPC management (control-plane): `5350`
- Gossip (cluster mode): `7946` (UDP)
- Relay UDP range: `49152–65535` (must match across `turn.toml`, docker-compose, Helm — see RB-5)

## Reference: readiness states

The node reports one of three readiness states on `/ready`:

- **Ready** — serving; `/ready` returns 200.
- **Draining** — lame-duck; `/ready` returns 503 so load balancers stop sending
  new allocations while existing ones wind down. Terminal for the node's lifetime
  once entered via drain/shutdown.
- **Degraded** — in cluster mode, persistence write-behind events were dropped, so
  in-memory state has diverged from the backend; `/ready` returns 503 so a
  failover controller stops trusting this node. Recovers to Ready only after a
  successful reconciliation pass (see RB-1).

---

## RB-1 — Node stuck / flapping Degraded (persistence write-drops)

**Symptoms**
- `/ready` returns 503 with the node otherwise serving traffic.
- Prometheus `tarantool_writes_dropped_total` is increasing.
- Logs: `writer channel full — WriteOp dropped`, and reconcile lines
  (`reconcile pass while drops active`, `reconcile complete — returning to Ready`).

**What it means**
The write-behind channel to the state backend (Tarantool) filled up, so allocation
events were dropped. In-memory state is still authoritative and correct for live
traffic, but the backend has diverged (missing `Create`/`Refresh`, or a `Remove`
that never landed). The node self-heals: on drops it goes Degraded and runs
reconciliation; it returns to Ready only once a reconcile pass completes cleanly.

**Diagnosis**
1. Confirm the drop counter is rising: scrape `/metrics`, watch `tarantool_writes_dropped_total`.
2. Check backend health — is Tarantool slow or unreachable? (see RB-3). Sustained
   drops almost always mean the backend can't keep up with the write rate.
3. Check the reconcile logs: if you see `reconcile complete — returning to Ready`
   the node recovered; if you see repeated `reconcile failed — staying Degraded`,
   the backend is still unhealthy.

**Remediation**
1. If the backend is the bottleneck, address that first (RB-3). Reconciliation
   cannot complete while the backend is unreachable.
2. A single burst that has since stopped is self-healing — the node reconciles and
   returns to Ready after the first fully successful reconcile pass. Actual time
   depends on the monitor interval, the number of live/backend allocations, and
   backend latency — it is not a fixed value. No action needed beyond confirming
   recovery.
3. If drops are sustained under normal load, the write-behind channel is
   undersized for the offered rate. Increase `persistence.channel_capacity` (and/or
   `batch_max_size`) in config and roll the node. `TODO(operator)`: size against
   your measured peak allocation churn.
4. Do **not** force the node back to Ready manually — Degraded is protecting the
   cluster from adopting divergent state on failover.

**Why it self-heals (context)**
Reconciliation deletes backend rows for this node that are no longer live (zombies
from a dropped `Remove`) and re-emits the full live allocation set (repairing
dropped `Create`/`Refresh`). It only clears Degraded when that pass succeeds.

---

## RB-2 — Drain a node for maintenance (and undrain)

**Goal** Take a node out of rotation for maintenance while *minimizing* impact.
Drain stops new allocations and lets existing ones wind down; it does **not**
guarantee zero dropped sessions if the node is stopped before its active
allocations end. For a hard no-drop guarantee, wait for the active-allocation
count to reach zero, or rely on proven active-session failover (not yet — see #15).

**Procedure**
1. Drain via the management API (routes a command to the specific node through the
   command log): `node.drain` with the target `node_id`.
2. Verify: the node's `/ready` returns 503 (Draining); load balancers stop sending
   new allocations. Existing allocations continue until they expire or the node is
   stopped.
3. Watch active allocations drain down (via `/metrics` or `top_talkers`) before
   stopping the process.
4. To return the node to service: `node.undrain` with the target `node_id`. `/ready`
   returns 200 again.

**Notes**
- Draining targets **one node** — the command carries a `node_id`. A drain request
  with an empty/unknown node id is refused (honest error), not silently applied.
- Draining is applied by the node itself (sets readiness + begins routing drain);
  the control-plane waits for the node to confirm before reporting success.
- `undrain` best-effort reverses readiness; in-flight routing lame-duck may not be
  fully reversible mid-drain — prefer undrain only if the node has not yet been
  stopped.

---

## RB-3 — State backend (Tarantool) slow or unreachable

**Symptoms**
- RB-1 Degraded flapping; `tarantool_writes_dropped_total` climbing.
- Backend operation timeouts in logs (per-operation deadline is enforced, ~5s).
- Failover / user-refresh loops logging backend errors.

**What it means**
Every backend operation has a hard per-operation deadline; a hung connection
returns a timeout rather than blocking forever, and the connection slot is poisoned
and reconnected. The data plane never blocks on the backend — in-memory state stays
authoritative — but persistence and cross-node features (failover adoption, user
refresh) degrade.

**Diagnosis**
1. Check Tarantool health directly (its own monitoring / `tt` console).
2. Confirm network path node → Tarantool `3301` (or configured URI).
3. Check whether it is a capacity problem (write rate > backend throughput → RB-1
   channel-capacity tuning) or an availability problem (backend down/unreachable).

**Remediation**
1. **Backend down**: the nodes keep serving live traffic from memory. Restore the
   backend; nodes reconcile automatically once it is reachable (RB-1). Do not
   restart nodes to "fix" this — that would lose the in-memory state that the
   backend is missing.
2. **Backend slow**: scale/tune Tarantool, or reduce write pressure
   (`batch_max_delay` / `batch_max_size`). `TODO(operator)`: capacity target.
3. **Auth/connection errors after a rotation**: verify `backend.user` /
   `backend.password` (or the Tarantool role/password provisioned by
   `deploy/tarantool/init.lua`) match the node config.

---

## RB-4 — Force-remove a stuck allocation

**Goal** Delete a specific allocation cluster-wide (e.g. abuse, stuck relay port).

**Procedure**
1. Use the management API to delete the allocation by id.
2. The control-plane resolves the **owning node** from the backend record, routes a
   delete command to that node, and **waits for confirmation** (bounded ~10s). It
   does not report success unless the owning node actually removed it.

**Failure modes & what they mean**
- `NotFound` — no such allocation in the backend (already gone, or wrong id).
- `Unimplemented` / "requires a shared state backend" — cluster persistence is not
  enabled, so there is no routing target. In single-node deployments, operate on
  that node directly.
- Timeout ("node unreachable or not polling") — the owning node did not apply the
  command in time. Check that node's health (RB-1/RB-3) and the command-log poll
  loop; the command remains durable and will be retried when the node recovers.

---

## RB-5 — Relay traffic dropped despite successful allocations

**Symptoms**
- Clients allocate successfully, but relayed media/data does not flow.
- In the load generator (`channeldata` mode), `loss` is high while `errs` is ~0.

**What it means**
The published relay UDP port range does not match the range the server actually
allocates from. Allocations land on ports that are not published/forwarded, so the
relay path is black-holed.

**Diagnosis**
1. Compare the relay range in all three places: `deploy/turn.toml` `[turn.relay]
   min_port/max_port`, the docker-compose published `…/udp` range, and Helm
   `relayPortRange`.
2. The CI gate `deploy-consistency` (`scripts/check-deploy-consistency.sh`) is meant
   to catch this before deploy — check whether it was bypassed.

**Remediation**
1. Make all three ranges identical and redeploy. `turn.toml` is the source of truth.
2. On Kubernetes with `hostNetwork`, ensure the full UDP relay range is reachable to
   the pod's host and not blocked by NetworkPolicy/firewall.

---

## RB-6 — Shutdown / rolling restart (persistence not lost)

**Goal** Stop or roll a node without cutting off the persistence flush.

**What happens on SIGTERM**
The node begins lame-duck drain, then shuts down. On shutdown it joins the
write-behind writer within a bounded budget and does **not** cancel the final
flush prematurely. This is not a guarantee the writes land: if the backend is
unreachable or slow, the flush can still fail or time out within the budget —
the outcome is recorded in logs/metrics/exit policy. Mandatory background tasks
are joined within their own budget.

**Procedure**
1. Ensure the orchestrator's `terminationGracePeriodSeconds` is **≥ the node's
   shutdown budget** (lame-duck drain grace + persistence flush budget + margin).
   The node logs its computed budget at startup — size the grace period from that.
2. Prefer draining first (RB-2) to minimize impact, then SIGTERM. Note: this is
   low-impact, not zero-impact — sessions still live when the node stops are cut.
3. Do not shut a node down from the control-plane expecting it to gracefully stop a
   *different* node's process — node lifecycle is driven by the orchestrator
   (SIGTERM) or a routed shutdown command; the control-plane will refuse an
   unrouted shutdown rather than act on the wrong process.

---

## RB-7 — TLS / mTLS on the management plane

**Symptoms**
- gRPC management clients fail to connect, or connect without the expected client-
  auth enforcement.

**What it means**
The management gRPC server runs in one of: plaintext, TLS (server cert only), or
mTLS (server cert + required client CA). Client-certificate verification is only
enforced in **mTLS** mode; in plain TLS mode client certs are not required.

**Diagnosis / remediation**
1. Confirm the intended mode in config (`mode = "mtls"` requires a client CA).
2. In mTLS, verify the client presents a cert signed by the configured client CA;
   a missing/for-wrong-CA client cert is rejected by design.
3. If clients connect but you expected mutual auth, the server is likely in plain
   TLS mode — set mTLS and provide the client CA root.

---

## RB-8 — Backup & restore drill (durable backend)

**Goal** Prove the state backend can be backed up and restored, and that a
restored node comes up consistent. A backup is not considered verified until a
restore drill has succeeded. Applies only to persistent/cluster deployments.

**Backup — verify**
1. Backup creation runs and completes; the artifact is consistent (point-in-time).
2. Backup is encrypted and stored separately from the primary backend.
3. Retention and monitoring exist; a failed backup alerts.

**Restore — drill in an isolated environment**
1. Deploy a clean Tarantool instance.
2. Restore the backup.
3. Verify schema version matches the expected `init.lua` schema.
4. Verify runtime users are present.
5. Verify the **command-log** space restored (P0 #4 durable commands live here —
   it must be backed up and restored alongside allocations, or in-flight control
   operations are lost).
6. Verify allocation rows.
7. Reconcile command state: **already-confirmed** (done/failed) commands are inert;
   **unfinished** (pending/in_progress) commands should be dropped or re-driven on
   startup rather than silently re-applied to a now-different cluster state. Decide
   and document which — do not let a stale in_progress command re-execute blindly.
8. Purge stale allocations and ownership rows that no longer correspond to live
   nodes (otherwise a fresh cluster adopts zombies — same class as RB-1).
9. **Tenant-scoped consistency**: confirm restored allocations/users/secrets stay
   within their tenant/realm boundaries — a restore must not blur tenant isolation.
10. Start a node; perform authentication; perform a fresh `Allocate`.
11. Record RPO and RTO from the drill.

`TODO(operator)`: record the environment, backup tool, RPO/RTO, and the chosen
policy for unfinished commands.

---

## Escalation & ownership

`TODO(operator)`: fill in on-call rotation, paging thresholds (e.g. "Degraded > N
minutes pages"), and dashboards. The mechanisms above expose the signals
(`/ready`, `tarantool_writes_dropped_total`, reconcile log lines, active-allocation
count); alerting policy on top of them is a deployment decision.

## RB-Management — desired/observed mismatch or failed runtime apply

**Symptoms:** `turna_config_desired_observed_mismatch` is non-zero,
`turna_config_oldest_unapplied_ms` grows, the management read API reports
`desired`/`applying`/`failed`, or observed version does not advance.

**Diagnosis:** read node-scoped config state; correlate request ID,
idempotency key, expected version, node incarnation, terminal status, and audit
entry. Confirm the target heartbeat incarnation matches the command. Inspect
Tarantool availability and the command-log migration/error counters. Do not
re-submit a different payload under the same idempotency key.

**Remediation:** for a lost response, retry the identical request/key. For a
version conflict, reload observed state and create a new intent/key with the new
expected version. For backend failure, restore backend health; restart only after
confirming the last observed state is valid. The node restores confirmed observed
state before readiness and must not be forced into unlimited bootstrap defaults.
