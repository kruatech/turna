# Turna — Operations & Deployment Overview (§29)

Operator-facing overview of what Turna is made of, how it is deployed, and the
safety mechanisms that govern its runtime behaviour. This document only describes
mechanisms present in the codebase; tunables an operator must choose are marked
`TODO(operator)`. See also: [Runbooks](./runbooks.md) and
[SLO & Capacity](./slo-and-capacity.md).

## 1. Components

- **Node** (`turna-node`) — the TURN/STUN data plane. Owns the authoritative
  in-memory allocation state and relays traffic. Everything on the hot path is
  served from memory; the node never blocks on the backend.
- **Control-plane** (`turna-control`) — management gRPC API for cluster operations
  (list/delete allocations, drain/undrain, user management, stats). It does not sit
  on the data path; it acts on nodes by routing durable commands (see §4).
- **State backend** (Tarantool, or in-memory) — shared persistence for allocations,
  users, heartbeats, and the control→node command log. In-memory is single-node
  only; a shared backend is required for cluster mode and persistence.
- **Admin / CLI clients** — talk to the control-plane over gRPC.

## 2. Deployment modes

### Single-node
- This is the canonical GA topology: one TURN node owns one public IP and relay
  range; gossip and transparent active-session failover are disabled.
- An in-memory backend is acceptable only for an explicitly ephemeral node. It
  does not preserve runtime config, user limits, users, or command outcomes
  across process restarts.
- A persistent standalone deployment attaches the same Tarantool management
  backend to the control plane and node while keeping `cluster_mode = false`.
  Node-targeted mutations, idempotent replay, desired/observed state, command
  GC and startup restore then use the durable backend without enabling the
  experimental multi-node dataplane.
- The management plane is enabled by a durable (Tarantool) backend independently
  of allocation write-behind: with persistence disabled the node still runs the
  command log, restore, migration, command worker, and the incarnation heartbeat
  used for command targeting, but does **not** rehydrate old allocations or start
  the allocation writer — those run only under an allocation-persistence profile,
  and adoption/failover only under the cluster profile.
- Operations that require durable routing fail closed when no shared backend is
  attached; they never report local or fabricated success.

### Cluster (production)
- Requires a shared state backend (Tarantool) with persistence enabled.
- Gossip membership on `7946/udp`; allocations persisted via write-behind; failover
  adoption and reconciliation active.
- Readiness gates (`Draining`, `Degraded`) protect peers from routing to a node
  that is leaving or has diverged from the backend.

Config validation is strict and fails fast: an unknown `backend.type`, cluster mode
on an in-memory backend, or write-behind persistence on an in-memory backend are
rejected at startup rather than silently downgraded. Environment overrides are
folded into the effective config **before** validation, so production guards cannot
be bypassed via env vars.

## 3. Ports & endpoints (defaults)

- TURN/STUN `3478` (UDP/TCP), TLS `5349` (TCP)
- Health/metrics `9090`: `/health` (liveness), `/ready` (readiness), `/metrics`
- Management gRPC `5350`
- Gossip `7946/udp` (cluster)
- Relay UDP range `49152–65535` — **must match** across `deploy/turn.toml`,
  docker-compose, and Helm; enforced by the `deploy-consistency` CI gate
  (`scripts/check-deploy-consistency.sh`). See runbook RB-5.

## 4. Runtime safety mechanisms (what governs behaviour)

These are the properties operators most need to understand; each has a
corresponding runbook.

- **Readiness state machine** — `Ready` / `Draining` / `Degraded`. `/ready` returns
  503 for the latter two so load balancers and failover controllers react
  correctly. (RB-1, RB-2)
- **Write-behind + reconciliation** — allocation changes are persisted
  asynchronously. If the write-behind channel overflows, events are dropped and the
  node goes `Degraded`; it reconciles (deletes backend zombies, re-emits live
  state) and returns to `Ready` only when the backend is consistent again. The drop
  counter is `tarantool_writes_dropped_total`. (RB-1, RB-3)
- **Bounded backend operations** — every backend call has a per-operation deadline;
  a hung backend returns a timeout and the connection is recycled, so the data
  plane never stalls on persistence. (RB-3)
- **Command log (control→node)** — the control-plane enqueues durable, node-targeted
  commands (delete allocation, drain/undrain, shutdown, runtime config, and user
  limits); the owning node claims and
  applies them and reports completion. The control-plane waits for confirmation and
  never reports fictitious success. (RB-2, RB-4, RB-6)
- **Graceful shutdown budget** — on SIGTERM the node drains, then joins the
  persistence writer and mandatory tasks within a bounded budget so the final flush
  is not cut off. Size `terminationGracePeriodSeconds` ≥ the logged budget. (RB-6)
- **Task supervision** — mandatory background tasks are supervised; an unexpected
  exit flips the node to `Degraded` and initiates shutdown rather than silently
  losing a subsystem.
- **Management TLS/mTLS** — plaintext, TLS, or mTLS; client-certificate
  verification is enforced only in mTLS mode. (RB-7)

## 5. Configuration surface (where to look)

- `deploy/turn.toml` — server config: `[turn]`, `[turn.relay]` (port range),
  `[turn.relay.quota]` (bandwidth/allocation limits), `[cluster]`,
  `[cluster.backend]`, `[cluster.persistence]`, TLS.
- Helm: `deploy/helm/turna/values.yaml` and `values-production.example.yaml`
  (relay range, quotas, `allowUnlimitedBandwidth`, replica/anti-affinity).
- Tarantool schema/roles: `deploy/tarantool/init.lua` (spaces, stored functions,
  grants — including the command-log space/functions).

`TODO(operator)`: pin the effective values for your environment (per-node
allocation cap vs relay-port ceiling — see SLO doc §1 — write-behind channel size,
quotas) and keep Helm, `turn.toml`, and the docs in agreement.

## 6. Day-2 operations

- Drain/undrain for maintenance and rolling restarts → RB-2, RB-6.
- Backend incidents → RB-3.
- Capacity & SLOs → [SLO & Capacity](./slo-and-capacity.md); establish the baseline
  with the load generator in steady state (`--warmup` then `--duration`).
- Deploy-time consistency (relay range, Helm render) is gated in CI
  (`deploy-consistency`, `helm-validate`).

`TODO(operator)`: on-call rotation, dashboards, and alert thresholds (the mechanisms
above expose the signals; the alerting policy is a deployment decision).

## Management command lifecycle

1. The control plane validates target, idempotency key, optional patch, and the
   available static constraints.
2. It resolves the target node's current process incarnation from heartbeat and
   appends a typed JSON command to the durable log.
3. Atomic claim filters by both node ID and incarnation; lease/claim-token
   fencing protects completion.
4. The node serializes runtime applies, checks expected version, prepares
   desired state, atomically publishes its immutable snapshot/cache, and
   confirms observed state or rolls the local publication back.
5. The control plane decodes the durable terminal result. Conflict and no-op are
   terminal business outcomes, not transient backend failures.
6. Durable idempotency records outlive command-row GC, so a retry after response
   loss or GC returns the original outcome.

Before readiness, a persistent node adopts its new process incarnation and
restores only confirmed observed runtime/limits state. Interrupted desired state
is retained as failed/mismatched for diagnosis rather than silently published.

## Startup sequence

A node reaches readiness only after the mandatory restore steps for its profile:

1. Parse config.
2. Production validation (environment overrides are folded in **before**
   validation, so guards cannot be bypassed via env vars).
3. Initialize identity / process incarnation.
4. Create and bind transport listeners.
5. Connect the management backend (if the management profile is enabled).
6. Restore the confirmed observed runtime configuration.
7. Restore the confirmed observed user limits.
8. Restore allocations only under an allocation-persistence profile.
9. Start the command worker.
10. Start the bounded, resumable schema migration as a **background** task.
11. Start the allocation writer only under an allocation-persistence profile;
    start ownership adoption / failover and gossip only under the cluster profile
    (`cluster_mode`), never merely because persistence is enabled.
12. Set readiness (`Ready`).

Dataplane readiness is not signalled before the mandatory restore steps (6–8)
complete. A persistent node adopts its new incarnation and restores only
confirmed observed state; interrupted desired state is retained as
failed/mismatched for diagnosis rather than silently published. The command-log
migration runs in the background and does **not** gate the TURN dataplane
readiness: a node serves and accepts management commands while an in-progress
migration continues (legacy rows are handled leniently until upgraded). It is
instead surfaced on a distinct management-plane readiness sub-signal
(`turna_management_readiness`), which reaches `ready` only once the mandatory
migration phases complete — so the dataplane and management contours are never
conflated under one flag.

### Profile worker matrix

Which optional workers a node runs is a pure function of its profile
(`profile_gates`), so the tiers never leak into one another:

| Profile                          | Mgmt plane | Alloc rehydrate + writer | Ownership adoption / failover | Gossip |
| -------------------------------- | :--------: | :----------------------: | :---------------------------: | :----: |
| Standalone, no durable backend   |     no     |            no            |              no               |   no   |
| Management-only (durable backend)|    yes     |            no            |              no               |   no   |
| Management + persistence         |    yes     |           yes            |              no               |   no   |
| Cluster + persistence            |    yes     |           yes            |             yes               |  yes   |

The management plane is enabled by any durable (Tarantool) backend; allocation
rehydrate + write-behind by an allocation-persistence profile; ownership
adoption / failover and gossip **only** by `cluster_mode`. Failover is never
inferred from persistence being on — a standalone or management-only persistent
node must not adopt peers' allocations.

Readiness has matching tiers: the **dataplane** signal depends on listener bind
and the mandatory startup restore; the **management** signal
(`turna_management_readiness`) additionally depends on backend connect, restore,
the command worker, incarnation publication, and the mandatory migration phases;
**cluster** concerns (membership, ownership/failover) apply only to a cluster
node and never make a standalone node wait on a cluster worker.

## Failure matrix

| Failure                                          | Behaviour                                                        |
| ------------------------------------------------ | --------------------------------------------------------------- |
| Control-plane unavailable                        | Dataplane keeps serving existing allocations                    |
| Tarantool unavailable at startup (mgmt profile)  | Node does not become `Ready` (fail-closed)                      |
| Command completion lost                          | Outcome recovered from durable operation metadata               |
| Version (expected-version) conflict              | Terminal business `conflict` in an `OK` transport response      |
| Observed confirmation failed                     | Local publication rolled back; `failed` + `rolled_back`         |
| Allocation writer overflow/failure               | Per persistence profile: `Degraded` + reconcile, then `Ready`   |
| Gossip stopped (cluster)                         | Task supervision flips the node to `Degraded`/shutdown          |
| Admin unavailable                                | TURN dataplane is unaffected (admin is off the hot path)        |
