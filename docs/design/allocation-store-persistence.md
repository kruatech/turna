# AllocationStore ↔ Tarantool: persistence and failover

**Status:** draft
**Date:** 2026-05-17
**Author:** turna-server team
**Track:** task #3 from the post-Block-C roadmap

---

## 1. Problem

Two state subsystems exist in the codebase and don't talk to each other:

- `turna_session::AllocationStore` — in-memory, `DashMap`-based, the source of truth on the hot path (called from `relay::processor` for every STUN/TURN message).
- `turna_state_backend::Backend` (`Memory` | `Tarantool`) — async, fully wired, but nothing on the data plane invokes it.

Concrete consequences:

1. **Restart loses all allocations.** When `turna-node` restarts, every active TURN session is gone. Clients have to re-Allocate from scratch.
2. **No failover.** If node N dies, node M cannot pick up N's sessions because it never sees them — even though `StoredAllocation::node_id` exists in the schema and `Backend::find_by_node()` is implemented.
3. **`Backend` is dead code in `services/node`.** It is created (or not) in `control-plane` only. The TURN data path runs entirely in RAM.

## 2. Goals and non-goals

### In scope

- Persist allocation lifecycle events (`Create`, `Refresh`, `Remove`, `AddPermission`, `AddChannel`) to `Backend` from the hot path.
- On startup, load this node's prior allocations from `Backend` back into `AllocationStore` (bulk-load).
- On peer node failure (detected via missing heartbeat), claim its allocations into the local store.
- Operate under realistic load: ~100k active allocations per node, ~333 Refresh/s steady-state.

### Out of scope (deferred)

- Sharing **live UDP sockets** across nodes (kernel-level — impossible without SO_REUSEPORT trickery and shared state on the same machine).
- Migration of in-flight RTP streams. Failover means the **client re-establishes the relay path** on the new node using the persisted allocation record; it does NOT mean the existing UDP stream survives.
- Multi-region replication, sharding, conflict resolution beyond simple node ownership.
- TLS / mTLS to Tarantool (separate ticket).
- Schema migrations / online upgrade story.

## 3. Current state — what the code actually looks like

### `AllocationStore` (sync API)

```rust
// crates/session/src/lib.rs
pub struct AllocationStore {
    allocations:       DashMap<SocketAddr, Allocation>,
    relay_to_client:   DashMap<SocketAddr, SocketAddr>,
    channel_to_client: DashMap<(u16, u16), SocketAddr>,
    user_allocations:  DashMap<String, Vec<SocketAddr>>,
    pub ports:         PortAllocator,
    max_allocations:   usize,
    pub quota:         BandwidthQuota,
}

impl AllocationStore {
    pub fn create(&self, client: SocketAddr, relay: SocketAddr,
                  username: String, key: Vec<u8>, lifetime: u32)
                  -> Result<(), SessionError>;
    pub fn refresh(&self, client: &SocketAddr, lifetime: u32) -> Result<(), SessionError>;
    pub fn remove(&self,  client: &SocketAddr, relay: SocketAddr) -> Result<(), SessionError>;
    pub fn add_permission(&self, client: &SocketAddr, peer_ip: IpAddr) -> Result<(), SessionError>;
    pub fn add_channel(&self, client: &SocketAddr, channel: u16, peer: SocketAddr) -> Result<(), SessionError>;
    pub fn cleanup_expired(&self) -> usize;
    // ... lookups, accessors ...
}
```

All methods are **sync** and are called directly from `crates/relay/src/processor.rs`, which is also fully sync. Example call site:

```rust
// crates/relay/src/processor.rs:395
if let Err(_) = self.store.create(src, relay_addr, username, key.clone(), lifetime) {
    self.store.ports.release(relay_port);
    return self.encode_error(msg, src, 508, "Insufficient Capacity");
}
```

### `Backend` (async API)

```rust
// crates/state-backend/src/lib.rs
impl Backend {
    pub async fn store_allocation(&self, alloc: &StoredAllocation) -> Result<()>;
    pub async fn remove_allocation(&self, relay_port: u16) -> Result<()>;
    pub async fn find_by_node(&self, node_id: &str) -> Result<Vec<StoredAllocation>>;
    pub async fn find_expired(&self, before_ms: u64) -> Result<Vec<StoredAllocation>>;
    pub async fn heartbeat(&self, hb: &NodeHeartbeat) -> Result<()>;
    pub async fn get_live_nodes(&self, max_age: Duration) -> Result<Vec<NodeHeartbeat>>;
    // ... rooms, bandwidth updates, ping ...
}
```

`StoredAllocation` already carries `node_id`, `relay_port` (primary key), `permissions: Vec<String>`, `channels: Vec<StoredChannel>`, and timing fields. **The schema is sufficient. We do not need to change it for this work.**

### The mismatch

- `AllocationStore` is sync. `Backend` is async. They cannot be merged via a single trait without breaking one side.
- `AllocationStore::create()` is on the data plane and is called at line rate. Any synchronous network I/O here is a non-starter.

## 4. Design — write-behind log with async writer task

### High-level shape

```
        ┌──────────────────────────────────────────┐
        │ relay::processor (sync, hot path)        │
        │                                          │
        │   store.create(...)  ─────┐              │
        │   store.refresh(...) ─────┤              │
        │   store.remove(...)  ─────┤              │
        │   store.add_perm(... ─────┤              │
        │   store.add_chan(... ─────┤              │
        └────────────────────────── │ ─────────────┘
                                    │
                  (1) update DashMap synchronously, return Ok
                  (2) push WriteOp event into unbounded mpsc
                                    │
                                    ▼
                          ┌─────────────────────┐
                          │ mpsc::UnboundedSender│
                          │ <WriteOp>            │
                          └──────────┬───────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────┐
        │ writer task (tokio, single)                │
        │                                            │
        │   loop:                                    │
        │     - drain up to N events  OR             │
        │       wait up to T_batch ms                │
        │     - coalesce by relay_port               │
        │     - flush as a batch to Backend          │
        │     - record metrics                       │
        │     - on Backend error: backoff + retry    │
        └─────────────────┬──────────────────────────┘
                          │
                          ▼
                  ┌───────────────┐
                  │   Backend     │  (Memory | Tarantool)
                  └───────────────┘
```

### Key decisions

#### D1. Sync API stays sync. New work goes through a channel.

`AllocationStore` keeps its existing signatures. We add a private `tx: Option<UnboundedSender<WriteOp>>` field. Every mutating method, after applying the change to `DashMap`, pushes a `WriteOp` to the channel.

```rust
pub enum WriteOp {
    Create   { stored: StoredAllocation },
    Refresh  { relay_port: u16, expires_at_ms: u64 },
    Remove   { relay_port: u16 },
    Permission { relay_port: u16, peer_ip: String, expires_at_ms: u64 },
    Channel  { relay_port: u16, number: u16, peer_addr: String, expires_at_ms: u64 },
}
```

If `tx` is `None`, the store works exactly as it does today (single-node, no persistence). This makes the change additive and the "without Tarantool" mode trivially the old behaviour.

#### D2. Write-behind, not write-through.

Hot path returns to the client before Tarantool has acknowledged the write. The window of potential loss is bounded by the batch interval (default `100ms`) plus the time it takes Tarantool to apply one batch.

**Trade-off accepted:** if the node crashes within ~100–500ms of accepting an Allocate, the failover node won't know about that allocation. The affected client will issue a new Allocate request on its next retransmit (TURN clients retransmit Allocate per RFC 8489 §6.3.1) and get a fresh port. This is the same observable behaviour they'd see today on any restart — we are not regressing.

**Why not write-through:** with 100k allocations and Refresh every 5 minutes, steady-state write rate is ~333 ops/s, with bursts. Write-through pins p99 of every TURN response to p99 of Tarantool. A Tarantool GC pause or WAL flush becomes a TURN latency spike. Write-behind decouples them.

**Why not hybrid (Create=through, rest=behind):** adds complexity for marginal benefit. The "important" event semantically is failover taking over a still-alive call, and for that case the lost write is the *most recent* one — making Create write-through doesn't help, because what matters is whether the *last* Refresh (or AddChannel) got through, and those are write-behind in this hybrid too. We prefer one consistent model.

The design will, however, **expose batch parameters in config** so the operator can tune toward write-through behaviour if profiling demands it:

```toml
[state.persistence]
mode             = "write_behind"   # "write_behind" | "disabled"
batch_max_size   = 256              # flush when this many ops queued
batch_max_delay_ms = 100            # OR when this much time elapsed
channel_capacity = 65536            # bounded queue; on full -> degraded mode
```

Setting `batch_max_size = 1, batch_max_delay_ms = 0` gets close to write-through (still async, but immediate).

#### D3. Channel is bounded, not unbounded.

Documented above as unbounded for the diagram's clarity, but the production choice is **bounded** with capacity 64k–128k events. Rationale: if Tarantool goes down for 10 minutes under full load, an unbounded channel will OOM the process. With a bounded channel, when full we enter **degraded mode**:

- log a `tarantool_writer_overloaded` warning,
- increment `tarantool_writes_dropped_total` metric,
- **silently drop further events for that window**.

Dropping is acceptable because the in-memory state is still correct — we are only losing the persistence layer's view, which is exactly what happens when Tarantool is down anyway. When the writer drains the queue and recovers, the operator can decide whether to trigger a full re-sync via a manual tool (see §7).

#### D4. Coalescing inside one batch.

Within one batch window, multiple ops for the same `relay_port` can be coalesced:

- `Create` + `Refresh` → single `Create` with the refreshed `expires_at_ms`.
- `Create` + `Remove` → drop both (the allocation existed for <100ms in DB-visible history).
- `Refresh` + `Refresh` → keep latest only.
- `Permission` for same `(relay_port, peer_ip)` → keep latest.

This drops the steady-state write rate roughly 2–3× under normal patterns.

#### D5. Writer task lifecycle.

- Spawned once from `services/node/src/main.rs` after `create_backend()`.
- Receives `Arc<Backend>` + the `Receiver<WriteOp>` end of the channel.
- Listens on `shutdown_rx` (already exists in `main.rs`). On shutdown:
  1. Stop accepting new events from `tx` (close the channel from sender side via `Drop` on `AllocationStore`).
  2. Drain the channel.
  3. Flush final batch.
  4. Exit.

This piggybacks on the graceful shutdown drain that already exists for gRPC (Block B).

#### D6. Cleanup of expired allocations.

`AllocationStore::cleanup_expired()` runs periodically already. When it removes an allocation, that triggers a `WriteOp::Remove` → eventually deleted from Tarantool. Good.

Independently, Tarantool can keep its own expiration sweep (`find_expired` → delete) as a backstop, in case the source node died without sending the Remove. This is the "garbage collection" path for crashed-node leftovers.

### Bulk-load on startup

```rust
// services/node/src/main.rs (pseudocode)
let backend = create_backend(&config.state).await?;
let store   = Arc::new(AllocationStore::new(...));

// Replay this node's allocations
let mine = backend.find_by_node(&node_id).await?;
let count = mine.len();
for stored in mine {
    store.rehydrate(stored)?;  // new method: insert without re-emitting WriteOp
}
info!(count, "rehydrated allocations from backend");

// Attach the writer
let (tx, rx) = mpsc::channel(config.state.persistence.channel_capacity);
store.attach_writer(tx);
tokio::spawn(run_writer_task(backend.clone(), rx, shutdown_rx.clone()));
```

`rehydrate()` is a new sync method that inserts a `StoredAllocation` into `DashMap` **without** going through `create()` (so no event is emitted, no port is re-allocated — the port is already taken because it's `StoredAllocation::relay_port`).

For 100k allocations at ~200 bytes each:
- Network: 20 MB to fetch from Tarantool (single `find_by_node` call, maybe paginated).
- Memory: ~20 MB resident.
- Time: estimated 1–3 seconds startup overhead.

This is acceptable for a TURN server restart. Clients tolerate this much.

### Failover — claim sessions of a dead node

A separate periodic task (every `10s`, configurable):

```rust
async fn failover_claim_task(backend: Arc<Backend>, store: Arc<AllocationStore>, my_node_id: String) {
    loop {
        sleep(10s).await;
        let live = backend.get_live_nodes(Duration::from_secs(30)).await?;
        let live_ids: HashSet<_> = live.iter().map(|n| n.node_id.clone()).collect();

        // Any allocation whose owner is NOT in live_ids is orphaned.
        // We could pull a list of all node_ids ever seen, or use a dedicated method.
        // For now: look for allocations with node_id not in live_ids AND not us.
        for orphan_node in known_nodes_not_in(&live_ids) {
            let orphans = backend.find_by_node(&orphan_node).await?;
            for mut alloc in orphans {
                // Atomic ownership transfer: CAS-like update.
                // If somebody else already claimed it, skip.
                if backend.claim_allocation(&alloc, &my_node_id).await.is_ok() {
                    alloc.node_id = my_node_id.clone();
                    store.rehydrate(alloc)?;
                }
            }
        }
    }
}
```

**This requires a new Backend method** `claim_allocation(&self, alloc: &StoredAllocation, new_node_id: &str) -> Result<()>` that performs a compare-and-swap: "set node_id to `new_node_id` only if it's currently `alloc.node_id`". In Tarantool this is a single Lua function on the server side.

**Failure semantics:**
- The client's existing UDP socket on the dead node is gone. Their next packet to the old relay address will hit nothing.
- The TURN client implementation will detect this (no response) and re-allocate. The new Allocate hits the new node — but **the username and credentials are recognised**, and instead of creating a brand-new allocation we can return the **existing** allocation (now owned by us) at a **new** relay address.
- **Caveat:** the relay port changes. Existing peers learn the new address through the new Allocate response. This is not zero-downtime — there's a 1–10s reconnect gap. For UDP voice this is one or two glitches. Acceptable for v1 of failover.

**True zero-gap failover** (same relay port reachable on another physical machine) requires anycast or floating IPs at the infra layer, and is explicitly out of scope here.

### Heartbeat task

Independent of the writer:

```rust
async fn heartbeat_task(backend: Arc<Backend>, my_node: NodeIdentity, metrics: Arc<Metrics>) {
    loop {
        sleep(5s).await;
        let hb = NodeHeartbeat {
            node_id: my_node.id.clone(),
            addr:    my_node.addr.to_string(),
            active_allocations: metrics.active_allocations.load(Relaxed),
            // ... cpu, mem, uptime, draining ...
            last_seen_ms: now_ms(),
            draining: shutdown_in_progress.load(),
        };
        if let Err(e) = backend.heartbeat(&hb).await {
            warn!(?e, "heartbeat failed");
        }
    }
}
```

This already aligns with the existing `Backend::heartbeat()` API; we're just calling it from the right place.

## 5. Failure modes and what we do about each

| Failure | Behaviour |
|---|---|
| Tarantool down at startup | Node refuses to start if `state.type = "tarantool"`. Operator can switch to `memory` for emergency standalone. |
| Tarantool goes down mid-flight | Writer task retries with the existing backoff (Block A). Channel fills. When channel is full, we drop events and metrics show it. In-memory state remains correct. |
| Tarantool comes back after long outage | Writer drains. Any events dropped during outage are permanently lost; on next normal cleanup pass, in-memory state is the source of truth. |
| Hot-path crash mid-batch | Up to `batch_max_delay_ms + flush_duration` of events lost. Failover node sees state from before the loss. |
| Two nodes try to claim the same allocation | CAS in `claim_allocation` means exactly one wins. The loser observes `Conflict` and moves on. |
| Clock skew between nodes | Heartbeat `max_age` is 30s by default, much larger than realistic NTP skew. Not a concern in practice. |
| Slow Tarantool (high p99) | Writer falls behind, channel grows. If it hits `channel_capacity` we degrade. Operator alerts on `tarantool_writer_queue_depth > 50% capacity`. |

## 6. Metrics to add

All `turna_health::Metrics` style (AtomicU64, Prometheus endpoint):

- `tarantool_writer_queue_depth` — current channel depth, gauge.
- `tarantool_writer_batches_total` — counter.
- `tarantool_writer_ops_total{op="create|refresh|remove|permission|channel"}` — counter.
- `tarantool_writer_batch_duration_seconds` — histogram (reuses Block A histogram infra).
- `tarantool_writes_dropped_total` — counter, alarms above 0.
- `tarantool_writer_coalesced_total` — counter (how many events got merged).
- `failover_claims_total{result="success|conflict|error"}` — counter.
- `rehydrated_allocations_total` — counter, observed at startup.

## 7. Operator runbook (sketch)

To be expanded in `docs/README.md` under task #6, but the rough shape:

```bash
# Check writer health
curl :9090/metrics | grep tarantool_writer

# Force re-sync of in-memory store from Tarantool (rare; e.g., after dropped writes)
turnactl state resync

# Inspect orphan allocations (no live owner node)
turnactl state orphans

# Force-claim orphan allocations for the current node
turnactl state claim --node-id <dead-node>

# Emergency: disable persistence on a running node (sets writer to no-op)
turnactl state set-mode disabled
```

The `turnactl` tool already exists in `tools/turnactl`; these subcommands are part of this work.

## 8. Plan — split into PRs

Each PR should land independently, be reviewable in <2 hours, and not break `cargo test`.

### PR 1: scaffolding — `WriteOp` channel, no-op writer

Goal: introduce the plumbing without changing behaviour.

- Add `WriteOp` enum to `crates/session/src/lib.rs`.
- Add `tx: Option<UnboundedSender<WriteOp>>` field to `AllocationStore`.
- Add `attach_writer(&mut self, tx)` and emit events from `create`, `refresh`, `remove`, `add_permission`, `add_channel`.
- Add a writer task that **drains and discards** events (no Backend yet).
- Wire it up in `services/node/src/main.rs` but only when a new `state.persistence.mode = "scaffold"` is set, default off.
- Tests: events are emitted exactly once per mutation; channel drop doesn't panic.

**Risk:** very low. Code paths exist but are gated.

### PR 2: writer task talks to `Backend`

- Implement `run_writer_task(backend, rx, shutdown_rx)`.
- Implement batching (size + time), coalescing per `relay_port`.
- Add metrics from §6.
- Implement bounded channel; on full, log+drop.
- Tests: with a fake `Backend` that records calls, verify N events → 1 batch; coalescing of Create+Remove → no-op.

**Risk:** medium. The batching+coalescing logic deserves unit tests on its own.

### PR 3: bulk-load on startup, `rehydrate()` method

- Add `AllocationStore::rehydrate(&self, StoredAllocation) -> Result<(), SessionError>`.
- In `services/node/src/main.rs`, after creating Backend, call `find_by_node(my_node_id)` and rehydrate each.
- Make `node_id` come from config / env (`TURNA_NODE_ID`, with a sane default like hostname).
- Tests: round-trip — create allocs, drop store, re-create from Backend, verify state matches.

**Risk:** medium. The `rehydrate` path must not double-allocate ports, must not emit events, must respect `max_allocations`.

### PR 4: heartbeat task

- Spawn `heartbeat_task` from `main.rs`.
- Wire `metrics.active_allocations` and other gauges into `NodeHeartbeat`.
- Tests: integration test with `Backend::Memory` (sufficient — `heartbeat` and `get_live_nodes` are implemented there too).

**Risk:** low. Self-contained.

### PR 5: failover claim

- Add `Backend::claim_allocation(&alloc, new_node_id)` with CAS semantics, for both `Memory` and `Tarantool` backends.
- Add `failover_claim_task`.
- Document the relay-port-change caveat in the runbook.
- Tests: simulate dead node — spawn two stores against shared Memory backend, kill heartbeat from store A, verify store B claims A's allocations.

**Risk:** medium-high. CAS semantics in Tarantool need to be correct (Lua function on server side).

### PR 6: config, turnactl, docs

- Flesh out `[state.persistence]` config section in `deploy/turn.toml` + `crates/config/src/lib.rs`.
- Add `turnactl state` subcommands.
- Update `docs/README.md` (overlaps with task #6).

**Risk:** low.

## 9. Open questions

1. **Node identity.** Where does `node_id` come from? Options: hostname, configured string, UUID file on disk persisted across restarts. I lean toward "configured string with hostname default" — explicit and stable.

2. **Memory backend semantics for `get_live_nodes`.** Today's `InMemoryBackend` returns whatever's been written. In single-process tests of failover, that's fine. In production with `Backend::Memory`, there are no other nodes — failover is a no-op. Document this.

3. **What about `cleanup_expired` racing with the writer?** Cleanup currently runs in `AllocationStore::cleanup_expired`, called from `processor`? — need to check. If it removes an allocation that's still in the writer's queue as `Create`, coalescing handles it. Safe.

4. **`StoredAllocation::key` field is missing.** The TURN long-term credential key (HMAC secret) is in `Allocation::key: Vec<u8>` in memory but is **not** in `StoredAllocation`. After failover, the new node won't have this — it would need to recompute from username+realm+password, but the password isn't in the store either. **This means failover only works if `AuthMode::Static` is used** (passwords are in config, readable by all nodes) **or if there's a shared auth backend.** With ephemeral credentials this needs more thought. Flag for later.

5. **Should `WriteOp::Create` be sent before or after the DashMap insert succeeds?** After, definitely. Otherwise a failed `create` (e.g., MaxAllocations) would still hit Tarantool. Current plan: insert first, emit on success.

## 10. Acceptance

This work is "done" when:

- A node restart restores all active allocations within 3 seconds of process start.
- Killing a node's process (SIGKILL, not graceful) causes a peer node to claim its allocations within ~15 seconds.
- Under load (1000 concurrent clients, 60s, the existing `turna-load-test`), p99 Allocate latency does not regress more than 5% vs. memory-only mode.
- All metrics in §6 are visible on `/metrics`.
- `cargo test -p turna-session -p turna-state-backend -p turna-relay` passes.
- The fuzz suite still runs clean for 1 hour.

---

**Next action after sign-off:** start PR 1.
