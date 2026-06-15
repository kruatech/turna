# Cluster mode

Single-node `turna-node` is enough for many self-hosted deployments — one
beefy server can handle thousands of concurrent allocations. You need
cluster mode when **any** of these is true:

- You want **failover**: if one node dies, surviving nodes pick up its
  allocations after the configured failure-detection window, roughly 5 seconds
  with current defaults (`live_window_secs=3`, `suspicion_ticks=2`,
  `sweep_interval_secs=1`).
- You want **rolling upgrades** without dropping calls: drain one node,
  re-deploy, repeat.
- You're scaling beyond what one box can carry (~100k concurrent
  allocations on commodity hardware).

## How it works (1-minute version)

```
┌─────────┐       ┌─────────┐       ┌─────────┐
│ turna-1   │       │ turna-2   │       │ turna-3   │
│ (live)  │       │ (live)  │       │  XX     │  ← node 3 just died
└────┬────┘       └────┬────┘       └─────────┘
     │ writes           │ writes
     │ heartbeats       │ heartbeats
     ▼                  ▼
   ┌──────────────────────┐
   │      Tarantool       │  ← single source of cluster truth
   │   turna_allocations    │
   │   turna_nodes          │
   └──────────────────────┘
```

Each `turna-node` writes its allocation state to Tarantool (write-behind,
non-blocking) and publishes heartbeats. Current config defaults publish a
heartbeat every 1 second, consider a peer stale after 3 seconds, sweep every 1
second, and require 2 consecutive stale sweeps before claiming. The first
surviving node to win a CAS on a record takes ownership and rehydrates it
locally.

Detailed design is in `docs/design/allocation-store-persistence.md`.



## Redirect-based horizontal scaling without an external LB

`cluster_mode = true` enables the lightweight gossip + TURN redirect path for
new clients:

1. Every node announces itself **and its known-peer table** over UDP gossip
   (anti-entropy), so nodes learn peers transitively even with incomplete seed
   lists. Liveness is driven by a per-node `seq`: a live node's sequence keeps
   advancing and propagates, refreshing `last_seen` cluster-wide; a dead node's
   `seq` freezes everywhere and ages out after `gossip_timeout_secs`.
2. Each node builds the same `HashRing` from live nodes. A **clean shutdown
   broadcasts a `leaving` message** so peers drop the node immediately (like a
   NATS route close); a node that *crashes* is removed after
   `gossip_timeout_secs` once its `seq` stops advancing.
3. For a STUN request from a client without a local allocation, the processor
   hashes `client_ip:client_port` and picks the owner via **rendezvous (HRW)
   hashing** — `argmax over nodes of xxh64(node_id || key)`. HRW remaps only
   ~1/N of keys when a node joins/leaves, regardless of the node's id, so adding
   a node never reshuffles unrelated clients.
4. If the selected node is remote, the local node returns STUN/TURN error
   `300 Try Alternate` with `ALTERNATE-SERVER` (plain MAPPED-ADDRESS format,
   RFC 5389 §15.5) pointing at the selected node.
5. Clients with an existing local allocation are never redirected, even if the
   ring changes.

Minimal two-node example:

```toml
[cluster]
node_id = "node-a"
cluster_mode = true
cluster_name = "prod"                 # nodes only merge with the same name
gossip_bind = "0.0.0.0:7946"
gossip_seeds = ["10.0.0.12:7946"]
gossip_advertise_addr = "10.0.0.11:7946"  # set behind NAT/k8s; else inferred
gossip_interval_secs = 2
gossip_timeout_secs = 30
turn_announce_addr = "10.0.0.11:3478"
cluster_secret = "change-me-shared-across-nodes"  # HMAC auth for gossip
drain_grace_secs = 5                  # lame-duck window on shutdown

[cluster.failure_detection]
heartbeat_interval_secs = 1
live_window_secs = 3
sweep_interval_secs = 1
suspicion_ticks = 2
```

The same `cluster_name` and `cluster_secret` must be set on every node. An
empty `cluster_secret` leaves gossip unauthenticated; set it before exposing the
gossip port to any untrusted network, otherwise a host that can reach the port
can inject a node and redirect clients to it.

On the second node, use a different `node_id`, swap the seed, and set
`turn_announce_addr` to that node's externally reachable TURN address.

This mode is independent of allocation persistence: you can use redirects for
load distribution with the in-memory backend, and enable Tarantool persistence
separately when you also need failover/rehydration.

## Architecture decisions worth knowing

- **Write-behind, not write-through.** A failed Tarantool write doesn't
  stall the data plane. Eventual consistency window is ≤100ms
  (`batch_max_delay_ms`).
- **No leader election.** Each node makes decisions locally based on
  what Tarantool tells it; CAS prevents conflicts.
- **Client port changes on failover.** This isn't zero-downtime — a
  client whose node dies sees a UDP timeout, retries via DNS, and lands
  on a survivor with a new relay port. Voice clients glitch for ~1–2
  seconds. For zero-gap, you'd need anycast or floating IP at the
  infrastructure layer — out of scope for turna.
- **All nodes are identical.** Same `turn.toml`, same auth config, same
  Tarantool address. The only difference is `node_id`.

## Prerequisites

- Two or more Linux hosts on the same private network (sub-millisecond
  latency between them ideally; certainly < 50ms).
- One Tarantool instance reachable from every turna-node host. For
  production-grade durability you want **Tarantool replication**
  (master/replica or RAFT) — see Tarantool docs. For an MVP a single
  Tarantool box is fine, with the understanding that it's a SPOF.
- `turna-node` binaries built in release mode on each host.

## Step 1 — Provision Tarantool

Pick a host. Install Tarantool 2.10+ from the official repo.
Run the bootstrap script once:

```sh
# Adjust paths to match your install
sudo install -d -m 0755 /var/lib/tarantool
sudo chown tarantool:tarantool /var/lib/tarantool

# Run the script. On first invocation it generates a random password
# and prints it once — capture it.
sudo -u tarantool tarantool /path/to/turna/deploy/tarantool/init.lua
```

Output ends with something like:

```
GENERATED PASSWORD (capture this once; will not be shown again):

  3a7f9c1e8b2d6f4a05e3c9d8b7a6f5e4

Set on the turna-node host:
  export TURNA_BACKEND_URI='0.0.0.0:3301'
  export TURNA_BACKEND_USER='turna'
  export TURNA_BACKEND_PASSWORD='3a7f9c1e8b2d6f4a05e3c9d8b7a6f5e4'
```

What the script did:

- Locked down the anonymous `guest` user (revoked every privilege).
- Created three spaces (`turna_allocations`, `turna_nodes`, `turna_rooms`)
  with the indexes turna needs.
- Created a role `turna_app` with read/write on those spaces only.
- Created a user `turna` with a random password and granted it `turna_app`.

The script is **idempotent**. Re-running it after an upgrade is safe.
If you want to control the password explicitly (rotation, vault
integration), set `TURNA_PASSWORD` in the environment before running:

```sh
TURNA_PASSWORD="$(openssl rand -hex 16)" \
    sudo -E -u tarantool tarantool deploy/tarantool/init.lua
```

## Step 2 — Configure each turna-node

`turn.toml` is identical on every node **except** `node_id`. The minimal
cluster-mode block:

```toml
production = true

[turn]
external_ip = "<this host's public IP>"
realm       = "turna"

[turn.auth]
shared_secret = "${TURNA_SHARED_SECRET}"

[cluster]
node_id = "${TURNA_NODE_ID}"        # e.g. "node-east-1", unique per host
cluster_mode = true
cluster_name = "prod"
gossip_bind = "0.0.0.0:7946"
gossip_seeds = ["10.0.0.12:7946"]      # swap per host
gossip_advertise_addr = "10.0.0.11:7946"
cluster_secret = "${TURNA_CLUSTER_SECRET}"

[cluster.backend]
type      = "tarantool"
uri       = "${TURNA_BACKEND_URI}"
user      = "${TURNA_BACKEND_USER}"
password  = "${TURNA_BACKEND_PASSWORD}"
pool_size = 0                      # 0 = library default (8)

[cluster.persistence]
mode = "write_behind"              # enables allocation persistence
```

Per-host environment:

```sh
# On host A
TURNA_NODE_ID=node-east-1
TURNA_BACKEND_URI=tarantool.internal:3301
TURNA_BACKEND_USER=turna
TURNA_BACKEND_PASSWORD=<from step 1>
TURNA_SHARED_SECRET=<your generated secret>
TURNA_PRODUCTION=true

# On host B
TURNA_NODE_ID=node-east-2
# rest identical
```

## Step 3 — Verify

On each node:

```sh
./turna-node --dump-config /etc/turna/turn.toml | head -40
```

You should see `[cluster.backend] type = "tarantool"` with non-empty
`user` and the masked password. If any are blank, env substitution
didn't happen.

Start `turna-node`. Logs should show:

```
INFO state backend: tarantool user="turna" pool_size=8
INFO connected to Tarantool uri=... user="turna" pool_size=8
INFO Tarantool schema initialized
INFO bulk-load: fetched records from backend node_id="node-east-1" count=0
INFO heartbeat task starting node_id="node-east-1" interval=1s
INFO failover task starting sweep_interval=1s live_window=3s suspicion_ticks=2
```

After both nodes are up, query Tarantool to confirm they see each other:

```
$ tt connect turna:<password>@tarantool.internal:3301
> box.space.turna_nodes:select{}
- - ['node-east-1', '{"node_id":"node-east-1", ...}']
  - ['node-east-2', '{"node_id":"node-east-2", ...}']
```

## Failover timeline

```
T=0       Node-A dies (kernel panic, kill -9, anything)
T=0..3    Peers still consider node-A live while its last heartbeat is fresh
T=3..5    Node-A is stale for consecutive sweep ticks
T≈5       Node-B excludes node-A, claims its allocations via CAS, and rehydrates
          them into its local store
```

The window is configurable under `[cluster.failure_detection]`. Tighter windows
produce faster failover but increase false positives during network blips; widen
`live_window_secs` and/or `suspicion_ticks` on jittery WAN links.

## Rolling upgrade

```sh
# On the node you're upgrading:
sudo systemctl reload turna-node      # if you wire SIGUSR1 to drain
# OR
sudo systemctl stop turna-node        # SIGTERM = graceful drain (~30s)

# Upgrade the binary
sudo install -m 0755 ./turna-node /usr/local/bin/turna-node
sudo systemctl start turna-node       # restarts, bulk-loads from Tarantool,
                                    # reclaims its own allocations
```

The window between stop and start should be shorter than your configured
failure-detection window if you want to avoid other nodes claiming allocations.
If it is longer, other nodes will claim them — correctness is preserved, but
affected clients may briefly reconnect.

For a planned removal or long upgrade, put the node in drain mode first:

```sh
turnactl drain
# or send SIGTERM and let the node enter its lame-duck drain path
```

Drain mode stops new allocations locally and, in cluster mode, lets peers route
new clients elsewhere during the grace window.

## Adding a node

1. Provision a new host.
2. Copy `turn.toml`. Set `TURNA_NODE_ID` to a unique value.
3. Start `turna-node`.
4. It registers via heartbeat. Other nodes don't need any config change.

## Removing a node

1. Stop `turna-node` on that host.
2. After the configured failure-detection window other nodes consider it dead and
   reclaim its allocations.
3. Optionally clean up its row in `turna_nodes`:
   ```
   box.space.turna_nodes:delete("node-east-1")
   ```
   Not strictly necessary — it just keeps `turna_nodes` tidy.

## Limitations

- **`node_id` must be unique per host.** Identical ids are deduplicated into a
  single ring entry, so every node would serve locally and balancing silently
  does nothing. Cluster mode logs a warning if `node_id` is left at the default
  `"node-1"`. Set `TURNA_NODE_ID` per host.

- **Redirects are loop-free only once rings converge.** With anti-entropy
  gossip and HRW, every node computes the same owner, so a client reaches its
  owner in exactly one redirect. During the brief convergence window after a
  topology change (a few `gossip_interval_secs`), two nodes can momentarily
  disagree and a client may be redirected a second time. This is bounded by the
  convergence window and by client-side redirect caps (pion/libnice/webrtc-rs
  all cap redirects), costing at most a couple of extra RTTs.

- **Old sessions are not migrated.** HRW only places *new* clients; existing
  allocations stay on their node until they expire (they are pinned and never
  redirected). This is intentional for TURN, where sessions are short-lived.

- **STUN clients without 300 support stay on their first node.** WebRTC stacks
  honour `300 Try Alternate`; a plain STUN client that ignores it keeps using
  the node it first contacted. Correctness is unaffected, balancing is just
  coarser for those clients.

- **Lame-duck drain.** On SIGTERM/SIGINT a node sets a draining flag, keeps
  redirecting *new* clients to other nodes for `drain_grace_secs`, broadcasts a
  `leaving` message, then exits. Existing sessions are never interrupted — they
  run until they expire. Good for rolling deploys.

- **Membership observability is wired on the server side only.** `HashRing`
  exposes a `snapshot()` and `ClusterRouting::members()` returns the current
  live nodes. Surfacing it as a `turnactl cluster nodes` command or a
  management `/cluster` endpoint still needs wiring in the `turnactl` /
  `management` crates.

- **Permission expiry is approximate.** `StoredAllocation::permissions`
  doesn't carry per-IP timestamps; on failover the new owner assumes a
  fresh 5-minute TTL. Clients refresh through normal CreatePermission
  shortly after, so this matters only for the first ~5 minutes
  post-failover.

- **The Lua `claim_allocation` script runs on Tarantool itself.** It's
  not exercised by `cargo test`. The first time you fail a real node
  in production is the first time the script runs. The script is short
  and uses only standard Tarantool primitives; if it breaks, the
  symptom is `BackendError::Serialization` from the failover task and
  the failed claim is logged.

- **No automatic Tarantool failover.** If your Tarantool box dies the
  entire cluster freezes. Use Tarantool's own replication / RAFT to
  cover that — out of scope for turna.

- **No cross-cluster federation.** Each Tarantool box is one cluster.
  Multi-region setups need separate Tarantool clusters and an
  upstream load balancer that routes clients to the right region.

## Troubleshooting

**Logs show `state backend init failed: slot 0/8: auth failed`.**
Wrong user or password. Re-check `TURNA_BACKEND_USER` /
`TURNA_BACKEND_PASSWORD`. To verify the password independently:

```sh
tt connect turna:<password>@tarantool.internal:3301
```

If that fails too, run `deploy/tarantool/init.lua` again with
`TURNA_PASSWORD` set to refresh the password on the Tarantool side.

**Logs show `heartbeat task: backend send failed` repeating.**
Tarantool is unreachable or rejecting writes. The data plane is fine —
clients are still served — but other nodes will eventually decide
this one is dead and claim its allocations. `tail -f
/tmp/tarantool.log` on the Tarantool host to diagnose.

**Failover doesn't pick up dead node's allocations.**
Check `box.space.turna_nodes:select{}` on Tarantool — is the dead node's
`last_seen_ms` actually old? If it's recent, your clock might be off
or someone is still publishing heartbeats under that node_id. Check
`box.space.turna_allocations.index.by_node:select{"<dead-node-id>"}` to
see what's tagged as theirs.

**`bulk-load` rehydrates nothing on restart.**
After a normal restart this is expected if the writer hasn't flushed
yet — `batch_max_delay_ms = 100` means at most 100ms of writes are in
flight. After a kill -9 you may lose up to that window. Tighter
durability is a `mode = "write_through"` story — not implemented
because it would block the data plane on Tarantool latency.
