# Cluster mode

Single-node `turna-node` is enough for many self-hosted deployments — one
beefy server can handle thousands of concurrent allocations. You need
cluster mode when **any** of these is true:

- You want **failover**: if one node dies, surviving nodes pick up its
  allocations within ~40 seconds.
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
non-blocking) and publishes a heartbeat every 5 seconds. Each node also
sweeps every 10 seconds: if a peer's last heartbeat is older than 30
seconds, that peer is presumed dead and its allocations become eligible
for claim. The first surviving node to win a CAS on a record takes
ownership and rehydrates it locally.

Detailed design is in `docs/design/allocation-store-persistence.md`.

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
seeds   = []                       # not used yet — set for future gossip

[cluster.backend]
type      = "tarantool"
uri       = "${TURNA_BACKEND_URI}"
user      = "${TURNA_BACKEND_USER}"
password  = "${TURNA_BACKEND_PASSWORD}"
pool_size = 0                      # 0 = library default (8)

[cluster.persistence]
mode = "write_behind"              # this is what flips cluster mode on
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
INFO heartbeat task starting node_id="node-east-1" interval=5s
INFO failover task starting sweep_interval=10s live_window=30s
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
T=0..5    Node-A stops sending heartbeats
T=5..30   Node-A's last_seen_ms is < 30s ago — peers still consider it live
T=30      Node-B's failover sweep tick: get_live_nodes(max_age=30s)
          excludes node-A; allocations stamped node_id=node-A become orphans
T=30..40  Node-B claims them via CAS, rehydrates into local store
T=40      Client retries hit node-B, get matched to rehydrated allocations
```

The window is configurable: `failover::DEFAULT_LIVE_WINDOW` (30s) and
`failover::DEFAULT_SWEEP_INTERVAL` (10s) in `services/node/src/failover.rs`.
Tighter windows = faster failover, but more false positives during
brief network blips. 30s is a reasonable default; we don't currently
expose it through `turn.toml`.

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

The window between stop and start should be < 30s to avoid triggering
failover on other nodes. If it's longer, other nodes will claim
allocations — which is also fine, just costs the affected clients a
brief reconnect.

For a longer-running upgrade (e.g. major version with schema migration),
manually mark the node as draining first:

```sh
turnactl drain node-east-1          # (TODO — currently you SIGTERM)
```

This sets `draining = true` in the next heartbeat, signalling peers to
preemptively claim — no 30-second wait.

## Adding a node

1. Provision a new host.
2. Copy `turn.toml`. Set `TURNA_NODE_ID` to a unique value.
3. Start `turna-node`.
4. It registers via heartbeat. Other nodes don't need any config change.

## Removing a node

1. Stop `turna-node` on that host.
2. After `live_window` (default 30s) other nodes consider it dead and
   reclaim its allocations.
3. Optionally clean up its row in `turna_nodes`:
   ```
   box.space.turna_nodes:delete("node-east-1")
   ```
   Not strictly necessary — it just keeps `turna_nodes` tidy.

## Limitations

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
