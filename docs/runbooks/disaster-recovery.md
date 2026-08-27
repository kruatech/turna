# Disaster recovery runbook

`incidents.md` covers a node misbehaving. This covers losing one, losing all of
them, or losing the state behind them. Each entry: what happened → what is true
about the system right now → what to do.

Read the second column first. Most DR mistakes come from acting on a belief about
the system that stopped being true.

## The thing to know before any of this

**A relay carries no durable user data.** Allocations are ephemeral by design —
600-second lifetimes, refreshed by clients — so there is nothing to restore in the
sense a database has. What can be lost is *configuration*, the *audit log*, and
the *cluster's view of itself*.

That makes recovery cheaper than it looks and the priorities different from a
stateful service. **Getting a node serving again matters more than recovering
what it was serving**, because what it was serving is gone either way and the
clients have already moved on via ICE restart.

---

## Losing one node

### A node is gone and the cluster has others

**What is true:** its allocations are lost. Clients on it are mid-reconnect and
will land on a surviving node. There is no media-session migration in this
version, so nothing is transferred — the sessions are re-established from
scratch.

**Do:**
1. Check the survivors have headroom before doing anything else:
   `curl -s node:9090/capacity` on each. A node reporting `SATURATED` cannot
   absorb another's clients, and the failure above the ceiling is a cliff not a
   slope — see `docs/capacity/`.
2. If they do, nothing is urgent. Replace the node at a normal pace.
3. If they do not, this is a capacity incident wearing a DR costume. Add a node
   or shed load; recovering the dead one will not be fast enough.

**Do not** rush the replacement into service without
`scripts/verify/deployment-compliance.sh`. A node built under time pressure is
where `production = false` gets left behind.

### A node is gone and it was the only one

**What is true:** the service is down. All allocations are lost. Clients are
retrying and will keep retrying.

**Do:**
1. Start a replacement from the same config. If the config is also gone, see
   below — that is the harder problem.
2. `turna-node --dump-config /etc/turna/turn.toml` before starting it. Validation
   catches what would otherwise be a second outage ten seconds later.
3. The clients need no intervention. They are retrying.

**Time to recovery is bounded by getting a process up, not by any restore.** If
it is taking longer than that, the bottleneck is config or certificates, which is
what the sections below are for.

---

## Losing configuration

### The config file is gone or corrupt

**What is true:** the node is either running on config it read at startup — in
which case there is no rush — or it is not running.

**Do:**
1. **If the node is still up, get the config out of it before anything else:**
   `turna-node --dump-config` prints the *file*, not the running state, so that
   does not help. Instead take a support bundle:
   `scripts/support-bundle.sh --config /etc/turna/turn.toml`. It includes the
   config with secrets masked, which is enough to rebuild the file — the secrets
   come from the secret store, not from the backup.
2. Rebuild from the offline bundle's template
   (`turna-offline-*/config/turn.toml`) plus the values in the support bundle.
3. Validate before restarting.

**Masked secrets are not a problem here.** They were never meant to live in this
file: `${TURNA_SHARED_SECRET}` and `file:///run/secrets/...` are the supported
forms, and a config that lost its literal secrets lost nothing that was not a
mistake.

### The TLS certificate or key is gone

**What is true:** TURNS, DTLS, QUIC and WebTransport will not start. Plain UDP
TURN is unaffected and still serving.

**Do:**
1. Disable the affected listeners and restart. **A node serving UDP is worth more
   than a node not serving.** Losing TURNS costs the clients behind restrictive
   firewalls; losing everything costs all of them.
2. Reissue and re-enable. Certificate reload is live on TLS, QUIC and
   WebTransport — no restart needed once the files are back. On DTLS's stock path
   it is not, and that listener needs a restart; see
   `docs/security/security-profile.md`.

---

## Losing the state backend

### Tarantool is gone and is not coming back

**What is true:** allocations in memory are unaffected — the backend is
write-behind, not the source of truth for a live allocation. What stops working
is cross-node visibility, failover, and the durable command log.

**Do:**
1. Check `turna_backend_readiness`. A value of 2 means degraded, and degraded
   still relays.
2. Decide whether to run standalone. `[backend]` can be removed and the node
   restarted: it will serve, without clustering.
3. Restore Tarantool from backup per `docs/runbooks/tarantool-backup.md`.
   Allocations in the backup are stale and will be reconciled or expire — do not
   try to preserve them.

**The reconciliation direction matters.** The node reconciles the backend against
its own memory, not the other way round. A restored backend with old allocations
does not resurrect them.

### The whole cluster's state is inconsistent

**What is true:** nodes disagree about who owns what. Clients may be sent to a
node that does not have their allocation.

**Do:**
1. Prefer the simple resolution: drain and restart nodes one at a time.
   Allocations are ephemeral, so a full cycle through the cluster resolves the
   disagreement by outliving it.
2. `scripts/verify/upgrade-rollback.sh` is the same procedure and can be read as
   its runbook.

**Do not** attempt to repair the state by hand. It is worth less than the
allocations it holds, and those expire in ten minutes.

---

## Losing the audit log

**What is true:** the chain is broken or the file is gone. Past entries cannot be
reconstructed, and that is the point of a hash chain — a log that could be
rebuilt could be forged.

**Do:**
1. `VerifyAudit` on what remains, to establish where the chain stops being
   intact.
2. Preserve the remnant before starting a new chain. It is evidence, whatever
   state it is in.
3. Start a fresh chain and **record the gap**: what period is not covered, and
   why. An audit log with an unexplained gap is worse than one with an explained
   one, because a reader cannot tell a loss from a deletion.

**Adding a field to the entry also breaks the chain**, by design — the hash covers
the entry. If verification fails right after an upgrade, check whether the entry
shape changed before concluding tampering.

---

## Losing a whole site

**What is true:** there is no multi-DC failover in this version. Region awareness
is not implemented. Nothing automatic will happen.

**Do:**
1. Stand up nodes elsewhere and change what clients are told. The relay does not
   redirect across sites, so this is a change at the signalling layer above it.
2. `ALTERNATE-SERVER` redirects work within a cluster — and note they were broken
   across three releases because the attribute carried the wrong type. If a
   redirect appears to do nothing on an older build, that is why.

**This is the gap worth planning around rather than working around.** It is listed
as needing design in `docs/roadmap/enterprise-gap-2026-08-27.md`, and no runbook
substitutes for the feature.

---

## What has been rehearsed, and what has not

Honesty here matters more than completeness: a runbook whose steps have never
been executed is a document, not a procedure.

| scenario | rehearsed |
|---|---|
| Node restart with clients connected | **yes** — reconnect storm, 150/150 recovered, slowest 3 ms |
| Drain and binary swap | **yes** — `upgrade-rollback.sh` |
| Rollback to the previous version | **yes** — same script, against the *new* config, which is what an operator has |
| Backend degradation | **partial** — CAS failover in CI, not under load |
| Config rebuilt from a support bundle | **no** |
| Certificate loss and reissue | **no** |
| Audit chain break and restart | **no** |
| Site loss | **no** — and cannot be, without a second site |

The four "no" rows are the ones to rehearse next. Each is cheap: they need one
node and a deliberate act of destruction, not a cluster.
