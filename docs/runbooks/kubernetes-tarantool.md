# Runbook — turna on Kubernetes with the Tarantool backend

Read `docs/runbooks/tarantool-backup.md` first if you have not: it covers backup,
restart and recovery of Tarantool itself, and this runbook does not repeat it.
What follows is only the Kubernetes-specific half — what the chart does, what it
deliberately does not do, and the order the pieces have to come up in.

## 0. What the chart will and will not give you

Establish this before planning anything, because two of the limits surprise
people at the wrong moment.

**The chart deploys `turna-node` and nothing else.** There is no
`turna-control-plane` workload and no Service for the management port; the
ConfigMap sets `[management] enabled = false` on loopback. So `turnactl` and the
admin console cannot reach a chart deployment. They assume the single-host
topology in `docs/admin/README.md`. If you need the ops API in Kubernetes you are
writing that workload yourself.

**The chart configures plain UDP TURN only.** Its ConfigMap has no `[tls]`,
`[turn.dtls]` or `[turn.quic]` section, and no override hook. TURNS, DTLS and
QUIC/WebTransport work in the node and are exercised by CI, but are not reachable
through this chart — certificate material needs Secret mounting the chart does
not do. Supply your own ConfigMap for those.

**The chart does not deploy Tarantool.** `state.*` tells turna where to find one.
Standing it up, giving it a persistent volume, backing it up and upgrading it are
yours. That is the subject of the backup runbook above.

**Cluster mode is experimental.** `values.yaml` says so in the section above
`cluster:`: it gives gossip and TURN 300 redirects, not transparent allocation
continuity and not zero-gap rolling upgrades. GA is standalone-first. Enabling it
switches the workload from a Deployment to a StatefulSet.

## 1. Provision Tarantool first

turna will not create the schema. `deploy/tarantool/init.lua` does, and it must
run against the instance before any turna pod starts — a node that connects to an
unprovisioned Tarantool fails on its first call rather than degrading.

Run it once as the instance script, with the application password supplied rather
than generated:

    TURNA_PASSWORD=<from your secret store> tarantool /path/to/init.lua

If you omit `TURNA_PASSWORD` the script generates one and prints it **once**,
which is a poor fit for anything automated. Supply it. The script also creates the
`turna_app` user (override with `TURNA_USER`) and grants per-function execute
rights rather than blanket access.

Verify before continuing — this is cheap and the alternative is debugging a
CrashLoopBackOff:

    tt connect <host>:3301 -f - <<'EOF'
    print(box.space.turna_allocations ~= nil)
    print(box.func['turna_init_schema'] ~= nil)
    print(box.schema.user.exists('turna_app'))
    EOF

All three must print `true`.

The schema is defined in exactly one place — that file. There is no second
Rust-side copy to keep in step, whatever older notes may say.

## 2. Put the backend password in a Secret

The chart never puts the backend password in the ConfigMap. It reads it from an
existing Secret and injects it as `TURNA_BACKEND_PASSWORD`, which the ConfigMap
expands into `[cluster.backend] password`.

    kubectl create secret generic turna-tarantool \
      --from-literal=backend-password='<the TURNA_PASSWORD from step 1>'

Then point the chart at it. Note `existingSecretKey` defaults to
`backend-password`; if you name the key something else, set it.

    state:
      enabled: true
      type: "tarantool"
      uri: "tarantool.turna-management.svc.cluster.local:3301"
      user: "turna_app"
      existingSecret: "turna-tarantool"
      existingSecretKey: "backend-password"
      poolSize: 8
      persistenceMode: "write_behind"

`deploy/helm/turna/values-production.example.yaml` carries this shape already.

## 3. Two settings that fail closed, and one that does not

`persistenceMode: "write_behind"` with `type: "memory"` is **refused at startup**
in production: an in-memory backend gives no durable persistence, and validation
says so rather than letting you believe otherwise. If the pod refuses to start
with that message, the fix is the backend, not the mode.

`cluster.enabled: true` with a memory backend is likewise refused — the in-memory
backend is process-local and cannot be shared between pods.

What does **not** fail closed is `state.enabled: false` with
`persistenceMode` left at its default. That is a legitimate standalone
deployment; it simply keeps no state across a restart, and clients re-Allocate.
Make sure that is what you meant.

## 4. Order of operations

1. Tarantool up, volume attached, `init.lua` applied, the three checks in §1
   passing.
2. Secret created.
3. `helm install` / `helm upgrade`.
4. Watch the first pod's logs for the backend connection before declaring
   success. A pod can pass its readiness probe on the health port while the
   backend is unreachable, because readiness follows the listener.

## 5. What to watch afterwards

These are exported by every node and described in `docs/OBSERVABILITY.md`:

| Metric | Why |
|---|---|
| `turna_backend_readiness` | `2` = degraded. The node is serving but its view of the backend is not healthy. |
| `tarantool_connection_state` | `0` connected, `1` reconnecting, `2` failed. |
| `tarantool_pool_slots{state="broken"}` | Connections the pool gave up on. Sustained non-zero means the backend, the network policy, or the credentials. |
| `tarantool_writes_dropped_total` | Write-behind events discarded because the writer channel was full. Each one is allocation state that will not survive a restart — `docs/OBSERVABILITY.md` says page on this, and it is right. |
| `tarantool_writer_errors_total` | Backend errors during a writer flush. |
| `turna_command_log_oldest_unfinished_ms` | A management command that never reached a terminal state — an operation that silently did not happen. |

Note the prefix: the Tarantool series are `tarantool_*`, not `turna_tarantool_*`.
Getting that wrong gives you a dashboard panel and an alert that are both
permanently empty, which reads as health.

`docs/alerts/turna.yml` is a maintained starter rules file. Install it into your
Prometheus; the chart does not, and `deploy/prometheus.yml` is a dev-stack config
that loads no rules.

## 6. NetworkPolicy

`networkPolicy.enabled: true` opens ingress for the STUN port (UDP and TCP), the
relay range (UDP, using `endPort` — needs Kubernetes 1.25 or newer), the health
port from `metricsFrom`, and the gossip port in cluster mode. Egress allows DNS
and is otherwise unrestricted, so reaching Tarantool needs no extra rule.

It does **not** open 5349 or 5350: consistent with §0, since the chart cannot
configure those listeners anyway. If you supply your own ConfigMap to enable
TURNS, remember the policy too — otherwise the listener binds and nothing reaches
it, which looks like a TURNS bug and is not.

## 7. Upgrades

The relay port range published by the Service and allowed by the NetworkPolicy
must equal `[turn.relay] min_port..max_port`. `scripts/check-deploy-consistency.sh`
gates that across `turn.toml`, docker-compose and the Helm values in CI, because
the failure mode is silent: allocations succeed and their relay traffic is
dropped.

Set `terminationGracePeriodSeconds` at least as high as the shutdown budget the
node prints at startup (`shutdown_budget_secs`, which sums the drain grace and the
persistence flush). Killing a node before it flushes discards write-behind events
that had not reached Tarantool.
