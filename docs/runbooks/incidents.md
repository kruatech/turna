# Incident runbook

Maps the Prometheus alerts in `docs/alerts/turna-rc.yml` to diagnosis and
action. Each entry: what fired → what to check → what to do. Health surfaces:
`GET /ready` (200 ready / 503 not-ready or draining), `GET /status` (JSON),
`GET /metrics` (Prometheus), and the `turna_backend_readiness` gauge
(0=starting, 1=ready, 2=degraded, 3=draining).

## Readiness

### TurnaStuckStarting (`turna_backend_readiness == 0`)
Node has not reached ready. Most often fail-closed config: production mode
refuses to start with placeholder secrets, an unreadable TLS/DTLS cert, or an
invalid cluster secret.
- Check: node logs at startup for the specific refusal; `GET /ready` returns 503.
- Do: fix the flagged config (real secrets, readable PKCS#8 ECDSA-P-256 cert for
  DTLS, `cluster_secret` set). Fail-closed is intentional — do not work around it.

### TurnaBackendDegraded (`turna_backend_readiness == 2`)
Process reached ready but a dependency degraded — usually the state backend
(Tarantool) became unreachable. Serving continues on local state; cluster reads
may be stale.
- Check: `TarantoolConnectionNotConnected` / `TarantoolPoolBroken` firing too;
  `tarantool_connection_state` (0=connected).
- Do: restore Tarantool connectivity (see tarantool-backup.md). Readiness returns
  to 1 automatically once the backend recovers (I6 degraded→ready).

### TurnaTransportDegraded (`turna_transport_readiness == 2`)
A transport listener degraded (e.g. TLS cert reload failed on mtime change).
- Check: logs for TLS/DTLS errors; cert file readability/expiry.
- Do: fix/renew the cert; turna hot-reloads by mtime once the file is valid.

## Correctness / stability

### TurnaProcessorPanics (`increase(turna_processor_panics_total[5m]) > 0`)
A packet processor task panicked. Should be zero (the 12h soak had zero).
- Check: logs for the panic backtrace and the triggering packet shape.
- Do: capture the log, treat as a bug (report). A single panic is contained per
  task but must not recur — escalate.

## Tarantool / persistence

### TarantoolConnectionNotConnected (`tarantool_connection_state != 0`)
State: 0=connected, 1=reconnecting, 2=failed. Non-zero = not serving.
- Check: Tarantool process/container up; network to :3301; `tarantool_pool_slots`.
- Do: restart Tarantool if down (see tarantool-backup.md for safe restart and
  recovery); the pool reconnects automatically.

### TarantoolWritesDropped (`increase(tarantool_writes_dropped_total[5m]) > 0`)
Write-behind queue overflowed under load (R6): allocation updates were dropped.
Local serving is unaffected; the backend view lags.
- Check: write rate vs capacity; whether it correlates with a load spike.
- Do: if sustained, scale Tarantool or raise the write-behind capacity; brief
  bursts self-heal. Accept that a crash during backlog loses those updates.

### TarantoolWriterErrors / TarantoolPoolBroken
Backend errors or a broken pool slot.
- Do: check Tarantool health/logs; a broken slot is retried, a persistently
  broken pool needs a Tarantool restart.

## Cluster / failover

### TurnaFailoverErrors (`increase(failover_errors_total[10m]) > 0`)
The failover sweep hit backend errors while enumerating/claiming orphans.
- Check: `find_by_node` failures in logs; Tarantool health.
- Do: transient errors self-heal (next sweep retries). Persistent errors point
  at Tarantool — restore it.

### TurnaFailoverLostRaceSpike (`increase(failover_lost_race_total[10m]) > 50`)
Many claims lost the CAS race. A few is normal (two survivors racing). A large
spike suggests clock skew: a node with a fast clock mis-classifies live peers as
dead and spins claiming allocations the live owner keeps re-asserting.
- Check: inter-node clock skew (NTP status on all nodes); which node is sweeping.
- Do: fix NTP / keep skew < `live_window` (3s). CAS keeps correctness (no
  split-brain), but the spinning wastes work — see COMPLIANCE §3.

## Backpressure / capacity

### TurnaSendQueueDrops (`rate(turna_send_queue_dropped_total[5m]) > 1`)
Per-relay outbound queue is full; newest datagrams dropped (bounded-queue by
design, not a crash). The 12h soak had zero — sustained drops mean overload.
- Check: which relays; PPS vs capacity; CPU.
- Do: scale out / add nodes; investigate a hot allocation. Brief spikes tolerable.

### TurnaAllocationsNearMax (`turna_active_allocations > 45000`)
Approaching `max_alloc` (50000). New allocations will be refused at the cap.
Also note: failover of a node this large takes tens of seconds (see docs/scale/).
- Do: add nodes to spread load; keep per-node counts well below the cap for fast
  failover.

## Abuse / security signals

### TurnaAuthFailureSpike / TurnaParserRejectionSpike / TurnaMalformedPacketSpike / TurnaPeerRejectedSpike / TurnaQuotaExceededSpike
Elevated rejection rates. These are turna working as designed (rejecting bad
auth, malformed STUN, forbidden peers, over-quota) — the alert flags *volume*.
- Check: `turna_auth_failures_by_reason_total` by reason; source IPs; whether one
  client or broad.
- Do: if a single source, block upstream (firewall). If broad, likely a scan or
  misconfigured client fleet. turna already rejects them; the concern is load.

## Management

### TurnaForcedStreamKills (`increase(grpc_forced_kills_total[15m]) > 0`)
The gRPC control plane force-killed streams.
- Check: control-plane logs; client behaviour.
- Do: usually a misbehaving control client; investigate the caller.
