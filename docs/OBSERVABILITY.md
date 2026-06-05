# Observability

`turna-node` and `turna-control-plane` expose three observability surfaces:

| Surface | URL | Format | Authentication |
|---|---|---|---|
| Liveness / readiness | `GET /health` on the health port | `text/plain` | none |
| Snapshot status | `GET /status` on the health port | `application/json` | none |
| Prometheus metrics | `GET /metrics` on the health port | text-format | none |
| Structured logs | stdout (journald-friendly) | text or JSON | n/a |
| Distributed traces | OTLP exporter | OTLP/gRPC | the collector's auth |

The health port defaults to `0.0.0.0:9090` — change with
`[health].listen` or `TURNA_HEALTH_ADDR`. **Do not expose this to the
public Internet**; use a firewall rule that limits it to your
monitoring host.

## /health

Returns the literal string `ok` when the process is alive and not
draining, `draining` while shutting down. Use this for load-balancer
liveness probes; route traffic away from `draining` nodes.

```sh
$ curl -sS http://node:9090/health
ok
```

## /status

JSON snapshot of high-level state. Suitable for dashboards that don't
have Prometheus or for quick eyeballing:

```sh
$ curl -sS http://node:9090/status | jq .
{
  "uptime_secs": 1287,
  "active_allocations": 3142,
  "draining": false,
  "version": "0.1.0",
  "node_id": "node-east-1",
  "persistence_mode": "write_behind",
  "backend_type": "tarantool"
}
```

Cheap to call; no authentication. Don't poll it faster than once per
second.

## /metrics — full reference

Text format compatible with Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: turna
    scrape_interval: 15s
    static_configs:
      - targets: ['node-east-1:9090', 'node-east-2:9090']
```

### Counters

| Metric | Description |
|---|---|
| `turna_packets_received_total` | UDP packets read off the wire. |
| `turna_packets_sent_total` | UDP packets written. |
| `turna_bytes_received_total` | Bytes received. |
| `turna_bytes_sent_total` | Bytes sent. |
| `turna_allocations_created_total` | Successful Allocate requests. |
| `turna_allocations_refreshed_total` | Refresh with lifetime > 0. |
| `turna_allocations_removed_total` | Explicit deallocate or TTL expiry. |
| `turna_auth_failures_total` | Requests rejected for bad credentials. Suspicious if non-zero on a private deployment. |
| `turna_stun_parse_errors_total` | Packets that looked like STUN but failed to parse. |
| `turna_bpf_filter_drops_estimated` | Best-effort estimate of how many packets the kernel BPF filter dropped (delta of `/proc/net/snmp` UDP errors since start). |
| `tarantool_writer_batches_total` | Batches flushed by the write-behind writer. |
| `tarantool_writer_ops_total` | Individual `WriteOp` events committed. |
| `tarantool_writer_coalesced_total` | Events merged inside a batch (Create+Remove→noop, Refresh+Refresh→latest, etc). |
| `tarantool_writer_errors_total` | Failed `store_allocation` / `remove_allocation` / etc. |
| `tarantool_writes_dropped_total` | Events dropped because the writer's bounded channel was full. **Alert on this.** |

### Gauges

| Metric | Description |
|---|---|
| `turna_active_allocations` | Current count. |
| `turna_active_channels` | Currently bound TURN channels. |
| `turna_allocation_create_in_flight` | Allocate handlers currently running. |
| `turna_draining` | `1` if the node is in graceful shutdown, else `0`. |

### Histograms / latency

| Metric | Description |
|---|---|
| `turna_allocate_duration_us` | End-to-end Allocate latency. |
| `turna_refresh_duration_us` | Refresh latency. |
| `turna_send_indication_relay_us` | Time spent in the SendIndication relay path. |
| `tarantool_eval_duration_us` | iproto EVAL latency to Tarantool, per request. |

(All histograms are bucketed in microseconds; quantiles configured at
Prometheus's side via `histogram_quantile`.)

## Recommended alerts

Drop-in starter rules. Place under `/etc/prometheus/rules/turna.yml`:

```yaml
groups:
- name: turna
  interval: 30s
  rules:

  # --- Hard ---

  - alert: TurnaWritesDropped
    expr: rate(tarantool_writes_dropped_total[5m]) > 0
    for: 2m
    labels: { severity: page }
    annotations:
      summary: "turna: Tarantool writer is shedding events ({{ $labels.instance }})"
      description: "Cluster state in Tarantool is falling behind. Failover safety degraded."

  - alert: TurnaBackendErrorsBurst
    expr: rate(tarantool_writer_errors_total[5m]) > 0.1
    for: 5m
    labels: { severity: page }
    annotations:
      summary: "turna: Tarantool backend errors > 0.1 ops/sec"

  - alert: TurnaNodeDown
    expr: up{job="turna"} == 0
    for: 2m
    labels: { severity: page }
    annotations:
      summary: "turna instance is unreachable: {{ $labels.instance }}"

  # --- Warn ---

  - alert: TurnaAuthFailuresHigh
    expr: rate(turna_auth_failures_total[5m]) > 1
    for: 10m
    labels: { severity: warn }
    annotations:
      summary: "turna: > 1 auth failure/sec for 10m"
      description: "Could indicate credential leak, misconfigured client, or active probing."

  - alert: TurnaAllocateLatencyP99
    expr: |
      histogram_quantile(0.99,
        sum by (le, instance) (rate(turna_allocate_duration_us_bucket[5m]))
      ) > 50000
    for: 10m
    labels: { severity: warn }
    annotations:
      summary: "turna: p99 Allocate latency > 50ms"

  - alert: TurnaDraining
    expr: turna_draining == 1
    for: 10m
    labels: { severity: warn }
    annotations:
      summary: "turna: node has been draining for > 10 minutes"
      description: "Either a stuck shutdown or a forgotten 'drain' state."
```

`TurnaWritesDropped` is the one you must not silence. Anything > 0 means
Tarantool can't keep up; failover correctness depends on this counter
staying at zero.

## Structured logs

By default `turna-node` emits human-readable logs to stdout. systemd's
journal captures them; `journalctl -u turna-node -f` shows them live.

For ingestion into a log store (Loki, ElasticSearch, etc.), enable
JSON output:

```toml
[turn.observability]
json_logs = true
```

Each event becomes one line of JSON like:

```json
{"timestamp":"2026-05-17T20:31:14.123Z","level":"INFO","target":"turna_node",
 "message":"allocation created","client_addr":"203.0.113.10:54321",
 "relay_addr":"10.0.0.1:49283","username":"alice"}
```

Fields you'll want to index:
- `level` (INFO / WARN / ERROR)
- `target` (module name — useful for filtering noise)
- `client_addr`, `relay_addr`, `username` (for per-user investigation)
- `error` / `reason` (on WARN+)

Secrets are never logged: `shared_secret`, `password`, raw HMAC keys
are stripped at the source.

### Loki labels

Recommended `relabel_configs` for Promtail / Vector:

```yaml
labels:
  service: turna
  node_id: <from TURNA_NODE_ID or _SYSTEMD_UNIT>
  level: <level>
```

Don't promote `client_addr` / `username` to labels — high-cardinality
ingestion kills Loki performance. Keep them in the line body and
filter at query time with `| json | username="alice"`.

## OpenTelemetry traces

Set the OTLP endpoint to enable export:

```toml
[turn.observability]
otlp_endpoint     = "http://otel-collector.internal:4317"
trace_sample_rate = 0.01    # 1% of regular requests; errors always sampled
```

Spans emitted (representative):

- `turn.allocate` — full Allocate handler
- `turn.refresh`
- `turn.create_permission`
- `turn.channel_bind`
- `turn.send_indication` (only when sampled — high volume)
- `tarantool.eval` — every iproto round-trip
- `tarantool.writer.batch` — write-behind flush

Span attributes include `client_addr`, `username` (allocate / refresh
only), and any error string when status is ERROR.

Errors and Allocate spans are **always** sampled regardless of
`trace_sample_rate` — this is the most useful tail-based sampling for
TURN diagnostics.

### Minimal otel-collector pipeline

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    timeout: 1s

exporters:
  otlp/tempo:
    endpoint: tempo.internal:4317
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo]
```

## Dashboards

A Grafana dashboard JSON is **not yet shipped** — see TODO.md. Until
it lands, useful PromQL one-liners:

```promql
# Concurrent allocations across the cluster
sum(turna_active_allocations)

# Throughput per node, bytes/sec
rate(turna_bytes_received_total[1m])

# p50 / p95 / p99 of Allocate latency
histogram_quantile(0.99,
  sum by (le) (rate(turna_allocate_duration_us_bucket[5m]))
)

# Writer health: events committed vs dropped
rate(tarantool_writer_ops_total[5m])
rate(tarantool_writes_dropped_total[5m])

# Coalescing efficiency
rate(tarantool_writer_coalesced_total[5m]) /
rate(tarantool_writer_ops_total[5m])

# Auth failure rate (probing indicator)
rate(turna_auth_failures_total[5m]) by (instance)
```

## Cluster-wide queries

When more than one node is running, sum / max appropriately:

```promql
# Total cluster capacity in use
sum(turna_active_allocations)

# How balanced is the cluster? (low values = even distribution)
stddev(turna_active_allocations) / avg(turna_active_allocations)

# Are any nodes refusing to talk to Tarantool?
sum by (instance) (rate(tarantool_writer_errors_total[5m]))
```

## Caveats

- **Heartbeat resource fields are zero.** `cpu_usage_pct`,
  `memory_usage_pct`, `total_bandwidth_bps` in `NodeHeartbeat` are
  currently published as 0. They're meant for the (future) cluster
  scheduler. For real resource monitoring use `node_exporter`.
- **Failover task isn't on /metrics yet.** PR 5's `FailoverStats` is
  internal to the process; once exported it'll add
  `turna_failover_claimed_total`, `turna_failover_lost_race_total`,
  `turna_failover_errors_total`. Track via TODO.md.
- **No /metrics auth.** Anyone who can reach the health port reads
  everything. Lock down with firewall rules. If you need
  authenticated metrics endpoint, front it with nginx + basic auth or
  put it behind your VPN.
