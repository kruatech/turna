# Observability

`turna-node` exposes health, status, Prometheus metrics, logs, and optional
OpenTelemetry traces.

| Surface | Endpoint / sink | Format | Auth |
|---|---|---|---|
| Health | `GET /health` on `[health].listen` | `text/plain` | none |
| Status | `GET /status` on `[health].listen` | JSON | none |
| Metrics | `GET /metrics` on `[health].listen` | Prometheus text | none |
| Logs | stdout / journald | text or JSON | n/a |
| Traces | OTLP exporter | OTLP/gRPC | collector-dependent |

The code default for `[health].listen` is `0.0.0.0:8080`; the annotated
`deploy/turn.toml`, Docker and Helm paths use `0.0.0.0:9090`. Do not expose the
health port to the public Internet.

## `/health`

```sh
curl -sS http://127.0.0.1:9090/health
# ok
```

Returns `ok` while serving and `draining` while a graceful shutdown is in
progress.

## `/status`

```sh
curl -sS http://127.0.0.1:9090/status | jq .
```

Representative fields include uptime, active allocations, drain state, version,
node id, persistence mode and backend type. Treat this endpoint as a quick
operator snapshot, not as the primary metrics interface.

## `/metrics`

Minimal Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: turna
    scrape_interval: 15s
    static_configs:
      - targets: ['node-east-1:9090', 'node-east-2:9090']
```

### Core metrics

| Metric | Type | Meaning |
|---|---|---|
| `turna_active_allocations` | gauge | Current allocation count. |
| `turna_total_allocations` | counter | Total successful allocations since start. |
| `turna_packets_received` | counter | Packets received. |
| `turna_packets_sent` | counter | Packets sent. |
| `turna_bytes_received` | counter | Bytes received. |
| `turna_bytes_sent` | counter | Bytes sent. |
| `turna_auth_failures` | counter | Auth failures. |
| `turna_rate_limited` | counter | Rate-limited requests. |
| `turna_zero_copy_forwards` | counter | Zero-copy forwards. |
| `turna_draining` | gauge | `1` while draining, else `0`. |
| `turna_uptime_seconds` | gauge | Process uptime. |

### Drop and rejection metrics

| Metric | Type | Meaning |
|---|---|---|
| `turna_send_queue_dropped_total` | counter | Packets dropped due to a full send channel. |
| `turna_parser_rejections_total` | counter | STUN messages rejected by parser limits/validation. |
| `turna_malformed_packets_total` | counter | Packets classified as unknown/malformed. |
| `turna_quota_exceeded_total` | counter | Packets dropped due to quota. |
| `turna_peer_rejected_total` | counter | Permission/ChannelBind/Send requests rejected by peer filter. |

### RTP/QoS metrics

| Metric | Type | Meaning |
|---|---|---|
| `turna_rtp_streams` | gauge | Active RTP streams tracked by QoS. |
| `turna_rtp_avg_loss_percent` | gauge | Average packet loss. |
| `turna_rtp_max_loss_percent` | gauge | Max packet loss. |
| `turna_rtp_avg_jitter_ms` | gauge | Average jitter. |
| `turna_rtp_max_jitter_ms` | gauge | Max jitter. |
| `turna_rtp_total_bitrate_kbps` | gauge | Aggregate RTP bitrate. |

### Tarantool and persistence metrics

| Metric | Type | Meaning |
|---|---|---|
| `tarantool_reconnect_attempts_total` | counter | Reconnect attempts. |
| `tarantool_reconnect_success_total` | counter | Successful reconnects. |
| `tarantool_connection_state` | gauge | `0=connected`, `1=reconnecting`, `2=failed`. |
| `tarantool_writer_batches_total` | counter | Write-behind batches flushed. |
| `tarantool_writer_ops_total` | counter | Individual write ops applied. |
| `tarantool_writer_coalesced_total` | counter | Events coalesced inside a batch. |
| `tarantool_writer_errors_total` | counter | Backend errors during writer flush. |
| `tarantool_writes_dropped_total` | counter | Events dropped because the writer channel was full. Page on this. |
| `tarantool_pool_slots{state="idle|busy|broken"}` | gauge | Tarantool connection-pool slot state. |

### gRPC/control-plane and cluster metrics

| Metric | Type | Meaning |
|---|---|---|
| `grpc_active_streams` | gauge | Currently open gRPC streaming RPCs. |
| `grpc_shutdown_drain_ms` | gauge | Duration of last control-plane drain. |
| `grpc_forced_kills_total` | counter | Drain timeouts that forced stream closure. |
| `failover_claimed_total` | counter | Allocations claimed from dead nodes. |
| `failover_lost_race_total` | counter | CAS claims lost to another node. |
| `failover_errors_total` | counter | Backend errors during failover sweeps. |
| `failover_sweep_duration_us` | gauge | Duration of the latest failover sweep. |
| `turna_cluster_redirects_total` | counter | TURN 300 redirects sent. |
| `turna_cluster_nodes` | gauge | Live nodes in the gossip ring including self. |

### Histograms

| Metric | Meaning |
|---|---|
| `turna_stun_request_duration_seconds` | STUN/TURN request processing latency. |
| `turna_relay_forward_duration_seconds` | ChannelData relay forwarding latency. |
| `turna_auth_duration_seconds` | Authentication processing latency. |
| `turna_allocation_lifetime_seconds` | Allocation lifetime distribution. |

Use `histogram_quantile` in Prometheus:

```promql
histogram_quantile(0.99,
  sum by (le) (rate(turna_stun_request_duration_seconds_bucket[5m]))
)
```

### Optional metric families

Depending on enabled features and runtime paths, `/metrics` may also include:

- tenant metrics from `render_tenant_metrics()`;
- auth-reason metrics from `render_auth_reason_metrics()`;
- transport metrics from `render_transport_metrics()`;
- relay-route metrics such as `turna_relay_route_forwarded_ratio` on io_uring
  builds;
- QUIC/WebTransport and DTLS counters when those listeners are enabled.

## Starter alerts

A maintained starter rules file lives at `docs/alerts/turna.yml`. Install it as
a Prometheus rule file and adjust thresholds to your traffic profile.

The most important alerts are:

```promql
# Node down
up{job="turna"} == 0

# Persistence correctness risk
rate(tarantool_writes_dropped_total[5m]) > 0

# Backend write errors
rate(tarantool_writer_errors_total[5m]) > 0.1

# Auth failures / probing
rate(turna_auth_failures[5m]) > 1

# Internal backpressure
rate(turna_send_queue_dropped_total[5m]) > 0
```

## Structured logs

By default the node emits human-readable logs. Enable JSON logs for ingestion:

```toml
[turn.observability]
json_logs = true
```

Do not promote high-cardinality values such as `client_addr`, `relay_addr`, or
`username` to Loki/Prometheus labels. Keep them in the log body and filter at
query time.

Secrets (`shared_secret`, passwords, HMAC keys) must never appear in logs. Treat
logs as network metadata and apply retention controls.

## OpenTelemetry traces

```toml
[turn.observability]
otlp_endpoint = "http://otel-collector.internal:4317"
trace_sample_rate = 0.01
max_spans_per_second = 1000
```

Minimal collector pipeline:

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

## Caveats

- `/metrics`, `/status`, and `/health` are unauthenticated. Restrict the health
  port with firewall rules, VPN, or a reverse proxy.
- Some optional metric families are emitted only when the relevant feature/path
  is active.
- A Grafana dashboard JSON is not shipped yet. Use the PromQL examples above as
  the initial dashboard source.


## Runtime management and migration metrics

The following label-free metrics are exported by the node/control plane:

| Metric | Type | Meaning |
|---|---|---|
| `turna_management_commands_accepted_total` | counter | Durable management commands accepted. |
| `turna_config_update_applied_total` / `turna_config_update_noop_total` | counter | Applied and no-op runtime config outcomes. |
| `turna_config_update_conflicts_total` / `turna_config_update_failures_total` | counter | Version conflicts and failures. |
| `turna_config_update_rollback_total` | counter | Publications rolled back after observed-state confirmation failed. |
| `turna_config_observed_version` | gauge | Local node observed runtime config version. |
| `turna_config_desired_observed_mismatch` | gauge | Whether durable desired and observed config differ. |
| `turna_config_oldest_unapplied_ms` | gauge | Age of the current unapplied desired config. |
| `turna_user_limits_*` | counter/gauge | Applied/no-op/conflict/failure outcomes and over-limit subjects. |
| `turna_command_log_migration_*` | counter/gauge | Bounded migration progress, errors, and completion. |
| `turna_runtime_config_apply_duration_seconds` | histogram | Node-side config/limit apply latency. |

No `node_id`, realm, tenant, or username labels are emitted. Use the management
read API for per-node desired/observed details and audit logs for subject-level
investigation.
