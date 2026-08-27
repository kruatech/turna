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
| `turna_relay_ports_in_use` | gauge | Relay ports held by an allocation **or** by an unclaimed EVEN-PORT reservation — a reserved port is unavailable to anyone else, so counting it free would understate how full the pool is. Summed across the global pool and any tenant pools. |
| `turna_relay_ports_total` | gauge | Relay ports configured, summed the same way: `max_port - min_port + 1` per pool. |
| `turna_relay_ports_utilization_percent` | gauge | Percent of the range in use. **The one to alert on.** Reads 0 rather than 100 before the first sample, so an alert on a high value cannot fire during startup. |
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
  builds.

### Encrypted-transport metrics

`render_transport_metrics()` always emits these series; they read `0` when the
listener is disabled or the feature is not compiled in, so a dashboard can be
built once and stay valid.

#### Security event export (`[observability] syslog_endpoint`)

RFC 5424 syslog to a SIEM. Security-relevant events only — authentication
failures, authorisation denials, peer refusals, rate-limit trips, audit entries,
readiness transitions. Not relayed traffic: a SIEM billed per event that receives
a line per frame gets switched off, and a switched-off SIEM catches nothing.

| metric | type | meaning |
|---|---|---|
| `turna_syslog_sent_total` | counter | Events written to the collector. |
| `turna_syslog_dropped_total` | counter | Events lost: transport error, or a busy path under `non_blocking`. **Alert on any sustained value.** A gap in a security log is worse than a visible failure, because an investigation reads absence as "nothing happened". |

Dropping rather than blocking is deliberate. A collector that stops reading must
not be able to stall the relay — security logging that can take the service down
is a worse posture than logging that can gap, provided the gap is counted. It is.

Addresses are sent verbatim by default. That is the opposite of the support
bundle's choice, and for a reason: a SIEM is inside the operator's trust boundary
and an authentication-failure event without a source is not actionable.
`syslog_redact_addresses = true` hashes them, and loses cross-event correlation —
which is most of what a SIEM is for.

#### Dashboard

`deploy/grafana/turna-overview.json`. Schema 39, which loads on Grafana 10 and 11.
Import and pick a Prometheus datasource.

Panels are ordered by the question an operator asks first — is it serving, then
traffic, then refusals, then per-transport. Each panel's description says what the
number *means* rather than restating its name, because a dashboard that needs a
runbook open beside it is half a dashboard.

Three panels are worth knowing about before an incident:

**Send queue drops.** Non-zero means the node discarded media before sending it.
Clients cannot see this, so a clean-looking loss measurement is not evidence
against it — a capacity figure came out 27 % too high for exactly that reason.

**Relay ports in use.** The blind spot until 2026-08-26. A range fills silently
and the first symptom is `Allocate` failing. Alert here, not on allocation count.

**Tenants aggregated away.** Non-zero means some tenants are inside `__other`
rather than named. Not a fault — but if a specific tenant cannot be found, this is
why.

#### Relay port exhaustion

`turna_relay_ports_utilization_percent` is the series to alert on, and it was
absent until 2026-08-26. The range is bounded by `[turn.relay] min_port`/`max_port`
and config validation warns when `max_allocations` exceeds half of it, but nothing
reported occupancy at runtime: the range filled silently and the first symptom was
`Allocate` beginning to fail. The gap surfaced while looking for this metric during
a 24-hour soak and finding it did not exist.

Two things make a range fill faster than the allocation count suggests. EVEN-PORT
reservations hold a port without an allocation behind it, and a range overlapping
the host's ephemeral range loses ports to processes that have nothing to do with
turna — which has bitten this project: a peer socket landed inside the relay range
and the relay forwarded to itself.

**Tenant pools are summed, not labelled.** Per-tenant series are how a Prometheus
instance dies when a customer has ten thousand tenants, and §10 of the enterprise
specification asks for cardinality protection in the same document that asks for
this metric. `AllocationStore::port_pool_usage()` returns `(pool, in_use, capacity)`
per pool for anything that needs the detail — the management API, a support bundle —
without every scrape paying for it. Resist adding the label.

#### `GET /capacity`

Served on the health listener beside `/metrics`. Returns the node's capacity state
in the vocabulary the enterprise specification asks for — `AVAILABLE`, `DEGRADED`,
`DRAINING`, `SATURATED`, `UNAVAILABLE` — with the raw numbers beside the verdict so
a caller can apply its own policy.

Always answers `200`, including when saturated: a caller asking "can you take this"
needs an answer rather than an error to interpret. `/ready` remains the endpoint
that speaks in status codes.

The response carries a `signals` object naming which inputs the state actually
weighed. Allocations, send-queue pressure and readiness are in; bps, pps, CPU and
memory are not, and saying so in the response is cheaper than a caller discovering
it during an incident. Design and rationale: `docs/design/capacity-api.md`.

#### TURNS — TLS over TCP (`[tls]`)

| metric | type | meaning |
|--------|------|---------|
| `turna_tls_active_connections` | gauge | Established TURNS connections. |
| `turna_tls_connections_total` | counter | Connections accepted since start. |
| `turna_tls_closed_total` | counter | Connections closed. |
| `turna_tls_handshake_failures_total` | counter | TLS handshakes that failed (client/cert mismatch, RST, scanners). |
| `turna_tls_handshake_timeouts_total` | counter | Handshakes over `handshake_timeout_secs`. |
| `turna_tls_rejected_over_cap_total` | counter | Refused at `max_connections`. |
| `turna_tls_rejected_per_ip_total` | counter | Refused at `max_connections_per_ip`. |
| `turna_tls_idle_timeouts_total` | counter | Closed by `read_timeout_secs`. |
| `turna_tls_framing_errors_total` | counter | Invalid or over-sized TURN-over-TCP framing. |
| `turna_tls_accept_errors_total` | counter | `accept()` errors survived without stopping the listener (e.g. `EMFILE`). |
| `turna_tls_bytes_rx_total` / `turna_tls_bytes_tx_total` | counter | Decrypted bytes in / bytes written out. |
| `turna_tls_cert_reloads_total` | counter | Successful certificate hot-reloads. |
| `turna_tls_cert_reload_failures_total` | counter | Failed reloads; the previous certificate stays in service. |
| `turna_tls_rejected_rate_limit_total` | counter | Handshakes refused by `max_handshakes_per_sec_per_ip`, before `accept()` does any TLS work. Distinct from `rejected_per_ip`, which caps *concurrent* connections: a source that connects and drops in a loop trips this one and never that one. |
| `turna_tls_alpn_rejected_total` | counter | Connections closed after the handshake because `alpn_required` was set and the client negotiated no ALPN. Non-zero here means either a probe or a real client that does not offer ALPN — check before assuming the former. |

#### TURN-over-SCTP (`[turn.sctp]`)

Refused under `production = true`. These exist so a deployment that opts in on an
internal network can see what the listener is doing — it shipped with no counters
at all, which meant a listener that had stopped accepting looked identical to an
idle one: socket bound, process healthy, nothing moving.

`turna_sctp_readiness` follows the listener's own `listening` flag, set after bind
and cleared on drain. It is not a separate belief about whether the listener is
up, because a separate belief is what lets a dead listener keep reporting Ready.

| metric | type | meaning |
|--------|------|---------|
| `turna_sctp_active_associations` | gauge | Established associations. |
| `turna_sctp_associations_total` | counter | Associations accepted since start. |
| `turna_sctp_closed_total` | counter | Associations closed. |
| `turna_sctp_rejected_over_cap_total` | counter | Refused at `max_connections`. |
| `turna_sctp_rejected_per_ip_total` | counter | Refused at `max_connections_per_ip`. |
| `turna_sctp_rejected_rate_limit_total` | counter | Refused by `max_associations_per_sec_per_ip`, before any per-association work. Distinct from `rejected_per_ip`, which caps *concurrent* associations: a source that associates and drops in a loop trips this one and never that one. |
| `turna_sctp_idle_timeouts_total` | counter | Closed by `read_timeout_secs`. |
| `turna_sctp_framing_errors_total` | counter | Invalid or over-sized TURN-over-stream framing. Same codec as TURN-over-TCP. |
| `turna_sctp_accept_errors_total` | counter | `accept()` errors survived without stopping the listener (e.g. `EMFILE`). Non-zero used to be impossible here for the wrong reason: a single such error returned from the accept loop and took the listener down until restart. |
| `turna_sctp_send_dropped_total` | counter | Outbound frames dropped because the per-association channel was full or gone. Non-zero means a client lost relayed data. Previously discarded without a counter, so this was invisible. |
| `turna_sctp_bytes_rx_total` / `turna_sctp_bytes_tx_total` | counter | Bytes read from / written to clients. |
| `turna_sctp_readiness` | gauge | 0=starting, 1=ready, 2=degraded, 3=draining. `starting` while SCTP is disabled or not built. |

#### DTLS (`[turn.dtls]`)

| metric | type | meaning |
|--------|------|---------|
| `turna_dtls_active_sessions` | gauge | Live sessions. |
| `turna_dtls_sessions_total` | counter | Sessions admitted. |
| `turna_dtls_rejected_over_cap_total` | counter | Refused at `max_sessions`. |
| `turna_dtls_rejected_per_ip_total` | counter | Refused at `max_sessions_per_ip`. |
| `turna_dtls_closed_total` | counter | Sessions closed. |
| `turna_dtls_idle_timeouts_total` | counter | Closed by `idle_timeout_secs`. |
| `turna_dtls_bytes_rx_total` / `turna_dtls_bytes_tx_total` | counter | Decrypted / encrypted bytes. |
| `turna_dtls_outbound_dropped_total` | counter | Egress queue full (drop-newest). |
| `turna_dtls_outbound_oversize_total` | counter | Datagram exceeded `mtu` and was dropped — raise `[turn.dtls].mtu`. |
| `turna_dtls_accept_timeouts_total` | counter | Handshakes abandoned at `accept_timeout_secs`. Counts accepts *we* gave up on, not stack-level handshake failures. See the note below on why this metric exists. |
| `turna_dtls_handshake_failures_total` | counter | Handshakes that failed. **`demux = true` only** — zero on the default path, where a failure is not observable (see below). |
| `turna_dtls_inbound_dropped_total` | counter | **`demux = true` only.** Datagrams dropped because one peer's inbound queue was full. The handshake retransmits; a live session that cannot keep up must not stall the demux loop for everyone else. |
| `turna_dtls_rejected_rate_limit_total` | counter | **`demux = true` only.** Handshakes refused by `max_handshakes_per_sec_per_ip`, before any DTLS state exists. |
| `turna_dtls_cert_reloads_total` | counter | **`demux = true` only.** Successful certificate hot-reloads; new sessions get the new material, live ones are untouched. |
| `turna_dtls_cert_reload_failures_total` | counter | **`demux = true` only.** Failed reloads; the previous certificate stays in service. |

**On `turna_dtls_handshake_failures_total`, and why it depends on `demux`.** This
document previously said the metric deliberately did not exist, and on the default
path that is still the right description: `webrtc_dtls::listener::accept()` runs the
whole handshake inside the stack, below the point the server observes it, so a
failure never reaches this layer and no counter here could be honest.

`[turn.dtls] demux = true` changes that. On the demux path turna owns the UDP socket
and runs each handshake in its own task, so a failure happens *in our code* and the
counter is a real observation. Consequences for a dashboard:

- With `demux = false` (the default), the metric reads `0` always. Do not alert on
  it, and do not read `0` as "no failures".
- With `demux = true`, alert on it normally.

Independent of `demux`, `turna_dtls_accept_timeouts_total` **is** always meaningful:
it counts handshakes the listener abandoned at `accept_timeout_secs`. That bound
exists because of an upstream liveness bug ([webrtc-rs/webrtc#614](https://github.com/webrtc-rs/webrtc/issues/614)):
`accept()` has no timeout of its own, so before the bound a single peer that started
a handshake and went silent parked the accept loop and DTLS served **nobody** — with
the socket bound, the process healthy and `turna_dtls_readiness` still reading
`1`. If this counter moves on the default path, remember that accepts there are
serial, so a sustained rate means new-session throughput is degraded one timeout
window at a time.

#### QUIC / WebTransport (`[turn.quic]`)

| metric | type | meaning |
|--------|------|---------|
| `turna_quic_active_sessions` | gauge | Live sessions. |
| `turna_quic_sessions_total` / `turna_quic_closed_total` | counter | Sessions admitted / closed. |
| `turna_quic_datagrams_rx_total` / `turna_quic_datagrams_tx_total` | counter | Media path (unreliable datagrams). |
| `turna_quic_streams_opened_total` | counter | Client-opened bidi streams (control path). |
| `turna_quic_control_bytes_tx_total` | counter | Bytes written on control streams. |
| `turna_quic_send_errors_total` | counter | Outbound send failures, including a full per-session egress queue. |
| `turna_quic_handshake_failures_total` | counter | Connections/sessions that failed before becoming usable. |
| `turna_quic_control_dropped_no_stream_total` | counter | Control responses with no open bidi stream to answer on (client framing problem). |
| `turna_quic_rejected_over_cap_total` / `turna_quic_rejected_per_ip_total` | counter | Refused at `max_sessions` / `max_sessions_per_ip`. On the WebTransport path this happens **before** the handshake. |
| `turna_quic_cert_reloads_total` | counter | Successful certificate hot-reloads. Both paths: `Endpoint::reload_config` on WebTransport, `Endpoint::set_server_config` on raw QUIC. |
| `turna_quic_cert_reload_failures_total` | counter | Failed reloads; the previous certificate stays in service. |
| `turna_quic_rejected_rate_limit_total` | counter | Handshakes refused by the per-IP rate limiter, before any handshake work. |
| `turna_quic_migrations_total` | counter | Observed client address changes. A steady non-zero rate is normal on mobile networks; a spike with no session growth can be address spoofing. |

#### Per-listener readiness

`turna_transport_readiness`, `turna_tls_readiness`, `turna_dtls_readiness` and
`turna_quic_readiness` use the same encoding as `turna_backend_readiness`
(`0`=starting, `1`=ready, `2`=degraded, `3`=draining). Each listener gauge
follows whether its socket is bound, so `2` means that listener died while the
process kept running — worth alerting on, because `/ready` may still be green.

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

# An encrypted listener died while the process lives (/ready may still be green)
turna_tls_readiness == 2 or turna_dtls_readiness == 2 or turna_quic_readiness == 2

# TURNS certificate rotation is not being picked up
rate(turna_tls_cert_reload_failures_total[15m]) > 0

# DTLS mtu is below the media path in use — one-way media
rate(turna_dtls_outbound_oversize_total[5m]) > 0

# DTLS handshakes being abandoned at the accept bound. On the default path accepts
# are serial, so a sustained rate means new-session throughput is degraded — and
# before that bound existed, one silent peer stopped DTLS entirely.
rate(turna_dtls_accept_timeouts_total[5m]) > 0
```

Encrypted-transport rules live in `docs/alerts/transport-backends.yml`, with
per-alert operator response in `docs/runbooks/encrypted-transports.md`.

### Series not yet described here

`scripts/check-doc-claims.sh` asserts that every metric the health crate exports
appears in this file, and reports **47 series that predate that check**, across five
families: `turna_afxdp_*`, `turna_uring_*`, `turna_command_log_*`,
`turna_relay_route_*`, `turna_user_limits_*`, plus `turna_processor_panics_total`
and `turna_management_readiness`. They are exported and scrapeable; they are simply
undocumented, so treat a `0` from any of them as "not described here" rather than
"nothing happening".

They sit on an explicit allowlist in that script rather than being skipped quietly.
The allowlist is by prefix, which means a *new* metric inside one of those families
would also pass unnoticed — so remove a family from the list as it gets documented,
and do not add prefixes to silence a new subsystem.

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
