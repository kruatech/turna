# Configuration reference

Every section of `turn.toml` and every `TURNA_*` env variable explained.

## How values are resolved

1. `turn.toml` is read from disk.
2. **`${VAR}`** placeholders are replaced with the named env variable.
   `${VAR:-default}` provides a fallback if the env var is unset.
3. **`file:///path`** values are replaced with the trimmed contents of
   that file. Useful for systemd `LoadCredential`, Kubernetes mounted
   secret volumes, or HashiCorp Vault agent files.
4. The resulting TOML is parsed and validated.
5. If validation fails, the process exits with a non-zero code and a
   message explaining what's wrong.

The same `turn.toml` file can therefore serve dev (no env, defaults
used) and production (env overrides + `production = true`).

## Top-level

| TOML key       | Type | Default | Notes |
|----------------|------|---------|-------|
| `production`   | bool | `false` | When `true`, validation refuses placeholder secrets and empty `external_ip`. Can also be set via `TURNA_PRODUCTION=true|1|yes|on`. |

## `[turn]`

| TOML key      | ENV               | Default          | Notes |
|---------------|-------------------|------------------|-------|
| `listen`      | `TURNA_LISTEN_ADDR` | `0.0.0.0:3478`   | UDP and TCP bind. |
| `external_ip` | `TURNA_EXTERNAL_IP` | `""`             | Public IP advertised to clients. **Required** in production. |
| `realm`       | `TURNA_REALM`       | `"turna"`     | Auth realm. Must match clients' realm. |

### `[turn.auth]`

| Key             | ENV                  | Default                    | Notes |
|-----------------|----------------------|----------------------------|-------|
| `shared_secret` | `TURNA_SHARED_SECRET`  | `"change-me-in-production"` | Used for time-limited credentials. Fatal in production if left at default. |
| `token_ttl`     | —                    | `86400`                    | Max lifetime of a time-limited credential (seconds). |
| `static_users`  | per-user             | `[]`                       | Array of `{username, password}`. When non-empty, `AuthMode::LongTerm` is used instead of shared-secret. |

### `[turn.relay]`

| Key               | Default | Notes |
|-------------------|---------|-------|
| `min_port`        | `49152` | Lower bound of the relay port range. |
| `max_port`        | `65535` | Upper bound. |
| `max_allocations` | `50000` | Hard cap on simultaneous allocations. |

### `[turn.observability]`

| Key                    | ENV                | Default | Notes |
|------------------------|--------------------|---------|-------|
| `otlp_endpoint`        | `TURNA_OTLP_ENDPOINT`| `""`    | OTLP gRPC endpoint, e.g. `http://otel-collector:4317`. Empty disables OTel export. |
| `trace_sample_rate`    | —                  | `0.01`  | Fraction of spans sampled. Errors and `Allocate` are always sampled. |
| `json_logs`            | —                  | `false` | Structured JSON logs (recommended for production log ingestion). |
| `max_spans_per_second` | —                  | `1000`  | Hard cap on tracing throughput. |

## `[signaling]`

The coturn-style HTTP credentials server. Only needed if your client
SDK uses that protocol.

| Key                  | ENV                  | Default              |
|----------------------|----------------------|----------------------|
| `listen`             | `TURNA_SIGNALING_ADDR` | `0.0.0.0:9001`       |
| `turn_url`           | `TURNA_TURN_URL`       | `turn:127.0.0.1:3478` |
| `turn_shared_secret` | `TURNA_SHARED_SECRET`  | (same as `[turn.auth]`) |

## `[health]`

| Key      | ENV               | Default          |
|----------|-------------------|------------------|
| `listen` | `TURNA_HEALTH_ADDR` | `0.0.0.0:9090`   |

Exposes `GET /health`, `/status`, `/metrics`.

## `[cluster]`

Multi-node mode. Leave at defaults for single-node operation.

| Key           | ENV            | Default     |
|---------------|----------------|-------------|
| `node_id`     | `TURNA_NODE_ID`  | `"node-1"`  |
| `gossip_port` | —              | `7946`      |
| `seeds`       | —              | `[]`        |

### `[cluster.backend]`

| Key      | ENV                | Default   | Notes |
|----------|--------------------|-----------|-------|
| `type`   | `TURNA_BACKEND_TYPE` | `"memory"` | `memory` or `tarantool`. |
| `uri`    | `TURNA_BACKEND_URI`  | `""`      | `host:port` for Tarantool. |

**Tarantool authentication is not yet wired through this config.** See
the TODO note in `deploy/turn.toml` and in `TODO.md`. Workaround: place
Tarantool on a private network and rely on network-level access
controls.

### `[cluster.persistence]`

Write-behind persistence of allocation state. See [CLUSTER.md](CLUSTER.md)
for the conceptual model.

| Key                | ENV                     | Default      | Notes |
|--------------------|-------------------------|--------------|-------|
| `mode`             | `TURNA_PERSISTENCE_MODE`  | `"disabled"` | `"disabled"` or `"write_behind"`. |
| `channel_capacity` | —                       | `65536`      | Bounded mpsc; drops on overflow. |
| `batch_max_size`   | —                       | `256`        | Flush after this many events. |
| `batch_max_delay_ms` | —                     | `100`        | Flush at most this often. |

## `[management]`

| Key      | ENV             | Default            |
|----------|-----------------|--------------------|
| `listen` | `TURNA_GRPC_ADDR` | `127.0.0.1:5350`   |

gRPC ops API. Bound to localhost by default. Expose via firewall only
to operators / dashboard hosts.

## `[grpc]` (TLS for the management API)

TLS configuration for the gRPC API served by `turna-control-plane`.

```toml
[grpc]
tls_mode = "disabled"   # "disabled" | "tls" | "mtls"
tls_cert = ""           # path to server cert PEM (required for tls/mtls)
tls_key  = ""           # path to server private-key PEM (required for tls/mtls)
tls_ca   = ""           # path to CA cert PEM (required for mtls)
```

| Key        | ENV                  | Default      | Notes |
|------------|----------------------|--------------|-------|
| `tls_mode` | `TURNA_GRPC_TLS_MODE`  | `"disabled"` | `"disabled" \| "tls" \| "mtls"`. |
| `tls_cert` | `TURNA_GRPC_TLS_CERT`  | `""`         | Path to server cert PEM. Required when `tls_mode != "disabled"`. |
| `tls_key`  | `TURNA_GRPC_TLS_KEY`   | `""`         | Path to server private-key PEM. Required when `tls_mode != "disabled"`. |
| `tls_ca`   | `TURNA_GRPC_TLS_CA`    | `""`         | Path to CA cert PEM. Required for `tls_mode = "mtls"`. |

Resolution order: **env wins when non-empty**, otherwise the value
from `turn.toml`, otherwise the default. This lets you ship a
committed `turn.toml` with the TLS *shape* (mode + CA path) and
override only per-host paths via env at deploy time.

**Never** put PEM contents into env variables. The cells above are
file paths, not PEM bodies.

Mode meanings:

- **`disabled`** — plaintext. The production validator refuses this
  combination unless `management.listen` is bound to `127.0.0.1` /
  `::1`. Use only when the gRPC API is reachable from the local host.
- **`tls`** — server presents a cert; clients verify the server.
  Adequate when the network is trusted but you want encryption in
  transit.
- **`mtls`** — both server and client present certs signed by `tls_ca`.
  Recommended for any deployment where the control plane is reachable
  beyond `localhost`. See [MTLS.md](MTLS.md) for the full setup guide.

The control-plane checks that the configured PEM files exist at
startup. A missing file is fatal, not a silent fall-through to
plaintext.

## How to inspect the loaded config

There's no built-in `--dump-config` flag today (planned — see TODO.md).
For now, the easiest way to see what got loaded is the startup log:

```
INFO turna_config: config loaded and validated path=/etc/turna/turn.toml
INFO turna: starting listen=0.0.0.0:3478 realm=turna
```

If you see `WARN` lines about defaults, something in the file or env is
not what you expected.
