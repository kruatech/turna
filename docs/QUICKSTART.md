# Quickstart

Get the current Turna workspace running locally as a TURN/STUN server.

**Prerequisites:** Rust toolchain from `rust-toolchain.toml` (`cargo --version`).

## Build

```sh
cargo build --release
```

Key binaries in the current workspace:

- `target/release/turna-node` — TURN/STUN server (media relay)
- `target/release/turna-control-plane` — gRPC ops API (optional)
- `target/release/turnactl` — management CLI (optional)

There is currently no `turna-signaling` binary or bundled browser demo in this
workspace. The quickstart is intentionally TURN-only so the documented path
matches the repository.

---

## Run the TURN/STUN server

```sh
./target/release/turna-node deploy/turn.toml
```

You'll see expected dev warnings about `shared_secret` and `external_ip`.
That's fine for local use. In production, set `production = true`, provide a
real `TURNA_SHARED_SECRET`, and set `TURNA_EXTERNAL_IP` to the public IP that
clients can reach.

---

## Verify health and metrics

```sh
# Health check
curl -sS http://127.0.0.1:9090/health
# → ok

# Prometheus metrics
curl -sS http://127.0.0.1:9090/metrics | head -20
```

## Verify STUN/TURN behaviour

With coturn tools installed, run a STUN Binding check:

```sh
stunclient 127.0.0.1 -p 3478
```

For an authenticated TURN allocation, use the static user commented in your
config or generate coturn-style time-limited credentials from
`TURNA_SHARED_SECRET`.

---

## Docker Compose

From the repository root:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

Then verify:

```sh
curl -sS http://127.0.0.1:9090/health
curl -sS http://127.0.0.1:9091/-/healthy  # Prometheus, optional
```

---

## Configuration

All defaults are safe for local development. For reference:

| What | Default | Override |
|---|---|---|
| TURN/STUN port | `0.0.0.0:3478` | `TURNA_LISTEN_ADDR` |
| Health/metrics port | `0.0.0.0:9090` | `TURNA_HEALTH_ADDR` |
| gRPC management port | `127.0.0.1:5350` | `TURNA_GRPC_ADDR` |
| Shared secret | `change-me-in-production` | `TURNA_SHARED_SECRET` |
| External IP | _(empty, warns)_ | `TURNA_EXTERNAL_IP` |
| Persistence | disabled | `[cluster.persistence] mode = "write_behind"` |

The annotated config template is at `deploy/turn.toml`.

---

## What's next

- **Deploy to a server** → [DEPLOY.md](DEPLOY.md)
- **Every config knob** → [CONFIGURATION.md](CONFIGURATION.md)
- **Metrics and alerts** → [OBSERVABILITY.md](OBSERVABILITY.md)
- **Multi-node cluster** → [CLUSTER.md](CLUSTER.md)

---

## Troubleshooting

**"address already in use" on port 3478.**
Another TURN server (coturn?) is running.
`sudo lsof -i :3478` to find it; stop it, or override with
`TURNA_LISTEN_ADDR=0.0.0.0:3479`.

**"address already in use" on port 9090.**
Set `TURNA_HEALTH_ADDR=0.0.0.0:9091` and retry.

**TURN allocation succeeds but peers cannot exchange media.**
Make sure the relay UDP port range is reachable. For local Docker bridge tests,
keep `deploy/docker-compose.yml` port range in sync with `[turn.relay]`. For
production, prefer host networking or a load balancer/firewall rule that exposes
the full relay range.

**Remote clients receive an unusable relay address.**
Set `TURNA_EXTERNAL_IP` or `[turn].external_ip` to the public IP of the machine
running `turna-node`.

**"validation: turn.auth.shared_secret is empty".**
You set `TURNA_SHARED_SECRET` to an empty string. Either unset it or set a real
value.

**Process exits with a "validation" error.**
You set `TURNA_PRODUCTION=true` without real secrets and/or `external_ip`.
Generate a secret with `openssl rand -hex 32`, set `TURNA_EXTERNAL_IP`, or unset
`TURNA_PRODUCTION` for local development.


## Runtime management quick check

Runtime mutations are node-scoped durable commands. They require a configured
state backend, a live node heartbeat/incarnation, a non-empty idempotency key,
and the current observed version. The dynamic whitelist is limited to global
allocation count, default per-user allocation count, and
`max_bytes_per_sec_per_allocation` (bytes/second). `set_user_limits` resolves each field through
user → tenant → node runtime defaults → bootstrap defaults. The admin UI keeps
its bearer token only in `sessionStorage`; production mutations without a token
are rejected.
