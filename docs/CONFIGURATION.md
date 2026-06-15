# Turna configuration reference

`turna-node` takes a single TOML config path as its first argument:

```bash
turna-node /etc/turna/turn.toml
```

Every section uses `#[serde(deny_unknown_fields)]` — an unknown key is a hard
error, not a warning. All sections have defaults, so a minimal config is short.
Secrets support `${VAR}` / `${VAR:-default}` and `file:///path` substitution.

This document covers the transport-relevant sections. Keys, defaults and
constraints below are taken from `crates/config/src/lib.rs`.

---

## `[turn]`

| key | type | default | notes |
|-----|------|---------|-------|
| `listen` | socket addr | `0.0.0.0:3478` | UDP listen address (IANA STUN/TURN port). |
| `external_ip` | string | `""` | Public IP advertised to clients. **Required in production** and must parse as a valid IPv4/IPv6 address. |
| `realm` | string | `"turna"` | Authentication realm. |
| `transport` | enum | `tokio` | Datapath backend: `tokio` \| `io_uring` \| `af_xdp` \| `auto` (see below). |

### `transport` values

- `tokio` — epoll + `recvmmsg`/`sendmmsg`. Default, safest, all platforms.
- `io_uring` — Linux io_uring datapath. Requires a binary built with
  `--features io-uring`; fails fast at startup if io_uring is unavailable.
- `af_xdp` — AF_XDP ring datapath. Requires `--features af-xdp`, Linux,
  `CAP_NET_RAW`, and an external XDP program steering traffic to the bound NIC
  queue. Never auto-selected.
- `auto` — io_uring when available at runtime, else tokio. Opt-in (dev/bench).

---

## `[turn.auth]`

| key | type | default | notes |
|-----|------|---------|-------|
| `shared_secret` | string | (built-in placeholder) | coturn-style `lt-cred-mech` (time-limited credentials). |
| `token_ttl` | u64 | `86400` | Token lifetime, seconds. |
| `static_users` | array of `{ username, password }` | `[]` | Long-term static credentials. |

Use **one** of: `static_users` (long-term) or `shared_secret` (time-limited).

```toml
[turn.auth]
static_users = [{ username = "alice", password = "s3cret" }]
# or:
# shared_secret = "${TURNA_SHARED_SECRET}"
```

---

## `[health]`

| key | type | default | notes |
|-----|------|---------|-------|
| `listen` | socket addr | `0.0.0.0:9090` | Serves `/health`, `/ready`, `/metrics`, `/status`, `/cluster`. |

The startup validator rejects a `[health].listen` port that collides with
another service (e.g. a management port already bound to `9090`); pick a free
port such as `9091` in that case.

### Endpoints

- `GET /health` — liveness. `200 ok`, or `503` while draining.
- `GET /ready` — readiness. `200 ready` only when the node is in the `Ready`
  state and not draining; `503` otherwise (`not ready` / `draining`).
- `GET /metrics` — Prometheus text exposition.

---

## `[turn.io_uring]`

Used only when `transport = "io_uring"`.

| key | type | default | notes |
|-----|------|---------|-------|
| `relay_socket_capacity_per_worker` | usize | `256` | Max relay sockets (allocations) per io_uring worker. Hard-capped at **1024** (16-bit msghdr index packed into the CQE user_data). |

---

## `[turn.dtls]`

TURN over DTLS (RFC 7350). Disabled by default. Requires `--features dtls`.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the DTLS listener. |
| `listen` | socket addr | `0.0.0.0:5349` | IANA TURNS/DTLS port. |
| `cert_path` | path | `/etc/turna/tls/cert.pem` | PEM certificate. Must be **readable** — an unreadable path aborts startup (fail-fast). |
| `key_path` | path | `/etc/turna/tls/key.pem` | PEM private key. Must be readable. |
| `max_sessions` | usize | `10000` | Post-handshake admission cap (`0` = unlimited). |
| `idle_timeout_secs` | u64 | `300` | Per-session idle timeout. |
| `mtu` | usize | `1200` | Application record MTU; caps outbound TURN responses to avoid IP fragmentation. |
| `outbound_queue_capacity` | usize | `1024` | Bounded per-session egress queue. When full, the **newest** outbound datagram is dropped (counted as `turna_dtls_outbound_dropped_total`) rather than blocking the relay path. |

### Certificate requirements

The DTLS stack negotiates `ECDHE-ECDSA-*` cipher suites, so the certificate
key **must be ECDSA (P-256)** — an RSA key will load but no cipher will
negotiate. Generate one with:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=turn.local"
```

---

## `[turn.af_xdp]`

AF_XDP ring datapath. Used only when `transport = "af_xdp"`. Requires
`--features af-xdp`, Linux, `CAP_NET_RAW`, and an external XDP program steering
the chosen NIC queue (see `docs/runbooks/af-xdp.md`). **Experimental** — see the
support tier in `docs/compatibility/transport-backends.md`.

| key | type | notes |
|-----|------|-------|
| `interface` | string | NIC name, e.g. `eth0`. |
| `queue_id` | u32 | NIC queue id to bind the AF_XDP socket to. |
| `frame_count` | u32 | UMEM frame count. |
| `frame_size` | u32 | UMEM frame size, bytes. Must be ≥ 2048 and ≥ MTU+14. |
| `fill_ring_size` | u32 | Fill ring size (power of two). |
| `comp_ring_size` | u32 | Completion ring size. |
| `rx_ring_size` | u32 | RX ring size. |
| `tx_ring_size` | u32 | TX ring size. |
| `zero_copy` | bool | Zero-copy mode (requires driver support). |
| `need_wakeup` | bool | Use the `NEED_WAKEUP` flag. |
| `src_mac` | string | Source MAC for TX frames. Empty → placeholder until neighbor resolution lands. |
| `dst_mac` | string | Next-hop (gateway) MAC. Empty → placeholder. |

A startup preflight validates ring geometry (power-of-two, `frame_size ≥ 2048`),
that the interface exists and is up, that the queue exists, `frame_size ≥ MTU+14`,
and `CAP_NET_RAW`. Any failure aborts startup.

---

## Metrics (Prometheus)

Exposed on `[health].listen` `/metrics`. Transport-relevant series:

- io_uring: `turna_uring_workers`, `turna_uring_cqe_drained_total`,
  `turna_uring_cqe_batches_total`, `turna_uring_cqe_max_batch`,
  `turna_uring_sq_push_failed_total`, `turna_uring_sq_len`,
  `turna_uring_sq_capacity`, `turna_uring_cq_len`,
  `turna_uring_buffers_available`, `turna_uring_relay_capacity_exhausted_total`.
- AF_XDP: `turna_afxdp_rx_frames_total`, `turna_afxdp_tx_frames_total`,
  `turna_afxdp_rx_bytes_total`, `turna_afxdp_tx_bytes_total`,
  `turna_afxdp_parse_drops_total`, `turna_afxdp_tx_drops_total`,
  `turna_afxdp_relay_ports_registered`, `turna_afxdp_umem_free_frames`.
- DTLS: `turna_dtls_active_sessions`, `turna_dtls_sessions_total`,
  `turna_dtls_rejected_over_cap_total`, `turna_dtls_closed_total`,
  `turna_dtls_idle_timeouts_total`, `turna_dtls_bytes_rx_total`,
  `turna_dtls_bytes_tx_total`, `turna_dtls_outbound_dropped_total`.
- Readiness: `turna_backend_readiness` (`0`=starting, `1`=ready, `2`=degraded,
  `3`=draining).

Alert rules: `docs/alerts/transport-backends.yml`.
