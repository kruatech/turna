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

## Relayed address family — IPv4 by default, IPv6 opt-in

Independent of any listener. Set by `[turn] external_ip6`:

| `external_ip6` | `REQUESTED-ADDRESS-FAMILY = IPv4` (or absent) | `= IPv6` |
|---|---|---|
| empty (default) | relay socket binds `0.0.0.0`, advertises `external_ip` | `440 Address Family not Supported` |
| an IPv6 literal | unchanged | relay socket binds `[::]`, advertises `external_ip6` |

Rules that hold in both modes:

- One allocation serves **one** family. A peer in the other family is refused with
  `443 Peer Address Family Mismatch` on CreatePermission and ChannelBind (RFC 6156
  §4.2); a Send indication with a mismatched peer is dropped and counted, since an
  indication has no error response.
- `RESERVATION-TOKEN` and `REQUESTED-ADDRESS-FAMILY` are mutually exclusive per RFC
  8656 §7.2 — a request carrying both gets `400`.
- Putting an IPv6 literal in `external_ip` does **not** enable IPv6 relaying; it
  only changes what is advertised for v4-family allocations. `external_ip6` is the
  key that matters, and validation rejects a v4 literal in it.
- RFC 6062 **TCP** relay allocations stay IPv4-only regardless of `external_ip6`:
  the TCP relay datapath has no v6 path, so an IPv6 family request there is still
  `440`.
- `ADDITIONAL-ADDRESS-FAMILY` (one Allocate asking for both families at once) is
  **not** implemented — see `docs/protocol-gap.md` → IPv6.

The relay port pool is shared: a given port number is bound in exactly one family
at a time, so enabling IPv6 does not change port accounting or capacity.

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
| `max_sessions_per_ip` | usize | `0` | Per-source-IP session cap (`0` = unlimited). Anti slot-exhaustion; rejections counted as `turna_dtls_rejected_per_ip_total`. |
| `accept_timeout_secs` | u64 | `10` | Upper bound on one DTLS `accept()`, i.e. on a single handshake. `0` disables it. **Liveness guard, not tuning:** `webrtc-dtls` runs the whole handshake inline inside `accept()` with no timeout of its own ([webrtc-rs/webrtc#614](https://github.com/webrtc-rs/webrtc/issues/614)), so one peer that starts a handshake and goes silent parks the accept loop forever — DTLS stops serving everyone while the socket stays bound and `turna_dtls_readiness` still reads Ready. On timeout the handshake is abandoned and counted (`turna_dtls_accept_timeouts_total`). Keep it comfortably above real handshake latency, or a slow client is dropped. |
| `demux` | bool | `false` | Own the UDP socket instead of `webrtc_dtls::listen()`. `listen()` runs handshakes **serially** inside `accept()` ([#614](https://github.com/webrtc-rs/webrtc/issues/614)), which forces three compromises: caps apply only *after* the crypto, a handshake rate limit has nowhere to live, and the certificate is fixed at bind time. `demux = true` fixes all three — one task per handshake, admission before any DTLS state exists, live certificate reload. Opt-in because it replaces the path that has recorded verification (`docs/dtls/`). |
| `max_handshakes_per_sec_per_ip` | u32 | `0` | Per-source-IP handshake **rate** limit (`turna_dtls_rejected_rate_limit_total`). **Requires `demux = true`** — startup fails otherwise, rather than silently doing nothing. |
| `handshake_burst_per_ip` | u32 | `0` | Burst allowance. `0` = twice the rate. |
| `cert_reload_secs` | u64 | `0` | Poll cert/key and hot-reload for new sessions (`turna_dtls_cert_reloads_total`). **Requires `demux = true`**; on the stock path the listener can only warn that the files changed. |
| `idle_timeout_secs` | u64 | `300` | Per-session idle timeout. Must be **> 0** (a zero timeout would close every session immediately) — validated at startup. |
| `mtu` | usize | `1200` | Application record MTU, valid range **576..65535**. An outbound datagram larger than this is **dropped** and counted as `turna_dtls_outbound_oversize_total`, rather than sent and left to IP fragmentation (widely dropped, and a silent one-way media failure). The receive buffer is sized independently to a full DTLS plaintext fragment (16 KiB). |
| `outbound_queue_capacity` | usize | `1024` | Bounded per-session egress queue. When full, the **newest** outbound datagram is dropped (counted as `turna_dtls_outbound_dropped_total`) rather than blocking the relay path. |

`cert_path`/`key_path` may **both** be empty as an explicit opt-in to an
ephemeral self-signed certificate (dev/test only; the node logs a warning).
Setting only one of the two is a configuration error. A configured but
unloadable certificate aborts startup rather than silently downgrading.

Enabling this section on a binary built without `--features dtls` is a **startup
error**, not a warning — a configured listener is never silently absent.

DTLS has **no certificate hot-reload**: the stack fixes its configuration at
listen time, so swapping material would mean rebinding the socket and dropping
every live session. The node watches the files and logs a loud warning when they
change; picking up a rotated certificate needs a restart. (TURNS, below, does
reload without one.)

### Certificate requirements

The DTLS stack negotiates `ECDHE-ECDSA-*` cipher suites, so the certificate
key **must be ECDSA (P-256)** — an RSA key will load but no cipher will
negotiate. Generate one with:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=turn.local"
```

---

## `[tls]` — TURNS (TURN over TLS-over-TCP)

**Root-level** section (not `[turn.tls]`). For clients on UDP-blocked networks.
Requires `--features tls`. Maturity: **beta**.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the TURNS listener. |
| `listen` | socket addr | `0.0.0.0:5349` | IANA TURNS port (TCP). |
| `cert_path` | path | `/etc/turna/tls/cert.pem` | PEM certificate chain. |
| `key_path` | path | `/etc/turna/tls/key.pem` | PEM private key (PKCS#8 / PKCS#1 / SEC1). |
| `max_frame_size` | usize | `65536` | Max framed STUN/ChannelData message. An over-sized or invalid frame closes the connection and increments `turna_tls_framing_errors_total`. |
| `handshake_timeout_secs` | u64 | `5` | TLS handshake deadline (`turna_tls_handshake_timeouts_total`). |
| `read_timeout_secs` | u64 | `300` | Per-connection idle read timeout (`turna_tls_idle_timeouts_total`). |
| `max_connections` | usize | `10000` | Global connection cap (`turna_tls_rejected_over_cap_total`). |
| `max_connections_per_ip` | usize | `0` | Per-source-IP cap (`0` = unlimited). Without it a single source can occupy every slot of `max_connections` (`turna_tls_rejected_per_ip_total`). |
| `cert_reload_secs` | u64 | `30` | Re-read `cert_path`/`key_path` on this interval and pick up a rotated certificate without a restart. New connections use the new material; established ones keep their session. A failed reload keeps the previous certificate in service and increments `turna_tls_cert_reload_failures_total`. `0` disables reloading. |
| `enable_alpn` | bool | `true` | Advertise ALPN `stun.turn`. |
| `max_handshakes_per_sec_per_ip` | u32 | `0` | Per-source-IP handshake **rate** limit (`0` = unlimited), `turna_tls_rejected_rate_limit_total`. `max_connections_per_ip` bounds only *concurrent* connections: a source that connects and drops in a loop never trips it while still costing a TLS handshake each time. Refused before the handshake. |
| `handshake_burst_per_ip` | u32 | `0` | Burst allowance for the rate limit. `0` = twice the rate. |
| `alpn_required` | bool | `false` | RFC 7443 strict mode: refuse a client that negotiates no ALPN (`turna_tls_alpn_rejected_total`). Requires `enable_alpn = true` — the combination `alpn_required = true` with `enable_alpn = false` is a startup error. Default `false` = compatible. |
| `client_ca` | path | `""` | PEM bundle of CAs allowed to sign a TURNS **client** certificate. Empty = no client-certificate verification, which is what a public TURN server wants. Enables mTLS on the TURNS listener only — the management plane keeps its own `[grpc] tls_ca`. |
| `require_client_cert` | bool | `false` | Refuse a client that presents no certificate. Requires `client_ca`; the combination `require_client_cert = true` with an empty `client_ca` is a startup error. `false` lets an unauthenticated client through TLS and leaves it to the long-term credential check, which is what makes a staged rollout across an existing fleet possible. **No CRL/OCSP** — same deliberate position as the management plane (`docs/MTLS.md` → Revocation); revoke by rotating the CA. |

Lifecycle notes: the listener drains cooperatively on SIGTERM (it stops
accepting and lets established connections close themselves), and a transient
`accept()` failure such as `EMFILE` is counted
(`turna_tls_accept_errors_total`) with backoff instead of terminating the
listener. When a control connection closes, its allocation is released
immediately — the connection *is* the allocation's 5-tuple — instead of pinning
a relay port until the lifetime expires.

---

## `[turn.tcp_relay]` — RFC 6062 TCP relay allocations

Lets a client relay **TCP** to peers (`CONNECT` / `CONNECTION-BIND`) instead of
UDP. Disabled by default. **Requires `[tls]` enabled:** RFC 6062 §4.1 mandates a
TCP/TLS control connection, and an Allocate with `REQUESTED-TRANSPORT = 6`
arriving over UDP, DTLS or QUIC is refused with `400 Bad Request`.

> **Refused in production.** With `production = true`, config validation rejects
> `enabled = true` and the node does not start. The feature is implemented and
> testable with `production = false`; the gate lifts once interop and
> pipelined-client hardening are done (`docs/protocol-gap.md` → TCP relay).

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Accept `REQUESTED-TRANSPORT = 6` on Allocate. |
| `connect_timeout_secs` | u64 | `30` | Outbound connect deadline; failure or timeout answers `447`. |
| `idle_timeout_secs` | u64 | `30` | Reap a peer connection that is connected but never `ConnectionBind`-ed. |
| `max_per_allocation` | usize | `10` | Concurrent peer connections per allocation. |
| `max_total` | usize | `50000` | Concurrent peer connections overall (`446`/`508` beyond it). |
| `buffer_size` | usize | `16384` | Per-direction relay buffer. |

A `ConnectionBind` must be authenticated with the **same credentials** as the
`CONNECT` (or the allocation owner, for peer-initiated connections) —
`CONNECTION-ID` is a sequential, guessable value, so this ownership check is
what prevents one authenticated client hijacking another's pending connection.

---

## `[turn.quic]` — QUIC / WebTransport

Requires `--features quic` (raw QUIC datapath) or `--features web-transport`
(browser HTTP/3 CONNECT; implies `quic`). Maturity: **experimental**.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the listener. |
| `web_transport` | bool | `true` | `true` = WebTransport over HTTP/3; `false` = raw QUIC. Needs `--features web-transport` when `true`. |
| `listen` | socket addr | `0.0.0.0:5350` | UDP. Numerically collides with `[management].listen` (TCP) — different protocols, so the binds do not conflict. |
| `cert_path` / `key_path` | path | `/etc/turna/tls/…` | Same PEM material as `[tls]` by default. |
| `max_bi_streams` | u64 | `256` | Concurrent bidi streams per connection. **Raw QUIC only.** |
| `max_uni_streams` | u64 | `256` | Concurrent uni streams per connection. **Raw QUIC only.** |
| `enable_datagrams` | bool | `true` | QUIC datagrams (RFC 9221) for media. **Raw QUIC only.** |
| `max_datagram_size` | usize | `1200` | Sizes the datagram receive buffer. **Raw QUIC only.** |
| `idle_timeout_secs` | u64 | `30` | Connection idle timeout. **Raw QUIC only.** |
| `keep_alive_secs` | u64 | `10` | Keep-alive interval. |
| `alpn` | list | `["stun.turn"]` | **Raw QUIC only** — WebTransport negotiates `h3` itself, so this key is inert when `web_transport = true`. |
| `max_sessions` | usize | `10000` | Session cap (`0` = unlimited), `turna_quic_rejected_over_cap_total`. Enforced **pre**-handshake on the WebTransport path, post-handshake on raw QUIC. |
| `max_sessions_per_ip` | usize | `0` | Per-source-IP cap (`0` = unlimited), `turna_quic_rejected_per_ip_total`. Same timing as above. |
| `cert_reload_secs` | u64 | `30` | Poll `cert_path`/`key_path` and hot-reload the certificate without dropping live sessions. Works on **both** paths (`Endpoint::reload_config` on WebTransport, `Endpoint::set_server_config` on raw QUIC); only new sessions see the new material. `0` disables. |
| `max_handshakes_per_sec_per_ip` | u32 | `0` | Per-source-IP handshake **rate** limit (`0` = unlimited). Complements `max_sessions_per_ip`, which only bounds *concurrent* sessions: a source that opens and drops sessions in a loop never trips a concurrency cap while still costing a handshake each time. Checked before the handshake on both paths (`turna_quic_rejected_rate_limit_total`). |
| `handshake_burst_per_ip` | u32 | `0` | Burst allowance for the rate limit. `0` = twice the rate, so a page opening several sessions at once is not penalised. |

On the **WebTransport** path (`web_transport = true`) the keys marked *raw QUIC
only* have no effect: reaching the underlying `quinn` server config requires an
API wtransport keeps behind its quinn re-export. The listener names those keys in
a startup warning, so the config never silently looks effective. Session caps,
keep-alive and certificate reload do apply there. Set `web_transport = false` if
you need the transport limits enforced.

Connection migration (the client's address changing mid-session) is detected by
polling the peer address every 2s; the listener re-keys its egress registries and
counts it as `turna_quic_migrations_total`. On the WebTransport path migration can
be disabled at the QUIC layer via the builder; the raw-QUIC path uses quinn's
default. Details: `docs/design/quic-webtransport.md` §7.

Enabling `[turn.quic]` without `--features quic`, or `web_transport = true`
without `--features web-transport`, is a **startup error**.

---

## `[turn.sctp]` — TURN-over-SCTP (experimental)

Client **control** transport over an SCTP association: STUN/TURN framed exactly as
TURN-over-TCP, with the relay socket to the peer staying **UDP**. Requires
`--features sctp` and the host `sctp` kernel module. Disabled by default.

> **No RFC defines SCTP for TURN.** `TRANSPORT_SCTP = 132` is the IANA protocol
> number (RFC 4960), not a standardised TURN relayed-transport value — it names the
> control transport only.
>
> **Refused in production.** `production = true` rejects `enabled = true`.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the SCTP listener. |
| `listen` | socket addr | `0.0.0.0:3478` | No standardised TURN-over-SCTP port. |
| `max_frame_size` | usize | `65536` | Max framed STUN/ChannelData message (shares the TURNS frame codec). |
| `read_timeout_secs` | u64 | `300` | Per-connection idle read timeout. |
| `max_connections` | usize | `10000` | Concurrent SCTP associations. |
| `backlog` | i32 | `1024` | `listen(2)` backlog. |

The control channel is **plaintext** — TLS-over-SCTP is out of scope, so anything
an operator would protect with TURNS is unprotected here. Awkward in containers
(needs the host kernel module) and of low real-world use; `docs/protocol-gap.md`
rates it lowest priority and suggests it may be dropped rather than matured. Only
wired in the tokio backend, not io_uring.

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
  `turna_dtls_rejected_over_cap_total`, `turna_dtls_rejected_per_ip_total`,
  `turna_dtls_closed_total`, `turna_dtls_idle_timeouts_total`,
  `turna_dtls_bytes_rx_total`, `turna_dtls_bytes_tx_total`,
  `turna_dtls_outbound_dropped_total`, `turna_dtls_outbound_oversize_total`.
- TURNS (`[tls]`): `turna_tls_active_connections`,
  `turna_tls_connections_total`, `turna_tls_closed_total`,
  `turna_tls_handshake_failures_total`, `turna_tls_handshake_timeouts_total`,
  `turna_tls_rejected_over_cap_total`, `turna_tls_rejected_per_ip_total`,
  `turna_tls_idle_timeouts_total`, `turna_tls_framing_errors_total`,
  `turna_tls_accept_errors_total`, `turna_tls_bytes_rx_total`,
  `turna_tls_bytes_tx_total`, `turna_tls_cert_reloads_total`,
  `turna_tls_cert_reload_failures_total`.
- QUIC/WebTransport: `turna_quic_active_sessions`, `turna_quic_sessions_total`,
  `turna_quic_closed_total`, `turna_quic_datagrams_rx_total`,
  `turna_quic_datagrams_tx_total`, `turna_quic_streams_opened_total`,
  `turna_quic_control_bytes_tx_total`, `turna_quic_send_errors_total`,
  `turna_quic_handshake_failures_total`,
  `turna_quic_control_dropped_no_stream_total`,
  `turna_quic_rejected_over_cap_total`, `turna_quic_rejected_per_ip_total`,
  `turna_quic_cert_reloads_total`, `turna_quic_cert_reload_failures_total`,
  `turna_quic_rejected_rate_limit_total`, `turna_quic_migrations_total`.
- Readiness: `turna_backend_readiness` (`0`=starting, `1`=ready, `2`=degraded,
  `3`=draining). Per-component gauges use the same encoding:
  `turna_transport_readiness` (primary UDP backend), `turna_tls_readiness`,
  `turna_dtls_readiness`, `turna_quic_readiness` — each follows whether that
  listener's socket is actually bound, so a listener that dies while the process
  survives reads `2`. A disabled listener stays at `0`.
  `turna_management_readiness` is a distinct management-plane sub-signal,
  `ready` only once the mandatory command-log migration phases complete; it does
  not gate the TURN dataplane.

Alert rules: `docs/alerts/transport-backends.yml`.

## Dynamic node runtime configuration

The node-scoped management API exposes a strict dynamic whitelist:

| Field | Unit | Dynamic |
|---|---:|---|
| `max_allocations` | allocations | yes |
| `max_allocations_per_user` | allocations/user | yes |
| `max_bytes_per_sec_per_allocation` | bytes/second | yes |

Every request supplies `node_id`, `idempotency_key`, and `expected_version`.
Proto optional presence distinguishes absent from zero. Zero keeps the existing
config-domain meaning and is validated against production safety policy. A
multi-field request creates one candidate and publishes one immutable snapshot;
readers cannot observe a mixed version. Drain is a separate RPC. Listener,
external IP, relay range, transport/backend/workers, identities, credentials,
secret paths, and production safety flags require restart/redeployment.

`GetConfig(node_id)` returns desired and observed versions/snapshots, status,
last apply error, and update time. It does not mix the control-plane bootstrap
configuration with a node's runtime state.

## User-limit overrides

`set_user_limits` supports global, tenant (`realm` + tenant), and user
(`realm` + tenant + username) subjects. Durable subject keys use
length-prefixed components, so delimiters and Unicode cannot alias identities.
Each field independently uses one of `INHERIT`, `VALUE`, `UNLIMITED`, or
`DISABLED`; `0` is not overloaded to represent all four states.

Resolution order is user → tenant → node runtime defaults → bootstrap defaults.
A finite node ceiling is a hard upper bound: a requested `VALUE` above it, or
`UNLIMITED` on a user/tenant scope, is clamped to the ceiling rather than
honoured. `UNLIMITED` removes only the narrower override; true unlimited
requires the node-wide policy to permit it. The `SetUserLimits` response reports
both the requested intent and the resolved `effective` values, and lists any
clamped fields in `effective.capped_fields` (inherited fields in
`inherited_fields`). Enforcement always uses the effective value.

**Bandwidth is per-allocation.** The policy is selected for a user through
inheritance, but the resulting effective budget is applied separately to each
allocation. Multiple allocations of one user have independent budgets; this is
not an aggregate per-user limiter. Bandwidth is read from the local immutable
cache on the packet path; no Tarantool lookup occurs there.

**Lifetime** effective value is the minimum of the absolute protocol maximum,
the node-wide ceiling, any tenant/user override, and the OAuth/token expiry
chosen at Allocate. A finite requested `max_lifetime_secs` above the node's
absolute ceiling is rejected (`INVALID_ARGUMENT`) before it enters the command
log. `max_lifetime_secs` applies to new Allocate and caps the next Refresh;
reducing it does not forcibly shorten an already-confirmed allocation.

See `docs/MANAGEMENT_API.md` for the exact RPC request/response contract.

## `[cluster.command_log]`

Durable command-log retention and bounded GC for the control-plane. Keys and
defaults are from `crates/config/src/lib.rs` (`CommandLogConfig`).

| key | type | default | notes |
|-----|------|---------|-------|
| `retain_done_secs` | u64 | `604800` (7d) | Retain `done` commands this long after completion. |
| `retain_failed_secs` | u64 | `2592000` (30d) | Retain `failed` commands. |
| `retain_superseded_secs` | u64 | `604800` (7d) | Retain `superseded` commands. |
| `retain_expired_secs` | u64 | `604800` (7d) | Retain `expired` commands. |
| `retain_idempotency_secs` | u64 | `2592000` (30d) | Minimum retention for idempotency records. |
| `sweep_interval_secs` | u64 | `900` (15 min) | GC sweep cadence. `0` disables GC. |
| `batch_size` | usize | `1000` | Max records deleted per batch (bounds per-transaction work). |
| `max_batches_per_sweep` | u32 | `10` | Max batches per sweep; a backlog drains across sweeps. |
| `sweep_jitter_secs` | u64 | `60` | Random jitter added to each sweep start so instances don't sweep in lockstep. |

Invariants:

- Terminal commands are pruned by age **per status**; non-terminal states
  (pending/claimed/running) are **never** TTL-pruned — stuck commands are
  handled by claim reclaim and dead-lettering, not GC.
- Idempotency records are retained independently and, by the GC ordering rule,
  are **never dropped before the command they guard**, regardless of
  `retain_idempotency_secs`. This is what makes a post-GC replay return the
  stored outcome (see `docs/command-log-lease.md`).

## `[cluster.command_log]` — migration

The same bounds drive the bounded, resumable legacy-schema migration
(`commands → idempotency → complete`). See `RELEASE.md` for the upgrade
procedure and `docs/command-log-lease.md` for phase detail.
