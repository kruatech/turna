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
| `listen_extra` | array of socket addr | `[]` | Further UDP listen addresses (coturn's repeated `listening-ip`). See [Multiple UDP listeners](#multiple-udp-listeners-listen_extra). |
| `external_ip` | string | `""` | Public IP advertised to clients. **Required in production** and must parse as a valid IPv4/IPv6 address, or as coturn's `PUBLIC/PRIVATE` mapping — see [1:1 NAT](#11-nat-external_ip--publicprivate). |
| `realm` | string | `"turna"` | Authentication realm. |
| `transport` | enum | `tokio` | Datapath backend: `tokio` \| `io_uring` \| `af_xdp` \| `auto` (see below). |

### `transport` values

- `tokio` — epoll + `recvmmsg`/`sendmmsg`. Default, safest, all platforms.
- `io_uring` — supported Linux UDP datapath, opt-in. Requires a binary built with
  `--features io-uring`; fails fast at startup if io_uring is unavailable.
- `af_xdp` — opt-in Linux AF_XDP datapath. Requires `--features af-xdp` and
  privileges to bind XSK sockets and load/attach the embedded selective XDP
  program. Never auto-selected. See [the runbook](runbooks/af-xdp.md).
- `auto` — io_uring when available at runtime, else tokio. Opt-in (dev/bench).

### Multiple UDP listeners (`listen_extra`)

```toml
[turn]
listen       = "198.51.100.20:3478"
listen_extra = ["10.0.0.5:3478", "198.51.100.21:3478"]
```

Every address is served by the same processor, allocation store, rate limiters
and peer filter; each gets its own `SO_REUSEPORT` recv workers. STUN/TURN
responses leave from the socket the request arrived on, and so does relayed
peer→client data for an allocation made through that listener — a client (or its
NAT) that only accepts packets from the address it sent to keeps working.

Rules, all checked at startup:

- **tokio only.** `transport = "io_uring"`, `"af_xdp"` and `"auto"` are refused
  with `listen_extra` set: those backends own a single socket and would leave the
  extra addresses silently unserved.
- No duplicates, and no wildcard address (`0.0.0.0` / `[::]`) on the same port
  as another listener. With `SO_REUSEPORT` the kernel would accept both binds and
  split one address's traffic between them.
- No overlap with the other **UDP** listeners that are enabled — `[turn.dtls]`
  and `[turn.quic]` — on the same port and the same address (or a wildcard on
  either side). TCP listeners (`[health]`, `[management]`, `[tls]`,
  `[turn.tcp]`) and SCTP are other protocols and do not conflict. An address
  that cannot be bound aborts startup.
- **Not combinable with `[turn.migration] enabled = true`** (RFC 8016
  mobility). The socket an allocation's relayed data leaves from is fixed when
  the allocation is created; a mobility re-key moves the allocation to a new
  client address but not to the listener that address uses, so a client that
  moved to another listener would receive Data indications from an address it
  never sent to. Refused at startup rather than half-working.
- The addresses join `listen` in the peer filter's unconditional self-deny.

**Limitation — one allocation per client source address.** Allocations are
keyed by the client's address and port only, not by which listener they arrived
on (as before this key existed). A client that allocates on the primary and on
an extra address *from the same source socket* is talking about one
allocation: the second Allocate gets `437 Allocation Mismatch`, and the
allocation stays bound to the first listener. Use a separate socket (source
port) per server address, which is what ICE agents do anyway.

There is **one relay address per family**: `[turn.relay] bind_ip` / `bind_ip6`
(coturn's `relay-ip`) do not take lists. The relayed address is built from a
single advertised `external_ip` throughout the relay path; per-allocation relay
addresses are a larger change than this key. Run one node per relay address if
you need several.

### 1:1 NAT (`external_ip = "PUBLIC/PRIVATE"`)

For a host that only owns a private address which the provider maps 1:1 onto a
public one (AWS elastic IP, GCP external IP):

```toml
[turn]
listen      = "0.0.0.0:3478"
external_ip = "203.0.113.10/10.0.0.5"   # advertise PUBLIC, relay sockets bind PRIVATE
```

This is shorthand for `external_ip = "203.0.113.10"` plus `[turn.relay] bind_ip
= "10.0.0.5"`, which already expressed the same thing and still works. Checked at
startup: both halves IP literals of the same family, neither unspecified; in
`external_ip` both must be IPv4 (the private half binds the IPv4 relay sockets —
put an IPv6 pair in `external_ip6`, whose private half pins `bind_ip6`); and a
`bind_ip` / `bind_ip6` that names a *different* address than the private half is
an error rather than a silent choice. The private address joins the peer
filter's self-deny, as `bind_ip` does.

---

## `[turn.auth]`

| key | type | default | notes |
|-----|------|---------|-------|
| `shared_secret` | string | (built-in placeholder) | coturn-style `lt-cred-mech` (time-limited credentials). |
| `token_ttl` | u64 | `86400` | Token lifetime, seconds. |
| `static_users` | array of `{ username, password }` | `[]` | Long-term static credentials. |
| `advertise_userhash` | bool | `false` | RFC 8489 username anonymity. When true every nonce carries the §9.2 nonce cookie with "Username anonymity" set, so conforming clients send `USERHASH` instead of `USERNAME`. **Refused** unless the base realm and every tenant use `static_users` (TURN REST / OAuth cannot resolve a hash), and refused together with `[turn.auth.webhook] enabled` (a hash is resolved from the local user table only). A `USERHASH` request is *accepted* on long-term realms whatever this says. A SIGHUP reload that would switch a realm between `static_users` and a shared secret (or back) is refused for that realm and logged — the mechanism, and with it USERHASH eligibility, changes only on restart. |
| `require_binding_auth` | bool | `false` | coturn `secure-stun`. When `true`, a STUN Binding without MESSAGE-INTEGRITY is answered with a 401 challenge; one with credentials must carry a valid NONCE and gets a response signed with the same MESSAGE-INTEGRITY variant. **Leave off** on a node browsers also use as their STUN server: they send Binding unauthenticated and would lose their server-reflexive candidate. Counted in `turna_binding_auth_challenges_total`. |

Use **one** of: `static_users` (long-term) or `shared_secret` (time-limited).
`[turn.auth.webhook]` (below) extends the long-term form with users looked up
on your signalling service.

```toml
[turn.auth]
static_users = [{ username = "alice", password = "s3cret" }]
# or:
# shared_secret = "${TURNA_SHARED_SECRET}"
```

---

## `[turn.auth.webhook]`

Look up long-term users that are not in `static_users` through your signalling
service. **Off by default.** The request/response contract, the signature, the
caching and fail-closed behaviour, and what each transport does while a lookup is
in flight are in **[auth-webhook.md](auth-webhook.md)**.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enabling it makes the base realm long-term (static users first, then the webhook). Refused together with `[turn.auth.oauth]`. |
| `url` | string | `""` | `https://` required; `http://` only with `production = false`. `${VAR}` / `file://` substitution applies. |
| `bearer_token` | string | `""` | Sent as `Authorization: Bearer …`. Masked in `--dump-config`. |
| `signing_secret` | string | `""` | HMAC-SHA256 key for `X-Turna-Signature`. Masked in `--dump-config`. Under `production = true` at least one of this and `bearer_token` is required. |
| `ca_file` | string | `""` | PEM bundle trusted **instead of** the system roots (private CA). An unreadable or empty file stops startup. |
| `timeout_ms` | u64 | `2000` | Whole-request timeout, 1..=10000. A timeout is a failure. |
| `max_concurrency` | usize | `32` | Lookups in flight at once. |
| `queue_depth` | usize | `1024` | Lookups waiting for a slot; beyond it a request fails closed (500). |
| `positive_ttl_secs` | u64 | `300` | Cache lifetime of a found user. Also the revocation lag. The endpoint can shorten it per user with `ttl_secs`. |
| `negative_ttl_secs` | u64 | `30` | Cache lifetime of a 404. |
| `error_ttl_secs` | u64 | `2` | How long a failed lookup keeps failing (500) before it is retried. ≥ 1. |
| `max_entries` | usize | `100000` | Cap on cached users. |
| `lookups_per_ip_burst` / `lookups_per_ip_rps` | u32 | `16` / `2` | Per-source-IP budget for lookups a request may **start** (cache hits and joining an in-flight lookup are free). Over it, that source gets 500. Stops one host with a valid NONCE from filling `queue_depth` with random usernames. Raise it for a large office behind one NAT. |
| `lookups_per_prefix_burst` / `lookups_per_prefix_rps` | u32 | `64` / `8` | The same per /24 (IPv4) or /48 (IPv6). |

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
- RFC 6062 **TCP** relay allocations are IPv4-only unless `[turn.tcp_relay]
  allow_ipv6 = true` is also set; then an IPv6 family request binds the relayed TCP
  listener v6 (`IPV6_V6ONLY`, on `[turn.relay] bind_ip6`) and advertises
  `external_ip6`. Without that key an IPv6 TCP request is `440`, as before.
- `ADDITIONAL-ADDRESS-FAMILY` (one Allocate asking for both families at once) is
  **not** implemented — see `docs/protocol-gap.md` → IPv6.

The relay port pool is shared: a given port number is bound in exactly one family
at a time, so enabling IPv6 does not change port accounting or capacity.

---

## `[turn.io_uring]`

Used only when `transport = "io_uring"`. See the
[support record](verification/io-uring-supported-2026-09-19.md) and
[runbook](runbooks/io-uring.md). Build with `--features io-uring` and select the
backend explicitly. Kernel policy must permit ring creation.

`TURNA_IOURING_WORKERS` selects a positive worker count; otherwise the node uses
available parallelism. Buffers/rings consume memory per worker. The latest runs
held approximately 134 MiB on cloud and 1073 MiB on the local server; these are
configuration-specific measurements, not fixed requirements or a kernel comparison.

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
| `max_sessions_per_ip` | usize | `16` | Per-source-IP session cap (`0` = unlimited). Anti slot-exhaustion; rejections counted as `turna_dtls_rejected_per_ip_total`. |
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
| `min_version` | string | `"1.2"` | Lowest TLS version offered: `"1.2"` (TLS 1.2 and 1.3 — the behaviour before this key existed) or `"1.3"`. Nothing older exists in rustls, so coturn's `no-tlsv1` / `no-tlsv1_1` have no counterpart to set. |
| `cipher_suites` | array of string | `[]` | Allowlist, by rustls name, in preference order. Empty = the rustls defaults (unchanged behaviour). Valid names: `TLS13_AES_256_GCM_SHA384`, `TLS13_AES_128_GCM_SHA256`, `TLS13_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`. An unknown or duplicated name is a startup error, as is a list of only TLS 1.2 suites with `min_version = "1.3"`. TLS 1.2 suites also need a key of the matching type (ECDSA vs RSA): the key is checked when the certificate is loaded (startup and every hot-reload), and an allowlist that leaves nothing usable with it — e.g. only `TLS_ECDHE_ECDSA_*` suites with an RSA certificate and no TLS 1.3 suite — makes the TURNS listener refuse to start (the node reports Degraded, as for any certificate that fails to load; a failed reload keeps the previous material). TLS 1.2 suites that all mismatch the key while TLS 1.3 suites remain only log a warning: TLS 1.3 clients are still served. Applies to TURNS only: QUIC is TLS 1.3 by definition (RFC 9001) and builds its own rustls config, which these keys do not touch. |
| `proxy_protocol` | bool | `false` | Expect a HAProxy PROXY protocol header (v1 or v2) on every connection and use its source address as the client's. See [PROXY protocol](#proxy-protocol-tls-and-turntcp). |
| `proxy_protocol_trusted_cidrs` | array of CIDR | `[]` | Load balancers allowed to send the header. Required, non-empty, when `proxy_protocol = true`. |
| `proxy_protocol_timeout_secs` | u64 | `5` | Deadline for the header, before the TLS handshake starts. Must be positive when `proxy_protocol = true`. |
| `require_client_cert` | bool | `false` | Refuse a client that presents no certificate. Requires `client_ca`; the combination `require_client_cert = true` with an empty `client_ca` is a startup error. `false` lets an unauthenticated client through TLS and leaves it to the long-term credential check, which is what makes a staged rollout across an existing fleet possible. **No CRL/OCSP** — same deliberate position as the management plane (`docs/MTLS.md` → Revocation); revoke by rotating the CA. |

Lifecycle notes: the listener drains cooperatively on SIGTERM (it stops
accepting and lets established connections close themselves), and a transient
`accept()` failure such as `EMFILE` is counted
(`turna_tls_accept_errors_total`) with backoff instead of terminating the
listener. When a control connection closes, its allocation is released
immediately — the connection *is* the allocation's 5-tuple — instead of pinning
a relay port until the lifetime expires.

### PROXY protocol (`[tls]` and `[turn.tcp]`)

Behind a TCP load balancer every connection comes from the balancer, so the
per-IP caps, handshake and TURN rate limits, peer filter decisions, the
allocation's 5-tuple, XOR-MAPPED-ADDRESS and every log line would see one
client. With `proxy_protocol = true` the listener reads a
[PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt)
header first and uses its source address for all of those. Configured per
listener: `[tls]` and `[turn.tcp]` each have their own three keys.

- **Trusted sources only.** A connection whose socket address is outside
  `proxy_protocol_trusted_cidrs` is closed before anything is read. A trusted
  source that sends no header, a malformed one, an unsupported one, or sends it
  late is closed too — there is no fallback to the socket address, which would
  let a client that reaches the listener directly skip the balancer.
- **Accepted:** v1 `TCP4`/`TCP6`, v2 `PROXY` over TCP/IPv4 or TCP/IPv6 (TLVs
  skipped). v1 `UNKNOWN`, v2 `LOCAL` and v2 `UNSPEC` — the balancer's own health
  checks — are served with the socket address, as the specification requires.
  v2 over UDP or UNIX sockets is refused.
- Refusals are counted in `turna_tls_proxy_rejected_total` /
  `turna_tcp_proxy_rejected_total`.
- Configure the balancer to send the header (HAProxy `send-proxy` /
  `send-proxy-v2`, AWS NLB target-group attribute `proxy_protocol_v2.enabled`).
  With TURNS the balancer must pass TLS through (TCP mode), not terminate it.
- **Connections waiting for their header count against `max_connections`.** A
  permit is taken when the connection is accepted, before the header is read,
  and kept until the connection closes, so a trusted source that opens
  connections and sends nothing holds at most `max_connections` of them for
  `proxy_protocol_timeout_secs`; the excess is refused immediately
  (`turna_{tls,tcp}_rejected_over_cap_total`).
- **Trusted ranges are never relay peers.** While PROXY protocol is on for an
  enabled listener, its `proxy_protocol_trusted_cidrs` are added to the peer
  filter's *unconditional* deny — `allowed_peer_ranges` and
  `allow_loopback_peers` do not reopen them. Reason: the relay's own traffic
  may come from an address inside the trusted range (a node on the balancer's
  subnet). If a client could make the relay open an RFC 6062 connection or send
  datagrams to a PROXY-trusting listener — this node's, or another node's in
  the same pool — that listener would see a trusted source, accept a header the
  *client* wrote, and every per-IP control would key on an address the client
  chose. A load-balancer subnet is never a legitimate media peer, so refusing it
  costs nothing (CreatePermission / ChannelBind / CONNECT answer 403).
- Keep the allowlist to the balancers' own addresses. If the relay bind address
  (`bind_ip`, or the private half of `external_ip`) falls inside a trusted range
  the node logs a warning at startup: relayed traffic then leaves from a source
  the listeners trust, and the peer deny above only covers listeners inside the
  range — not another node's listener reachable at an address outside it.

---

## `[turn.tcp]` — plain TURN over TCP (opt-in)

`turn:host:3478?transport=tcp`, without TLS. **Disabled by default.** TURNS is the
better TCP fallback — it gets through firewalls that inspect or block other TCP
ports, and it keeps the TURN control traffic off the wire in the clear — and the
default ICE configuration in the README does not use this listener. It exists
for deployments whose clients are already configured with the plain-TCP URL.

It is the TURNS listener without the handshake: framing, caps, idle timeout,
cooperative drain, release-on-close and PROXY protocol behave identically, and
RFC 6062 TCP relay works over it (§4.1 allows a TCP control connection). Needs
the `tls` build feature (a default one; a build without it refuses to start with
`[turn.tcp]` enabled) and `transport = "tokio"`. Counters are the
`turna_tcp_*` family in [OBSERVABILITY.md](OBSERVABILITY.md).

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the listener. |
| `listen` | socket addr | `0.0.0.0:3478` | TCP. Same number as the UDP listener, which does not conflict (different protocol). Must not equal `[tls] listen`'s port, `[health]`'s or `[management]`'s. |
| `max_frame_size` | usize | `65536` | Max framed STUN/ChannelData message, `20..=65555`. |
| `read_timeout_secs` | u64 | `300` | Per-connection idle read timeout. Must be > 0. |
| `max_connections` | usize | `10000` | Global connection cap. Must be > 0. |
| `max_connections_per_ip` | usize | `64` | Per-source-IP cap (`0` = unlimited). |
| `max_connections_per_sec_per_ip` | u32 | `0` | Per-source-IP new-connection rate (`0` = unlimited). |
| `connection_burst_per_ip` | u32 | `0` | Burst allowance. `0` = twice the rate. |
| `proxy_protocol` | bool | `false` | As in `[tls]`. |
| `proxy_protocol_trusted_cidrs` | array of CIDR | `[]` | As in `[tls]`. |
| `proxy_protocol_timeout_secs` | u64 | `5` | As in `[tls]`. |

Publish `3478/tcp` (firewall, container, Helm chart) yourself when you enable it;
the shipped deployment files only publish what is on by default.

---

## `[turn.tcp_relay]` — RFC 6062 TCP relay allocations

Lets a client relay **TCP** to peers (`CONNECT` / `CONNECTION-BIND`) instead of
UDP. Disabled by default. **Requires `[tls]` or `[turn.tcp]` enabled:** RFC 6062
§4.1 mandates a TCP/TLS control connection, and an Allocate with
`REQUESTED-TRANSPORT = 6` arriving over UDP, DTLS or QUIC is refused with
`400 Bad Request`.

> **Allowed in production since 2026-08-25.** Until then `production = true`
> rejected `enabled = true`; the gate was lifted once interop with coturn's client
> and the pipelined-client case were on record (`docs/interop/coturn-2026-08-23.md`,
> `docs/interop/transports-2026-08-19.md`). What validation still does: with
> `production = true`, `enabled = true` with neither `[tls]` nor `[turn.tcp]` enabled is a startup error
> (a warning otherwise) — there would be no connection to carry the allocation.
> IPv4 by default; IPv6 is opt-in with `allow_ipv6 = true` plus `[turn] external_ip6`,
> otherwise a v6 TCP allocation answers `440`.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Accept `REQUESTED-TRANSPORT = 6` on Allocate. |
| `connect_timeout_secs` | u64 | `30` | Outbound connect deadline; failure or timeout answers `447`. |
| `idle_timeout_secs` | u64 | `30` | Reap a peer connection that is connected but never `ConnectionBind`-ed. |
| `max_per_allocation` | usize | `10` | Concurrent peer connections per allocation. |
| `max_total` | usize | `50000` | Concurrent peer connections overall (`446`/`508` beyond it). |
| `buffer_size` | usize | `16384` | Per-direction relay buffer. |
| `allow_ipv6` | bool | `false` | Serve `REQUESTED-ADDRESS-FAMILY = IPv6` TCP allocations: listener bound v6 (`IPV6_V6ONLY`, `[turn.relay] bind_ip6`), `[turn] external_ip6` advertised. **Requires `external_ip6`** (validation). Off → `440`, as before. Cross-family peers get `443` on CreatePermission, so CONNECT cannot reach them. |

A `ConnectionBind` must be authenticated with the **same credentials** as the
`CONNECT` (or the allocation owner, for peer-initiated connections) —
`CONNECTION-ID` is a sequential, guessable value, so this ownership check is
what prevents one authenticated client hijacking another's pending connection.

---

## `[turn.nat_discovery]` — RFC 5780 NAT behaviour discovery

Answers STUN Binding on four UDP sockets — A1:P1, A1:P2, A2:P1, A2:P2 — so a client
can ask for a reply from the other address and/or port (`CHANGE-REQUEST`) and learn
how its NAT maps and filters. Off by default. The TURN listener is not one of the
four and keeps answering `CHANGE-REQUEST` with `420`, as RFC 5780 §6 requires of a
socket with no alternate address.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Serve RFC 5780 on the four sockets. |
| `primary_ip` | string | `""` | A1, the address clients are pointed at (e.g. through `_stun-behavior._udp`). |
| `alternate_ip` | string | `""` | A2, a second address of the **same family**, assigned to this host. |
| `primary_port` | u16 | `3478` | P1. Collides with a TURN listener on the same address or on the wildcard — move one of them. |
| `alternate_port` | u16 | `3479` | P2, distinct from P1. |

Validation refuses `enabled = true` unless both addresses parse, differ, share a
family and are not a wildcard; unless the ports differ; and when a port collides
with `turn.listen`, an enabled DTLS or QUIC listener, or any relay port range. A
bind failure at startup stops the node: a discovery service answering from three of
its four addresses would report the wrong NAT type.

Replies are unauthenticated and `CHANGE-REQUEST` can send them from three different
sources, so every request passes the `[turn.rate_limit]` tiers and the
unauthenticated-reply budget before anything is sent. With discovery enabled that
budget is **shared by every processor on the node** — the TURN listener, the
discovery sockets, DTLS/QUIC and each io_uring worker — so a spoofed victim gets one
budget (burst 64, 8/s per source IP) in total, not one per listener. With discovery
off each processor keeps its own, as before. `PADDING` and `RESPONSE-PORT` are not
implemented and are answered `420`. Only Binding is served. UDP only.

**Amplification.** A discovery reply carries four addresses (XOR-MAPPED, MAPPED,
RESPONSE-ORIGIN, OTHER-ADDRESS): **80 bytes** for IPv4 and **128 bytes** for IPv6
with the default `software_attribute = "product"` (4 bytes more with `"full"`, 12
fewer with `"none"`), against a 20-byte request (28 with CHANGE-REQUEST) — up to
**4×** for IPv4 and **6.4×** for IPv6. The TURN listener's own Binding reply is 44
bytes (2.2×). The shared budget above is what bounds it; the sizes are pinned by
`discovery_reply_sizes_match_the_documentation`.

**Authenticated Bindings.** A discovery Binding that carries MESSAGE-INTEGRITY is
handled by the RFC 8489 long-term mechanism: NONCE, REALM and USERNAME/USERHASH are
required (`400`), the nonce must be one this responder issued to that source and
still fresh (`438` with a new one), the integrity must verify (`401`), and the success
response is signed with the same MESSAGE-INTEGRITY variant (RFC 5780 §6.1).
Discovery clients normally send no credentials and get an unsigned reply.

The addresses must be the ones clients reach: `RESPONSE-ORIGIN` and `OTHER-ADDRESS`
name them, so behind a 1:1 NAT they would name private addresses.

```toml
[turn.nat_discovery]
enabled = true
primary_ip = "203.0.113.10"
alternate_ip = "203.0.113.11"
primary_port = 3478      # TURN listener on another address, or move these ports
alternate_port = 3479
```

---

## `[turn.quic]` — QUIC / WebTransport

Requires `--features quic` (raw QUIC datapath) or `--features web-transport`
(browser HTTP/3 CONNECT; implies `quic`). Both are **supported** on Linux/macOS
with tokio; see [support scope](verification/quic-webtransport-supported-2026-09-18.md).

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the listener. |
| `web_transport` | bool | `true` | `true` = WebTransport over HTTP/3; `false` = raw QUIC. Needs `--features web-transport` when `true`. |
| `listen` | socket addr | `0.0.0.0:5350` | UDP. Numerically collides with `[management].listen` (TCP) — different protocols, so the binds do not conflict. |
| `cert_path` / `key_path` | path | `/etc/turna/tls/…` | Same PEM material as `[tls]` by default. |
| `max_bi_streams` | u64 | `256` | Concurrent bidi streams per connection. Applied on both paths. |
| `max_uni_streams` | u64 | `256` | Concurrent uni streams per connection. Applied on both paths. |
| `enable_datagrams` | bool | `true` | QUIC datagrams (RFC 9221) for media. Applied on both paths. |
| `max_datagram_size` | usize | `1200` | Sizes the datagram receive buffer. Applied on both paths. |
| `idle_timeout_secs` | u64 | `30` | Connection idle timeout. Applied on both paths. |
| `keep_alive_secs` | u64 | `10` | Keep-alive interval. |
| `alpn` | list | `["stun.turn"]` | **Raw QUIC only** — WebTransport negotiates `h3` itself, so this key is inert when `web_transport = true`. |
| `max_sessions` | usize | `10000` | Session cap (`0` = unlimited), `turna_quic_rejected_over_cap_total`. Enforced before the handshake on both paths. |
| `max_sessions_per_ip` | usize | `16` | Per-source-IP cap (`0` = unlimited), `turna_quic_rejected_per_ip_total`. Same timing as above. |
| `cert_reload_secs` | u64 | `30` | Poll `cert_path`/`key_path` and hot-reload the certificate without dropping live sessions. Works on **both** paths (`Endpoint::reload_config` on WebTransport, `Endpoint::set_server_config` on raw QUIC); only new sessions see the new material. `0` disables. |
| `max_handshakes_per_sec_per_ip` | u32 | `0` | Per-source-IP handshake **rate** limit (`0` = unlimited). Complements `max_sessions_per_ip`, which only bounds *concurrent* sessions: a source that opens and drops sessions in a loop never trips a concurrency cap while still costing a handshake each time. Checked before the handshake on both paths (`turna_quic_rejected_rate_limit_total`). |
| `handshake_burst_per_ip` | u32 | `0` | Burst allowance for the rate limit. `0` = twice the rate, so a page opening several sessions at once is not penalised. |

Both paths apply the configured transport limits and certificate reload.
Only `alpn` is intentionally raw-QUIC-only: WebTransport negotiates `h3`.
DATAGRAM payloads are bounded by the configured cap and negotiated peer limit;
media delivery is unreliable and loss remains visible in test reports.

Connection migration (the client's address changing mid-session) is detected by
polling the peer address every 2s; the listener re-keys its egress registries and
counts it as `turna_quic_migrations_total`. On the WebTransport path migration can
be disabled at the QUIC layer via the builder; the raw-QUIC path uses quinn's
default. Details: `docs/design/quic-webtransport.md` §7.

Enabling `[turn.quic]` without `--features quic`, or `web_transport = true`
without `--features web-transport`, is a **startup error**.

---

## `[turn.sctp]` — TURN-over-SCTP (supported on Linux/tokio)

Opt-in native SCTP client-to-server transport for STUN/TURN control and
ChannelData. The peer-side relay stays **UDP**. Requires a Linux node built with
`--features sctp`, kernel SCTP support (built in or loaded as a module), and
`[turn] transport = "tokio"` (the default). Other backend selections are rejected
when SCTP is enabled. `production = true` is allowed; normal production secret,
address and quota checks still apply. Builds without `sctp` fail at startup.

This is a project-specific TURN mapping, not a standardized SCTP relay allocation
or browser WebRTC DataChannel. IP protocol **132** must pass through the network;
opening a TCP/UDP port does not open SCTP. Containers use the host kernel support.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enable the SCTP listener. |
| `listen` | socket addr | `0.0.0.0:3478` | No standardized TURN-over-SCTP port. |
| `max_frame_size` | usize | `65536` | Framed STUN/ChannelData limit; valid range 20..65555. |
| `read_timeout_secs` | u64 | `300` | Positive idle read timeout; outbound traffic does not reset it. |
| `max_connections` | usize | `10000` | Concurrent association cap; 0 disables this cap. |
| `max_connections_per_ip` | usize | `0` | Per-IP concurrent cap; 0 disables this cap. |
| `max_associations_per_sec_per_ip` | u32 | `0` | Per-IP accepted-association rate; 0 disables limiting. |
| `association_burst_per_ip` | u32 | `0` | 0 selects twice the configured rate. |
| `backlog` | i32 | `1024` | Positive `listen(2)` backlog. |

The SCTP channel has **no TLS encryption**. TURN authentication does not add
transport confidentiality. Only one ordered SCTP stream is used; multi-stream
SCTP and multihoming/failover are not support claims. See
[SCTP evidence and limitations](verification/sctp-supported-2026-09-18.md) and
[metrics](OBSERVABILITY.md#turn-over-sctp-turnsctp).

---

## `[turn.af_xdp]`

AF_XDP ring datapath. Used only when `transport = "af_xdp"`. Requires a Linux
`--features af-xdp` build and privileges for XSK/BPF/XDP setup. The node loads
its own address/port-selective program. **Supported within the verified Linux
IPv4 UDP copy-mode scope**; see [evidence and limitations](verification/af-xdp-supported-2026-09-22.md)
and [the runbook](runbooks/af-xdp.md). Native attach does not imply zero-copy.

| key | type | notes |
|-----|------|-------|
| `interface` | string | NIC name, e.g. `eth0`. |
| `queue_id` | u32 | Legacy single queue (default 0), used when `queue_ids` is empty. |
| `queue_ids` | array of u32 | Explicit RX queues; must cover every RX queue reported by the interface. Unique IDs below 64. Empty preserves `queue_id`. |
| `attach_mode` | string | `auto` (legacy: native if zero-copy, otherwise SKB), `skb`, or `native`. Native + copy is supported as a selectable mode; hardware verification remains required. |
| `frame_count` | u32 | UMEM frames per queue, at most 4096 with current ring geometry. |
| `frame_size` | u32 | Fixed at 4096; must fit MTU+14. Inert overrides are rejected. |
| `fill_ring_size` | u32 | Fixed at 2048, as are completion/RX/TX rings. |
| `comp_ring_size` | u32 | Completion ring size. |
| `rx_ring_size` | u32 | RX ring size. |
| `tx_ring_size` | u32 | TX ring size. |
| `zero_copy` | bool | Force zero-copy bind (requires driver support and native attach). False forces copy. Actual socket mode is checked with XDP_OPTIONS; no silent fallback. |
| `need_wakeup` | bool | Use the `NEED_WAKEUP` flag. |
| `src_mac` | string | Source MAC for TX frames. Empty reads the configured interface MAC. |
| `dst_mac` | string | Fallback next-hop MAC. Empty attempts default-gateway ARP lookup; unresolved fallback remains observable. |

Validation/preflight checks fixed ring geometry, interface/queue coverage, MTU,
mode compatibility and `CAP_NET_RAW`. Binding and BPF attach must also succeed;
NET_RAW alone does not grant all required BPF/XDP privileges. A concrete listen
IP is required. Readiness follows initialization of every configured queue.

---

## `[turn.relay]` — capacity thresholds

| key | type | default | notes |
|-----|------|---------|-------|
| `max_packets_per_sec` | u64 | `0` | Relayed packets/second this node can carry, from a measurement. `0` leaves the rate reported by `/capacity` and **not judged**. |
| `rate_soft_percent` | u64 | `60` | Percent of the above at which `/capacity` reports `DEGRADED`. |
| `rate_hard_percent` | u64 | `80` | Percent at which it reports `SATURATED`. |
| `drain_timeout_secs` | u64 | `30` | How long shutdown waits for allocations to end. |
| `max_total_bytes_per_sec` | u64 | `0` | Node-wide cap on relayed bytes/second, both directions and all allocations combined (coturn `bps-capacity`, different mechanism — see below). RFC 6062 TCP-relay data is not counted. `0` = no cap. Values below 1500 are refused. |

**Measure `max_packets_per_sec`; do not estimate it.**
`scripts/verify/capacity-profile.sh` on the hardware in question. A figure from
other hardware is worse than none, because it looks measured.

**Why 60/80 and not the 75/95 the allocation thresholds use.** The failure shapes
differ. Allocations degrade gracefully: at the cap no new allocation is granted and
every existing client keeps working. Packet rate does not degrade at all and then
falls off a cliff — measured on a 32-thread host, clean at 112 000 pps, failing at
120 000, shedding a million frames in two minutes at 128 000. Seven percent between
perfect and broken.

At 80 % that leaves 30 400 pps of headroom before the cliff. At 90 % it would leave
19 200, which at these rates is seconds of traffic growth.

**`max_total_bytes_per_sec` drops, it does not refuse sessions.** One token
bucket (one second of burst) shared by every allocation on every packet
datapath (UDP, TURNS, DTLS, QUIC, SCTP). Once it is empty, relayed packets —
ChannelData, Send indications and peer→client traffic alike — are dropped and counted in `turna_relay_capacity_dropped_packets_total` /
`_bytes_total`; the configured figure is exported as
`turna_relay_capacity_bytes_per_sec`. coturn's `bps-capacity` instead reserves
bandwidth per session at allocation time and refuses new sessions when it runs
out. The practical difference: under turna's cap every call on the node degrades
together, so size it as a ceiling you never expect to reach (a paid egress
allowance, a shared uplink), not as admission control. Every relayed packet
updates one shared atomic while the cap is on; it costs nothing when off.

Two limits of the mechanism. **It is first come, first served**: there is no
fairness between allocations, so a single heavy allocation can spend the budget
the others needed — bound each one with `max_bytes_per_sec_per_allocation`, and
use this cap only for the sum. **RFC 6062 TCP-relay data is not counted**: it is
copied between TCP sockets outside the packet processor, so a node relaying TCP
peers can exceed the figure by that traffic.

**`drain_timeout_secs` is a bound, not a target.** The drain loop also exits early
when three consecutive polls remove nothing: a node whose clients vanished without
a `Refresh(0)` holds allocations that cannot expire inside a 30-second window, so
it used to pay the full timeout with nothing to wait for. Measured after the
change: 1 second. A node draining live traffic is unaffected — its allocations end,
the count moves, and the loop keeps waiting.

---

## `[grpc.rbac]` — management-plane access control

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Enforce roles. **Default-deny when true.** |
| `roles` | map of name → list of permissions | `{}` | Extends and can override the built-ins. |
| `bindings` | map of fingerprint → list of role names | `{}` | SHA-256 certificate fingerprints, lower-case hex, no colons. |

```toml
[grpc.rbac]
enabled = true

[grpc.rbac.roles]
oncall = ["node:drain", "stats:read", "allocations:read"]

[grpc.rbac.bindings]
"3fa1...c9" = ["admin"]
"7bd2...04" = ["oncall"]
```

Get a fingerprint with:

```sh
openssl x509 -in client.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-Z' 'a-z'
```

Built-in roles, which `roles` may extend or replace: `viewer` (everything that
cannot change state), `operator` (the above plus freeing an allocation, adjusting
a user's limits, draining a node), `admin` (everything, including
`node:shutdown`).

`shutdown` is in `admin` alone. Draining is a rolling upgrade and happens weekly;
shutting a node down is not, and no amount of care makes it reversible.

**Enabling this on a running deployment locks out every client until each is
bound.** That is why it is opt-in rather than a default somebody discovers during
an incident. Startup refuses `enabled = true` with no bindings, because there is no
reading of that which anybody meant.

Roles live in configuration rather than in code because the interesting roles are
the ones nobody anticipated, and a hardcoded set makes each new one a release.

---

## `[grpc] revocation_list` — revoking a client certificate

| key | type | default | notes |
|-----|------|---------|-------|
| `revocation_list` | string | `""` | Path to a file of SHA-256 fingerprints that may not be used. Empty disables it. |

```text
# laptop lost 2026-08-14, ticket OPS-4471
3fa1c9...  # alice@example.com, issued 2026-06-01
7bd204...
```

Colons and upper case are accepted, because that is what
`openssl x509 -fingerprint -sha256` emits and an operator pasting its output
should not have to know otherwise.

**This is not RFC 5280 CRL.** No CA-signed list, no `nextUpdate` freshness rule, no
distribution point. It is a local deny-list checked when an RPC arrives, so a
revoked client completes the TLS handshake and is refused on its first call. If a
compliance regime names CRL or OCSP specifically, this does not satisfy it — see
`docs/security/mtls-revocation.md`.

What it has that CRL cannot have here: **it works with no route off the host.** A
CRL has to reach the node from the CA, and the deployments that most need
revocation are the air-gapped ones. OCSP is worse for the same reason — it needs a
reachable responder, and configuring it in an air-gapped contour means either
failing every handshake or soft-fail, which is the absence of revocation with the
appearance of it.

**Fail-closed.** A configured path that cannot be read stops the node from
starting, and a malformed line is an error naming the line. A list that is
configured and silently empty looks like protection and is not.

Checked **before** RBAC. Both refusals return `permission_denied`, so the order
looks cosmetic and is not: a revoked certificate that also lacks the permission
would be audited as a missing role, an operator reading that would grant the role,
and the revoked certificate would then work.

---

## `[observability]` — security export and log content

| key | type | default | notes |
|-----|------|---------|-------|
| `syslog_endpoint` | string | `""` | `udp://host:514` or `tcp://host:601`. Empty disables export. |
| `syslog_redact_addresses` | bool | `false` | Hash client addresses before sending them. |
| `log_allocation_addresses` | bool | `true` | Log client IP addresses on the three per-allocation INFO lines. |
| `node_audit_path` | string | `""` | Where the node writes its audit chain. Empty keeps it in memory only. |
| `node_audit_entries` | usize | `256` | Entries kept in the in-memory ring. |
| `log_to_stdout` | bool | `true` | Write the log to stdout. `false` is refused unless a file or syslog log sink is configured. |
| `log_file.path` | string | `""` | Also write the log to this file. Empty disables. The directory must exist and be writable by the service user. |
| `log_file.rotation` | string | `"size"` | `size`, `daily`, `hourly` (UTC) or `external` (never rotate; logrotate + SIGHUP). |
| `log_file.max_size_mb` | u64 | `100` | Size limit for `rotation = "size"`. Must be > 0. |
| `log_file.max_files` | usize | `7` | Rotated files kept, 1..=1000. The active file is not counted. |
| `log_file.level` | string | `"trace"` | Narrows the file: `error`/`warn`/`info`/`debug`/`trace`. Applied after `RUST_LOG`, so it cannot widen it. |
| `log_syslog.endpoint` | string | `""` | Send **every** log line (not only security events) to `unix:///dev/log`, `udp://host:514` or `tcp://host:601`. Empty disables. |
| `log_syslog.level` | string | `"info"` | Lowest level sent. Applied after `RUST_LOG`. |
| `log_syslog.queue_capacity` | usize | `8192` | Lines buffered for the sender thread; beyond it they are dropped and counted in `turna_log_syslog_dropped_total`. |

`syslog_endpoint` also accepts `unix:///dev/log` since the log-sink work: the
exporter gained the local socket, and the security events can use it too.

**Log file and full-log syslog are opt-in and change nothing when unset.** They
carry the same lines as stdout, rendered by the same redacting formatter: the
`log_allocation_addresses` switch applies to them, and credential-named fields are
replaced with `[redacted]`. `log_syslog` is not the security export —
`syslog_endpoint` keeps sending only the curated security events, and the full
log carries MSGID `LOG` so SIEM rules on the security MSGIDs are unaffected.

SIGHUP reopens the log file (for logrotate with `rotation = "external"`) and also
reloads shared secrets, which is idempotent: a reload with an unchanged file
changes nothing. A log file or syslog sink that cannot be opened at startup is
reported on stderr and again at WARN once stdout logging is up; the node keeps
serving with stdout only rather than refusing to start over a log destination.

**`syslog_endpoint` carries security events only** — authentication failures,
authorisation denials, peer refusals, rate-limit trips, audit entries, readiness
transitions. Not relayed traffic. A SIEM billed per event that receives a line per
frame gets switched off, and a switched-off SIEM catches nothing.

Dropping rather than blocking when the collector is slow, with the drops counted in
`turna_syslog_dropped_total`. Security logging that can stall the relay is a worse
posture than logging that can gap visibly. **Alert on that counter**: a silent gap
in a security log is worse than a visible failure, because an investigation reads
absence as "nothing happened".

**`syslog_redact_addresses` defaults to false, and that is deliberate.** A SIEM is
inside the operator's trust boundary, and an authentication-failure event without a
source is not actionable. Turning it on loses the ability to correlate one attacker
across events, which is most of what a SIEM is for.

**`log_allocation_addresses` is named for its scope.** It covers three INFO lines
in the relay — allocation created, TCP allocation created, allocation migrated —
and nothing else. Those are per-allocation, so a busy node writes one line
containing a client address for every allocation it grants: 13.7 million of them in
this project's own three-hour soak.

It defaults to `true`, which is not the privacy-forward choice. `src` on the
allocation line is the field an operator correlates a complaint against, and
removing it silently in an upgrade breaks what logs are used for. Set it false and
those addresses log as `ip-<12 hex>` under a per-process salt.

**What it does not cover:** ten WARN lines in the TURNS, QUIC and SCTP transports
also carry an address, deliberately outside this switch. All ten are *refusals* —
a per-IP cap, a rate limit, a session ceiling — so the volume is bounded by attacks
rather than by traffic, and the address is the most useful part: "who is being
refused" cannot be acted on without it. A deployment that must log no client
address anywhere cannot get that from configuration today.
See `docs/security/log-data-audit-transports.md`.

**`node_audit_path`** makes the node's own audit chain persistent. On startup the
existing chain is replayed and **verified**, `seq` resumes across rotation
boundaries, and a break fails closed. That is what makes start and stop events
worth recording there as well as in syslog: the chain survives the restart they
describe, and syslog puts them where a compromised node cannot reach them.

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

## Rate limiting (`[turn.rate_limit]`)

Five tiers, each a token bucket described by a `_burst` (depth) and a `_rps`
(refill per second): `per_ip` and `per_prefix` on the packet path,
`allocate`, `create_permission` and `channel_bind` on the control path. The
`allocate` tier is the strict one, because each Allocate costs a relay port, a
socket and a store entry.

Two sets of them live under `[turn.rate_limit]`. `default` applies to everyone;
`trusted` applies to sources matched by `trusted_prefixes`.

```toml
[turn.rate_limit]
trusted_prefixes = ["198.51.100.0/24"]

[turn.rate_limit.trusted]
allocate_burst = 512
allocate_rps = 128
```

The `default` values are the ones that were previously hardcoded, so upgrading
without writing this section changes nothing.

**Why the trusted tier exists.** The defaults are sized against abuse from the
open internet, where a source address is one client. An office is not: several
hundred people leave through one NAT address. A browser sends an Allocate per ICE
transport, so a 300-person meeting starting on the hour is roughly 600 Allocates
from one IP — 35 seconds at the default 16/s, which is longer than a browser's
ICE gathering waits before timing out and retrying, and the retries lengthen the
queue. The data-plane tiers have the same problem: 300 relaying participants at
~300 pps each is ~90 000 pps from one source against a default refill of 50 000.

**`trusted_prefixes` is not authentication.** Anyone who can spoof a source
address inside those ranges gets the higher ceiling. It is a capacity knob; list
only prefixes you route. It is empty by default, because a default that guessed
at RFC 1918 would hand the higher ceiling to whatever private network happened to
reach the node.

**Refresh shares the `allocate` tier.** It was the one authenticated method
without a per-method limit; over the budget it is answered `486` like Allocate. A
client refreshes every few minutes, so the shared budget costs it nothing.

**No value may be `0`.** Config validation refuses it. A zero refill is a bucket
that empties once and never fills again, which is never what "0" is meant to
express, and this limiter has no way to say "unlimited".

The `TURNA_RATE_LIMIT_BURST`, `TURNA_ALLOCATE_RPS` and related environment
variables still override these and now warn each time they do. They are
deprecated: a limit set there appears in no config file and in no
`--dump-config` output, which is how an operator ends up hunting for a ceiling
that is written down nowhere.

## Auto-ban (`[turn.auto_ban]`)

fail2ban built into the datapath, **off by default**. A source that fails
authentication `auth_failures` times — or, if enabled, is refused by a rate
limiter `rate_limit_violations` times — within `window_secs` has **every packet**
dropped for `ban_secs`: STUN, ChannelData, all transports. The check is the first
thing the processor does with a packet, before classification, rate limiting,
parsing or authentication, and costs one atomic load while nothing is banned.
Bans expire on their own; there is no unban command to forget.

| key | type | default | notes |
|-----|------|---------|-------|
| `enabled` | bool | `false` | Turn the feature on. |
| `auth_failures` | u32 | `10` | Auth failures in the window that trigger a ban. `0` disables this trigger. |
| `rate_limit_violations` | u32 | `0` | Rate-limiter refusals in the window that trigger a ban. `0` (default) disables this trigger — see below. |
| `credential_lookups` | u32 | `20` | `[turn.auth.webhook]` lookups one source starts, or is refused by its lookup budget, in the window that trigger a ban. Joining a lookup already in flight does not count. `0` disables it. Inert without the webhook. |
| `window_secs` | u64 | `60` | Counting window. Must be > 0 when enabled. |
| `ban_secs` | u64 | `600` | Ban duration. Must be > 0 when enabled. |
| `scope` | string | `"ip"` | `"ip"` counts and bans the address; `"prefix"` counts and bans the /24 (IPv4) or /48 (IPv6), for attackers rotating through a block. |
| `allowlist` | array of CIDR | `[]` | Never counted, never banned. |
| `exempt_trusted_prefixes` | bool | `true` | Also exempt `[turn.rate_limit] trusted_prefixes` — the NAT addresses many users share. |
| `max_tracked` | usize | `65536` | Cap on sources with a running offence count. The idlest of a small sample is evicted beyond it. |
| `max_bans` | usize | `16384` | Cap on simultaneous bans. A ban beyond it is **refused** (`turna_autoban_refused_full_total`), never evicting another. |

```toml
[turn.auto_ban]
enabled = true
auth_failures = 10
window_secs = 60
ban_secs = 600
allowlist = ["198.51.100.0/24"]   # your office egress
```

**What counts as an auth failure.** Only requests that carried a valid NONCE and
then failed credential validation: Allocate, Refresh, CreatePermission,
ChannelBind, CONNECT and ConnectionBind. The nonce is bound to the client address
and has to be fetched with a round trip, so this evidence cannot be forged with a
spoofed source. A Binding with bad MESSAGE-INTEGRITY is deliberately **not**
counted: it needs no nonce, and counting it would let anyone get a victim banned.
**`Expired` does not count.** A stale TURN REST credential or OAuth token is a
client clock or a cached credential, not guessing; it is still counted in
`turna_auth_failures`. A credential lookup that is merely pending or unavailable
(the auth webhook) is not a failure either; lookups a source *starts* count
separately, toward `credential_lookups`.

**Prefix scope and the allowlist.** With `scope = "prefix"` a ban covers the
whole /24 or /48, but an allowlisted address inside it is still let through.
Addresses from a dual-stack socket (`::ffff:a.b.c.d`) are treated as the IPv4
client for keys, prefixes and the allowlist.

**Why `rate_limit_violations` is off by default.** It counts refused packets, and
a UDP packet can carry any source address. An attacker who can spoof can make the
node ban an address of their choosing — a customer, a partner's NAT, a monitoring
probe. Turn it on only where spoofing is filtered upstream (BCP 38), and keep your
own ranges in `allowlist`. `docs/security/accepted-risks.md` records this.

**Events.** Each ban writes `auto-ban: source banned` (WARN) and each expiry
`auto-ban: ban expired, source unbanned` (INFO) from `turna_relay::abuse`. Both
reach syslog as `SOURCE_BANNED` with `src_ip`, `reason` and `detail`. The address
follows `[observability] log_allocation_addresses` like every other client address.
Metrics: `turna_autoban_bans_total`, `turna_autoban_active`,
`turna_autoban_dropped_total`, `turna_autoban_refused_full_total`.

**One table for the node.** Every datapath (UDP, TURNS, DTLS, QUIC, SCTP, the
io_uring/AF_XDP processors) shares it, so a ban applies everywhere at once. It is
per node, not per cluster: a source banned on one node can still reach another
until it fails there too.

## Bandwidth quota: what it is and is not

`[turn.relay.quota] max_bytes_per_sec_per_allocation` is **abuse protection, not
QoS**, and two properties decide how to size it.

**It drops, it does not throttle.** Over the limit, packets are discarded and
`turna_quota_exceeded_total` increments. There is no backpressure and no signal
to the sender, so a client does not degrade to a lower bitrate — it loses frames,
which looks to the user (and to whoever is debugging) like a network fault.

**One window covers both directions.** Client→peer and peer→client share the
same budget, so the figure has to cover a participant's upload *and* everything
they receive.

That combination means a value set close to real usage produces intermittent
frame loss at exactly the moments the call gets busy. For a conferencing product
through an SFU, work out the received side first: a participant sending 1080p at
2-4 Mbit/s might receive 9 tiles at 0.5-2 Mbit/s each plus a screen share, so
30-40 Mbit/s of headroom is ordinary, not exceptional. `corporate.toml`'s
4 000 000 bytes/s (32 Mbit/s) is already tight for a large meeting;
`selfhosted.toml` uses 12 500 000 (100 Mbit/s), which is far above legitimate use
and still low enough to make relaying a bulk transfer unattractive.

Under `production = true` a value of `0` (unlimited) is refused unless
`allow_unlimited_bandwidth = true` is set explicitly. For individual accounts
that genuinely need more, use `set_user_limits` through the control plane rather
than raising the figure for everyone.

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
