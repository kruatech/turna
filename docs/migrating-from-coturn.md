# Migrating from coturn

Option-by-option mapping from `turnserver.conf` to `turn.toml`, plus the places
where the two servers do not have equivalent behaviour and you have to make a
decision rather than translate a line.

Read [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) first if you are moving
production traffic — several coturn features map onto something `turna` marks
beta or scopes narrowly, and one (OAuth) maps onto something it refuses outright
under `production = true`.

## The shape of the difference

coturn is configured by a flat file of ~125 options plus, optionally, a SQL or
Redis database for users. `turna` is configured by a TOML file, and anything that
changes at runtime (limits, users) goes through a gRPC API instead of a file
reload or a database row. So a migration has three parts:

1. static configuration → `turn.toml` (the tables below);
2. users and credentials → either static config or the runtime API;
3. anything you were doing with `turnadmin`, the telnet CLI, or SQL → the gRPC
   API on `turna-control-plane` (partly wrapped by `turnactl`).

## Option-by-option mapping

Every option in coturn's reference configuration,
[`examples/etc/turnserver.conf`](https://raw.githubusercontent.com/coturn/coturn/master/examples/etc/turnserver.conf)
on `master` as fetched on 2026-09-24 — **125 options** — in the order of the
areas below. Each row says one of:

- **key** — the exact TOML key. Every key named here exists in
  `crates/config/src/lib.rs`; `scripts/check-doc-claims.sh` fails if one stops
  existing. Semantics can still differ; the note says how.
- **no equivalent** — turna has nothing that does this.
- **by design** — turna covers the need differently, or always behaves one
  way and has no switch for it. The note says which.

Rows for features that are being worked on elsewhere describe what `main` does
today; they carry an invisible `parity-pr` HTML comment in the source so they
can be found and updated when that work lands.

`turna-node --dump-config /etc/turna/turn.toml` prints the effective
configuration, secrets masked, without starting a listener — use it to check a
translation. [CONFIGURATION.md](CONFIGURATION.md) documents every key.

### Listeners and addressing

| coturn | turna | kind | note |
|---|---|---|---|
| `listening-device` | — | no equivalent | no `SO_BINDTODEVICE`; bind by address with `[turn] listen` |
| `listening-port` | `[turn] listen` | key | address and port are one value, e.g. `"0.0.0.0:3478"`. UDP only — see `no-tcp` |
| `tls-listening-port` | `[tls] listen` | key | plus `[tls] enabled = true`. `tls` is a default feature of `turna-node`, so a standard build has it |
| `alt-listening-port` | — | no equivalent | the alternate port exists for RFC 5780, which turna does not implement <!-- parity-pr --> |
| `alt-tls-listening-port` | — | no equivalent | as `alt-listening-port` <!-- parity-pr --> |
| `tcp-proxy-port` | — | no equivalent | no PROXY protocol support on any listener <!-- parity-pr --> |
| `listening-ip` | `[turn] listen` | key | one address per process. Several `listening-ip` lines have no equivalent: run one process per address <!-- parity-pr --> |
| `aux-server` | — | no equivalent | one UDP listener per process |
| `udp-self-balance` | — | by design | load spreading across nodes is cluster mode's redirect (`[cluster]`), not auxiliary listeners |
| `external-ip` | `[turn] external_ip`, `[turn] external_ip6` | key | required under `production = true`. The `PUBLIC/PRIVATE` form has no direct equivalent: set `listen` to the private address and `external_ip` to the public one. IPv6 relaying is enabled by setting `external_ip6` |
| `no-udp` | — | no equivalent | the UDP listener (`[turn] listen`) is always on |
| `no-tcp` | — | by design | there is no plain TURN-over-TCP listener at all, so this is always in force; TCP clients use TURNS <!-- parity-pr --> |
| `no-tls` | `[tls] enabled` | key | `false` is the default |
| `dtls` | `[turn.dtls] enabled` | key | also needs a `--features dtls` build and its own `cert_path` / `key_path`; the default `listen` is `0.0.0.0:5349` |
| `no-dtls` | `[turn.dtls] enabled` | key | `false` is the default |
| `respond-http-unsupported` | — | no equivalent | an HTTP request on the TURNS port gets a failed TLS handshake, not an HTTP answer |

### Relay addresses, ports and datapath

| coturn | turna | kind | note |
|---|---|---|---|
| `relay-device` | — | no equivalent | bind by address with `[turn.relay] bind_ip` |
| `relay-ip` | `[turn.relay] bind_ip`, `bind_ip6` | key | one address per family. Empty (the default) binds relay sockets on the wildcard address |
| `relay-threads` | — | by design | no config key; the `TURNA_WORKERS` environment variable sets the runtime's worker threads (`services/node/src/main.rs`) |
| `cpus` | — | by design | as `relay-threads` |
| `min-port` / `max-port` | `[turn.relay] min_port`, `max_port` | key | same meaning. Keep range and firewall in agreement — `scripts/check-deploy-consistency.sh` checks where it is declared. Per-tenant pools: `[[tenants]] relay_port_range` |
| `sock-buf-size` | `[turn] socket_recv_buffer_bytes`, `socket_send_buffer_bytes` | key | separate receive and send sizes; 0 leaves the kernel default. Raise `net.core.rmem_max` / `net.core.wmem_max` first |
| `udp-recvmmsg` | `[turn] transport` | by design | the default `tokio` backend batches with `recvmmsg`/`sendmmsg` on Linux, with no switch; `"io_uring"` and `"af_xdp"` are the alternatives |
| `udp-recvmmsg-log` | — | no equivalent | batching is not reported separately |
| `udp-gso` | — | no equivalent | no UDP segmentation offload on the relay send path |
| `multiplex-peer` | — | no equivalent | one relay socket per allocation |
| `multiplex-peer-port` | — | no equivalent | as `multiplex-peer` |
| `multiplex-peer-max-peers` | — | no equivalent | as `multiplex-peer` |
| `no-udp-relay` | — | no equivalent | UDP relaying is always available |
| `no-tcp-relay` | `[turn.tcp_relay] enabled` | key | `false` (no TCP relay) is the default. RFC 6062 is beta, needs `[tls]`, IPv4 only — see [below](#things-that-are-not-a-translation) |
| `server-relay` | — | no equivalent | the permission check on relayed packets cannot be switched off |
| `ne` | — | by design | coturn ignores it too |
| `keep-address-family` | — | by design | the relayed family follows REQUESTED-ADDRESS-FAMILY (RFC 6156), never the client's transport family |
| `allocation-default-address-family` | — | by design | no key; an Allocate without REQUESTED-ADDRESS-FAMILY gets IPv4, which is coturn's default too |

### Authentication and users

| coturn | turna | kind | note |
|---|---|---|---|
| `lt-cred-mech` | `[[turn.auth.static_users]]`, `[turn.auth] shared_secret` | by design | long-term credentials are the only mechanism for client auth (OAuth aside), so there is no switch |
| `no-auth` | — | no equivalent | every Allocate is authenticated |
| `use-auth-secret` | `[turn.auth] shared_secret` | key | the REST scheme (`base64(HMAC-SHA1(secret, "expiry:name"))`) is what browsers use and works the same. Setting the secret is the switch |
| `static-auth-secret` | `[turn.auth] shared_secret` | key | file or env form: `"file:///run/secrets/turn"` or `"${TURNA_SHARED_SECRET}"`. Several coturn secrets: turna takes two — the current one and `[turn.auth] previous_shared_secret` for a rotation, reloaded on `SIGHUP`. Expiry is checked with `credential_clock_skew_secs` of grace |
| `rest-api-separator` | — | by design | fixed: the first `:` separates expiry from user id |
| `server-name` | `[turn.auth.oauth] server_name` | key | used, as in coturn, for OAuth (the AEAD associated data) |
| `oauth` | `[turn.auth.oauth] enabled` | key | implemented including `kid` key selection (`[[turn.auth.oauth.keys]]`, `strict_kid`) and the RFC 7635 §6.1 lifetime cap, **but `config::validate()` refuses it under `production = true`** pending interop against a real Authorization Server. Keys come from config, not a database |
| `user` | `[[turn.auth.static_users]]` `username` / `password` | key | plaintext password only; coturn's `0x…` pre-hashed key form has no equivalent. At runtime: gRPC `AddUser` / `turnactl user add` (needs the Tarantool backend) |
| `userdb` | — | by design | no SQLite; runtime users live in the Tarantool backend (`[cluster.backend]`), which stores pre-derived keys, never a password |
| `psql-userdb` | — | by design | as `userdb` |
| `mysql-userdb` | — | by design | as `userdb` |
| `mongo-userdb` | — | by design | as `userdb` |
| `redis-userdb` | — | by design | as `userdb` |
| `secret-key-file` | — | no equivalent | only encrypts coturn's MySQL password |
| `realm` | `[turn] realm` | key | several realms: one `[[tenants]]` entry each (`realm`, own secret, users, relay pool, quotas) |
| `check-origin-consistency` | — | no equivalent | ORIGIN is decoded and logged, never enforced (it is client-forgeable) |
| `stateless-nonce` | — | by design | nonces are always stateless: an HMAC over client address and issue time under a per-process key |
| `stateless-nonce-secret` | — | by design | the key is generated per process and not configurable; after a restart clients take one extra 401/438 |
| `stale-nonce` | — | by design | nonce lifetime fixed at 630 s |
| `secure-stun` | — | no equivalent | Binding is always answered without credentials (within the per-source budget); MESSAGE-INTEGRITY is verified when present |

### Quotas, lifetimes and rate limits

| coturn | turna | kind | note |
|---|---|---|---|
| `user-quota` | `[turn.relay.quota] max_per_user` | key | concurrent allocations per username. **Default 100** (coturn: 0 = unlimited); 0 is unlimited here too. Runtime: gRPC `SetUserLimits` |
| `total-quota` | `[turn.relay] max_allocations` | key | must not exceed the number of ports in the relay range — validation refuses it |
| `max-bps` | `[turn.relay.quota] max_bytes_per_sec_per_allocation` | key | bytes/second per allocation; coturn counts each direction separately, so check [CONFIGURATION.md](CONFIGURATION.md) before reusing a number. `0` (unlimited) is refused under `production = true` unless `allow_unlimited_bandwidth = true` |
| `bps-capacity` | — | no equivalent | `[turn.relay] max_packets_per_sec` is a capacity figure for reporting (`/capacity`), not an enforced ceiling |
| `max-allocate-lifetime` | — | no equivalent | no config key: the ceiling is fixed at 3600 s (`turn::MAX_LIFETIME`). A lower global, per-tenant or per-user cap is `max_lifetime_secs` in gRPC `SetUserLimits` |
| `channel-lifetime` | — | by design | fixed at 600 s (RFC 8656) |
| `permission-lifetime` | — | by design | fixed at 300 s (RFC 8656) |
| `max-allocate-timeout` | — | no equivalent | each request is bounded, the whole handshake is not |
| `unauthorized-ratelimit` | — | by design | always on and not configurable: at most 8 unauthenticated replies (401s and Binding responses alike) per second per source address, burst 64 |
| `unauthorized-ratelimit-rps` | — | by design | fixed at 8/s; see above. The configurable tiers are `[turn.rate_limit.default]` / `[turn.rate_limit.trusted]` with `[turn.rate_limit] trusted_prefixes` for NAT-heavy sources |

### STUN and TURN protocol behaviour

| coturn | turna | kind | note |
|---|---|---|---|
| `fingerprint` | — | by design | responses to authenticated requests always carry FINGERPRINT; not configurable |
| `stun-only` | — | no equivalent | TURN cannot be switched off |
| `no-stun` | — | no equivalent | Binding cannot be switched off |
| `no-software-attribute` | `[turn] software_attribute` | key | `"none"`. The default `"product"` sends `turna` without a version; `"full"` is refused under `production = true` |
| `mobility` | `[turn.migration] enabled` | key | RFC 8016; `ticket_secret` must be stable across restarts and nodes |
| `rfc5780` | — | no equivalent | RFC 5780 NAT behaviour discovery is not implemented <!-- parity-pr --> |
| `stun-backward-compatibility` | — | no equivalent | Binding responses carry XOR-MAPPED-ADDRESS only, never MAPPED-ADDRESS |
| `rfc3489-compatibility` | — | no equivalent | a request without the magic cookie is not STUN to turna |
| `rfc5766-channel-numbers` | — | by design | always accepted: turna takes channel numbers `0x4000`–`0x7FFE`, including the `0x5000`+ range RFC 8656 reserves ([COMPLIANCE.md](COMPLIANCE.md)) |
| `include-reason-string` | — | by design | reason phrases are fixed strings, mostly the standard phrase for the code |

### TLS and DTLS

| coturn | turna | kind | note |
|---|---|---|---|
| `cert` | `[tls] cert_path` | key | PEM chain. `[turn.dtls] cert_path` for DTLS. Reloaded without a restart: `[tls] cert_reload_secs` (default 30); `[turn.dtls] cert_reload_secs` (0 = off, the default; demux path only) |
| `pkey` | `[tls] key_path` | key | PKCS#8 / PKCS#1 / SEC1. DTLS (`[turn.dtls] key_path`) needs an ECDSA P-256 key |
| `pkey-pwd` | — | no equivalent | encrypted private keys are not supported |
| `raw-public-keys` | — | no equivalent | no RFC 7250 |
| `cipher-list` | — | no equivalent | rustls' safe defaults; not configurable <!-- parity-pr --> |
| `CA-file` | `[tls] client_ca` | key | mTLS on the TURNS listener; add `require_client_cert = true` to refuse clients without one |
| `ec-curve-name` | — | no equivalent | rustls chooses |
| `dh566` | — | by design | no finite-field DH: TLS 1.2+ with ECDHE only |
| `dh1066` | — | by design | as `dh566` |
| `dh-file` | — | by design | as `dh566` |
| `tlsv1` | — | by design | TLS 1.0 is never offered (rustls: 1.2 and 1.3) <!-- parity-pr --> |
| `tlsv1_1` | — | by design | TLS 1.1 is never offered <!-- parity-pr --> |
| `no-tlsv1_2` | — | no equivalent | 1.2 and 1.3 are both always offered; there is no minimum-version key <!-- parity-pr --> |
| `acme-redirect` | — | no equivalent | certificates are provisioned outside turna and picked up by the reload above |

Related turna keys with no coturn counterpart: `[tls] enable_alpn` / `alpn_required`
(RFC 7443 strict mode), `handshake_timeout_secs`, `max_connections_per_ip`,
`max_handshakes_per_sec_per_ip`. For DTLS, `[turn.dtls] accept_timeout_secs`
bounds a handshake — a problem coturn does not have and turna had to bound.

### Peer access control

This is where the two designs differ most, and where a line-by-line translation
is the wrong approach.

coturn's model is a denylist you must write. A hardened `turnserver.conf` carries
a dozen `denied-peer-ip` ranges, and getting that list right — in every address
representation — is the thing that has produced repeated bypass CVEs.

`turna` inverts it: the security-critical ranges are denied in code and an
allow-list **cannot** re-open them, private ranges are denied by default, and
peer addresses are normalized first so a single rule covers every
representation of the same IPv4. See [security/peer-filter.md](security/peer-filter.md).

| coturn | turna | kind | note |
|---|---|---|---|
| `allow-loopback-peers` | `[turn.peer_filter] allow_loopback_peers` | key | dev/test only; loopback peers are denied by default, as in coturn |
| `no-multicast-peers` | — | by design | always denied, and not configurable off |
| `denied-peer-ip` | `[turn.peer_filter] denied_peer_ranges` | key | CIDR list, on top of the profile. Loopback, RFC 1918, link-local (incl. cloud metadata), `::ffff:*`, ULA and the v4-embedding v6 prefixes need no entry — they are denied already |
| `allowed-peer-ip` | `[turn.peer_filter] allowed_peer_ranges` | key | CIDR list; allow wins over deny, but cannot re-open the always-denied special-use ranges. To relay into RFC 1918 wholesale, `[turn.peer_filter] profile = "lan"` |

**Do not port your `denied-peer-ip` list mechanically.** It is not needed for the
special-use ranges, and porting it can only add rules that were already implied.
What is worth porting is any *business* deny/allow list specific to your network.

### Logging and monitoring

| coturn | turna | kind | note |
|---|---|---|---|
| `verbose` | — | by design | log level is the `RUST_LOG` environment variable |
| `Verbose` | — | by design | as `verbose` (`RUST_LOG=debug`) |
| `no-stdout-log` | — | no equivalent | logs always go to stdout, for the init system to route <!-- parity-pr --> |
| `log-file` | — | no equivalent | no log file; stdout only <!-- parity-pr --> |
| `syslog` | `[turn.observability] syslog_endpoint` | by design | forwards **security events only** (auth failures, denials, rate-limit trips, audit entries) as RFC 5424 to `udp://` or `tcp://`; the general log does not go to syslog <!-- parity-pr --> |
| `syslog-facility` | — | no equivalent | the facility of the security-event export is not configurable <!-- parity-pr --> |
| `simple-log` | — | no equivalent | no log file to roll over <!-- parity-pr --> |
| `log-min-level` | — | by design | `RUST_LOG` |
| `new-log-timestamp` | — | by design | timestamps are always RFC 3339; `[turn.observability] json_logs = true` for structured output |
| `new-log-timestamp-format` | — | no equivalent | the timestamp format is fixed |
| `log-binding` | — | no equivalent | no switch for per-Binding logging; `RUST_LOG` is the only verbosity control |
| `prometheus` | `[health] listen` | by design | metrics are always on, at `/metrics` on the health listener |
| `prometheus-port` | `[health] listen` | key | address and port in one value |
| `prometheus-username-labels` | — | no equivalent | per-user traffic is not a metric label; gRPC `GetTopTalkers` answers the question at runtime |
| `redis-statsdb` | — | no equivalent | no allocation-event or traffic accounting export; allocation state lives in the Tarantool backend when clustered <!-- parity-pr --> |

Tracing has no coturn counterpart: `[turn.observability] otlp_endpoint`,
`trace_sample_rate`, `max_spans_per_second`.

### Alternate servers and draining

| coturn | turna | kind | note |
|---|---|---|---|
| `alternate-server` | `[cluster]` | by design | no static list. In cluster mode a node answers 300 Try Alternate with the owning node's address, and during drain; outside it, run independent nodes behind DNS as you would coturn |
| `tls-alternate-server` | `[cluster]` | by design | as `alternate-server` |
| `udp-alternate-server` | `[cluster]` | by design | as `alternate-server` |
| `tcp-alternate-server` | `[cluster]` | by design | as `alternate-server` |
| `drain-min-allocations` | `[turn.relay] drain_timeout_secs` | by design | drain starts on SIGTERM or gRPC `SetDraining` (not SIGUSR1); the node stops accepting and waits up to `drain_timeout_secs` for allocations to end, not for a count. `[cluster] drain_grace_secs` for a cluster member |

### Administration and process

| coturn | turna | kind | note |
|---|---|---|---|
| `cli` | `[management] listen` | by design | no telnet CLI. Management is gRPC, served by `turna-control-plane` at `[management] listen` (loopback by default); `turnactl` wraps part of it |
| `cli-ip` | `[management] listen` | by design | as `cli` |
| `cli-port` | `[management] listen` | by design | as `cli` |
| `cli-password` | `[grpc] tls_mode` | by design | no password: plaintext only on loopback (validation refuses otherwise in production), `"mtls"` for remote access, plus `[grpc.rbac]` |
| `cli-max-output-sessions` | — | no equivalent | no CLI sessions |
| `web-admin` | — | by design | the admin UI is a separate process, `turna-admin` (`services/admin`), with its own configuration |
| `web-admin-ip` | — | by design | as `web-admin` |
| `web-admin-port` | — | by design | as `web-admin` |
| `web-admin-listen-on-workers` | — | no equivalent | as `web-admin` |
| `pidfile` | — | no equivalent | leave it to the init system |
| `proc-user` | — | no equivalent | the service unit or container sets the user |
| `proc-group` | — | no equivalent | as `proc-user` |

Two operational changes that are not option lines: a limit change is gRPC
`UpdateConfig` / `SetUserLimits` on `turna-control-plane` — no restart,
versioned and idempotent (`turnactl` has no command for it) — rather than an
edit and `systemctl restart`; and `turnadmin`'s user management is gRPC
`AddUser` / `RemoveUser` (`turnactl user add` / `user remove`).

## Features with no coturn option line

Differences an operator comparing the two will ask about, as they stand on
`main`:

| Feature | turna today |
|---|---|
| USERHASH (RFC 8489 §14.4) | not implemented; a request carrying it is answered 420, as for any unknown comprehension-required attribute <!-- parity-pr --> |
| ADDITIONAL-ADDRESS-FAMILY (one Allocate, both families) | not implemented — blocked on a storage decision, [design/additional-address-family.md](design/additional-address-family.md) <!-- parity-pr --> |
| IPv6 for RFC 6062 TCP relay | not implemented; a v6 TCP allocation answers 440 <!-- parity-pr --> |
| Authentication through an external HTTP service | not available; users come from config, the REST secret or the Tarantool backend <!-- parity-pr --> |
| Automatic banning of abusive sources | not available; the per-source rate limits refuse, they do not ban <!-- parity-pr --> |
| Distribution packages (deb/rpm) | not available; build from source and install the binary with `deploy/systemd`, or build the image from `deploy/Dockerfile` / use the Helm chart ([DEPLOY.md](DEPLOY.md)) <!-- parity-pr --> |

## Things that are not a translation

**Clustering.** If you were running N independent coturn instances behind
round-robin DNS or `alternate-server`, that keeps working — point clients at
several `turna` nodes the same way. `turna`'s cluster mode adds gossip discovery
and shared allocation metadata, but read the honest boundary first: it does
**not** migrate a live media path between nodes, and neither did your coturn
setup. Do not treat cluster mode as a prerequisite for migrating.

**TCP relay (RFC 6062).** If you relied on `no-tcp-relay` being *off* — i.e. you
actually relay TCP — enable `[turn.tcp_relay]`. It is beta and off by default.
It was refused under `production = true` until 2026-08-25, when interop with
coturn's own client put the missing evidence on record
(`docs/interop/coturn-2026-08-23.md`); it is allowed now. Two conditions: `[tls]`
must be enabled, because turna has no plain-TCP listener and RFC 6062's control
connection therefore runs over TURNS (validation refuses the combination under
`production = true`); and it is IPv4 only. Size for it first — a listener and a
connection per relayed peer is a different profile from UDP relaying.

**io_uring / AF_XDP.** Migrate on `transport = "tokio"` first and evaluate
backend changes separately. io_uring is now [supported on Linux](verification/io-uring-supported-2026-09-19.md)
for the stated UDP scope; AF_XDP is [supported within its verified Linux IPv4 UDP
copy-mode scope](verification/af-xdp-supported-2026-09-22.md). This does not extend
support to every listener/backend combination. In particular SCTP requires tokio.
Validate the full configuration and required listeners before cutover.

**Per-source limits.** coturn applies no Allocate rate limit by default; turna
does (`[turn.rate_limit.default]`: burst 32, 16 Allocates/s per source address),
plus the fixed unauthenticated-reply budget above. An office or VPN egress with
hundreds of users behind one address needs its prefix in
`[turn.rate_limit] trusted_prefixes` before cutover, or its users' ICE gathering
will time out at the top of the hour.

## A minimal equivalent config

A common hardened coturn file:

```
listening-port=3478
tls-listening-port=5349
external-ip=203.0.113.10
min-port=49152
max-port=65535
realm=turn.example.com
lt-cred-mech
use-auth-secret
static-auth-secret=SECRET
cert=/etc/coturn/cert.pem
pkey=/etc/coturn/key.pem
no-cli
no-multicast-peers
no-loopback-peers
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
user-quota=12
total-quota=1200
```

becomes:

```toml
production = true

[turn]
listen      = "0.0.0.0:3478"
external_ip = "203.0.113.10"
realm       = "turn.example.com"
transport   = "tokio"

[turn.auth]
shared_secret = "file:///run/secrets/turn_shared_secret"

[turn.relay]
min_port        = 49152
max_port        = 65535
max_allocations = 1200

[turn.relay.quota]
max_per_user                     = 12
max_bytes_per_sec_per_allocation = 12500000   # ~100 Mbit/s; 0 is refused in production

[tls]
enabled   = true
listen    = "0.0.0.0:5349"
cert_path = "/etc/turna/cert.pem"
key_path  = "/etc/turna/key.pem"

[health]
listen = "0.0.0.0:9090"

[management]
listen = "127.0.0.1:5350"
```

Every `denied-peer-ip` line, `no-cli`, `no-multicast-peers` and
`no-loopback-peers` disappear — not because they are unsupported, but because
they are the default and cannot be configured away.

## Verifying the migration

1. Check the translation without starting a listener:

   ```
   turna-node --dump-config /etc/turna/turn.toml
   ```

   It loads and validates the file, prints the effective configuration with
   secrets masked, and exits. Validation is fail-fast, so anything the validator
   rejects — a placeholder secret, a missing `external_ip` under `production`, an
   `io_uring` datapath next to an enabled SCTP listener — aborts here rather than at 3am.
2. Point one client at the new server with `iceTransportPolicy: "relay"` and
   confirm a relay candidate. The browser interop procedure that was used for
   TURNS is in [interop/v0.3.0-rc.1.md](interop/v0.3.0-rc.1.md).
3. Run the relay-abuse checks before exposing it:
   [security/relay-abuse-testing.md](security/relay-abuse-testing.md).
4. Compare `turna_active_allocations` against the load you expected from coturn's
   session count before cutting DNS over.
5. To compare the two servers on your own hardware — allocation rate, relay
   throughput and loss, memory per allocation, CPU — `bench/matrix.sh` runs the
   same scenarios against both ([bench/README.md](../bench/README.md)).

## Keeping this document true

The option list is coturn's, at the date above; a newer coturn may add options
that are not here. The turna side is checked: `scripts/check-doc-claims.sh`
resolves every `[section]` and `[section] key` named in the tables' turna and
note columns against the config structs in `crates/config/src/lib.rs`, by path,
and every bare `snake_case` key in a note against its row's turna-column
section (a gRPC field is accepted only where the note says gRPC). Prose outside
the tables is not checked. What it cannot check is a
"no equivalent" that has become wrong because turna gained the feature — the
`parity-pr` markers flag the rows where that is expected soon.
