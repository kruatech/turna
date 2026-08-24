# Migrating from coturn

Option-by-option mapping from `turnserver.conf` to `turn.toml`, plus the places
where the two servers do not have equivalent behaviour and you have to make a
decision rather than translate a line.

Read [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) first if you are moving
production traffic — several coturn features map onto something `turna` marks
experimental, and one maps onto something it refuses outright under
`production = true`.

## The shape of the difference

coturn is configured by a flat file of ~200 flags plus, optionally, a SQL or Redis
database for users. `turna` is configured by a TOML file, and anything that
changes at runtime (limits, users) goes through a gRPC API instead of a file
reload or a database row. So a migration has three parts:

1. static configuration → `turn.toml` (the tables below);
2. users and credentials → either static config or the runtime API;
3. anything you were doing with `turnadmin`, the telnet CLI, or SQL → `turnactl`.

## Listeners and addressing

| coturn | turna | notes |
|---|---|---|
| `listening-port=3478` | `[turn] listen = "0.0.0.0:3478"` | address and port are one value |
| `listening-ip=1.2.3.4` | same `[turn] listen` | multiple `listening-ip` lines have no single-key equivalent — run one process per public IP, which is the canonical topology here |
| `tls-listening-port=5349` | `[tls] listen = "0.0.0.0:5349"` | plus `[tls] enabled = true`, and the binary must be built `--features tls` |
| `external-ip=1.2.3.4` | `[turn] external_ip = "1.2.3.4"` | required under `production = true`; empty is refused |
| `external-ip=PUBLIC/PRIVATE` | `[turn] external_ip` = the public one | the NAT-mapping form has no direct equivalent; set `listen` to the private address and `external_ip` to the public one |
| `relay-ip=…` | — | relay sockets bind on the same interface as `listen` |
| `min-port` / `max-port` | `[turn.relay] min_port` / `max_port` | same meaning. Keep the range and the firewall in agreement — `scripts/check-deploy-consistency.sh` checks the three places it is declared |
| `realm=turn.example.com` | `[turn] realm` | same |
| `no-udp` / `no-tcp` / `no-tls` / `no-dtls` | omit the corresponding section, or `enabled = false` | there is no "start everything then switch bits off" model |

## Authentication

| coturn | turna | notes |
|---|---|---|
| `use-auth-secret` + `static-auth-secret=S` | `[turn.auth] shared_secret = "S"` | the REST ephemeral-credential scheme (`base64(HMAC-SHA1(secret, "expiry:name"))`) works the same; this is what browsers use |
| `lt-cred-mech` + `user=name:password` | static users in config, or `turnactl user add` | the runtime path needs the Tarantool backend — see below |
| `static-auth-secret` in a DB table | — | no SQL backend exists. Use the file/env form: `shared_secret = "file:///run/secrets/turn"` or `"${TURNA_SHARED_SECRET}"` |
| users in MySQL/PostgreSQL/SQLite/Redis | Tarantool backend + `turnactl user add` | this is the biggest structural change in a migration. `AddUser`/`RemoveUser` persist pre-derived long-term keys, never a plaintext password |
| `oauth` (RFC 7635) | `[turn.auth.oauth]` | implemented including `kid` key selection and the §6.1 lifetime cap, **but the validator refuses it under `production = true`** pending interop against a real Authorization Server. coturn's own model expects an external program to manage keys in the database; turna reads them from config |
| `max-allocate-lifetime` | `[turn.relay.quota]` lifetime overrides, per user/tenant | also settable at runtime via `set_user_limits` |

## Peer access control

This is where the two designs differ most, and where a line-by-line translation
is the wrong approach.

coturn's model is a denylist you must write. A hardened `turnserver.conf` carries
a dozen `denied-peer-ip` ranges, and getting that list right — in every address
representation — is the thing that has produced repeated bypass CVEs.

`turna` inverts it: the security-critical ranges are denied in code and an
allow-list **cannot** re-open them, private ranges are denied by default, and
peer addresses are normalized first so a single rule covers every
representation of the same IPv4.

| coturn | turna |
|---|---|
| the whole `denied-peer-ip` block for loopback, RFC 1918, link-local, `::1`, `::ffff:*`, ULA | nothing to write — that is the default. See [security/peer-filter.md](security/peer-filter.md) |
| `no-loopback-peers` | default; `[turn.peer_filter] allow_loopback_peers = true` is the dev-only opt-out |
| `no-multicast-peers` | default, and not configurable off |
| `allowed-peer-ip=10.20.0.0/16` | `[turn.peer_filter] allowed_peer_ranges = ["10.20.0.0/16"]` |
| `denied-peer-ip=203.0.113.0/24` | `[turn.peer_filter] denied_peer_ranges = ["203.0.113.0/24"]` |
| — | `[turn.peer_filter] profile = "lan"` if you *want* RFC 1918 relaying (the default `internet-facing` denies it) |

**Do not port your `denied-peer-ip` list mechanically.** It is not needed for the
special-use ranges, and porting it can only add rules that were already implied.
What is worth porting is any *business* deny/allow list specific to your network.

## Quotas and rate limiting

| coturn | turna |
|---|---|
| `user-quota` | `[turn.relay.quota] max_per_user` |
| `total-quota` | `[turn.relay] max_allocations` |
| `max-bps` | `[turn.relay.quota] max_bytes_per_sec_per_allocation` (bytes/second) — `0` is unlimited and is **refused** under `production = true` unless you also set `allow_unlimited_bandwidth = true` |
| `unauthorized-ratelimit` (4.14+) | tiered rate limiting is on by default; see the auth-failure metrics |

## TLS

| coturn | turna |
|---|---|
| `cert=` / `pkey=` | `[tls] cert_path` / `key_path` |
| `no-tlsv1`, `no-tlsv1_1` | not needed — the listener does not offer them |
| `dh2066`, `cipher-list` | not exposed |
| certificate reload | automatic on mtime change, no restart and no signal |

DTLS is a separate section, `[turn.dtls]`, and needs `--features dtls`. Note
`handshake_timeout_secs` there: it has no coturn equivalent because coturn does
not have the unbounded-handshake problem `turna` had to bound.

## Operations

| coturn | turna |
|---|---|
| `prometheus`, `prometheus-port=9641` | always on, at `[health] listen` → `/metrics` |
| `verbose`, `log-file`, `syslog`, `simple-log` | `[turn.observability] json_logs`; logs go to stdout, for the init system to route |
| `no-cli` (disable the telnet admin) | nothing to disable — there is no telnet CLI. Management is gRPC at `[management] listen`, loopback by default |
| `turnadmin` | `turnactl` |
| edit config + `systemctl restart` for a limit change | `turnactl` / gRPC `update_config`, no restart, versioned and idempotent |
| `pidfile` | leave it to the init system |

## Things that are not a translation

**Clustering.** If you were running N independent coturn instances behind
round-robin DNS or `alternate-server`, that keeps working — point clients at
several `turna` nodes the same way. `turna`'s cluster mode adds gossip discovery
and shared allocation metadata, but read the honest boundary first: it does
**not** migrate a live media path between nodes, and neither did your coturn
setup. Do not treat cluster mode as a prerequisite for migrating.

**TCP relay (RFC 6062).** If you relied on `no-tcp-relay` being *off* — i.e. you
actually relay TCP — note that `[turn.tcp_relay]` is **refused under
`production = true`** pending interop verification. That is a real blocker for a
production migration, not a formality.

**io_uring / AF_XDP.** Do not enable these as part of a migration. They are
experimental, and they do not start the TURNS, TCP-relay, SCTP or mobility
listeners at all — the config validator will refuse the combination. Migrate on
`transport = "tokio"` and evaluate datapaths separately.

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
   `io_uring` datapath next to a TURNS listener — aborts here rather than at 3am.
2. Point one client at the new server with `iceTransportPolicy: "relay"` and
   confirm a relay candidate. The browser interop procedure that was used for
   TURNS is in [interop/v0.3.0-rc.1.md](interop/v0.3.0-rc.1.md).
3. Run the relay-abuse checks before exposing it:
   [security/relay-abuse-testing.md](security/relay-abuse-testing.md).
4. Compare `turna_active_allocations` against the load you expected from coturn's
   session count before cutting DNS over.

## Gaps in this document

Written against the option names in coturn's `turnserver.conf` reference and
`turna`'s `crates/config`. Options not covered here are ones where no equivalent
was confirmed rather than ones known to be absent — if you depend on a
`turnserver.conf` line that is missing above, treat it as unmapped and check
[CONFIGURATION.md](CONFIGURATION.md) rather than assuming a default.
