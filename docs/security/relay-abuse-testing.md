# Relay-abuse verification

Procedure for proving that a running `turna-node` cannot be used as a general
purpose proxy into the network it sits in. Run it against your own server, on a
release build, before any deployment that faces untrusted clients.

**Fill in the Result column from an actual run.** An unfilled table is not
evidence — the same rule the rest of this repo applies to benchmark numbers.

## Why this document exists

Relay abuse is the primary threat to a TURN server: the protocol's whole job is
forwarding traffic to an address the client names, so a server without peer
restrictions is an open proxy that reaches localhost, RFC 1918 space and cloud
metadata endpoints. Published incidents have used exactly this to retrieve cloud
IAM credentials.

The reference implementation has been bypassed three times in this class, always
by an address *representation* the filter did not recognise: first `0.0.0.0`,
`[::]` and `[::1]`, then IPv4-mapped IPv6 (`::ffff:127.0.0.1`) as a bypass of
that fix, then the mapped form again against a different guard. The lesson is
that the filter logic being correct is not the same as every representation
reaching it.

## What this proves and what it does not

* **Proves:** the filter is *wired* at every entry point where a peer address
  enters the relay, over the transports you actually enable.
* **Does not prove:** that the filter's decision logic is right. That is what the
  unit tests in `crates/relay/src/peer_filter.rs` are for. Both halves are
  needed: a correct function that is not called is worth nothing, and a called
  function that is wrong is worth nothing.

## Setup

Build and run a node with the transports you intend to expose:

```
cargo build --release
./target/release/turna-node deploy/turn.toml
```

Two things about the configuration under test:

* `production = true` is the honest setting to test, but note that it **refuses**
  `[turn.tcp_relay] enabled = true`. TCP relay is the higher-impact vector
  (arbitrary TCP, not just UDP), so if you intend to ship it, test it separately
  with `production = false` and treat the result as a gate on ever enabling it.
* Do **not** set `allow_loopback_peers` or `TURNA_ALLOW_LOOPBACK_PEERS=1`. Those
  exist for local test rigs and switch off a tier-1 deny.

The tool for part A is `stunner` (<https://github.com/firefart/stunner>), listed
in Enable Security's RTC-hacking resources. Common flags: `-s host:port`,
`-u`/`-p` for credentials, `--protocol tcp|udp`, `--tls`, `-d` for debug. Check
`--help` for the exact spelling in the version you get.

## Part A — the scans an attacker runs first

`range-scan` walks a set of private and restricted ranges and reports which ones
the server will forward to. Every range must come back unreachable.

```
./stunner info      -s YOUR_HOST:3478 -u USER -p PASS
./stunner range-scan -s YOUR_HOST:3478 -u USER -p PASS --protocol udp
```

| # | Check | Expected | Result |
|---|---|---|---|
| A1 | `info` connects and reports server details | connects; no unexpected capability advertised | |
| A2 | `range-scan --protocol udp` | every range unreachable | |
| A3 | `range-scan --protocol tcp` (only if `[turn.tcp_relay]` is on) | every range unreachable | |
| A4 | SOCKS proxy module against an internal service you control | connection refused / never established | |

Notes on A3/A4: the SOCKS module relays **TCP only**, so with `[turn.tcp_relay]`
disabled (the default) it has nothing to work with. A "nothing happened" result
there means the feature is off, not that the filter held — record which it was.

## Part B — representation vectors

`range-scan` knows about private ranges. It does **not** know about the IPv6
transition forms, and those are precisely where the reference implementation
kept failing. These need a client that will put an arbitrary address into
`XOR-PEER-ADDRESS` — coturn's `turnutils_uclient -e <peer>` works, or extend
`tools/diff-test`.

Send a `CreatePermission` (and, separately, a `Send` indication and a
`ChannelBind`) for each address below. All must be refused with **403 Forbidden**,
and `turna_peer_rejected_total` must increase by one per attempt.

| # | Peer address | Reaches | Expected | Result |
|---|---|---|---|---|
| B1 | `127.0.0.1` | localhost | 403 | |
| B2 | `::1` | localhost | 403 | |
| B3 | `::ffff:127.0.0.1` | localhost via IPv4-mapped | 403 | |
| B4 | `::127.0.0.1` | localhost via IPv4-compatible `::/96` | 403 | |
| B5 | `64:ff9b::7f00:1` | localhost via NAT64 | 403 | |
| B6 | `2002:7f00:1::` | localhost via 6to4 | 403 | |
| B7 | `169.254.169.254` | cloud metadata | 403 | |
| B8 | `::ffff:169.254.169.254` | cloud metadata, mapped | 403 | |
| B9 | `64:ff9b::a9fe:a9fe` | cloud metadata via NAT64 | 403 | |
| B10 | `2002:a9fe:a9fe::` | cloud metadata via 6to4 | 403 | |
| B11 | `0.0.0.0` and `0.0.0.1` | "this host on this network" | 403 | |
| B12 | `2001::1` | Teredo prefix | 403 | |
| B13 | `100::1` | discard prefix | 403 | |
| B14 | `10.0.0.1`, `192.168.1.1`, `172.16.0.1`, `fd00::1` | RFC 1918 / ULA | 403 under the default `internet-facing` profile | |
| B15 | `100.64.0.1` | CGNAT shared space | 403 | |
| B16 | `240.0.0.1` | reserved | 403 | |

Repeat B3–B6 and B8–B10 over **every** enabled client transport (plain UDP,
TURNS on 5349, DTLS, QUIC). The filter lives in the shared packet processor, so
one transport passing is strong evidence for the rest — but the point of this
part is to catch a listener that bypasses the processor, which is exactly what a
per-transport run would reveal.

If `[turn.tcp_relay]` is enabled, repeat the whole table using `Connect` rather
than `Send`. That path opens a TCP socket to the peer and is the one worth the
most attention.

## Part C — negative controls

A table of all-403 can mean the filter works, or that relaying is broken
entirely, or that it over-blocks. These must **succeed**.

| # | Peer address | Expected | Result |
|---|---|---|---|
| C1 | `8.8.8.8` | permission created, relay works end to end | |
| C2 | `2606:4700:4700::1111` | permission created | |
| C3 | `64:ff9b::808:808` (NAT64 to 8.8.8.8) | permission created — a legitimate NAT64 peer must stay reachable | |
| C4 | `2002:808:808::` (6to4 to 8.8.8.8) | permission created | |
| C5 | `203.0.113.1` | permission created — the documentation range is deliberately not blocked | |
| C6 | Real media through the relay | bytes flow both directions | |

C3 and C4 are the important ones. A blanket deny of the transition prefixes would
pass all of part B and quietly break every client on an IPv6-only network.

## Part D — availability, not confidentiality

Relay abuse is one of three threat categories; the other two are denial of
service and plain software vulnerability. Worth recording in the same run:

| # | Check | Expected | Result |
|---|---|---|---|
| D1 | Unauthenticated allocation flood | rejected; `turna_auth_failures` rises; node stays Ready | |
| D2 | Allocation quota exhaustion per user | 486; other users unaffected | |
| D3 | `stunner`'s TLV boundary / memory-disclosure module | no memory returned | |
| D4 | Bandwidth cap per allocation | enforced; `turna_quota_exceeded_total` rises | |

## Recording the result

Append a dated block per run: turna commit SHA, build features, config profile,
tool version, and the filled tables. Keep failed runs — a fixed finding with its
before/after is worth more than a table that was green on the first try.

Do not summarise this file as "passed" anywhere else in the repo until every row
has a result.
