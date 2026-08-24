# Relayed media — IPv6 and QUIC — 2026-08-19

Both paths previously had only control-plane evidence: an allocation was granted and a
permission accepted, and nothing had ever carried a byte. That distinction stopped
being academic the same day, when the io_uring datapath was found to answer 10 800
allocations per second while forwarding nothing at all. These two runs close the gap
for IPv6 and raw QUIC.

Host: Ubuntu 24.04, kernel 6.14, 32 cpus. Loopback, `production = false`,
`[turn.peer_filter] allow_loopback_peers = true`, relay ports 20000–20847.

## IPv6 relayed transport

`turna-load-test channel-data --family v6` — allocates with
`REQUESTED-ADDRESS-FAMILY = IPv6`, binds its peer socket on `[::1]` (it must match
the relayed family, or RFC 6156 §4.2 refuses the permission with 443), and relays
real traffic through it.

Server: `[turn] external_ip6 = "::1"`.

| | |
|---|---|
| frames sent | 20 000 |
| **frames relayed back to the peer** | **20 000** |
| errors / loss | 0 / 0 |
| bytes out → in | 3.28 MB → 3.20 MB |
| rps | 1 000 |
| latency p50 / p95 / p99 | 0.5 ms / 1 ms / 1 ms |

**Pass.** The v6 relay socket, the v6 permission and the v6 channel binding all carry
traffic. Combined with the conformance run
(`conformance-2026-08-18.md` — 440 when `external_ip6` is unset, 443 on a
cross-family peer, the v4-embedding transition prefixes denied), the IPv6 relay path
is verified end to end.

### Routable IPv6, 2026-08-23

Repeated on a host with real global addresses: the node on `2a0c:db40:0:82fe::3`, the
peer on `2a0c:db40:0:82fe::2` — two routable addresses, not loopback and not a ULA on a
down bridge.

| | |
|---|---|
| frames sent | 6 010 |
| **relayed back to the peer** | **6 010** |
| errors / loss | 0 / 0 |
| bytes out → in | 962 KiB → 939 KiB |
| latency p50 / p99 / max | 0.5 ms / 0.5 ms / 1.9 ms |

`[turn.peer_filter] profile = "lan"` with **no** `allow_loopback_peers`: the earlier run
needed that concession because both ends sat on `::1`, and it is what made the result
weaker than it looked. This one does not.

What remains outside this: routing between *different hosts*. Both addresses belong to
one machine, so the frames cross the v6 stack and the v6 relay socket but not a router.
The client machine here reaches the internet through a proxy on this same server, so an
"external" run from it would leave from this address anyway — a genuinely off-host test
needs a second machine with its own v6.

### A client bug this found

The control socket was bound in the v4 family unconditionally
(`peer_bind_addr(false)`), so against a v6 server it could not send at all. The request
never left, `allocate` failed with no response to report, and the run showed 10 setup
errors and zero packets while the server logged **nothing** — because nothing reached
it. `tcpdump` proved the path was fine, which is what pointed at the client.

The family now follows the server's address (`control_bind_addr`). The same fix applies
to the DTLS client, which had the identical hardcoded v4 bind.

**Not covered:** routing between different hosts, as above.
Also unchanged: `ADDITIONAL-ADDRESS-FAMILY` is not implemented
(`docs/design/additional-address-family.md`), and RFC 6062 TCP relay stays IPv4-only.

## TURN over raw QUIC, including media

`turna-load-test quic-check`, extended to relay media rather than stopping at
CreatePermission.

| step | result |
|---|---|
| QUIC handshake, ALPN `stun.turn` | ok |
| 401 challenge on the control stream | ok |
| Authenticated Allocate | ok, relayed `127.0.0.1:20000` |
| CreatePermission | ok |
| ChannelBind, channel `0x4000` | ok |
| **client → relay → peer** | **20/20 frames arrived at the peer socket** |
| **peer → relay → client** | **returned as ChannelData on the same QUIC stream (30 bytes)** |
| session close | clean |

**Pass.** The reverse direction is the one worth noting: the peer's UDP packet was
picked up on the relay socket, wrapped as ChannelData, and routed back onto the
client's own QUIC stream. That exercises the per-stream reply routing, which is the
part of the QUIC bridge most likely to be subtly wrong and which no control-plane
check touches.

**Not covered:** sustained load or duration on QUIC (the soak harness drives UDP
only), the WebTransport/H3 path (no client), and any implementation other than this
one — a client written against the same reading of the spec as the server will agree
with it about a shared misreading.

## Why these runs exist in this form

A control-plane check answers "was the allocation granted". A media check answers "did
a byte move". Those are different questions, and for three hours on 2026-08-19 the
io_uring datapath answered the first with a resounding yes and the second, silently,
with no.

Every verification here now ends at a byte arriving somewhere, not at a `200 OK`.
