# Enterprise network profile

What turna needs from a corporate network, and what it does when it does not get
it. Written from what has actually gone wrong here rather than from a template —
the proxy entry below cost an afternoon.

## Ports

| port | protocol | direction | required | notes |
|---|---|---|---|---|
| 3478 | UDP | inbound | yes | TURN/STUN. The path everything else falls back from. |
| 3478 | TCP | inbound | no | TURN over TCP. Only if clients cannot use UDP at all. |
| 5349 | TCP | inbound | recommended | TURNS. **Put it on 443 instead** — see below. |
| 443 | TCP | inbound | recommended | TURNS on the port no firewall blocks. One config value. |
| 49152–65535 | UDP | inbound | yes | Relay range, narrowable via `[turn.relay] min_port`/`max_port`. |
| 9090 | TCP | inbound | no | Health and metrics. Bind to a management interface, not the public one. |
| 9443 | TCP | inbound | no | gRPC management, mTLS. Same. |
| 3301 | TCP | outbound | only if clustered | Tarantool. |
| 7946 | TCP+UDP | both | only if clustered | Gossip between nodes. |

The relay range is the entry that surprises people: it must be open inbound, it
is large by default, and it must not overlap the host's ephemeral range. Check
with `cat /proc/sys/net/ipv4/ip_local_port_range` — a peer socket landing inside
the relay range makes the relay forward to itself, which has happened here.

## Why TURNS belongs on 443

A relay exists for clients whose network blocks the direct path. Those same
networks block 5349. Running TURNS on 443 makes it indistinguishable from HTTPS
to a firewall doing port-based filtering, which is most of them.

This is a config value, not a build option: `[tls] listen = "0.0.0.0:443"`. The
cost is that 443 is usually taken, so the node needs its own address or a
front-end that passes TCP through untouched — not one that terminates TLS, since
TURNS is not HTTP and a terminating proxy will not forward it.

## Proxies

**A system HTTP proxy silently prevents WebTransport.** Chrome returns
`ERR_TUNNEL_CONNECTION_FAILED`, zero packets reach the node, nothing appears in
its logs, and `nc` from the same machine works. Diagnosing this took an afternoon
because every signal on the server side said "no client ever arrived", which is
true and unhelpful.

If WebTransport fails and the node sees nothing, check the client's proxy
settings before anything else.

| proxy type | UDP TURN | TURNS 443 | WebTransport | DTLS |
|---|---|---|---|---|
| No proxy | works | works | works | works |
| HTTP CONNECT, TCP only | blocked | works | **blocked** | blocked |
| SOCKS5 with UDP associate | works | works | depends on client | works |
| TLS-terminating front end | n/a | **breaks** — TURNS is not HTTP | breaks | n/a |
| Transparent TCP pass-through | n/a | works | works | n/a |

The row that catches deployments is the last but one. A load balancer configured
for HTTPS will accept the TURNS connection and then fail to speak TURN, and the
symptom is a handshake that completes followed by silence.

## Firewalls with connection tracking

A relay holds thousands of UDP flows, each idle between talk bursts. Two things
follow.

**UDP timeouts must exceed the client's keepalive.** Linux conntrack defaults to
30 seconds for unreplied UDP and 120 for established. TURN clients refresh every
few minutes, so a 30-second timeout drops flows between refreshes and the call
survives only because ICE re-establishes — visible to the user as a glitch.

**The conntrack table must be sized for the flow count**, not the client count.
Each relayed session is at least two flows. A node at 10 000 sessions wants
`net.netfilter.nf_conntrack_max` well above 20 000, and the failure when it is
not is packet loss that looks exactly like capacity exhaustion.

## MTU

The relay does not fragment and honours DONT-FRAGMENT on both address families.
A path with an MTU below the client's assumption drops large frames silently, and
the symptom is video failing while audio works — audio frames are small enough.

If a deployment has tunnels in the path, the clients need their MTU lowered;
there is nothing the relay can do about a packet it must not fragment.

## IPv6

Relayed IPv6 works and is verified between two globally routable addresses. Two
limits worth knowing before designing around it: `ADDITIONAL-ADDRESS-FAMILY` is
not implemented, so a client cannot request both families in one allocation; and
the RFC 6062 TCP relay is IPv4-only — an IPv6 `Connect` answers 440.

## What to give a network team

Ports table above, the conntrack numbers, and one sentence: TURNS on 443, and no
TLS termination in front of it. Those three are what most escalations turn out to
be.
