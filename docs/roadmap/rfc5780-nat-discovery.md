# RFC 5780 — NAT behaviour discovery

**Implemented 2026-09-24, opt-in, UDP only.** This page used to explain why it was
deferred; it now records what was built, what was left out on purpose, and what is
still owed. Operator reference: `[turn.nat_discovery]` in
[CONFIGURATION.md](../CONFIGURATION.md). Evidence:
[interop/rfc5780-natdiscovery-2026-09-24.md](../interop/rfc5780-natdiscovery-2026-09-24.md).

## What it is

A STUN extension letting a client work out what kind of NAT it is behind —
whether mappings depend on the destination, whether filtering does. A client that
knows can pick a connection strategy instead of trying everything.

## The constraint that shaped it

**It needs a second IP address on the node.** The mechanism rests on the server
answering from a different address or port than the request arrived on, so the
client can observe whether its mapping changed. `OTHER-ADDRESS` advertises where
that second address is; `CHANGE-REQUEST` asks the server to use it. One address
cannot implement it — that is the RFC, not this design — so config validation
refuses `enabled = true` without two concrete addresses of the same family, exactly
as coturn refuses CHANGE-REQUEST without two listening IPs.

## What was built

| piece | where |
|---|---|
| `CHANGE-REQUEST` (0x0003) decode/encode, `RESPONSE-ORIGIN` (0x802B), `OTHER-ADDRESS` (0x802C) | `proto-stun/src/attribute.rs`, getters in `message.rs` |
| Response logic: Table 1 source selection, MAPPED + XOR-MAPPED, RESPONSE-ORIGIN, OTHER-ADDRESS | `PacketProcessor::handle_nat_discovery` |
| Four sockets A1:P1, A1:P2, A2:P1, A2:P2 and the reply-socket choice | `relay/src/nat_discovery.rs` |
| Config, validated: two same-family concrete addresses, two distinct ports, no collision with UDP listeners or relay ranges | `[turn.nat_discovery]`, `crates/config` |

**Separate sockets, not the TURN listener.** The TURN listener may be io_uring,
AF_XDP or a reuseport group, and none of those can reply from a socket other than
the one a request arrived on. Teaching every datapath to do so would touch the hot
path of every deployment for a feature almost none enable. The discovery service
therefore runs on its own four sockets (RFC 5780 §9.2 allows a separate port,
advertised with the `stun-behavior` SRV name), and the TURN listener keeps
answering CHANGE-REQUEST with 420 — which §6 requires of a socket with no
alternate.

The trap noted here before still holds and is now a test: **`CHANGE-REQUEST` is
attribute 0x0003**, the value `ATTR_ALTERNATE_SERVER` wrongly held for three
releases. `change_request_is_not_alternate_server` pins them apart.

## Amplification

Each reply is unauthenticated, and CHANGE-REQUEST lets a spoofed request aim
replies from three different sources at a victim. coturn keeps RFC 5780 off by
default for this reason, and so does turna. When on:

- every request passes the configured `[turn.rate_limit]` ingress tiers and then
  the unauthenticated-reply budget (the one Binding and 401 already share) before
  anything — success, 401 or 420 — is sent;
- PADDING (§7.6) and RESPONSE-PORT (§7.5), the two attributes §10 discusses, are
  not implemented; both are optional for a server and are answered 420, so a reply
  always goes to the request's source and is never padded;
- only Binding is served on the four sockets; TURN methods are dropped.

## Still owed

- A run from behind a real NAT against two public addresses. The recorded interop is
  loopback, which proves the wire and the socket choice but not NAT classification.
- TCP and TLS (§6 SHOULD).
- Advertised-address overrides for a node behind 1:1 NAT: RESPONSE-ORIGIN and
  OTHER-ADDRESS name the bound addresses today.

## Whether it is worth doing

Unchanged from when this was deferred: WebRTC clients rarely use NAT behaviour
discovery — ICE tries candidates and finds what works. The case for it is a
non-WebRTC client that wants to choose a strategy up front, or a diagnostic that
reports what kind of NAT a user is behind. That is why it is opt-in and costs
nothing when off.
