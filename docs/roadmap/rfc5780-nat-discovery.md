# RFC 5780 — NAT behaviour discovery

Deferred, not declined. Recorded because "we decided not to yet, and here is what
it needs" is a different state from an unnoticed gap, and only one of them can be
picked up by somebody else.

## What it is

A STUN extension letting a client work out what kind of NAT it is behind —
whether mappings depend on the destination, whether filtering does. A client that
knows can pick a connection strategy instead of trying everything.

## Why it is not done

**It needs a second IP address on the node.** The whole mechanism rests on the
server answering from a different address or port than the request arrived on, so
the client can observe whether its mapping changed. `OTHER-ADDRESS` advertises
where that second address is; `CHANGE-REQUEST` asks the server to use it.

One address cannot implement it. Not a limitation of the design here — it is what
the RFC requires.

## What implementing it involves

| piece | where |
|---|---|
| `CHANGE-REQUEST` (0x0003) decode | `proto-stun/src/attribute.rs` |
| `RESPONSE-ORIGIN` (0x802b), `OTHER-ADDRESS` (0x802c) encode | same |
| A second bound address, and sending from the one the request asks for | `transport` and the datapath |
| Config for the alternate address, validated to be genuinely different | `crates/config` |

One trap worth writing down: **`CHANGE-REQUEST` is attribute 0x0003**, which is
the value `ATTR_ALTERNATE_SERVER` wrongly held for three releases. Whoever adds
this will be adding the constant that was the bug. The test that guards
`ALTERNATE_SERVER` asserts encoded bytes rather than the constant, so it will not
be fooled — but the collision is worth knowing before the confusion, not after.

## Whether it is worth doing

Honest answer: unclear. WebRTC clients rarely use NAT behaviour discovery — ICE
tries candidates and finds what works, which gets the same outcome without asking.
The case for it is a non-WebRTC client that wants to choose a strategy up front,
or a diagnostic that reports what kind of NAT a user is behind.

`tools/browser-probes/connectivity-check.html` covers most of the diagnostic value
already, from the client side, without needing a second address.

Worth revisiting when a second address exists anyway, rather than acquiring one
for this.
