# RFC 5780 NAT behaviour discovery against coturn's client — 2026-09-24

`turnutils_natdiscovery` from coturn 4.6.1 (Ubuntu package `4.6.1-1build4`) —
an RFC 5780 client written independently of turna — run against a debug build of
this branch with `[turn.nat_discovery]` enabled on two loopback addresses.

| Check | Result |
|---|---|
| Mapping behaviour (`-m`): request to A1:P1, then to A2:P1 (the OTHER-ADDRESS IP) | pass — both answered; RESPONSE-ORIGIN and OTHER-ADDRESS consistent with RFC 5780 §6.1 Table 1; "Endpoint Independent Mapping" |
| Filtering behaviour (`-f`): plain request, then CHANGE-REQUEST change-IP + change-port | pass — second response arrived **from A2:P2** (RESPONSE-ORIGIN `127.0.0.2:34791`); "Endpoint Independent Filtering" |
| PADDING (`-P`) | refused with **420 Unknown Attribute**, by design (PADDING is optional for a server and is a fragmentation/amplification tool) |

## What this does and does not show

- It shows the wire format and the Table 1 source selection agree with an
  independent implementation: coturn's client parses CHANGE-REQUEST replies,
  RESPONSE-ORIGIN and OTHER-ADDRESS as turna writes them, and receives replies from
  the socket turna chose.
- It does **not** show behaviour through a real NAT. Both addresses are loopback
  (`127.0.0.1`, `127.0.0.2`) on one host, so the verdicts "Endpoint Independent"
  describe the absence of a NAT, which is the expected answer here. A run from behind
  a real NAT against two public addresses is still owed.
- UDP only. RFC 5780 §6's SHOULD for TCP and TLS is not implemented.

## Configuration used

```toml
[turn]
listen = "127.0.0.1:34780"
[turn.nat_discovery]
enabled = true
primary_ip = "127.0.0.1"
alternate_ip = "127.0.0.2"
primary_port = 34790
alternate_port = 34791
```

Command: `turnutils_natdiscovery -m -f -p 34790 127.0.0.1`, then
`turnutils_natdiscovery -f -P -p 34790 127.0.0.1`.

## Transcript

```

-= Mapping Behavior Discovery =-

========================================
RFC 5780 response 1
No ALG: Mapped == XOR-Mapped
0: : IPv4. Response origin: : 127.0.0.1:34790
0: : IPv4. Response origin: : 127.0.0.1:34790
0: : IPv4. Other addr: : 127.0.0.2:34791
0: : IPv4. UDP reflexive addr: 127.0.0.1:39615
0: : IPv4. Local addr: : 0.0.0.0:39615

========================================
RFC 5780 response 2
No ALG: Mapped == XOR-Mapped
0: : IPv4. Response origin: : 127.0.0.2:34790
0: : IPv4. Other addr: : 127.0.0.1:34791
0: : IPv4. UDP reflexive addr: 127.0.0.1:39615
0: : IPv4. Local addr: : 0.0.0.0:39615

========================================
NAT with Endpoint Independent Mapping!
========================================

-= Filtering Behavior Discovery =-

========================================
RFC 5780 response 3
No ALG: Mapped == XOR-Mapped
0: : IPv4. Response origin: : 127.0.0.1:34790
0: : IPv4. Other addr: : 127.0.0.2:34791
0: : IPv4. UDP reflexive addr: 127.0.0.1:56428
0: : IPv4. Local addr: : 0.0.0.0:56428

========================================
RFC 5780 response 4
No ALG: Mapped == XOR-Mapped
0: : IPv4. Response origin: : 127.0.0.2:34791
0: : IPv4. Other addr: : 127.0.0.2:34791
0: : IPv4. UDP reflexive addr: 127.0.0.1:56428
0: : IPv4. Local addr: : 0.0.0.0:56428

========================================
NAT with Endpoint Independent Filtering!
========================================
exit=0
=== -P (PADDING)

-= Filtering Behavior Discovery =-
The response is an error 420 (Unknown Attribute)
exit=0
```
