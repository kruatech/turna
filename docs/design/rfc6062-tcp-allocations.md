# Design: RFC 6062 TCP Allocations (Audit-3 F1)

Status: **design / not yet implemented**. This document scopes the work, flags a
hard architectural prerequisite, and lays out a chunked implementation plan so
F1 can be landed safely rather than as one large change.

## 1. What RFC 6062 adds

RFC 6062 ("TURN Extensions for TCP Allocations") lets a TURN client relay **TCP**
(not UDP) to peers. New protocol elements (codepoints verified against the RFC):

| Element | Codepoint | Notes |
|---|---|---|
| Connect (method) | `0x000A` | client → server: open TCP to peer |
| ConnectionBind (method) | `0x000B` | client → server: bind a data connection |
| ConnectionAttempt (method) | `0x000C` | server → client: **indication** of inbound peer conn |
| CONNECTION-ID (attribute) | `0x002A` | 32-bit unsigned; identifies a peer data connection |
| REQUESTED-TRANSPORT value | `6` | TCP (vs UDP = 17) on Allocate |
| Error 446 | — | Connection Already Exists |
| Error 447 | — | Connection Timeout or Failure |

For a TCP allocation the relayed transport address is a **listening TCP socket**,
not a UDP socket. Channels and ChannelData are **not** used; all peer traffic is
raw TCP spliced between two TCP connections.

## 2. Hard prerequisite — there is no TCP client transport today

RFC 6062 §3.2/§4: a TCP allocation's 5-tuple transport **MUST be TCP or
TLS-over-TCP**, and the client opens a **second** TCP connection per peer for
CONNECTION-BIND. The current server has **no TCP/TLS transport for TURN clients**
at all — `crates/transport` is UDP-only (`uring`, `af_xdp`, `worker`,
`hugepages`); the other client transports are DTLS-over-UDP and QUIC. The only
TCP `accept()` in the tree is the HTTP `/metrics` server.

Consequences:

- **F1 cannot function without first adding a TCP/TLS TURN control transport.**
  This is itself a substantial feature (a TCP listener, TLS termination, a
  per-connection read/parse loop, auth over a long-lived connection).
- The packet model is the deeper mismatch. The hot path is
  `PacketProcessor::process(raw: Bytes, src) -> Vec<Action>` — a pure,
  connectionless function over single UDP datagrams. RFC 6062 needs:
  - a **persistent** client control connection (state lives across messages);
  - **server-initiated** messages (ConnectionAttempt indications pushed to the
    client without a request);
  - a **second** client TCP connection (the data connection) correlated to the
    first by CONNECTION-ID;
  - **buffering** of peer→server data after the peer connects and before
    ConnectionBind arrives (RFC 6062 §5.3 + RFC 4732 §2.1.3 DoS limit).

  None of these fit a stateless datagram processor. F1 needs a connection-
  oriented sub-system alongside it.

The good news: the **data plane already exists**. `crates/relay/src/splice.rs`
(hardened in Audit-1 H1) does epoll-driven byte-splicing between two sockets —
exactly what CONNECTION-BIND needs to join the client data connection to the
peer connection.

## 3. Proposed architecture

```
                 ┌────────────────────── TURN server ──────────────────────┐
  client ──TCP(control)──▶│ TCP/TLS control listener (NEW)                  │
     │                    │   • per-connection auth + STUN/TURN state       │
     │                    │   • handles Allocate(TCP) / Connect /           │
     │                    │     ConnectionBind; pushes ConnectionAttempt    │
     │                    │                                                 │
     │                    │ Allocate(TCP) ⇒ relay = TCP *listener* socket   │
     │                    │                                                 │
     │  Connect(peer) ───▶│  outbound TCP connect → peer  (timeout ⇒ 447)   │──TCP──▶ peer
     │  ◀── CONNECTION-ID │  register pending peer conn under CONNECTION-ID  │
     │                    │                                                 │
     │  (2nd TCP conn) ──▶│  ConnectionBind(CONNECTION-ID)                  │
     │                    │   ⇒ splice client-data-conn ⇄ peer-conn (splice.rs)
     │                    │                                                 │
     │  ◀ ConnectionAttempt (peer dialed the relay listener; buffered)      │◀─TCP── peer
                          └─────────────────────────────────────────────────┘
```

### Allocation model changes (`crates/session`)
- A TCP allocation owns a **TCP listener** bound to the relayed transport
  address (the port pool can stay; bind `TcpListener` instead of `UdpSocket`).
- New per-allocation tables:
  - `peer_connections: HashMap<u32 /*CONNECTION-ID*/, PeerConn>` where `PeerConn`
    holds the peer `TcpStream`, its `SocketAddr`, a pre-bind buffer, and state
    (`Pending` after Connect/Attempt, `Bound` after ConnectionBind).
  - CONNECTION-ID generation: random 32-bit, unique within the allocation.
- Permissions still apply: Connect to a peer requires a permission and passes
  through `is_forbidden_peer` (same SSRF/special-use denylist as UDP) → 403.

### Control handlers (new connection-oriented module, NOT the UDP processor)
- `handle_allocate` gains a TCP branch: `REQUESTED-TRANSPORT == 6` ⇒ TCP
  allocation (bind listener). Mutually exclusive with EVEN-PORT semantics per
  RFC (TCP + EVEN-PORT interplay is allowed; reservation tokens unchanged).
- `Connect`: validate XOR-PEER-ADDRESS (400 if missing/invalid, 403 if
  forbidden, 446 if a connection to that peer already exists), then async
  outbound `TcpStream::connect` with a timeout (447 on fail/timeout). On success
  allocate CONNECTION-ID, store `PeerConn::Pending`, return it in the response.
- `ConnectionBind`: on a *data* connection, look up CONNECTION-ID, mark `Bound`,
  then hand both sockets to `splice.rs`. Flush any buffered peer data first.
- Inbound peer accept on the relay listener: if a permission exists for the
  peer IP, allocate CONNECTION-ID, buffer peer data (bounded), and push a
  **ConnectionAttempt** indication on the control connection. Drop if no
  permission, or if the buffer would exceed the policy limit (RFC 4732 §2.1.3).

### Data plane
Reuse `crates/relay/src/splice.rs` to splice `client_data_conn ⇄ peer_conn`
once bound. No new hot-path code; the H1-hardened splice handles backpressure
and byte-loss correctly.

## 4. Chunked implementation plan

Each chunk compiles independently (you build + report, as we've worked so far).

1. **proto-stun primitives** — `Method::{Connect, ConnectionBind, ConnectionAttempt}`
   in `method.rs`; `Attribute::ConnectionId(u32)` + `ATTR_CONNECTION_ID = 0x002A`;
   `TRANSPORT_TCP = 6`; error reasons 446/447. Self-contained, RFC-verifiable.
   **Needs: `crates/protocol/proto-stun/src/method.rs`** (not currently shared).
2. **TCP/TLS control transport** — the listener + per-connection loop + auth.
   The prerequisite. Largest chunk; depends on the chosen TLS stack.
3. **Session TCP allocation model** — TCP listener allocation, `PeerConn` tables,
   CONNECTION-ID registry, permission checks.
4. **Connect handler** — outbound connect + timeout + 446/447 + CONNECTION-ID.
5. **Inbound accept + ConnectionAttempt** — relay-listener accept loop, bounded
   buffering, indication push.
6. **ConnectionBind + splice wiring** — bind data conn, flush buffer, splice.
7. **Integration test** — extend `tests/integration` with a TCP allocate →
   connect → bind → relay round-trip.

## 5. Open questions for the owner

1. **Is a TCP/TLS TURN control transport in scope/planned?** Without it, chunks
   3–7 have nothing to run on. If TLS-over-TCP is desired, which stack
   (rustls?) and where does termination live (in-process vs a fronting proxy)?
2. Where should the connection-oriented sub-system live — a new crate
   (`turna-tcp`?) or inside `relay`? It should not be wedged into the UDP
   `PacketProcessor`.
3. Buffering policy limit for pre-bind peer data (bytes per pending connection,
   total per allocation)?

## 6. Recommendation

F1 is an architecture project, not an incremental audit fix, and its critical
path is the **TCP control transport** that does not exist yet. Recommend:

- Decide §5.1 first (is TCP client transport in scope?).
- If yes, land chunk 1 (proto-stun primitives — send `method.rs`) as the
  groundwork, then build chunk 2 (TCP transport) as a dedicated effort.
- Until then, F1 stays in design; the other audit findings (C1, H1, M1, L1, O1,
  Q1–Q5, F2, F4) are already closed.
