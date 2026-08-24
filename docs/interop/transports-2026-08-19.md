# Transport verification — all paths — 2026-08-19

Eleven checks, every transport the server implements, one run
(`scripts/verify/transports.sh`). Ubuntu 24.04, kernel 6.14, 32 cpus, loopback.

Three of these transports had never carried a TURN allocation before this run, and
one of them had never been touched by any client at all.

| Check | Result |
|---|---|
| Conformance: address family + peer filter | pass |
| IPv6 relayed media | pass |
| TURNS, functional, including relayed media | pass |
| TURNS under load, allocation churn | pass |
| TURNS under load, relayed media | pass |
| **RFC 6062 TCP relay** | **pass** |
| **RFC 6062, payload pipelined with ConnectionBind** | **pass** |
| **DTLS allocation + media, `demux = false`** | **pass** |
| **DTLS allocation + media, `demux = true`** | **pass** |
| raw QUIC, including relayed media | pass |
| **WebTransport / H3** | **pass** |

**Every check ends at a byte arriving on the far side.** Not at a success response —
that distinction is the reason this file exists. The io_uring datapath answered 10 800
allocations per second for three hours while forwarding nothing
(`docs/soak/endurance-2026-08-19.md`), and no control-plane check could have caught
it.

## What each one newly establishes

**RFC 6062 TCP relay** — the production gate on `[turn.tcp_relay]` was there for want
of interop evidence, not for want of code. Both forms now pass, and the pipelined one
matters most: it sends the first application bytes in the *same write* as
`ConnectionBind`, which RFC 6062 §5.4 permits and which the detach prebuffer in
`transport::tcp_tls` exists to handle. That prebuffer had never been exercised by a
real client. It works.

**DTLS** — the first TURN allocation ever completed over this transport, on both
listener paths. The recorded evidence before this was a transport handshake and
nothing more. `demux = false` is the shipping default; `demux = true` is the owned
demultiplexer. They accept handshakes differently — serially versus one task each —
so both were run, and one result would not have stood for the other.

**WebTransport / H3** — previously untouched by anything. Now: session, control
stream, allocation, relayed media both ways.

**TURNS under load** — the missing piece. TURNS had browser interop but no endurance
evidence and no way to get any, because the load tool spoke UDP only. Both load shapes
now run: allocation churn (which pays the TLS handshake each time, as a reconnecting
client does) and sustained relayed media over long-lived sessions.

## Four faults in the clients, and what each taught

None of these were server bugs. Recording them because each one is the kind of mistake
that would recur:

**Relayed media comes back as a QUIC datagram, not on the stream.** The QUIC and
WebTransport clients read only the control stream and timed out while the server had
already delivered the reply. The server is right: media is unreliable by nature, and a
reliable stream would impose retransmission and head-of-line blocking that UDP does
not have. Stream for control, datagrams for media — that is what `enable_datagrams`
and `max_datagram_size` are for. The proof was server-side:
`turna_quic_datagrams_tx_total = 1` with
`turna_quic_control_dropped_no_stream_total = 0`. TURNS and DTLS have no datagram
channel, so there the reply must arrive in-band; both clients note this so nobody
"fixes" them the same way.

**RFC 6062 runs over TURNS, not plain TCP.** turna has no plain-TCP TURN listener —
the TCP relay's connection state is adopted by the TLS bridge. Pointing the client at
3478 got `Connection refused`. The hint was in `relay::handler`, in a comment, and I
read past it.

**The data connection needs its own 401.** Reusing the control connection's nonce
earned `438 Stale Nonce`, because the nonce is bound to the client's 5-tuple and the
data connection arrives from a different source port. Credentials are shared per
RFC 6062 §4.3; the nonce is not.

**A held port looks like a broken transport.** Two failures in an earlier run were an
unfinished node from the previous phase still holding its ports. Worth knowing before
diagnosing anything else: check that nothing is left over first.

## Not covered

- **OAuth (RFC 7635)** — needs a real authorization server issuing AEAD tokens. The
  one remaining gap that is not a client.
- **AF_XDP** — needs a dedicated NIC and root; an XDP program intercepts traffic below
  the stack, so it cannot share the primary interface.
- **Sustained load on anything but TURNS and UDP** — the soak harness drives UDP, and
  `transports.sh` is functional rather than endurance.
- **A browser.** `wt-check` uses `wtransport` on both sides and one reading of the
  spec, so a shared misreading stays invisible. It catches server-side faults ahead of
  a browser test; it does not replace one.
- **A routable IPv6 peer.** The host has only a ULA on a down bridge, so v6 covers
  everything except off-host routing.
