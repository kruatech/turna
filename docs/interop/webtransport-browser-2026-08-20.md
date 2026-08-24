# TURN over WebTransport — browser interop — 2026-08-20

Chrome 151 on macOS, against `https://turna.quinter.ru:3479/` with a Let's Encrypt
certificate. Five checks, all passing.

| Check | Result |
|---|---|
| WebTransport session established | pass |
| Bidirectional control stream opens | pass |
| 401 challenge, then an authenticated Allocate | pass — relayed `45.88.174.72:20000` |
| CreatePermission and ChannelBind accepted | pass — channel `0x4000` |
| Relayed data comes back | pass — returned as a WebTransport **datagram**, 44 bytes |

## Why this run counts differently

`wt-check` in `turna-load-test` already exercised this path
(`docs/interop/transports-2026-08-19.md`), and it was explicitly recorded there as
**not** interop evidence: that client uses `wtransport` — the same library as the
server — and one reading of the spec, so anything both got wrong stayed invisible.

This run has neither property in common with the server:

- **The HTTP/3 stack is Chrome's**, not `wtransport`'s.
- **Every byte of TURN is assembled in browser JavaScript**
  (`wt-browser-probe.html`): the STUN header, attribute TLVs with their 4-byte
  padding, XOR-PEER-ADDRESS and XOR-RELAYED-ADDRESS, ChannelData framing, and
  MESSAGE-INTEGRITY.
- **The long-term credential key is an independent MD5.** SubtleCrypto deliberately
  does not implement MD5, so it is written from scratch in the page and checked
  against known vectors before use.

`MESSAGE-INTEGRITY accepted` is the line that matters. The server validated an HMAC
over a message encoded by unrelated code — which is precisely what a shared library
cannot tell you, because it cannot disagree with itself.

## Media returns as a datagram

The relayed reply came back on the datagram channel, not the control stream — the same
split as raw QUIC. That is the correct design: media is unreliable by nature, and a
reliable stream would add retransmission and head-of-line blocking that UDP does not
have. The stream carries control messages; `[turn.quic] enable_datagrams` and
`max_datagram_size` govern the media path.

Worth stating because a client reading only the stream sees the allocation succeed and
the media vanish — which is exactly how both the Rust QUIC and WebTransport clients
failed before being corrected.

## A diagnostic worth remembering

The first attempts failed with `Opening handshake failed`, and **zero packets reached
the server** — `tcpdump` on port 3479 caught nothing while `turna_quic_sessions_total`
and `turna_quic_handshake_failures_total` both stayed at 0. Those two facts together
rule out the certificate and the listener: there was nothing to reject.

The cause was a system proxy on the client machine. Chrome routes WebTransport through
it, the proxy cannot tunnel to a non-standard port, and the browser therefore never
emitted UDP at all. `nc -u` from the same machine reached the server fine, which is
what made it confusing — the browser and the shell were not taking the same path.

The console gave it away as `net::ERR_TUNNEL_CONNECTION_FAILED`, which the JavaScript
`WebTransportError` does not carry. Running Chrome with a separate profile and
`--no-proxy-server` fixed it:

```
open -na "Google Chrome" --args --user-data-dir=/tmp/chrome-wt --no-proxy-server
```

Two lessons for anyone repeating this: check the browser console rather than the JS
error object, and confirm packets arrive at all before suspecting TLS.

## Also found

The node ran for eight minutes with its health listener unable to bind — the port was
already taken by an unrelated Go process, and the metrics being scraped were that
process's. turna carried on serving traffic regardless.

That is worth a look on its own: with `[health]` configured, failing to bind it should
be fatal, or an operator believes the node is observable when it is not. Not
investigated here; recorded in [../OPEN-DECISIONS.md](../OPEN-DECISIONS.md).

## Scope

One browser engine, one run, functional. Firefox and Safari did not implement
WebTransport at the time of writing, so a three-engine matrix like the TURNS one is not
available. No endurance: there is no load driver for this transport.
