# Design: TURN over DTLS (RFC 7350)

Status: **design / not implemented.** Plan for adding a DTLS transport so TURN
clients can run the control + data channel over encrypted UDP, complementing the
existing TURNS (TLS-over-TCP) and QUIC/WebTransport transports. This is the
separate, multi-phase task deferred until the QUIC and AF_XDP work landed.

## 1. Goal

Offer **TURN over DTLS** per RFC 7350: the same STUN/TURN/ChannelData protocol
the UDP and TURNS transports already speak, wrapped in a DTLS 1.2/1.3 session
over UDP. The motivation is clients on networks that require encrypted transport
but suffer under TURNS's TCP behaviour — TLS-over-TCP adds head-of-line blocking
and retransmit-induced latency to what is fundamentally a real-time media path.
DTLS keeps the datagram model (no HOL across messages) while still encrypting
the client↔server leg.

Scope boundary, stated up front: DTLS terminates **at turna** for the
client↔server leg only. The server↔peer leg stays plain UDP, exactly as it is
for the UDP and TURNS transports. This is *not* DTLS-SRTP key negotiation (that
is an endpoint-to-endpoint concern turna never participates in) and *not* a new
allocation model — it is a third way to carry the existing TURN protocol, a
sibling of `tcp_tls.rs`.

## 2. Current state (precise)

- No DTLS anywhere in the tree; no `dtls` feature.
- TURNS exists in `crates/transport/src/tcp_tls.rs`: a rustls acceptor with ALPN
  `stun.turn`, self-describing STUN/ChannelData framing, certificate hot-reload
  by mtime, connection limit + idle timeout, and events that feed the
  transport-agnostic `PacketProcessor` (the processor never knows the transport
  type).
- QUIC/WebTransport (`quic.rs` + `relay/quic_bridge.rs`) established the pattern
  this design reuses: a per-session map keyed by client address, datagrams fed
  straight to `PacketProcessor::process_slice`, and outbound `Action::Send`
  routed back over the session.
- **rustls (the TLS stack used by TURNS and QUIC) does not implement DTLS.** It
  is TLS-only by design. DTLS therefore requires a different library — this is
  the one decision that gates everything else (§3).

## 3. Library choice (the gating decision)

Three realistic options, in Rust:

- **OpenSSL (`openssl` crate, FFI).** Mature, battle-tested DTLS 1.2 and (recent
  OpenSSL) DTLS 1.3, with built-in `HelloVerifyRequest` cookie support for
  amplification/DoS resistance. Cost: a C dependency (build/audit/supply-chain
  surface) alongside the pure-Rust rustls already in the tree, and a second TLS
  stack to manage certs for.
- **`webrtc-dtls` (pure Rust, from the webrtc-rs project).** No C dependency,
  DTLS 1.2 only, designed precisely for this UDP real-time use case, includes
  cookie exchange. Cost: smaller maturity/audit history than OpenSSL; DTLS 1.2
  ceiling; pulls in part of the webrtc-rs stack.
- **`tokio-openssl`** as an async wrapper over option 1 if we want DTLS sessions
  driven on the tokio runtime rather than a hand-rolled poll loop.

Recommendation to confirm: **`openssl` (+ `tokio-openssl`)** for the first
implementation — its DTLS, cookie exchange, and PMTU handling are the most
proven, which matters for a public-facing UDP listener where DoS resistance is
not optional. Revisit `webrtc-dtls` if avoiding the C dependency outweighs the
maturity gap. *No code should be written until this is settled*, because the
session/handshake API shape differs substantially between the two.

## 4. Architecture

A single UDP socket bound to the DTLS port (default 5349/udp, distinct from the
3478 plaintext port; co-locating with TURNS's 5349/tcp is fine — different
protocols). One listener task owns the socket and demultiplexes by client
5-tuple into per-client DTLS sessions, mirroring `quic.rs`:

```
        recv_from(socket) ─► demux by SocketAddr ─► DtlsSession (handshake | established)
              ▲                                            │ decrypt
              │                                            ▼
        encrypt + send_to ◄── Action::Send ◄── PacketProcessor::process_slice(msg, src)
```

- **Demux.** A `HashMap<SocketAddr, DtlsSession>`. New source address with a
  ClientHello → start a handshake session (subject to the cookie check, §5).
- **Established session.** Each decrypted record is exactly one TURN message
  (datagram-bounded), handed to `process_slice` — no stream framer is needed
  (contrast TURNS, which must de-frame a TCP byte stream). This is the same
  shape as the QUIC datagram path.
- **Outbound.** `Action::Send { data, target }` whose `target` matches a live
  session's address is encrypted through that session and written to the socket.
  Relay-plane actions (Forward / RegisterRelay …) behave exactly as on the UDP
  path; only the final client-bound send is encrypted.

Reuse, do not duplicate: the certificate loader and mtime hot-reload from
`tcp_tls.rs`, and the `PacketProcessor` integration shape from `quic_bridge.rs`.

## 5. DTLS specifics that must be handled

- **Cookie exchange (`HelloVerifyRequest`).** Mandatory for a public UDP server:
  the server replies to the first ClientHello with a stateless cookie and only
  allocates session state once the client echoes it, defeating spoofed-source
  amplification. OpenSSL and webrtc-dtls both provide this; the listener must
  enable it rather than allocating a session per raw ClientHello.
- **Retransmission + timers.** DTLS runs its own handshake retransmission state
  machine over lossy UDP; the chosen library drives this, but the listener must
  pump per-session timeouts (a timer wheel or per-session deadline) so stalled
  handshakes are retransmitted and dead sessions are reaped.
- **MTU / fragmentation.** DTLS fragments handshake records to the path MTU;
  application records must stay within it to avoid IP fragmentation. Expose an
  MTU knob (default ~1200, matching the QUIC datagram default) and respect it
  when sizing outbound TURN responses.
- **Session lifecycle + limits.** Idle timeout, max concurrent sessions, and
  explicit teardown on `close_notify` — analogous to the TURNS connection limit
  and idle timeout, but keyed by address rather than TCP connection.
- **Replay / epoch.** DTLS records carry epoch + sequence; the library handles
  anti-replay, but session resumption / rehandshake across address changes is
  out of scope for Phase 1 (a client that rebinds re-handshakes).

## 6. Configuration & feature flag

- Cargo: `dtls = ["dep:openssl", "dep:tokio-openssl"]` (or the webrtc-dtls
  equivalent), optional, mirroring how `tls`/`quic` gate their deps.
- Config: a `[turn.dtls]` section (sibling of `[turn.quic]`): `enabled`,
  `listen` (default `0.0.0.0:5349`), `cert_path`, `key_path`, `max_sessions`,
  `idle_timeout_secs`, `mtu`, `cookie_secret` (or auto-generated per process).
- Node wiring: a self-contained `dtls_listener.rs` in `services/node` exposing
  `spawn_dtls(cfg, processor)`, started from `main` behind `if config.dtls.enabled`
  — the exact pattern `quic_listener.rs` already uses, so main stays a one-line
  touch.

## 7. Phased plan

- **Phase 1 — listener + handshake.** Bind the UDP socket, wire the DTLS library,
  implement cookie exchange and per-address session demux, complete a handshake
  with a real client (e.g. `openssl s_client -dtls`). No TURN processing yet.
- **Phase 2 — datapath.** Decrypt established-session records → `process_slice`;
  encrypt `Action::Send` back. Reach end-to-end Allocate/Refresh/ChannelData over
  DTLS against a TURN client (browsers don't speak TURN-over-DTLS directly;
  validate with coturn's client or `turnutils`).
- **Phase 3 — config + main.** `[turn.dtls]` section + `dtls_listener.rs` +
  `spawn_dtls` start; cert hot-reload reuse.
- **Phase 4 — hardening.** Session timers/reaping, MTU enforcement, max-sessions
  backpressure, metrics (handshakes, active sessions, cookie rejects, decrypt
  errors), and graceful drain parity with the other transports.

## 8. Risks & open questions

- **Second TLS stack.** OpenSSL adds a C dependency next to rustls; webrtc-dtls
  avoids it but is less proven and DTLS-1.2-only. Decision in §3 drives this.
- **DoS surface.** A public DTLS port is an amplification target; the cookie
  exchange must be correct before exposure. Treat Phase 1 cookie handling as a
  security-review gate, not a checkbox.
- **Testing without browsers.** No mainstream browser uses TURN-over-DTLS, so
  validation relies on coturn's client / `turnutils_uclient` and `openssl
  s_client`; CI coverage will be thinner than for the TCP/UDP paths.
- **Cert sharing.** Confirm the same PEM material can back TURNS (rustls), QUIC
  (rustls), and DTLS (openssl/webrtc-dtls) without per-stack format quirks.
- **Standalone vs shared processor.** Like the AF_XDP backend, the listener needs
  an `Arc<PacketProcessor>`; under the tokio backend it can take `server.processor()`,
  under io_uring it builds its own — settle this when wiring Phase 3.

## 9. Testing strategy

Handshake unit/integration against `openssl s_client -dtls1_2`; cookie-exchange
test (drop the first ClientHello response, assert no state allocated until the
cookie round-trips); end-to-end Allocate→ChannelData with `turnutils_uclient`
over DTLS in Phase 2; soak test for session reaping and the max-sessions cap in
Phase 4. As with the QUIC/AF_XDP drafts, library-API-specific code is verified
on a real build/host, not in this environment.
