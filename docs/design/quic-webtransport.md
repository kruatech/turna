# Design: QUIC / WebTransport transport

Status: **design / not implemented.** Plan for turning the `quic.rs` skeleton
into a working WebTransport-over-HTTP/3 transport. Unlike AF_XDP, this needs no
special hardware and is largely verifiable on any Linux/macOS host, so it is the
lower-risk of the two transport designs.

## 1. Goal

Let browsers reach turna over a single encrypted QUIC connection: WebTransport
over HTTP/3, with bidirectional streams for signaling and datagrams / uni
streams for media. Benefits over WebSocket+UDP: one connection, built-in TLS
1.3, native connection migration (CID), per-stream (not per-connection) head-of-
line blocking, and unreliable datagrams for low-latency media.

**Scope note.** This is **not** RFC TURN-over-QUIC (which is not standardized).
It is a WebTransport media/signaling transport that terminates at turna and
bridges into the existing processing path — closer in spirit to `tls_bridge.rs`
than to a TURN relay allocation. The design keeps that boundary explicit.

## 2. Current state (precise)

- `crates/transport/src/quic.rs` exists, is declared in `lib.rs` (`pub mod quic;`),
  and is a **skeleton**:
  - `QuicConfig` carries `listen_addr`, ALPN (`h3`, `webtransport`), and
    `enable_datagrams`.
  - `QuicServer::run` is a **placeholder** — it logs, then `tokio::signal::ctrl_c().await`
    and returns; the `quinn::Endpoint` accept loop is commented out.
  - `WebTransportSession`, `BiStream`, `UniStream` are stubs (`send`/`recv`
    return `Ok`/empty with `// quinn: …` comments).
- No `quinn` dependency and no `quic` feature in `Cargo.toml`.
- TLS material already exists for the `tls` feature: `tcp_tls.rs` loads certs
  with **hot-reload by mtime** — reuse that loader rather than adding a second.

## 3. Dependencies

Add behind a `quic` feature (all `optional`):

- `quinn` (0.11) — pure-Rust QUIC. Reuses `rustls` (already an optional dep for
  the `tls` feature) + `ring`.
- For the WebTransport/H3 layer, **strongly recommend `wtransport`** (a
  WebTransport server built on quinn) to avoid hand-rolling the HTTP/3
  `CONNECT :protocol=webtransport` handshake and SETTINGS negotiation.
  Alternative: `h3` + `h3-webtransport` (more control, more plumbing).

`Cargo.toml` sketch:
```
[features]
quic = ["dep:quinn", "dep:wtransport", "dep:rustls", "dep:rustls-pemfile"]
```

## 4. Phased plan

**Phase 1 — real QUIC endpoint.**
- Implement `QuicServer::run`: build a `quinn::ServerConfig` from a rustls cert
  (reuse `tcp_tls.rs`'s loader + hot-reload), set ALPN, `Endpoint::server`,
  accept loop, one task per connection. Emit `QuicEvent`s on the existing
  channel. This alone is testable over loopback.

**Phase 2 — WebTransport sessions.**
- Via `wtransport`: accept the WebTransport CONNECT, expose
  `WebTransportSession` with real `open_bi_stream` / `open_uni_stream` /
  `send_datagram` / `recv_datagram` backed by quinn. Map: bidi → signaling,
  datagrams + uni → media.

**Phase 3 — bridge into turna.**
- New `crates/relay/src/quic_bridge.rs`, analogous to `tls_bridge.rs`: connect
  QUIC/WebTransport events to the consumer (`PacketProcessor` for STUN/TURN
  semantics if framing TURN over a stream, or directly to the signaling/SFU
  layer for a pure media transport). Decide the framing contract here — this is
  the main product decision, not a technical blocker.

**Phase 4 — wiring & ops.**
- Start the QUIC server from `services/node/src/main.rs` behind the `quic`
  feature + config (`[quic] enabled, listen`), next to the TLS server start.
  Add a `/metrics` counter or two (active QUIC sessions, datagrams) using the
  existing `Metrics`/histogram machinery.
- Note the synergy with RFC 8016: QUIC has native CID migration, so a QUIC
  client surviving an IP change does not need the TURN mobility-ticket path.

## 5. Test strategy

- **Loopback (here / CI, no hardware):** quinn + wtransport both run in-process;
  a test client can complete the handshake and echo over a bidi stream / a
  datagram against a server on `127.0.0.1`. This makes Phases 1–2 genuinely
  verifiable without your box (unlike AF_XDP).
- **Browser interop (your box):** a real Chrome WebTransport client against the
  node for end-to-end confidence (ALPN, cert, CONNECT).
- **Cert hot-reload:** reuse and extend the `tcp_tls.rs` test.

## 6. Effort & risk

- **Effort:** medium–large; `wtransport` removes most of the H3/WebTransport
  plumbing, leaving the bridge (Phase 3) and the framing contract as the real
  work.
- **Risk:** dependency weight (quinn + rustls + ring); ALPN/cert wiring; and the
  product question of what rides over WebTransport (signaling only vs media vs
  TURN-framed). Lower implementation risk than AF_XDP — no `unsafe`, no kernel
  dependency, loopback-testable.
- **Suggested order:** do this **before** AF_XDP — it is more testable here and
  delivers a browser-reachable path sooner.
