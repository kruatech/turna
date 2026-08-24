# Design: QUIC / WebTransport transport

Status: **implemented, experimental.** Two paths ship behind Cargo features:
raw QUIC (`quic`) and WebTransport-over-HTTP/3 (`web-transport`, which implies
`quic`). Selected at runtime with `[turn.quic] web_transport`.

Implementation: `crates/transport/src/quic.rs` (endpoint, session tasks),
`crates/relay/src/quic_bridge.rs` (framing + processor bridge),
`services/node/src/quic_listener.rs` (wiring, egress, metrics).

Sections 2-4 below describe the original plan and are kept for the rationale;
§7 records what actually landed and what is still missing.

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

## 7. Implemented vs missing (current)

### Implemented

- **Endpoint + accept loop** for both raw QUIC (quinn) and WebTransport
  (wtransport), each with a cooperative shutdown path.
- **Framing contract** (§3 of `quic_bridge.rs`): bidi streams carry
  concatenated self-describing TURN messages, reassembled incrementally by
  `StreamFramer`; datagrams carry exactly one message. ChannelData padding is
  consumed off the wire and excluded from what the processor sees.
- **Bidirectional relay.** Client→peer goes through `process_owned` (never
  `process_slice`, which would emit `ForwardZeroCopy` the QUIC egress cannot
  resolve); peer→client arrives via the shared `client_sinks` registry, with
  ChannelData sent as a datagram and control as a stream write.
- **Per-stream control replies** (raw QUIC): each accepted bidi stream's send
  half is retained and a response goes back on the stream its request came in on.
- **Session caps**: `max_sessions`, `max_sessions_per_ip`.
- **Metrics**: `turna_quic_*` including handshake failures, rejections, and
  `turna_quic_readiness`.
- **Fail-fast startup** if `[turn.quic]` is enabled without the `quic` feature,
  or `web_transport = true` without `web-transport`.
- **Allocation release** when a session closes.

### Also implemented on the WebTransport path (wtransport 0.7)

- **Part of `[turn.quic]` is applied**: listen address, identity, `keep_alive`,
  the session caps, and `cert_reload_secs`. The *transport* limits
  (`max_bi_streams`, `max_uni_streams`, `enable_datagrams`,
  `max_datagram_size`, `idle_timeout_secs`) are **not** — reaching the underlying
  `quinn::ServerConfig` needs `ServerConfig::quic_config_mut()`, which wtransport
  keeps behind its quinn re-export and is not in scope in this build. The
  listener warns at startup naming exactly those keys, so the config never looks
  effective when it isn't. `alpn` is inert by design (wtransport negotiates `h3`).
  See `TODO(quic-wt-limits)` in `crates/transport/src/quic.rs`.
- **Pre-handshake admission control.** `IncomingSession` exposes
  `remote_address()` and `refuse()`, so `max_sessions` / `max_sessions_per_ip`
  are enforced *before* the QUIC/H3 handshake — cheaper and more useful against
  abuse than the raw path, which can only check post-handshake.
- **Per-stream control replies.** Every accepted bidi stream's send half is
  retained under a per-session stream key, so a response goes back on the stream
  its request arrived on (previously only the first stream was kept, and every
  stream reported id 0). The key is opaque routing state between the transport
  and the bridge, not the on-wire QUIC stream id — the real index would need the
  same gated quinn re-export as above.
- **Certificate hot-reload on both paths**, polled by mtime on
  `[turn.quic].cert_reload_secs` (`turna_quic_cert_reloads_total`,
  `turna_quic_cert_reload_failures_total`). WebTransport uses
  `Endpoint::reload_config(cfg, rebind = false)`; raw QUIC uses
  `Endpoint::set_server_config(Some(cfg))`. Both affect new sessions only, live
  ones are untouched. The raw path rebuilds through the same
  `build_quic_config()` used at startup, so startup and reload cannot drift.
- **Session descriptor is honest**: `datagrams_available` comes from
  `Connection::max_datagram_size()` and `local_addr` from
  `Endpoint::local_addr()`.
- **Migration detection.** QUIC only exposes a migrated address after path
  validation and neither backend emits an event for it, so each session task
  polls `remote_address()` every `MIGRATION_POLL` (2s) and emits
  `ConnectionMigrated` on a change. The bridge re-keys its address index, the
  listener re-keys `client_sinks`, and the per-IP admission slot moves with the
  client — otherwise the old IP stayed charged for a session it no longer owns.
  Counted as `turna_quic_migrations_total`. `allow_migration` is set on the
  WebTransport builder; the raw path keeps quinn's default.
- **Per-IP handshake rate limit** (`max_handshakes_per_sec_per_ip`, token bucket
  with burst). Checked before the handshake on both paths — `refuse()` on
  WebTransport, dropping the `Incoming` on raw QUIC. This closes the gap that
  `max_sessions_per_ip` alone left open: a source cycling sessions never reaches
  a concurrency cap.

### Missing / known gaps

1. **`alpn` is inert on the WebTransport path** (wtransport forces `h3`).
2. **No loopback or browser interop test yet** — §5 remains the plan.

Closed: the transport limits *are* applied on the WebTransport path. The
wtransport dependency now enables its `quinn` feature, which exposes
`ServerConfig::quic_config_mut()`; `build_wt_config` installs a
`quinn::TransportConfig` built from `[turn.quic]` exactly like the raw path. The
same re-export would also give back the real on-wire stream ids — the opaque
per-session counter is kept deliberately, since routing needs a stable key rather
than the QUIC index.

Note on `--all-features`: `web-transport` pulls wtransport's own bundled quinn,
which can conflict with the standalone `quinn` dependency. Build the two QUIC
features separately when diagnosing.
