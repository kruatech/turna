# TURN over DTLS (RFC 7350)

Encrypted UDP transport for TURN, implemented with the pure-Rust `webrtc-dtls`
(DTLS 1.2) stack. Disabled by default; enabled with the `dtls` build feature and
`[turn.dtls] enabled = true`. Implementation: `crates/transport/src/dtls.rs` +
`services/node/src/dtls_listener.rs`.

Operational notes (cert format, fail-closed behaviour, live handshake
verification) are in `docs/dtls/v0.3.0-rc.1.md`. In short: the operator key must
be PKCS#8 ECDSA-P-256, and a configured-but-unloadable cert now fails closed
(the node refuses to start) rather than silently falling back to an ephemeral
self-signed cert.

## Shape

The shape mirrors the QUIC listener: a listener task emits `DtlsEvent`s
(`NewSession` / `Datagram` / `SessionClosed`) onto a channel, and an
`OutboundRegistry` (`session_id → sender`) carries encrypted responses back into
the originating session. Each DTLS record is exactly one TURN message
(datagram-bounded), so — unlike TURNS-over-TCP — there is no stream de-framing;
the relay bridge feeds each record straight to `PacketProcessor::process_slice`.

`session_id` is the client's socket address string (sessions are keyed by
5-tuple), so an outbound `Action::Send { target }` is a direct registry lookup.

## Handshake & anti-spoofing

Cookie exchange, per-address demux, and the handshake are handled **inside**
`webrtc-dtls`' listener: `accept()` only yields a `Conn` after a completed
handshake (HelloVerifyRequest round-trip included), so spoofed/garbage UDP never
reaches the TURN layer. The amplification surface of the listener's
pre-handshake per-address buffer is a security-review item (DoS limits — DTL-9 —
are a follow-up).

## Certificates

The negotiated suites are `ECDHE-ECDSA-*`, so the key **must be ECDSA P-256**;
an RSA key loads but no cipher negotiates. Provide `cert_path` / `key_path` (PEM):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/CN=turn.local"
```

## Lifecycle & hardening (implemented)

- **Fail-fast startup (DTL-1).** `[turn.dtls]` is validated before the relay
  server starts; problems (e.g. unreadable `cert_path`/`key_path`, enabled
  without the `dtls` feature) abort the process rather than starting partially.
- **Admission control.** Post-handshake `max_sessions` cap; over-cap sessions are
  dropped (`turna_dtls_rejected_over_cap_total`).
- **Idle timeout.** Per-session `idle_timeout_secs`
  (`turna_dtls_idle_timeouts_total`).
- **Graceful shutdown (DTL-4).** On the shutdown watch, the accept loop stops
  taking new handshakes and live sessions wind down cooperatively.
- **Bounded outbound (DTL-3).** Each session's egress queue is bounded
  (`outbound_queue_capacity`, default 1024). When full, the **newest** datagram
  is dropped (`turna_dtls_outbound_dropped_total`) instead of blocking the relay
  return path. The registry sender is a bounded `mpsc::Sender`; both bridge send
  sites use `try_send` with drop-newest semantics.
- **Per-IP session cap (DTL-9).** `max_sessions_per_ip`
  (`turna_dtls_rejected_per_ip_total`); 0 = unlimited.
- **Receive buffer ≥ one DTLS plaintext fragment.** Sized to
  `max(mtu, 16 KiB)`: a DTLS 1.2 record carries up to 2^14 bytes of plaintext, so
  a smaller buffer truncated large client records and killed the session.
- **Outbound MTU enforced.** A datagram larger than `mtu` is dropped and counted
  (`turna_dtls_outbound_oversize_total`) rather than sent and left to IP
  fragmentation, which is widely dropped and produces silent one-way media.
- **Allocation released on session close.** The DTLS session is the client's
  5-tuple, so its allocation and relay port are freed immediately instead of at
  TTL expiry.
- **Readiness.** `turna_dtls_readiness` is derived from whether the UDP listener
  is bound (0=starting, 1=ready, 2=degraded).

## Metrics

`turna_dtls_active_sessions`, `turna_dtls_sessions_total`,
`turna_dtls_rejected_over_cap_total`, `turna_dtls_rejected_per_ip_total`,
`turna_dtls_closed_total`, `turna_dtls_idle_timeouts_total`,
`turna_dtls_bytes_rx_total`, `turna_dtls_bytes_tx_total`,
`turna_dtls_outbound_dropped_total`, `turna_dtls_outbound_oversize_total`,
`turna_dtls_readiness`.

Not yet exposed (requires hooks below `webrtc-dtls`' `accept()`): handshake
failures and timeouts — a failed handshake never surfaces to this layer.

## Testing

`tests/integration` carries a feature-gated end-to-end client
(`stun_binding_over_dtls`): it completes a real DTLS 1.2 handshake against the
listener and runs a STUN Binding exchange over the session.

```bash
cargo test -p turna-integration-tests --features dtls -- --ignored dtls
```

Requires a live server built and configured with the `dtls` feature.

## Certificate handling

`cert_path`/`key_path` must be a PKCS#8 ECDSA P-256 pair. Setting **both** to the
empty string is an explicit opt-in to an ephemeral self-signed certificate for
dev/test (the listener logs a warning); setting only one is a configuration
error. A configured-but-unloadable certificate fails startup rather than silently
downgrading.

## Not done / follow-ups

- Handshake-rate DoS limits and pre-handshake amplification review of the
  listener buffer: the handshake runs inside `webrtc-dtls`, so throttling needs
  hooks below `accept()` (or a UDP demultiplexer in front of the listener).
- **No certificate hot-reload.** `webrtc-dtls` takes its `Config` at `listen()`,
  so swapping material would mean rebinding the socket and dropping every live
  session. A rotated certificate currently needs a process restart. The node does
  watch `cert_path`/`key_path` and logs a loud warning when they change, so a
  silent "renewed but not served" state is at least visible; TURNS
  (`crates/transport/src/tcp_tls.rs`) does reload without a restart.
- DTLS 1.2 only (the stack does not implement RFC 9147 DTLS 1.3), and no
  Connection ID (RFC 9146) — a client whose address changes gets a new session
  and must re-allocate.
