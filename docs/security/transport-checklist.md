# Transport security checklist

State of the security-relevant controls across the transport backends, as
implemented. ✅ = in code; ⚠ = partial / follow-up; ❌ = not done.

## Startup integrity

- ✅ **Fail-fast configuration.** Invalid `[turn.dtls]` (unreadable cert/key,
  enabled-without-feature) aborts startup (DTL-1). AF_XDP runs a preflight
  (interface up, queue exists, ring geometry, `frame_size ≥ MTU+14`,
  `CAP_NET_RAW`) and aborts on any failure (AFX-2). No partial-start state.
- ✅ **External IP validation.** `turn.external_ip` must parse as a valid IP in
  production.

## Unauthenticated input (the UDP parse surface)

- ✅ **Shared, transport-independent STUN/ChannelData parser.** Every backend
  feeds bytes to the same `turna-proto-stun` decoders, so behaviour is identical
  (verified byte-for-byte tokio↔io_uring, `scripts/e2e/backend_diff_bytes.sh`).
- ✅ **Attribute-count cap** (security limit, MAX=32) and length/alignment checks
  reject malformed messages.
- ✅ **BPF prefilter** (tokio backend) drops non-STUN/ChannelData and oversized
  datagrams before userspace.
- ✅ **Fuzz targets** for the decoders ship at `fuzz/` (`fuzz_stun`,
  `fuzz_stun_semantic`, `fuzz_turn`, `fuzz_turn_lifecycle`, `fuzz_encode`);
  run with `cargo +nightly fuzz run fuzz_stun`. ⚠ Continuous fuzzing runs are
  an operational task (not yet run in CI here).

## TURNS (TLS over TCP)

- ✅ **Cooperative drain.** The accept loop stops on the shutdown watch and
  established connections close themselves, instead of the listener task being
  `abort()`ed mid-write.
- ✅ **Accept-error resilience.** A transient `accept()` failure (EMFILE,
  ECONNABORTED) is counted (`turna_tls_accept_errors_total`) with backoff; it no
  longer terminates the listener until the next process restart.
- ✅ **Connection caps.** Global `max_connections` plus per-source-IP
  `max_connections_per_ip` (`turna_tls_rejected_over_cap_total`,
  `turna_tls_rejected_per_ip_total`).
- ✅ **Handshake timeout** with its own counters
  (`turna_tls_handshake_failures_total`, `turna_tls_handshake_timeouts_total`).
- ✅ **Certificate hot-reload** by mtime (`cert_reload_secs`); a failed reload
  keeps the previous material in service and increments
  `turna_tls_cert_reload_failures_total`.
- ✅ **Framing errors counted** (`turna_tls_framing_errors_total`) rather than
  looking like a normal disconnect.
- ✅ **Allocation released on connection close** — the control connection is the
  allocation's 5-tuple, so its relay port is freed immediately instead of at TTL.
- ⚠ **No client-certificate (mTLS) option** for TURNS clients; authentication is
  the TURN long-term/JWT credential only.

## DTLS

- ✅ **Handshake/anti-spoof inside webrtc-dtls.** `accept()` only yields a `Conn`
  after a completed handshake (HelloVerifyRequest cookie round-trip), so spoofed
  UDP never reaches the TURN layer.
- ✅ **Post-handshake admission control** (`max_sessions`, over-cap rejected).
- ✅ **Per-source-IP concurrent session cap** (DTL-9, `max_sessions_per_ip`) —
  anti slot-exhaustion; `turna_dtls_rejected_per_ip_total`.
- ✅ **Bounded outbound queue** (DTL-3, drop-newest) — a slow/abusive peer cannot
  grow unbounded server memory; `turna_dtls_outbound_dropped_total`.
- ✅ **Per-session idle timeout.**
- ⚠ **Pre-handshake amplification / rate limiting.** The listener's
  pre-handshake per-address buffer is not rate-limited above `accept()`
  (handshake lives inside webrtc-dtls); pre-handshake throttling is a follow-up.
- ✅ **ECDSA cert requirement** documented (ECDHE-ECDSA suites).
- ✅ **Receive buffer sized to a full DTLS plaintext fragment** (2^14) so a large
  client record cannot be truncated into a session kill.
- ✅ **Outbound MTU enforced** — a datagram over `[turn.dtls].mtu` is dropped and
  counted (`turna_dtls_outbound_oversize_total`) instead of relying on IP
  fragmentation.
- ✅ **Allocation released on session close.**
- ❌ **No certificate hot-reload** (`webrtc-dtls` takes its `Config` at
  `listen()`); a rotated certificate requires a restart.

## QUIC / WebTransport

- ✅ **Session caps.** `max_sessions` and `max_sessions_per_ip`
  (`turna_quic_rejected_over_cap_total`, `turna_quic_rejected_per_ip_total`),
  applied post-handshake as on the DTLS path.
- ✅ **Cooperative drain** on the shutdown watch for both the raw-QUIC and
  WebTransport accept loops.
- ✅ **Bounded per-session outbound queue** (`QUIC_OUTBOUND_CAP`, drop-newest,
  `turna_quic_send_errors_total`).
- ✅ **Bounded stream reassembly buffer** — a desynchronised or hostile bidi
  stream cannot grow the framer without limit.
- ✅ **Per-stream control replies** on the raw-QUIC path (a response goes back on
  the stream its request arrived on).
- ✅ **Pre-handshake admission control on the WebTransport path.**
  `IncomingSession` exposes the peer address and can be refused, so the session
  and per-IP caps are enforced before any QUIC/H3 handshake work. The raw-QUIC
  path can only check post-handshake.
- ✅ **Certificate hot-reload on the WebTransport path** via
  `Endpoint::reload_config(cfg, rebind = false)` — live sessions are untouched;
  a failed reload keeps the previous material
  (`turna_quic_cert_reload_failures_total`).
- ⚠ **`[turn.quic]` transport limits apply on the raw-QUIC path only** (stream
  counts, datagram buffer, idle timeout); on the WebTransport path they are not
  reachable and the listener warns about it at startup. `alpn` is inert there.
- ✅ **Per-IP handshake rate limit** (`max_handshakes_per_sec_per_ip`, token
  bucket + burst), enforced before the handshake on both paths
  (`turna_quic_rejected_rate_limit_total`). Off by default; enable it on any
  internet-facing listener.
- ✅ **Connection migration detected** by polling the peer address; the egress
  registries and the per-IP admission slot follow the client
  (`turna_quic_migrations_total`).
- ❌ **No certificate hot-reload on the raw-QUIC path** (`web_transport = false`).

## Relaying

- ✅ **Peer-address filter** (M1). Default `internet-facing` profile denies
  RFC1918/ULA and always-denied special-use ranges (loopback, link-local incl.
  cloud-metadata, multicast, broadcast, `0.0.0.0/8`) — closes the
  SSRF-into-private-network vector. `lan` profile is explicit opt-in.
- ✅ **io_uring relay capacity bound** (`relay_socket_capacity_per_worker`,
  hard-capped 1024) — bounds per-worker relay resources;
  `turna_uring_relay_capacity_exhausted_total`.

## AF_XDP

- ✅ Requires `CAP_NET_RAW` and an operator-owned external XDP program; the
  server never loads/removes XDP programs.
- ⚠ TX neighbor (ARP/NDP) MAC resolution is a placeholder (Phase 1); src/dst MAC
  are static config.

## Lifecycle

- ✅ **Graceful drain** on SIGTERM/SIGINT (lame-duck, `drain_grace_secs`); all
  backends stop accepting new work cooperatively and release resources on exit.
- ✅ **Readiness signalling** (`/ready`, `turna_backend_readiness`, per-component
  `turna_transport_readiness`, `turna_dtls_readiness`, `turna_tls_readiness`,
  `turna_quic_readiness`). Each listener's gauge is now actually written — it is
  derived from whether the listening socket is bound, so a listener that dies
  while the process survives shows up as `2` (degraded).

## Open items (not done)

- ❌ DTL-9 pre-handshake rate limiting / amplification review for **DTLS**: the
  handshake runs inside `webrtc-dtls` below `accept()`, so a rate limit there
  needs a UDP demultiplexer in front of the listener. The QUIC paths now have
  one (`max_handshakes_per_sec_per_ip`).
- ❌ Certificate hot-reload for DTLS, and for the raw-QUIC path (TURNS and
  WebTransport both reload).
- ❌ mTLS / client certificates for TURNS clients.

- ❌ `unsafe` audit refresh (io_uring/AF_XDP raw-syscall + mmap paths).
- ❌ Load/soak runs and continuous fuzzing in CI. The encrypted-transport plan
  (what to run, what to record) is `docs/verification/encrypted-transports.md`;
  §4 there lists the specific missing automated tests.
- ❌ Differential vs coturn (§7.2) executed against a live coturn.
