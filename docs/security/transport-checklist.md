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
  `turna_transport_readiness` / `turna_dtls_readiness`).

## Open items (not done)

- ❌ DTL-9 pre-handshake rate limiting / amplification review (needs hooks below
  webrtc-dtls `accept()`).
- ❌ `unsafe` audit refresh (io_uring/AF_XDP raw-syscall + mmap paths).
- ❌ Load/soak runs and continuous fuzzing in CI.
- ❌ Differential vs coturn (§7.2) executed against a live coturn.
