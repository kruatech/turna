# turna — protocol compliance & deliberate constraints

Scope: STUN/TURN protocol behaviour of `turna` v0.3.0-beta.1. Every row marked
**Verified** was read directly in the source during this review (crate paths
given). Rows marked **Confirm** were *not* verified against code here and must be
checked before this document is published as a compliance claim.

Suggested home in-repo: `docs/COMPLIANCE.md`.

---

## 1. RFCs and what is implemented

| RFC | Area | Status | Notes (source) |
|-----|------|--------|----------------|
| 5389 / 8489 | STUN Binding, MESSAGE-INTEGRITY | **Verified** | Binding request → XOR-MAPPED-ADDRESS + SOFTWARE. HMAC-SHA-1 (5389) and HMAC-SHA-256 (8489) both accepted (`processor::handle_binding`, `proto-stun/message.rs`). |
| 8489 | MESSAGE-INTEGRITY-SHA256 hardening | **Verified** | Tag length constrained to 16–32 and a multiple of 4 before truncated verify (F1, `proto-stun/integrity.rs`); any non-FINGERPRINT attribute after MESSAGE-INTEGRITY invalidates it (I1, `proto-stun/message.rs`). |
| 5389 | FINGERPRINT | **Verified** | Handled; only FINGERPRINT may follow MESSAGE-INTEGRITY (I1). |
| 5389 §7.3.1 | Unknown comprehension-required attrs | **Verified** | Unknown type `< 0x8000` in a request → 420 + UNKNOWN-ATTRIBUTES; `0x8000+` ignored; 0x001C/0x001D allowlisted (I3, `processor::reject_unknown_comprehension_required`). |
| 5766 / 8656 | Allocate / Refresh / CreatePermission / ChannelBind | **Verified** | All four methods handled with long-term auth challenge, nonce, MESSAGE-INTEGRITY (`processor` handlers). |
| 5766 / 8656 | Send / Data indications | **Verified** | Send indication relays to a permitted peer; peer→client falls back to a Data indication when no channel is bound (`processor::handle_send_indication`, `process_relay_recv`). |
| 8656 §7.2 | EVEN-PORT + RESERVATION-TOKEN | **Verified** | R=0 (even port) and R=1 (even + reserved odd + token) supported; the two attributes are mutually exclusive → 400; reserved port freed on create failure (I9, `session::PortAllocator`). |
| 8656 §12 | Channel bindings | **Verified** | Channel number validated (`turn::is_valid_channel`); (channel,peer) uniqueness enforced → 400 on conflict; 10-minute lifetime (`session::add_channel`). |
| 8656 §9 | Permissions | **Verified** | 5-minute lifetime; multiple XOR-PEER-ADDRESS per CreatePermission installed; forbidden peers → 403 (`processor::handle_create_permission`, `peer_filter`). |
| 8656 §16.4 | DONT-FRAGMENT | **Verified** | Sets IP DF via `IP_MTU_DISCOVER` on the relay socket (Linux); Send-indication payload over MTU dropped (`processor`, `set_dont_fragment`). |
| 8016 | Connection Migration (MOBILITY-TICKET) | **Verified, optional** | Off by default; when enabled, a signed ticket + valid credentials re-key an allocation to a new 5-tuple with epoch anti-replay (`processor::try_migration_refresh`, `session::re_key`). |
| — | Cluster redirect (300 Try Alternate) | **Verified** | New clients redirected to their owning node via a 300 with ALTERNATE-SERVER when clustering is on / during drain (`processor::maybe_redirect_new_client`). |
| 5389 / 8489 | SASLprep / OpaqueString on credentials | **Verified: not applied (by design)** | `long_term_key` = `MD5(username:realm:password)` and `long_term_key_sha256` = `SHA-256(...)` hash the raw UTF-8 bytes with no normalization (`crypto/lib.rs`, explicitly documented). See §3 constraint. |
| 8656 | Channel-number range | **Verified** | `is_valid_channel` accepts `0x4000..=0x7FFE` (`CHANNEL_MIN`/`CHANNEL_MAX`, `proto-turn/lib.rs`) — the RFC 8656 usable range. |
| 5766/8656 | ALTERNATE-SERVER | **Verified** | `build_redirect_response` emits a 300 "Try Alternate" carrying `Attribute::AlternateServer(addr)` (`proto-turn/lib.rs`). |

---

## 2. Error-code catalog (Verified)

Codes actually emitted by `processor` (grep `encode_error` / builders):

- **300** Try Alternate — cluster redirect / lame-duck drain.
- **400** Bad Request — malformed request; EVEN-PORT⊕RESERVATION-TOKEN violation; too many peers in one CreatePermission (>32, B5); channel/peer uniqueness conflict; invalid channel.
- **401** Unauthorized — auth challenge (REALM + NONCE); also the fail-closed path when a request lacks a NONCE.
- **403** Forbidden — CreatePermission/ChannelBind/Send to a filtered (special-use) peer.
- **420** Unknown Attribute — unknown comprehension-required attribute (I3).
- **437** Allocation Mismatch — no allocation on the 5-tuple; lost create race (B1); migration ticket/epoch mismatch.
- **438** Stale Nonce — expired/rotated nonce.
- **442** Unsupported Transport Protocol — REQUESTED-TRANSPORT ≠ UDP.
- **486** Allocation Quota Reached — per-allocation permission/channel cap (B5); rate-limit rejections.
- **508** Insufficient Capacity — no relay port available; server draining.

---

## 3. Deliberate constraints (Verified — by design, not bugs)

- **UDP relay transport only.** `REQUESTED-TRANSPORT` must be UDP or the Allocate is rejected with 442. TCP-allocation (RFC 6062) and TLS/DTLS *relay-leg* transports are not offered (`processor::handle_allocate`). This concerns the turna↔peer leg only. The *client↔turna* leg does support TURNS (TURN-over-TLS-over-TCP) via the `tls` feature — verified end-to-end with Chrome, Firefox and Safari (see `docs/interop/`).
- **IPv4 relay sockets.** Relay sockets bind `0.0.0.0` (`session::PortAllocator::allocate_and_bind` / `allocate_even_and_bind`), i.e. IPv4 only. Peer addresses are normalized `::ffff:` → v4 (`peer_filter::normalize_addr`). An IPv6 relay would additionally need `IPV6_MTU_DISCOVER` (noted in `set_dont_fragment`). **If IPv6 relay is a requirement, it is not implemented today.**
- **Default MTU 1280.** `PacketProcessor` defaults to `mtu = 1280`; DONT-FRAGMENT drops oversized Send-indication payloads against this value. Operators set the real path MTU at construction (`with_mtu`).
- **Experimental transports are feature-gated and off by default.** `quic` / `web-transport` (raw-QUIC / WebTransport ingress) and `af-xdp` (kernel-bypass datapath) compile only under their features. The B6 bounded-queue work applies to those paths; the default production profile does not include them. `af-xdp` is Linux-only (its `build.rs` refuses to build elsewhere by design).
- **Nonce lifetime 630s, client-bound.** Nonces are an HMAC over client address + issue time under an ephemeral per-process key (`processor::NonceManager`): no server-side nonce table, and a restart forces a fresh 401 for outstanding nonces.
- **Per-allocation resource caps.** 256 permissions and 256 channel bindings per allocation; 32 peers per CreatePermission (B5). Compile-time constants, not config.
- **Credentials are not SASLprep/OpaqueString-normalized.** Long-term keys hash the raw `username:realm:password` UTF-8 bytes (`crypto/lib.rs`). ASCII credentials (the common case) interoperate fine; a client that normalizes non-ASCII credentials per RFC 8489 OpaqueString / RFC 5389 SASLprep before hashing would derive a different key and fail integrity. If non-ASCII credentials must interoperate, add normalization at both key-derivation sites (kept in parity today).
- **Cluster failover assumes roughly-synchronized clocks (NTP).** Node liveness is `last_seen_ms` compared against the sweeper's local wall-clock; a dead node is confirmed after ~5s (`live_window` 3s + `suspicion_ticks` 2 × `sweep_interval` 1s). NTP-class skew (<1s) is well within this margin. If a node's clock runs minutes ahead it may mis-classify live peers as dead — but `claim_allocation` CAS preserves correctness: the mis-claim spins against the live node's re-asserted heartbeats rather than producing split-brain or data loss (`services/node/src/failover.rs`). Deploy nodes with NTP and keep inter-node skew below `live_window`. Confirmed by the failover-integration tests against a live Tarantool (`integration_failover_claim_is_atomic`, `_stale_claim_rejected`, `_sweep_reassigns_dead_node`).
- **Failover time scales linearly with allocations-per-node.** A dead node's orphans are enumerated once (`find_by_node` — ~84 ms for 50k rows, 23.7 MB), then reassigned one `claim_allocation` CAS at a time over iproto. At 50k allocations this is on the order of tens of seconds in production (sequential claim loop + parsing a ~24 MB response); see `docs/scale/`. It is correct (all rows reassigned, exactly-one-winner) but not instant. Keep per-node allocation counts within a few thousand for fast failover. `find_by_node` has no limit, so 100k+ per node would warrant pagination on that path.

---

## 4. Beta scope (what is supported as stable)

For a `v0.3.0-beta.1` cut, the supported surface is exactly the Verified rows
above; the rest is experimental, out of scope, or unverified.

**Supported (stable):** UDP TURN relay (non-UDP → 442); IPv4 relay; long-term
and shared-secret auth (realm-scoped); strict STUN/TURN parsing; bounded
allocations, permissions (256), channels (256), peers-per-request (32) with
atomic global/tenant quotas; fail-closed production config.

**Verified since the beta cut (rc.1, see `docs/`):** multi-node failover
adoption end-to-end — a killed owner's allocations claimed by the survivor via
backend CAS, no split-brain (`docs/failover/`); external-client interop with
coturn and all three major browser engines — Chrome 150, Firefox 152, Safari
26.5, each 5/5 over TURNS with a trusted cert (allocate, auth-negative 401,
end-to-end relay data, TLS transport, RAF) (`docs/interop/`); a 12-hour relay
soak with no memory/fd leak (`docs/soak/`).

**Not supported as stable (experimental / out of scope / unverified):** IPv6
relay (IPv4-only today); QUIC / WebTransport ingress (feature-gated); AF_XDP and
io_uring datapaths (feature-gated, not runtime-verified); TURN-over-DTLS
(transport verified — DTLS 1.2 handshake + operator cert, `openssl s_client
-dtls`, verify code 0 — but the full allocate-over-DTLS cycle is not exercised
by a live TURN client; no common DTLS-TURN client exists and browsers use
TURNS/TCP. The STUN/TURN layer is transport-independent and is verified over
UDP/TURNS. DTLS requires a PKCS#8 ECDSA-P-256 key and fails closed if a
configured cert cannot load; see `docs/dtls/`); an exhaustive
browser matrix (three engines verified on macOS; mobile browsers, other OSes
and older versions not yet); large-scale (10k–50k allocations) and real-network
(non-loopback) load; SASLprep / non-ASCII credentials (absent by design, §3).

## 5. Not covered here / owed verification

Documentation the review flagged that needs a code read or a runtime measurement
before it can be stated as fact — deliberately **not** asserted above:

- **CGNAT / large-scale port-exhaustion** behaviour and sizing guidance — needs a load measurement, not a code claim.
- **RSS / multi-queue AF_XDP** scaling characteristics — measurement.
- **Feature-support matrix accuracy** — regenerate from `Cargo.toml` feature definitions and confirm each documented feature name still exists.
- **IPv6 relay** — decide and document explicitly whether it is out of scope for this release (current code: IPv4-only relay, §3).
- **Datagram/size constants** — confirm the various buffer-size constants
  (STUN response buffers, `read_to_end(1 MiB)` on raw-QUIC streams, 4096-byte
  Data-indication buffer) are internally consistent with the advertised MTU and
  document any intentional headroom.

---

*Generated as part of the production-hardening review. Pair with
`SECURITY_OPS.md` (security posture, known-limitations) for the full picture.*
