# turna — protocol compliance & deliberate constraints

Scope: STUN/TURN protocol behaviour of `turna` v0.3.0. Every row marked
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

- **300** Try Alternate — cluster redirect / lame-duck drain. **Wire fix
  2026-08-18:** the accompanying `ALTERNATE-SERVER` attribute was encoded as type
  **0x0003** (which is RFC 5780 CHANGE-REQUEST) instead of **0x8023**, so clients
  could not read the alternate address and the redirect was effectively a bare
  300. Corrected in `proto-stun::ATTR_ALTERNATE_SERVER`, and now guarded by
  `proto-turn` tests that assert the **encoded bytes**:
  `redirect_encodes_alternate_server_as_0x8023` and
  `redirect_encodes_error_code_300`. They check the literal type on the wire and the
  plain (non-XOR) MAPPED-ADDRESS encoding, because a test written against the
  constant would have passed throughout the bug — the enum variant was right, the
  round-trip tests used the same wrong value on both sides, and the documentation
  claimed the fix had already been made.
  Still owed, and separate: that a client actually *follows* the redirect. That needs
  two nodes in cluster mode (`maybe_redirect_new_client` returns early without
  `[cluster]`), and no client in this repo follows `300` — pion's harness does not.
  The wire format was the risk; following it was never verified before either.
- **400** Bad Request — malformed request; EVEN-PORT⊕RESERVATION-TOKEN violation; too many peers in one CreatePermission (>32, B5); channel/peer uniqueness conflict; invalid channel; `REQUESTED-TRANSPORT = TCP` arriving over a non-TCP ingress (UDP/DTLS/QUIC/SCTP) per RFC 6062 §4.1.
- **401** Unauthorized — auth challenge (REALM + NONCE); also the fail-closed path when a request lacks a NONCE.
- **403** Forbidden — CreatePermission/ChannelBind/Send to a filtered (special-use) peer.
- **420** Unknown Attribute — unknown comprehension-required attribute (I3).
- **437** Allocation Mismatch — no allocation on the 5-tuple; lost create race (B1); migration ticket/epoch mismatch.
- **438** Stale Nonce — expired/rotated nonce.
- **440** Address Family not Supported — `REQUESTED-ADDRESS-FAMILY = IPv6` when `[turn] external_ip6` is unset, or on an RFC 6062 TCP allocation (always).
- **442** Unsupported Transport Protocol — REQUESTED-TRANSPORT is neither UDP nor (TCP with `[turn.tcp_relay]` enabled).
- **443** Peer Address Family Mismatch — CreatePermission/ChannelBind naming a peer in a different family than the allocation's relayed address (RFC 6156 §4.2).
- **486** Allocation Quota Reached — per-allocation permission/channel cap (B5); rate-limit rejections.
- **508** Insufficient Capacity — no relay port available; server draining.

---

## 3. Deliberate constraints (Verified — by design, not bugs)

- **Relayed transport: UDP by default, TCP only behind an off-by-default feature.**
  `REQUESTED-TRANSPORT` must be UDP, or the Allocate is rejected with **442** —
  *unless* `[turn.tcp_relay]` is enabled, in which case `REQUESTED-TRANSPORT = TCP`
  (RFC 6062) is accepted. Two conditions apply to that path: the request must
  arrive over the TCP/TLS control connection (RFC 6062 §4.1) or it is rejected
  with **400**, and `production = true` refuses to start with
  `[turn.tcp_relay].enabled = true` at all. So on a production profile the
  constraint still reads "UDP relay only" — but it is now a config gate, not an
  absence of implementation. TLS/DTLS *relay-leg* transports remain unoffered.
  This concerns the turna↔peer leg only. The *client↔turna* leg supports TURNS
  (TURN-over-TLS-over-TCP) via the `tls` feature — verified end-to-end with
  Chrome, Firefox and Safari (see `docs/interop/`).
- **Relay sockets: IPv4 by default, IPv6 opt-in.** With `[turn] external_ip6`
  empty (the default) relay sockets bind `0.0.0.0` and an IPv6 Allocate is refused
  with 440 — the historical behaviour. Set it, and
  `session::PortAllocator::*_family` binds the socket in the family the client
  requested and the processor advertises `external_ip6`. One allocation serves one
  family: a cross-family peer is refused with **443** (RFC 6156 §4.2). Peer
  addresses are still normalized `::ffff:` → v4 (`peer_filter::normalize_addr`).
  DONT-FRAGMENT is family-aware (`IPV6_MTU_DISCOVER` on a v6 relay socket), and
  the peer filter denies the v4-embedding v6 transition prefixes (NAT64
  `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32`, IPv4-compatible `::/96`)
  so the v4 deny rules cannot be bypassed through a v6 literal.
  The v6 relay socket is bound `IPV6_V6ONLY` (`socket2` under `cfg(unix)`; the
  option has to be applied between `socket()` and `bind()`, which `std` cannot
  express), so the family separation is explicit at the socket rather than resting
  only on the checks above. Still missing for a complete v6 story:
  `ADDITIONAL-ADDRESS-FAMILY` — blocked on a storage decision, see
  `docs/design/additional-address-family.md` — and v6 for RFC 6062 TCP relay.
  **Interop verified** on routable global v6 addresses, both by our own client and by coturn's (`docs/interop/relayed-media-2026-08-19.md`, `docs/interop/coturn-2026-08-23.md`). Not covered: routing between different hosts.
- **Default MTU 1280.** `PacketProcessor` defaults to `mtu = 1280`; DONT-FRAGMENT drops oversized Send-indication payloads against this value. Operators set the real path MTU at construction (`with_mtu`).
- **Experimental transports are feature-gated and off by default.** `quic` /
  `web-transport` (raw-QUIC / WebTransport ingress), `sctp` (client control
  transport, no RFC defines it, plaintext channel) and `af-xdp` (kernel-bypass
  datapath) compile only under their features. The B6 bounded-queue work applies
  to those paths; the default production profile does not include them. `af-xdp`
  is Linux-only (its `build.rs` refuses to build elsewhere by design) and is the
  only feature that pulls an LGPL-licensed branch into the dependency graph —
  see §7.
- **Three features are refused outright under `production = true`.**
  `config::validate()` fails the start when `turn.tcp_relay.enabled`,
  `turn.sctp.enabled` or `turn.auth.oauth.enabled` is set in a production
  profile. This is policy, not a defect: each is implemented and testable with
  `production = false`, and each has an exit condition
  (`docs/protocol-gap.md`).
- **Nonce lifetime 630s, client-bound.** Nonces are an HMAC over client address + issue time under an ephemeral per-process key (`processor::NonceManager`): no server-side nonce table, and a restart forces a fresh 401 for outstanding nonces.
- **Per-allocation resource caps.** 256 permissions and 256 channel bindings per allocation; 32 peers per CreatePermission (B5). Compile-time constants, not config.
- **Credentials are not SASLprep/OpaqueString-normalized.** Long-term keys hash the raw `username:realm:password` UTF-8 bytes (`crypto/lib.rs`). ASCII credentials (the common case) interoperate fine; a client that normalizes non-ASCII credentials per RFC 8489 OpaqueString / RFC 5389 SASLprep before hashing would derive a different key and fail integrity. If non-ASCII credentials must interoperate, add normalization at both key-derivation sites (kept in parity today).
- **Cluster failover assumes roughly-synchronized clocks (NTP).** Node liveness is `last_seen_ms` compared against the sweeper's local wall-clock; a dead node is confirmed after ~5s (`live_window` 3s + `suspicion_ticks` 2 × `sweep_interval` 1s). NTP-class skew (<1s) is well within this margin. If a node's clock runs minutes ahead it may mis-classify live peers as dead — but `claim_allocation` CAS preserves correctness: the mis-claim spins against the live node's re-asserted heartbeats rather than producing split-brain or data loss (`services/node/src/failover.rs`). Deploy nodes with NTP and keep inter-node skew below `live_window`. Confirmed by the failover-integration tests against a live Tarantool (`integration_failover_claim_is_atomic`, `_stale_claim_rejected`, `_sweep_reassigns_dead_node`).
- **Failover time scales linearly with allocations-per-node.** A dead node's orphans are enumerated once (`find_by_node` — ~84 ms for 50k rows, 23.7 MB), then reassigned one `claim_allocation` CAS at a time over iproto. At 50k allocations this is on the order of tens of seconds in production (sequential claim loop + parsing a ~24 MB response); see `docs/scale/`. It is correct (all rows reassigned, exactly-one-winner) but not instant. Keep per-node allocation counts within a few thousand for fast failover. `find_by_node` has no limit, so 100k+ per node would warrant pagination on that path.

---

## 4. Beta scope (what is supported as stable)

For the `v0.3.0` release, the supported surface is exactly the Verified rows
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

**Not supported as stable (experimental / out of scope / unverified):** RFC 6062
TCP relay,
TURN-over-SCTP and RFC 7635 OAuth (implemented but refused under
`production = true`); QUIC / WebTransport ingress (feature-gated); AF_XDP and
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
- ~~**IPv6 relay** — decide and document explicitly whether it is out of scope.~~
  **Decided, then implemented as opt-in.** The earlier decision was "out of scope,
  440 always". It is now `[turn] external_ip6`: empty keeps the 440 behaviour, set
  enables per-family relay sockets with RFC 6156 §4.2 enforcement (443 on a
  cross-family peer). What remains open is *evidence*, not implementation — no
  test or interop run covers a v6 allocation. Recorded in `README.md`,
  `docs/CONFIGURATION.md`, `docs/feature-support.md` and
  `docs/PRODUCTION_READINESS.md` (R10); gaps in `docs/protocol-gap.md` → IPv6.
- **Datagram/size constants** — partially closed. The `read_to_end(1 MiB)` on
  raw-QUIC streams is **gone**: control streams are now read per chunk
  (`pump_quic_stream` / `pump_wt_stream`), because a control stream stays open for
  the session's lifetime and `read_to_end` never completed. The DTLS receive
  buffer was also corrected to a full DTLS plaintext fragment (2^14) rather than
  `max(mtu, 2 KiB)`. Still owed: confirming the STUN response buffers and the
  4096-byte Data-indication buffer against the advertised MTU, and documenting any
  intentional headroom.

---

## 6. Keeping this document true

`scripts/check-doc-claims.sh` (run it from the repository root; wire it into
`scripts/ci-checks.sh`) asserts that the load-bearing claims in this file and in
`docs/protocol-gap.md`, `docs/feature-support.md`, `README.md` and
`docs/alerts/` are backed by a grep over the code:

- `ATTR_ALTERNATE_SERVER` is 0x8023, not the CHANGE-REQUEST value 0x0003.
- No document makes a live claim of an RFC 5780 codec while none exists.
- If `node_migration.rs` has no callers, some document says "unwired".
- Every metric in an alert `expr:` is actually exported by `turna-health`.
- Each `production = true` refusal named in the docs still exists in
  `config::validate()`, matched on the operator-visible diagnostic rather than the
  field path (the field path alone still matches after the gate is deleted).
- Every bypass-relevant v6 prefix the peer filter denies (NAT64, 6to4, Teredo,
  IPv4-compatible) is mentioned somewhere in the docs. An incomplete deny list
  reads as permission, and this is the one check whose subject is a security
  boundary.
- Every Cargo feature named in the docs is declared in a manifest.

Each check was verified to fail when the corresponding fact is broken, not just to
pass on a good tree. The gate exists because an audit register that drifts is worse
than none: a false "done" hid a shipped wire bug.

---

## 7. Licence election — `libxdp-sys` (feature `af-xdp`)

> Renumbered from §6 when the doc-truth gate section was added. `deny.toml` cites
> "docs/COMPLIANCE.md §6" for this election — update that comment to §7, or
> renumber back if you prefer the citation stable.

`libxdp-sys`, and the vendored C libraries it binds (`libxdp`, `libbpf`), are
offered under **`LGPL-2.1 OR BSD-2-Clause`**. Turna **elects `BSD-2-Clause`**.

- The disjunction lets a downstream user pick either branch; electing the
  permissive one keeps the `af-xdp` build free of copyleft obligations.
- The declared SPDX string uses the **deprecated** identifier `LGPL-2.1` (current
  spelling: `LGPL-2.1-only` / `LGPL-2.1-or-later`), so cargo-deny cannot parse it
  and previously degraded to a warning — meaning this crate's licence was not
  actually being checked. `deny.toml` now carries a `[[licenses.clarify]]` entry
  pinning the elected expression.
- **Scope:** `af-xdp` is the only feature that brings an LGPL branch into the
  graph. It is absent from default and production builds, and is Linux-only.
- If you ship a binary built with `--features af-xdp`, this election is the
  licence position to state, and the BSD-2-Clause notice for `libxdp`/`libbpf`
  belongs in `NOTICE`.

---

*Generated as part of the production-hardening review. Pair with
`SECURITY_OPS.md` (security posture, known-limitations) for the full picture.*
