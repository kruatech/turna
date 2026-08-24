# Turna — Protocol Feature Gap Registry

Fact-based status of STUN/TURN protocol features, grounded in code symbols
observed in the source (not the roadmap's aspirations). This is the input to any
protocol-expansion work (plan §38–65): it says what exists, what is missing, and
what each `partial` needs to become `stable`.

**Evidence discipline.** "Confirmed" = a concrete symbol/file was seen.
"Unverified" = plausibly present but not inspected — treated as an audit item, not
a claim. Line numbers are omitted (they drift); symbols/paths are stable enough.

**Transport pass 2026-08-13**: the TLS / DTLS / QUIC-WebTransport rows below were
re-checked against the code after the encrypted-transport hardening work; entries
marked "Done since the audit" reflect that pass. The codec rows are unchanged.

**Doc-truth gate.** This file is the register operators and auditors read, and it
has been wrong before: the RFC 5780 entry claimed a codec that did not exist, and
in doing so hid a real wire bug (`ATTR_ALTERNATE_SERVER` was 0x0003, i.e.
CHANGE-REQUEST, so every `300 Try Alternate` was unreadable). `scripts/check-doc-claims.sh`
now ties the load-bearing claims here to a grep over the code and fails CI when
they diverge. If you change a status line below, run it.

**Codec audit performed 2026-07-12** against `crates/protocol/proto-stun/src/{lib,
header,message,attribute,method}.rs`, `crates/protocol/proto-turn/src/lib.rs`,
`crates/crypto/src/lib.rs`, `crates/relay/src/processor.rs` (auth path in
`crates/auth/src/lib.rs`), and the `proto-{stun,turn}/tests/property.rs` suites.
`proto-stun/src/integrity.rs` and `error.rs` were also inspected (2026-07-12,
follow-up): the MI/fingerprint *compute* internals are now verified, not inferred.

## Cross-cutting notes

- **STUN codec** lives in a dedicated crate `turna_proto_stun`
  (`attribute` / `header` / `message` / `method`). Its *internals* (full attribute
  coverage, integrity variants) were **not** inspected here — several rows below
  depend on a codec-level conformance audit.
- **`transport` naming collision.** In config, `transport` already means the
  **datapath backend** (`tokio` / `io_uring` / `af_xdp`), a third meaning distinct
  from *client transport* (listeners) and *relayed transport*. Relayed transport is
  currently **UDP-only**. When TCP relay (6062) lands, the client-vs-relayed split
  the roadmap requires must avoid reusing the `transport` name (§40.1).
- **SSRF/peer policy is already first-class**: `crates/relay/src/peer_filter.rs`
  (`is_forbidden_peer`, `normalize_ip`) + a validated peer-filter config profile.
  New relayed transports must route through it, not around it.
- **Production gate (config `validate()`).** With `production=true`: experimental
  transports are refused (`turn.tcp_relay.enabled` / `turn.sctp.enabled` → hard
  error), an unlimited per-allocation bandwidth cap (`max_bytes_per_sec_per_allocation = 0`) is
  refused unless `allow_unlimited_bandwidth = true` is set to accept the risk, and
  the shipped production Helm example now pins a finite `maxBytesPerSecPerAllocation`. So the
  "not production" notes below are **enforced**, not merely advisory.

## Summary

| Feature | Status | Confirmed by |
|---|---|---|
| STUN core (RFC 8489) | present, audited + hardened | typed attrs, 420, SHA-1/256 verify+sign, vectors+fuzz |
| TURN UDP (RFC 8656) | present, **interop verified** | 7 methods, TURN attrs typed, EVEN-PORT/RESV, builder roundtrips; agreement with coturn's client (`docs/interop/coturn-2026-08-23.md`) |
| EVEN-PORT / RESERVATION-TOKEN | present | `get_even_port`, `allocate_even_and_bind` |
| IPv6 (RFC 8656) | partial | relaying works per-family behind `[turn] external_ip6`; **relayed media and coturn interop verified on routable addresses**; still no `ADDITIONAL-ADDRESS-FAMILY`, and no run across different hosts |
| Mobility (RFC 8016) | partial | `Attribute::MobilityTicket` issue+reissue |
| DTLS (RFC 7350) | present, **interop verified** | `DtlsSection` (feature-gated); allocation, media both directions on both listener paths, 20 min under load, and agreement with coturn's client (`docs/interop/coturn-2026-08-23.md`) |
| TLS 1.3 / TURNS | present, audit needed | `[tls]` listener config |
| ALPN (RFC 7443) | partial | referenced in config + node main |
| TURN REST credentials | present (compat) | `AuthMode::SharedSecret` HMAC |
| Multi-realm / tenant | present, isolation tests needed | per-tenant range + disjointness validation + realm match |
| Peer filtering (SSRF) | present | `peer_filter` module |
| TCP relay (RFC 6062) | **near-complete (experimental)** | Allocate(TCP)+CONNECT+ConnectionBind raw-detach over TLS + **peer-initiated relayed TCP listener + accept loop + CONNECTION-ATTEMPT indication + ConnectionBind on peer-initiated conns**; ConnectionBind ownership-bound (O#1), leak-safe detach (O#2); off by default; remaining: pipelined-client hardening + interop verification; **still refused under `production=true`** pending interop verification |
| NAT discovery (RFC 5780) | **absent** | no codec in the tree — see the section below; the earlier "codec done" claim was wrong |
| OAuth (RFC 7635) | **done** (stages 1–3) | codec + AuthMode::OAuth (AEAD decrypt + MI-by-mac_key; token-time = §6.2 fixed-point + clock skew) + config wiring + 401 THIRD-PARTY-AUTHORIZATION challenge + §6.1 lifetime cap incl. zero-remaining 401 + **`kid`-from-USERNAME key selection (RFC 7635 §6.1): kid-tagged keys select one AS-RS key directly; `strict_kid` opt-in rejects unknown/absent kid, default keeps trial-decrypt fallback for rotation**. Remaining: RFC 6062 TCP-allocate binding |
| ORIGIN | **present (codec)** | `Attribute::Origin` (0x802F) parse/encode/getter |
| QUIC / WebTransport | **both beta** — raw QUIC has correctness, relayed media and 20 min under load, but **no independent implementation can exist**: no RFC defines TURN over raw QUIC. WebTransport has browser interop (Chrome 151, real certificate, `docs/interop/webtransport-browser-2026-08-20.md`) plus 20 min under load | `quic.rs` raw-QUIC + wtransport H3 paths; per-stream control replies, session + per-IP caps, per-IP handshake rate limit, cert hot-reload and the full `[turn.quic]` transport limits on **both** paths (the wtransport `quinn` dependency feature is enabled, so `quic_config_mut()` is reachable). Remaining: `alpn` inert on H3 (wtransport forces `h3`), no interop test |
| SCTP client transport | **wired** | codec + bridge + transport server + server.with_sctp + [turn.sctp] config + Cargo feature; needs compile pass + host kernel; **refused under `production=true`** (config gate) |

---

## present / audit-needed

### STUN core — RFC 8489 — audited
- **Header** (`header.rs`): `MAGIC_COOKIE = 0x2112A442` validated on decode;
  `transaction_id: [u8; 12]`; all four classes (Request / Indication /
  SuccessResponse / ErrorResponse) with correct C0/C1 bit encoding.
- **Attributes typed** (`attribute.rs`): MAPPED-ADDRESS, ALTERNATE-SERVER (plain
  MAPPED format, no XOR — correct), XOR-MAPPED-ADDRESS, USERNAME (**strict UTF-8**,
  no lossy repair — preserves signed bytes), MESSAGE-INTEGRITY (strict 20 B),
  FINGERPRINT (strict 4 B), ERROR-CODE, REALM, NONCE, SOFTWARE, UNKNOWN-ATTRIBUTES.
- **Parser hardening**: per-attribute value-length cap and total-attribute-count
  cap (both rejected *before* buffer bounds, so no distinct error oracle);
  BufferTooShort bounds checks; 4-byte padding honored and its **value ignored**
  per RFC 8489 §14 (documented, deliberate — coturn/pion compatible).
- **420 comprehension-required**: implemented in `processor.rs`
  (`reject_unknown_comprehension_required`) — any `Attribute::Unknown` with
  `attr_type < 0x8000` → `420` + UNKNOWN-ATTRIBUTES list, **before** method dispatch.
  Tested (`unknown_comprehension_required_yields_420`: 0x0021→420, 0x8021→not-420).
- **Integrity end-to-end** (auth path): SHA-256 MESSAGE-INTEGRITY-SHA256 verified
  when present (`verify_integrity_sha256` + SHA-256 key), else RFC 5389 HMAC-SHA-1
  (+ MD5 key). PASSWORD-ALGORITHM (0x001D) consistency enforced → `400` on mismatch;
  not required (legacy 5389 clients omit it). User-enumeration timing equalized
  (dummy verify for unknown users).
- **SHA-256 response signing — done**: `encode_with_integrity_sha256` exists in
  `message.rs`, and `processor.rs::encode_with_integrity_auto` auto-selects it when
  the request carried a SHA-256 MESSAGE-INTEGRITY, else SHA-1 — wired for Allocate/
  Refresh/CreatePermission/ChannelBind responses.
- **Integrity compute internals — audited clean** (`integrity.rs`): HMAC-SHA1
  compute + constant-time `verify_slice`; HMAC-SHA256 compute + verify with
  left-truncation restricted to {16,20,24,28,32} bytes per RFC 8489 §14.6 (rejects
  short/empty tags before comparing); FINGERPRINT = CRC32/ISO-HDLC ⊕ 0x5354554E.
  Unit tests cover tamper / wrong-key / truncated-tag for both. No defect.
- **Not a defect — correct by omission**: **USERHASH (0x001E)** is not implemented;
  since it is comprehension-required, the server correctly answers `420` per
  RFC 8489 §7.3.1. The optional userhash anonymity mechanism (§9.2.4) is simply not
  supported; a userhash-only client cannot authenticate. Document, don't "fix".
- **Minor**: MESSAGE-INTEGRITY-SHA256 and PASSWORD-ALGORITHM are decoded as
  `Attribute::Unknown` ("Stage 1"), not first-class typed variants — read/verify
  works (and is exercised), there is just no typed *encode* for them.
- **Tests present**: `property.rs` roundtrips; `rfc5769_vectors.rs` — RFC 5769
  §2.2/§2.3 known-answer decode (XOR-MAPPED-ADDRESS → 192.0.2.1:32853 and the IPv6
  vector), which a symmetric XOR bug cannot pass; `fuzz_decode.rs` — proptest
  no-panic over arbitrary bytes for decode/classify/channel-data + deterministic
  edge cases. **Still thin**: IPv6 addresses in the generative roundtrip strategies;
  integrity/fingerprint known-answer (needs the long-term key, lives in the auth
  path). src-level unit tests already cover the DoS-guard limits and bad magic cookie.
- **partial→stable — CLOSED for the codec.** Done: RFC 5769 known-answer vectors
  (`rfc5769_vectors.rs`), no-panic fuzz (`fuzz_decode.rs`), generative IPv6 XOR-address
  roundtrips (`ipv6_roundtrip.rs`), SHA-1/SHA-256 verify **and** sign, integrity
  compute internals audited, USERHASH decision (correct-by-omission). Typed encode for
  MI-SHA256/PASSWORD-ALGORITHM is deliberately **not** added — the generic `encode()`
  skips integrity/fingerprint (added separately via `encode_with_integrity*`), so a
  typed variant in the generic loop would be inert; read+verify already work via the
  `Unknown` path. Remaining is interop/leak/boundary, which is stand work (#9/#14).
- **Priority**: highest (everything rides on it) — but this is now *hardening*, not
  build-from-scratch.

### TURN UDP — RFC 8656 — audited (codec), interop verified
- **Methods** (`method.rs`): Binding 0x0001, Allocate 0x0003, Refresh 0x0004,
  Send 0x0006, Data 0x0007, CreatePermission 0x0008, ChannelBind 0x0009 — the full
  RFC 8656 method set. (This bullet used to add "no Connect/ConnectionBind,
  confirming 6062 absent"; that is stale — `Method::{Connect, ConnectionBind,
  ConnectionAttempt}` 0x000A/0B/0C now exist, see the RFC 6062 section below.)
- **TURN attributes typed** (`attribute.rs` + `proto-turn`): LIFETIME(u32),
  REQUESTED-TRANSPORT(u8), XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS, CHANNEL-NUMBER,
  DATA, DONT-FRAGMENT, EVEN-PORT(bool R-bit), RESERVATION-TOKEN([u8;8]),
  REQUESTED-ADDRESS-FAMILY(Ipv4/Ipv6), MOBILITY-TICKET.
- **EVEN-PORT / RESERVATION-TOKEN**: `get_even_port`, `allocate_even_and_bind`,
  RFC 8656 §7.2 mutual-exclusion enforced; 0x0017/0x0018 decode as typed variants
  (regression-tested so they never spuriously 420).
- **Builders tested**: `proto-turn/tests/property.rs` — Allocate request/response
  and CreatePermission roundtrips assert REQUESTED-TRANSPORT, XOR-RELAYED/MAPPED,
  LIFETIME, XOR-PEER-ADDRESS survive encode→decode.
- **Not verified here**: RESERVATION-TOKEN reservation *lifetime*, fd/port cleanup
  on expiry, ICMP handling, mandatory error-response matrix — these are runtime/e2e,
  not codec, so they belong to the stand plans, not this audit.
- **partial→stable (remaining)**: external WebRTC interop; expiry-without-leak test;
  duplicate-Allocate; relay-range boundary from an external client (see #9/#14 plans).
- **Priority**: highest (core product) — codec is solid; remaining work is interop
  and runtime-leak proof, not protocol implementation.

### TLS 1.3 / TURNS
- **Confirmed**: `[tls]` listener config; rustls `with_safe_default_protocol_versions`
  pinned to the `ring` provider (`tls12` + 1.3, so ≤1.1 is out by construction);
  ALPN `stun.turn` / `stun.nat-discovery` advertised when `enable_alpn`.
- **Done since the audit**: **cert reload without datapath restart** —
  `CertReloader` polls mtime on `[tls].cert_reload_secs` and each new connection
  takes the current `ServerConfig`; a failed reload keeps the previous material
  (`turna_tls_cert_reloads_total`, `turna_tls_cert_reload_failures_total`).
  Connection caps (global + per-IP), handshake timeout with its own counters, and
  accept-error resilience are in (`docs/security/transport-checklist.md`).
- **Unverified (audit)**: 0-RTT / early-data policy stated explicitly; behaviour on
  expired / unknown-CA client certs (no client auth is configured today).
- **Done since the audit**: a handshake **rate** limit —
  `[tls].max_handshakes_per_sec_per_ip` / `handshake_burst_per_ip`, the same
  token bucket the QUIC paths use (`crate::ratelimit::HandshakeLimiter`, lifted
  out of `quic.rs` so a `--features tls` build can reach it). Refused before
  `tls.accept()`, counted as `turna_tls_rejected_rate_limit_total`. Off by
  default, like the QUIC one.
- **Done since the audit**: ALPN **strict** mode — `[tls].alpn_required` refuses a
  client that negotiates no ALPN (`turna_tls_alpn_rejected_total`). rustls already
  failed the handshake on a non-overlapping offer; the gap was the client offering
  none at all. Default stays compatible.
- **Required tests**: 1.3 handshake, 1.2 compat, ≤1.1 rejected, expired/unknown-CA,
  cert reload (covered by `docs/verification/encrypted-transports.md`), handshake
  flood bound.
- **Done since the audit**: interop evidence, re-recorded against the current code —
  Chrome 151 / Firefox 153 / Safari 26.5, full allocation and bidirectional relayed
  data, with `relayProtocol: tls` confirming the transport on the two engines that
  report it (`docs/interop/turns-browsers-2026-08-18.md`).
- **Done 2026-08-22/23**: 24 h under load against this code with zero relayed-frame
  loss and no leak (`docs/soak/endurance-24h-2026-08-22.md`), a Let's Encrypt chain
  validated by a verifying client on a public deployment, and agreement with coturn's
  client (`docs/interop/coturn-2026-08-23.md`). TURNS is **supported**.
- **Remaining**: version/early-data policy documented.
- **Priority**: high (TURNS is the common browser path).

### TURN REST credentials (compatibility, NOT an RFC)
- **Confirmed**: `AuthMode::SharedSecret { realm, secret }`, HMAC (SHA-1) validation.
- **Note**: based on an expired draft — must be documented as a compatibility
  extension, never "RFC" (matches §48).
- **Unverified (audit)**: expiry-timestamp parsing/skew window, constant-time
  compare, **secret rotation** (active+retiring overlap), allocation lifetime capped
  to credential TTL, algorithm selection by config (not guessed).
- **Required tests**: coturn-issuer interop both ways; expired timestamp rejected;
  bounded skew; overlap rotation without outage; tenant-A secret rejected in B.
- **partial→stable**: rotation + skew + cross-tenant negative tests pass.
- **Priority**: high (interop with existing coturn deployments).

### Multi-realm / multi-tenant
- **Confirmed**: per-tenant `relay_port_range` with disjointness + empty/inverted
  validation; per-tenant `max_allocations` (now capacity-validated); per-tenant
  `shared_secret`/`static_users`; strict per-realm key derivation and REALM match;
  placeholder-secret rejection per tenant in prod.
- **Unverified (audit)**: nonce bound to realm/server identity; per-realm OAuth/REST
  key isolation; metrics not leaking cross-tenant identifiers as labels.
- **Required tests** (negative, via real API + auth flow, not just unit): same
  username in two realms; realm-A creds rejected in B; ORIGIN cannot switch tenant;
  quota-A does not affect B; force-delete scoped to tenant.
- **partial→stable**: isolation negative-test suite green end-to-end.
- **Priority**: high (multi-tenant is a stated feature).

---

## partial

### IPv6 — RFC 8656 / RFC 6156
- **Confirmed**: `Attribute::RequestedAddressFamily` used in Allocate.
- **Done since the audit**: IPv6 *relaying* itself. `[turn] external_ip6` (empty =
  off, and then an IPv6 Allocate still answers 440) turns on a v6 relay socket:
  `session::PortAllocator::{allocate_and_bind_family, allocate_even_and_bind_family,
  claim_and_bind_family}` bind in `RelayFamily::{V4,V6}`, and the processor
  advertises `external_ip6` in XOR-RELAYED-ADDRESS for v6 allocations. RFC 6156
  §4.2 family separation is enforced: a cross-family peer is refused with **443
  Peer Address Family Mismatch** on CreatePermission and ChannelBind, and dropped
  (counted) on a Send indication, which has no error response. The relay port pool
  is shared — one port number is bound in exactly one family at a time, so port
  accounting is unchanged. Config validation rejects a v4 literal in
  `external_ip6`.
- **Also done**: IPv6 peer-filter classes and a family-aware DONT-FRAGMENT.
  `peer_filter::is_special_v6` now denies, besides link-local: deprecated
  site-local `fec0::/10`, and the **v4-embedding transition prefixes** — NAT64
  `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32` and the deprecated
  IPv4-compatible `::/96`. That last group is the security-relevant one: each
  carries an arbitrary IPv4 address inside a v6 literal, so without them every v4
  rule (169.254.169.254, RFC 1918, the operator deny list) was bypassable by
  asking for the v6 spelling of the same target — reachable the moment IPv6
  relaying existed. Also denied: discard-only `100::/64`, benchmarking
  `2001:2::/48`, ORCHIDv2 `2001:20::/28`. Deliberately **not** denied:
  documentation `2001:db8::/32` — it embeds no IPv4 address, so it is not a bypass,
  and it is the canonical stand-in for a public v6 address in test suites (denying
  it broke this crate's own peer-filter test). ULA
  `fc00::/7` remains under `deny_private`, unchanged. And `set_dont_fragment` now
  takes the relay family and uses `IPPROTO_IPV6`/`IPV6_MTU_DISCOVER` on a v6
  socket — the v4 option does not set DF on an `AF_INET6` socket, so a v6
  allocation with DONT-FRAGMENT would have silently fragmented.
- **Also done**: `IPV6_V6ONLY` is now set on v6 relay sockets (`socket2` under
  `cfg(unix)` in `turna-session`; the option has to be applied between `socket()`
  and `bind()`, which `std` cannot express). The family separation no longer rests
  only on the three downstream checks.
- **Absent — and blocked on a schema decision, not on protocol work**:
  `ADDITIONAL-ADDRESS-FAMILY` (RFC 8656 §7.2 — one Allocate asking for both
  families, which is what a dual-stack WebRTC client wants). The protocol side is
  small; the state side is not. `turna_allocations` in both
  `deploy/tarantool/init.lua` and the Rust `INIT_SCRIPT` uses **`relay_port` as the
  primary key**, so one allocation cannot hold two relay ports without choosing
  one of:
  1. keep `relay_port` as the v4 port and carry the v6 port inside the `data` blob
     — no schema change, but the v6 port loses its index, so port-collision
     detection and `pool_states` cover only half the allocation (there is an
     existing `rehydrate_double_port_conflict` test asserting the guarantee this
     would weaken);
  2. two tuples per allocation linked by `allocation_id` — keeps both ports
     indexed, but `by_user` quota counting double-counts and refresh/remove become
     transactional across two tuples;
  3. change the primary key — cleanest model, needs a migration story for live
     data.
  Recommendation: (3) if a schema migration is acceptable in this release,
  otherwise (1) with the halved guarantee written down explicitly rather than
  discovered later. **Not started** — picking wrong here is expensive to unwind,
  and `init.lua` carries an explicit "change one place, change both" coupling with
  the Rust script. Full analysis, per-option edit lists, the test list and the
  ordering argument: [docs/design/additional-address-family.md](design/additional-address-family.md).
- **Absent**: IPv6 for RFC 6062 TCP relay (still 440 there — the TCP relay datapath
  has no v6 path).
- **Verified 2026-08-18** (`docs/interop/conformance-2026-08-18.md`): the control
  plane, in both configurations — 440 with `external_ip6` unset, an IPv6 relayed
  address when set, 443 in both directions on a cross-family peer, and all four
  v4-embedding transition prefixes denied with 403.
- **Verified 2026-08-19** (`docs/interop/relayed-media-2026-08-19.md`): relayed
  **media** over IPv6 — 20 000 frames through a v6 allocation, zero loss, p50 0.5 ms,
  using `channel-data --family v6` (peer on `[::1]`, since a cross-family peer is
  refused with 443 by design).
- **Verified 2026-08-23**: relayed media between two *routable* global v6 addresses —
  6 010 of 6 010 frames, zero loss, peer filter in `lan` profile with no loopback
  concession. Still outside: routing between different hosts (both addresses belong to
  one machine).
- **Required tests**: v4→v4, v4→v6 refused with 443, v6→v6 relaying, v6→v4 refused;
  440 when `external_ip6` is unset; v4-mapped normalization; external IPv6 peer
  (not loopback); EVEN-PORT on a v6 allocation.
- **partial→stable**: the tests above recorded, plus IPv6 peer-filter classes.
- **Priority**: high (dual-stack is table stakes for WebRTC).

### Mobility — RFC 8016
- **Confirmed**: `Attribute::MobilityTicket` issued on Allocate and reissued on
  Refresh; a no-allocation-with-ticket path (migration) is referenced.
- **Absent/unverified**: ticket crypto binding contents, replay/expiry rejection,
  cross-node migration (needs state availability + relay routing + fencing — per
  #4/#16 this is at most same-cluster, likely **same-node** today), race handling.
- **Required tests**: address change preserving relay addr + channel binds; replay
  rejected; modified/expired/wrong-realm ticket rejected; cross-node policy defined.
- **Wiring status (checked 2026-08-18)**: `crates/relay/src/node_migration.rs`
  (`MigrationCoordinator`, `DrainCoordinator`, `MigrationPayload`) is referenced
  **only** by `crates/relay/src/lib.rs`'s `pub mod` line — nothing calls it. So
  cross-node migration is not "unverified", it is **unwired**: there is no path
  that transfers an allocation to another node. `turna_transport::migration`
  (tickets / ReKey) *is* wired, which is the part that works.
- **partial→stable**: negative + e2e migration tests; and a decision on
  `node_migration.rs` — wire it (needs payload transfer over the control-plane
  gRPC, plus fencing) or delete it, because a tested-but-uncalled module reads as
  a feature that exists.
- **Priority**: medium.

### DTLS — RFC 7350
- **Confirmed**: `DtlsSection` config (feature `dtls`, `mtu`, `max_sessions`,
  outbound-drop metric) — a real listener path, not a stub.
- **Done since the audit**: per-IP session cap; receive buffer sized to a full DTLS
  plaintext fragment (2^14 — it was 2 KiB, so a large client record killed the
  session); outbound MTU enforced by dropping + counting
  (`turna_dtls_outbound_oversize_total`) instead of relying on IP fragmentation;
  allocation released on session close; cooperative drain; readiness gauge.
  Anti-amplification is covered by the HelloVerifyRequest cookie exchange inside
  `webrtc-dtls::listen()`.
- **Upstream liveness bug, mitigated 2026-08-18**: `DtlsListener::accept()` runs
  `DTLSConn::new()` — the entire handshake — inline and with no timeout
  (webrtc-rs/webrtc#614). A peer that starts a handshake and goes silent therefore
  parked the accept loop forever, taking the whole DTLS listener out of service
  from a single packet, with no signal: socket bound, process healthy, readiness
  Ready, no counter moving. The cookie exchange does not help — it defends against
  spoofed sources, not a real peer that stops. `[turn.dtls].accept_timeout_secs`
  (default 10) now bounds the accept and counts abandonments
  (`turna_dtls_accept_timeouts_total`). Liveness restored; concurrency not — the
  accepts are still serial, so a flood costs one timeout window each. Owning the
  UDP demultiplexer is the structural fix and is the same work that would enable a
  handshake rate limit and certificate hot-reload. All three should be done
  together, not separately.
- **Structural fix implemented, opt-in**: `crates/transport/src/dtls_demux.rs`
  (`[turn.dtls] demux = true`) owns the UDP socket and runs one task per
  handshake, which closes all four items at once — concurrency, admission control
  *before* any DTLS state exists, `max_handshakes_per_sec_per_ip`, and
  `cert_reload_secs`. Failed handshakes become observable there
  (`turna_dtls_handshake_failures_total`), which the stock path cannot do. The
  HelloVerifyRequest cookie exchange is unaffected: it lives in the server-side
  `DTLSConn` handshake, not in the listener we replaced, and established sessions
  still go through the shared `handle_dtls_session`, so the record pump, MTU
  enforcement and idle reaper cannot drift between the two paths.
  **Default off**: it displaces the only DTLS path with recorded verification
  (`docs/dtls/`). `partial→stable` for DTLS now means an interop run on the demux
  path, after which the default can flip.
- **Verified 2026-08-23**: DTLS 1.2 interop against coturn's `turnutils_uclient`
  (`docs/interop/coturn-2026-08-23.md`) — an implementation written elsewhere — plus
  allocation and relayed media on both listener paths and 20 min under load.
- **Absent/unverified**: in-code handshake **rate**
  bound (the handshake runs below `accept()`, so it needs a UDP demultiplexer in
  front — currently an ops mitigation via `iptables hashlimit`), loss/reorder/
  duplicate handling, ALPN over DTLS, **certificate hot-reload** (the stack fixes
  its config at `listen()`; rotation logs a warning and needs a restart), DTLS 1.3
  (RFC 9147) and Connection ID (RFC 9146) are not in the stack at all.
- **Required tests**: 1.2 allocation; loss/reorder in handshake; invalid cookie;
  handshake timeout; cert rotation; ALPN.
- **partial→stable**: interop + amplification + failure tests; DTLS 1.0 gated off.
- **Priority**: medium (nice-to-have; UDP+TLS cover most clients).

### ALPN — RFC 7443
- **Confirmed**: referenced in config and node main.
- **Absent/unverified**: `stun.turn` / `stun.nat-discovery` labels advertised and
  selected; strict vs compatible mode; SNI/ALPN kept separate.
- **Required tests**: TLS/DTLS with each label; missing ALPN in strict vs compatible;
  unknown ALPN rejected.
- **partial→stable**: label selection + strict/compatible modes proven on TLS+DTLS.
- **Priority**: medium (ties to TLS/DTLS rows).

---

## absent (greenfield — do not start before Gate B/C/D, see production plan)

### TCP relay — RFC 6062 — partial (engine exists, wiring remains)
- **Present** (`crates/relay/src/tcp_relay.rs`): `TcpRelayManager` with `handle_connect()`
  (§4.3, opens TCP to peer, returns CONNECTION-ID) and a two-phase ConnectionBind
  (§4.4) — `claim(id, owner)` (atomic `WaitingForBind`→`Claimed`, and now verifies the
  binding client's credentials match the CONNECT owner — O#1) then
  `attach_bound()` (`Claimed`→`Bound`, raw splice, generic over the client stream);
  `Connect`→`WaitingForBind`→`Claimed`→`Bound`→`Close` state machine, idle-timeout and
  max-connection guards.
- **Codec layer — done**: `Method::{Connect,ConnectionBind,ConnectionAttempt}`
  (0x000A/0B/0C), `Attribute::ConnectionId` (0x002A), `TRANSPORT_TCP = 6`, and
  `StunMessage::get_connection_id()`; tests in `tests/tcp_relay_codec.rs`.
- **Wired over TLS (unified role transition)**: `handle_allocate` accepts
  `REQUESTED-TRANSPORT=TCP` (reserves a relay port, `set_transport(Tcp)`);
  `connect_decision`/`connection_bind_decision` in `processor.rs`; the TURNS bridge
  (`tls_bridge.rs`) runs CONNECT out-of-band and, on a validated ConnectionBind,
  atomically claims the peer connection, writes the success, then **detaches** the
  TLS stream into raw relay mode — `DetachedConn` carries the unread prebuffer so no
  bytes are lost (`run_with_detach` / `ConnCtl::Detach` in `tcp_tls.rs`). Config-gated
  (`[turn.tcp_relay] enabled=false` by default).
- **Security fixes (review O)**: (O#1) `CONNECTION-ID` is a guessable sequential
  value, so `ConnectionBind` is now bound to the authenticated allocation — the
  peer connection records the CONNECT client's long-term key as `owner`, and
  `claim()` rejects (as not-found, no oracle) a bind from any other credential,
  closing a cross-client hijack. (O#2) if the detach handoff to the transport
  cannot be delivered after a successful claim, the claim is rolled back
  (`TcpRelayManager::release`) instead of leaking a `Claimed` connection forever;
  the idle-timeout reaper also now covers a stuck `Claimed` (not just
  `WaitingForBind`). Tests: `claim_requires_matching_owner`,
  `release_removes_claimed_connection`. The transport-side detach handoff no
  longer silently drops: the router delivers the detach with a bounded `send`
  (not `try_send`) on a decoupled task, so a transiently full per-connection queue
  waits instead of losing the detach, and a closed connection is surfaced (logged)
  rather than dropped; if the raw-relay receiver is gone when the framed
  connection tries to hand off its stream, `handle_conn` closes the connection
  (emitting `ConnectionClosed`) instead of reporting a phantom `Detached`. A
  positive end-to-end detach *ack* back to the session layer remains a possible
  future hardening, but the silent-loss path is closed.
- **Peer-initiated — done**: on a TCP allocation, `handle_allocate_tcp` binds a
  relayed `std::net::TcpListener` on `0.0.0.0:relay_port` (mirroring the UDP pool)
  **before committing the allocation** — a bind failure releases the port and
  rejects the Allocate (508) rather than returning a half-working allocation — and
  emits `Action::RegisterTcpListener`. The TLS bridge adopts it and runs an
  accept loop: each accepted peer connection is registered via
  `TcpRelayManager::register_incoming` (owner = allocation key) and the client is
  notified with a `ConnectionAttempt` indication (`turn::build_connection_attempt`,
  CONNECTION-ID + XOR-PEER-ADDRESS, unauthenticated over the TLS control channel)
  routed to its control connection via `client_sinks[client_addr]`. The client then
  ConnectionBinds the id through the existing (ownership-checked) path. `CloseRelay`
  aborts the accept loop; if the client is gone the pending peer conn is `release`d.
  The listener is dropped without panic if a TCP allocation ever reaches the UDP /
  SCTP dispatch path.
- **Ingress-transport gating — done**: `handle_allocate` now takes an `ingress_tcp`
  flag. `process` (UDP / SCTP / borrowed-slice ingress) passes `false`; the TURNS
  bridge calls a new `process_tcp_control` which passes `true`. A `REQUESTED-TRANSPORT
  =TCP` request over any non-TCP ingress is rejected with **400 Bad Request** (RFC 6062
  §4.1) before any port is reserved — previously it created a half-working allocation
  whose relayed listener was then dropped.
- **Remaining**: pipelined-client hardening — a non-conformant client sending app bytes
  before the ConnectionBind success could have them mis-framed (RFC clients wait for
  success; the prebuffer captures any leftover). Verify against a real server with
  `cargo` + an interop harness before lifting the `production=true` gate.
- **Scope reality**: a TCP-relay socket is **node-local** and cannot migrate via the
  backend — seamless failover for TCP relay must not be claimed (§45.6).
- **Priority**: medium-high (enterprise/firewalled clients). Now a wiring job, not a
  from-scratch build.

### NAT behavior discovery — RFC 5780 — ABSENT (this entry was wrong)
- **Correction (2026-08-18).** This section previously claimed the codec was done,
  listing `ATTR_CHANGE_REQUEST`, `Attribute::ChangeRequest`, `ATTR_RESPONSE_ORIGIN`,
  `ATTR_OTHER_ADDRESS`, the matching getters and a test `tests/nat_discovery.rs`.
  **None of that exists.** A repo-wide grep for `ChangeRequest`, `OtherAddress` and
  `ResponseOrigin` over `crates/` returns nothing, and `proto-stun/tests/` has no
  `nat_discovery.rs`. Treat RFC 5780 as not started.
- **Bug the stale entry was hiding.** It also claimed `ATTR_ALTERNATE_SERVER` had
  been corrected from 0x0003 to 0x8023. It had not — the constant was still
  **0x0003**, which is CHANGE-REQUEST. Since ALTERNATE-SERVER is the payload of a
  300 Try Alternate, every cluster redirect and every lame-duck drain redirect was
  sending an attribute a conforming client cannot recognise as the alternate
  address. Fixed now (`ATTR_ALTERNATE_SERVER = 0x8023`); 0x0003 is kept as
  `ATTR_CHANGE_REQUEST_RESERVED` purely so the collision cannot come back.
  **This is a wire-behaviour change — the redirect path needs a re-test.**
- **Remaining (all of it)**: the codec, and then the *service*, which needs a
  **2×IP / 2×port** topology so the server can answer from an alternate
  address/port per CHANGE-REQUEST. That conflicts with the current
  single-relay-IP hostNetwork model, so the networking model (#9) comes first.
- **Priority**: low. Without the dual-address topology the codec alone buys
  nothing, so the honest status is "not started", not "partial".
- **Priority**: low (experimental; niche).

### OAuth third-party authorization — RFC 7635 — done (stages 1–3)
- **Codec layer — done**: `ATTR_ACCESS_TOKEN` (0x001B, comprehension-required) +
  `Attribute::AccessToken(Vec<u8>)`; `ATTR_THIRD_PARTY_AUTHORIZATION` (0x802E,
  comprehension-optional) + `Attribute::ThirdPartyAuthorization(Vec<u8>)`;
  `get_access_token()` / `get_third_party_authorization()`; test
  `tests/oauth_codec.rs`. Token bytes are opaque at this layer.
- **Auth layer — done** (`AuthMode::OAuth { realm, as_rs_key, server_name }`):
  `validate()` early-dispatches OAuth; `validate_oauth` reads ACCESS-TOKEN,
  AEAD-decrypts the self-contained token (`decrypt_access_token`/`aead_decrypt`:
  AES-128/256-GCM by key length, 12-byte nonce, AAD = server name), checks
  timestamp+lifetime, then verifies MESSAGE-INTEGRITY with the enclosed `mac_key`
  (SHA-256 or SHA-1). Tests in `oauth_tests` (accept / wrong-AAD / expired /
  tampered-MI). Needs `aes-gcm = "0.10"` added to `crates/auth/Cargo.toml`.
- **Wiring — done**: a config OAuth kind builds an `AuthMode::OAuth` (per realm)
  from `[turn.auth]`; the processor emits a 401 THIRD-PARTY-AUTHORIZATION
  challenge (`build_oauth_challenge` via `base_oauth_identity`) when credentials
  are absent; the node assembles it in `main.rs`.
- **§6.1 lifetime binding — done**: `validate_with_lifetime` surfaces the token's
  remaining lifetime; Allocate and Refresh cap the granted lifetime by it so an
  allocation never outlives its authorizing token. A token with **zero** remaining
  — one that expired inside the clock-skew grace and therefore still authenticates
  — is refused with 401 rather than granting a 0-second (already-dead) allocation.
  On Refresh this refusal fires only when the client asked to *keep* the
  allocation (requested LIFETIME > 0); an explicit `LIFETIME == 0` release is
  always honoured, since releasing never extends beyond the token. Test:
  `token_expired_within_skew_grace_reports_zero_remaining` (auth) + the processor
  `token_max_lifetime == Some(0)` guards in `handle_allocate` / `handle_refresh`.
- **`kid` key selection — done** (RFC 7635 §6.1): `[[turn.auth.oauth.keys]]`
  entries carry `{kid, key}`. A USERNAME that matches a `kid` selects that key
  directly (single decrypt). Behaviour on no/unknown match is profile-dependent:
  with `strict_kid = false` (default, rotation-friendly) the server trial-decrypts
  across the kid keyring + kid-less `as_rs_keys`; with `strict_kid = true` an
  unknown or absent kid is **rejected** (no fallback), matching a strict RFC /
  high-assurance profile. Config validates hex/length + non-empty, unique kids.
  Tests: `kid_username_selects_matching_key`,
  `strict_kid_rejects_unknown_and_missing_username` (auth).
- **Remaining**: RFC 6062 TCP-allocate lifetime binding (the TCP relay datapath is
  experimental/off).
- **Priority**: low-medium (long-term + REST cover common cases).

### ORIGIN — present (codec)
- **Done**: `ATTR_ORIGIN = 0x802F` + `Attribute::Origin(String)` — parse (lossy,
  so a malformed origin never fails the message), encode, and `StunMessage::
  get_origin()` / `origins()` (multiple ORIGINs preserved in order, per the draft).
  Codec test: `tests/origin.rs`.
- **Trust enforced by omission**: ORIGIN is decoded and exposed for logging/policy
  only. It is deliberately **not** wired into auth or tenant resolution — tenant is
  resolved from REALM after integrity, and ORIGIN is client-forgeable (§49.2).
- **Optional follow-ons** (not done, low priority): origin→realm selection for the
  auth challenge, and an origin allow/deny policy in config. Both are policy
  features on top of the now-available attribute, not codec work.

### SCTP client transport — partial (control-transport only)
- **No RFC**: no TURN RFC defines SCTP as a *relayed* transport. Only sane form is
  **TURN-over-SCTP as a client control transport** (STUN/TURN length-framed over an
  SCTP association, like TURN-over-TCP); the relay socket to the peer stays UDP.
  `TRANSPORT_SCTP = 132` is the IANA protocol number (RFC 4960), not a standardized
  TURN relayed-transport value — used here only to name the control transport.
- **Done**: `TRANSPORT_SCTP` constant; `crates/relay/src/sctp_bridge.rs` — the
  relay-side glue (a faithful adaptation of `tls_bridge.rs`, reusing the shared
  `TcpTransportEvent`/`TcpSendCommand` stream events; relayed traffic goes out UDP
  via the same `OutMsg`/`ClientSinks` machinery). Registered under `feature = "sctp"`.
- **Transport server — written** (`crates/transport/src/sctp.rs`): faithful mirror
  of `tcp_tls`, minus TLS. One-to-one SCTP (`SOCK_STREAM`+`IPPROTO_SCTP`) via
  `socket2` + `tokio::io::unix::AsyncFd`; reuses the shared `TcpFrameCodec` and the
  `TcpConnectionId/TcpTransportEvent/TcpSendCommand` types; registered under
  `feature = "sctp"` in `transport/lib.rs`. Plaintext control channel (TLS-over-SCTP
  out of scope). Highest-uncertainty blind module — has `// VERIFY (on-repo)` marks
  at the socket2/SCTP-specific spots; expect a compile pass.
- **Wiring — done** (`with_sctp` path, mirroring TURNS):
  - Cargo: `turna-transport` gains `sctp = ["tls"]`; `turna-relay` gains
    `sctp = ["turna-transport/sctp"]`. `socket2`/`libc` were already non-optional
    `cfg(unix)` deps — nothing new to add.
  - `RelayServer::with_sctp(SctpTransportConfig)` + an `sctp_config` field; the
    bridge is spawned in `run()` under `#[cfg(feature = "sctp")]`, sharing the relay
    send channel + `client_sinks` exactly like the TURNS bridge.
  - `config`: `[turn.sctp]` section (`SctpSection`: enabled/listen/max_frame_size/
    read_timeout_secs/max_connections/backlog; disabled by default).
  - node `main.rs`: `build_sctp_transport_config` + `if config.sctp.enabled { …
    with_sctp … }` in the tokio backend, after the TURNS block.
  - Fixed `TcpConnectionId::next` visibility to `pub(crate)` so the sctp module can
    mint connection ids.
- **Remaining**: (1) **Host**: Linux `sctp` kernel module loaded. (2) io_uring
  backend: SCTP is only wired in the tokio backend path (mirrors where TURNS is
  wired); add to the io_uring arm if needed. (3) The control channel is
  **plaintext** — TLS-over-SCTP is out of scope, so anything an operator would
  protect with TURNS is unprotected here. (4) It is missing the hardening every
  other listener received: no per-IP connection cap, no handshake rate limit, no
  `turna_sctp_*` metrics, no readiness gauge, and no cooperative drain.
- **Fixed 2026-08-18**: `sctp_bridge` did not release the allocation on
  `ConnectionClosed`, so a closed association held its relay port until the TTL and
  a reconnecting client hit 437. `tls_bridge` had that release; SCTP was missing
  it. Now mirrored.
- **Recommendation stands, sharpened**: low real-world use, high attack surface,
  awkward in containers (needs the host SCTP kernel module). Position: **keep it
  refused under `production = true` and do not invest further** — the gate already
  makes it unshippable, so hardening it buys nothing. The only open decision is
  deletion. Keep experimental, off by default.
- **Priority**: lowest.

---

## Recommended order (after production Gates B/C/D)

1. **Audit, don't rebuild** what exists: STUN 8489 codec conformance, TURN 8656
   attribute conformance + external interop, TLS policy — these are `present` but
   need proof, and they gate everything.
2. Promote the `partial` set to `stable` where ROI is high: IPv6 (full matrix),
   REST rotation, multi-tenant isolation tests, ALPN, DTLS 1.2 interop, mobility.
3. Only then greenfield, by ROI: TCP relay (6062) → OAuth (7635) → NAT discovery
   (5780) / ORIGIN → SCTP (or drop SCTP).

Do not begin greenfield RFCs while production Gates B (config), C (networking, #9),
D (capacity, #14) are open — hardening the existing UDP profile outranks widening
the protocol surface.
