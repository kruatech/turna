# Turna — Protocol Feature Gap Registry

Fact-based status of STUN/TURN protocol features, grounded in code symbols
observed in the source (not the roadmap's aspirations). This is the input to any
protocol-expansion work (plan §38–65): it says what exists, what is missing, and
what each `partial` needs to become `stable`.

**Evidence discipline.** "Confirmed" = a concrete symbol/file was seen.
"Unverified" = plausibly present but not inspected — treated as an audit item, not
a claim. Line numbers are omitted (they drift); symbols/paths are stable enough.

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
| TURN UDP (RFC 8656) | present, audited (interop pending) | 7 methods, TURN attrs typed, EVEN-PORT/RESV, builder roundtrips |
| EVEN-PORT / RESERVATION-TOKEN | present | `get_even_port`, `allocate_even_and_bind` |
| IPv6 (RFC 8656) | partial | `Attribute::RequestedAddressFamily` |
| Mobility (RFC 8016) | partial | `Attribute::MobilityTicket` issue+reissue |
| DTLS (RFC 7350) | partial | `DtlsSection` (feature-gated) |
| TLS 1.3 / TURNS | present, audit needed | `[tls]` listener config |
| ALPN (RFC 7443) | partial | referenced in config + node main |
| TURN REST credentials | present (compat) | `AuthMode::SharedSecret` HMAC |
| Multi-realm / tenant | present, isolation tests needed | per-tenant range + disjointness validation + realm match |
| Peer filtering (SSRF) | present | `peer_filter` module |
| TCP relay (RFC 6062) | **near-complete (experimental)** | Allocate(TCP)+CONNECT+ConnectionBind raw-detach over TLS + **peer-initiated relayed TCP listener + accept loop + CONNECTION-ATTEMPT indication + ConnectionBind on peer-initiated conns**; ConnectionBind ownership-bound (O#1), leak-safe detach (O#2); off by default; remaining: pipelined-client hardening + interop verification; **still refused under `production=true`** pending interop verification |
| NAT discovery (RFC 5780) | **partial** | codec done (CHANGE-REQUEST/OTHER-ADDRESS/RESPONSE-ORIGIN); dual-IP datapath remains (#9) |
| OAuth (RFC 7635) | **done** (stages 1–3) | codec + AuthMode::OAuth (AEAD decrypt + MI-by-mac_key; token-time = §6.2 fixed-point + clock skew) + config wiring + 401 THIRD-PARTY-AUTHORIZATION challenge + §6.1 lifetime cap incl. zero-remaining 401 + **`kid`-from-USERNAME key selection (RFC 7635 §6.1): kid-tagged keys select one AS-RS key directly; `strict_kid` opt-in rejects unknown/absent kid, default keeps trial-decrypt fallback for rotation**. Remaining: RFC 6062 TCP-allocate binding |
| ORIGIN | **present (codec)** | `Attribute::Origin` (0x802F) parse/encode/getter |
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

### TURN UDP — RFC 8656 — audited (codec), interop pending
- **Methods** (`method.rs`): Binding 0x0001, Allocate 0x0003, Refresh 0x0004,
  Send 0x0006, Data 0x0007, CreatePermission 0x0008, ChannelBind 0x0009 — the full
  RFC 8656 method set. No Connect/ConnectionBind (confirms 6062 TCP-relay absent).
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
- **Confirmed**: `[tls]` listener config (TURNS enable).
- **Unverified (audit)**: version floor (reject ≤1.1), 0-RTT disabled by default,
  cert reload without datapath restart, handshake rate limiting.
- **Required tests**: 1.3 handshake, 1.2 compat, ≤1.1 rejected, expired/unknown-CA,
  cert reload, handshake flood bound.
- **partial→stable**: version policy + early-data-off + reload proven; ALPN wired.
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

### IPv6 — RFC 8656
- **Confirmed**: `Attribute::RequestedAddressFamily` used in Allocate.
- **Absent/unverified**: all four client/relay/peer family combinations actually
  relaying; `ADDITIONAL-ADDRESS-FAMILY`; IPv6-specific peer filtering (link-local,
  ULA, v4-mapped, metadata ranges) as distinct from the v4 checks; external IPv6.
- **Required tests**: v4→v4, v4→v6, v6→v4, v6→v6; unsupported family error;
  v4-mapped normalization; external IPv6 peer (not loopback).
- **partial→stable**: full transport matrix + IPv6 peer-filter classes + external test.
- **Priority**: high (dual-stack is table stakes for WebRTC).

### Mobility — RFC 8016
- **Confirmed**: `Attribute::MobilityTicket` issued on Allocate and reissued on
  Refresh; a no-allocation-with-ticket path (migration) is referenced.
- **Absent/unverified**: ticket crypto binding contents, replay/expiry rejection,
  cross-node migration (needs state availability + relay routing + fencing — per
  #4/#16 this is at most same-cluster, likely **same-node** today), race handling.
- **Required tests**: address change preserving relay addr + channel binds; replay
  rejected; modified/expired/wrong-realm ticket rejected; cross-node policy defined.
- **partial→stable**: negative + e2e migration tests; cross-node behaviour documented
  (or explicitly limited to same-node).
- **Priority**: medium.

### DTLS — RFC 7350
- **Confirmed**: `DtlsSection` config (feature `dtls`, `mtu`, `max_sessions`,
  outbound-drop metric) — a real listener path, not a stub.
- **Absent/unverified**: DTLS 1.2 interop, anti-amplification (stateless cookie,
  handshake bounds), loss/reorder/duplicate handling, ALPN over DTLS, DTLS 1.0 kept
  legacy-only/off.
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

### NAT behavior discovery — RFC 5780 — partial (codec done)
- **Codec layer — done**: `ATTR_CHANGE_REQUEST` (0x0003) +
  `Attribute::ChangeRequest{change_ip,change_port}`; `ATTR_RESPONSE_ORIGIN` (0x802B)
  + `Attribute::ResponseOrigin(SocketAddr)`; `ATTR_OTHER_ADDRESS` (0x802C) +
  `Attribute::OtherAddress(SocketAddr)` (MAPPED-ADDRESS format, v4+v6); getters
  `get_change_request/get_other_address/get_response_origin`; test
  `tests/nat_discovery.rs`. (RESPONSE-PORT/PADDING/CACHE-TIMEOUT skipped — client
  test knobs, low value.)
- **Bug fixed while here**: `ATTR_ALTERNATE_SERVER` was **0x0003 (wrong — that is
  CHANGE-REQUEST)**; corrected to the RFC 5389/8489 value **0x8023**. This changes
  the wire value the server sends in 300 Try-Alternate redirects to the correct one
  (coturn/pion expect 0x8023); tests reference the constant symbolically so they
  follow the fix. Behaviour change — verify.
- **Remaining (datapath, gated on #9)**: the behaviour-discovery *service* needs a
  **2×IP / 2×port** topology so the server can answer from an alternate address/port
  per CHANGE-REQUEST — conflicts with the current single-relay-IP hostNetwork model,
  so resolve the networking model (#9) first.
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
- **Remaining**: (1) a **compile pass** — the socket layer (`socket2`+`AsyncFd`,
  `// VERIFY` marks in `sctp.rs`) was written without a compiler. (2) **Host**: Linux
  `sctp` kernel module loaded. (3) io_uring backend: SCTP is only wired in the tokio
  backend path (mirrors where TURNS is wired); add to the io_uring arm if needed.
- **Recommendation stands**: low real-world use, high attack surface, awkward in
  containers (needs the host SCTP kernel module). Keep experimental, off by default.
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
