# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-08-24

A correctness and verification release. No API breaks; one wire-behaviour fix
that operators of clustered deployments will notice, and one that changes which
IPv6 peers are accepted. Both are called out first.

### Changed — wire behaviour (read before upgrading)

- **`ALTERNATE-SERVER` attribute type corrected from `0x0003` to `0x8023`**
  (RFC 5389 §15.5 / RFC 8489 §14.15). `0x0003` is `CHANGE-REQUEST` (RFC 5780) and
  was never this attribute. Since `ALTERNATE-SERVER` is the payload of a
  `300 Try Alternate`, **every cluster redirect and every lame-duck drain redirect
  was sending a type no conforming client could read as the alternate address** —
  the redirect degraded to a bare 300. Clients (coturn, pion, browsers) will now
  follow redirects that previously did nothing.
  *Action:* re-test the cluster-redirect and drain paths against a real client.
  Anything that was silently compensating for broken redirects may behave
  differently.

- **The IPv6 peer filter now denies the v4-embedding transition prefixes**: NAT64
  `64:ff9b::/96`, 6to4 `2002::/16`, Teredo `2001::/32`, and the deprecated
  IPv4-compatible `::/96`. Each carries an arbitrary IPv4 address inside a v6
  literal, so without them every v4 rule — link-local `169.254.169.254`, RFC 1918,
  the operator deny list — was bypassable by asking for the v6 spelling of the
  same target. Also denied: deprecated site-local `fec0::/10`, discard-only
  `100::/64`, benchmarking `2001:2::/48`, ORCHIDv2 `2001:20::/28`.
  Deliberately **not** denied: documentation `2001:db8::/32` (embeds no IPv4
  address, and is the canonical example address in test suites).
  *Action:* if any deployment legitimately relays to peers behind NAT64 or 6to4,
  it will now get `403 Forbidden`. Use the `allowed` CIDR list for those.

### Fixed

- **DTLS listener could be parked indefinitely by a single peer.**
  `webrtc_dtls::listener::accept()` runs the whole handshake inline with no
  timeout of its own ([webrtc-rs/webrtc#614](https://github.com/webrtc-rs/webrtc/issues/614)),
  so a peer that began a handshake and went silent stopped the accept loop and the
  DTLS listener served **nobody** — while the socket stayed bound, the process
  stayed healthy, `turna_dtls_readiness` still read Ready, and no counter moved.
  A one-packet, silent outage. Bounded by the new
  `[turn.dtls].accept_timeout_secs` (default 10) with
  `turna_dtls_accept_timeouts_total`. Note this restores liveness but not
  concurrency: accepts are still serial on the default path, so a deliberate flood
  degrades new-session throughput one timeout window at a time. See
  `[turn.dtls].demux` below for the structural fix.

- **TURN-over-SCTP leaked allocations.** `sctp_bridge` did not release the
  allocation when the association closed, so its relay port was held until the TTL
  expired and a reconnecting client collided with `437 Allocation Mismatch`.
  `tls_bridge` already did this; SCTP now mirrors it. (SCTP remains refused under
  `production = true`.)

- **`DONT-FRAGMENT` did nothing on an IPv6 relay socket.** `set_dont_fragment` set
  `IPPROTO_IP`/`IP_MTU_DISCOVER`, which does not set DF on an `AF_INET6` socket, so
  a v6 allocation with `DONT-FRAGMENT` would have fragmented silently. Now
  family-aware (`IPPROTO_IPV6`/`IPV6_MTU_DISCOVER`), with a test per family.

### Added

- **IPv6 relayed transport (RFC 6156), opt-in via `[turn] external_ip6`.** Empty
  (the default) keeps the previous behaviour: an explicit IPv6 Allocate is answered
  `440 Address Family not Supported`. Set, the relay socket binds in the family the
  client requested and the matching address is advertised in
  `XOR-RELAYED-ADDRESS`. One allocation serves one family: a cross-family peer is
  refused with **`443 Peer Address Family Mismatch`** on CreatePermission and
  ChannelBind, and dropped (counted) on a Send indication, which has no error
  response. Config validation rejects a v4 literal in `external_ip6`.
  Not implemented: `ADDITIONAL-ADDRESS-FAMILY`, IPv6 for RFC 6062 TCP relay (still
  `440` there), `IPV6_V6ONLY` on the relay socket. **No interop evidence yet.**

- **Per-source-IP handshake rate limit for TURNS** —
  `[tls].max_handshakes_per_sec_per_ip` / `handshake_burst_per_ip`,
  `turna_tls_rejected_rate_limit_total`. `max_connections_per_ip` bounds only
  *concurrent* connections, so a source that connects and drops in a loop never
  tripped it while still costing a TLS handshake each time. Refused before
  `tls.accept()`. Off by default, like the QUIC equivalent. The limiter moved from
  `quic.rs` to `crate::ratelimit` so a `--features tls` build can reach it.

- **ALPN strict mode for TURNS** — `[tls].alpn_required`,
  `turna_tls_alpn_rejected_total`. rustls already fails the handshake on a
  non-overlapping ALPN offer; the gap was the client that offers **none**.
  Default off (compatible). `alpn_required` without `enable_alpn` is a startup
  error, since nothing would be advertised and every client would be refused.

- **`[turn.quic]` transport limits now apply on the WebTransport path too**
  (stream counts, datagram buffer, idle timeout). This depends on
  `wtransport = { features = ["quinn"] }` in `crates/transport/Cargo.toml`, which is
  what exposes `ServerConfig::quic_config_mut()`; drop that feature and the build
  fails rather than silently reverting to a no-op. These keys previously looked
  effective and did nothing on H3. `alpn` remains inert there by
  design (wtransport forces `h3`).

- **`[turn.dtls].demux` — owned UDP demultiplexer for DTLS (opt-in, off by
  default).** `webrtc_dtls::listen()` runs handshakes serially inside `accept()`,
  which forces three compromises at once: admission control can only apply *after*
  the crypto, a handshake rate limit has nowhere to live, and the certificate is
  fixed at bind time. Owning the socket closes all three: one task per handshake,
  session/per-IP caps applied to the first datagram from an unknown address,
  `max_handshakes_per_sec_per_ip`, and `cert_reload_secs`. Handshake failures also
  become observable (`turna_dtls_handshake_failures_total`) because they fail in our
  own task rather than below `accept()`.
  The HelloVerifyRequest cookie exchange is unaffected (it lives in the server-side
  `DTLSConn`, not the listener), and established sessions still go through the
  shared session handler, so the record pump, MTU enforcement and idle reaper cannot
  drift between paths.
  **Off by default because it displaces the only DTLS path with recorded
  verification.** The checklist that would allow the default to flip is in
  `docs/verification/encrypted-transports.md`.

- **mTLS for TURNS clients** — `[tls].client_ca` and `[tls].require_client_cert`.
  Optional presentation (`require_client_cert = false`, the default with a CA set)
  verifies a client that offers a certificate and lets one without through TLS, to
  be judged by the normal long-term credential check — that is what allows an
  existing fleet to migrate without a flag day. `require_client_cert = true` with
  no CA is a startup error. The certificate reloader carries the CA, so a server
  certificate rotation cannot silently switch mTLS off.
  **No CRL/OCSP**, deliberately and consistently with the management plane
  (`docs/MTLS.md` → Revocation): revoke by rotating the CA. This is the TURNS data
  plane only; `[grpc] tls_ca` is unchanged.

- **`IPV6_V6ONLY` on v6 relay sockets.** Previously the v6 relay socket followed the
  kernel default, which on Linux is dual-stack — one relay port straddled both
  families and the "one allocation, one family" invariant held only because three
  downstream checks compensated (v4-mapped normalisation, no v4 permission on a v6
  allocation, the 443 mismatch check). Now explicit at the socket. Needs `socket2`
  in `turna-session` under `cfg(unix)`, because the option must be applied between
  `socket()` and `bind()`, which `std` cannot express.

- **`scripts/check-doc-claims.sh`** — CI gate tying load-bearing documentation
  claims to a grep over the code. It exists because a false doc claim hid the
  `ALTERNATE-SERVER` bug above: `docs/protocol-gap.md` asserted the fix had already
  been made. Eight checks, each verified to fail when the corresponding fact is
  broken. Wire it into `scripts/ci-checks.sh` after the `rustfmt` step, or call
  `scripts/ci-doc-truth.sh`.

- **Wired into CI** (`scripts/ci-checks.sh`, after the `rustfmt` step) and extended
  to ten checks. The ninth: every bypass-relevant v6 prefix the peer filter denies
  is mentioned in the docs — an incomplete deny list reads as permission. The tenth
  asserts *completeness* rather than a specific fact — every metric the health crate
  exports must appear in `docs/OBSERVABILITY.md`. That is the check that would have
  caught these eight new metrics shipping undocumented without a human noticing;
  it also surfaced 47 pre-existing undocumented series, now on an explicit
  allowlist in the script rather than skipped quietly.

- **`scripts/docker/af-xdp-check.Dockerfile`** — compile-check image for
  `--features af-xdp`, the one feature that cannot be checked on a dev mac
  (`build.rs` refuses to build off Linux) or in the plain `rust:1` image (no C
  toolchain for the vendored libxdp/libbpf).

- All eight new metrics are described in `docs/OBSERVABILITY.md`, including which
  ones read `0` for a structural reason: `turna_dtls_handshake_failures_total` is
  only meaningful with `demux = true`, because on the default path a handshake
  failure is not observable at all. That distinction was previously stated in
  `docs/OBSERVABILITY.md` as "this metric deliberately does not exist" — true then,
  false now, and corrected.

- New metrics: `turna_tls_rejected_rate_limit_total`,
  `turna_tls_alpn_rejected_total`, `turna_dtls_accept_timeouts_total`,
  `turna_dtls_handshake_failures_total`, `turna_dtls_inbound_dropped_total`,
  `turna_dtls_rejected_rate_limit_total`, `turna_dtls_cert_reloads_total`,
  `turna_dtls_cert_reload_failures_total`. Alert rules for each in
  `docs/alerts/transport-backends.yml`.

### Documentation — corrections, not polish

Three documented claims were false. They are called out here because an audit
register that drifts is worse than none:

- **RFC 5780 (NAT behaviour discovery) was documented as having a finished codec**, listing
  `ATTR_CHANGE_REQUEST`, `Attribute::ChangeRequest`, `ATTR_RESPONSE_ORIGIN`,
  `ATTR_OTHER_ADDRESS`, their getters and a test `tests/nat_discovery.rs`. **None of
  it exists.** Now recorded as not implemented. This stale entry is also what hid
  the `ALTERNATE-SERVER` bug.
- **Cross-node session migration was documented as "unverified".** It is
  **unwired**: `crates/relay/src/node_migration.rs` has no callers, so no allocation
  is ever transferred between nodes. What works is same-node mobility (RFC 8016
  tickets, ReKey, migration epoch) in `turna_transport::migration`. The module now
  says so in its own header, and the open decision (wire via control-plane gRPC with
  fencing, or delete) is recorded.
- **`af_xdp.rs` claimed "IPv4 only, IPv6 is a TODO"** in its frame layer. The v6
  frame stack (`build_eth_ipv6_udp`, `parse_eth_ipv6_udp`, ICMPv6 ND) is implemented;
  what remains IPv4-only is the ring datapath wiring.

### Verified in this pass

`docs/interop/conformance-2026-08-18.md` records two runs on a developer machine:

- **Address family and peer filter**, run twice (with and without
  `[turn] external_ip6`) because the two configurations must behave differently.
  All probes correct: `440` when unset, IPv6 relayed address when set, `443` in both
  directions, and `403` on NAT64 / 6to4 / Teredo / IPv4-compatible — the last group
  being the check that the v4 deny rules cannot be bypassed through a v6 literal.
- **TURN over raw QUIC**: handshake, `401`, authenticated Allocate with a relayed
  address, CreatePermission, clean close. The first interop evidence `[turn.quic]`
  has ever had, which moves raw QUIC from *experimental* to *beta*. WebTransport
  stays experimental — no client has exercised it.
- **TURNS across three browser engines** (`docs/interop/turns-browsers-2026-08-18.md`):
  Chrome 151, Firefox 153 and Safari 26.5 each completed a relay candidate, two
  negative-auth probes, bidirectional relayed data, and a relay-path confirmation —
  with `relayProtocol: tls` on the two engines that expose it. This replaces the
  earlier browser matrix, which predated the transport hardening and therefore did not
  cover shipping code. Server side: no connection or allocation leak, zero handshake or
  framing failures, and **both** credential-rejection paths exercised
  (`integrity_failed` and `invalid_credentials` each moved by 2).
- **Production gates**: all three refused features rejected at `production = true`
  with a message naming the key.

Neither run exercises relayed media, so IPv6 and QUIC both stay short of stable.

- **Endurance on Linux, both datapaths** (`docs/soak/endurance-2026-08-19.md`): 3 h
  each, 13.7 M and 58.5 M allocations, 441 M and 702 M packets, RSS flat to 0.2 %, no
  fd or thread growth, zero dropped packets, zero panics, clean drain on `SIGTERM`.
  io_uring came out ~4× faster on Allocate with an order of magnitude better tail
  latency, at ~28× the resident memory — the first real comparison of the two
  datapaths. ChannelData forwarding under load was **not** exercised (harness fault,
  recorded), which is why `io-uring` stays experimental.

- **Fixed: the io_uring datapath forwarded nothing.** `ForwardAction::ZeroCopyViaRelay`
  never re-armed the main recv slot — `msghdr_idx` was not even carried through the
  batch, so it could not — and each relayed packet consumed one slot permanently. A
  worker went deaf after exactly as many relayed packets as it had slots: 64. Control
  traffic was unaffected because it takes the `Send` path, which re-arms, so
  allocation ran at ~10 800/s while not one byte of media moved. The justifying
  comment described an earlier true-zero-copy send; the loop had since started copying
  the payload out, so there was nothing to wait for.
  Before: 0 of 960 448 frames relayed. After: 935 340 and 962 843 frames, zero errors,
  ~17 000 rps, p99 5 ms. This moves `io-uring` from experimental to beta.

- Three defects found by those runs rather than by tests: the rustls crypto provider
  was not pinned on the raw-QUIC path (fatal only when `tls` and `quic` are enabled
  together, which is why a mac build never saw it); a QUIC listener could die from a
  panic with no log line and no metric; and `turna_transport_readiness` was exported,
  documented and never set — on either datapath.

- **Relayed media verified for IPv6 and raw QUIC**
  (`docs/interop/relayed-media-2026-08-19.md`). `channel-data` gained `--family v6`,
  which allocates with `REQUESTED-ADDRESS-FAMILY = IPv6` and binds its peer on `[::1]`
  — 20 000 frames relayed with zero loss at p50 0.5 ms. `quic-check` gained a media
  stage: 20/20 ChannelData frames client→relay→peer, and the peer's reply returned as
  ChannelData on the same QUIC stream, which is the per-stream reply routing no
  control-plane check touches.

  Both existed only as control-plane checks before. That stopped being a technicality
  the same day, when io_uring was found answering 10 800 allocations per second while
  forwarding nothing: "the allocation succeeded" and "a byte moved" are different
  claims, and only the second is worth recording.

- **`turna-load-test` now speaks every transport the server does.** It was UDP-only,
  which is why so much of the verification plan read "needs a client" — TURNS, DTLS,
  RFC 6062 and WebTransport could not be exercised at all, and TURNS could not be
  soaked, which is what kept it at `beta`.

  Added: `tls-check` and `tls` (TURNS functionally and under load, the latter being
  what a TURNS soak needs), `dtls-check` (the first TURN allocation over DTLS),
  `tcp-relay-check [--pipelined]` (RFC 6062, with the pipelined form that exercises
  the server's detach prebuffer), and `wt-check` (the H3 path). Stream framing and
  the test certificate verifier moved into `stream_common` so the four stream
  transports cannot drift apart.

  Two limits stated in the code rather than left implicit: `wt-check` is not a
  browser substitute — client and server share `wtransport` and one reading of the
  spec, so a shared misreading stays invisible — and `dtls-check` must be run against
  both `[turn.dtls] demux` settings, since they accept handshakes differently.

- **Every transport verified functionally, in one run**
  (`docs/interop/transports-2026-08-19.md`, `scripts/verify/transports.sh`): 11 checks,
  all passing. Three transports had never carried a TURN allocation before, and
  WebTransport had never been touched by any client.

  Newly established: **RFC 6062** both plain and with the payload pipelined into the
  `ConnectionBind` write — the case the detach prebuffer exists for and had never
  exercised; **DTLS** allocation and relayed media on *both* listener paths, the first
  allocation ever completed over that transport; **WebTransport** session through to
  relayed media; and **TURNS under load**, which was impossible while the load tool
  spoke UDP only.

  Four faults surfaced, all in the new clients rather than the server. The most
  instructive: relayed media returns as a QUIC/WebTransport **datagram**, not on the
  control stream — correct, since media is unreliable and a reliable stream would add
  retransmission and head-of-line blocking. A client reading only the stream sees the
  allocation work and the media vanish.

- **Fixed: the AF_XDP datapath leaked its receive frames.** `recv_batch` took the
  descriptor buffer for `poll_and_consume` out of `free_frames` (the TX pool).
  `poll_and_consume` overwrites the first `n` entries with descriptors pointing at the
  frames the kernel filled from the fill ring, so those were returned correctly while
  the `n` frames drained from the pool had their addresses destroyed and went nowhere.
  Reception stopped for good after exactly pool-size frames — `rx_frames_total` came
  out as **exactly 2015 in three runs at different rates**, which congestion cannot
  produce. A second leak sat in the same lines: `fill.produce()` returns how many
  descriptors it placed, and the result was discarded.

  Fixed with a dedicated `rx_scratch` buffer, the pattern already used for
  `comp_scratch` a few lines above, plus a `fill_ring_full` counter so a saturated ring
  is visible. Before: 2015 frames, 43–66 % loss. After: 7123 frames, **0.0 % loss at
  three rates** (`docs/interop/af-xdp-2026-08-19.md`). This moves `af-xdp` to beta.

  This is the second leak of exactly this shape in one day — the io_uring datapath went
  deaf after precisely 64 relayed packets for the same class of reason. Both were
  invisible to every existing check and both showed up as a hard stop at a pool or slot
  count. Worth remembering as a pattern rather than two incidents.

- Two AF_XDP configuration traps recorded rather than fixed
  (`docs/roadmap/af-xdp-phase2.md`): `frame_count` above twice the ring size kills RX
  silently, because the rings stay pinned at the library default while `frame_count` is
  honoured; and `zero_copy` drives both the XSK bind flag and the XDP attach mode, which
  are orthogonal — so a native attach cannot be requested without also requesting
  zero-copy. Also: `fill_ring_size`, `comp_ring_size`, `rx_ring_size` and
  `tx_ring_size` are accepted and ignored.

- `turna_afxdp_umem_free_frames` documented as counting the **TX** pool. It read a
  healthy 2016 throughout the leak above, because it never watched RX.

- **WebTransport has browser interop**
  (`docs/interop/webtransport-browser-2026-08-20.md`). Chrome 151 against a Let's
  Encrypt certificate: session, control stream, 401, authenticated Allocate,
  CreatePermission, ChannelBind, and relayed media returned as a datagram.

  It counts where the Rust `wt-check` did not, and the reason is worth stating: that
  client shares `wtransport` and one reading of the spec with the server, so a shared
  misreading is invisible to it. The browser probe shares neither — the HTTP/3 stack is
  Chrome's, and every STUN byte, the MD5 credential key and the MESSAGE-INTEGRITY HMAC
  are assembled in page JavaScript. `MESSAGE-INTEGRITY accepted` therefore means the
  server agreed with an encoder it has nothing in common with.

- **TURNS is supported.** 24 h under load on a public deployment with its real Let's
  Encrypt certificate (`docs/soak/endurance-24h-2026-08-22.md`): 9.6 h of relayed media
  at **zero loss** across 16 cycles, 4.8 h of allocation churn at 441/s, and no leak on
  RSS, descriptors, threads or allocations. Together with the three-browser interop and
  a chain validated by a verifying client, that closes every condition.

  The same run puts `io-uring` on record for kernel **6.8** as well as 6.14: 9.6 h of
  relayed media at 0.006 % loss, descriptors flat.

- **Fixed: the load client could not sustain a session past ten minutes.** TURN
  bindings expire — allocation and channel at 600 s, permission at 300 s — and nothing
  refreshed them. Past the deadline the server correctly dropped ChannelData for a
  binding that no longer existed, and silently, because there is no error to send to a
  client talking to a closed channel.

  It cost two 24 h runs to find, because it presents as a capacity cliff: 67 % loss on
  every transport at every rate, while rehearsals with phases under 600 s passed
  perfectly clean. What settled it was arithmetic — delivery matched `600/duration` to
  within 2 % on two unrelated transports. Both clients now refresh every 240 s, and the
  analyser recognises the signature rather than suggesting a rate comparison.

  **This reaches backwards:** any long `channel-data` phase run before the fix was
  measuring a decaying session, so throughput figures from the earlier three-hour soaks
  should not be quoted. Their leak findings stand.

- **Load drivers for WebTransport, QUIC and DTLS**, and 20 minutes each at zero loss
  (`docs/soak/transport-load-2026-08-23.md`). All three had correctness and no
  endurance because nothing could drive them. Each phase runs 1200 s deliberately:
  bindings expire at 600 s, so a driver that failed to refresh would show exactly 50 %
  loss, and a zero is evidence the refresh works rather than merely that traffic flowed.

- **IPv6 relaying verified on routable addresses** — 6 010 of 6 010 frames between two
  global v6 addresses with the peer filter in its `lan` profile and no loopback
  concession (`docs/interop/relayed-media-2026-08-19.md`). Earlier runs used `::1` and a
  ULA on a down bridge.

- **Fixed: the load client's control socket was always bound in the v4 family.** Against
  a v6 server it could not send at all, so `allocate` failed with no response to report
  and the run showed setup errors while the server logged nothing — nothing reached it.
  The family now follows the server address. The DTLS client had the identical bug.

- **Interop against coturn's client** (`docs/interop/coturn-2026-08-23.md`): 5 of 5
  paths — UDP, TURNS, **DTLS**, the IPv6 relay and RFC 6062 — verified by
  `turnutils_uclient`, which is not our code.

  For DTLS this was the missing condition: correctness and endurance were already
  recorded, but every client that had exercised it was written here. It now has an
  independent implementation agreeing about the wire.

  For UDP, TURNS, IPv6 and RFC 6062 it replaces self-testing with interop. RFC 6062
  especially: its pipelined-bytes case had only ever been exercised by the client
  written to exercise it.

  QUIC is now the only transport with no independent implementation, and structurally
  so — no RFC defines TURN over raw QUIC, so there is nothing for anyone to implement
  against.

### Not verified in this pass

Everything below compiles and passes unit tests; none of it has interop or soak
evidence, and two of the fixes change observable behaviour:

- The `ALTERNATE-SERVER` fix (redirect and drain paths) — needs a real client.
- The DTLS accept bound — needs the regression test in
  `docs/verification/encrypted-transports.md` ("start a handshake and go silent;
  a second normal client must still connect").
- IPv6 relaying end to end, including the peer-filter bypass checks
  (NAT64/6to4/Teredo/IPv4-compatible must all answer `403`).
- The DTLS demux path in full.
- Production gates on RFC 6062 TCP relay, SCTP and OAuth remain in place; lifting
  them is gated on interop, not on code.


## [0.3.0] - 2026-07-14

Production GA — all production blockers flagged in the `0.3.0-rc.2` external
audit are closed; the management subsystem is code-verified (full Rust workspace
suite with `--all-features`, plus the Tarantool stored-procedure TAP suites).
Optional high-performance / alternative-transport datapaths and multi-node
cluster mode remain feature-gated and **experimental**.

### GA Highlights
- Runtime config management: versioned updates, immutable snapshot, CAS, rollback.
- User limits: global / tenant / user scopes, inheritance, reservations, exact replay.
- Durable command log v2 with idempotency and lost-completion recovery.
- Three-phase resumable migration: page-CAS, monotonic fencing generation, canonical hash.
- Exact-u64 versioning (runtime, user-limits, fencing token); overflow refused.
- Atomic observed confirmation (journal write + observed bump in one `box.atomic`).
- Management / persistence / cluster profile separation; failover gated on `cluster_mode`.
- Admin control-plane API and Admin UI.


### Added
- End-to-end node-targeted `update_config` with optional proto presence,
  expected-version conflict detection, typed deterministic command payloads,
  one-shot immutable snapshot publication, no-op semantics, rollback reporting,
  and responses decoded from the target node's terminal result.
- End-to-end `set_user_limits` for global, tenant, and realm/tenant/user scopes,
  including independent inherit/value/unlimited/disabled modes, effective-limit
  reporting, lower-than-current-usage behavior, and restart restore.
- Durable desired/observed runtime and limits state for memory and Tarantool
  backends, process-incarnation fencing, startup adoption/restore before
  readiness, and a bounded, resumable, leased three-phase command-log migration
  (`commands` → `idempotency` → `complete`) that recomputes legacy payload
  hashes with the canonical Rust hash and terminally closes orphaned idempotency
  rows. The idempotency phase is a fetch/apply pair guarded by a monotonic lease
  fencing generation: apply commits under a full compare-and-swap (version,
  phase, cursor, owner, token, unexpired lease) in a single `box.atomic`
  transaction, so a stale page cannot land, partial-terminal rows are enriched
  by consulting the linked command's status, and a GC'd-then-reused idempotency
  key is never clobbered.
- Concurrency-safe user/tenant/global allocation reservations with rollback and
  local immutable limit lookup on allocation, refresh, and packet paths.
- Node-scoped admin forms, desired/observed status, version conflict handling,
  retry-stable idempotency keys, session-only admin token storage, and admin
  container smoke coverage.
- Socket-level gossip drain/leaving/rejoin integration coverage.

### Changed
- Runtime quota APIs consistently use `max_bytes_per_sec_per_allocation`; telemetry fields that
  measure traffic remain explicitly named `bandwidth_bps` (bits/second).
- The canonical Helm production example is standalone-first: one TURN pod per
  public IP/relay range, Tokio transport, finite resources/bandwidth, and a
  separately managed Tarantool backend for durable management state.
- The Helm multi-node StatefulSet is explicitly experimental and no longer
  presented as the canonical GA topology.
- `UserLimitScope` numbering changed: `UNSPECIFIED = 0` (required-but-unset
  guard), `GLOBAL = 1`, `TENANT = 2`, `USER = 3`. Numeric `0` is no longer
  `GLOBAL`; an unset scope is rejected instead of silently treated as global.
- `SetUserLimits` usage fields renamed for unambiguous meaning:
  `current_usage` → `max_user_allocations_in_scope`,
  `usage_above_limit` → `max_user_allocations_above_limit` (highest single-user
  allocation count in the scope, not an aggregate total).
- Command `done` now denotes completed transport processing, not necessarily
  `applied`; the business outcome (`applied` / `no_op` / `conflict` / `failed` /
  `superseded`) is carried in the typed result.
- Management-plane persistence (command-log, runtime config, limits state) is
  decoupled from allocation write-behind: the management backend is enabled
  whenever a durable (Tarantool) backend is configured, independent of whether
  allocation write-behind persistence is on.
- Durable operation outcomes are persisted at the observed-version confirmation
  — atomically with the observed bump and before command completion — keyed by
  idempotency key, so a lost completion still recovers the original result even
  after a later operation overwrites the single most-recent-applied slot; every
  later journal write (completion, dead-letter, stale finalize) is guarded so a
  terminal outcome is never downgraded. Non-mutating terminal outcomes (`no_op`,
  version `conflict`, validation `failed`) are recorded into the same journal via
  `record_command_outcome` before completion under the identical contract, and
  the handler consults the journal before re-validating, so a replay after the
  state has changed returns the original outcome rather than re-deriving a
  different one.
- Runtime and user-limits versions are exact unsigned 64-bit throughout the
  Tarantool path: a single parser normalizes string/number/cdata to a u64,
  comparisons and CAS never route a version through a float (exact above 2^53),
  and an increment at `u64::MAX` is refused with an error rather than wrapping.
- Management-plane readiness is surfaced on a distinct `turna_management_readiness`
  gauge that reaches `ready` only after the mandatory migration phases complete;
  the TURN dataplane readiness is independent. Allocation rehydrate and the
  write-behind writer run only under an allocation-persistence profile, and
  ownership adoption/failover only under the cluster profile.
- Drain publishes `leaving` at the start of drain.
- The local user-limits cache carries a monotonic generation independent of the
  durable subject version; a no-op publish neither stores nor advances it.

### Fixed
- Proto/field drift between the wire contract and the Rust/TypeScript surfaces.
- Optimistic-concurrency (expected-version) drift on runtime-config updates.
- Helm allocation-cap value that could exceed the usable relay-port range.
- Post-GC idempotency replay: a retry after the command row was collected now
  resolves from the retained idempotency record instead of polling to timeout.
- Lost-completion recovery: an applied operation whose completion was lost is
  recovered from durable operation metadata and returns its original outcome
  without re-applying the side effect.
- Stale-incarnation command recovery: commands targeting a dead incarnation are
  finalized as `superseded` and no longer accumulate as non-terminal rows.
- Legacy idempotency migration for pre-existing Tarantool command rows.
- Per-user allocation reservation race under concurrent Allocate.
- Mixed runtime snapshot: readers now observe one atomic versioned snapshot.
- Unsafe global default scope (`GLOBAL = 0`) removed.
- Front-end/back-end field-name mismatch on the admin surface.
- User-limits cache generation overflow now returns an explicit error instead of
  panicking, leaving the current snapshot unpublished.

### Compatibility
- Protobuf field numbers are preserved; retired pre-GA fields are marked
  `reserved` (numbers and names) rather than reused.
- Source/JSON rename of the bandwidth quota field to
  `max_bytes_per_sec_per_allocation`. Durable command/state JSON written with the
  old `max_bytes_per_sec` key is still read (deserialization alias); telemetry
  `bandwidth_bps` (bits/second) is unchanged.
- `UserLimitScope` enum numeric change (`UNSPECIFIED = 0`); clients relying on
  `GLOBAL = 0` must update.
- Old Tarantool schema requires the bounded/resumable migration
  (commands → idempotency → complete). See `RELEASE.md`.
- Management API semantics: accepted is not applied; callers must inspect the
  terminal business outcome, not only the gRPC status.
- New mandatory mutation fields: `node_id`, `idempotency_key`,
  `expected_version` (where applicable), and `reason`. Older clients may require
  updates.

### Known limitations
- No transparent active-session failover; an existing media path does not
  migrate to another node.
- No general multi-replica shared-IP Helm topology; standalone-first is the
  canonical GA profile.
- Experimental transport backends (AF_XDP; io_uring/QUIC/DTLS per their stated
  scope).
- Admin token model: session-only bearer token; not a full RBAC/identity system.
- Bandwidth enforcement is per-allocation (independent budget per allocation),
  not an aggregate per-user limiter.
- Limits atomicity is guaranteed within the limits domain, not necessarily
  jointly with the runtime-config domain.

### Verification boundary
- These entries describe source changes only. Build, tests, Tarantool runtime,
  frontend, Docker, Helm, migration upgrades, and live TURN scenarios must be
  run on the exact release commit before assigning GA status.

## [0.3.0-rc.2] - 2026-07-12
Second release candidate on top of `0.3.0-rc.1`. Lands the admin control-plane
stage 2 (gRPC mutations) and DTLS fail-closed hardening, and records the
verification finished since rc.1 (multi-day endurance, mobile/multi-OS interop).
NOT GA: an external code audit flagged production blockers that are still open —
notably the control-plane's management model (mutations must be proven to reach
a live node, not a control-plane-local store), the gRPC TLS env-override /
`tls` vs `mtls` gap, Helm/K8s production topology, unknown-backend fallback,
task supervision, and Tarantool operation timeouts. See docs/verification/
pre-GA-status.md and the audit follow-up before promoting to a stable release.

Verification completed (see `docs/`):
- Endurance: a continuous relay run of more than 5 full days (uptime 434,908 s,
  ~130M packets, 21.4 GB) with flat memory (RSS below start), stable fds, and
  zero error counters across the soak window — no leak at a multi-day horizon
  (`docs/soak/endurance-v0.3.0-rc.1.md`), extending the 12-hour soak.
- Browser interop broadened to mobile and multi-OS: iPhone (Safari/Chrome),
  Android (Chrome/Firefox), iPad, Windows, Linux, macOS — each 5/5 over TURNS
  (TCP/TLS) from the external network, including mobile 4G/5G
  (`docs/interop/v0.3.0-rc.1.md`).
- DTLS: transport + DTLS 1.2 handshake + allocate confirmed against a live node
  with `turnutils_uclient` and `openssl s_client -dtls` (`docs/dtls/`).
- A consolidated pre-GA verification map, honest about what is and is not
  covered (`docs/verification/pre-GA-status.md`).

### Added
- Admin console stage 2: mutating operations via a gRPC bridge to the
  control-plane (`SetDraining`, `DeleteAllocation`, `AddUser`/`RemoveUser`,
  plus reads). Operator mutations are gated by an `X-Admin-Token`; the
  HTTP-to-node mutation path was removed in favour of gRPC only. Verified live
  end-to-end (drain/undrain/stats/auth) (`docs/admin/`).
  - `SetUserLimits` and `UpdateConfig` are defined in the proto/surface but
    still return `Unimplemented` — the live runtime-config snapshot (S4) and
    limit enforcement (S5) that back them are in progress. They are NOT part of
    the working mutation surface yet and must not be advertised as such.

### Security
- Admin fail-closed hardening: a plaintext (`http://`) non-loopback gRPC address
  is refused, and — symmetrically — a non-loopback `--listen` with no
  `--auth-token` is refused, so an exposed console cannot serve unauthenticated
  mutations. The config checks run before any network dial.
- DTLS transport now fails closed when a configured operator certificate cannot
  be loaded, instead of silently falling back to an ephemeral self-signed cert
  (`crates/transport/src/dtls.rs`).

## [0.3.0-rc.1] - 2026-07-06

Release-candidate hardening on top of `0.3.0-beta.1`: interop, cluster
failover, and deploy-artifact fixes surfaced by live verification on Linux
(fuzz, coturn interop, soak, multi-node failover drill, Helm/Docker).

Verification highlights (see `docs/`): a 12-hour relay soak with no memory/fd
leak (518M packets, 0 panics, 0 drops, P99 500 us — `docs/soak/`); a live
multi-node failover drill that found and fixed the list-truncation P1
(`docs/failover/`); and real-browser WebRTC interop over TURNS with a trusted
Let's Encrypt cert — allocate, auth-negative (401), end-to-end relay data
transfer, and the RAF fix all confirmed with Chrome (`docs/interop/`).

### Fixed
- REQUESTED-ADDRESS-FAMILY (0x0017): the Allocate flow now parses this base
  RFC 8656 attribute. An explicit IPv4 request is honoured; an IPv6 request is
  refused with `440 Address Family not Supported`. Previously the strict
  unknown-attribute handling answered `420` to any client sending it
  (e.g. `turnutils_uclient -X`, dual-stack browsers), breaking allocation.
- Cluster failover on the Tarantool backend: list-returning stored functions
  used `return unpack(res)`, a flat multiple-return that the iproto CALL parser
  truncated to a single row. This silently broke `find_by_node`,
  `get_live_nodes`, `list_allocations`, and the other list reads, so the
  failover sweep saw at most one node/orphan and adoption never completed in a
  real cluster. Fixed to `return res`; a live drill now shows a killed owner's
  allocations claimed by the survivor (`failover_claimed_total` increments,
  owner reassigned in the backend, no split-brain).
- `TURNA_WORKERS=0` no longer panics on startup. Zero (the Helm chart's default
  meaning "auto") now maps to CPU-count autodetection, matching unset/invalid.
- Config parse tests isolate the `TURNA_PRODUCTION` env var so a concurrent
  production-validation test can't leak into an unrelated parse test.
- `/metrics` output: several counters were emitted with leading indentation
  that broke Prometheus parsing; all counter lines are now flush-left.
- Strict STUN parser: enforce 4-byte body alignment up front and treat a
  declared length past the packet as `BufferTooShort`; padding value is ignored
  per RFC (non-zero padding tolerated).

### Changed
- Malformed REQUESTED-ADDRESS-FAMILY (bad length or unknown family) is dropped
  silently with `parser_rejections` incremented, like any malformed STUN
  attribute — intentional anti-amplification, not a `400` response.

### Migration
- The Tarantool stored-function fix changes `deploy/tarantool/init.lua`. Because
  functions are created with `if_not_exists = true`, an existing Tarantool
  instance will NOT pick up the new bodies on restart: drop and recreate the
  affected functions (or reload the schema) when upgrading a live cluster.
  Fresh installs are unaffected.

## [0.3.0-beta.1]

Production-hardening of the core UDP/IPv4 TURN path. No new features; this
release closes the concurrency, resource-bound, protocol-strictness and
fail-closed-config gaps that kept `0.2.0-alpha.1` at alpha. See
[docs/COMPLIANCE.md](docs/COMPLIANCE.md) for the supported/not-supported scope.

### Fixed
- Atomic allocation create: a lost create race now returns `437 Allocation
  Mismatch` instead of silently overwriting an existing allocation.
- Global and per-tenant allocation quotas enforced with atomic reserve/rollback
  accounting (no quota race); per-user tracking is tenant-scoped.
- EVEN-PORT reservations released immediately on create failure instead of
  leaking until the sweep.

### Security
- Bounded per-allocation resources: 256 permissions, 256 channels, 32 peers per
  CreatePermission.
- Bandwidth quota enforced on all relay paths (channel data, Send-indication
  egress, peer -> client), not only ChannelData.
- Bounded internal QUIC/AF_XDP outbound and neighbour queues (experimental).
- Fail-closed production config: placeholder/empty shared or cluster secrets,
  unlimited bandwidth without explicit opt-in, and non-loopback plaintext
  management binds are refused at startup.

### Changed
- Strict STUN/TURN parsing: exact attribute lengths; MESSAGE-INTEGRITY /
  MESSAGE-INTEGRITY-SHA256 strictness; `420 UNKNOWN-ATTRIBUTES` for unknown
  comprehension-required attributes (symmetric encode/parse); reserved/unknown
  message types rejected.
- Runtime user revocation now propagates to live nodes via the backend refresh
  loop (config static users are never affected).
- Readiness degrades to `503` when backend writes are dropped, and recovers.

### CI
- New `msrv` job builds + tests on the pinned 1.95.0 toolchain (`--locked`) on
  every PR/push.
- The remaining tag-pinned action (`ossf/scorecard-action`) pinned by commit SHA.

## [0.2.0-alpha.1] - 2026-06-15

First public pre-release. Builds on the internal `v0.1.0` tag with multi-node
clustering, multi-tenant auth, and the QUIC/DTLS/AF_XDP transport foundation.
The default tokio UDP datapath is the supported path; the alternative transports
are experimental — see [README](README.md#status) and
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md).

### Added
- **Multi-node clustering (`turna-cluster`).** Gossip-based discovery, a hash
  ring, and TURN-redirect load balancing. Cluster config covers the gossip
  bind/seeds, announce address, shared HMAC secret, and drain grace; heartbeat
  and failure-detection settings control failover timing. Redirect-mode settings
  are validated against the TURN external address, and cluster redirect /
  live-node counts are exported as metrics.
- **Multi-tenant authentication.** `AuthRegistry`-based realm resolution with
  per-tenant results, multi-tenant config validation (unique ids, realms, and
  disjoint relay port ranges), tenant-isolated relay port pools with per-tenant
  limits, and per-tenant allocation counters in Prometheus.
- **QUIC, DTLS and WebTransport transports** with their listeners, plus relay
  node migration, relay routing primitives, and transport-layer certificate
  management. All are behind Cargo features and experimental.
- **AF_XDP transport backend — selective XDP filter.** Embedded XDP program
  attached to the configured interface that redirects only UDP datagrams whose
  destination port is in the BPF `ports` map into the AF_XDP socket
  (`xsks_map`); everything else is passed to the kernel (`XDP_PASS`). Attach
  mode follows `zero_copy` (SKB/copy vs native). Relay ports are registered into
  the map dynamically as allocations are created.
- **AF_XDP neighbour resolution.** Per-destination next-hop MAC resolution via
  ARP/NDP with a TTL cache, active resolution kick on cache miss, serve-stale
  while refreshing, and TTL-based eviction. New metric
  `turna_afxdp_neighbor_cache_entries`.
- **TURN-over-TLS (TURNS) listener** configuration defaults.
- **`MESSAGE-INTEGRITY-SHA256` support (RFC 8489)**, preserving the legacy
  `MESSAGE-INTEGRITY` path for long-term-credential compatibility.
- **`turnactl failover status`** subcommand exposing `claimed_total`,
  `lost_race_total`, `errors_total`, `last_sweep_us`, and draining counters.

### Changed
- **gRPC stack upgraded to tonic 0.14 / prost 0.14** (`turna-control`).
  Build-time codegen moved to `tonic-prost-build`; runtime uses `tonic-prost`.
  TLS feature switched from `tls` to `tls-ring`.
- **OpenTelemetry stack upgraded to 0.32** (`turna-observability`):
  `opentelemetry` / `opentelemetry_sdk` / `opentelemetry-otlp` (grpc-tonic) to
  `0.32`, and `tracing-opentelemetry` to `0.33`. This moves OTLP export onto
  `tonic 0.14` / `prost 0.14` / `http 1` / `hyper 1`, eliminating the duplicate
  `tonic 0.11` / `http 0.2` / `hyper 0.14` generation that the old
  `opentelemetry-otlp 0.16` had pulled in.
- **Relay wiring switched from `AuthMode` to `AuthRegistry`** across the relay
  processor, server, and node.
- **STUN encode APIs are now fallible.** `encode`, `encode_with_integrity`, and
  `encode_channel_data` return `Result`; callers propagate `BufferTooSmall`
  instead of panicking on an undersized output buffer.
- **io_uring worker count is configurable** via `TURNA_IOURING_WORKERS`.

### Fixed
- **io_uring graceful shutdown.** On `SIGTERM`, workers now wait for all relays
  to be reclaimed *and* all in-flight send slots to complete (bounded by the
  drain grace window) before tearing down, so in-flight sends are no longer
  dropped during lame-duck shutdown.
- **io_uring send-slot handling.** Send-slot accounting/reuse so submitted sends
  are tracked to completion (including cancellations) rather than leaked.
- **io_uring relay lifecycle.** `CloseRelay` actions are mapped into a
  `ForwardAction` instead of being dropped; in-flight ops are cancelled with
  `AsyncCancel2` before reclaiming closing relays; recv slots are re-armed on
  transient recv errors to avoid slot starvation.
- **`pin_to_core` bounds check.** Worker core pinning now validates the core id
  against the `cpu_set_t` capacity and runs unpinned (with a warning) instead of
  risking undefined behaviour when the id is out of range.
- **AF_XDP build.** `build.rs` resolves the architecture UAPI include path
  (`asm/types.h`) so the embedded XDP program compiles with `clang -target bpf`.
- Assorted Clippy lints; the workspace builds clean under `clippy --workspace -D warnings`.
- Audited `#[allow(dead_code)]`: removed stale annotations and two dead helper functions, kept and documented the genuinely-reserved ones.

### Security
- **`rustls-pemfile` (unmaintained, RUSTSEC-2025-0134) removed from the default
  build.** PEM parsing in `turna-transport` (the `tls` and `quic` features) was
  migrated to `rustls-pki-types`, so `rustls-pemfile` is no longer a direct
  dependency. The only remaining occurrence is transitive, via `wtransport`
  under the experimental `web-transport` feature (`wtransport 0.6.1`, the
  latest release, still depends on it), and is absent from default/production
  builds. `cargo deny check advisories` is clean — the advisory is not
  surfaced because the default graph does not enable `web-transport` — so no
  `deny.toml` ignore is carried. Tracked as RISK-001 in
  `docs/security/accepted-risks.md`.
- **Hardened HS256 JWT secrets.** A minimum secret length (>= 32 bytes) is
  enforced at both the sign and verify boundaries, and placeholder secrets are
  rejected at startup.
- **Stricter STUN auth.** Requests carrying an unknown or inconsistent
  `PASSWORD-ALGORITHM` declaration are rejected as `400 Bad Request`.

### Dependency hygiene (cargo-deny)
- `turna-benchmark` marked `publish = false` so license checks skip it.
- Trimmed unused entries from the license `allow` list.
- Removed the `bans.skip-tree` for `opentelemetry-otlp`: upgrading the
  OpenTelemetry stack to 0.32 (tonic 0.14 / http 1 / hyper 1) eliminated the
  older `tonic 0.11` generation it had pulled in, so the skip-tree is no longer
  needed. `skip` entries for the `getrandom` / `hashbrown` multi-version
  transitives remain. The full picture is tracked in
  `docs/security/dependency-dedup.md`.

[Unreleased]: https://github.com/kruatech/turna/compare/v0.3.0...HEAD
[0.3.1]: https://github.com/kruatech/turna/compare/v0.3.1-rc.2...v0.3.1
[0.3.0]: https://github.com/kruatech/turna/compare/v0.3.0-rc.2...v0.3.0
[0.3.0-rc.2]: https://github.com/kruatech/turna/compare/v0.3.0-rc.1...v0.3.0-rc.2
[0.3.0-rc.1]: https://github.com/kruatech/turna/compare/v0.3.0-beta.1...v0.3.0-rc.1
[0.3.0-beta.1]: https://github.com/kruatech/turna/compare/v0.2.0-alpha.1...v0.3.0-beta.1
[0.2.0-alpha.1]: https://github.com/kruatech/turna/compare/v0.1.0...v0.2.0-alpha.1
