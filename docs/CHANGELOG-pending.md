# CHANGELOG — pending section

Ready to paste into `CHANGELOG.md` under a new version heading. Kept in a separate
file because the real `CHANGELOG.md` was not part of this pass and merging it blind
would risk clobbering entries.

Ordering follows severity for an operator reading it during an upgrade, not the
order the work happened in.

---

## Unreleased

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
