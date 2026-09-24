# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Tooling: the workspace declares `rust-version = "1.95"` (the toolchain the
  `msrv` job builds and tests on) and every member inherits it. CI now runs
  `scripts/check-doc-claims.sh`, which existed and passed but was run by no
  workflow, and lints the admin frontend with ESLint (`npm run lint`). Dependabot
  covers the frontend's npm dependencies. A `Makefile` wraps the CI checks for
  local use; `.editorconfig` added.
- `deploy/Dockerfile.admin`: Node 24 (LTS) instead of Node 25, which reached end
  of life on 2026-06-01, and the same pinned `rust:1.95.0` image as
  `deploy/Dockerfile` instead of `rust:1.98.0`. The CI `frontend` job uses Node 24
  to match.

- Document AF_XDP as **supported within the verified Linux IPv4 UDP copy-mode scope**
  (SKB/native, Linux 6.8.0-87, `virtio_net`, two RX queues). Record four-hour
  native WAN media and 15-minute churn, resource cleanup and XDP detach. Keep
  zero-copy unverified and earlier control timeouts unresolved; no root-cause
  fix is claimed. Reconcile loader, queue, geometry and metric documentation.
  See `docs/verification/af-xdp-supported-2026-09-22.md`.

- Promote the io_uring UDP datapath to **supported on Linux**, opt-in, with
  tested kernels 6.8.0-87 and 6.14.0-33. Record receive/cancel recovery tests,
  functional acceptance and shutdown, 30-minute media, four-hour authenticated
  churn on cloud and short second-kernel churn. Document worker-dependent memory,
  configuration limits and the earlier failed fresh-socket churn separately.
  See `docs/verification/io-uring-supported-2026-09-19.md`.

- Promote QUIC and WebTransport to supported within the Linux/macOS tokio
  scope. Reconcile configuration, operations and support documentation with the
  implemented limits, routing, cleanup and recorded verification. Keep WAN loss,
  project-specific mappings and unverified multi-day endurance explicit; see
  `docs/verification/quic-webtransport-supported-2026-09-18.md`.

- Promote native TURN-over-SCTP to **supported on Linux/tokio**, opt-in. Lift the
  production refusal while retaining platform/feature/framing validation; reject
  backend selections that do not start the SCTP listener. The channel remains
  plaintext and the peer-side relay UDP. Record native functional, lifecycle/limits
  and 30-minute WAN evidence in `docs/verification/sctp-supported-2026-09-18.md`.
  No QUIC/WebTransport status change or multi-day endurance claim.

### Security

- **`services/admin`: the read-only API routes required no token.**
  `/api/status`, `/api/metrics`, `/api/health`, `/api/ready` and `/api/cluster`
  returned the node's full Prometheus surface, its readiness and the cluster
  topology to anyone who could reach the port. Only `/api/manage` checked.

  The startup guard reasoned about "unauthenticated mutations" and was correct
  about mutations, which is how this survived: the read side was never the thing
  being checked. Every `/api` route now authenticates.

- **`services/admin`: the token was compared with `==`.** String equality
  returns as soon as two bytes differ, so rejection time was proportional to how
  many leading characters were right — recoverable one character at a time over
  enough requests, on an endpoint reachable by anyone who can route to it.
  Constant-time comparison now.

- **`services/admin`: nothing slowed down token guessing.** A wrong answer cost
  the sender nothing, so an attacker had an unlimited guessing rate against a
  static string. Failed authentications are now delayed with exponential backoff
  (capped at two seconds); success is never delayed and resets the counter.

  A delay rather than a lockout on purpose: locking out after N failures hands
  anyone who can reach the port the ability to lock the operator out of their own
  admin surface, trading a brute-force risk for a denial-of-service certainty.

- **`services/admin`: a non-loopback bind now warns that the wire is plain
  HTTP.** The token protects the surface, not the transport — on a non-loopback
  bind it travels in a header in the clear on every request, as do the metrics
  and topology in the replies. A warning and not a refusal, because the common
  shape is a TLS terminator in front; what must not happen is an operator
  concluding that `--auth-token` made the exposure safe.

### Added

- Helm: `metrics.serviceMonitor` now renders a Prometheus Operator
  `ServiceMonitor` (it was declared in `values.yaml` and set by the production
  example, but no template used it). It is created only when the cluster serves
  `monitoring.coreos.com/v1`, selects the internal service via the new
  `app.kubernetes.io/component: internal` label and scrapes `/metrics` on the
  health port. The chart also gains `NOTES.txt`: service names, a readiness
  check, the chart's UDP-only scope, and a warning when a ServiceMonitor was
  requested but the operator API is absent.

- **Stateless address validation on the DTLS demux path (RFC 6347 §4.2.1).** A
  ClientHello without a cookie this node issued is now answered with a
  HelloVerifyRequest and **nothing is allocated** — the cookie is
  `HMAC-SHA256(key, client_addr ‖ time_bucket)`, derived rather than stored, so
  a million spoofed hellos cost a million HMACs and zero bytes of retained
  state. Binding to the address is what makes it worth issuing: a cookie
  harvested by a real client is useless from anywhere else.

  `max_pending_handshakes`, added earlier in this release, bounded how much a
  flood could allocate but did not stop the allocation happening before the
  sender was known to exist. It stays as the backstop. New counter:
  `turna_dtls_cookie_challenges_total`, which should track new DTLS sessions
  one-for-one.

  The parser reads five fields and refuses a fragmented ClientHello rather than
  reassembling one: reassembly means holding state for an unvalidated address,
  which is the thing being avoided. Anything malformed is dropped in silence,
  because replying would make this an amplifier for whatever was sent.

  A validated ClientHello is handed to the DTLS connection as it arrived, and
  the handshake resumes at the sequence the client is actually on. This needed
  the DTLS stack to move into the tree as `crates/dtls`: the upstream crate runs
  its own cookie exchange, cannot be told the address is already proved, and has
  no equivalent of GnuTLS's `gnutls_dtls_prestate_set` for resuming a handshake
  mid-flight.

  Three counters are seeded to 1 on a server resuming after an external
  HelloVerifyRequest, which consumed sequence 0 (RFC 6347 §4.2.4): the fragment
  buffer, so the `message_seq = 1` ClientHello is yielded rather than held
  forever at an index nobody reads; `handshake_recv_sequence`, so the flight
  finds it in the cache; and `handshake_send_sequence`, so the ServerHello
  leaves at sequence 1 — without which the client rejects the handshake at
  Finished, since the message sequence is part of the transcript hash (§4.2.6).

  One cookie exchange, one round trip. Verified against OpenSSL `s_client` with
  a real certificate chain — one handshake, one client, on loopback.

  **The DTLS interop and soak evidence recorded before this release describes
  the old stack and does not carry over.** `docs/feature-support.md` and
  `docs/PRODUCTION_READINESS.md` R4 say so, and
  `docs/verification/dtls-stack-2026-09-15.md` lists what has to be rerun: a
  spoofed-source flood, three browsers, coturn's client, twenty-four hours under
  load, certificate hot-reload, and a real interface with packet loss.

- `[turn] allow_core_dumps` (default `false`): the node now calls
  `setrlimit(RLIMIT_CORE, 0)` and `prctl(PR_SET_DUMPABLE, 0)` at startup. The
  shared secret is resident for the whole run — a `String` in the config, bytes
  in `AuthMode`, a second copy in `previous_shared_secret` during a rotation —
  so a dump written by `systemd-coredump`, which most distributions enable by
  default, put it on disk in the clear, as did `/proc/<pid>/mem` to any
  same-user process. Compromising a TURN REST secret means minting credentials
  for anyone, so this is not a crash-report inconvenience. Setting it to `true`
  warns under `production = true`.
- Seven `abuse_*` regression tests in `tests/integration`, one per configuration
  finding: `software_attribute = full`, an unknown `software_attribute`, a zero
  rate-limit refill, a malformed trusted prefix, `tcp_relay` without `[tls]`, a
  family mismatch in `bind_ip`, and a leftover `[signaling]` section. The
  wire-level halves of findings 21 and 30 are unit tests in `turna-qos` and
  `turna-session`, where the failure actually lives.

### Changed

- `deploy/turn.toml` and `deploy/examples/selfhosted.toml` document the keys
  added in this release, including the two whose defaults changed —
  `[tls] max_connections_per_ip` (0 → 64) and the DTLS/QUIC
  `max_sessions_per_ip` (0 → 16). The annotated config is the reference an
  operator reads, and it was six keys behind the schema.

### Fixed

- Admin console: send the `X-Admin-Token` on every `/api` request, not only on
  `POST /api/manage`. Since 0.5.0 the backend requires the token on reads too, so
  with a token configured every status/metrics/health poll failed with 401 (and
  health/ready rendered as "down"). A rejected read now shows an "admin token
  required" banner with a prompt, and polling pauses until a token is entered.
- Config: the RBAC doc comment and the "enabled with no bindings" error named the
  section `[management.rbac]`; the section actually parsed is `[grpc.rbac]`
  (`[management]` has `deny_unknown_fields`, so the documented form was rejected).

- **Key material was freed without being overwritten.** The shared secret is
  resident for the whole run, and a SIGHUP rotation made that worse rather than
  better: the new `AuthMode` and `TurnaConfig` were swapped in and the old
  ones — holding the previous secret — were dropped, leaving the bytes wherever
  the allocator put them next. One readable copy accumulated per reload, in the
  process image and, if the page was ever swapped, on disk.

  `AuthMode` and `AuthConfig` now zeroize on drop, covering the shared secret,
  `previous_shared_secret` and the OAuth AS-RS and kid keys. This is `Drop`
  rather than a `SecretBox` type on purpose: no call site changes, nothing has
  to remember to wrap anything, and a future variant that forgets is a missing
  arm in one place rather than a missing wrapper somewhere in the tree.

  It does not claim to be complete: the secret still exists in memory while the
  node runs, and a copy taken into a local lives until that local drops. What it
  removes is the long tail of copies that outlive their usefulness. With
  `allow_core_dumps = false` closing the dump and `/proc/<pid>/mem` paths, the
  three exposures the audit listed are now addressed.

- Transport: the per-IP DTLS session counters (both listener paths), the
  io_uring relay-route table, the UDP buffer pool and the hugepage free list use
  `parking_lot::Mutex` instead of `std::sync::Mutex` + `.lock().unwrap()`. A
  panic while one of these was held used to poison it, and every later
  `.unwrap()` on the recv/send path then panicked too. The demux path already
  ignored poisoning by hand (`into_inner()`); all of them now share the
  workspace's stated hot-path lock policy.

- **`file://` secrets were read without checking their permissions.** The whole
  point of the indirection is to keep the value out of the config file, and a
  secret mounted at the default 0644 looked exactly as safe as one at 0600 —
  the config said `file:///run/secrets/...` either way. Group- or
  world-readable now warns with the mode and the file.

- **The death of one receive worker was invisible until all of them died.** Only
  the all-dead case set `Degraded`. With N workers on `SO_REUSEPORT` sockets the
  kernel hashes clients across them, so one worker exiting takes out 1/N of the
  traffic — and the node stayed Ready with every metric clean while a fraction
  of calls degraded silently, which is the shape that gets blamed on the network
  for a week. `turna_recv_workers_alive` now reports the count, any loss logs
  `recv_worker_died`, and losing a quarter or more sets `Degraded`. It does not
  recover on its own; the log line says so.

- **Nothing bounded unauthenticated replies to one address.** A Binding response
  is 48 bytes for a 20-byte request and needs no credentials, so the only limit
  was the per-IP ingress budget — which under spoofing belongs to the victim,
  not the attacker: up to 50 000 replies/second, about 2.4 MB/s aimed at whoever
  the attacker named as the source. The ingress tiers are the wrong instrument
  here because they bound what a source may *ask*, and a real client legitimately
  asks thousands of times a second once it is relaying.

  A separate budget (64 burst, 8/s per IP) now covers the replies the node
  *emits* before authentication — Binding responses and 401 challenges — of
  which a real client needs single digits in its whole life. Over budget the
  reply is dropped in silence: answering "you are rate limited" would itself be
  an unauthenticated reply to the same address. New counter:
  `turna_unauth_replies_suppressed_total`.

- **`508 Server Draining` was answered before authentication.** The check sat
  seven lines above the comment explaining why 437 and 442 had been moved
  *below* authentication, for the same two reasons: an unauthenticated reply
  goes to a source address that may be spoofed, and it tells a scanner the
  node's lifecycle state. A real client learns a node is draining one round trip
  later — challenge, credentials, then 508 (or 300 Try Alternate in a cluster).

- **The SOFTWARE attribute named the release to anyone who sent 20 bytes.** The
  Binding response carrying it is unauthenticated, so the exact version went to
  any scanner matching against a CVE list, plus about 16 bytes of free
  amplification on a reflected Binding. RFC 5389 §15.10 makes the attribute
  optional. `[turn] software_attribute` now takes `none`, `product` (the
  default: `turna` with no version) or `full`, and `full` is refused under
  `production = true`.

- **Security switches were reachable from the environment.**
  `TURNA_ALLOW_LOOPBACK_PEERS` was ORed with the config value, so one line
  copied out of a dev compose file opened relaying into loopback while
  `turn.toml` read clean. The environment is not an auditable source of policy:
  not in git, absent from `--dump-config`, inherited by child processes, visible
  in `docker inspect` and `/proc/*/environ`. Under `production = true` such a
  variable is now a startup error naming the config key to use instead.
  `TURNA_PRODUCTION` stays honoured — it can only tighten.

- **`turna_claim_allocation` performed its compare-and-swap without
  `box.atomic`.** This is the failover CAS primitive, and the three procedures
  beside it in the same file wrap themselves with a comment saying memtx does
  not make a stored proc atomic by itself. It works today only because a Lua
  function without yields is effectively atomic under memtx; enable
  `memtx_use_mvcc_transaction_manager`, or move the space to vinyl, and two
  nodes can both pass the `expected_node_id` check and both update — the split
  brain the CAS exists to prevent.

- **The Tarantool bootstrap generated a password and printed it to STDOUT.**
  STDOUT of a container or service is journald and docker logs, usually a
  central collector with its own retention and a far wider set of readers than a
  state-backend credential deserves. The script now requires `TURNA_PASSWORD` or
  `TURNA_PASSWORD_FILE` and refuses to run without one: there is no way for it
  to hand a secret to an operator that does not also hand it to whoever reads
  the logs. A rerun with a new value rotates the credential.

- **Three log sites ran at `warn!`, once per packet, before authentication.** A
  STUN decode error (with the parser's message), an auth failure, and the rate
  limiter refusing a source — all with attacker-controlled content, all on the
  pre-auth path. One gigabit host is roughly 1.5 M packets/second and a `warn!`
  line is 100-200 bytes, so the log became the denial of service: journald's own
  rate limit starts dropping the whole stream, taking with it the messages an
  operator needs to see what is happening. The counters were already there and
  are the honest signal. `turna_common::LogThrottle` now gates all three — first
  occurrence, then every power of two, with the running total on the line.

- **Relay ports were handed out consecutively.** A relay port is public: it
  travels in XOR-RELAYED-ADDRESS and ends up in the SDP. Knowing one told an
  off-path attacker where the next allocations were, and the permitted peer —
  the SFU — is not a secret either, so spoofed packets from that address reached
  a client's RTP stack. SRTP keeps the contents safe; the jitter buffer and the
  loss counters do not care that a packet failed to authenticate. The cursor now
  starts at a random point in the range and still walks linearly, so allocation
  stays O(1) while the range is sparse. RFC 6056 §3.3; coturn already
  randomises.

- **The node's own addresses were valid relay peers.** Nothing stopped an
  authenticated client pointing a peer at `external_ip:3478` (traffic loops
  through the STUN path, burning CPU), at the health port (the entire Prometheus
  surface, when it is not on loopback), or at another allocation's relay port.
  `internet-facing` does not cover it, because a node's public address is public
  — which is exactly why it is reachable and why it must not also be a relay
  target. Every listener, `external_ip` / `external_ip6` and the relay `bind_ip`
  now join the unconditional deny, which the allow-list cannot override.

- **`max_per_user` and `set_user_limits` did not match the identity they were
  meant to limit.** Accounting keyed on the raw USERNAME, and for shared-secret
  (TURN REST) credentials that is `"<unix_expiry>:<userid>"` by the
  coturn-compatible contract — a different string every time the signalling
  service mints a credential, which is per call or per `token_ttl` at best.

  So `max_per_user` capped one pair of credentials rather than one person, and
  the cap reset the moment a client asked for a fresh credential: a compromised
  account, or a signalling bug handing out credentials without limit, stepped
  around it by construction. `set_user_limits(user = "alice")` — a documented GA
  contract — could never match, because the stored key was
  `"1758012345:alice"`.

  `AuthMode::subject_of` now yields the canonical subject: the userid for TURN
  REST, the username unchanged for long-term credentials (where a colon is part
  of the identity) and for OAuth. `AuthResolution` carries it, and quotas,
  lifetime policy and overrides key on it. The credential as presented is
  recorded on the `allocation created` log line, so the audit trail keeps it.

  **`max_per_user` now means what it says**, which makes existing values too
  low: one person legitimately holds several allocations at once — two ICE
  transports, a second device, a reconnect whose old allocation has not yet
  expired. `deploy/examples/selfhosted.toml` goes from 6 to 12.

- **DTLS: a spoofed ClientHello allocated state before anything proved the
  source address was real.** On the demux path — the default since 0.5.0 — a
  datagram from an unknown address allocated a channel, a map entry, a
  `DTLSConn` and a task, and held them for `accept_timeout_secs`. RFC 6347
  §4.2.1 puts the HelloVerifyRequest cookie exchange ahead of exactly that;
  `webrtc-dtls` performs it *inside* `DTLSConn`, after the state exists.

  Nothing bounded it. `max_sessions` counts sessions that completed a
  handshake — `active` is incremented only on success — so it bounded nothing
  an attacker has to do, and `max_sessions_per_ip` and the handshake rate
  limiter both key on an address the sender chose. One ~100-byte ClientHello
  bought ten seconds of state: 100 000 spoofed packets per second is an
  out-of-memory kill in seconds, from any address, with no credentials.

  `[turn.dtls] max_pending_handshakes` (512) now caps handshakes in flight, and
  `max_sessions_per_ip` (16) and `max_handshakes_per_sec_per_ip` (8) default to
  on rather than unlimited. New counters: `pending_handshakes`,
  `rejected_pending_cap`.

  This is a bound, not the fix. The fix is a stateless cookie in the
  demultiplexer, so nothing is allocated until a ClientHello carries a cookie
  this node issued — which is what `DTLSv1_listen` does and what the stock
  `listen()` path got from `webrtc-dtls` before demux replaced it.

- **QUIC: no address validation before the handshake.** Every spoofed Initial
  bought a full TLS 1.3 handshake — ECDHE plus a certificate signature — whose
  result went to an address that never asked. quinn caps amplification at 3x, so
  the reflection is weak; the cost is CPU, and a signature per spoofed packet is
  a cryptographic denial of service that needs no amplification to work.

  Unvalidated Initials are now answered with `retry()`: a stateless token, one
  datagram, no state kept. `[turn.quic] max_sessions_per_ip` (16) and
  `max_handshakes_per_sec_per_ip` (8) also default to on. New counter:
  `turna_quic_retries_sent_total`.

  Both paths are covered. On the WebTransport path the check runs **before** the
  per-IP tables are touched, because everything after it keys on an address that
  is whatever the sender put in the packet until quinn has validated it —
  admitting an unvalidated Initial would let a spoofed source consume a slot
  belonging to an address that never sent anything.

- **TURNS had no per-source connection cap.** `max_connections_per_ip` defaulted
  to 0 while `max_connections` was 10 000 and the read timeout 300 seconds, so
  one host could hold the entire budget in silence and leave legitimate TURNS
  clients refused — the clients whose network blocks UDP and who have no other
  way in. The handshake rate limiter bounds speed, not how many connections are
  held. Default is now 64.

- **A full rate-limiter table refused every new source instead of making room.**
  `ShardedRateLimiter::check` returned `false` for any address not already
  tracked once the table hit its 65 536-entry cap — before authentication and
  before parsing. Filling it costs about 1.3 MB of spoofed UDP from 65 536
  addresses, and the entries only cleared 600 seconds later, so repeating the
  burst every ten minutes held the door shut against new clients indefinitely.
  Established clients kept working throughout, so allocation counts looked
  healthy while nobody new could connect.

  A limiter that fails closed against *unknown* sources fails closed against
  *legitimate* ones the moment addresses can be spoofed, which for UDP is
  always. The table now evicts the idlest of a bounded sample instead: a spoofed
  address sends one packet and ages, a real client sending continuously has the
  smallest age in any sample. Evicting a live client is survivable in a way
  refusing it is not — it gets a fresh bucket, i.e. more budget, not less. New
  counters: `evictions()` and a fill level via `len()` / `max_entries()`.

  The accompanying `warn!` fired once per refused packet, from an
  attacker-chosen source address — a log amplifier on the same path as the
  denial it reported. It is now one line per power of two.

- **Unclaimed EVEN-PORT reservations leaked their ports until restart.**
  `EVEN-PORT R=1` takes two ports, and expiry ran only inside
  `claim_reservation` — so a client that asked for a pair and never presented
  the RESERVATION-TOKEN held the odd port for the life of the process. At the
  default Allocate rate against a 16 384-port range, one authenticated client
  exhausts the pool in about seventeen minutes.

  The symptom hid the cause: 508 Insufficient Capacity for everyone,
  `turna_relay_ports_in_use` at 100 %, the capacity API reporting SATURATED, and
  a live-allocation count too low to explain any of it. Recovery was a restart,
  or the luck of an unrelated client presenting a token.
  `PortAllocator::sweep_expired_reservations` now also runs from the periodic
  maintenance sweep, across the base pool and every tenant pool.

## [0.5.0] - 2026-09-14

### Breaking

- **`[sfu]`, `[signaling]` and `[recording]` are removed from the config schema.**
  The schema is `deny_unknown_fields`, so a config still carrying any of them
  will not load. Delete the sections; nothing else is needed.

  They were parsed, validated and read by nothing. `[signaling]` was the
  expensive one: `turn_shared_secret` was **mandatory**, and in production a
  placeholder value was a hard validation error — so every operator had to
  generate, deploy and rotate a secret for a service that does not exist in this
  workspace, while its default `listen` of `0.0.0.0:9001` took part in the
  port-conflict check and suggested something was listening there. A secret that
  is accepted and consumed by nothing is a false security boundary: it gets
  rotated on schedule and written into audit reports, and none of that protects
  anything.

  Loading a config with one of the three now fails with a message naming the
  section, the release that removed it, and what to do — not with serde's bare
  `unknown field`, which reads like a typo the operator did not make.

  A minimal TURN-only config (`[turn]`, `[turn.auth]`, `[health]`) now validates.
  Before this change it did not.

### Added

- `turna-transport::TLS_AVAILABLE`, mirroring `dtls::DTLS_AVAILABLE` and
  `quic::QUIC_AVAILABLE`.
- The node **refuses to start** when `[tls] enabled = true` on a binary built
  without the `tls` feature. Previously the whole TURNS block was compiled out
  and `tls_cfg` discarded with no log line at all, so the node came up healthy,
  reported healthy, and served nothing on 5349 — while `EXPOSE 5349/tcp` in the
  image and `deploy/examples/corporate.toml` both said otherwise. Clients on
  UDP-blocked networks simply could not connect, and no metric said why. DTLS and
  QUIC had this guard already.
- Config warning under `production = true` when `[tls]` is disabled: the node is
  UDP-only and has no TCP fallback, which is a legitimate deployment but should
  be read in the log rather than inferred from the users who cannot connect.
- Config error (production; warning otherwise) when `[turn.tcp_relay]` is enabled
  without `[tls]`. RFC 6062 carries the TCP allocation over the TLS control
  connection and turna has no plain-TCP listener, so the datapath was
  unreachable. The field documentation had said "requires `[tls]` enabled" all
  along; nothing checked it.
- CI job `tls-fail-closed`: builds the node with `--no-default-features` and
  asserts it refuses a config that enables `[tls]`, with the rebuild instruction
  in the message.
- README section "Client ICE configuration", stating the two URLs that are served
  and the one that is not.

### Added (continued)

- `[turn.rate_limit]` — the tiered limiter's tunables, previously readable only
  from `TURNA_RATE_LIMIT_*` and friends. Those overrides still work and now warn
  each time they fire; they are deprecated and go away in the release after next.

  Two tiers: `default`, whose values are byte-identical to what was hardcoded
  before, and `trusted`, applied to sources inside `trusted_prefixes`. The case
  the strict defaults get wrong is an office behind one NAT address. A browser
  sends one Allocate per ICE transport, so a 300-person meeting is ~600 Allocates
  from one IP; at the default 16/s that is 35 seconds, longer than a browser's
  ICE gathering waits before timing out and retrying — which lengthens the queue
  the client is already stuck behind. The data-plane tiers matter for the same
  reason: 300 relaying participants at ~300 pps each is ~90 000 pps from one
  source, against a default refill of 50 000.

  `trusted_prefixes` is empty by default and is not an authentication boundary.
- `[turn.relay] bind_ip` / `bind_ip6` — pin the relay sockets to one address.
  They bound every interface before, so on a node with a public and a private
  NIC, relay ports 49152-65535 were open on the private side too. The peer
  filter closes the outbound direction; it does not stop inbound packets on a
  relay port. The RFC 6062 TCP listener uses the same address.
- `[turn] socket_recv_buffer_bytes` / `socket_send_buffer_bytes` — `SO_RCVBUF` /
  `SO_SNDBUF` for the listener and every relay socket. The node logs the size the
  kernel actually gave and warns when it was clamped, because `setsockopt` is
  clamped to `net.core.rmem_max` **silently**: asking for 16 MB on a stock host
  succeeds and yields 212 992 bytes. A receive-buffer overflow is dropped in the
  kernel, so it appears in no turna metric at all — `nstat -az UdpRcvbufErrors`
  is the only thing that counts it.
- `deploy/sysctl.d/99-turna.conf`, `deploy/systemd/turna-node.service`,
  `deploy/examples/selfhosted.toml` and `docs/SELFHOSTED.md` — the single-node
  self-hosted path, which had no entry point across 96 documentation files.

### Changed

- **`docker-compose.yml` uses `network_mode: host`.** Publishing 16 384 UDP relay
  ports through the bridge creates a forwarding rule per port and, depending on
  the Docker version and `userland-proxy`, a `docker-proxy` process per port:
  container start measured in tens of seconds, and an extra NAT hop on the media
  path. It also hid the client's source address behind the gateway's, which
  quietly collapsed per-IP rate limiting into one shared bucket for everyone.

  Prometheus moves to host networking too — it cannot reach a loopback-bound
  health port from the bridge — and now binds 9091 explicitly, since the
  published `9091:9090` mapping that used to separate it from turna's health
  port does not exist in host mode.
- **`[health] listen` defaults to `127.0.0.1:9090`.** It serves `/health` and the
  entire Prometheus surface, several hundred series including per-tenant detail.
  It was `0.0.0.0` while `docker-compose.yml` published it, so the default
  deployment offered the metric surface to anything that could route to the host.
- `EXPOSE 9090/tcp` removed from the image for the same reason.
- **`tls` is now a default feature of `turna-node`.** It is the only TCP entry
  point the node has, so the safe configuration is the one you get by doing
  nothing; opting out is `--no-default-features`, an explicit decision. The
  release image passes `--features tls` explicitly as well, so moving `tls` out
  of `default` later cannot silently drop TURNS from the image.

### Removed

- **`turna_auth::{store, rotation, jwt, user}`** — 1 310 lines of user
  registration, Argon2 hashing, JWT signing and token revocation with no callers
  outside the crate (0 of 3, 0 of 6, 0 of 5 and 0 of 3 `pub` items). The crate
  header presented them as "User auth (Phase 2)", which is how a reader concludes
  turna has platform user auth; it had the code and did not run it.

  Authenticating users is the signalling service's job — turna receives a TURN
  REST credential and validates it. `docs/OPEN-DECISIONS.md` decision 7 is closed
  accordingly. `jsonwebtoken`, `argon2`, `password-hash` and `uuid` go with them,
  as does `TURNA_JWT_SECRET`, which was required by a constructor nothing called
  and set nowhere in the chart, the configs or the docs.

### Fixed

- **TURN REST credentials had no clock-skew tolerance.** The credential is minted
  by the signalling service and checked here, on a different machine; a
  disagreement between the two clocks produced 100 % `Expired` across every
  client at once with nothing in the log pointing at time. `[turn.auth]
  credential_clock_skew_secs` (300 by default) closes it, and a rejection now
  logs `expiry`, `now` and the gap, because a large constant gap is the signature
  of skew and is invisible when the message only says "expired". The RFC 7635
  OAuth path had a skew allowance from the start. Even with the grace this stays
  stricter than coturn, which does not check expiry at all.
- `rust-toolchain.toml` pins 1.95.0 and every CI job uses it, while
  `deploy/Dockerfile` built on `rust:1.98.0`. rustup inside the container saw the
  pin and downloaded 1.95.0 on every build, so each image build depended on
  `static.rust-lang.org` and CI and the image compiled with different compilers.
  The image now pins 1.95.0.
- `deploy/Dockerfile` built without `--features tls` while exposing 5349/tcp.
- `3478/tcp` is no longer exposed or published. turna has no plain
  TURN-over-TCP listener, so a client ICE entry of
  `turn:host:3478?transport=tcp` met a connection refused after spending part of
  its gathering budget. `docker-compose.yml`, the `EXPOSE` list and the README
  `docker run` example all advertised the port.
- README claimed JWT authentication and credential rotation as features. The
  `jwt`, `store`, `rotation` and `user` modules in `turna-auth` have no callers
  (see `docs/OPEN-DECISIONS.md` decision 7).
- README stated that `SIGHUP` is not handled and that the shared secret needs a
  restart. The handler exists and has since 0.4.0: it re-reads the config file
  and republishes `shared_secret` / `previous_shared_secret` without dropping
  calls. Operators were planning rolling restarts for a config reload.
- README stated that RFC 6062 TCP relay is refused under `production = true`.
  That gate was lifted when coturn interop was recorded.
- `scripts/check-doc-claims.sh` checked `deploy/examples/public-turn.toml`, which
  does not exist — the extractor skipped the missing path, so
  `deploy/examples/public.toml` was never checked while the section reported a
  clean pass. A listed config that is not on disk is now a failure.
- `docs/CLUSTER.md`, `docs/security/accepted-risks.md`: the gossip replay window
  survives a restart (`seq` starts at 0 on process start, so a captured frame —
  including a `leaving` — is accepted by a node that has just restarted), and the
  Tarantool iproto connection is plaintext. Both are bounded by the private
  network the cluster already requires, and both are now written down with the
  remediation rather than left to be rediscovered. RISK-004 and RISK-005.
- `docs/deployment/host-tuning.md`: the capacity cliff has a structural cause —
  N receive workers feed a single egress task through one 8192-slot channel, so
  client→peer throughput is bounded by one consumer. Roughly 250-350
  simultaneously relaying video clients per node, reached as a cliff. Sharding by
  `relay_port % M` is the fix and is deliberately not made yet: the 112 000 pps
  figure is a loopback measurement, and a rewrite justified by it would be
  justified by the wrong bottleneck.
- **`log_allocation_addresses = false` reached three log lines out of twelve.**
  The switch exists to keep client addresses out of stdout, and the allocation
  lifecycle lines honoured it — while auth failures, forbidden-peer denials,
  quota drops, decode errors and cluster redirects wrote the address verbatim
  whatever it was set to. An operator who turned it off got the opposite of what
  they concluded, and the lines that leaked are the high-frequency ones. All
  twelve now go through the same function, including the peer addresses from
  CreatePermission and ChannelBind, which had no redacting path at all.
- **The redaction salt was derived from the process start time.** That is the
  exact fallback `observability::syslog` documents CodeQL catching and rejecting:
  a restart time is often observable from outside — a rolling upgrade, a status
  page, a gap in the metrics — so the search space collapses against four billion
  IPv4 addresses, while the label still *looks* like a hash. It is now eight
  bytes from `/dev/urandom`; if that read fails the node says so once and writes
  addresses verbatim rather than producing a label that protects nothing.
- `#![forbid(unsafe_code)]` added to every crate that contains none:
  `turna-config`, `turna-qos`, `turna-crypto`, `turna-session`, `turna-auth`,
  `turna-proto-turn`, `turna-cluster`, `turna-health`, `turna-observability`,
  `turna-control`, `turna-proto-stun`, `turna-common` and `turna-packet` —
  thirteen in all. `turna-transport` and
  `turna-relay` keep theirs, which is the point. `docs/unsafe-audit.md`
  claims the audited `unsafe` inventory is confined to transport and relay; the
  attribute makes that claim checkable by the compiler instead of by a grep
  someone remembers to run.
- `scripts/check-doc-claims.sh` scanned only `docs/` for stale SIGHUP claims, so
  the one in `README.md` — the file an operator reads first — sat one directory
  outside its reach for the life of the check.

The entries under the "(from the pending notes)" headings were kept in
`docs/CHANGELOG-pending.md` and were not moved here at release time. That file
was last changed in the 0.5.0 release commit (`f092e60`), so everything in it
shipped in 0.5.0.

### Changed (from the pending notes) — read this one first

- **`[turn.dtls] demux` now defaults to `true`.** A config with
  `[turn.dtls] enabled = true` and no `demux` key takes the demultiplexer path
  after upgrading, where before it took `webrtc_dtls::listener::listen()`.

  The stock listener held the default because it was the path with a recorded
  24-hour run — not because it was better. Two §7 P0 requirements are unreachable
  on it rather than unimplemented: `listen()` owns the socket and fixes its
  certificate at bind time, and the handshake completes below `accept()` where
  nothing can rate-limit it.

  Both halves of the evidence are now on record. Correctness:
  `scripts/verify/dtls-demux.sh`, 9 of 9, including the per-IP handshake limiter
  refusing 15 handshakes before any DTLS state was created. Stability:
  `docs/soak/soak-24h-dtls-2026-09-01.md` — 24 hours, eleven DTLS cycles identical
  to three significant figures, a spread of 16 frames in 1.7 million, zero egress
  drops, and the node exiting cleanly on SIGTERM.

  *To keep the previous behaviour:* set `demux = false`. Note that
  `cert_reload_secs` and `max_handshakes_per_sec_per_ip` must then be removed —
  validation refuses them on the stock path, because there they read as protection
  that is not there.

  *Not established:* a real NIC. The run was over loopback, and handshakes over a
  network lose packets — which is where a demultiplexer is most likely to differ
  from a listener that owns its socket.

### Added (from the pending notes)

- **Shared-secret rotation on SIGHUP, without a restart.** The two-secret window
  below shipped without a way to move between its steps: the secret was read once
  at startup, so every step meant a rolling restart. SIGHUP now re-reads the same
  config file and republishes the SharedSecret backends. Nothing else from the
  reloaded file is applied.

  A rotation is: new secret into `shared_secret`, old one into
  `previous_shared_secret`, `kill -HUP` each node, wait for
  `turna_auth_previous_secret_total` to flatten, remove the old secret, SIGHUP
  again.

  A signal rather than a management RPC, deliberately: the secret stays on the
  host, cannot land in an audit record, and needs no proto change. The reasoning,
  including why `UpdateConfig` was rejected, is in `docs/OPEN-DECISIONS.md` §0,
  which this closes.

  *Refused rather than half-applied:* a config that fails validation (secrets stay
  as they were), a changed realm, a tenant added since startup. All logged.
  Secrets are never logged, nor hashed into a log.

  *Not covered:* non-unix targets have no SIGHUP and still need a restart.
  `scripts/verify/rotation-under-load.sh` now runs its secret phase by default —
  it was disabled because it used to SIGHUP a node with no handler, killing it,
  after which every remaining assertion passed against the dead process.

- **Two shared secrets during a rotation window** — `[turn.auth]
  previous_shared_secret`, and the same key per tenant. Rotating the secret used to
  invalidate every credential already issued, so the documented workaround was to
  schedule a low-traffic window. With this set, credentials signed with either
  validate.

  `turna_auth_previous_secret_total` counts what still uses the old one. That
  counter is not an extra: a rotation ends by removing the old secret, and without
  a number an operator cannot tell whether that is safe.

- **`[turn.auth] require_sha256`** refuses clients that can only do MD5 long-term
  keys. SHA-256 was already preferred when a client advertises it; the fallback was
  silent. Off by default — most deployed TURN clients predate RFC 8489.

### Fixed (from the pending notes)

- **An IPv6 `[turn] external_ip` silently broke RFC 6062 TCP relaying.** A v6
  literal there is legal and only changes what is advertised for v4-family
  allocations — except for TCP allocations, whose relayed listener binds
  `0.0.0.0`. A client that sent no `REQUESTED-ADDRESS-FAMILY` got a SUCCESS
  carrying a v6 relayed address that nothing served, so peer-initiated
  connections could never arrive, with nothing logged. Now answered `440`, the
  same as an explicit IPv6 request, with the reason logged.

- **`rtnetlink` 0.21 → 0.23**, which drops RUSTSEC-2024-0436 (`paste`
  unmaintained) from the tree rather than ignoring it: `netlink-packet-core`
  0.8.1 was the only package pulling it, and 0.9.0 has no dependencies at all.
  The `deny.toml` ignore was removed, not silenced. No code change — the API
  `neighbor.rs` uses is unchanged across the bump, verified by diffing the
  published sources.

- **`osv-scanner.toml` still ignored an advisory `deny.toml` had dropped.** That
  file opens by saying it is "kept in sync with the [advisories].ignore list in
  deny.toml", and nothing enforced it — so removing RUSTSEC-2024-0436 from one
  left the other claiming turna still accepts it. cargo-deny gates CI from the
  first; OSSF Scorecard's Vulnerabilities check reads only the second, so the two
  tools would have reported different risk postures. Synced, with a gate on the
  invariant the file states about itself.

  Four places still named `rtnetlink 0.21 / netlink-packet-route 0.30` after the
  bump, including the `neighbor.rs` header that records which versions its
  netlink wire-format handling was grounded against. Corrected.

- **Worked configuration examples** under `deploy/examples/`: `public-turn.toml`
  (internet-facing, REST credentials, secure peer filter, every quota set),
  `corporate.toml` (TURNS on 443, named users, `lan` peer filter with a deny list
  and a note on why that setting is the dangerous one), `cluster.toml` (gossip
  plus Tarantool, with the experimental caveat up front).

  They are not prose. Each is included in the `check-doc-claims` config-key gate,
  and CI now loads all three through the real validator with `production = true`
  — the strict branch, which the default Helm render does not exercise. An
  example that does not load is worse than none: it gets copied, edited, and the
  failure is blamed on the edit.

- **Tarantool schema-migration runbook**
  (`docs/runbooks/tarantool-schema-migration.md`). Opens by separating the two
  things called "migration" here, because confusing them is the main way this goes
  wrong: `init.lua` provisioning, which is idempotent and whose upgrade procedure
  is "run it again", and the bounded command-log backfill inside the node, which
  runs itself and gates the management plane while it works.

  The part worth writing down is what idempotence does **not** cover:
  `if_not_exists` creates what is missing and never alters what exists, so a
  changed field type or index part leaves the old shape in place, silently. No
  current change needs that; the composite key discussed for
  `ADDITIONAL-ADDRESS-FAMILY` would, which is why its design doc asks for a
  documented procedure and a rollback.

  Also: the three Lua suites are named as the contract for the stored functions
  (they now run in CI), and schema rollback is stated as unsupported with the
  reason — `if_not_exists` has no inverse, so the backup taken in step 1 is the
  rollback.

- **Kubernetes + Tarantool runbook** (`docs/runbooks/kubernetes-tarantool.md`).
  Provisioning order — schema before pods, with three checks that must print
  `true` — the Secret wiring for the backend password, the two settings that
  refuse to start (`write_behind` on a memory backend; cluster mode on one) and
  the one that does not, what to watch afterwards, and the NetworkPolicy's
  relationship to ports the chart cannot configure anyway.

  It opens with what the chart does **not** do, because two of those limits
  surprise people at the wrong moment: no ops API and no encrypted transports.
  Every metric it names was checked against the health crate — the first draft
  named two that do not exist (`turna_tarantool_pool_broken`,
  `turna_persistence_dropped_total`; the real series are `tarantool_*` without the
  `turna_` prefix), which would have given the reader a permanently empty panel
  that reads as health.

- **Seven of `turnactl`'s eleven documented commands cannot work.** Its header
  listed all eleven as if they did. `ManagementClient::send` sends four as plain
  GETs to the health server — `ping`, `status`, `allocations count`,
  `cluster nodes` — and those are fine, and `user add` / `user remove` go over
  gRPC to the control plane. **Everything else POSTs to `/manage`, and nothing in
  the workspace serves that path:**

  * the health server routes `/capacity /cluster /health /metrics /ready /status`
    and no more, and `--addr` defaults to its port;
  * the `("POST", "/manage")` handler in `turna_management` belongs to
    `integration::serve`, which has no callers — the crate is depended on only by
    `turnactl`, and only for its client half;
  * `services/admin` serves `/api/manage`: different path, port and protocol.

  So `failover status`, `drain`, `undrain`, `allocations list|get|kill` and
  `rooms list` fail against a healthy node — and the error reads "Is turna-node
  running with management API on 127.0.0.1:9090?", sending the operator to debug a
  deployment that is fine. The client's own comment says the server would be on
  9091 while the default is 9090, so the halves never agreed even in intent.

  `rooms list` is doubly dead: it needs `StoreHandler::list_rooms`, and
  `StoreHandler` has no implementation anywhere — there is no rooms feature and no
  `turna-signaling` binary.

  The header now says exactly which commands reach a server and why the rest do
  not, with a two-way gate. Wire it or delete it is decision 8 in
  `docs/OPEN-DECISIONS.md`; the gRPC control plane already covers allocations,
  drain, users and config, with authentication, RBAC and an audit trail this HTTP
  surface has none of. No code removed.

- **73 Prometheus alert rules that nothing validated.** Kubernetes manifests are
  checked offline with kubeconform; the rules in `docs/alerts/` were checked by
  nothing, so a malformed expression — an unbalanced paren, an unknown function,
  a bad `for:` duration — surfaced when an operator loaded the file into their own
  Prometheus. `promtool check rules` now runs in the same offline-validation job.

  All 73 pass today; this was verified with a real promtool before the step was
  added, along with each failure mode it is meant to catch. The rules were also
  audited for the semantic errors promtool cannot see — `rate()` over a gauge, a
  counter compared without `rate()`, a division that yields NaN on a zero
  denominator — and had none of them. The extractor's own coverage was checked
  first: 73 of 73 expressions parsed, so "no problems" means something.

- **A gate for the admin UI / admin service command boundary.** The two meet over
  JSON (`POST /api/manage` with a command name), so nothing compiles them
  together — the same shape that let the Python SDK drift, minus a compiler on
  either side. All 13 commands the UI sends are handled today; the gate keeps it
  that way. Its extractor fails loudly if it parses nothing, rather than passing
  on an empty set.

  Parameters are deliberately **not** checked. The service reads some through
  helpers (`u32_limit(params, "max_allocations")`) rather than `params["..."]`,
  and a first extractor that missed those produced a false positive. A gate that
  cries wolf gets ignored, which is worse than the gap it covers; the frontend's
  TypeScript already makes the required parameters non-optional.

- **The Helm chart serves plain UDP TURN only, and said so nowhere.** Its
  ConfigMap has nine sections — no `[tls]`, no `[turn.dtls]`, no `[turn.quic]` —
  and no `extraConfig` hook, so TURNS, DTLS and QUIC/WebTransport cannot be
  enabled through it at all. The node supports them and CI now exercises two of
  them end to end; they are simply out of the chart's reach, because certificate
  material needs Secret mounting and a rotation story the chart does not have.

  That is a defensible scope. What was not defensible is that the README offered
  the chart as *the* Kubernetes path with no caveat, so an operator needing TURNS
  in Kubernetes discovered the limit by reading the template. Now stated in the
  README, in `values.yaml`, and at the top of the ConfigMap, with a two-way gate:
  if the chart gains an encrypted-transport section the notes must go, or they
  become the false claim instead.

  The chart also deploys **`turna-node` alone** — no `turna-control-plane`
  workload, no Service for the management port, `[management] enabled = false` on
  loopback. So there is no ops API in a chart deployment: `turnactl` and the admin
  console cannot reach it. They assume the single-host topology in
  `docs/admin/README.md` with the control plane on `127.0.0.1:5350`;
  `deploy/docker-compose.yml` runs the node alone for the same reason. Stated in
  the same three places, with the gate checking for an actual workload rather
  than a mention of one.

  `[turn.peer_filter]` is also absent, and that one is safe: its defaults are
  `internet-facing` with `allow_loopback_peers = false`, so omitting the section
  denies private and loopback peers rather than allowing them. Checked rather
  than assumed, and written down next to the scope note.

- **Two CI jobs that could report a clean run having done nothing.** The nightly
  fuzz workflow put `cargo fuzz list` into a variable and looped over it, skipping
  blank lines; an empty list meant zero iterations and `exit 0`. A cargo-fuzz
  whose output format changed, or a workspace it could not read, would have looked
  like a clean nightly indefinitely — and a nightly is exactly the job nobody
  watches. The list is now checked against the `[[bin]]` count in
  `fuzz/Cargo.toml`, and the loop counts what actually ran.

  `ci.yml`'s `fuzz-build` job smoke-ran five target names written out by hand, so
  a new target was built by one step and never run by the next. It now derives the
  list from the manifest, with the same guard.

- **Three Tarantool test suites that nothing ran.**
  `deploy/tarantool/tests/*_test.lua` pin the CAS semantics the failover claim
  depends on — migration idempotency, the exact-u64 parser, and the runtime /
  user-limits CAS round-trip including rollback on an injected write failure.
  `GA_FINAL_REPORT.md` (now `docs/verification/v0.3.0-ga-final-report.md`) documented the commands and no job used them, so the
  contract was unenforced in the one place where getting CAS wrong loses
  allocations silently. Added to the `failover-integration` job, which already
  has a Tarantool container up. Checked first that each suite exits non-zero on
  failure; a suite that printed FAIL and exited 0 would have made this a green
  step proving nothing.

- **1 310 lines of user/JWT auth that nothing calls, presented as a feature.**
  `turna-auth`'s `store.rs` (659), `rotation.rs` (403), `jwt.rs` (184) and
  `user.rs` (64) implement user registration, login, Argon2 password hashing, JWT
  signing, token revocation and a blacklist — and have **no callers outside the
  auth crate**. Verified per module by taking every `pub` item and searching the
  workspace: 0 of 3, 0 of 6, 0 of 5, 0 of 3. They reference each other and
  nothing else; their tests exercise code nothing runs.

  The crate header advertised them as "User auth (Phase 2)", which is how a
  reader concludes turna has platform user auth. It has the code, not the
  feature. This also explains why `TURNA_JWT_SECRET` — required by
  `UserStoreConfig::try_from_env` — is set nowhere: not in the Helm chart, not in
  a shipped config, not in the docs.

  **Superseded in 0.5.0: the four modules were deleted.** They were first marked
  unwired in the crate root and in each module, with a `check-doc-claims` gate
  holding the labels honest, and "wire it or delete it" was recorded as decision
  7 in `docs/OPEN-DECISIONS.md`. That decision is now closed as *delete*:
  authenticating users is the signalling service's job, and turna validates a
  TURN REST credential derived from `[turn.auth] shared_secret`. The
  `jsonwebtoken`, `argon2`, `password-hash` and `uuid` dependencies went with
  them, as did `TURNA_JWT_SECRET`. The gate now asserts the deletion instead of
  the labels: if one of these files returns it must have a caller outside the
  crate.

- **A second source of truth for the Tarantool schema that does not exist.**
  `tarantool::INIT_SCRIPT` was deleted, leaving a bare comment header where it had
  been — and five places went on describing it as live: `turna-state-backend`'s
  `lib.rs` said the init script "is embedded" in it, `deploy/tarantool/init.lua`
  carried a "change one place, change both" note, and the
  `ADDITIONAL-ADDRESS-FAMILY` migration plan — in `OPEN-DECISIONS.md`, its design
  doc and `protocol-gap.md` — budgeted for updating both files.

  So the Option-3 schema migration was costed for work that does not exist, and
  whoever started it would have gone looking for a constant that is not there. The
  schema is defined once, in `deploy/tarantool/init.lua`; the Rust backend calls
  the `turna_init_schema` stored function that file defines.

  The same doc comment also gave a setup command pointing at
  `deploy/tarantool_init.lua`, which is not a path in this repository — anyone who
  copied it got "No such file". Corrected to `deploy/tarantool/init.lua`, and
  `tarantoolctl` to `tt`.

- **The production Helm example was never parsed.** `helm template` with
  `values-production.example.yaml` went through kubeconform, which validates
  Kubernetes schema and knows nothing about `turn.toml`; only the *default*
  values had their rendered config parsed by turna-config. So the file operators
  are told to copy produced a config nothing checked — and `production = true` is
  precisely the branch the default render does not exercise (placeholder-secret
  refusal, the unlimited-bandwidth rule, write_behind on an in-memory backend, a
  non-loopback management listener). CI now renders and parses it too.

  The `check-doc-claims` config gate also reads the ConfigMap template directly:
  its keys are literal even though its values are Go-template expressions, so a
  key that no config struct declares is caught in the fast gate, on a machine
  with no helm.

- **Four methods of the Python SDK could not work.** `tools/sdk/python/turna_sdk.py`
  is shipped for operators and nothing ever compiled it against
  `management.proto`, so it drifted silently while the proto was restructured:

  * `allocations()` sent `limit`; the field is `page_size`.
  * `drain()` sent a `reason`; `SetDrainingRequest` has no such field. It carries
    `draining`, `node_id`, `idempotency_key`. `node_id` was never sent at all.
  * `delete_allocation()` sent `allocation_id`; the field is `id`.
  * `set_user_limits()` sent `username`, which is **`reserved`** — retired along
    with three siblings when that request became a `target` plus a tri-state
    `patch`, deliberately rather than reassigned.

  protobuf raises `ValueError` on an unknown field, so each of these failed
  before the call left the process. `set_user_limits` is rewritten to the current
  shape and now requires `expected_version`, for the same reason `update_config`
  does. `drain()` grew `node_id` and lost `reason`; record the reason in your own
  change log — the node's audit entry is keyed by the correlation id the client
  already sends.

  `scripts/check-doc-claims.sh` gained a gate that walks the SDK's AST and checks
  every `pb` field, enum and rpc against the proto, including `reserved` ones.

- **Two artefacts nobody was checking.** `scripts/check-doc-claims.sh` gained a
  gate for each.

  The Grafana dashboard shipped in `deploy/` is imported and then trusted, and a
  panel whose metric was renamed does not error — it draws an empty graph. On a
  wall display "no data" and "nothing happening" are the same picture. All 23
  metrics it names currently exist; the gate keeps it that way.

  The shipped configs (`turn.toml`, `deploy/turn.toml`, the two under `bench/`)
  are parsed with `deny_unknown_fields`, so a key that no longer exists is not
  ignored — the node refuses to start. A stale key is a startup failure waiting
  for whoever copies the file. None are stale today.

- **Six verification scripts passed when they could not measure.** A second pass
  over the same class as the SIGPIPE bug below, looking for checks that succeed
  for the wrong reason rather than checks that fail.

  `errs` was defaulted to `0` in `af-xdp-lab.sh`, `capacity-profile.sh` and
  `air-gap.sh`, so a load-tool JSON with no `errs` field read as "zero errors" and
  the phase passed unmeasured — while three sibling scripts already defaulted the
  same field to `1`. The same question was answered two ways in one directory; it
  is now required outright, and its absence names itself.

  `send_queue_dropped` was read as `... .get(..., 0) || echo 0` in
  `deployment-compliance.sh`, `capacity-profile.sh` and `mixed-load.sh`. Every way
  of failing to read it — endpoint down, malformed JSON, field renamed — became
  the number zero, and zero prints "no egress queue drops". In
  `capacity-profile.sh` it was worse than cosmetic: an unreadable `/status` made
  the per-phase delta negative, a negative is not `> 0`, and the phase kept its
  PASS, so a capacity ceiling could be set from a phase whose drops were never
  measured. Unreadable, absent and zero are now three different outcomes.

- **Five verification and CI scripts reported the opposite of the truth** under
  `set -o pipefail`. `printf ... | grep -q` lets grep exit at its first match, the
  writer dies of SIGPIPE, and the pipeline returns 141 — so a proto field that had
  not changed was reported as broken (about 1 run in 6), a declared Cargo feature
  as unknown, an existing `load-test` subcommand as missing, and, worst,
  `dtls-demux.sh` printed "port released" over a port that was still bound.

- **`--dump-config` printed the backend URI whole**, and a Tarantool URI is
  `user:password@host`. The password was disclosed on the line directly above one
  that carefully masks the password field.

- **`auth failed` was logged at WARN for requests with no credentials at all.**
  RFC 5389 §10.2 requires the client to send one, get 401 with a realm and nonce,
  and only then sign — so that was one warning per allocation attempt: 4.8 GB of
  log per hour at soak rates, which filled a 50 GB disk. Now DEBUG.
  `IntegrityFailed`, which means a wrong password, stays at WARN.

## [0.4.0] - 2026-08-30

### Fixed — read this one first

- **The node never exited on `SIGTERM`.** `run_tokio` let the Tokio runtime drop
  implicitly, and `Runtime::drop` waits for every spawned task to finish. Four
  metric tickers loop forever by design — one says "Runs until process exit" in
  its own comment — so the drop blocked and the process stayed alive until
  something killed it.

  Measured before the fix: alive past 45 seconds after `SIGTERM`, two threads
  left, one a worker in `hrtimer_nanosleep`. After: exits in about 12 seconds with
  status 0.

  **This affected every restart on every node**, in every configuration —
  confirmed identically with the stock DTLS listener and with DTLS disabled
  entirely. An orchestrator would wait out its termination grace period and then
  kill hard, on every rollout.

  It left no trace in the logs because everything that logs had already finished:
  drain completed in milliseconds, `all allocations drained` was written, and all
  four `join_within_budget` calls returned within their budgets. The wait was
  after the last line anything writes.

  It went uncaught because every verification script ends by killing the node with
  `SIGKILL`. `scripts/verify/dtls-demux.sh` was the first to assert that the node
  exits on its own, and it found this on its first clean run.

  *Action:* none, but if your deployment had a long termination grace period
  because turna "took a while to stop", it can be shortened.

### Added

- **Client-certificate revocation for the management plane** —
  `[grpc] revocation_list`, a file of SHA-256 fingerprints that may not be used.
  Checked before RBAC, because a revoked certificate that also lacks a permission
  must be audited as revoked: an operator reading `rbac_denied` would grant the
  role, and the revoked certificate would then work.

  **Not RFC 5280 CRL** — no CA-signed list, no freshness rule. A revoked client
  completes the TLS handshake and is refused on its first RPC. That trade buys
  what CRL cannot have here: it works with no route off the host, which is the
  deployment that most needs revocation. See `docs/security/mtls-revocation.md`.

  Fail-closed: a configured path that cannot be read stops the node, because a
  list that is configured and silently empty looks like protection.

- **RBAC for the management plane** — `[grpc.rbac]`, with roles defined in
  configuration rather than in code. `viewer`, `operator` and `admin` are
  defaults, not the vocabulary. Bindings are by certificate fingerprint, not by a
  field inside the certificate: reading a role from the OU would hand
  authorisation to whoever signs certificates.

  Default-deny, and enabling it on a running deployment locks out every client
  until each is bound — which is why it is opt-in.

- **Packet-rate thresholds in `/capacity`** — `[turn.relay] max_packets_per_sec`
  with `rate_soft_percent` (60) and `rate_hard_percent` (80).

  Lower than the allocation thresholds on purpose, and the measured curve is why:
  allocations degrade gracefully, and packet rate does not degrade at all and then
  falls off a cliff. On a 32-thread host, clean at 112 000 pps and shedding a
  million frames at 128 000 — seven percent between perfect and broken. At 80 %
  there are 30 400 pps of headroom before the cliff; at 90 % there would be
  19 200.

  0 leaves the rate reported and not judged, which is the default.

- **Security-event export to syslog** — `[observability] syslog_endpoint`,
  RFC 5424 over UDP or TCP. Security-relevant events only: a SIEM billed per event
  that receives a line per relayed frame gets switched off, and a switched-off
  SIEM catches nothing.

  Implemented as a tracing layer rather than calls at each refusal site. Those
  sites already log with the source address as a field, so a layer covers a new
  one by the act of writing its log line — and `processor.rs` is untouched.

- **`event = "..."` on 37 log lines**, so the layers can match a field instead of
  message text. Text matching failed measurably twice while this was being built:
  the first syslog rule set matched 2 of 7 messages in `processor.rs`, and the
  first audit rule set matched 6 of 22 — missing `all recv workers exited —
  datapath is dead`, the most serious line in `server.rs`.

- **The node keeps its own audit chain** — `[observability] node_audit_path`.
  Persistent when set: the existing chain is replayed and verified on startup and
  fails closed on a break. Start and stop events go here as well as to syslog —
  the chain survives the restart they describe, and syslog puts them where a
  compromised node cannot reach them.

- **Per-tenant metric cardinality is capped** at 100 series per family, with the
  tail aggregated into `__other` and `turna_tenant_series_omitted` reporting how
  many. Five families carried an unbounded `tenant` label: ten thousand tenants
  meant fifty thousand series per scrape per node.

  The tail is aggregated rather than dropped so sums still reconcile, and the
  truncation is itself a metric so it can be alerted on rather than discovered.

- **Correlation metadata** — `x-turna-correlation-id` on management RPCs, logged
  and carried into audit entries. Metadata rather than a proto field: adding one
  to sixteen request messages is sixteen chances to burn a field number
  permanently, and this contract already carries `reserved 1 to 4` from that.

- **`turna_dtls_handshake_failures_total` and
  `turna_dtls_rejected_rate_limit_total` are now exported.** Both counters existed
  and were filled by the node; neither reached `/metrics`. A metric present in a
  struct and absent from the endpoint is invisible in the same way a missing one
  is, and worse — somebody reading the struct concludes the signal is available.

- **`[turn.relay] drain_timeout_secs`**, and the drain loop now exits early when
  three consecutive polls remove nothing. A node holding allocations whose clients
  vanished paid the full 30 seconds waiting for expiries that could not happen
  inside the window; measured after: 1 second.

- **`[observability] log_allocation_addresses`** — named for its scope. It covers
  the three per-allocation INFO lines in the relay and nothing else. Ten WARN
  lines in the transports also carry an address and are deliberately outside it:
  all ten are refusals, so the volume is bounded by attacks rather than traffic,
  and the address is the most useful part of a refusal.

### Added — verification

- `scripts/verify/dtls-demux.sh` — nine checks on the DTLS demux path, producing
  the recorded run the default-flip decision was missing.
- `scripts/verify/mixed-load.sh` — UDP and TURNS at once, each measured alone
  first at the same rate so the mixed result is a delta.
- `scripts/verify/capacity-profile.sh` — finds the packet-rate ceiling by
  doubling until failure, then bisecting.
- `scripts/verify/capacity-regression.sh` — compares against a per-machine
  baseline, keyed on CPU model, core count and kernel rather than hostname.
- `scripts/verify/rotation-under-load.sh` — certificate rotation with media
  flowing.
- `scripts/verify/deployment-compliance.sh` — checks a live deployment against
  `docs/security/security-profile.md`.
- `scripts/verify/reproducible-build.sh` — builds twice in directories of
  different length and compares. Refuses to run on macOS, where `LC_UUID` makes
  it impossible.
- `scripts/offline-bundle.sh` and `scripts/offline-upgrade-bundle.sh`.
- `scripts/support-bundle.sh` — redaction by default; addresses hashed with a
  per-bundle salt that is discarded.
- `scripts/forecast.py` — hardware forecast from the measured ceiling.
- `tools/browser-probes/connectivity-check.html` — client-side diagnosis, one
  file, no dependencies.
- `deploy/grafana/turna-overview.json` — 24 panels, schema 39.
- `tools/sdk/python/turna_sdk.py` — mTLS required by the constructor.

### Verified in this pass

Measured, not argued. Each of these is an observation.

- **112 000 relayed packets/second** on a 32-thread Threadripper 1950X, 120 s,
  zero loss, zero egress drops. Measured twice, identically. The failure above it
  is a cliff, not a slope: 120 000 fails and 128 000 sheds a million frames in two
  minutes. There is no warning band.
- **DTLS demux path: 9 of 9.** Relays 21 612 frames with 12 concurrent sessions,
  reloads certificates live (0 → 1, no failures), and the per-IP handshake rate
  limiter refused 15 handshakes before any DTLS state was created. Both §7 P0
  requirements that the stock path cannot provide.
- **Mixed UDP + TURNS: no node interference.** Zero loss on both transports in
  both phases, no egress drops.
- **Air-gap: 7 of 7**, re-verified after all of the above.
- **Reproducible builds: 3 of 3** binaries byte-identical from different build
  directories, re-verified.
- **Certificate rotation under load:** counter 0 → 1, no reload failures, 36 021
  frames relayed with zero errors across the swap.
- **Drain with abandoned allocations: 1 second**, down from the full 30-second
  timeout.

### Known limitations — found by the above

- **The shared secret cannot be rotated without a restart.** No signal handler
  (`SIGHUP` is not handled) and `UpdateConfig` carries allocation limits, not the
  secret. So §7's rotation-without-downtime holds for certificates and not for the
  credential a leak would force you to change. Ephemeral credentials expire on
  their own, which softens it; the secret they derive from still needs a restart.

- **`turna_dtls_handshake_failures_total` did not move** when malformed datagrams
  were sent at the DTLS port. Possibly correct — the datagram may be discarded
  before the DTLS state machine engages — but it means that check did not exercise
  the counter, and the counter is documented as honest only on the demux path.

- **The mixed-load result held the wrong thing constant.** Loss was zero
  throughout, and the TLS *generator* sent 17 % fewer frames in the mixed phase
  (72 012 → 60 010) while UDP sent the same (180 060 → 180 059). The node
  delivered everything it was given; the generators were competing for the cores
  they share. Generators on separate hosts would settle it.

- **The DTLS demux path has no 24-hour run.** Nine checks over five minutes say it
  is correct; the stock path holds the default on the strength of a recorded 24
  hours, and correctness is a different claim from stability.

### Documentation — corrections, not polish

- `docs/capacity/threadripper-1950x-2026-08-26.md` — the measured ceiling, the
  curve, and three wrong numbers that preceded it.
- `docs/verification/runs-2026-08-28.md` — every run, and three conclusions of
  mine that the runs overturned.
- `docs/security/security-profile.md` — one hardening checklist instead of a dozen
  scattered documents.
- `docs/security/log-data-audit-2026-08-27.md` and `log-data-audit-transports.md`
  — what the logs contain, including the negative results.
- `docs/deployment/enterprise-network-profile.md` — ports, the proxy matrix, and
  the case where a system HTTP proxy silently prevents WebTransport with zero
  packets reaching the node.
- `docs/deployment/host-tuning.md` — from measurements on this project's hardware,
  with the IRQ and RSS advice marked as not verified here.
- `docs/runbooks/disaster-recovery.md` — and a table of which scenarios have
  actually been rehearsed.
- `docs/SUPPORT-POLICY-OPTIONS.md` — four LTS options priced in work visible in
  this repository, and the observation that turna is 0.3.1, so an LTS channel on a
  0.x version means the version number and the support policy say different
  things.
- **A factor-of-two claim about the capacity figure was removed because it was
  wrong.** `sent ≈ recv` in the profile was read as evidence of a round trip; the
  receive task listens on the peer socket, so it is one traversal. The forecast had
  been doubling — 26 nodes where 13 are needed.

### Also in this release — found while closing out the CI

- **A CodeQL 4.x upgrade surfaced 71 alerts on code that had not changed.** All 71
  are closed by changes to the code rather than by dismissals. Two were real:
  `capacity.yml` had no `permissions` block, and test output printed a working TURN
  password in full. The rest were rules without the context to judge.

  Test credentials now come from the environment (`.env.test`, mirrored in the
  workflow) rather than from literals in the source. Wrapping them in a helper was
  tried first and did not work — CodeQL follows the value through the function.

- **`codeql-action/init` and `analyze` must move together.** Dependabot opens one PR
  per path, and either alone leaves init 4.x reading a database analyze 3.x wrote —
  reported only as `CodeQL job status was configuration error`.

- **A duplicate top-level `env:` key made GitHub reject the CI workflow outright.**
  The run failed in 0 seconds, so the three required checks never appeared and the
  branch ruleset had nothing to wait for. The symptom was a pull request that could
  not be merged for no visible reason.

- `.env.test` is excluded from the container image — not because the values are
  secret, but because a file named `.env` in a container invites the assumption
  that something reads it.


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

[Unreleased]: https://github.com/kruatech/turna/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/kruatech/turna/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kruatech/turna/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/kruatech/turna/compare/v0.3.1-rc.2...v0.3.1
[0.3.0]: https://github.com/kruatech/turna/compare/v0.3.0-rc.2...v0.3.0
[0.3.0-rc.2]: https://github.com/kruatech/turna/compare/v0.3.0-rc.1...v0.3.0-rc.2
[0.3.0-rc.1]: https://github.com/kruatech/turna/compare/v0.3.0-beta.1...v0.3.0-rc.1
[0.3.0-beta.1]: https://github.com/kruatech/turna/compare/v0.2.0-alpha.1...v0.3.0-beta.1
[0.2.0-alpha.1]: https://github.com/kruatech/turna/compare/v0.1.0...v0.2.0-alpha.1
