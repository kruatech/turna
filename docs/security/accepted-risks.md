# Accepted risks

Security/maintenance risks consciously accepted for the current release, with
their compensating controls and a review point. This is a living register;
each entry is revisited at the version named under "Review by".

## RISK-001 — `rustls-pemfile` reachable only via the opt-in `web-transport` feature

- **Status:** **resolved** — `rustls-pemfile` is no longer in the dependency graph
  at all, including with `--features web-transport`
  (`cargo tree -p turna-transport --features web-transport -i rustls-pemfile`
  reports no matching package). `wtransport 0.7.1` dropped it.
- **Description:** `rustls-pemfile` is flagged unmaintained
  (RUSTSEC-2025-0134; the upstream repository was archived in August 2025).
- **Why it stays:** the direct dependency was removed — `turna-transport` now
  parses PEM via `rustls-pki-types` under the `tls`/`quic` features. The only
  remaining occurrence is transitive, through `wtransport` under the
  opt-in `web-transport` feature. `wtransport 0.6.1` still depended on it, so
  no dependency bump removed it at the time; the workspace has since moved to
  `wtransport 0.7.1`, which does not.
- **Compensating controls:** `cargo deny check advisories` is green because the
  default graph does not enable `web-transport`, so the crate is not in release
  builds; the PEM surface only touches operator-supplied certificate files at
  startup; the advisory is tracked here rather than ignored silently.
- **Planned remediation:** done — `wtransport` migrated off `rustls-pemfile`
  upstream. If `web-transport` is ever pinned back to a 0.6.x release the risk
  returns; the `Cargo.lock` check above is what to re-run.
- **Review by:** closed.

## RISK-002 — duplicate dependency versions (previous gRPC/HTTP generation)

- **Status:** resolved in `0.2.0-alpha.1`.
- **Description:** the workspace previously shipped two generations of the
  gRPC/HTTP stack (`tonic` 0.11 + 0.14, `axum` 0.6 + 0.8, `hyper` 0.14 + 1,
  `http` 0.2 + 1, `prost` 0.12 + 0.14, `thiserror` 1 + 2, …), with the old
  generation pulled entirely through `opentelemetry-otlp 0.16 → tonic 0.11`.
- **Resolution:** the OpenTelemetry crates were upgraded to `0.32`
  (`opentelemetry-otlp` on `grpc-tonic` → `tonic 0.14`, `prost 0.14`, `http 1`,
  `hyper 1`; `tracing-opentelemetry 0.33`), collapsing the previous generation.
  `tonic` now resolves to a single major (`0.14.x`), and the
  `opentelemetry-otlp` `skip-tree` has been removed from `deny.toml`.
- **Residual:** only benign minor-version multiplicity remains (`socket2`
  0.5/0.6, `hashbrown`, `getrandom`, plus dev-only `proptest`/`criterion`
  trees); tracked in `docs/security/dependency-dedup.md`.
- **Review by:** closed; residuals tracked in the dedup roadmap.

## RISK-003 — LGPL branch in the `af-xdp` dependency graph

- **Status:** accepted, mitigated by licence election.
- **Description:** `libxdp-sys` and the C libraries it binds (`libxdp`, `libbpf`)
  are offered under `LGPL-2.1 OR BSD-2-Clause`. It is the only crate in the
  workspace that brings an LGPL branch into the graph, and it arrives solely
  through the `af-xdp` feature.
- **Aggravating factor found 2026-08-13:** the declared SPDX string uses the
  **deprecated** identifier `LGPL-2.1`, which cargo-deny cannot parse — it
  degraded to a warning, so this crate's licence was effectively **not being
  checked** at all. It only became visible once `deny.toml` moved to
  `all-features = true`.
- **Mitigation:** Turna elects the permissive branch, `BSD-2-Clause`, pinned
  explicitly via `[[licenses.clarify]]` in `deny.toml` so the check is real and
  the election is machine-readable. Recorded for audit in `docs/COMPLIANCE.md` §6.
  `af-xdp` is absent from the default build and is Linux-only; explicitly enabled
  production builds must retain the license election and required notices.
- **Planned remediation:** none needed while the election holds. If a binary is
  shipped with `--features af-xdp`, add the BSD-2-Clause notice for
  `libxdp`/`libbpf` to `NOTICE`.
- **Review by:** each release shipping `af-xdp`; copy-mode support promotion does
  not replace dependency/license checks or the notice requirement above.

## RISK-006 — the DTLS stack is a maintained copy, not a tracked dependency

- **Status:** accepted; applies only when `[turn.dtls] enabled = true`.
- **Description:** `crates/dtls` is webrtc-dtls 0.10.0 brought into the tree and
  modified (MIT OR Apache-2.0; origin and changes recorded in
  `crates/dtls/src/lib.rs` and `NOTICE`). It is not pinned to upstream and does
  not receive upstream's fixes. A security fix published for webrtc-dtls, or for
  pion/dtls which it ports, will not reach this copy unless somebody carries it
  across.
- **Why it stays:** turna validates the client's address statelessly before
  allocating anything — a ClientHello without a cookie this node issued is
  answered with a HelloVerifyRequest and no state is kept. The upstream crate
  performs that exchange inside the connection, after the allocation, and
  exposes no way to say the address is already proved: `flight0` generates its
  own random cookie, `flight2` compares against it, and an externally issued
  cookie can never match. Handing it a stripped ClientHello fails too, because
  that message carries `message_seq = 1` while `full_pull_map` demands an exact
  match. Both were observed on the wire. Closing the amplification hole
  therefore required a change to the handshake state machine, which cannot be
  made from outside the crate.
- **Compensating controls:** the modification is small and localised (five
  files, each marked); the flag it adds is dangerous alone and is set in exactly
  one place, behind the address gate; `max_pending_handshakes` remains as a
  backstop; the DTLS path is opt-in and off by default.
- **Planned remediation:** offer the change upstream as pion/dtls's
  `InsecureSkipVerifyHello` equivalent. If it lands, this copy can go back to
  being a dependency.
- **Review by:** whenever webrtc-dtls or pion/dtls publishes a security
  advisory, and at each turna release while DTLS is enabled anywhere. Check
  https://github.com/webrtc-rs/webrtc and https://github.com/pion/dtls.

## RISK-004 — gossip replay survives a node restart

- **Status:** accepted for the experimental cluster mode; not applicable to a
  standalone node, which runs no gossip.
- **Description:** gossip frames are signed with HMAC-SHA256, so forgery needs
  the cluster secret. Replay of a captured frame is bounded only by
  `seq > node.seq`, and `seq` starts at 0 on process start
  (`crates/cluster/src/gossip.rs:138`). After a restart a node accepts any
  captured frame with a higher `seq` — including a `leaving`, which evicts a live
  node from the ring and plants a tombstone suppressing it for
  `gossip_interval_secs × 3`.
- **Why it stays:** the attack needs a position on the gossip network, which is
  a private segment by deployment requirement, and cluster mode is marked
  experimental in the README. The fix touches the wire format, which is not worth
  changing while the mode is experimental and the deployment guidance already
  excludes the exposure.
- **Compensating controls:** the cluster secret is mandatory and validated in
  production; `docs/CLUSTER.md` states the private-network requirement under
  Limitations; an evicted node rejoins on its next gossip interval, so the
  impact is a bounded balancing disruption rather than a lasting one.
- **Planned remediation:** include a per-process `boot_id` in the signed payload
  and accept `seq` monotonically within a `boot_id`, so a new boot resets the
  counter without accepting the previous boot's frames. Alternatively a
  timestamp with a bounded acceptance window.
- **Review by:** whenever cluster mode leaves experimental status.

## RISK-005 — Tarantool iproto is plaintext

- **Status:** accepted; not applicable to the standalone `memory` backend, which
  is the default.
- **Description:** `tcp_connect_and_auth` in
  `crates/state-backend/src/tarantool.rs` speaks iproto over plain TCP.
  Authentication is chap-sha1, so the password is not sent in the clear, but the
  allocation records are — and those carry client and peer addresses.
- **Why it stays:** turna does not implement iproto over TLS, and the standard
  deployment for a state backend is a private network. Adding a TLS iproto
  client is a larger change than the exposure justifies while the deployment
  requirement covers it.
- **Compensating controls:** backend credentials are required and never logged;
  `docs/CLUSTER.md` states the requirement under Limitations; stunnel or
  WireGuard in front of the backend closes it without changing turna.
- **Review by:** whenever cluster mode leaves experimental status.

## RISK — active-session HA remains experimental

**Scope:** multi-node gossip/redirect/failover tooling.
**Accepted boundary:** GA does not promise relay-socket rehydration, preservation
of the old relay IP, conflict-free relay-port adoption, or media continuity after
owner death. Durable metadata is not equivalent to a live socket.
**Mitigation:** canonical production deployment is standalone-first, one public
IP/range per node; use drain for planned maintenance, monitor remaining
allocations, and treat cluster StatefulSet mode as experimental.
**Exit condition:** a separately verified socket/port ownership protocol and
end-to-end media continuity tests across process/node death.

## RISK-007 — auto-ban's rate-limit trigger can be aimed at a victim by spoofing

- **Status:** accepted, and **off by default** (`[turn.auto_ban]
  rate_limit_violations = 0`). The auth-failure trigger does not carry this risk.
- **Description:** with `rate_limit_violations > 0`, a source is banned after
  that many rate-limiter refusals in the window. Rate limits refuse raw packets,
  and a UDP packet can carry any source address, so an attacker able to spoof
  can flood with a victim's address and get the victim banned for `ban_secs` —
  a customer, a partner's NAT, a monitoring probe.
- **Why it is offered anyway:** where spoofing is filtered upstream (BCP 38 on
  the provider edge, or a node reachable only through a load balancer that
  terminates the path), it bans flooders that never attempt authentication,
  which the auth-failure trigger cannot see.
- **Compensating controls:** off by default; config validation warns when it is
  enabled; `allowlist` and `exempt_trusted_prefixes` keep an operator's own
  ranges out of reach; bans expire on their own; every ban is a
  `SOURCE_BANNED` syslog event with the reason, so a mistaken ban is visible.
  The auth-failure trigger counts only requests behind a valid client-bound
  NONCE (a completed round trip), and Binding requests with bad
  MESSAGE-INTEGRITY — which skip the nonce — are deliberately not counted.
- **Review by:** if a cluster-wide ban table is ever added, since that would
  multiply the reach of a forged ban across nodes.

## RISK-008 — auth webhook: cached credentials outlive revocation, and uncached users depend on the endpoint

- **Status:** accepted; applies only with `[turn.auth.webhook] enabled = true`
  (off by default).
- **Description:** (1) a user's keys are cached for up to `positive_ttl_secs`
  (default 300 s, capped per answer by the endpoint's `ttl_secs`), so a user
  removed or re-keyed in the signalling service can still authenticate against
  this node until the entry expires, and an allocation already granted runs to
  its own lifetime; (2) a user not in the cache cannot allocate while the
  endpoint is down or slow — requests fail closed with `500` for
  `error_ttl_secs` at a time; (3) the first request of an uncached user over
  UDP costs one client retransmission interval, and over QUIC/WebTransport
  streams it is not answered at all (the client's transaction timeout applies).
- **Why it stays:** caching is what keeps the endpoint off the per-request
  path; failing closed is the only safe default for an authentication decision;
  the retransmission cost follows from never blocking the synchronous datapath.
- **Compensating controls:** TTLs are configurable down to one second and the
  endpoint can shorten them per user; `turna_auth_webhook_errors_total` and
  `turna_auth_webhook_unavailable_total` with alert rules make an outage
  visible; static users keep working throughout; TURNS and SCTP requests are
  re-processed rather than left to time out.
- **Review by:** when QUIC stream re-processing is added, or if a revocation
  push channel is ever introduced.

