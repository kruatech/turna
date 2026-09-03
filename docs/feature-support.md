# Feature & RFC support

What turna implements today and at what maturity. The goal is to set accurate
expectations rather than imply everything is production-grade.

> Maturity labels below are derived from the project's Status notes, the Cargo
> feature set, and the implemented data paths. **Maintainer: confirm/adjust the
> labels** — extend the table for any RFC/feature not yet listed rather than
> leaving a guess in place.

| Feature / RFC                              | Status                  | Notes |
| ------------------------------------------ | ----------------------- | ----- |
| STUN Binding (RFC 5389)                    | stable                  | Core protocol. |
| TURN relay over UDP (RFC 5766 / RFC 8656)  | stable                  | Default tokio data path. |
| Long-term credentials (RFC 5389/5766)      | stable                  | HMAC-SHA1; realm/nonce. |
| Shared-secret auth                         | stable                  | HMAC; secret via env/Secret. |
| Connection migration / mobility (RFC 8016) | partial                 | Tickets issued and re-issued, ReKey + migration epoch persisted — that path is wired and works. **Cross-node** migration is **unwired**: `relay/src/node_migration.rs` has no callers, so no allocation is ever transferred to another node. Treat as same-node only. |
| TLS over TCP (`tls`)                        | **supported**                    | Feature-gated. Metrics, per-IP cap, cert hot-reload, cooperative drain, accept-error resilience. **Interop re-verified against the current code** (`docs/interop/turns-browsers-2026-08-18.md`): Chrome 151 / Firefox 153 / Safari 26.5 — relay candidate, negative auth on two rejection paths, bidirectional relayed data, and `relayProtocol: tls` confirming TURNS on the two engines that expose it. Server side: no connection or allocation leak, zero handshake or framing failures. Per-IP handshake **rate** limit and opt-in ALPN strict mode are in. **Supported.** Both remaining gaps are closed: a **24 h soak against this code** (`docs/soak/endurance-24h-2026-08-22.md`) — 9.6 h of relayed media at zero loss, 4.8 h of allocation churn at 441/s, no leak on RSS, descriptors, threads or allocations, every error counter flat — and a run against a **public Let's Encrypt chain** on a real deployment, validated by `openssl s_client -verify_return_error` (`Verify return code: 0`) rather than by the load client, which accepts any certificate by design. mTLS is verified too, including the case that carries it: a client with no certificate is refused when `require_client_cert = true`. |
| TURN over TCP relay (RFC 6062)             | beta, **no longer refused in production** | Implemented over TURNS (CONNECT / ConnectionBind / peer-initiated listener, ownership-bound binds). **Interop verified twice**: our own client exercised both the plain form and the one that pipelines the first application bytes into the same write as `ConnectionBind` — the case RFC 6062 §5.4 permits and the reason the detach prebuffer in `transport::tcp_tls` exists (`docs/interop/transports-2026-08-19.md`) — and coturn's `turnutils_uclient` then agreed about the wire (`docs/interop/coturn-2026-08-23.md`). The `production = true` refusal was lifted on 2026-08-25 once that second implementation was on record. **Size for it before enabling:** a listener and a connection per relayed peer, which is a different operational profile from UDP relaying, and the gate no longer makes that decision for you. Still IPv4-only — an IPv6 TCP allocation answers 440. |
| DTLS (`dtls`)                               | beta                    | Feature-gated. Fail-fast, session + per-IP caps, idle reaper, bounded egress, MTU enforcement, drain, metrics. **Allocation and relayed media verified** (`docs/interop/transports-2026-08-19.md`) on **both** listener paths (`demux = true`, the default since 2026-09-01, and `demux = false`, the stock listener): handshake, 401, authenticated Allocate, CreatePermission, ChannelBind, and media in both directions. **Interop against coturn's `turnutils_uclient`** (`docs/interop/coturn-2026-08-23.md`): 40/40 messages relayed over DTLS by a client written by other people, in another language, from an independent reading of RFC 7350 — the condition DTLS was missing. Plus 20 minutes under load at zero loss (`docs/soak/transport-load-2026-08-23.md`). The earlier record was a transport handshake only. Missing: handshake rate limiting (runs below `accept()`), cert hot-reload. **Serially-accepted handshakes** on the default path — `webrtc-dtls` runs each handshake inline inside `accept()` with no timeout (webrtc-rs/webrtc#614); `accept_timeout_secs` bounds it so one silent peer cannot park the listener forever. `[turn.dtls] demux = true` (**the default since 2026-09-01**, verified 2026-08-28 — `scripts/verify/dtls-demux.sh`, 9 checks of 9) owns the UDP socket instead: concurrent handshakes, pre-handshake admission, per-IP handshake rate limit, certificate hot-reload, and observable handshake failures. Measured on that path: 21 612 frames relayed across 12 concurrent sessions with zero errors, certificate reloaded live (0 → 1, no failures), and the limiter refusing **15 handshakes before any DTLS state was created**. The two things listed above as missing from the stock path are therefore available on the default one. The 24-hour run the stock path's claim rested on now exists for demux too (`docs/soak/soak-24h-dtls-2026-09-01.md`): eleven DTLS cycles identical to three significant figures, a spread of 16 frames in 1.7 million, zero egress drops, and the node exiting cleanly on SIGTERM. Still absent: a real NIC — handshakes over a network lose packets, which is where a demultiplexer is most likely to differ from a listener that owns its socket. |
| QUIC (`quic`)                               | beta                    | Feature-gated. Raw-QUIC datapath: per-stream control replies, session + per-IP caps, handshake rate limit, cert hot-reload, drain, full `[turn.quic]` config. **Interop recorded including relayed media** (`docs/interop/relayed-media-2026-08-19.md`): handshake, 401, Allocate, CreatePermission, ChannelBind, 20/20 frames client→relay→peer, and the peer's reply returned as ChannelData on the same stream. Remaining for stable: sustained load (the soak harness is UDP-only) and an independent client implementation. |
| WebTransport (`web-transport`)             | beta                    | Feature-gated. Browser H3 path; pre-handshake admission, cert hot-reload, per-stream replies and the `[turn.quic]` transport limits all apply. **Browser interop recorded** (`docs/interop/webtransport-browser-2026-08-20.md`): Chrome 151 against a Let's Encrypt certificate — session, control stream, authenticated Allocate, ChannelBind and relayed media returned as a datagram, with every STUN byte, the MD5 key and the HMAC assembled in browser JavaScript rather than by the server's own library. Remaining: `alpn` inert (wtransport forces `h3`), no endurance driver, and one engine only — Firefox and Safari do not implement WebTransport. |
| TURN-over-SCTP (`sctp`)                    | **refused in production, not being matured** | No RFC defines SCTP for TURN; this is a client *control* transport only (relay stays UDP), and the control channel is **plaintext** — anything you would protect with TURNS is unprotected here. Needs the host `sctp` kernel module. `production = true` rejects `[turn.sctp].enabled`. There is no plan to promote it: it has none of the hardening the other listeners got (no per-IP cap, no rate limit, no `turna_sctp_*` metrics, no readiness gauge, no cooperative drain) and no users. Usable for testing with `production = false`. |
| Third-party authorization (RFC 7635 OAuth) | **refused in production** | AEAD access tokens, `kid` key selection, §6.1 lifetime capping implemented. `production = true` rejects `[turn.auth.oauth].enabled`. |
| IPv6 relayed transport (RFC 6156 / 8656)   | beta                    | **Relayed media verified on routable addresses** (`docs/interop/relayed-media-2026-08-19.md`): 6 010 of 6 010 frames between two global v6 addresses, zero loss, p99 0.5 ms, with the peer filter in its `lan` profile and no loopback concession. Earlier runs used `::1` and a ULA. Remaining: routing between different hosts, and `ADDITIONAL-ADDRESS-FAMILY` (one Allocate, both families) which is blocked on a storage decision, not protocol work. | **Conformance recorded** in both configurations (`docs/interop/conformance-2026-08-18.md`): 440 when unset, IPv6 relayed address when set, 443 both directions, and the v4-embedding transition prefixes denied. Opt-in with `[turn] external_ip6`: the relay socket binds in the requested family and the matching address is advertised. One family per allocation — a cross-family peer gets **443** (Send indications are dropped and counted). Unset → **440**, as before. IPv6-specific peer-filter classes are in (NAT64 / 6to4 / Teredo / IPv4-compatible are denied, so the v4 deny rules cannot be bypassed via a v6 literal), and DONT-FRAGMENT uses the v6 socket option. The v6 relay socket is bound `IPV6_V6ONLY`, so a v6 allocation cannot straddle both families at the socket. Not implemented: `ADDITIONAL-ADDRESS-FAMILY` (blocked on a storage decision — `docs/design/additional-address-family.md`) and IPv6 for RFC 6062 TCP relay. No interop evidence. |
| NAT behaviour discovery (RFC 5780)         | **not implemented**     | No codec in the tree — an earlier "codec complete" claim here was wrong (grep for CHANGE-REQUEST / OTHER-ADDRESS / RESPONSE-ORIGIN returns nothing). The service would also need a 2×IP / 2×port topology this deployment model does not have. |
| ALPN (RFC 7443)                            | partial                 | `stun.turn` advertised on TURNS; strict vs compatible mode not implemented, and ALPN over DTLS is unverified. Inert on the WebTransport path (wtransport forces `h3`). |
| Shared-secret ("TURN REST") credentials    | compatibility           | coturn-compatible, based on an **expired draft** — not an RFC. Secret rotation overlap and skew window unverified. |
| io_uring data path (`io-uring`)            | beta, Linux-only         | Compile-gated; kernel-dependent. **Endurance and relaying both recorded** (`docs/soak/endurance-2026-08-19.md`) on Ubuntu 24.04 / kernel 6.14: 3 h, 58.5 M allocations, 702 M packets, no leak, clean drain, ~4× tokio's Allocate throughput at 1/20th the tail latency; ChannelData relaying 935 340 + 962 843 frames with zero errors at ~17 000 rps, p99 5 ms. Costs ~28× tokio's resident memory (1032 MiB vs 37 MiB) — pre-registered ring buffers, fixed at startup. A relay-slot leak that made it forward nothing was found and fixed by this run. Remaining before `supported`: a run on the kernel *you* deploy, since io_uring behaviour is version-sensitive. |
| AF_XDP data path (`af-xdp`)                | beta (lab-verified), Linux-only | Kernel-bypass; requires NIC/kernel support and root. **Verified correct on a veth lab** (`docs/interop/af-xdp-2026-08-19.md`): conformance plus relayed media at three rates, 7123 frames, zero loss, ARP/NDP answered by the datapath, peer filter enforced. That run found and fixed an RX frame leak that capped reception at exactly the pool size (2015 frames) — the same shape as the io_uring slot leak found the same day. **Not a capacity result:** veth attaches in SKB mode, so every frame is copied and none of the kernel-bypass benefit is present. Validate on the target NIC before enabling. |
| Runtime user CRUD (`AddUser`/`RemoveUser`) | supported (needs mgmt backend) | Requires the Tarantool management backend; unavailable on an in-memory backend. |

Default builds use the tokio UDP data path; everything marked *experimental*,
*beta* or *refused in production* is opt-in via Cargo features.

- **Supported** — verified end to end, and the behaviour does not depend on the
  kernel or hardware underneath. TURNS is here: browser interop across three
  engines, a Let's Encrypt chain validated by a verifying client, agreement with
  coturn's client, and 24 h under load with zero relayed-frame loss.
- **Beta** — hardening done in source (limits, metrics, readiness, graceful drain,
  fail-fast startup) and runs recorded against the current code, but with a caveat
  stated per transport in the Notes column. Two kinds of caveat occur:
  - *environment-dependent* — `io-uring` and `af-xdp` are verified on named kernels
    and, for AF_XDP, only on a veth lab in SKB mode. Verify on yours.
  - *no independent implementation* — this now applies to **QUIC alone**, and
    structurally: no RFC defines TURN over raw QUIC, so no second implementation
    exists and none can be written against a specification that does not exist.
    DTLS left this group via coturn, WebTransport via a browser.
- **Experimental** — functional gaps remain, not just missing test evidence.
- **Refused in production** — the strongest signal: `config::validate()` rejects
  the feature outright when `production = true`, so it cannot ship by accident.
  Usable for testing with `production = false`.
- **Partial** — the protocol element exists but not the whole feature; the note
  says what is missing. `docs/protocol-gap.md` is the authoritative register and
  states, per feature, what each `partial` needs to become stable. The Linux-only data paths do not build on macOS (see the
`af-xdp`/`io-uring` notes in `CONTRIBUTING.md`).

## GA management feature matrix

| Capability | Source status | Verification required before GA |
|---|---|---|
| Node-targeted `update_config` | implemented | workspace + live update/restart |
| Durable desired/observed config | memory + Tarantool implemented | clean/upgrade/outage tests |
| Global/tenant/user limits | implemented | concurrency + restart + packet tests |
| Atomic allocation reservations | implemented | race/rollback/rehydrate tests |
| Admin config/limits UI | implemented | npm build + container smoke + live CP |
| Standalone Helm profile | implemented | lint/render/kubeconform + live deploy |
| `SetDraining` (drain/undrain) | implemented | drain/leaving + grace deadline tests |
| `DeleteAllocation` | implemented | idempotent not-found retry test |
| Idempotent management retry | implemented + covered by tests | lost-completion + replay tests |
| Restart restore (config + limits) | implemented + covered by tests | clean/upgrade/outage runs |
| Per-allocation bandwidth enforcement | implemented + covered by tests | two-allocation independence test |
| Audit log (tamper-evident) | implemented | fail-closed on unhealthy audit |
| Transparent active-session HA | not GA | future milestone; media path does not migrate |

“Implemented” here is a source-level statement, not a claim that the current
working tree has passed the release verification commands.
