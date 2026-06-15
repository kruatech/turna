# Security & performance remediation — June 2026

Closeout for the `turna` code audit. Each audit finding maps to its fix, the
files touched, current status, and any residual risk or behavioural change to
be aware of.

## Status summary

All High / Medium / Low findings and the full P-series (P1–P5) are resolved.
The remaining items are optional hardening follow-ups from audit §3 (continuous
fuzzing, model checking, a dependency upgrade), not findings.

## Findings

| ID | Title | Fix | Files | Status | Residual / breaking change |
|----|-------|-----|-------|--------|----------------------------|
| H1 | splice(2) busy-loop on EAGAIN (self-DoS) | Rewrote as an epoll state machine: EPOLLOUT arming, full pipe drain, half-close shutdown, no busy spin | `relay/splice.rs` | Done | None. `splice_relay()` signature unchanged |
| M1 | SSRF — RFC1918/ULA peers allowed by default | `PeerPolicy` + CIDR matcher behind a global `OnceLock`; default profile denies private ranges, LAN relaying is opt-in via `[turn.peer_filter] profile="lan"` | `relay/peer_filter.rs`, `config/lib.rs`, `services/node/src/main.rs`, `docs/security/peer-filter.md` | Done | **Breaking:** default now denies RFC1918/ULA peers. LAN deployments must set `profile="lan"` |
| M2 | `encode*` write without bounds check (panic risk) | `encode` / `encode_value` / `encode_channel_data` return `Result<usize>`; callers use `encode_or_drop!` (drop packet on overflow) | `proto-stun/{message,attribute}.rs`, `relay/processor.rs` | Done | None. Overflow now drops the outbound packet instead of panicking |
| M3 | IP-ban-after-N-failures wired nowhere (dead) | Removed the orphaned module | `auth/rate_limit.rs` (deleted) | Done | None (was never reachable) |
| M4 | Plain-TLS management plane on public addr w/o client auth | Config validation gate; gRPC already enforces mTLS when TLS is configured | `config/lib.rs`, `control/grpc.rs`, `docs/security/management-tls.md` | Done | Config now rejects TLS-mode management on a public address without mTLS |
| L1 | Dead timing-unsafe password compare | Deleted the dead `verify_turn_credentials` (kept `generate_turn_credentials`, no vuln) | `crypto/lib.rs` | Done | None |
| L2 | No minimum JWT HS256 secret length | Reject secrets < 32 bytes in `sign_jwt`/`verify_jwt` | `auth/jwt.rs` | Done | A short secret now errors (`InvalidKeyFormat`) at both boundaries. `aud` skipped — the second (oauth) stack was removed in L3 |
| L3 | Two parallel auth stacks (oauth dead) | Removed the orphaned oauth module | `auth/oauth.rs` (deleted) | Done | None |
| L4 | splice loses bytes/stats at the boundary | Folded into the H1 rewrite (full drain, accurate accounting) | `relay/splice.rs` | Done | None |
| L5 | Global (non-per-client) rotating nonce | Documented as accepted risk (MESSAGE-INTEGRITY mandatory; ≤30s reuse window; RFC-permitted) | `docs/security/threat-model.md` | Accepted | Revisit only if per-client nonce isolation becomes a requirement |
| L6 | Bandwidth-limit window not enforced on roll | `check_bandwidth` now enforces the completed window (returns `Err` when over quota); roll is a single critical section | `session/lib.rs` | Done | Slightly stricter: a boundary packet over quota is now dropped (was allowed) |
| P1 | Copy on the "zero-copy" io_uring/AF_XDP path | `Action::ForwardZeroCopy { offset, len }` forwards straight from the registered recv buffer (existing `ZeroCopyViaRelay` worker path); tokio path unchanged | `relay/processor.rs`, `relay/handler.rs`, `relay/server.rs`, `services/node/src/af_xdp_listener.rs` | Done | Kill switch `TURNA_URING_ZEROCOPY_FORWARD=0`. **Must build + bench under `io-uring`/`af-xdp` on Linux.** Holds recv buffers slightly longer — watch the buffer pool under soak |
| P2 | Two `Instant::now()` + histogram per packet | Sampled timings (`should_sample`), default `TURNA_LATENCY_SAMPLE_N=1` (unchanged); operators raise N under load | `relay/processor.rs` | Done | Default behaviour identical; histograms become sampled estimates when N>1 |
| P3 | DashMap `Ref` held over RTP analysis/metrics | Capture fields, `drop(alloc)` before `analyze()`/metrics in `process_relay_recv` | `relay/processor.rs` | Done | None (pure reorder) |
| P4 | Mutex token bucket on the hot path | Lock-free: `DashMap<IpAddr, AtomicTokenBucket>`, single-`AtomicU64` CAS bucket; denied packets are read-only | `qos/lib.rs`, `qos/Cargo.toml` | Done | **Validate with loom + bench before merge.** Standalone `RateLimiter` (HashMap) intentionally unchanged. Entry cap is now soft under concurrency |
| P5 | Double limiter pass (per-IP + per-prefix) on ChannelData | ChannelData uses per-IP-only `check_ingress_ip`; STUN keeps the full gate | `relay/processor.rs`, `qos/lib.rs` | Done | Per-prefix aggregate protection no longer applied to the media path (established sessions are bounded by the bandwidth quota; unknown sources drop at allocation lookup) |

## Incidental fixes

- `transport/bpf_filter.rs` test corruption offset (`bad[4]` → `bad[12]`): the test mutated the UDP header, not the STUN magic cookie. Pre-existing test bug, not introduced by remediation.
- `qos` `unexpected_cfgs` warning for `cfg(loom)`: added a `check-cfg` lint so `-D warnings` CI stays green.

## Hardening follow-ups (audit §3)

| Item | What ships now | What remains (owner action) |
|------|----------------|------------------------------|
| Continuous fuzzing of `encode` | `fuzz/fuzz_targets/fuzz_encode.rs` + Cargo bin + CI smoke entry (catches the M2 class) | Let nightly fuzz accumulate corpus |
| Model checking | `qos` token-bucket loom model; `relay` nonce-rotation loom model; `miri` + `loom` CI jobs | Run them on Linux/nightly; for the *production* `NonceManager`, inject the clock to model the struct directly |
| RUSTSEC ignores | Resolved — `tonic` upgraded to 0.14 (codegen → `tonic-prost-build`, TLS API moved); `deny.toml` advisory ignores removed and `cargo deny check advisories` is green | `rustls-pemfile` (RUSTSEC-2025-0134, unmaintained) is **not** fully removed: it remains a direct dep of `turna-transport` (`tls`/`quic` PEM parsing) and transitive via `wtransport` (`web-transport`), so it cannot be dropped while QUIC/WebTransport are offered. cargo-deny does not surface the unmaintained advisory under the current config. Planned cleanup: migrate PEM parsing to `rustls-pki-types` |

## Verification checklist

- `cargo build --workspace --tests` and `cargo test --workspace` — green.
- Under features: `cargo build --features io-uring` and `--features af-xdp` on Linux (P1 paths are `cfg`-gated and not built by default).
- `RUSTFLAGS="--cfg loom" cargo test -p turna-qos --lib loom_bucket` and `-p turna-relay --test loom_nonce`.
- `cargo +nightly miri test -p turna-proto-stun -p turna-packet`.
- `cd fuzz && cargo +nightly fuzz run fuzz_encode -- -max_total_time=60`.
- Relay benches (`bench/`, `tools/benchmark` → `RESULTS.md`) before/after for P1 and P4.
