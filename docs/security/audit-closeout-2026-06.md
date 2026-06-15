# Security & robustness audit closeout — June 2026

Consolidated status for the two remediation passes:

- **Audit 1** — security + performance review (`turna-audit.md`).
- **Audit 2** — operational / robustness review (round 2).

Each finding below links to the delivery that closed it. "Delivery N" is the
Nth remediation archive applied to the tree; archive names are given in the
last column. Verification commands assume the archives have been unpacked at
the workspace root.

Status legend: **Fixed** (code + tests), **Fixed (doc)** (mitigated /
documented, code change blocked upstream), **Accepted** (residual risk
acknowledged), **Mechanism** (fix landed; one wiring step deferred to a feature
that is not yet integrated).

---

## Audit 1 — security + performance

| ID | Finding | Status | Resolution | Delivery |
|----|---------|--------|------------|----------|
| H1 | Relay splice busy-loop on a full/empty pipe | Fixed | epoll-driven state machine in `relay/splice.rs` | 1 — `turna_h1l4_splice_01` |
| L4 | Splice could lose bytes on partial transfer | Fixed | same state machine tracks in-flight bytes | 1 — `turna_h1l4_splice_01` |
| M2 | `encode*` could panic on malformed input | Fixed | `encode*`→`Result`; `encode_or_drop!` at all call sites | 2 — `turna_m2_encode_result_02` |
| M1 | SSRF: relay would forward to RFC1918 / link-local peers | Fixed | `PeerPolicy` peer-filter + `[turn.peer_filter]` config | 3 — `turna_m1_peer_policy_03` (+ 4 config) |
| M3 | Dead IP-ban path (rate_limit) | Fixed | removed dead module | 4 — `turna_m3m4l3_authclean_mtls_04` |
| M4 | Management plane allowed plaintext | Fixed | mTLS (server cert + client CA) on the gRPC plane | 4 — `turna_m3m4l3_authclean_mtls_04` |
| L3 | Dead OAuth path | Fixed | removed dead module | 4 — `turna_m3m4l3_authclean_mtls_04` |
| L1 | Dead timing-unsafe credential compare | Fixed | removed unused `verify_turn_credentials` | 5 — `turna_l1l2_crypto_jwt_05` |
| L2 | No minimum JWT secret length | Fixed | `MIN_HS256_SECRET_LEN = 32` enforced | 5 — `turna_l1l2_crypto_jwt_05` |
| L6 | Bandwidth window not enforced on roll | Fixed | enforce-on-roll in `session::check_bandwidth` | 6 — `turna_l6_bandwidth_window_06` |
| L5 | Process-global nonce | Accepted | documented in threat-model; per-realm rotation is the upgrade path | 6 — `turna_l6_bandwidth_window_06` (doc) |
| P2 | Two `Instant::now()` per packet | Fixed | sampled histograms (`TURNA_LATENCY_SAMPLE_N`) | 7 — `turna_p2p3p5_hotpath_07` |
| P3 | DashMap `Ref` held across analysis | Fixed | drop allocation before analyze | 7 — `turna_p2p3p5_hotpath_07` |
| P5 | Double rate-limiter pass | Fixed | per-IP ingress check only for ChannelData | 7 — `turna_p2p3p5_hotpath_07` |
| P1 | Userspace copy on the io_uring path | Fixed | `Action::ForwardZeroCopy`; kill-switch `TURNA_URING_ZEROCOPY_FORWARD` | 8 — `turna_p1_zerocopy_forward_08` |
| P4 | Mutex token-bucket on the hot path | Fixed | lock-free `ShardedRateLimiter` (CAS, packed atomic) | 9 — `turna_p4_lockfree_limiter_09` |
| — | Test/observability debt | Fixed | fuzz target, miri + loom jobs, CI, closeout doc | 10 — `turna_archdebt_fuzz_loom_ci_10` |

---

## Audit 2 — operational / robustness

| ID | Finding (as reported) | Finding on inspection | Status | Resolution | Delivery |
|----|------------------------|------------------------|--------|------------|----------|
| #6 | `cleanup_expired` blocks all shards | Confirmed: write lock held across a full map scan | Fixed | `cleanup_expired_budget`: read-only classify pass + per-key short locks; re-check expiry before remove | 11 — `turna_r2_06_cleanup_incremental_11` |
| #1 | AF_XDP datapath "silently drops" | Imprecise: live path is the real `XskDatapath`; the silent path was an unused `AfXdpTransport` stub | Fixed | stub `recv_batch`/`send_to` → `unimplemented!()` (loud, not silent) | 12 — `turna_r2_01_02_afxdp_stub_drain_test_12` |
| #2 | io_uring drain untested | Confirmed | Fixed | `io_uring_drain` test: detects hang vs panic on shutdown | 12 — `turna_r2_01_02_afxdp_stub_drain_test_12` |
| #4 | JWT revocations lost on restart | Imprecise: `load_active_revocations` is real; nobody warms the blacklist at startup | Mechanism | `UserStore::warm_revocations` + restart regression test; startup wiring deferred (see below) | 13 — `turna_r2_04_revocation_warmup_13` |
| #9 | No CRL for mTLS | Confirmed; real CRL blocked on the tonic stack | Fixed (doc) | documented current posture + operational mitigations (short-lived certs, per-client intermediates, network allowlist); no misleading config field added | 14 — `turna_r2_09_mtls_revocation_doc_14` |
| #3 | DTLS is only a stub | Imprecise: real impl under `--features dtls`; the stub is the no-feature path; the real bug was a swallowed `NotSupported` | Fixed | `DTLS_AVAILABLE` const + node startup fail-fast when `[turn.dtls]` is enabled without the feature | 15 — `turna_r2_03_dtls_failfast_15` |
| #8 | turnactl has no failover status | Confirmed (counters already existed in `Metrics`) | Fixed | `failover.status` command + `turnactl failover status` reading `failover_*` counters | 16 — `turna_r2_08_turnactl_failover_16` |
| #5 | No per-tenant traffic metrics | Confirmed (per-tenant *allocation* count existed; traffic did not) | Fixed | per-tenant bytes/packets/closed accrued at allocation teardown (design (a), no hot-path cost); exported on `/metrics` via a provider | 17 — `turna_r2_05_tenant_traffic_17` |
| #7 | No failover tests with Tarantool | Confirmed | Fixed | CAS/takeover integration tests (stale-claim rejection, concurrent-claim atomicity, dead-node sweep) + `failover-integration` CI job | 18 — `turna_r2_07_failover_tests_ci_18` |

---

## Residual / owner-side items

None of the audit findings remain open. The items below are application,
build, hardware-validation, or upstream-dependency tasks that cannot be
completed or validated from the source alone.

### Apply & build
- Unpack deliveries 15–18 and run `cargo build/test/clippy --workspace` with
  `RUSTFLAGS="-D warnings"`. Two things surface only at compile time:
  - **#3 path:** the node references `turna_transport::dtls::DTLS_AVAILABLE`,
    assuming `pub mod dtls` in `crates/transport/src/lib.rs`. If `dtls` is
    re-exported without a public module, change the reference to
    `turna_transport::DTLS_AVAILABLE` and add `pub use dtls::DTLS_AVAILABLE;`.
  - **loom lint:** `crates/qos/Cargo.toml` needs
    `[lints.rust] unexpected_cfgs = { check-cfg = ['cfg(loom)'] }` (from the
    Audit 1 loom work); without it the `-D warnings` build fails.

### Deferred wiring
- **#4 revocation warm-up:** call `backend.load_active_revocations(now_ms)` →
  `store.warm_revocations(..)` at startup, where the JWT `UserStore` and the
  `TarantoolBackend` are constructed. As of this writing the Phase-2 user-auth
  `UserStore` is not instantiated in either the node or the control-plane
  binary, so there is no live call site yet. The helper + regression test are
  in place; add the three-line call when user-auth is integrated.
- **#7 CI job:** align the `failover-integration` job with the actual
  `deploy/tarantool/init.lua` — image major (2 vs 3), whether the script runs
  as the instance entrypoint or is applied to a running instance, and the
  `turna_app` auth credentials.

### Hardware / environment validation
- P1 (io_uring zero-copy) and P4 (lock-free limiter): build, benchmark, and run
  loom/miri on Linux.
- Fuzz targets and the soak / failover scenarios against a real Tarantool
  cluster.

### Upstream dependency track
- **tonic 0.12.3 → 0.14.x.** Unblocks removing the RUSTSEC ignores
  (`rustls-pemfile`, webpki) and enables a real client-certificate CRL for #9
  (currently mitigated by documentation only). Requires the
  `tonic-build` → `tonic-prost-build` split and the TLS API move; keep the
  `deny.toml` ignores until it compiles.

---

*Closeout compiled June 2026. Per-finding engineering notes accompany each
delivery; design rationale for the larger items lives under `docs/design/` and
`docs/security/`.*
