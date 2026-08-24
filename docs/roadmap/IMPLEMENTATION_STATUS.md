# Transport backends 10/10 — implementation status

**shipped** = applied in the repo; **verified** = compiles + tests pass on a
real toolchain; **validated (hw)** = exercised on real hardware/traffic;
**pending (hw)** = needs hardware/traffic not yet run.

## Build / verification status (updated 2026-06-11)

The earlier caveat — *"authored without a local compiler; verified only
structurally"* — is **RETIRED**. The workspace was built, linted and tested on a
real toolchain (Rust 1.95.0) on 2026-06-11. Important correction to the previous
version of this section: the build and the lint were **not** clean on the first
pass. The fixes below were required before the matrix passed; the earlier
"clean / passing / clean" wording did not reflect an actual run.

- `cargo build --workspace --all-features` — **passes after one fix.** The
  initial build failed at `crates/transport/src/dtls.rs:260` with `E0308`
  (`u32` vs `usize`: `n` is `u32`, `max_per_ip` is `usize`). Fixed by widening
  the `u32` operand: `n as usize >= max_per_ip`.
- `cargo test --workspace --all-features` — **passing.** All suites report
  `test result: ok` with no failures; the only `ignored` entries are doc-test
  `ignore`s and the explicitly-`#[ignore]`d long-running tests.
- `cargo clippy --workspace --all-features -- -D warnings` — **passes after
  fixes.** The initial run produced ~20 lints (turna-transport 10, turna-relay 5,
  turna-node 5): `io_other_error`, `manual_is_multiple_of`,
  `manual_saturating_arithmetic`, `new_without_default`, `needless_borrow`,
  `collapsible_if`, `len_zero`, `let_and_return`, `let_unit_value`. Applied with
  `cargo clippy --fix --workspace --all-features --allow-no-vcs`. The autofix of
  `io_other_error` then left two `redundant_closure` lints (`|e| Error::other(e)`),
  fixed by hand in `crates/relay/src/splice.rs:399` and
  `services/node/src/main.rs:564` (`.map_err(Error::other)`). Clippy is then clean
  under `-D warnings`, with no `undocumented_unsafe_blocks` findings.

Scope of this run: it used `--all-features`. The per-feature single-crate build
loop (`<none>`, `af-xdp`, `dtls`, `io-uring`, `quic`, `web-transport`, `tls`) was
not re-executed in this session. The AF_XDP Phase 2 live veth validation
(IPv4+IPv6) recorded under "AF_XDP live validation" below is a separate hardware
claim and was not part of this build/lint/test run.

Structural verification (brace/paren balance, unique edit anchors,
`format!` placeholder==arg) remains the authoring discipline, but the
compile/test/clippy matrix is the source of truth.

## Stage 0 - buildable baseline
- **shipped+verified** `dtls` feature links `rustls`.

## Stage 1 - production-safe startup
- **shipped+verified** AFX-1: public `unimplemented!` AF_XDP stub removed.
- **shipped+verified** DTL-1: `spawn_dtls -> Result`; invalid `[turn.dtls]` aborts startup.
- **shipped+verified** 2.2: default `transport = "tokio"` (+ test).
- **shipped+verified** AFX-2: AF_XDP startup preflight (interface/queue/MTU/CAP_NET_RAW) (+ test).
- **shipped+verified** 2.4: `/ready` + `Readiness` state machine (Starting/Ready/Degraded/Draining), gauge `turna_backend_readiness`. NOTE: process-level; per-backend granularity not wired (see pending).

## Stage 2 - lifecycle & backpressure
- **shipped+verified** AFX-5: AF_XDP graceful shutdown.
- **shipped+verified** DTL-4: DTLS graceful shutdown.
- **shipped+verified** IOU-2 / IOU-2b: configurable io_uring relay capacity + `turna_uring_relay_capacity_exhausted_total`.
- **shipped+verified** DTL-3: bounded per-session DTLS outbound queue (drop-newest) + `turna_dtls_outbound_dropped_total` + `[turn.dtls].outbound_queue_capacity`.

## Stage 3 - e2e / differential
- **shipped** suite-level Tokio<->io_uring differential: `scripts/e2e/backend_diff.sh`.
- **shipped** 7.1 byte-level differential: `scripts/e2e/backend_diff_bytes.sh`.
- **shipped+verified** DTL-5: TURN-over-DTLS e2e client test (`tests/integration`, feature `dtls`, `stun_binding_over_dtls`, `#[ignore]`).
- **shipped** AFX-7 lab: `scripts/lab/af_xdp_{veth_setup,smoke,cleanup}.sh`.
- **shipped+verified** F-5: integration tests no longer pass vacuously. A hermetic
  harness in `tests/integration/src/lib.rs` spawns `turna-node` as a child process
  on ephemeral ports (temp tokio config, waits for `/ready`, dies with the test
  process via `PR_SET_PDEATHSIG`), so `target_addr()` always resolves to a live
  server; `TURNA_TEST_REQUIRE_SERVER` turns "no server" into a hard failure (both
  the `skip_if_no_server!` macro and the inline `get_realm_nonce` skip), so a green
  CI run can no longer hide an unexercised e2e cycle. A standalone CI job (step 1)
  is optional given the hermetic default.
- **pending (hw)** 7.2 coturn differential (needs a coturn instance).

## Stage 4 - observability & ops
- **shipped** alert rules: `docs/alerts/transport-backends.yml`.
- **shipped+verified** io_uring relay-capacity metric (IOU-2b).
- **shipped+validated (hw)** AF_XDP metrics:
  - core: `turna_afxdp_{rx,tx}_frames_total`, `_{rx,tx}_bytes_total`, `_parse_drops_total`, `_tx_drops_total`, `_relay_ports_registered`, `_umem_free_frames`.
  - Phase 2: `turna_afxdp_arp_replies_total`, `turna_afxdp_ndp_replies_total` (counters); `turna_afxdp_neighbor_unresolved`, `turna_afxdp_tx_inflight`, `turna_afxdp_neighbor_cache_entries` (gauges); `turna_afxdp_info{interface,queue}` (identity/info).
  - NOTE: RX-side ring occupancy is intentionally NOT a separate gauge - it is covered by `_umem_free_frames`; only TX in-flight (`tx_inflight = tx_produced - comp_consumed`) is exported, since xsk-rs 0.6 exposes no ring indices and the fill ring is recycled 1:1.
- **shipped+verified** DTLS outbound-drop metric (DTL-3).
- **shipped+verified** `turna_backend_readiness` gauge (2.4).
- **shipped** per-IP DTLS reject counter (`turna_dtls_rejected_per_ip_total`) and the outbound-oversize counter (`turna_dtls_outbound_oversize_total`).
- **won't fix (not observable)** `turna_dtls_handshake_failures/timeouts`: a failed DTLS handshake never surfaces above `webrtc-dtls::accept()`, so no counter can be honest. The alert that referenced it was removed from `docs/alerts/transport-backends.yml` rather than left unfirable. Equivalent counters DO exist for TURNS (`turna_tls_handshake_failures/timeouts_total`) and QUIC (`turna_quic_handshake_failures_total`), where the handshake is observable.
- **shipped** per-listener readiness granularity: `turna_transport_readiness` (primary UDP backend), `turna_tls_readiness`, `turna_dtls_readiness`, `turna_quic_readiness`, `turna_afxdp_readiness`. **Correction 2026-08-18:** `turna_transport_readiness` was exported and documented but `set_transport_readiness()` was never called from anywhere, so it read `0` (starting) for the whole life of every process — including one serving traffic. Found by a browser interop run against a healthy node, alongside the same gap in AF_XDP. Both now set Ready at bind and Draining on shutdown — each derived from whether that listener's socket is bound, so a listener that dies while the process survives reads `2` (degraded) even when `/ready` is green. AF_XDP still shares the process-level backend gauge.
- **shipped** runbook for the encrypted transports (`docs/runbooks/encrypted-transports.md`, covering the rules in `docs/alerts/transport-backends.yml`); **pending** dashboards.

## Stage 4b - AF_XDP Phase 2 (datapath completeness)
All four planned items shipped, compile clean, frame logic unit-tested, and the
datapath validated live (IPv4+IPv6):

- **shipped+validated (hw)** IPv6: pure L2-L4 framing (`build/parse_eth_ipv6_udp`,
  `udp_checksum_v6`), `recv_batch` demux of `ETHERTYPE_IPV6`, family-matched TX
  (single-stack to the `listen` family), and NDP - `maybe_ndp_reply` answers
  ICMPv6 Neighbour Solicitation with a Neighbour Advertisement (hop limit 255,
  Solicited+Override, `icmpv6_checksum`). Unit tests cover build/parse/checksum.
- **shipped+validated (hw)** ring-pending: `turna_afxdp_tx_inflight` gauge.
- **shipped+validated (hw)** netlink-neighbor: async resolver (`crate::neighbor`,
  rtnetlink 0.21 / netlink-packet-route 0.30) does target -> next-hop (kernel LPM)
  -> neighbour MAC, maintains a shared `NeighborCache`; send paths resolve
  per-target with a fallback to the static `dst_mac` and queue an async resolve
  on a cache miss. Standalone `examples/neigh_probe` validates resolution.
  - **Known limitation (by design):** when the XDP redirect steals all ingress on
    the AF_XDP interface, the kernel neighbour table is never populated for an
    on-link peer on that same interface, so netlink resolution returns nothing
    and the static `dst_mac` fallback is used. The resolver covers gateway /
    off-link next hops (learned via other interfaces) and any address the kernel
    knows otherwise. **Phase 2.1 idea:** learn peer MACs from the ARP/NDP the
    datapath already intercepts (`sender_mac` is in hand in `maybe_arp_reply`),
    populating the cache for on-link XDP-interface peers without static config.
- **shipped+validated (hw)** per-queue labelling via `turna_afxdp_info{interface,queue}`
  (non-breaking identity metric; generalises to multi-queue - one line per bound
  instance). True multi-queue binding itself is future work.

## Stage 5 - performance
- **pending (hw)** benchmark matrix + real `bench/RESULTS.md` + coturn baseline + tuning guide. Must come from real runs - no placeholder numbers.

## Stage 6 - security / reliability
- **shipped+verified** unsafe audit: every `unsafe` block carries a `// SAFETY:` rationale; `clippy::undocumented_unsafe_blocks` at zero under `-D warnings`.
- **shipped+verified** fuzz targets (`fuzz/`: stun, stun-semantic, turn, turn-lifecycle, encode); smoke-run clean (fuzz_stun 4M+ exec, no crash). CI builds all targets and runs a 30s smoke per target (`.github/workflows/ci.yml`, `fuzz-build` job, nightly toolchain); longer/extended fuzzing campaigns remain pending.
- **shipped+verified** property tests: `proto-stun/tests/property.rs` proptest
  roundtrips for STUN attributes and the raw ChannelData frame codec
  (`encode/decode/is_channel_data`: roundtrip, 4-byte padding, channel-range
  classifier, buffer-too-short); `proto-turn/tests/property.rs` covers public
  TURN builder encode/decode invariants.
- **shipped** mutation testing entrypoint: `scripts/ci/mutants_proto_stun.sh`
  runs `cargo-mutants` on the proto-stun parser (`message.rs`); `.github/workflows/mutation.yml`
  runs it manually or weekly so it does not make normal PR CI slow/flaky. Mark
  as verified after the workflow has completed successfully on GitHub.
- **shipped+verified** loom: `turna-qos` token-bucket CAS model (`loom_bucket`,
  `RUSTFLAGS="--cfg loom"`); `loom` is a regular `cfg(loom)` dependency since the
  bucket's production code swaps in loom atomics under that cfg. NOTE: the relay
  nonce loom test cannot run workspace-wide under `--cfg loom` because tokio gates
  `tokio::net` behind `cfg(not(loom))`; documented but not runnable in place.
- **partially shipped** DTL-9 DoS: webrtc-dtls `listen()` performs a HelloVerifyRequest cookie exchange before `accept()` (amplification covered); a per-IP **concurrent session** cap is now in-code (`[turn.dtls].max_sessions_per_ip`, `turna_dtls_rejected_per_ip_total`). A per-IP handshake **rate** cap above `accept()` remains **pending (Linux)** and is still mitigated operationally via `iptables hashlimit` on the DTLS port — the handshake runs inside webrtc-dtls, so an in-code rate limit needs a UDP demultiplexer in front of the listener. The QUIC paths do have one in-code (`[turn.quic].max_handshakes_per_sec_per_ip`, token bucket + burst, checked pre-handshake).
- **pending (hw)** load/soak runs, security docs.

## Transport-backend docs

These were tracked here as "to write" in an earlier revision; the files now
exist in the tree (verified 2026-06-11):

- `docs/CONFIGURATION.md` — `[turn.io_uring]` / `[turn.af_xdp]` /
  `[turn.dtls].outbound_queue_capacity` and default-transport guidance.
- `docs/design/dtls-turn.md` — DTLS fail-fast startup, graceful shutdown and
  bounded outbound; no "not implemented" wording remains.
- `docs/compatibility/transport-backends.md` — backend feature matrix.
- `docs/runbooks/af-xdp.md` — AF_XDP deploy/runbook/capabilities.

Their internal coverage was not re-audited as part of this status update. Still
open: confirm the README support-tier table (item 2.1) reflects the current
backends.

## Build / verify (Linux)
```bash
# correctness (this is what retires F-1)
cargo build --workspace --all-features
cargo test  --workspace --all-features
# per-feature (cfg-gate coverage)
for f in "" af-xdp dtls io-uring quic web-transport tls; do
  [ -z "$f" ] && cargo build -p turna-transport \
              || cargo build -p turna-transport --features "$f" || break
done
# strict cleanliness
cargo clippy --workspace --all-features -- -D warnings
# AF_XDP frame unit tests
cargo test -p turna-transport --features af-xdp frame
```

## AF_XDP live validation (level B, veth lab)
Reproducible on a host (no risk to SSH if bound to a dedicated veth, not the
management NIC). Datapath bound to `turna-veth0` (10.123.0.1 / `fd00::1`), peer in
netns `turna-peer` (10.123.0.2 / `fd00::2`); `scripts/lab/` builds the veth.

Confirmed (2026-06-11), IPv4 and IPv6:
- xsk-rs attaches the default XDP redirect program on bind (`ip link` shows the prog); datapath enters its loop.
- ARP / NDP: the datapath answers for its own IP (`arp_replies` / `ndp_replies` increment; peer learns our MAC).
- full path RX -> `process_slice` -> `send_to` -> TX: a STUN Binding Request from the peer returns a Binding Success (0x0101) over both v4 and v6.
- `tx_inflight` moves under send and settles (completions reclaimed lazily on the next send).
- netlink-neighbor hot-path: on a cache miss the send path queues a resolve; with the next hop present in the kernel table the async resolver populates the cache (`neighbor_cache_entries` >= 1).
- `turna_afxdp_info{interface,queue}` exported.

## Endpoints
- `GET /health` - liveness (503 while draining).
- `GET /ready`  - readiness: 200 only in state Ready and not draining.
- `GET /metrics` - Prometheus text.

## Unreleased management-plane implementation

S4 runtime config, durable desired/observed restore, S5 scoped limits, atomic
allocation reservations, bounded command-log migration, admin management UI,
and the standalone-first chart profile are implemented in source. This section
does not supersede the dated transport verification above: the new changes need
a fresh workspace/Tarantool/frontend/container/Helm/live run on the exact commit.
