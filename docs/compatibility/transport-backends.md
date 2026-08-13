# Transport backends — compatibility & support tiers

Turna selects one datapath backend at startup via `[turn].transport`. DTLS is an
additional encrypted listener that runs alongside the chosen UDP backend.

## Build features

| backend | cargo feature | crate dep | extra build deps |
|---------|---------------|-----------|------------------|
| tokio   | (none, default) | — | — |
| io_uring | `io-uring` | `io-uring` 0.7 (pure Rust) | — |
| af_xdp  | `af-xdp` | `xsk-rs` 0.6 (libbpf) | `clang`, `llvm`, `libelf-dev`, `zlib1g-dev`, `libbpf-dev` |
| dtls    | `dtls` | `webrtc-dtls` 0.10 + `webrtc-util` 0.9 + `rustls` | C compiler (for `ring`) |
| tls (TURNS) | `tls` | `rustls` 0.23 + `tokio-rustls` 0.26 | C compiler (for `ring`) |
| quic    | `quic` | `quinn` 0.11 + `rustls` 0.23 | C compiler (for `ring`) |
| web-transport | `web-transport` (implies `quic`) | `wtransport` (bundles its own quinn) | C compiler |

Features compose, e.g. `--features "io-uring,dtls"`.

```bash
cargo build --release -p turna-node                       # tokio
cargo build --release -p turna-node --features io-uring
cargo build --release -p turna-node --features dtls
cargo build --release -p turna-node --features af-xdp
```

## Platform matrix

| backend | Linux | macOS | runtime requirements |
|---------|:-----:|:-----:|----------------------|
| tokio   | ✅ | ✅ | none |
| io_uring | ✅ | ❌ | kernel io_uring; fails fast if unavailable |
| af_xdp  | ✅ | ❌ | `CAP_NET_RAW`, external XDP program on the bound NIC queue |
| dtls    | ✅ | ✅ | ECDSA P-256 cert/key (readable) |

## Support tiers

- **tokio — Stable / default.** All platforms. The production default. Full TURN
  cycle covered by the integration suite.
- **io_uring — Supported (Linux).** Opt-in via `transport = "io_uring"` + build
  feature. Protocol behaviour verified byte-for-byte against tokio
  (`scripts/e2e/backend_diff_bytes.sh`).
- **dtls — Beta.** Opt-in listener. Fail-fast on misconfig, graceful shutdown,
  session + per-IP caps, idle reaper, bounded outbound queue (drop-newest),
  outbound MTU enforcement. TURN-over-DTLS exercised by `tests/integration`
  (`stun_binding_over_dtls`, feature `dtls`) — STUN Binding only, no media test
  yet. Missing: pre-handshake rate limiting, certificate hot-reload.
- **tls (TURNS) — Beta.** Opt-in listener on 5349/TCP. Connection caps (global +
  per-IP), handshake timeout, certificate hot-reload, cooperative drain,
  accept-error resilience, `turna_tls_*` metrics. This is also the control
  transport RFC 6062 TCP allocations require.
- **quic / web-transport — Experimental.** Opt-in. Raw QUIC applies the full
  `[turn.quic]` config and routes control replies per stream; the WebTransport
  (H3) path does neither (a startup warning names the ignored keys). No interop
  test yet. Build the two features separately — `web-transport` bundles its own
  quinn, which can conflict with the standalone `quinn` dep under
  `--all-features`.
- **af_xdp — Experimental / Phase 1.** Opt-in (Linux + `CAP_NET_RAW` + external
  XDP). Compiles and passes startup preflight; neighbor (ARP/NDP) resolution for
  TX MACs is a placeholder/follow-up, and runtime requires a veth lab or an
  XDP-capable NIC (`scripts/lab/af_xdp_*.sh`). Not recommended for production yet.

## Lifecycle (all backends)

- Startup is fail-fast: invalid `[turn.dtls]` or a failed AF_XDP preflight aborts
  the process instead of running partially. Enabling `[turn.dtls]`, `[turn.quic]`
  or `[turn.quic] web_transport` on a binary built without the matching feature
  (`dtls`, `quic`, `web-transport`) is also a startup error, so a configured
  listener can never be silently absent.
- `SIGTERM`/`SIGINT` triggers a lame-duck drain (`cluster.drain_grace_secs`);
  io_uring workers, the AF_XDP loop, and the DTLS listener all stop accepting new
  work cooperatively and release resources on exit. An externally-loaded XDP
  program is left untouched.
- Readiness is exposed on `/ready` and `turna_backend_readiness`
  (`0`=starting, `1`=ready, `2`=degraded, `3`=draining), plus per-component
  gauges: `turna_transport_readiness` (primary UDP backend),
  `turna_dtls_readiness`, `turna_tls_readiness`, `turna_quic_readiness`. Each
  listener gauge follows whether its socket is actually bound, so a listener that
  dies while the process survives reads `2`.

## Differential testing

- Suite-level Tokio↔io_uring parity: `scripts/e2e/backend_diff.sh <config>`.
- Byte-level Tokio↔io_uring parity: `scripts/e2e/backend_diff_bytes.sh A B [--json]`
  (point at two instances differing only in `[turn].transport`).
- vs. coturn: the same `diff-test` tool with `--coturn` aimed at a coturn instance.

---

## README support-tier table (paste into §2.1)

```markdown
| Transport | Platform | Feature flag | Tier |
|-----------|----------|--------------|------|
| tokio     | Linux/macOS | (default) | Stable (default) |
| io_uring  | Linux    | `io-uring`   | Supported |
| TURNS (TLS/TCP) | Linux/macOS | `tls` | Beta |
| DTLS      | Linux/macOS | `dtls`    | Beta |
| QUIC      | Linux/macOS | `quic`    | Experimental |
| WebTransport | Linux/macOS | `web-transport` | Experimental |
| AF_XDP    | Linux    | `af-xdp`     | Experimental (Phase 1) |
```
