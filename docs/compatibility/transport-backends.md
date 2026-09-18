# Transport backends — compatibility & support tiers

Turna selects one datapath backend at startup via `[turn].transport`. DTLS, TURNS,
QUIC and SCTP are additional client-facing listeners that run alongside the chosen
UDP backend — they are not datapath backends and are not selected by `transport`.

Note the naming collision called out in `docs/protocol-gap.md`: `transport` in
config means the **datapath backend** (`tokio` / `io_uring` / `af_xdp`), which is a
different thing from a *client* transport (the listeners) and from the *relayed*
transport (currently UDP only, IPv4 only).

## Build features

| backend | cargo feature | crate dep | extra build deps |
|---------|---------------|-----------|------------------|
| tokio   | (none, default) | — | — |
| io_uring | `io-uring` | `io-uring` 0.7 (pure Rust) | — |
| af_xdp  | `af-xdp` | `xsk-rs` 0.6 (libbpf) | `clang`, `llvm`, `libelf-dev`, `zlib1g-dev`, `libbpf-dev` |

> `af-xdp` cannot be compile-checked on a dev mac or in the plain `rust:1` image:
> `build.rs` refuses to build off Linux by design, and `libxdp-sys` / `libbpf-sys`
> need the C toolchain above to build their vendored libraries. Use
> `scripts/docker/af-xdp-check.Dockerfile` — it pins the same package list as this
> row, so change both together. It checks compile + lint + the pure L2–L4 frame
> tests; the datapath itself still needs the lab host
> (`scripts/lab/af_xdp_veth_setup.sh`).
| dtls    | `dtls` | `webrtc-dtls` 0.10 + `webrtc-util` 0.9 + `rustls` | C compiler (for `ring`) |
| tls (TURNS) | `tls` | `rustls` 0.23 + `tokio-rustls` 0.26 | C compiler (for `ring`) |
| sctp    | `sctp` (implies `tls`) | reuses the TURNS frame codec; `socket2` + `libc` | host `sctp` kernel module at runtime |
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
| sctp    | ✅ | ❌ | host `sctp` kernel module; plaintext control channel |

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
  yet. On the default path: no pre-handshake rate limiting and no certificate
  hot-reload — both are available with `[turn.dtls] demux = true`, which owns the
  UDP socket instead of `webrtc_dtls::listen()`.
- **tls (TURNS) — Supported.** Opt-in listener on 5349/TCP. Connection caps (global +
  per-IP), handshake timeout, certificate hot-reload, cooperative drain,
  accept-error resilience, `turna_tls_*` metrics. This is also the control
  transport RFC 6062 TCP allocations require.
- **sctp — Supported on Linux/tokio.** Opt-in native one-to-one SCTP carrying
  TURN control and ChannelData; the peer-side relay remains UDP. Allowed in
  production, with global/per-IP caps, rate limiting, metrics, readiness and
  cooperative drain. Requires kernel SCTP and network access for IP protocol 132.
  Plaintext and project-specific; no WebRTC DataChannel or independent client
  interoperability claim. Other backend selections are rejected when enabled.
  See [support evidence](../verification/sctp-supported-2026-09-18.md).
- **quic / web-transport — Supported on Linux/macOS with tokio.** Opt-in.
  Both paths apply transport limits, admission and per-stream reply routing.
  WebTransport negotiates `h3`; configured `alpn` applies only to raw QUIC.
  Both features can be built together. [Evidence and scope](../verification/quic-webtransport-supported-2026-09-18.md).
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
| TURNS (TLS/TCP) | Linux/macOS | `tls` | **Supported** |
| DTLS      | Linux/macOS | `dtls`    | Beta |
| SCTP      | Linux    | `sctp`       | Supported with tokio; native SCTP, plaintext |
| QUIC (`quic`) | Linux/macOS, tokio | `quic` | Supported; see [scope](../verification/quic-webtransport-supported-2026-09-18.md). |
| WebTransport (`web-transport`) | Linux/macOS, tokio | `web-transport` | Supported; see [scope](../verification/quic-webtransport-supported-2026-09-18.md). |
| AF_XDP    | Linux    | `af-xdp`     | Experimental (Phase 1) |
```
