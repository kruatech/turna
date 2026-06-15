# Release Guide

How to build, verify, and (optionally) publish a turna release candidate.

> Verify the exact Cargo feature names against each crate's `Cargo.toml` before
> tagging — the sets below are the intended configuration, not a guarantee that
> every name is exposed by the target crate.

## Prerequisites

- **Rust toolchain 1.95+** (workspace builds and lints were verified on 1.95).
- For the **`af-xdp`** feature (the embedded XDP program is compiled at build time
  via `clang -target bpf`):
  - `clang` and `llvm`
  - `linux-libc-dev` — arch UAPI headers (e.g. `asm/types.h`)
  - `libelf` and `zlib` development headers (vendored libbpf build)
  - Debian/Ubuntu: `sudo apt-get install -y clang llvm linux-libc-dev libelf-dev zlib1g-dev`
- **Kernel minimums at runtime** (see `docs/transport-backends.md`):
  io_uring NODROP ≥ 5.5; AF_XDP copy mode ≥ 5.10; AF_XDP zero-copy / multi-queue ≥ 5.15.

## Feature flags

Optional/high-performance backends are behind Cargo features:

- `io-uring` — io_uring datapath (Linux; no extra privileges)
- `af-xdp` — AF_XDP datapath (Linux; needs the clang/libxdp toolchain above; `CAP_NET_RAW` at runtime)
- `dtls`, `web-transport`, `quic`, `tls` — signalling / transport options

## Building a release candidate

```bash
cargo build --release -p turna-node --features io-uring,af-xdp,dtls,web-transport
```

**Caveat:** enabling `quic` together with `web-transport` can hit the
`wtransport` bundled-quinn vs standalone quinn conflict. If a build with both
fails to compile, that combination is the cause — not the datapath features.
For a focused datapath build use `--features io-uring,af-xdp`.

## Checks before tagging

```bash
cargo deny check                              # advisories / bans / licenses / sources
cargo clippy --workspace -- -D warnings       # lib + bins + tests
cargo test  --workspace --all-features -- --skip dtls --skip full_soak
```

- `cargo deny check` is expected green (advisories clean; the older
  `opentelemetry-otlp 0.16` transport stack is acknowledged via `bans.skip-tree`
  rather than deduplicated — see CHANGELOG).
- On `--all-features`, see the quic/web-transport caveat above. A narrower run
  is `cargo clippy -p turna-transport --features io-uring,af-xdp -- -D warnings`.
- Tests that require an external server (e.g. Tarantool) or long soak runs are
  expected to be skipped/ignored in CI.

## Runtime notes

- Transport backend is selected in config: `[turn] transport = "tokio" | "io_uring" | "af_xdp"`.
  `io_uring` and `af_xdp` are never auto-selected — request them explicitly.
- **AF_XDP** requires a concrete `listen` IP (not `0.0.0.0`) and `CAP_NET_RAW`/root,
  and attaches an XDP program to the configured interface (removed on clean
  shutdown; after `SIGKILL` clear with `ip link set dev <iface> xdpgeneric off`).
- Metrics are served at `/metrics` (Prometheus); the health server port is set
  via `[health].listen` (default `0.0.0.0:8080`).
- Full backend reference: `docs/transport-backends.md`.

## Publishing to crates.io (optional — not yet configured)

If/when publishing library crates:

- Keep `publish = false` on internal/binary crates and tools.
- For publishable libraries, remove `publish = false` and add `description`,
  `readme`, and `license` fields. Candidate set per maintainers: `proto-stun`,
  `proto-turn`, `packet`, `crypto`, `common`, `rtp-analyzer`, `health`,
  `observability`. Confirm each is actually self-contained and license-clean
  before flipping it publishable.
