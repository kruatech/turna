# Benchmarking

turna is designed for high-throughput relay workloads, but throughput depends
heavily on the host, NIC, kernel, and data path. This document explains how to
run the benchmarks and — just as importantly — how to report numbers so they
mean something. **Do not compare numbers across environments without the
environment details below.**

## What kinds of benchmarks exist

- **Microbenchmarks (Criterion).** Hot-path parsing/encoding, e.g. the STUN
  parser bench under `crates/protocol/proto-stun/benches/`. These measure CPU
  cost per operation in isolation, not end-to-end relay throughput.
- **Load tools.** `tools/load-test` (`turna-load-test`) and `tools/benchmark`
  (`turna-benchmark`) drive synthetic TURN traffic against a running server.
- **Soak tests.** `tests/soak` exercises sustained load / stability over time.

## Running microbenchmarks

```
# Whole workspace, or target a single crate's benches.
cargo bench --workspace
cargo bench -p turna-proto-stun
```

Criterion writes reports under `target/criterion/`. The bench profile keeps
debug info (`[profile.bench] debug = true`) for profiling; that does not change
the optimization level.

## Running load / soak

The load and soak tools take their own options — invoke them with `--help` to
see the current flags rather than relying on values copied from elsewhere:

```
cargo run --release -p turna-load-test -- --help
cargo run --release -p turna-benchmark -- --help
```

Always build with `--release` for any throughput measurement; debug builds are
not representative.

## Data path matters

The default tokio UDP data path is the portable baseline. The Linux-only
`io-uring` and `af-xdp` data paths target higher throughput via reduced syscall
overhead and kernel bypass, but require specific kernel/NIC support and are
experimental. A number is only meaningful next to the data path it was measured
on. See `docs/feature-support.md` for maturity.

## Required disclosure when reporting numbers

A throughput/latency figure without context is not reproducible. Report at
least:

- CPU model, core count, and whether SMT is on.
- NIC model and link speed; driver; offload settings.
- Kernel version and relevant `sysctl`s (e.g. `net.core.rmem_max`,
  `net.core.wmem_max`).
- Data path (`tokio` / `io-uring` / `af-xdp`) and build flags / features.
- Deployment shape: single node vs cluster, host vs container, hostNetwork.
- Workload: number of clients/allocations, packet size, target bitrate,
  measurement duration, and warm-up.
- turna version (commit/tag) and Rust toolchain (this repo pins `1.95.0`).

## Claims policy

Describe turna as "designed for high-throughput relay workloads" rather than
making comparative claims ("faster than X") unless those claims are backed by
published, reproducible numbers with the environment disclosed as above.
