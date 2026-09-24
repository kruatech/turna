# Reproducible Builds

## Requirements

- Rust 1.95.0 (pinned in `rust-toolchain.toml`)
- Dependencies are pinned in `Cargo.lock`

## Build

```bash
# Install the correct Rust version
rustup toolchain install 1.95.0

# Verify the version
rustc --version  # should be 1.95.0

# Build
cargo build --release -p turna-node

# Check dependencies for vulnerabilities
cargo deny check
```

## Verification

```bash
# The binary hash must match on an identical environment
sha256sum target/release/turna-node
```

## Lockfile

`Cargo.lock` is committed to the repository — this guarantees identical
dependency versions on all machines.

## cargo-deny

Dependency check:
```bash
cargo deny check
```

Config: `deny.toml`
