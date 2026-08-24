#!/usr/bin/env bash
# P-BUILD / P4: per-feature build + lint + test gate.
#
# Why this shape: feature combinations are enumerated by `cargo hack
# --feature-powerset`, which reads the ACTUAL [features] tables from the
# workspace Cargo.toml files. Nothing here hardcodes feature names, so the
# matrix can't drift from the manifests.
#
# Prereq (installed automatically if missing):
#   cargo install cargo-hack
#
# Usage:
#   scripts/ci-checks.sh              # full gate
#   SKIP_POWERSET=1 scripts/ci-checks.sh   # fast path: default+all-features only
#
# Notes:
# - `af-xdp` is Linux-only by design (its build.rs refuses to build off-Linux).
#   The powerset run is therefore split: on non-Linux we exclude that feature.
# - Toolchain: run under the version pinned in rust-toolchain.toml so CI matches
#   local. This script does not pin a version — it uses whatever `cargo` resolves
#   (i.e. the pinned toolchain when rust-toolchain.toml is present).

set -euo pipefail

CLIPPY_FLAGS="-D warnings"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

ensure_cargo_hack() {
  if ! cargo hack --version >/dev/null 2>&1; then
    log "installing cargo-hack"
    cargo install cargo-hack --locked
  fi
}

os_is_linux() { [ "$(uname -s)" = "Linux" ]; }

# 1. Formatting + baseline lint (default features).
log "rustfmt --check"
cargo fmt --all -- --check

# Documentation claims tied to code facts. Cheap, and it exists because a
# false doc claim once hid a shipped wire bug (ALTERNATE-SERVER was 0x0003).
log "doc-truth gate"
bash scripts/check-doc-claims.sh

log "clippy (default features, all targets)"
cargo clippy --workspace --all-targets -- $CLIPPY_FLAGS

# 2. No-default-features build — keeps #[cfg(feature=...)] gating honest
#    (this is the build that catches an attribute accidentally detached from
#    its item, e.g. a feature-gated type left ungated).
log "check --no-default-features"
cargo check --workspace --no-default-features

# 3. Tests (default features).
log "test (default features)"
cargo test --workspace

# 4. Feature powerset — the real matrix, enumerated from Cargo.toml.
if [ "${SKIP_POWERSET:-0}" = "1" ]; then
  log "SKIP_POWERSET=1 → all-features build/test only"
  cargo clippy --workspace --all-targets --all-features -- $CLIPPY_FLAGS
  cargo test --workspace --all-features
else
  ensure_cargo_hack
  if os_is_linux; then
    log "cargo hack --feature-powerset (Linux: includes af-xdp)"
    cargo hack --workspace --feature-powerset --no-dev-deps clippy -- $CLIPPY_FLAGS
    log "cargo hack --feature-powerset test (Linux)"
    cargo hack --workspace --feature-powerset test
  else
    # af-xdp cannot build here; exclude it from the powerset so the rest is
    # still covered on macOS/dev hosts. (Adjust the name if the feature is
    # spelled differently in the manifest — cargo hack will error clearly if so.)
    log "cargo hack --feature-powerset (non-Linux: excluding af-xdp)"
    cargo hack --workspace --feature-powerset --no-dev-deps --exclude-features af-xdp clippy -- $CLIPPY_FLAGS
  fi
fi

log "all checks passed"
