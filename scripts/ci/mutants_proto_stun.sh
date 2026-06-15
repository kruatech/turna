#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

target_file="crates/protocol/proto-stun/src/message.rs"
if [[ ! -f "$target_file" ]]; then
  echo "ERROR: file not found: $target_file" >&2
  exit 1
fi

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "cargo-mutants not found; installing it with cargo install"
  cargo install cargo-mutants --locked || cargo install cargo-mutants
fi

# Baseline first: cargo-mutants assumes the unmodified package is green.
cargo test -p turna-proto-stun --locked

: "${MUTANTS_TIMEOUT_SECONDS:=60}"
: "${MUTANTS_JOBS:=2}"

echo "Running cargo-mutants for $target_file"
echo "timeout=${MUTANTS_TIMEOUT_SECONDS}s jobs=${MUTANTS_JOBS}"

cargo mutants \
  --package turna-proto-stun \
  --file "$target_file" \
  --timeout "$MUTANTS_TIMEOUT_SECONDS" \
  --jobs "$MUTANTS_JOBS"
