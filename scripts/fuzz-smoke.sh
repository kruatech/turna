#!/usr/bin/env bash
# Local fuzz smoke runner — mirrors the CI "smoke" mode.
#
# Usage:
#   scripts/fuzz-smoke.sh [SECONDS_PER_TARGET]   # default 30
#   scripts/fuzz-smoke.sh 5 stun_parser          # one target, 5s
#
# Requires a nightly toolchain and cargo-fuzz (Linux/macOS):
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
set -euo pipefail

secs="${1:-30}"
only="${2:-}"

if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  echo "cargo-fuzz not found. Install with: cargo install cargo-fuzz" >&2
  exit 127
fi

targets="$(cargo +nightly fuzz list)"
if [ -n "$only" ]; then
  targets="$only"
fi

rc=0
while IFS= read -r t; do
  [ -z "$t" ] && continue
  echo "=== fuzzing ${t} for ${secs}s ==="
  if ! RUST_BACKTRACE=1 cargo +nightly fuzz run "$t" -- \
        -max_total_time="${secs}" -timeout=15; then
    echo "!!! ${t}: crash or hang (see fuzz/artifacts/)" >&2
    rc=1
  fi
done <<< "$targets"

if [ "$rc" -eq 0 ]; then
  echo "OK — no crashes in ${secs}s/target"
fi
exit "$rc"
