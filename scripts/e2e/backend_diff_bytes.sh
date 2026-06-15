#!/usr/bin/env bash
# Stage 3 (§7.1) — BYTE-LEVEL backend differential.
#
# Compares two RUNNING turna instances response-by-response using the existing
# `diff-test` tool, repurposing its --turna/--coturn flags as "backend A" vs
# "backend B" (both turna). Point them at the SAME build differing ONLY in
# `[turn].transport` (e.g. tokio vs io_uring) to prove byte-level parity between
# the transport backends — diff-test already reports attribute/byte-level
# response divergences (it was written for turna-vs-coturn).
#
# This complements `backend_diff.sh` (which runs the integration *suite* per
# backend, pass/fail granularity); this script is the finer byte-for-byte check.
#
# Boot two instances first, e.g.:
#   cargo build --release -p turna-node --features io-uring
#   # configA.toml:  [turn] transport="tokio"     + listen 127.0.0.1:3478
#   # configB.toml:  [turn] transport="io_uring"  + listen 127.0.0.1:3479
#   ./target/release/turna-node configA.toml &
#   ./target/release/turna-node configB.toml &
#
# Usage:
#   scripts/e2e/backend_diff_bytes.sh <addrA> <addrB> [--json]
#
# Exit codes are passed through from diff-test:
#   0 = no discrepancies (byte-level parity)
#   1 = discrepancies found
#   2 = error (server unreachable etc.)

set -euo pipefail

A="${1:?usage: backend_diff_bytes.sh <addrA> <addrB> [--json]}"
B="${2:?usage: backend_diff_bytes.sh <addrA> <addrB> [--json]}"
shift 2 || true

command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }

printf '\033[36m==>\033[0m byte-level differential: A(--turna)=%s  B(--coturn)=%s\n' "$A" "$B" >&2

exec cargo run --release --quiet -p turna-diff-test --bin diff-test -- \
  --turna "$A" --coturn "$B" "$@"
