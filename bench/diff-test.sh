#!/usr/bin/env bash
# bench/diff-test.sh — differential protocol testing: turna vs coturn
#
# Запускает оба сервера и прогоняет diff-test против них.
# Требования (Linux): coturn установлен, repo собран в release.
#
# Usage:
#   bash bench/diff-test.sh
#   bash bench/diff-test.sh --json > diff-results.json

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${TARGET_DIR:-$(pwd)/target/release}"
TURNA_NODE="$TARGET_DIR/turna-node"
DIFF_TEST="$TARGET_DIR/diff-test"

[ -x "$TURNA_NODE"  ] || { echo "ERROR: turna-node not built" >&2; exit 2; }
[ -x "$DIFF_TEST" ] || { echo "ERROR: diff-test not built" >&2; exit 2; }
command -v turnserver >/dev/null || { echo "ERROR: coturn not installed" >&2; exit 2; }

TURNA_PID=""; COTURN_PID=""
cleanup() {
    [ -n "$TURNA_PID"    ] && kill "$TURNA_PID"    2>/dev/null || true
    [ -n "$COTURN_PID" ] && kill "$COTURN_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_port() {
    for _ in $(seq 1 50); do
        ss -lnu 2>/dev/null | grep -qE ":$1 " && return 0
        sleep 0.1
    done
    echo "ERROR: port $1 not up" >&2; return 1
}

"$TURNA_NODE" "$BENCH_DIR/turna.toml" >/tmp/turna-diff.log 2>&1 &
TURNA_PID=$!
wait_port 3478

turnserver -c "$BENCH_DIR/coturn.conf" >/tmp/coturn-diff.log 2>&1 &
COTURN_PID=$!
wait_port 3479

"$DIFF_TEST" --turna 127.0.0.1:3478 --coturn 127.0.0.1:3479 "$@"
