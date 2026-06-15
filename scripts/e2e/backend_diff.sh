#!/usr/bin/env bash
# Stage 3 (Milestone 3) — backend differential e2e runner.
#
# Runs the EXISTING integration suite (`tests/integration`, a live-server TURN
# client) against the same node booted on different transport backends, then
# compares the per-backend results. This implements the Tokio-vs-io_uring
# differential of roadmap §7.1 by reusing the one suite instead of duplicating
# assertions per backend.
#
# It builds ONE binary with `--features io-uring` (the io_uring feature only
# *adds* a backend; `transport = "tokio"` still selects tokio), then flips
# `[turn].transport` in a copy of the base config per run.
#
# DTLS (DTL-5) and AF_XDP (AFX-7) are NOT covered here: DTLS needs a
# DTLS-wrapped client and AF_XDP needs a privileged veth lab — separate steps.
#
# Usage:
#   scripts/e2e/backend_diff.sh [base_config.toml]
#
# Env (all optional):
#   BACKENDS          space-separated list  (default: "tokio io_uring")
#   TARGET            TURN host:port the client hits (default: 127.0.0.1:3478)
#   HEALTH_URL        readiness probe URL    (default: http://127.0.0.1:9090/health)
#   TEST_FILTER       cargo test name filter (default: empty = whole suite)
#   START_TIMEOUT     seconds to await /health (default: 20)
#   TURNA_TEST_SECRET / TURNA_TEST_USER / TURNA_TEST_PASS  forwarded to the suite
#
# Exit: 0 if every backend's suite result is identical (parity), 1 otherwise.

set -euo pipefail

BASE_CFG="${1:-deploy/turn.toml}"
BACKENDS="${BACKENDS:-tokio io_uring}"
TARGET="${TARGET:-127.0.0.1:3478}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:9090/health}"
TEST_FILTER="${TEST_FILTER:-}"
START_TIMEOUT="${START_TIMEOUT:-20}"

err() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
log() { printf '\033[36m==>\033[0m %s\n' "$*"; }

[ -f "$BASE_CFG" ] || { err "base config not found: $BASE_CFG"; exit 1; }
command -v cargo >/dev/null || { err "cargo not found"; exit 1; }
command -v curl  >/dev/null || { err "curl not found";  exit 1; }

WORK="$(mktemp -d)"
NODE_PID=""
cleanup() {
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
  [ -n "$NODE_PID" ] && wait "$NODE_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Write a per-backend config: copy base, force [turn].transport = <backend>.
# Portable (no `sed -i`): rewrite the transport line if present, else insert it
# under the [turn] table header.
make_cfg() {
  local backend="$1" out="$2"
  if grep -qE '^[[:space:]]*transport[[:space:]]*=' "$BASE_CFG"; then
    sed -E "s|^[[:space:]]*transport[[:space:]]*=.*|transport = \"${backend}\"|" "$BASE_CFG" > "$out"
  else
    awk -v b="$backend" '
      { print }
      /^\[turn\][[:space:]]*$/ && !done { print "transport = \"" b "\""; done=1 }
    ' "$BASE_CFG" > "$out"
  fi
}

await_health() {
  local deadline=$(( $(date +%s) + START_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS -o /dev/null --max-time 2 "$HEALTH_URL"; then return 0; fi
    sleep 0.5
  done
  return 1
}

log "building turna-node (release, --features io-uring)"
cargo build --release -p turna-node --features io-uring

BIN="target/release/turna-node"
[ -x "$BIN" ] || { err "binary not found at $BIN after build"; exit 1; }

declare -A RESULT
for backend in $BACKENDS; do
  cfg="$WORK/turn-${backend}.toml"
  make_cfg "$backend" "$cfg"
  log "starting node: transport=${backend}  (config: $cfg)"
  "$BIN" "$cfg" >"$WORK/${backend}.node.log" 2>&1 &
  NODE_PID=$!

  if ! await_health; then
    err "node (transport=${backend}) did not become healthy within ${START_TIMEOUT}s"
    err "----- last 40 log lines -----"; tail -n 40 "$WORK/${backend}.node.log" >&2 || true
    RESULT[$backend]="START_FAILED"
    kill "$NODE_PID" 2>/dev/null || true; wait "$NODE_PID" 2>/dev/null || true; NODE_PID=""
    continue
  fi
  log "node healthy; running integration suite against $TARGET"

  set +e
  TURNA_TEST_TARGET="$TARGET" \
    cargo test -p turna-integration-tests ${TEST_FILTER:+"$TEST_FILTER"} -- --nocapture \
    >"$WORK/${backend}.test.log" 2>&1
  rc=$?
  set -e
  RESULT[$backend]=$([ $rc -eq 0 ] && echo PASS || echo "FAIL(rc=$rc)")
  log "transport=${backend}: ${RESULT[$backend]}  (log: $WORK/${backend}.test.log)"

  kill "$NODE_PID" 2>/dev/null || true; wait "$NODE_PID" 2>/dev/null || true; NODE_PID=""
done

echo
log "backend differential summary"
first=""; parity=1
for backend in $BACKENDS; do
  printf '  %-10s %s\n' "$backend" "${RESULT[$backend]:-SKIPPED}"
  if [ -z "$first" ]; then first="${RESULT[$backend]:-}"; \
  elif [ "${RESULT[$backend]:-}" != "$first" ]; then parity=0; fi
done

if [ "$parity" -eq 1 ]; then
  log "PARITY: all backends produced identical suite results"
  exit 0
else
  err "DIVERGENCE: backends disagree — inspect the per-backend test logs in the summary above"
  exit 1
fi
