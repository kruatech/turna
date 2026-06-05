#!/usr/bin/env bash
# bench/run.sh — compare turna vs coturn on the same hardware.
#
# Three runs, all using turna-load-test as the client:
#   1. turna with BPF filter ON  (production setup)
#   2. turna with BPF filter OFF (apples-to-apples vs coturn)
#   3. coturn
#
# Output: a Markdown comparison table on stdout. Raw JSON for each run
# is kept in bench/results/ so you can re-aggregate later.
#
# Requirements (Linux):
#   - coturn installed (`apt install coturn` / `dnf install coturn`)
#   - jq installed   (`apt install jq`)
#   - this repo built in release mode (`cargo build --release`)
#   - ports 3478, 3479, 9101, 9190, 5350 free
#
# Usage:
#   bash bench/run.sh                       # defaults: c=200, duration=30s
#   CONCURRENCY=500 DURATION=60 bash bench/run.sh
#   SKIP_COTURN=1 bash bench/run.sh         # only turna runs
#
# Honest disclaimer: this script does not pin CPUs, set RT priorities,
# or otherwise prevent noisy neighbours. For "publishable" numbers,
# also: tasksset to specific cores, disable turbo-boost, fix sysctl,
# repeat 3+ times. This script is enough for "is turna in the same
# ballpark as coturn" — not for "turna is 12.3% faster".

set -euo pipefail

# ── Inputs ────────────────────────────────────────────────────────────────────
CONCURRENCY="${CONCURRENCY:-200}"
DURATION="${DURATION:-30}"
SKIP_COTURN="${SKIP_COTURN:-0}"
GARBAGE_PPS="${GARBAGE_PPS:-0}"        # pps of random garbage; 0 = clean run
TARGET_DIR="${TARGET_DIR:-$(pwd)/target/release}"
BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$BENCH_DIR/results"
mkdir -p "$RESULTS_DIR"

# Binaries (resolved relative to repo root, not bench dir).
TURNA_NODE="$TARGET_DIR/turna-node"
TURNA_BENCH="$TARGET_DIR/turna-load-test"

# ── Pre-flight checks ─────────────────────────────────────────────────────────
need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: $1 not found in PATH. Install it before running bench." >&2
        exit 1
    }
}
need jq
[ -x "$TURNA_NODE" ]  || { echo "ERROR: $TURNA_NODE not built. Run: cargo build --release" >&2; exit 1; }
[ -x "$TURNA_BENCH" ] || { echo "ERROR: $TURNA_BENCH not built. Run: cargo build --release" >&2; exit 1; }
if [ "$SKIP_COTURN" != "1" ]; then
    need turnserver
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date +%H:%M:%S)] $*" >&2; }

# Free up ports if leftover from a previous run.
kill_port() {
    local port="$1"
    local pids
    pids="$(ss -lntpu 2>/dev/null | awk -v p=":$port " '$0 ~ p { for (i=1;i<=NF;i++) if ($i ~ /pid=/) print $i }' | grep -oP 'pid=\K[0-9]+' | sort -u || true)"
    if [ -n "${pids:-}" ]; then
        log "killing leftover process(es) on port $port: $pids"
        echo "$pids" | xargs -r kill -9 2>/dev/null || true
        sleep 0.5
    fi
}
kill_port 3478
kill_port 3479
kill_port 9190

# Single trap to clean up whatever we spawned.
TURNA_PID=""
COTURN_PID=""
cleanup() {
    [ -n "$TURNA_PID"    ] && kill "$TURNA_PID"    2>/dev/null || true
    [ -n "$COTURN_PID" ] && kill "$COTURN_PID" 2>/dev/null || true
    sleep 0.3
    kill_port 3478
    kill_port 3479
    kill_port 9190
}
trap cleanup EXIT INT TERM

# Wait for a port to start accepting UDP. coturn and turna both bind
# synchronously so a 2s wait is plenty in practice; this is belt and
# braces.
wait_port() {
    local port="$1"
    for _ in $(seq 1 50); do
        if ss -lnu 2>/dev/null | grep -qE ":$port\b"; then
            return 0
        fi
        sleep 0.1
    done
    echo "ERROR: port $port did not come up in 5s" >&2
    return 1
}

run_one() {
    # $1 = label, $2 = server addr, $3 = output JSON file
    local label="$1" server="$2" out="$3"
    log "running: label=$label  server=$server  c=$CONCURRENCY  d=${DURATION}s"
    "$TURNA_BENCH" \
        --server "$server" \
        --duration "$DURATION" \
        --json \
        --label "$label" \
        binding \
        --concurrency "$CONCURRENCY" \
        > "$out"
    log "  → $(jq -r '"rps=\(.rps|round)  p50=\(.lat_p50_us)µs  p95=\(.lat_p95_us)µs  p99=\(.lat_p99_us)µs  errs=\(.errs)"' "$out")"
}

# ── Garbage traffic helper ───────────────────────────────────────────────────
# Starts garbage.sh in background, returns its PID in $GARBAGE_PID.
GARBAGE_PID=""
start_garbage() {
    if [ "${GARBAGE_PPS}" != "0" ]; then
        log "starting garbage sender @ ${GARBAGE_PPS} pps"
        local _port="${CURRENT_TARGET_PORT:-3478}"
        GARBAGE_PPS="$GARBAGE_PPS" DURATION="$DURATION" \
            bash "$BENCH_DIR/garbage.sh" --target "127.0.0.1:$_port" --pps "$GARBAGE_PPS" &
        GARBAGE_PID=$!
    fi
}
stop_garbage() {
    if [ -n "$GARBAGE_PID" ]; then
        kill "$GARBAGE_PID" 2>/dev/null || true
        GARBAGE_PID=""
    fi
}
GARBAGE_LABEL=""
[ "${GARBAGE_PPS}" != "0" ] && GARBAGE_LABEL=" +garbage@${GARBAGE_PPS}pps"

# ── Run 1: turna with BPF on ────────────────────────────────────────────────────
log "── starting turna (BPF ON) ──"
TURNA_BUFFER_POOL_SIZE=65536 TURNA_RATE_LIMIT_BURST=1000000 TURNA_RATE_LIMIT_RPS=10000000 TURNA_BPF_FILTER=1 "$TURNA_NODE" "$BENCH_DIR/turna.toml" >/tmp/turna-bpf-on.log 2>&1 &
TURNA_PID=$!
export CURRENT_TARGET_PORT=3478
wait_port 3478
start_garbage
run_one "turna-bpf-on${GARBAGE_LABEL}" "127.0.0.1:3478" "$RESULTS_DIR/turna-bpf-on.json"
stop_garbage
kill "$TURNA_PID" 2>/dev/null || true
wait "$TURNA_PID" 2>/dev/null || true
TURNA_PID=""
sleep 1

# ── Run 2: turna with BPF off ───────────────────────────────────────────────────
log "── starting turna (BPF OFF) ──"
TURNA_BUFFER_POOL_SIZE=65536 TURNA_RATE_LIMIT_BURST=1000000 TURNA_RATE_LIMIT_RPS=10000000 TURNA_BPF_FILTER=0 "$TURNA_NODE" "$BENCH_DIR/turna.toml" >/tmp/turna-bpf-off.log 2>&1 &
TURNA_PID=$!
export CURRENT_TARGET_PORT=3478
wait_port 3478
start_garbage
run_one "turna-bpf-off${GARBAGE_LABEL}" "127.0.0.1:3478" "$RESULTS_DIR/turna-bpf-off.json"
stop_garbage
kill "$TURNA_PID" 2>/dev/null || true
wait "$TURNA_PID" 2>/dev/null || true
TURNA_PID=""
sleep 1

# ── Run 3: coturn ─────────────────────────────────────────────────────────────
if [ "$SKIP_COTURN" = "1" ]; then
    log "SKIP_COTURN=1, not running coturn"
else
    log "── starting coturn ──"
    turnserver -c "$BENCH_DIR/coturn.conf" >/tmp/coturn-bench-stdout.log 2>&1 &
    COTURN_PID=$!
    export CURRENT_TARGET_PORT=3479
    wait_port 3479
    start_garbage
run_one "coturn${GARBAGE_LABEL}" "127.0.0.1:3479" "$RESULTS_DIR/coturn.json"
stop_garbage
    kill "$COTURN_PID" 2>/dev/null || true
    wait "$COTURN_PID" 2>/dev/null || true
    COTURN_PID=""
fi

# ── Render comparison table ───────────────────────────────────────────────────
log "── results ──"
echo
echo "## Benchmark results — concurrency=$CONCURRENCY, duration=${DURATION}s, garbage=${GARBAGE_PPS}pps"
echo
echo "| Run | RPS | avg (µs) | p50 (µs) | p95 (µs) | p99 (µs) | min (µs) | max (µs) | Errors |"
echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"

emit_row() {
    local file="$1"
    [ -s "$file" ] || return 0
    jq -r '
        "| \(.label) | \(.rps | round) | \(.lat_avg_us) | \(.lat_p50_us) | \(.lat_p95_us) | \(.lat_p99_us) | \(.lat_min_us) | \(.lat_max_us) | \(.errs) |"
    ' "$file"
}
emit_row "$RESULTS_DIR/turna-bpf-on.json"
emit_row "$RESULTS_DIR/turna-bpf-off.json"
[ "$SKIP_COTURN" != "1" ] && emit_row "$RESULTS_DIR/coturn.json"

echo
echo "Raw JSON: $RESULTS_DIR/"
echo "Server logs: /tmp/turna-bpf-on.log, /tmp/turna-bpf-off.log, /tmp/coturn-bench-stdout.log, /tmp/coturn-bench.log"
