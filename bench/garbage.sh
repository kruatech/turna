#!/usr/bin/env bash
# bench/garbage.sh — send random UDP garbage to a turna server.
#
# Used alongside bench/run.sh to demonstrate the BPF filter benefit:
# with BPF ON, garbage is dropped in-kernel before the copy to userspace;
# with BPF OFF, every garbage packet costs a syscall + parse-then-reject.
#
# Usage (standalone):
#   bash bench/garbage.sh --target 127.0.0.1:3478 --pps 10000 --duration 30
#
# Usage (from run.sh via env):
#   GARBAGE_PPS=10000 bash bench/run.sh
#
# Requirements:
#   - python3 (for the raw UDP sender — zero extra deps)
#   - OR: iperf3 as an alternative (`--mode iperf3`)
#
# Options:
#   --target  HOST:PORT   destination (default: 127.0.0.1:3478)
#   --pps     N           packets per second (default: 5000)
#   --duration N          seconds to run (default: run until killed)
#   --size    N           payload bytes per packet (default: 200)
#   --mode    python|iperf3  sender backend (default: python)

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET="${TARGET:-127.0.0.1:3478}"
PPS="${PPS:-5000}"
DURATION="${DURATION:-0}"          # 0 = infinite
SIZE="${SIZE:-200}"                # bytes per packet
MODE="${GARBAGE_MODE:-rust}"

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)   TARGET="$2";   shift 2 ;;
        --pps)      PPS="$2";      shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --size)     SIZE="$2";     shift 2 ;;
        --mode)     MODE="$2";     shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

HOST="${TARGET%:*}"
PORT="${TARGET##*:}"

log() { echo "[garbage $(date +%H:%M:%S)] $*" >&2; }

# ── Python sender (zero extra deps) ──────────────────────────────────────────
run_python() {
    log "starting python garbage sender → ${HOST}:${PORT} @ ${PPS} pps, size=${SIZE}B"
    python3 - <<PYEOF
import socket, time, os, sys

host    = "$HOST"
port    = int("$PORT")
pps     = int("$PPS")
size    = int("$SIZE")
dur     = int("$DURATION")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
interval = 1.0 / pps
start = time.monotonic()
sent = 0

# Pre-generate a few random-looking payloads to rotate through.
# Real garbage: mix of random bytes, no valid STUN magic cookie (0x2112A442).
payloads = [os.urandom(size) for _ in range(16)]

try:
    while True:
        t0 = time.monotonic()
        if dur > 0 and (t0 - start) >= dur:
            break
        sock.sendto(payloads[sent % 16], (host, port))
        sent += 1
        elapsed = time.monotonic() - t0
        sleep = interval - elapsed
        if sleep > 0:
            time.sleep(sleep)
except KeyboardInterrupt:
    pass
finally:
    elapsed_total = time.monotonic() - start
    actual_pps = sent / elapsed_total if elapsed_total > 0 else 0
    print(f"garbage: sent={sent} elapsed={elapsed_total:.1f}s actual_pps={actual_pps:.0f}", file=sys.stderr)
    sock.close()
PYEOF
}

# ── iperf3 sender (alternative) ───────────────────────────────────────────────
run_iperf3() {
    command -v iperf3 >/dev/null 2>&1 || {
        echo "ERROR: iperf3 not found. Use --mode python instead." >&2
        exit 1
    }
    # iperf3 in UDP mode as a rough garbage source.
    # NOTE: iperf3 requires a server; this is only useful if you have
    # iperf3 -s running somewhere. For most uses, python mode is better.
    local bw=$(( PPS * SIZE * 8 ))  # bits/sec
    log "starting iperf3 garbage → ${HOST}:${PORT} @ ${bw} bps"
    local dur_flag=""
    [ "$DURATION" -gt 0 ] && dur_flag="-t $DURATION"
    iperf3 -c "$HOST" -p "$PORT" -u -b "${bw}" ${dur_flag}
}

run_rust() {
    local bin
    bin="$(dirname "$0")/../target/release/garbage-gen"
    if [ ! -x "$bin" ]; then
        log "garbage-gen not built, falling back to python"
        run_python
        return
    fi
    log "starting rust garbage-gen → ${HOST}:${PORT} @ ${PPS} pps, size=${SIZE}B"
    "$bin" --target "${HOST}:${PORT}" --pps "$PPS" --duration "$DURATION" --size "$SIZE"
}

# ── Run ───────────────────────────────────────────────────────────────────────
case "$MODE" in
    rust)    run_rust   ;;
    python)  run_python  ;;
    iperf3)  run_iperf3  ;;
    *)
        echo "Unknown mode: $MODE. Use python or iperf3." >&2
        exit 1 ;;
esac
