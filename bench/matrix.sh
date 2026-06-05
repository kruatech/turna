#!/usr/bin/env bash
# bench/matrix.sh — benchmark matrix: turna vs coturn vs eturnal vs pion.
#
# Scenarios per server (each repeated $REPEATS times, median reported):
#   binding   — unauthenticated STUN Binding RPS + latency
#   allocate  — full authenticated Allocate handshake rate (REST creds)
#   relay     — ChannelData relay throughput/loss/latency, one run per
#               payload size in $PAYLOADS
#
# All servers share one TURN REST secret ("bench-secret"), so the same
# load-test credentials work everywhere. Servers run sequentially, each
# pinned to $SERVER_CPUS; the load generator is pinned to $CLIENT_CPUS.
#
# Usage (defaults sized for a 16c/32t machine):
#   bash bench/matrix.sh
#   DURATION=60 REPEATS=5 bash bench/matrix.sh
#   SERVERS="turna-bpf-on coturn" SCENARIOS="binding" bash bench/matrix.sh
#
# Requirements:
#   - cargo build --release            (turna-node + turna-load-test)
#   - coturn:  apt install coturn      (or drop from SERVERS)
#   - eturnal: https://eturnal.net     (or drop from SERVERS; ETURNAL_BIN
#              overrides the binary, default `eturnalctl`)
#   - pion:    go toolchain — built automatically into bench/bin/
#   - jq, python3
#
# Host prep for publishable numbers: see bench/PLAN.md.

set -eo pipefail

# ── Inputs ────────────────────────────────────────────────────────────────────
DURATION="${DURATION:-30}"
REPEATS="${REPEATS:-3}"
CONCURRENCY="${CONCURRENCY:-200}"            # binding
ALLOC_CONCURRENCY="${ALLOC_CONCURRENCY:-64}" # allocate
CHANNELS="${CHANNELS:-200}"                  # relay
PPS="${PPS:-500}"                            # relay: per-channel pps
PAYLOADS="${PAYLOADS:-160 1200}"             # relay payload sizes, bytes
SECRET="${SECRET:-bench-secret}"
SERVER_CPUS="${SERVER_CPUS:-0-7}"
CLIENT_CPUS="${CLIENT_CPUS:-8-15}"
SERVERS="${SERVERS:-turna-bpf-on turna-bpf-off coturn eturnal pion}"
SCENARIOS="${SCENARIOS:-binding allocate relay}"
TARGET_DIR="${TARGET_DIR:-$(pwd)/target/release}"
ETURNAL_BIN="${ETURNAL_BIN:-eturnalctl}"

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="$BENCH_DIR/results/matrix-$STAMP"
mkdir -p "$RESULTS_DIR" "$BENCH_DIR/bin"

TURNA_NODE="$TARGET_DIR/turna-node"
LT="$TARGET_DIR/turna-load-test"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }

# taskset is Linux-only; degrade gracefully elsewhere.
PIN_S=(); PIN_C=()
if command -v taskset >/dev/null 2>&1; then
    PIN_S=(taskset -c "$SERVER_CPUS")
    PIN_C=(taskset -c "$CLIENT_CPUS")
else
    log "WARN: taskset not found — running without CPU pinning"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: $1 not found" >&2; exit 1; }; }
need jq; need python3
[ -x "$TURNA_NODE" ] || { echo "ERROR: $TURNA_NODE not built (cargo build --release)" >&2; exit 1; }
[ -x "$LT" ]         || { echo "ERROR: $LT not built (cargo build --release)" >&2; exit 1; }

# ── Server registry ───────────────────────────────────────────────────────────
server_port() {
    case "$1" in
        turna-bpf-on|turna-bpf-off) echo 3478 ;;
        coturn)  echo 3479 ;;
        eturnal) echo 3480 ;;
        pion)    echo 3481 ;;
        *) echo "ERROR: unknown server $1" >&2; exit 1 ;;
    esac
}

server_available() {
    case "$1" in
        turna-bpf-on|turna-bpf-off) return 0 ;;
        coturn)  command -v turnserver >/dev/null 2>&1 ;;
        eturnal) command -v "$ETURNAL_BIN" >/dev/null 2>&1 ;;
        pion)
            if [ -x "$BENCH_DIR/bin/pion-turn" ]; then return 0; fi
            if command -v go >/dev/null 2>&1; then
                log "building pion-turn bench server..."
                (cd "$BENCH_DIR/pion-turn" && go build -o "$BENCH_DIR/bin/pion-turn" .) \
                    && return 0 || return 1
            fi
            return 1 ;;
    esac
}

SRV_PID=""
start_server() {
    local name="$1" log_file="/tmp/bench-$name.log"
    case "$name" in
        turna-bpf-on)
            TURNA_BUFFER_POOL_SIZE=65536 TURNA_RATE_LIMIT_BURST=100000000 \
            TURNA_RATE_LIMIT_RPS=100000000 TURNA_PREFIX_BURST=100000000 \
            TURNA_PREFIX_RPS=100000000 TURNA_BPF_FILTER=1 \
                "${PIN_S[@]}" "$TURNA_NODE" "$BENCH_DIR/turna.toml" >"$log_file" 2>&1 & ;;
        turna-bpf-off)
            TURNA_BUFFER_POOL_SIZE=65536 TURNA_RATE_LIMIT_BURST=100000000 \
            TURNA_RATE_LIMIT_RPS=100000000 TURNA_PREFIX_BURST=100000000 \
            TURNA_PREFIX_RPS=100000000 TURNA_BPF_FILTER=0 \
                "${PIN_S[@]}" "$TURNA_NODE" "$BENCH_DIR/turna.toml" >"$log_file" 2>&1 & ;;
        coturn)
            "${PIN_S[@]}" turnserver -c "$BENCH_DIR/coturn.conf" >"$log_file" 2>&1 & ;;
        eturnal)
            ETURNAL_ETC_DIR="$BENCH_DIR" \
                "${PIN_S[@]}" "$ETURNAL_BIN" foreground >"$log_file" 2>&1 & ;;
        pion)
            "${PIN_S[@]}" "$BENCH_DIR/bin/pion-turn" >"$log_file" 2>&1 & ;;
    esac
    SRV_PID=$!
}

stop_server() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
        SRV_PID=""
    fi
    # eturnalctl forks an Erlang VM; make sure nothing lingers.
    pkill -f "eturnal" 2>/dev/null || true
    sleep 1
}
trap stop_server EXIT INT TERM

wait_port() {
    local port="$1"
    for _ in $(seq 1 100); do
        if ss -lnu 2>/dev/null | grep -qE ":$port\b"; then return 0; fi
        sleep 0.1
    done
    echo "ERROR: port $port did not come up in 10s" >&2
    return 1
}

# ── Client invocations ────────────────────────────────────────────────────────
run_case() {
    # $1 server name, $2 scenario id, $3 repeat index
    local srv="$1" scen="$2" r="$3"
    local port; port="$(server_port "$srv")"
    local label="$srv|$scen|r$r"
    local out="$RESULTS_DIR/${srv}__${scen}__r${r}.json"

    case "$scen" in
        binding)
            "${PIN_C[@]}" "$LT" --server "127.0.0.1:$port" --duration "$DURATION" \
                --json --label "$label" \
                binding --concurrency "$CONCURRENCY" > "$out" ;;
        allocate)
            "${PIN_C[@]}" "$LT" --server "127.0.0.1:$port" --duration "$DURATION" \
                --json --label "$label" --secret "$SECRET" \
                allocate --concurrency "$ALLOC_CONCURRENCY" > "$out" ;;
        relay-*)
            local payload="${scen#relay-}"
            "${PIN_C[@]}" "$LT" --server "127.0.0.1:$port" --duration "$DURATION" \
                --json --label "$label" --secret "$SECRET" \
                channeldata -n "$CHANNELS" --pps "$PPS" --payload "$payload" > "$out" ;;
    esac
    jq -r '"    " + .label + ": rps=\(.rps|round) p50=\(.lat_p50_us)µs p99=\(.lat_p99_us)µs errs=\(.errs)"' "$out" >&2
}

# Expand "relay" into one scenario per payload size.
expand_scenarios() {
    local out=()
    for s in $SCENARIOS; do
        if [ "$s" = "relay" ]; then
            for p in $PAYLOADS; do out+=("relay-$p"); done
        else
            out+=("$s")
        fi
    done
    echo "${out[@]}"
}

# ── Main loop ─────────────────────────────────────────────────────────────────
SCEN_LIST="$(expand_scenarios)"
log "matrix: servers=[$SERVERS] scenarios=[$SCEN_LIST] repeats=$REPEATS duration=${DURATION}s"
log "results → $RESULTS_DIR"

for srv in $SERVERS; do
    if ! server_available "$srv"; then
        log "SKIP $srv: binary not available"
        continue
    fi
    port="$(server_port "$srv")"
    log "── $srv (port $port) ──"
    start_server "$srv"
    wait_port "$port"
    sleep 1   # let the runtime settle

    for scen in $SCEN_LIST; do
        for r in $(seq 1 "$REPEATS"); do
            run_case "$srv" "$scen" "$r"
            sleep 1
        done
    done
    stop_server
done

# ── Aggregate: median across repeats, Markdown summary ────────────────────────
python3 - "$RESULTS_DIR" <<'PYEOF'
import json, sys, glob, os, statistics as st
from collections import defaultdict

rd = sys.argv[1]
runs = defaultdict(list)   # (server, scenario) -> [json...]
for f in sorted(glob.glob(os.path.join(rd, "*.json"))):
    base = os.path.basename(f)[:-5]
    srv, scen, _r = base.split("__")
    try:
        runs[(srv, scen)].append(json.load(open(f)))
    except Exception as e:
        print(f"WARN: {f}: {e}", file=sys.stderr)

def med(rows, key):
    vals = [r[key] for r in rows]
    return st.median(vals)

scens = sorted({s for (_, s) in runs})
servers = sorted({sv for (sv, _) in runs})
lines = []
lines.append(f"# Benchmark matrix — {os.path.basename(rd)}\n")
lines.append(f"Medians over repeats. Raw JSON in `{rd}`.\n")
for scen in scens:
    lines.append(f"\n## {scen}\n")
    if scen.startswith("relay-"):
        lines.append("| Server | Mbps out of relay | Loss % | p50 (µs) | p99 (µs) | Errors |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for sv in servers:
            rows = runs.get((sv, scen))
            if not rows: continue
            mbps = st.median([r["bytes_in"]*8/r["duration_s"]/1e6 for r in rows])
            loss = st.median([(r["sent"]-r["recv"])/r["sent"]*100 if r["sent"] else 0.0 for r in rows])
            lines.append(f"| {sv} | {mbps:.1f} | {loss:.2f} | {med(rows,'lat_p50_us'):.0f} "
                         f"| {med(rows,'lat_p99_us'):.0f} | {med(rows,'errs'):.0f} |")
    else:
        unit = "alloc/s" if scen == "allocate" else "RPS"
        lines.append(f"| Server | {unit} | p50 (µs) | p95 (µs) | p99 (µs) | Errors |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for sv in servers:
            rows = runs.get((sv, scen))
            if not rows: continue
            lines.append(f"| {sv} | {med(rows,'rps'):.0f} | {med(rows,'lat_p50_us'):.0f} "
                         f"| {med(rows,'lat_p95_us'):.0f} | {med(rows,'lat_p99_us'):.0f} "
                         f"| {med(rows,'errs'):.0f} |")

out = "\n".join(lines) + "\n"
open(os.path.join(rd, "summary.md"), "w").write(out)
print(out)
PYEOF

log "summary → $RESULTS_DIR/summary.md (paste into bench/RESULTS.md)"
