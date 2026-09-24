#!/usr/bin/env bash
# bench/matrix.sh — turna vs coturn (and optionally eturnal, pion) on the same
# scenarios, the same credentials and the same client.
#
# Scenarios per server (each repeated $REPEATS times, median reported):
#   memory    — establish $HOLD_ALLOCS allocations (each with one permission
#               and one channel), sample the server's VmRSS before / while held /
#               after release: resident bytes per active allocation. Each repeat
#               gets a freshly started server, so earlier runs' allocator state
#               does not blur the delta.
#   binding   — unauthenticated STUN Binding RPS + latency
#   allocate  — allocation rate: every cycle a fresh client doing the full
#               401 challenge → authenticated Allocate → Refresh(lifetime=0)
#   relay     — $CHANNELS concurrent allocations pumping ChannelData at $PPS
#               each through the relay to a local peer: delivered pps, Mbit/s,
#               loss, one-way latency — one run per payload size in $PAYLOADS
#
# Every scenario also records the server's CPU% over the measured window
# (utime+stime from /proc/<pid>/stat, sampled by turna-load-test itself at the
# start and end of the window, after setup and warm-up). The relay figure is the
# one that matters; the others are recorded for completeness.
#
# All servers share one TURN REST secret ("bench-secret"), so the same load-test
# credentials work everywhere. Servers run sequentially, each pinned to
# $SERVER_CPUS; the load generator is pinned to $CLIENT_CPUS.
#
# Output, in bench/results/matrix-<timestamp>/:
#   <server>__<scenario>__r<N>.json   raw turna-load-test output, one per run
#   meta.json                         host, kernel, versions, parameters, tuning
#   results.json                      meta + every run + the median summary
#   results.csv                       the median summary, one row per server×scenario
#   summary.md                        the same summary as Markdown tables
#
# Usage (defaults sized for a 16c/32t machine; see bench/PLAN.md):
#   bash bench/matrix.sh
#   DURATION=60 REPEATS=5 bash bench/matrix.sh                 # publication run
#   SERVERS="turna-bpf-off coturn" SCENARIOS="relay" bash bench/matrix.sh
#   SMOKE=1 SERVERS=turna-bpf-off bash bench/matrix.sh         # harness self-test
#
# Requirements:
#   - turna-node + turna-load-test built (cargo build --release; TARGET_DIR
#     overrides where they are looked up)
#   - coturn, pinned, one of:
#       COTURN_SOURCE=docker (default)  docker; pulls $COTURN_IMAGE by digest
#       COTURN_SOURCE=native            `turnserver` from the distro package; the
#                                       installed version must equal
#                                       $COTURN_NATIVE_VERSION unless
#                                       COTURN_ALLOW_UNPINNED=1
#   - eturnal: https://eturnal.net (optional; ETURNAL_BIN, default `eturnalctl`)
#   - pion:    go toolchain (optional) — built automatically into bench/bin/
#   - jq, python3
#
# Numbers from this script are only meaningful on dedicated, prepared hardware
# (bench/PLAN.md, "Host preparation"). SMOKE=1 exists to prove the harness runs
# end to end; its output is not a measurement and must not be published.

set -eo pipefail

# ── Inputs ────────────────────────────────────────────────────────────────────
SMOKE="${SMOKE:-0}"
if [ "$SMOKE" = "1" ]; then
    # Seconds, not minutes: exercises every code path, measures nothing.
    : "${DURATION:=3}" "${WARMUP:=1}" "${REPEATS:=1}" "${CONCURRENCY:=8}"
    : "${ALLOC_CONCURRENCY:=4}" "${CHANNELS:=8}" "${PPS:=50}" "${PAYLOADS:=160}"
    : "${HOLD_ALLOCS:=100}" "${HOLD_SETTLE:=1}"
fi
DURATION="${DURATION:-30}"                   # measured seconds per run
WARMUP="${WARMUP:-5}"                        # discarded seconds before each run
REPEATS="${REPEATS:-3}"
CONCURRENCY="${CONCURRENCY:-200}"            # binding: closed-loop tasks
BINDING_SOCKETS="${BINDING_SOCKETS:-256}"    # binding: sockets (= sources) per task;
                                             # turna answers <= 8/s per source, so
                                             # CONCURRENCY x this x 8 bounds its RPS
ALLOC_CONCURRENCY="${ALLOC_CONCURRENCY:-64}" # allocate
CHANNELS="${CHANNELS:-200}"                  # relay: concurrent allocations
PPS="${PPS:-500}"                            # relay: per-channel pps
PAYLOADS="${PAYLOADS:-160 1200}"             # relay payload sizes, bytes
HOLD_ALLOCS="${HOLD_ALLOCS:-5000}"           # memory: allocations held
HOLD_PARALLEL="${HOLD_PARALLEL:-32}"         # memory: setup concurrency
HOLD_SETTLE="${HOLD_SETTLE:-3}"              # memory: seconds before each sample
SECRET="${SECRET:-bench-secret}"
# Client source addresses, spread over 127.0.0.1-127.0.255.254 (Linux routes all
# of 127/8 to lo). Every server gets the same spread. It matters for two
# reasons, neither of them a server's throughput:
#   - turna answers at most 8 unauthenticated replies per second per source
#     address (burst 64; `unauth_reply_limiter`, not configurable). Every Binding
#     response and every 401 challenge is one, so from a handful of sources the
#     binding and allocate scenarios would measure that anti-reflection budget.
#   - coturn refuses a new Allocate from a 5-tuple whose allocation was just
#     deleted with Refresh(0) — observed with 4.6.1 as 437 for more than 120 s.
#     A fresh client per cycle from one address soon lands on a recently used
#     ephemeral port; spreading sources makes that collision negligible.
SOURCE_IPS="${SOURCE_IPS:-65534}"
SERVER_CPUS="${SERVER_CPUS:-0-7}"
CLIENT_CPUS="${CLIENT_CPUS:-8-15}"
SERVERS="${SERVERS:-turna-bpf-on turna-bpf-off coturn eturnal pion}"
SCENARIOS="${SCENARIOS:-memory binding allocate relay}"
TARGET_DIR="${TARGET_DIR:-${CARGO_TARGET_DIR:-$(pwd)/target}/release}"
ETURNAL_BIN="${ETURNAL_BIN:-eturnalctl}"

# coturn pins. The image digest is the multi-arch index of
# coturn/coturn:4.7.0-r4-debian as published on Docker Hub (2025-12-18); the
# native pin is Ubuntu 24.04's package. Change them together with a note in
# RESULTS.md — a result without the exact coturn build is not reproducible.
COTURN_SOURCE="${COTURN_SOURCE:-docker}"
COTURN_IMAGE="${COTURN_IMAGE:-coturn/coturn:4.7.0-r4-debian@sha256:a00afb5b4890de4df22bbe70379c6b316685dffee297d53cac1271dcb91fab93}"
COTURN_NATIVE_VERSION="${COTURN_NATIVE_VERSION:-4.6.1-1build4}"
COTURN_ALLOW_UNPINNED="${COTURN_ALLOW_UNPINNED:-0}"
COTURN_CONTAINER="turna-bench-coturn"

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$BENCH_DIR/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="${RESULTS_DIR:-$BENCH_DIR/results/matrix-$STAMP}"
mkdir -p "$RESULTS_DIR" "$BENCH_DIR/bin"

TURNA_NODE="$TARGET_DIR/turna-node"
LT="$TARGET_DIR/turna-load-test"
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

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

coturn_native_version() {
    dpkg-query -W -f='${Version}' coturn 2>/dev/null \
        || rpm -q --qf '%{VERSION}-%{RELEASE}' coturn 2>/dev/null \
        || echo unknown
}

server_available() {
    case "$1" in
        turna-bpf-on|turna-bpf-off) return 0 ;;
        coturn)
            if [ "$COTURN_SOURCE" = docker ]; then
                if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
                    log "coturn: COTURN_SOURCE=docker but no usable docker daemon (COTURN_SOURCE=native uses the distro package)"
                    return 1
                fi
                docker image inspect "$COTURN_IMAGE" >/dev/null 2>&1 \
                    || docker pull "$COTURN_IMAGE" >&2 || return 1
                return 0
            fi
            command -v turnserver >/dev/null 2>&1 || return 1
            local v; v="$(coturn_native_version)"
            if [ "$v" != "$COTURN_NATIVE_VERSION" ]; then
                if [ "$COTURN_ALLOW_UNPINNED" = 1 ]; then
                    log "WARN: coturn $v installed, pin is $COTURN_NATIVE_VERSION (COTURN_ALLOW_UNPINNED=1)"
                else
                    log "coturn: installed $v, pin is $COTURN_NATIVE_VERSION — set COTURN_ALLOW_UNPINNED=1 to run anyway"
                    return 1
                fi
            fi
            return 0 ;;
        eturnal) command -v "$ETURNAL_BIN" >/dev/null 2>&1 ;;
        pion)
            if [ -x "$BENCH_DIR/bin/pion-turn" ]; then return 0; fi
            if command -v go >/dev/null 2>&1; then
                log "building pion-turn bench server..."
                if (cd "$BENCH_DIR/pion-turn" && go build -o "$BENCH_DIR/bin/pion-turn" .); then
                    return 0
                fi
            fi
            return 1 ;;
    esac
}

SRV_PID=""       # what we started, for stop_server
SRV_TARGET=""    # the process whose /proc the load generator samples
start_server() {
    local name="$1" log_file="$RESULTS_DIR/server-$1.log"
    SRV_PID=""; SRV_TARGET=""
    case "$name" in
        turna-bpf-on)
            TURNA_BPF_FILTER=1 "${PIN_S[@]}" "$TURNA_NODE" "$BENCH_DIR/turna.toml" >"$log_file" 2>&1 &
            SRV_PID=$! ;;
        turna-bpf-off)
            TURNA_BPF_FILTER=0 "${PIN_S[@]}" "$TURNA_NODE" "$BENCH_DIR/turna.toml" >"$log_file" 2>&1 &
            SRV_PID=$! ;;
        coturn)
            if [ "$COTURN_SOURCE" = docker ]; then
                docker rm -f "$COTURN_CONTAINER" >/dev/null 2>&1 || true
                # Host networking: the container must not add a NAT hop the
                # native servers do not have.
                docker run -d --rm --name "$COTURN_CONTAINER" --network host \
                    --cpuset-cpus "$SERVER_CPUS" \
                    -v "$BENCH_DIR/coturn.conf:/etc/coturn/turnserver.conf:ro" \
                    "$COTURN_IMAGE" -c /etc/coturn/turnserver.conf >"$log_file" 2>&1
                # The image's entrypoint execs turnserver, so the container's
                # init PID (as the host sees it) is the server itself.
                SRV_TARGET="$(docker inspect -f '{{.State.Pid}}' "$COTURN_CONTAINER")"
            else
                "${PIN_S[@]}" turnserver -c "$BENCH_DIR/coturn.conf" >"$log_file" 2>&1 &
                SRV_PID=$!
            fi ;;
        eturnal)
            ETURNAL_ETC_DIR="$BENCH_DIR" \
                "${PIN_S[@]}" "$ETURNAL_BIN" foreground >"$log_file" 2>&1 &
            SRV_PID=$! ;;
        pion)
            "${PIN_S[@]}" "$BENCH_DIR/bin/pion-turn" >"$log_file" 2>&1 &
            SRV_PID=$! ;;
    esac
    # taskset execs the server, so $! is the server's own PID.
    [ -n "$SRV_TARGET" ] || SRV_TARGET="$SRV_PID"
}

resolve_target() {
    # eturnalctl starts an Erlang VM as a child; sample the VM, not the wrapper.
    if [ "$1" = eturnal ]; then
        local vm
        vm="$(pgrep -n -f 'beam.smp.*eturnal' || true)"
        [ -n "$vm" ] && SRV_TARGET="$vm"
    fi
    return 0
}

stop_server() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
        SRV_PID=""
    fi
    if command -v docker >/dev/null 2>&1; then
        docker stop "$COTURN_CONTAINER" >/dev/null 2>&1 || true
    fi
    # eturnalctl forks an Erlang VM; make sure nothing lingers.
    pkill -f "beam.smp.*eturnal" 2>/dev/null || true
    SRV_TARGET=""
    sleep 1
}
trap stop_server EXIT INT TERM

# Is anything bound to UDP $1? /proc/net/udp{,6} rather than ss(8), which
# minimal hosts and containers often lack.
udp_bound() {
    local hex; hex="$(printf '%04X' "$1")"
    grep -qE "^ *[0-9]+: [0-9A-F]+:$hex " /proc/net/udp /proc/net/udp6 2>/dev/null
}

wait_port() {
    local port="$1"
    for _ in $(seq 1 100); do
        if udp_bound "$port"; then return 0; fi
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
    local common=(--server "127.0.0.1:$port" --json --label "$label"
                  --secret "$SECRET" --clk-tck "$CLK_TCK" --source-ips "$SOURCE_IPS")
    [ -n "$SRV_TARGET" ] && common+=(--server-pid "$SRV_TARGET")
    local rc=0

    case "$scen" in
        memory)
            "${PIN_C[@]}" "$LT" "${common[@]}" \
                hold -n "$HOLD_ALLOCS" --parallel "$HOLD_PARALLEL" \
                --settle "$HOLD_SETTLE" --channel > "$out" || rc=$? ;;
        binding)
            "${PIN_C[@]}" "$LT" "${common[@]}" --duration "$DURATION" --warmup "$WARMUP" \
                binding --concurrency "$CONCURRENCY" --sockets-per-task "$BINDING_SOCKETS" \
                > "$out" || rc=$? ;;
        allocate)
            "${PIN_C[@]}" "$LT" "${common[@]}" --duration "$DURATION" --warmup "$WARMUP" \
                allocate --concurrency "$ALLOC_CONCURRENCY" --fresh > "$out" || rc=$? ;;
        relay-*)
            local payload="${scen#relay-}"
            "${PIN_C[@]}" "$LT" "${common[@]}" --duration "$DURATION" --warmup "$WARMUP" \
                channel-data -n "$CHANNELS" --pps "$PPS" --payload "$payload" > "$out" || rc=$? ;;
    esac
    if [ "$rc" -ne 0 ] || ! jq -e . "$out" >/dev/null 2>&1; then
        log "    $label: FAILED (exit $rc) — kept as $(basename "$out").failed, excluded from the summary"
        mv "$out" "$out.failed" 2>/dev/null || true
        return 0
    fi
    if [ "$scen" = memory ]; then
        jq -r '"    " + .label + ": established=\(.established)/\(.requested) bytes/alloc=\(.rss_bytes_per_allocation) errs=\(.errs)"' "$out" >&2
    else
        jq -r '"    " + .label + ": rate=\(.rps|round)/s p50=\(.lat_p50_us)µs p99=\(.lat_p99_us)µs errs=\(.errs) server_cpu=\(.server_cpu_pct)%"' "$out" >&2
    fi
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

# ── Metadata: what a reader needs to reproduce, or distrust, the numbers ─────
sysctl_val() { sysctl -n "$1" 2>/dev/null || echo unknown; }
coturn_version_string() {
    if [ "$COTURN_SOURCE" = docker ]; then echo "image $COTURN_IMAGE"
    else echo "native $(coturn_native_version)"; fi
}
write_meta() {
    # Everything goes through the environment, never into Python source, so a
    # value containing a quote cannot break (or inject into) the script.
    META_OUT="$RESULTS_DIR/meta.json" \
    M_STAMP="$STAMP" M_SMOKE="$SMOKE" \
    M_KERNEL="$(uname -r)" \
    M_CPU="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//')" \
    M_NPROC="$(nproc 2>/dev/null || echo unknown)" \
    M_MEM="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)" \
    M_GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)" \
    M_CLK="$CLK_TCK" M_ULIMIT="$(ulimit -n)" \
    M_RMEM_MAX="$(sysctl_val net.core.rmem_max)" M_WMEM_MAX="$(sysctl_val net.core.wmem_max)" \
    M_RMEM_DEF="$(sysctl_val net.core.rmem_default)" M_WMEM_DEF="$(sysctl_val net.core.wmem_default)" \
    M_BACKLOG="$(sysctl_val net.core.netdev_max_backlog)" \
    M_COMMIT="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)" \
    M_DIRTY="$(git -C "$REPO_DIR" status --porcelain 2>/dev/null | head -1)" \
    M_NODE="$TURNA_NODE" M_COTURN="$(coturn_version_string)" \
    M_SERVERS="$SERVERS" M_SCENARIOS="$SCENARIOS" M_DURATION="$DURATION" M_WARMUP="$WARMUP" \
    M_REPEATS="$REPEATS" M_CONC="$CONCURRENCY" M_ACONC="$ALLOC_CONCURRENCY" \
    M_BSOCK="$BINDING_SOCKETS" M_SRCIPS="$SOURCE_IPS" \
    M_CHANNELS="$CHANNELS" M_PPS="$PPS" M_PAYLOADS="$PAYLOADS" M_HOLD="$HOLD_ALLOCS" \
    M_HOLD_PAR="$HOLD_PARALLEL" M_HOLD_SETTLE="$HOLD_SETTLE" \
    M_SCPU="$SERVER_CPUS" M_CCPU="$CLIENT_CPUS" \
    python3 - <<'PYEOF'
import json, os
e = os.environ
meta = {
    "stamp": e["M_STAMP"],
    "smoke": e["M_SMOKE"] == "1",
    "host": {
        "kernel": e["M_KERNEL"], "cpu_model": e["M_CPU"], "nproc": e["M_NPROC"],
        "mem_total_kb": e["M_MEM"], "governor": e["M_GOV"], "clk_tck": e["M_CLK"],
        "ulimit_n": e["M_ULIMIT"],
        "sysctl": {
            "net.core.rmem_max": e["M_RMEM_MAX"], "net.core.wmem_max": e["M_WMEM_MAX"],
            "net.core.rmem_default": e["M_RMEM_DEF"], "net.core.wmem_default": e["M_WMEM_DEF"],
            "net.core.netdev_max_backlog": e["M_BACKLOG"],
        },
    },
    "versions": {
        "turna_commit": e["M_COMMIT"], "turna_tree_dirty": e["M_DIRTY"] != "",
        "turna_node": e["M_NODE"], "coturn": e["M_COTURN"],
    },
    "params": {k: e[v] for k, v in {
        "servers": "M_SERVERS", "scenarios": "M_SCENARIOS", "duration_s": "M_DURATION",
        "warmup_s": "M_WARMUP", "repeats": "M_REPEATS", "binding_concurrency": "M_CONC",
        "binding_sockets_per_task": "M_BSOCK", "source_ips": "M_SRCIPS",
        "allocate_concurrency": "M_ACONC", "relay_channels": "M_CHANNELS",
        "relay_pps_per_channel": "M_PPS", "relay_payloads": "M_PAYLOADS",
        "hold_allocations": "M_HOLD", "hold_parallel": "M_HOLD_PAR",
        "hold_settle_s": "M_HOLD_SETTLE", "server_cpus": "M_SCPU", "client_cpus": "M_CCPU",
    }.items()},
}
json.dump(meta, open(e["META_OUT"], "w"), indent=2)
PYEOF
    local rmem; rmem="$(sysctl_val net.core.rmem_max)"
    if [ "$rmem" != unknown ] && [ "$rmem" -lt 268435456 ]; then
        log "WARN: net.core.rmem_max=$rmem, below bench/PLAN.md's 268435456 — host not prepared; relay loss will include kernel buffer drops"
    fi
}

# ── Main loop ─────────────────────────────────────────────────────────────────
SCEN_LIST="$(expand_scenarios)"
log "matrix: servers=[$SERVERS] scenarios=[$SCEN_LIST] repeats=$REPEATS duration=${DURATION}s warmup=${WARMUP}s"
[ "$SMOKE" = 1 ] && log "SMOKE=1: harness self-test — these numbers are not a measurement"
log "results → $RESULTS_DIR"
write_meta
need_fds=$(( CONCURRENCY * BINDING_SOCKETS + 2 * HOLD_ALLOCS + 2 * CHANNELS + 1024 ))
if [ "$(ulimit -n)" != unlimited ] && [ "$(ulimit -n)" -lt "$need_fds" ]; then
    log "WARN: ulimit -n is $(ulimit -n), the client needs about $need_fds (bench/PLAN.md sets 1048576)"
fi

boot_server() {
    local srv="$1" port
    port="$(server_port "$srv")"
    start_server "$srv"
    wait_port "$port"
    sleep 1   # let the runtime settle
    resolve_target "$srv"
    if [ -n "$SRV_TARGET" ]; then log "   $srv up on $port, sampling /proc/$SRV_TARGET"; fi
}

for srv in $SERVERS; do
    if ! server_available "$srv"; then
        log "SKIP $srv: not available"
        continue
    fi
    log "── $srv ──"
    others=()
    for scen in $SCEN_LIST; do
        if [ "$scen" = memory ]; then
            # A fresh server per repeat: the before/held delta is only
            # comparable when no earlier run has grown the allocator's pools.
            for r in $(seq 1 "$REPEATS"); do
                boot_server "$srv"
                run_case "$srv" memory "$r"
                stop_server
            done
        else
            others+=("$scen")
        fi
    done
    [ "${#others[@]}" -gt 0 ] || continue
    boot_server "$srv"
    for scen in "${others[@]}"; do
        for r in $(seq 1 "$REPEATS"); do
            run_case "$srv" "$scen" "$r"
            sleep 1
        done
    done
    stop_server
done

# ── Aggregate: median across repeats → JSON, CSV, Markdown ────────────────────
python3 "$BENCH_DIR/summarize.py" "$RESULTS_DIR"
log "summary → $RESULTS_DIR/summary.md, results.csv, results.json"
