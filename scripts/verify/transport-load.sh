#!/usr/bin/env bash
#
# Sustained load over WebTransport, raw QUIC and DTLS.
#
# These three had correctness on record and no endurance, because until now nothing
# could drive them under load — `wt-check`, `quic-check` and `dtls-check` each open one
# session for a few seconds. This runs the load drivers that fill that gap.
#
# EACH PHASE IS LONGER THAN 600 SECONDS ON PURPOSE
#
# TURN allocations and channel bindings last 600 s and permissions 300 s. A client that
# does not refresh them delivers only the first ten minutes of any longer run, and the
# server correctly drops the rest — silently, because there is nobody to send an error
# to. That cost two 24 h runs to find (docs/soak/endurance-24h-2026-08-22.md), so every
# phase here crosses the deadline and would expose a driver that failed to refresh.
#
# WHY THREE NODE RUNS
#
# `[turn.quic] web_transport` is either true or false, so QUIC and WebTransport cannot
# share a listener. DTLS has its own port but is kept separate so a failure names one
# transport rather than three.
#
# USAGE
#
#   scripts/verify/transport-load.sh                    # 3 × 20 min
#   PHASE_SECS=2400 scripts/verify/transport-load.sh     # longer
#
# Artifacts in transport-load-<timestamp>/.

set -uo pipefail

PHASE_SECS="${PHASE_SECS:-1200}"
PHASES="${PHASES:-wt quic dtls}"
MAX_LOSS_PERCENT="${MAX_LOSS_PERCENT:-0}"
MAX_ERRORS="${MAX_ERRORS:-0}"
[[ "$PHASES" =~ [^[:space:]] ]] || { echo "PHASES must name a transport" >&2; exit 1; }
for phase in $PHASES; do
  case "$phase" in wt|quic|dtls|sctp) ;; *) echo "unknown phase: $phase" >&2; exit 1 ;; esac
done
[ -n "$PHASES" ] || { echo "PHASES must not be empty" >&2; exit 1; }
want() { case " $PHASES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
CONC="${CONC:-10}"
PPS="${PPS:-10}"
PAYLOAD="${PAYLOAD:-160}"
OUT="${OUT:-transport-load-$(date +%Y%m%d-%H%M%S)}"

TURN_PORT="${TURN_PORT:-3479}"
QUIC_PORT="${QUIC_PORT:-3480}"
DTLS_PORT="${DTLS_PORT:-5350}"
HEALTH_PORT="${HEALTH_PORT:-9095}"
SIGNALING_PORT="${SIGNALING_PORT:-9002}"
EXTERNAL_IP="${EXTERNAL_IP:-127.0.0.1}"
SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
SERVER_NAME="${SERVER_NAME:-localhost}"
CERT_PATH="${CERT_PATH:-}"
KEY_PATH="${KEY_PATH:-}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
mkdir -p "$OUT"

SECRET="tl-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
BUILD_FLAGS=(--release)
BIN_DIR=target/release
if [ "${BUILD_PROFILE:-release}" = dev ]; then BUILD_FLAGS=(); BIN_DIR=target/debug; fi
NODE="$BIN_DIR/turna-node"
LOAD="$BIN_DIR/turna-load-test"
FEATURES="tls,quic,web-transport,dtls"
if want sctp; then
  python3 scripts/verify/transport-observe.py sctp || exit 1
  FEATURES="$FEATURES,sctp"
fi
SUMMARY="$OUT/summary.md"
PASS=0
FAIL=0

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

[[ "$PHASE_SECS" =~ ^[1-9][0-9]*$ ]] || die "PHASE_SECS must be a positive integer"
if [ "${SHORT_RUN:-0}" != 1 ]; then
  [ "$PHASE_SECS" -gt 700 ] || die "Use SHORT_RUN=1 for a short load check"
fi

if curl -fsS --max-time 2 "http://127.0.0.1:$HEALTH_PORT/metrics" >/dev/null 2>&1; then
  die "127.0.0.1:$HEALTH_PORT is already in use. Set HEALTH_PORT, or the sampler would
read another process for the whole run."
fi

say "building"
cargo build --locked "${BUILD_FLAGS[@]}" -p turna-node --features "$FEATURES" \
  > "$OUT/build-node.log" 2>&1 || { tail -20 "$OUT/build-node.log"; die "node build failed"; }
cargo build --locked "${BUILD_FLAGS[@]}" -p turna-load-test --features "$FEATURES" \
  > "$OUT/build-load.log" 2>&1 || { tail -20 "$OUT/build-load.log"; die "load build failed"; }

if [ -z "$CERT_PATH" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 2 -subj "/CN=$SERVER_NAME" 2>/dev/null \
    || die "certificate generation failed"
  CERT_PATH="$PWD/$OUT/cert.pem"
  KEY_PATH="$PWD/$OUT/key.pem"
fi

{
  echo "# Transport load runs — $(date -u +%FT%TZ)"
  echo
  echo "- host: $(hostname), $(getconf _NPROCESSORS_ONLN) cpus"
  echo "- kernel: $(uname -sr)"
  echo "- per phase: ${PHASE_SECS}s, $CONC sessions, $PPS pps each, ${PAYLOAD} B payload"
  if [ "${SHORT_RUN:-0}" = 1 ]; then
    echo "- mode: SHORT LOAD CHECK; nonce expiry and endurance are not established"
  else
    echo "- mode: extended load; duration exceeds the 600 s binding lifetime"
  fi
  echo
  echo "| Transport | Sent | Relayed back | Loss | Errors | Verdict |"
  echo "|---|---|---|---|---|---|"
} > "$SUMMARY"

NODE_PID=""
SAMPLE_PID=""
stop_node() {
  if [ -n "$SAMPLE_PID" ]; then
    kill -TERM "$SAMPLE_PID" 2>/dev/null
    wait "$SAMPLE_PID" 2>/dev/null
    SAMPLE_PID=""
  fi
  [ -n "$NODE_PID" ] || return 0
  kill -TERM "$NODE_PID" 2>/dev/null
  for _ in $(seq 20); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
  kill -KILL "$NODE_PID" 2>/dev/null
  wait "$NODE_PID" 2>/dev/null
  NODE_PID=""
}
trap stop_node EXIT INT TERM

start_node() { # $1 = label, $2 = extra sections
  cat > "$OUT/turn-$1.toml" <<EOF
production = false
[turn]
listen      = "0.0.0.0:$TURN_PORT"
external_ip = "$EXTERNAL_IP"
realm       = "load"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 20000
max_port = 20847
max_allocations = 800
[turn.relay.quota]
max_per_user = 0
[health]
listen = "127.0.0.1:$HEALTH_PORT"
$2
EOF
  "$NODE" "$OUT/turn-$1.toml" > "$OUT/node-$1.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 40); do
    curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && return 0
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 0.5
  done
  say "  node did not start; last lines:"
  tail -10 "$OUT/node-$1.log"
  return 1
}

judge() { # $1 = transport, $2 = json file
  python3 - "$1" "$2" "$PHASE_SECS" "$3" "$MAX_LOSS_PERCENT" "$MAX_ERRORS" "$CONC" "$PPS" <<'PY'
import json, sys
name, path, phase = sys.argv[1], sys.argv[2], float(sys.argv[3])
client_rc, max_loss, max_errors = int(sys.argv[4]), float(sys.argv[5]), int(sys.argv[6])
try:
    d = json.loads(open(path).read().strip().splitlines()[-1])
except Exception as e:
    print(f"| {name} | — | — | — | — | **FAIL** (no result: {e}) |")
    sys.exit(1)
sent, recv, errs = d.get("sent", 0), d.get("recv", 0), d.get("errs", 0)
if sent == 0:
    print(f"| {name} | 0 | 0 | — | {errs} | **FAIL** (nothing sent) |")
    sys.exit(1)
loss = (sent - recv) / sent * 100
verdict = "**pass**"
note = ""
expected_sent = phase * int(sys.argv[7]) * int(sys.argv[8])
if client_rc != 0 or loss > max_loss or recv > sent + 2 * int(sys.argv[7]) or errs > max_errors or sent < expected_sent * 0.99 or float(d.get("duration_s", 0)) < phase * 0.99:
    verdict = "**FAIL**"
    if sent < expected_sent * 0.99:
        note = f" — incomplete send volume: expected about {expected_sent:.0f}"
    expected = 600.0 / phase * 100
    if abs((100 - loss) - expected) < 8:
        note = f" — matches 600/{phase:.0f}s: bindings expired, the driver is not refreshing"
print(f"| {name} | {sent} | {recv} | {loss:.2f}% | {errs} | {verdict}{note} |")
sys.exit(0 if verdict == "**pass**" else 1)
PY
}

run_phase() { # $1 = transport label, $2 = config sections, $3... = load command
  local label="$1" extra="$2"; shift 2
  say "phase $label: ${PHASE_SECS}s"
  if ! start_node "$label" "$extra"; then
    printf '| %s | — | — | — | — | **FAIL** (node did not start) |\n' "$label" >> "$SUMMARY"
    FAIL=$((FAIL + 1))
    stop_node
    return 1
  fi
  python3 scripts/verify/transport-observe.py sample --pid "$NODE_PID" --port "$HEALTH_PORT" \
    --out "$OUT/$label-resources.jsonl" &
  SAMPLE_PID=$!
  "$@" > "$OUT/$label.json" 2> "$OUT/$label.err"
  local client_rc=$?
  judge "$label" "$OUT/$label.json" "$client_rc" >> "$SUMMARY"
  # Captured immediately: anything between the command and a bare `$?` silently
  # changes what is being tested.
  local rc=$?
  if [ "$label" != dtls ]; then
    if ! python3 scripts/verify/transport-observe.py cleanup --transport "$label" --port "$HEALTH_PORT" > "$OUT/$label-cleanup.log" 2>&1; then
      printf '| %s cleanup | — | — | — | — | **FAIL** |\n' "$label" >> "$SUMMARY"
      rc=1
    fi
  fi
  # Stop sampling before inspecting JSONL, while the node is still alive.
  stop_node
  if python3 scripts/verify/transport-observe.py report --out "$OUT/$label-resources.jsonl" > "$OUT/$label-monitoring.log" 2>&1; then
    printf '| %s monitoring | — | — | — | — | **pass** |\n' "$label" >> "$SUMMARY"
  else
    printf '| %s monitoring | — | — | — | — | **FAIL** (incomplete samples) |\n' "$label" >> "$SUMMARY"
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    PASS=$((PASS + 1)); say "  pass  $label"
  else
    FAIL=$((FAIL + 1)); say "  FAIL  $label — see $label.json and $label.err"
  fi
  stop_node
}

WT_SECTION="$(printf '[turn.quic]\nenabled = true\nlisten = "[::]:%s"\ncert_path = "%s"\nkey_path = "%s"\nweb_transport = true\n' "$QUIC_PORT" "$CERT_PATH" "$KEY_PATH")"
QUIC_SECTION="$(printf '[turn.quic]\nenabled = true\nlisten = "0.0.0.0:%s"\ncert_path = "%s"\nkey_path = "%s"\nweb_transport = false\n' "$QUIC_PORT" "$CERT_PATH" "$KEY_PATH")"
DTLS_SECTION="$(printf '[turn.dtls]\nenabled = true\nlisten = "0.0.0.0:%s"\ncert_path = "%s"\nkey_path = "%s"\n' "$DTLS_PORT" "$CERT_PATH" "$KEY_PATH")"

if want wt; then
run_phase webtransport "$WT_SECTION" \
  "$LOAD" --secret "$SECRET" --duration "$PHASE_SECS" --warmup 30 --json \
  wt --url "https://$SERVER_NAME:$QUIC_PORT/" -c "$CONC" --pps "$PPS" --payload "$PAYLOAD"
fi

if want quic; then
run_phase quic "$QUIC_SECTION" \
  "$LOAD" --server "$SERVER_HOST:$QUIC_PORT" --secret "$SECRET" \
  --duration "$PHASE_SECS" --warmup 30 --json \
  quic -c "$CONC" --pps "$PPS" --payload "$PAYLOAD" --server-name "$SERVER_NAME"
fi

if want sctp; then
run_phase sctp '[turn.sctp]
enabled = true
listen = "127.0.0.1:3481"
max_connections_per_ip = 16' \
  "$LOAD" --server 127.0.0.1:3481 --secret "$SECRET" \
  --duration "$PHASE_SECS" --warmup 30 --json \
  sctp -c "$CONC" --pps "$PPS" --payload "$PAYLOAD"
fi

if want dtls; then
run_phase dtls "$DTLS_SECTION" \
  "$LOAD" --server "$SERVER_HOST:$DTLS_PORT" --secret "$SECRET" \
  --duration "$PHASE_SECS" --warmup 30 --json \
  dtls -c "$CONC" --pps "$PPS" --payload "$PAYLOAD"
fi

{
  echo
  echo "**$PASS passed, $FAIL failed.**"
  cat <<'EOF'

Load check only. These clients use the same transport libraries as the server:
the clients here share a library and one reading of the spec with the server, so a
shared misreading stays invisible. WebTransport has browser interop recorded separately
(`docs/interop/webtransport-browser-2026-08-20.md`). This run does not establish
independent interoperability or browser compatibility.
EOF
} >> "$SUMMARY"

say "done — $PASS passed, $FAIL failed"
echo
cat "$SUMMARY"
[ "$FAIL" -eq 0 ]
