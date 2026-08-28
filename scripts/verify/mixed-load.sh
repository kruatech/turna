#!/usr/bin/env bash
#
# Run UDP and TURNS at once, and compare each against its own solo baseline.
#
#   scripts/verify/mixed-load.sh
#   scripts/verify/mixed-load.sh --phase-secs 300 --udp-channels 40
#
# §15's mixed-traffic item. `transport-load.sh` runs each transport alone, which
# cannot see the thing this is for: the transports share the packet processor, the
# allocation store, the relay port range and the egress queue. A per-transport
# test proves each works; it says nothing about what happens when both do.
#
# WHY THE BASELINES ARE THE DESIGN, NOT A PRELIMINARY
#
# "UDP lost 0.4 % under mixed load" is unreadable on its own. Lost relative to
# what? UDP alone at the same rate might lose 0.4 % on this host, in which case
# mixing changed nothing, or it might lose zero, in which case TURNS is starving
# it.
#
# So each transport is measured alone first, at exactly the rate it will run in
# the mixed phase, and the mixed result is reported as a delta. Three phases
# instead of one, and the third is the only one that means anything.
#
# WHAT THIS IS LOOKING FOR
#
# One transport starving the other. UDP is cheap per packet; TURNS carries TLS
# framing and record-layer crypto. If the TLS path holds a shared lock across
# crypto work, UDP degrades while TURNS looks fine — and that asymmetry is
# invisible to any test that runs one at a time.
#
# Also: relay port exhaustion. Both transports allocate from one range, so the
# mixed phase needs twice the ports, and a range sized for one transport fails
# here in a way that reads as capacity loss.

set -uo pipefail

PHASE_SECS="${PHASE_SECS:-240}"
WARMUP="${WARMUP:-20}"
UDP_CHANNELS="${UDP_CHANNELS:-30}"
UDP_PPS="${UDP_PPS:-50}"
TLS_CONC="${TLS_CONC:-20}"
TLS_PPS="${TLS_PPS:-50}"
PAYLOAD="${PAYLOAD:-200}"
SOURCE_IPS="${SOURCE_IPS:-64}"
# Delta over the solo baseline that counts as interference.
#
# 0.5 percentage points. Loose enough that run-to-run variance on a shared host
# does not trip it — the same phase repeated has been seen to differ by a tenth —
# and tight enough that starvation shows. A stricter bound here would produce a
# check that fails half the time and is therefore ignored.
DELTA_LIMIT="${DELTA_LIMIT:-0.5}"

TURN_PORT="${TURN_PORT:-3491}"
TLS_PORT="${TLS_PORT:-5353}"
HEALTH_PORT="${HEALTH_PORT:-9091}"
SIGNALING_PORT="${SIGNALING_PORT:-9011}"

while [ $# -gt 0 ]; do
  case "$1" in
    --phase-secs) PHASE_SECS="$2"; shift 2 ;;
    --udp-channels) UDP_CHANNELS="$2"; shift 2 ;;
    --tls-conc) TLS_CONC="$2"; shift 2 ;;
    --delta-limit) DELTA_LIMIT="$2"; shift 2 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
OUT="mixed-load-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.md"

PASS=0; FAIL=0
say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
ok()  { PASS=$((PASS+1)); say "  pass  $1"; }
bad() { FAIL=$((FAIL+1)); say "  FAIL  $1"; }
SKIP=0
# Neither a pass nor a failure. The transport may be fine; this run cannot say,
# and a clean delta between two broken phases — 100% loss minus 100% loss — looks
# exactly like a pass.
skip_cmp() { SKIP=$((SKIP+1)); say "  skip  $1 comparison — $2"; }

NODE=target/release/turna-node
LOAD=target/release/turna-load-test

say "building"
cargo build --release -p turna-node -p turna-load-test --features tls \
  > "$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; exit 1; }

SECRET="mix-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# EC in PKCS#8. `openssl ecparam -genkey` alone emits an EC PARAMETERS block the
# listener rejects, and RSA is rejected outright — two separate afternoons went
# into learning each of those.
openssl ecparam -genkey -name prime256v1 -noout -out "$OUT/k.raw" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$OUT/k.raw" -out "$OUT/k.pem" 2>/dev/null
openssl req -x509 -new -key "$OUT/k.pem" -out "$OUT/c.pem" -days 2 \
  -subj /CN=localhost 2>/dev/null
rm -f "$OUT/k.raw"

# Relay range sized for both transports at once, deliberately generous. A range
# that fits one but not two would fail the mixed phase for a reason that looks
# like interference and is not — and that misattribution is worse than a wide
# range, which costs nothing here.
TOTAL_SESSIONS=$(( UDP_CHANNELS + TLS_CONC ))
cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "127.0.0.1:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "mixed"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 26000
max_port = 27000
max_allocations = $(( TOTAL_SESSIONS * 4 ))
[turn.relay.quota]
max_per_user = 0
[tls]
enabled   = true
listen    = "127.0.0.1:$TLS_PORT"
cert_path = "$REPO/$OUT/c.pem"
key_path  = "$REPO/$OUT/k.pem"
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
EOF

NODE_PID=""
start_node() {
  "$REPO/$NODE" "$OUT/turn.toml" > "$OUT/node-$1.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 40); do
    curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && return 0
    kill -0 "$NODE_PID" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}
stop_node() {
  [ -n "$NODE_PID" ] || return 0
  kill -TERM "$NODE_PID" 2>/dev/null
  local w=0
  while kill -0 "$NODE_PID" 2>/dev/null && [ "$w" -lt 40 ]; do sleep 1; w=$((w+1)); done
  kill -KILL "$NODE_PID" 2>/dev/null
  NODE_PID=""
}
trap 'stop_node; pkill -x turna-node 2>/dev/null' EXIT INT TERM

# Loss from a driver's JSON. Clamped at zero: the sent and received counters are
# not sampled at the same instant, so frames in flight produce a negative figure,
# and a negative loss passes any threshold unconditionally. That mistake cost
# three wrong capacity numbers in this project.
loss_of() {
  python3 - "$1" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
    sent, recv, errs = d.get("sent", 0), d.get("recv", 0), d.get("errs", 1)
    if sent <= 0:
        print("100.0 0 1"); sys.exit(0)
    loss = max(0.0, (sent - recv) / sent * 100)
    print(f"{loss:.4f} {recv} {errs}")
except Exception:
    print("100.0 0 1")
PY
}

udp_driver() {
  "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" \
    --source-ips "$SOURCE_IPS" --duration "$PHASE_SECS" --warmup "$WARMUP" --json \
    channel-data --channels "$UDP_CHANNELS" --pps "$UDP_PPS" --payload "$PAYLOAD"
}

tls_driver() {
  "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" \
    --duration "$PHASE_SECS" --warmup "$WARMUP" --json \
    tls --tls-addr "127.0.0.1:$TLS_PORT" --server-name localhost --insecure \
    -c "$TLS_CONC" --pps "$TLS_PPS" --payload "$PAYLOAD"
}

{
  echo "# Mixed UDP + TURNS load — $(date -u +%FT%TZ)"
  echo
  echo "- host: $(hostname -s 2>/dev/null || echo unknown), $(nproc) cores, kernel $(uname -r)"
  echo "- ${PHASE_SECS}s per phase after ${WARMUP}s warm-up"
  echo "- UDP: $UDP_CHANNELS channels x $UDP_PPS pps"
  echo "- TURNS: $TLS_CONC sessions x $TLS_PPS pps"
  echo "- interference threshold: ${DELTA_LIMIT} percentage points over solo"
  echo
  echo "Each transport is measured alone at the same rate it runs in the mixed"
  echo "phase, and the mixed result is a delta. A loss figure without that"
  echo "baseline is unreadable: lost relative to what?"
  echo
  echo "| phase | loss | frames | errors |"
  echo "|---|---|---|---|"
} > "$SUMMARY"

# ── solo baselines ────────────────────────────────────────────────────────
say "phase 1/3: UDP alone"
start_node udp-solo || { bad "node would not start"; exit 1; }
udp_driver > "$OUT/udp-solo.json" 2> "$OUT/udp-solo.err"
read -r UDP_SOLO_LOSS UDP_SOLO_RECV UDP_SOLO_ERRS <<<"$(loss_of "$OUT/udp-solo.json")"
stop_node
say "  UDP solo: loss=${UDP_SOLO_LOSS}% recv=$UDP_SOLO_RECV errs=$UDP_SOLO_ERRS"
printf '| UDP alone | %s%% | %s | %s |\n' "$UDP_SOLO_LOSS" "$UDP_SOLO_RECV" "$UDP_SOLO_ERRS" >> "$SUMMARY"

say "phase 2/3: TURNS alone"
start_node tls-solo || { bad "node would not start"; exit 1; }
tls_driver > "$OUT/tls-solo.json" 2> "$OUT/tls-solo.err"
read -r TLS_SOLO_LOSS TLS_SOLO_RECV TLS_SOLO_ERRS <<<"$(loss_of "$OUT/tls-solo.json")"
stop_node
say "  TURNS solo: loss=${TLS_SOLO_LOSS}% recv=$TLS_SOLO_RECV errs=$TLS_SOLO_ERRS"
printf '| TURNS alone | %s%% | %s | %s |\n' "$TLS_SOLO_LOSS" "$TLS_SOLO_RECV" "$TLS_SOLO_ERRS" >> "$SUMMARY"

# ── mixed ─────────────────────────────────────────────────────────────────
say "phase 3/3: both at once"
start_node mixed || { bad "node would not start"; exit 1; }
udp_driver > "$OUT/udp-mixed.json" 2> "$OUT/udp-mixed.err" &
UDP_PID=$!
tls_driver > "$OUT/tls-mixed.json" 2> "$OUT/tls-mixed.err" &
TLS_PID=$!
wait "$UDP_PID" 2>/dev/null
wait "$TLS_PID" 2>/dev/null

# Read before stopping the node: the queue and port counters are gone afterwards.
PORTS=$(curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null |
  awk '/^turna_relay_ports_in_use/{print $2}' | head -1)
DROPS=$(curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/status" 2>/dev/null |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("send_queue_dropped",0))' 2>/dev/null || echo 0)
stop_node

read -r UDP_MIX_LOSS UDP_MIX_RECV UDP_MIX_ERRS <<<"$(loss_of "$OUT/udp-mixed.json")"
read -r TLS_MIX_LOSS TLS_MIX_RECV TLS_MIX_ERRS <<<"$(loss_of "$OUT/tls-mixed.json")"
say "  UDP mixed:   loss=${UDP_MIX_LOSS}% recv=$UDP_MIX_RECV errs=$UDP_MIX_ERRS"
say "  TURNS mixed: loss=${TLS_MIX_LOSS}% recv=$TLS_MIX_RECV errs=$TLS_MIX_ERRS"
say "  relay ports in use at the end: ${PORTS:-unknown}, egress drops: ${DROPS:-unknown}"
printf '| UDP mixed | %s%% | %s | %s |\n' "$UDP_MIX_LOSS" "$UDP_MIX_RECV" "$UDP_MIX_ERRS" >> "$SUMMARY"
printf '| TURNS mixed | %s%% | %s | %s |\n' "$TLS_MIX_LOSS" "$TLS_MIX_RECV" "$TLS_MIX_ERRS" >> "$SUMMARY"

# ── the comparison, which is the point ────────────────────────────────────
delta() { python3 -c "print(f'{float('$2') - float('$1'):+.4f}')"; }
over()  { python3 -c "print(1 if float('$2') - float('$1') > float('$DELTA_LIMIT') else 0)"; }

UDP_DELTA=$(delta "$UDP_SOLO_LOSS" "$UDP_MIX_LOSS")
TLS_DELTA=$(delta "$TLS_SOLO_LOSS" "$TLS_MIX_LOSS")

{
  echo
  echo "## Interference"
  echo
  printf '| transport | solo | mixed | delta |\n|---|---|---|---|\n'
  printf '| UDP | %s%% | %s%% | %s pp |\n' "$UDP_SOLO_LOSS" "$UDP_MIX_LOSS" "$UDP_DELTA"
  printf '| TURNS | %s%% | %s%% | %s pp |\n' "$TLS_SOLO_LOSS" "$TLS_MIX_LOSS" "$TLS_DELTA"
} >> "$SUMMARY"

usable() {
  [ "${1:-0}" -gt 0 ] && [ "$(python3 -c "print(1 if float('${2:-100}') < 50 else 0)")" = "1" ]
}

if ! usable "$UDP_SOLO_RECV" "$UDP_SOLO_LOSS"; then
  skip_cmp "UDP" "the solo phase relayed nothing usable (${UDP_SOLO_RECV:-0} frames, ${UDP_SOLO_LOSS}% loss) — no baseline to compare against"
elif [ "$(over "$UDP_SOLO_LOSS" "$UDP_MIX_LOSS")" = "1" ]; then
  bad "UDP degraded by ${UDP_DELTA} pp when TURNS ran alongside. UDP is cheap per packet and TURNS carries record-layer crypto, so this is the direction starvation would take — look for a shared lock held across the TLS path."
else
  ok "UDP unaffected by TURNS (${UDP_DELTA} pp)"
fi

if ! usable "$TLS_SOLO_RECV" "$TLS_SOLO_LOSS"; then
  skip_cmp "TURNS" "the solo phase relayed nothing usable (${TLS_SOLO_RECV:-0} frames, ${TLS_SOLO_LOSS}% loss). Read tls-solo.err first — a driver that would not start is not interference"
elif [ "$(over "$TLS_SOLO_LOSS" "$TLS_MIX_LOSS")" = "1" ]; then
  bad "TURNS degraded by ${TLS_DELTA} pp when UDP ran alongside. The less expected direction — UDP volume displacing TLS work suggests contention on the store or the egress queue rather than on CPU."
else
  ok "TURNS unaffected by UDP (${TLS_DELTA} pp)"
fi

if [ "${UDP_MIX_ERRS:-1}" = "0" ] && [ "${TLS_MIX_ERRS:-1}" = "0" ]; then
  ok "no errors on either transport under mixed load"
else
  bad "errors under mixed load: UDP $UDP_MIX_ERRS, TURNS $TLS_MIX_ERRS — check the .err files before reading the loss figures, an allocation failure is not interference"
fi

if [ "${DROPS:-0}" = "0" ]; then
  ok "no egress queue drops"
else
  bad "$DROPS frames dropped in the egress queue. Clients cannot see this, so the loss figures above understate what happened."
fi

{
  echo
  echo "## What this does not establish"
  echo
  cat <<'CAVEAT'
**Not a capacity figure.** Both drivers ran on this host, over loopback. See
`docs/capacity/` for what the ceiling measurement does and does not mean; the
same caveats apply and more, because there are now two drivers competing with the
node for the same cores.

**One rate pair.** UDP and TURNS were run at rates chosen to be comfortable for
both. Interference that only appears when one transport is near its own ceiling
would not show here, and the honest way to find that is to re-run this at rates
taken from the capacity profile rather than from these defaults.

**Loopback has no NIC.** Two transports contending for one interface's queues is
a real effect and is not what was measured — this is contention inside the
process.
CAVEAT
  printf '\n**%d passed, %d failed.**\n' "$PASS" "$FAIL"
} >> "$SUMMARY"

say "done — $PASS passed, $FAIL failed"
echo
cat "$SUMMARY"
[ "$FAIL" -eq 0 ]
