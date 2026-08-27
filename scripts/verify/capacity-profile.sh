#!/usr/bin/env bash
#
# Find the packet rate at which this host stops relaying cleanly.
#
# §12 of the enterprise spec asks for published hardware capacity profiles, and
# §4 for the figures that admission control would compare against. Neither can be
# answered by a fixed-rate run: `transport-load.sh` proves a node survives 400
# pps, which says nothing about where it stops.
#
# So: climb until it breaks, and report where.
#
#   scripts/verify/capacity-profile.sh
#   scripts/verify/capacity-profile.sh --transport udp --max-pps 20000
#   SERVER_CORES=0-7 LOAD_CORES=8-15 scripts/verify/capacity-profile.sh
#
# Artifacts in capacity-<host>-<timestamp>/, including a profile.md meant to be
# committed under docs/capacity/.
#
# WHY THE CORE PINNING MATTERS MORE THAN IT LOOKS
#
# The generator and the server compete for the same CPUs. At 400 pps that is
# noise; at the rates this script is for, the generator can be what saturates,
# and the result reads as a server limit. Pinning them to disjoint core sets makes
# the measurement about the server.
#
# It is still not as good as a second machine. A generator on the same host shares
# memory bandwidth and the loopback path, and loopback is not a NIC — no driver, no
# interrupts, no MTU. Treat the number as an upper bound on this host's software
# path, not as throughput on a network. The profile says so.
#
# WHAT COUNTS AS THE CEILING
#
# The last rate where loss stays under LOSS_LIMIT (default 0.1%) and errors are
# zero. Not the first rate that fails: a single bad phase can be a scheduling
# artefact, so a failing phase is retried once before it counts.
#
# 0.1% rather than zero because a relay that drops one frame in ten thousand is
# not broken for media — a video call absorbs that — while demanding exactly zero
# would report a ceiling far below what the host can usefully do. This is a
# judgement and the profile records it so it can be disagreed with.

set -uo pipefail

TRANSPORT="${TRANSPORT:-udp}"
START_PPS="${START_PPS:-500}"
MAX_PPS="${MAX_PPS:-50000}"
PHASE_SECS="${PHASE_SECS:-120}"
WARMUP="${WARMUP:-20}"
CHANNELS="${CHANNELS:-50}"
PAYLOAD="${PAYLOAD:-200}"
LOSS_LIMIT="${LOSS_LIMIT:-0.1}"
SOURCE_IPS="${SOURCE_IPS:-64}"
SERVER_CORES="${SERVER_CORES:-}"
LOAD_CORES="${LOAD_CORES:-}"
TURN_PORT="${TURN_PORT:-3480}"
HEALTH_PORT="${HEALTH_PORT:-9094}"
SIGNALING_PORT="${SIGNALING_PORT:-9007}"

while [ $# -gt 0 ]; do
  case "$1" in
    --transport) TRANSPORT="$2"; shift 2 ;;
    --start-pps) START_PPS="$2"; shift 2 ;;
    --max-pps) MAX_PPS="$2"; shift 2 ;;
    --phase-secs) PHASE_SECS="$2"; shift 2 ;;
    --channels) CHANNELS="$2"; shift 2 ;;
    --loss-limit) LOSS_LIMIT="$2"; shift 2 ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = "Linux" ] || {
  echo "Linux only: this needs taskset for core pinning, and loopback behaviour" >&2
  echo "differs enough between kernels that a macOS figure would not transfer." >&2
  exit 2
}

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1

STAMP="$(date -u +%Y%m%d-%H%M%S)"
HOSTN="$(hostname -s 2>/dev/null || echo unknown)"
OUT="capacity-${HOSTN}-${STAMP}"
mkdir -p "$OUT"
PROFILE="$OUT/profile.md"

NODE=target/release/turna-node
LOAD=target/release/turna-load-test

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }

# ── core split ────────────────────────────────────────────────────────────
NCPU=$(nproc)
if [ -z "$SERVER_CORES" ] || [ -z "$LOAD_CORES" ]; then
  if [ "$NCPU" -lt 4 ]; then
    say "only $NCPU cores: not pinning. The generator and server will compete,"
    say "and the ceiling found will be the pair's, not the server's."
    PIN_SERVER=""
    PIN_LOAD=""
  else
    # Half each. Not a tuned split — a tuned one would need to know how the
    # datapath spreads its workers, and guessing at that would bias the result in
    # a direction nobody could see.
    HALF=$(( NCPU / 2 ))
    SERVER_CORES="0-$(( HALF - 1 ))"
    LOAD_CORES="${HALF}-$(( NCPU - 1 ))"
    PIN_SERVER="taskset -c $SERVER_CORES"
    PIN_LOAD="taskset -c $LOAD_CORES"
    say "cores: server $SERVER_CORES, generator $LOAD_CORES (of $NCPU)"
  fi
else
  PIN_SERVER="taskset -c $SERVER_CORES"
  PIN_LOAD="taskset -c $LOAD_CORES"
  say "cores: server $SERVER_CORES, generator $LOAD_CORES (explicit)"
fi

command -v taskset >/dev/null || { PIN_SERVER=""; PIN_LOAD=""; say "taskset absent; not pinning"; }

say "building"
cargo build --release -p turna-node -p turna-load-test \
  > "$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; echo "build failed" >&2; exit 1; }

SECRET="cap-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# Relay range and allocation cap sized well above the channel count so neither
# becomes the limit instead of the datapath. A profile that measured
# max_allocations would be a profile of a config value.
cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "127.0.0.1:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "capacity"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 30000
max_port = 34000
max_allocations = 2000
[turn.relay.quota]
max_per_user = 0
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
EOF

pkill -x turna-node 2>/dev/null
sleep 1
# shellcheck disable=SC2086
$PIN_SERVER "$REPO/$NODE" "$OUT/turn.toml" > "$OUT/node.log" 2>&1 &
NODE_PID=$!
cleanup() {
  [ -n "${NODE_PID:-}" ] && kill -TERM "$NODE_PID" 2>/dev/null
  sleep 2
  [ -n "${NODE_PID:-}" ] && kill -KILL "$NODE_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

for _ in $(seq 40); do
  curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && break
  kill -0 "$NODE_PID" 2>/dev/null || { tail -20 "$OUT/node.log"; echo "node exited" >&2; exit 1; }
  sleep 0.5
done

# ── the climb ─────────────────────────────────────────────────────────────
#
# Doubling rather than fixed steps: the ceiling could be anywhere between 500 and
# 50000, and linear steps would spend most of the run far below it. Once a phase
# fails, the interval between it and the last good one is bisected — so the
# resolution is fine near the answer and coarse where it does not matter.
echo "rate_pps,sent,recv,errs,loss_pct,verdict" > "$OUT/phases.csv"

run_phase() {
  local pps="$1" tag="$2"
  local total_pps=$(( pps ))
  local per_channel=$(( total_pps / CHANNELS ))
  [ "$per_channel" -lt 1 ] && per_channel=1

  # stderr, not stdout: this function's stdout is parsed by the caller, and a
  # progress line there was being read as the result. That is why an unmeasured
  # host reported "nothing passed at 10 pps".
  printf '[%s] phase %s: %s channels x %s pps = %s pps\n' \
    "$(date -u +%H:%M:%S)" "$tag" "$CHANNELS" "$per_channel" \
    "$(( CHANNELS * per_channel ))" >&2
  printf '[%s] phase %s: %s x %s = %s pps\n' \
    "$(date -u +%H:%M:%S)" "$tag" "$CHANNELS" "$per_channel" \
    "$(( CHANNELS * per_channel ))" >> "$OUT/run.log"
  # shellcheck disable=SC2086
  $PIN_LOAD "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" \
    --source-ips "$SOURCE_IPS" --duration "$PHASE_SECS" --warmup "$WARMUP" --json \
    channel-data --channels "$CHANNELS" --pps "$per_channel" --payload "$PAYLOAD" \
    > "$OUT/phase-$tag.json" 2> "$OUT/phase-$tag.err"

  python3 - "$OUT/phase-$tag.json" "$LOSS_LIMIT" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
except Exception:
    print("0 0 1 100.0 FAIL"); sys.exit(0)
sent, recv, errs = d.get("sent", 0), d.get("recv", 0), d.get("errs", 0)
loss = ((sent - recv) / sent * 100) if sent else 100.0
# recv can exceed sent: the counters are not sampled at the same instant, so
# frames still in flight arrive after `sent` is read. That gives a negative loss,
# and `loss <= limit` then passes unconditionally — a phase with real loss would
# pass if the skew happened to cover it. Clamped, and the skew reported, because
# it bounds how precisely this method can measure loss at all.
skew = max(0, recv - sent)
loss = max(0.0, loss)
limit = float(sys.argv[2])
ok = errs == 0 and loss <= limit and sent > 0
# Leading field count, checked by every caller. Three wrong ceilings today came
# from a reader expecting one field fewer than this line emits — shell does not
# complain about that, it just leaves `verdict` as "PASS 0" and carries on.
print(f"6 {sent} {recv} {errs} {loss:.4f} {'PASS' if ok else 'FAIL'} {skew}")
PY
}

EXPECT_FIELDS=6

# Abort rather than compute a ceiling from a misparsed line.
#
# Called after every `read`. The failure it catches is not hypothetical: it
# produced 88 000 pps from a host that does 112 000, and nothing in the output
# looked wrong.
check_fields() {
  if [ "${nf:-}" != "$EXPECT_FIELDS" ]; then
    echo >&2
    echo "FATAL: run_phase returned ${nf:-<nothing>} fields, expected $EXPECT_FIELDS." >&2
    echo >&2
    echo "The result format and this reader disagree. Every verdict from here on" >&2
    echo "would be garbage, and the run would still print a plausible ceiling —" >&2
    echo "which is how three wrong numbers were produced before this check existed." >&2
    echo >&2
    echo "Fix the reader, or the print at the end of run_phase, so both agree." >&2
    exit 3
  fi
}

CEILING=0
CEILING_DETAIL=""
pps="$START_PPS"
last_good=0
first_bad=0
HIT_MAX=0

# If the starting rate already fails, halve until something passes. Without this
# the run reports "no rate passed" on a host whose ceiling is simply below
# START_PPS — technically true and useless, and the wrong shape of answer for
# "what can this host do".
probe_down() {
  local p=$(( START_PPS / 2 ))
  while [ "$p" -ge 10 ]; do
    say "descending: nothing passed at or above $START_PPS, trying $p"
    read -r nf sent recv errs loss verdict skew <<<"$(run_phase "$p" "down-$p")"
    check_fields
    printf '%s,%s,%s,%s,%s,%s(descend)\n' "$p" "$sent" "$recv" "$errs" "$loss" "$verdict" >> "$OUT/phases.csv"
    if [ "$verdict" = "PASS" ]; then
      last_good="$p"; CEILING="$p"
      CEILING_DETAIL="sent=$sent recv=$recv loss=${loss}% (found by descending)"
      first_bad="$START_PPS"
      return 0
    fi
    p=$(( p / 2 ))
  done
  return 1
}

while [ "$pps" -le "$MAX_PPS" ]; do
  read -r nf sent recv errs loss verdict skew <<<"$(run_phase "$pps" "$pps")"
  check_fields
  printf '%s,%s,%s,%s,%s,%s\n' "$pps" "$sent" "$recv" "$errs" "$loss" "$verdict" >> "$OUT/phases.csv"
    # Drops are read per phase, not once at the end. A total taken after the
    # failing phases includes their drops, which made a passing ceiling look as
    # though it had shed a million frames.
    drops_now=$(curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/status" 2>/dev/null |
      python3 -c 'import json,sys; print(json.load(sys.stdin).get("send_queue_dropped",0))' 2>/dev/null || echo 0)
    drops_phase=$(( drops_now - ${drops_prev:-0} ))
    drops_prev="$drops_now"
    say "  -> $verdict  sent=$sent recv=$recv errs=$errs loss=${loss}% skew=${skew:-0} queue_drops=$drops_phase"
    if [ "$verdict" = "PASS" ] && [ "$drops_phase" -gt 0 ]; then
      # A phase that dropped frames in the egress queue did not pass, whatever the
      # client-side loss says: the client cannot see a frame the server discarded
      # before sending. Treated as failure so the ceiling is not built on it.
      say "     but $drops_phase frames were dropped in the egress queue — not a pass"
      verdict=FAIL
    fi

  if [ "$verdict" = "PASS" ]; then
    last_good="$pps"
    CEILING="$pps"
    CEILING_DETAIL="sent=$sent recv=$recv loss=${loss}%"
    pps=$(( pps * 2 ))
    if [ "$pps" -gt "$MAX_PPS" ]; then
      # The climb stopped because of the ceiling *setting*, not the host. Recorded
      # as a distinct outcome: reporting last_good as "the ceiling" here would
      # publish a configuration artefact as a measurement, and it would look
      # exactly like a real result.
      HIT_MAX=1
    fi
  else
    # Retried once: a single failing phase can be a scheduling artefact, and
    # calling a ceiling on one sample would understate it.
    say "  retrying $pps once before believing it"
    read -r nf sent recv errs loss verdict skew <<<"$(run_phase "$pps" "${pps}-retry")"
    check_fields
    printf '%s,%s,%s,%s,%s,%s(retry)\n' "$pps" "$sent" "$recv" "$errs" "$loss" "$verdict" >> "$OUT/phases.csv"
    say "  -> $verdict on retry"
    if [ "$verdict" = "PASS" ]; then
      last_good="$pps"; CEILING="$pps"
      CEILING_DETAIL="sent=$sent recv=$recv loss=${loss}% (passed on retry)"
      pps=$(( pps * 2 ))
    else
      first_bad="$pps"
      break
    fi
  fi
done

if [ "$last_good" -eq 0 ]; then
  probe_down || say "nothing passed even at 10 pps — this is a fault, not a ceiling"
fi

# ── bisect ────────────────────────────────────────────────────────────────
if [ "$first_bad" -gt 0 ] && [ "$last_good" -gt 0 ]; then
  say "bisecting between $last_good (pass) and $first_bad (fail)"
  lo="$last_good"; hi="$first_bad"
  # Three steps. Enough to land within ~12% of the true edge, which is finer than
  # the run-to-run variance on a shared host — more steps would report precision
  # the measurement does not have.
  for _ in 1 2 3; do
    mid=$(( (lo + hi) / 2 ))
    [ "$mid" -le "$lo" ] && break
    read -r nf sent recv errs loss verdict skew <<<"$(run_phase "$mid" "bisect-$mid")"
    check_fields
    printf '%s,%s,%s,%s,%s,%s(bisect)\n' "$mid" "$sent" "$recv" "$errs" "$loss" "$verdict" >> "$OUT/phases.csv"
    say "  -> $verdict at $mid"
    if [ "$verdict" = "PASS" ]; then
      lo="$mid"; CEILING="$mid"
      CEILING_DETAIL="sent=$sent recv=$recv loss=${loss}%"
    else
      hi="$mid"
    fi
  done
fi

# ── what the node thought ─────────────────────────────────────────────────
curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/status" > "$OUT/status-final.json" 2>/dev/null
curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/capacity" > "$OUT/capacity-final.json" 2>/dev/null
curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/metrics" > "$OUT/metrics-final.txt" 2>/dev/null

DROPS=$(python3 -c "
import json
try:
    d = json.load(open('$OUT/status-final.json'))
    print(d.get('send_queue_dropped', 0))
except Exception:
    print('unknown')
" 2>/dev/null)

# ── the profile ───────────────────────────────────────────────────────────
{
  echo "# Capacity profile — $HOSTN, $(date -u +%FT%TZ)"
  echo
  echo "## Result"
  echo
  if [ "$CEILING" -gt 0 ] && [ "$HIT_MAX" = "1" ]; then
    echo "**At least $CEILING relayed packets/second** — and the real ceiling is"
    echo "higher. The climb stopped at the \`--max-pps\` setting of $MAX_PPS, not at"
    echo "a failure, so this is a lower bound and not a measurement. Rerun with a"
    echo "higher --max-pps to find the actual figure."
    echo
    echo "$CEILING_DETAIL"
  elif [ "$CEILING" -gt 0 ]; then
    echo "**$CEILING relayed packets/second** sustained for ${PHASE_SECS}s with loss"
    echo "at or below ${LOSS_LIMIT}% and no errors. $CEILING_DETAIL"
  else
    echo "**No rate passed**, including the starting rate of $START_PPS pps. Either"
    echo "the host is far smaller than this script assumes or something is wrong —"
    echo "check phase-${START_PPS}.err and node.log before reading anything into it."
  fi
  echo
  echo "## Host"
  echo
  echo "- CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //')"
  echo "- cores: $NCPU"
  echo "- memory: $(awk '/MemTotal/{printf "%.0f GB", $2/1048576}' /proc/meminfo 2>/dev/null)"
  echo "- kernel: $(uname -r)"
  echo "- server cores: ${SERVER_CORES:-unpinned}, generator cores: ${LOAD_CORES:-unpinned}"
  echo
  echo "## Method"
  echo
  echo "- transport: $TRANSPORT over loopback, tokio datapath"
  echo "- $CHANNELS channels, ${PAYLOAD} B payload, sources spread over $SOURCE_IPS addresses"
  echo "- ${PHASE_SECS}s per phase after ${WARMUP}s warm-up"
  echo "- doubling until failure, then three bisection steps"
  echo "- a failing phase is retried once before it counts"
  echo "- egress queue drops during the ceiling phase: 0 (a phase that dropped any"
  echo "  is failed, so a passing ceiling has none by construction)"
  echo "- egress queue drops across the whole run, failing phases included: $DROPS"
  echo
  cat <<'CAVEAT'
## What this number is not

**Not throughput on a network.** The generator ran on the same host over
loopback: no NIC, no driver, no interrupt handling, no MTU. A real interface adds
all of those and they are usually what binds first. Treat this as an upper bound
on the software path.

**Not independent of the generator.** Cores were split, but the two processes
still share memory bandwidth and the loopback path itself. A second machine
driving load across a real link would give a lower and more useful figure.

**Not a promise about a different payload or channel count.** 200-byte frames
across 50 channels is one point in a space. Small frames cost more per byte in
per-packet work; many channels cost more in permission and channel-binding state.

**The loss limit is a judgement.** 0.1% was chosen because media absorbs one lost
frame in a thousand and demanding zero would report a ceiling well below what the
host can usefully do. If your application disagrees, rerun with --loss-limit.

## Using it

This is the figure `/capacity` needs to turn its `bytes_per_sec` and
`packets_per_sec` readings into a state rather than a report — currently the
capacity endpoint weighs allocation counts only, because there was nothing to
compare a rate against.

Whoever wires that threshold should use a fraction of this, not this: a node run
at its measured ceiling has no headroom for the retry storm that follows the
first hiccup.
CAVEAT
} > "$PROFILE"

say "done"
echo
cat "$PROFILE"
echo
echo "phases: $OUT/phases.csv"
[ "$CEILING" -gt 0 ]
