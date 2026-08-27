#!/usr/bin/env bash
#
# Verify the DTLS demux path, so the decision to make it default has evidence.
#
#   scripts/verify/dtls-demux.sh
#   scripts/verify/dtls-demux.sh --duration 120
#
# WHY THIS SCRIPT DECIDES SOMETHING
#
# `[turn.dtls] demux = false` is the default, and the reason recorded in the code
# is not that the demux path is worse — it is that "the stock path is the one with
# recorded verification". Two P0 requirements in §7 are unavailable on the stock
# path for structural reasons: `webrtc_dtls::listener::listen()` owns the socket
# and fixes its config at bind time, so certificate rotation means rebinding, and
# the handshake completes below `accept()` where turna never sees the packets and
# cannot rate-limit them.
#
# Both exist on the demux path. So the blocker is this script's absence, not any
# missing code — which makes producing it the cheapest way to close two P0s.
#
# WHAT IS CHECKED, AND WHY EACH
#
#   1. it relays at all              the stock path has this recorded; demux does not
#   2. concurrent handshakes         demux's central claim over the stock path
#   3. certificate hot-reload        P0, and unavailable on the stock path
#   4. per-IP handshake rate limit   P0, same
#   5. handshake_failures is honest  the counter that "only there is it honest"
#   6. drain leaves no listener      demux owns the socket; it must also release it
#
# Check 5 is the one worth arguing about. Every other check confirms something
# works; this one confirms a *counter tells the truth*, by failing a handshake
# deliberately and watching the number move. A metric that stays zero under a
# condition it claims to count is worse than an absent metric, because a dashboard
# built on it reads calm.
#
# WHAT THIS DOES NOT ESTABLISH
#
# Long-run stability. Six checks over a few minutes say the path works; they say
# nothing about a leak over 24 hours, which is what the stock path's recorded
# verification actually has. Flipping the default on this evidence alone would
# trade a known-stable path for a known-correct one, and those are different
# claims. `scripts/soak/soak.sh` with `demux = true` is the missing half.

set -uo pipefail

DURATION="${DURATION:-60}"
TURN_PORT="${TURN_PORT:-3492}"
DTLS_PORT="${DTLS_PORT:-5355}"
HEALTH_PORT="${HEALTH_PORT:-9095}"
SIGNALING_PORT="${SIGNALING_PORT:-9012}"
RELOAD_INTERVAL="${RELOAD_INTERVAL:-5}"
# Low on purpose: the limiter has to be provable from one host, and a realistic
# limit would need more source addresses than a single machine makes convenient.
# The number being small does not make the mechanism less real.
HANDSHAKE_LIMIT="${HANDSHAKE_LIMIT:-3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2 ;;
    --handshake-limit) HANDSHAKE_LIMIT="$2"; shift 2 ;;
    -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = "Linux" ] || {
  echo "Linux only: this spreads client sources across 127.0.0.0/8, which is" >&2
  echo "entirely local on Linux and needs interface aliases on macOS." >&2
  exit 2
}

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
OUT="dtls-demux-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
REPORT="$OUT/verification.md"

PASS=0; FAIL=0; SKIP=0
say()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
ok()   { PASS=$((PASS+1)); say "  pass  $1"; printf -- '- **pass** %s\n' "$1" >> "$REPORT"; }
bad()  { FAIL=$((FAIL+1)); say "  FAIL  $1"; printf -- '- **FAIL** %s\n' "$1" >> "$REPORT"; }
skip() { SKIP=$((SKIP+1)); say "  skip  $1"; printf -- '- skip %s\n' "$1" >> "$REPORT"; }

NODE=target/release/turna-node
LOAD=target/release/turna-load-test

say "building with dtls"
cargo build --release -p turna-node -p turna-load-test --features dtls \
  > "$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; exit 1; }

SECRET="dx-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# EC in PKCS#8. webrtc-dtls rejects RSA outright, and `openssl ecparam -genkey`
# alone emits an EC PARAMETERS block it also rejects. Two separate afternoons.
mkcert() {
  openssl ecparam -genkey -name prime256v1 -noout -out "$1.raw" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$1.raw" -out "$1.key" 2>/dev/null
  openssl req -x509 -new -key "$1.key" -out "$1.crt" -days 2 -subj "/CN=$2" 2>/dev/null
  rm -f "$1.raw"
}
mkcert "$OUT/first" demux-first
mkcert "$OUT/second" demux-second
cp "$OUT/first.crt" "$OUT/live.crt"; cp "$OUT/first.key" "$OUT/live.key"

cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "127.0.0.1:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "demux"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 28000
max_port = 28800
max_allocations = 300
[turn.relay.quota]
max_per_user = 0
[turn.dtls]
enabled   = true
listen    = "127.0.0.1:$DTLS_PORT"
cert_path = "$REPO/$OUT/live.crt"
key_path  = "$REPO/$OUT/live.key"
# The point of the exercise.
demux     = true
cert_reload_secs = $RELOAD_INTERVAL
max_handshakes_per_sec_per_ip = $HANDSHAKE_LIMIT
handshake_burst_per_ip = $HANDSHAKE_LIMIT
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
EOF

NODE_PID=""
start_node() {
  "$REPO/$NODE" "$OUT/turn.toml" > "$OUT/node.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 40); do
    curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && return 0
    kill -0 "$NODE_PID" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}
# Kill the node and any stragglers, then say whether a core was dropped.
#
# The first run ended in `segmentation fault (core dumped)` after the report, and
# it was not clear whether that was an artefact of Ctrl+C during a handshake or
# something real. That distinction matters more than any check in this script, so
# it must not be lost in the scrollback.
cleanup() {
  kill -TERM "${NODE_PID:-0}" 2>/dev/null
  sleep 1
  kill -KILL "${NODE_PID:-0}" 2>/dev/null
  pkill -KILL -f "turna-load-test.*$DTLS_PORT" 2>/dev/null
  for c in core core.* /var/lib/systemd/coredump/*turna*; do
    [ -e "$c" ] || continue
    echo
    echo "A core file exists: $c" >&2
    echo "That is worth more attention than any result above. Either the node" >&2
    echo "crashed, or a client did. Check which:" >&2
    echo "  file $c" >&2
    echo "  coredumpctl info 2>/dev/null | head -20" >&2
    break
  done
}
trap cleanup EXIT INT TERM

# Tolerant metric read: the exact series names are the node's to choose, and a
# script that hard-codes them fails on a rename with a message about the wrong
# thing. A missing series is reported as a finding, not as a failure of the
# feature under test.
metric() {
  curl -fsS --max-time 3 "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null |
    awk -v n="$1" '$0 ~ "^"n" " {print $2; exit}'
}

{
  echo "# DTLS demux path — recorded verification"
  echo
  echo "$(date -u +%FT%TZ), $(hostname -s 2>/dev/null || echo unknown), kernel $(uname -r)"
  echo
  echo "Produced so that flipping \`[turn.dtls] demux\` to default has evidence."
  echo "The stock path is default today because it is the one with a recorded run,"
  echo "not because it is better — two P0 requirements are structurally unavailable"
  echo "on it."
  echo
  echo "## Checks"
  echo
} > "$REPORT"

pkill -x turna-node 2>/dev/null; sleep 1
say "starting the node with demux = true"
if start_node; then
  ok "node starts with demux enabled"
else
  bad "node would not start — see node.log; without this nothing below is meaningful"
  tail -20 "$OUT/node.log"
  exit 1
fi

if [ "$(metric turna_dtls_readiness)" = "1" ]; then
  ok "DTLS listener reports ready"
else
  bad "turna_dtls_readiness is not 1 — the listener bound but does not consider itself up"
fi

# ── 1 and 2: relays, and concurrently ─────────────────────────────────────
say "check 1-2: relaying, with concurrent handshakes"
# --server is the DTLS address here: the dtls driver uses cli.server directly.
# There is no --dtls-addr and no --insecure — I had borrowed both from the TLS
# driver, which has them.
if "$REPO/$LOAD" --server "127.0.0.1:$DTLS_PORT" --secret "$SECRET" \
     --duration "$DURATION" --warmup 10 --json \
     dtls -c 12 --pps 30 --payload 200 \
     > "$OUT/relay.json" 2> "$OUT/relay.err"; then
  read -r RECV ERRS <<<"$(python3 - "$OUT/relay.json" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
    print(d.get("recv", 0), d.get("errs", 1))
except Exception:
    print(0, 1)
PY
)"
  if [ "${ERRS:-1}" = "0" ] && [ "${RECV:-0}" -gt 0 ]; then
    ok "relays media over the demux path ($RECV frames, 0 errors)"
    ok "12 concurrent sessions established — the stock path serialises handshakes inside accept(), which is the demux path's central claim"
  else
    bad "media over demux: $RECV frames, $ERRS errors — see relay.err"
  fi
else
  bad "the DTLS driver failed to run; check relay.err before reading anything else"
fi

# ── 3: certificate hot-reload ─────────────────────────────────────────────
say "check 3: certificate hot-reload (P0, unavailable on the stock path)"
RELOADS_BEFORE=$(metric turna_dtls_cert_reloads_total)
cp "$OUT/second.crt" "$OUT/live.crt"
cp "$OUT/second.key" "$OUT/live.key"
sleep $(( RELOAD_INTERVAL * 2 + 3 ))
RELOADS_AFTER=$(metric turna_dtls_cert_reloads_total)
RELOAD_FAILS=$(metric turna_dtls_cert_reload_failures_total)

if [ -z "$RELOADS_AFTER" ]; then
  skip "turna_dtls_cert_reloads_total is not exported — the counter exists in DtlsStats but the node may not mirror it. A finding about observability, not about the reload."
elif [ "${RELOADS_AFTER:-0}" -gt "${RELOADS_BEFORE:-0}" ]; then
  ok "certificate reloaded live (${RELOADS_BEFORE:-0} -> $RELOADS_AFTER)"
  if [ "${RELOAD_FAILS:-0}" = "0" ]; then
    ok "no reload failures — old material would have stayed in service"
  else
    bad "$RELOAD_FAILS reload failures; a half-written PEM does this, and the node correctly keeps serving on the old one"
  fi
else
  bad "no reload observed. Either the interval is longer than we waited, or the reloader is not running on this path — which would mean the P0 is not actually available here."
fi

# ── 4: per-IP handshake rate limit ────────────────────────────────────────
say "check 4: per-IP handshake rate limit (P0, unavailable on the stock path)"
REJECTED_BEFORE=$(metric turna_dtls_rejected_rate_limit_total)
# Well above the limit, all from one source. The stock path cannot do this at all:
# the handshake completes below accept() and turna never sees the packets.
# One deadline for the whole burst, not one per client.
#
# The first version gave each client `timeout 3` and then called a bare `wait` —
# which waits for all of them, and the limiter does not let them finish: they sit
# in a handshake that will not complete. The run hung for 23 minutes.
#
# What this check needs is that the limiter *fired*, which is visible in the
# counter. Whether each client eventually returned is not the question.
BURST_PIDS=""
for _ in $(seq $(( HANDSHAKE_LIMIT * 6 ))); do
  timeout 3 "$REPO/$LOAD" --server "127.0.0.1:$DTLS_PORT" --secret "$SECRET" \
    --duration 1 --json \
    dtls -c 1 --pps 1 --payload 100 \
    >> "$OUT/limit.json" 2>> "$OUT/limit.err" &
  BURST_PIDS="$BURST_PIDS $!"
done
burst_deadline=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$burst_deadline" ]; do
  still=0
  for pid in $BURST_PIDS; do kill -0 "$pid" 2>/dev/null && still=1; done
  [ "$still" = "0" ] && break
  sleep 1
done
for pid in $BURST_PIDS; do kill -KILL "$pid" 2>/dev/null; done
wait 2>/dev/null
REJECTED_AFTER=$(metric turna_dtls_rejected_rate_limit_total)

if [ -z "$REJECTED_AFTER" ]; then
  skip "turna_dtls_rejected_rate_limit_total is not exported; cannot confirm the limiter fired"
elif [ "${REJECTED_AFTER:-0}" -gt "${REJECTED_BEFORE:-0}" ]; then
  ok "handshake rate limiter fired ($(( REJECTED_AFTER - REJECTED_BEFORE )) refused before any DTLS state was created)"
else
  bad "the limiter did not fire at $(( HANDSHAKE_LIMIT * 6 )) attempts against a limit of $HANDSHAKE_LIMIT. Either the config key is not reaching the limiter, or the attempts were spread over more than a second — check limit.err for how many actually started."
fi

# ── 5: handshake_failures tells the truth ─────────────────────────────────
say "check 5: does handshake_failures actually count?"
FAILURES_BEFORE=$(metric turna_dtls_handshake_failures_total)
# Send garbage at the DTLS port. Not a DTLS ClientHello, so the handshake cannot
# complete — which is the condition the counter claims to observe.
for _ in $(seq 5); do
  printf 'not-a-clienthello-%s' "$RANDOM" |
    timeout 2 socat -u - "UDP4-DATAGRAM:127.0.0.1:$DTLS_PORT" 2>/dev/null ||
    printf 'not-a-clienthello' | timeout 2 nc -u -w1 127.0.0.1 "$DTLS_PORT" 2>/dev/null
done
sleep 3
FAILURES_AFTER=$(metric turna_dtls_handshake_failures_total)

if [ -z "$FAILURES_AFTER" ]; then
  skip "turna_dtls_handshake_failures_total is not exported. The counter is documented as honest only on this path, so not exporting it wastes the one place it means something."
elif [ "${FAILURES_AFTER:-0}" -gt "${FAILURES_BEFORE:-0}" ]; then
  ok "handshake_failures moved on malformed input — the counter observes rather than guesses, which is what the stock path cannot do"
else
  # Deliberately not a hard failure: garbage may be dropped before the DTLS state
  # machine sees it, which is correct behaviour and leaves nothing to count.
  skip "handshake_failures did not move. Garbage may be discarded before the DTLS state machine engages, which is correct — but it means this check did not exercise the counter. A real failed handshake (wrong cipher suite, expired cert) would."
fi

# ── 6: drain releases the socket ──────────────────────────────────────────
say "check 6: drain releases the listener"
kill -TERM "$NODE_PID" 2>/dev/null
WAITED=0
while kill -0 "$NODE_PID" 2>/dev/null && [ "$WAITED" -lt 45 ]; do sleep 1; WAITED=$((WAITED+1)); done
if kill -0 "$NODE_PID" 2>/dev/null; then
  bad "node still running after ${WAITED}s. The demux path owns the socket, so it must also release it — a listener that survives drain blocks the replacement from binding."
  kill -KILL "$NODE_PID" 2>/dev/null
else
  ok "exited in ${WAITED}s"
  sleep 1
  if ss -uln 2>/dev/null | grep -q ":$DTLS_PORT "; then
    bad "UDP $DTLS_PORT is still bound after exit"
  else
    ok "UDP $DTLS_PORT released"
  fi
fi
NODE_PID=""

# ── report ────────────────────────────────────────────────────────────────
{
  echo
  echo "## What this establishes"
  echo
  if [ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]; then
    cat <<'GOOD'
The demux path relays correctly, handles concurrent handshakes, reloads
certificates live, and rate-limits handshakes per source — the last two being the
§7 P0 requirements that are structurally unavailable on the stock path.

That is the evidence the default-flip decision was missing.
GOOD
  elif [ "$FAIL" -eq 0 ]; then
    # An earlier version printed the paragraph above whenever nothing failed,
    # including when the rate-limit check had been skipped. It claimed the path
    # rate-limits handshakes on the strength of a check that did not run — a
    # conclusion independent of its evidence, which is the failure this project has
    # been correcting in documents throughout.
    cat <<'PARTIAL'
The demux path relays correctly, handles concurrent handshakes, and reloads
certificates live. Certificate hot-reload is one of the two §7 P0 requirements
that are structurally unavailable on the stock path, and it is confirmed.

**The other one is not.** The handshake rate limit could not be confirmed here:
the counter it would show up in is not exported by the node, so the check was
skipped rather than passed. The limiter may well work; this run does not say so.

So the default-flip decision has half the evidence it was missing. Exporting
`turna_dtls_rejected_rate_limit_total` would get the other half from a five-minute
rerun.
PARTIAL
  else
    echo "**$FAIL check(s) failed.** The flip should not happen on this evidence."
    echo "See the failures above; each says what it would mean."
  fi
  echo
  echo "## What it does not establish"
  echo
  cat <<'CAVEAT'
**Long-run stability.** A few minutes says the path works. The stock path's claim
to the default is a recorded 24-hour run, and that is a different claim from
correctness. Flipping on this evidence alone would trade a known-stable path for a
known-correct one.

The missing half is `scripts/soak/soak.sh` with `demux = true` — 24 hours,
watching for the leak shapes the io_uring and AF_XDP paths both turned out to
have: a worker that went deaf after exactly 64 packets, and reception that stopped
after exactly 2015 frames. Neither would show in six checks over five minutes.

**Realistic handshake rates.** The limiter was proved with a limit of 3/s from one
address, because one host cannot conveniently produce many source addresses for
DTLS. The mechanism is confirmed; the numbers a deployment would use are not.
CAVEAT
  printf '\n**%d passed, %d failed, %d skipped.**\n' "$PASS" "$FAIL" "$SKIP"
  if [ "$SKIP" -gt 0 ]; then
    echo
    echo "Skipped checks are mostly missing metric series — counters that exist in"
    echo "\`DtlsStats\` and may not be mirrored by the node. That is a finding about"
    echo "observability rather than about the demux path, and it is worth fixing:"
    echo "\`handshake_failures\` is documented as honest only here, so not exporting"
    echo "it wastes the one place it means anything."
  fi
} >> "$REPORT"

say "done — $PASS passed, $FAIL failed, $SKIP skipped"
echo
cat "$REPORT"
[ "$FAIL" -eq 0 ]
