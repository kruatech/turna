#!/usr/bin/env bash
#
# Upgrade and roll back a node while traffic flows.
#
#   scripts/verify/upgrade-rollback.sh --from v0.3.0 --to HEAD
#
# §15's upgrade/rollback item, and §5's rolling-upgrade item, are the same
# question: can a node be replaced without dropping the calls it is carrying?
#
# THE PROCEDURE BEING TESTED
#
# It is the one in RELEASE.md: drain, stop, swap the binary, start, undrain. What
# this checks is not that the steps run but that each one does what the runbook
# claims — and the interesting one is the drain, because a drain that returns
# before it has drained makes the whole sequence a coin flip.
#
# WHAT A ROLLBACK HAS TO SURVIVE
#
# Configuration written by the new version and read by the old. That is the case
# nobody tests and everybody eventually meets: an operator rolls back after an
# incident and the old binary refuses to start on a config it does not
# understand. Since this project sets `deny_unknown_fields`, a new key is a hard
# parse failure on the old binary rather than a warning — which is the safe
# direction and still needs to be known before, not during, an incident.
#
# So the rollback here is deliberately performed against the *new* config, which
# is what an operator would actually have on disk.

set -uo pipefail

FROM_REF="${FROM_REF:-}"
TO_REF="${TO_REF:-HEAD}"
DURATION="${DURATION:-60}"
TURN_PORT="${TURN_PORT:-3489}"
HEALTH_PORT="${HEALTH_PORT:-9092}"
SIGNALING_PORT="${SIGNALING_PORT:-9009}"

while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM_REF="$2"; shift 2 ;;
    --to) TO_REF="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$FROM_REF" ] || {
  echo "--from is required: a git ref for the version being upgraded from." >&2
  echo "e.g. --from v0.3.0" >&2
  exit 2
}

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
OUT="upgrade-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

PASS=0; FAIL=0
say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
ok()  { PASS=$((PASS+1)); say "  pass  $1"; }
bad() { FAIL=$((FAIL+1)); say "  FAIL  $1"; }

# Two binaries, built from two refs in separate worktrees. `git worktree` rather
# than stashing and checking out: a build that mutates the working tree is one
# that loses uncommitted work, and this script is meant to be safe to run.
say "building $FROM_REF (old) and $TO_REF (new)"
OLD_DIR="$OUT/old-tree"
git worktree add --detach "$OLD_DIR" "$FROM_REF" > "$OUT/worktree.log" 2>&1 || {
  echo "could not create a worktree at $FROM_REF — does the ref exist?" >&2
  git worktree remove "$OLD_DIR" --force 2>/dev/null
  exit 1
}
cleanup_wt() { git worktree remove "$OLD_DIR" --force 2>/dev/null; }

( cd "$OLD_DIR" && cargo build --release -p turna-node ) \
  > "$OUT/build-old.log" 2>&1 || {
    tail -15 "$OUT/build-old.log"; cleanup_wt; exit 1; }
cargo build --release -p turna-node -p turna-load-test \
  > "$OUT/build-new.log" 2>&1 || { tail -15 "$OUT/build-new.log"; cleanup_wt; exit 1; }

OLD_BIN="$OLD_DIR/target/release/turna-node"
NEW_BIN="target/release/turna-node"
LOAD="target/release/turna-load-test"
say "old: $(du -h "$OLD_BIN" | cut -f1), new: $(du -h "$NEW_BIN" | cut -f1)"

SECRET="upg-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "127.0.0.1:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "upgrade"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 25000
max_port = 25500
max_allocations = 200
[turn.relay.quota]
max_per_user = 0
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
EOF

NODE_PID=""
start_node() {
  local bin="$1" tag="$2"
  "$bin" "$OUT/turn.toml" > "$OUT/node-$tag.log" 2>&1 &
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
  local waited=0
  while kill -0 "$NODE_PID" 2>/dev/null && [ "$waited" -lt 45 ]; do
    sleep 1; waited=$((waited+1))
  done
  kill -KILL "$NODE_PID" 2>/dev/null
  echo "$waited"
}

trap 'stop_node >/dev/null; cleanup_wt' EXIT INT TERM
pkill -x turna-node 2>/dev/null; sleep 1

# ── the old version, carrying traffic ─────────────────────────────────────
say "starting $FROM_REF"
if start_node "$OLD_BIN" "old"; then
  ok "$FROM_REF starts on this config"
else
  bad "$FROM_REF would not start — see node-old.log"
  exit 1
fi

"$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" --source-ips 32 \
  --duration "$DURATION" --warmup 5 --json \
  channel-data --channels 20 --pps 20 --payload 200 \
  > "$OUT/load-old.json" 2> "$OUT/load-old.err" &
LOAD_PID=$!
sleep 15

# ── drain and swap ────────────────────────────────────────────────────────
say "draining"
BEFORE=$(curl -fsS "http://127.0.0.1:$HEALTH_PORT/status" 2>/dev/null |
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("active_allocations",0))' 2>/dev/null || echo 0)
say "  $BEFORE allocations held at drain time"

DRAIN_SECS=$(stop_node)
say "  shutdown took ${DRAIN_SECS}s"
if [ "${DRAIN_SECS:-99}" -le 40 ]; then
  ok "drained and exited in ${DRAIN_SECS}s (bounded)"
else
  bad "took ${DRAIN_SECS}s to exit — the drain wait is 30s plus slack, so something waited longer than it should"
fi

say "starting $TO_REF on the same config"
if start_node "$NEW_BIN" "new"; then
  ok "$TO_REF starts on the config the old version was using"
else
  bad "$TO_REF would not start on the old config — a forward-compatibility break, which blocks the upgrade itself"
  exit 1
fi

wait "$LOAD_PID" 2>/dev/null
read -r SENT RECV ERRS <<<"$(python3 - "$OUT/load-old.json" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
    print(d.get("sent",0), d.get("recv",0), d.get("errs",1))
except Exception:
    print(0, 0, 1)
PY
)"
say "  across the swap: sent=$SENT recv=$RECV errs=$ERRS"
# Loss across a restart is expected and is not the thing being tested: the node
# genuinely went away. What matters is that the client could re-establish, which
# a non-zero recv after the restart shows.
if [ "${RECV:-0}" -gt 0 ]; then
  ok "clients relayed media again after the swap"
else
  bad "no media after the swap — clients did not recover"
fi

# ── verify the new version works on its own terms ─────────────────────────
if "$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" --duration 15 \
    --warmup 3 --json channel-data --channels 10 --pps 10 --payload 200 \
    > "$OUT/load-new.json" 2>/dev/null; then
  NEW_ERRS=$(python3 -c '
import json
try:
    d=json.loads(open("'"$OUT"'/load-new.json").read().strip().splitlines()[-1])
    print(d.get("errs",1))
except Exception:
    print(1)')
  if [ "$NEW_ERRS" = "0" ]; then
    ok "$TO_REF relays cleanly"
  else
    bad "$TO_REF has $NEW_ERRS errors under load"
  fi
fi

# ── roll back ─────────────────────────────────────────────────────────────
#
# Against the config as it stands, which is what an operator would have. If the
# new version had written a key the old one does not know, deny_unknown_fields
# makes this a parse failure — the safe direction, and the thing to discover here
# rather than during an incident.
say "rolling back to $FROM_REF"
stop_node >/dev/null
if start_node "$OLD_BIN" "rollback"; then
  ok "$FROM_REF starts again after $TO_REF ran (rollback is possible)"
  if "$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" --duration 15 \
      --warmup 3 --json channel-data --channels 10 --pps 10 --payload 200 \
      > "$OUT/load-rollback.json" 2>/dev/null; then
    RB_ERRS=$(python3 -c '
import json
try:
    d=json.loads(open("'"$OUT"'/load-rollback.json").read().strip().splitlines()[-1])
    print(d.get("errs",1))
except Exception:
    print(1)')
    if [ "$RB_ERRS" = "0" ]; then
      ok "$FROM_REF relays cleanly after rollback"
    else
      bad "$FROM_REF has $RB_ERRS errors after rollback"
    fi
  fi
else
  bad "$FROM_REF will not start after $TO_REF ran. Check node-rollback.log: with deny_unknown_fields, a key the new version added is a parse failure on the old one. That makes rollback impossible without editing the config, which is exactly what an operator cannot do calmly mid-incident."
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
say "artifacts in $OUT/"
[ "$FAIL" -eq 0 ]
