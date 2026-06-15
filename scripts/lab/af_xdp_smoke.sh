#!/usr/bin/env bash
# AFX-7 lab smoke: bring up a veth pair, boot turna-node on the AF_XDP backend,
# verify the TURN datapath with the existing integration suite, then clean up.
#
# This is a LAB harness: AF_XDP needs Linux, root (CAP_NET_RAW + CAP_NET_ADMIN),
# the `af-xdp` feature, and an XDP redirect program steering the queue into the
# XSK. The redirect setup is environment-specific (kernel/driver); this script
# uses the *external* XDP-ownership model — point XDP_OBJ/XDP_SECTION at a
# program you attach, or pre-attach one and set ATTACH=skip. See
# docs/design/af-xdp-datapath.md.
#
# Determinism + cleanup: every resource is torn down on exit, even on failure.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DEV0="${DEV0:-turna-veth0}"
BASE_CFG="${BASE_CFG:-deploy/turn.toml}"
LISTEN="${LISTEN:-10.123.0.1:3478}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:9090/health}"
START_TIMEOUT="${START_TIMEOUT:-20}"
ATTACH="${ATTACH:-}"          # set to "skip" if you pre-attached an XDP program
XDP_OBJ="${XDP_OBJ:-}"        # path to a .o XDP redirect object (external mode)
XDP_SECTION="${XDP_SECTION:-xdp}"

err() { printf '\033[31m%s\033[0m\n' "$*" >&2; }
log() { printf '\033[36m==>\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { err "must run as root (CAP_NET_RAW + CAP_NET_ADMIN)"; exit 1; }
[ -f "$BASE_CFG" ]    || { err "base config not found: $BASE_CFG"; exit 1; }
command -v cargo >/dev/null || { err "cargo not found"; exit 1; }
command -v curl  >/dev/null || { err "curl not found";  exit 1; }

WORK="$(mktemp -d)"; NODE_PID=""
cleanup() {
  [ -n "$NODE_PID" ] && { kill "$NODE_PID" 2>/dev/null || true; wait "$NODE_PID" 2>/dev/null || true; }
  if [ -z "$ATTACH" ] && [ -n "$XDP_OBJ" ]; then ip link set dev "$DEV0" xdp off 2>/dev/null || true; fi
  "$HERE/af_xdp_cleanup.sh" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log "setting up veth pair"
"$HERE/af_xdp_veth_setup.sh"

if [ -z "$ATTACH" ] && [ -n "$XDP_OBJ" ]; then
  log "attaching external XDP redirect ($XDP_OBJ sec=$XDP_SECTION) to $DEV0"
  ip link set dev "$DEV0" xdp obj "$XDP_OBJ" sec "$XDP_SECTION"
elif [ "$ATTACH" = "skip" ]; then
  log "ATTACH=skip — assuming an XDP redirect is already attached to $DEV0"
else
  err "no XDP redirect: set XDP_OBJ=<prog.o> (external mode) or ATTACH=skip"
  err "AF_XDP cannot receive without a program redirecting the queue into the XSK"
  exit 1
fi

log "building turna-node (release, --features af-xdp)"
cargo build --release -p turna-node --features af-xdp
BIN="target/release/turna-node"
[ -x "$BIN" ] || { err "binary missing: $BIN"; exit 1; }

# Per-run config: force af_xdp transport + bind to the veth.
SRC_MAC="$(cat /sys/class/net/$DEV0/address)"
DST_MAC="$(cat /sys/class/net/turna-veth1/address)"
CFG="$WORK/turn-afxdp.toml"
cp "$BASE_CFG" "$CFG"
{
  echo
  echo "[turn]"
  echo "listen = \"$LISTEN\""
  echo "transport = \"af_xdp\""
  echo "[turn.af_xdp]"
  echo "interface = \"$DEV0\""
  echo "queue_id = 0"
  echo "src_mac = \"$SRC_MAC\""
  echo "dst_mac = \"$DST_MAC\""
} >> "$CFG"
log "NOTE: if your base config already has [turn]/[turn.af_xdp], merge instead of append"

log "starting AF_XDP node"
"$BIN" "$CFG" >"$WORK/node.log" 2>&1 & NODE_PID=$!

deadline=$(( $(date +%s) + START_TIMEOUT ))
until curl -fsS -o /dev/null --max-time 2 "$HEALTH_URL"; do
  [ "$(date +%s)" -lt "$deadline" ] || { err "node not healthy in ${START_TIMEOUT}s"; tail -n 40 "$WORK/node.log" >&2; exit 1; }
  sleep 0.5
done
log "node healthy; running integration suite against $LISTEN"

set +e
TURNA_TEST_TARGET="$LISTEN" cargo test -p turna-integration-tests -- --nocapture 2>&1 | tee "$WORK/test.log"
rc=${PIPESTATUS[0]}
set -e

[ $rc -eq 0 ] && log "AF_XDP smoke PASSED" || { err "AF_XDP smoke FAILED (rc=$rc); node log:"; tail -n 40 "$WORK/node.log" >&2; }
exit $rc
