#!/usr/bin/env bash
#
# Air-gap verification: does turna work with no route off the host, and does it
# stay quiet?
#
# Closes four §6 requirements from the enterprise spec, all P0, all of which were
# architectural beliefs rather than observations:
#
#   Air-gapped mode              — starts and relays with no default route
#   Zero outbound telemetry      — opens nothing outbound, by default
#   No mandatory cloud deps      — same test, stated as a claim
#   No mandatory external DNS    — resolver removed, node does not care
#
# HOW, AND WHY THIS WAY
#
# The node runs inside a network namespace containing only loopback: no default
# route, no resolver, no path to anything. If it starts, completes a TURN
# allocation and relays media in both directions in there, it does not need the
# internet. If `ss` inside the namespace shows no socket to a non-loopback
# address, it did not try.
#
# A namespace rather than a firewall rule on purpose. A DROP rule leaves the
# connection attempt visible only in a counter nobody reads; an empty namespace
# makes the attempt fail loudly and, more importantly, makes "it opened nothing"
# an observation instead of an inference.
#
# WHAT THIS DOES NOT PROVE
#
# That no *code path* ever reaches outward — only that none is taken during
# startup and a relayed session. A path behind a config flag, or one taken on a
# rare error, would not appear here. The counter-check (`ss` showing nothing
# outbound) narrows that, but a test cannot prove a negative about code it did
# not execute.
#
# REQUIRES root (network namespaces), Linux, and a release build.
#
#   sudo scripts/verify/air-gap.sh
#
# Artifacts in air-gap-<timestamp>/.

set -uo pipefail

NS="${NS:-turna-airgap}"
OUT="${OUT:-air-gap-$(date +%Y%m%d-%H%M%S)}"
# Not the obvious defaults. 9090 is `[management]`'s default and config
# validation rejects the collision — correctly, since it has no idea the ports are
# inside a namespace. 3478 is usually taken by a coturn on the same host.
TURN_PORT="${TURN_PORT:-3485}"
HEALTH_PORT="${HEALTH_PORT:-9098}"
SIGNALING_PORT="${SIGNALING_PORT:-9005}"
FRAMES="${FRAMES:-200}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1

PASS=0
FAIL=0
say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
ok()   { PASS=$((PASS + 1)); say "  pass  $1"; printf '| %s | **pass** | %s |\n' "$2" "$3" >> "$SUMMARY"; }
bad()  { FAIL=$((FAIL + 1)); say "  FAIL  $1"; printf '| %s | **FAIL** | %s |\n' "$2" "$3" >> "$SUMMARY"; }

[ "$(uname -s)" = "Linux" ] || die "network namespaces are Linux-only; this check cannot run on $(uname -s)"
[ "$(id -u)" = "0" ] || die "needs root for network namespaces: sudo scripts/verify/air-gap.sh"
command -v ip >/dev/null || die "iproute2 not installed"
command -v ss >/dev/null || die "ss (iproute2) not installed"

mkdir -p "$OUT"
SUMMARY="$OUT/summary.md"

NODE=target/release/turna-node
LOAD=target/release/turna-load-test

# Build only if the binaries are missing. This script needs root for network
# namespaces, and `sudo` does not inherit a user's PATH, so cargo is typically
# not on it — which turned a working setup into "cargo: command not found".
# Building beforehand as the normal user and running this with sudo is the
# expected flow; the fallback exists for a machine where cargo *is* on root's
# path.
if [ ! -x "$NODE" ] || [ ! -x "$LOAD" ]; then
  command -v cargo >/dev/null || die "$NODE or $LOAD missing, and cargo is not on PATH.
Build them first as your normal user:
  cargo build --release -p turna-node -p turna-load-test
then re-run this with sudo."
  say "building (binaries were missing)"
  cargo build --release -p turna-node -p turna-load-test \
    > "$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; die "build failed"; }
else
  say "using existing release binaries"
fi

SECRET="airgap-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

{
  echo "# Air-gap verification — $(date -u +%FT%TZ)"
  echo
  echo "- host: $(hostname), kernel $(uname -r)"
  echo "- namespace: \`$NS\` — loopback only, no default route, no resolver"
  echo
  echo "The node runs with no path off the host. Each check below is an"
  echo "observation inside that namespace, not an inference from the code."
  echo
  echo "| check | result | detail |"
  echo "|---|---|---|"
} > "$SUMMARY"

cleanup() {
  [ -n "${NODE_PID:-}" ] && kill -TERM "$NODE_PID" 2>/dev/null
  sleep 1
  [ -n "${NODE_PID:-}" ] && kill -KILL "$NODE_PID" 2>/dev/null
  ip netns pids "$NS" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  rm -rf /etc/netns/"$NS" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ── the namespace ──────────────────────────────────────────────────────────
#
# Only `lo`, brought up. Nothing else is added: no veth, no default route, so
# there is no way out even if something tried.
#
# The empty resolv.conf is bind-mounted by `ip netns exec` from
# /etc/netns/<ns>/resolv.conf — the mechanism iproute2 provides for exactly this.
# Without it the namespace inherits the host's resolver and "no external DNS"
# would go untested.
ip netns del "$NS" 2>/dev/null
ip netns add "$NS" || die "could not create namespace $NS"
ip netns exec "$NS" ip link set lo up || die "could not bring up lo in $NS"
mkdir -p /etc/netns/"$NS"
: > /etc/netns/"$NS"/resolv.conf

say "namespace $NS: loopback only"
say "  routes:    $(ip netns exec "$NS" ip route show | wc -l) (expect 0 default)"
say "  resolvers: $(ip netns exec "$NS" awk '/^nameserver/{n++} END{print n+0}' /etc/resolv.conf 2>/dev/null)"

if [ "$(ip netns exec "$NS" ip route show default 2>/dev/null | wc -l)" = "0" ]; then
  ok "no default route in the namespace" "Namespace has no route off-host" "\`ip route show default\` is empty"
else
  bad "namespace still has a default route" "Namespace has no route off-host" "a default route exists — the rest of this run proves nothing"
  die "refusing to continue: the namespace is not isolated"
fi

# ── config: everything loopback, nothing external ─────────────────────────
cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "127.0.0.1:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "airgap"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 20000
max_port = 20200
max_allocations = 64
[turn.relay.quota]
max_per_user = 0
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
EOF

say "starting the node inside $NS"
ip netns exec "$NS" "$REPO/$NODE" "$OUT/turn.toml" > "$OUT/node.log" 2>&1 &
NODE_PID=$!

for _ in $(seq 40); do
  ip netns exec "$NS" curl -fsS --max-time 1 \
    "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && break
  kill -0 "$NODE_PID" 2>/dev/null || break
  sleep 0.5
done

if ip netns exec "$NS" curl -fsS --max-time 2 \
    "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1; then
  ok "node starts with no route off-host" "Starts air-gapped" "ready in a namespace with only loopback"
else
  bad "node did not become ready" "Starts air-gapped" "see node.log — a startup path may need the network"
  tail -20 "$OUT/node.log"
  die "cannot continue without a running node"
fi

# ── does it relay? ────────────────────────────────────────────────────────
#
# The point of the whole exercise. A node that starts but cannot relay is not
# air-gap capable, it is just quiet — and "it started" is the check that let a
# three-hour soak pass while nothing was being relayed.
say "relaying $FRAMES frames inside the namespace"
ip netns exec "$NS" "$REPO/$LOAD" \
  --server "127.0.0.1:$TURN_PORT" --secret "$SECRET" \
  --duration 20 --json \
  channel-data --channels 4 --pps 5 --payload 160 \
  > "$OUT/load.json" 2> "$OUT/load.err"

RELAYED=$(python3 - "$OUT/load.json" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
    print(f"{d.get('recv',0)} {d.get('sent',0)} {d.get('errs',0)}")
except Exception:
    print("0 0 0")
PY
)
RECV=$(echo "$RELAYED" | cut -d' ' -f1)
SENT=$(echo "$RELAYED" | cut -d' ' -f2)
ERRS=$(echo "$RELAYED" | cut -d' ' -f3)

if [ "${RECV:-0}" -gt 0 ] && [ "${ERRS:-1}" = "0" ]; then
  ok "relayed media works air-gapped ($RECV/$SENT frames)" \
     "Relays media air-gapped" "$RECV of $SENT frames returned to the peer, 0 errors"
else
  bad "no relayed media ($RECV/$SENT, $ERRS errors)" \
      "Relays media air-gapped" "$RECV of $SENT frames, $ERRS errors — see load.err"
fi

# ── did it open anything outbound? ────────────────────────────────────────
#
# Inside the namespace there is nowhere to go, so a connection attempt would show
# as SYN-SENT rather than ESTABLISHED. Both are looked for. Loopback is expected
# and excluded.
OUTBOUND=$(ip netns exec "$NS" ss -tanp 2>/dev/null |
  awk 'NR>1 && $1 != "LISTEN" {print $5}' |
  grep -vE '^(127\.|\[::1\]|\*)' | sort -u)

if [ -z "$OUTBOUND" ]; then
  ok "no outbound socket to any non-loopback address" \
     "Opens nothing outbound" "\`ss -tanp\` shows only loopback and listeners"
else
  bad "outbound sockets found: $(echo "$OUTBOUND" | tr '\n' ' ')" \
      "Opens nothing outbound" "found: $(echo "$OUTBOUND" | tr '\n' ' ')"
fi

# ── telemetry off by default ──────────────────────────────────────────────
#
# `otlp_endpoint` defaults to the empty string and the exporter is only built
# when it is non-empty, so this is checking that the default is what the code
# says — and that the node announces it rather than leaving an operator guessing.
# Two signals, either of which settles it. The sentence is the one an operator
# would look for; the empty `otlp=` field on the startup line is the one that
# cannot be wrong, because it is the configured value being echoed back.
if grep -q "distributed tracing disabled" "$OUT/node.log"; then
  ok "OTLP disabled by default, and says so" \
     "Zero outbound telemetry by default" "node logged 'distributed tracing disabled (no OTLP endpoint configured)'"
elif grep -qE 'telemetry initialized.*otlp=( |$)' "$OUT/node.log"; then
  ok "OTLP endpoint empty on the startup line" \
     "Zero outbound telemetry by default" "\`otlp=\` is empty in 'telemetry initialized' — no exporter was built"
else
  bad "could not confirm OTLP is disabled from the log" \
      "Zero outbound telemetry by default" "neither the disabled message nor an empty otlp= field found; check node.log"
fi

# ── DNS ───────────────────────────────────────────────────────────────────
# `grep -c` prints 0 and exits 1 when nothing matches, so a `|| echo 0` fallback
# appends a second zero and the value becomes "0\n0" — which is neither 0 nor a
# number. Counted with awk instead, which returns a count and exits 0 either way.
NS_COUNT=$(ip netns exec "$NS" awk '/^nameserver/{n++} END{print n+0}' /etc/resolv.conf 2>/dev/null)
NS_COUNT=${NS_COUNT:-0}
if [ "${NS_COUNT:-1}" = "0" ]; then
  ok "ran with no resolver configured" \
     "No mandatory external DNS" "/etc/resolv.conf in the namespace has no nameserver, and the node worked"
else
  bad "namespace had $NS_COUNT resolvers — DNS was not actually removed" \
      "No mandatory external DNS" "the bind-mount did not take effect; this check proved nothing"
fi

# ── metrics still work ────────────────────────────────────────────────────
#
# Observability that needs the internet is not observability in this deployment
# model, so it is checked rather than assumed.
SERIES=$(ip netns exec "$NS" curl -fsS --max-time 2 \
  "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null | grep -c '^turna_' || echo 0)
if [ "${SERIES:-0}" -gt 20 ]; then
  ok "metrics scrape works air-gapped ($SERIES series)" \
     "Local observability air-gapped" "$SERIES turna_ series on /metrics"
else
  bad "metrics scrape returned $SERIES series" \
      "Local observability air-gapped" "expected the usual series count; got $SERIES"
fi

{
  echo
  echo "**$PASS passed, $FAIL failed.**"
  cat <<'EOF'

### What this establishes

turna needs no route off the host: it starts, relays media in both directions,
serves its own metrics, and opens no socket to any non-loopback address, with no
default route and no resolver present.

### What it does not

That no code path *can* reach outward — only that none is taken during startup
and a relayed session. A path behind a config flag (`otlp_endpoint`, a Tarantool
backend, a cluster peer) or one taken on a rare error would not appear here. Those
are opt-in by construction, which is an argument, not a measurement.

Nor does it cover offline *installation* — that is packaging, tested separately.
EOF
} >> "$SUMMARY"

say "done — $PASS passed, $FAIL failed"
echo
cat "$SUMMARY"
[ "$FAIL" -eq 0 ]
