#!/usr/bin/env bash
#
# AF_XDP on the veth lab: allocation **and relayed media**, not just the control
# plane.
#
# WHY NOT scripts/lab/af_xdp_smoke.sh
#
# That script predates the embedded XDP program. It demands an external one
# (`XDP_OBJ=...` or `ATTACH=skip`) and refuses to run without it, but the node now
# carries its own — `build.rs` compiles `src/bpf/xdp_turn.c` and `af_xdp.rs` embeds
# the object via `include_bytes!`, attaching it with `xdp_program__attach` and
# detaching in `Drop`. So there is nothing to attach by hand.
#
# It also runs the integration suite, which exercises the control plane. That is not
# enough: the io_uring datapath answered 10 800 allocations per second for three
# hours while forwarding nothing (docs/soak/endurance-2026-08-19.md). This script
# ends at bytes arriving at a peer.
#
# WHY THE PEER LIVES IN A NETWORK NAMESPACE
#
# `scripts/lab/af_xdp_veth_setup.sh` puts both ends of the pair in the host
# namespace, and that cannot work for this: with 10.123.0.1 and 10.123.0.2 both
# local to one stack, the kernel short-circuits the traffic through `lo` and it never
# traverses the veth link at all. Proven directly:
#
#   $ ip route get 10.123.0.1 from 10.123.0.2
#   local 10.123.0.1 from 10.123.0.2 dev lo
#
# The XDP program on turna-veth0 then sees nothing — `rx_frames_total = 0` and
# `parse_drops_total = 0` together, i.e. not "dropped after parsing" but "never
# arrived". So the peer end goes into its own netns, which is what every serious
# AF_XDP-on-veth setup does.
#
# WHAT IT PROVES, AND WHAT IT CANNOT
#
# A veth pair is a virtual link. It exercises the frame path, the XDP attach, the
# UMEM rings and the relay logic — everything except a real NIC driver, which is the
# entire reason AF_XDP exists. A pass here is real but partial, and the write-up must
# say so.
#
# USAGE
#
#   sudo scripts/verify/af-xdp-lab.sh
#
# Needs root (CAP_NET_RAW + CAP_NET_ADMIN), Linux, and clang/llvm/libelf/libbpf for
# the BPF object. Tears the lab down on exit, including on failure.

set -uo pipefail

DEV0="${DEV0:-turna-veth0}"
DEV1="${DEV1:-turna-veth1}"
IP0="${IP0:-10.123.0.1}"
IP1="${IP1:-10.123.0.2}"
NS="${NS:-turna-lab}"
FRAME_COUNT="${FRAME_COUNT:-4096}"
# Rate for the throughput phase. Deliberately modest: the UMEM cannot be enlarged
# past 4096 frames (see the config comment), generic-XDP copies every frame, and this
# is a veth — so this measures the lab, not the NIC AF_XDP exists for. Raising it
# produces loss that says nothing about the datapath.
HI_CHANNELS="${HI_CHANNELS:-10}"
HI_PPS="${HI_PPS:-20}"
# 4 channels x 10 pps x 60 s = 2400 frames, comfortably past the ~2016-frame pool.
LONG_SECS="${LONG_SECS:-60}"
OUT="${OUT:-afxdp-$(date +%Y%m%d-%H%M%S)}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (CAP_NET_RAW + CAP_NET_ADMIN)"
[ "$(uname -s)" = Linux ] || die "AF_XDP is Linux-only"
# Checked before the build, so a missing cargo is not reported as a missing BPF
# toolchain. `sudo` resets PATH, and rustup installs cargo under the invoking user's
# home — so running this with plain `sudo` loses it.
command -v cargo >/dev/null || die "cargo is not on PATH.
Running under sudo drops the user PATH, and rustup keeps cargo in \$HOME/.cargo/bin.
Re-run as:  sudo -E env \"PATH=\$PATH\" scripts/verify/af-xdp-lab.sh"
command -v clang >/dev/null || die "clang is not on PATH; the BPF object needs it \
(clang, llvm, libelf-dev, zlib1g-dev, libbpf-dev)"
command -v ip >/dev/null || die "iproute2 'ip' not found"
command -v ethtool >/dev/null || die "ethtool not found; needed to disable veth offloads"
# The rings are fixed at 2048 in af_xdp.rs regardless of frame_count, and the RX
# half of the UMEM must fit the fill ring. Past 4096 the fill ring cannot be
# populated and RX dies silently — rx_frames_total simply reads 0.
if [ "$FRAME_COUNT" -gt 4096 ]; then
  die "FRAME_COUNT=$FRAME_COUNT exceeds 2x the fixed 2048 ring size.
RX would stop entirely and report nothing. Either keep it <= 4096 or make
af_xdp.rs size the rings from frame_count first."
fi
# `ip netns` needs /var/run/netns, which iproute2 creates, but a missing mount
# namespace support would fail later and less clearly.
ip netns list >/dev/null 2>&1 || die "'ip netns' does not work here; the peer end \
must live in its own namespace or traffic short-circuits through lo"
mkdir -p "$OUT"

NODE_PID=""
cleanup() {
  if [ -n "$NODE_PID" ]; then
    kill -TERM "$NODE_PID" 2>/dev/null
    for _ in $(seq 20); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "$NODE_PID" 2>/dev/null
    # Reaped, not just signalled: without this the script exits while the child is
    # still running and the next `unzip` of this file fails with "text file busy".
    wait "$NODE_PID" 2>/dev/null
  fi
  # The node detaches its own XDP program in Drop; removing the pair is belt and
  # braces in case it did not get that far.
  ip link del "$DEV0" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  say "lab torn down"
}
trap cleanup EXIT INT TERM

# ── build ───────────────────────────────────────────────────────────────────
say "building with --features af-xdp (build.rs compiles the BPF object)"
cargo build --release -p turna-node --features af-xdp > "$OUT/build-node.log" 2>&1 \
  || { tail -20 "$OUT/build-node.log"; die "node build failed — see $OUT/build-node.log"; }
cargo build --release -p turna-load-test > "$OUT/build-load.log" 2>&1 \
  || { tail -20 "$OUT/build-load.log"; die "load-test build failed"; }

# ── lab ─────────────────────────────────────────────────────────────────────
say "setting up the veth pair with the peer in a namespace"
{
  ip netns del "$NS" 2>/dev/null
  ip link del "$DEV0" 2>/dev/null
  ip netns add "$NS"
  ip link add "$DEV0" type veth peer name "$DEV1"
  # Peer end into the namespace, so traffic to $IP0 has to cross the wire.
  ip link set "$DEV1" netns "$NS"
  # AF_XDP on veth is sensitive to offloads; disable the usual culprits on both ends.
  ethtool -K "$DEV0" tx off rx off tso off gso off gro off 2>/dev/null
  ip netns exec "$NS" ethtool -K "$DEV1" tx off rx off tso off gso off gro off 2>/dev/null
  ip addr add "$IP0/24" dev "$DEV0"
  ip link set "$DEV0" up
  ip netns exec "$NS" ip addr add "$IP1/24" dev "$DEV1"
  ip netns exec "$NS" ip link set "$DEV1" up
  ip netns exec "$NS" ip link set lo up
} > "$OUT/veth.log" 2>&1 || { cat "$OUT/veth.log"; die "veth/netns setup failed"; }

SRC_MAC="$(cat "/sys/class/net/$DEV0/address")"
DST_MAC="$(ip netns exec "$NS" cat "/sys/class/net/$DEV1/address")"
say "  host: $DEV0 $IP0 ($SRC_MAC)"
say "  netns $NS: $DEV1 $IP1 ($DST_MAC)"

# Static neighbour entry for the node, both directions.
#
# The XDP program redirects ALL ingress into the xsk, so the kernel's ARP responder on
# turna-veth0 is bypassed and the datapath has to answer ARP itself. On a cold cache
# the client's first packet is queued behind that resolution and can be lost — and the
# conformance probes send one request each with no retry, so a single lost packet fails
# a probe. Exactly one probe failed this way: the first, with every later one passing.
#
# A real client retries and would never notice. Pinning the entry removes the cold
# start from the measurement instead of papering over a retry the tool does not do.
# The reference AF_XDP-on-veth setups do the same thing.
ip netns exec "$NS" ip neigh replace "$IP0" lladdr "$SRC_MAC" dev "$DEV1" nud permanent \
  2>>"$OUT/veth.log" || say "  warning: could not pin the neighbour entry; the first probe may fail"
ip neigh replace "$IP1" lladdr "$DST_MAC" dev "$DEV0" nud permanent 2>>"$OUT/veth.log" || true

# Sanity: the route must leave via the veth, not via lo. If this says `lo` the run
# would measure nothing, exactly as it did before the namespace was added.
ROUTE="$(ip netns exec "$NS" ip route get "$IP0" 2>&1)"
case "$ROUTE" in
  *" dev $DEV1"*) say "  route ok: $IP0 leaves via $DEV1" ;;
  *) die "route from the namespace does not use $DEV1:
$ROUTE
Without that, traffic never crosses the veth and AF_XDP sees nothing." ;;
esac

# The peer lives on $IP1, which is off-loopback, so `allow_loopback_peers` is not
# what matters here — `profile = "lan"` is, because 10.123.0.0/24 is private and the
# default profile denies private ranges as SSRF protection.
#
# Relay ports stay below the ephemeral range: the client's peer socket gets an
# ephemeral port, and if that landed inside the relay range the relay would forward
# to an address it is itself serving.
cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "$IP0:3478"
external_ip = "$IP0"
realm       = "afxdp"
transport   = "af_xdp"
[turn.af_xdp]
interface = "$DEV0"
queue_id  = 0
src_mac   = "$SRC_MAC"
dst_mac   = "$DST_MAC"
# DO NOT raise this past 2x the ring size (4096 with the current 2048 rings).
#
# af_xdp.rs honours frame_count but hardcodes the rings to the library defaults
# (rings 2048), and the RX half of the UMEM has to fit the fill ring. Setting 16384
# gave umem_free_frames = 8160 against a 2048-entry fill ring, the fill ring stayed
# empty, and RX died completely and silently: rx_frames_total went from 2015 to 0.
# NOTE: no backticks in this heredoc, it is unquoted and they would run as commands.
frame_count = $FRAME_COUNT
[turn.auth]
shared_secret = "afxdp-lab-secret"
[turn.peer_filter]
profile = "lan"
[turn.relay]
min_port = 20000
max_port = 20847
max_allocations = 800
[turn.relay.quota]
max_per_user = 0
[health]
listen = "127.0.0.1:9091"
[signaling]
listen             = "127.0.0.1:9001"
turn_shared_secret = "afxdp-lab-secret"
EOF

target/release/turna-node --dump-config "$OUT/turn.toml" > "$OUT/config-resolved.txt" 2>"$OUT/config-error.txt" \
  || { cat "$OUT/config-error.txt"; die "config rejected"; }

say "starting the node on the AF_XDP backend"
target/release/turna-node "$OUT/turn.toml" > "$OUT/node.log" 2>&1 &
NODE_PID=$!
READY=0
for i in $(seq 40); do
  if curl -fsS --max-time 1 http://127.0.0.1:9091/ready >/dev/null 2>&1; then READY=1; break; fi
  kill -0 "$NODE_PID" 2>/dev/null || break
  sleep 0.5
done
if [ "$READY" != 1 ]; then
  say "node did not become ready; last lines:"
  tail -25 "$OUT/node.log"
  die "AF_XDP node failed to start. A bind or XDP attach failure lands here — the \
program is embedded, so this is not a missing-object problem."
fi
say "node ready after $((i / 2))s"

# /ready is process-level and does not cover the AF_XDP backend: the datapath's own
# gauge turna_afxdp_readiness flips to 1 only after XskDatapath::bind() has seeded
# the fill ring, attached the selective XDP program and populated xsks_map/ports
# (af_xdp_listener.rs sets it right before the RX loop; its own comment says /ready
# "will not show it"). Probing earlier sends the client's single, never-retried
# packet into an interface with no redirect and no kernel UDP listener on 3478 —
# a guaranteed loss, and exactly one: the first probe of the run.
AFXDP_READY=0
for _ in $(seq 40); do
  v="$(curl -fsS --max-time 1 http://127.0.0.1:9091/metrics 2>/dev/null | awk '$1=="turna_afxdp_readiness"{print $2}')"
  if [ "${v:-0}" = "1" ]; then AFXDP_READY=1; break; fi
  kill -0 "$NODE_PID" 2>/dev/null || break
  sleep 0.5
done
if [ "$AFXDP_READY" != 1 ]; then
  say "AF_XDP datapath never became ready; last lines:"
  tail -25 "$OUT/node.log"
  die "turna_afxdp_readiness != 1 — bind/XDP attach failed or is stuck (see node.log)"
fi
say "AF_XDP datapath ready (XDP program attached, maps seeded)"

# ── checks ──────────────────────────────────────────────────────────────────
FAIL=0
run() { # name, log, command...
  local name="$1"
  local log="$OUT/$2"
  shift 2
  "$@" > "$log" 2>&1
  # Captured immediately: anything inserted between the command and a bare `$?`
  # silently changes what is being tested.
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    say "  pass  $name"
  else
    say "  FAIL  $name (rc=$rc, see $(basename "$log"))"
    FAIL=$((FAIL + 1))
  fi
}

LOAD=target/release/turna-load-test
# --bind-ip is the point: every socket must sit on $IP1, or the relay's forward to
# the peer has nowhere to arrive. A loopback bind cannot reach $IP0 across the veth.
# `ip netns exec` is what makes this a real wire test: the client sits on the far
# side of the veth, so its packets must be received by the XDP program.
run "conformance over AF_XDP" conformance.log \
  ip netns exec "$NS" "$LOAD" --server "$IP0:3478" --secret afxdp-lab-secret \
  --bind-ip "$IP1" conformance

# The load tool exits 0 after a run in which nothing worked: it reports failure in
# its counters, not its status. Checking only the exit code called a phase with
# `sent: 0, recv: 0, errs: 20` a pass. And requiring merely `recv > 0` passed a run
# that lost two thirds of its traffic. So the loss ratio is asserted, with a
# threshold that depends on what the phase is for.
assert_loss() { # label, log, max_loss_percent
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
label, path, limit = sys.argv[1], sys.argv[2], float(sys.argv[3])
try:
    d = json.loads(open(path).read().strip().splitlines()[-1])
except Exception as e:
    print(f"  FAIL  {label}: JSON unreadable ({e})")
    sys.exit(1)
sent, recv, errs = d.get("sent", 0), d.get("recv", 0), d.get("errs", 0)
if sent == 0:
    print(f"  FAIL  {label}: nothing sent ({errs} errors) — the phase did not run")
    sys.exit(1)
loss = (sent - recv) / sent * 100
verdict = "pass" if loss <= limit and errs == 0 else "FAIL"
print(f"  {verdict}  {label}: {sent} sent, {recv} relayed back, {loss:.1f}% lost,"
      f" {errs} errors (limit {limit:.0f}%)")
sys.exit(0 if verdict == "pass" else 1)
PY
}

# Correctness: a rate low enough that buffering cannot be the explanation. Loss here
# means the datapath is wrong, not busy.
run "AF_XDP relayed media, low rate" media-low.log \
  ip netns exec "$NS" "$LOAD" --server "$IP0:3478" --secret afxdp-lab-secret \
  --bind-ip "$IP1" --duration 15 --json channel-data --channels 4 --pps 10 --payload 160
assert_loss "low-rate media" "$OUT/media-low.log" 2 || FAIL=$((FAIL + 1))

# The decisive one. Same low rate that lost nothing above, run long enough that the
# total crosses the UMEM pool size (~2016 frames).
#
# Why it matters: rx_frames_total came out as *exactly* 2015 in two runs at different
# rates and durations. Congestion does not produce a constant. A hard stop at the pool
# size is what a frame leak looks like — frames taken off RX and never returned to the
# fill ring. Passing here means the pool recycles; failing here localises the fault to
# the RX refill path and has nothing to do with rate.
run "AF_XDP relayed media, low rate past the pool size" media-long.log \
  ip netns exec "$NS" "$LOAD" --server "$IP0:3478" --secret afxdp-lab-secret \
  --bind-ip "$IP1" --duration "$LONG_SECS" --json channel-data --channels 4 --pps 10 --payload 160
assert_loss "low-rate media past the pool" "$OUT/media-long.log" 2 || FAIL=$((FAIL + 1))
say "  (frames received so far: $(curl -fsS http://127.0.0.1:9091/metrics 2>/dev/null | awk '$1=="turna_afxdp_rx_frames_total"{print $2}'))"

# Throughput: informational, and generous. On veth the attach is SKB mode, which
# copies every frame — this measures the lab, not the NIC AF_XDP is meant for.
run "AF_XDP relayed media, high rate" media-high.log \
  ip netns exec "$NS" "$LOAD" --server "$IP0:3478" --secret afxdp-lab-secret \
  --bind-ip "$IP1" --duration 20 --json channel-data --channels "$HI_CHANNELS" --pps "$HI_PPS" --payload 160
assert_loss "high-rate media" "$OUT/media-high.log" 20 || FAIL=$((FAIL + 1))

# Same for the datapath itself: if AF_XDP received no frames, whatever was measured
# did not go through it.
RX="$(curl -fsS http://127.0.0.1:9091/metrics 2>/dev/null | awk '$1=="turna_afxdp_rx_frames_total"{print $2}')"
TX="$(curl -fsS http://127.0.0.1:9091/metrics 2>/dev/null | awk '$1=="turna_afxdp_tx_frames_total"{print $2}')"
if [ "${RX:-0}" = 0 ] && [ "${TX:-0}" = 0 ]; then
  say "  FAIL  AF_XDP carried no frames (rx=$RX tx=$TX) — the backend was selected but \
never saw traffic. On veth the program attaches in SKB (generic) mode, where XSK \
redirect is kernel-dependent; check the attach mode in node.log."
  FAIL=$((FAIL + 1))
else
  say "  pass  AF_XDP carried frames (rx=$RX tx=$TX)"
fi

# Where refusals come from, if there were any. `errs` on the client side is silent
# about the reason: a quota, the rate limiter and a dropped frame all look the same.
say "server-side rejections (all zero means the losses were not refusals):"
curl -fsS http://127.0.0.1:9091/metrics 2>/dev/null \
  | grep -E '^turna_(quota_exceeded_total|rate_limited|peer_rejected_total|send_queue_dropped_total|auth_failures|malformed_packets_total|parser_rejections_total) ' \
  | tee "$OUT/rejections.txt" || true

# ARP/NDP replies are the datapath standing in for the kernel responder that the XDP
# redirect bypasses. Zero with a pinned neighbour entry is expected; zero *without*
# one means clients cannot resolve the node at all.
say "AF_XDP datapath counters:"
curl -fsS http://127.0.0.1:9091/metrics 2>/dev/null \
  | grep -E '^turna_afxdp_' | tee "$OUT/afxdp-metrics.txt" | grep -v ' 0$' || true

{
  echo "# AF_XDP lab — $(date -u +%FT%TZ)"
  echo
  echo "- host: $(hostname), $(uname -sr)"
  echo "- link: veth pair $DEV0 ($IP0, host) <-> $DEV1 ($IP1, netns $NS)"
  echo "- checks failed: $FAIL"
  echo
  echo "A veth pair is a virtual link: this covers the frame path, the XDP attach, the"
  echo "UMEM rings and the relay logic, but **not a real NIC driver** — which is the"
  echo "reason AF_XDP exists. A pass here is real and partial."
  echo
  echo '## AF_XDP counters'
  echo '```'
  cat "$OUT/afxdp-metrics.txt" 2>/dev/null
  echo '```'
} > "$OUT/summary.md"

say "done — $FAIL failed. Artifacts in $OUT/"
[ "$FAIL" -eq 0 ]
