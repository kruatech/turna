#!/usr/bin/env bash
#
# Interop against coturn's TURN client.
#
# WHY THIS IS DIFFERENT FROM EVERY OTHER CHECK HERE
#
# `turna-load-test` proves the server does what *we* think the RFC says. It shares a
# reading of the spec with the server — and, for the stream transports, a library — so
# a mistake made in both places is invisible to it. Every record in docs/interop/ says
# so explicitly.
#
# `turnutils_uclient` is coturn's: different authors, different language, an
# independent reading of RFC 5766/8656 and RFC 7350. When it and turna agree, that
# means something the in-tree client cannot mean.
#
# It reaches further than expected. One binary covers UDP, TCP, TLS, DTLS, the IPv6
# relay and the RFC 6062 TCP relay — so this closes the interop gap for DTLS and
# strengthens four paths that were only ever self-tested.
#
# WHAT IT CANNOT COVER
#
# QUIC and WebTransport. coturn does not implement TURN over raw QUIC because no RFC
# defines it, and there is nothing to implement. WebTransport has its own independent
# check: a browser (docs/interop/webtransport-browser-2026-08-20.md).
#
# USAGE
#
#   scripts/verify/coturn-interop.sh
#
# ~2 minutes. Artifacts in coturn-interop-<timestamp>/.

set -uo pipefail

OUT="${OUT:-coturn-interop-$(date +%Y%m%d-%H%M%S)}"
TURN_PORT="${TURN_PORT:-3479}"
TLS_PORT="${TLS_PORT:-5350}"
DTLS_PORT="${DTLS_PORT:-5351}"
PEER_PORT="${PEER_PORT:-3481}"
HEALTH_PORT="${HEALTH_PORT:-9095}"
SIGNALING_PORT="${SIGNALING_PORT:-9002}"
MSGS="${MSGS:-20}"
CLIENTS="${CLIENTS:-2}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
mkdir -p "$OUT"

USER_NAME="interop"
PASSWORD="interop-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SUMMARY="$OUT/summary.md"
PASS=0
FAIL=0
SKIP=0

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

command -v turnutils_uclient >/dev/null || die "turnutils_uclient not found (apt install coturn)"
command -v turnutils_peer >/dev/null || die "turnutils_peer not found (apt install coturn)"

say "building"
cargo build --release -p turna-node --features "tls,dtls" > "$OUT/build.log" 2>&1 \
  || { tail -20 "$OUT/build.log"; die "node build failed"; }

# EC, not RSA. The DTLS listener refuses an RSA key at startup with
# "dtls: listen: invalid private key type" — webrtc-dtls supports EC keys only. The
# first version of this script used RSA to be kind to coturn's OpenSSL and the
# listener simply never came up, which showed as a DTLS handshake failure and looked
# like an interop problem.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -subj "/CN=localhost" 2>/dev/null \
  || die "certificate generation failed"

{
  echo "# Interop against coturn's client — $(date -u +%FT%TZ)"
  echo
  echo "- turna: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "- coturn client: $(turnutils_uclient -h 2>&1 | head -1)"
  echo "- host: $(hostname), $(uname -sr)"
  echo
  echo "The point of this file: **turnutils_uclient is not our code.** Where it agrees"
  echo "with turna, two independent readings of the RFC agree — which is what the"
  echo "in-tree load client, sharing a reading with the server, cannot establish."
  echo
  echo "| Check | Transport | Result |"
  echo "|---|---|---|"
} > "$SUMMARY"

# Long-term credentials with a static user: `-W` (REST secret) exists, but a plain
# user removes a second moving part from the first interop run.
NODE_PID=""; PEER_PID=""
cleanup() {
  [ -n "$PEER_PID" ] && kill "$PEER_PID" 2>/dev/null
  if [ -n "$NODE_PID" ]; then
    kill -TERM "$NODE_PID" 2>/dev/null
    for _ in $(seq 20); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "$NODE_PID" 2>/dev/null
    wait "$NODE_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "0.0.0.0:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "interop"
transport   = "tokio"
[turn.auth]
# NOTE: no backticks in this heredoc. It is unquoted so the variables expand, which
# means backticks run as commands — the previous version silently dropped the
# shared_secret line for exactly that reason, and the shell printed
# "shared_secret: command not found".
# shared_secret is mandatory and validated as non-default; it is set even though this
# run authenticates with a static user, because coturn's client takes -u/-w directly.
shared_secret = "$PASSWORD"
static_users = [{ username = "$USER_NAME", password = "$PASSWORD" }]
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 20000
max_port = 20847
max_allocations = 800
[turn.relay.quota]
max_per_user = 0
[turn.tcp_relay]
enabled = true
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$PASSWORD"
[tls]
enabled = true
listen  = "0.0.0.0:$TLS_PORT"
cert_path = "$PWD/$OUT/cert.pem"
key_path  = "$PWD/$OUT/key.pem"
[turn.dtls]
enabled = true
listen  = "0.0.0.0:$DTLS_PORT"
cert_path = "$PWD/$OUT/cert.pem"
key_path  = "$PWD/$OUT/key.pem"
EOF

target/release/turna-node --dump-config "$OUT/turn.toml" > "$OUT/config-resolved.txt" 2>&1 \
  || { cat "$OUT/config-resolved.txt"; die "config rejected — check that static_users is the right key for this build"; }

say "starting turna (UDP $TURN_PORT, TURNS $TLS_PORT, DTLS $DTLS_PORT)"
target/release/turna-node "$OUT/turn.toml" > "$OUT/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 40); do
  curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && break
  kill -0 "$NODE_PID" 2>/dev/null || break
  sleep 0.5
done
curl -fsS --max-time 2 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 \
  || { tail -15 "$OUT/node.log"; die "turna did not become ready"; }

say "starting turnutils_peer on $PEER_PORT (coturn's echo peer)"
turnutils_peer -p "$PEER_PORT" > "$OUT/peer.log" 2>&1 &
PEER_PID=$!
sleep 1

# turnutils_uclient reports per-session totals at the end; a run that allocated but
# relayed nothing still exits 0, so the output is checked rather than the status.
run_check() { # name, transport, port, extra flags...
  local name="$1" transport="$2" port="$3"; shift 3
  local log="$OUT/${name}.log"
  say "check: $name"
  turnutils_uclient -m "$CLIENTS" -n "$MSGS" -p "$port" \
    -u "$USER_NAME" -w "$PASSWORD" -e 127.0.0.1 -r "$PEER_PORT" \
    "$@" 127.0.0.1 > "$log" 2>&1
  local rc=$?
  # "tot_send_msgs" / "tot_recv_msgs" are what the tool prints; anything else means
  # it failed before relaying.
  local sent recv
  sent="$(grep -oE 'tot_send_msgs=[0-9]+' "$log" | tail -1 | cut -d= -f2)"
  recv="$(grep -oE 'tot_recv_msgs=[0-9]+' "$log" | tail -1 | cut -d= -f2)"
  if [ -n "${recv:-}" ] && [ "${recv:-0}" -gt 0 ] && [ "${recv:-0}" = "${sent:-x}" ]; then
    PASS=$((PASS + 1)); say "  pass  $name — $recv/$sent messages relayed"
    printf '| %s | %s | **pass** — %s/%s relayed |\n' "$name" "$transport" "$recv" "$sent" >> "$SUMMARY"
  elif [ -n "${recv:-}" ] && [ "${recv:-0}" -gt 0 ]; then
    FAIL=$((FAIL + 1)); say "  FAIL  $name — $recv of $sent relayed"
    printf '| %s | %s | **FAIL** — only %s of %s relayed |\n' "$name" "$transport" "$recv" "$sent" >> "$SUMMARY"
  else
    FAIL=$((FAIL + 1)); say "  FAIL  $name (rc=$rc, no messages relayed) — see ${name}.log"
    printf '| %s | %s | **FAIL** (rc=%s, nothing relayed) |\n' "$name" "$transport" "$rc" >> "$SUMMARY"
  fi
}

# There is no plaintext-TCP TURN listener in turna: the only TCP ingress is TURNS, and
# the RFC 6062 relay's connection state is adopted by the TLS bridge. Both TCP rows
# therefore go to the TURNS port with -S. Pointing them at the UDP port earns
# "Connection refused", which is the server being right and the test being wrong.
run_check udp      "UDP"                 "$TURN_PORT"
run_check turns    "TLS over TCP"        "$TLS_PORT"  -t -S
run_check dtls     "DTLS over UDP"       "$DTLS_PORT" -S
run_check ipv6     "UDP, IPv6 relay"     "$TURN_PORT" -g
run_check tcprelay "RFC 6062 over TURNS" "$TLS_PORT"  -t -S -T

{
  echo
  echo "**$PASS passed, $FAIL failed, $SKIP skipped.**"
  cat <<'EOF'

### What this establishes, and what it does not

Where a row passes, turna and an implementation written by other people agree about
the wire. That is interop, and it is the one thing the in-tree client cannot provide
for the transport it drives.

It does not cover endurance — these are short functional runs; see docs/soak/ for that.
It does not cover QUIC, because coturn does not implement TURN over raw QUIC: no RFC
defines it, so there is nothing to implement. WebTransport has a browser instead
(docs/interop/webtransport-browser-2026-08-20.md).

The IPv6 row uses `-g`, which asks for an IPv6 relay address; on a host without one
configured it will be refused with 440 and show as a failure. That refusal is correct
behaviour, so read the log before treating it as a defect.
EOF
} >> "$SUMMARY"

say "done — $PASS passed, $FAIL failed"
echo
cat "$SUMMARY"
[ "$FAIL" -eq 0 ]
