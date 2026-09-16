#!/usr/bin/env bash
#
# Functional verification of every transport, in one run.
#
# Each check ends at a byte arriving somewhere — an allocation, a permission and a
# success response are not evidence that a relay relays. The io_uring datapath
# answered 10 800 allocations per second for three hours while forwarding nothing
# (docs/soak/endurance-2026-08-19.md), which is why every probe here sends media and
# waits for it on the far side.
#
# Several transports cannot share one node: `[turn.quic] web_transport` is either
# true or false, and `[turn.dtls] demux` likewise. So this runs the node several
# times with different configs rather than once.
#
# USAGE (from the repository root):
#
#   scripts/verify/transports.sh
#
# ~3 minutes. Everything lands in transports-<timestamp>/.
#
# PHASES selects which transports run (space-separated: udp turns dtls quic wt).
# The default is all of them; CI uses a subset so QUIC/WebTransport get an
# end-to-end gate on every PR without paying for the full matrix:
#
#   PHASES="quic wt" scripts/verify/transports.sh
#
# An unknown phase name is a hard error, not a silent no-op — a typo that runs
# zero checks and exits 0 is the worst outcome a verification script can have.

set -uo pipefail

OUT="${OUT:-transports-$(date +%Y%m%d-%H%M%S)}"
ALL_PHASES="udp turns dtls quic wt"
PHASES="${PHASES:-$ALL_PHASES}"
for _p in $PHASES; do
  case " $ALL_PHASES " in
    *" $_p "*) ;;
    *) echo "unknown phase '$_p' — valid: $ALL_PHASES" >&2; exit 1 ;;
  esac
done
# Space-padded substring match, so "quic" never matches inside another name.
want() { case " $PHASES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
mkdir -p "$OUT"

SECRET="verify-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NODE=target/release/turna-node
LOAD=target/release/turna-load-test
SUMMARY="$OUT/summary.md"
PASS=0
FAIL=0

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
note() { printf '%s\n' "$1" >> "$SUMMARY"; }

result() { # name, exit code, log file
  if [ "$2" = 0 ]; then
    PASS=$((PASS + 1)); note "| $1 | **pass** | \`$(basename "$3")\` |"; say "  pass  $1"
  else
    FAIL=$((FAIL + 1)); note "| $1 | **FAIL** | \`$(basename "$3")\` |"; say "  FAIL  $1"
  fi
}

{
  echo "# Transport verification — $(date -u +%FT%TZ)"
  echo
  echo "- host: $(hostname), $(uname -sr)"
  echo "- git: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo
  echo "| Check | Result | Log |"
  echo "|---|---|---|"
} > "$SUMMARY"

# ── build ───────────────────────────────────────────────────────────────────
say "building (node: all transports; load tool: all clients)"
cargo build --release -p turna-node \
  --features "tls,dtls,quic,web-transport" > "$OUT/build-node.log" 2>&1 || {
  echo "node build failed — see $OUT/build-node.log"; exit 1; }
cargo build --release -p turna-load-test \
  --features "tls,dtls,quic,web-transport" > "$OUT/build-load.log" 2>&1 || {
  echo "load-test build failed — see $OUT/build-load.log"; exit 1; }

# `-addext subjectAltName`: rustls -- which both the node and every client here
# use -- has never honoured CN as a name. A certificate with only `/CN=localhost`
# matches nothing, so any probe that actually validates the name is refused. The
# TLS/DTLS probes skip verification and never noticed; `wt-check` does not, which
# is why it was the one that failed. Both loopback literals are listed so a probe
# may address the node by name or by either IP.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null

# ── config generator ────────────────────────────────────────────────────────
# `allow_loopback_peers` is on because every probe here relays to a peer on
# 127.0.0.1, which the filter refuses by default — correctly, it is SSRF
# protection. It must not appear in a production config.
#
# The relay range sits below the ephemeral range: on loopback the peer socket gets
# an ephemeral port, and if that lands inside the relay range the relay forwards to
# an address it is itself serving. The symptom is millions of forwarded packets on
# the server and none received by the client.
gen_config() { # $1 = extra sections, $2 = extra lines inside [turn]
  cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "0.0.0.0:3478"
external_ip = "127.0.0.1"
${2:-}
realm       = "verify"
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
listen = "127.0.0.1:9091"
$1
EOF
}

NODE_PID=""
start_node() { # $1 = label
  "$NODE" "$OUT/turn.toml" > "$OUT/node-$1.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 40); do
    curl -fsS --max-time 1 http://127.0.0.1:9091/ready >/dev/null 2>&1 && return 0
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 0.5
  done
  say "  node did not become ready — see node-$1.log"
  tail -5 "$OUT/node-$1.log"
  return 1
}
stop_node() {
  [ -n "$NODE_PID" ] || return 0
  kill -TERM "$NODE_PID" 2>/dev/null
  for _ in $(seq 20); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
  kill -KILL "$NODE_PID" 2>/dev/null
  NODE_PID=""
}
trap 'stop_node' EXIT INT TERM

run() { # name, log-suffix, command...
  local name="$1" suffix="$2"; shift 2
  local log="$OUT/$suffix.log"
  "$@" > "$log" 2>&1
  result "$name" "$?" "$log"
}

# ── 1. UDP: conformance, IPv6 control plane and IPv6 media ──────────────────
if want udp; then
say "phase 1: UDP, conformance and IPv6"
# `external_ip6` is a key inside [turn], not a section, hence the second argument.
gen_config "$(printf '[turn.tcp_relay]\nenabled = true\n')" 'external_ip6 = "::1"'
if start_node udp; then
  run "conformance (address family + peer filter)" conformance \
    "$LOAD" --server 127.0.0.1:3478 --secret "$SECRET" conformance
  run "IPv6 relayed media" ipv6-media \
    "$LOAD" --server 127.0.0.1:3478 --secret "$SECRET" --duration 10 \
    channel-data --channels 10 --pps 50 --payload 160 --family v6
fi
stop_node
fi

# ── 2. TURNS ────────────────────────────────────────────────────────────────
if want turns; then
say "phase 2: TURNS"
gen_config "$(printf '[turn.tcp_relay]\nenabled = true\n\n[tls]\nenabled = true\nlisten = "0.0.0.0:5349"\ncert_path = "%s"\nkey_path = "%s"\n' "$OUT/cert.pem" "$OUT/key.pem")"
if start_node turns; then
  run "TURNS functional (incl. relayed media)" tls-check \
    "$LOAD" --server 127.0.0.1:5349 --secret "$SECRET" tls-check
  run "TURNS under load (allocation churn)" tls-load \
    "$LOAD" --server 127.0.0.1:5349 --secret "$SECRET" --duration 15 --json tls -c 20
  run "TURNS under load (relayed media)" tls-load-media \
    "$LOAD" --server 127.0.0.1:5349 --secret "$SECRET" --duration 15 --json \
    tls -c 10 --channel-data --pps 50
  # RFC 6062 lives here, not in the UDP phase: turna has no plain-TCP TURN
  # listener, and the TCP relay's connection state is adopted by the TLS bridge.
  # Pointing it at 3478 gets `Connection refused`.
  run "RFC 6062 TCP relay" tcp-relay \
    "$LOAD" --server 127.0.0.1:5349 --secret "$SECRET" tcp-relay-check
  run "RFC 6062, payload pipelined with ConnectionBind" tcp-relay-pipelined \
    "$LOAD" --server 127.0.0.1:5349 --secret "$SECRET" tcp-relay-check --pipelined
fi
stop_node
fi

# ── 3. DTLS, both listener paths ────────────────────────────────────────────
if want dtls; then
for DEMUX in false true; do
  say "phase 3: DTLS (demux = $DEMUX)"
  # The per-IP handshake rate limit defaults to 8 since 0.5.0 and is refused
  # with `demux = false`: on the stock listener the handshake runs below
  # accept(), where the limit cannot be enforced, and config validation says so
  # rather than accepting a setting that would do nothing. The stock phase
  # therefore has to turn it off explicitly.
  #
  # Without this the phase did not run at all and the script still reported
  # "10 passed, 0 failed" — the silent-no-op outcome this file's own header
  # calls the worst one a verification script can have.
  DTLS_RATE=$([ "$DEMUX" = "true" ] && echo 8 || echo 0)
  gen_config "$(printf '[turn.dtls]\nenabled = true\nlisten = "0.0.0.0:5350"\ncert_path = "%s"\nkey_path = "%s"\ndemux = %s\nmax_handshakes_per_sec_per_ip = %s\n' "$OUT/cert.pem" "$OUT/key.pem" "$DEMUX" "$DTLS_RATE")"
  if start_node "dtls-$DEMUX"; then
    run "DTLS allocation + media (demux = $DEMUX)" "dtls-$DEMUX" \
      "$LOAD" --server 127.0.0.1:5350 --secret "$SECRET" dtls-check
  fi
  stop_node
done
fi

# ── 4. QUIC, then WebTransport (mutually exclusive on one listener) ─────────
if want quic; then
say "phase 4: raw QUIC"
gen_config "$(printf '[turn.quic]\nenabled = true\nlisten = "0.0.0.0:3479"\ncert_path = "%s"\nkey_path = "%s"\nweb_transport = false\n' "$OUT/cert.pem" "$OUT/key.pem")"
if start_node quic; then
  run "raw QUIC (incl. relayed media)" quic-check \
    "$LOAD" --server 127.0.0.1:3479 --secret "$SECRET" quic-check
fi
stop_node
fi

if want wt; then
say "phase 5: WebTransport"
# `[::]` rather than `0.0.0.0`: `wt-check` addresses the node by name, and on a
# host whose /etc/hosts maps `localhost` to ::1 first -- which GitHub's
# ubuntu-latest does -- the client sends to [::1]:3479 while a 0.0.0.0 listener
# hears only IPv4. The datagrams went nowhere, and the node's own counters said
# so: after thirty seconds accepted=0 AND handshake_failures=0, i.e. not one
# packet ever arrived. `quic-check` passed on the same port because it dials
# 127.0.0.1 literally. A dual-stack socket accepts both.
gen_config "$(printf '[turn.quic]\nenabled = true\nlisten = "[::]:3479"\ncert_path = "%s"\nkey_path = "%s"\nweb_transport = true\n' "$OUT/cert.pem" "$OUT/key.pem")"
if start_node wt; then
  run "WebTransport / H3" wt-check \
    "$LOAD" --secret "$SECRET" wt-check --url https://localhost:3479/
fi
stop_node
fi

# ── summary ─────────────────────────────────────────────────────────────────
{
  echo
  echo "**$PASS passed, $FAIL failed.** Phases run: \`$PHASES\`."
  echo
  echo "Not covered here: OAuth (needs a real authorization server), AF_XDP (needs a"
  echo "dedicated NIC and root), and sustained load on anything but TURNS — the soak"
  echo "harness drives UDP. \`wt-check\` is not a browser: client and server share"
  echo "\`wtransport\` and one reading of the spec, so a shared misreading stays"
  echo "invisible."
} >> "$SUMMARY"

say "done — $PASS passed, $FAIL failed. Summary: $SUMMARY"
echo
cat "$SUMMARY"
# A run that executed nothing is a failure, not a pass: it means every selected
# phase failed to start its node, and exiting 0 there would make the CI gate
# green while proving nothing.
if [ "$((PASS + FAIL))" -eq 0 ]; then
  say "no checks ran at all — treating as failure"
  exit 1
fi
[ "$FAIL" -eq 0 ]
