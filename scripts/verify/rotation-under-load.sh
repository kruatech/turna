#!/usr/bin/env bash
#
# Rotate a certificate, and a shared secret, while media is flowing.
#
#   scripts/verify/rotation-under-load.sh
#   scripts/verify/rotation-under-load.sh --only cert
#
# §15 asks for both. The question in each case is not "does rotation work" — the
# reloader has unit coverage — but "does it work without dropping the calls that
# are in progress", which only a run with traffic can answer.
#
# WHAT EACH ROTATION SHOULD DO TO EXISTING SESSIONS
#
# **Certificate: nothing.** TLS material is read per accepted connection, so a
# session established under the old certificate keeps its negotiated keys. If
# existing sessions break, the reload is tearing down the listener rather than
# swapping the material, and that is a different and worse implementation than
# the one documented.
#
# **Shared secret: nothing, until the credential expires.** TURN long-term
# credentials are checked at Allocate and then the allocation stands on its own.
# A rotation mid-call must not invalidate a live allocation; it must invalidate
# the *next* Allocate using the old secret. Both halves are checked, because a
# rotation that only did the first would look successful and leave the old
# credential working.
#
# The failure this is looking for is the one where rotation appears to work
# because nobody was using the node at the time.

set -uo pipefail

ONLY="${ONLY:-both}"
DURATION="${DURATION:-90}"
CHANNELS="${CHANNELS:-20}"
PPS="${PPS:-20}"
TURN_PORT="${TURN_PORT:-3488}"
TLS_PORT="${TLS_PORT:-5351}"
HEALTH_PORT="${HEALTH_PORT:-9093}"
SIGNALING_PORT="${SIGNALING_PORT:-9008}"

while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
OUT="rotation-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

PASS=0; FAIL=0
say()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
ok()   { PASS=$((PASS+1)); say "  pass  $1"; }
bad()  { FAIL=$((FAIL+1)); say "  FAIL  $1"; }

NODE=target/release/turna-node
LOAD=target/release/turna-load-test
say "building"
cargo build --release -p turna-node -p turna-load-test --features tls \
  > "$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; exit 1; }

SECRET_OLD="rot-old-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SECRET_NEW="rot-new-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# EC, PKCS#8. Both matter: webrtc-dtls rejects RSA, and `openssl ecparam -genkey`
# alone emits an EC PARAMETERS block that the listener also rejects. Two separate
# afternoons went into learning each.
mkcert() {
  local out="$1" cn="$2"
  openssl ecparam -genkey -name prime256v1 -noout -out "$out.raw" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$out.raw" -out "$out.key" 2>/dev/null
  openssl req -x509 -new -key "$out.key" -out "$out.crt" -days 2 \
    -subj "/CN=$cn" 2>/dev/null
  rm -f "$out.raw"
}
mkcert "$OUT/first" "rotation-test-first"
mkcert "$OUT/second" "rotation-test-second"
cp "$OUT/first.crt" "$OUT/live.crt"; cp "$OUT/first.key" "$OUT/live.key"

cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "127.0.0.1:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "rotation"
transport   = "tokio"
[turn.auth]
shared_secret = "$SECRET_OLD"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 24000
max_port = 24500
max_allocations = 200
[turn.relay.quota]
max_per_user = 0
[tls]
enabled   = true
listen    = "127.0.0.1:$TLS_PORT"
cert_path = "$REPO/$OUT/live.crt"
key_path  = "$REPO/$OUT/live.key"
cert_reload_secs = 5
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET_OLD"
EOF

pkill -x turna-node 2>/dev/null; sleep 1
"$REPO/$NODE" "$OUT/turn.toml" > "$OUT/node.log" 2>&1 &
NODE_PID=$!
trap 'kill -TERM $NODE_PID 2>/dev/null; sleep 1; kill -KILL $NODE_PID 2>/dev/null' EXIT INT TERM

for _ in $(seq 40); do
  curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && break
  kill -0 "$NODE_PID" 2>/dev/null || { tail -20 "$OUT/node.log"; exit 1; }
  sleep 0.5
done

# ── certificate ───────────────────────────────────────────────────────────
if [ "$ONLY" = "both" ] || [ "$ONLY" = "cert" ]; then
  say "cert rotation: starting $DURATION s of media"
  "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET_OLD" \
    --source-ips 32 --duration "$DURATION" --warmup 10 --json \
    channel-data --channels "$CHANNELS" --pps "$PPS" --payload 200 \
    > "$OUT/cert-load.json" 2> "$OUT/cert-load.err" &
  LOAD_PID=$!

  sleep $(( DURATION / 3 ))
  say "cert rotation: swapping the certificate mid-run"
  cp "$OUT/second.crt" "$OUT/live.crt"
  cp "$OUT/second.key" "$OUT/live.key"
  RELOADS_BEFORE=$(curl -fsS "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null |
    awk '/^turna_tls_cert_reloads_total/{print $2}' | head -1)
  sleep 12   # two reload intervals plus slack

  RELOADS_AFTER=$(curl -fsS "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null |
    awk '/^turna_tls_cert_reloads_total/{print $2}' | head -1)
  FAILURES=$(curl -fsS "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null |
    awk '/^turna_tls_cert_reload_failures_total/{print $2}' | head -1)

  wait "$LOAD_PID" 2>/dev/null
  read -r RECV ERRS <<<"$(python3 - "$OUT/cert-load.json" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
    print(d.get("recv", 0), d.get("errs", 1))
except Exception:
    print(0, 1)
PY
)"

  if [ "${RELOADS_AFTER:-0}" -gt "${RELOADS_BEFORE:-0}" ]; then
    ok "certificate reloaded (${RELOADS_BEFORE:-0} -> ${RELOADS_AFTER:-0})"
  else
    bad "no reload observed; turna_tls_cert_reloads_total did not move. Either the interval is longer than we waited or the reloader is not running."
  fi
  if [ "${FAILURES:-0}" = "0" ]; then
    ok "no reload failures (old material would have stayed in service)"
  else
    bad "$FAILURES reload failures — check node.log; a half-written PEM does this"
  fi
  if [ "${ERRS:-1}" = "0" ] && [ "${RECV:-0}" -gt 0 ]; then
    ok "media survived the rotation ($RECV frames, 0 errors)"
  else
    bad "media disrupted: $RECV frames, $ERRS errors. TLS material is read per connection, so an established session should not notice — if it did, the reload is tearing down the listener."
  fi
fi

# ── shared secret ─────────────────────────────────────────────────────────
# The secret half is disabled, because the mechanism it tested does not exist.
#
# It sent SIGHUP to reload the config. The node does not handle SIGHUP — zero
# references in services/node/src/main.rs — so it died, and the next check ("the
# old secret no longer grants allocations") passed against a dead node. It would
# have passed against any dead node.
#
# There is no hot rotation of shared_secret by any route: UpdateConfig carries
# max_allocations, max_allocations_per_user and max_bytes_per_sec_per_allocation,
# and not the secret.
#
# So §7's "credential rotation without downtime" holds for certificates —
# verified above, 0 -> 1 with media uninterrupted — and does not hold for the
# shared secret, which needs a restart. That is recorded in
# docs/verification/ rather than tested by a check that cannot pass honestly.
#
# Set ROTATE_SECRET=1 to run it anyway, once a mechanism exists.
if [ "${ROTATE_SECRET:-0}" = "1" ] && { [ "$ONLY" = "both" ] || [ "$ONLY" = "secret" ]; }; then
  say "secret rotation: starting $DURATION s of media on the old secret"
  "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET_OLD" \
    --source-ips 32 --duration "$DURATION" --warmup 10 --json \
    channel-data --channels "$CHANNELS" --pps "$PPS" --payload 200 \
    > "$OUT/secret-load.json" 2> "$OUT/secret-load.err" &
  LOAD_PID=$!

  sleep $(( DURATION / 3 ))
  say "secret rotation: rewriting the config and reloading"
  sed -i.bak "s/$SECRET_OLD/$SECRET_NEW/g" "$OUT/turn.toml"
  kill -HUP "$NODE_PID" 2>/dev/null
  sleep 5

  # A live allocation must survive. The credential was checked at Allocate; the
  # allocation stands on its own after that.
  wait "$LOAD_PID" 2>/dev/null
  read -r RECV ERRS <<<"$(python3 - "$OUT/secret-load.json" <<'PY'
import json, sys
try:
    d = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
    print(d.get("recv", 0), d.get("errs", 1))
except Exception:
    print(0, 1)
PY
)"
  if [ "${ERRS:-1}" = "0" ] && [ "${RECV:-0}" -gt 0 ]; then
    ok "existing sessions survived the secret rotation ($RECV frames)"
  else
    bad "existing sessions broke: $RECV frames, $ERRS errors. A rotation must not invalidate an allocation already granted."
  fi

  # And the old secret must stop working for *new* allocations. Without this half
  # a rotation that changed nothing would pass the test above.
  say "secret rotation: the old secret must now be refused"
  if "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET_OLD" \
      --duration 8 --json channel-data --channels 1 --pps 2 --payload 100 \
      > "$OUT/old-secret.json" 2>/dev/null; then
    OLD_OK=$(python3 -c '
import json,sys
try:
    d=json.loads(open("'"$OUT"'/old-secret.json").read().strip().splitlines()[-1])
    print(1 if d.get("recv",0) > 0 else 0)
except Exception:
    print(0)')
    if [ "$OLD_OK" = "0" ]; then
      ok "old secret no longer grants allocations"
    else
      bad "the old secret still works. The rotation did not take effect, and the test above passed only because nothing had changed."
    fi
  else
    ok "old secret rejected (client could not allocate)"
  fi

  if "$REPO/$LOAD" --server "127.0.0.1:$TURN_PORT" --secret "$SECRET_NEW" \
      --duration 8 --json channel-data --channels 1 --pps 2 --payload 100 \
      > "$OUT/new-secret.json" 2>/dev/null; then
    NEW_OK=$(python3 -c '
import json,sys
try:
    d=json.loads(open("'"$OUT"'/new-secret.json").read().strip().splitlines()[-1])
    print(1 if d.get("recv",0) > 0 and d.get("errs",1) == 0 else 0)
except Exception:
    print(0)')
    if [ "$NEW_OK" = "1" ]; then
      ok "new secret grants allocations"
    else
      bad "the new secret does not work either — the node may not have reloaded at all"
    fi
  else
    bad "new secret rejected: rotation left the node accepting neither credential"
  fi
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
say "artifacts in $OUT/"
[ "$FAIL" -eq 0 ]
