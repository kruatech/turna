#!/usr/bin/env bash
#
# mTLS for TURNS clients: both halves.
#
# WHY A PRIVATE CA
#
# Client certificates come from a CA you run. Public issuers — Let's Encrypt and its
# peers — sign server certificates only, so the real Let's Encrypt certificate this
# deployment has is the wrong shape for this test and cannot be substituted. That is
# not a workaround: it is how mTLS is meant to work, and `docs/MTLS.md` says the same
# about the management plane.
#
# So this script mints a CA, a server certificate signed by it, and a client
# certificate signed by it, all with a two-day life and all thrown away at the end.
#
# WHAT IT CHECKS
#
#   1. require_client_cert = true, client presents a valid certificate  -> works
#   2. require_client_cert = true, client presents none                 -> refused
#   3. client_ca set, require_client_cert = false, no certificate       -> works
#
# The second is the one that matters. A configuration that accepts everybody looks
# identical to a working one from the first check alone, which is exactly the shape of
# false green this codebase has produced twice already.
#
# The third is the staged-rollout mode: an existing fleet can migrate without a flag
# day, because a client without a certificate still gets in and is judged on its TURN
# credentials.
#
# USAGE
#
#   scripts/verify/mtls.sh
#
# ~1 minute. Artifacts in mtls-<timestamp>/.

set -uo pipefail

OUT="${OUT:-mtls-$(date +%Y%m%d-%H%M%S)}"
TLS_PORT="${TLS_PORT:-5350}"
TURN_PORT="${TURN_PORT:-3480}"
HEALTH_PORT="${HEALTH_PORT:-9093}"
SIGNALING_PORT="${SIGNALING_PORT:-9003}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
mkdir -p "$OUT"

SECRET="mtls-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NODE=target/release/turna-node
LOAD=target/release/turna-load-test
SUMMARY="$OUT/summary.md"
PASS=0
FAIL=0

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null || die "openssl required"

say "building with --features tls"
cargo build --release -p turna-node --features tls > "$OUT/build-node.log" 2>&1 \
  || { tail -15 "$OUT/build-node.log"; die "node build failed"; }
cargo build --release -p turna-load-test --features tls > "$OUT/build-load.log" 2>&1 \
  || { tail -15 "$OUT/build-load.log"; die "load-test build failed"; }

# ── the throwaway PKI ───────────────────────────────────────────────────────
say "minting a private CA, a server certificate and a client certificate"
{
  # CA
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$OUT/ca.key" -out "$OUT/ca.crt" -subj "/CN=turna-test-ca"

  # Server certificate, signed by the CA. SAN is required: rustls ignores the CN.
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/server.key" -out "$OUT/server.csr" -subj "/CN=localhost"
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
    > "$OUT/server.ext"
  openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/server.crt" -days 2 -extfile "$OUT/server.ext"

  # Client certificate. clientAuth in extendedKeyUsage is what makes it usable as
  # one — a server certificate presented by a client is refused by a correct verifier.
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/client.key" -out "$OUT/client.csr" -subj "/CN=turna-test-client"
  printf 'extendedKeyUsage=clientAuth\n' > "$OUT/client.ext"
  openssl x509 -req -in "$OUT/client.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -out "$OUT/client.crt" -days 2 -extfile "$OUT/client.ext"
} > "$OUT/pki.log" 2>&1 || { tail -20 "$OUT/pki.log"; die "PKI generation failed"; }

{
  echo "# mTLS for TURNS clients — $(date -u +%FT%TZ)"
  echo
  echo "Private CA: \`$OUT/ca.crt\` (throwaway, two-day life)."
  echo "Client certificate subject: $(openssl x509 -in "$OUT/client.crt" -noout -subject)"
  echo
  echo "| Check | Expected | Result |"
  echo "|---|---|---|"
} > "$SUMMARY"

NODE_PID=""
stop_node() {
  [ -n "$NODE_PID" ] || return 0
  kill -TERM "$NODE_PID" 2>/dev/null
  for _ in $(seq 20); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.5; done
  kill -KILL "$NODE_PID" 2>/dev/null
  wait "$NODE_PID" 2>/dev/null
  NODE_PID=""
}
trap stop_node EXIT INT TERM

start_node() { # $1 = require_client_cert, $2 = log label
  cat > "$OUT/turn.toml" <<EOF
production = false
[turn]
listen      = "0.0.0.0:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "mtls"
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
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
[tls]
enabled = true
listen  = "0.0.0.0:$TLS_PORT"
cert_path = "$PWD/$OUT/server.crt"
key_path  = "$PWD/$OUT/server.key"
client_ca = "$PWD/$OUT/ca.crt"
require_client_cert = $1
EOF
  "$NODE" "$OUT/turn.toml" > "$OUT/node-$2.log" 2>&1 &
  NODE_PID=$!
  for _ in $(seq 40); do
    curl -fsS --max-time 1 "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && return 0
    kill -0 "$NODE_PID" 2>/dev/null || break
    sleep 0.5
  done
  say "  node did not start; last lines:"
  tail -8 "$OUT/node-$2.log"
  return 1
}

record() { # name, expectation, rc, want_rc, log
  local name="$1" expect="$2" rc="$3" want="$4" log="$5"
  if [ "$rc" = "$want" ]; then
    PASS=$((PASS + 1)); say "  pass  $name"
    printf '| %s | %s | **pass** |\n' "$name" "$expect" >> "$SUMMARY"
  else
    FAIL=$((FAIL + 1)); say "  FAIL  $name (rc=$rc, wanted $want) — see $(basename "$log")"
    printf '| %s | %s | **FAIL** (rc=%s) |\n' "$name" "$expect" "$rc" >> "$SUMMARY"
  fi
}

# ── 1 & 2: require_client_cert = true ───────────────────────────────────────
say "phase: require_client_cert = true"
if start_node true required; then
  "$LOAD" --server "127.0.0.1:$TLS_PORT" --secret "$SECRET" tls-check \
    --client-cert "$OUT/client.crt" --client-key "$OUT/client.key" \
    > "$OUT/with-cert.log" 2>&1
  record "client presents a valid certificate" "accepted" "$?" 0 "$OUT/with-cert.log"

  # The one that matters. A server that accepts this is accepting everybody, and the
  # first check alone cannot tell the difference.
  "$LOAD" --server "127.0.0.1:$TLS_PORT" --secret "$SECRET" tls-check \
    > "$OUT/without-cert.log" 2>&1
  record "client presents no certificate" "refused" "$?" 1 "$OUT/without-cert.log"
fi
stop_node

# ── 3: staged rollout ───────────────────────────────────────────────────────
say "phase: client_ca set, require_client_cert = false (staged rollout)"
if start_node false optional; then
  "$LOAD" --server "127.0.0.1:$TLS_PORT" --secret "$SECRET" tls-check \
    > "$OUT/optional-no-cert.log" 2>&1
  record "no certificate, presentation optional" "accepted" "$?" 0 "$OUT/optional-no-cert.log"
fi
stop_node

{
  echo
  echo "**$PASS passed, $FAIL failed.**"
  cat <<'EOF'

The refusal case is the load-bearing one: a server that accepts a client with no
certificate while `require_client_cert = true` is accepting everybody, and a check that
only exercises the happy path cannot see the difference.

Not covered here: certificate revocation. There is no CRL or OCSP in the code,
deliberately and consistently with the management plane (`docs/MTLS.md` → Revocation) —
revocation is the PKI's job, and revoking here means rotating the CA.
EOF
} >> "$SUMMARY"

say "done — $PASS passed, $FAIL failed"
echo
cat "$SUMMARY"
[ "$FAIL" -eq 0 ]
