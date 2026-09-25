#!/usr/bin/env bash
#
# RFC 7635 OAuth verification kit — the wrapper around `turna-oauth-verify`.
#
# WHY THIS EXISTS
#
# turna refuses `[turn.auth.oauth] enabled = true` under `production = true`
# until OAuth has been verified against a real authorization server
# (docs/PRODUCTION_READINESS.md R9). A token issuer written in this repository
# would only test one reading of RFC 7635 against itself, so the evidence has to
# come from YOUR AS. This script makes collecting it mechanical; the procedure
# and what to record are in docs/runbooks/oauth-verification.md.
#
# USAGE
#
#   scripts/verify/oauth-verification.sh selftest
#       Build the node and the kit, start a throwaway node on loopback with
#       OAuth enabled (production = false) and a random AS-RS key, mint tokens
#       as an AS would, run the whole flow including the refusals, stop the node.
#       Proves the plumbing — NOT interop.
#
#   scripts/verify/oauth-verification.sh inspect --server-name NAME \
#       --as-rs-key-hex HEX --token BASE64
#       Open a token minted by your AS with turna's own decoder. No node needed.
#
#   scripts/verify/oauth-verification.sh exercise --server HOST:PORT \
#       --token BASE64 --mac-key-b64 BASE64 [--kid KID] [--sha256]
#       Run the full client flow against your node with a token from your AS.
#       Passing this, with the output kept, is the evidence the runbook asks for.
#
# Everything after the subcommand is passed to `turna-oauth-verify`. Set
# TURNA_OAUTH_VERIFY_BIN / TURNA_NODE_BIN to use prebuilt binaries.
#
# Exit status: that of the kit (0 pass, 1 a step failed, 2 bad input).

set -uo pipefail

cd "$(dirname "$0")/../.."

cmd="${1:-}"
[ -n "$cmd" ] || { sed -n '2,36p' "$0"; exit 2; }
shift

TARGET_DIR="${CARGO_TARGET_DIR:-target}"

kit() {
  if [ -z "${TURNA_OAUTH_VERIFY_BIN:-}" ]; then
    cargo build -q -p turna-oauth-verify || exit 2
    TURNA_OAUTH_VERIFY_BIN="$TARGET_DIR/debug/turna-oauth-verify"
  fi
  "$TURNA_OAUTH_VERIFY_BIN" "$@"
}

case "$cmd" in
  inspect | exercise | mint)
    kit "$cmd" "$@"
    exit $?
    ;;
  selftest) ;;
  *)
    echo "unknown subcommand: $cmd (selftest | inspect | exercise | mint)" >&2
    exit 2
    ;;
esac

# ── selftest: a throwaway node ────────────────────────────────────────────────
if [ -z "${TURNA_NODE_BIN:-}" ]; then
  cargo build -q -p turna-node || exit 2
  TURNA_NODE_BIN="$TARGET_DIR/debug/turna-node"
fi

free_port() {
  python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET, getattr(socket, sys.argv[1])); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])' "$1"
}
TURN_PORT="$(free_port SOCK_DGRAM)"
HEALTH_PORT="$(free_port SOCK_STREAM)"
AS_RS_KEY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SERVER_NAME="turn.selftest.invalid"
WORK="$(mktemp -d)"
trap 'kill "$NODE_PID" 2>/dev/null; wait "$NODE_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

cat >"$WORK/turn.toml" <<TOML
production = false
[turn]
listen = "127.0.0.1:$TURN_PORT"
realm = "turna"
transport = "tokio"
[turn.auth.oauth]
enabled = true
server_name = "$SERVER_NAME"
as_rs_keys = ["$AS_RS_KEY"]
[turn.relay]
min_port = 49152
max_port = 49500
max_allocations = 64
[health]
listen = "127.0.0.1:$HEALTH_PORT"
TOML

"$TURNA_NODE_BIN" "$WORK/turn.toml" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
for _ in $(seq 1 100); do
  curl -fsS "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1 && break
  sleep 0.1
done
if ! curl -fsS "http://127.0.0.1:$HEALTH_PORT/ready" >/dev/null 2>&1; then
  echo "node did not become ready; log:" >&2
  cat "$WORK/node.log" >&2
  exit 2
fi

kit selftest --server "127.0.0.1:$TURN_PORT" --as-rs-key-hex "$AS_RS_KEY" \
  --server-name "$SERVER_NAME" "$@"
