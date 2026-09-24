#!/usr/bin/env bash
# Short live UDP suite on tokio and io_uring. Not byte-level or endurance evidence.
# Optional base config; default is an isolated loopback-only test configuration.
# OUT, TARGET, HEALTH_URL, START_TIMEOUT, TEST_FILTER may be overridden.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${OUT:-backend-diff-$(date +%Y%m%d-%H%M%S)}"
TARGET="${TARGET:-127.0.0.1:13478}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:19098/ready}"
START_TIMEOUT="${START_TIMEOUT:-30}"
BACKENDS="${BACKENDS:-tokio io_uring}"
[[ "$BACKENDS" == 'tokio io_uring' ]] || { echo 'This comparison requires BACKENDS="tokio io_uring"'; exit 1; }
umask 077
mkdir "$OUT"
NODE_PID=""
stop_node() {
  if [[ -n "$NODE_PID" ]]; then
    kill -TERM "$NODE_PID" 2>/dev/null || true
    for ((n=0; n<240; n++)); do
      kill -0 "$NODE_PID" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$NODE_PID" 2>/dev/null; then
      echo "FAIL shutdown: node did not exit within 60 seconds (pid=$NODE_PID)" >&2
      kill -KILL "$NODE_PID" 2>/dev/null || true
      wait "$NODE_PID" 2>/dev/null || true
      NODE_PID=""
      return 1
    fi
    local rc=0
    wait "$NODE_PID" || rc=$?
    echo "node shutdown: exit=$rc"
    NODE_PID=""
    return "$rc"
  fi
}
trap 'stop_node || true' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
BASE_CFG="${1:-$OUT/base.toml}"
if [[ $# == 0 ]]; then
  [[ "$TARGET" == 127.0.0.1:13478 && "$HEALTH_URL" == http://127.0.0.1:19098/ready ]] || { echo 'Custom endpoints require an explicit matching config'; exit 1; }
  cat > "$BASE_CFG" <<'TOML'
production = false
[turn]
listen = "127.0.0.1:13478"
external_ip = "127.0.0.1"
realm = "backend-diff"
transport = "tokio"
[[turn.auth.static_users]]
username = "testuser"
password = "testpass"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 23000
max_port = 23255
max_allocations = 128
[health]
listen = "127.0.0.1:19098"
TOML
  unset TURNA_TEST_SECRET
  export TURNA_TEST_USER=testuser TURNA_TEST_PASS=testpass
fi
# Parse config, validate actual destinations, refuse occupied sockets before build.
python3 - "$BASE_CFG" "$TARGET" "$HEALTH_URL" <<'PY'
import socket,sys,tomllib,urllib.parse
cfg=tomllib.load(open(sys.argv[1],'rb')); url=urllib.parse.urlparse(sys.argv[3])
assert cfg['turn']['listen']==sys.argv[2], 'TARGET/config mismatch'
assert cfg['health']['listen']==f'{url.hostname}:{url.port}', 'health/config mismatch'
assert url.scheme=='http' and url.path=='/ready', 'use HTTP /ready'
for kind,addr in [(socket.SOCK_DGRAM,sys.argv[2]),(socket.SOCK_STREAM,cfg['health']['listen'])]:
 host,port=addr.rsplit(':',1)
 assert host=='127.0.0.1', 'this isolated runner requires IPv4 loopback'
 with socket.socket(socket.AF_INET,kind) as s:s.bind((host,int(port)))
PY
cargo build --locked --release -p turna-node --features io-uring > "$OUT/build.log" 2>&1 || { cat "$OUT/build.log"; exit 1; }
printf 'backend\tresult\n' > "$OUT/summary.tsv"
all_ok=1
for backend in tokio io_uring; do
  cfg="$OUT/$backend.toml"
  python3 - "$BASE_CFG" "$cfg" "$backend" <<'PY'
import re,sys,tomllib
s=open(sys.argv[1]).read();pat=r'(?ms)^\[turn\][ \t]*\n(.*?)(?=^\[|\Z)'
m=re.search(pat,s);assert m, 'missing [turn]'
body=re.sub(r'(?m)^\s*transport\s*=.*\n?', '', m[1])
s=s[:m.start(1)]+f'transport = "{sys.argv[3]}"\n'+body+s[m.end(1):]
assert tomllib.loads(s)['turn']['transport']==sys.argv[3]
open(sys.argv[2],'w').write(s)
PY
  target/release/turna-node "$cfg" > "$OUT/$backend.node.log" 2>&1 &
  NODE_PID=$!
  ready=0
  for ((n=0; n<START_TIMEOUT*2; n++)); do
    kill -0 "$NODE_PID" 2>/dev/null || break
    if curl -fsS --max-time 1 "$HEALTH_URL" > "$OUT/$backend.ready.json" 2>/dev/null; then
      kill -0 "$NODE_PID" 2>/dev/null && ready=1
      break
    fi
    sleep 0.5
  done
  ok=1
  if [[ $ready == 1 ]]; then
    # Explicit live-server tests: exclude startup, cluster and optional transports.
    tests=(stun_binding malformed_packet_ignored concurrent_bindings turn_allocate turn_allocate_wrong_password turn_refresh turn_create_permission turn_channel_bind turn_channel_data_relay turn_stale_nonce_challenge)
    if [[ -n "${TEST_FILTER:-}" ]]; then tests=("$TEST_FILTER"); fi
    for name in "${tests[@]}"; do
      log="$OUT/$backend.$name.test.log"
      rc=0
      TURNA_TEST_REQUIRE_SERVER=1 TURNA_TEST_TARGET="$TARGET" \
      TURNA_TEST_WRONG_PW=definitely-wrong-password \
        cargo test --locked --release -p turna-integration-tests --lib "tests::$name" -- --exact --nocapture > "$log" 2>&1 || rc=$?
      if [[ $rc != 0 ]] || ! grep -q 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log" || grep -qiE 'SKIP:|skipping' "$log"; then
        ok=0
        echo "FAIL $backend $name — $log"
      else
        echo "PASS $backend $name"
      fi
    done
    kill -0 "$NODE_PID" 2>/dev/null || ok=0
  else
    echo "FAIL $backend startup — $OUT/$backend.node.log"
    ok=0
  fi
  stop_node || ok=0
  if [[ $ok == 1 ]]; then result=PASS; else result=FAIL; all_ok=0; fi
  printf '%s\t%s\n' "$backend" "$result" >> "$OUT/summary.tsv"
done
cat "$OUT/summary.tsv"
echo "Logs retained: $OUT (configs may contain test credentials)"
[[ $all_ok == 1 ]]
