#!/usr/bin/env bash
#
# Overnight endurance run, ~7.5 hours, unattended.
#
# WHAT IT IS FOR
#
# Three transports have correctness on record but no endurance
# (docs/interop/transports-2026-08-19.md). This closes the endurance half for the
# two that can be driven without new code:
#
#   TURNS, relayed media   3h    <- the missing piece for TURNS -> supported
#   TURNS, allocation churn 1.5h <- pays the TLS handshake every time, as a
#                                   reconnecting client does
#   io_uring, relayed media 3h   <- the 3h run on record never relayed; the
#                                   channel-data phase failed to start
#
# It deliberately does NOT touch scripts/soak/soak.sh. That script already accepts a
# pre-written config and a TURNA_LOAD_CMD override, so everything here is composition.
# Reaching into it would risk reverting someone else's fix for no gain.
#
# WHAT IT DOES NOT ESTABLISH
#
# The certificate is self-signed. The load client accepts any certificate by design,
# so this measures the TLS datapath, not certificate validation — a run against a real
# chain (you have a Let's Encrypt cert for a real domain) is a separate five-minute
# check and is what the browser interop record still lacks.
#
# Nor does it add an independent implementation: the client here shares one reading of
# the spec with the server. Endurance and interop are different claims.
#
# USAGE
#
#   scripts/verify/overnight.sh              # ~7.5h
#   HOURS=4 scripts/verify/overnight.sh      # scaled down proportionally
#
# Everything lands in overnight-<timestamp>/.

set -uo pipefail

HOURS="${HOURS:-7.5}"
OUT="${OUT:-overnight-$(date +%Y%m%d-%H%M%S)}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1

# Phase budget, proportional so a shorter rehearsal keeps the same shape.
TOTAL_SECS="$(python3 -c "print(int(float('$HOURS') * 3600))")"
TURNS_MEDIA_SECS="${TURNS_MEDIA_SECS:-$((TOTAL_SECS * 40 / 100))}"
TURNS_CHURN_SECS="${TURNS_CHURN_SECS:-$((TOTAL_SECS * 20 / 100))}"
URING_MEDIA_SECS="${URING_MEDIA_SECS:-$((TOTAL_SECS * 40 / 100))}"

# Concurrency: modest on purpose. This is an endurance run, and a rate that saturates
# something turns every later signal into noise about the saturation.
TLS_CONC="${TLS_CONC:-100}"
TLS_PPS="${TLS_PPS:-25}"
UDP_CHANNELS="${UDP_CHANNELS:-200}"
UDP_PPS="${UDP_PPS:-25}"

# Relay ports must sit below the kernel ephemeral range or the relay forwards to
# itself on loopback; soak.sh enforces this too.
RELAY_MIN=20000
RELAY_MAX=20847
MAX_ALLOC=800

# Ports. Defaults suit a machine with nothing else on them; override where something
# already holds one (a coturn on 3478, another service on 9091).
TURN_PORT="${TURN_PORT:-3478}"
TLS_PORT="${TLS_PORT:-5349}"
HEALTH_PORT="${HEALTH_PORT:-9091}"
SIGNALING_PORT="${SIGNALING_PORT:-9001}"

# Certificate. Empty means "generate a self-signed one", which measures the TLS
# datapath but not chain validation — the client accepts any certificate by design.
#
# Point these at a real certificate to close that gap. Note what does and does not
# change: the server then presents a chain a real client would accept, and that is
# worth having on record, but this load client still does not verify it. Chain
# validation is proven by a verifying client — `openssl s_client -verify_return_error`
# or a browser — not by this run.
CERT_PATH="${CERT_PATH:-}"
KEY_PATH="${KEY_PATH:-}"
# Address the load client connects to, and the SNI it presents. With a real
# certificate these should be the public address and the certificate's name.
TLS_TARGET="${TLS_TARGET:-127.0.0.1:$TLS_PORT}"
SERVER_NAME="${SERVER_NAME:-localhost}"
# External address the node advertises in its relayed candidates. On a public host
# this must be the public IP, or clients receive an unreachable relay address.
EXTERNAL_IP="${EXTERNAL_IP:-127.0.0.1}"

SECRET="overnight-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SUMMARY="$OUT/summary.md"

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

# Below this the phases are too short for the analyser to say anything: it needs
# several idle windows to compare floors, and refuses outright under 10 samples.
if [ "$TOTAL_SECS" -lt 1800 ]; then
  die "HOURS=$HOURS gives ${TOTAL_SECS}s total, which is too short to conclude anything.
The analyser compares idle floors across cycles and needs several of them. Use 0.5h at
the very least for a rehearsal, and 4h+ for a result worth recording."
fi

mkdir -p "$OUT" || die "cannot create $OUT"
command -v python3 >/dev/null || die "python3 required"
command -v openssl >/dev/null || die "openssl required"

# A health port held by something else is not a warning, it is a run that measures the
# wrong process for a day. Checked before the build so it costs seconds.
if curl -fsS --max-time 2 "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null | grep -q .; then
  if curl -fsS --max-time 2 "http://127.0.0.1:$HEALTH_PORT/metrics" 2>/dev/null | grep -q '^turna_'; then
    die "something is already serving turna metrics on 127.0.0.1:$HEALTH_PORT.
Another node is running; stop it or set HEALTH_PORT."
  fi
  die "127.0.0.1:$HEALTH_PORT is held by another process (its /metrics has no turna_ series).
Set HEALTH_PORT to a free port — otherwise the sampler reads that process for the whole run."
fi

say "building"
cargo build --release -p turna-node --features "tls,io-uring" > "$OUT/build-node.log" 2>&1 \
  || { tail -20 "$OUT/build-node.log"; die "node build failed"; }
cargo build --release -p turna-load-test --features tls > "$OUT/build-load.log" 2>&1 \
  || { tail -20 "$OUT/build-load.log"; die "load-test build failed"; }

if [ -z "$CERT_PATH" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 3 -subj "/CN=$SERVER_NAME" 2>/dev/null \
    || die "certificate generation failed"
  CERT_PATH="$PWD/$OUT/cert.pem"
  KEY_PATH="$PWD/$OUT/key.pem"
  CERT_KIND="self-signed (measures the TLS datapath, not chain validation)"
else
  [ -r "$CERT_PATH" ] || die "CERT_PATH is not readable: $CERT_PATH"
  [ -r "$KEY_PATH" ] || die "KEY_PATH is not readable: $KEY_PATH"
  CERT_KIND="supplied: $CERT_PATH"
  say "using the supplied certificate; subject/issuer:"
  openssl x509 -in "$CERT_PATH" -noout -subject -issuer -dates 2>&1 | sed 's/^/  /' | tee -a "$OUT/run.log"
fi

{
  echo "# Overnight endurance run"
  echo
  echo "- started: $(date -u +%FT%TZ)"
  echo "- host: $(hostname), $(nproc) cpus, $(awk '/MemTotal/{printf "%.0f GiB", $2/1048576}' /proc/meminfo)"
  echo "- kernel: $(uname -sr)"
  echo "- git: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)$( [ -n "$(git status --porcelain 2>/dev/null)" ] && echo ' (DIRTY)')"
  echo "- budget: ${HOURS}h — TURNS media ${TURNS_MEDIA_SECS}s, TURNS churn ${TURNS_CHURN_SECS}s, io_uring media ${URING_MEDIA_SECS}s"
  echo "- certificate: $CERT_KIND"
  echo "- TURNS target: $TLS_TARGET (SNI $SERVER_NAME), external_ip $EXTERNAL_IP"
} > "$SUMMARY"

# Load duration for a phase of `$1` seconds.
#
# soak.sh shortens its load window on short runs (DURATION/3, floored at 60; 1800 for
# an hour or more), and a TURNA_LOAD_CMD bypasses the trimming it applies to its own
# rotation. A command that outlives its window is killed before it writes its JSON,
# which leaves an empty file and no error — the exact silent failure this script exists
# to avoid. So the duration is derived, not hardcoded.
load_duration() {
    python3 - "$1" <<'PY'
import sys
run = int(sys.argv[1])
phase = 1800 if run >= 3600 else max(60, run // 3)
warm = 30 if phase >= 120 else 5
# 15 s reserved for the tool to write its results.
#
# This bounds the command to its phase, but not to the *run*: soak.sh starts a cycle
# whenever one is due, and the last one can begin with less than a phase left. The
# tool then gets killed mid-flight and its JSON is never written — every 24 h phase
# ended with exactly one "empty file" failure for that reason. soak.sh trims its own
# rotation for this; a TURNA_LOAD_CMD bypasses that trimming, so the floor below keeps
# the loss to one truncated cycle rather than a missing result.
print(max(10, phase - warm - 15))
PY
}
load_warmup() {
    python3 - "$1" <<'PY'
import sys
run = int(sys.argv[1])
phase = 1800 if run >= 3600 else max(60, run // 3)
print(30 if phase >= 120 else 5)
PY
}

# `soak.sh` writes its own config only when the file is absent, so pre-writing it is the
# supported way to add sections it does not know about.
write_config() { # $1 = target path, $2 = transport, $3 = extra sections
  cat > "$1" <<EOF
production = false
[turn]
listen      = "0.0.0.0:$TURN_PORT"
external_ip = "$EXTERNAL_IP"
realm       = "overnight"
transport   = "$2"
[turn.auth]
shared_secret = "$SECRET"
[turn.peer_filter]
# The load tool binds its peer sockets on loopback, which the filter refuses by
# default — correctly, it is SSRF protection. dev/test only.
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = $RELAY_MIN
max_port = $RELAY_MAX
max_allocations = $MAX_ALLOC
[turn.relay.quota]
# One --uid for every client means all concurrency lands on one username; the default
# per-user cap would refuse most of it and the run would measure the refusal path.
max_per_user = 0
[health]
listen = "127.0.0.1:$HEALTH_PORT"
[signaling]
listen             = "127.0.0.1:$SIGNALING_PORT"
turn_shared_secret = "$SECRET"
$3
EOF
}

TLS_SECTION="$(printf '[tls]\nenabled = true\nlisten = "0.0.0.0:%s"\ncert_path = "%s"\nkey_path = "%s"\n' "$TLS_PORT" "$CERT_PATH" "$KEY_PATH")"

phase() { # $1 = label, $2 = seconds, $3 = transport, $4 = extra config, $5 = load cmd
  local label="$1" secs="$2" transport="$3" extra="$4" cmd="$5"

  # A phase given no time is one the operator turned off, not one that failed.
  # Running it anyway produced "only 1 samples — too few to say anything" and counted
  # as a failure, which buries the phases that did run.
  if [ "$secs" -lt 60 ]; then
    say "phase $label: skipped (budget ${secs}s)"
    printf '\n## %s\n\nSkipped — no time budget (%ss).\n' "$label" "$secs" >> "$SUMMARY"
    SKIPPED=$((SKIPPED + 1))
    return 0
  fi

  local dir="$OUT/soak-$label"
  mkdir -p "$dir"
  write_config "$dir/turn.toml" "$transport" "$extra"

  say "phase $label: ${secs}s (transport=$transport)"
  # HEALTH_ADDR matters as much as the config: soak.sh scrapes it directly and
  # defaults to 127.0.0.1:9091. Setting the port only in the node's config left the
  # sampler reading an unrelated process that happened to hold 9091 — every turna_*
  # check in the 24 h run came back "series absent" and told us nothing.
  DURATION_SECS="$secs" \
  OUT_DIR="$dir" \
  CONFIG="$dir/turn.toml" \
  SHARED_SECRET="$SECRET" \
  HEALTH_ADDR="127.0.0.1:$HEALTH_PORT" \
  TURN_PORT="$TURN_PORT" \
  RELAY_MIN="$RELAY_MIN" RELAY_MAX="$RELAY_MAX" MAX_ALLOCATIONS="$MAX_ALLOC" \
  NODE_BIN="target/release/turna-node" \
  TURNA_LOAD_CMD="$cmd" \
    bash scripts/soak/soak.sh > "$dir/stdout.log" 2>&1
  local rc=$?

  {
    printf '\n## %s\n\n' "$label"
    if [ -f "$dir/verdict.txt" ] && grep -q '^VERDICT' "$dir/verdict.txt"; then
      echo '```'
      sed -n '/^  \(PASS\|FAIL\|WARN\|SKIP\)/p;/^VERDICT/,$p' "$dir/verdict.txt"
      echo '```'
    elif [ -f "$dir/verdict.txt" ]; then
      echo "The analyser reached no verdict:"
      echo '```'
      head -5 "$dir/verdict.txt"
      echo '```'
    else
      echo "No verdict produced — see \`soak-$label/stdout.log\`."
    fi
    printf '\nExit code: %s. Load results:\n\n' "$rc"
    echo '```'
    for f in "$dir"/load-*.json; do
      [ -s "$f" ] && printf '%s: %s\n' "$(basename "$f")" "$(head -c 320 "$f" | tr -d '\n')"
    done
    echo '```'
  } >> "$SUMMARY"

  say "phase $label finished rc=$rc"
  return $rc
}

FAILED=0
SKIPPED=0

# ── TURNS, relayed media ────────────────────────────────────────────────────
# The phase that matters most: TURNS is the transport browsers use, and it has never
# had sustained relayed traffic through it. `--duration` is trimmed so the command
# finishes inside soak.sh's 1800s load window and writes its JSON — a phase that
# outlives its window leaves an empty file and no error.
phase turns-media "$TURNS_MEDIA_SECS" tokio "$TLS_SECTION" \
  "target/release/turna-load-test --server $TLS_TARGET --secret $SECRET \
--duration $(load_duration $TURNS_MEDIA_SECS) --warmup $(load_warmup $TURNS_MEDIA_SECS) --json --label turns-media \
tls -c $TLS_CONC --channel-data --pps $TLS_PPS --server-name $SERVER_NAME" || FAILED=$((FAILED + 1))

# ── TURNS, allocation churn ─────────────────────────────────────────────────
# Connect, handshake, allocate, drop, repeat. Different stress from the above: it pays
# the TLS handshake every iteration, which is what a reconnecting client does and what
# the per-IP handshake rate limiter exists for.
phase turns-churn "$TURNS_CHURN_SECS" tokio "$TLS_SECTION" \
  "target/release/turna-load-test --server $TLS_TARGET --secret $SECRET \
--duration $(load_duration $TURNS_CHURN_SECS) --warmup $(load_warmup $TURNS_CHURN_SECS) --json --label turns-churn tls -c $TLS_CONC --server-name $SERVER_NAME" \
  || FAILED=$((FAILED + 1))

# ── io_uring, relayed media ─────────────────────────────────────────────────
# The 3h io_uring run on record never relayed anything: its channel-data phases failed
# to start for harness reasons, and the RX slot leak it later turned out to have would
# have capped it anyway. This is the run that was supposed to happen.
phase uring-media "$URING_MEDIA_SECS" io_uring "" \
  "target/release/turna-load-test --server 127.0.0.1:$TURN_PORT --secret $SECRET \
--duration $(load_duration $URING_MEDIA_SECS) --warmup $(load_warmup $URING_MEDIA_SECS) --json --label uring-media \
channel-data --channels $UDP_CHANNELS --pps $UDP_PPS --payload 160" \
  || FAILED=$((FAILED + 1))

{
  RAN=$((3 - SKIPPED))
  printf '\n## Verdict\n\n'
  if [ "$SKIPPED" -gt 0 ]; then
    echo "$SKIPPED phase(s) were switched off for this run and are not counted below."
    echo
  fi
  if [ "$RAN" -eq 0 ]; then
    echo "**No phase ran.** Every budget was zero — nothing was measured."
  elif [ "$FAILED" -eq 0 ]; then
    echo "All $RAN phase(s) that ran passed."
  else
    echo "**$FAILED of $RAN phase(s) that ran failed.** Read each phase above; the"
    echo "analyser names what each failing signal means."
  fi
  cat <<'EOF'

### What this does and does not support

Endurance for TURNS and for the io_uring datapath under relayed load. Combined with
`docs/interop/transports-2026-08-19.md`, TURNS now has correctness, browser interop and
endurance.

Still outstanding for `supported`:

- **Chain validation.** Whatever certificate the server presented, this client accepts
  any — it is a verification client. A run here says nothing about chain validation
  either way; that is proven by a verifying client (`openssl s_client
  -verify_return_error`, or a browser).
- **An independent implementation.** The load client shares a library and one reading of
  the spec with the server, so a shared misreading stays invisible. For TURNS the
  three-browser interop covers this; for DTLS, QUIC and WebTransport it does not.
- **DTLS, QUIC and WebTransport endurance.** No load driver exists for them yet.
- **io_uring on your deployment kernel**, if it is not the one this ran on: io_uring
  behaviour is version-sensitive and one kernel is not evidence for another.
EOF
} >> "$SUMMARY"

say "done — $FAILED of $((3 - SKIPPED)) phase(s) failed, $SKIPPED skipped. Summary: $SUMMARY"
echo
cat "$SUMMARY"
[ "$FAILED" -eq 0 ]
