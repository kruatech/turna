#!/usr/bin/env bash
#
# 6-hour endurance soak for a turna node on a real Linux host.
#
# WHAT THIS PROVES, AND WHAT IT DOES NOT
#
# A soak answers exactly one question: does the node degrade over time under
# steady load. It does NOT prove interop, and it does not prove the wire-behaviour
# fixes in this release are correct — those need the functional cases in
# docs/verification/interop-plan.md (Tier 0), which take half an hour and should be
# run BEFORE spending six hours here. A green soak on a broken redirect path is
# still a broken redirect path.
#
# WHAT IT WATCHES
#
#   RSS growth              a leak shows as a rising floor, not a rising peak
#   open fds                relay sockets or control connections not released
#   active allocations      must return to ~0 between load phases; a floor that
#                           climbs is the allocation-release bug class (the SCTP
#                           leak found in this release was exactly this shape)
#   relay port exhaustion   508s appearing late = ports not recycled
#   error counters          any of them moving during steady state is a finding
#   readiness               a listener dying while the process lives
#
# The analysis is in scripts/soak/analyze.py — thresholds are explicit there, and
# it prints a verdict per signal rather than one green light, because "no crash"
# and "no leak" are different claims.
#
# USAGE
#
#   # 1. build once, with the features you intend to soak
#   cargo build --release -p turna-node --features tls
#
#   # 2. tell it how to generate load (see LOAD below), then:
#   sudo scripts/soak/soak.sh
#
# Everything is overridable by environment variable; defaults target a 16-core /
# 64 GB host.

set -uo pipefail

# ── configuration ────────────────────────────────────────────────────────────
DURATION_SECS="${DURATION_SECS:-21600}"        # 6h
# Sample interval scales with the run, for the same reason the phase lengths do: at
# 30 s a 150 s rehearsal yields 5 samples, and the analyser correctly refuses to
# conclude anything from that — so the rehearsal produced an empty verdict and an
# exit code with no explanation.
if [ "$DURATION_SECS" -lt 900 ]; then
  _DEF_SAMPLE=5
elif [ "$DURATION_SECS" -lt 3600 ]; then
  _DEF_SAMPLE=10
else
  _DEF_SAMPLE=30
fi
SAMPLE_SECS="${SAMPLE_SECS:-$_DEF_SAMPLE}"     # metric sample interval
OUT_DIR="${OUT_DIR:-soak-$(date +%Y%m%d-%H%M%S)}"
NODE_BIN="${NODE_BIN:-target/release/turna-node}"
CONFIG="${CONFIG:-$OUT_DIR/turn.toml}"
HEALTH_ADDR="${HEALTH_ADDR:-127.0.0.1:9091}"
# Datapath under test. The whole point of a second soak run is to change this,
# so it is a variable rather than a hardcoded line in the generated config.
TRANSPORT="${TRANSPORT:-tokio}"

# Ingress rate limits, raised for the duration of the soak.
#
# Not a workaround for a server defect — the opposite. The limiter is per source IP
# and per prefix, and a loopback soak sends every client from 127.0.0.1, so the
# server is doing exactly what it should: refusing one address that behaves like a
# flood. Left at defaults this produced 3.1M `turna_rate_limited` on tokio and 56M
# on io_uring, about 60 successful allocations between them, and a soak that
# measured nothing while reporting no leaks.
#
# These are environment variables, not config keys — see `PacketProcessor::new`.
export TURNA_RATE_LIMIT_RPS="${TURNA_RATE_LIMIT_RPS:-200000}"
export TURNA_RATE_LIMIT_BURST="${TURNA_RATE_LIMIT_BURST:-200000}"
export TURNA_PREFIX_RPS="${TURNA_PREFIX_RPS:-200000}"
export TURNA_PREFIX_BURST="${TURNA_PREFIX_BURST:-200000}"
export TURNA_ALLOCATE_RPS="${TURNA_ALLOCATE_RPS:-100000}"
export TURNA_ALLOCATE_BURST="${TURNA_ALLOCATE_BURST:-100000}"
export TURNA_CREATE_PERM_RPS="${TURNA_CREATE_PERM_RPS:-100000}"
export TURNA_CREATE_PERM_BURST="${TURNA_CREATE_PERM_BURST:-100000}"
export TURNA_CHANNEL_BIND_RPS="${TURNA_CHANNEL_BIND_RPS:-100000}"
export TURNA_CHANNEL_BIND_BURST="${TURNA_CHANNEL_BIND_BURST:-100000}"
TURN_PORT="${TURN_PORT:-3478}"
# Exercise the DTLS demux path as well as UDP.
#
# Off by default: it needs a certificate and adds a phase, and a soak that has to
# generate keys to start is a soak that fails for a reason unrelated to the relay.
#
# demux = true specifically, because the stock listener already has a recorded
# 24-hour run and the demux path is the one that does not.
SOAK_DTLS="${SOAK_DTLS:-0}"
DTLS_PORT="${DTLS_PORT:-5349}"
RELAY_MIN="${RELAY_MIN:-20000}"
RELAY_MAX="${RELAY_MAX:-20847}"                # 848 ports; deliberately finite so
                                               # port recycling is actually tested
MAX_ALLOCATIONS="${MAX_ALLOCATIONS:-800}"      # must be <= usable relay ports, or
                                               # config validation refuses to start
                                               # ("a cap above the port count is
                                               # unreachable"). 800 sits just under
                                               # the 848-port range, so the pool is
                                               # still the practical limit.
SHARED_SECRET="${SHARED_SECRET:-soak-secret-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

# ── load ─────────────────────────────────────────────────────────────────────
# `turna-load-test` (CLI name `turna-bench`) has three modes, and they stress
# different leak paths, so the soak rotates them rather than picking one:
#
#   allocate     allocation lifecycle churn -> relay port recycling, release on
#                close, per-user quota accounting
#   channel-data sustained relayed media    -> egress queues, byte counters, MTU
#                path, the datapath itself
#   binding      bare STUN, no auth         -> the cheapest path; a leak visible
#                here is in the parser or the socket layer, not in allocations
#
# The tool authenticates with the REST shared secret, which is the same value as
# `[turn.auth] shared_secret` in the generated config — that is why it works
# without a static user.
LOAD_BIN="${LOAD_BIN:-target/release/turna-load-test}"
ALLOC_CONCURRENCY="${ALLOC_CONCURRENCY:-400}"  # kept below the relay port count so
                                               # exhaustion does not mask the
                                               # recycling signal (see RELAY_MAX)
BINDING_CONCURRENCY="${BINDING_CONCURRENCY:-200}"
CHANNELS="${CHANNELS:-400}"
# Lower than the UDP concurrency: a DTLS session costs a handshake and per-session
# crypto state, and the point here is duration rather than peak.
DTLS_CONCURRENCY="${DTLS_CONCURRENCY:-50}"
PPS="${PPS:-50}"                               # per channel; 400x50 = 20k pps at
                                               # 160 B ≈ 26 Mbit/s — steady, not a
                                               # stress test. A soak measures
                                               # duration, not peak.
PAYLOAD="${PAYLOAD:-160}"                      # a 20 ms G.711 frame
# Phase lengths scale with the run so a rehearsal is actually short. Left fixed, a
# `DURATION_SECS=300` rehearsal still told the load tool to run for 1770 s — the
# phases outlived the run they were rehearsing.
if [ "$DURATION_SECS" -lt 3600 ]; then
  _DEF_LOAD=$(( DURATION_SECS / 3 ))
  _DEF_IDLE=$(( DURATION_SECS / 6 ))
  [ "$_DEF_LOAD" -lt 60 ] && _DEF_LOAD=60
  [ "$_DEF_IDLE" -lt 30 ] && _DEF_IDLE=30
else
  _DEF_LOAD=1800
  _DEF_IDLE=300
fi
LOAD_PHASE_SECS="${LOAD_PHASE_SECS:-$_DEF_LOAD}"
IDLE_PHASE_SECS="${IDLE_PHASE_SECS:-$_DEF_IDLE}"

# Override to replace the rotation entirely with one command.
LOAD_CMD="${TURNA_LOAD_CMD:-}"

# Modes to rotate through. Override to exercise one path directly — e.g.
# LOAD_MODES="channel-data" to test relaying without waiting for it to come up in a
# four-phase rotation. Space-separated; the rotation is the list, cycled.
LOAD_MODES="${LOAD_MODES:-allocate channel-data allocate binding}"

# Mode for cycle N (1-based). The default list puts two allocate phases per
# channel-data phase, because allocation churn is where this codebase has actually
# had leaks.
load_cmd_for_cycle() {
  local n="$1"
  local remaining="$2"
  local label mode base
  if [ -n "$LOAD_CMD" ]; then printf '%s' "$LOAD_CMD"; return; fi

  # shellcheck disable=SC2206
  set -- $LOAD_MODES
  local count=$#
  local idx=$(( (n - 1) % count ))
  eval "base=\${$((idx + 1))}"

  case "$base" in
    # clap derives the subcommand name from the enum variant: ChannelData ->
    # channel-data. Spelled without the hyphen this silently produced empty
    # load-*.json for a whole 3 h run, so the relay data path was never exercised
    # while the soak still reported a clean pass.
    channel-data) mode="channel-data --channels $CHANNELS --pps $PPS --payload $PAYLOAD" ;;
    binding)      mode="binding --concurrency $BINDING_CONCURRENCY" ;;
    allocate)     mode="allocate --concurrency $ALLOC_CONCURRENCY" ;;
    dtls)         mode="dtls -c $DTLS_CONCURRENCY --pps $PPS --payload $PAYLOAD" ;;
    *)            mode="$base" ;;
  esac
  label="cycle${n}-$(printf '%s' "$mode" | awk '{print $1}')"
  # --duration is the measured window and the tool exits after it. --warmup keeps
  # ramp-up out of the reported numbers without shortening the load phase.
  # Warmup is subtracted from the phase, and both are floored so a short rehearsal
  # cannot ask for a negative duration.
  local warm=30
  [ "$LOAD_PHASE_SECS" -lt 120 ] && warm=5
  local dur=$(( LOAD_PHASE_SECS - warm ))
  [ "$dur" -lt 10 ] && dur=10

  # Never ask for more time than the run has left. `turna-load-test` writes its JSON
  # only when it finishes, so a phase that outlives the run leaves an EMPTY
  # load-N.json and no error — which is how two channel-data phases went missing
  # from a 3 h run while everything else reported a clean pass. Reserve 15 s for the
  # tool to write its output.
  local budget=$(( remaining - warm - 15 ))
  if [ "$budget" -lt "$dur" ]; then
    dur="$budget"
  fi
  # The dtls mode uses --server as the DTLS address; every other mode uses the
  # TURN port. Getting this wrong produced `unexpected argument '--dtls-addr'` in
  # a sibling script and cost a full run, so it branches here rather than being
  # assumed.
  local port="$TURN_PORT"
  case "$base" in dtls) port="$DTLS_PORT" ;; esac
  printf '%s --server 127.0.0.1:%s --secret %s --uid soak --duration %s --warmup %s --json --label %s %s' \
    "$LOAD_BIN" "$port" "$SHARED_SECRET" "$dur" "$warm" "$label" "$mode"
}

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT_DIR/soak.log"; }
die() { printf '[%s] FATAL: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; exit 1; }

# ── preflight ────────────────────────────────────────────────────────────────
[ -x "$NODE_BIN" ] || die "$NODE_BIN not found or not executable. Build first:
  cargo build --release -p turna-node --features tls"

command -v curl >/dev/null || die "curl is required"
command -v python3 >/dev/null || die "python3 is required (for the analysis step)"

if [ -z "$LOAD_CMD" ] && [ ! -x "$LOAD_BIN" ]; then
  die "$LOAD_BIN not found. Build it:
  cargo build --release -p turna-load-test
Or set TURNA_LOAD_CMD to replace the built-in rotation with your own command."
fi

# Verify the subcommands exist before spending hours on them. A misspelled mode
# fails instantly, writes an empty load-*.json, and the soak carries on reporting a
# clean pass over a phase that never ran — which is exactly what happened for three
# hours with `channeldata` instead of `channel-data`.
if [ -z "$LOAD_CMD" ]; then
  _HELP="$("$LOAD_BIN" --help 2>&1 || true)"
  for _m in allocate binding channel-data; do
    printf '%s' "$_HELP" | grep -q -- "$_m" \
      || die "$LOAD_BIN has no '$_m' subcommand. Its CLI changed; fix the rotation in
this script rather than letting the phase silently produce nothing."
  done
fi

# Validation refuses `max_allocations` above the usable port count, and a soak that
# dies on config is six hours of nothing. Check the arithmetic here, where the error
# can name both numbers.
# The relay range must not overlap the kernel's ephemeral range.
#
# On a loopback soak the load tool binds its "peer" socket with port 0, so the kernel
# hands it an ephemeral port. If that lands inside the relay range, the relay forwards
# the packet to an address it is itself serving — the traffic loops between
# allocations instead of reaching the test. Symptom: the server reports tens of
# millions of packets forwarded while the client reports `recv: 0`, and it reads like
# a broken datapath. Linux defaults to 32768–60999, which fully covers a naive
# 49152–49999 choice.
if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
  read -r _EPH_LO _EPH_HI < /proc/sys/net/ipv4/ip_local_port_range
  if [ "$RELAY_MIN" -le "$_EPH_HI" ] && [ "$RELAY_MAX" -ge "$_EPH_LO" ]; then
    die "relay range $RELAY_MIN-$RELAY_MAX overlaps the ephemeral range $_EPH_LO-$_EPH_HI.
On loopback the load tool's peer socket would get a port inside the relay range and
the relay would forward to itself: the server counts millions of forwards, the client
receives nothing, and it looks like the datapath is broken.
Pick a range below the ephemeral one, e.g. RELAY_MIN=20000 RELAY_MAX=20847."
  fi
fi

USABLE_PORTS=$((RELAY_MAX - RELAY_MIN + 1))
if [ "$MAX_ALLOCATIONS" -gt "$USABLE_PORTS" ]; then
  die "MAX_ALLOCATIONS ($MAX_ALLOCATIONS) exceeds the usable relay ports ($USABLE_PORTS
in range $RELAY_MIN-$RELAY_MAX). Config validation rejects that as unreachable.
Either lower MAX_ALLOCATIONS or widen RELAY_MIN/RELAY_MAX."
fi
if [ "$ALLOC_CONCURRENCY" -ge "$USABLE_PORTS" ]; then
  log "WARNING: ALLOC_CONCURRENCY ($ALLOC_CONCURRENCY) is at or above the port count
($USABLE_PORTS). The run will sit in port exhaustion, which masks the recycling
signal this soak is looking for."
fi

mkdir -p "$OUT_DIR"

# Refuse now rather than at hour 12.
#
# The first 24-hour attempt filled the disk after 13 minutes and produced nothing
# usable. A day of wall-clock time lost to a check that costs a second is the worst
# trade in this repository, so this is a hard refusal and not a warning.
#
# Budget: 300 MB per hour at INFO, which is roughly what was observed once the log
# level was fixed, plus a 2 GB floor for the artifacts. Deliberately generous — an
# overestimate costs a refusal that a flag overrides, and an underestimate costs
# the day this exists to protect.
MIN_FREE_MB="${MIN_FREE_MB:-$(( DURATION_SECS / 3600 * 300 + 2048 ))}"
FREE_MB=$(df -Pm . | awk 'NR==2 {print $4}')
if [ "${FREE_MB:-0}" -lt "$MIN_FREE_MB" ]; then
  cat >&2 <<EOF
FATAL: ${FREE_MB} MB free, and this run wants at least ${MIN_FREE_MB} MB.

A soak that fills the disk halfway through costs a day and produces nothing. The
first 24-hour attempt here wrote 4.3 GB of node.stdout in 13 minutes, because the
node logs at DEBUG by default; that is fixed, but the budget still has to be
checked because the log grows with duration and load.

  * free space, or
  * lower DURATION_SECS, or
  * set MIN_FREE_MB explicitly if you know better than this estimate
EOF
  exit 1
fi
say "disk: ${FREE_MB} MB free, budget ${MIN_FREE_MB} MB for ${DURATION_SECS}s"

# And a cap, so even a correct estimate cannot be defeated by an unexpected log
# rate. Truncation loses the middle of the log, which is better than losing the
# run — rotation would be better still and needs more than a shell script.
LOG_CAP_MB="${LOG_CAP_MB:-4096}"
(
  while sleep 300; do
    [ -f "$OUT_DIR/node.stdout" ] || continue
    sz=$(( $(stat -c%s "$OUT_DIR/node.stdout" 2>/dev/null || echo 0) / 1048576 ))
    if [ "$sz" -gt "$LOG_CAP_MB" ]; then
      printf '\n--- truncated at %s MB, %s ---\n' "$sz" "$(date -u +%FT%TZ)" \
        >> "$OUT_DIR/node.stdout"
      : > "$OUT_DIR/node.stdout"
      printf '[%s] node.stdout exceeded %s MB and was truncated\n' \
        "$(date -u +%H:%M:%S)" "$LOG_CAP_MB" >> "$OUT_DIR/soak.log"
    fi
  done
) &
LOG_WATCHER=$! || die "cannot create $OUT_DIR"

# ── host facts worth recording: a soak result without them is not comparable ──
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "host=$(hostname)"
  echo "kernel=$(uname -sr)"
  echo "cpus=$(nproc)"
  echo "mem_total_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  echo "git_rev=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_dirty=$(git status --porcelain 2>/dev/null | wc -l)"
  echo "node_bin=$NODE_BIN"
  echo "transport=$TRANSPORT"
  echo "duration_secs=$DURATION_SECS"
  echo "sample_secs=$SAMPLE_SECS"
  echo "relay_ports=$RELAY_MIN-$RELAY_MAX (max_allocations=$MAX_ALLOCATIONS)"
  echo "load_mode=$([ -n "$LOAD_CMD" ] && echo custom || echo rotation)"
  echo "load_cmd_override=$LOAD_CMD"
  echo "alloc_concurrency=$ALLOC_CONCURRENCY channels=$CHANNELS pps=$PPS payload=$PAYLOAD"
  echo "load_phase_secs=$LOAD_PHASE_SECS idle_phase_secs=$IDLE_PHASE_SECS"
  echo "load_modes=$LOAD_MODES"
  echo "rate_limits: per_ip=${TURNA_RATE_LIMIT_RPS:-default} prefix=${TURNA_PREFIX_RPS:-default} allocate=${TURNA_ALLOCATE_RPS:-default}"
  echo "ulimit_nofile=$(ulimit -n)"
  echo "somaxconn=$(cat /proc/sys/net/core/somaxconn 2>/dev/null || echo n/a)"
  echo "rmem_max=$(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo n/a)"
} > "$OUT_DIR/environment.txt"

log "environment recorded in $OUT_DIR/environment.txt"

# `git_dirty` is not cosmetic: a soak run against uncommitted changes cannot be
# reproduced, and this file is what a future reader uses to decide whether the
# result still applies.
if [ "$(git status --porcelain 2>/dev/null | wc -l)" != "0" ]; then
  log "WARNING: working tree is dirty — this run will not be reproducible from git_rev alone"
fi

# ── config ───────────────────────────────────────────────────────────────────
if [ ! -f "$CONFIG" ]; then
  # EC in PKCS#8. webrtc-dtls rejects RSA outright, and `openssl ecparam -genkey`
  # alone emits an EC PARAMETERS block it also rejects. Learned the hard way.
  if [ "$SOAK_DTLS" = "1" ] && [ ! -f "$OUT_DIR/dtls.crt" ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out "$OUT_DIR/dtls.raw" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$OUT_DIR/dtls.raw" \
      -out "$OUT_DIR/dtls.key" 2>/dev/null
    openssl req -x509 -new -key "$OUT_DIR/dtls.key" -out "$OUT_DIR/dtls.crt" \
      -days 2 -subj "/CN=soak" 2>/dev/null
    rm -f "$OUT_DIR/dtls.raw"
    [ -s "$OUT_DIR/dtls.crt" ] || die "could not generate a DTLS certificate"
    log "generated a DTLS certificate for the demux path"
  fi

  cat > "$CONFIG" <<EOF
# Generated by scripts/soak/soak.sh — do not hand-edit for a running soak.
#
# production = false on purpose: production mode refuses a placeholder secret and
# demands external_ip, neither of which is meaningful on a loopback soak. The
# things production mode gates (the three refused features) are not under test
# here anyway.
production = false

[turn]
listen      = "0.0.0.0:$TURN_PORT"
external_ip = "127.0.0.1"
realm       = "soak"
transport   = "$TRANSPORT"

[turn.auth]
shared_secret = "$SHARED_SECRET"

[turn.relay]
min_port = $RELAY_MIN
max_port = $RELAY_MAX
# Set explicitly, and it MUST NOT exceed the usable port count: validation refuses
# a cap above the range ("unreachable"). The default 10000 against this deliberately
# narrow range is exactly the combination that fails, so leaving it out is not an
# option here.
max_allocations = $MAX_ALLOCATIONS

$(if [ "$SOAK_DTLS" = "1" ]; then cat <<DTLS
[turn.dtls]
enabled   = true
listen    = "0.0.0.0:$DTLS_PORT"
cert_path = "$PWD/$OUT_DIR/dtls.crt"
key_path  = "$PWD/$OUT_DIR/dtls.key"
# The point of running this at all: the stock listener has a recorded 24-hour run
# and the demux path does not. demux also enables the two things the stock path
# cannot do — per-IP handshake rate limiting and live certificate reload.
demux     = true
cert_reload_secs = 300
DTLS
fi)

[turn.peer_filter]
# The `channel-data` mode binds its peer socket on 127.0.0.1, and loopback is a
# forbidden peer by default — correct behaviour (it is SSRF protection), but it makes
# a loopback relay test impossible. Without this, every channel fails
# CreatePermission with 403 during warmup, `--warmup` then RESETS the counters, and
# the phase reports sent=0 recv=0 errs=0 for its whole duration: a failed phase that
# looks like an idle one. That cost a 20-minute run to diagnose.
#
# dev/test only — this must never appear in a production config.
profile = "lan"
allow_loopback_peers = true

[turn.relay.quota]
# The load tool sends ONE `--uid` for every client, so all concurrency lands on a
# single username. The default per-user cap is 100, which refuses everything above
# that with 486 Allocation Quota Reached — and the client retries in a tight loop, so
# a soak configured this way records millions of errors, a handful of successes, and a
# clean "PASS" for absence of leaks under absence of load. That is worse than a
# failure, because it looks like a result. 0 = no per-user cap; the cap under test
# here is the relay port pool.
max_per_user = 0

[health]
listen = "$HEALTH_ADDR"

[signaling]
listen             = "127.0.0.1:9001"
turn_shared_secret = "$SHARED_SECRET"
EOF
  log "generated $CONFIG"
fi

# ── start ────────────────────────────────────────────────────────────────────
# Validate the config before committing six hours to it. `--dump-config` loads and
# validates, then exits — cheaper than discovering a typo at hour four.
if ! "$NODE_BIN" --dump-config "$CONFIG" > "$OUT_DIR/config-resolved.txt" 2> "$OUT_DIR/config-error.txt"; then
  log "config rejected:"
  cat "$OUT_DIR/config-error.txt" >&2
  die "fix $CONFIG and re-run"
fi
log "config validated; resolved form in $OUT_DIR/config-resolved.txt"

# The config path is POSITIONAL — `turna-node [OPTIONS] [CONFIG_PATH]`. There is no
# --config flag.
# Raise the ingress rate limits for the duration of the soak.
#
# Not a workaround for a server defect — the opposite. The limiter is per source IP
# and per prefix, and a loopback soak sends every one of its clients from
# 127.0.0.1, so the server is doing exactly what it should: refusing a single
# address that behaves like a flood. Left at defaults this produced 3.1M
# `turna_rate_limited` on tokio and 56M on io_uring, ~60 successful allocations
# between them, and a soak that measured nothing.
#
# These are environment variables rather than config keys (see
# `PacketProcessor::new` — TURNA_RATE_LIMIT_*, TURNA_ALLOCATE_*, etc.), which is
# why they are set here and recorded in environment.txt rather than appearing in
# the generated TOML.
# RUST_LOG=info, not the built-in default.
#
# `TelemetryConfig::default()` is "info,turna=debug" — every turna module at
# DEBUG, which is right for development and wrong for a run measured in days. At
# 400 allocations/second it produced 4.3 GB in 13 minutes: a 24-hour run would
# need about 470 GB, and the first attempt died at 91% disk.
#
# Overridable, because a soak chasing a specific bug may want DEBUG and a shorter
# duration.
RUST_LOG="${RUST_LOG:-info}" "$NODE_BIN" "$CONFIG" \
  > "$OUT_DIR/node.stdout" 2> "$OUT_DIR/node.stderr" &
NODE_PID=$!
log "node started, pid $NODE_PID"

cleanup() {
  local rc=$?
  kill -KILL "${LOG_WATCHER:-0}" 2>/dev/null
  if kill -0 "$NODE_PID" 2>/dev/null; then
    log "sending SIGTERM (drain path is part of what is under test)"
    kill -TERM "$NODE_PID" 2>/dev/null
    for _ in $(seq 1 30); do
      kill -0 "$NODE_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$NODE_PID" 2>/dev/null; then
      log "FINDING: node still alive 30s after SIGTERM — drain did not complete"
      kill -KILL "$NODE_PID" 2>/dev/null
    else
      log "node exited cleanly on SIGTERM"
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ── readiness gate: never start sampling against a node that is not up ───────
READY=0
for i in $(seq 1 60); do
  if curl -fsS --max-time 2 "http://$HEALTH_ADDR/ready" >/dev/null 2>&1; then
    READY=1
    log "node ready after ${i}s"
    break
  fi
  kill -0 "$NODE_PID" 2>/dev/null || die "node exited during startup — see $OUT_DIR/node.stderr"
  sleep 1
done
[ "$READY" = 1 ] || die "node did not become ready in 60s — see $OUT_DIR/node.stderr"

# ── sampler ──────────────────────────────────────────────────────────────────
# One CSV row per sample. Series are pulled by name; a missing series records as
# empty rather than 0, so the analysis can tell "absent" from "zero" — that
# distinction matters for the DTLS handshake-failure counter, which is
# structurally 0 on the default path.
SERIES="turna_active_allocations turna_total_allocations turna_uptime_seconds \
turna_packets_received turna_packets_sent turna_bytes_received turna_bytes_sent \
turna_send_queue_dropped_total turna_malformed_packets_total \
turna_parser_rejections_total turna_peer_rejected_total turna_auth_failures \
turna_quota_exceeded_total turna_rate_limited turna_processor_panics_total \
turna_transport_readiness turna_backend_readiness turna_draining \
turna_tls_active_connections turna_tls_handshake_failures_total \
turna_tls_rejected_over_cap_total turna_tls_rejected_per_ip_total \
turna_tls_rejected_rate_limit_total turna_tls_accept_errors_total \
turna_tls_framing_errors_total turna_tls_cert_reload_failures_total \
turna_tls_readiness"

{
  printf 'ts,elapsed,phase,rss_kb,vmsize_kb,threads,fds'
  for s in $SERIES; do printf ',%s' "$s"; done
  printf '\n'
} > "$OUT_DIR/samples.csv"

sample() {
  local phase="$1" start="$2"
  local now elapsed rss vm thr fds metrics line
  now=$(date +%s)
  elapsed=$((now - start))
  rss=$(awk '/^VmRSS:/{print $2}' "/proc/$NODE_PID/status" 2>/dev/null)
  vm=$(awk '/^VmSize:/{print $2}' "/proc/$NODE_PID/status" 2>/dev/null)
  thr=$(awk '/^Threads:/{print $2}' "/proc/$NODE_PID/status" 2>/dev/null)
  fds=$(ls "/proc/$NODE_PID/fd" 2>/dev/null | wc -l)
  metrics=$(curl -fsS --max-time 5 "http://$HEALTH_ADDR/metrics" 2>/dev/null)

  line="$now,$elapsed,$phase,${rss:-},${vm:-},${thr:-},${fds:-}"
  for s in $SERIES; do
    # Match the series at line start with a space after the name, so
    # turna_tls_readiness does not pick up a longer name sharing the prefix.
    v=$(printf '%s\n' "$metrics" | awk -v k="$s" '$1==k {print $2; exit}')
    line="$line,${v:-}"
  done
  printf '%s\n' "$line" >> "$OUT_DIR/samples.csv"
}

# ── main loop: alternating load and idle phases ──────────────────────────────
# The idle phases are the point. Under continuous load a leak and a working cache
# look identical; it is the failure to return to baseline during idle that
# distinguishes them.
START=$(date +%s)
PHASE_END=$START
PHASE="idle"
LOAD_PID=""
CYCLE=0

log "soak running for ${DURATION_SECS}s, sampling every ${SAMPLE_SECS}s"
log "phases: ${LOAD_PHASE_SECS}s load / ${IDLE_PHASE_SECS}s idle"

while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  [ "$ELAPSED" -ge "$DURATION_SECS" ] && break

  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    log "FINDING: node process died after ${ELAPSED}s — see $OUT_DIR/node.stderr"
    echo "node_died_at_elapsed=$ELAPSED" >> "$OUT_DIR/findings.txt"
    break
  fi

  if [ "$NOW" -ge "$PHASE_END" ]; then
    if [ "$PHASE" = "idle" ]; then
      CYCLE=$((CYCLE + 1))
      PHASE="load"
      PHASE_END=$((NOW + LOAD_PHASE_SECS))
      # Remaining wall-clock for this run, so the phase can be trimmed to fit.
      REMAINING=$(( START + DURATION_SECS - NOW ))
      if [ "$REMAINING" -lt 60 ]; then
        log "cycle $CYCLE: only ${REMAINING}s left — not starting a load phase that cannot finish and write its results"
        PHASE="idle"
        PHASE_END=$(( NOW + IDLE_PHASE_SECS ))
        sample "$PHASE" "$START"
        sleep "$SAMPLE_SECS"
        continue
      fi
      CMD=$(load_cmd_for_cycle "$CYCLE" "$REMAINING")
      # The secret is in the command line; keep it out of the log.
      log "cycle $CYCLE: load phase starting — $(printf '%s' "$CMD" | sed "s/--secret [^ ]*/--secret ***/")"
      # shellcheck disable=SC2086
      ( eval "$CMD" ) > "$OUT_DIR/load-$CYCLE.json" 2> "$OUT_DIR/load-$CYCLE.log" &
      LOAD_PID=$!
    else
      PHASE="idle"
      PHASE_END=$((NOW + IDLE_PHASE_SECS))
      if [ -n "$LOAD_PID" ] && kill -0 "$LOAD_PID" 2>/dev/null; then
        log "cycle $CYCLE: load command still running past its phase; leaving it"
      fi
      log "cycle $CYCLE: idle phase starting (this is where a leak shows)"
    fi
  fi

  sample "$PHASE" "$START"
  sleep "$SAMPLE_SECS"
done

log "sampling complete: $(( $(wc -l < "$OUT_DIR/samples.csv") - 1 )) samples"

# A final idle sample after everything settles: the last data point is the one
# compared against the first.
log "settling for 60s before the final sample"
sleep 60
sample "settle" "$START"

# ── analysis ─────────────────────────────────────────────────────────────────
python3 "$(dirname "$0")/analyze.py" "$OUT_DIR" | tee "$OUT_DIR/verdict.txt"
ANALYSIS_RC=${PIPESTATUS[0]}

# Per-phase JSON from the load tool: throughput and latency per cycle, which is
# what shows a *performance* drift that the leak checks would not catch.
if ls "$OUT_DIR"/load-*.json >/dev/null 2>&1; then
  log "per-phase load results:"
  for f in "$OUT_DIR"/load-*.json; do
    printf '  %s: %s\n' "$(basename "$f")" "$(head -c 400 "$f" | tr -d '\n')" | tee -a "$OUT_DIR/soak.log"
  done
fi

log "artifacts in $OUT_DIR/ — samples.csv, verdict.txt, environment.txt, load-*.json, node.stderr"
log "record the run in docs/soak/ following the format of the existing files there"
exit "$ANALYSIS_RC"
