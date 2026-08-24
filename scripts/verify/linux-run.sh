#!/usr/bin/env bash
#
# Unattended Linux verification run, ~7 hours.
#
# WHAT THIS CLOSES, AND WHAT IT CANNOT
#
# It runs everything the existing tooling can actually drive:
#
#   phase 0  ~15 min  build matrix, config gates, conformance probes, quic-check
#   phase 1  3 h      soak on the default tokio datapath
#   phase 2  3 h      soak on the io_uring datapath      <- lifts io_uring to beta
#   phase 3  ~10 min  AF_XDP veth lab + short load       <- first step for af-xdp
#
# It does NOT cover TURNS, DTLS, RFC 6062 TCP relay, or WebTransport under load, for
# one reason: `turna-load-test` speaks UDP only (`UdpSocket::bind` in
# `turn_client.rs`). There is no TLS/DTLS/QUIC load generator, so a soak on those
# paths cannot be created — that is a missing client, not a missing machine, and no
# amount of runtime here substitutes for it. The browser harness and `quic-check`
# cover their control planes functionally; endurance on them stays open.
#
# Everything lands in one directory. Nothing here needs a human between phases.
#
# USAGE
#
#   sudo scripts/verify/linux-run.sh                  # full ~7h
#   PHASES="0 1" sudo scripts/verify/linux-run.sh     # subset
#   SOAK_SECS=1800 sudo scripts/verify/linux-run.sh   # shorter soaks, for a rehearsal
#
# Run a rehearsal first. A typo discovered at hour six is six hours gone.

set -uo pipefail

RUN_DIR="${RUN_DIR:-verify-$(date +%Y%m%d-%H%M%S)}"
SOAK_SECS="${SOAK_SECS:-10800}"          # 3h each, twice
PHASES="${PHASES:-0 1 2 3}"
IFACE="${IFACE:-}"                        # af-xdp: leave empty to use the veth lab
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

mkdir -p "$RUN_DIR"
SUMMARY="$RUN_DIR/summary.md"

say(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RUN_DIR/run.log"; }
head2(){ printf '\n## %s\n\n' "$1" >> "$SUMMARY"; }
note(){ printf '%s\n' "$1" >> "$SUMMARY"; }
have(){ command -v "$1" >/dev/null 2>&1; }

{
  echo "# Linux verification run"
  echo
  echo "- date: $(date -u +%FT%TZ)"
  echo "- host: $(hostname), $(nproc) cpus, $(awk '/MemTotal/{printf "%.0f GiB", $2/1048576}' /proc/meminfo)"
  echo "- kernel: $(uname -sr)"
  echo "- git: $(git rev-parse HEAD 2>/dev/null || echo unknown)$( [ -n "$(git status --porcelain 2>/dev/null)" ] && echo ' (DIRTY — not reproducible from this rev)')"
  echo "- phases: $PHASES"
  echo "- soak length: ${SOAK_SECS}s each"
} > "$SUMMARY"

say "run directory: $RUN_DIR"
[ "$(id -u)" = 0 ] || say "WARNING: not root. Phase 3 (AF_XDP) needs root and will be skipped."

# ── phase 0: everything fast ────────────────────────────────────────────────
if [[ " $PHASES " == *" 0 "* ]]; then
  say "phase 0: build matrix and fast checks"
  head2 "Phase 0 — build matrix and fast checks"

  P0_FAIL=0
  for F in "" "--features tls" "--features dtls" "--features quic" "--features sctp" "--features io-uring"; do
    LABEL="${F:-default}"
    if cargo build --release -p turna-node $F > "$RUN_DIR/build-${LABEL// /_}.log" 2>&1; then
      note "- build \`${LABEL}\`: ok"
    else
      note "- build \`${LABEL}\`: **FAILED** — see build-${LABEL// /_}.log"
      P0_FAIL=1
    fi
  done
  cargo build --release -p turna-load-test --features quic > "$RUN_DIR/build-loadtest.log" 2>&1 \
    && note "- build \`turna-load-test --features quic\`: ok" \
    || { note "- build \`turna-load-test\`: **FAILED**"; P0_FAIL=1; }

  # doc-truth gate
  if bash scripts/check-doc-claims.sh > "$RUN_DIR/doc-claims.log" 2>&1; then
    note "- doc-truth gate: ok ($(grep -c '  ok ' "$RUN_DIR/doc-claims.log") checks)"
  else
    note "- doc-truth gate: **FAILED** — see doc-claims.log"
    P0_FAIL=1
  fi

  # production gates: each refused feature must stop the node starting
  SEC="verify-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  head2 "Production gates"
  for K in "[turn.tcp_relay]" "[turn.sctp]" "[turn.auth.oauth]"; do
    cat > "$RUN_DIR/gate.toml" <<EOF
production = true
[turn]
listen = "0.0.0.0:3478"
external_ip = "203.0.113.10"
realm = "verify"
[turn.auth]
shared_secret = "$SEC"
[turn.relay]
min_port = 49152
max_port = 49999
max_allocations = 800
[turn.relay.quota]
allow_unlimited_bandwidth = true
[signaling]
listen = "127.0.0.1:9001"
turn_shared_secret = "$SEC"
$K
enabled = true
EOF
    if target/release/turna-node --dump-config "$RUN_DIR/gate.toml" >/dev/null 2>"$RUN_DIR/gate.err"; then
      note "- \`$K\` with production=true: **STARTED — the gate is missing**"
      P0_FAIL=1
    else
      note "- \`$K\` with production=true: refused — \`$(tail -1 "$RUN_DIR/gate.err" | cut -c1-160)\`"
    fi
  done

  # Rebuild for the probes. Every `cargo build` overwrites
  # target/release/turna-node, so the binary left by the matrix loop above is
  # whichever came last -- io-uring, i.e. no QUIC. The probe config enables
  # [turn.quic] and the node correctly refuses to start without the feature. Rule
  # from here on: build what the phase needs immediately before using it, and never
  # rely on what a previous phase left in place.
  say "phase 0: rebuilding with tls,quic for the probes"
  if ! cargo build --release -p turna-node --features "tls,quic" > "$RUN_DIR/build-probe.log" 2>&1; then
    note "- probe binary (\`tls,quic\`): **FAILED** -- see build-probe.log"
    P0_FAIL=1
  fi

  # conformance + quic-check, both configurations of external_ip6
  say "phase 0: conformance probes"
  head2 "Conformance and QUIC"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$RUN_DIR/key.pem" -out "$RUN_DIR/cert.pem" -days 2 -subj "/CN=localhost" 2>/dev/null

  probe_cfg(){ # $1 = extra [turn] lines
    cat > "$RUN_DIR/probe.toml" <<EOF
production = false
[turn]
listen = "0.0.0.0:3478"
external_ip = "127.0.0.1"
$1
realm = "verify"
transport = "tokio"
[turn.auth]
shared_secret = "$SEC"
[turn.relay]
min_port = 49152
max_port = 49999
max_allocations = 800
[health]
listen = "127.0.0.1:9091"
[signaling]
listen = "127.0.0.1:9001"
turn_shared_secret = "$SEC"
[turn.quic]
enabled = true
listen = "0.0.0.0:3479"
cert_path = "$RUN_DIR/cert.pem"
key_path = "$RUN_DIR/key.pem"
web_transport = false
EOF
  }
  start_probe_node(){
    target/release/turna-node "$RUN_DIR/probe.toml" > "$RUN_DIR/probe-node.log" 2>&1 &
    PROBE_PID=$!
    for _ in $(seq 30); do
      curl -fsS --max-time 1 http://127.0.0.1:9091/ready >/dev/null 2>&1 && return 0
      sleep 1
    done
    return 1
  }

  for MODE in "off" "on"; do
    [ "$MODE" = on ] && probe_cfg 'external_ip6 = "::1"' || probe_cfg ""
    if start_probe_node; then
      OUT="$RUN_DIR/conformance-ipv6-$MODE.log"
      target/release/turna-load-test --server 127.0.0.1:3478 --secret "$SEC" conformance > "$OUT" 2>&1
      RC=$?
      note "- conformance, external_ip6 **$MODE**: $( [ $RC = 0 ] && echo ok || echo "**FAILED**" ) — see $(basename "$OUT")"
      [ $RC = 0 ] || P0_FAIL=1
      if [ "$MODE" = on ]; then
        QOUT="$RUN_DIR/quic-check.log"
        target/release/turna-load-test --server 127.0.0.1:3479 --secret "$SEC" quic-check > "$QOUT" 2>&1
        QRC=$?
        note "- quic-check: $( [ $QRC = 0 ] && echo ok || echo "**FAILED**" ) — see $(basename "$QOUT")"
        [ $QRC = 0 ] || P0_FAIL=1
        sleep 8
        curl -fsS http://127.0.0.1:9091/metrics > "$RUN_DIR/metrics-after-probes.txt" 2>/dev/null
      fi
      kill -TERM "$PROBE_PID" 2>/dev/null; wait "$PROBE_PID" 2>/dev/null
    else
      note "- conformance, external_ip6 **$MODE**: **node did not start**"
      note "  \`$(grep -m1 -E "^Error" "$RUN_DIR/probe-node.log" 2>/dev/null | cut -c1-280)\`"
      note "  (full log: probe-node.log)"
      P0_FAIL=1
      kill -KILL "$PROBE_PID" 2>/dev/null
    fi
  done

  note ""
  note "Phase 0 verdict: $( [ $P0_FAIL = 0 ] && echo "all clear" || echo "**something failed — read it before trusting the soaks below**" )"
  say "phase 0 done (fail=$P0_FAIL)"
fi

# ── soak helper ─────────────────────────────────────────────────────────────
run_soak(){ # $1 = transport, $2 = label
  # Separate `local` statements on purpose: bash declares every name in a single
  # `local` before assigning them, so `dir="...$label"` on the same line expands an
  # unset variable and `set -u` aborts the run.
  local transport="$1"
  local label="$2"
  local dir="$RUN_DIR/soak-$label"
  say "soak: $label (transport=$transport, ${SOAK_SECS}s)"
  head2 "Soak — $label (transport = $transport)"

  mkdir -p "$dir"
  # soak.sh owns its config; TRANSPORT is what selects the datapath under test.
  DURATION_SECS="$SOAK_SECS" OUT_DIR="$dir" TRANSPORT="$transport" \
    NODE_BIN="target/release/turna-node" \
    bash scripts/soak/soak.sh > "$dir/soak-stdout.log" 2>&1
  local rc=$?

  if [ -f "$dir/verdict.txt" ] && grep -q '^VERDICT' "$dir/verdict.txt"; then
    note '```'
    sed -n '/^  \(PASS\|FAIL\|WARN\|SKIP\)/p;/^VERDICT/,$p' "$dir/verdict.txt" >> "$SUMMARY"
    note '```'
  elif [ -f "$dir/verdict.txt" ]; then
    # The analyser ran but reached no verdict — it says why (too few samples, no
    # CSV). An empty code block here is worse than useless, so print its output.
    note "The analyser reached no verdict:"
    note '```'
    head -5 "$dir/verdict.txt" >> "$SUMMARY"
    note '```'
  else
    note "No verdict produced — see soak-stdout.log. The soak did not get far enough to analyse."
  fi
  note ""
  note "Exit code: $rc. Artifacts: \`$(basename "$dir")/\` (samples.csv, load-*.json, node.stderr)."
  say "soak $label finished rc=$rc"
}

if [[ " $PHASES " == *" 1 "* ]]; then
  # The tokio soak is endurance for the path that is already `supported`, so it is a
  # regression check on this release rather than a status change.
  if cargo build --release -p turna-node --features tls > "$RUN_DIR/build-soak-tokio.log" 2>&1; then
    run_soak tokio default
  else
    head2 "Soak -- default (tokio)"
    note "Build with \`--features tls\` failed; see build-soak-tokio.log. Nothing to soak."
  fi
fi

if [[ " $PHASES " == *" 2 "* ]]; then
  # This is the one that changes a status: io_uring is `experimental` for want of a
  # run, not for want of code.
  if cargo build --release -p turna-node --features io-uring > "$RUN_DIR/build-iouring.log" 2>&1; then
    run_soak io_uring io_uring
  else
    head2 "Soak — io_uring"
    note "Build with \`--features io-uring\` failed; see build-iouring.log. Nothing to soak."
  fi
fi

# ── phase 3: AF_XDP ─────────────────────────────────────────────────────────
if [[ " $PHASES " == *" 3 "* ]]; then
  say "phase 3: AF_XDP"
  head2 "AF_XDP"
  if [ "$(id -u)" != 0 ]; then
    note "Skipped: needs root (CAP_NET_RAW, and attaching an XDP program to a queue)."
  elif ! cargo build --release -p turna-node --features af-xdp > "$RUN_DIR/build-afxdp.log" 2>&1; then
    note "Build with \`--features af-xdp\` failed; see build-afxdp.log. Needs clang, llvm, libelf-dev, zlib1g-dev, libbpf-dev."
  else
    note "Build ok."
    if [ -x scripts/lab/af_xdp_veth_setup.sh ]; then
      bash scripts/lab/af_xdp_veth_setup.sh > "$RUN_DIR/afxdp-veth-setup.log" 2>&1 \
        && note "- veth lab set up: ok" || note "- veth lab set up: **failed** — see afxdp-veth-setup.log"
      if [ -x scripts/lab/af_xdp_smoke.sh ]; then
        bash scripts/lab/af_xdp_smoke.sh > "$RUN_DIR/afxdp-smoke.log" 2>&1 \
          && note "- veth smoke: ok" || note "- veth smoke: **failed** — see afxdp-smoke.log"
      fi
      [ -x scripts/lab/af_xdp_cleanup.sh ] && bash scripts/lab/af_xdp_cleanup.sh >> "$RUN_DIR/afxdp-veth-setup.log" 2>&1
    else
      note "- \`scripts/lab/af_xdp_veth_setup.sh\` not executable or missing; skipped."
    fi
    note ""
    note "A veth smoke is the *first* step, not the verification: AF_XDP on a real NIC"
    note "queue behaves differently, and a pass here says the frame path and the XDP"
    note "attach work, nothing about the NIC you will deploy on."
  fi
fi

# ── what this run could not cover ───────────────────────────────────────────
head2 "Not covered by this run, and why"
cat >> "$SUMMARY" <<'EOF'
This run drives UDP only, on both datapaths. The other transports now have clients —
they are simply not part of this orchestration, because each needs its own server
config (a certificate, a port, a feature flag) rather than another phase here.

| Path | How to check it |
|---|---|
| TURNS, functional | `turna-load-test --features tls ... tls-check` |
| TURNS, under load | `turna-load-test --features tls ... tls -c N [--channel-data]` — this is what a TURNS soak needs |
| DTLS | `--features dtls ... dtls-check`. Run against **both** `[turn.dtls] demux = false` and `true`: they accept handshakes differently |
| RFC 6062 TCP relay | `tcp-relay-check` and `tcp-relay-check --pipelined`. Run both — the pipelined form is the one the server's detach prebuffer exists for |
| QUIC, incl. relayed media | `--features quic ... quic-check` |
| WebTransport | `--features web-transport ... wt-check --url https://host:port/`. Not a browser: same library on both sides |
| IPv6 relayed media | `channel-data --family v6`, with `[turn] external_ip6` set |
| OAuth (RFC 7635) | still needs a real authorization server issuing AEAD tokens — the one gap that is not a client |

Every one of those ends at a byte arriving somewhere rather than at a success
response. That distinction is not academic: the io_uring datapath answered 10 800
allocations per second for three hours while relaying nothing at all.
EOF

say "done — summary in $SUMMARY"
echo
sed -n '1,40p' "$SUMMARY"
echo
echo "Full summary: $SUMMARY"
