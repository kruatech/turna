#!/usr/bin/env bash
#
# Check a running deployment against docs/security/security-profile.md.
#
#   scripts/verify/deployment-compliance.sh --config /etc/turna/turn.toml
#   scripts/verify/deployment-compliance.sh --config turn.toml --health 127.0.0.1:9090
#
# Exit 0 when every non-negotiable item holds, 1 otherwise. Recommendations are
# reported and do not fail the run: an operator who has decided against one
# should not have a red check forever, and a check that is always red is one
# nobody reads.
#
# WHY THIS EXISTS RATHER THAN A DOCUMENT
#
# The security profile is a list of things to set. Nothing verified that a
# deployment had set them, so the profile's real function was to be read once
# during setup and never again. A configuration drifts; a document does not
# notice.
#
# WHAT IT CANNOT SEE
#
# The config file as written, and the node's own endpoints. Not the firewall, not
# the conntrack table, not whether the relay range overlaps the ephemeral range on
# a *different* host. Those are in the network profile and need someone to look.

set -uo pipefail

CONFIG=""
HEALTH="${HEALTH:-127.0.0.1:9090}"

while [ $# -gt 0 ]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --health) HEALTH="$2"; shift 2 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$CONFIG" ] || { echo "--config is required" >&2; exit 2; }
[ -r "$CONFIG" ] || { echo "cannot read $CONFIG" >&2; exit 2; }

FAILED=0
WARNED=0

fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; printf '        %s\n' "$2"; FAILED=$((FAILED+1)); }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; printf '        %s\n' "$2"; WARNED=$((WARNED+1)); }
pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
section() { printf '\n== %s\n' "$1"; }

# Value of a top-level or dotted key. Naive on purpose: a TOML parser here would
# be a dependency, and the keys checked are simple assignments. A key inside an
# array-of-tables would be missed, which is stated rather than silently wrong.
val() { grep -E "^[[:space:]]*$1[[:space:]]*=" "$CONFIG" | head -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/^"//; s/"$//' ; }
has_section() { grep -qE "^[[:space:]]*\[$1\]" "$CONFIG"; }

echo "deployment compliance — $CONFIG"

section "Non-negotiable"

PROD=$(val production)
if [ "$PROD" = "true" ]; then
  pass "production = true"
else
  fail "production is not true" \
    "Validation then permits placeholder secrets, unlimited per-allocation bandwidth, and three experimental transports. This single flag gates most of the rest."
fi

SECRET=$(val shared_secret)
case "$SECRET" in
  "") warn "no shared_secret found" "Either it is in an array-of-tables this check cannot read, or static users are in use." ;;
  \$\{*|file://*) pass "shared_secret comes from the environment or a file" ;;
  changeme|secret|CHANGEME|test|password)
    fail "shared_secret is a placeholder" \
      "This is the credential that mints TURN sessions. production = true refuses some placeholders, but not every string somebody types." ;;
  *) warn "shared_secret is a literal in the config" \
      "Use \${TURNA_SHARED_SECRET} or file:///run/secrets/... — a literal ends up in a ticket attachment sooner or later." ;;
esac

if has_section "management"; then
  if grep -qE '^[[:space:]]*require_client_cert[[:space:]]*=[[:space:]]*true' "$CONFIG"; then
    pass "management requires a client certificate"
  else
    fail "management does not require a client certificate" \
      "The management plane mints users and shuts nodes down. Without mTLS, reaching the port is enough."
  fi
else
  pass "no management section — the plane is not exposed"
fi

MINP=$(val min_port); MAXP=$(val max_port)
if [ -n "$MINP" ] && [ -n "$MAXP" ]; then
  if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
    read -r EMIN EMAX < /proc/sys/net/ipv4/ip_local_port_range
    if [ "$MINP" -le "$EMAX" ] && [ "$MAXP" -ge "$EMIN" ]; then
      fail "relay range [$MINP,$MAXP] overlaps the ephemeral range [$EMIN,$EMAX]" \
        "A peer socket can land inside the relay range and the relay forwards to itself. This has happened in this project."
    else
      pass "relay range does not overlap the ephemeral range"
    fi
  else
    warn "cannot read the ephemeral range" "Check by hand that [$MINP,$MAXP] is clear of it."
  fi
else
  warn "relay range not set explicitly" "The default is 49152-65535, which overlaps the ephemeral range on most Linux hosts."
fi

if has_section "turn.peer_filter"; then
  pass "peer filter configured explicitly"
else
  warn "no [turn.peer_filter] section" \
    "The default denies private ranges, which is right for an internet-facing relay and wrong for a LAN one. Either is fine; deciding is the point."
fi

section "Recommended"

if grep -qE '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true' <<<"$(sed -n '/\[management.rbac\]/,/^\[/p' "$CONFIG")"; then
  pass "RBAC enabled"
else
  warn "RBAC is not enabled" \
    "Every management client is an administrator. Note enabling is default-deny: bind identities first or you will lock yourself out."
fi

if grep -qE '^[[:space:]]*max_per_user[[:space:]]*=[[:space:]]*[1-9]' "$CONFIG"; then
  pass "per-user allocation quota set"
else
  warn "no per-user quota" "One credential can consume the whole relay port range."
fi

for t in tls dtls quic sctp; do
  if has_section "turn.$t" || has_section "$t"; then
    if grep -qE "^[[:space:]]*max_connections_per_ip[[:space:]]*=[[:space:]]*[1-9]" "$CONFIG"; then
      pass "$t has a per-IP cap somewhere in the config"
    else
      warn "$t enabled with no per-IP connection cap" \
        "One source can hold every slot. Set max_connections_per_ip."
    fi
    break
  fi
done

if grep -qE '^[[:space:]]*syslog_endpoint[[:space:]]*=[[:space:]]*"[^"]+' "$CONFIG"; then
  pass "syslog export configured"
else
  warn "no syslog endpoint" \
    "Security events go nowhere durable. An investigation then reads the absence of events as the absence of attacks."
fi

if grep -qE '^[[:space:]]*drain_timeout_secs[[:space:]]*=' "$CONFIG"; then
  pass "drain timeout set explicitly"
else
  warn "drain timeout not set" \
    "Default 30 s, and a node whose clients vanished pays it in full — five minutes across a ten-node rolling upgrade."
fi

section "Live checks"

if READY=$(curl -fsS --max-time 3 "http://$HEALTH/ready" 2>/dev/null); then
  pass "health endpoint answers"
  if CAP=$(curl -fsS --max-time 3 "http://$HEALTH/capacity" 2>/dev/null); then
    STATE=$(printf '%s' "$CAP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state","?"))' 2>/dev/null)
    case "$STATE" in
      AVAILABLE|DEGRADED) pass "capacity state: $STATE" ;;
      UNAVAILABLE) fail "capacity state UNAVAILABLE" "The node is not ready, or no capacity limit was published — in which case it cannot honestly claim headroom." ;;
      *) warn "capacity state: $STATE" "Not an error, but not a node you would send new work to." ;;
    esac
  fi
  DROPS=$(curl -fsS --max-time 3 "http://$HEALTH/status" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("send_queue_dropped",0))' 2>/dev/null || echo 0)
  if [ "${DROPS:-0}" -gt 0 ]; then
    warn "send_queue_dropped is $DROPS" \
      "The node has discarded media before sending it. Clients cannot see this, so a clean-looking loss measurement is not evidence against it."
  else
    pass "no egress queue drops"
  fi
else
  warn "health endpoint unreachable at $HEALTH" \
    "Either the node is down or the address is wrong. Note a failed health bind is fatal since 2026-08-25, so a running node has a working endpoint."
fi

printf '\n%d failed, %d warnings\n' "$FAILED" "$WARNED"
if [ "$FAILED" -gt 0 ]; then
  echo
  echo "Failures are items from docs/security/security-profile.md marked"
  echo "non-negotiable. Warnings are recommendations — decide and move on rather"
  echo "than leaving a check permanently red."
fi
exit $(( FAILED > 0 ? 1 : 0 ))
