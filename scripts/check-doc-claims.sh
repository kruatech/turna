#!/usr/bin/env bash
#
# Doc-truth gate: assert that documentation claims are backed by code.
#
# WHY THIS EXISTS
#
# `docs/protocol-gap.md` claimed, for months, that the RFC 5780 codec was done —
# listing `ATTR_CHANGE_REQUEST`, `Attribute::ChangeRequest`, `ATTR_RESPONSE_ORIGIN`,
# `ATTR_OTHER_ADDRESS`, their getters and a test `tests/nat_discovery.rs`. None of
# it existed. The same stale entry also claimed `ATTR_ALTERNATE_SERVER` had been
# corrected from 0x0003 to 0x8023. It had not — the constant was still 0x0003,
# which is CHANGE-REQUEST, so every `300 Try Alternate` (cluster redirect,
# lame-duck drain) shipped an attribute no conforming client could read as the
# alternate address. A false doc claim hid a real wire bug.
#
# Docs cannot be unit-tested, but the specific claims that matter can be tied to a
# grep over the code. That is all this script does: each check is one claim, one
# fact, and a message saying which side to fix. Add a check whenever a doc
# statement is load-bearing enough that silently drifting would mislead an
# operator or an auditor.
#
# Run from the repository root. Exits 1 on any divergence.

set -uo pipefail

FAILED=0
CHECKS=0

pass() { CHECKS=$((CHECKS + 1)); printf '  ok   %s\n' "$1"; }
fail() {
  CHECKS=$((CHECKS + 1))
  FAILED=$((FAILED + 1))
  printf '  FAIL %s\n' "$1" >&2
  printf '       %s\n' "$2" >&2
}

section() { printf '\n== %s\n' "$1"; }

for d in crates docs services; do
  [ -d "$d" ] || {
    echo "check-doc-claims: $d/ not found — run from the repository root" >&2
    exit 1
  }
done

# ---------------------------------------------------------------------------
section "STUN attribute values that clients depend on"
# ---------------------------------------------------------------------------

# ALTERNATE-SERVER is 0x8023 (RFC 5389 §15.5 / RFC 8489 §14.15). 0x0003 is
# CHANGE-REQUEST (RFC 5780) and was the value shipped by mistake.
if grep -qE '^pub const ATTR_ALTERNATE_SERVER: u16 = 0x8023;' \
  crates/protocol/proto-stun/src/attribute.rs; then
  pass "ATTR_ALTERNATE_SERVER = 0x8023"
else
  fail "ATTR_ALTERNATE_SERVER is not 0x8023" \
    "0x0003 is CHANGE-REQUEST. A 300 Try Alternate carrying it is unreadable to clients."
fi

# ---------------------------------------------------------------------------
section "RFC 5780 (NAT behaviour discovery): docs must not claim a codec that is absent"
# ---------------------------------------------------------------------------

if grep -rqE 'ChangeRequest|ATTR_CHANGE_REQUEST[^_]|ResponseOrigin|OtherAddress' \
  --include='*.rs' crates/protocol; then
  CODEC_5780=yes
else
  CODEC_5780=no
fi

if [ "$CODEC_5780" = no ]; then
  # Only a *live* claim is a failure. Corrective prose ("previously claimed the
  # codec was done", "that was wrong") legitimately contains the same words, so
  # lines carrying a retraction marker are excluded.
  CLAIMS=$(grep -rniE 'codec (is )?(done|complete)|codec only' docs README.md 2>/dev/null |
    grep -iE '5780|change-request|other-address|response-origin' |
    grep -viE 'previously|was wrong|correction|none of that|not exist|absent|stale|no codec')
  if [ -n "$CLAIMS" ]; then
    fail "docs claim an RFC 5780 codec, but none exists in crates/protocol" \
      "Either implement it or correct the doc. Lines: $(printf '%s' "$CLAIMS" | head -3 | tr '\n' ';')"
  else
    pass "no codec in tree, and no doc makes a live claim of one"
  fi
else
  pass "RFC 5780 codec present in crates/protocol (doc claims are allowed)"
fi

# ---------------------------------------------------------------------------
section "Cross-node migration: 'works' claims require the module to be wired"
# ---------------------------------------------------------------------------

if [ -f crates/relay/src/node_migration.rs ]; then
  # Callers outside the module itself and outside the `pub mod` declaration.
  CALLERS=$(grep -rlE 'node_migration::|MigrationCoordinator|DrainCoordinator|MigrationPayload' \
    --include='*.rs' crates services tools tests 2>/dev/null |
    grep -v 'crates/relay/src/node_migration.rs' |
    grep -v 'crates/relay/src/lib.rs' | wc -l | tr -d ' ')
  if [ "$CALLERS" = "0" ]; then
    if grep -rqiE 'cross-node migration' docs README.md 2>/dev/null &&
      ! grep -rqiE 'cross-node migration is \*\*unwired\*\*|cross-node migration is unwired|unwired' docs README.md 2>/dev/null; then
      fail "node_migration.rs has no callers, but no doc says so" \
        "Say 'unwired' (not merely 'unverified'), or wire/delete the module."
    else
      pass "node_migration.rs is unwired and the docs say so"
    fi
  else
    pass "node_migration.rs has $CALLERS caller file(s)"
  fi
else
  pass "node_migration.rs removed"
fi

# ---------------------------------------------------------------------------
section "Every metric named in docs/alerts exists in turna-health"
# ---------------------------------------------------------------------------

HEALTH=crates/health/src/lib.rs
if [ -f "$HEALTH" ]; then
  MISSING_METRICS=""
  # Only `expr:` lines. A comment may legitimately name a metric that does NOT
  # exist — docs/alerts/transport-backends.yml explains why there is deliberately
  # no DTLS handshake-failure rule, and naming the absent counter is the point.
  for m in $(grep -rhE '^\s*expr:' docs/alerts 2>/dev/null |
    grep -ohE 'turna_[a-z0-9_]+' | sort -u); do
    grep -qF "$m" "$HEALTH" || MISSING_METRICS="$MISSING_METRICS $m"
  done
  if [ -n "$MISSING_METRICS" ]; then
    fail "alert rules reference metrics that turna-health never emits:$MISSING_METRICS" \
      "An alert on a metric that is never exported can never fire. Remove the rule or add the metric."
  else
    pass "all metrics referenced by alert rules are exported"
  fi
else
  fail "$HEALTH not found" "expected the health crate at that path"
fi

# ---------------------------------------------------------------------------
section "Production-refused features: docs must match config::validate()"
# ---------------------------------------------------------------------------

CONFIG=crates/config/src/lib.rs
if [ -f "$CONFIG" ]; then
  # Match the operator-visible diagnostic, not just the field path: the field path
  # also appears in the schema and in unrelated checks, so grepping for it would
  # still pass after the gate itself was deleted (verified with a negative test).
  for key in turn.tcp_relay.enabled turn.sctp.enabled turn.auth.oauth.enabled; do
    field=$(printf '%s' "$key" | sed 's/^turn\.//; s/\.enabled$//')
    if grep -qF "$key = true in production" "$CONFIG"; then
      pass "validate() refuses $key in production"
    else
      fail "$key is no longer refused in production by $CONFIG" \
        "If the gate was lifted deliberately, update docs/PRODUCTION_READINESS.md (R9), docs/feature-support.md and README.md — they all still say 'refused in production' for $field."
    fi
  done
fi

# ---------------------------------------------------------------------------
section "Every exported metric is described in docs/OBSERVABILITY.md"
# ---------------------------------------------------------------------------

# Nine checks above assert specific facts. This one asserts *completeness*, which
# is the gap that let eight new metrics ship undocumented: nothing was wrong, just
# missing, and no check was looking. A metric nobody can find is a metric nobody
# builds a dashboard on.
OBS=docs/OBSERVABILITY.md
if [ -f "$HEALTH" ] && [ -f "$OBS" ]; then
  # ── Documentation debt, explicit rather than silent ──
  #
  # These families were already undocumented when this check was written (47
  # series across five subsystems). They are listed instead of skipped quietly,
  # because a silent skip is precisely the failure mode this whole script exists
  # to prevent — and the list is meant to shrink.
  #
  # KNOWN LIMITATION: this is a prefix allowlist, so a *new* metric added inside
  # one of these families also slips through. Removing a family from the list is
  # the only way to get real coverage for it. Do that as each one gets documented;
  # do not add prefixes here to silence a new subsystem.
  DEBT_PREFIXES="turna_afxdp_ turna_uring_ turna_command_log_ turna_relay_route_ turna_user_limits_"
  DEBT_SINGLES="turna_processor_panics_total turna_management_readiness"

  UNDOC=""
  DEBT_COUNT=0
  # Series names come from the Prometheus text block in the health crate: the
  # exported name is what appears at the start of a rendered line.
  for m in $(grep -ohE '^ +turna_[a-z0-9_]+ \{\}' "$HEALTH" 2>/dev/null |
    tr -d ' {}' | sort -u); do
    grep -qF "$m" "$OBS" && continue
    KNOWN=0
    for pfx in $DEBT_PREFIXES; do
      case "$m" in "$pfx"*) KNOWN=1; break ;; esac
    done
    for one in $DEBT_SINGLES; do
      [ "$m" = "$one" ] && KNOWN=1
    done
    if [ "$KNOWN" = 1 ]; then
      DEBT_COUNT=$((DEBT_COUNT + 1))
    else
      UNDOC="$UNDOC $m"
    fi
  done
  [ "$DEBT_COUNT" -gt 0 ] && printf '       (%d pre-existing undocumented series in known-debt families)\n' "$DEBT_COUNT"
  if [ -n "$UNDOC" ]; then
    fail "metrics exported but absent from $OBS:$UNDOC" \
      "Add a row to the matching table in $OBS. If a metric is only meaningful under some config, say so in the row — a metric that reads 0 for a structural reason must not look like 'no problems'."
  else
    pass "every exported metric appears in $OBS"
  fi
fi

# ---------------------------------------------------------------------------
section "Peer-filter documentation covers the v6 prefixes the code denies"
# ---------------------------------------------------------------------------

# The peer filter is a security boundary, and its documentation is what an operator
# reads to decide whether their peer population is affected. When the v4-embedding
# v6 transition prefixes were added to `is_special_v6`, any document listing the
# denied ranges became incomplete — and an incomplete deny list reads as permission.
#
# Only the prefixes that actually block a bypass are checked. Denying the
# documentation prefix, benchmarking, ORCHID and so on is housekeeping; NAT64, 6to4,
# Teredo and IPv4-compatible each smuggle an arbitrary IPv4 address inside a v6
# literal, which is what makes them load-bearing.
PF=crates/relay/src/peer_filter.rs
if [ -f "$PF" ]; then
  MISSING_DOC=""
  # term-in-code -> term to look for in the docs
  for pair in "0xff9b:NAT64" "0x2002:6to4" "Teredo:Teredo" "IPv4-compatible:IPv4-compatible"; do
    code="${pair%%:*}"
    doc="${pair##*:}"
    grep -qF "$code" "$PF" || continue   # not denied in code, nothing to document
    grep -rqiF "$doc" docs README.md 2>/dev/null || MISSING_DOC="$MISSING_DOC $doc"
  done
  if [ -n "$MISSING_DOC" ]; then
    fail "peer filter denies prefixes no document mentions:$MISSING_DOC" \
      "An operator reading the deny list will not know their NAT64/6to4/Teredo peers now get 403. Update docs/security/peer-filter.md (and the CHANGELOG entry)."
  else
    pass "every bypass-relevant v6 prefix denied in code is documented"
  fi
fi

# ---------------------------------------------------------------------------
section "Cargo feature names used in docs actually exist"
# ---------------------------------------------------------------------------

FEATURE_MANIFESTS=$(ls crates/transport/Cargo.toml crates/relay/Cargo.toml \
  services/node/Cargo.toml 2>/dev/null)
if [ -n "$FEATURE_MANIFESTS" ]; then
  DECLARED=$(awk '/^\[features\]/{f=1;next} /^\[/{f=0} f && /=/ {print $1}' \
    $FEATURE_MANIFESTS | sort -u)
  UNKNOWN=""
  for f in io-uring af-xdp web-transport dtls sctp tls quic; do
    printf '%s\n' "$DECLARED" | grep -qx "$f" || UNKNOWN="$UNKNOWN $f"
  done
  if [ -n "$UNKNOWN" ]; then
    fail "docs reference Cargo features that no manifest declares:$UNKNOWN" \
      "Feature renamed or removed? Update docs/compatibility/transport-backends.md and docs/feature-support.md."
  else
    pass "every documented feature name is declared in a manifest"
  fi
fi

# ---------------------------------------------------------------------------
printf '\ncheck-doc-claims: %d checks, %d failed\n' "$CHECKS" "$FAILED"
[ "$FAILED" -eq 0 ] || {
  echo "check-doc-claims: FAIL — documentation and code disagree (see above)" >&2
  exit 1
}
echo "check-doc-claims: OK — documented claims match the code"
