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
section "Every .rs under a crate's src/ is reachable as a module"
# ---------------------------------------------------------------------------

# A file with no `mod` declaration is not unwired -- it is INVISIBLE. cargo never
# compiles it, clippy never lints it, `cargo test` never runs its tests, and no
# amount of reading `lib.rs` reveals that it is there. graceful.rs (FD passing +
# memfd state handover, 302 lines) sat in crates/relay/src in exactly that state.
# The unwired-module gates above each name one module; this one needs no list, so
# the next such file is caught the day it lands.
#
# The lookup is deliberately loose -- `mod <name>;` anywhere in the same crate's
# src tree counts, under any cfg -- because a false positive here blocks CI on a
# legitimate layout, while a miss only costs what we already had.

ORPHANS=""
for SRCDIR in crates/*/src crates/*/*/src services/*/src; do
  [ -d "$SRCDIR" ] || continue
  while IFS= read -r RSFILE; do
    [ -n "$RSFILE" ] || continue
    MODNAME=$(basename "$RSFILE" .rs)
    case "$MODNAME" in
      lib | main | mod) continue ;;
    esac
    if ! grep -rqE "^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?mod[[:space:]]+$MODNAME[[:space:]]*;" \
      "$SRCDIR" 2>/dev/null; then
      ORPHANS="$ORPHANS $RSFILE"
    fi
  done <<EOF
$(find "$SRCDIR" -type f -name '*.rs' 2>/dev/null)
EOF
done

if [ -z "$ORPHANS" ]; then
  pass "every .rs under crates/*/src and services/*/src is declared as a module"
else
  fail "source files that no mod declaration reaches:$ORPHANS" \
    "cargo does not compile these at all. Declare them (pub mod <name>;) or delete them -- an undeclared file cannot even be known to build."
fi

# ---------------------------------------------------------------------------
section "Scenario example configs: present means CI must load them"
# ---------------------------------------------------------------------------

# deploy/examples/ was empty while ci.yml carried a step that loaded
# deploy/examples/*.toml, so the step could only fail. It was removed rather
# than softened -- a step passing on zero inputs is the green-run-that-checked-
# nothing this repository refuses. This is the other half of that decision: the
# day the examples are written, the step has to come back, or they ship
# unvalidated and nobody finds out.

EX_COUNT=$(find deploy/examples -maxdepth 1 -name '*.toml' 2>/dev/null | wc -l | tr -d ' ')
CI_LOADS_EXAMPLES=0
grep -q "deploy/examples/\*.toml" .github/workflows/ci.yml 2>/dev/null && CI_LOADS_EXAMPLES=1
if [ "$EX_COUNT" -eq 0 ] && [ "$CI_LOADS_EXAMPLES" -eq 0 ]; then
  pass "no example configs, and ci.yml does not pretend to load any"
elif [ "$EX_COUNT" -gt 0 ] && [ "$CI_LOADS_EXAMPLES" -eq 1 ]; then
  pass "$EX_COUNT example config(s), and ci.yml loads them"
elif [ "$EX_COUNT" -gt 0 ]; then
  fail "deploy/examples/ holds $EX_COUNT config(s) that CI never loads" \
    "Restore the 'Parse the scenario example configs' step in .github/workflows/ci.yml. An example that does not load is worse than none: it is copied, edited, and the failure is blamed on the edit."
else
  fail "ci.yml loads deploy/examples/*.toml, but there are none" \
    "Either write the examples or drop the step. A step with no inputs reports a clean check on nothing."
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
  for key in turn.auth.oauth.enabled; do
    field=$(printf '%s' "$key" | sed 's/^turn\.//; s/\.enabled$//')
    if grep -qF "$key = true in production" "$CONFIG"; then
      pass "validate() refuses $key in production"
    else
      fail "$key is no longer refused in production by $CONFIG" \
        "If the gate was lifted deliberately, update docs/PRODUCTION_READINESS.md (R9), docs/feature-support.md and README.md — they all still say 'refused in production' for $field."
    fi
  done

  # The reverse assertion, for gates that were lifted deliberately.
  #
  # turn.tcp_relay.enabled was refused under `production` until 2026-08-25, when
  # interop against coturn's client put the missing evidence on record
  # (docs/interop/coturn-2026-08-23.md). Removing it from the list above stops
  # this check demanding a gate that should no longer exist — but leaves nothing
  # watching for its return, and a revert or a bad merge would reinstate it
  # silently. Which is exactly the kind of quiet regression this script exists
  # for, so it is checked in both directions.
  #
  # If you are reintroducing the refusal on purpose, delete the matching entry
  # here and move the key back to the loop above.
  # SCTP: native Linux/tokio evidence is in verification/sctp-supported-2026-09-18.md.
  LIFTED_GATES="turn.tcp_relay.enabled turn.sctp.enabled"
  for key in $LIFTED_GATES; do
    if grep -qF "$key = true in production" "$CONFIG"; then
      fail "$key is refused in production again, but the docs say the gate was lifted" \
        "Either the refusal came back by accident (a revert or a merge), or it came back on purpose — in which case move $key from LIFTED_GATES back into the required list in this script, and correct docs/PRODUCTION_READINESS.md (R9), docs/feature-support.md and README.md."
    else
      pass "$key stays lifted (gate not reintroduced)"
    fi
  done
fi

# ---------------------------------------------------------------------------
section "Lifted and implemented features: docs must not still call them refused or missing"
# ---------------------------------------------------------------------------

# The reverse check above watches the code. This one watches the prose: after the
# RFC 6062 gate was lifted on 2026-08-25, docs/migrating-from-coturn.md,
# docs/COMPLIANCE.md, docs/protocol-gap.md and docs/CONFIGURATION.md went on
# telling operators it was "refused under production = true" — a migration
# blocker that did not exist. Same shape for OAuth, which docs/why-turna.md
# listed as "Not implemented" while `AuthMode::OAuth` shipped.
#
# Claims wrap across lines, so this reads paragraphs, list items and table rows
# rather than lines, and attributes a "refused in production" to the nearest
# feature named before it — a sentence listing TCP relay and then OAuth "(refused
# under production = true)" is about OAuth. Paragraphs that carry a retraction
# marker ("lifted", "until 2026-…", "used to") are history, not claims. Verified
# to flag the three stale RFC 6062 sites on the pre-fix tree.
if ! grep -qF "turn.tcp_relay.enabled = true in production" "$CONFIG"; then
  STALE_6062=$(python3 - <<'PYEOF'
import glob, re
feature = re.compile(r'6062|tcp_relay|TCP relay|OAuth|7635|SCTP|QUIC|WebTransport|io_uring|AF_XDP|DTLS', re.I)
claim = re.compile(r'refus\w*\s+(?:\*\*)?\s*(?:under|in)\s+`?production|production\s*=\s*true`?\s+refuses', re.I)
retract = re.compile(r'lifted|until 20|no longer|used to|was refused|previously|reintroduc|came back|come back|earlier', re.I)
for f in sorted(glob.glob('docs/**/*.md', recursive=True)) + ['README.md']:
    text = open(f, encoding='utf-8').read()
    for block in re.split(r'\n\s*\n|\n(?=\|)|\n(?=\s*[-*] )', text):
        flat = ' '.join(block.split())
        if retract.search(flat):
            continue
        for m in claim.finditer(flat):
            before = list(feature.finditer(flat[:m.start()]))
            if before and re.match(r'6062|tcp_relay|TCP relay', before[-1].group(0), re.I):
                print(f + ': ' + flat[:100])
                break
PYEOF
)
  if [ -n "$STALE_6062" ]; then
    fail "docs still say RFC 6062 TCP relay is refused in production; validate() no longer refuses it" \
      "Correct the doc (the gate was lifted 2026-08-25), or mark the sentence as history. $(printf '%s' "$STALE_6062" | head -3 | tr '\n' ';')"
  else
    pass "no doc calls RFC 6062 TCP relay refused in production"
  fi
fi

if grep -qE 'OAuth \{' crates/auth/src/lib.rs 2>/dev/null; then
  STALE_OAUTH=$(grep -rniE '(oauth|7635).*not implemented' docs README.md 2>/dev/null |
    grep -viE 'previously|was wrong|used to|correction|earlier')
  if [ -n "$STALE_OAUTH" ]; then
    fail "docs say RFC 7635 OAuth is not implemented, but AuthMode::OAuth exists" \
      "It is implemented and refused under production = true — say that. Lines: $(printf '%s' "$STALE_OAUTH" | head -3 | tr '\n' ';')"
  else
    pass "no doc calls OAuth unimplemented while AuthMode::OAuth exists"
  fi
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
  # ── Documentation debt: now empty, and meant to stay that way ──
  #
  # This list once held five families (turna_afxdp_, turna_uring_,
  # turna_command_log_, turna_relay_route_, turna_user_limits_) — 46 series that
  # predated the check. They are described in docs/OBSERVABILITY.md and the
  # prefixes are gone, so those families get real coverage now.
  #
  # KNOWN LIMITATION, kept here because it is the reason the list is empty: this
  # is a *prefix* allowlist, so listing a family also hides any NEW metric added
  # inside it. That is what let series ship undocumented in the first place. Do
  # not add a prefix here to silence a new subsystem — document the metric.
  DEBT_PREFIXES=""
  DEBT_SINGLES=""

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
  # Here-string, not `printf ... | grep -q`: with `pipefail` set, grep -q exits at
  # its first match and printf dies of SIGPIPE (141), which pipefail turns into a
  # failed pipeline — so a feature that IS declared gets reported as unknown, at
  # random. Same bug that made check-proto-compat.sh flake.
  for f in io-uring af-xdp web-transport dtls sctp tls quic; do
    grep -qx "$f" <<<"$DECLARED" || UNKNOWN="$UNKNOWN $f"
  done
  if [ -n "$UNKNOWN" ]; then
    fail "docs reference Cargo features that no manifest declares:$UNKNOWN" \
      "Feature renamed or removed? Update docs/compatibility/transport-backends.md and docs/feature-support.md."
  else
    pass "every documented feature name is declared in a manifest"
  fi
fi

# ---------------------------------------------------------------------------
section "Helm chart scope: transports it cannot configure are declared"
# ---------------------------------------------------------------------------

# The chart's ConfigMap has nine sections and no escape hatch, so a Helm install
# serves plain UDP TURN — no TURNS, DTLS or QUIC. That is a defensible scope; it
# was just written nowhere, while the README presented the chart as *the*
# Kubernetes path. An operator who needs TURNS in Kubernetes found out by reading
# the template.
#
# Two-way: if the chart gains a `[tls]` section the scope notes must go, or they
# become the false claim instead.
CM=deploy/helm/turna/templates/configmap.yaml
if [ -f "$CM" ] && [ -f README.md ] && [ -f deploy/helm/turna/values.yaml ]; then
  # `sysctls` contains the substring "tls" — match the section header, not the
  # word, or this passes on a chart that has no TLS at all.
  if grep -qE '^\s*\[(tls|turn\.dtls|turn\.quic)\]' "$CM"; then
    if grep -q 'plain UDP TURN only' README.md; then
      fail "the chart now configures an encrypted transport, but README still says 'plain UDP TURN only'" \
        "Remove the scope note — it has become the inaccurate claim."
    else
      pass "chart configures encrypted transports and no scope note contradicts it"
    fi
  else
    MISSING=""
    grep -q 'plain UDP TURN only' README.md || MISSING="$MISSING README.md(transports)"
    grep -q 'plain UDP TURN only' deploy/helm/turna/values.yaml || MISSING="$MISSING values.yaml(transports)"
    grep -q 'SCOPE' "$CM" || MISSING="$MISSING configmap.yaml(transports)"
    # Second limit, same class: the chart deploys turna-node alone, so turnactl
    # and the admin console cannot reach it. Checked against the templates rather
    # than trusted: if a control-plane workload ever appears, the note must go.
    #
    # Matches non-comment lines only. The first version grepped the name anywhere
    # and tripped on the SCOPE comment that explains the absence — a note saying
    # "there is no control plane here" read as a control plane being here. The
    # same shape as the INIT_SCRIPT check two sections down, and it caught me the
    # same way.
    if ! grep -rqE '^[^#]*turna-control-plane' deploy/helm/turna/templates/ 2>/dev/null; then
      grep -q 'No ops API in the chart' README.md || MISSING="$MISSING README.md(ops-api)"
      grep -q 'no ops API' "$CM" || MISSING="$MISSING configmap.yaml(ops-api)"
    else
      grep -q 'No ops API in the chart' README.md && \
        MISSING="$MISSING README.md(stale-ops-api-note)"
    fi
    if [ -n "$MISSING" ]; then
      fail "the chart cannot configure TURNS/DTLS/QUIC and these do not say so:$MISSING" \
        "The README offers the chart as the Kubernetes path. Someone deploying TURNS there needs to learn this before the install, not from the template."
    else
      pass "chart is UDP-only and all three places say so"
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "turna-auth: the deleted modules stay deleted"
# ---------------------------------------------------------------------------

# store.rs, rotation.rs, jwt.rs and user.rs — 1310 lines of user registration,
# Argon2 hashing, JWT signing and token revocation — had no callers outside the
# auth crate and were deleted in 0.5.0 (OPEN-DECISIONS decision 7: authenticating
# users is the signalling service's job; turna gets a TURN REST credential).
#
# This used to check that each file carried an UNWIRED label. With the files gone
# that loop passed over an empty list, which is the shape of check this script
# exists to prevent — a green tick on nothing. It now asserts the decision
# instead: the file is absent, or it is back AND something outside the crate
# actually calls it.
AUTH_SRC=crates/auth/src
if [ -d "$AUTH_SRC" ]; then
  AUTH_BAD=""
  for m in store rotation jwt user; do
    f="$AUTH_SRC/$m.rs"
    [ -f "$f" ] || continue
    # Matched by MODULE PATH, not by type name. `User` is too generic: a bare
    # `grep -w User` hits state-backend's own types, and narrowing to files that
    # also mention turna_auth still hits turna-health, which renders a metric
    # called turna_auth_previous_secret_total and a HELP string containing the
    # word "User". A module path cannot be produced by coincidence.
    if grep -rlE "turna_auth::(\\{[^}]*\\b$m\\b|$m\\b)" --include='*.rs' \
         crates services tools tests 2>/dev/null | grep -qv "^$AUTH_SRC/"; then
      continue   # back on purpose, and wired — fine
    fi
    AUTH_BAD="$AUTH_BAD $m"
  done
  if [ -n "$AUTH_BAD" ]; then
    fail "turna-auth modules deleted in 0.5.0 are back with no callers:$AUTH_BAD" \
      "Either wire them and say so in docs/OPEN-DECISIONS.md decision 7, or delete them again. Unwired code in this crate is what the deletion was for."
  else
    pass "the four unwired turna-auth modules are gone (or back and wired)"
  fi
fi

# ---------------------------------------------------------------------------
section "deny.toml and osv-scanner.toml ignore the same advisories"
# ---------------------------------------------------------------------------

# osv-scanner.toml opens by stating it is "kept in sync with the
# [advisories].ignore list in deny.toml", and nothing enforced that. Removing an
# advisory from one and not the other leaves the two tools disagreeing about what
# is accepted — cargo-deny drives CI, OSSF Scorecard's Vulnerabilities check reads
# only osv-scanner.toml. Whichever way they drift, one of them is lying about the
# project's risk posture. This happened during the rtnetlink bump.
if [ -f deny.toml ] && [ -f osv-scanner.toml ]; then
  ADV_DIFF=$(python3 - <<'ADVPY'
import sys, tomllib
try:
    deny = tomllib.load(open("deny.toml", "rb"))
    osv = tomllib.load(open("osv-scanner.toml", "rb"))
except Exception as e:
    print("PARSE " + str(e)); raise SystemExit(0)
a = sorted(e["id"] for e in deny.get("advisories", {}).get("ignore", []) if isinstance(e, dict))
b = sorted(e["id"] for e in osv.get("IgnoredVulns", []))
only_deny = [x for x in a if x not in b]
only_osv = [x for x in b if x not in a]
out = []
if only_deny: out.append("deny-only:" + ",".join(only_deny))
if only_osv: out.append("osv-only:" + ",".join(only_osv))
print(" ".join(out))
ADVPY
)
  case "$ADV_DIFF" in
    PARSE*) fail "could not parse the advisory files (${ADV_DIFF#PARSE })" \
              "Fix the TOML; the check cannot compare them." ;;
    "") pass "both advisory ignore lists hold the same ids" ;;
    *) fail "deny.toml and osv-scanner.toml disagree about ignored advisories: $ADV_DIFF" \
         "cargo-deny gates CI from the first, Scorecard reads only the second. An id in one and not the other means one of them misstates what this project accepts." ;;
  esac
fi

# ---------------------------------------------------------------------------
section "Tarantool schema has one source of truth"
# ---------------------------------------------------------------------------

# `tarantool::INIT_SCRIPT` was deleted, and five places kept referring to it: this
# crate's lib.rs said the init script "is embedded" in it, init.lua carried a
# "change one place, change both" note, and the ADDITIONAL-ADDRESS-FAMILY
# migration plan — in OPEN-DECISIONS, the design doc and protocol-gap — budgeted
# for updating both. A plan that budgets for a second source of truth is planning
# work that does not exist, and the migration was costed higher than it is.
#
# Fails only when a doc asserts the constant exists while the code has none. Text
# that says it does NOT exist is what this check produced and must not trip it.
SB=crates/state-backend/src/tarantool.rs
if [ -f "$SB" ]; then
  if grep -qE '^\s*(pub )?(const|static) INIT_SCRIPT' "$SB"; then
    pass "INIT_SCRIPT exists in $SB; references to it are legitimate"
  else
    PHANTOM=""
    for f in $(grep -rl 'INIT_SCRIPT' docs crates deploy --include='*.md' --include='*.rs' --include='*.lua' 2>/dev/null); do
      # A line that denies the constant is the correction, not the claim. The
      # match is per LINE, so a denial split across two lines does not exempt the
      # one naming INIT_SCRIPT — keep the denial and the name together.
      #
      # The negation must sit NEXT TO the name, within the same sentence. A list of
      # bare keywords matched anywhere on the line was tried and was useless: English
      # prose contains "not" constantly, so every assertion got exempted and the check
      # silently stopped checking. Verified both ways: the eight real mentions are
      # exempted, and four historical assertions are all caught.
      if grep 'INIT_SCRIPT' "$f" |
         grep -qivE '(\bno\b|\bnot\b|never|deleted|removed|gone|phantom|used to)[^.]{0,80}INIT_SCRIPT|INIT_SCRIPT[^.]{0,80}(no longer|not exist|deleted|removed|gone|phantom|used to)'; then
        PHANTOM="$PHANTOM $f"
      fi
    done
    if [ -n "$PHANTOM" ]; then
      fail "no INIT_SCRIPT in $SB, but these still refer to it as if it exists:$PHANTOM" \
        "The Tarantool schema is defined once, in deploy/tarantool/init.lua. Either restore the constant or fix the reference — a migration plan that expects two files budgets for work that does not exist."
    else
      pass "no INIT_SCRIPT in the code, and nothing claims otherwise"
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "turnactl: POST /manage has a server, or the header says it does not"
# ---------------------------------------------------------------------------

# Seven of turnactl's eleven documented commands POST to /manage, and nothing
# serves that path: the health server routes six GETs and no /manage, and the
# `("POST", "/manage")` handler in turna_management belongs to a server with no
# callers. The failure text sends the operator to debug their deployment.
#
# Two-way. If somebody starts that server, the header's warning becomes the false
# claim and has to go.
TURNACTL=tools/turnactl/src/main.rs
if [ -f "$TURNACTL" ] && [ -f "$HEALTH" ]; then
  # A real caller means `integration::serve` or ManagementServer referenced from
  # outside the management crate, on a non-comment line — the same distinction the
  # Helm control-plane check needed, for the same reason.
  SERVED=0
  if grep -rqE '^[^/]*\b(ManagementServer|integration::serve)\b' \
       --include='*.rs' services crates tools 2>/dev/null \
     && ! grep -rlE '^[^/]*\b(ManagementServer|integration::serve)\b' \
       --include='*.rs' services crates tools 2>/dev/null |
       grep -qxv 'crates/management/src/lib.rs'; then
    SERVED=0
  fi
  grep -qE '"/manage"' "$HEALTH" && SERVED=1
  if [ "$SERVED" = 1 ]; then
    if grep -q 'nothing serves that path' "$TURNACTL"; then
      fail "/manage now has a server, but turnactl's header still says nothing serves it" \
        "Remove the warning — it has become the inaccurate claim."
    else
      pass "/manage is served and the turnactl header does not deny it"
    fi
  else
    if grep -q 'nothing serves that path' "$TURNACTL"; then
      pass "no /manage server, and turnactl's header says which commands work"
    else
      fail "turnactl documents commands that POST to /manage, which nothing serves" \
        "Seven of its eleven commands fail against a healthy node, with an error blaming the deployment. Say so in the header, or start the server. See docs/OPEN-DECISIONS.md decision 8."
    fi
  fi
fi

# ---------------------------------------------------------------------------
section "Admin UI sends only commands the admin service handles"
# ---------------------------------------------------------------------------

# The UI and the service meet over JSON — `POST /api/manage` with a command name
# — so nothing compiles the two together. A renamed command is a button that
# returns an error at runtime and nowhere else. Same boundary that let the Python
# SDK drift, minus a compiler on either side.
#
# Commands only. Their PARAMETERS are deliberately not checked here: the service
# reads some through helpers (`u32_limit(params, "max_allocations")`) rather than
# `params["..."]`, and an extractor that missed those reported a false positive
# on the first attempt. A gate that cries wolf gets ignored, which is worse than
# the gap it covers. The frontend's TypeScript already makes the required ones
# non-optional.
ADMIN_RS=services/admin/src/grpc_client.rs
ADMIN_FE=services/admin/frontend/src
if [ -f "$ADMIN_RS" ] && [ -d "$ADMIN_FE" ]; then
  ADMIN_BAD=$(python3 - "$ADMIN_RS" "$ADMIN_FE" <<'ADMINPY'
import glob, os, re, sys
rs, fe_dir = sys.argv[1], sys.argv[2]
handled = set(re.findall(r'^\s+"([a-z_]+\.[a-z_]+|ping)" =>', open(rs).read(), re.M))
fe = "".join(open(f, encoding="utf-8").read()
             for f in glob.glob(os.path.join(fe_dir, "**", "*.ts*"), recursive=True))
sent = set(re.findall(r"postManage(?:<[^>]*>)?\(\s*'([a-z_.]+)'", fe))
if not handled or not sent:
    print("PARSER handled=%d sent=%d" % (len(handled), len(sent))); raise SystemExit(0)
print(" ".join(sorted(sent - handled)))
ADMINPY
)
  case "$ADMIN_BAD" in
    PARSER*) fail "the admin command extractor is broken (${ADMIN_BAD#PARSER })" \
               "It found nothing on one side, so this check would pass over any drift. Fix the extractor." ;;
    "") pass "every command the admin UI sends is handled by the service" ;;
    *) fail "the admin UI sends commands the service does not handle:$ADMIN_BAD" \
         "These are buttons that fail at runtime. Rename on one side or add the handler. (The reverse — a handler with no button — is fine: the API is allowed to be wider than the UI.)" ;;
  esac
fi

# ---------------------------------------------------------------------------
section "Python SDK matches management.proto"
# ---------------------------------------------------------------------------

# The SDK is shipped for operators and nothing compiled it against the proto, so
# it drifted silently: `ListAllocations` was sent `limit` (the field is
# `page_size`), `SetDraining` a `reason` it has no field for, `DeleteAllocation`
# an `allocation_id` (the field is `id`), and `SetUserLimits` a `username` that is
# `reserved` — retired when that request was restructured. Four of its methods
# raised ValueError from protobuf before the call left the process.
#
# AST-based, not grep: a nested `pb.UserLimitTarget(...)` inside a request
# constructor has its own field set, and a flat regex reports its keywords as
# belonging to the outer message. That false positive cost a round here.
SDK=tools/sdk/python/turna_sdk.py
PROTO_FILE=crates/control/proto/management.proto
if [ -f "$SDK" ] && [ -f "$PROTO_FILE" ]; then
  SDK_BAD=$(python3 - "$SDK" "$PROTO_FILE" <<'SDKPY'
import ast, re, sys
sdk_path, proto_path = sys.argv[1], sys.argv[2]
proto = open(proto_path).read()
msgs, reserved = {}, {}
for m in re.finditer(r"message (\w+)\s*\{(.*?)\n\}", proto, re.S):
    body = m.group(2)
    msgs[m.group(1)] = set(re.findall(r"(?:optional\s+|repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+", body))
    reserved[m.group(1)] = set(re.findall(r'"(\w+)"', " ".join(re.findall(r"reserved[^;]*;", body))))
for m in re.finditer(r"message (\w+)\s*\{([^{}]*)\}", proto):
    msgs.setdefault(m.group(1), set())
    msgs[m.group(1)] |= set(re.findall(r"(?:optional\s+|repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+", m.group(2)))
enums = set()
for m in re.finditer(r"enum \w+\s*\{(.*?)\n\}", proto, re.S):
    enums |= set(re.findall(r"(\w+)\s*=\s*\d+", m.group(1)))
rpcs = set(re.findall(r"rpc (\w+)\(", proto))
if len(msgs) < 10 or not rpcs:
    print("PARSER proto yielded %d messages / %d rpcs" % (len(msgs), len(rpcs))); raise SystemExit(0)
try:
    tree = ast.parse(open(sdk_path).read())
except SyntaxError as e:
    print("SYNTAX %s" % e); raise SystemExit(0)
bad = []
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
       and isinstance(node.func.value, ast.Name) and node.func.value.id == "pb":
        typ = node.func.attr
        if typ not in msgs:
            continue
        for k in node.keywords:
            if not k.arg:
                continue
            if k.arg not in msgs[typ]:
                bad.append("L%d:%s.%s(absent)" % (node.lineno, typ, k.arg))
            elif k.arg in reserved.get(typ, set()):
                bad.append("L%d:%s.%s(reserved)" % (node.lineno, typ, k.arg))
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
       and node.value.id == "pb" and node.attr.isupper():
        if node.attr not in enums and node.attr not in msgs:
            bad.append("L%d:pb.%s(no such enum)" % (node.lineno, node.attr))
for node in ast.walk(tree):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) \
       and node.value.attr == "_stub" and node.attr not in rpcs:
        bad.append("L%d:rpc %s" % (node.lineno, node.attr))
print(" ".join(sorted(set(bad))))
SDKPY
)
  case "$SDK_BAD" in
    PARSER*) fail "the proto extractor for the SDK check is broken (${SDK_BAD#PARSER })" \
               "It parsed too little to judge anything, so this check would pass over real drift." ;;
    SYNTAX*) fail "$SDK is not valid Python (${SDK_BAD#SYNTAX })" "Fix the file; the check cannot inspect it." ;;
    "") pass "every pb field, enum and rpc the SDK names exists in the proto" ;;
    *) fail "the SDK names proto fields/rpcs that do not exist:$SDK_BAD" \
         "protobuf raises ValueError on an unknown field, so these methods fail before the call leaves the process. A 'reserved' field was retired deliberately — read the comment on it in $PROTO_FILE." ;;
  esac
fi

# ---------------------------------------------------------------------------
section "Grafana dashboard panels reference metrics that exist"
# ---------------------------------------------------------------------------

# The alert rules already get this check. The dashboard did not, and it is the
# artefact an operator imports and then trusts: a panel whose metric was renamed
# does not error, it draws an empty graph. "No data" and "nothing happening" look
# identical on a wall display.
DASH=deploy/grafana/turna-overview.json
if [ -f "$DASH" ] && [ -f "$HEALTH" ]; then
  DASH_MISSING=$(python3 - "$DASH" "$HEALTH" <<'DASHPY'
import json, re, sys
dash, health = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(dash))
except Exception as e:
    print("UNPARSEABLE " + str(e)); raise SystemExit(0)
exprs = []
def walk(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "expr" and isinstance(v, str):
                exprs.append(v)
            else:
                walk(v)
    elif isinstance(o, list):
        for i in o:
            walk(i)
walk(d)
if not exprs:
    print("NOEXPRS"); raise SystemExit(0)
src = open(health).read()
names = set()
for e in exprs:
    names |= set(re.findall(r"\bturna_[a-z0-9_]+", e))
missing = []
for n in names:
    # A histogram panel references _bucket/_sum/_count; the crate exports the base.
    base = re.sub(r"_(bucket|sum|count)$", "", n)
    if base not in src:
        missing.append(n)
print(" ".join(sorted(missing)))
DASHPY
)
  case "$DASH_MISSING" in
    UNPARSEABLE*) fail "$DASH is not valid JSON" "Grafana will refuse the import. ${DASH_MISSING#UNPARSEABLE }" ;;
    NOEXPRS) fail "no PromQL expressions found in $DASH" "The extractor found nothing, so this check would pass over any drift. Fix the extractor, not the dashboard." ;;
    "") pass "every dashboard metric is exported by turna-health" ;;
    *) fail "dashboard panels reference metrics that do not exist:$DASH_MISSING" \
         "Rename them in $DASH or restore the metric. A stale panel draws an empty graph, which reads as 'nothing happening'." ;;
  esac
fi

# ---------------------------------------------------------------------------
section "Shipped configs use only keys the config structs declare"
# ---------------------------------------------------------------------------

# `TurnaConfig` and its sections are `#[serde(deny_unknown_fields)]`, so a key
# that no longer exists is not ignored — the node refuses to start. A stale key in
# a shipped config or an example is therefore a startup failure waiting for
# whoever copies it, and nothing else here would catch it.
CFG_SRC=crates/config/src/lib.rs
if [ -f "$CFG_SRC" ]; then
  # The Helm ConfigMap is included as a pseudo-config: its keys are literal in the
  # template even though its values are Go-template expressions, so they can be
  # checked without rendering. CI renders and parses it for real (default AND
  # production-example values), but only on the packaging job — this catches a bad
  # key in the fast gate, and on a machine with no helm.
  # deploy/examples/public.toml — NOT public-turn.toml, which is what this list
  # said until 0.5.0. The extractor skips a path that does not exist, so the one
  # public-facing example went unchecked while the section reported a clean pass.
  # Missing files are now an explicit failure below rather than a silent skip.
  CFG_BAD=$(python3 - "$CFG_SRC" turn.toml deploy/turn.toml bench/turna.toml bench/smoke-tarantool.toml \
    deploy/examples/public.toml deploy/examples/corporate.toml deploy/examples/cluster.toml <<'CFGPY'
import os, re, sys, tomllib
src = open(sys.argv[1]).read()
known = set()
for m in re.finditer(r"pub struct \w+\s*\{(.*?)\n\}", src, re.S):
    body = m.group(1)
    for fm in re.finditer(r'(?:#\[serde\(rename\s*=\s*"([^"]+)"\)\][^\n]*\n\s*)?pub (?:r#)?(\w+)\s*:', body):
        known.add(fm.group(1) or fm.group(2))
if len(known) < 50:
    print("PARSER only " + str(len(known)) + " fields extracted"); raise SystemExit(0)

def keys(d):
    out = set()
    for k, v in d.items():
        out.add(k)
        if isinstance(v, dict):
            out |= keys(v)
        elif isinstance(v, list):
            for it in v:
                if isinstance(it, dict):
                    out |= keys(it)
    return out

bad = []

# The Helm ConfigMap: keys are literal, values are Go-template expressions, so it
# cannot be parsed as TOML. Check the key names directly instead of skipping it —
# it is the production deployment path.
HELM_TPL = "deploy/helm/turna/templates/configmap.yaml"
if os.path.isfile(HELM_TPL):
    tpl = open(HELM_TPL).read()
    # A missing marker is a FAILURE, not a skip. The first version of this treated
    # "turn.toml: |" being absent as "nothing to check" and passed — so renaming
    # the ConfigMap key would have silently disabled the check instead of failing
    # it. Same shape as every other bug this script exists to catch.
    if "turn.toml: |" not in tpl:
        bad.append(HELM_TPL + "(no 'turn.toml: |' block — extractor or template changed)")
    else:
        block = tpl.split("turn.toml: |", 1)[1]
        names = set(re.findall(r"^\s{4,}([a-z_][a-z0-9_]*)\s*=", block, re.M))
        for s in re.findall(r"^\s{4,}\[\[?([a-z_.]+)\]\]?", block, re.M):
            names |= set(s.split("."))
        if not names:
            bad.append(HELM_TPL + "(extracted no keys)")
        for k in sorted(names - known):
            bad.append(HELM_TPL + ":" + k)

for path in sys.argv[2:]:
    if not os.path.isfile(path):
        # A silent skip is how deploy/examples/public.toml went unchecked for
        # months under a misspelled path. If a shipped config moves, this check
        # has to say so rather than quietly cover one file fewer.
        bad.append(path + "(listed here but not on disk — fix the path or drop it)")
        continue
    raw = open(path).read()
    # ${VAR:-default} placeholders are not TOML; substitute so the file parses.
    raw = re.sub(r"\$\{[A-Za-z0-9_]+(?::-([^}]*))?\}", lambda m: m.group(1) or "x", raw)
    try:
        d = tomllib.loads(raw)
    except Exception as e:
        bad.append(path + "(unparseable: " + str(e) + ")")
        continue
    for k in sorted(keys(d) - known):
        bad.append(path + ":" + k)
print(" ".join(bad))
CFGPY
)
  case "$CFG_BAD" in
    PARSER*) fail "the config-struct field extractor is broken (${CFG_BAD#PARSER })" \
               "It found too few fields to judge anything, so this check would pass over real drift." ;;
    "") pass "shipped configs use only declared keys" ;;
    *) fail "shipped configs carry keys no config struct declares:$CFG_BAD" \
         "deny_unknown_fields makes these fatal at startup, not ignored. Remove the key or restore the field." ;;
  esac
fi

# ---------------------------------------------------------------------------
section "coturn migration table names only config keys that exist"
# ---------------------------------------------------------------------------

# docs/migrating-from-coturn.md maps every coturn option to a turna key. A key
# that is misspelled or later renamed turns the table into instructions that
# fail at startup (deny_unknown_fields). This resolves every `[section] key` in
# the table's turna column against the config structs *by path* — not just by
# field name, so `[management.rbac]` (the struct field lives under [grpc]) fails
# even though a field called `rbac` exists somewhere.
MIG=docs/migrating-from-coturn.md
if [ -f "$MIG" ] && [ -f "$CFG_SRC" ]; then
  MIG_BAD=$(python3 - "$CFG_SRC" "$MIG" <<'MIGPY'
import re, sys
src, doc = open(sys.argv[1]).read(), open(sys.argv[2]).read()
structs = {}
for m in re.finditer(r"pub struct (\w+)\s*\{(.*?)\n\}", src, re.S):
    fields = {}
    for fm in re.finditer(r'(?:#\[serde\(rename\s*=\s*"([^"]+)"\)\][^\n]*\n\s*)?pub (?:r#)?(\w+)\s*:\s*([^\n]+?),?\s*$', m.group(2), re.M):
        fields[fm.group(1) or fm.group(2)] = fm.group(3)
    structs[m.group(1)] = fields
if "TurnaConfig" not in structs or len(structs) < 20:
    print("PARSER"); raise SystemExit(0)

def child(struct, field):
    ty = structs.get(struct, {}).get(field)
    if ty is None:
        return None, False
    inner = [t for t in re.findall(r"\w+", ty) if t in structs]
    return (inner[-1] if inner else ""), True

def resolve(path):
    cur = "TurnaConfig"
    for seg in path:
        cur, ok = child(cur, seg)
        if not ok:
            return None
    return cur

bad, seen = [], 0
for line in doc.splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) < 3 or not cells[0].startswith("`"):
        continue
    section = None
    for tok in re.findall(r"`([^`]+)`", cells[1]):
        m = re.match(r"^\[\[?([a-z0-9_.]+)\]\]?(?:\s+([a-z0-9_]+))?$", tok)
        if m:
            section = m.group(1)
            st = resolve(section.split("."))
            if st is None:
                bad.append("[" + section + "]"); section = None; continue
            if m.group(2):
                seen += 1
                if m.group(2) not in structs.get(st, {}):
                    bad.append("[" + section + "] " + m.group(2))
        elif section and re.match(r"^[a-z0-9_]+$", tok):
            seen += 1
            st = resolve(section.split("."))
            if tok not in structs.get(st, {}):
                bad.append("[" + section + "] " + tok)
if seen < 30:
    print("PARSER"); raise SystemExit(0)
print("; ".join(bad))
MIGPY
)
  case "$MIG_BAD" in
    PARSER) fail "the migration-table key extractor found too little to judge" \
              "Either the table format or the config structs changed shape; fix the extractor rather than skipping the check." ;;
    "") pass "every turna key in the coturn mapping table exists at its path" ;;
    *) fail "the coturn mapping table names keys the config does not have: $MIG_BAD" \
         "Correct the row in $MIG (or restore the key); an operator copying it gets a startup failure." ;;
  esac
fi

# ---------------------------------------------------------------------------
section "SIGHUP: docs must not deny a handler the node has"
# ---------------------------------------------------------------------------

# Four documents stated, from a dated measurement, that SIGHUP was not handled
# and that the shared secret therefore needed a restart. When the handler landed
# those became false in the direction that costs an operator real work: planning
# a rolling restart for something that is now a config reload.
#
# Direction matters. This fails only when the code HAS a handler and a doc still
# denies it. A dated verification run may keep its original wording — that is what
# a run report is — provided it carries a marker saying the finding was later
# fixed, which is why runs-*.md is exempted by that marker rather than by name.
NODE_MAIN=services/node/src/main.rs
if [ -f "$NODE_MAIN" ]; then
  if grep -q 'SignalKind::hangup()' "$NODE_MAIN"; then
    STALE=""
    # README.md included: it carried "SIGHUP is not handled" for the whole life
    # of this check, one directory outside its reach, and that is the line an
    # operator reads before planning a rolling restart.
    for d in $(grep -rl 'SIGHUP' docs README.md --include='*.md' 2>/dev/null); do
      # Exempt a report that already flags itself as superseded.
      grep -q 'FIXED SINCE' "$d" && continue
      if grep -qE 'does not handle SIGHUP|SIGHUP. is not handled|SIGHUP is not handled' "$d"; then
        STALE="$STALE $d"
      fi
    done
    if [ -n "$STALE" ]; then
      fail "the node handles SIGHUP, but these docs still say it does not:$STALE" \
        "Update them. An operator reading this plans a rolling restart for what is now a config reload."
    else
      pass "no doc denies the SIGHUP handler the node has"
    fi
  else
    pass "no SIGHUP handler in the node; nothing for docs to contradict"
  fi
fi

# ---------------------------------------------------------------------------
section "tests/README.md tells people the command CI actually runs"
# ---------------------------------------------------------------------------

# The README said `cargo test --workspace --all-features`. That enables the
# AF_XDP dependency graph, which crates/transport/build.rs refuses to build on a
# non-Linux target — so the documented way to run the suite ended in a panic on
# macOS, after a long compile. On Linux it needs native inputs the plain test job
# does not install, and CI only ever `check`s that configuration, never tests it.
TREADME=tests/README.md
CI_YML=.github/workflows/ci.yml
if [ -f "$TREADME" ] && [ -f "$CI_YML" ]; then
  # The `test` job's command, whatever it currently is.
  CI_TEST_CMD=$(grep -oE 'cargo test --workspace[^"]*' "$CI_YML" | head -1)
  if [ -z "$CI_TEST_CMD" ]; then
    fail "no 'cargo test --workspace' command found in $CI_YML" \
      "The extraction broke, so this check would pass over any drift. Fix the grep, not the workflow."
  elif grep -qF "$CI_TEST_CMD" "$TREADME"; then
    pass "$TREADME documents the CI command ($CI_TEST_CMD)"
  else
    fail "$TREADME does not document the command CI runs" \
      "CI runs '$CI_TEST_CMD'. Make the README match it — a contributor who follows the README must get the same result as the gate."
  fi
fi

# ---------------------------------------------------------------------------
section "Test fixtures: ci.yml and .env.test.example agree"
# ---------------------------------------------------------------------------

# The auth and processor suites read their fixtures from the environment. The
# canonical values live in ci.yml's `env:` block, so CI was green while a fresh
# clone failed five turna-relay tests with "is not set — source .env.test" — and
# `.env.test` is gitignored and never generated, so the error message pointed at
# a file nobody could obtain. `.env.test.example` is the tracked copy that closes
# that, and this check keeps the two from drifting: a value added to CI but not
# to the example puts the repository straight back into the state above.
EXAMPLE=.env.test.example
if [ -f "$EXAMPLE" ] && [ -f .github/workflows/ci.yml ]; then
  # Normalised separately on purpose. The ci.yml form is `  NAME: value`, so the
  # FIRST colon is the separator — sed replaces one occurrence, which keeps
  # values that themselves contain a colon (a host:port, a malformed nonce)
  # intact. The example form is already `NAME=value` and must NOT go through that
  # substitution, or the colon inside the value would be eaten.
  CI_ENV=$(sed -n '/^env:/,/^[^ #]/p' .github/workflows/ci.yml |
    grep -E '^  TURNA_TEST_[A-Z0-9_]+:' |
    sed -E 's/^[[:space:]]+//; s/:[[:space:]]*/=/' |
    sed -E 's/="(.*)"$/=\1/' | sort)
  EX_ENV=$(grep -E '^TURNA_TEST_[A-Z0-9_]+=' "$EXAMPLE" |
    sed -E 's/="(.*)"$/=\1/' | sort)
  if [ -z "$CI_ENV" ]; then
    fail "no TURNA_TEST_* variables found in ci.yml's env: block" \
      "The parser found nothing, so this check would pass over any drift. Fix the extraction rather than the workflow."
  elif [ "$CI_ENV" = "$EX_ENV" ]; then
    pass "every CI test fixture is mirrored in $EXAMPLE ($(grep -c '^TURNA_TEST_' "$EXAMPLE") variables)"
  else
    fail "ci.yml and $EXAMPLE disagree about the test fixtures" \
      "Run: diff <(sed -n '/^env:/,/^[^ #]/p' .github/workflows/ci.yml | grep -E '^  TURNA_TEST_') $EXAMPLE — then make the example match CI. A fixture only in CI means a fresh clone cannot run the suite."
  fi
fi

# ---------------------------------------------------------------------------
section "Management proto: field numbers keep their meaning"
# ---------------------------------------------------------------------------

# Delegated to its own script because the parsing is substantial, but reported
# here so one command still covers everything. A contract the Conference product
# is about to bind to should not need a separate habit to check.
if [ -x scripts/check-proto-compat.sh ]; then
  if OUT=$(scripts/check-proto-compat.sh 2>&1); then
    pass "wire contract unchanged ($(printf '%s' "$OUT" | tail -1))"
  else
    fail "management.proto changed incompatibly" \
      "Run scripts/check-proto-compat.sh for the detail. A field number that changes meaning is misread by existing clients with no error on either side."
  fi
fi

# ---------------------------------------------------------------------------
printf '\ncheck-doc-claims: %d checks, %d failed\n' "$CHECKS" "$FAILED"
[ "$FAILED" -eq 0 ] || {
  echo "check-doc-claims: FAIL — documentation and code disagree (see above)" >&2
  exit 1
}
echo "check-doc-claims: OK — documented claims match the code"
