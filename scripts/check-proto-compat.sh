#!/usr/bin/env bash
#
# Wire-compatibility gate for crates/control/proto/management.proto.
#
# A gRPC contract does not break when the file is edited. It breaks when a field
# *number* changes meaning: a client compiled against the old definition decodes
# field 7 as whatever it was told field 7 is, and if the server has since changed
# its type or reused it, the client misreads the bytes with no error anywhere.
# Protobuf's wire format has no version check to catch that.
#
# So this records number/name/type per message and fails on change or removal.
# Additions pass — they are how a contract is supposed to grow.
#
#   scripts/check-proto-compat.sh            # verify
#   scripts/check-proto-compat.sh --accept   # record an intentional change
#
# The baseline lives in crates/control/proto/COMPAT_BASELINE and is committed.
# A diff in review is the point: it is the moment somebody decides whether a
# change is safe, and a silent regeneration would remove that moment.

set -uo pipefail

PROTO=crates/control/proto/management.proto
BASELINE=crates/control/proto/COMPAT_BASELINE

[ -f "$PROTO" ] || { echo "proto not found: $PROTO" >&2; exit 1; }

# One line per field: MessageName field_number field_name type
#
# Handles both block messages and the single-line form this file uses heavily
# (`message Foo { string id = 1; string reason = 2; }`), which a naive
# line-oriented pass would miss entirely — and missing them silently would make
# this gate worse than absent, since it would report success over a third of the
# contract.
extract() {
  tr '\n' ' ' < "$PROTO" |
  sed 's/\/\/[^{}]*//g' |
  grep -oE 'message[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\{[^{}]*\}' |
  while read -r block; do
    msg=$(printf '%s' "$block" | sed -E 's/^message[[:space:]]+([A-Za-z0-9_]+).*/\1/')
    printf '%s' "$block" |
      sed 's/^[^{]*{//; s/}$//' |
      tr ';' '\n' |
      grep -E '=[[:space:]]*[0-9]+' |
      grep -vE '^[[:space:]]*(reserved|option)' |
      while read -r f; do
        num=$(printf '%s' "$f" | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/')
        name=$(printf '%s' "$f" | sed -E 's/[[:space:]]*=[[:space:]]*[0-9]+.*//' |
               awk '{print $NF}')
        typ=$(printf '%s' "$f" | sed -E 's/[[:space:]]*=[[:space:]]*[0-9]+.*//' |
              awk '{$NF=""; print}' | tr -s ' ' | sed 's/ $//; s/^ //')
        [ -n "$name" ] && printf '%s %s %s %s\n' "$msg" "$num" "$name" "$typ"
      done
  done | sort -u
}

CURRENT=$(extract)

if [ -z "$CURRENT" ]; then
  echo "FAIL: extracted no fields from $PROTO." >&2
  echo "      The parser found nothing, which means it is broken rather than the" >&2
  echo "      contract being empty. Refusing to write an empty baseline: that" >&2
  echo "      would make every future change pass." >&2
  exit 1
fi

if [ "${1:-}" = "--accept" ]; then
  printf '%s\n' "$CURRENT" > "$BASELINE"
  echo "baseline written: $(printf '%s\n' "$CURRENT" | wc -l | tr -d ' ') fields"
  echo "Commit it. The diff is where somebody decides the change was safe."
  exit 0
fi

if [ ! -f "$BASELINE" ]; then
  printf '%s\n' "$CURRENT" > "$BASELINE"
  echo "no baseline; created one with $(printf '%s\n' "$CURRENT" | wc -l | tr -d ' ') fields"
  echo "Commit $BASELINE. Future runs compare against it."
  exit 0
fi

# Changed or vanished: present in the baseline, absent now, matched by
# message+number. That is exactly the case a client cannot detect.
BROKEN=""
while read -r msg num name typ; do
  [ -z "$msg" ] && continue
  if ! printf '%s\n' "$CURRENT" | grep -qxF "$msg $num $name $typ"; then
    now=$(printf '%s\n' "$CURRENT" | awk -v m="$msg" -v n="$num" \
          '$1==m && $2==n {$1="";$2="";print}' | tr -s ' ' | sed 's/^ //')
    if [ -z "$now" ]; then
      BROKEN="$BROKEN\n  $msg field $num ($name $typ) removed — reserve the number instead"
    else
      BROKEN="$BROKEN\n  $msg field $num was ($name $typ), now ($now)"
    fi
  fi
done <<EOF
$(cat "$BASELINE")
EOF

ADDED=$(printf '%s\n' "$CURRENT" | grep -vxF -f "$BASELINE" | wc -l | tr -d ' ')

if [ -n "$BROKEN" ]; then
  echo "check-proto-compat: FAIL — the wire contract changed incompatibly" >&2
  printf '%b\n' "$BROKEN" >&2
  cat >&2 <<'HELP'

A client built against the old definition will misread these fields with no
error: protobuf carries no version marker, so the bytes decode either way.

If the change is wrong, restore the field number and add a new one instead.
If it is deliberate — a field genuinely retired — mark the number `reserved` so
it can never come back, and re-record the baseline:

  scripts/check-proto-compat.sh --accept

UpdateConfigRequest already has `reserved 1 to 4` from exactly this situation.
HELP
  exit 1
fi

echo "check-proto-compat: OK — $(printf '%s\n' "$CURRENT" | wc -l | tr -d ' ') fields unchanged, $ADDED added"
