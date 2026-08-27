#!/usr/bin/env bash
#
# Compare this machine's capacity against its own committed baseline.
#
#   scripts/verify/capacity-regression.sh                 # compare
#   scripts/verify/capacity-regression.sh --accept        # record a new baseline
#
# §12's performance-regression item.
#
# WHY THIS IS NOT A CI JOB
#
# The obvious shape would be a gate on every pull request. It does not work.
# GitHub's hosted runners are shared two-core VMs, and a packet-rate measurement
# there varies between runs by more than any regression worth catching. A gate
# that fails half the time for reasons unrelated to the code is a gate people
# learn to re-run until it passes, which is worse than not having it: it consumes
# attention and produces no signal.
#
# So the comparison is per machine, against a baseline recorded on that machine,
# and it runs where the baseline was made — a self-hosted runner, or by hand
# before a release. `.github/workflows/capacity.yml` in this archive is the
# scheduled form for a self-hosted runner; it is deliberately not wired to
# pull_request.
#
# WHAT THE BASELINE FILE IS
#
# `docs/capacity/baselines.tsv`, one line per machine:
#
#   <machine-id>	<pps>	<date>	<commit>
#
# Machine identity is CPU model plus core count plus kernel major.minor. Not the
# hostname: a hostname survives a hardware change and a baseline compared across
# different hardware is the same mistake as comparing across runners, just
# slower to notice.
#
# TOLERANCE
#
# 10 % below baseline fails. The capacity profiler's own bisection resolves to
# about 12 % of the true edge, so a tighter bound would be measuring the
# measurement. A regression smaller than that is invisible to this method and
# saying so is better than pretending otherwise.

set -uo pipefail

MODE="compare"
TOLERANCE_PCT="${TOLERANCE_PCT:-10}"
PROFILE_ARGS="${PROFILE_ARGS:---phase-secs 120}"

while [ $# -gt 0 ]; do
  case "$1" in
    --accept) MODE="accept"; shift ;;
    --tolerance) TOLERANCE_PCT="$2"; shift 2 ;;
    --profile-args) PROFILE_ARGS="$2"; shift 2 ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO" || exit 1
BASELINES="docs/capacity/baselines.tsv"

[ "$(uname -s)" = "Linux" ] || {
  echo "Linux only: the capacity profiler needs taskset, and a figure from" >&2
  echo "another platform would not be comparable with a Linux baseline anyway." >&2
  exit 2
}

# Machine identity. CPU model, cores, kernel major.minor — the three things that
# move a packet-rate ceiling. A hostname would survive a CPU swap and produce a
# comparison across different hardware, which is the failure this whole script is
# arranged to avoid.
machine_id() {
  local cpu cores kern
  cpu=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- |
        sed 's/^ *//; s/ \+/ /g; s/ /_/g')
  cores=$(nproc)
  kern=$(uname -r | cut -d. -f1,2)
  printf '%s-%sc-k%s' "${cpu:-unknown}" "$cores" "$kern"
}

MID="$(machine_id)"
echo "machine: $MID"

# ── measure ───────────────────────────────────────────────────────────────
echo "running the capacity profiler ($PROFILE_ARGS)"
# shellcheck disable=SC2086
if ! scripts/verify/capacity-profile.sh $PROFILE_ARGS > /tmp/cap-reg.log 2>&1; then
  echo
  echo "the profiler failed or found no passing rate. Its output:" >&2
  tail -25 /tmp/cap-reg.log >&2
  exit 1
fi

LATEST_DIR=$(ls -td capacity-* 2>/dev/null | head -1)
[ -n "$LATEST_DIR" ] || { echo "no capacity-* directory produced" >&2; exit 1; }

# The ceiling, from the profile rather than re-derived from the phases: the
# profiler owns the definition, including the bisection and the retry rule, and a
# second parser here would eventually disagree with it.
PPS=$(grep -oE '\*\*(At least )?[0-9]+ relayed packets/second\*\*' "$LATEST_DIR/profile.md" 2>/dev/null |
      grep -oE '[0-9]+' | head -1)
LOWER_BOUND_ONLY=$(grep -c 'At least' "$LATEST_DIR/profile.md" 2>/dev/null || echo 0)

[ -n "$PPS" ] || {
  echo "could not read a ceiling from $LATEST_DIR/profile.md" >&2
  exit 1
}
echo "measured: $PPS pps"

if [ "${LOWER_BOUND_ONLY:-0}" != "0" ]; then
  echo
  echo "The profiler stopped at its --max-pps rather than at a failure, so this is" >&2
  echo "a lower bound and not a measurement. Comparing a lower bound against a" >&2
  echo "baseline would report a regression that may not exist, or hide one that" >&2
  echo "does. Re-run with a higher --max-pps." >&2
  exit 1
fi

# ── accept ────────────────────────────────────────────────────────────────
if [ "$MODE" = "accept" ]; then
  mkdir -p "$(dirname "$BASELINES")"
  touch "$BASELINES"
  COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
  # Rewrite this machine's line, leave others. A file per machine would avoid the
  # rewrite and make a fleet's baselines invisible to each other, which is worse
  # — somebody comparing two machines wants both numbers in one place.
  TMP=$(mktemp)
  grep -v "^${MID}	" "$BASELINES" > "$TMP" 2>/dev/null || true
  printf '%s\t%s\t%s\t%s\n' "$MID" "$PPS" "$(date -u +%F)" "$COMMIT" >> "$TMP"
  sort -o "$BASELINES" "$TMP"
  rm -f "$TMP"
  echo
  echo "baseline recorded: $MID = $PPS pps at $COMMIT"
  echo "Commit $BASELINES. The diff in review is where somebody decides whether a"
  echo "changed ceiling was intended."
  exit 0
fi

# ── compare ───────────────────────────────────────────────────────────────
if [ ! -f "$BASELINES" ]; then
  echo
  echo "no baseline file. Record one:"
  echo "  scripts/verify/capacity-regression.sh --accept"
  exit 0
fi

BASE_LINE=$(grep "^${MID}	" "$BASELINES" | head -1)
if [ -z "$BASE_LINE" ]; then
  echo
  echo "no baseline for this machine. Others on record:"
  cut -f1,2 "$BASELINES" | sed 's/^/  /'
  echo
  echo "A ceiling is not comparable across hardware, so this is not a failure —"
  echo "record one for this machine:"
  echo "  scripts/verify/capacity-regression.sh --accept"
  exit 0
fi

BASE_PPS=$(printf '%s' "$BASE_LINE" | cut -f2)
BASE_DATE=$(printf '%s' "$BASE_LINE" | cut -f3)
BASE_COMMIT=$(printf '%s' "$BASE_LINE" | cut -f4)

DELTA_PCT=$(python3 -c "print(f'{($PPS - $BASE_PPS) / $BASE_PPS * 100:+.1f}')")
FLOOR=$(python3 -c "print(int($BASE_PPS * (1 - $TOLERANCE_PCT / 100)))")

echo
echo "baseline: $BASE_PPS pps ($BASE_DATE, $BASE_COMMIT)"
echo "measured: $PPS pps ($DELTA_PCT%)"
echo "floor:    $FLOOR pps (baseline less ${TOLERANCE_PCT}%)"
echo

if [ "$PPS" -lt "$FLOOR" ]; then
  cat >&2 <<EOF
REGRESSION: $PPS pps is below the floor of $FLOOR.

Before assuming it is the code, rule out the machine. A capacity figure moves with
anything that competes for cores, and this measurement puts the load generator on
the same host — another process, a different kernel, a changed CPU governor, or
thermal throttling all show up here as a regression.

  * was anything else running? the profiler pins cores but does not own the machine
  * has the kernel changed? the baseline records only major.minor
  * cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor

If the machine is unchanged, the profile in $LATEST_DIR has the phase-by-phase
numbers. The shape matters as much as the ceiling: a cliff that moved down is a
different problem from a curve that became a slope.

If the drop is intended — a feature that costs throughput, knowingly — record the
new baseline:
  scripts/verify/capacity-regression.sh --accept
EOF
  exit 1
fi

if [ "$PPS" -gt "$BASE_PPS" ]; then
  IMPROVE=$(python3 -c "print(f'{($PPS - $BASE_PPS) / $BASE_PPS * 100:.1f}')")
  echo "OK — and ${IMPROVE}% above baseline."
  echo
  echo "Worth a look rather than just accepting: an improvement this method cannot"
  echo "explain is sometimes a measurement that got easier, not a server that got"
  echo "faster. Check that the phases still show the same cliff and that errors"
  echo "were zero throughout."
else
  echo "OK — within tolerance."
fi

echo
echo "profile: $LATEST_DIR/profile.md"
