#!/usr/bin/env bash
# Regenerate the unsafe-code inventory used by docs/unsafe-audit.md.
#
# Usage:  ./scripts/unsafe-inventory.sh                 # print to stdout
#         ./scripts/unsafe-inventory.sh > /tmp/inv.md   # save to file
#
# Compares current `unsafe` block locations against the audited set. If a new
# `unsafe` block appears in a file that was audited, it must be reviewed and
# documented in docs/unsafe-audit.md.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "# Unsafe inventory — auto-generated"
echo ""
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""
echo "## Counts per crate"
echo ""
echo "| Crate | unsafe occurrences |"
echo "|---|---|"

for crate_dir in crates/*/; do
    crate=$(basename "$crate_dir")
    n=$(grep -rn --include='*.rs' '\bunsafe\b' "$crate_dir" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -gt 0 ]; then
        printf "| %s | %s |\n" "$crate" "$n"
    fi
done

echo ""
echo "## Counts per file (audited crates only)"
echo ""
echo "| File | unsafe occurrences |"
echo "|---|---|"

# These are the files covered by docs/unsafe-audit.md. If a new entry appears
# below that's not in the audit doc, the audit is stale.
AUDITED_PATHS=(
    "crates/transport/src/batch.rs"
    "crates/transport/src/uring.rs"
    "crates/transport/src/hugepages.rs"
    "crates/transport/src/gso.rs"
    "crates/transport/src/worker.rs"
    "crates/transport/src/numa.rs"
    "crates/transport/src/bpf_filter.rs"
    "crates/transport/src/buffer.rs"
    "crates/transport/src/af_xdp.rs"
    "crates/relay/src/processor.rs"
    "crates/relay/src/graceful.rs"
    "crates/relay/src/server.rs"
    "crates/relay/src/splice.rs"
)

for f in "${AUDITED_PATHS[@]}"; do
    if [ -f "$f" ]; then
        n=$(grep -c '\bunsafe\b' "$f" 2>/dev/null || echo 0)
        printf "| %s | %s |\n" "$f" "$n"
    fi
done

echo ""
echo "## New \`unsafe\` outside the audited set"
echo ""

# Find unsafe blocks in files that AREN'T in the audited list — these are
# either new files added since the audit, or stub crates that gained unsafe.
all_unsafe_files=$(grep -rl --include='*.rs' '\bunsafe\b' crates/ services/ 2>/dev/null | sort -u)

found_new=0
for f in $all_unsafe_files; do
    skip=0
    for audited in "${AUDITED_PATHS[@]}"; do
        if [ "$f" = "$audited" ]; then
            skip=1
            break
        fi
    done
    if [ "$skip" = 0 ]; then
        if [ "$found_new" = 0 ]; then
            echo "These files contain \`unsafe\` but are not in docs/unsafe-audit.md."
            echo "Either audit them or add to AUDITED_PATHS here."
            echo ""
            found_new=1
        fi
        echo "- \`$f\` ($(grep -c '\bunsafe\b' "$f") occurrences)"
    fi
done

if [ "$found_new" = 0 ]; then
    echo "(none — all \`unsafe\` code is within audited files)"
fi

echo ""
echo "## SAFETY / NEEDS-REVIEW / SUSPECT marker counts"
echo ""
echo "| Marker | Count |"
echo "|---|---|"
for marker in "SAFETY:" "NEEDS-REVIEW:" "SUSPECT:"; do
    n=$(grep -r --include='*.rs' "// $marker" crates/ 2>/dev/null | wc -l | tr -d ' ')
    printf "| %s | %s |\n" "$marker" "$n"
done
