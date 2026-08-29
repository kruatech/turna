#!/usr/bin/env bash
#
# Does the same source produce the same binary twice?
#
# Builds the working tree twice **in different directories** and compares
# hashes. The different directories are the substance: building twice in one
# place holds constant the largest source of divergence — the absolute path
# embedded in panic messages and debug info — and so passes while the property
# does not hold.
#
#   scripts/verify/reproducible-build.sh
#
# Exit 0 when every binary matches, 1 otherwise. Expect 1 on the first run: Rust
# gets close but the ecosystem is not uniformly careful, and a single build script
# that stamps a timestamp is enough. The value here is the list of which binaries
# differ, not the pass.
#
# RUN THIS ON LINUX. The release artifacts are linux/amd64, and macOS cannot pass
# it: Apple's linker embeds an LC_UUID that changes between links, so the binaries
# differ within the first kilobyte no matter what the source does. Verifying
# reproducibility on a platform the project does not ship measures the wrong
# thing — and reports a failure that cannot be fixed, which is worse than not
# running it.
#
# Needs about 4 GB of disk and two full release builds' worth of time.

set -uo pipefail

if [ "$(uname -s)" = "Darwin" ] && [ "${ALLOW_DARWIN:-0}" != "1" ]; then
  cat >&2 <<'WHY'
reproducible-build: refusing to run on macOS.

Apple's linker embeds an LC_UUID that differs between links, so binaries diverge
inside the first kilobyte regardless of the source. The failure is real and
unfixable here, and a check that always fails is one people learn to ignore.

The release builds linux/amd64. Run it there:
  ssh <linux-host> 'cd turna && scripts/verify/reproducible-build.sh'

To see the macOS result anyway:  ALLOW_DARWIN=1 scripts/verify/reproducible-build.sh
WHY
  exit 2
fi

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BINS="turna-node turna-control-plane turnactl"
WORK="${WORK:-$(mktemp -d)}"
KEEP="${KEEP:-0}"

# Two paths of deliberately different length. Same length would leave a
# fixed-size field identical by luck and hide a real difference.
A="$WORK/a"
B="$WORK/build-two-longer-path"

cleanup() { [ "$KEEP" = "1" ] || rm -rf "$WORK"; }
trap cleanup EXIT

echo "reproducible-build: comparing two builds of $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo 'working tree')"
echo "  A: $A"
echo "  B: $B"
echo

# Copy rather than clone: the point is to check the tree as it stands, including
# uncommitted work. Clone would silently test a different thing.
for d in "$A" "$B"; do
  mkdir -p "$d"
  # rsync rather than a `git ls-files | tar` pipeline: bsdtar on macOS rejects
  # the flag combination that version used, and the exclusions here are legible
  # where a tar file-list was not. `target` is excluded because copying a build
  # directory would defeat the exercise — each side must compile from scratch.
  rsync -a --delete \
    --exclude '.git/' --exclude 'target/' --exclude 'fuzz/target/' \
    --exclude '*.zip' --exclude '*.tgz' \
    "$REPO/" "$d/" || {
      echo "FAIL: could not copy the tree to $d" >&2; exit 1; }
done

# Same flags the release build uses, with each directory remapped to nothing so
# the binaries should agree despite the paths differing.
build() {
  local dir="$1"
  ( cd "$dir" &&
    RUSTFLAGS="--remap-path-prefix=$dir= --remap-path-prefix=$HOME/.cargo=" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}" \
    cargo build --locked --release $(for b in $BINS; do printf -- '--bin %s ' "$b"; done) \
      > "$dir/build.log" 2>&1 ) || {
      echo "FAIL: build failed in $dir; last lines:" >&2
      tail -15 "$dir/build.log" >&2
      return 1
    }
}

echo "building A..."
build "$A" || exit 1
echo "building B..."
build "$B" || exit 1
echo

DIFFER=0
SAME=0
for b in $BINS; do
  ha=$(sha256sum "$A/target/release/$b" 2>/dev/null | cut -d' ' -f1)
  hb=$(sha256sum "$B/target/release/$b" 2>/dev/null | cut -d' ' -f1)
  if [ -z "$ha" ] || [ -z "$hb" ]; then
    printf '  %-22s MISSING\n' "$b"
    DIFFER=$((DIFFER + 1))
    continue
  fi
  if [ "$ha" = "$hb" ]; then
    printf '  %-22s identical  %s\n' "$b" "${ha:0:16}"
    SAME=$((SAME + 1))
  else
    printf '  %-22s DIFFERS\n' "$b"
    printf '      A %s\n' "$ha"
    printf '      B %s\n' "$hb"
    DIFFER=$((DIFFER + 1))
    # Where, roughly. Not a diagnosis, but it separates "a timestamp somewhere"
    # from "wholesale divergence", and those need different investigations.
    if command -v cmp >/dev/null; then
      # GNU cmp says "differ: byte N, line M"; BSD cmp says "differ: char N".
      # Matching only the GNU wording printed the whole line instead of a number,
      # which is how this check first reported "first difference at byte
      # /var/folders/...".
      off=$(cmp "$A/target/release/$b" "$B/target/release/$b" 2>/dev/null |
            sed -E 's/.*(byte|char) ([0-9]+).*/\2/')
      sza=$(stat -c%s "$A/target/release/$b" 2>/dev/null ||
            stat -f%z "$A/target/release/$b" 2>/dev/null)
      [ -n "$off" ] && printf '      first difference at byte %s of %s\n' "$off" "$sza"
    fi
  fi
done

echo
if [ "$DIFFER" -eq 0 ]; then
  echo "reproducible-build: OK — $SAME/$SAME binaries reproduce"
  exit 0
fi

echo "reproducible-build: $DIFFER binary(ies) differ"
cat <<'HELP'

This is the expected first result and is worth reading rather than fixing
blindly. Common causes, in the order they usually turn up:

  * a build script embedding a timestamp — SOURCE_DATE_EPOCH is set here, but a
    script has to honour it
  * a dependency embedding its own absolute path; --remap-path-prefix covers the
    workspace and ~/.cargo, not a path a crate constructs itself
  * proc-macro output depending on HashMap iteration order
  * incremental compilation artifacts leaking in; release builds should not, but
    CARGO_INCREMENTAL=0 rules it out

"First difference at byte N of M" separates a small stamp near the start from
wholesale divergence. Those need different investigations.

Keep the trees to look at them:  KEEP=1 scripts/verify/reproducible-build.sh
HELP
exit 1
