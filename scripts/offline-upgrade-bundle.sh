#!/usr/bin/env bash
#
# Build an upgrade bundle for an air-gapped host: from one version to another.
#
#   scripts/offline-upgrade-bundle.sh --from v0.3.0
#   scripts/offline-upgrade-bundle.sh --from v0.3.0 --to v0.3.2 --out /mnt/media
#
# §6's offline-upgrade item. The installation bundle answers "how do I get turna
# onto a host with no internet". This answers the harder one: "how do I move a
# running one, and get back if it goes wrong".
#
# WHAT MAKES AN UPGRADE BUNDLE DIFFERENT
#
# An installation bundle describes one version. An upgrade bundle has to describe
# a *transition*, and the part nobody packages is the part that bites:
#
# **Which config keys changed.** This project sets `deny_unknown_fields` on every
# section, which is stricter than a schema version and better — a typo names
# itself. It also means a key the new version added makes the **old** binary
# refuse to start on the config the new one wrote. So a rollback that would have
# worked yesterday fails after the upgrade has run once, and it fails at exactly
# the moment somebody is under pressure.
#
# So this bundle computes the key diff between the two versions and ships it, with
# the rollback consequence spelled out per key. That is the artifact — the
# binaries are the easy half.
#
# WHY BOTH BINARIES ARE INCLUDED
#
# The old one too. A rollback on an air-gapped host cannot fetch anything, and an
# upgrade bundle that only contains the new version is a one-way door dressed as a
# procedure.

set -uo pipefail

FROM_REF=""
TO_REF="${TO_REF:-HEAD}"
OUTDIR="${OUTDIR:-.}"
SKIP_IMAGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM_REF="$2"; shift 2 ;;
    --to) TO_REF="$2"; shift 2 ;;
    --out) OUTDIR="$2"; shift 2 ;;
    --skip-image) SKIP_IMAGE=1; shift ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$FROM_REF" ] || {
  echo "--from is required: the version being upgraded from, as a git ref." >&2
  echo "Without it there is no transition to describe, and the config diff —" >&2
  echo "which is the point of this bundle — cannot be computed." >&2
  exit 2
}

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1

git rev-parse --verify "$FROM_REF" >/dev/null 2>&1 || {
  echo "--from $FROM_REF is not a ref in this repository" >&2; exit 1; }

FROM_VER=$(git show "$FROM_REF:Cargo.toml" 2>/dev/null |
           grep -m1 '^version' | sed -E 's/.*"([^"]+)".*/\1/')
TO_VER=$(git show "$TO_REF:Cargo.toml" 2>/dev/null |
         grep -m1 '^version' | sed -E 's/.*"([^"]+)".*/\1/')
[ -n "$FROM_VER" ] && [ -n "$TO_VER" ] || {
  echo "could not read versions from Cargo.toml at both refs" >&2; exit 1; }

STAGE="turna-upgrade-${FROM_VER}-to-${TO_VER}"
WORK="$OUTDIR/$STAGE"
rm -rf "$WORK"
mkdir -p "$WORK/bin-old" "$WORK/bin-new" || exit 1

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
MISSING=""
note_missing() { MISSING="$MISSING
  - $1"; }

say "upgrade bundle: $FROM_VER -> $TO_VER"

# ── the config diff, which is the reason this script exists ───────────────
say "computing the config key diff"

extract_keys() {
  # Every `pub <name>:` inside crates/config, at the given ref. Crude — it does
  # not know which struct a field belongs to, so a name appearing in two sections
  # collapses to one entry.
  #
  # That imprecision is stated in the report rather than papered over: a parser
  # that understood the struct tree would be better, and a wrong one that looked
  # authoritative would be worse than a rough one that says it is rough.
  git show "$1:crates/config/src/lib.rs" 2>/dev/null |
    grep -oE '^\s+pub [a-z_]+:' |
    sed -E 's/^\s+pub //; s/:$//' |
    sort -u
}

extract_keys "$FROM_REF" > "$WORK/keys-old.txt"
extract_keys "$TO_REF" > "$WORK/keys-new.txt"

ADDED=$(comm -13 "$WORK/keys-old.txt" "$WORK/keys-new.txt")
REMOVED=$(comm -23 "$WORK/keys-old.txt" "$WORK/keys-new.txt")
N_ADDED=$(printf '%s' "$ADDED" | grep -c . || true)
N_REMOVED=$(printf '%s' "$REMOVED" | grep -c . || true)

say "  $N_ADDED keys added, $N_REMOVED removed"

# ── binaries, both versions ───────────────────────────────────────────────
export RUSTFLAGS="--remap-path-prefix=$PWD= --remap-path-prefix=$HOME/.cargo="

build_at() {
  local ref="$1" dest="$2" tree
  tree="$WORK/.tree-$(printf '%s' "$ref" | tr -c 'a-zA-Z0-9' _)"
  # A worktree rather than a checkout: a build that mutates the working tree
  # loses uncommitted work, and this script should be safe to run mid-change.
  git worktree add --detach "$tree" "$ref" > /dev/null 2>&1 || return 1
  export SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$ref")"
  ( cd "$tree" && cargo build --locked --release \
      --bin turna-node --bin turna-control-plane --bin turnactl ) \
      > "$WORK/build-$dest.log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    for b in turna-node turna-control-plane turnactl; do
      cp "$tree/target/release/$b" "$WORK/$dest/"
    done
    rm -f "$WORK/build-$dest.log"
  fi
  git worktree remove "$tree" --force > /dev/null 2>&1
  return $rc
}

say "building $FROM_VER"
build_at "$FROM_REF" bin-old || note_missing "old binaries (see build-bin-old.log)"
say "building $TO_VER"
build_at "$TO_REF" bin-new || note_missing "new binaries (see build-bin-new.log)"

# ── image ─────────────────────────────────────────────────────────────────
if [ "$SKIP_IMAGE" = "0" ] && command -v docker >/dev/null 2>&1; then
  say "building the new image"
  if docker build -f deploy/Dockerfile -t "turna:$TO_VER" . > "$WORK/img.log" 2>&1; then
    docker save "turna:$TO_VER" | gzip -9 > "$WORK/turna-${TO_VER}-image.tar.gz"
    rm -f "$WORK/img.log"
  else
    tail -15 "$WORK/img.log"
    note_missing "new image (docker build failed)"
  fi
  # The old image is deliberately not rebuilt. A rollback on Kubernetes pulls the
  # previous tag, which is already in the cluster's registry — and if it is not,
  # that is a registry retention problem this bundle cannot fix by carrying a
  # tarball nobody will think to load.
else
  [ "$SKIP_IMAGE" = "0" ] && note_missing "new image (docker not installed)"
fi

# ── chart ─────────────────────────────────────────────────────────────────
if command -v helm >/dev/null 2>&1; then
  helm package deploy/helm/turna --destination "$WORK" > /dev/null 2>&1 ||
    note_missing "Helm chart"
else
  cp -a deploy/helm/turna "$WORK/helm-chart"
fi

# ── changelog slice ───────────────────────────────────────────────────────
if [ -f CHANGELOG.md ]; then
  # From the top down to the old version's heading — what changed in between,
  # rather than the whole file. An operator upgrading two versions does not need
  # the history of ten.
  awk -v stop="$FROM_VER" '
    /^## / { if (seen && index($0, stop)) exit; seen=1 }
    seen { print }
  ' CHANGELOG.md > "$WORK/CHANGES.md" 2>/dev/null
  [ -s "$WORK/CHANGES.md" ] || rm -f "$WORK/CHANGES.md"
fi

# ── the report ────────────────────────────────────────────────────────────
cat > "$WORK/UPGRADE.md" <<EOF
# turna $FROM_VER → $TO_VER, offline

Built $(date -u +%FT%TZ) from $(git rev-parse --short "$TO_REF").

## Read this before starting: the rollback window closes

This project sets \`deny_unknown_fields\` on every config section. A key the new
version added makes the **old binary refuse to start** on the config the new one
wrote.

That is the safe direction — the old binary does not silently ignore a setting it
cannot honour — and it has a consequence worth understanding before rather than
during: **once the new version has written config, rolling back needs the config
edited too.** Not just the binary swapped.

$( if [ "$N_ADDED" -gt 0 ]; then
cat <<ADDED

### Keys added in $TO_VER ($N_ADDED)

These do not exist in $FROM_VER. If any appears in the config, $FROM_VER will not
parse it.

\`\`\`
$ADDED
\`\`\`

**Before rolling back:** remove these from the config file, or keep a copy of the
$FROM_VER config alongside it. The second is better — an edit made under pressure
is an edit that goes wrong.
ADDED
else
  printf '\n### No config keys were added\n\nRollback needs only the binary swapped.\n'
fi )

$( if [ "$N_REMOVED" -gt 0 ]; then
cat <<REMOVED

### Keys removed in $TO_VER ($N_REMOVED)

\`\`\`
$REMOVED
\`\`\`

The **new** version will refuse a config still containing these. Remove them
before upgrading, not after — the node will not start, and the first thing you
will see is a parse error rather than a hint.
REMOVED
fi )

**How this diff was computed, and its limits.** Every \`pub <name>:\` in
\`crates/config\` at each ref, compared. It does not know which section a field
belongs to, so a name used in two sections appears once, and a field renamed
within a struct shows as one addition and one removal without saying they are
related. Rough on purpose: a parser that understood the struct tree would be
better, and a wrong one that looked authoritative would be worse.

Cross-check against \`CHANGES.md\` in this bundle before trusting either.

## Verify

\`\`\`sh
sha256sum -c SHA256SUMS
\`\`\`

Proves the bundle arrived intact, not that it is the bundle that was built — the
same caveat as the installation bundle, and the same answer: compare the image
digest against what cosign signed, using a key that reached this side of the gap
by a route you chose.

## Upgrade, with the rollback prepared first

\`\`\`sh
# 1. Keep what you are rolling back to. This is the step that gets skipped.
cp /etc/turna/turn.toml /etc/turna/turn.toml.$FROM_VER
cp \$(command -v turna-node) /usr/local/bin/turna-node.$FROM_VER

# 2. Drain. Returns when the node accepts the instruction, not when it finishes.
turnactl drain --reason "upgrade to $TO_VER"
watch -n2 'curl -s localhost:9090/status | grep active_allocations'
\`\`\`

Wait for it to reach zero, or stop waiting when it stalls. A node whose clients
vanished without a Refresh holds allocations until their 600-second lifetime
expires — the drain has a bounded wait for that reason, and measured 1 second on
a node holding abandoned allocations once stall detection was added.

\`\`\`sh
# 3. Stop, swap, start.
systemctl stop turna
install -m 755 bin-new/turna-node /usr/local/bin/turna-node
turna-node --dump-config /etc/turna/turn.toml    # BEFORE starting
systemctl start turna

# 4. Check it, do not assume it.
curl -s localhost:9090/ready
scripts/verify/deployment-compliance.sh --config /etc/turna/turn.toml
\`\`\`

\`--dump-config\` first, every time. It runs the same validation the node does at
startup, and finding a config error there costs seconds instead of an outage.

## Rollback

\`\`\`sh
systemctl stop turna
install -m 755 bin-old/turna-node /usr/local/bin/turna-node
cp /etc/turna/turn.toml.$FROM_VER /etc/turna/turn.toml   # the copy from step 1
turna-node --dump-config /etc/turna/turn.toml
systemctl start turna
\`\`\`

If step 1 was skipped and $FROM_VER refuses to start, the added-keys list above is
what to remove from the config.

## Kubernetes

\`\`\`sh
docker load < turna-${TO_VER}-image.tar.gz
docker tag turna:$TO_VER your-registry.internal/turna:$TO_VER
docker push your-registry.internal/turna:$TO_VER
helm upgrade turna ./turna-*.tgz --set image.tag=$TO_VER
# rollback:
helm rollback turna
\`\`\`

\`helm rollback\` restores the chart values, **not the config file** if it is
mounted from outside the chart. Check which it is before relying on it.

## Rehearsed?

\`scripts/verify/upgrade-rollback.sh --from $FROM_REF\` runs this procedure with
traffic flowing, including the rollback against the *new* config — which is what
an operator would actually have on disk. Run it on a test host before running
this on a real one.
EOF

# Checksums last, so UPGRADE.md and the key lists are covered. An earlier version
# of the installation bundle computed them first and left its instructions —
# including the image digest — outside the only integrity check it had.
( cd "$WORK" && rm -f keys-old.txt keys-new.txt &&
  find . -type f ! -name SHA256SUMS -print0 |
  sort -z | xargs -0 sha256sum > SHA256SUMS )

TARBALL="$OUTDIR/${STAGE}.tar.gz"
tar czf "$TARBALL" -C "$OUTDIR" "$STAGE"

say "done"
echo
echo "bundle: $TARBALL"
echo "size:   $(du -h "$TARBALL" | cut -f1)"
echo "sha256: $(sha256sum "$TARBALL" | cut -d' ' -f1)"
echo
echo "config keys added: $N_ADDED, removed: $N_REMOVED"
if [ "$N_ADDED" -gt 0 ]; then
  echo
  echo "Rollback will need the old config kept, not just the old binary."
  echo "UPGRADE.md lists the keys and says so at the top."
fi

if [ -n "$MISSING" ]; then
  echo
  echo "NOT included:"
  printf '%b\n' "$MISSING"
fi
