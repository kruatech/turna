#!/usr/bin/env bash
#
# Build an installation bundle for a host with no internet.
#
#   scripts/offline-bundle.sh
#   scripts/offline-bundle.sh --arch linux/arm64 --out /mnt/media
#
# §6's offline-installation item. The target is a deployment where the node has no
# route off its own network — the case `scripts/verify/air-gap.sh` proves turna can
# run in. That verification is worth little if getting turna onto such a host
# requires a registry.
#
# WHAT GOES IN, AND THE ONE THAT MATTERS
#
#   the container image, as a tarball        docker load, no registry
#   the Helm chart, packaged                 helm install ./turna-x.y.z.tgz
#   static binaries                          for hosts with no container runtime
#   a config template                        with the production settings set
#   SHA256SUMS                               and why it is not enough, below
#   INSTALL.md                               generated, with the digests in it
#
# **The image digest is recorded in INSTALL.md, not only in the checksum file.**
# A checksum proves the tarball arrived intact. It does not prove the tarball is
# the one that was built, because whoever hands you a modified bundle hands you a
# matching SHA256SUMS with it. The digest ties the image to what the release
# workflow signed with cosign, and that chain is the part a checksum cannot
# replace.
#
# WHAT THIS DOES NOT SOLVE
#
# Trust. A bundle carried in on a disk is as trustworthy as the disk and the
# person. Verifying the cosign signature needs the public key, which needs to
# reach the air-gapped side somehow — out of band, once, by a route the operator
# decides. This script prints what to verify; it cannot create a root of trust
# where there is none, and pretending otherwise would be the more dangerous
# omission.

set -uo pipefail

ARCH="${ARCH:-linux/amd64}"
OUTDIR="${OUTDIR:-.}"
VERSION=""
SKIP_IMAGE=0
SKIP_BINARIES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH="$2"; shift 2 ;;
    --out) OUTDIR="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --skip-image) SKIP_IMAGE=1; shift ;;
    --skip-binaries) SKIP_BINARIES=1; shift ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1

# Version from the workspace manifest, not from a flag with a default. A bundle
# labelled with a version it does not contain is worse than an unlabelled one:
# somebody will trust the label.
if [ -z "$VERSION" ]; then
  VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
fi
[ -n "$VERSION" ] || { echo "could not read the version from Cargo.toml" >&2; exit 1; }

STAGE="turna-offline-${VERSION}"
WORK="$OUTDIR/$STAGE"
rm -rf "$WORK"
mkdir -p "$WORK" || { echo "cannot create $WORK" >&2; exit 1; }

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
MISSING=""
note_missing() { MISSING="$MISSING
  - $1"; }

say "building an offline bundle for turna $VERSION ($ARCH)"

# ── image ─────────────────────────────────────────────────────────────────
IMAGE_DIGEST=""
if [ "$SKIP_IMAGE" = "0" ]; then
  if command -v docker >/dev/null 2>&1; then
    say "building the container image"
    if docker build --platform "$ARCH" -f deploy/Dockerfile \
         -t "turna:$VERSION" . > "$WORK/image-build.log" 2>&1; then
      say "saving it as a tarball"
      docker save "turna:$VERSION" | gzip -9 > "$WORK/turna-${VERSION}-image.tar.gz"
      # The digest of the image as built, which is what ties this tarball to the
      # signature the release workflow produced. `docker save` output has its own
      # checksum but no relationship to the registry digest.
      IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "turna:$VERSION" 2>/dev/null ||
                     docker inspect --format='{{.Id}}' "turna:$VERSION" 2>/dev/null || echo "")
      rm -f "$WORK/image-build.log"
      say "  image: $(du -h "$WORK/turna-${VERSION}-image.tar.gz" | cut -f1)"
    else
      tail -20 "$WORK/image-build.log"
      note_missing "container image (docker build failed — see image-build.log)"
    fi
  else
    note_missing "container image (docker not installed)"
  fi
fi

# ── chart ─────────────────────────────────────────────────────────────────
if command -v helm >/dev/null 2>&1; then
  say "packaging the Helm chart"
  if helm package deploy/helm/turna --destination "$WORK" > /dev/null 2>&1; then
    say "  chart: $(ls "$WORK"/turna-*.tgz | head -1 | xargs basename)"
  else
    note_missing "Helm chart (helm package failed)"
  fi
else
  # Copied raw rather than skipped: `helm install ./dir` works on a directory, so
  # a bundle without helm on the build host is still installable.
  say "helm not installed — copying the chart directory instead"
  cp -a deploy/helm/turna "$WORK/helm-chart"
fi

# ── binaries ──────────────────────────────────────────────────────────────
if [ "$SKIP_BINARIES" = "0" ]; then
  say "building binaries"
  # The same flags the release workflow uses, so a binary from this bundle is
  # byte-identical to the published one. Verified: all three reproduce across
  # different build directories (docs/capacity, and the reproducible-build check).
  export RUSTFLAGS="--remap-path-prefix=$PWD= --remap-path-prefix=$HOME/.cargo="
  export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || echo 1700000000)"
  if cargo build --locked --release \
       --bin turna-node --bin turna-control-plane --bin turnactl \
       > "$WORK/build.log" 2>&1; then
    mkdir -p "$WORK/bin"
    for b in turna-node turna-control-plane turnactl; do
      cp "target/release/$b" "$WORK/bin/"
    done
    rm -f "$WORK/build.log"
    say "  binaries: $(du -sh "$WORK/bin" | cut -f1)"
  else
    tail -20 "$WORK/build.log"
    note_missing "binaries (cargo build failed — see build.log)"
  fi
fi

# ── config ────────────────────────────────────────────────────────────────
say "writing a config template"
mkdir -p "$WORK/config"
cat > "$WORK/config/turn.toml" <<'TOML'
# turna configuration — offline deployment template.
#
# Every value below marked REQUIRED must be changed. The node refuses to start
# with several of them unset under production = true, which is deliberate: a
# template that starts as-is is a template that reaches production as-is.

production = true

[turn]
listen = "0.0.0.0:3478"
# REQUIRED. The address clients reach this node on. Not a private address unless
# every client is on the same network — it goes into the relayed candidate, and a
# client cannot use an address it cannot route to.
external_ip = "CHANGE-ME"
realm = "CHANGE-ME"
transport = "tokio"

[turn.auth]
# REQUIRED. Never a literal here. Either form works:
#   shared_secret = "${TURNA_SHARED_SECRET}"
#   shared_secret = "file:///run/secrets/turna-shared-secret"
shared_secret = "${TURNA_SHARED_SECRET}"

[turn.peer_filter]
# "internet" denies RFC 1918 and ULA — right for a public relay, and it will
# refuse to relay to your own network. "lan" permits private ranges. Choosing is
# the point; there is no default that is right for both.
profile = "internet"

[turn.relay]
# Must not overlap the host's ephemeral range. Check:
#   cat /proc/sys/net/ipv4/ip_local_port_range
# A peer socket inside the relay range makes the relay forward to itself.
min_port = 30000
max_port = 40000
max_allocations = 4000

[turn.relay.quota]
# Per-username cap. 0 is unlimited, which lets one credential consume the whole
# port range.
max_per_user = 20

[tls]
# TURNS. Put it on 443: the networks that block the direct path also block 5349,
# and 443 is indistinguishable from HTTPS to a port-based filter. Needs its own
# address, or a front end that passes TCP through *without* terminating TLS —
# TURNS is not HTTP and a terminating proxy will not forward it.
enabled = false
listen = "0.0.0.0:5349"
cert_path = "/etc/turna/tls/cert.pem"
key_path = "/etc/turna/tls/key.pem"

[health]
# Bind to a management interface, not the public one.
listen = "127.0.0.1:9090"

[observability]
# Empty means no outbound telemetry, which is what an air-gapped deployment
# wants and is the default.
otlp_endpoint = ""
# A syslog collector on the local network. Security events only.
syslog_endpoint = ""

[signaling]
listen = "127.0.0.1:9001"
turn_shared_secret = "${TURNA_SHARED_SECRET}"
TOML

# ── instructions ──────────────────────────────────────────────────────────
#
# Written before the checksums, deliberately. INSTALL.md carries the image digest,
# which is the one value in this bundle worth altering — it is what an operator
# compares against the cosign signature. A first version computed the checksums
# first and left INSTALL.md uncovered, which put the digest outside the only
# integrity check the bundle has.
IMAGE_TAR="turna-${VERSION}-image.tar.gz"
CHART=$(ls "$WORK"/turna-*.tgz 2>/dev/null | head -1 | xargs -r basename)

cat > "$WORK/INSTALL.md" <<EOF
# turna $VERSION — offline installation

Built $(date -u +%FT%TZ) for \`$ARCH\` from commit \
$(git rev-parse --short HEAD 2>/dev/null || echo unknown).

## Verify before installing

\`\`\`sh
sha256sum -c SHA256SUMS
\`\`\`

That proves the bundle arrived intact. **It does not prove the bundle is the one
that was built** — anyone who hands you a modified bundle hands you a matching
SHA256SUMS with it.

$( [ -n "$IMAGE_DIGEST" ] && cat <<DIGEST
The image built here:

    $IMAGE_DIGEST

Compare against the digest cosign signed for this release. That chain is the part
a checksum cannot replace, and it needs the public key to have reached this side
of the air gap by some route you chose — this bundle cannot establish a root of
trust it does not have.
DIGEST
)

## Container runtime

\`\`\`sh
docker load < $IMAGE_TAR
mkdir -p /etc/turna
cp config/turn.toml /etc/turna/turn.toml
# edit it — every REQUIRED value, and read the comments
docker run -d --name turna --network host \\
  -v /etc/turna:/etc/turna:ro \\
  -e TURNA_SHARED_SECRET="\$(cat /run/secrets/turna-secret)" \\
  turna:$VERSION
\`\`\`

\`--network host\` because a relay hands out its own address and needs the
port range reachable. Bridged networking works only with the whole relay range
published, which is thousands of rules.

## Kubernetes

\`\`\`sh
docker load < $IMAGE_TAR
docker tag turna:$VERSION your-registry.internal/turna:$VERSION
docker push your-registry.internal/turna:$VERSION
helm install turna ${CHART:-./helm-chart} \\
  --set image.repository=your-registry.internal/turna \\
  --set image.tag=$VERSION
\`\`\`

## No container runtime

\`\`\`sh
install -m 755 bin/turna-node bin/turna-control-plane bin/turnactl /usr/local/bin/
mkdir -p /etc/turna && cp config/turn.toml /etc/turna/
# edit it, then:
turna-node --dump-config /etc/turna/turn.toml   # refuses if something is wrong
turna-node /etc/turna/turn.toml
\`\`\`

\`--dump-config\` first, always. It runs the same validation the node does at
startup and prints the config with secrets masked — which is also the output to
attach to a ticket, unlike \`--dump-config-raw\`.

## After installing

\`\`\`sh
scripts/verify/deployment-compliance.sh --config /etc/turna/turn.toml
\`\`\`

Checks the deployment against \`docs/security/security-profile.md\`. Failures are
non-negotiable items; warnings are decisions to make rather than ignore.

## What is not in this bundle

- **TLS certificates.** Yours, and a bundled one would be worse than none.
- **The cosign public key.** See above.
- **A Tarantool server**, if you intend to cluster. Separate, and its own bundle.
- **Kernel modules.** \`io_uring\` and AF_XDP need kernel support that a tarball
  cannot supply; \`transport = "tokio"\` needs none and is the default.
EOF

# ── checksums ─────────────────────────────────────────────────────────────
#
# Last, so everything including INSTALL.md is covered.
say "computing checksums"
( cd "$WORK" && find . -type f ! -name SHA256SUMS -print0 |
    sort -z | xargs -0 sha256sum > SHA256SUMS )

# ── package ───────────────────────────────────────────────────────────────
TARBALL="$OUTDIR/${STAGE}.tar.gz"
say "packaging"
tar czf "$TARBALL" -C "$OUTDIR" "$STAGE"
OUTER_SUM=$(sha256sum "$TARBALL" | cut -d' ' -f1)

say "done"
echo
echo "bundle:   $TARBALL"
echo "size:     $(du -h "$TARBALL" | cut -f1)"
echo "sha256:   $OUTER_SUM"
echo "contents: $(find "$WORK" -type f | wc -l | tr -d ' ') files"

if [ -n "$MISSING" ]; then
  echo
  echo "NOT included:"
  printf '%b\n' "$MISSING"
  echo
  echo "Listed rather than left absent: a bundle missing a component that nobody"
  echo "mentioned is one somebody discovers on the air-gapped side, where fixing"
  echo "it is expensive."
fi

echo
echo "Publish that sha256 by a different route than the bundle. Both arriving"
echo "together means an attacker who replaced one replaced the other."
