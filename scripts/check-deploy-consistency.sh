#!/usr/bin/env bash
#
# P0 §7.3 / §24 — deployment consistency gate.
#
# The relay UDP port range is declared in THREE independent places that must
# agree, or allocations succeed while their relay traffic is silently dropped
# (P0 #13):
#
#   1. deploy/turn.toml            [turn.relay] min_port / max_port   (source of truth)
#   2. deploy/docker-compose.yml   published "<min>-<max>:<min>-<max>/udp"
#   3. deploy/helm/turna/values.yaml   relayPortRange.min / .max
#
# This script parses all three with plain awk/grep (no toml/yaml deps) and
# fails the build on any divergence. It is intentionally strict: exact integer
# equality, host-range == container-range in compose.
#
# Run from the repository root.

set -euo pipefail

TOML="deploy/turn.toml"
COMPOSE="deploy/docker-compose.yml"
VALUES="deploy/helm/turna/values.yaml"

fail() { echo "deploy-consistency: FAIL: $*" >&2; exit 1; }

for f in "$TOML" "$COMPOSE" "$VALUES"; do
  [ -f "$f" ] || fail "expected file not found: $f (run from repo root)"
done

# ── 1. turn.toml [turn.relay] (stop at the next [section] so we don't pick up
#       [turn.relay.quota] or anything else). ────────────────────────────────
relay_block="$(awk '
  /^\[turn\.relay\]/          { grab=1; next }
  grab && /^\[/               { grab=0 }
  grab                        { print }
' "$TOML")"

toml_min="$(printf '%s\n' "$relay_block" | awk -F= '/^[[:space:]]*min_port[[:space:]]*=/ {gsub(/[^0-9]/,"",$2); print $2; exit}')"
toml_max="$(printf '%s\n' "$relay_block" | awk -F= '/^[[:space:]]*max_port[[:space:]]*=/ {gsub(/[^0-9]/,"",$2); print $2; exit}')"

[ -n "$toml_min" ] && [ -n "$toml_max" ] || fail "could not read [turn.relay] min_port/max_port from $TOML"

# ── 2. docker-compose published relay UDP range: "<h1>-<h2>:<c1>-<c2>/udp" ────
compose_line="$(grep -E '"[0-9]+-[0-9]+:[0-9]+-[0-9]+/udp"' "$COMPOSE" || true)"
[ -n "$compose_line" ] || fail "no published relay UDP range (\"<min>-<max>:<min>-<max>/udp\") found in $COMPOSE"

read -r c_h1 c_h2 c_c1 c_c2 <<<"$(printf '%s\n' "$compose_line" | sed -E 's/.*"([0-9]+)-([0-9]+):([0-9]+)-([0-9]+)\/udp".*/\1 \2 \3 \4/')"

[ "$c_h1" = "$c_c1" ] && [ "$c_h2" = "$c_c2" ] \
  || fail "compose host range ${c_h1}-${c_h2} != container range ${c_c1}-${c_c2} in $COMPOSE"

# ── 3. helm values relayPortRange.min / .max ─────────────────────────────────
helm_min="$(awk '
  /^[[:space:]]*relayPortRange:/ { grab=1; next }
  grab && /^[[:space:]]*min:/    { gsub(/[^0-9]/,"",$0); print; exit }
  grab && /^[[:alpha:]]/         { grab=0 }
' "$VALUES")"
helm_max="$(awk '
  /^[[:space:]]*relayPortRange:/ { grab=1; next }
  grab && /^[[:space:]]*max:/    { gsub(/[^0-9]/,"",$0); print; exit }
  grab && /^[[:alpha:]]/         { grab=0 }
' "$VALUES")"

[ -n "$helm_min" ] && [ -n "$helm_max" ] || fail "could not read relayPortRange.min/max from $VALUES"

# ── Compare all three against the toml source of truth ───────────────────────
echo "deploy-consistency: turn.toml=${toml_min}-${toml_max}  compose=${c_h1}-${c_h2}  helm=${helm_min}-${helm_max}"

ok=1
[ "$c_h1" = "$toml_min" ] && [ "$c_h2" = "$toml_max" ] || { echo "  MISMATCH: docker-compose ${c_h1}-${c_h2} != turn.toml ${toml_min}-${toml_max}" >&2; ok=0; }
[ "$helm_min" = "$toml_min" ] && [ "$helm_max" = "$toml_max" ] || { echo "  MISMATCH: helm ${helm_min}-${helm_max} != turn.toml ${toml_min}-${toml_max}" >&2; ok=0; }

[ "$ok" = 1 ] || fail "relay UDP range diverges across deploy artifacts (see above)"

echo "deploy-consistency: OK — relay UDP range agrees across turn.toml, docker-compose, and helm values"

# ── 4. Release-version consistency ───────────────────────────────────────────
# The workspace Cargo version is the source of truth; Helm chart version +
# appVersion, the Dockerfile default, the values image tag, and the README
# install tag must all match it, or an operator can mix artifacts from
# different releases (P0 release blocker).
CARGO_TOML="Cargo.toml"
CHART="deploy/helm/turna/Chart.yaml"
DOCKERFILE="deploy/Dockerfile"
README="README.md"
ADMIN_BUILD="services/admin/build.rs"

for f in "$CARGO_TOML" "$CHART" "$DOCKERFILE" "$README" "$ADMIN_BUILD"; do
  [ -f "$f" ] || fail "expected file not found: $f (run from repo root)"
done

cargo_ver="$(awk -F'"' '/^\[workspace\.package\]/{g=1} g&&/^version[[:space:]]*=/{print $2; exit}' "$CARGO_TOML")"
chart_ver="$(awk '/^version:/{print $2; exit}' "$CHART")"
chart_app="$(awk -F'"' '/^appVersion:/{print $2; exit}' "$CHART")"
docker_ver="$(awk -F= '/^ARG VERSION=/{print $2; exit}' "$DOCKERFILE")"
helm_tag="$(awk -F'"' '/^[[:space:]]*tag:[[:space:]]*"/{print $2; exit}' "$VALUES")"
readme_ver="$(grep -oE 'tag = "v[0-9][^"]*"' "$README" | head -1 | sed -E 's/.*"v([^"]+)".*/\1/')"

[ -n "$cargo_ver" ] || fail "could not read [workspace.package] version from $CARGO_TOML"

echo "deploy-consistency: cargo=${cargo_ver} chart=${chart_ver} appVersion=${chart_app} docker=${docker_ver} helmTag=${helm_tag} readme=${readme_ver}"

vok=1
[ "$chart_ver"  = "$cargo_ver" ] || { echo "  MISMATCH: Chart.yaml version ${chart_ver} != Cargo ${cargo_ver}" >&2; vok=0; }
[ "$chart_app"  = "$cargo_ver" ] || { echo "  MISMATCH: Chart.yaml appVersion ${chart_app} != Cargo ${cargo_ver}" >&2; vok=0; }
[ "$docker_ver" = "$cargo_ver" ] || { echo "  MISMATCH: Dockerfile ARG VERSION ${docker_ver} != Cargo ${cargo_ver}" >&2; vok=0; }
[ "$helm_tag"   = "$cargo_ver" ] || { echo "  MISMATCH: values.yaml image tag ${helm_tag} != Cargo ${cargo_ver}" >&2; vok=0; }
[ "$readme_ver" = "$cargo_ver" ] || { echo "  MISMATCH: README install tag ${readme_ver} != Cargo ${cargo_ver}" >&2; vok=0; }
[ "$vok" = 1 ] || fail "release versions diverge across artifacts (see above)"
echo "deploy-consistency: OK — release version ${cargo_ver} agrees across Cargo, Helm chart, Dockerfile, values, and README"

# ── 5. Proto single-source ───────────────────────────────────────────────────
# The admin client MUST compile the canonical control proto directly, never a
# local copy that can silently drift (a stale copy missing node_id /
# idempotency_key / audit RPCs breaks the admin build).
grep -qE 'crates/control/proto/management\.proto' "$ADMIN_BUILD" \
  || fail "admin build.rs must compile crates/control/proto/management.proto (single source of truth)"
echo "deploy-consistency: OK — admin client compiles the canonical control proto (no drift)"
