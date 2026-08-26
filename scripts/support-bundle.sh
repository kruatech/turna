#!/usr/bin/env bash
#
# Collect a support bundle: everything needed to investigate an incident, and
# nothing that stops it being shareable.
#
#   scripts/support-bundle.sh                        # redacted, addresses hashed
#   scripts/support-bundle.sh --include-secrets      # for your own machine only
#   scripts/support-bundle.sh --strip-addresses      # drop addresses entirely
#   scripts/support-bundle.sh --health 127.0.0.1:9090 --config /etc/turna/turn.toml
#
# Produces turna-bundle-<host>-<timestamp>.tar.gz with a MANIFEST inside.
#
# WHY REDACTION IS THE DEFAULT
#
# A bundle carrying `shared_secret` cannot be attached to a ticket, so it does
# not get attached and this script was pointless. A redacting mode you have to
# remember is one that is forgotten exactly when the incident is urgent.
#
# Client addresses are hashed with a salt generated per bundle and then thrown
# away: "is one client responsible" stays answerable within the bundle, and the
# address does not leave the machine. That is a judgement, not a rule — override
# it if your jurisdiction or your incident says otherwise.

set -uo pipefail

HEALTH="${HEALTH:-127.0.0.1:9090}"
CONFIG="${CONFIG:-}"
INCLUDE_SECRETS=0
STRIP_ADDRESSES=0
INCLUDE_ADDRESSES=0
LOG_LINES="${LOG_LINES:-2000}"

while [ $# -gt 0 ]; do
  case "$1" in
    --health) HEALTH="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --include-secrets) INCLUDE_SECRETS=1; shift ;;
    --strip-addresses) STRIP_ADDRESSES=1; shift ;;
    --include-addresses) INCLUDE_ADDRESSES=1; shift ;;
    --log-lines) LOG_LINES="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

STAMP="$(date -u +%Y%m%d-%H%M%S)"
HOSTN="$(hostname -s 2>/dev/null || echo unknown)"
OUT="turna-bundle-${HOSTN}-${STAMP}"
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 1; }

# Per-bundle salt, used to hash addresses and then discarded. Not written to the
# bundle: if it were, the hashing would be reversible by anyone holding the file,
# which is the opposite of the point.
SALT="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

OMITTED=""
note_omitted() { OMITTED="$OMITTED
  - $1"; }

# ── addresses ─────────────────────────────────────────────────────────────
#
# Applied to every text file that goes in, not just logs: config carries listen
# and external addresses, and /status carries client addresses.
scrub() {
  if [ "$INCLUDE_ADDRESSES" = "1" ]; then
    cat
    return
  fi
  if [ "$STRIP_ADDRESSES" = "1" ]; then
    sed -E 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/<ipv4>/g; s/([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}/<ipv6>/g'
    return
  fi
  # Hash: stable within the bundle, unrecoverable outside it. Loopback and the
  # unspecified address are left alone — they identify nobody and hashing them
  # would make a bundle harder to read for no gain.
  awk -v salt="$SALT" '
    function h(a) {
      cmd = "printf %s " salt a " | sha256sum | cut -c1-12"
      cmd | getline out
      close(cmd)
      return "ip-" out
    }
    {
      line = $0
      while (match(line, /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/)) {
        a = substr(line, RSTART, RLENGTH)
        if (a ~ /^(127\.|0\.0\.0\.0)/) {
          # leave it, but move past it so the loop terminates
          printf "%s", substr(line, 1, RSTART + RLENGTH - 1)
          line = substr(line, RSTART + RLENGTH)
          continue
        }
        printf "%s%s", substr(line, 1, RSTART - 1), h(a)
        line = substr(line, RSTART + RLENGTH)
      }
      print line
    }'
}

# ── secrets ───────────────────────────────────────────────────────────────
#
# Value-side redaction on the keys that carry credentials. Deliberately a
# denylist of key names rather than a heuristic on the values: a heuristic that
# guesses wrong in the safe direction makes the bundle useless, and one that
# guesses wrong in the other direction is the reason this script exists.
redact_secrets() {
  if [ "$INCLUDE_SECRETS" = "1" ]; then
    cat
    return
  fi
  sed -E \
    -e 's/^([[:space:]]*(shared_secret|turn_shared_secret|password|token|secret|client_secret|mac_key|api_key)[[:space:]]*=[[:space:]]*).*/\1"<redacted>"/I' \
    -e 's/^([[:space:]]*key[[:space:]]*=[[:space:]]*)"[^"]*"/\1"<redacted>"/' \
    -e 's/(BEGIN [A-Z ]*PRIVATE KEY-----)/\1 <redacted, body removed>/'
}

fetch() {
  local path="$1" dest="$2"
  if curl -fsS --max-time 5 "http://${HEALTH}${path}" 2>/dev/null |
       scrub > "$OUT/$dest"; then
    [ -s "$OUT/$dest" ] || { rm -f "$OUT/$dest"; note_omitted "$dest (endpoint answered empty)"; }
  else
    rm -f "$OUT/$dest"
    note_omitted "$dest (could not reach http://${HEALTH}${path})"
  fi
}

echo "collecting into $OUT/"

# The runbooks are metric-driven, so this is the centre of the bundle.
fetch /metrics   metrics.txt
fetch /status    status.json
fetch /capacity  capacity.json
fetch /cluster   cluster.json
fetch /ready     ready.txt

# ── config ────────────────────────────────────────────────────────────────
if [ -n "$CONFIG" ]; then
  if [ -r "$CONFIG" ]; then
    redact_secrets < "$CONFIG" | scrub > "$OUT/config.toml"
  else
    note_omitted "config.toml ($CONFIG not readable)"
  fi
else
  note_omitted "config.toml (no --config given; pass one, it is usually the answer)"
fi

# ── host and build ────────────────────────────────────────────────────────
{
  echo "uname: $(uname -srm)"
  echo "kernel_cmdline_present: $([ -r /proc/cmdline ] && echo yes || echo no)"
  echo "cpus: $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
  echo "mem_total_kb: $(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo unknown)"
  echo "ulimit_nofile: $(ulimit -n)"
  # Kernel version decides whether io_uring and AF_XDP behave, and both have
  # produced version-specific bugs here.
  echo "io_uring_available: $([ -e /proc/sys/kernel/io_uring_disabled ] && echo maybe || echo unknown)"
} > "$OUT/host.txt" 2>/dev/null

for candidate in "$(command -v turna-node 2>/dev/null)" target/release/turna-node; do
  [ -n "$candidate" ] && [ -x "$candidate" ] || continue
  # Exit code ignored on purpose: `--version` on some builds writes the string and
  # then exits non-zero, which had this reporting the file as both present and
  # omitted. A manifest that contradicts itself is worse than either half alone,
  # because a reader cannot tell which to believe. Judge by the artifact.
  "$candidate" --version > "$OUT/version.txt" 2>&1
  break
done
if [ ! -s "$OUT/version.txt" ]; then
  rm -f "$OUT/version.txt"
  note_omitted "version.txt (turna-node not found, or --version produced nothing)"
fi

# ── logs ──────────────────────────────────────────────────────────────────
#
# Last N lines only. A full log is usually too large to attach and rarely more
# useful than the tail plus the metrics.
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u turna --no-pager -n "$LOG_LINES" 2>/dev/null |
    redact_secrets | scrub > "$OUT/journal.txt" ||
    note_omitted "journal.txt (journalctl failed)"
  # `-s` is not enough: journalctl writes "-- No entries --" (17 bytes) when the
  # unit exists but has logged nothing, and when it does not exist at all. Both
  # pass a size check and neither carries information, so a bundle would ship a
  # file that looks like collected logs and is not.
  if ! grep -qvE '^-- (No entries|Logs begin|Journal)' "$OUT/journal.txt" 2>/dev/null; then
    rm -f "$OUT/journal.txt"
    note_omitted "journal.txt (journalctl returned no entries — not run under systemd?)"
  fi
else
  note_omitted "journal.txt (no journalctl)"
fi

# ── manifest ──────────────────────────────────────────────────────────────
#
# Always written, and it names what is missing. Without that the recipient cannot
# distinguish an incomplete bundle from a healthy system — an absent file reads as
# a healthy subsystem, which is a mistake this project has made before.
{
  echo "# turna support bundle"
  echo
  echo "created:        $(date -u +%FT%TZ)"
  echo "host:           $HOSTN"
  echo "health_addr:    $HEALTH"
  echo "collector:      scripts/support-bundle.sh"
  echo
  echo "## Redaction"
  echo
  if [ "$INCLUDE_SECRETS" = "1" ]; then
    echo "secrets:        **INCLUDED** (--include-secrets). Do not share this bundle."
  else
    echo "secrets:        redacted (shared_secret, passwords, tokens, private keys)"
  fi
  case "1" in
    "$INCLUDE_ADDRESSES") echo "addresses:      **INCLUDED verbatim** (--include-addresses)" ;;
    "$STRIP_ADDRESSES")   echo "addresses:      removed (--strip-addresses)" ;;
    *) echo "addresses:      hashed with a per-bundle salt, discarded after use."
       echo "                Correlation holds inside this bundle; the addresses"
       echo "                cannot be recovered from it. Loopback left as-is." ;;
  esac
  echo
  echo "## Contents"
  echo
  for f in "$OUT"/*; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    [ "$b" = "MANIFEST.md" ] && continue
    printf -- '- %s (%s bytes)\n' "$b" "$(wc -c < "$f" | tr -d ' ')"
  done
  if [ -n "$OMITTED" ]; then
    echo
    echo "## Omitted"
    echo
    echo "Listed rather than left absent: a missing file otherwise reads as a"
    echo "healthy subsystem."
    printf '%s\n' "$OMITTED"
  fi
} > "$OUT/MANIFEST.md"

tar czf "${OUT}.tar.gz" "$OUT" && rm -rf "$OUT"

echo
echo "bundle: ${OUT}.tar.gz  ($(wc -c < "${OUT}.tar.gz" | tr -d ' ') bytes)"
if [ "$INCLUDE_SECRETS" = "1" ]; then
  echo
  echo "WARNING: --include-secrets was given. This bundle contains credentials"
  echo "         in the clear. Do not attach it to a ticket."
fi
echo
echo "Check what went in before sending it — that habit is what makes the"
echo "redaction trustworthy rather than assumed:"
echo "  tar xzf ${OUT}.tar.gz -O ${OUT}/MANIFEST.md"
echo "  tar xzf ${OUT}.tar.gz -O ${OUT}/config.toml | grep -i secret"
