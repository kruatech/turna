#!/usr/bin/env bash
# Convenience wrapper so CI can call one entry point for the doc-truth gate.
#
# Insert into scripts/ci-checks.sh right after the `rustfmt --check` step:
#
#     log "doc-truth gate"
#     bash scripts/check-doc-claims.sh
#
# This wrapper exists so a pipeline that does not use ci-checks.sh can still run
# the gate without knowing the script's name.
set -euo pipefail
exec bash "$(dirname "$0")/check-doc-claims.sh"
