#!/usr/bin/env python3
"""
Teach the doc-claims gate that the RFC 6062 refusal is gone on purpose.

The check holds its own list of three keys and asserts each still has a refusal
in config::validate(). It does not read the documentation, despite the section
title — so updating the docs could not satisfy it, and I spent three guesses
about its logic before reading it. The lesson is the one this whole gate exists
to enforce: read the thing, do not infer it.

Two changes:

  * `turn.tcp_relay.enabled` comes off the required list.
  * A new assertion in the other direction: the refusal must NOT come back
    without a deliberate edit here. A gate that was lifted after evidence
    arrived can be reintroduced by a merge or a revert, and nothing would have
    noticed — which is the same class of silence the gate was built to catch.

Run from the repository root. Idempotent.
"""

import sys
import pathlib

p = pathlib.Path("scripts/check-doc-claims.sh")
if not p.exists():
    print("FAIL: scripts/check-doc-claims.sh not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "LIFTED_GATES" in s:
    print("FAIL: already applied")
    sys.exit(1)

old = """  for key in turn.tcp_relay.enabled turn.sctp.enabled turn.auth.oauth.enabled; do"""
new = """  for key in turn.sctp.enabled turn.auth.oauth.enabled; do"""
if s.count(old) != 1:
    print(f"FAIL: found {s.count(old)} occurrences of the key list, expected 1")
    sys.exit(1)
s = s.replace(old, new)
print("  ok  tcp_relay removed from the required-refusal list")

# Assert the other direction too.
anchor = """  done
fi

# ---------------------------------------------------------------------------
section "Every exported metric is described in docs/OBSERVABILITY.md\""""
new_anchor = """  done

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
  LIFTED_GATES="turn.tcp_relay.enabled"
  for key in $LIFTED_GATES; do
    if grep -qF "$key = true in production" "$CONFIG"; then
      fail "$key is refused in production again, but the docs say the gate was lifted" \\
        "Either the refusal came back by accident (a revert or a merge), or it came back on purpose — in which case move $key from LIFTED_GATES back into the required list in this script, and correct docs/PRODUCTION_READINESS.md (R9), docs/feature-support.md and README.md."
    else
      pass "$key stays lifted (gate not reintroduced)"
    fi
  done
fi

# ---------------------------------------------------------------------------
section "Every exported metric is described in docs/OBSERVABILITY.md\""""

if s.count(anchor) != 1:
    print(f"FAIL: found {s.count(anchor)} occurrences of the section anchor, expected 1")
    sys.exit(1)
s = s.replace(anchor, new_anchor)
print("  ok  reverse assertion added")

p.write_text(s)

print()
print("Verify — and note the check count goes from 10 to 11:")
print()
print("  bash scripts/check-doc-claims.sh")
