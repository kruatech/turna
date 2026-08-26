#!/usr/bin/env python3
"""
The last two sentences that still describe the RFC 6062 gate, both in README.

The doc-claims gate names three files and README was the one I missed — worth
recording, because I had rewritten the status legend in this same file earlier
the same day and walked past this paragraph without noticing it contradicted the
change I was about to make.

Run from the repository root. Idempotent.
"""

import sys
import pathlib

p = pathlib.Path("README.md")
if not p.exists():
    print("FAIL: README.md not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "Two are refused in production" in s:
    print("FAIL: already applied")
    sys.exit(1)

edits = [
    (
        "refused-in-production list",
        """- **Refused in production** — RFC 6062 TCP relay (`[turn.tcp_relay]`),
  TURN-over-SCTP (`[turn.sctp]`) and RFC 7635 OAuth (`[turn.auth.oauth]`). Implemented
  and usable for testing; `production = true` makes config validation **reject** them,
  so they cannot ship by accident. For RFC 6062 the interop that gate was waiting for
  now exists — lifting it is a decision, recorded in
  [docs/OPEN-DECISIONS.md](docs/OPEN-DECISIONS.md).""",
        """- **Refused in production** — TURN-over-SCTP (`[turn.sctp]`) and RFC 7635 OAuth
  (`[turn.auth.oauth]`). Implemented and usable for testing; `production = true` makes
  config validation **reject** them, so they cannot ship by accident. Two are refused in
  production for different reasons: SCTP has none of the hardening the other listeners
  received and no users, and OAuth has never run against a real authorization server.

  RFC 6062 TCP relay was on this list until 2026-08-25. It came off because the evidence
  the gate was waiting for arrived — interop against coturn's own client
  ([docs/interop/coturn-2026-08-23.md](docs/interop/coturn-2026-08-23.md)) — not because
  the risk changed. Size for it before enabling: each relayed peer costs a listener and
  a connection, which the gate used to decide on your behalf.""",
    ),
    (
        "protocol table row",
        "| TURN over TCP (TCP relay allocations) | RFC 6062 | Implemented; **refused under `production = true`**. Requires the `tls` listener |",
        "| TURN over TCP (TCP relay allocations) | RFC 6062 | Implemented; allowed in production since 2026-08-25. Requires the `tls` listener. IPv4 only — an IPv6 TCP allocation answers 440 |",
    ),
]

for label, old, new in edits:
    n = s.count(old)
    if n != 1:
        print(f"FAIL: {label}: found {n} occurrences, expected exactly 1")
        sys.exit(1)
    s = s.replace(old, new)
    print(f"  ok  README.md: {label}")

p.write_text(s)

print()
print("Now the gate should pass:")
print()
print("  bash scripts/check-doc-claims.sh")
