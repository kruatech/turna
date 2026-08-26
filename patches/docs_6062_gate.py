#!/usr/bin/env python3
"""
The RFC 6062 production gate is gone; five sentences in the docs still say it is
there. This corrects them.

This matters more than tidiness. `check-doc-claims.sh` reads the docs to find
which refusals are claimed and then asserts each one exists in
`config::validate()` — matched on the operator-visible diagnostic rather than the
field path, precisely so that deleting a gate cannot pass unnoticed. Leaving
these sentences in place would fail that gate, which is the gate working.

It is also the failure mode this project has already paid for once:
ATTR_ALTERNATE_SERVER stayed broken across three releases because the docs said
it was fixed.

What is *not* changed: `docs/COMPLIANCE.md` keeps saying an RFC 6062 allocation
always answers 440 for IPv6. That is still true — the TCP relay path is
IPv4-only, and lifting a production gate did not implement a missing address
family.

Run from the repository root. Idempotent.
"""

import sys
import pathlib


def die(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def patch(path: str, edits: list[tuple[str, str, str]]) -> None:
    p = pathlib.Path(path)
    if not p.exists():
        die(f"{path} not found — run from the repository root")
    s = p.read_text()
    for label, old, new in edits:
        n = s.count(old)
        if n != 1:
            die(f"{path} / {label}: found {n} occurrences, expected exactly 1")
        s = s.replace(old, new)
        print(f"  ok  {path.split('/')[-1]}: {label}")
    p.write_text(s)


fs = pathlib.Path("docs/feature-support.md")
if not fs.exists():
    die("docs/feature-support.md not found — run from the repository root")
if "no longer refused" in fs.read_text():
    die("already applied")

patch(
    "docs/feature-support.md",
    [
        (
            "tcp relay row",
            "| TURN over TCP relay (RFC 6062)             | **refused in production** (gate liftable) | Implemented over TURNS (CONNECT / ConnectionBind / peer-initiated listener, ownership-bound binds). **Interop verified** (`docs/interop/transports-2026-08-19.md`): both the plain form and the one that pipelines the first application bytes into the same write as `ConnectionBind` — the case RFC 6062 §5.4 permits and the reason the detach prebuffer in `transport::tcp_tls` exists. That prebuffer had never been exercised by a real client. The `production = true` refusal is still in `config::validate()` and is now a **decision**, not a missing prerequisite. |",
            "| TURN over TCP relay (RFC 6062)             | beta, **no longer refused in production** | Implemented over TURNS (CONNECT / ConnectionBind / peer-initiated listener, ownership-bound binds). **Interop verified twice**: our own client exercised both the plain form and the one that pipelines the first application bytes into the same write as `ConnectionBind` — the case RFC 6062 §5.4 permits and the reason the detach prebuffer in `transport::tcp_tls` exists (`docs/interop/transports-2026-08-19.md`) — and coturn's `turnutils_uclient` then agreed about the wire (`docs/interop/coturn-2026-08-23.md`). The `production = true` refusal was lifted on 2026-08-25 once that second implementation was on record. **Size for it before enabling:** a listener and a connection per relayed peer, which is a different operational profile from UDP relaying, and the gate no longer makes that decision for you. Still IPv4-only — an IPv6 TCP allocation answers 440. |",
        ),
    ],
)

patch(
    "docs/PRODUCTION_READINESS.md",
    [
        (
            "readiness table row",
            "| RFC 6062 TCP relay allocations | **Refused in production** | `production = true` rejects `[turn.tcp_relay].enabled` — config validation fails, the node does not start. Test it with `production = false`; the gate lifts when interop and pipelined-client hardening are done. |",
            "| RFC 6062 TCP relay allocations | Beta, allowed in production | The `production = true` refusal was lifted on 2026-08-25: interop is recorded against our own client and against coturn's (`docs/interop/coturn-2026-08-23.md`), including the pipelined `ConnectionBind` case that no independent client had exercised before. What the gate used to stand in for — a sizing decision, since each relayed peer costs a listener and a connection — is now yours to make. Still IPv4-only. |",
        ),
        (
            "R9 heading and body",
            """### R9 — experimental features are refused in production, and that is deliberate

`config::validate()` hard-fails when `production = true` and any of
`turn.tcp_relay.enabled`, `turn.sctp.enabled`, or `turn.auth.oauth.enabled` is
set. The node does not start with a diagnostic naming the key.""",
            """### R9 — two experimental features are refused in production, and that is deliberate

`config::validate()` hard-fails when `production = true` and either
`turn.sctp.enabled` or `turn.auth.oauth.enabled` is set. The node does not start,
with a diagnostic naming the key.

`turn.tcp_relay.enabled` was on that list until 2026-08-25. It came off because
the evidence the gate was waiting for arrived — interop against an independent
implementation — not because the risk changed. The remaining two are refused for
different reasons: SCTP has none of the hardening the other listeners received
and no users, and OAuth has never been exercised against a real authorization
server.""",
        ),
        (
            "risk summary row",
            "| RFC 6062 TCP relay, SCTP, OAuth | Refused in production (R9) |",
            "| SCTP, OAuth | Refused in production (R9) |\n| RFC 6062 TCP relay | Beta, no longer refused — gate lifted 2026-08-25 (R9) |",
        ),
    ],
)

patch(
    "docs/COMPLIANCE.md",
    [
        (
            "validate list",
            """- **Three features are refused outright under `production = true`.**
  `config::validate()` fails the start when `turn.tcp_relay.enabled`,""",
            """- **Two features are refused outright under `production = true`.**
  `config::validate()` fails the start when""",
        ),
    ],
)

print()
print("applied. The one that matters:")
print()
print("  bash scripts/check-doc-claims.sh")
print()
print("That gate reads these documents for claimed refusals and asserts each one")
print("exists in config::validate(). It was failing before this patch — correctly,")
print("because the docs claimed a gate that had been removed.")
print()
print("Two more files mention the old state and need a look by eye:")
print("  docs/verification/interop-plan.md:98  — an action item now done")
print("  docs/COMPLIANCE.md:76                 — check the sentence still parses")
