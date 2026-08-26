#!/usr/bin/env python3
"""
Fix the whitespace in the AF_XDP validation messages.

The previous patch used backslash line continuations inside the Rust string
literals so the source would stay under the line limit. They did not survive the
trip through the generating script, so the runs of indentation ended up inside
the message text:

    turn.af_xdp.frame_size = 2048 is not applied: the UMEM is built with
                         the library default of 4096. Set it to 4096
                         or remove the key.

The validation itself was correct — all three errors fired and startup was
refused, which is what it is for. This only rewrites the text as single-line
literals so an operator reads a sentence instead of a column of spaces.

Run from the repository root. Idempotent.
"""

import re
import sys
import pathlib

p = pathlib.Path("crates/config/src/lib.rs")
if not p.exists():
    print("FAIL: crates/config/src/lib.rs not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "is not applied" not in s:
    print("FAIL: AF_XDP validation not present — apply afxdp_validation.py first")
    sys.exit(1)

if "  " not in "".join(re.findall(r'"turn\.af_xdp\.[^"]*"', s)):
    print("FAIL: already applied (no runs of whitespace in the messages)")
    sys.exit(1)

# Collapse any run of two or more spaces inside the three af_xdp message
# literals. Scoped to those literals so nothing else in the file is touched.
count = 0


def collapse(m: re.Match) -> str:
    global count
    before = m.group(0)
    after = re.sub(r"\s{2,}", " ", before)
    if after != before:
        count += 1
    return after


s = re.sub(r'"turn\.af_xdp\.[^"]*"', collapse, s)

if count == 0:
    print("FAIL: nothing changed")
    sys.exit(1)

p.write_text(s)
print(f"  ok  {count} message literals collapsed to single spaces")

# Show them, so the result is visible rather than asserted.
for m in re.findall(r'"turn\.af_xdp\.[^"]*"', p.read_text()):
    print(f"      {m[:110]}")
