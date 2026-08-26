#!/usr/bin/env python3
"""
Fixes what pass 2 missed: the twelve SCTP counter fields were added to `Metrics`
but not to its explicit `Self { ... }` initializer, so the struct no longer
constructs.

Worth noting how this surfaced. `Metrics` is built field-by-field rather than
with `..Default::default()`, which is why adding a field is a compile error
instead of a silently-zero counter. That is the design working: the compiler
listed all twelve by name. A `..Default::default()` there would have compiled
fine and shipped twelve counters that never moved.

Run from the repository root. Idempotent.
"""

import sys
import pathlib

p = pathlib.Path("crates/health/src/lib.rs")
if not p.exists():
    print("FAIL: crates/health/src/lib.rs not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "sctp_active: AtomicU64::new(0)" in s:
    print("FAIL: already applied")
    sys.exit(1)

old = "            tls_alpn_rejected: AtomicU64::new(0),"
n = s.count(old)
if n != 1:
    print(f"FAIL: found {n} occurrences of the anchor, expected exactly 1")
    sys.exit(1)

new = """            tls_alpn_rejected: AtomicU64::new(0),
            sctp_active: AtomicU64::new(0),
            sctp_conns_total: AtomicU64::new(0),
            sctp_closed_total: AtomicU64::new(0),
            sctp_rejected_over_cap: AtomicU64::new(0),
            sctp_rejected_per_ip: AtomicU64::new(0),
            sctp_rejected_rate_limit: AtomicU64::new(0),
            sctp_idle_timeouts: AtomicU64::new(0),
            sctp_framing_errors: AtomicU64::new(0),
            sctp_accept_errors: AtomicU64::new(0),
            sctp_send_dropped: AtomicU64::new(0),
            sctp_bytes_rx: AtomicU64::new(0),
            sctp_bytes_tx: AtomicU64::new(0),"""

p.write_text(s.replace(old, new))
print("  ok  twelve SCTP counters initialized")

chk = p.read_text()
fields = [
    "sctp_active",
    "sctp_conns_total",
    "sctp_closed_total",
    "sctp_rejected_over_cap",
    "sctp_rejected_per_ip",
    "sctp_rejected_rate_limit",
    "sctp_idle_timeouts",
    "sctp_framing_errors",
    "sctp_accept_errors",
    "sctp_send_dropped",
    "sctp_bytes_rx",
    "sctp_bytes_tx",
]
missing = [f for f in fields if f"{f}: AtomicU64::new(0)" not in chk]
if missing:
    print(f"FAIL: still missing {missing}")
    sys.exit(1)
print("  ok  all twelve present")
