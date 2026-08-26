#!/usr/bin/env python3
"""
Apply the enterprise-readiness patches in dependency order.

WHY AN ORDER EXISTS

Several patches anchor on text an earlier one introduced. `rate_sampler` inserts
next to a field `capacity_api` added; `drain_wiring` needs the setter
`drain_timeout` defines; `reconnect_storm` needs the CLI flag `source_spread`
adds. Run out of order they refuse with "found 0 occurrences" rather than
corrupting anything — every patch verifies its anchor is unique before writing —
but the failure is confusing when the cause is sequence rather than content.

ALREADY-MERGED PATCHES

The SCTP, AF_XDP and RFC 6062 work is in `main` (PR #113). Those scripts are
included so this archive is a complete record, and they will refuse as
already-applied on any tree that has that merge. A refusal there is the expected
outcome, not a problem.

WHAT THIS DOES NOT DO

Verify. Every patch checks its own anchors, and this checks the order, but
nothing here builds or tests anything. Two of these needed a compiler round to
find a mistake I had made — `PacketProcessor` where a `RelayServer` was expected,
and a `match` arm returning the wrong type — and a runner that reported success
on both would have been worse than no runner.

    python3 patches/apply_all.py          # apply, in order
    python3 patches/apply_all.py --list   # show the order and stop
"""

import subprocess
import sys
import pathlib

# In dependency order. The comment on each is what it needs, where that is not
# obvious from the name.
ORDER = [
    # ── already in main via PR #113; these will refuse ──────────────────────
    ("sctp_hardening.py", "merged"),
    ("sctp_wiring.py", "merged — needs sctp_hardening"),
    ("sctp_fix_init.py", "merged — needs sctp_wiring"),
    ("sctp_final.py", "merged"),
    ("afxdp_validation.py", "merged"),
    ("afxdp_msg_cleanup.py", "merged — needs afxdp_validation"),
    ("pass_logs_and_gates.py", "merged"),
    ("docs_6062_gate.py", "merged"),
    ("readme_6062.py", "merged"),
    ("gate_script_6062.py", "merged"),
    # ── the enterprise branch ──────────────────────────────────────────────
    ("capacity_api.py", "first: others anchor on what it adds"),
    ("relay_ports_metric.py", "needs capacity_api"),
    ("relay_ports_wiring.py", ""),
    ("observability_ports.py", "documents the port metrics"),
    ("rate_sampler.py", "needs capacity_api"),
    ("rate_ticker.py", "needs relay_ports_wiring"),
    ("host_load.py", "needs rate_sampler"),
    ("airgap_fixes.py", "telemetry log line + the air-gap check"),
    ("source_spread.py", ""),
    ("reconnect_storm.py", "needs source_spread"),
    ("drain_timeout.py", ""),
    ("drain_wiring.py", "needs drain_timeout"),
    ("correlation_metadata.py", ""),
    ("proto_compat_gate.py", ""),
    ("tenant_cardinality.py", "needs capacity_api and rate_sampler"),
]

here = pathlib.Path(__file__).parent

if "--list" in sys.argv:
    for i, (name, note) in enumerate(ORDER, 1):
        suffix = f"  ({note})" if note else ""
        print(f"{i:2}. {name}{suffix}")
    sys.exit(0)

if not pathlib.Path("Cargo.toml").exists():
    print("FAIL: run from the repository root")
    sys.exit(1)

applied, refused, missing, failed = [], [], [], []

for name, _note in ORDER:
    path = here / name
    if not path.exists():
        missing.append(name)
        continue
    r = subprocess.run(
        [sys.executable, str(path)], capture_output=True, text=True
    )
    out = r.stdout + r.stderr
    if r.returncode == 0:
        applied.append(name)
        print(f"  applied  {name}")
    elif "already applied" in out or "already exists" in out:
        refused.append(name)
        print(f"  present  {name}")
    else:
        failed.append((name, out.strip().splitlines()[-1] if out.strip() else "?"))
        print(f"  FAILED   {name}")

print()
print(f"applied {len(applied)}, already present {len(refused)}, failed {len(failed)}")

if missing:
    print(f"\nnot in this archive: {', '.join(missing)}")

if failed:
    print("\nfailures:")
    for name, why in failed:
        print(f"  {name}: {why}")
    print()
    print("A 'found 0 occurrences' failure usually means the anchor text differs")
    print("from the tree this was written against — often because `cargo fmt`")
    print("reflowed it. The patch prints which anchor; compare it with the file.")

print()
print("Nothing here has been compiled. Next:")
print()
print("  cargo fmt --all")
print("  cargo clippy --workspace --all-targets \\")
print("    --features \"tls,dtls,quic,web-transport,sctp\" -- -D warnings")
print("  cargo test --workspace --features sctp -- --test-threads=1")
print("  bash scripts/check-doc-claims.sh")
print()
print("Expect the compiler to find work these patches leave behind on purpose:")
print("  * AuditEntry call sites need the new correlation_id field")
print("  * render_tenant_allocation_metrics (the fifth tenant family) is not")
print("    capped — its shape differs enough that guessing would be worse")
sys.exit(1 if failed else 0)
