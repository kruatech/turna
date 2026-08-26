#!/usr/bin/env python3
"""
Two fixes from the first air-gap run. One is mine, one is the code's.

THE CODE'S
----------
`telemetry.rs` logs "OTLP endpoint not configured — distributed tracing disabled"
*before* installing the tracing subscriber, on the line above `try_init_with_fmt!`.
A log emitted before a subscriber exists goes nowhere, so that message has never
reached a log file. An operator checking whether telemetry is off finds nothing —
which is how the air-gap check came to fail on a node that was behaving correctly.

Moved after initialisation, where the neighbouring "telemetry initialised" line
already lives and is visible.

MINE
----
`grep -c` prints 0 and *exits 1* when there are no matches, so
`grep -c ... || echo 0` printed two zeros and the comparison read "0\\n0". Visible
in the run as `resolvers: 0` followed by a stray `0`, and as
`namespace had 0\\n0 resolvers`. Replaced with a form that cannot produce it.

Also: the OTLP check now asserts on the line that is actually emitted — the
`otlp=` field of "telemetry initialised" being empty — rather than on a line that
was never going to appear. Asserting on the observable output rather than the
intended output is the same discipline as the rest of these checks.

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


tel = pathlib.Path("crates/observability/src/telemetry.rs")
if not tel.exists():
    die("crates/observability/src/telemetry.rs not found — run from the repository root")
if "tracing disabled (no OTLP endpoint" in tel.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. Move the message to where it can be seen.
# ---------------------------------------------------------------------------
patch(
    "crates/observability/src/telemetry.rs",
    [
        (
            "remove the pre-subscriber log",
            """    } else {
        info!("OTLP endpoint not configured — distributed tracing disabled");
        // Registry → EnvFilter → fmt
        let base = tracing_subscriber::registry().with(filter);
        try_init_with_fmt!(base)?;
    }""",
            """    } else {
        // No log here: the subscriber is installed on the next line, and anything
        // emitted before it exists is discarded. This message used to live here
        // and had therefore never appeared in a log — found when an air-gap check
        // looked for it and a correctly-behaving node failed the check. It now
        // goes out below, with the other startup line.
        //
        // Registry → EnvFilter → fmt
        let base = tracing_subscriber::registry().with(filter);
        try_init_with_fmt!(base)?;
    }""",
        ),
        (
            "log after the subscriber exists",
            """    info!(
        service  = %config.service_name,
        version  = %config.service_version,
        instance = %config.instance_id,
        otlp     = %config.otlp_endpoint,
        sampling = config.sampling.base_ratio,
        "telemetry initialized"
    );""",
            """    if !otlp_enabled {
        // Stated explicitly rather than left to be inferred from the empty
        // `otlp=` field below. An operator verifying that a deployment sends
        // nothing outward should find a sentence saying so, not an absence.
        info!("distributed tracing disabled (no OTLP endpoint configured)");
    }

    info!(
        service  = %config.service_name,
        version  = %config.service_version,
        instance = %config.instance_id,
        otlp     = %config.otlp_endpoint,
        sampling = config.sampling.base_ratio,
        "telemetry initialized"
    );""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. The check: assert on what is emitted, and stop double-counting zeros.
# ---------------------------------------------------------------------------
patch(
    "scripts/verify/air-gap.sh",
    [
        (
            "otlp assertion",
            """if grep -q "OTLP endpoint not configured" "$OUT/node.log"; then
  ok "OTLP disabled by default, and says so" \\
     "Zero outbound telemetry by default" "node logged 'OTLP endpoint not configured — distributed tracing disabled'"
else
  bad "no log line confirming OTLP is disabled" \\
      "Zero outbound telemetry by default" "expected 'OTLP endpoint not configured' in the log"
fi""",
            """# Two signals, either of which settles it. The sentence is the one an operator
# would look for; the empty `otlp=` field on the startup line is the one that
# cannot be wrong, because it is the configured value being echoed back.
if grep -q "distributed tracing disabled" "$OUT/node.log"; then
  ok "OTLP disabled by default, and says so" \\
     "Zero outbound telemetry by default" "node logged 'distributed tracing disabled (no OTLP endpoint configured)'"
elif grep -qE 'telemetry initialized.*otlp=( |$)' "$OUT/node.log"; then
  ok "OTLP endpoint empty on the startup line" \\
     "Zero outbound telemetry by default" "\\`otlp=\\` is empty in 'telemetry initialized' — no exporter was built"
else
  bad "could not confirm OTLP is disabled from the log" \\
      "Zero outbound telemetry by default" "neither the disabled message nor an empty otlp= field found; check node.log"
fi""",
        ),
        (
            "resolver count",
            """NS_COUNT=$(ip netns exec "$NS" sh -c 'grep -c "^nameserver" /etc/resolv.conf 2>/dev/null || echo 0')""",
            """# `grep -c` prints 0 and exits 1 when nothing matches, so a `|| echo 0` fallback
# appends a second zero and the value becomes "0\\n0" — which is neither 0 nor a
# number. Counted with awk instead, which returns a count and exits 0 either way.
NS_COUNT=$(ip netns exec "$NS" awk '/^nameserver/{n++} END{print n+0}' /etc/resolv.conf 2>/dev/null)
NS_COUNT=${NS_COUNT:-0}""",
        ),
        (
            "resolver display",
            """say "  resolvers: $(ip netns exec "$NS" sh -c 'grep -c nameserver /etc/resolv.conf 2>/dev/null || echo 0')\"""",
            """say "  resolvers: $(ip netns exec "$NS" awk '/^nameserver/{n++} END{print n+0}' /etc/resolv.conf 2>/dev/null)\"""",
        ),
    ],
)

print()
print("Verify — the awk form, before running the whole thing again:")
print()
print("  awk '/^nameserver/{n++} END{print n+0}' /dev/null    # expect: 0")
print()
print("Then:")
print("  cargo build --release -p turna-node")
print("  sudo env \"PATH=$PATH\" scripts/verify/air-gap.sh")
