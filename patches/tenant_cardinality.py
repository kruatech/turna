#!/usr/bin/env python3
"""
Bound per-tenant metric cardinality — §10's P0, and the one gap in this project's
observability that gets worse the more successful the product is.

THE PROBLEM

Five metric families carry a `tenant` label with no cap on how many tenants:

    turna_tenant_allocations_total{tenant="..."}
    turna_tenant_bytes_relayed_total{tenant="..."}
    turna_tenant_packets_relayed_total{tenant="..."}
    turna_tenant_allocations_closed_total{tenant="..."}
    (and the fourth field of the traffic snapshot)

Escaping is handled, so this is not an injection issue. It is arithmetic: at ten
thousand tenants that is fifty thousand series returned on every scrape, from
every node. Prometheus does not degrade gracefully there — it consumes memory
proportional to series count and the operator finds out when it dies.

The same specification that asks for per-tenant metrics also asks, in §10, for
cardinality protection. The two requirements are in tension and the resolution
belongs in the code rather than in a warning nobody reads.

THE SHAPE OF THE FIX

Top N by volume, an aggregate bucket for the tail, and a counter of what was
omitted:

    turna_tenant_bytes_relayed_total{tenant="acme"}     42000
    turna_tenant_bytes_relayed_total{tenant="__other"}  1300
    turna_tenant_series_omitted                         9847

Three properties, each deliberate:

**The large tenants stay individually visible.** They are the ones an operator
investigates, and ranking by volume is a better guess at "interesting" than
insertion order.

**The tail is not lost, only aggregated.** A total that silently excluded 9,847
tenants would make `sum(turna_tenant_bytes_relayed_total)` disagree with
`turna_bytes_relayed` for no visible reason.

**The truncation is itself a metric.** An operator who wonders why their tenant is
missing has a series that says how many are, and it can be alerted on. A limit
that hides its own operation is how a dashboard comes to be trusted while wrong.

Tenant names are also truncated: a name is an identifier from configuration, and
one long enough to matter inflates every line of every scrape.

DEFAULT: 100

Enough that a deployment with a handful of real tenants sees no change at all, and
small enough that the worst case is 500 series rather than unbounded. Configurable
because the right number depends on how many tenants an operator actually watches
individually, which is not something this code can know.

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


health = pathlib.Path("crates/health/src/lib.rs")
if not health.exists():
    die("crates/health/src/lib.rs not found — run from the repository root")
if "TENANT_SERIES_CAP" in health.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. The cap, the tail bucket, and the visibility of both.
# ---------------------------------------------------------------------------
s = health.read_text()
anchor = "/// `AllocationStore::tenant_traffic_snapshot`. `None` omits"
if s.count(anchor) != 1:
    die("could not find the tenant traffic provider docs to anchor the cap")

cap = '''/// Maximum tenants emitted individually per metric family.
///
/// Five families carry a `tenant` label. Without a cap, a deployment with ten
/// thousand tenants returns fifty thousand series on every scrape from every
/// node, and Prometheus's memory use is proportional to series count — the
/// operator discovers this when it dies rather than when it grows.
///
/// 100 by default: a deployment with a handful of real tenants sees no change,
/// and the worst case becomes 500 series rather than unbounded.
static TENANT_SERIES_CAP: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(100);

/// Label value used for the aggregate of everything past the cap.
///
/// Double underscore because a tenant identifier could plausibly be "other";
/// this one is chosen to be awkward on purpose.
const TENANT_OTHER: &str = "__other";

/// Longest tenant name emitted. A name is an identifier from configuration, and
/// one long enough to matter inflates every line of every scrape.
const TENANT_NAME_MAX: usize = 64;

/// Override how many tenants are emitted individually. 0 disables the cap, which
/// is a decision an operator can make for a deployment they know is small.
pub fn set_tenant_series_cap(n: usize) {
    TENANT_SERIES_CAP.store(n, std::sync::atomic::Ordering::Relaxed);
}

fn tenant_cap() -> usize {
    TENANT_SERIES_CAP.load(std::sync::atomic::Ordering::Relaxed)
}

/// Escape a tenant name for a Prometheus label value, and truncate it.
fn tenant_label(t: &str) -> String {
    let mut out = t.replace('\\\\', "\\\\\\\\").replace('"', "\\\\\\"");
    if out.len() > TENANT_NAME_MAX {
        out.truncate(TENANT_NAME_MAX);
        out.push('~');
    }
    out
}

/// Split tenants into those emitted individually and an aggregate of the rest.
///
/// Ranked by `weight` descending, so the tenants an operator is most likely to
/// investigate stay visible and the long tail collapses. Returns
/// `(kept, other_count)` — the caller sums the tail itself, since what to sum
/// differs per family.
fn cap_tenants<T: Copy>(
    samples: &[(String, T)],
    weight: impl Fn(&T) -> u64,
) -> (Vec<(String, T)>, usize) {
    let cap = tenant_cap();
    if cap == 0 || samples.len() <= cap {
        return (samples.to_vec(), 0);
    }
    let mut ranked: Vec<(String, T)> = samples.to_vec();
    ranked.sort_by_key(|(_, v)| std::cmp::Reverse(weight(v)));
    let omitted = ranked.len() - cap;
    ranked.truncate(cap);
    (ranked, omitted)
}

/// `AllocationStore::tenant_traffic_snapshot`. `None` omits'''

health.write_text(s.replace(anchor, cap, 1))
print("  ok  lib.rs: cap, tail bucket and helpers")

# ---------------------------------------------------------------------------
# 2. Apply it to the traffic families.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "traffic render",
            """fn render_tenant_traffic_metrics(samples: &[(String, u64, u64, u64)]) -> String {
    if samples.is_empty() {
        return String::new();
    }
    let esc = |t: &str| t.replace('\\\\', "\\\\\\\\").replace('"', "\\\\\\"");
    let mut out = String::new();""",
            """fn render_tenant_traffic_metrics(samples: &[(String, u64, u64, u64)]) -> String {
    if samples.is_empty() {
        return String::new();
    }

    // Ranked by bytes: of the three counters here, bytes is the one an operator
    // chases first, and using a single ranking for all three keeps the same
    // tenants visible across families — a tenant present in one and aggregated
    // in another would be worse than either.
    let triples: Vec<(String, (u64, u64, u64))> = samples
        .iter()
        .map(|(t, b, p, c)| (t.clone(), (*b, *p, *c)))
        .collect();
    let (kept, omitted) = cap_tenants(&triples, |(b, _, _)| *b);
    let tail: (u64, u64, u64) = if omitted == 0 {
        (0, 0, 0)
    } else {
        let kept_names: std::collections::HashSet<&str> =
            kept.iter().map(|(t, _)| t.as_str()).collect();
        triples
            .iter()
            .filter(|(t, _)| !kept_names.contains(t.as_str()))
            .fold((0u64, 0u64, 0u64), |(a, b2, c2), (_, (b, p, c))| {
                (a + b, b2 + p, c2 + c)
            })
    };

    let esc = |t: &str| tenant_label(t);
    let mut out = String::new();

    // Emitted whether or not anything was omitted, so the series exists to alert
    // on and a dashboard does not have to cope with it appearing and vanishing.
    out.push_str(
        "# HELP turna_tenant_series_omitted Tenants aggregated into __other because the per-family cap was reached\\n\\
         # TYPE turna_tenant_series_omitted gauge\\n",
    );
    out.push_str(&format!("turna_tenant_series_omitted {omitted}\\n"));""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 3. Actually apply it. Computing a cap and then iterating the full set is the
#    exact shape of a setting that does nothing — the pattern this codebase spent
#    a day removing from the AF_XDP section.
# ---------------------------------------------------------------------------
patch(
    "crates/health/src/lib.rs",
    [
        (
            "bytes loop",
            """    for (t, bytes, _, _) in samples {""",
            """    for (t, (bytes, _, _)) in &kept {""",
        ),
        (
            "packets loop",
            """    for (t, _, packets, _) in samples {""",
            """    for (t, (_, packets, _)) in &kept {""",
        ),
        (
            "closed loop",
            """    for (t, _, _, closed) in samples {""",
            """    for (t, (_, _, closed)) in &kept {""",
        ),
    ],
)

# The __other line belongs after each family's loop, before the next family's
# HELP. Anchored on the HELP lines that follow, so each lands in the right place.
s2 = health.read_text()
for family, field, next_help in [
    ("bytes", "tail.0", "# HELP turna_tenant_packets_relayed_total"),
    ("packets", "tail.1", "# HELP turna_tenant_allocations_closed_total"),
]:
    anchor = f'    out.push_str(\n        "{next_help}'
    if s2.count(anchor) != 1:
        die(f"could not anchor the __other line for {family}: {s2.count(anchor)} matches")
    line = (
        f'    if omitted > 0 {{\n'
        f'        out.push_str(&format!(\n'
        f'            "turna_tenant_{family}_relayed_total{{{{tenant=\\"{{}}\\"}}}} {{}}\\n",\n'
        f'            TENANT_OTHER, {field}\n'
        f'        ));\n'
        f'    }}\n'
    )
    s2 = s2.replace(anchor, line + anchor, 1)
    print(f"  ok  lib.rs: __other for {family}")
health.write_text(s2)

# the last family has no following HELP, so it goes at the end of the function
patch(
    "crates/health/src/lib.rs",
    [
        (
            "closed __other",
            """    for (t, (_, _, closed)) in &kept {""",
            """    for (t, (_, _, closed)) in &kept {""",
        ),
    ],
)

s3 = health.read_text()
tail_anchor = """        ));
    }

    out
}"""
if s3.count(tail_anchor) == 1:
    s3 = s3.replace(
        tail_anchor,
        """        ));
    }
    if omitted > 0 {
        out.push_str(&format!(
            "turna_tenant_allocations_closed_total{{tenant=\\"{}\\"}} {}\\n",
            TENANT_OTHER, tail.2
        ));
    }

    out
}""",
        1,
    )
    health.write_text(s3)
    print("  ok  lib.rs: __other for closed")
else:
    print(f"  !!  could not anchor the last __other line ({s3.count(tail_anchor)} matches)")
    print("      add it by hand at the end of render_tenant_traffic_metrics")

print()
print("Applied to the four traffic families. The fifth —")
print("render_tenant_allocation_metrics, around line 645 — iterates a map and")
print("needs the same treatment; it is left because its shape differs enough that")
print("guessing at it would be worse than saying so.")
print()
print("Verify with an assertion, not by eye. This is the one place where a wrong")
print("result looks exactly like a right one, because both are a wall of text:")
print()
print("  cargo build -p turna-health")
print("  cargo test -p turna-health")
print()
print("Then count what a scrape actually returns with the cap in force — the")
print("number is the whole point:")
print()
print("  curl -s localhost:9099/metrics | grep -c turna_tenant_")
