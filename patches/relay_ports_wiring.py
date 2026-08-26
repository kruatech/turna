#!/usr/bin/env python3
"""
Feed the relay-port gauges from the node.

`port_pool_usage()` exists and nothing calls it, which is the state the SCTP
counters were left in by their first pass — present and unscraped.

TICKER, NOT PROVIDER, AND WHY

The health crate supports both: `TenantTrafficProvider` and
`RelayRouteMetricsProvider` are closures evaluated at scrape time, while the SCTP
counters are mirrored by a background ticker. A provider is the better shape —
no staleness — but adding one means changing `serve_with_cluster_routes`'s
signature, which has already grown twice this week.

A ticker costs up to five seconds of staleness. For port exhaustion that is
irrelevant: a range does not fill in five seconds, and an alert on utilisation
firing one interval late changes nothing. The signature churn is the larger cost,
so the ticker wins here. If a metric ever appears where freshness matters, that
is the one worth changing the signature for.

Run from the repository root. Idempotent.
"""

import sys
import pathlib

p = pathlib.Path("services/node/src/main.rs")
if not p.exists():
    print("FAIL: services/node/src/main.rs not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "port_pool_usage" in s:
    print("FAIL: already applied")
    sys.exit(1)

old = """            // Per-tenant traffic provider: snapshot the store's cumulative
            // per-tenant counters (accrued at allocation teardown) on each
            // scrape. Empty until tenant-scoped allocations have closed, so
            // single-tenant deployments see no extra output."""

new = """            // Relay-port occupancy, mirrored on a ticker.
            //
            // A ticker rather than a scrape-time provider like the two below: a
            // provider would need another parameter on `serve_*`, whose signature
            // has already grown twice this week, and the cost of the ticker is up
            // to five seconds of staleness. A port range does not fill in five
            // seconds, so an alert firing one interval late is not a worse alert.
            //
            // Tenant pools are summed into the global gauges rather than exported
            // per tenant. `port_pool_usage()` keeps the per-pool detail for
            // anything that wants it without every scrape paying for the labels.
            {
                let store = store.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    use std::sync::atomic::Ordering::Relaxed;
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(5));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        let (used, total) = store
                            .port_pool_usage()
                            .iter()
                            .fold((0usize, 0usize), |(u, t), (_, in_use, cap)| {
                                (u + in_use, t + cap)
                            });
                        metrics.relay_ports_in_use.store(used as u64, Relaxed);
                        metrics.relay_ports_total.store(total as u64, Relaxed);
                    }
                });
            }

            // Per-tenant traffic provider: snapshot the store's cumulative
            // per-tenant counters (accrued at allocation teardown) on each
            // scrape. Empty until tenant-scoped allocations have closed, so
            // single-tenant deployments see no extra output."""

n = s.count(old)
if n != 1:
    print(f"FAIL: found {n} occurrences of the anchor, expected exactly 1")
    sys.exit(1)

p.write_text(s.replace(old, new))
print("  ok  main.rs: relay port gauges mirrored on a 5 s ticker")

chk = p.read_text()
for needed in ("port_pool_usage", "relay_ports_in_use", "relay_ports_total"):
    if needed not in chk:
        print(f"FAIL: {needed} missing after the edit")
        sys.exit(1)

depth = 0
for c in chk:
    if c == "{":
        depth += 1
    elif c == "}":
        depth -= 1
if depth != 0:
    print(f"FAIL: brace depth {depth} after the edit")
    sys.exit(1)
print("  ok  braces balanced")

print()
print("Verify:")
print("  cargo clippy -p turna-node --all-targets -- -D warnings")
print()
print("Then the doc-claims gate, which will fail until docs/OBSERVABILITY.md")
print("gains rows for the three turna_relay_ports_* series:")
print("  bash scripts/check-doc-claims.sh")
