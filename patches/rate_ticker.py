#!/usr/bin/env python3
"""
Feed the rate sampler: one tick per second, beside the port-pool ticker.

A separate task rather than folding it into the existing five-second one. The
sampler's window is defined in one-second buckets, so ticking it every five
seconds would fill two buckets in ten — the mean would divide a five-second delta
by one second and report five times the real rate, or divide by ten buckets of
which eight are stale. Sharing the ticker would silently make the numbers wrong
rather than obviously break.

Cheap enough to leave alone: two atomic loads, two swaps, two stores per second.

Run from the repository root. Idempotent.
"""

import sys
import pathlib

p = pathlib.Path("services/node/src/main.rs")
if not p.exists():
    print("FAIL: services/node/src/main.rs not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "rates.tick" in s:
    print("FAIL: already applied")
    sys.exit(1)

old = """            // Relay-port occupancy, mirrored on a ticker."""

new = """            // Relayed traffic rate, sampled once a second.
            //
            // Its own task rather than a branch of the five-second port ticker
            // below: `RateSampler`'s window is ten one-second buckets, so ticking
            // it every five seconds would put a five-second delta into a bucket
            // meant to hold one second and leave eight buckets stale. The mean
            // would be wrong by roughly a factor of five while still looking like
            // a plausible number — the failure mode worth avoiding, since nothing
            // would flag it.
            //
            // The cost is two loads, two swaps and two stores per second.
            {
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    use std::sync::atomic::Ordering::Relaxed;
                    let mut tick =
                        tokio::time::interval(std::time::Duration::from_secs(1));
                    // Skip rather than Burst: after a stall, catching up would
                    // write several buckets from one counter reading and report a
                    // rate that never happened.
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        let bytes = metrics.bytes_received.load(Relaxed)
                            + metrics.bytes_sent.load(Relaxed);
                        let packets = metrics.packets_received.load(Relaxed)
                            + metrics.packets_sent.load(Relaxed);
                        metrics.rates.tick(bytes, packets);
                    }
                });
            }

            // Relay-port occupancy, mirrored on a ticker."""

n = s.count(old)
if n != 1:
    print(f"FAIL: found {n} occurrences of the anchor, expected exactly 1")
    sys.exit(1)

p.write_text(s.replace(old, new, 1))
print("  ok  main.rs: rate sampler ticked once a second")

chk = p.read_text()
if "metrics.rates.tick(bytes, packets)" not in chk:
    print("FAIL: tick call missing")
    sys.exit(1)

depth = 0
for c in chk:
    if c == "{":
        depth += 1
    elif c == "}":
        depth -= 1
if depth != 0:
    print(f"FAIL: brace depth {depth}")
    sys.exit(1)
print("  ok  braces balanced")

print()
print("Verify:")
print("  cargo clippy -p turna-health -p turna-node --all-targets -- -D warnings")
print()
print("Then watch it fill — the first ten seconds should report null, and a")
print("steady load should settle on a number:")
print()
print("  curl -s localhost:9099/capacity | python3 -c \\")
print("    'import json,sys; d=json.load(sys.stdin); print(d[\"bytes_per_sec\"], d[\"packets_per_sec\"])'")
print()
print("Note: bytes_per_sec sums received AND sent, so a relayed frame counts")
print("twice — in and out. That is the load on the node, not the traffic of one")
print("direction, which is the number an admission decision wants.")
