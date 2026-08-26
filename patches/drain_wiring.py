#!/usr/bin/env python3
"""
Wire `drain_timeout_secs` at all three places a RelayServer is built.

`with_external_ip6` appears three times in services/node — the io_uring datapath,
the tokio datapath, and the QUIC/DTLS relay egress each construct their own
server. Adding the drain timeout to one of them would make the key work in some
configurations and silently not in others, which is worse than not working at
all: a setting that behaves differently depending on the datapath is one an
operator cannot reason about, and the failure does not reproduce.

The AF_XDP section in this project accepted five keys it never applied. That is
the shape being avoided here.

Run from the repository root. Idempotent.
"""

import sys
import pathlib

p = pathlib.Path("services/node/src/main.rs")
if not p.exists():
    print("FAIL: services/node/src/main.rs not found — run from the repository root")
    sys.exit(1)

s = p.read_text()

if "with_drain_timeout_secs" in s:
    print("FAIL: already applied")
    sys.exit(1)

# Three distinct surroundings, so each is anchored on its own context rather than
# on the shared `.with_external_ip6(external_ip6)` line.
edits = [
    (
        "io_uring datapath",
        """                        cluster_routing.clone(),
                    )
                    .with_external_ip6(external_ip6),
                );
                let af_cfg = config.af_xdp.clone();""",
        """                        cluster_routing.clone(),
                    )
                    .with_external_ip6(external_ip6)
                    .with_drain_timeout_secs(config.relay.drain_timeout_secs),
                );
                let af_cfg = config.af_xdp.clone();""",
    ),
    (
        "tokio datapath",
        """                    migration,
                    tcp_relay,
                )
                .with_external_ip6(external_ip6);""",
        """                    migration,
                    tcp_relay,
                )
                .with_external_ip6(external_ip6)
                .with_drain_timeout_secs(config.relay.drain_timeout_secs);""",
    ),
    (
        "QUIC/DTLS relay egress",
        """                                cluster_routing.clone(),
                            )
                            .with_external_ip6(external_ip6),
                        );
                        let qd_sinks = turna_relay::new_client_sinks();""",
        """                                cluster_routing.clone(),
                            )
                            .with_external_ip6(external_ip6)
                            .with_drain_timeout_secs(config.relay.drain_timeout_secs),
                        );
                        let qd_sinks = turna_relay::new_client_sinks();""",
    ),
]

for label, old, new in edits:
    n = s.count(old)
    if n != 1:
        print(f"FAIL: {label}: found {n} occurrences, expected exactly 1")
        sys.exit(1)
    s = s.replace(old, new)
    print(f"  ok  {label}")

p.write_text(s)

count = p.read_text().count("with_drain_timeout_secs")
if count != 3:
    print(f"FAIL: expected 3 call sites, found {count}")
    sys.exit(1)
print(f"  ok  all three construction sites wired")

print()
print("Verify:")
print("  cargo clippy -p turna-node --all-targets -- -D warnings")
print()
print("Then confirm the key is actually read, which is the whole point:")
print()
print("  # set it to something distinctive and watch the drain take that long")
print("  sed 's|max_allocations = 400|max_allocations = 400\\\\ndrain_timeout_secs = 5|' \\\\")
print("    /tmp/storm.toml > /tmp/drain5.toml")
print()
print("A node holding abandoned allocations should now exit in about two seconds")
print("regardless — the stall detection fires before any timeout — so to see the")
print("key take effect, drain a node with *live* traffic and compare 5 against 30.")
