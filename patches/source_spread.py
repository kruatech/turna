#!/usr/bin/env python3
"""
Spread load clients across source addresses, so a test measures the server
instead of the per-IP rate limiter.

WHAT THIS FIXES

`TieredLimits::allocate` is `(32, 16)` — 32 allocations/second per source IP with
a burst of 16. Every load client binds to `127.0.0.1:0`, so they share one source
and the limiter refuses most of them: measured, 122 refusals against 59
allocations when 38 channels were requested. The limiter was correct; the
measurement was of the limiter.

That is also not what a real deployment looks like. Clients arrive from many
addresses, where the per-IP allocate limit never binds and the ceiling that
matters is `per_prefix` at 40 000/s. A test that puts every client behind one
address measures a pathological case — everyone behind a single NAT — and calls
it capacity.

HOW

On Linux the whole of `127.0.0.0/8` is local, so `127.0.0.2`, `127.0.0.3` and so
on are usable as source addresses with no interface configuration at all. Client
`i` binds to `127.0.0.(1 + i % spread)`.

`--source-ips N` opts in; the default of 1 keeps existing behaviour, because
changing what every existing check measures without being asked would invalidate
the records already written against them.

Implemented as a round-robin counter inside `control_bind_addr` rather than an
index parameter: every client binds its control socket exactly once, so call
order distributes them identically, and no call site has to change.

Not portable: macOS requires `ifconfig lo0 alias` for anything but 127.0.0.1, and
this silently gets one source there. Documented in the flag's help rather than
worked around, since the load host in this project is Linux.

WHY IT IS NOT THE RECONNECT-STORM TEST YET

This is the prerequisite. A storm test drops N established allocations at once and
measures how many come back and how fast — and until clients can arrive from
different addresses, that test would only ever re-measure `allocate: (32, 16)`.

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


tc = pathlib.Path("tools/load-test/src/turn_client.rs")
if not tc.exists():
    die("tools/load-test/src/turn_client.rs not found — run from the repository root")
if "SOURCE_SPREAD" in tc.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. The spreading itself.
# ---------------------------------------------------------------------------
patch(
    "tools/load-test/src/turn_client.rs",
    [
        (
            "spread state and helper",
            """pub fn control_bind_addr(server: SocketAddr) -> String {
    peer_bind_addr(server.is_ipv6())
}""",
            """/// How many distinct loopback source addresses to spread control sockets over.
/// 1 (the default) means every client uses `127.0.0.1`, as before.
pub static SOURCE_SPREAD: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Round-robin position within the spread. One bump per control socket.
static SPREAD_NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Local address for a **control** socket, spread across `--source-ips`
/// addresses in `127.0.0.0/8` when that flag is set.
///
/// Rotates rather than taking a client index, so no caller changes: each client
/// binds its control socket exactly once, in `allocate_family`, and round-robin
/// by call order distributes them the same way an index would.
///
/// This exists because the per-source-IP allocate limit is 32/s with a burst of
/// 16 (`TieredLimits::allocate`), and every client sharing `127.0.0.1` means a
/// load test measures that limiter rather than the server: 38 requested channels
/// produced 122 refusals against 59 allocations.
///
/// A real deployment does not look like that. Clients arrive from many
/// addresses, where the per-IP limit never binds and `per_prefix` (40 000/s) is
/// the ceiling that matters. One source address is the everyone-behind-one-NAT
/// case — worth testing deliberately, but not capacity.
///
/// `--bind-ip` wins when set: it exists for labs where the server is not on
/// loopback and the source must be a specific address, and overriding it here
/// would break those. IPv6 is not spread — `::2` is not local the way
/// `127.0.0.2` is, and adding it needs interface configuration.
pub fn control_bind_addr(server: SocketAddr) -> String {
    if BIND_IP.get().is_some() || server.is_ipv6() {
        return peer_bind_addr(server.is_ipv6());
    }
    match SOURCE_SPREAD.get().copied().unwrap_or(1) {
        0 | 1 => peer_bind_addr(false),
        spread => {
            // Capped at 250 to stay inside the last octet; a run needing more
            // sources than that needs more than one host anyway.
            let spread = spread.min(250);
            let n = SPREAD_NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % spread + 1;
            format!("127.0.0.{n}:0")
        }
    }
}""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. The flag.
# ---------------------------------------------------------------------------
patch(
    "tools/load-test/src/main.rs",
    [
        (
            "cli flag",
            """    #[arg(long)]
    bind_ip: Option<String>,
}""",
            """    #[arg(long)]
    bind_ip: Option<String>,

    /// Spread client control sockets over N addresses in 127.0.0.0/8.
    ///
    /// Defaults to 1 — every client from 127.0.0.1, as before. Raise it when a
    /// run is meant to measure the server rather than the per-source-IP allocate
    /// limiter, which is 32/s with a burst of 16: 38 channels from one address
    /// produced 122 refusals against 59 allocations.
    ///
    /// Linux only. The whole of 127.0.0.0/8 is local there; macOS needs
    /// `ifconfig lo0 alias 127.0.0.2` for each address and will otherwise bind
    /// them all to the same place without saying so.
    ///
    /// Ignored when --bind-ip is given, and for IPv6 servers.
    #[arg(long, default_value_t = 1)]
    source_ips: u32,
}""",
        ),
        (
            "wire the flag",
            """    // Set before any client runs: `peer_bind_addr` reads it for every socket.
    if let Some(ref ip) = cli.bind_ip {""",
            """    // Set before any client runs: `control_bind_addr_indexed` reads it.
    if cli.source_ips > 1 {
        let _ = turn_client::SOURCE_SPREAD.set(cli.source_ips);
        eprintln!(
            "source spread: clients bound across 127.0.0.1-127.0.0.{} \\
             (Linux only; on macOS these need lo0 aliases)",
            cli.source_ips.min(250)
        );
    }

    // Set before any client runs: `peer_bind_addr` reads it for every socket.
    if let Some(ref ip) = cli.bind_ip {""",
        ),
    ],
)

print()
print("applied — no call sites needed changing.")
print()
print("Verify:")
print("  cargo build --release -p turna-load-test")
print()
print("Then the thing worth checking, since it is the whole point: run 38")
print("channels with and without the spread and compare the server's")
print("rate_limited counter. Without it we measured 122 refusals against 59")
print("allocations; with it, that should largely go away.")
