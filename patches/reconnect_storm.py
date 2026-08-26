#!/usr/bin/env python3
"""
Reconnect storm — §15 P0.

WHAT IT MEASURES

N clients hold allocations. All of them vanish at once — sockets dropped, no
Refresh with lifetime 0, which is what a client losing its network or a node
disappearing looks like from the server's side. Then all N come back
simultaneously.

The numbers that matter: how many re-establish, how long the last one takes, and
whether the server's own protections stand in the way of recovery. A rate limiter
that correctly refuses an attacker also refuses a datacentre's worth of clients
returning after a link flap, and the difference between those two cases is not
visible from inside the limiter.

WHY IT COULD NOT BE WRITTEN BEFORE TODAY

Every load client bound to `127.0.0.1`, so a storm would have measured
`TieredLimits::allocate` — 32/s per source with a burst of 16 — and nothing else.
With `--source-ips`, clients arrive from distinct addresses as they do in
production, where the per-IP limit does not bind and `per_prefix` (40 000/s) is
the ceiling. Measured back to back: 38 channels from one source gave 33 errors and
5 allocations; from 40 sources, 0 errors and 38 allocations, with the limiter
untouched.

The storm is still worth running in both shapes. One source is the
everyone-behind-one-NAT case and a real deployment has some of those; it is simply
not the same question.

WHAT IT DOES NOT MEASURE

Recovery of *media*. The clients re-allocate, which is what a TURN server can
offer; whether a call resumes depends on ICE restart in the application above,
outside this server's responsibility (§18 of the spec is explicit about that).

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


main = pathlib.Path("tools/load-test/src/main.rs")
if not main.exists():
    die("tools/load-test/src/main.rs not found — run from the repository root")
if "ReconnectStorm" in main.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. The mode.
# ---------------------------------------------------------------------------
patch(
    "tools/load-test/src/main.rs",
    [
        (
            "mode variant",
            """enum Mode {
    Binding {""",
            """enum Mode {
    /// Establish N allocations, drop them all at once, and re-establish them
    /// simultaneously — a link flap or a node loss, from the server's side.
    ///
    /// Reports how many came back, how long the slowest took, and what the
    /// server refused along the way. Pair it with `--source-ips`: from a single
    /// source this measures the per-IP allocate limiter (32/s, burst 16) rather
    /// than the server, which is a different and much smaller question.
    ReconnectStorm {
        /// Clients in the storm.
        #[arg(long, default_value_t = 100)]
        clients: usize,
        /// Storms to run. More than one shows whether recovery degrades as
        /// limiter budgets deplete — the first storm is always the kindest.
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        /// Seconds to hold allocations before dropping them.
        #[arg(long, default_value_t = 5)]
        settle: u64,
        /// Seconds to wait for reconnection before calling a client lost.
        #[arg(long, default_value_t = 30)]
        recover_timeout: u64,
    },
    Binding {""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. The implementation.
# ---------------------------------------------------------------------------
s = main.read_text()
anchor = "#[tokio::main]\nasync fn main() {"
if s.count(anchor) != 1:
    die("could not find main() to anchor the storm implementation")

impl = '''/// One round: establish `clients` allocations, drop them, re-establish.
///
/// Returns `(established, recovered, slowest_recovery_ms)`.
///
/// Establishment and recovery are both concurrent — a storm is defined by
/// everyone arriving at once, and staggering them would measure something else.
/// Each client is timed individually so the reported figure is the slowest
/// client's recovery rather than the wall time of the round, which would be the
/// same number only by coincidence.
async fn storm_round(
    server: SocketAddr,
    creds: &turn_client::Creds,
    clients: usize,
    settle: u64,
    recover_timeout: u64,
    round: usize,
) -> (usize, usize, u128) {
    // ── establish ──────────────────────────────────────────────────────────
    let mut sessions = Vec::with_capacity(clients);
    let mut handles = Vec::with_capacity(clients);
    for _ in 0..clients {
        let creds = creds.clone();
        handles.push(tokio::spawn(async move {
            turn_client::allocate_family(server, &creds, 0, None).await.ok()
        }));
    }
    for h in handles {
        if let Ok(Some(sess)) = h.await {
            sessions.push(sess);
        }
    }
    let established = sessions.len();
    if established == 0 {
        eprintln!("  round {round}: nothing established — check credentials and --source-ips");
        return (0, 0, 0);
    }

    tokio::time::sleep(Duration::from_secs(settle)).await;

    // ── the drop ───────────────────────────────────────────────────────────
    //
    // Sockets dropped without a Refresh(lifetime=0). A client that sends the
    // Refresh is a client shutting down politely, and the server frees the
    // allocation immediately; a client whose network vanished sends nothing and
    // the allocation lingers until its lifetime expires. The second is the case
    // a storm is about, and it is harder on the server: the returning clients
    // ask for new allocations while the old ones still hold relay ports.
    drop(sessions);

    // ── the storm ──────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(established);
    for _ in 0..established {
        let creds = creds.clone();
        let deadline = Duration::from_secs(recover_timeout);
        handles.push(tokio::spawn(async move {
            let started = Instant::now();
            match tokio::time::timeout(
                deadline,
                turn_client::allocate_family(server, &creds, 0, None),
            )
            .await
            {
                Ok(Ok(_sess)) => Some(started.elapsed().as_millis()),
                _ => None,
            }
        }));
    }

    let mut recovered = 0usize;
    let mut slowest = 0u128;
    for h in handles {
        if let Ok(Some(ms)) = h.await {
            recovered += 1;
            slowest = slowest.max(ms);
        }
    }

    println!(
        "  round {round}: {recovered}/{established} recovered, slowest {slowest} ms, \\
         round took {} ms",
        t0.elapsed().as_millis()
    );
    (established, recovered, slowest)
}

async fn run_reconnect_storm(
    server: SocketAddr,
    creds: turn_client::Creds,
    clients: usize,
    rounds: usize,
    settle: u64,
    recover_timeout: u64,
    json: bool,
) {
    if !json {
        println!("Reconnect storm: {clients} clients, {rounds} rounds, {settle}s settle");
        println!("Drop is ungraceful — no Refresh(0) — so old allocations still hold");
        println!("relay ports while the returning clients ask for new ones.");
        println!("═══════════════════════════════════════════");
    }

    let mut worst_recovery = 0u128;
    let mut total_established = 0usize;
    let mut total_recovered = 0usize;

    for round in 1..=rounds {
        let (est, rec, slow) =
            storm_round(server, &creds, clients, settle, recover_timeout, round).await;
        total_established += est;
        total_recovered += rec;
        worst_recovery = worst_recovery.max(slow);
        // Between rounds: long enough for a token bucket to refill, short enough
        // that the run stays useful. Without a gap, later rounds would measure
        // depletion from earlier ones rather than the storm itself — which is
        // worth measuring, but as a separate question.
        if round < rounds {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    let lost = total_established.saturating_sub(total_recovered);
    if json {
        println!(
            "{{\\"mode\\":\\"reconnect_storm\\",\\"clients\\":{clients},\\"rounds\\":{rounds},\\
             \\"established\\":{total_established},\\"recovered\\":{total_recovered},\\
             \\"lost\\":{lost},\\"worst_recovery_ms\\":{worst_recovery}}}"
        );
    } else {
        println!("═══════════════════════════════════════════");
        println!("  Established:  {total_established}");
        println!("  Recovered:    {total_recovered}");
        println!("  Lost:         {lost}");
        println!("  Worst client: {worst_recovery} ms");
        println!("───────────────────────────────────────────");
        if lost > 0 {
            println!("  A client that did not come back is one whose call stays down.");
            println!("  Check the server's rate_limited and quota_exceeded counters");
            println!("  before concluding the server was overloaded — a refusal and");
            println!("  an overload look identical from here.");
        }
    }
}

'''

main.write_text(s.replace(anchor, impl + anchor, 1))
print("  ok  main.rs: storm implementation")

# ---------------------------------------------------------------------------
# 3. Name and dispatch.
# ---------------------------------------------------------------------------
patch(
    "tools/load-test/src/main.rs",
    [
        (
            "mode name",
            """            Mode::Allocate { .. } => "allocate",""",
            """            Mode::Allocate { .. } => "allocate",
            Mode::ReconnectStorm { .. } => "reconnect-storm",""",
        ),
        (
            "dispatch arm",
            """        Mode::Allocate { concurrency } => {""",
            """        Mode::ReconnectStorm {
            clients,
            rounds,
            settle,
            recover_timeout,
        } => {
            if !cli.json && turn_client::SOURCE_SPREAD.get().is_none() {
                eprintln!(
                    "warning: no --source-ips, so every client shares 127.0.0.1 and this \
                     measures the per-IP allocate limiter (32/s, burst 16) rather than the \
                     server. Deliberate? Then this is the everyone-behind-one-NAT case."
                );
            }
            run_reconnect_storm(
                cli.server,
                creds,
                clients,
                rounds,
                settle,
                recover_timeout,
                cli.json,
            )
            .await
        }
        Mode::Allocate { concurrency } => {""",
        ),
    ],
)

print()
print("applied. Verify:")
print("  cargo build --release -p turna-load-test")
print()
print("Then run it, with the source spread and watching the server's counters —")
print("a client that failed to return because it was refused is a different")
print("finding from one that timed out, and the storm cannot tell them apart:")
print()
print("  target/release/turna-load-test --server 127.0.0.1:3486 \\")
print("    --secret cap-secret-123 --source-ips 60 \\")
print("    reconnect-storm --clients 50 --rounds 3")
print()
print("  curl -s localhost:9099/status | python3 -c \\")
print("    'import json,sys; d=json.load(sys.stdin); print(d[\"rate_limited\"], d[\"quota_exceeded\"])'")
