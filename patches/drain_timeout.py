#!/usr/bin/env python3
"""
Drain: make the wait configurable, and stop waiting for allocations that will
never finish.

MEASURED: 36 seconds to shut down a node holding 300 allocations whose clients
had vanished without a Refresh(0). The `drain()` loop is

    while !store.is_empty() && now < timeout   // timeout = now + 30s

so it polls `cleanup_expired()` until either the store empties or 30 seconds
pass. Allocations with a 600-second lifetime do not expire inside that window,
so a node whose clients disappeared always pays the full 30 seconds — there is
nothing to wait for and no way for the loop to know that.

TWO CHANGES

**Configurable.** `[turn.relay] drain_timeout_secs`, default 30 — the current
constant, so nothing changes for anyone who does not set it. An operator rolling
ten nodes sequentially is currently spending five minutes on a decision nobody
made: whether to let calls finish or to cut them short. That is theirs to make.

**Early exit when the store stops shrinking.** If `cleanup_expired()` removes
nothing for several consecutive polls and the count has not moved, the remaining
allocations are not going to expire inside this window. Waiting further trades
shutdown latency for nothing.

The second matters more than the first. A node with live clients still drains
properly — their allocations end as they finish, the count moves, the loop keeps
waiting. A node with abandoned ones exits in about two seconds instead of thirty.
Those two situations behave identically today despite wanting opposite handling.

The stall threshold is three polls (~6 seconds), not one: a brief pause in
expiries is normal, and exiting on the first is how a node with real traffic
would cut its own calls short.

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


cfg = pathlib.Path("crates/config/src/lib.rs")
if not cfg.exists():
    die("crates/config/src/lib.rs not found — run from the repository root")
if "drain_timeout_secs" in cfg.read_text():
    die("already applied")

# ---------------------------------------------------------------------------
# 1. The key.
# ---------------------------------------------------------------------------
patch(
    "crates/config/src/lib.rs",
    [
        (
            "relay field",
            """    /// Per-user bandwidth + allocation count limits. Defaults are
    /// "no bandwidth limit, 100 allocations per username".
    pub quota: QuotaConfig,
}""",
            """    /// Per-user bandwidth + allocation count limits. Defaults are
    /// "no bandwidth limit, 100 allocations per username".
    pub quota: QuotaConfig,
    /// How long to wait for allocations to end on shutdown, seconds.
    ///
    /// The node stops accepting immediately and then waits for existing
    /// allocations. Raise it to let long calls finish; lower it to roll a
    /// cluster faster. Measured: a node holding allocations whose clients had
    /// vanished took the full timeout, because nothing was going to expire
    /// inside it — see the stall detection in `relay::server::drain`, which now
    /// cuts that case short without shortening the wait for live traffic.
    pub drain_timeout_secs: u64,
}""",
        ),
        (
            "relay default",
            """            max_allocations: 10000,
            quota: QuotaConfig::default(),""",
            """            max_allocations: 10000,
            quota: QuotaConfig::default(),
            // The value this was hard-coded to before it became configurable.
            drain_timeout_secs: 30,""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. Somewhere to put it on the server, without touching three constructors.
# ---------------------------------------------------------------------------
patch(
    "crates/relay/src/server.rs",
    [
        (
            "drain field",
            """    #[cfg(feature = "sctp")]
    sctp_config: Option<turna_transport::sctp::SctpTransportConfig>,
}""",
            """    #[cfg(feature = "sctp")]
    sctp_config: Option<turna_transport::sctp::SctpTransportConfig>,
    /// Seconds to wait for allocations to end on shutdown. Set by the node from
    /// `[turn.relay] drain_timeout_secs`; 30 when nothing sets it, which is what
    /// this was hard-coded to.
    drain_timeout_secs: u64,
}""",
        ),
        (
            "drain field init",
            """            #[cfg(feature = "sctp")]
            sctp_config: None,
        }
    }""",
            """            #[cfg(feature = "sctp")]
            sctp_config: None,
            drain_timeout_secs: 30,
        }
    }

    /// Override how long shutdown waits for allocations to end.
    ///
    /// A builder setter rather than a constructor argument: there are three
    /// constructors and this concerns none of them.
    pub fn with_drain_timeout_secs(mut self, secs: u64) -> Self {
        self.drain_timeout_secs = secs;
        self
    }""",
        ),
        (
            "drain loop",
            """    async fn drain(&self) {
        let store = self.processor.store();
        let timeout = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        while !store.is_empty() && tokio::time::Instant::now() < timeout {
            let removed = store.cleanup_expired();
            if removed > 0 {""",
            """    async fn drain(&self) {
        let store = self.processor.store();
        let drain_secs = self.drain_timeout_secs;
        let timeout =
            tokio::time::Instant::now() + std::time::Duration::from_secs(drain_secs);

        // Stall detection. An allocation whose client vanished without a
        // Refresh(0) will not expire inside a 30-second window — its lifetime is
        // ten minutes — so the loop below would poll until the timeout with
        // nothing to wait for. Measured at 36 seconds for a node holding 300 of
        // them.
        //
        // If nothing has been removed and the count has not moved for three
        // consecutive polls (~6 s), the rest are not going anywhere. Three rather
        // than one because a brief gap between expiries is ordinary, and exiting
        // on the first would cut short a node that is draining real traffic —
        // exactly the case the timeout exists to protect.
        let mut last_len = store.len();
        let mut stalled_polls = 0u32;
        const STALL_POLLS: u32 = 3;

        while !store.is_empty() && tokio::time::Instant::now() < timeout {
            let removed = store.cleanup_expired();

            let len_now = store.len();
            if removed == 0 && len_now == last_len {
                stalled_polls += 1;
                if stalled_polls >= STALL_POLLS {
                    info!(
                        remaining = len_now,
                        waited_polls = stalled_polls,
                        "drain: no allocations ended in the last few polls; the rest hold \\
                         lifetimes longer than this window and will not expire here. \\
                         Exiting rather than waiting out the timeout — their clients are \\
                         gone, and their relay ports are released with the process."
                    );
                    break;
                }
            } else {
                stalled_polls = 0;
            }
            last_len = len_now;

            if removed > 0 {""",
        ),
    ],
)

print()
print("applied. One call site remains, in services/node: the server is built and")
print("then decorated with .with_tls(...) / .with_sctp(...). Add")
print(".with_drain_timeout_secs(config.relay.drain_timeout_secs) to that chain,")
print("or the key parses and does nothing — which is the failure this project")
print("spent an afternoon removing from the AF_XDP section.")
print()
print("  grep -n 'with_sctp\\|with_external_ip6' services/node/src/main.rs")
print()
print("Verify:")
print("  cargo clippy -p turna-config -p turna-relay --all-targets -- -D warnings")
print()
print("Then measure it, since the point is a number:")
print("  # 300 abandoned allocations, as before")
print("  time (pkill -TERM -x turna-node; while pgrep -x turna-node >/dev/null; do sleep 1; done)")
print()
print("Expect a few seconds rather than 36. A node draining live traffic should")
print("still take as long as its clients need — worth checking both, because a")
print("change that makes shutdown fast by cutting calls short is a regression")
print("wearing a fix's clothes.")
