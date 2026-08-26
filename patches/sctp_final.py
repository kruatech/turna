#!/usr/bin/env python3
"""
Pass 3 of the SCTP work: close the loop.

Pass 1 added counters inside the transport, pass 2 exposed them and added the
config keys. Two things remained:

  server.rs   the bridge gained two parameters; the caller still passes four
  docs        thirteen new series must be documented or check-doc-claims.sh
              fails — it asserts every exported metric appears in
              OBSERVABILITY.md, which is the gate that stopped this project
              from shipping metrics nobody could interpret

The readiness note in the docs is worth reading before the table: the gauge is
driven by the listener's own `listening` flag rather than by a separate belief
about whether it is up. A listener that stopped accepting cannot keep reporting
Ready — which is the failure mode the health port had, and the reason it is
called out.

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


# ---------------------------------------------------------------------------
# 1. The call site. `listener_metrics` and `listener_shutdown` already exist
#    here; the shutdown receiver needs a second clone because the first is
#    consumed by the post-exit check below it.
# ---------------------------------------------------------------------------
srv = pathlib.Path("crates/relay/src/server.rs")
if not srv.exists():
    die("crates/relay/src/server.rs not found — run from the repository root")
if "sctp_bridge_shutdown" in srv.read_text():
    die("already applied (sctp_bridge_shutdown exists)")

patch(
    "crates/relay/src/server.rs",
    [
        (
            "bridge call",
            """            let listener_metrics = self.processor.metrics().clone();
            let listener_shutdown = shutdown.clone();
            sctp_handle = Some(tokio::spawn(async move {
                let res =
                    crate::sctp_bridge::run_sctp_bridge(sctp_cfg, proc, relay_tx, sinks).await;""",
            """            let listener_metrics = self.processor.metrics().clone();
            let listener_shutdown = shutdown.clone();
            // A second receiver: the first is consumed by the post-exit check
            // below, which distinguishes a deliberate drain from a crash. The
            // bridge needs its own so it can stop accepting on the same signal.
            let sctp_bridge_shutdown = shutdown.clone();
            let sctp_bridge_metrics = listener_metrics.clone();
            sctp_handle = Some(tokio::spawn(async move {
                let res = crate::sctp_bridge::run_sctp_bridge(
                    sctp_cfg,
                    proc,
                    relay_tx,
                    sinks,
                    sctp_bridge_metrics,
                    sctp_bridge_shutdown,
                )
                .await;""",
        ),
    ],
)

# ---------------------------------------------------------------------------
# 2. Documentation. The gate reads this file, so the series names must match
#    the render exactly.
# ---------------------------------------------------------------------------
patch(
    "docs/OBSERVABILITY.md",
    [
        (
            "sctp table",
            """#### DTLS (`[turn.dtls]`)""",
            """#### TURN-over-SCTP (`[turn.sctp]`)

Refused under `production = true`. These exist so a deployment that opts in on an
internal network can see what the listener is doing — it shipped with no counters
at all, which meant a listener that had stopped accepting looked identical to an
idle one: socket bound, process healthy, nothing moving.

`turna_sctp_readiness` follows the listener's own `listening` flag, set after bind
and cleared on drain. It is not a separate belief about whether the listener is
up, because a separate belief is what lets a dead listener keep reporting Ready.

| metric | type | meaning |
|--------|------|---------|
| `turna_sctp_active_associations` | gauge | Established associations. |
| `turna_sctp_associations_total` | counter | Associations accepted since start. |
| `turna_sctp_closed_total` | counter | Associations closed. |
| `turna_sctp_rejected_over_cap_total` | counter | Refused at `max_connections`. |
| `turna_sctp_rejected_per_ip_total` | counter | Refused at `max_connections_per_ip`. |
| `turna_sctp_rejected_rate_limit_total` | counter | Refused by `max_associations_per_sec_per_ip`, before any per-association work. Distinct from `rejected_per_ip`, which caps *concurrent* associations: a source that associates and drops in a loop trips this one and never that one. |
| `turna_sctp_idle_timeouts_total` | counter | Closed by `read_timeout_secs`. |
| `turna_sctp_framing_errors_total` | counter | Invalid or over-sized TURN-over-stream framing. Same codec as TURN-over-TCP. |
| `turna_sctp_accept_errors_total` | counter | `accept()` errors survived without stopping the listener (e.g. `EMFILE`). Non-zero used to be impossible here for the wrong reason: a single such error returned from the accept loop and took the listener down until restart. |
| `turna_sctp_send_dropped_total` | counter | Outbound frames dropped because the per-association channel was full or gone. Non-zero means a client lost relayed data. Previously discarded without a counter, so this was invisible. |
| `turna_sctp_bytes_rx_total` / `turna_sctp_bytes_tx_total` | counter | Bytes read from / written to clients. |
| `turna_sctp_readiness` | gauge | 0=starting, 1=ready, 2=degraded, 3=draining. `starting` while SCTP is disabled or not built. |

#### DTLS (`[turn.dtls]`)""",
        ),
    ],
)

print()
print("applied. Verify in this order:")
print()
print("  cargo clippy -p turna-transport -p turna-relay -p turna-health \\")
print("    -p turna-config -p turna-node --features sctp --all-targets -- -D warnings")
print("  bash scripts/check-doc-claims.sh")
print("  cargo test --workspace --features sctp")
print()
print("The doc-claims gate is the one that matters here: it reads the render in")
print("crates/health and asserts each series appears in OBSERVABILITY.md. If a")
print("name is misspelled in either place, it says which.")
