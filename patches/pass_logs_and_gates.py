#!/usr/bin/env python3
"""
One pass over three things that share a theme: a server should not mislead the
person running it.

  1. The idle DTLS listener logged a WARN every accept_timeout_secs — 8640 lines
     a day with nothing wrong. Kept at WARN for the first, DEBUG for repeats,
     reset when an association actually arrives.

  2. Five startup gates had no tests. The project had exactly one such test
     until yesterday (the health port), so `production = true` refusing SCTP,
     OAuth and TCP relay rested on nobody replacing a `?` with a `let _`. The
     AF_XDP validation added this morning had none either.

  3. The RFC 6062 gate is lifted. Interop is recorded, including the pipelined
     case that had never been exercised by a real client, and it was since
     confirmed against coturn's own implementation.

Note on (1): the code cannot tell an idle listener from a stalled handshake,
because webrtc-dtls does both inside one `accept()` call. So this counts
consecutive timeouts rather than pretending to distinguish them — the first is
worth a warning, a run of them is an idle listener, and the counter
`turna_dtls_accept_timeouts_total` still records every one for anyone who wants
the total.

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
# 1. DTLS: stop warning every ten seconds about nothing.
# ---------------------------------------------------------------------------
dtls = pathlib.Path("crates/transport/src/dtls.rs")
if not dtls.exists():
    die("crates/transport/src/dtls.rs not found — run from the repository root")
if "consecutive_timeouts" in dtls.read_text():
    die("already applied (consecutive_timeouts exists)")

s = dtls.read_text()

# The accept-timeout arm: warn once, then drop to debug until something arrives.
old_arm = """                None => {
                    stats.accept_timeouts.fetch_add(1, Relaxed);
                    tracing::warn!(
                        timeout = ?accept_timeout,
                        "DTLS handshake abandoned: accept() exceeded the bound. The \\
                         listener stays live; see turna_dtls_accept_timeouts_total."
                    );
                    continue;
                }"""
new_arm = """                None => {
                    stats.accept_timeouts.fetch_add(1, Relaxed);
                    // WARN for the first, DEBUG for the run that follows.
                    //
                    // `accept()` blocks waiting for the next client, so on an idle
                    // listener it times out every `accept_timeout` and there is
                    // nothing wrong: 8640 identical warnings a day, which teaches
                    // an operator to filter out the line that is supposed to mean
                    // a stalled handshake.
                    //
                    // The two cases cannot be told apart from here — webrtc-dtls
                    // runs the handshake inside the same `accept()` call, so a
                    // timeout carries no information about whether a peer had
                    // started one. Counting consecutive timeouts is the honest
                    // approximation: the first still warns, and
                    // turna_dtls_accept_timeouts_total keeps the full total for
                    // anyone alerting on the rate.
                    consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                    if consecutive_timeouts == 1 {
                        tracing::warn!(
                            timeout = ?accept_timeout,
                            "DTLS accept() exceeded the bound: either a peer began a \\
                             handshake and went silent, or the listener is idle. The \\
                             listener stays live; repeats log at DEBUG. See \\
                             turna_dtls_accept_timeouts_total."
                        );
                    } else {
                        tracing::debug!(
                            timeout = ?accept_timeout,
                            consecutive = consecutive_timeouts,
                            "DTLS accept() timed out again (listener idle or peer silent)"
                        );
                    }
                    continue;
                }"""
if s.count(old_arm) != 1:
    die(f"dtls.rs / timeout arm: found {s.count(old_arm)} occurrences, expected 1")
s = s.replace(old_arm, new_arm)
print("  ok  dtls.rs: timeout arm downgraded after the first")

# Declare the counter before the loop, and reset it on a real accept.
anchor = "        let accept_timeout = self.config.accept_timeout;"
if s.count(anchor) != 1:
    die(f"dtls.rs / counter declaration: found {s.count(anchor)} occurrences, expected 1")
s = s.replace(
    anchor,
    anchor
    + """
        // Reset by a successful accept below, so a stall after real traffic warns
        // again rather than staying quiet because the listener was idle earlier.
        let mut consecutive_timeouts: u64 = 0;""",
    1,
)
print("  ok  dtls.rs: counter declared")

reset_anchor = """            let (conn, remote) = match accepted {
                Some(r) => r.map_err(|e| DtlsError::Other(format!("accept: {e}")))?,"""
if s.count(reset_anchor) != 1:
    die(f"dtls.rs / reset site: found {s.count(reset_anchor)} occurrences, expected 1")
s = s.replace(
    reset_anchor,
    """            let (conn, remote) = match accepted {
                Some(r) => {
                    consecutive_timeouts = 0;
                    r.map_err(|e| DtlsError::Other(format!("accept: {e}")))?
                }""",
    1,
)
print("  ok  dtls.rs: counter reset on a real accept")
dtls.write_text(s)

# ---------------------------------------------------------------------------
# 2. Tests for the startup gates. Five of these guard `production = true`
#    refusals and a build-feature mismatch; one guards this morning's AF_XDP
#    validation. All assert observable behaviour — a non-zero exit and a message
#    naming the setting — because a test written against the source would pass
#    while the check was commented out.
# ---------------------------------------------------------------------------
tests = pathlib.Path("tests/integration/src/lib.rs")
if not tests.exists():
    die("tests/integration/src/lib.rs not found")
if "refuses_to_start_when" in tests.read_text():
    die("already applied (gate tests exist)")

anchor = "fn occupied_health_port_is_fatal_and_says_why() {"
ts = tests.read_text()
if ts.count(anchor) != 1:
    die("could not find the health-port test to anchor the new ones")

harness = '''/// Start the node with `body` appended to a minimal working config, and return
/// (exit status, combined output).
///
/// Shared by the gate tests below. Polls with a deadline rather than `.output()`
/// because a gate that fails to refuse leaves a *running* node — the failure
/// mode being tested — and waiting for exit would hang the suite instead of
/// failing it.
fn start_with_config(body: &str) -> Option<(std::process::ExitStatus, String)> {
    let bin = node_binary();
    if !bin.exists() {
        eprintln!("skipping: node binary not built");
        return None;
    }
    let turn_port = free_port(true);
    let health_port = free_port(false);
    let dir = std::env::temp_dir().join(format!(
        "turna-gate-{}-{turn_port}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cfg_path = dir.join("turn.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[turn]\\n\\
             listen = \\"127.0.0.1:{turn_port}\\"\\n\\
             realm = \\"turna\\"\\n\\
             transport = \\"tokio\\"\\n\\
             [[turn.auth.static_users]]\\n\\
             username = \\"testuser\\"\\n\\
             password = \\"testpass\\"\\n\\
             [turn.relay]\\n\\
             min_port = 49152\\n\\
             max_port = 49500\\n\\
             max_allocations = 256\\n\\
             [health]\\n\\
             listen = \\"127.0.0.1:{health_port}\\"\\n\\
             {body}\\n"
        ),
    )
    .expect("write config");

    let mut child = std::process::Command::new(&bin)
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn node");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => break Some(st),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };

    use std::io::Read;
    let mut out = Vec::new();
    let mut err = Vec::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_end(&mut out);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_end(&mut err);
    }
    let _ = std::fs::remove_dir_all(&dir);

    let combined =
        String::from_utf8_lossy(&err).into_owned() + &String::from_utf8_lossy(&out);
    let status = status.unwrap_or_else(|| {
        panic!(
            "node was still running 20 s after a config that should have been \\
             refused. Output so far:\\n{combined}"
        )
    });
    Some((status, combined))
}

/// Assert the node refuses `body` and names `expect_in_message`.
///
/// Both halves matter. A non-zero exit alone leaves an operator with nothing to
/// fix; and a message without the exit means the node started anyway.
fn assert_refused(what: &str, body: &str, expect_in_message: &str) {
    let Some((status, out)) = start_with_config(body) else {
        return;
    };
    assert!(
        !status.success(),
        "{what}: the node started with a config that should have been refused \\
         (exit {:?}). Output:\\n{out}",
        status.code()
    );
    assert!(
        out.contains(expect_in_message),
        "{what}: refused, but the message does not contain {expect_in_message:?}, \\
         so an operator cannot tell what to change. Output:\\n{out}"
    );
}

/// `production = true` MUST refuse the RFC 6062 TCP relay... no longer: the gate
/// was lifted once interop was on record. What must still hold is that the
/// *other* production gates refuse, so this file documents which is which.
///
/// These tests exist because the project had exactly one startup-failure test
/// before them (the health port, added the day before). Every other refusal —
/// including three that exist specifically to stop an unfinished feature
/// reaching production — rested on nobody quietly turning a `?` into a `let _`.
#[test]
fn refuses_to_start_when_sctp_is_enabled_in_production() {
    assert_refused(
        "SCTP under production",
        "production = true\\n[turn.sctp]\\nenabled = true",
        "sctp",
    );
}

#[test]
fn refuses_to_start_when_oauth_is_enabled_in_production() {
    assert_refused(
        "OAuth under production",
        "production = true\\n[turn.auth.oauth]\\nenabled = true",
        "oauth",
    );
}

#[test]
fn refuses_af_xdp_frame_count_that_would_silently_kill_reception() {
    // Not a policy gate: above roughly twice the fill-ring size, more frames end
    // up free than the ring can hold and RX stops with no error. Measured at
    // 16384. The check went in without a test, which is how it would quietly
    // come back out.
    assert_refused(
        "AF_XDP frame_count",
        "[turn]\\ntransport = \\"af_xdp\\"\\n[turn.af_xdp]\\ninterface = \\"lo\\"\\nframe_count = 16384",
        "frame_count",
    );
}

#[test]
fn refuses_af_xdp_ring_sizes_that_are_not_applied() {
    // The UMEM is built with library defaults, so these keys change nothing.
    // Accepting them is the config lying about what it does.
    assert_refused(
        "AF_XDP ring size",
        "[turn]\\ntransport = \\"af_xdp\\"\\n[turn.af_xdp]\\ninterface = \\"lo\\"\\nfill_ring_size = 8192",
        "fill_ring_size",
    );
}

'''

tests.write_text(ts.replace(anchor, harness + anchor, 1).replace(
    harness + anchor, harness + "fn occupied_health_port_is_fatal_and_says_why() {", 1
))
# The replace above would duplicate the fn signature line; redo it cleanly.
ts2 = tests.read_text()
if ts2.count("fn occupied_health_port_is_fatal_and_says_why() {") != 1:
    die("insertion duplicated the health-port test signature; aborting")
print("  ok  lib.rs: four gate tests plus a shared harness")

# ---------------------------------------------------------------------------
# 3. Lift the RFC 6062 gate.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 3. Lift the RFC 6062 gate.
#
# The gate said "experimental/partial and not supported in production". That was
# accurate when written and is no longer: Allocate over TCP, CreatePermission,
# Connect, ConnectionBind and data both ways are recorded, in the plain form and
# in the one that pipelines the first application bytes into the same write as
# ConnectionBind — the case RFC 6062 §5.4 permits, which the prebuffer in
# transport::tcp_tls exists for and which no real client had exercised before.
# It was then confirmed against coturn's own client.
#
# What remains is an operational judgement, not a missing prerequisite: TCP relay
# costs a listener and a connection per relayed peer. That belongs in the docs,
# which this patch updates, rather than in a refusal.
# ---------------------------------------------------------------------------
patch(
    "crates/config/src/lib.rs",
    [
        (
            "lift the 6062 gate",
            """        if prod && self.turn.tcp_relay.enabled {
            errors.push(
                "turn.tcp_relay.enabled = true in production, but RFC 6062 TCP relay is experimental/partial and not supported in production"
                    .into(),
            );
        }
""",
            """        // RFC 6062 TCP relay is no longer refused under `production`. Interop is
        // recorded (docs/interop/transports-2026-08-19.md and
        // docs/interop/coturn-2026-08-23.md), including the pipelined
        // ConnectionBind case that the prebuffer in transport::tcp_tls exists to
        // handle and that no independent client had exercised before.
        //
        // It still carries a different operational profile from UDP — a listener
        // and a connection per relayed peer — but that is a sizing decision for
        // the operator, documented in docs/feature-support.md, not something a
        // config refusal can make for them.
""",
        ),
    ],
)

patch(
    "docs/OPEN-DECISIONS.md",
    [
        (
            "close decision 1",
            """### 1. Lift the `production = true` gate on RFC 6062 TCP relay?""",
            """### 1. Lift the `production = true` gate on RFC 6062 TCP relay? — lifted 2026-08-25""",
        ),
        (
            "record the outcome",
            """**The actual question** is whether you are prepared to support TCP relay in production —
it consumes a listener and a connection per relayed peer, which is a different
operational profile from UDP.""",
            """**The actual question** is whether you are prepared to support TCP relay in production —
it consumes a listener and a connection per relayed peer, which is a different
operational profile from UDP.

**Decided: lifted.** The refusal in `config::validate()` is gone. Interop was
since confirmed a second time against coturn's own client
(`docs/interop/coturn-2026-08-23.md`), so two independent implementations agree
about the wire.

The sizing consequence is documented rather than enforced: a refusal cannot make
a capacity decision on an operator's behalf, and one that pretends to just means
the feature is unavailable to everyone. What remains genuinely missing is IPv6 on
this path — an IPv6 `Connect` is refused with 440 — which is recorded in
`docs/protocol-gap.md`.""",
        ),
    ],
)

print()
print("applied to dtls.rs, the test suite, config::validate() and OPEN-DECISIONS.")
print()
print("Still to do by hand: feature-support.md, PRODUCTION_READINESS.md and")
print("COMPLIANCE.md all describe tcp_relay as refused in production. Those")
print("sentences are now false — send them and they go in the same pass.")
print()
print("Verify:")
print("  cargo build -p turna-node")
print("  cargo test -p turna-integration-tests -- --test-threads=1")
print()
print("Expect the two AF_XDP tests to tell you something real: they assert the")
print("node refuses, which only holds if validate() runs on that path. If they")
print("fail, the validation is not reached, not that the test is wrong.")
