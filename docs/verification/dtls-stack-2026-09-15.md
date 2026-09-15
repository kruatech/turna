# Verifying the DTLS stack after the 0.5.0 change

The DTLS server side changed in 0.5.0: `webrtc-dtls` 0.10 as a dependency became
`crates/dtls` in the tree, with a modified handshake state machine (a server
whose caller validated the client's address starts at handshake sequence 1, not
0 — see `crates/dtls/src/lib.rs`).

Every DTLS interop run, soak and loss figure recorded before that date was
measured against the old stack. None of them describes what ships now. This page
lists what has to be redone, what counts as passing, and what each run would
actually catch — because a run whose failure mode nobody stated is a run nobody
can fail.

## What has been verified so far

One handshake, one client, on loopback: OpenSSL `s_client` against a Let's
Encrypt chain, full DTLS 1.2 handshake, `ECDHE-ECDSA-AES128-GCM-SHA256`,
`Verification: OK`, `turna_dtls_cookie_challenges_total` = 1,
`turna_dtls_sessions_total` = 1, no timeouts, no failures.

That establishes that the state machine change is correct for the happy path
against an independent implementation. It establishes nothing about loss,
retransmission, concurrency, browsers, or a flood — which is most of what a DTLS
stack has to survive.

## 1. Spoofed-source flood — the reason this work happened

The defect being closed was: a spoofed ClientHello allocated a channel, a map
entry, a connection and a task before anything proved the sender existed. This
run is the one that says whether the fix holds.

Needs a second machine or `hping3`, because the whole point is a source address
the sender does not own.

```
# Baseline, on the node
ps -o rss= -p $(pgrep -f turna-node)
curl -s 127.0.0.1:39090/metrics | grep -E "dtls_cookie_challenges|dtls_pending_handshakes|dtls_rejected_pending_cap|dtls_sessions_total"

# ~100 000 spoofed ClientHellos. Use a captured ClientHello as the payload;
# random bytes exercise the parser's reject path instead, which is also worth
# running, separately, to confirm malformed input is dropped in silence.
sudo hping3 --udp -p 35349 -a 198.51.100.1 -i u10 -c 100000 -d 120 <node address>

# After
ps -o rss= -p $(pgrep -f turna-node)
curl -s 127.0.0.1:39090/metrics | grep -E "dtls_cookie_challenges|dtls_pending_handshakes|dtls_rejected_pending_cap|dtls_sessions_total"
```

Passing looks like: `cookie_challenges` up by roughly the packet count,
`pending_handshakes` at or near zero throughout, `rejected_pending_cap` at zero,
RSS flat. A legitimate client must still complete a handshake **during** the
flood — run `openssl s_client` while `hping3` is going, and that is the half of
this test people skip.

Failing looks like: `pending_handshakes` climbing, RSS climbing, or the
legitimate client timing out. Any of those means state is being allocated before
validation and the fix does not hold under the load it was written for.

## 2. Browser interop — three engines

The old record has browsers via WebTransport, not DTLS. No browser has ever
completed a DTLS handshake against this stack.

Chrome, Firefox and Safari, each through `tools/browser-probes/`. What this
catches that `openssl` cannot: browsers send extensions and cipher-suite orders
that OpenSSL does not, and their retransmission timing differs. The state
machine change touches sequence numbers, and sequence numbers are exactly what a
retransmit exercises.

Record the result in `docs/interop/` with the date and the browser versions,
alongside the existing files.

## 3. coturn's client — an implementation nobody here wrote

```
turnutils_uclient -v -D -u <user> -w <credential> -p 35349 <host>
```

This was the run that moved DTLS out of "handshake only" in August. It has to be
repeated because it validated the old stack. `-D` is the DTLS flag; check it
against your coturn version before relying on the invocation.

## 4. Twenty-four hours under load

The previous 24-hour run (`docs/soak/soak-24h-dtls-2026-09-01.md`) covered the
demux path on the old crate.

What a day catches that twenty minutes does not: slow leaks in the per-peer maps,
sequence-number wraparound over many handshakes, certificate reload in the
middle of live sessions, and drift between the eleven cycles the previous run
compared to three significant figures.

Use whatever drove the previous soak (`scripts/soak/soak.sh`, and
`tools/load-test` has a `dtls_client`), and compare against the old file's
numbers — not to match them, but to see where they differ and whether the
difference has an explanation.

Watch throughout, not only at the end:

```
curl -s 127.0.0.1:39090/metrics | grep -E "dtls_active_sessions|dtls_sessions_total|dtls_handshake_failures|dtls_accept_timeouts|dtls_inbound_dropped|dtls_outbound_dropped|dtls_pending_handshakes"
ps -o rss= -p $(pgrep -f turna-node)
```

A handshake failure rate that is flat and non-zero is more interesting than one
that is zero: it means something reproducible is failing, and at scale it will
be a client population rather than a fluke.

## 5. Certificate hot-reload under live sessions

`cert_reload_secs` on the demux path has not been exercised against the current
crate.

Set `cert_reload_secs = 30`, establish a session, replace the certificate files
on disk, and confirm: `turna_dtls_cert_reloads_total` increments,
`cert_reload_failures_total` stays at zero, the live session keeps carrying
media, and a new handshake gets the new certificate. Then replace them with a
*broken* file and confirm the previous certificate stays in service and the
failure counter moves — that behaviour is recorded as working in
`PRODUCTION_READINESS.md` R4 and, like everything else here, was measured on the
old stack.

## 6. Packet loss on a real interface

The old feature-support entry names this as the standing gap even for the
previous stack: *"Still absent: a real NIC — handshakes over a network lose
packets, which is where a demultiplexer is most likely to differ from a listener
that owns its socket."*

It is more relevant now, not less. The change is in sequence handling, and loss
is what makes sequence handling matter — a dropped HelloVerifyRequest means the
client retransmits its first ClientHello at `message_seq 0` while the server has
moved on, which is the exact interaction this code changed.

Two machines, `tc netem` with 1–5 % loss on the path, then a handshake loop.
Every handshake must complete, and `dtls_accept_timeouts_total` must stay at
zero.

## Lifting the beta label

All six, recorded in `docs/interop/` and `docs/soak/` with dates, and the
`feature-support.md` row rewritten to cite them rather than the August files.

Until then the row says what is true: the evidence predates the stack.
