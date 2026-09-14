# Abuse-resistance audit, 2026-09-14 — what was found and what was done

Second audit pass against `main` at 0.4.0: denial of service, spoofed sources,
identity, secrets, process privileges, bootstrap. Eighteen findings, numbered
21-38 to continue the first pass.

This page records the outcome per finding, including the two that were closed by
writing them down rather than by changing code, and the three that are not
closed. It exists so the next person reading the audit document does not have to
re-derive which parts still apply.

## Closed in 0.5.0

| # | Finding | Where the fix lives |
|---|---|---|
| 21 | A full rate-limiter table refused every new source for 600 s — ~1.3 MB of spoofed UDP bought a remote, anonymous lockout | `qos`: evict the idlest of a bounded sample instead of refusing; throttled warning; `evictions()` |
| 22 | `max_per_user` and `set_user_limits` keyed on the raw TURN REST username, so they limited one credential rather than one person | `auth::AuthMode::subject_of`, carried on `AuthResolution`; quotas and overrides key on it |
| 23 | Three `warn!` sites ran per packet, pre-auth, with attacker-controlled content | `common::LogThrottle`; first occurrence then every power of two |
| 24 | Relay ports were handed out consecutively, so one port predicted the next | `session`: random cursor start, linear probing unchanged |
| 25 | The node's own addresses were valid relay peers | `peer_filter`: unconditional deny that the allow-list cannot override |
| 26 | Secrets survived in core dumps, in `/proc/<pid>/mem` and in freed memory; `file://` secrets were read without checking permissions | `[turn] allow_core_dumps` (default off) → `RLIMIT_CORE` + `PR_SET_DUMPABLE`; `Drop` zeroization on `AuthMode` and `AuthConfig`; permission warning |
| 27 | `TURNA_ALLOW_LOOPBACK_PEERS` overrode config policy invisibly | Startup error under `production = true`, naming the config key |
| 28 | TURNS had no per-source connection cap | `max_connections_per_ip` default 0 → 64 |
| 29 | SOFTWARE named the release in an unauthenticated response | `[turn] software_attribute`; `product` by default, `full` refused in production |
| 30 | Unclaimed EVEN-PORT reservations leaked their ports until restart | `sweep_expired_reservations` now runs from the periodic sweep, all pools |
| 31 | One receive worker dying was invisible until all of them died | `turna_recv_workers_alive`, `recv_worker_died`, `Degraded` past 25 % loss |
| 32 | Nothing bounded unauthenticated replies to one address | Separate budget (64 burst, 8/s) for Binding responses and 401 challenges |
| 33 | `508 Server Draining` was answered before authentication | Check moved below the challenge, beside 437/442 |
| 34 | No regression tests for abuse | Seven `abuse_*` config tests; the wire-level halves of 21 and 30 as unit tests |
| 35 | DTLS allocated per-peer state before the cookie exchange — OOM in seconds from any address | Stateless HelloVerifyRequest in the demultiplexer (`dtls_cookie`): nothing is allocated until a ClientHello carries a cookie this node issued. `max_pending_handshakes` (512) stays as the backstop |
| 36 | QUIC ran a full TLS handshake for every spoofed Initial | `incoming.retry()` for unvalidated addresses on both the raw QUIC and WebTransport paths; per-IP caps on by default |
| 37 | `turna_claim_allocation` did its compare-and-swap without `box.atomic` | Wrapped, like the three procedures beside it |
| 38 | The Tarantool bootstrap generated a password and printed it to STDOUT | Password is required, never generated, never printed |

## Not closed, and why

**26 is closed, with a caveat worth stating.** Dumps, `/proc/<pid>/mem` and
freed memory are all addressed, but the secret still exists in memory while the
node runs, and a copy taken into a local by `validate()` lives until that local
drops. Zeroization removes the copies that outlive their usefulness — of which a
rotating deployment accumulated one per reload — not the working copy. Anything
that can read this process's memory while it is running still gets the secret.

**35 is closed, with one thing to watch.** `webrtc-dtls` performs its own
HelloVerifyRequest inside `DTLSConn`. If it still does so after this gate, a
client pays two cookie round trips instead of one — slower, not broken, and the
protocol allows it. Watch handshake latency after enabling DTLS; if it has
doubled, the second exchange is the one to remove, on the `webrtc-dtls` side.
Removing this gate instead would put the memory back at the mercy of the sender.

**34, two scenarios still missing.** A TURNS per-IP connection cap exercised over
a real TLS listener, and 508-requires-auth checked on the wire. Both need a test
client that speaks the transport, which the integration harness does not have.
Named in the test file rather than quietly absent.

## Two things the audit got right that are worth repeating

The pattern behind 21, 30 and 35 is the same: a limit that counts the wrong
thing. `max_entries` bounded memory by refusing legitimate clients; `max_sessions`
counted handshakes that had already succeeded; reservation expiry ran only when
somebody happened to claim one. In each case the mechanism existed, looked
correct in a unit test, and did not do the job once someone was trying.

And the reason none of it was caught: every abuse path was tested at the level of
the data structure, never at the level of the node. That is what the `abuse_*`
group is for, and why each new one should fail on the commit before its fix.
