# Transport log audit — 2026-08-27

Follow-up to `log-data-audit-2026-08-27.md`, which covered the relay and node and
said plainly that the transports were not read. They have been now.

## The finding is the opposite of what I went looking for

I expected the relay's problem repeated: per-allocation INFO lines carrying client
addresses at volume. Ten lines across TURNS, QUIC and SCTP do carry an address,
and they are a different kind of line entirely.

| file | level | message |
|---|---|---|
| `tcp_tls.rs` | WARN | TURNS connection refused: per-IP handshake rate limit |
| `tcp_tls.rs` | WARN | connection limit reached |
| `tcp_tls.rs` | WARN | TURNS connection refused: per-IP cap reached |
| `quic.rs` | WARN | QUIC session refused: max_sessions reached |
| `quic.rs` | WARN | QUIC session refused: per-IP cap reached |
| `quic.rs` | WARN | QUIC handshake refused: per-IP rate limit |
| `quic.rs` | WARN | WebTransport handshake refused: per-IP rate limit |
| `sctp.rs` | WARN | SCTP association refused: per-IP rate limit |
| `sctp.rs` | WARN | SCTP connection limit reached |
| `sctp.rs` | WARN | SCTP association refused: per-IP cap reached |

**All ten are WARN. All ten are refusals.** Neither is true of the relay's three,
which were INFO and fired once per allocation — 13.7 million lines in a three-hour
soak.

That inverts the argument for hashing them:

**Volume is bounded by attacks, not by traffic.** A node relaying happily writes
none of these. A node under pressure writes many, which is when they are wanted.

**The address is the point.** "Who is being refused" is the operator's question. A
refusal with no subject cannot be blocked, called about, or correlated across
transports.

**They are what the syslog layer forwards.** Hashing them would send a SIEM
refusal events with no actionable subject, and correlating an attacker across
events is most of what a SIEM is for.

## So the defect is in the setting, not the logs

`log_client_addresses` did not reach the transports, and its name implied it did.
An operator setting it false and reading the name would have concluded the
deployment logged no client addresses. They would have found out otherwise from a
compliance review.

**Renamed to `log_allocation_addresses`**, which is what it covers. Free to do
now: the key was added in the same unreleased body of work, so nothing depends on
the old name. It would not be free next month, and that is the argument for doing
it today rather than adding a note.

The alternative — extending the switch to the transports — was rejected. It would
be consistent, and it would destroy ten high-value low-volume events to solve a
problem they do not have.

## What is therefore not possible

**A deployment cannot suppress every client address through configuration.** To
silence the transport refusals it would have to raise their log level above WARN,
which also silences things it wants.

Named rather than omitted. If a customer needs it, the fix is a shared helper in
`turna-observability` that both crates call — the transports cannot use the
relay's, because `turna-transport` does not depend on `turna-relay`, and inverting
that dependency to move one boolean would be the wrong trade.

## Negative results

**No secrets in any transport log macro.** No key material, no shared secret, no
session key.

**No payload logged** at any level in any transport.

**`server.rs` logs no addresses at all** — 22 log macros, none carrying one. It
deals in listeners and lifecycle, not in peers.

## Still not covered

**Third-party crates.** `rustls`, `quinn` and `webrtc-dtls` log under their own
targets and were not read. What they emit at INFO is unexamined, and a
dependency's log line is outside anything this project's configuration reaches.

Worth stating because it is the remaining hole: an audit that implies it covered
everything is less useful than one that says where it stopped.
