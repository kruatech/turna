# Transport load — WebTransport, QUIC, DTLS — 2026-08-23

Ubuntu 24.04, kernel 6.8, 4 cpus. Twenty minutes per transport, 10 sessions each at
10 pps, `scripts/verify/transport-load.sh`.

| Transport | Sent | Relayed back | Loss | Errors |
|---|---|---|---|---|
| WebTransport (H3) | 69 020 | 69 020 | **0.00 %** | 10 |
| raw QUIC | 69 020 | 69 020 | **0.00 %** | 10 |
| DTLS | 69 022 | 69 022 | **0.00 %** | 10 |

These three had correctness on record and no endurance, because nothing could drive
them: `wt-check`, `quic-check` and `dtls-check` each open one session for a few
seconds. The load drivers added for this run
(`turna-load-test wt|quic|dtls -c N --pps N`) close that.

**Each phase runs 1200 s deliberately.** Allocations and channel bindings last 600 s;
a driver that does not refresh them delivers only the first ten minutes and the server
correctly discards the rest, silently. At 1200 s that shows up as exactly 50 % loss —
so a zero here is evidence the refresh works, not just that traffic flowed. The script
refuses to run a phase under 700 s for the same reason.

The 10 errors per phase are one per session, recorded at teardown when the final send
races the stop signal. Benign, but not zero, so they are stated.

## What this does not establish

**No independent implementation drives any of these.** The clients share a library and
one reading of the spec with the server, so a shared misreading stays invisible.

- **WebTransport** has that covered separately: a browser probe with its own HTTP/3
  stack and hand-written STUN (`docs/interop/webtransport-browser-2026-08-20.md`).
- **DTLS** does not. RFC 7350 defines the transport, so a second implementation is
  possible — pion is the obvious candidate — but none has been run against this server.
- **QUIC** cannot have it. No RFC defines TURN over raw QUIC and no second
  implementation exists, so interop is not available to be obtained. Endurance is the
  ceiling for this transport until that changes.

Also not covered: a real certificate chain (self-signed here; the client accepts any by
design), and any rate near saturation — 100 pps per transport on a 4-cpu host is
deliberately modest, because endurance measures degradation and a saturated host turns
every later signal into noise about the saturation.

## Noted while running

`accept() exceeded the bound` is logged at **WARN every ten seconds** on an idle DTLS
listener. It is not a fault: on the stock path `accept()` blocks waiting for the next
client, hits `accept_timeout_secs`, logs, and loops. But a warning every ten seconds
with nothing wrong is 8 640 lines a day and teaches an operator to ignore the line that
is supposed to mean something.

The distinction worth drawing: a timeout with **no handshake started** is the idle case
and belongs at DEBUG; a timeout with a handshake **begun and abandoned** is the case the
warning was written for. Recorded in [../OPEN-DECISIONS.md](../OPEN-DECISIONS.md); not
changed here.
