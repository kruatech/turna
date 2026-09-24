# Transport lifecycle, admission and backpressure probes

This patch adds tests for QUIC, WebTransport and native Linux SCTP. It does not
promote support status or change production transport limits. Apply after the
step-2, SCTP_NODELAY and monitoring patches.

## Scenarios (five per selected transport)

1. **Reconnect**: one authenticated client at a time; default ten cycles. Each
   cycle verifies both media directions and closes normally. Allocation/session
   counts and Linux node FD count must return to baseline (FD slack: two).
2. **Crash**: retain a healthy client while killing another established client
   with SIGKILL. Default three repetitions. The killed process cannot send an
   application close. Require server cleanup, continued two-way media on the
   surviving client, and successful reconnection afterward. QUIC/H3 idle timeout
   is shortened to ten seconds only in the test config.
3. **Global cap**: configure two total sessions and no per-IP cap. Hold two
   allocations, reject a third client, verify the global rejection counter and
   continued media. Kill one holder, then verify its slot can be reused.
4. **Per-IP cap**: configure four total sessions, but only one from an IP. Reject
   a second client from 127.0.0.1, verify the per-IP rejection counter, preserve
   existing media, release the holder and verify admission afterward.
5. **Pressure/non-reader**: keep a healthy session alongside a client that stops
   reading reliable replies. Flood the latter's control stream with authenticated
   Refresh requests, bounded by eight MiB and twelve seconds. Require an outbound
   overload/error counter to increase, server-side offender cleanup while that
   client process remains alive, continued healthy media, and reconnection.
   The sixty-second idle timeout exceeds the twenty-second pressure deadline:
   passive idle expiry cannot satisfy the test. This combines queue pressure and
   a non-reading peer; it does not separately benchmark slow readers or promise
   lossless service to an intentionally overloaded connection.

Media checks use a real UDP peer. Every probe validates an exact 159-byte payload
including a sequence number, verifies the relay source address, echoes it back,
and validates returned ChannelData with optional four-byte alignment padding.
A client emits READY only after this succeeds. Healthy holders repeat this round
trip every 200 ms with a three-second deadline. SIGUSR1 requests graceful client
closure; SIGKILL is reserved for deliberate crash cases.

Every case starts its own node. Resource samples include RSS, CPU, server-side FD
count and unlabelled HTTP metrics. A missing required metric is a failure. RSS
must stay within baseline + 64 MiB by default, including pressure. This is a
coarse safety bound for a small test, not proof that there is no memory leak.
The post-cleanup FD bound is baseline + 2 to allow transient HTTP descriptors.
On macOS FD checks are unavailable; Linux is required for that evidence.

The script refuses an occupied health port and stops only its own processes on
exit/interruption. Do not run it concurrently with other turna verification
scripts on the same host: they can share other service ports and relay ranges.

## Run on cloud (existing SSH terminal)

```bash
cd /home/anton/projects/turna
source /home/anton/.cargo/env

PHASES="quic wt sctp" CYCLES=10 CRASH_ROUNDS=3 \
HEALTH_PORT=19096 OUT=transports-lifecycle-linux \
python3 scripts/verify/transport-lifecycle.py
```

The script preflights native SCTP, builds both release binaries with `--locked`,
creates a temporary certificate and runs fifteen scenarios. Expect fifteen PASS
rows. The configured order is QUIC, WebTransport, SCTP; within each, reconnect,
crash, global-cap, ip-cap, pressure. Allow several minutes per transport plus
build time. No twenty-minute or endurance run is needed for these scenarios.

From the Mac repository root:

```bash
PHASES="quic wt" CYCLES=10 CRASH_ROUNDS=3 \
HEALTH_PORT=19096 OUT=transports-lifecycle-macos \
python3 scripts/verify/transport-lifecycle.py
```

Expect ten scenarios; native SCTP is Linux-only.

Supported environment overrides: `OUT`, `PHASES`, `CASES`, `CYCLES`, `CRASH_ROUNDS`,
`HEALTH_PORT` (19096), `TRANSPORT_PORT` (3484), `TURN_PORT` (3476),
`MAX_RSS_GROWTH_MIB` (64), `FD_SLACK` (2), `BUILD_PROFILE` (`release` or `dev`).
Increasing memory/FD tolerances changes the acceptance criterion; retain those
values with results rather than increasing them to hide a failure.

CI also runs the reduced two-cycle/one-crash suite for all three transports
and uploads its logs. The CI job itself has not been executed in this workspace.

## Evidence and limits

Keep `summary.md`, `build.log`, each `.node.log`, `.client.log` and
`.resources.jsonl`. Client logs distinguish READY, healthy round trips,
pressure start, bytes written, blocked/rejected writes and normal close.
A timeout, rejected healthy client, missing metric, unreclaimed allocation,
missing rejection counter or early offender exit is a failure, never a skip.

These are loopback correctness/resource tests with a small number of clients.
They do not establish peak throughput, cross-network NAT behavior, browser
interoperability, or multiday endurance. QUIC/WT probes use the existing Rust
libraries; SCTP uses actual kernel protocol 132 sockets.

To repeat only a failed pressure case on cloud after reviewing its logs:

```bash
cd /home/anton/projects/turna
source /home/anton/.cargo/env
PHASES="sctp" CASES="pressure" OUT=transports-sctp-pressure-recheck \
python3 scripts/verify/transport-lifecycle.py
```

## Development validation (2026-09-18)

- Linux debug node/client, two reconnect cycles and one crash round per transport.
- QUIC: all five scenarios passed.
- WebTransport: all five scenarios passed, using the exact IPv4 endpoint to avoid
  localhost resolving to a different listener address.
- Clippy with QUIC + WebTransport + SCTP: passed with `-D warnings`.
- Default/no-feature and SCTP-only load-client builds: checked successfully.
- Invalid phase/case selections and zero cycle count fail before building.
- Native SCTP network cases were not run in this development kernel, which lacks
  SCTP support. Run all fifteen cases on cloud; compilation is not network proof.
