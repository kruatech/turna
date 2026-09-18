# Transport hardening — step 2 (2026-09-18)

Cumulative source patch against `01aee9d22afd0ef4fdba689478f0ec936f956f28`,
for `feature/supported-transports`. Includes step 1 and the stale-nonce fix.
This document supersedes step 1's remaining-work notes. No support labels or
production SCTP guard are changed before native/browser/endurance evidence.

## Code changes

- QUIC and WebTransport: independent bounded stream writers, shared session reply
  budget, five-second write deadlines, cancellation/reaping of stream tasks,
  malformed framing closes the session, mandatory negotiated datagrams and
  configured datagram size limits. `allow_migration` applies to both backends;
  zero keep-alive disables keep-alive. Preserve allocation ownership on conflicts.
- SCTP: native Linux one-to-one sockets with one ordered SCTP stream, independent
  reading/writing, bounded writes, read idle timeout unaffected by outgoing
  traffic, truncated-frame rejection, overloaded association closure and
  allocation ownership checks. A global connection cap of zero means unlimited.
  Invalid configuration and builds without SCTP fail explicitly.
- SCTP has no TCP-style half-close. The probe reads final replies before SCTP
  shutdown; see RFC 6458 section 4.1.7. SCTP is the client-to-server transport;
  the allocated relay remains UDP. This is not WebRTC SCTP-over-DTLS.
- Native `sctp-check` and `sctp` load modes. Functional probe checks authentication,
  forced 438 recovery for Refresh/CreatePermission/ChannelBind, unaligned
  ChannelData payloads, both relay directions, fragmented Binding and shutdown.
- QUIC/WT functional probes retain 128-stream/credit/FIN and raw migration checks,
  and add malformed-stream closure followed by successful reconnection.
- QUIC/WT load sends media via DATAGRAM. Failed workers stop their receiver;
  warmup errors survive the counter reset. Credentials last duration + warmup +
  one hour, instead of expiring after one hour during a long run.
- Verification builds with `--locked`; `BUILD_PROFILE=dev` is optional, release
  is the default. `PHASES` accepts `sctp`, with a real kernel preflight. Missing
  SCTP support fails rather than silently skipping. CI includes native SCTP.
- Functional and load scripts check zero allocations and sessions after clients
  exit. Load requires at least 99% of scheduled sends, honors client errors and
  samples RSS/CPU/FDs/metrics every five seconds. Resource sampling is diagnostic,
  not an automatic leak verdict. On macOS FD count is unavailable.
- Local browser stand: temporary EC certificate with explicit SHA-256 pin,
  loopback-only page, real UDP echo peer, exact return-payload checks for five
  stream and five datagram messages. Chrome uses its own WebTransport stack.

## Verification scope

Development environment: Linux, Rust 1.95.0. Not the user's cloud host or Mac.
166 tests passed across config/load/relay/transport; two existing doctests ignored.
The SCTP transport unit tests use stream socket pairs for I/O/framing behavior;
only the native Linux functional probe establishes SCTP protocol operation.
Clippy with SCTP + QUIC + WebTransport and `-D warnings` passed.
Raw QUIC and WebTransport functional probes and both cleanup checks passed
(four checks total), including forced 438, 128 streams, malformed-stream
closure/reconnect and raw QUIC migration.
Short load: each transport ran 30 measured seconds after 30 seconds warmup,
10 sessions × 10 packets/s, 160-byte payload. QUIC and WebTransport each
sent/received 3,000 packets, zero errors/loss; post-run cleanup passed.
Resource JSONL sampling produced records for both phases. This is only a smoke
check of the load harness, not five-minute or endurance evidence.

Native SCTP cannot run in this development kernel (`Protocol not supported`).
The local browser stand starts, serves the pinned page, echoes UDP and shuts
down cleanly on SIGTERM. Chromium download timed out, so no browser
interoperability result is claimed.
Run the commands below on the actual hosts and retain the reports before
promoting support status. Five-minute load does not establish nonce expiry,
endurance or browser compatibility. Long runs are a later gate.

The load table's `Relayed back` column is inherited: QUIC, WebTransport and SCTP
load count arrivals at the UDP peer (client → server → peer), not a full echo.
The separate functional probes verify the return path and payload contents.

## macOS: functional checks

From the repository root after unpacking:

```bash
PHASES="quic wt" HEALTH_PORT=19091 OUT=transports-step2-macos \
  bash scripts/verify/transports.sh
```

The script builds both release binaries before running. Four checks should pass,
including allocation/session cleanup. For a browser check in a separate run:

```bash
python3 scripts/verify/webtransport-browser.py
```

Open `http://127.0.0.1:8765/` in Chrome/Chromium, press Run, then Download log.
Stop the Python process with Ctrl-C afterward. Do not run this stand concurrently
with another local verification node. Requires Cargo, Python 3 and OpenSSL with
`-addext` (use the Homebrew OpenSSL already installed if macOS's bundled command
lacks it). The certificate pin and temporary test secret are prefilled.

## cloud: functional checks, then five minutes per transport

In the existing SSH terminal:

```bash
cd /home/anton/projects/turna
source /home/anton/.cargo/env
sudo modprobe sctp
python3 scripts/verify/transport-observe.py sctp

PHASES="quic wt sctp" HEALTH_PORT=19091 OUT=transports-step2-linux \
  bash scripts/verify/transports.sh
```

Expect six checks: each transport's functional probe and allocation/session
cleanup. If they pass, run:

```bash
SHORT_RUN=1 PHASES="quic wt sctp" PHASE_SECS=300 CONC=10 PPS=10 \
  HEALTH_PORT=19095 OUT=transport-load-step2-linux \
  bash scripts/verify/transport-load.sh
```

Three sequential phases: about 16–17 minutes plus the build, including 30 seconds
warmup per phase. Expected measured volume: about 30,000 packets per transport.
Do not run the functional and load scripts concurrently on the same host.
`SHORT_RUN=1` changes the duration gate, not loss/error/cleanup requirements.

The kernel module must exist; installing `libsctp` alone cannot supply kernel
support. No special userspace SCTP library is needed by these native sockets.
These commands use loopback and do not require exposing a new cloud port.

## Evidence to retain

- `transports-step2-linux/summary.md`, probe logs and cleanup logs.
- `transport-load-step2-linux/summary.md`, all `.json`, `.err`,
  `*-resources.jsonl`, `*-cleanup.log`, node logs.
- Downloaded browser JSON, browser version and platform.
- During long runs, compare resource samples after warmup and after cleanup.
  A flat-looking graph alone is not a lifetime/nonce/interop test.

Run 1,200 seconds per transport only after these short checks pass, without
`SHORT_RUN=1`. Then increase the duration. No week-long run is needed to debug
basic framing or stale nonce recovery: those have direct functional probes.
