# TURN-over-SCTP: supported on Linux/tokio

## Decision and scope

Native SCTP is supported as an opt-in client-to-Turna transport on Linux using
the tokio backend. `production = true` permits it; normal production checks still
apply. The binary must be built with `--features sctp`, kernel SCTP must be
available, and the network must allow IP protocol 132. A loadable `sctp` module
is one way to supply kernel support; built-in support also works. Containers
share the host kernel. macOS/Windows are not supported by this implementation.

One ordered stream in a one-to-one association carries framed STUN/TURN requests,
responses and ChannelData. Relay traffic toward the peer remains UDP. This is a
project-specific TURN mapping, not an SCTP relay allocation, browser WebRTC
DataChannel or SCTP-over-DTLS. The SCTP transport provides no TLS encryption.
SCTP multistream operation and multihoming/failover are not verified scope.
The `sctp` feature reuses types behind `tls`; that dependency does not encrypt SCTP.

Global/per-IP association caps, per-IP association rate limiting, framing bounds,
independent idle read timeouts, bounded writes/queues, NODELAY, readiness, metrics,
allocation cleanup and cooperative drain are implemented. Per-IP limits default
to disabled; configure them for the deployment. Other backend selections are
rejected when SCTP is enabled, rather than silently omitting the listener.

## Recorded evidence

The following results were supplied by the operator during the 2026-09-18
verification session. Cloud: Ubuntu 24.04.3, Linux 6.8.0-87-generic, x86_64.
Remote WAN client: Linux x86_64 on kz, connecting to cloud over native SCTP.
Cloud's UDP echo peer was on loopback; an external peer-to-relay path was not tested.

| Check | Result | Scope |
|---|---|---|
| Native functional + allocation/session cleanup | 2/2 PASS | `transports-sctp-nodelay-linux`; actual Linux SCTP sockets |
| 60-second load | 6000/6000, errors 0 | 10 sessions, 10 pps, 160-byte payload |
| 300-second load | 30000/30000, errors 0 | `transport-load-sctp-nodelay-300s` |
| 1200-second load | 120001/120001, errors 0 | Exceeds 600-second binding lifetime; after nonce-retry fixes |
| Lifecycle/limits | SCTP 5/5 PASS | reconnect (10 cycles), crash (3 rounds), global cap, per-IP cap, pressure; `transports-lifecycle-linux` |
| WAN 10 seconds, 50 pps | 5000/5000, errors 0 | 10 sessions; after client read-readiness fix |
| WAN 300 seconds | 29980/29980, errors 0 | 10 sessions, 10 pps; verified payloads |
| WAN 1800 seconds | 179817/179817, errors 0 | 10 sessions, 10 pps; verified payloads; all sessions PASS |
| WAN server monitoring/cleanup | PASS | `echoes=179817`, `echo_errors=[]` for the 1800-second run |

Earlier failed runs remain failures. NODELAY fixed the short-run send-rate issue.
The pipelined test client subsequently needed a record-aware readiness fix:
TCP short-read assumptions stalled queued SCTP records. The client now uses
`readable()`/`try_read()`; the server already used `AsyncFd`. A regression test
with queued record sockets fails with the old client read and passes with the fix.
This is test-client evidence, not an additional server change in this promotion.

## Limits of the claim

- No independent third-party TURN-over-SCTP implementation was tested. Kernel
  transport and payload verification do not establish universal interoperability.
- No 24-hour or 72-hour run has been completed. Thirty-minute WAN testing is the
  longest recorded SCTP WAN run here; no multi-day claim is made.
- A local-Linux route failed to establish SCTP while kz-to-cloud succeeded.
  Reachability through a particular NAT, firewall or provider must be checked.
- Existing native tests used the test stand's non-production configuration.
  This promotion changes configuration policy, not the SCTP datapath. Production
  validation is covered by config tests; production deployments still require
  valid secrets, advertised addresses, peer policy and quota settings.
- QUIC and WebTransport are separate work items and are not promoted here.

## Reproducing the native checks

On a Linux host with SCTP support, from the repository root:

```bash
cargo build --locked --release -p turna-node -p turna-load-test \
  --features "tls,dtls,quic,web-transport,sctp"
python3 scripts/verify/transport-observe.py sctp
PHASES=sctp HEALTH_PORT=19095 OUT=sctp-supported-functional \
  bash scripts/verify/transports.sh
PHASES=sctp CYCLES=10 CRASH_ROUNDS=3 HEALTH_PORT=19096 \
  OUT=sctp-supported-lifecycle python3 scripts/verify/transport-lifecycle.py
```

Output directories must be new. The network stand is documented in
[transports-network.md](transports-network.md); it uses test credentials and
loopback relay addresses and is not a production configuration template.
