# QUIC / WebTransport — step 1

Historical step-1 report; see [step 2](transports-step2.md) for the cumulative patch.

Base: `01aee9d22afd0ef4fdba689478f0ec936f956f28`. Apply to the existing
`feature/supported-transports` branch. No push is required.

This patch fixes transport correctness and adds regression coverage. It does
not promote any transport to supported. SCTP is unchanged in this patch.

## Changes

- Separate STUN/ChannelData reassembly for each bidirectional stream.
- Release a stream's framing state and send half on receive EOF, after queued
  replies; half-close still delivers the final response and returns stream credit.
- Reserve global and per-IP connection slots before handshake. A guard releases
  reservations on failure, timeout and task cancellation; concurrent handshakes
  cannot all pass a stale active-session count.
- Bound handshake waits to 10 seconds and stream writes to 5 seconds. A failed
  or timed-out write closes the connection rather than retrying a partial frame.
- Re-key the TURN allocation and its indexes when QUIC validates a new address.
  Check migration collisions and destination IP admission limits. Publish the
  new egress sink before changing the allocation's address.
- Validate enabled QUIC configuration: datagrams required, usable stream counts,
  datagram-size bound.
- Extend quic-check and wt-check to 128 short streams with interleaved partial
  requests, reply routing and half-close checks. The verification script sets
  max_bi_streams=8, so the probe must recover stream credit. Binding probes are
  paced below the existing unauthenticated-reply budget.
- Rebind the raw QUIC client to a new UDP port after ChannelBind, then verify
  the existing allocation relays media in both directions.
- Drain the load client's queued media before closing; retain the WebTransport
  endpoint and wait for connection close to reach the server.
- Verification fails on node startup errors. Load verification preserves the
  client exit status and checks duration, loss and errors. PHASES can select
  quic/wt independently; MAX_LOSS_PERCENT and MAX_ERRORS default to zero.

## Files in the patch ZIP

```text
crates/config/src/lib.rs
crates/relay/src/processor.rs
crates/relay/src/quic_bridge.rs
crates/transport/src/quic.rs
services/node/src/quic_listener.rs
tools/load-test/src/main.rs
tools/load-test/src/quic_client.rs
tools/load-test/src/stream_common.rs
tools/load-test/src/wt_client.rs
scripts/verify/transports.sh
scripts/verify/transport-load.sh
docs/verification/quic-wt-step1.md
```

## Checks performed in the development Linux environment

Rust 1.95.0, locked dependencies, debug build of node and load client with QUIC
and WebTransport. This environment is not the user's Ubuntu server or macOS.

- Relay: 33 tests passed. Transport: 58 tests passed. Two existing doc tests ignored.
- QUIC config selection: 4 tests passed.
- Clippy for node/load client with QUIC and WebTransport: passed with -D warnings.
- cargo fmt and shell syntax checks: passed.
- Raw QUIC: 128 streams, UDP-port migration, 20/20 media frames to peer and
  a returned ChannelData datagram: passed.
- WebTransport: 128 streams, 20/20 media frames to peer and a returned
  ChannelData datagram: passed.
- Short load sanity check, each transport separately: two sessions, 15 seconds,
  10 packets/s/session, 160-byte payload. Each sent 300, received 300, errors 0.
  This is not endurance evidence.

Network checks used a temporary loopback node, self-signed localhost certificate,
LAN peer-filter profile with allow_loopback_peers=true, eight bidi streams and
real UDP peers. The commands below reproduce the checked scenarios through the
repository harness; that harness builds release binaries and additional transports.

## macOS: after unpacking into the repository root

```bash
set -a
source .env.test.example
set +a
cargo fmt --all -- --check
cargo test --locked -p turna-config quic_
cargo test --locked -p turna-relay -p turna-transport --features turna-transport/web-transport
PHASES="quic wt" OUT=transports-step1-macos bash scripts/verify/transports.sh
cat transports-step1-macos/summary.md
```

Check that the code update landed:

```bash
grep -n 'framers: HashMap' crates/relay/src/quic_bridge.rs
grep -n 'migrate_quic_allocation' crates/relay/src/processor.rs
grep -n 'struct Admission\|StreamReadClosed' crates/transport/src/quic.rs
grep -n '128 streams' tools/load-test/src/quic_client.rs tools/load-test/src/wt_client.rs
```

## Full source archive → scp cloud → unpack

Run from the macOS repository root after the checks. This reads current working
files, including uncommitted edits, not the old HEAD contents. The new document is
added explicitly. Build output, local credentials and test-run directories are not
included. Git is used only on the Mac to select tracked source paths.

```bash
git ls-files -z > /tmp/turna-step1-source-files
printf '%s\0' docs/verification/quic-wt-step1.md >> /tmp/turna-step1-source-files
COPYFILE_DISABLE=1 tar -czf /Volumes/media/downloads/turna_source_step1.tar.gz --null -T /tmp/turna-step1-source-files
scp /Volumes/media/downloads/turna_source_step1.tar.gz cloud:/home/anton/turna_source_step1.tar.gz
ssh cloud 'bash -s' <<'SH'
set -eu
cd /home/anton/projects
if [ -e turna ]; then
  mv turna "turna-backup-$(date -u +%Y%m%d-%H%M%S)"
fi
mkdir turna
tar -xzf /home/anton/turna_source_step1.tar.gz -C turna
SH
```

The previous server tree is preserved in the timestamped backup. Do not run this
while another test is using that tree. The new tree needs no Git metadata.

## Ubuntu: functional check, then sustained load

Install only missing build dependencies:

```bash
ssh cloud
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev protobuf-compiler openssl curl python3 tmux
cd /home/anton/projects/turna
source /home/anton/.cargo/env
set -a
source .env.test.example
set +a
PHASES="quic wt" OUT=transports-step1-linux bash scripts/verify/transports.sh
cat transports-step1-linux/summary.md
```

First run 20 minutes per transport (40 minutes plus build/startup):

```bash
tmux new-session -d -s turna-step1 'cd /home/anton/projects/turna && source /home/anton/.cargo/env && PHASES="quic wt" PHASE_SECS=1200 CONC=10 PPS=10 OUT=transport-load-step1-linux bash scripts/verify/transport-load.sh > /home/anton/turna-step1-run.log 2>&1'
tail -f /home/anton/turna-step1-run.log
```

After that passes, 24 hours per transport (48 hours total):

```bash
tmux new-session -d -s turna-step1-48h 'cd /home/anton/projects/turna && source /home/anton/.cargo/env && PHASES="quic wt" PHASE_SECS=86400 CONC=10 PPS=10 OUT=transport-load-step1-48h bash scripts/verify/transport-load.sh > /home/anton/turna-step1-48h.log 2>&1'
```

Return results as an archive from the Mac:

```bash
ssh cloud 'tar -czf /home/anton/turna_step1_results.tar.gz -C /home/anton/projects/turna transports-step1-linux transport-load-step1-linux'
scp cloud:/home/anton/turna_step1_results.tar.gz /Volumes/media/downloads/
```

## Remaining before supported

- macOS and actual Ubuntu verification of this patch; sustained-load results and
  resource-growth inspection across reconnects and malformed traffic.
- Browser WebTransport interoperability of this patch, including trust/origin
  configuration; the shared wtransport client cannot establish browser compatibility.
- Fault injection, blocked-reader/write-timeout behavior, path change under load,
  restart and certificate-rotation checks. Stream writes have a timeout but still
  share the session loop; this patch does not eliminate all write-side blocking.
- SCTP implementation, Linux kernel/dependency requirements, framing and real
  relayed-media tests; no SCTP support claim is made here.
