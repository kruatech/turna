# Cross-host transport check

`scripts/verify/transport-network.py` supplies a cloud-side stand and a remote
client harness for QUIC, WebTransport and native Linux SCTP. It does not change
production transport behavior. Start with 300 seconds per transport.

## Topology and scope

The client runs on a different host, behind its normal router. TURN control and
ChannelData travel over the public network to the cloud host. A UDP echo peer
runs on cloud loopback at 127.0.0.1:39001, reached through real TURN allocations
using relay ports 22000..22847. Replies return through the transport to the client.
No SSH tunnel, port forwarding to the client's LAN or public echo port is needed.
This exercises WAN transport, not an external peer-to-relay UDP path.

The stand deliberately advertises loopback relay addresses and permits loopback
peers. Its generated certificate is self-signed; Rust clients accept it without
PKI validation. This is not certificate validation, browser interoperability,
independent implementation interoperability, or a production deployment recipe.

QUIC and WT use UDP 3484 sequentially. SCTP uses native protocol 132 port 3485.
Health binds only 127.0.0.1:19097; auxiliary TURN binds 127.0.0.1:3476. Preflight
refuses occupied listener ports. Existing services are not stopped or changed.

## Preparation

Build client: `cargo build --locked --release -p turna-load-test --features
"tls,dtls,quic,web-transport,sctp"`. On cloud build node with the same features.

Run `python3 scripts/verify/transport-network.py init` once on the coordinating
machine. It exclusively creates `/tmp/turna-network-credentials.json`, mode 0600.
Copy that file to the same path on both Linux machines using the Mac SSH aliases.
Do not regenerate between phases. No credentials are included in the patch.

Allow UDP 3484 and SCTP 3485 on cloud for the remote client's current public IPv4.
If the client's dynamic address changes, update those rules before restarting.
An SCTP-capable kernel does not establish SCTP support through NAT or the provider.

## One phase

Cloud terminal (leave running):

```
python3 scripts/verify/transport-network.py serve --transport quic --out network-quic-cloud-300s
```

After READY, remote client terminal:

```
python3 scripts/verify/transport-network.py client --transport quic --seconds 300 --out network-quic-client-300s
```

Default destination: 45.88.174.72. Override with `--server` (IPv4 or DNS name).
Default concurrency: 10 sessions, rate: 10 round trips/s each, payload: 160 bytes.
After the client completes, press Ctrl+C in the cloud terminal. The server harness
checks allocation/session cleanup and complete resource monitoring, then terminates
only its own node and sampler. Node and sampler are isolated from terminal Ctrl+C
so cleanup is checked while the node remains alive. Wait for the final server result.

Repeat with `--transport wt`, then `--transport sctp`, and unique output directories.
For longer checks use `--seconds 1200` on the client; the server waits until stopped.
There is no automatic escalation from short to long tests.

## Acceptance and artifacts

Each session generates a random token and sequence in the payload, and validates
returned channel, length and every payload byte. UDP echoes from other sources,
wrong sequences, truncation and payload changes cannot count as success. Control
refresh runs every 240 seconds using the existing stale-nonce retry implementation.

The driver sends on a paced schedule with at most **128 packets in flight per
session**. It validates the session token, sequence, channel, length and every
payload byte. Reordering is accepted; duplicates and unknown sequences fail.
Every outstanding packet has a 5-second deadline; a full window fails explicitly.
For QUIC/WT DATAGRAM, expiry removes the packet from the pending window, records
its deadline violation, and **continues the full run** without retransmission.
Native SCTP retains fail-fast echo timeouts. Before control refresh the driver
drains pending media (or accounts for expired DATAGRAMs); refresh errors still
abort. At the end pending replies are drained for their remaining deadlines.
Missed timer ticks are skipped rather than caught up in bursts.

A valid late DATAGRAM echo is counted once as verified and as late; its previous
deadline violation remains recorded. Duplicate/unknown sequences, invalid payloads,
connection errors, send errors, and refresh failures remain fatal. Exact duplicate
tracking uses a bitmap bounded by the run's send budget (up to 10.8 MB per session
at the maximum one-day/1000-pps settings). At most 32 expired sequence numbers are
logged to stderr; final JSON includes a sample of up to 32 still-missing sequences.

The v2 report separates three gates:

- **Stability**: completed requested duration, no operational/protocol/close errors,
  and no pending packets at the end. This alone does not establish media delivery;
  even a total media blackout can finish if control remains healthy.
- **Rate**: at least 99% of target sends and a nonempty in-flight window.
- **Delivery**: zero missing echoes **and** zero five-second deadline violations.

Overall PASS still requires all three gates and exit code zero. There is no new
loss allowance. A completed DATAGRAM diagnostic with loss has `errs=0` but a
nonzero exit code and Delivery/Overall FAIL. Early failures retain `errs=1` and
Stability FAIL. Old binaries lacking the v2 schema cannot pass this harness.

Per-session JSON records missing echoes, loss percentage (missing/sent), deadline
violations, late echoes, completion, refresh counts, peak in-flight count and
pending-at-end. Mean/max RTT include replies received before expiry only, with
late replies reported separately. Client QUIC/WT statistics are sampled before
close: UDP and DATAGRAM-frame counts, path lost/sent packets, congestion events
and current RTT. QUIC packet loss counters include protocol traffic; they are not
application echo loss, and successful DATAGRAM enqueue does not prove delivery.
No warmup or reset obscures initialization or first packets. This remains a
low-rate correctness check, not a saturation benchmark.

Earlier WAN runs used stop-and-wait and failed volume at both 10 and 5 pps on the
kz route despite all sent payloads returning correctly. Preserve those results as
FAIL for offered volume; the pipelined driver is a distinct test revision, not a
retroactive reclassification. Native SCTP in this stand does not use TLS.

Client: summary.md, results.json, per-session JSON and stderr, manifest.json.
Cloud: resources.jsonl, cleanup.log, monitoring.log, server-result.json, node.log,
manifest.json. Manifests include binary SHA-256, host/kernel and UTC timestamp.
The client PASS and cloud monitoring/cleanup PASS are both required.

Cloud output also contains a private test key and config with the shared secret:
do not publish the entire output directory. Credentials live separately in /tmp.
The output directory is created exclusively (reruns cannot overwrite evidence).

Local verification: payload/token validation, delayed/reordered echoes at the
requested rate, duplicate rejection and missing-reply timeout tests; clippy with
warnings denied;
loopback smoke runs exercise the new cloud/client harness for QUIC and WT. Native
SCTP and actual WAN behavior must be established on the user's Linux hosts.

## Diagnostic revision after the 2026-09-18 QUIC WAN failure

The old fail-fast WAN run sent 152859 payloads, the server received and echoed
152854 and clients verified 152853. Server send/queue/parser errors were zero.
The archive does not identify where the missing DATAGRAMs were lost. Preserve
that run as FAIL; these diagnostic changes do not reclassify it or repair a
proven server fault. They allow future runs to finish and expose loss separately.

Run regression tests with:

```
cargo test --locked -p turna-load-test --features "tls,dtls,quic,web-transport,sctp"
python3 -m unittest discover -s scripts/verify -p test_transport_network_result.py
```

Tests cover continued sending and refresh after a missing DATAGRAM, complete
media blackout, late/duplicate/unknown echoes, payload and connection errors,
refresh failure, strict SCTP timeout, and separate acceptance gates. Native SCTP
kernel/WAN validation still requires Linux with SCTP support.

Local validation of this revision: 17 Rust tests and 6 report-gate tests passed;
clippy with tests and warnings denied passed. Real loopback QUIC and WT each
verified 400/400 echoes (two sessions, 10 seconds, 20 pps). Dropping one UDP echo
at a separate test peer produced 80/79 in each transport over the full eight
seconds, `completed=true`, `errs=0`, one missing echo and one deadline violation:
Stability/Rate PASS, Delivery/Overall FAIL, process exit 1. Server monitoring and
cleanup passed for both stands. These are local checks, not a new WAN result.


## Explicit WAN acceptance policies

`--acceptance strict` remains the default: zero missing echoes, zero deadline
violations, successful session operation and at least 99% of offered volume.
`--acceptance transport` checks QUIC/WT session completion, zero reported
protocol/operational errors, drained pending tracking, at least 99% of offered
volume and nonzero verified echoes. It allows the existing Rust exit code 1 only
when the diagnostics establish completed operation with a delivery failure.
SCTP requires strict delivery under either policy.

Transport acceptance is deliberately NOT a network quality threshold: even
large loss can coexist with operational sessions. Always inspect Delivery,
Missing and Deadlines. No missing echo or deadline is removed, retried or
reclassified as delivered. A transport-policy PASS is not sufficient by itself
to declare a feature supported. Server monitoring/cleanup is a separate required
check; loss attribution requires additional evidence such as paired captures.
Old results remain unchanged and retain their original strict verdicts.

Example on the kz client, with the matching WT cloud stand already READY:

```sh
cd /tmp/turna
python3 scripts/verify/transport-network.py client \
  --transport wt --seconds 60 --sessions 10 --pps 10 \
  --acceptance transport \
  --out "network-wt-kz-transport-60s-$(date +%Y%m%d-%H%M%S)"
```

Only the Python runner/report changed; existing v2 Rust clients need no rebuild.
For captured evidence and scope, see [WT WAN capture analysis](webtransport-wan-2026-09-18.md).
