# AF_XDP WAN runner

`python3 scripts/verify/af-xdp-wan.py --help` (Python 3.11+).
Run from the repository root. The runner is specific to the test deployment:
cloud 45.88.174.72:13478, health 127.0.0.1:19100, relay 23000–23255;
kz client/UDP peer 176.12.76.60. It uses the temporary test shared secret
`afxdp-wan-test-20260920`; do not use it for a production deployment.

Server: `serve --config afxdp-wan-skb-20260920-010144/turn.toml --mode native --out afxdp-native-cloud`.
The existing config must select ens3, queue_ids [0,1], copy mode and the
addresses above. Only attach_mode is changed in the private output copy.
The runner refuses an existing XDP attachment and occupied test ports.
It does not change NIC channels, RSS or offloads. A native attach failure is
recorded as failure; there is no automatic fallback to SKB.

Client: `client --out afxdp-native-kz`. Run after server READY, within one minute.
Server default window is 480 seconds, client is 300 seconds. Both stop
automatically. Client deadline is duration + 60 seconds. Node gets SIGTERM
and up to 60 seconds to exit; forced termination fails the run.
Kz requires root for a temporary source/relay-port-scoped iptables rule;
the rule is removed in finally. Cloud runs as root for AF_XDP.

Server summary requires nonzero RX and TX on every configured queue, zero
queue parse/TX errors, zero global send drops, no registered relay ports or
in-flight TX at the final sample, clean node exit, and XDP detached.
Per-queue counters are structured INFO logs (`AF_XDP queue stats`), not new
Prometheus families. RX counts parsed UDP frames; TX counts successful
submission, not delivery. Final snapshots are emitted after TX draining.
Neither equal server RX/TX counts nor server PASS proves client delivery.

Client media summary requires exit 0, zero operational errors, consistent counts,
at least 99% of requested volume/duration, and delivery >= --min-delivery-percent
(default 99.99). strict_delivery remains separate and visible. The threshold was
agreed after the original 4-hour run; its original strict FAIL is not overwritten.

Use client --workload churn --seconds 900 for confirmed allocation/deletion cycles.
This invokes the corrected allocate command with concurrency 10 and retained
source sockets. Rebuild the load tool from current sources: churn_request must
confirm Refresh lifetime=0, and retry stale nonce. Churn always requires zero
errors/loss, matching counts, >=1000 completed cycles and full requested duration;
media loss tolerance never applies to churn. This is allocation/map churn, not
media payload verification or a throughput benchmark. Run the server for 1200s
and start the client within one minute of READY, leaving time to observe cleanup.

Server resources.jsonl and metrics-final.txt are retained. Resource gate requires
>=12 samples, median RSS growth between first/last 12 samples <=64 MiB, and final
FD <=initial FD+2. Final active allocations must be zero. These are bounded-growth
checks, not proof of absence of all leaks; preserve the raw series for review.
Server summary and client summary must both pass.


Validation of this patch in the development environment: seven verdict/resource
unit tests, Python syntax and Rust syntax parsing. Rust compilation and native
NIC runtime verification must run on the target Linux host.


## UDP churn retry revision — 2026-09-21 (historical findings)

The ratefix run completed 33,908 of 35,076 cycles, with 1,168 errors.
The remaining 12 allocations were 304–537 seconds old at shutdown, below
600-second expiry. Eleven other allocations expired at about 600 seconds.
These observations do not establish a descriptor leak. They also do not make
this churn run pass. The location of packet loss has not been established.

The load client now retransmits identical UDP request bytes and transaction IDs
at exponential intervals starting at 500 ms, within the existing total request
timeout (2 seconds by default). Responses must match source, transaction ID,
method, cookie and message length. Terminal timeouts remain errors.

The processor caches successful authenticated UDP Allocate/Refresh responses,
not their side effects. Duplicate requests return the stored response without
repeating RegisterRelay or CloseRelay. Changed bytes with the same source and
transaction ID are dropped. TCP control bypasses this cache. This follows the
transaction-state principle in [RFC 8489 sections 6.2.1 and 6.3.1](https://www.rfc-editor.org/rfc/rfc8489.html#section-6.3.1).

Cache limits: 64 source-address shards, 128 responses per shard, 40-second TTL,
requests up to 4096 bytes and responses up to 1024 bytes. Oldest entries are
replaced at capacity; replay retention can therefore be shorter under pressure.
This is not a claim of unlimited replay protection or a full STUN implementation.
The original ingress limiter remains active; unauthenticated/error replies do
not populate the cache. Re-run high-rate local churn before accepting this
shared processor change for release.

Server churn preflight now requires an explicit trusted test tier for kz;
it does not change production quotas. Pass `--workload churn` on BOTH ends.
The server report includes the individual cleanup counters. Client acceptance
still requires zero errors, complete cycles and adequate duration/volume.
Resource and cleanup gates are unchanged. Do not convert a failing run to PASS
by waiting out abandoned allocations.

New Rust regression tests cover lost Allocate/delete replies, delayed old
Allocate after deletion, concurrent duplicates, changed request bytes, cache
expiry/capacity, client retransmission after lost request/reply, wrong-source
responses and bounded timeout. These tests must run on the build host; syntax
checking alone is insufficient. Later native churn passed: 49,647/49,647 cycles
over 900 seconds, with full cleanup. The earlier timeout cause remains unknown.
See [current support scope and complete evidence](af-xdp-supported-2026-09-22.md).
