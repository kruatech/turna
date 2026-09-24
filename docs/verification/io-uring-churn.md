# io_uring allocation churn acceptance

The 2026-09-18/19 cloud run on Linux 6.8.0-87 lasted 4.02 hours.
Its 16 measured phases each reported 3600 allocation errors. Resource
floors stayed stable (RSS approximately 134 MiB, 19 descriptors, 14 threads,
zero idle allocations); shutdown completed normally. This is not clean
churn acceptance. Server logs show unauthenticated-reply suppression;
the old client's error reporting cannot attribute every failure to it.

The allocation load mode now retains one UDP socket per worker. It learns
a challenge on the first allocation, deletes it with authenticated Refresh(0),
checks the zero-lifetime response, and repeats authenticated Allocate on the
same socket. This is necessary because server nonces bind the source port
as well as the IP. It retries a stale nonce once. Each successful measured
operation includes both allocation creation and confirmed deletion; latency
includes both requests. It does not measure fresh-source handshake throughput.

Failures are logged by stage and STUN code (first eight and powers of two).
Warmup failures remain in the final error count. Measured operations are
classified at their start, avoiding counter-reset races. A failed operation
abandons the uncertain session after best-effort deletion and backs off.
The soak sampler includes turna_unauth_replies_suppressed_total. Allocation
phases with errors or inconsistent attempted/completed totals fail analysis.

## Recorded acceptance after the client fix

Cloud Linux 6.8.0-87: the 300-second check completed 3,893,883 measured cycles
with zero errors. The subsequent four-hour run completed **237,891,751**
measured create/delete cycles across 16 phases, zero errors/loss, no
unauthenticated-reply suppression, stable idle resource floors and clean shutdown.
Local Linux 6.14.0-33: two 95-second measured phases within a 300-second check
completed **3,369,859** cycles, zero errors/loss and clean shutdown.

The earlier failed run above remains a failure; its counters are not included in
these totals. See [the evidence record](io-uring-supported-2026-09-19.md) for run
IDs, resource measurements and the distinction between measured and warmup totals.

The previously verified 30-minute ChannelData run remains separate evidence:
144020 measured packets sent/received, zero errors/loss, stable resource floors.
The supported scope is Linux UDP; these loopback runs do not establish WAN
behaviour or independent interoperability.
