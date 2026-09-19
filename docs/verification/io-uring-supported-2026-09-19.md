# io_uring — supported Linux scope — 2026-09-19 UTC

## Decision and scope

The `io-uring` feature is **supported on Linux** for the explicitly selected
`[turn] transport = "io_uring"` UDP datapath. Tokio remains the default.
Supported means maintained and verified within this scope, not guaranteed on
every kernel, host security policy or workload. The current evidence covers
x86_64 Linux **6.8.0-87-generic** (cloud) and **6.14.0-33-generic** (local server).
The local run directory names use local time on September 20; console timestamps
are UTC on September 19. Do not infer a 24-hour run from that date difference.

Build with `--features io-uring`; ring creation must be permitted by the kernel
and container/security policy. Explicit selection fails startup when unavailable.
This promotion concerns UDP STUN/TURN allocation and relay behaviour. It does
not promote AF_XDP, establish every optional listener/backend combination, or
claim transparent allocation survival across NAT rebinding or node migration.
SCTP requires tokio. Existing listener support records keep their own scope.

## Evidence

The cloud media and corrected four-hour churn artifacts were inspected from
operator-supplied archives. Recovery and second-kernel results below are from
operator-supplied command output. These are not claims of rerunning the tests in
the documentation editing environment. A git revision was unavailable on cloud;
run IDs identify the tested working tree plus patches, not an independently
reproducible release hash. Preserve the artifacts alongside the resulting commit.

| Kernel / check | Result | Evidence |
|---|---|---|
| 6.8 recovery | PASS | Five real-kernel SQ/receive/cancel/buffer regressions; full transport suite 68 passed; worker drain test 1 passed |
| 6.8 functional | PASS in supplied checks | Initial suite passed the other nine cases per backend; after correcting the test peer address, two-way ChannelData passed on tokio and io_uring (`uring-relay-check-20260919-001951`) |
| 6.8 media, 1800-second harness | PASS | `uring-load-fixed-1800s-20260919-005940`; two 720-second measured phases, **144,020/144,020** packets, zero errors/loss, p99 1 ms |
| 6.8 authenticated churn, 300-second harness | PASS | `uring-churn-auth-300s-20260919-164653`; **3,893,883** measured create/delete cycles, zero errors |
| 6.8 authenticated churn, 14400-second harness | PASS | `uring-churn-auth-14400s-20260919-165418`; 16 × 720-second measured phases, **237,891,751/237,891,751** complete cycles, zero errors/loss, p99 5 ms |
| 6.14 functional and shutdown | PASS | `uring-backend-614-drainfix-20260920-021750`; ten live tests on each backend, **20/20**, both node exits 0 |
| 6.14 authenticated churn, 300-second harness | PASS | `uring-churn-614-300s-20260920-022516`; **1,724,372 + 1,645,487 = 3,369,859** measured cycles, zero errors/loss, p99 5 ms, clean SIGTERM |

The 6.14 functional suite covers Binding, malformed input, concurrency,
Allocate, wrong password, Refresh, CreatePermission, ChannelBind, two-way
ChannelData and stale nonce. It is a suite-level comparison, not byte-level
interoperability. No separate 6.14 recovery unit-test output was supplied;
functional acceptance must not be relabelled as that unit-test result.

### Resource observations

- Cloud four-hour churn: 478 samples over approximately 4.02 hours, idle RSS
  137088 → 137216 KiB (128 KiB increase), approximately 134 MiB peak;
  idle FDs 19, threads 14 after startup, idle allocations 0. Readiness stayed
  healthy; observed error counters and unauthenticated-reply suppression stayed
  flat. Node exited cleanly on SIGTERM.
- Cloud media: RSS approximately 134 MiB, idle FDs 19, threads 14,
  allocations returned to zero; clean shutdown.
- Local short churn: RSS approximately 1073 MiB with no reported idle-floor
  growth, idle FDs 75 → 75, threads 75 → 80 (reported PASS), idle allocations
  0 → 0. Readiness stable and checked error counters flat. Thread count was
  not constant; this short run is not evidence of long-term thread stability.

Measured churn rates were approximately 19,765–20,973 complete cycles/s on cloud
and 17,321–18,151 on the local host. These are different host configurations,
not a kernel performance comparison or a guaranteed production capacity.
Server allocation totals include warmup: 247,743,628 on the cloud long run and
3,536,405 on the local short run. Do not add them to client measured totals.

Worker count defaults to available parallelism and can be set with
`TURNA_IOURING_WORKERS`. Registered buffers/rings are per worker, so memory
consumption depends on worker and pool configuration. 134 MiB and 1073 MiB are
observations, not a universal memory requirement or evidence of a kernel leak.

## Failures kept in the record

The first four-hour churn (`uring-churn-14400s-20260919-014148`) failed with
57,600 errors. It repeatedly created fresh challenged sessions; server logs show
unauthenticated-reply suppression. Old diagnostics cannot attribute every error
uniquely. This run is not accepted or reclassified as successful.

The corrected client retains its source socket and nonce, retries stale nonce,
and counts success only after authenticated creation and confirmed Refresh(0)
deletion. Warmup errors remain visible. This tests authenticated lifecycle churn,
not fresh-source challenge throughput; no rate limiter was disabled to obtain PASS.

Earlier media clients left one final packet per channel unread at shutdown.
The corrected media run above has matching sent/received totals. The initial
6.14 functional run passed all tests but the harness killed the node after ten
seconds during draining. With a 60-second shutdown allowance, both backends
exited 0. A timeout or forced kill still fails the runner.

## Limits and repeatability

These loopback tests establish the recorded lifecycle, resource and media
behaviour. They do not establish WAN loss tolerance, an independent client
implementation, all address-family combinations, arbitrary worker/capacity
settings, NIC line rate, or multi-day endurance of this revision. The new long
run is four hours of a load/idle harness, including 3.2 hours of measured churn;
it is not four hours of continuous media.

Historical August endurance reports retain their original results and defects.
They are supplementary evidence for older revisions, not substituted for the
current recovery and churn checks.

[Operator runbook](../runbooks/io-uring.md),
[recovery tests](io-uring-recovery.md),
[functional runner](io-uring-backend-diff.md),
[churn semantics](io-uring-churn.md).
