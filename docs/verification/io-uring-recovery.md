# io_uring receive and cancellation recovery

This revision retains receive slots when the submission queue is full and retries
before subsequent submit/wait operations. An error completion on an open relay
also retains the slot for rearming. Closing relays discard unsubmitted receives
and return their buffers before reclaiming the msghdr block. Cancellation requests
that do not fit in the SQ are retained and retried with priority over receives.

Relay creation refuses an existing/draining port and insufficient receive buffers
before publishing a socket. SQ pressure defers initial receive submission rather
than leaving a partially initialized relay through an error return. Any other
initial receive submission error begins relay teardown.

Five real-kernel regressions cover main receive recovery after SQ saturation,
closing an entirely deferred relay, cancellation retry after SQ saturation,
open-relay receive error recovery, and rejection with insufficient buffers.
The worker drain test requires receipt of a UDP probe before shutdown; a worker
that exits during setup can no longer produce a false PASS.

Validation in the editing environment: test targets compile and clippy with
warnings denied passes. Runtime recovery tests fail at ring creation with EPERM;
this environment does not permit io_uring. No runtime PASS is claimed here.

Operator validation on cloud Linux 6.8.0-87 subsequently passed all five recovery
regressions, the full 68-test transport unit suite and the worker drain test.
The editing environment restriction above is not a failure of that cloud run.
No second-kernel recovery unit-test result is inferred from functional or churn
logs. See the [support record](io-uring-supported-2026-09-19.md).

Run on a Linux host that permits io_uring, without sudo:

```sh
cargo test --locked -p turna-transport --features io-uring --lib recovery_tests -- --nocapture
cargo test --locked -p turna-transport --features io-uring --test io_uring_drain -- --nocapture
```

These are short, isolated loopback tests. No external TURN service or long-running
load is needed. Their success does not establish backend parity, production load
capacity or endurance; those checks follow after this recovery regression passes.
