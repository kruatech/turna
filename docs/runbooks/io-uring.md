# Operating the supported io_uring UDP datapath

## Select and size

Use Linux with kernel io_uring enabled and allowed by the host/container policy.
Current tested kernels are 6.8.0-87-generic and 6.14.0-33-generic on x86_64.
Tokio remains the default; select io_uring explicitly for predictable deployment.

From the repository root:

```bash
cargo build --locked --release -p turna-node --features io-uring
cargo build --locked --release -p turna-load-test
```

Set `transport = "io_uring"` in the existing `[turn]` section. Keep the real
external IP, authentication, peer filter and relay range appropriate for the
production deployment. Do not copy loopback test configuration into production.
Validate the complete config with the node's existing validation workflow before
launching it. SCTP is restricted to tokio; UDP backend support does not imply
support for every listener combination.

`TURNA_IOURING_WORKERS` sets a positive worker count; otherwise available CPU
parallelism is used. Each worker owns buffers and ring resources. Size worker
count and `[turn.io_uring] relay_socket_capacity_per_worker` together. That
capacity defaults to 256 and is capped at 1024 per worker; it is not an override
of global allocation quotas or available relay ports. Measure actual RSS and
FD demand before raising either. Recorded RSS ranged from 134 MiB on cloud to
1073 MiB on the local host, with stable floors in the respective tests.

## Deployment verification

Run on an isolated Linux checkout/test host with the required loopback ports free:

```bash
cargo test --locked -p turna-transport --features io-uring
cargo test --locked -p turna-load-test
OUT=uring-backend-$(date +%Y%m%d-%H%M%S) bash scripts/e2e/backend_diff.sh
```

The functional runner builds the node, runs ten cases on each backend, and
requires both clean exits. Its 60-second shutdown allowance includes draining;
forced kill is a failure. Unit tests alone do not exercise sustained relay media.

A short authenticated churn check (roughly six minutes including settling):

```bash
TRANSPORT=io_uring \
DURATION_SECS=300 LOAD_PHASE_SECS=100 IDLE_PHASE_SECS=50 \
LOAD_MODES=allocate \
ALLOC_CONCURRENCY=10 \
TURN_PORT=13478 HEALTH_ADDR=127.0.0.1:19098 \
RELAY_MIN=23000 RELAY_MAX=23255 MAX_ALLOCATIONS=128 \
OUT_DIR=uring-churn-300s-$(date +%Y%m%d-%H%M%S) \
bash scripts/soak/soak.sh
```

A relay check that crosses the 600-second binding lifetime:

```bash
TRANSPORT=io_uring \
DURATION_SECS=1800 LOAD_PHASE_SECS=750 IDLE_PHASE_SECS=150 \
LOAD_MODES=channel-data CHANNELS=10 PPS=10 PAYLOAD=160 \
ALLOC_CONCURRENCY=10 \
TURN_PORT=13478 HEALTH_ADDR=127.0.0.1:19098 \
RELAY_MIN=23000 RELAY_MAX=23255 MAX_ALLOCATIONS=128 \
OUT_DIR=uring-media-1800s-$(date +%Y%m%d-%H%M%S) \
bash scripts/soak/soak.sh
```

Run these sequentially because they share ports. Record `environment.txt`,
`samples.csv`, `verdict.txt`, complete `load-*.json`, client/node errors and the
console shutdown result. Preserve the source revision and local patch identity.
Do not publish generated configs containing credentials.

For extended authenticated churn, use the same isolated settings with
`LOAD_MODES=allocate`, `DURATION_SECS=14400`, `LOAD_PHASE_SECS=750` and
`IDLE_PHASE_SECS=150`. This alternates load and idle, not continuous media.
Require matching client attempts/completions, zero errors, returned idle
allocations/FD floors, bounded RSS and successful shutdown. Investigate warnings;
do not lower acceptance thresholds to turn a failing run green.

## Observe and diagnose

- Readiness: `turna_transport_readiness` and `turna_backend_readiness`.
- Pressure: `turna_uring_sq_len`, `turna_uring_sq_capacity`,
  `turna_uring_sq_push_failed_total`, `turna_uring_buffers_available`.
  Failed SQ pushes count attempts: deferred receives/cancels are retried, so
  this counter alone is not a dropped-packet count.
- Capacity: `turna_uring_relay_capacity_exhausted_total`,
  `turna_uring_inflight_send_slots`, `turna_uring_send_slot_stalled_total`.
- Delivery and auth: client sent/received/errors, `turna_send_queue_dropped_total`
  and `turna_unauth_replies_suppressed_total`. Repeated new-source challenges can
  hit the reply limiter; authenticated churn reuses each worker's socket.
- Resources: RSS, open FDs, threads and allocations during load and after cleanup.
  Stable RSS at a high baseline may reflect worker buffers; rising idle floors
  require investigation.

Stop the owning test script normally and allow its node cleanup to finish.
The soak console may report its log-size watcher as killed; distinguish that
helper from the node's final `node exited cleanly on SIGTERM` result.
For services, honor the node's logged shutdown budget in supervisor settings.

If ring creation fails, inspect kernel/container permissions and use explicit
tokio as an operational fallback if required; do not silently report an io_uring
PASS while testing a fallback backend. After kernel or configuration changes,
repeat the relevant checks. See [the support evidence](../verification/io-uring-supported-2026-09-19.md).
