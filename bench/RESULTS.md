# Benchmark results

Template only: fill this in after running `bench/run.sh` on your hardware.
Do not use placeholder rows as a performance claim.

## Run YYYY-MM-DD

**Hardware:** _e.g. AMD Ryzen 9 5950X, 32GB DDR4-3600, Linux 6.5,
network: loopback_

**Settings:**
- `CONCURRENCY=200`
- `DURATION=30s`
- turna commit: `<git-sha>`
- coturn version: `<output of turnserver -V>`

**Results:**

| Run | RPS | p50 (µs) | p95 (µs) | p99 (µs) | Errors |
|---|---:|---:|---:|---:|---:|
| turna-bpf-on  | <fill-in> | <fill-in> | <fill-in> | <fill-in> | <fill-in> |
| turna-bpf-off | <fill-in> | <fill-in> | <fill-in> | <fill-in> | <fill-in> |
| coturn      | <fill-in> | <fill-in> | <fill-in> | <fill-in> | <fill-in> |

**Observations / notes:**

- _Anything unexpected? Anomalies? Tunings applied?_

---

(Replicate the block above for each significant re-run — different
hardware, different commit, different methodology.)
