# Benchmark results

Fill this in after running `bench/run.sh` on your hardware.

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
| turna-bpf-on  | _xxx_ | _xxx_ | _xxx_ | _xxx_ | _xxx_ |
| turna-bpf-off | _xxx_ | _xxx_ | _xxx_ | _xxx_ | _xxx_ |
| coturn      | _xxx_ | _xxx_ | _xxx_ | _xxx_ | _xxx_ |

**Observations / notes:**

- _Anything unexpected? Anomalies? Tunings applied?_

---

(Replicate the block above for each significant re-run — different
hardware, different commit, different methodology.)
