# Benchmark — turna vs coturn

Three back-to-back STUN binding runs on the same machine:

1. **`turna-bpf-on`** — turna with the in-kernel BPF filter active
   (production setup).
2. **`turna-bpf-off`** — turna with the filter disabled, so every packet
   reaches userspace. This is the apples-to-apples comparison with
   coturn, which doesn't use a kernel filter.
3. **`coturn`** — reference implementation.

The goal is "is turna in the same ballpark as coturn", not 0.1%-precision
microbenchmarks. See the disclaimer at the top of `run.sh` for what
the script does and does not control.

## Prerequisites

- Linux. (BPF is Linux-only; on macOS the filter run reduces to the
  same code path as `turna-bpf-off`.)
- `coturn` installed (`apt install coturn` on Debian/Ubuntu;
  `dnf install coturn` on Fedora/RHEL).
- `jq` installed (`apt install jq`).
- turna built in release mode:

  ```sh
  cargo build --release
  ```

- Ports `3478`, `3479`, `9101`, `9190`, `5350` free.

## Running

From the repo root:

```sh
bash bench/run.sh
```

Defaults: concurrency 200, duration 30 seconds per run. Override with
env vars:

```sh
CONCURRENCY=500 DURATION=60 bash bench/run.sh
```

Skip the coturn run (e.g. on a machine without coturn installed):

```sh
SKIP_COTURN=1 bash bench/run.sh
```

## What you'll see

Stderr shows live progress as each run executes; stdout is a Markdown
table you can paste into a doc:

```
## Benchmark results — concurrency=200, duration=30s

| Run | RPS | p50 (µs) | p95 (µs) | p99 (µs) | Errors |
|---|---:|---:|---:|---:|---:|
| turna-bpf-on  | 47832 |  500 |  1000 |  5000 | 0 |
| turna-bpf-off | 45104 |  500 |  1000 |  5000 | 0 |
| coturn      | 38217 |  500 |  5000 | 10000 | 12 |
```

The example numbers above are made up — fill in actual values from
your machine in `bench/RESULTS.md` once you've run it.

Raw per-run JSON lives in `bench/results/`, e.g. `turna-bpf-on.json`.
Server logs in `/tmp/turna-bench.log` and `/tmp/coturn-bench*.log`.

## Interpreting the numbers

**RPS (responses per second)** is the throughput of the binding loop.
Each iteration is one Binding Request out, one Binding Response back.
Higher is better. With concurrency 200 and a fast loopback, both turna
and coturn should comfortably exceed 30k RPS. The CPU/network stack
becomes the bottleneck, not parsing.

**p50 / p95 / p99 latency** is the request-to-response round-trip
inside the binding loop. Resolution is bucketed (next bucket boundary
above the actual value), so don't read tiny differences as significant.
Order-of-magnitude comparisons are reliable.

**Errors** are timeouts (no response in 2s) and socket failures. On a
healthy loopback this should be zero. Non-zero errors usually mean the
server hit a saturation point (queue full, ephemeral port range
exhausted on the client side).

## BPF on vs off — what to expect

On a normal benchmark workload (every packet is a real STUN binding),
the BPF filter should add a tiny constant overhead to the in-kernel
path and otherwise be invisible. **The big win shows up when the
server is also receiving garbage packets** (scan traffic, broken
clients, malformed data). With BPF on, the garbage is dropped before
the kernel-to-userspace copy. Without BPF, every garbage packet costs
us a context switch and a parse-then-reject in userspace.

The bench script doesn't (currently) generate garbage traffic
alongside the real binding requests. If you want to demonstrate the
BPF benefit, run turna in production with the filter on and watch
`/proc/net/snmp` Udp errors trend down compared to filter-off.

## Re-running with stricter controls

For "publishable" numbers, tighten the methodology:

```sh
# Pin both server and client to specific cores
sudo cset shield -c 1,3,5,7 --kthread on
taskset -c 1 ./target/release/turna-node bench/turna.toml &
sleep 1
taskset -c 3 ./target/release/turna-load-test --server 127.0.0.1:3478 \
    --duration 60 --json binding -c 200

# Disable turbo boost (Intel)
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# Bigger socket buffers (both ends)
sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216

# Repeat 5 times and report the median, not the mean.
```

`run.sh` doesn't do any of this — that's deliberate, to keep the
script readable for the "is it in the ballpark" use case.

## Methodology caveats (honest list)

- **One client process.** A single `turna-load-test` instance with high
  concurrency may itself be the bottleneck before the server is. If
  RPS plateaus around `concurrency / round_trip`, you're saturating
  the client. Try a second client process or higher concurrency.
- **Loopback only.** Real network has different costs (NIC interrupt,
  IRQ steering, real bandwidth). Loopback numbers are useful for "did
  we regress the parsing path" but not for "how many calls can we
  serve from this VM".
- **STUN Binding only.** TURN Allocate/Refresh/Send paths are different
  in both servers. The `turna-load-test` Allocate and ChannelData modes
  are currently stubs that fall back to Binding — they exist as a CLI
  surface but don't yet exercise the Allocate state machine. Wider
  protocol coverage is on the roadmap (see `TODO.md`).
- **Single host.** A real TURN node lives behind a NAT/firewall and
  receives off-network traffic. We aren't measuring that here.

## RESULTS.md template

Once you've run it on your hardware, commit your numbers to
`bench/RESULTS.md` with the date, machine spec, and any deviations
from defaults. That way the comparison stays meaningful over time.
