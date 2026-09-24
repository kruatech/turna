# Benchmark plan & methodology

Fixed methodology for the published turna-vs-others numbers. The point
of writing this down *before* running: anyone (including a sceptic)
can reproduce the table in `RESULTS.md` from scratch.

## Contenders

| Server | Language | Why it's in the matrix |
|---|---|---|
| turna (BPF on)  | Rust   | our production configuration |
| turna (BPF off) | Rust   | apples-to-apples vs servers without a kernel pre-filter |
| coturn          | C      | the de-facto standard |
| eturnal         | Erlang | the actively-developed modern alternative |
| pion/turn       | Go     | popular in self-hosted WebRTC stacks |

All four speak the same TURN REST credential convention, configured
with one shared secret (`bench-secret`) — see `turna.toml`,
`coturn.conf`, `eturnal.yml`, `pion-turn/main.go`.

**Pinned builds.** coturn: `coturn/coturn:4.7.0-r4-debian@sha256:a00afb5b4890de4df22bbe70379c6b316685dffee297d53cac1271dcb91fab93`
(`COTURN_SOURCE=docker`, the default) or the Ubuntu 24.04 package
`4.6.1-1build4` (`COTURN_SOURCE=native`; any other installed version is refused
unless `COTURN_ALLOW_UNPINNED=1`). turna: the commit recorded in `meta.json`,
built with `cargo build --release`. Publish results against one pin only, and
say which.

## Scenarios

0. **memory** — establish `HOLD_ALLOCS` authenticated allocations, each with
   one permission and one channel (`turna-load-test hold --channel`), hold,
   release. Server `VmRSS` sampled before, while held and after release; each
   repeat on a freshly started server. Metric: resident bytes per active
   allocation.
1. **binding** — unauthenticated STUN Binding, closed loop,
   `CONCURRENCY` tasks, each rotating over `BINDING_SOCKETS` source sockets.
   Measures the cheapest request path: parser + dispatcher + response encoding.
   Metric: RPS, p50/p95/p99 latency.
2. **allocate** — every cycle a new client (`allocate --fresh`): new socket,
   unauthenticated Allocate → 401 challenge → authenticated Allocate →
   Refresh(lifetime=0), deletion confirmed. Closed loop, `ALLOC_CONCURRENCY`
   tasks. Measures auth + HMAC + allocation bookkeeping. Metric:
   allocations/sec, cycle latency percentiles.
3. **relay-PAYLOAD** — `CHANNELS` allocations each pumping ChannelData
   at `PPS` packets/sec with PAYLOAD-byte payloads through the relay to
   a local peer socket. Measures the data plane: throughput out of the
   relay (delivered pps, Mbit/s), loss %, one-way relay latency percentiles,
   and server CPU % over the measured window. Run for 160 B (voice-like) and
   1200 B (video-like) payloads.
4. Optional (`bench/run.sh`): re-run binding with `GARBAGE_PPS` of random UDP noise via
   `garbage.sh` to compare behaviour under junk floods (turna's
   cheap-reject claim).

Every scenario records server CPU % and `VmRSS` at the start and end of its
measured window (`turna-load-test --server-pid`). All client sockets are spread
over 65 534 loopback source addresses — README.md explains why this is needed
for both turna (per-source unauthenticated-reply budget) and coturn (5-tuple
held after Refresh(0)).

## Hardware & layout (reference box: 16c/32t, 128 GB, Ubuntu)

Loopback benchmark, server and client on the same machine but pinned
to disjoint core sets so they don't steal each other's cycles:

- server: `SERVER_CPUS=0-7`
- client: `CLIENT_CPUS=8-15`

Leave the SMT siblings (16-31 on a typical 16c/32t layout — check
`lscpu -e`) idle, or pin them away from 0-15; hyperthread pairs sharing
a core add noise. 128 GB RAM is far beyond what any contender needs —
memory is not a variable here.

## Host preparation (run before measuring)

```bash
# performance governor — no frequency ramping mid-run
sudo cpupower frequency-set -g performance || \
  echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# file descriptors: binding opens CONCURRENCY x BINDING_SOCKETS sockets
# (51 200 by default), memory 1 per held allocation, relay 2 per channel
ulimit -n 1048576

# UDP buffers — defaults drop packets long before the servers do
sudo sysctl -w net.core.rmem_max=268435456 net.core.wmem_max=268435456
sudo sysctl -w net.core.rmem_default=16777216 net.core.wmem_default=16777216
sudo sysctl -w net.core.netdev_max_backlog=65536

# optional, for run-to-run stability: disable turbo
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
```

Close browsers/IDEs; check `htop` is quiet before starting.

## Protocol

- `REPEATS=3` minimum (5 for publication); **median** reported, with the
  number of surviving repeats beside it.
- `DURATION=30` s measured per run by default, `60` s for publication.
- `WARMUP=5` s of traffic before every measured window, discarded (allocation
  setup happens before the warm-up, so it is excluded too).
- Servers run **sequentially**, never in parallel; one settle second after each
  server start.
- `meta.json` records hardware, kernel, governor, socket-buffer sysctls,
  `ulimit -n`, turna commit, the exact coturn build and every parameter. Copy it
  into `RESULTS.md` with the summary; add `eturnalctl version` / the pion-turn
  module version if those servers ran.
- `SMOKE=1` shrinks everything to seconds to check the harness itself. Its
  output is marked as a smoke run and is never a result.

## Running

```bash
cargo build --release
docker pull coturn/coturn:4.7.0-r4-debian@sha256:a00afb5b4890de4df22bbe70379c6b316685dffee297d53cac1271dcb91fab93
sudo apt install jq                   # + eturnal, go per their docs
SMOKE=1 bash bench/matrix.sh          # harness check, seconds
bash bench/matrix.sh                  # defaults
DURATION=60 REPEATS=5 bash bench/matrix.sh   # publication run
```

Output: `bench/results/matrix-<timestamp>/` — `results.csv` and
`results.json` (machine-readable), `summary.md` (paste into `RESULTS.md`
together with the host block from `meta.json`).

## Honesty notes (include alongside published numbers)

- Loopback excludes the NIC/driver path; absolute numbers will differ
  on real networks. Relative ordering is what this measures.
- The load generator is itself a tokio program and can become the
  bottleneck at the high end — watch client-side CPU; if the client
  cores saturate, the server-side numbers are a lower bound.
- coturn is run close to its defaults; a tuned coturn
  (`--relay-threads`, etc.) may do better. Publish the configs (they
  are in this directory) so anyone can re-tune and re-run.
- Latency percentiles come from a bucketed histogram (bucket bounds in
  the JSON); they are resolution-limited, fine for cross-server
  comparison, not for microsecond-level claims.
- turna runs with its configurable per-source rate limits raised and its
  per-user quota off (`bench/turna.toml` says why for each); its fixed
  unauthenticated-reply budget (8/s per source) stays, and the source spread
  keeps it out of the measurement. A production turna from one busy NAT address
  behaves differently — that is the `trusted_prefixes` tier's job, and not what
  this benchmark measures.
- Memory per allocation is RSS growth: it includes allocator retention and
  excludes kernel socket buffers.
