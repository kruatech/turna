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

## Scenarios

1. **binding** — unauthenticated STUN Binding, closed loop,
   `CONCURRENCY` tasks. Measures the cheapest request path: parser +
   dispatcher + response encoding. Metric: RPS, p50/p95/p99 latency.
2. **allocate** — full authenticated Allocate handshake
   (401 challenge → MESSAGE-INTEGRITY request → success), then
   Refresh(lifetime=0) to release. Closed loop, `ALLOC_CONCURRENCY`
   tasks. Measures auth + HMAC + allocation bookkeeping. Metric:
   allocations/sec, handshake latency percentiles.
3. **relay-PAYLOAD** — `CHANNELS` allocations each pumping ChannelData
   at `PPS` packets/sec with PAYLOAD-byte payloads through the relay to
   a local peer socket. Measures the data plane: throughput out of the
   relay (Mbps), loss %, one-way relay latency percentiles. Run for
   160 B (voice-like) and 1200 B (video-like) payloads.
4. Optional: re-run binding with `GARBAGE_PPS` of random UDP noise via
   `garbage.sh` to compare behaviour under junk floods (turna's
   cheap-reject claim).

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

# file descriptors: relay scenario opens 2 sockets per channel
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

- `REPEATS=3` minimum (5 for publication); **median** reported.
- `DURATION=30` s per run for smoke, `60` s for publication.
- Servers run **sequentially**, never in parallel.
- One warm-up second after server start before the first run.
- Record in `RESULTS.md`: exact hardware, kernel (`uname -r`), turna
  commit, `turnserver -V` / `eturnalctl version` / pion-turn module
  version, and the env values used.

## Running

```bash
cargo build --release
sudo apt install coturn jq            # + eturnal, go per their docs
bash bench/matrix.sh                  # smoke, defaults
DURATION=60 REPEATS=5 bash bench/matrix.sh   # publication run
```

Output: `bench/results/matrix-<timestamp>/summary.md` — paste into
`RESULTS.md` together with the hardware block.

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
