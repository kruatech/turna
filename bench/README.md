# Benchmark — turna vs coturn

One command runs the same scenarios, with the same client, the same TURN REST
credentials and the same source-address spread, against turna and coturn — and,
when installed, eturnal and pion/turn:

```sh
bash bench/matrix.sh
```

**Numbers from this harness are only meaningful when produced on dedicated,
prepared hardware** (see [PLAN.md](PLAN.md): core isolation, governor, socket
buffers, file descriptors). Nothing in this repository was measured that way
yet; `RESULTS.md` is a template until someone does. A laptop, a CI runner or a
shared VM produces numbers that measure the neighbours. `SMOKE=1` exists to
prove the harness works end to end and is labelled as such in every output file.

## What it measures

| Scenario | What the client does | Reported |
|---|---|---|
| `memory` | Establish `HOLD_ALLOCS` allocations (default 5 000), each with one permission and one channel; hold; release all with Refresh(lifetime=0). A fresh server for each repeat. | server `VmRSS` before, while held and after release; **resident bytes per active allocation** = (held − before) / established |
| `binding` | Closed-loop unauthenticated STUN Binding from `CONCURRENCY` tasks, each rotating over `BINDING_SOCKETS` sockets | Binding RPS, p50/p99 latency, errors, server CPU % |
| `allocate` | Every cycle a new client (new socket): Allocate → 401 challenge → authenticated Allocate → Refresh(lifetime=0), deletion confirmed | **allocations/s**, p50/p99 of the whole cycle, errors, server CPU % |
| `relay` | `CHANNELS` concurrent allocations, each sending ChannelData at `PPS` through the relay to a local peer socket; once per payload size in `PAYLOADS` (default 160 B and 1200 B) | sent and delivered **pps**, **Mbit/s** out of the relay, **loss %**, one-way p50/p99, **server CPU % during the relay phase** |

Every scenario is driven by `turna-load-test` (`tools/load-test`), modes
`hold`, `binding`, `allocate --fresh` and `channel-data`. Server CPU and RSS come
from `/proc/<pid>/stat` (utime + stime) and `/proc/<pid>/status` (`VmRSS`), and
are sampled **by the load generator itself** at the start and end of the measured
window — after allocation setup and after the warm-up is discarded — because only
it knows where that window is (`--server-pid`, `tools/load-test/src/procfs.rs`).
CPU is percent of one core, so a multi-threaded server can exceed 100.

### Output

`bench/results/matrix-<timestamp>/`:

| File | Content |
|---|---|
| `results.csv` | one row per server × scenario, medians across repeats (machine-readable) |
| `results.json` | `meta` + every raw run + the same summary |
| `summary.md` | the summary as Markdown tables — what goes into `RESULTS.md` |
| `meta.json` | kernel, CPU model, governor, relevant sysctls, `ulimit -n`, turna commit (and whether the tree was dirty), exact coturn build, every parameter |
| `<server>__<scenario>__r<N>.json` | raw `turna-load-test --json` output per run; a failed run is kept as `….json.failed` and excluded from medians |
| `server-<name>.log` | the server's own output |

The `runs` column says how many repeats a median is over, so a row built from
fewer surviving repeats than requested is visible.

## Reproducibility

- **coturn is pinned.** `COTURN_SOURCE=docker` (default) runs
  `coturn/coturn:4.7.0-r4-debian` by digest
  (`sha256:a00afb5b4890de4df22bbe70379c6b316685dffee297d53cac1271dcb91fab93`,
  the multi-arch index as published on Docker Hub) with host networking and the
  same CPU set. `COTURN_SOURCE=native` uses the distro package and refuses to run
  unless it is exactly `COTURN_NATIVE_VERSION` (default `4.6.1-1build4`, Ubuntu
  24.04) — `COTURN_ALLOW_UNPINNED=1` overrides, and `meta.json` records what
  actually ran either way.
- **Same configuration surface.** `turna.toml`, `coturn.conf`, `eturnal.yml` and
  `pion-turn/main.go` all serve plain UDP with the REST secret `bench-secret` and
  realm `bench`. turna and coturn additionally run with quotas off and loopback
  peers allowed (the relay scenario's peer sockets are on `127.0.0.1`); eturnal's
  default peer blacklist was not checked against that.
- **Warm-up, duration, repetitions.** `WARMUP` seconds (default 5) of traffic are
  discarded before each measured `DURATION` (default 30); `REPEATS` (default 3;
  5 for publication) and the **median** is reported. Servers run one at a time,
  pinned to `SERVER_CPUS`; the client is pinned to `CLIENT_CPUS`.
- **Host tuning** is in [PLAN.md](PLAN.md#host-preparation-run-before-measuring).
  The script records the relevant settings in `meta.json` and warns when
  `net.core.rmem_max` or `ulimit -n` are below what the plan requires; it does
  not change host settings itself.

### Why the load comes from 65 534 loopback addresses

Two server behaviours would otherwise be measured instead of throughput, so the
harness spreads client sockets over `127.0.0.1`–`127.0.255.254` (`SOURCE_IPS`,
`--source-ips`) for every server alike:

- **turna's unauthenticated-reply budget.** A node answers at most 8
  unauthenticated replies per second per source address (burst 64;
  `unauth_reply_limiter` in `crates/relay/src/processor.rs`, not configurable).
  It is an anti-reflection control, and every Binding response and every 401
  challenge draws on it. From one address, the binding and allocate scenarios
  would report that budget. `CONCURRENCY × BINDING_SOCKETS × 8` per second is the
  ceiling the binding scenario can observe against turna (409 600/s with the
  defaults); errors in the binding row mean a source reached it and the spread
  must widen.
- **coturn's hold on a deleted allocation's 5-tuple.** After Refresh(0),
  coturn 4.6.1 answers a new Allocate from the same 5-tuple with 437 for more
  than 120 s (observed with a one-socket probe). A fresh client per cycle from one
  address soon lands on a recently used ephemeral port and collects those 437s.
  This is also why `allocate` without `--fresh` — one socket per worker, Allocate
  and Refresh(0) repeated on it — is not usable against coturn.

turna's configurable limits are raised in `turna.toml` (`[turn.rate_limit.default]`,
`[turn.relay.quota] max_per_user = 0`) for the same reason: coturn has no
Allocate rate limit and no per-user quota by default. The file says why for each.

## Prerequisites

- Linux (procfs, `taskset`; all of 127.0.0.0/8 routed to `lo`).
- `jq`, `python3`.
- turna built in release mode: `cargo build --release` (binaries are looked up in
  `$TARGET_DIR`, default `$CARGO_TARGET_DIR/release` or `target/release`).
- coturn: docker with a running daemon, or the pinned distro package.
- Optional: eturnal (`ETURNAL_BIN`), a Go toolchain for pion.

## Running

```sh
bash bench/matrix.sh                                         # everything, defaults
DURATION=60 REPEATS=5 bash bench/matrix.sh                   # publication settings
SERVERS="turna-bpf-off coturn" SCENARIOS="relay" bash bench/matrix.sh
CHANNELS=1000 PPS=50 PAYLOADS=1200 SCENARIOS=relay bash bench/matrix.sh
SMOKE=1 SERVERS="turna-bpf-off coturn" COTURN_SOURCE=native bash bench/matrix.sh
```

Every knob is an environment variable documented at the top of `matrix.sh`.
`turna-bpf-on` and `turna-bpf-off` are the same binary with the in-kernel BPF
pre-filter on or off (`TURNA_BPF_FILTER`); `turna-bpf-off` is the like-for-like
comparison with servers that have no kernel filter.

`bench/run.sh` is the older quick path: STUN Binding only, three runs (BPF on,
BPF off, coturn), a Markdown table on stdout. It uses the same source spread.

## Interpreting the numbers

- **Binding RPS** is the cheapest request path — parser, dispatcher, response
  encoding. It says little about relay capacity.
- **Allocations/s** includes two round trips, HMAC verification, relay-port
  allocation and deletion. p50/p99 are for the whole cycle.
- **Relay pps / Mbit/s / loss** is the data plane. `Mbit/s` is relayed UDP payload
  arriving at the peer (ChannelData framing is stripped by the relay). Loss is
  `(sent − delivered) / sent`; on an unprepared host it is dominated by kernel
  socket-buffer drops (`nstat -az UdpRcvbufErrors`), not by the server.
- **Server CPU %** in the relay table is the figure to compare against delivered
  pps: CPU per relayed packet is the efficiency number. At low offered load
  every server delivers everything and only the CPU column differs.
- **Bytes per allocation** is resident-set growth divided by allocations held. It
  includes allocator retention and excludes kernel socket buffers (not in RSS).
  Compare servers at the same `HOLD_ALLOCS`; the `after release` column shows how
  much the allocator kept.
- **Latency percentiles** come from a bucketed histogram (bounds in the raw JSON):
  good for order-of-magnitude comparison, not for microsecond claims.

## Methodology caveats

- **One client process.** A single `turna-load-test` can saturate before the
  server does. Watch the client cores; if they are pegged, the server figures are
  a lower bound.
- **Loopback only.** No NIC, driver, IRQ or real-network cost. Relative ordering
  on the same box is what this measures, not deployment capacity — for that, see
  `scripts/verify/capacity-profile.sh` and `[turn.relay] max_packets_per_sec`.
- **One process sampled.** CPU and RSS are for the server's main PID (turna and
  coturn are single-process, multi-threaded). eturnal is sampled at its Erlang VM
  (`beam.smp`), not at `eturnalctl`.
- **Defaults, not tuned configurations.** coturn runs with its default thread
  model; a tuned coturn (`relay-threads`, `cpus`) may do better. The configs are
  in this directory so anyone can re-tune and re-run.

## Results

Once a run on prepared hardware exists, paste `summary.md` and the host block
from `meta.json` into `bench/RESULTS.md`, with the date and any deviation from
the defaults.
