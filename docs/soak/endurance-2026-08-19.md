# Endurance soak — 2026-08-19

Two datapaths, three hours each, on a 32-core / 126 GiB Linux host. Load from
`turna-load-test` via `scripts/soak/soak.sh`, alternating load and idle phases so a
leak shows as a floor that fails to return to baseline.

**Environment**

| | |
|---|---|
| Host | 32 cpus, 126 GiB, Linux 6.14.0-33-generic |
| Build | `--features tls` (tokio run), `--features io-uring` (io_uring run), release |
| Config | loopback, relay ports 49152–49999, `max_allocations = 800`, `max_per_user = 0` |
| Ingress rate limits | raised (see below) |
| Duration | 10800 s per datapath, 360 samples each |

## Result: no leak on either datapath

| Signal | tokio | io_uring |
|---|---|---|
| RSS, idle floor | 37780 → 37856 kB (**+0.2 %**) | 1056072 → 1056072 kB (**0.0 %**) |
| RSS peak under load | 39 MiB | 1031 MiB |
| File descriptors, idle floor | 42 → 42 | 727 → 727 |
| Threads | 33 → 33 | 97 → 97 |
| Active allocations, idle floor | 0 → 0 | 0 → 0 |
| Allocations churned | 13 688 758 | 58 552 244 |
| Packets received | 441 656 185 | 702 146 266 |
| `send_queue_dropped_total` | 0 | 0 |
| `processor_panics_total` | 0 | 0 |
| `malformed_packets_total` | 0 | 0 |
| `parser_rejections_total` | 0 | 0 |
| Drain on `SIGTERM` | clean | clean |

Both processes exited cleanly on `SIGTERM`, which is part of what the run tests —
the drain path is not exercised by anything else.

## Throughput, and the cost of it

Not the point of a soak, but the numbers came out of it and are the first real
comparison of the two datapaths.

| | tokio | io_uring |
|---|---|---|
| Allocate | ~2 500 rps, p50 5 ms, p99 100 ms | ~10 800 rps, p50 500 µs, p99 5 ms |
| Binding | 187 288 rps, p50 1 ms | 292 220 rps, p50 1 ms |
| Resident memory | 37 MiB | 1032 MiB |
| Threads | 33 | 97 |

io_uring is roughly 4× faster on Allocate and 1.6× on Binding, with an order of
magnitude better tail latency — for ~28× the resident memory. The memory is
pre-registered ring buffers, so it is a fixed cost paid at startup rather than growth
under load, which the flat RSS confirms.

A note for capacity planning: the io_uring run held an idle allocation floor of ~694
in an earlier 10-minute run against `max_allocations = 800`. It saturates the
configured cap before it saturates itself, so size the cap and the relay port range
to the traffic rather than to the backend.

## io_uring does not forward ChannelData

The finding this whole exercise was for, and it inverts the reading of everything
above it.

Identical test, identical config, only `[turn].transport` differs:

| | tokio | io_uring |
|---|---|---|
| ChannelData frames sent | 1 100 618 | 960 448 |
| **frames received back through the relay** | **1 100 618** | **0** |
| loss | 0 | 960 448 |
| bytes out → in | 180 MB → 176 MB | 157 MB → 0 |
| relayed rps | 19 644 | 0 |
| p50 / p99 latency | 5 ms / 10 ms | — |

So `io_uring` is not "unverified for relaying". It **does not relay**. A client
allocates — quickly, 10 800/s — installs a permission, binds a channel, sends media,
and nothing arrives at the peer. The control plane is excellent and the datapath does
not do its job.

**Read the endurance results above in that light.** Three hours of PASS on every
signal — no leak, no drops, no panics, flat RSS — described a datapath that was
forwarding nothing. That is the lesson worth keeping from this run: an endurance suite
measures degradation, and a component that does no work degrades beautifully. The
`channel-data` phase was the only check that would have caught it, and it was the one
phase that kept failing to run for harness reasons.

`turna_packets_sent` matching `turna_packets_received` on the server did not reveal it
either — those count the ingress socket, not the relay egress.

### Root cause: the relay send path leaked its recv slot

Each worker went permanently deaf after exactly 64 relayed packets — 64 being the
number of main recv slots it owns.

`ForwardAction::ZeroCopyViaRelay` deliberately did **not** re-arm the main recv slot,
with a comment explaining that the registered buffer stayed with the kernel until the
send completed, so re-arming early would be a use-after-free. That was true of an
earlier implementation that sent directly from the registered buffer. The loop now
copies the payload out (`to_vec()`) and releases the buffer immediately, so there is
nothing to wait for — but the slot was still never re-armed, and `msghdr_idx` was not
even carried in the batch, so it *could* not be. Every relayed packet consumed one
recv slot for good.

Control traffic was unaffected because it takes the `Send` path, which re-arms
normally. That is the shape of the whole symptom: allocation at ~10 800/s, 58.5 M
allocations over three hours, and not one relayed byte.

**Fix:** carry the recv slot through the batch and re-arm it after the payload is
copied, mirroring the `Send` path — re-arm rather than `release_buffer`, since the
buffer belongs to the slot and handing it to both the free pool and the kernel would
be a different bug.

### Confirmed fixed

Same test, same config, after the fix:

| | before | after |
|---|---|---|
| ChannelData relayed (phase 1) | 0 of 960 448 | **935 340, 0 errors** |
| ChannelData relayed (phase 2) | — | **962 843, 0 errors** |
| bytes returned through the relay | 0 | **150 MB + 154 MB** |
| relayed rps | 0 | **16 701 / 17 192** |
| p99 latency | — | **5 ms** |
| verdict | FAIL | **PASS** |

RSS still flat at 1031 MiB, fds and threads stable, every error counter flat. So the
endurance result above stands *and* now describes a datapath that actually forwards.

### How it stayed hidden

Worth listing, because each layer independently failed to show it:

- **Relay send completions with a negative result** incremented a shared `errors`
  counter that is neither logged per event nor exported as a metric. (Not the cause
  here — the sends succeeded — but it meant a failing send would have been just as
  invisible.)
- **The per-worker packet log** was gated on `stats.recv % 100_000`, and 960 k packets
  across 32 workers is 30 k each. It never fired.
- **`turna_packets_sent` matched `turna_packets_received`** on the server, which
  counts the ingress socket, not the relay egress.
- **The endurance suite reported PASS on every signal.** A datapath that forwards
  nothing does not leak, drop, or panic. Three hours of green described a component
  doing no work.

The only check that could have caught it was the `channel-data` phase, and that phase
failed to run for four separate harness reasons before it finally did.

## What this run does NOT establish

**Relayed data under load was never exercised.** The `channel-data` phases produced
no results in either run. Two separate causes, both in the harness:

1. The subcommand was spelled `channeldata`; clap derives `channel-data` from the
   enum variant, so the phase exited instantly and wrote an empty file.
2. After that was fixed, the phase's peer socket binds `127.0.0.1`, and loopback is a
   forbidden peer by default. Every channel failed `CreatePermission` with `403`
   during `--warmup` — and `--warmup` resets the counters, so the measurement window
   recorded `sent=0 recv=0 errs=0` for 370 s: a failed phase indistinguishable from
   an idle one.

So this soak covers **Allocate and Binding**, not ChannelData forwarding. For
`io_uring` that is the gap that keeps it *experimental*: a datapath that answers
control requests under load has not been shown to forward media under load.

Both harness faults are fixed (`allow_loopback_peers` in the generated config, and
`analyze.py` now reads `load-*.json` and fails a phase that reports all zeros), but
the run itself was not repeated.

Also not covered, for the reason stated in `docs/verification/interop-plan.md`:
TURNS, DTLS, RFC 6062 and WebTransport under load. `turna-load-test` speaks UDP only,
so no load can be placed on those paths at all. **The TURNS soak that would move
TURNS to `supported` is blocked on a TLS-capable load client, not on machine time.**

## Relay ports must not overlap the ephemeral range

Found while chasing why a `channel-data` phase forwarded nothing back. Worth stating
because the symptom points at the wrong component.

The load tool binds its "peer" socket with port 0, so the kernel assigns an ephemeral
port. Linux defaults to `32768–60999`, which fully covers a naive relay range of
`49152–49999`. When the peer's port falls inside the relay range, the relay forwards
the packet to an address it is itself serving: the traffic loops between allocations
instead of reaching the test.

What that looks like, and why it misleads: the server reported **53.9 M packets
received and 53.9 M sent, 2.8 GB out**, while the client reported `sent: 894400,
recv: 0`. Read alone, the server metrics say the datapath is working hard and the
client says it is broken — the natural conclusion is a forwarding bug in the backend.
The 60× discrepancy between what the client sent and what the server received is the
tell.

`soak.sh` now refuses to start on an overlap, names both ranges, and defaults to
`20000–20847`. On a real deployment this does not arise: peers are remote, and their
ports have nothing to do with the local ephemeral range.

## Rate limits, and why they were raised

Left at defaults, the run produced 3.1 M `turna_rate_limited` on tokio and 56 M on
io_uring, with about 60 successful allocations between them — and, before the analyser
was corrected, a clean "PASS" over that nothing.

The server was right. The limiter is per source IP and per prefix, and a loopback soak
sends every one of its 400 clients from `127.0.0.1`, which is indistinguishable from a
flood. The soak now raises `TURNA_RATE_LIMIT_RPS`, `TURNA_PREFIX_RPS`,
`TURNA_ALLOCATE_RPS` and friends for its own duration; the values land in
`environment.txt` so a run stays reproducible. These are environment variables rather
than config keys — see `PacketProcessor::new`.

Worth keeping in mind when reading any load result from a single-source harness: it
measures the datapath only after the limiter has been taken out of the picture, and
the limiter is part of production behaviour.

## Found by these runs

- **rustls crypto provider not pinned on the raw-QUIC path.** `build_quic_config`
  used `ServerConfig::builder()`, which resolves a *process-global* default provider
  and has none when two are in the graph. Under `--features "tls,quic"` — ring plus
  aws-lc-rs — it took the listener down between "QUIC server starting" and "QUIC
  endpoint listening", with no error logged and `turna_quic_readiness` stuck at 2.
  Invisible under `--features quic` alone, which is why the mac runs never saw it.
- **A QUIC listener could die silently.** The spawn logged a returned `Err` but not a
  panic: the task unwound, the JoinHandle was dropped, and the only trace was the
  consumer noticing its channel closed, at `INFO`. Now an error on both sides plus
  `readiness = Degraded`, so the alert fires.
- **`turna_transport_readiness` never left "starting"** on either datapath — exported,
  documented, listed as shipped, and never set. Found by comparing the two soak
  verdicts: tokio said "ready throughout" after the first fix, io_uring said
  "values seen: [0.0]", which is what revealed that the io_uring branch has its own
  startup path.

None of the three came from a test suite. Two came from reading a metrics dump during
an unrelated run, and one from a verdict diff between two backends.
