# Host tuning

§12's NUMA, IRQ and socket-tuning items. Written from what has been measured on
this project's own hardware rather than from a generic checklist, which means it
is narrower and the numbers in it are real.

**Read the last section first if you are about to change something.** Most of the
settings below matter less than the two that are not settings at all.

## What was measured, and on what

| | |
|---|---|
| host | AMD Ryzen Threadripper 1950X, 32 threads, **one NUMA node** |
| memory | 126 GB |
| kernel | 6.14.0-33-generic |
| result | 112 000 relayed packets/second, 120 s, zero loss, zero egress drops |
| method | UDP over loopback, server pinned to cores 0–15, generator to 16–31 |

Full profile and its caveats: `docs/capacity/threadripper-1950x-2026-08-26.md`.
The number is an upper bound on the software path, not network throughput — the
generator shared the host and there was no NIC in the way.

## The two things that matter most

**There is no warning band before the ceiling.** Every rate up to 112 000 relayed
every frame. Seven percent above it, the egress queue shed a million frames in
two minutes. A node at 110 000 looks perfectly healthy and is one traffic bump
from losing 6 % of media.

No amount of tuning changes that shape. It means **run at a fraction of the
measured ceiling**, and it means `turna_send_queue_dropped_total` is the series
that tells you the truth — a client-side loss measurement cannot see a frame the
server discarded before sending, and that discrepancy made a capacity figure come
out 27 % too high here.

**The relay port range must not overlap the host's ephemeral range.**

```sh
cat /proc/sys/net/ipv4/ip_local_port_range     # e.g. 32768 60999
```

The default relay range of 49152–65535 overlaps that on most Linux hosts. A peer
socket landing inside the relay range makes the relay forward to itself, and it
has happened in this project. Pick a range clear of it:

```toml
[turn.relay]
min_port = 20000
max_port = 30000
```

`scripts/verify/deployment-compliance.sh` checks this against the host's actual
range, so it is worth running rather than reasoning about.

## NUMA

**Check before doing anything:**

```sh
lscpu | grep -i numa
```

The Threadripper 1950X reports **one node** despite being a two-die part, so
nothing below applied to it and the measurement carries no NUMA penalty. That was
worth checking rather than assuming — a plan to pin across nodes on a
single-node machine is effort spent on nothing.

On a genuinely multi-node host:

**Keep the datapath on one node.** A relay's work is per-packet and touches the
allocation store constantly. Threads on one node and memory on another turns
every lookup into a cross-socket read.

```sh
numactl --cpunodebind=0 --membind=0 turna-node /etc/turna/turn.toml
```

**Do not split workers across nodes to "use the whole machine".** Two nodes at
half capacity each, with the store shared between them, is slower than one node
at full capacity. If a single node cannot carry the load, run two turna processes
with separate port ranges and let the layer above choose, rather than one process
straddling the interconnect.

**Bind the NIC's interrupts to the same node as the process.** A packet arriving
on a node the process is not on is copied across the interconnect before anything
looks at it.

```sh
cat /sys/class/net/eth0/device/numa_node
```

## IRQ, RSS and RPS

None of this was exercised here: the measurement ran over loopback, which has no
interrupts, no driver and no queues. Treat what follows as the standard advice it
is, not as something this project has verified.

**RSS queue count.** Match it to the cores the relay runs on, not to the whole
machine:

```sh
ethtool -l eth0            # look at "Combined"
ethtool -L eth0 combined 16
```

**IRQ affinity.** Spread the queues' interrupts across the relay's cores. `irqbalance`
usually does this adequately; the case to override it is a machine also running
something latency-sensitive that should not share cores with the relay.

**RPS only when RSS is unavailable.** RPS distributes in software, which costs
CPU the relay wants. On a NIC with working RSS it is a downgrade.

## Socket and kernel settings

**Receive buffers.** A relay bursts. The default socket buffer is small enough
that a burst is dropped in the kernel, before turna sees it — which appears in
`turna_packets_received` as packets that never arrived and in no error counter
anywhere.

```sh
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.rmem_default=1048576
```

**Conntrack, if a stateful firewall is in the path.** Sized for *flows*, not
clients: each relayed session is at least two. A node at 10 000 sessions wants
`nf_conntrack_max` well above 20 000, and the failure when it is short is packet
loss indistinguishable from capacity exhaustion.

```sh
sysctl -w net.netfilter.nf_conntrack_max=262144
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=180
```

The UDP timeout matters more than it looks. The default 120 s can be shorter than
a client's refresh interval, and a dropped flow between refreshes shows up as a
glitch the user notices and no counter records.

**File descriptors.** One per relay socket, plus the listeners.

```sh
ulimit -n              # 1024 is the usual default and is not enough
```

A node hitting the limit fails allocations with no obvious cause. `ulimit -n` is
in the support bundle's `host.txt` for exactly this reason.

## io_uring and AF_XDP

**io_uring** is verified on kernels 6.8 and 6.14 — 9.6 hours at 0.006 % loss. It
is kernel-version-sensitive by nature, so that is evidence about those two
kernels and not a general claim. A slot leak here made a worker go deaf after
exactly 64 packets while its control plane ran at 10 800 allocations/second; if
throughput drops to nothing on one worker while others are fine, that is the
shape to look for.

**AF_XDP** works on a veth lab in SKB mode. That copies every frame and therefore
demonstrates correctness, **not performance** — do not read the AF_XDP results as
a capacity figure. Five configuration keys in that section are refused at startup
because the UMEM is built with library defaults and they would otherwise be
accepted and ignored.

Neither is the default. `transport = "tokio"` needs no kernel features and is what
the 112 000 figure was measured on.

## Verifying rather than tuning

The honest order of operations:

1. **Measure first.** `scripts/verify/capacity-profile.sh` on the actual hardware.
   Every number above is from a different machine than yours.
2. **Fix the port range.** It is the one setting here that causes a correctness
   failure rather than a performance one.
3. **Change one thing at a time and re-measure.** The profiler's bisection
   resolves to about 12 % of the true edge, so a change smaller than that is not
   distinguishable from noise by this method — and `capacity-regression.sh` uses a
   10 % tolerance for the same reason.
4. **Watch `turna_send_queue_dropped_total`** throughout. It is the counter that
   catches a tuning change which improved the client-visible number by dropping
   frames earlier.

Most tuning changes will move the ceiling by less than the measurement can
resolve. That is not a reason to skip step 1 — it is the reason step 1 comes
first, so that a change can be shown to have done nothing rather than assumed to
have helped.
