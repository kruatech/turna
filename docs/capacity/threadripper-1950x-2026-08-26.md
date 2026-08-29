# Capacity profile — Threadripper 1950X, 2026-08-26

**112 000 relayed packets/second**, sustained 120 s, zero loss, zero egress-queue
drops. The first measured ceiling this project has on real hardware.

| | |
|---|---|
| CPU | AMD Ryzen Threadripper 1950X, 32 threads, one NUMA node |
| memory | 126 GB |
| kernel | 6.14.0-33-generic |
| transport | UDP over loopback, tokio datapath |
| shape | 50 channels, 200 B payload, sources spread over 64 addresses |
| cores | server 0–15, generator 16–31 |
| loss limit | 0.1 % |

## The curve

Clean to the edge, then abrupt:

| pps | loss | egress drops |
|---|---|---|
| 500 – 64 000 | 0 % | 0 |
| 96 000 | 0 % | 0 |
| **112 000** | **0 %** | **0** |
| 120 000 | fail | — |
| 128 000 | 5.84 % | 1 095 160 |

Nothing degrades gradually. Every rate up to 112 000 relays every frame; 7 %
above it, the egress queue starts shedding and a million frames go in two
minutes. That matters more for operations than the number does: **there is no
warning band.** A node at 110 000 looks perfectly healthy and is one traffic
bump from losing 6 % of media.

Which is the argument for admission control that acts on a fraction of this,
not on this.

## What this number is not

**Not network throughput.** Generator on the same host over loopback: no NIC, no
driver, no interrupts, no MTU. A real interface adds all of those and they are
usually what binds first. This is an upper bound on the software path.

**Not independent of the generator.** Cores were split, but both processes share
memory bandwidth and the loopback path. A second machine across a real link
would give a lower and more useful figure.

**One point in a space.** 200-byte frames across 50 channels. Small frames cost
more per byte in per-packet work; many channels cost more in permission and
channel-binding state.

**The 0.1 % limit is a judgement**, recorded so it can be disagreed with: media
absorbs one lost frame in a thousand, and demanding zero would report a ceiling
well below what the host can usefully do.

## Three wrong numbers before this one

Worth recording, because each was produced by the same measurement and looked
just as publishable.

**"Nothing passed at 10 pps."** `run_phase` printed a progress line to stdout,
which its caller parsed as the result. Every verdict was garbage. Caught because
the claim was *impossible* on 32 threads — not because it was implausible.

**120 000.** Verdicts were judged on client-side loss alone. The server had
already been shedding frames the client never saw. Reading `send_queue_dropped`
per phase — and failing a phase that dropped any — brought it down.

**88 000.** The python block gained a sixth output field and three of four `read`
sites still expected five, so `verdict` became `PASS 0` and every comparison
against `PASS` failed. The run descended from rates that had passed and the
bisection converged on noise.

That third one is the same mistake as changing `compute_chain`'s signature
earlier in the day: **change an output format, forget a reader.** The compiler
caught it in Rust. Shell caught nothing and returned a number instead.

## The unit, and a correction

**112 000 is one-way traversals.** `channel-data` mode sends client -> relay ->
peer and the receive task listens on the peer socket, so the relay handles each
frame once in and once out — the same work a real call's media costs.

A later reading of this document concluded the measurement counted *round trips*,
from `sent` and `recv` being within 30 of each other across 5.4 million frames.
That was wrong: the equality is exactly what a one-way path produces, since every
frame sent arrives. It sent me looking for a forwarding driver to settle an
uncertainty that did not exist, and it briefly doubled the hardware forecast — 26
nodes where 13 were needed.

**An equality consistent with two readings is evidence for neither.** Reading the
receive path took a minute.

## Using it

This is what `/capacity` has been missing. It reports `bytes_per_sec` and
`packets_per_sec` honestly but decides state on allocation counts alone, because
there was no figure to compare a rate against.

Do not use 112 000 as the threshold. Use a fraction of it — the curve above shows
why: at the ceiling there is no headroom for the retry storm that follows the
first hiccup, and the failure is a cliff rather than a slope.
