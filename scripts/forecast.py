#!/usr/bin/env python3
"""Forecast how much hardware a load needs, from what has actually been measured.

    scripts/forecast.py --sessions 5000
    scripts/forecast.py --sessions 25000 --codec video-720p --headroom 0.5
    scripts/forecast.py --pps 400000

§4's resource-forecasting item.

WHY THIS IS NOT A CALCULATOR WITH A NICE FORMULA

There is one measurement: 112 000 relayed packets/second on a 32-thread
Threadripper 1950X, over loopback, with the load generator on the same host.
Every number this prints is an extrapolation from that single point, and a single
point cannot tell you the shape of the curve.

So this tool does two things and refuses a third. It scales from the measurement
and says how. It states the assumptions inline so each one can be disagreed with.
It does **not** present a confidence interval, because there is no distribution
here to compute one from — a range printed with two decimal places would be more
misleading than the raw arithmetic.

THE ASSUMPTION THAT MATTERS MOST

Per-packet cost is assumed constant with load. That is the assumption most likely
to be wrong, and it is wrong in the dangerous direction: contention on the
allocation store grows with session count, so a forecast for 25 000 sessions from
a measurement at 50 channels probably **overestimates** what the hardware can do.

The measured curve gives one reason to think the error is not enormous — it was
flat from 500 to 112 000 pps with no degradation — and one reason to distrust
that: channel count was constant across those phases, so it tested packet rate
and not concurrency.

Treat the output as a starting point for a measurement, not as a substitute.
"""

import argparse
import sys

# ── the one real measurement ────────────────────────────────────────────────
BASELINE = {
    "machine": "AMD Ryzen Threadripper 1950X",
    "threads": 32,
    "relay_threads": 16,  # the profile pinned the server to cores 0-15
    "pps": 112_000,
    "payload_bytes": 200,
    "channels": 50,
    "source": "docs/capacity/threadripper-1950x-2026-08-26.md",
}

# ── codec profiles ──────────────────────────────────────────────────────────
#
# Packets per second per direction, per session. These are not measured here —
# they come from what WebRTC codecs typically emit, and a deployment with real
# traffic should replace them with its own numbers. Flagged in the output as
# assumed rather than measured, because the difference decides whether the answer
# is a forecast or a guess.
CODECS = {
    "audio-opus": {
        "pps": 50,  # 20 ms frames
        "bytes": 100,
        "note": "Opus at 20 ms. The cheapest realistic case.",
    },
    "video-360p": {
        "pps": 120,
        "bytes": 900,
        "note": "Assumes ~1 Mbps and MTU-sized packets.",
    },
    "video-720p": {
        "pps": 300,
        "bytes": 1100,
        "note": "Assumes ~2.5 Mbps. Keyframes burst well above this.",
    },
    "video-1080p": {
        "pps": 600,
        "bytes": 1200,
        "note": "Assumes ~5 Mbps. Bursts are what will bite, not the average.",
    },
    "mixed-call": {
        "pps": 170,
        "bytes": 800,
        "note": "One audio plus one 360p video stream — a typical 1:1 call.",
    },
}


def main() -> int:
    p = argparse.ArgumentParser(
        description="Forecast hardware for a relayed load, from measured data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--sessions", type=int, help="concurrent relayed sessions")
    p.add_argument("--pps", type=int, help="total relayed packets/second, if known")
    p.add_argument(
        "--codec",
        default="mixed-call",
        choices=sorted(CODECS),
        help="traffic profile per session (default: mixed-call)",
    )
    p.add_argument(
        "--headroom",
        type=float,
        default=0.6,
        help=(
            "fraction of the measured ceiling to plan for. Default 0.6 — the "
            "measured failure above the ceiling is a cliff, not a slope, so a node "
            "planned at 0.9 has nothing left for the retry storm that follows the "
            "first hiccup."
        ),
    )
    p.add_argument(
        "--traversal-factor",
        type=float,
        default=2.0,
        help=(
            "how many measured units one session-second of media costs. Default 2 "
            "and this is the number most likely to be wrong by a factor of two — "
            "see the note the tool prints. Set 1.0 for the optimistic reading."
        ),
    )
    args = p.parse_args()

    if not args.sessions and not args.pps:
        p.print_help()
        print("\nGive --sessions or --pps.", file=sys.stderr)
        return 2

    if not 0.1 <= args.headroom <= 1.0:
        print("--headroom must be between 0.1 and 1.0", file=sys.stderr)
        return 2

    codec = CODECS[args.codec]

    # ── the load ────────────────────────────────────────────────────────────
    if args.pps:
        total_pps = args.pps
        sessions = None
        basis = "given directly"
    else:
        sessions = args.sessions
        per_session = codec["pps"]
        # A relay receives and sends each packet, so a session's packet rate
        # counts twice against the node's ceiling. The 112 000 figure was measured
        # the same way, so the two are comparable — getting this wrong in either
        # direction halves or doubles the answer.
        total_pps = int(sessions * per_session * args.traversal_factor)
        basis = (
            f"{sessions} sessions x {per_session} pps x {args.traversal_factor:g} "
            "(traversal factor)"
        )

    usable = int(BASELINE["pps"] * args.headroom)
    nodes = -(-total_pps // usable)  # ceiling division

    bw_bps = total_pps * codec["bytes"] * 8

    # ── output ──────────────────────────────────────────────────────────────
    print(f"Forecast — {args.codec}")
    print("=" * 58)
    print()
    print(f"  load:            {total_pps:,} relayed pps  ({basis})")
    print(f"  bandwidth:       {bw_bps / 1e9:.2f} Gbps  (at {codec['bytes']} B/packet)")
    print()
    print(f"  measured ceiling: {BASELINE['pps']:,} pps on {BASELINE['machine']}")
    print(f"  planning at:      {usable:,} pps  ({args.headroom:.0%} of it)")
    print()
    print(f"  nodes needed:     {nodes}")
    if nodes > 1:
        print(f"  plus N+1:         {nodes + 1}  (one node's loss must be absorbable)")
    print()

    if sessions:
        per_node = sessions // nodes if nodes else sessions
        print(f"  sessions/node:    ~{per_node:,}")
        ports_needed = per_node * 2
        print(f"  relay ports/node: >={ports_needed:,}  (two per session, minimum)")
        if ports_needed > 16000:
            print(
                f"                    note: {ports_needed:,} ports is a wide range. "
                "Check it does not\n"
                "                    overlap the host's ephemeral range — "
                "cat /proc/sys/net/ipv4/ip_local_port_range"
            )
        print()

    # ── what this rests on ──────────────────────────────────────────────────
    print("Assumptions, each of which you can disagree with")
    print("-" * 58)
    print(f"  * {codec['note']}")
    print(
        f"  * {codec['pps']} pps and {codec['bytes']} B per stream are typical "
        "values, not\n    measured here. Replace them with your own if you have "
        "traffic to measure."
    )
    print(
        "  * Per-packet cost is constant with load. This is the assumption most\n"
        "    likely to be wrong, and it is wrong in the dangerous direction:\n"
        "    allocation-store contention grows with session count, so a forecast\n"
        "    for many sessions from a 50-channel measurement probably\n"
        "    OVERESTIMATES the hardware."
    )
    print(
        f"  * The ceiling is from {BASELINE['machine']} with {BASELINE['relay_threads']} "
        "cores for the\n    relay. Different hardware, different number — measure it "
        "with\n    scripts/verify/capacity-profile.sh rather than scaling by core count."
    )
    print(
        "  * It was measured over loopback with the generator on the same host.\n"
        "    A real NIC adds driver work, interrupts and an MTU, and those are\n"
        "    usually what binds first. So this is an upper bound."
    )
    print()

    print("The factor of two this cannot resolve")
    print("-" * 58)
    print(
        "  The measurement counted round trips. In the capacity profile `sent` and\n"
        "  `recv` were within 30 of each other over 5.4 million frames, which means\n"
        "  every frame the client sent came back: client -> relay -> peer -> relay ->\n"
        "  client. The node touched each frame four times.\n"
        "\n"
        "  A real call is not a round trip. A -> relay -> B is one traversal, and the\n"
        f"  node touches each frame twice. So {BASELINE['pps']:,} round trips per second\n"
        f"  might be worth about {BASELINE['pps'] * 2:,} one-way traversals — in which case\n"
        "  this forecast asks for twice the hardware it needs.\n"
        "\n"
        f"  --traversal-factor is 2.0 by default, the pessimistic reading. At 1.0 you\n"
        f"  would need {-(-total_pps // 2 // usable) if usable else 0} nodes instead of {nodes}.\n"
        "\n"
        "  Resolving this needs one measurement, not more arithmetic: run\n"
        "  capacity-profile.sh with a driver that forwards rather than echoes, and\n"
        "  compare. Until then the default errs toward buying too much, which is the\n"
        "  cheaper mistake."
    )
    print()
    print("What this deliberately does not print")
    print("-" * 58)
    print(
        "  A confidence interval. There is one measurement and no distribution to\n"
        "  compute one from. A range with decimal places would look like precision\n"
        "  this has none of."
    )
    print()
    print(f"Basis: {BASELINE['source']}")
    print()
    print("Next step is not more arithmetic. Run the profiler on the hardware you")
    print("intend to buy, then rerun this with that number in BASELINE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
