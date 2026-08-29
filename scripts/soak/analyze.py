#!/usr/bin/env python3
"""Analyse a soak run and give a verdict per signal.

Deliberately not one green light. "The node did not crash", "the node did not
leak" and "no errors occurred" are three different claims, and a soak that
collapses them into one PASS is how a leak ships.

Every threshold below is stated, with the reasoning, so a reader can disagree with
a specific number instead of distrusting the whole result. Exit code is non-zero if
any signal FAILs, so this can gate CI.
"""

import csv
import os
import sys

# ── thresholds, with reasoning ───────────────────────────────────────────────

# Long runs (>=30 h) additionally get a per-day breakdown. Halves are a good test
# over 24 h and a poor one over 72: a leak starting at hour 40 has its
# second-half minimum taken from the flat part at hour 36, and a 2 %/day leak is
# 6 % over three days — under any sane threshold, and obvious as three rising
# points. The halves verdict is kept unchanged so the archive of 24 h results
# stays comparable.
#
# RSS: compared between the *idle* floor early on and the idle floor at the end,
# never peaks. A relay under load legitimately grows; what matters is whether it
# gives the memory back. 15% allows for allocator fragmentation and jemalloc-style
# retention over six hours; a real leak in this codebase would be driven by
# per-allocation state and would run far past this.
RSS_GROWTH_PCT = 15.0

# File descriptors: relay sockets are one fd each, so a genuine leak is visible in
# whole numbers. A small drift is normal (log rotation, reconnects to the state
# backend), so this is absolute rather than proportional.
FD_GROWTH_ABS = 64

# Allocation floor: judged by TREND, not height.
#
# An earlier version failed any run whose idle floor exceeded 5, which was wrong: the
# load client asks for a 600 s allocation lifetime, so anything created during a load
# phase is still alive through a shorter idle window. A floor of 694 after 2M
# allocations is TTL steady state, not retention — RSS and fds were flat in the same
# run, which a real leak could not manage. What matters is whether the floor CLIMBS
# between the early and late idle windows.
ALLOC_FLOOR_GROWTH_PCT = 50.0
ALLOC_FLOOR_GROWTH_ABS = 50

# Thread count should be flat after startup. A per-connection task leak shows here
# before it shows in RSS.
THREAD_GROWTH_ABS = 8

# Counters that must not move during steady state. Any movement is a finding to
# explain, not necessarily a failure — hence WARN, except for panics.
ERROR_COUNTERS = [
    "turna_send_queue_dropped_total",
    "turna_malformed_packets_total",
    "turna_parser_rejections_total",
    "turna_tls_accept_errors_total",
    "turna_tls_framing_errors_total",
    "turna_tls_cert_reload_failures_total",
]

# A panic is never acceptable, however brief.
FATAL_COUNTERS = ["turna_processor_panics_total"]

# Readiness: 1 = ready. 2 = degraded means a listener died while the process kept
# running, which /ready may not reflect — that is precisely why these gauges exist.
READINESS_GAUGES = ["turna_transport_readiness", "turna_backend_readiness", "turna_tls_readiness"]

results = []


def report(level, signal, detail):
    results.append((level, signal, detail))


def num(row, key):
    v = row.get(key, "")
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


# Runs longer than this get the per-day treatment. 30 h rather than 24 because a
# run of exactly one day yields two buckets, and two buckets is the halves
# comparison with extra steps.
LONG_RUN_HOURS = 30

# A metric that rises in every bucket is a leak even when the total sits under the
# threshold.
#
# The test is "rose in every bucket", not a fixed count. A fixed three was the
# first attempt and was unreachable: three days give three buckets and therefore
# at most two rises, so the threshold could never trip on the run length it was
# written for. Found by feeding synthetic data through it rather than by waiting
# 72 hours to see.
#
# Needs at least three buckets, because two buckets rising is the halves
# comparison and is already covered by the growth threshold.
MONOTONE_MIN_BUCKETS = 3


def per_day_floors(samples, key, t0):
    """Minimum of `key` per 24-hour bucket.

    Returns [(day_index, floor)], skipping buckets with no samples rather than
    reporting them as zero — an absent bucket means the collector stopped, which
    is a different problem from a floor of nothing and must not read as one.
    """
    buckets = {}
    for r in samples:
        try:
            t = float(r.get("t", 0))
            v = float(r.get(key, 0))
        except (TypeError, ValueError):
            continue
        if v <= 0:
            continue
        day = int((t - t0) // 86400)
        buckets.setdefault(day, []).append(v)
    return [(d, min(vs)) for d, vs in sorted(buckets.items())]


def monotone_rise(floors):
    """Longest run of consecutive increases in the floors."""
    best = run = 0
    for (_, a), (_, b) in zip(floors, floors[1:]):
        if b > a:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def series(rows, key):
    return [(r, num(r, key)) for r in rows if num(r, key) is not None]


def main(out_dir):
    path = os.path.join(out_dir, "samples.csv")
    if not os.path.exists(path):
        print(f"FATAL: {path} not found")
        return 2
    with open(path) as f:
        rows = list(csv.DictReader(f))
    if len(rows) < 10:
        print(f"FATAL: only {len(rows)} samples — too few to say anything")
        return 2

    dur = num(rows[-1], "elapsed") or 0
    print(f"soak analysis: {len(rows)} samples over {dur / 3600:.2f}h\n")

    # A sample taken before the first load phase is not a baseline for anything;
    # the first idle floor AFTER load has run is. Fall back to early samples only
    # if no cycle completed.
    idle = [r for r in rows if r.get("phase") in ("idle", "settle")]
    load = [r for r in rows if r.get("phase") == "load"]

    if not load:
        report("FAIL", "load", "no load phase recorded — TURNA_LOAD_CMD produced nothing, so this run measures an idle process")
    if len(idle) < 4:
        report("WARN", "idle windows", f"only {len(idle)} idle samples; leak detection needs the idle floors")

    # ── long runs: per day ──
    #
    # Reported before the halves comparison rather than instead of it, so a long
    # run gets both readings. The halves number is what the archive is full of and
    # dropping it would make a 72 h result incomparable with every 24 h one.
    long_run = dur >= LONG_RUN_HOURS * 3600
    if long_run and idle:
        t0 = min(float(r.get("t", 0)) for r in idle)
        print(f"  run is {dur/3600:.1f}h — per-day floors as well as halves\n")
        for key, unit, scale in (("rss_kb", "MiB", 1024), ("fds", "fds", 1)):
            floors = per_day_floors(idle, key, t0)
            if len(floors) < 2:
                continue
            shown = ", ".join(
                f"d{d}: {v/scale:.0f}" for d, v in floors
            )
            print(f"  {key} idle floor by day — {shown} {unit}")
            rise = monotone_rise(floors)
            possible = len(floors) - 1
            first, last = floors[0][1], floors[-1][1]
            total = (last - first) / first * 100 if first else 0
            if len(floors) >= MONOTONE_MIN_BUCKETS and rise == possible:
                report(
                    "FAIL",
                    f"{key} trend",
                    f"rose in every one of {possible} day-to-day steps "
                    f"({total:+.1f}% overall). A metric that grows every single day "
                    f"is a leak whatever the total says, and this is what a halves "
                    f"comparison cannot see.",
                )
            elif rise > 0:
                report(
                    "PASS",
                    f"{key} trend",
                    f"{rise} of {possible} steps rose, {total:+.1f}% overall — "
                    f"not monotone",
                )
            else:
                report("PASS", f"{key} trend", f"no rise between days, {total:+.1f}% overall")

            # Stated because it is the case this test is weakest on: a leak that
            # begins in the final bucket produces one rise out of two and passes.
            # It needs either a longer run or the halves comparison below, which
            # sees it when the second half is mostly leaking.
            if rise > 0 and rise < possible and rise == 1 and possible == 2:
                print(
                    f"    note: the single rise is in the last day. A leak starting "
                    f"late looks like this and would pass — a longer run would "
                    f"separate them."
                )
        print()

    # ── RSS ──
    rss = series(idle, "rss_kb")
    if len(rss) >= 4:
        half = len(rss) // 2
        early = min(v for _, v in rss[:half])
        late = min(v for _, v in rss[half:])
        growth = (late - early) / early * 100 if early else 0
        detail = f"idle floor {early/1024:.0f} MiB -> {late/1024:.0f} MiB ({growth:+.1f}%)"
        if growth > RSS_GROWTH_PCT:
            report("FAIL", "RSS", f"{detail}; over the {RSS_GROWTH_PCT}% threshold — this is the leak signal")
        else:
            report("PASS", "RSS", detail)
        peak = max(v for _, v in series(rows, "rss_kb"))
        print(f"  (peak RSS under load: {peak/1024:.0f} MiB)")
    else:
        report("WARN", "RSS", "not enough idle samples to compare floors")

    # ── fds ──
    fds = series(idle, "fds")
    if len(fds) >= 4:
        half = len(fds) // 2
        early = min(v for _, v in fds[:half])
        late = min(v for _, v in fds[half:])
        detail = f"idle floor {early:.0f} -> {late:.0f} fds"
        if late - early > FD_GROWTH_ABS:
            report("FAIL", "file descriptors", f"{detail}; +{late-early:.0f} is a socket leak, one fd per unreleased relay socket")
        else:
            report("PASS", "file descriptors", detail)
    else:
        report("WARN", "file descriptors", "not enough idle samples")

    # ── threads ──
    thr = series(rows, "threads")
    if thr:
        early = thr[min(4, len(thr) - 1)][1]
        late = max(v for _, v in thr[len(thr) // 2:])
        detail = f"{early:.0f} -> {late:.0f} threads"
        if late - early > THREAD_GROWTH_ABS:
            report("FAIL", "threads", f"{detail}; a task-per-connection leak surfaces here before RSS")
        else:
            report("PASS", "threads", detail)

    # ── allocation floor ──
    alloc = series(idle, "turna_active_allocations")
    total = num(rows[-1], "turna_total_allocations")
    if len(alloc) >= 4:
        half = len(alloc) // 2
        early = min(v for _, v in alloc[:half])
        late = min(v for _, v in alloc[half:])
        detail = f"idle floor {early:.0f} -> {late:.0f} active"
        if total is not None:
            detail += f", {total:.0f} allocations churned"
        grew = late - early
        pct = (grew / early * 100) if early > 0 else (100.0 if late > ALLOC_FLOOR_GROWTH_ABS else 0.0)
        if grew > ALLOC_FLOOR_GROWTH_ABS and pct > ALLOC_FLOOR_GROWTH_PCT:
            report("FAIL", "allocation release",
                   f"{detail}; the floor is climbing, which is the shape of allocations"
                   " not being released. Cross-check RSS and fds — a real leak moves"
                   " them too.")
        else:
            report("PASS", "allocation release",
                   f"{detail}; floor stable, i.e. TTL steady state rather than"
                   " retention. The client requests a 600 s lifetime, so a shorter"
                   " idle window cannot drain it and height alone means nothing.")
    elif alloc:
        report("WARN", "allocation release",
               "too few idle samples to judge the trend, and height alone says nothing"
               " while the client's 600 s allocation lifetime outlasts the idle window")
    # A soak over no real load reports no leaks and looks like a pass — the most
    # misleading outcome available, so it fails rather than warns. It has happened: a
    # per-IP rate limit refused nearly everything, the load tool spun on the refusals,
    # and both backends recorded millions of errors, a few dozen successes, and a clean
    # verdict.
    #
    # But allocations alone are the wrong yardstick. A media phase holds a handful of
    # long-lived sessions and pushes tens of thousands of packets through them: 10
    # concurrent sessions produce 10 allocations and 24 000 relayed frames, which this
    # check called "not a load run". Churn phases are the opposite. So the volume is
    # whichever is larger — allocations, or packets actually relayed.
    packets = None
    ser = series(rows, "turna_packets_received")
    if ser:
        packets = ser[-1][1] - ser[0][1]
    if dur > 0 and (total is not None or packets is not None):
        alloc_n = total or 0
        pkt_n = packets or 0
        if alloc_n < 100 and pkt_n < 10_000:
            report("FAIL", "load volume",
                   f"only {alloc_n:.0f} allocations and {pkt_n:.0f} packets in"
                   f" {dur/3600:.2f}h — this is not a load run. Check load-*.json for the"
                   " error count before reading anything else here as a pass.")
        elif alloc_n < 100 and pkt_n < 100_000:
            report("WARN", "load volume",
                   f"{alloc_n:.0f} allocations, {pkt_n:.0f} packets — thin for a soak;"
                   " confirm against load-*.json that attempts are succeeding.")
        else:
            report("PASS", "load volume",
                   f"{alloc_n:.0f} allocations, {pkt_n:.0f} packets over {dur/3600:.2f}h")

    # ── error counters ──
    for key in ERROR_COUNTERS + FATAL_COUNTERS:
        s = series(rows, key)
        if not s:
            report("SKIP", key, "series absent from /metrics (feature not compiled, or renamed)")
            continue
        first, last = s[0][1], s[-1][1]
        delta = last - first
        fatal = key in FATAL_COUNTERS
        if delta > 0:
            report("FAIL" if fatal else "WARN", key,
                   f"+{delta:.0f} during the run" + ("" if fatal else " — explain it before calling the soak clean"))
        else:
            report("PASS", key, "flat")

    # ── readiness ──
    for key in READINESS_GAUGES:
        s = series(rows, key)
        if not s:
            report("SKIP", key, "series absent")
            continue
        # Ignore the drain at the very end: 3 = draining is expected there.
        body = [v for _, v in s[:-2]] or [v for _, v in s]
        degraded = [v for v in body if v == 2]
        if degraded:
            report("FAIL", key, f"read 2 (degraded) in {len(degraded)} samples — a listener died while the process lived, and /ready may have stayed green")
        elif all(v == 1 for v in body):
            report("PASS", key, "ready throughout")
        elif all(v == 0 for v in body):
            # 0 = starting, and a disabled listener never leaves it. Reporting that
            # as a warning trains the reader to skim warnings, which is worse than
            # saying nothing. The exception is the primary transport gauge: that one
            # sitting at 0 through a run that carried traffic IS a finding, and is
            # exactly how the io_uring datapath's missing readiness call surfaced.
            if key == "turna_transport_readiness":
                report("FAIL", key, "stuck at 0 (starting) for the whole run while traffic flowed — nothing is setting this gauge on this datapath")
            else:
                report("SKIP", key, "0 throughout — this listener is not enabled in the soak config")
        else:
            report("WARN", key, f"values seen: {sorted(set(body))}")

    # ── load phases, read from the tool's own JSON ──
    #
    # This exists because a phase can fail completely and leave the metrics looking
    # merely quiet. A `channel-data` phase whose peer permissions were all refused
    # reported sent=0 recv=0 errs=0 for 370 s — the setup failed during `--warmup`,
    # which resets the counters, so the measurement window recorded a tidy nothing.
    # Nothing in samples.csv distinguishes that from an idle server.
    import glob
    import json as _json
    files = sorted(glob.glob(os.path.join(out_dir, "load-*.json")),
                   key=lambda p: int("".join(c for c in os.path.basename(p) if c.isdigit()) or 0))
    if not files:
        report("WARN", "load phases", "no load-*.json — the load tool produced no results at all")
    # The rotation starts a cycle whenever one is due, so the final one can begin with
    # less than a full window left and be cut off before it writes. That is inherent to
    # the schedule rather than a fault, and it is only benign for the LAST file — an
    # empty file anywhere else means a phase died mid-run, which is a real failure.
    last_name = os.path.basename(files[-1]) if files else None
    for path in files:
        name = os.path.basename(path)
        raw = open(path).read().strip()
        if not raw and name == last_name and len(files) > 1:
            report("WARN", "load phase " + name,
                   "empty — the final cycle was still running when the run ended, which"
                   " the rotation cannot avoid. The cycles before it carry the result.")
            continue
        if not raw:
            report("FAIL", "load phase " + name,
                   "empty file — the phase was still running when the soak ended, so"
                   " it never wrote results. Its wall-clock budget was wrong.")
            continue
        try:
            d = _json.loads(raw)
        except ValueError:
            report("FAIL", "load phase " + name, "truncated JSON — the phase was cut off mid-write")
            continue
        label = d.get("label", name)
        sent, recv, errs = d.get("sent", 0), d.get("recv", 0), d.get("errs", 0)
        if sent == 0 and recv == 0 and errs == 0:
            report("FAIL", "load phase " + label,
                   "sent=0 recv=0 errs=0 — the phase did nothing and did not even record"
                   " a failure. Setup errors during --warmup are wiped by the counter"
                   " reset, so check this phase's stderr log.")
        elif recv == 0:
            report("FAIL", "load phase " + label,
                   f"{sent} sent, nothing received ({errs} errors) — no request succeeded")
        elif errs > recv:
            report("WARN", "load phase " + label,
                   f"{recv} ok vs {errs} errors — more failures than successes;"
                   " read the error cause before treating this run as representative")
        else:
            # Loss and error rates are always stated, never folded into a bare PASS.
            # A phase that relayed a third of what it sent used to read as clean:
            # `recv > 0` and `errs == 0` were both true while two thirds of the traffic
            # went missing, because loss lives in its own field and nothing looked at
            # it.
            #
            # These stay WARN rather than FAIL on purpose. On a small host a saturated
            # CPU produces real loss that is not a defect, and a check that cannot tell
            # capacity from a fault should say so rather than pick one.
            sent_total = d.get("sent", 0)
            lost = d.get("loss", 0)
            loss_pct = (lost / sent_total * 100) if sent_total else 0.0
            err_pct = (errs / (recv + errs) * 100) if (recv + errs) else 0.0
            extra = ""
            if d.get("bytes_in", 0) > 0:
                extra = f", {d['bytes_in']/1e6:.0f} MB relayed back"
            detail = (f"{recv} ok, {errs} errors, {d.get('rps', 0):.0f} rps,"
                      f" p99 {d.get('lat_p99_us', 0)/1000:.0f} ms{extra}")
            if lost:
                detail += f", {loss_pct:.0f}% of sent never came back"
            if loss_pct > 20:
                # Check the arithmetic before blaming capacity. TURN bindings expire —
                # allocation and channel at 600 s, permission at 300 s — so a client
                # that does not refresh delivers only the first 600 s of any longer
                # phase. That produces a delivery ratio of 600/duration, identically on
                # every transport and at any rate, and it reads exactly like a capacity
                # cliff. It cost a 24 h run to work out.
                hint = (" — high loss. Capacity or a fault? Compare against a shorter"
                        " phase and a lower rate: loss that scales with the rate is"
                        " capacity; loss that scales with the phase *duration* is an"
                        " expired binding the client never refreshed.")
                dur_s = d.get("duration_s", 0)
                if dur_s > 600:
                    expected = 600.0 / dur_s * 100
                    delivered = 100 - loss_pct
                    if abs(delivered - expected) < 8:
                        hint = (f" — delivered {delivered:.0f}% of a {dur_s:.0f} s phase,"
                                f" and 600/{dur_s:.0f} = {expected:.0f}%. That match is"
                                " the signature of an expired allocation or channel"
                                " binding: TURN bindings last 600 s and the client is"
                                " not refreshing them. Not capacity.")
                report("WARN", "load phase " + label, detail + hint)
            elif err_pct > 10:
                report("WARN", "load phase " + label,
                       detail + f" — {err_pct:.0f}% of attempts errored")
            else:
                report("PASS", "load phase " + label, detail)

    # ── output ──
    print()
    order = {"FAIL": 0, "WARN": 1, "SKIP": 2, "PASS": 3}
    for level, signal, detail in sorted(results, key=lambda r: order[r[0]]):
        print(f"  {level:<5} {signal:<38} {detail}")

    fails = [r for r in results if r[0] == "FAIL"]
    warns = [r for r in results if r[0] == "WARN"]
    print()
    if fails:
        print(f"VERDICT: FAIL — {len(fails)} signal(s) failed, {len(warns)} warning(s).")
        print("Do not record this as a passing soak. Each FAIL above names what it means.")
        return 1
    if warns:
        print(f"VERDICT: PASS with {len(warns)} warning(s). Explain each warning in the")
        print("write-up; an unexplained warning is a finding you decided not to look at.")
        return 0
    print("VERDICT: PASS — no leak signal, no error counter movement, readiness stable.")
    print("This covers endurance only. It says nothing about interop or about the")
    print("wire-behaviour changes in this release (see docs/verification/interop-plan.md).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
