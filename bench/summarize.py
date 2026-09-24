#!/usr/bin/env python3
"""Aggregate one bench/matrix.sh results directory.

Reads every ``<server>__<scenario>__r<N>.json`` (turna-load-test ``--json``
output) plus ``meta.json`` and writes, next to them:

* ``results.json`` — ``{"meta": ..., "runs": [...], "summary": [...], "failures": [...]}``
* ``results.csv``  — the summary, one row per server x scenario
* ``summary.md``   — the summary as Markdown tables (also printed)

Every summary value is the **median** across repeats. Runs that failed were
renamed ``*.json.failed`` by matrix.sh and are not read; the ``runs`` column
says how many repeats a median is over, so a row built from one surviving
repeat out of five is visible as such. Runs that produced nothing at all — a
server that did not start, a load generator that exited non-zero, a server
that was not available — are listed by matrix.sh in ``failures.tsv``; a
server x scenario with no surviving run gets a row with ``status`` FAILED (or
SKIPPED) instead of silently vanishing from the tables.

Standard library only, so it runs wherever matrix.sh does.
"""

import csv
import glob
import json
import os
import statistics as st
import sys
from collections import defaultdict

CSV_FIELDS = [
    "server", "scenario", "status", "runs",
    # binding / allocate / relay
    "rate_per_s", "lat_p50_us", "lat_p99_us", "errs",
    # relay
    "sent_pps", "delivered_pps", "mbit_s", "loss_pct",
    # every load scenario, from --server-pid
    "server_cpu_pct",
    # memory
    "allocations_held", "rss_kb_before", "rss_kb_held", "rss_kb_released",
    "rss_bytes_per_allocation",
]


def med(values):
    vals = [v for v in values if v is not None]
    return st.median(vals) if vals else None


def load_runs(rd):
    runs = []
    for f in sorted(glob.glob(os.path.join(rd, "*__*__r*.json"))):
        base = os.path.basename(f)[: -len(".json")]
        try:
            srv, scen, rep = base.split("__")
            data = json.load(open(f))
        except (ValueError, OSError) as e:
            print(f"WARN: {f}: {e}", file=sys.stderr)
            continue
        data.update({"server": srv, "scenario": scen, "repeat": int(rep.lstrip("r"))})
        runs.append(data)
    return runs


def load_failures(rd):
    path = os.path.join(rd, "failures.tsv")
    out = []
    if os.path.exists(path):
        for line in open(path):
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 4:
                out.append(dict(zip(("server", "scenario", "repeat", "reason"), parts)))
    return out


def scenario_key(scen):
    """memory, binding, allocate, then relay sections by payload size as a
    number — "relay-1200" sorts after "relay-160" as text, not as bytes."""
    fixed = {"memory": 0, "binding": 1, "allocate": 2}
    if scen in fixed:
        return (fixed[scen], 0, scen)
    if scen.startswith("relay-") and scen[len("relay-"):].isdigit():
        return (3, int(scen[len("relay-"):]), scen)
    return (4, 0, scen)


def relay_metrics(r):
    """Per-run relay figures. bytes_in is what reached the peer socket, i.e.
    the relayed UDP payload — ChannelData framing is stripped by the relay."""
    d = r.get("duration_s") or 0
    sent, recv = r.get("sent", 0), r.get("recv", 0)
    return {
        "sent_pps": sent / d if d else None,
        "delivered_pps": recv / d if d else None,
        "mbit_s": r.get("bytes_in", 0) * 8 / d / 1e6 if d else None,
        "loss_pct": max(sent - recv, 0) / sent * 100 if sent else None,
    }


def summarize(runs, failures=()):
    groups = defaultdict(list)
    for r in runs:
        groups[(r["server"], r["scenario"])].append(r)
    rows = []
    for (srv, scen), rs in sorted(groups.items(), key=lambda kv: (scenario_key(kv[0][1]), kv[0][0])):
        row = {k: None for k in CSV_FIELDS}
        row.update(server=srv, scenario=scen, status="ok", runs=len(rs))
        if scen == "memory":
            row.update(
                allocations_held=med([r.get("established") for r in rs]),
                rss_kb_before=med([r.get("rss_kb_before") for r in rs]),
                rss_kb_held=med([r.get("rss_kb_held") for r in rs]),
                rss_kb_released=med([r.get("rss_kb_released") for r in rs]),
                rss_bytes_per_allocation=med([r.get("rss_bytes_per_allocation") for r in rs]),
                errs=med([r.get("errs") for r in rs]),
            )
        else:
            row.update(
                rate_per_s=med([r.get("rps") for r in rs]),
                lat_p50_us=med([r.get("lat_p50_us") for r in rs]),
                lat_p99_us=med([r.get("lat_p99_us") for r in rs]),
                errs=med([r.get("errs") for r in rs]),
                server_cpu_pct=med([r.get("server_cpu_pct") for r in rs]),
            )
            if scen.startswith("relay-"):
                per = [relay_metrics(r) for r in rs]
                for k in ("sent_pps", "delivered_pps", "mbit_s", "loss_pct"):
                    row[k] = med([p[k] for p in per])
        rows.append(row)
    # A server x scenario that failed every time has no run to summarise; give it
    # a row anyway, so a missing server reads as FAILED rather than as absent.
    have = {(r["server"], r["scenario"]) for r in rows}
    for f in failures:
        key = (f["server"], f["scenario"])
        if key in have:
            continue
        have.add(key)
        row = {k: None for k in CSV_FIELDS}
        if f["reason"].startswith("skipped: "):
            status = "SKIPPED: " + f["reason"][len("skipped: "):]
        else:
            status = "FAILED: " + f["reason"]
        row.update(server=f["server"], scenario=f["scenario"], runs=0, status=status)
        rows.append(row)
    return rows


def fmt(v, nd=0):
    if v is None:
        return "n/a"
    return f"{v:.{nd}f}"


def markdown(rows, meta, rd, failures=()):
    by_scen = defaultdict(list)
    for row in rows:
        if row["status"] == "ok":
            by_scen[row["scenario"]].append(row)
    out = [f"# Benchmark matrix — {os.path.basename(rd)}", ""]
    if meta.get("smoke"):
        out += ["**SMOKE RUN — harness self-test, not a measurement. Do not publish.**", ""]
    v, h, p = meta.get("versions", {}), meta.get("host", {}), meta.get("params", {})
    out += [
        f"turna `{v.get('turna_commit', '?')}`"
        + (" (dirty tree)" if v.get("turna_tree_dirty") else "")
        + f" · coturn {v.get('coturn', '?')} · kernel {h.get('kernel', '?')} · "
        f"{h.get('cpu_model', '?')} ({h.get('nproc', '?')} CPUs)",
        "",
        f"Medians over up to {p.get('repeats', '?')} repeats; {p.get('duration_s', '?')} s "
        f"measured after {p.get('warmup_s', '?')} s warm-up. Server CPU is percent of one "
        "core over the measured window. Raw per-run JSON, `results.json` and "
        "`results.csv` are in this directory.",
        "",
    ]
    for scen in sorted(by_scen, key=scenario_key):
        rs = by_scen[scen]
        if scen == "memory":
            out += ["## Memory per active allocation (one permission + one channel each)", "",
                    "| Server | Held | RSS before (MiB) | RSS held (MiB) | Bytes / allocation | RSS after release (MiB) | Errors | Runs |",
                    "|---|---:|---:|---:|---:|---:|---:|---:|"]
            for r in rs:
                mib = lambda kb: fmt(kb / 1024, 1) if kb is not None else "n/a"
                out.append(f"| {r['server']} | {fmt(r['allocations_held'])} | {mib(r['rss_kb_before'])} "
                           f"| {mib(r['rss_kb_held'])} | {fmt(r['rss_bytes_per_allocation'])} "
                           f"| {mib(r['rss_kb_released'])} | {fmt(r['errs'])} | {r['runs']} |")
        elif scen.startswith("relay-"):
            out += [f"## ChannelData relay, {scen[len('relay-'):]} B payload "
                    f"({p.get('relay_channels', '?')} allocations × {p.get('relay_pps_per_channel', '?')} pps)", "",
                    "| Server | Sent pps | Delivered pps | Mbit/s out of relay | Loss % | p50 (µs) | p99 (µs) | Server CPU % | Runs |",
                    "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
            for r in rs:
                out.append(f"| {r['server']} | {fmt(r['sent_pps'])} | {fmt(r['delivered_pps'])} "
                           f"| {fmt(r['mbit_s'], 1)} | {fmt(r['loss_pct'], 2)} | {fmt(r['lat_p50_us'])} "
                           f"| {fmt(r['lat_p99_us'])} | {fmt(r['server_cpu_pct'], 1)} | {r['runs']} |")
        else:
            unit = "Allocations/s (401 → Allocate → Refresh 0)" if scen == "allocate" else "Binding RPS"
            out += [f"## {scen}", "",
                    f"| Server | {unit} | p50 (µs) | p99 (µs) | Errors | Server CPU % | Runs |",
                    "|---|---:|---:|---:|---:|---:|---:|"]
            for r in rs:
                out.append(f"| {r['server']} | {fmt(r['rate_per_s'])} | {fmt(r['lat_p50_us'])} "
                           f"| {fmt(r['lat_p99_us'])} | {fmt(r['errs'])} "
                           f"| {fmt(r['server_cpu_pct'], 1)} | {r['runs']} |")
        out.append("")
    if failures:
        out += ["## FAILED / skipped runs", "",
                "Excluded from every median above. A row here with no matching table row "
                "means that server has no result for that scenario at all.", "",
                "| Server | Scenario | Repeat | Reason |", "|---|---|---|---|"]
        for f in failures:
            out.append(f"| {f['server']} | {f['scenario']} | {f['repeat']} | {f['reason']} |")
        out.append("")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: summarize.py <results-dir>")
    rd = sys.argv[1]
    meta_path = os.path.join(rd, "meta.json")
    meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    runs = load_runs(rd)
    failures = load_failures(rd)
    rows = summarize(runs, failures)
    json.dump({"meta": meta, "runs": runs, "summary": rows, "failures": failures},
              open(os.path.join(rd, "results.json"), "w"), indent=2)
    with open(os.path.join(rd, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow({k: ("" if v is None else v) for k, v in row.items()})
    md = markdown(rows, meta, rd, failures)
    open(os.path.join(rd, "summary.md"), "w").write(md)
    print(md)


if __name__ == "__main__":
    main()
