#!/usr/bin/env python3
"""Aggregate one bench/matrix.sh results directory.

Reads every ``<server>__<scenario>__r<N>.json`` (turna-load-test ``--json``
output) plus ``meta.json`` and writes, next to them:

* ``results.json`` — ``{"meta": ..., "runs": [...], "summary": [...]}``
* ``results.csv``  — the summary, one row per server x scenario
* ``summary.md``   — the summary as Markdown tables (also printed)

Every summary value is the **median** across repeats. Runs that failed were
renamed ``*.json.failed`` by matrix.sh and are not read; the ``runs`` column
says how many repeats a median is over, so a row built from one surviving
repeat out of five is visible as such.

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
    "server", "scenario", "runs",
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


def summarize(runs):
    groups = defaultdict(list)
    for r in runs:
        groups[(r["server"], r["scenario"])].append(r)
    rows = []
    for (srv, scen), rs in sorted(groups.items()):
        row = {k: None for k in CSV_FIELDS}
        row.update(server=srv, scenario=scen, runs=len(rs))
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
    return rows


def fmt(v, nd=0):
    if v is None:
        return "n/a"
    return f"{v:.{nd}f}"


def markdown(rows, meta, rd):
    by_scen = defaultdict(list)
    for row in rows:
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
    order = sorted(by_scen, key=lambda s: (s != "memory", s != "binding", s != "allocate", s))
    for scen in order:
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
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: summarize.py <results-dir>")
    rd = sys.argv[1]
    meta_path = os.path.join(rd, "meta.json")
    meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    runs = load_runs(rd)
    rows = summarize(runs)
    json.dump({"meta": meta, "runs": runs, "summary": rows},
              open(os.path.join(rd, "results.json"), "w"), indent=2)
    with open(os.path.join(rd, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow({k: ("" if v is None else v) for k, v in row.items()})
    md = markdown(rows, meta, rd)
    open(os.path.join(rd, "summary.md"), "w").write(md)
    print(md)


if __name__ == "__main__":
    main()
