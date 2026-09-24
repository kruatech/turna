# Benchmark results

Template only: fill this in after running `bench/matrix.sh` on dedicated,
prepared hardware (bench/PLAN.md). Do not use placeholder rows as a performance
claim, and never paste a `SMOKE=1` run.

## Run YYYY-MM-DD

**Hardware:** _e.g. AMD Ryzen 9 5950X, 32GB DDR4-3600, Linux 6.5,
network: loopback_

**Settings:** the `params` block of `meta.json` (or: "defaults except …")
- turna commit: `<git-sha>` (from `meta.json`; must not be a dirty tree)
- coturn: `<image digest or package version, from meta.json>`
- host tuning applied: `<per bench/PLAN.md, or what differed>`

**Results:** paste `summary.md` from `bench/results/matrix-<timestamp>/`
(memory per allocation, binding, allocate, relay per payload — each with server
CPU %), and attach or link `results.csv` / `results.json`.

**Observations / notes:**

- _Anything unexpected? Anomalies? Tunings applied?_

---

(Replicate the block above for each significant re-run — different
hardware, different commit, different methodology.)
