# Turna — Operator TODO Tracker

Working checklist of everything left as `TODO(operator)` in the docs, plus items
flagged during P0 review. Each item says **what to decide**, **where it lives**, and
**how to determine it** (measure vs policy). Nothing here has an invented value —
that is the point of this list.

Legend: `[ ]` open · `[~]` in progress · `[x]` done
Type: **DEFECT** (must fix — wrong today) · **SIZING** (needs measurement) ·
**POLICY** (business/ops decision) · **RECORD** (write down a measured result)

---

## A. Config to reconcile

- [x] **DEFECT — per-node allocation cap exceeds relay-port ceiling. RESOLVED.**
  Per-node `max_allocations = 8192` — the conservative ceiling for the default
  relay range (49152–65535 = 16384 ports) under EVEN-PORT worst-case. Aligned in
  `deploy/turn.toml`, the Helm chart default (`values.yaml`), and the production
  example (`values-production.example.yaml`); documented in `slo-and-capacity.md`
  §1. Total capacity scales by node count (N × 8192), not by raising the cap or
  widening the range. `50000` remains only as the TCP-relay *connection* ceiling
  (`[turn.tcp_relay] max_total`) — a different resource, not UDP allocations.
  Config `validate()` rejects a cap above usable ports.

## B. Capacity sizing (determine by measurement — see §E)

- [ ] **SIZING — per-node allocation cap.** The intended concurrent-allocation limit
  (must be `≤` port ceiling from A). Source: `slo-and-capacity.md` §1,
  `operations-overview.md` §5.
- [ ] **SIZING — write-behind channel capacity / batch size.**
  `persistence.channel_capacity`, `batch_max_size`, `batch_max_delay` sized so
  `tarantool_writes_dropped_total` stays 0 at peak allocation churn.
  Source: runbook RB-1 (L64), RB-3 (L128).
- [ ] **SIZING — backend (Tarantool) throughput target.** Write ops/sec the backend
  must sustain at peak churn without drops. Source: runbook RB-3.
- [ ] **SIZING — quotas.** `[turn.relay.quota]` bandwidth/allocation limits per
  environment (incl. whether `allowUnlimitedBandwidth` is intended in prod).
  Source: `operations-overview.md` §5.

## C. SLO objectives (baseline + policy)

Define the objective values in the `slo-and-capacity.md` §3 table. SLIs are already
measurable; the numbers are yours.

- [ ] **POLICY — Node availability (Ready)** objective + window (e.g. %, 30d).
- [ ] **POLICY — Allocation success rate** objective + window.
- [ ] **POLICY — Relay delivery (1 − loss)** objective + window.
- [ ] **POLICY — Binding RTT p99** target (µs).
- [ ] **POLICY — Allocate handshake p99** target (µs).
- [ ] **POLICY — Relay one-way latency p99** target (µs).
- [ ] **POLICY — Error budget & alerting policy** derived from the above (paging on
  sustained Degraded, `tarantool_writes_dropped_total` rate > 0, success-rate
  breach, `available_ports` → 0). Source: `slo-and-capacity.md` §3.

## D. Operational policy

- [ ] **POLICY — On-call rotation & escalation.** Source: runbooks "Escalation"
  (L224), `operations-overview.md` §6 (L106).
- [ ] **POLICY — Dashboards.** Wire the exposed signals (`/ready`,
  `tarantool_writes_dropped_total`, active allocations, `available_ports`, latency
  histograms, `loss`) into dashboards.
- [ ] **POLICY — Alert thresholds** (e.g. "Degraded > N minutes pages"). Source:
  runbooks (L224), `operations-overview.md` §6.

## E. Baseline measurement (RECORD once measured)

- [ ] **RECORD — steady-state benchmark baseline.** Run the load generator with
  `--warmup` then `--duration` for `binding` / `allocate` / `channeldata`, ramp
  until a capacity dimension saturates, and record hardware + config + numbers in
  `slo-and-capacity.md` §4. Feeds B and C. Source: `slo-and-capacity.md` §4.

---

## F. Out of scope for these docs (separate work, not `TODO(operator)` placeholders)

Tracked here for visibility; these need a test stand, not doc edits. Executable
plans (procedure + pass/fail gates) live in `stand-test-plans.md`:

- [ ] #9 — networking model validation on a real cluster.
- [ ] #14 — execute the load runs (generator + honest methodology are done).
- [ ] #15 — failover under active traffic, end-to-end.
- [ ] P1/P2 — credential/secret rotation tests, tenant-isolation runs,
  backup/restore drill (procedure: runbook RB-8, incl. command-log + tenant-scoped
  consistency + unfinished-command policy).

---

### How to work this list
Fill values top-down: **A** (fix the defect) → **E** (measure baseline) → **B/C**
(size + set objectives from the baseline) → **D** (policy). A, B, C numbers should
land back in the referenced doc sections so the docs stop containing placeholders.

## GA implementation verification (open until executed)

The S4/S5 source implementation is present, but the following remain operator
release gates rather than assumed facts:

- run the exact workspace/all-feature/feature-matrix commands;
- exercise clean, legacy, interrupted, and resumed Tarantool migration;
- verify desired/observed restore and outage behavior;
- run concurrent user-cap and reservation rollback scenarios;
- build/run the admin image and validate token/retry/conflict behavior;
- render/validate the standalone Helm profile;
- run all live relay/update/restart/GC/drain scenarios on the exact release
  commit and record evidence.
