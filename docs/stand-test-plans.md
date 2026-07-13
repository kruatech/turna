# Turna — Stand Test Plans (#9 / #14 / #15)

Executable plans for the three remaining **stand** gates. These cannot be run from
source — they need real infrastructure. Each section is: prerequisites → procedure
→ what to measure → **pass/fail gate** → artifacts. Numeric thresholds are
operator policy derived from the #14 baseline and are marked `TODO(operator)`; they
are never invented here.

Maps to release gates: #9 → Gate C (environment), #14 → Gate D (capacity),
#15 → Gate E (HA semantics). See `operator-todo.md` and `slo-and-capacity.md`.

---

# #9 — Production networking validation (Gate C)

**Why it can't be code**: correctness depends on the actual public-IP model, CNI,
firewall, and routing — not on logic. Loopback tests prove nothing here.

## Recommended first-release model (simplest, provable)
- one dedicated public relay IP per TURN node;
- one node per host (hostNetwork + hostPort), enforced by the required
  pod anti-affinity (P0 #7);
- relay range `49152–65535` owned by that node;
- clients reach nodes via DNS or a list of TURN URIs;
- node failure ⇒ new allocations land on another node (no seamless move of an
  existing relay endpoint — that is #15, not #9).

## Prerequisites
- Real cluster on the production network (not minikube/loopback).
- `deploy-consistency` CI gate green (relay range identical across artifacts).
- External test client reachable from outside the cluster (v4 and v6 if v6 claimed).

## Procedure & per-check pass/fail
Run each from an **external** client. A check passes only if traffic actually flows
end-to-end (not just an Allocate success).

1. Allocate via external client → **pass**: relayed address is the node's public IP.
2. Peer traffic both directions → **pass**: bytes arrive both ways.
3. Relay range boundaries — allocate/relay on the **lowest**, a **mid**, and the
   **highest** port of `49152–65535` → **pass**: all three relay successfully
   (this is the RB-5 class — catches partial port publication).
4. IPv4 path → **pass**.
5. IPv6 path (only if IPv6 is claimed) → **pass** across the four family combos
   (defer to protocol-gap if IPv6 is still `partial`).
6. UDP client transport → **pass**.
7. TCP/TLS client transport → **pass**.
8. Two nodes serving simultaneously → **pass**: allocations distribute; each node's
   relay traffic uses its own public IP.
9. Pod rescheduled to another host → **pass**: new node serves new allocations;
   anti-affinity keeps one-per-host.
10. NetworkPolicy in place → **pass**: intended relay range reachable, nothing else.
11. Host firewall in place → **pass**: same.
12. Rolling restart → **pass**: no new-allocation outage window beyond drain.
13. Delete one node → **pass**: cluster keeps serving new allocations on survivors.
14. **Negative**: confirm a plain k8s `Service` does **not** route relay traffic to
    a random pod → **fail the gate** if relay packets reach the wrong pod (this is
    the classic clustered-TURN misroute).

## Artifacts (required to close)
Network diagram; Helm values used; firewall/NetworkPolicy rules; the exact IPs and
ranges; **raw packet capture** of one success and one failure case; a report naming
the precise infrastructure; known limitations.

## Gate C pass
All checks pass on real infra, boundary ports (check 3) and the misroute negative
(check 14) included, with artifacts recorded.

---

# #14 — Capacity / load qualification (Gate D)

**Tooling**: the load generator (methodology fixed in P0 #14 — `--warmup` then
`--duration`, honest `loss`, steady-state window). Run in steady state only.

## Profiles & commands
```
# Binding
turna-bench --warmup 10 --duration 60 --json binding    -c <C>
# Allocate lifecycle
turna-bench --warmup 10 --duration 60 --json allocate   -c <C>
# ChannelData relay
turna-bench --warmup 10 --duration 60 --json channeldata -n <N> --pps <P>
```

## Measure per profile
- **binding**: RPS, p50/p95/p99, CPU, RSS, loss, malformed/error rate, saturation.
- **allocate**: Allocate/Refresh/CreatePermission/ChannelBind RPS, remove/expiry
  rate, backend writes/s, write-behind queue depth, Tarantool latency,
  `tarantool_writes_dropped_total`, reconciliation activation, relay-port
  utilization (`available_ports`).
- **channeldata**: requested vs achieved PPS, sent/received/loss/dup/reorder,
  latency sample count + p50/p95/p99/p99.9/max, CPU, RSS, NIC throughput, queue drops.

## Load steps (each profile)
warmup → low → medium → planned peak → peak+reserve → saturation → recovery →
long steady-state (soak).

## Healthy-point gate (ALL must hold simultaneously)
- no sustained RSS growth;
- no fd leak;
- `tarantool_writes_dropped_total` rate == 0;
- reconciliation does **not** activate;
- loss ≤ `TODO(operator)` threshold;
- latency ≤ `TODO(operator)` threshold;
- `/ready` does not flap;
- backend queue does not grow unbounded;
- full recovery after load is removed.

A point failing **any** of these is not healthy.

## Required outputs (three distinct numbers — do not conflate)
- **physical ceiling** — architecture/port bound (e.g. ~16384 relay ports/node, or
  ~8192 under EVEN-PORT worst-case per the cap policy);
- **measured saturation point** — first sustained degradation;
- **operational limit** — production cap, set **below** the first bottleneck with
  headroom (ports, CPU, RAM, fd, backend throughput, NIC).

Never use the saturation point as the production limit. Feed the operational limit
back into `turn.toml`/Helm and `operator-todo.md` §B/§C.

## Gate D pass
Baseline recorded (hardware, config, commit, Tarantool topology, raw results per
`slo-and-capacity.md` §4); the three numbers established; operational limit set and
capacity-validated (`max_allocations ≤ usable_ports`, already enforced).

---

# #15 — Failover under active traffic (Gate E)

**Reality anchor**: the backend carries *state*, not live sockets. Ownership CAS
(#4) + reconciliation (#16) give state recovery; a UDP relay socket does not move,
and TCP relay is node-local. So the honest expected result today is **Level 1–2**,
not seamless (Level 3).

## Scenario
1. Node A owns an allocation.
2. Client creates a permission.
3. Client creates a channel binding.
4. Continuous bidirectional traffic flows through the allocation.
5. Every packet carries a sequence number.
6. Node A is killed **without graceful drain** (hard kill).
7. Cluster detects the failure.
8. Node B performs adoption (ownership CAS; old owner fenced).
9. Measure actual delivery on the relay path.
10. Client does **not** issue a new Allocate (only if testing seamless continuity).

## Measure
failure-detection time; ownership-adoption time; traffic-recovery time; total outage
duration; lost/duplicate/reordered packet counts; old-owner fencing confirmed;
permission state after adoption; channel-binding state after adoption; Refresh after
adoption; split-brain behaviour (two nodes must not both own).

## Result grading (declare exactly one — honestly)
- **Level 1 — state recovery**: backend ownership moved, state restored, new
  operations served by the new node. **May not** be called session continuity.
- **Level 2 — client-assisted recovery**: client does ICE restart / new Allocate /
  reconnect. May be called *cluster recovery*, **not** seamless failover.
- **Level 3 — active-session continuity**: the existing allocation keeps working
  with no new Allocate. Only then may "active-session failover" / "seamless failover"
  be used — and only if measured outage meets the agreed *seamless* definition.

## Gate E pass
Scenario executed on real infra; fencing proven (no split-brain); outage/loss
measured; the achieved **level explicitly declared** in docs; any "seamless" claim
backed by a measured outage number and a written definition.

---

# What is NOT in this document

- **`turna_proto_stun` conformance audit** (STUN 8489 attributes / integrity):
  needs the crate source — send it and it becomes a factual audit, per
  `protocol-gap.md`.
- **Numeric SLO/threshold values**: policy, set from the #14 baseline
  (`operator-todo.md` §C).
