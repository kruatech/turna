# Why turna

turna is a **high-performance, abuse-resistant TURN relay for WebRTC** —
memory-safe by construction, secure by default, and built for cloud and
multi-tenant operation from day one.

It is **not** an attempt to reimplement every coturn flag and legacy mode.
coturn is mature, widely deployed, and good at being a Swiss-army TURN/STUN
server. turna instead targets the path that the large majority of WebRTC
deployments actually use — **TURN over UDP with long-term / REST
credentials** — and makes that path faster under load, cheaper to reject
garbage, safer by default, and observable enough to run as a product.

> Status legend used throughout: ✅ shipped · 🚧 in progress · 📋 planned.
> **Maintainers: set these markers to match the current code before publishing.**

---

## Where coturn falls short

coturn 4.11.0 (May 2026) is actively maintained, but its C/libevent2
codebase carries a recurring set of weaknesses. None of this means coturn
is "bad" — it means there is a well-defined gap a modern implementation can
own.

### 1. Peer-address filtering has been bypassed repeatedly
The single most persistent class of coturn CVEs is relaying to addresses
that should be blocked. CVE-2020-26262 covered `0.0.0.0`, `[::]`, `[::1]`;
six years later **CVE-2026-27624** (fixed only in 4.9.0, Feb 2026) showed
that IPv4-mapped IPv6 (`::ffff:127.0.0.1`) still bypassed `denied-peer-ip`
for IPv4 ranges, because address-normalization happened *after* the deny
check. The same 4.9.0 release also fixed an **inverted admin-password
check that accepted any wrong password since ~2019**, plus multiple buffer
overflows across the DB drivers, HTTP server, and STUN handling.

*Source: coturn release notes / Debian tracker / enablesecurity hardening guide.*

### 2. Throughput ceiling under packet flood
Operators report a hard pps wall with packet loss "no matter the server
size" (coturn issue #616). UDP fast paths exist (recvmmsg/sendmmsg/GSO on
Linux, libevent2 otherwise) but there is no kernel-bypass option and no
cheap pre-state-machine reject for malformed or flood traffic — every
packet still walks the session/auth path before it can be dropped.

### 3. Observability is not product-grade
Metrics exist but are partial and sometimes broken — e.g. issue #1560:
`process_cpu_seconds_total` is exported as a gauge stuck at 0. There are no
reason-coded drop counters, no auth-failure breakdown, no per-realm
accounting, and no processing-latency histograms.

### 4. Memory safety is a constant tax
Written in C, coturn has shipped repeated out-of-bounds reads and buffer
overflows. Each is fixable, but the architecture makes "no UB on malformed
input" something you hope for rather than something the compiler enforces.

### 5. No native clustering
Horizontal scaling is DNS SRV / ALTERNATE-SERVER / external load balancer.
There is no built-in control plane, no shared allocation state, no
shard-aware routing, and no cluster-wide observability. HA is something you
assemble around coturn, not something it gives you.

### 6. Secure configuration requires expertise
coturn is flexible, which means it is easy to assemble an insecure or
inefficient config. The existence of dedicated third-party "hardening
guides" is itself the signal: a default install is not a safe public
deployment.

### 7. Multi-tenancy is realms, not a SaaS primitive
coturn has realms, users, DB backends, and REST auth — enough to
authenticate, not enough to run a tenant business. No per-tenant
bandwidth/pps/allocation quotas, no per-tenant port pools, no billing
counters, no abuse auto-throttle as first-class concepts.

### 8. Kubernetes / cloud-native is painful
TURN maps poorly onto Kubernetes: UDP, large relay port ranges, the need
for a public IP, allocation affinity, and health checks that actually prove
a relay path works. Synapse's own docs warn that TURN behind NAT needs port
forwarding and frequently breaks even when configured.

### 9. Benchmarks are hard to trust
coturn is the universal baseline, but comparisons are apples-to-oranges:
different configs, relay paths, limits, transports, and port ranges. There
is no canonical reproducible suite.

---

## How turna answers

turna's scope is deliberately narrow and deep. The table below maps each
coturn gap to turna's design answer and its current status.

| coturn gap | turna's answer | Status |
|---|---|---|
| Peer-filter bypasses (§1) | Single peer-filter that **normalizes the address before the deny check** (unwraps `::ffff:`, special-cases `0.0.0.0`/`[::]`/`[::1]`); RFC 6890 special-use ranges (loopback, link-local, multicast, unspecified, cloud-metadata `169.254.169.254`) denied by default; property-tested | ✅ (`relay::peer_filter`, env opt-in for loopback; config-driven ranges 📋) |
| Throughput ceiling (§2) | eBPF socket pre-filter (real, `TURNA_BPF_FILTER=1`); GSO + batched recvmmsg/sendmmsg on the tokio datapath; experimental io_uring thread-per-core datapath; per-core sharding with `SO_REUSEPORT` + NUMA pinning; hugepages | 🚧 (eBPF pre-filter ✅; io_uring experimental; AF_XDP scaffolding only — see PRODUCTION_READINESS.md R2/R3) |
| Cheap garbage reject (§2) | **Reject malformed packets before rate-limit, and before allocation lookup**; BPF/XDP pre-filter; zero-copy ChannelData fast path that skips full STUN parse | ✅ (classifier + zero-copy verified; XDP pre-filter 🚧) |
| Flood resistance | **Per-IP + per-prefix (/24, /48) + per-method (Allocate/CreatePermission/ChannelBind) limiters** (`qos::TieredRateLimiter`); bounded, sharded token buckets | ✅ (per-IP/prefix/method shipped; per-tenant quotas 📋) |
| Observability (§3) | Prometheus-first metrics (incl. `turna_peer_rejected_total`, malformed/rate-limited/quota/parser counters); OpenTelemetry traces; allocation lifecycle events; per-reason `auth_fail_reason` breakdown and latency histograms | ✅ partial (Prometheus/OTel ✅; reason-coded auth `turna_auth_failures_by_reason_total` and STUN/relay/auth latency histograms now emitted — runtime-unverified) |
| Memory safety (§4) | Rust; `unsafe` confined to the transport layer and tracked in `docs/security/unsafe-inventory.json` and checked in CI; continuous STUN/TURN fuzzing (`fuzz/`); property tests for ChannelData/STUN framing; strict parser rejects ambiguous frames | ✅ (fuzzing/inventory) |
| Differential correctness | `tools/diff-test` replays the same STUN/TURN packets through turna and coturn and asserts identical behavior | 🚧 |
| Clustering / HA (§5) | Built-in gRPC control plane; shared allocation state (`state-backend`: Tarantool/in-memory); node discovery; **graceful drain** and **live session migration** so node restarts don't drop calls; crash recovery | 🚧 |
| Config safety (§6) | **Secure-by-default**: `validate()` fails closed on the placeholder secret and missing `external_ip` in production; special-use peer ranges denied by default. Explicit profiles `dev`/`public`/`hardened`/`benchmark` planned | ✅ partial (fail-closed validation + peer default-deny ✅; named profiles 📋) |
| Diagnostics | Startup self-test of the relay path; explicit errors for "advertised IP mismatch" / "relay range closed"; per-packet reject reason on request | 📋 |
| Multi-tenancy (§7) | `tenant_id` as a first-class entity; quotas for bandwidth / allocations / pps / concurrent relays; per-tenant relay port pool and ACL; billing counters; abuse auto-throttle | 📋 |
| Kubernetes (§8) | Official Helm chart (`deploy/helm/turna`); `hostNetwork` mode; LoadBalancer mode with documented constraints; **readiness = a real TURN allocation check**, not a TCP ping; graceful shutdown (stop new allocations, drain old); config reload without restart | 🚧 (Helm ✅, real-allocation readiness 🚧) |
| Secret rotation | Credential rotation without restart; audit log for auth/admin changes | 🚧 |
| Benchmark trust (§9) | Reproducible suite in `bench/` with a **coturn-compatible profile**; JSON reports; packet-drop breakdown; CPU cycles/packet; allocations/sec; relay throughput by packet size; dedicated garbage-flood benchmark | 🚧 |

---

## What turna deliberately does *not* do yet

Saying no is part of being a product. These are explicit non-goals for the
first releases, planned but not blocking adoption for WebRTC-over-UDP:

- DTLS (TLS-over-UDP) allocations — *not yet*. Note that **TURN over TCP/TLS is
  already supported**: the TURNS transport (rustls, behind the `tls` feature,
  port 5349) and RFC 6062 TCP relay allocations are both implemented; only DTLS
  is outstanding. See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) (R4).
- OAuth third-party authorization (RFC 7635)
- SQL / Redis / Mongo user database backends
- RFC 5780 NAT-behavior discovery
- Full coturn flag-for-flag compatibility and legacy modes

**Operational caveats.** Some shipped features have experimental datapaths:
the io_uring backend's graceful drain is not yet runtime-verified,
sharded-ownership routing
is so far static-checked only, and cross-node migration requires the same
`ticket_secret` on every node. Run the default `transport = "tokio"` in
production and see [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) for the
full risk register and recommended configuration.

If you need those today, coturn remains the right tool. turna's bet is that
most WebRTC operators don't, and would trade them for speed, safety, and
operability on the common path.

---

## Drop-in expectations

turna aims to be a drop-in for the common WebRTC setup:

- **Long-term credentials** and the **coturn-compatible TURN REST API**
  (`<unix_expiry>:<userid>` + HMAC) so existing browser clients work
  unchanged; the embedded expiry is enforced (no never-expiring creds). ✅
- Same UDP relay semantics, verified by `diff-test` against coturn. 🚧
- Same `turnserver`-style config concepts where they make sense, exposed
  through safer profiles.

Anything turna does differently from coturn on the wire is a bug — that is
the contract `diff-test` exists to enforce.

---

## Security posture (summary)

- Unsafe peer relay targets denied by default; explicit allowlist to opt in.
- Unsafe config combinations fail startup rather than running insecurely.
- Safe TLS defaults; no silent fallback to weak versions.
- All input parsing is fuzzed continuously; ambiguous frames are rejected.
- `unsafe` blocks inventoried and reviewed; see `docs/security/`.
- Audit log for authentication and administrative changes.

See `docs/security/threat-model.md` and `docs/security/invariants.md` for
the full model, and `docs/SECURITY.md` to report a vulnerability.
