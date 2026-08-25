# Enterprise spec — where the tree actually stands

Written against `turna_enterprise_features_spec.docx` (123 requirements: 65 P0,
54 P1, 4 P2) and the tree at `main` as of 2026-08-26.

The spec carries its own *Текущее состояние* column. This document exists
because that column was written without the last week's work, so several
requirements it lists as needed are done, and — more usefully — a few it lists as
present are weaker than the label suggests. Where the two disagree, the
disagreement is stated rather than smoothed over.

**Read the classification first.** "Done" here means *observed*, not *written*:
there is a run, a test or a rendered metric behind it. That distinction is the
whole point of the exercise. A month of this project was spent discovering that
three hours of endurance had reported PASS on every signal while the datapath
relayed nothing, and that a 24-hour soak had been reading an unrelated process's
metrics. Anything below marked done has evidence attached; anything without
evidence is marked partial regardless of whether the code looks finished.

| mark | meaning |
|---|---|
| **done** | Implemented and observed. Evidence named. |
| **partial** | Exists, with a specific gap named. Not "nearly done". |
| **build** | Real engineering, no blocker. Estimate given where I have one. |
| **iron** | Cannot be answered without hardware we do not have. |
| **decide** | Waiting on a product or policy choice, not on work. |
| **question** | Worth asking whether it belongs in Turna at all. |

---

## The one structural finding

**Stage 1 of the spec's own implementation order — "prove scale" — is roughly
half built, and the half that exists is the half that is usually missing.**

The spec asks for reproducible tests with real bidirectional ChannelData traffic
rather than STUN Binding, 24 hours without growth in memory, fds or threads, and
a report naming exact hardware, OS, kernel and methodology. All three exist:
`turna-load-test` drives every transport with media in both directions,
`scripts/verify/overnight.sh` runs the soak with a leak analyser, and
`docs/soak/endurance-24h-2026-08-22.md` is that report.

What it cannot do is 10k/25k/50k. What was actually measured on the 4-core host
available: 441 TLS association attempts/s sustained on churn, and 400 relayed
packets/s clean over 9.6 hours. The ceiling sits somewhere above that and below
1250 pps, where two thirds of traffic was being dropped — the exact figure was
never established because the host is not the hardware the product will run on,
so pinning it down would measure the wrong machine.

Fifty thousand concurrent clients needs real nodes *and* distributed load
generation from several hosts, because a single generator saturates first.

**So the gating item for Stage 1 is hardware, not code.** Everything else in
Stage 1 is done. This is worth knowing before scheduling engineering against it.

The second finding is smaller and cheaper: **air-gap is close to free.** Turna
has no mandatory outbound dependency — Tarantool and OTLP are both configurable
and both optional. A network-namespace test with no default route would close
four P0 requirements in §6 in about a day. That is the highest ratio of closed
requirement to effort anywhere in the document.

---

## §4 Scaling and capacity

| req | P | state | note |
|---|---|---|---|
| Real media scale 10k/25k/50k | P0 | **partial** + **iron** | Generator, harness and report format done. The scale numbers need hardware and distributed generation. |
| Capacity-aware admission control | P0 | **build** | Today: per-IP rate limits, per-user quotas, `max_allocations`, bounded relay ports. All *count* limits. Nothing admits on bps, pps, CPU or queue depth. Weeks. |
| Capacity API | P0 | **partial**, observed (2026-08-26) | `GET /capacity`: five states, versioned, raw numbers beside the verdict (`docs/design/capacity-api.md`). Verified live — AVAILABLE idle, SATURATED at the hard threshold with the reason named. Partial because the state weighs allocations and send-queue pressure only; bps, pps, CPU and memory are absent and the `signals` field says so. **The 75 % soft threshold is unverified**: one host cannot drive enough concurrent allocations past `TieredRateLimiter`, which needs multiple source addresses or configurable limits. |
| Horizontal scaling | P0 | **partial** | Cluster, gossip and hash ring exist. `node_migration.rs` is unwired (the doc-claims gate asserts the docs say so). No media-session migration — a node loss drops its allocations. |
| Per-node capacity profile | P1 | **iron** | Needs measurement on the hardware being sold. |
| Resource forecasting | P1 | **build** | |
| Port exhaustion monitoring | P0 | **done** (2026-08-26) | Three gauges: in use, total, utilisation percent. Tenant pools summed rather than labelled — per-tenant series are how a Prometheus instance dies at ten thousand tenants, and §10 asks for cardinality protection in the same document. Verified live against the allocation count. |
| Bandwidth saturation alerts | P0 | **partial** | Byte counters per transport and per tenant exist; `docs/alerts/` has a rule pack. No saturation threshold because there is no published capacity to compare against — this one is downstream of the hardware profiles. |
| PPS saturation monitoring | P0 | **partial** | Same shape: `turna_packets_received`/`_sent` exist, the threshold does not. |

## §5 High availability

| req | P | state | note |
|---|---|---|---|
| N+1/N+2 redundancy | P0 | **decide** + **build** | A deployment contract, then a test that proves it. |
| Fast node failure detection | P0 | **partial** | Gossip detects a dead node. What is untested is the time to detect under load, which is the number that matters. |
| Client recovery / ICE restart | P0 | **build** (docs) | Mostly a client-side contract. Turna's part — fail cleanly and free the allocation — works; the integration spec does not exist. |
| Graceful drain | P0 | **done** | Verified on TURNS, DTLS, QUIC and SCTP. The `300 Try Alternate` redirect that drain relies on was broken for three releases — `ATTR_ALTERNATE_SERVER` carried `0x0003` instead of `0x8023`, so no conforming client could read the alternate address. Fixed and guarded by a test asserting the encoded bytes. |
| Rolling upgrades | P1 | **partial** | Drain works; the procedure is not written or tested. |
| Failure-under-load mode | P0 | **build** | Needs the node-loss-at-peak test from §15. |
| Multi-DC / region awareness / fallback | P1 | **build** (design first) | |
| Backup/restore runtime config | P1 | **partial** | Durable command log exists. Restore path untested. |
| DR runbook | P1 | **build** (docs) | |

## §6 Air-gapped operation

**Cheapest cluster of P0s in the document.** Four of these are verification, not
construction.

| req | P | state | note |
|---|---|---|---|
| Air-gapped mode | P0 | **done** (2026-08-26) | 7 of 7 in a namespace with loopback only: starts, relays 404/404 frames, opens no non-loopback socket, OTLP off, no resolver, metrics answer. `docs/verification/air-gap-capacity-2026-08-26.md`. Does not cover offline installation. |
| Zero outbound telemetry by default | P0 | **done** (2026-08-26) | Observed, not inferred. Found on the way: the log line announcing this had been emitted before the tracing subscriber existed and so had never appeared in any log. |
| No mandatory cloud dependencies | P0 | **done** (2026-08-26) | Asserted rather than argued: `ss` inside the namespace shows no socket to any non-loopback address. |
| No mandatory external DNS | P0 | **done** (2026-08-26) | Ran with no nameserver in the namespace. |
| Offline installation | P0 | **build** | Packaging: image tarball plus Helm chart plus checksums. |
| Offline upgrade bundles | P1 | **build** | |
| Privacy-safe support bundle | P1 | **build** | Overlaps §10's support bundle — one piece of work, not two. |
| Data-minimizing logs | P0 | **build** (audit) | Needs a pass over what is logged at INFO. Client addresses appear in allocation lines. |

## §7 Security and access control

The strongest section. Most of it is done, and two gaps are specific.

| req | P | state | note |
|---|---|---|---|
| mTLS management plane | P0 | **done** | `scripts/verify/mtls.sh`: accepted with a certificate, **refused without one** when `require_client_cert = true`, and the staged-rollout mode. The refusal is the case that carries it — a server accepting everybody is indistinguishable from a working one if only the happy path is run. |
| Management RBAC | P1 | **build** | |
| Infrastructure audit log | P1 | **build** | |
| Credential rotation without downtime | P0 | **partial** | |
| Credential revocation | P1 | **build** | No CRL/OCSP, deliberately — revocation means rotating the CA. Consistent with `docs/MTLS.md`, but a customer will ask. |
| Ephemeral TURN credentials | P0 | **done** | REST shared-secret and JWT. |
| Private CA support | P0 | **done** | The mTLS check mints a throwaway private CA, because client certificates come from a CA you run — public issuers sign server certificates only. |
| Certificate hot rotation | P0 | **partial** | Works on TLS, QUIC and WebTransport. **Absent on the stock DTLS path.** |
| CA trust rotation | P1 | **partial** | |
| Secret source abstraction | P1 | **done** | `${ENV}` and `file:///run/secrets/...` in config values. |
| Per-IP connection limits | P0 | **done** | The spec says "partially, for transports" — that was true until this week. SCTP was the last gap and now has both a cap and a rate limit. |
| Handshake rate limiting | P0 | **partial** | The spec's "uneven across transport paths" is still accurate: TURNS, QUIC and SCTP have it; the **stock DTLS path does not**. Same gap as certificate rotation, same place. |
| Protocol abuse protection | P0 | **done** | Peer filter denies private ranges *and* the v4-embedding v6 prefixes (NAT64, 6to4, Teredo, IPv4-compatible) — without those, every IPv4 rule was bypassable by asking for the v6 spelling of the same target. Five fuzz targets on the codec. |
| BPF early packet filtering | P1 | **partial** | AF_XDP attaches in SKB mode on veth, which copies every frame and reproduces none of the bypass behaviour the feature exists for. |
| Security hardening profile | P0 | **build** (docs) | Material exists across `docs/security/`; the single profile document does not. |

## §8 Multi-tenancy

Largely present. Nothing here is a surprise.

| req | P | state |
|---|---|---|
| Tenant isolation | P0 | **partial** |
| Per-tenant allocation quotas | P0 | **done** |
| Per-tenant bandwidth quotas | P0 | **partial** |
| Per-user limits | P0 | **done** |
| Dedicated relay port pools | P1 | **partial** |
| Tenant-scoped metrics | P1 | **done** — accrued at allocation teardown, so empty until tenants close allocations |
| Tenant-aware capacity policy | P1 | **build** — downstream of the Capacity API |

One caution: tenant-scoped metrics and §10's *metrics cardinality protection* pull
against each other. Per-tenant series are exactly how a Prometheus instance gets
killed by a customer with ten thousand tenants. Worth deciding the bound before
the feature is sold.

## §9 Corporate networks

| req | P | state | note |
|---|---|---|---|
| TURN UDP production path | P0 | **done** | Supported. 3 h endurance, 13.7 M allocations, 441 M packets, coturn interop. |
| TURNS over TCP/443 | P0 | **done** | Supported: three browser engines, a Let's Encrypt chain validated by a verifying client, coturn interop, 24 h at zero relayed-frame loss. Runs were on 5349; 443 is one config value, but nothing has been run there. |
| IPv6 relay support | P1 | **done** | 6010/6010 frames between two routable global addresses, peer filter in `lan` profile, no loopback concession. Missing: routing between *different* hosts, and `ADDITIONAL-ADDRESS-FAMILY`. |
| Proxy/firewall compatibility matrix | P0 | **build** (docs) | Worth noting from experience: a system proxy silently prevented Chrome from reaching WebTransport at all — `ERR_TUNNEL_CONNECTION_FAILED`, zero packets, while `nc` from the same machine worked. Exactly the class of thing this matrix is for. |
| Enterprise network profile | P0 | **build** (docs) | |
| Client/network diagnostics | P0 | **build** | |
| Connectivity test portal/API | P1 | **build** | `tools/browser-probes/` is a starting point. |
| MTU/path diagnostics | P1 | **partial** | DONT-FRAGMENT works on both families. |
| Multiple address profiles | P1 | **partial** | `external_ip` / `external_ip6`. |

## §10 Observability and operations

| req | P | state | note |
|---|---|---|---|
| Prometheus metrics | P0 | **done** | Plus a CI gate asserting every exported series is documented — which is how thirteen new SCTP series arrived documented rather than not. 46 series in known-debt families are still undocumented and the gate lists them rather than hiding them. |
| OpenTelemetry tracing | P0 | **done** | |
| Node health/readiness API | P0 | **done** | Hardened this week: the health port used to be bound inside a spawned task with its error discarded, so a node whose port was taken started anyway and scrapes read whatever else held it. We hit that — a 24 h run reported "series absent" for every `turna_*` check because the sampler was reading an unrelated process. Now fatal, with the project's first startup-failure test. |
| SLO metrics | P0 | **partial** | Latency histograms exist; no SLO definition to measure against. |
| SIEM export / Syslog | P1 | **build** | |
| Structured JSON logs | P0 | **needs checking** | I have not verified the formatter. |
| Metrics cardinality protection | P0 | **build** | See the §8 caution. |
| Operational dashboards | P1 | **build** | |
| Alert rule pack | P1 | **partial** | `docs/alerts/` exists and CI asserts every metric it names is exported. |
| Support bundle generator | P1 | **build** | |

## §11 Deployment

| req | P | state | note |
|---|---|---|---|
| Kubernetes deployment | P0 | **done** | Helm chart, lint, render and kubeconform in CI. |
| Bare-metal/systemd | P0 | **needs checking** | |
| Host-network performance profile | P0 | **partial** | |
| Multi-NIC / bonding / 10-100GbE | P1 | **iron** | |
| Versioned configuration schema | P0 | **partial** | |
| Config migrations | P1 | **partial** | |
| LTS release channel | P1 | **decide** | |
| Release rollback procedure | P1 | **partial** | `RELEASE.md` has one; untested. |
| Preflight validator | P0 | **done** | `config::validate()` plus `--dump-config`. Strengthened this week: AF_XDP now refuses five keys it was accepting and ignoring, and a `frame_count` that silently killed reception. |
| Deployment compliance report | P1 | **build** | |

## §12 Performance

| req | P | state | note |
|---|---|---|---|
| Tokio baseline | P0 | **done** | |
| io_uring | P1 | **done** (kernel-scoped) | Kernels 6.8 and 6.14, 9.6 h at 0.006 % loss. Version-sensitive by nature, so it is evidence about those two kernels. Found and fixed a slot leak that made a worker go deaf after exactly 64 packets while its control plane ran at 10 800 allocations/s. |
| AF_XDP | P2 | **partial** | Correct on a veth lab, three rates, zero loss — but SKB mode, so **not a capacity result**. Found a frame leak that stopped reception after exactly 2015 frames. |
| NUMA / IRQ / socket tuning / CPU affinity | P1–P2 | **build** (docs) | |
| Hardware sizing calculator | P1 | **iron** | |
| Published hardware capacity profiles | P0 | **iron** | The blocker for §4 and §15 both. |
| Performance regression CI | P1 | **build** | |

Note on the two datapath leaks: both presented identically — a hard stop at a
resource boundary, invisible to every existing check, found by comparing a
counter against the size of the thing it was exhausting. If a third datapath
appears, look there first.

## §13 Integration contract

| req | P | state |
|---|---|---|
| Stable versioned management API | P0 | **partial** |
| Node discovery/status API | P0 | **partial** — `/cluster` returns the ring |
| Runtime limits API | P0 | **partial** |
| Credential issuance contract | P0 | **partial** — signaling issues credentials; the contract is not versioned |
| Idempotent control operations | P0 | **needs checking** |
| Opaque correlation metadata | P1 | **build** |
| API compatibility test suite | P1 | **build** |
| SDK for control plane | P1 | **build** |

This section is the real integration risk. The Conference product will bind to
these, and "partial" here means the shape can still change under it.

## §14 Supply chain

| req | P | state | note |
|---|---|---|---|
| SBOM | P0 | **needs checking** | |
| Signed artifacts and images | P0 | **partial** | Build provenance attestation is in the release workflow. |
| Checksums | P0 | **needs checking** | |
| Reproducible builds | P1 | **build** | |
| Dependency vulnerability scanning | P0 | **done** | `cargo-deny` on every PR, plus Dependabot. Two advisories were closed the day they appeared, one by dropping an unmaintained crate. |
| Pinned CI dependencies | P1 | **done** | Actions pinned by commit SHA; the AF_XDP check image pinned by digest rather than a mutable tag. |
| FIPS-capable profile / HSM | P2 | **question** | Research, and worth confirming a customer actually requires it before starting. |
| Security release policy | P1 | **done** | `SECURITY.md`, private reporting enabled. |
| Unsafe-code inventory | P1 | **done** | `docs/unsafe-audit.md`, plus Miri in CI on the pure-memory crates. The syscall-bound unsafe cannot run under Miri and is covered by hardware soaks instead. |

## §15 Testing and certification

| req | P | state | note |
|---|---|---|---|
| 24 h endurance | P0 | **done** | Zero relayed-frame loss, no leak on any signal. Note what made it valid: the load client was not refreshing TURN bindings, so every long run before the fix was measuring a decaying session — 600 s of a 1755 s phase, presenting as a capacity cliff. Two 24 h runs were spent on that. |
| 72 h endurance | P1 | **build** (run) | The analyser compares halves; a 72 h run needs day-resolution instead. |
| 10k/25k/50k certified profiles | P0 | **iron** | |
| Mixed UDP/TURNS load | P0 | **build** | Drivers exist per transport; nothing mixes them in one run. Days, not weeks. |
| Reconnect storm | P0 | **build** | |
| Node loss at peak | P0 | **build** | Needs a cluster. |
| Backend degradation | P1 | **partial** | A Tarantool CAS failover test runs in CI. |
| Certificate rotation under load | P1 | **build** | |
| Secret rotation under load | P1 | **build** | |
| Air-gap integration test | P0 | **build** (~1 day) | |
| Browser/client interop matrix | P0 | **done** | Three browser engines on TURNS; a browser probe on WebTransport that assembles its own STUN, MD5 and HMAC; coturn's client on UDP, TURNS, DTLS, IPv6 and RFC 6062. Five paths against an implementation nobody here wrote. |
| Kernel/NIC certification matrix | P1 | **iron** | |
| Upgrade/rollback integration tests | P1 | **build** | |

---

## What I would do first, and why

**1. Air-gap verification (§6, four P0s, about a day).** Highest closed-requirement
per hour in the document, and it converts an architectural belief into a test.

**2. Capacity API (§4 and §13, P0).** ~~This is what the upper product binds
to.~~ **Done 2026-08-26**, in the partial sense above: the endpoint and the five
states exist, the load signals do not. Doing it before admission control was
deliberate and worked as intended — defining the states first gave admission
control a vocabulary to act on instead of inventing one.

What it revealed: a rate sampler is needed by three separate requirements — this
endpoint's `bandwidth_rate`/`packet_rate` signals, §4's bandwidth and pps
saturation alerts, and admission control itself. It is one piece of work serving
three, which makes it the next thing rather than admission control.

**3. Capacity-aware admission control (§4, P0).** Weeks. Needs bps, pps, CPU and
queue-depth signals; the counters for the first two exist.

**4. Mixed UDP/TURNS load and reconnect storm (§15, two P0s).** Days each, and both
extend the harness that already exists rather than starting one.

**5. Port exhaustion metric (§4, P0).** Small, and currently a blind spot: a relay
range filling up is invisible until allocations start failing.

**Not first: anything under *iron*.** The 10k/25k/50k profiles, hardware sizing and
the kernel/NIC matrix are the spec's headline claims, and none of them can be
started without deciding what hardware the product will be sold on. That decision
gates about eight P0s and belongs before the engineering, not after.

**Two P0s that are one piece of work:** certificate hot rotation and handshake rate
limiting are both missing on the stock DTLS path and nowhere else. Whoever touches
that listener should do both.

## Where this document may be wrong

Four requirements are marked **needs checking** because I have not verified them:
structured JSON logs, bare-metal/systemd deployment, SBOM and checksums, and
idempotent control operations. They may well be done. I have not looked, and
guessing would put this document in the same category as the spec's own stale
column — which is the thing it exists to correct.
