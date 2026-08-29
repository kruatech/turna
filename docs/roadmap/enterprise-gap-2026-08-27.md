# Enterprise spec — state as of 2026-08-27

Replaces `enterprise-gap-2026-08-26.md`, which is now wrong in a dozen places.

**Read this before starting work on any requirement.** The previous version cost
real time twice: I read its own entry "absent on the stock DTLS path" as "absent"
and set out to write a certificate reloader that already existed, and I had SBOM
and checksums marked "needs checking" when they had been done for weeks. The
column that lies in the optimistic direction wastes an afternoon; the one that
lies in the pessimistic direction wastes a week.

So the marks here mean something specific:

| mark | meaning |
|---|---|
| **done** | Observed working. Evidence named. Not "the code looks right". |
| **written** | Code exists, has never run. Distinct from done, and the distinction is the whole point. |
| **partial** | Exists with a named gap. Not "nearly done". |
| **iron** | Blocked on hardware or a second machine. Not a coding task. |
| **decide** | Blocked on a product choice. Not a coding task either. |
| **build** | Real work, nothing blocking it. |

## The three things worth knowing before reading further

**Stage 1 of the spec's own order is done except for the numbers.** The
generator, the harness, the report format and a measured ceiling all exist. What
remains is 10k/25k/50k, which needs load generated from other machines.

**A capacity figure now exists: 112 000 relayed pps** on 32 threads over
loopback. And the shape matters more than the number — nothing degrades
gradually. Every rate up to 112 000 relays every frame; 7 % above it the egress
queue sheds a million frames in two minutes. **There is no warning band.** A node
at 110 000 looks healthy and is one traffic bump from losing 6 % of media.

**Two P0s in §7 are a decision, not work.** Certificate hot-reload and handshake
rate limiting both exist for DTLS on the demux path, which is off by default
because the stock path is the one with recorded verification. Neither can exist on
the stock path: `listen()` owns the socket and the handshake completes below
`accept()`. Flipping the default closes both.

---

## §4 Scaling and capacity (9)

| req | P | state | note |
|---|---|---|---|
| Real media scale 10k/25k/50k | P0 | **partial** + **iron** | Everything but the numbers. Needs load from other hosts — one generator saturates before the server, measured. |
| Capacity-aware admission control | P0 | **build** — inputs ready | All four signals collected and observed: bytes/s, packets/s, CPU, memory. What is missing is a *threshold*, and 112 000 is now available to derive one from. Use a fraction — see the cliff above. |
| Capacity API | P0 | **done** | `GET /capacity`, five states, three observed live with distinct thresholds. `docs/design/capacity-api.md`. |
| Horizontal scaling | P0 | **partial** | Cluster, gossip, hash ring. `node_migration.rs` unwired and the docs say so. No media-session migration. |
| Per-node capacity profile | P1 | **done** for one machine | `docs/capacity/threadripper-1950x-2026-08-26.md`. One point, honestly bounded. |
| Resource forecasting | P1 | **written**, with a factor-of-two open | `scripts/forecast.py`. Scales from the one measurement and states every assumption inline. It also surfaced a real ambiguity: the capacity measurement counted **round trips** (`sent` and `recv` differed by 30 in 5.4 M frames), while a call is one traversal. So 112 000 may be worth 224 000 one-way, and the forecast may ask for twice the hardware. Resolvable by one run with a forwarding driver instead of an echo. |
| Port exhaustion monitoring | P0 | **done** | Three gauges, verified against the allocation count. Was a blind spot: the range filled silently and the first symptom was `Allocate` failing. |
| Bandwidth saturation alerts | P0 | **partial** | Rate sampler verified at 32 320 B/s against a prediction. Threshold pending the same decision as admission control. |
| PPS saturation monitoring | P0 | **partial** | Same sampler, 160 pkt/s against a predicted 160. |

## §5 High availability (11)

| req | P | state | note |
|---|---|---|---|
| N+1/N+2 redundancy | P0 | **iron** + **decide** | |
| Fast node failure detection | P0 | **partial** | Gossip detects it. Time-to-detect under load untested. |
| Client recovery / ICE restart | P0 | **done** (the server's half) | Reconnect storm: 150/150 recovered, slowest client 3 ms, limiter untouched. |
| Graceful drain | P0 | **done**, improved | Verified on four transports. Now `[turn.relay] drain_timeout_secs`, and the loop exits when nothing is expiring — a node holding abandoned allocations took the full 30 s waiting for expiries that could not happen. Measured after: 1 s. |
| Rolling upgrades | P1 | **written** | `scripts/verify/upgrade-rollback.sh`. Tests the RELEASE.md procedure including a rollback against the *new* config, which is what an operator would have. |
| Failure-under-load mode | P0 | **iron** | Needs a cluster. |
| Multi-DC / region awareness / fallback | P1 | **build** (design first) | |
| Backup/restore runtime config | P1 | **partial** | Durable command log exists; restore untested. |
| DR runbook | P1 | **done** | `docs/runbooks/disaster-recovery.md`. Starts from what changes every priority: a relay carries no durable user data, so getting a node serving again matters more than recovering what it served. Ends with a table of eight scenarios and which four have been rehearsed — a runbook whose steps have never run is a document, not a procedure. |

## §6 Air-gapped operation (8)

| req | P | state | note |
|---|---|---|---|
| Air-gapped mode | P0 | **done** | 7/7 in a namespace with loopback only. Relays 404/404 frames, opens no non-loopback socket. |
| Zero outbound telemetry by default | P0 | **done** | Observed. Found on the way: the log line announcing this was emitted before the tracing subscriber existed and had never appeared in any log. |
| No mandatory cloud dependencies | P0 | **done** | Asserted with `ss` inside the namespace rather than argued. |
| No mandatory external DNS | P0 | **done** | Ran with no nameserver. |
| Offline installation | P0 | **written** | `scripts/offline-bundle.sh`. Image tarball, chart, static binaries, config template, generated INSTALL.md with the image digest — recorded there and not only in the checksums, because anyone handing over a modified bundle hands over a matching SHA256SUMS with it. Checksums are computed last so INSTALL.md is covered; a first version left the digest outside the only integrity check. |
| Offline upgrade bundles | P1 | **written** | `scripts/offline-upgrade-bundle.sh`. Both binaries, and the artifact that matters: the config key diff between the two versions. `deny_unknown_fields` means a key the new version added makes the **old** binary refuse the config the new one wrote, so the rollback window closes once the upgrade has run. Verified on real versions — the five keys added this session are exactly what it reports. |
| Privacy-safe support bundle | P1 | **done** | `scripts/support-bundle.sh`. Redaction is the default; addresses hashed with a discarded per-bundle salt. Verified against six real secrets. |
| Data-minimizing logs | P0 | **done** | `docs/security/log-data-audit-2026-08-27.md`. Usernames and secrets never reach a log — a negative result worth recording. Three INFO lines carried the client address, all per-allocation, so 13.7 M allocations meant 13.7 M lines of personal data. `[observability] log_client_addresses`, default **true** to preserve behaviour, because `src` is the field an operator correlates a complaint against. |

## §7 Security and access control (15)

| req | P | state | note |
|---|---|---|---|
| mTLS management plane | P0 | **done** | Both halves: accepted with a certificate, **refused without one**. The refusal is what carries it. |
| Management RBAC | P1 | **written** | `crates/control/src/rbac.rs`, 11 tests, 16 RPCs checked. Roles in config so a new one needs no release. Default-deny. |
| Infrastructure audit log | P1 | **partial** | `InfraEvent` with eight categories from CIS 8.2 / ISO 27001 A.12.4, plus the node's own ring. Partial, and the reason is specific: `AuditLog` is an **in-memory ring**, not a file, so start and stop events — the two an auditor asks for first — cannot live in it, because they describe the restart that erases it. Those go to syslog. | `InfraEvent` and `record_infra` written, eight categories from CIS 8.2 / ISO 27001 A.12.4. Not wired: the hash chain lives in the control plane, the events happen in the node, and two writers on one chain is a correctness problem. Syslog covers the SIEM case. |
| Credential rotation without downtime | P0 | **partial** — certificates only (2026-08-28) | Certificate rotation verified under load: counter 0 -> 1, no reload failures, 36 021 frames relayed with zero errors across the swap. **The shared secret cannot be rotated hot at all** — the node does not handle SIGHUP, and `UpdateConfig` carries allocation limits and not the secret. Changing it needs a restart, which matters because it is the credential a leak would force you to change. | `scripts/verify/rotation-under-load.sh` checks both halves — live sessions survive, and the old secret stops granting new allocations. |
| Credential revocation | P1 | **decide** | No CRL/OCSP by design; revocation means rotating the CA. Documented, and the first thing a customer asks. |
| Ephemeral TURN credentials | P0 | **done** | |
| Private CA support | P0 | **done** | |
| Certificate hot rotation | P0 | **blocked on a defect** (2026-08-28) | Verified working on the DTLS demux path, and so is the per-IP handshake rate limit — 15 handshakes refused before any DTLS state was created. Both §7 P0s that the stock path cannot provide. But **the node does not exit on the demux path**: drain completes in two seconds (`all allocations drained` in the log) and two threads remain, so SIGTERM does not take it and an orchestrator would wait out its timeout and kill it. The flip is blocked on that, not on evidence. | Exists on DTLS's demux path. See the note at the top. |
| CA trust rotation | P1 | **partial** | |
| Secret source abstraction | P1 | **done** | `${ENV}` and `file://`. |
| Per-IP connection limits | P0 | **done** | Every transport. SCTP was the last gap. |
| Handshake rate limiting | P0 | **decide** | Same demux decision. |
| Protocol abuse protection | P0 | **done** | Peer filter including the v4-embedding v6 prefixes, five fuzz targets. |
| BPF early packet filtering | P1 | **partial** | AF_XDP attaches in SKB mode on veth — not a capacity result. |
| Security hardening profile | P0 | **done** | `docs/security/security-profile.md`, plus `scripts/verify/deployment-compliance.sh` which checks a deployment against it. Tested against a good and a bad config. |

## §8 Multi-tenancy (7)

Largely present before this work. One change: **tenant metric cardinality is now
capped** at 100 per family with the tail in `__other` and the omission counted.
Five families carried an unbounded label — ten thousand tenants meant fifty
thousand series per scrape, and §10 asks for cardinality protection in the same
document that asks for per-tenant metrics.

Remaining: per-tenant bandwidth quotas **partial**, dedicated relay port pools
**partial**, tenant-aware capacity policy **build**.

## §9 Corporate networks (9)

| req | P | state | note |
|---|---|---|---|
| TURN UDP | P0 | **done** | |
| TURNS over TCP/443 | P0 | **done** | Three browser engines, public chain, coturn, 24 h at zero loss. Runs were on 5349; 443 is one config value and nothing has run there. |
| IPv6 relay | P1 | **done** | Between routable global addresses. Missing: different hosts, and `ADDITIONAL-ADDRESS-FAMILY`. |
| Proxy/firewall matrix | P0 | **done** | In `docs/deployment/enterprise-network-profile.md`, including the case that cost an afternoon: a system HTTP proxy silently prevents WebTransport with zero packets reaching the node. |
| Enterprise network profile | P0 | **done** | Same document. Ports, conntrack sizing, the TLS-terminating-proxy trap. |
| Client/network diagnostics | P0 | **written** | `tools/browser-probes/connectivity-check.html`. Single file, no dependencies, runs on the client's network — which is the only place the answer exists. |
| Connectivity test portal/API | P1 | **partial** | The page above is most of it. |
| MTU/path diagnostics | P1 | **partial** | |
| Multiple address profiles | P1 | **partial** | |

## §10 Observability (11)

| req | P | state | note |
|---|---|---|---|
| Prometheus metrics | P0 | **done** | Plus a gate asserting every series is documented. |
| OpenTelemetry tracing | P0 | **done** | |
| Health/readiness API | P0 | **done** | Hardened: the health port was bound inside a spawned task with its error discarded, so a node whose port was taken started anyway and scrapes read whatever else held it. Now fatal, with the project's first startup-failure test. |
| SLO metrics | P0 | **partial** | Histograms exist; no SLO to measure against. |
| SIEM export | P1 | **written** | `crates/observability/src/syslog.rs` plus `syslog_layer.rs`, a tracing layer that forwards matching log events. Not call sites: the refusal sites already log with the address as a field, so a layer covers new ones automatically and leaves `processor.rs` untouched. `unmatched_security_targets` counts what the rules miss. | `crates/observability/src/syslog.rs`, RFC 5424, 8 tests. Security events only — a SIEM billed per event that receives a line per frame gets switched off. |
| Syslog | P1 | **written** | Same module. UDP and TCP with octet framing. | Same module, UDP and TCP with octet framing. |
| Structured JSON logs | P0 | **done** | Already existed. I had this as "needs checking" and would have written it again. |
| Metrics cardinality protection | P0 | **done** | See §8. |
| Operational dashboards | P1 | **written** | `deploy/grafana/turna-overview.json`, 24 panels, schema 39. Every metric checked to exist; three panel overlaps found and fixed — an overlapped panel is in the JSON and invisible on screen. |
| Alert rule pack | P1 | **partial** | Exists, and CI asserts every metric it names is exported. |
| Support bundle generator | P1 | **done** | See §6. |

## §11 Deployment (12)

| req | P | state | note |
|---|---|---|---|
| Kubernetes | P0 | **done** | |
| Bare-metal/systemd | P0 | **needs checking** | Still not looked at. |
| Host-network profile | P0 | **partial** | |
| Multi-NIC / bonding / 10-100GbE | P1 | **iron** | |
| Versioned configuration schema | P0 | **done**, differently | `deny_unknown_fields` on 37 structs, which is stricter than a version field: it names the unknown key instead of saying "this file is newer". |
| Config migrations | P1 | **build** | Nothing to migrate yet. |
| LTS release channel | P1 | **decide** | |
| Release rollback procedure | P1 | **written** | Script above. |
| Preflight validator | P0 | **done** | `validate()` plus `--dump-config`. AF_XDP now refuses five keys it was accepting and ignoring. |
| Deployment compliance report | P1 | **done** | Script above. |

## §12 Performance (10)

| req | P | state | note |
|---|---|---|---|
| Tokio baseline | P0 | **done** | |
| io_uring | P1 | **done** (kernel-scoped) | Two kernels, 9.6 h, 0.006 % loss. Found a slot leak that made a worker deaf after exactly 64 packets. |
| AF_XDP | P2 | **partial** | Correct on veth, SKB mode, **not a capacity result**. Found a frame leak that stopped reception after exactly 2015 frames. |
| NUMA / IRQ / socket tuning | P1–P2 | **done** | `docs/deployment/host-tuning.md`, from measurements on this project's hardware. Leads with the two things that are not settings: there is no warning band before the ceiling, and the relay range must not overlap the ephemeral range — the second is a correctness failure, not a performance one. IRQ and RSS advice is marked as **not verified here**, because loopback has no interrupts. |
| Hardware sizing calculator | P1 | **iron** | |
| Published hardware capacity profiles | P0 | **partial** | One machine, honestly bounded. The blocker for the rest is which hardware the product is sold on. |
| Performance regression CI | P1 | **written**, and deliberately not on PRs | `capacity-regression.sh` plus `.github/workflows/capacity.yml` on a self-hosted runner. A gate on hosted runners does not work: shared two-core VMs vary more between runs than any regression worth catching, and a check that fails half the time gets re-run until green. Baseline per machine, keyed on CPU model, core count and kernel — not hostname, which survives a hardware change. |

## §13 Integration contract (8)

This section was much further along than the previous analysis claimed —
idempotency keys on every mutating RPC, `expected_version` for optimistic
concurrency, `reserved` on retired fields, and `turna.management.v1` already
versioned. Two real gaps, both now closed.

| req | P | state | note |
|---|---|---|---|
| Stable versioned management API | P0 | **done** | Plus `scripts/check-proto-compat.sh`, which fails when a field number changes meaning. Proven to catch it. |
| Node discovery/status API | P0 | **partial** | `/cluster` returns the ring. |
| Runtime limits API | P0 | **done** | |
| Credential issuance contract | P0 | **partial** | Works; not versioned. |
| Idempotent control operations | P0 | **done** | Already existed on every mutating RPC. |
| Opaque correlation metadata | P1 | **written** | gRPC metadata rather than a proto field — sixteen messages is sixteen chances to burn a field number, and this contract already carries `reserved 1 to 4` from that. Sanitised at the boundary. |
| API compatibility test suite | P1 | **done** | The gate above. |
| SDK for control plane | P1 | **written** | `tools/sdk/python/turna_sdk.py`. mTLS required by the constructor, not optional. |

## §14 Supply chain (10)

Nearly all of it was already done — SBOM, cosign keyless signing, SLSA
provenance, checksums, dependency scanning, pinned CI. I had two of those as
"needs checking".

| req | P | state | note |
|---|---|---|---|
| Reproducible builds | P1 | **done** | All three binaries reproduce byte-for-byte on Linux from different build directories. macOS cannot (`LC_UUID`) and the script refuses to run there rather than reporting an unfixable failure. |
| FIPS-capable profile / HSM | P2 | **decide** | Worth confirming a customer requires it. |

## §15 Testing (13)

| req | P | state | note |
|---|---|---|---|
| 24 h endurance | P0 | **done** | Zero loss, no leak. What made it valid: the load client was not refreshing TURN bindings, so every earlier long run measured a decaying session. |
| 72 h endurance | P1 | **written** | Per-day mode in `analyze.py` for runs over 30 h. Halves hide a leak starting at hour 40 and a 2 %/day leak; per-day floors catch the second and the halves test still catches the first — the two are complementary and neither replaces the other. Found by synthetic data that the first threshold was unreachable on a 3-day run. |
| 10k/25k/50k certified | P0 | **iron** | |
| Mixed UDP/TURNS load | P0 | **written** | `scripts/verify/mixed-load.sh`. Solo baselines first, at the same rates, and the mixed result as a delta — a loss figure without a baseline is unreadable. Threshold 0.5 pp, loose enough that run-to-run variance does not trip it. |
| Reconnect storm | P0 | **done** | 150/150. Needs `--source-ips`, without which it measures the per-IP limiter. |
| Node loss at peak | P0 | **iron** | |
| Backend degradation | P1 | **partial** | CAS failover in CI. |
| Certificate rotation under load | P1 | **written** | |
| Secret rotation under load | P1 | **written** | Both halves checked, including that the old secret stops working. |
| Air-gap integration test | P0 | **done** | |
| Browser/client interop matrix | P0 | **done** | Three engines, a browser WebTransport probe, coturn on five paths. |
| Kernel/NIC certification matrix | P1 | **iron** | |
| Upgrade/rollback tests | P1 | **written** | |

---

## What to do next, in order

**1. Compile and run what is marked "written".** That category is now the largest
in this document, and it is the only one where I can be wrong invisibly. Each item
is code that exists and has never executed. Converting one to **done** costs a
command; leaving it costs the illusion of coverage.

The cheapest first: `cargo test -p turna-control rbac`,
`cargo test -p turna-observability syslog`, then the scripts in
`scripts/verify/`.

**2. Resolve the factor of two in the capacity figure.** One run settles it: the
current measurement echoes frames back to the client, so every frame crosses the
relay twice. A driver that forwards instead would say whether 112 000 means
112 000 or 224 000 one-way traversals. Until then every forecast and any admission
threshold is uncertain by 2×, which is the difference between 13 nodes and 26.

This is one measurement and it gates two other things. It should come before
either.

**3. Decide the demux default.** Two P0s in §7, no code. Needs a recorded run of
the demux path, which is the same shape of work as item 1.

**4. Decide the admission threshold**, after item 2. The measured curve is a cliff
— nothing degrades before the ceiling and 7 % above it a million frames go in two
minutes — so the argument is for a fraction well under, not for a margin.

**5. Decide the hardware.** Eight P0s across §4, §11, §12 and §15 wait on which
machine the product is sold on, and that decision belongs before the engineering
rather than after it.

**6. Then the cluster items.** Everything marked **iron** in §5 and §15 needs
three nodes and cannot be faked on one.

## What this document is still wrong about, as far as I know

`bare-metal/systemd` has been marked "needs checking" through four revisions and
has never been checked. It is probably fine. I have not looked.

The **written** entries are marks on code, not on behaviour. Every one of them was
verified as far as a toolchain-free check reaches — brace balance either side of
each edit, shell and python syntax, JSON and YAML validity, and the arithmetic run
against synthetic data. Three of them needed a second pass because such a check
caught what the script's own success message did not, which is the honest measure
of how far that gets you.

And one correction from this batch worth carrying forward: I designed a second
on-disk audit chain, at length and with reasons, before discovering that
`AuditLog` is an in-memory ring. The reasoning was sound and answered a question
the code had already settled differently. **Read the constructor before designing
around the type.**
