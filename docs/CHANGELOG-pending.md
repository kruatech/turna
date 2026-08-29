# CHANGELOG — pending section

Entries accumulate here between releases and move into `CHANGELOG.md` under a
version heading at release time.

### Fixed — read this one first

- **The node never exited on `SIGTERM`.** `run_tokio` let the Tokio runtime drop
  implicitly, and `Runtime::drop` waits for every spawned task to finish. Four
  metric tickers loop forever by design — one says "Runs until process exit" in
  its own comment — so the drop blocked and the process stayed alive until
  something killed it.

  Measured before the fix: alive past 45 seconds after `SIGTERM`, two threads
  left, one a worker in `hrtimer_nanosleep`. After: exits in about 12 seconds with
  status 0.

  **This affected every restart on every node**, in every configuration —
  confirmed identically with the stock DTLS listener and with DTLS disabled
  entirely. An orchestrator would wait out its termination grace period and then
  kill hard, on every rollout.

  It left no trace in the logs because everything that logs had already finished:
  drain completed in milliseconds, `all allocations drained` was written, and all
  four `join_within_budget` calls returned within their budgets. The wait was
  after the last line anything writes.

  It went uncaught because every verification script ends by killing the node with
  `SIGKILL`. `scripts/verify/dtls-demux.sh` was the first to assert that the node
  exits on its own, and it found this on its first clean run.

  *Action:* none, but if your deployment had a long termination grace period
  because turna "took a while to stop", it can be shortened.

### Added

- **Client-certificate revocation for the management plane** —
  `[grpc] revocation_list`, a file of SHA-256 fingerprints that may not be used.
  Checked before RBAC, because a revoked certificate that also lacks a permission
  must be audited as revoked: an operator reading `rbac_denied` would grant the
  role, and the revoked certificate would then work.

  **Not RFC 5280 CRL** — no CA-signed list, no freshness rule. A revoked client
  completes the TLS handshake and is refused on its first RPC. That trade buys
  what CRL cannot have here: it works with no route off the host, which is the
  deployment that most needs revocation. See `docs/security/mtls-revocation.md`.

  Fail-closed: a configured path that cannot be read stops the node, because a
  list that is configured and silently empty looks like protection.

- **RBAC for the management plane** — `[grpc.rbac]`, with roles defined in
  configuration rather than in code. `viewer`, `operator` and `admin` are
  defaults, not the vocabulary. Bindings are by certificate fingerprint, not by a
  field inside the certificate: reading a role from the OU would hand
  authorisation to whoever signs certificates.

  Default-deny, and enabling it on a running deployment locks out every client
  until each is bound — which is why it is opt-in.

- **Packet-rate thresholds in `/capacity`** — `[turn.relay] max_packets_per_sec`
  with `rate_soft_percent` (60) and `rate_hard_percent` (80).

  Lower than the allocation thresholds on purpose, and the measured curve is why:
  allocations degrade gracefully, and packet rate does not degrade at all and then
  falls off a cliff. On a 32-thread host, clean at 112 000 pps and shedding a
  million frames at 128 000 — seven percent between perfect and broken. At 80 %
  there are 30 400 pps of headroom before the cliff; at 90 % there would be
  19 200.

  0 leaves the rate reported and not judged, which is the default.

- **Security-event export to syslog** — `[observability] syslog_endpoint`,
  RFC 5424 over UDP or TCP. Security-relevant events only: a SIEM billed per event
  that receives a line per relayed frame gets switched off, and a switched-off
  SIEM catches nothing.

  Implemented as a tracing layer rather than calls at each refusal site. Those
  sites already log with the source address as a field, so a layer covers a new
  one by the act of writing its log line — and `processor.rs` is untouched.

- **`event = "..."` on 37 log lines**, so the layers can match a field instead of
  message text. Text matching failed measurably twice while this was being built:
  the first syslog rule set matched 2 of 7 messages in `processor.rs`, and the
  first audit rule set matched 6 of 22 — missing `all recv workers exited —
  datapath is dead`, the most serious line in `server.rs`.

- **The node keeps its own audit chain** — `[observability] node_audit_path`.
  Persistent when set: the existing chain is replayed and verified on startup and
  fails closed on a break. Start and stop events go here as well as to syslog —
  the chain survives the restart they describe, and syslog puts them where a
  compromised node cannot reach them.

- **Per-tenant metric cardinality is capped** at 100 series per family, with the
  tail aggregated into `__other` and `turna_tenant_series_omitted` reporting how
  many. Five families carried an unbounded `tenant` label: ten thousand tenants
  meant fifty thousand series per scrape per node.

  The tail is aggregated rather than dropped so sums still reconcile, and the
  truncation is itself a metric so it can be alerted on rather than discovered.

- **Correlation metadata** — `x-turna-correlation-id` on management RPCs, logged
  and carried into audit entries. Metadata rather than a proto field: adding one
  to sixteen request messages is sixteen chances to burn a field number
  permanently, and this contract already carries `reserved 1 to 4` from that.

- **`turna_dtls_handshake_failures_total` and
  `turna_dtls_rejected_rate_limit_total` are now exported.** Both counters existed
  and were filled by the node; neither reached `/metrics`. A metric present in a
  struct and absent from the endpoint is invisible in the same way a missing one
  is, and worse — somebody reading the struct concludes the signal is available.

- **`[turn.relay] drain_timeout_secs`**, and the drain loop now exits early when
  three consecutive polls remove nothing. A node holding allocations whose clients
  vanished paid the full 30 seconds waiting for expiries that could not happen
  inside the window; measured after: 1 second.

- **`[observability] log_allocation_addresses`** — named for its scope. It covers
  the three per-allocation INFO lines in the relay and nothing else. Ten WARN
  lines in the transports also carry an address and are deliberately outside it:
  all ten are refusals, so the volume is bounded by attacks rather than traffic,
  and the address is the most useful part of a refusal.

### Added — verification

- `scripts/verify/dtls-demux.sh` — nine checks on the DTLS demux path, producing
  the recorded run the default-flip decision was missing.
- `scripts/verify/mixed-load.sh` — UDP and TURNS at once, each measured alone
  first at the same rate so the mixed result is a delta.
- `scripts/verify/capacity-profile.sh` — finds the packet-rate ceiling by
  doubling until failure, then bisecting.
- `scripts/verify/capacity-regression.sh` — compares against a per-machine
  baseline, keyed on CPU model, core count and kernel rather than hostname.
- `scripts/verify/rotation-under-load.sh` — certificate rotation with media
  flowing.
- `scripts/verify/deployment-compliance.sh` — checks a live deployment against
  `docs/security/security-profile.md`.
- `scripts/verify/reproducible-build.sh` — builds twice in directories of
  different length and compares. Refuses to run on macOS, where `LC_UUID` makes
  it impossible.
- `scripts/offline-bundle.sh` and `scripts/offline-upgrade-bundle.sh`.
- `scripts/support-bundle.sh` — redaction by default; addresses hashed with a
  per-bundle salt that is discarded.
- `scripts/forecast.py` — hardware forecast from the measured ceiling.
- `tools/browser-probes/connectivity-check.html` — client-side diagnosis, one
  file, no dependencies.
- `deploy/grafana/turna-overview.json` — 24 panels, schema 39.
- `tools/sdk/python/turna_sdk.py` — mTLS required by the constructor.

### Verified in this pass

Measured, not argued. Each of these is an observation.

- **112 000 relayed packets/second** on a 32-thread Threadripper 1950X, 120 s,
  zero loss, zero egress drops. Measured twice, identically. The failure above it
  is a cliff, not a slope: 120 000 fails and 128 000 sheds a million frames in two
  minutes. There is no warning band.
- **DTLS demux path: 9 of 9.** Relays 21 612 frames with 12 concurrent sessions,
  reloads certificates live (0 → 1, no failures), and the per-IP handshake rate
  limiter refused 15 handshakes before any DTLS state was created. Both §7 P0
  requirements that the stock path cannot provide.
- **Mixed UDP + TURNS: no node interference.** Zero loss on both transports in
  both phases, no egress drops.
- **Air-gap: 7 of 7**, re-verified after all of the above.
- **Reproducible builds: 3 of 3** binaries byte-identical from different build
  directories, re-verified.
- **Certificate rotation under load:** counter 0 → 1, no reload failures, 36 021
  frames relayed with zero errors across the swap.
- **Drain with abandoned allocations: 1 second**, down from the full 30-second
  timeout.

### Known limitations — found by the above

- **The shared secret cannot be rotated without a restart.** No signal handler
  (`SIGHUP` is not handled) and `UpdateConfig` carries allocation limits, not the
  secret. So §7's rotation-without-downtime holds for certificates and not for the
  credential a leak would force you to change. Ephemeral credentials expire on
  their own, which softens it; the secret they derive from still needs a restart.

- **`turna_dtls_handshake_failures_total` did not move** when malformed datagrams
  were sent at the DTLS port. Possibly correct — the datagram may be discarded
  before the DTLS state machine engages — but it means that check did not exercise
  the counter, and the counter is documented as honest only on the demux path.

- **The mixed-load result held the wrong thing constant.** Loss was zero
  throughout, and the TLS *generator* sent 17 % fewer frames in the mixed phase
  (72 012 → 60 010) while UDP sent the same (180 060 → 180 059). The node
  delivered everything it was given; the generators were competing for the cores
  they share. Generators on separate hosts would settle it.

- **The DTLS demux path has no 24-hour run.** Nine checks over five minutes say it
  is correct; the stock path holds the default on the strength of a recorded 24
  hours, and correctness is a different claim from stability.

### Documentation — corrections, not polish

- `docs/capacity/threadripper-1950x-2026-08-26.md` — the measured ceiling, the
  curve, and three wrong numbers that preceded it.
- `docs/verification/runs-2026-08-28.md` — every run, and three conclusions of
  mine that the runs overturned.
- `docs/security/security-profile.md` — one hardening checklist instead of a dozen
  scattered documents.
- `docs/security/log-data-audit-2026-08-27.md` and `log-data-audit-transports.md`
  — what the logs contain, including the negative results.
- `docs/deployment/enterprise-network-profile.md` — ports, the proxy matrix, and
  the case where a system HTTP proxy silently prevents WebTransport with zero
  packets reaching the node.
- `docs/deployment/host-tuning.md` — from measurements on this project's hardware,
  with the IRQ and RSS advice marked as not verified here.
- `docs/runbooks/disaster-recovery.md` — and a table of which scenarios have
  actually been rehearsed.
- `docs/SUPPORT-POLICY-OPTIONS.md` — four LTS options priced in work visible in
  this repository, and the observation that turna is 0.3.1, so an LTS channel on a
  0.x version means the version number and the support policy say different
  things.
- **A factor-of-two claim about the capacity figure was removed because it was
  wrong.** `sent ≈ recv` in the profile was read as evidence of a round trip; the
  receive task listens on the peer socket, so it is one traversal. The forecast had
  been doubling — 26 nodes where 13 are needed.
