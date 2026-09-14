# CHANGELOG — pending section

Entries accumulate here between releases and move into `CHANGELOG.md` under a
version heading at release time; the last move was 0.4.0.

### Changed — read this one first

- **`[turn.dtls] demux` now defaults to `true`.** A config with
  `[turn.dtls] enabled = true` and no `demux` key takes the demultiplexer path
  after upgrading, where before it took `webrtc_dtls::listener::listen()`.

  The stock listener held the default because it was the path with a recorded
  24-hour run — not because it was better. Two §7 P0 requirements are unreachable
  on it rather than unimplemented: `listen()` owns the socket and fixes its
  certificate at bind time, and the handshake completes below `accept()` where
  nothing can rate-limit it.

  Both halves of the evidence are now on record. Correctness:
  `scripts/verify/dtls-demux.sh`, 9 of 9, including the per-IP handshake limiter
  refusing 15 handshakes before any DTLS state was created. Stability:
  `docs/soak/soak-24h-dtls-2026-09-01.md` — 24 hours, eleven DTLS cycles identical
  to three significant figures, a spread of 16 frames in 1.7 million, zero egress
  drops, and the node exiting cleanly on SIGTERM.

  *To keep the previous behaviour:* set `demux = false`. Note that
  `cert_reload_secs` and `max_handshakes_per_sec_per_ip` must then be removed —
  validation refuses them on the stock path, because there they read as protection
  that is not there.

  *Not established:* a real NIC. The run was over loopback, and handshakes over a
  network lose packets — which is where a demultiplexer is most likely to differ
  from a listener that owns its socket.

### Added

- **Shared-secret rotation on SIGHUP, without a restart.** The two-secret window
  below shipped without a way to move between its steps: the secret was read once
  at startup, so every step meant a rolling restart. SIGHUP now re-reads the same
  config file and republishes the SharedSecret backends. Nothing else from the
  reloaded file is applied.

  A rotation is: new secret into `shared_secret`, old one into
  `previous_shared_secret`, `kill -HUP` each node, wait for
  `turna_auth_previous_secret_total` to flatten, remove the old secret, SIGHUP
  again.

  A signal rather than a management RPC, deliberately: the secret stays on the
  host, cannot land in an audit record, and needs no proto change. The reasoning,
  including why `UpdateConfig` was rejected, is in `docs/OPEN-DECISIONS.md` §0,
  which this closes.

  *Refused rather than half-applied:* a config that fails validation (secrets stay
  as they were), a changed realm, a tenant added since startup. All logged.
  Secrets are never logged, nor hashed into a log.

  *Not covered:* non-unix targets have no SIGHUP and still need a restart.
  `scripts/verify/rotation-under-load.sh` now runs its secret phase by default —
  it was disabled because it used to SIGHUP a node with no handler, killing it,
  after which every remaining assertion passed against the dead process.

- **Two shared secrets during a rotation window** — `[turn.auth]
  previous_shared_secret`, and the same key per tenant. Rotating the secret used to
  invalidate every credential already issued, so the documented workaround was to
  schedule a low-traffic window. With this set, credentials signed with either
  validate.

  `turna_auth_previous_secret_total` counts what still uses the old one. That
  counter is not an extra: a rotation ends by removing the old secret, and without
  a number an operator cannot tell whether that is safe.

- **`[turn.auth] require_sha256`** refuses clients that can only do MD5 long-term
  keys. SHA-256 was already preferred when a client advertises it; the fallback was
  silent. Off by default — most deployed TURN clients predate RFC 8489.

### Fixed

- **An IPv6 `[turn] external_ip` silently broke RFC 6062 TCP relaying.** A v6
  literal there is legal and only changes what is advertised for v4-family
  allocations — except for TCP allocations, whose relayed listener binds
  `0.0.0.0`. A client that sent no `REQUESTED-ADDRESS-FAMILY` got a SUCCESS
  carrying a v6 relayed address that nothing served, so peer-initiated
  connections could never arrive, with nothing logged. Now answered `440`, the
  same as an explicit IPv6 request, with the reason logged.

- **`rtnetlink` 0.21 → 0.23**, which drops RUSTSEC-2024-0436 (`paste`
  unmaintained) from the tree rather than ignoring it: `netlink-packet-core`
  0.8.1 was the only package pulling it, and 0.9.0 has no dependencies at all.
  The `deny.toml` ignore was removed, not silenced. No code change — the API
  `neighbor.rs` uses is unchanged across the bump, verified by diffing the
  published sources.

- **`osv-scanner.toml` still ignored an advisory `deny.toml` had dropped.** That
  file opens by saying it is "kept in sync with the [advisories].ignore list in
  deny.toml", and nothing enforced it — so removing RUSTSEC-2024-0436 from one
  left the other claiming turna still accepts it. cargo-deny gates CI from the
  first; OSSF Scorecard's Vulnerabilities check reads only the second, so the two
  tools would have reported different risk postures. Synced, with a gate on the
  invariant the file states about itself.

  Four places still named `rtnetlink 0.21 / netlink-packet-route 0.30` after the
  bump, including the `neighbor.rs` header that records which versions its
  netlink wire-format handling was grounded against. Corrected.

- **Worked configuration examples** under `deploy/examples/`: `public-turn.toml`
  (internet-facing, REST credentials, secure peer filter, every quota set),
  `corporate.toml` (TURNS on 443, named users, `lan` peer filter with a deny list
  and a note on why that setting is the dangerous one), `cluster.toml` (gossip
  plus Tarantool, with the experimental caveat up front).

  They are not prose. Each is included in the `check-doc-claims` config-key gate,
  and CI now loads all three through the real validator with `production = true`
  — the strict branch, which the default Helm render does not exercise. An
  example that does not load is worse than none: it gets copied, edited, and the
  failure is blamed on the edit.

- **Tarantool schema-migration runbook**
  (`docs/runbooks/tarantool-schema-migration.md`). Opens by separating the two
  things called "migration" here, because confusing them is the main way this goes
  wrong: `init.lua` provisioning, which is idempotent and whose upgrade procedure
  is "run it again", and the bounded command-log backfill inside the node, which
  runs itself and gates the management plane while it works.

  The part worth writing down is what idempotence does **not** cover:
  `if_not_exists` creates what is missing and never alters what exists, so a
  changed field type or index part leaves the old shape in place, silently. No
  current change needs that; the composite key discussed for
  `ADDITIONAL-ADDRESS-FAMILY` would, which is why its design doc asks for a
  documented procedure and a rollback.

  Also: the three Lua suites are named as the contract for the stored functions
  (they now run in CI), and schema rollback is stated as unsupported with the
  reason — `if_not_exists` has no inverse, so the backup taken in step 1 is the
  rollback.

- **Kubernetes + Tarantool runbook** (`docs/runbooks/kubernetes-tarantool.md`).
  Provisioning order — schema before pods, with three checks that must print
  `true` — the Secret wiring for the backend password, the two settings that
  refuse to start (`write_behind` on a memory backend; cluster mode on one) and
  the one that does not, what to watch afterwards, and the NetworkPolicy's
  relationship to ports the chart cannot configure anyway.

  It opens with what the chart does **not** do, because two of those limits
  surprise people at the wrong moment: no ops API and no encrypted transports.
  Every metric it names was checked against the health crate — the first draft
  named two that do not exist (`turna_tarantool_pool_broken`,
  `turna_persistence_dropped_total`; the real series are `tarantool_*` without the
  `turna_` prefix), which would have given the reader a permanently empty panel
  that reads as health.

- **Seven of `turnactl`'s eleven documented commands cannot work.** Its header
  listed all eleven as if they did. `ManagementClient::send` sends four as plain
  GETs to the health server — `ping`, `status`, `allocations count`,
  `cluster nodes` — and those are fine, and `user add` / `user remove` go over
  gRPC to the control plane. **Everything else POSTs to `/manage`, and nothing in
  the workspace serves that path:**

  * the health server routes `/capacity /cluster /health /metrics /ready /status`
    and no more, and `--addr` defaults to its port;
  * the `("POST", "/manage")` handler in `turna_management` belongs to
    `integration::serve`, which has no callers — the crate is depended on only by
    `turnactl`, and only for its client half;
  * `services/admin` serves `/api/manage`: different path, port and protocol.

  So `failover status`, `drain`, `undrain`, `allocations list|get|kill` and
  `rooms list` fail against a healthy node — and the error reads "Is turna-node
  running with management API on 127.0.0.1:9090?", sending the operator to debug a
  deployment that is fine. The client's own comment says the server would be on
  9091 while the default is 9090, so the halves never agreed even in intent.

  `rooms list` is doubly dead: it needs `StoreHandler::list_rooms`, and
  `StoreHandler` has no implementation anywhere — there is no rooms feature and no
  `turna-signaling` binary.

  The header now says exactly which commands reach a server and why the rest do
  not, with a two-way gate. Wire it or delete it is decision 8 in
  `docs/OPEN-DECISIONS.md`; the gRPC control plane already covers allocations,
  drain, users and config, with authentication, RBAC and an audit trail this HTTP
  surface has none of. No code removed.

- **73 Prometheus alert rules that nothing validated.** Kubernetes manifests are
  checked offline with kubeconform; the rules in `docs/alerts/` were checked by
  nothing, so a malformed expression — an unbalanced paren, an unknown function,
  a bad `for:` duration — surfaced when an operator loaded the file into their own
  Prometheus. `promtool check rules` now runs in the same offline-validation job.

  All 73 pass today; this was verified with a real promtool before the step was
  added, along with each failure mode it is meant to catch. The rules were also
  audited for the semantic errors promtool cannot see — `rate()` over a gauge, a
  counter compared without `rate()`, a division that yields NaN on a zero
  denominator — and had none of them. The extractor's own coverage was checked
  first: 73 of 73 expressions parsed, so "no problems" means something.

- **A gate for the admin UI / admin service command boundary.** The two meet over
  JSON (`POST /api/manage` with a command name), so nothing compiles them
  together — the same shape that let the Python SDK drift, minus a compiler on
  either side. All 13 commands the UI sends are handled today; the gate keeps it
  that way. Its extractor fails loudly if it parses nothing, rather than passing
  on an empty set.

  Parameters are deliberately **not** checked. The service reads some through
  helpers (`u32_limit(params, "max_allocations")`) rather than `params["..."]`,
  and a first extractor that missed those produced a false positive. A gate that
  cries wolf gets ignored, which is worse than the gap it covers; the frontend's
  TypeScript already makes the required parameters non-optional.

- **The Helm chart serves plain UDP TURN only, and said so nowhere.** Its
  ConfigMap has nine sections — no `[tls]`, no `[turn.dtls]`, no `[turn.quic]` —
  and no `extraConfig` hook, so TURNS, DTLS and QUIC/WebTransport cannot be
  enabled through it at all. The node supports them and CI now exercises two of
  them end to end; they are simply out of the chart's reach, because certificate
  material needs Secret mounting and a rotation story the chart does not have.

  That is a defensible scope. What was not defensible is that the README offered
  the chart as *the* Kubernetes path with no caveat, so an operator needing TURNS
  in Kubernetes discovered the limit by reading the template. Now stated in the
  README, in `values.yaml`, and at the top of the ConfigMap, with a two-way gate:
  if the chart gains an encrypted-transport section the notes must go, or they
  become the false claim instead.

  The chart also deploys **`turna-node` alone** — no `turna-control-plane`
  workload, no Service for the management port, `[management] enabled = false` on
  loopback. So there is no ops API in a chart deployment: `turnactl` and the admin
  console cannot reach it. They assume the single-host topology in
  `docs/admin/README.md` with the control plane on `127.0.0.1:5350`;
  `deploy/docker-compose.yml` runs the node alone for the same reason. Stated in
  the same three places, with the gate checking for an actual workload rather
  than a mention of one.

  `[turn.peer_filter]` is also absent, and that one is safe: its defaults are
  `internet-facing` with `allow_loopback_peers = false`, so omitting the section
  denies private and loopback peers rather than allowing them. Checked rather
  than assumed, and written down next to the scope note.

- **Two CI jobs that could report a clean run having done nothing.** The nightly
  fuzz workflow put `cargo fuzz list` into a variable and looped over it, skipping
  blank lines; an empty list meant zero iterations and `exit 0`. A cargo-fuzz
  whose output format changed, or a workspace it could not read, would have looked
  like a clean nightly indefinitely — and a nightly is exactly the job nobody
  watches. The list is now checked against the `[[bin]]` count in
  `fuzz/Cargo.toml`, and the loop counts what actually ran.

  `ci.yml`'s `fuzz-build` job smoke-ran five target names written out by hand, so
  a new target was built by one step and never run by the next. It now derives the
  list from the manifest, with the same guard.

- **Three Tarantool test suites that nothing ran.**
  `deploy/tarantool/tests/*_test.lua` pin the CAS semantics the failover claim
  depends on — migration idempotency, the exact-u64 parser, and the runtime /
  user-limits CAS round-trip including rollback on an injected write failure.
  `GA_FINAL_REPORT.md` documented the commands and no job used them, so the
  contract was unenforced in the one place where getting CAS wrong loses
  allocations silently. Added to the `failover-integration` job, which already
  has a Tarantool container up. Checked first that each suite exits non-zero on
  failure; a suite that printed FAIL and exited 0 would have made this a green
  step proving nothing.

- **1 310 lines of user/JWT auth that nothing calls, presented as a feature.**
  `turna-auth`'s `store.rs` (659), `rotation.rs` (403), `jwt.rs` (184) and
  `user.rs` (64) implement user registration, login, Argon2 password hashing, JWT
  signing, token revocation and a blacklist — and have **no callers outside the
  auth crate**. Verified per module by taking every `pub` item and searching the
  workspace: 0 of 3, 0 of 6, 0 of 5, 0 of 3. They reference each other and
  nothing else; their tests exercise code nothing runs.

  The crate header advertised them as "User auth (Phase 2)", which is how a
  reader concludes turna has platform user auth. It has the code, not the
  feature. This also explains why `TURNA_JWT_SECRET` — required by
  `UserStoreConfig::try_from_env` — is set nowhere: not in the Helm chart, not in
  a shipped config, not in the docs.

  **Superseded in 0.5.0: the four modules were deleted.** They were first marked
  unwired in the crate root and in each module, with a `check-doc-claims` gate
  holding the labels honest, and "wire it or delete it" was recorded as decision
  7 in `docs/OPEN-DECISIONS.md`. That decision is now closed as *delete*:
  authenticating users is the signalling service's job, and turna validates a
  TURN REST credential derived from `[turn.auth] shared_secret`. The
  `jsonwebtoken`, `argon2`, `password-hash` and `uuid` dependencies went with
  them, as did `TURNA_JWT_SECRET`. The gate now asserts the deletion instead of
  the labels: if one of these files returns it must have a caller outside the
  crate.

- **A second source of truth for the Tarantool schema that does not exist.**
  `tarantool::INIT_SCRIPT` was deleted, leaving a bare comment header where it had
  been — and five places went on describing it as live: `turna-state-backend`'s
  `lib.rs` said the init script "is embedded" in it, `deploy/tarantool/init.lua`
  carried a "change one place, change both" note, and the
  `ADDITIONAL-ADDRESS-FAMILY` migration plan — in `OPEN-DECISIONS.md`, its design
  doc and `protocol-gap.md` — budgeted for updating both files.

  So the Option-3 schema migration was costed for work that does not exist, and
  whoever started it would have gone looking for a constant that is not there. The
  schema is defined once, in `deploy/tarantool/init.lua`; the Rust backend calls
  the `turna_init_schema` stored function that file defines.

  The same doc comment also gave a setup command pointing at
  `deploy/tarantool_init.lua`, which is not a path in this repository — anyone who
  copied it got "No such file". Corrected to `deploy/tarantool/init.lua`, and
  `tarantoolctl` to `tt`.

- **The production Helm example was never parsed.** `helm template` with
  `values-production.example.yaml` went through kubeconform, which validates
  Kubernetes schema and knows nothing about `turn.toml`; only the *default*
  values had their rendered config parsed by turna-config. So the file operators
  are told to copy produced a config nothing checked — and `production = true` is
  precisely the branch the default render does not exercise (placeholder-secret
  refusal, the unlimited-bandwidth rule, write_behind on an in-memory backend, a
  non-loopback management listener). CI now renders and parses it too.

  The `check-doc-claims` config gate also reads the ConfigMap template directly:
  its keys are literal even though its values are Go-template expressions, so a
  key that no config struct declares is caught in the fast gate, on a machine
  with no helm.

- **Four methods of the Python SDK could not work.** `tools/sdk/python/turna_sdk.py`
  is shipped for operators and nothing ever compiled it against
  `management.proto`, so it drifted silently while the proto was restructured:

  * `allocations()` sent `limit`; the field is `page_size`.
  * `drain()` sent a `reason`; `SetDrainingRequest` has no such field. It carries
    `draining`, `node_id`, `idempotency_key`. `node_id` was never sent at all.
  * `delete_allocation()` sent `allocation_id`; the field is `id`.
  * `set_user_limits()` sent `username`, which is **`reserved`** — retired along
    with three siblings when that request became a `target` plus a tri-state
    `patch`, deliberately rather than reassigned.

  protobuf raises `ValueError` on an unknown field, so each of these failed
  before the call left the process. `set_user_limits` is rewritten to the current
  shape and now requires `expected_version`, for the same reason `update_config`
  does. `drain()` grew `node_id` and lost `reason`; record the reason in your own
  change log — the node's audit entry is keyed by the correlation id the client
  already sends.

  `scripts/check-doc-claims.sh` gained a gate that walks the SDK's AST and checks
  every `pb` field, enum and rpc against the proto, including `reserved` ones.

- **Two artefacts nobody was checking.** `scripts/check-doc-claims.sh` gained a
  gate for each.

  The Grafana dashboard shipped in `deploy/` is imported and then trusted, and a
  panel whose metric was renamed does not error — it draws an empty graph. On a
  wall display "no data" and "nothing happening" are the same picture. All 23
  metrics it names currently exist; the gate keeps it that way.

  The shipped configs (`turn.toml`, `deploy/turn.toml`, the two under `bench/`)
  are parsed with `deny_unknown_fields`, so a key that no longer exists is not
  ignored — the node refuses to start. A stale key is a startup failure waiting
  for whoever copies the file. None are stale today.

- **Six verification scripts passed when they could not measure.** A second pass
  over the same class as the SIGPIPE bug below, looking for checks that succeed
  for the wrong reason rather than checks that fail.

  `errs` was defaulted to `0` in `af-xdp-lab.sh`, `capacity-profile.sh` and
  `air-gap.sh`, so a load-tool JSON with no `errs` field read as "zero errors" and
  the phase passed unmeasured — while three sibling scripts already defaulted the
  same field to `1`. The same question was answered two ways in one directory; it
  is now required outright, and its absence names itself.

  `send_queue_dropped` was read as `... .get(..., 0) || echo 0` in
  `deployment-compliance.sh`, `capacity-profile.sh` and `mixed-load.sh`. Every way
  of failing to read it — endpoint down, malformed JSON, field renamed — became
  the number zero, and zero prints "no egress queue drops". In
  `capacity-profile.sh` it was worse than cosmetic: an unreadable `/status` made
  the per-phase delta negative, a negative is not `> 0`, and the phase kept its
  PASS, so a capacity ceiling could be set from a phase whose drops were never
  measured. Unreadable, absent and zero are now three different outcomes.

- **Five verification and CI scripts reported the opposite of the truth** under
  `set -o pipefail`. `printf ... | grep -q` lets grep exit at its first match, the
  writer dies of SIGPIPE, and the pipeline returns 141 — so a proto field that had
  not changed was reported as broken (about 1 run in 6), a declared Cargo feature
  as unknown, an existing `load-test` subcommand as missing, and, worst,
  `dtls-demux.sh` printed "port released" over a port that was still bound.

- **`--dump-config` printed the backend URI whole**, and a Tarantool URI is
  `user:password@host`. The password was disclosed on the line directly above one
  that carefully masks the password field.

- **`auth failed` was logged at WARN for requests with no credentials at all.**
  RFC 5389 §10.2 requires the client to send one, get 401 with a realm and nonce,
  and only then sign — so that was one warning per allocation attempt: 4.8 GB of
  log per hour at soak rates, which filled a 50 GB disk. Now DEBUG.
  `IntegrityFailed`, which means a wrong password, stays at WARN.
