# TURNA Management API

Canonical reference for the management-plane RPC contract. Where another
document touches these RPCs it should summarize and link here rather than
restate the contract.

> Status legend used in this document: **implemented** (present in code),
> **covered by tests** (has automated regression coverage), **requires final
> verification** (not yet confirmed by a stand/soak run). No claim of
> "production verified" is made from static implementation alone.
>
> Version note: this document tracks release `0.3.1`
> (`[workspace.package].version`). The wire contract is taken from
> `crates/control/proto/management.proto`.

## 11.1 API overview

- **Proto package:** `turna.management.v1`
- **Service:** `TurnaManagement` (`crates/control/proto/management.proto`)
- **Transport:** gRPC over HTTP/2 (tonic server, `start_grpc_server`).
- **TLS / mTLS:** server TLS is configured via `GrpcTlsConfig`. When
  `require_client_auth = true`, the server requires and verifies a client
  certificate against the configured CA (mTLS). When `false`, transport is
  server-only TLS and clients must be authenticated by another mechanism.
- **Authentication / authorization:** privileged and mutating operations are
  gated by the audit/actor path; the audit log must be healthy or mutations
  fail closed (`FAILED_PRECONDITION`). Deployments must not expose the endpoint
  without TLS and an authenticating layer.
- **Timeout / retry policy:** mutations are idempotent (see 11.2); a client that
  does not observe a response may retry with the **same** `idempotency_key`.
- **Idempotency policy:** every mutation carries an `idempotency_key` scoped to
  one user intent. A retry with the same key and the same normalized payload
  returns the original outcome; the same key with a different payload is a
  conflict (see 11.3 and `docs/command-log-lease.md`).

## 11.2 Common mutation contract

Applies to `UpdateConfig`, `SetUserLimits`, `SetDraining`, `DeleteAllocation`.

- **`node_id`** — required and non-empty; identifies the target node.
- **`idempotency_key`** — required and non-empty; one key per user intent.
- **`reason`** — required for `UpdateConfig` and `SetUserLimits`; trimmed,
  non-empty, bounded in length, and free of control characters. The normalized
  value is what is stored in the audit trail. Empty/whitespace-only/oversized/
  control-character reasons are rejected with `INVALID_ARGUMENT`.
- **`expected_version`** — where applicable, an optimistic-concurrency (CAS)
  guard checked on the node against the current observed version.
- **Accepted is not applied.** A successful transport response means the command
  was processed to a terminal state; it does **not** by itself mean the change
  was applied. The applied/not-applied result is carried in the typed response
  (`terminal_status`), not in the gRPC status. Command completion (`done`) is a
  transport fact, not a business success.
- **Terminal result.** The typed business outcome is one of `applied`, `no_op`,
  `conflict`, `failed`, `superseded` (see `docs/command-log-lease.md`).
- **Audit.** An intent record is written durably before the operation and a
  completion record after it; if the intent cannot be made durable the operation
  is refused (fail-closed).
- **Retry rules.** Re-issuing the same intent (same key + same normalized
  payload) returns the stored outcome rather than re-applying the side effect.

Status: **implemented**; idempotent-retry, lost-completion recovery, and CAS
paths are **covered by tests**.

## 11.3 Error model

Two distinct channels carry failure information, and they must not be conflated:

1. **gRPC status** — request-level failures raised before or around command
   processing. These come from `CoreError`:

   | `CoreError`              | gRPC status            |
   | ------------------------ | ---------------------- |
   | `NotFound`               | `NOT_FOUND`            |
   | `AlreadyExists`          | `ALREADY_EXISTS`       |
   | `Invalid`                | `INVALID_ARGUMENT`     |
   | `FailedPrecondition`     | `FAILED_PRECONDITION`  |
   | `Internal`               | `INTERNAL`             |
   | `Unimplemented`          | `UNIMPLEMENTED`        |

2. **Business outcome** — the result of a command that was processed to a
   terminal state. Returned inside a **successful** (`OK`) transport response as
   `terminal_status`.

Mapping of common situations:

| Situation                                   | Channel            | Value                                   |
| ------------------------------------------- | ------------------ | --------------------------------------- |
| Missing/empty `node_id` / `idempotency_key` | gRPC status        | `INVALID_ARGUMENT`                       |
| Empty / oversized / control-char `reason`   | gRPC status        | `INVALID_ARGUMENT`                       |
| `UNSPECIFIED` scope                         | gRPC status        | `INVALID_ARGUMENT`                       |
| Finite lifetime above absolute ceiling      | gRPC status        | `INVALID_ARGUMENT`                       |
| Same idempotency key, different payload     | gRPC status        | `ALREADY_EXISTS`                         |
| Audit log unhealthy                         | gRPC status        | `FAILED_PRECONDITION`                    |
| Version (CAS) conflict                      | business outcome   | `OK` response, `terminal_status=conflict`|
| Applied / unchanged                         | business outcome   | `OK` response, `applied` / `no_op`       |
| Superseded by newer incarnation             | business outcome   | `OK` response, `terminal_status=superseded` |
| Apply failed / rolled back                  | business outcome   | `OK` response, `failed` (+ `rolled_back`)|

Note: a version conflict is a **business** outcome (`OK` transport,
`terminal_status=conflict`), not a gRPC `ABORTED`. Callers must inspect
`terminal_status`, not only the gRPC status.

Status: **implemented**; `CoreError` mapping and idempotency-conflict are
**covered by tests**.

## 11.4 `UpdateConfig`

Node-targeted mutation of the **dynamic** runtime whitelist only.

### Request (`UpdateConfigRequest`)

- `node_id` (5), `idempotency_key` (6), `expected_version` (7), `reason` (11).
- Optional patch fields: `max_allocations` (8), `max_allocations_per_user` (9),
  `max_bytes_per_sec_per_allocation` (10). Field numbers 1–4 are **reserved**
  (retired pre-GA local-mutation fields) and are not reused.

### Dynamic whitelist

Only these fields may be changed live: node-wide `max_allocations`,
default per-user allocations (`max_allocations_per_user`), and the
per-allocation bandwidth ceiling (`max_bytes_per_sec_per_allocation`).

### Excluded (not applied live)

Drain, listener, external IP, relay range, transport backend, credentials,
identity, and secrets are **not** part of `UpdateConfig`. Restart-required and
immutable-through-API fields are rejected or not applied live.

### Response (`UpdateConfigResponse`)

`request_id` (4), `previous_version` (5), `observed_version` (6), `changed` (7),
`applied` snapshot (8), `terminal_status` (9), `error` (10), `rolled_back` (11).
Fields 1–3 (`success`/`current`/`warnings`) are **reserved** (retired).

### Semantics

- **no_op** — identical desired content; the snapshot version does not advance.
- **conflict** — `expected_version` does not match the node's observed version.
- **restore** — after restart the confirmed observed configuration is restored
  for the management-backend profile.
- **retry** — same key + same payload returns the stored outcome.
- **lost-completion recovery** — if a completion is lost after the effect was
  applied, a later worker recognizes the operation identity in durable state and
  returns the original outcome without re-applying.

Status: **implemented**; no-op / conflict / restore / lost-completion are
**covered by tests**.

## 11.5 `SetUserLimits`

Global / tenant / user policy overrides.

### Request (`SetUserLimitsRequest`)

`node_id` (5), `target` (6), `idempotency_key` (7), `expected_version` (8),
`patch` (9), `reason` (10). Fields 1–4 are **reserved** (retired scalar
request, including the old `max_bandwidth_bps`/`max_lifetime`).

### Scope enum (`UserLimitScope`)

| Value          | Number | Subject fields required                          |
| -------------- | -----: | ------------------------------------------------ |
| `UNSPECIFIED`  | 0      | Rejected (`INVALID_ARGUMENT`)                    |
| `GLOBAL`       | 1      | No realm, tenant, or username                    |
| `TENANT`       | 2      | Realm + tenant; no username                      |
| `USER`         | 3      | Realm + username (tenant may be empty base realm)|

`UNSPECIFIED = 0` is the required-but-unset guard: a caller that forgets to set
the scope is rejected rather than silently treated as global.

### Limit value modes

Each patch field (`max_allocations`, `max_bytes_per_sec_per_allocation`,
`max_lifetime_secs`) carries an explicit mode; the four modes are strictly
separate and zero does not overload any of them:

- **inherit** — defer to the next broader scope / node default.
- **finite (`value`)** — a specific non-zero value (a `VALUE` mode with value 0
  is rejected; use `unlimited` or `disabled` explicitly).
- **unlimited** — no per-scope limit, subject to node ceilings (see below).
- **disabled** — the capability is turned off.

### Effective policy

- **Inheritance order:** user → tenant → global → node default.
- **Node ceiling caps overrides.** A finite node ceiling is a hard upper bound:
  a requested `finite` value above it, or `unlimited`, is clamped to the ceiling.
  `unlimited` on a user/tenant scope removes only the narrower override; it does
  **not** bypass a finite node ceiling. True unlimited requires the node-wide
  policy to permit it.
- **requested vs effective.** Enforcement always uses the effective (possibly
  clamped) value. Fields whose requested value was clamped are reported in
  `effective.capped_fields`; inherited fields in `effective.inherited_fields`.
- **Lowering a cap below current usage** does not tear down existing
  allocations; it blocks new ones until usage falls under the new cap.

### Bandwidth (per-allocation)

The bandwidth policy is selected for a user through global/tenant/user
inheritance, but the resulting effective budget is applied **separately to each
allocation**. Multiple allocations of one user have independent budgets; this is
**not** an aggregate per-user bandwidth limiter.

### Lifetime

Effective lifetime is the minimum of the absolute protocol maximum, the
node-wide ceiling, the tenant override, the user override, and the OAuth/token
lifetime chosen at allocation time. A finite requested lifetime above the
node's absolute ceiling is rejected with `INVALID_ARGUMENT` before it can enter
the command log.

### Response (`SetUserLimitsResponse`)

`request_id` (2), `previous_version` (3), `observed_version` (4),
`effective` (5), `max_user_allocations_in_scope` (6),
`max_user_allocations_above_limit` (7), `terminal_status` (8), `error` (9).
Field 1 (`success`) is **reserved**.

Usage fields (unambiguous, not aggregates):

- `max_user_allocations_in_scope` — USER scope: the target user's live
  allocation count; GLOBAL/TENANT scope: the highest allocation count held by
  any **one** user in that scope (worst-case user for per-user cap enforcement),
  **not** a scope-wide total.
- `max_user_allocations_above_limit` — true when the above exceeds the effective
  per-user cap (or the cap is disabled and any usage exists); always false when
  the cap is unlimited.

`effective` (`EffectiveUserLimits`) fields: `max_allocations` (1),
`max_bytes_per_sec_per_allocation` (2), `max_lifetime_secs` (3),
`inherited_fields` (4), `allocations_disabled` (5), `bandwidth_disabled` (6),
`lifetime_disabled` (7), `capped_fields` (8).

Status: **implemented**; capping, per-allocation bandwidth, lifetime reject,
scope validation, and usage semantics are **covered by tests**.

## 11.6 `GetConfig` → `NodeRuntimeConfig`

Read-only view of a node's runtime configuration state.

Request: `GetConfigRequest { node_id }`. Response `NodeRuntimeConfig`:
`node_id` (1), `desired_version` (2), `observed_version` (3), `observed`
snapshot (4), `pending_desired` snapshot (5), `status` (6), `last_apply_error`
(7), `updated_at_ms` (8).

- **desired version** is the version the management plane requested;
  **observed version** is the version the node actually applies. They are
  distinct and must not be used as synonyms.
- Both are unsigned 64-bit and compared with exact CAS across the full `u64`
  range (never routed through a floating-point value, so precision is exact
  above 2^53); an increment at `u64::MAX` is refused with an error and leaves
  state unchanged rather than wrapping or saturating.
- A pending/rollback state is visible via `status`, `pending_desired`, and
  `last_apply_error`.

Status: **implemented**.

## 11.7 Stats scope (`GetServerStats` → `ServerStats`)

- `backend_mode` reports the configured backend/profile.
- Some gauges are node-local and some are cluster-wide; interpret them by
  `backend_mode`.
- Zero runtime gauges reported by a control-plane view do **not** imply the
  absence of traffic in the cluster — they may be node-local counters not held
  by the queried component.

Status: **implemented**.

## 11.8 `SetDraining`

Request: `SetDrainingRequest { draining, node_id, idempotency_key }`. Response:
`SetDrainingResponse { success, active_allocations }`.

- Sets the node's local draining state immediately and publishes `leaving` at
  the **start** of drain.
- New allocations are redirected or rejected while draining.
- The process waits until the grace deadline (`drain_grace_secs`, default is a
  short window and is **not** a guarantee that long sessions survive); active
  allocations may be dropped after the deadline.
- Idempotent; undrain is expressed by setting `draining = false`.

Status: **implemented**.

## 11.9 `DeleteAllocation`

Request: `DeleteAllocationRequest { id, ... , idempotency_key }` (destructive ops
may require an idempotency key in high-assurance mode). Response:
`DeleteAllocationResponse { success }`.

- Targets an allocation by id on its owning node.
- Idempotent: a retry after the allocation is already gone is a no-op success
  (not-found is treated as already-deleted for retry safety).

Status: **implemented**.

## 11.10 Compatibility policy (pre-GA)

- **Protobuf field numbers are preserved.** Retired pre-GA fields are marked
  `reserved` (numbers and names) rather than reused with new meaning — see
  `UpdateConfigRequest` (1–4), `UpdateConfigResponse` (1–3),
  `SetUserLimitsRequest` (1–4), `SetUserLimitsResponse` (1).
- **Source-breaking renames.** The bandwidth quota field was renamed to
  `max_bytes_per_sec_per_allocation` at the source/JSON level; the protobuf
  field number is unchanged. Durable command/state JSON written with the old
  key is still read (deserialization alias). This is a pre-GA breaking rename at
  the source/JSON layer without a parallel alias beyond durable-read
  compatibility.
- **Enum change.** `UserLimitScope` uses `UNSPECIFIED = 0`, `GLOBAL = 1`,
  `TENANT = 2`, `USER = 3`. Numeric `0` is no longer `GLOBAL`.
- **New mandatory fields.** `node_id`, `idempotency_key`, `expected_version`
  (where applicable), and `reason` are required on the relevant mutations.
- **Migration.** Old Tarantool schema requires the bounded/resumable migration
  (commands → idempotency → complete phases); see `docs/command-log-lease.md`
  and `RELEASE.md`.
- **Client impact.** Old clients that relied on the retired scalar request
  layout, `GLOBAL = 0`, or the old bandwidth/usage field names must be updated.

Status: **implemented**; wire field-number preservation is **covered by tests**.
End-to-end interop with external clients **requires final verification**.
