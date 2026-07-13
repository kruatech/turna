# turna — Security hardening & operational notes

Status of the production-hardening pass on `turna` (0.2.0-alpha.1 -> 0.3.0-beta.1). Every item
below was verified against the source in this review; nothing here is inferred.

Suggested home in-repo: `docs/SECURITY_OPS.md`.

---

## 1. Hardening applied in this pass

All items landed as surgical edits with unit/stress tests where the surface was
testable. P0 blockers are closed in code.

| ID | Area | Change |
|----|------|--------|
| F1 | proto-stun `integrity.rs` | SHA256 MESSAGE-INTEGRITY rejects tags with length `<16`, `>32`, or not a multiple of 4 before truncated verify — closes the SHA256 downgrade/forgery path. |
| B1 | session `create_for_tenant` | Duplicate-client insert made atomic via `entry()` (loser → `AllocationExists` → 437). |
| B1-quotas | session | Global + per-tenant caps now use atomic counters (`fetch_add`→check→rollback) instead of racy `len()`/scan; released on `remove`/`force_remove` (covers Refresh lifetime=0, expiry sweep, revocation). `re_key` is a move and does not touch counters. Stress test: 100 racing Allocate at max=10 → stored count ≤ 10. |
| B2 | relay `processor.rs` | Bandwidth cap enforced on all three relay paths (channel-data, Send indication egress, peer→client). Note: `max_bytes_per_sec_per_allocation` now bounds both directions on a shared per-allocation window. |
| B3 | config | `cluster_mode=true` with an empty `cluster_secret` is a hard startup error. |
| B4 | session | Per-user allocation tracking re-keyed from bare `username` to `(realm, tenant, username)` — closes cross-realm and cross-tenant quota collisions. The key is derived from the authenticated realm and the allocation's tenant. |
| B5 | session + processor | Per-allocation caps: 256 permissions, 256 channel bindings (refresh exempt; over-cap → 486); 32 peers per CreatePermission (→ 400). |
| I1 | proto-stun `message.rs` | MESSAGE-INTEGRITY / -SHA256 verification fails if any non-FINGERPRINT attribute follows it (closes trailing-attribute signature bypass). |
| I2 | proto-stun `attribute.rs` | Strict exact-length parsing for REQUESTED-TRANSPORT, CHANNEL-NUMBER, DONT-FRAGMENT, EVEN-PORT (+reserved bits), RESERVATION-TOKEN. |
| I3 | proto-stun + processor | Unknown comprehension-required attributes (`type < 0x8000`) in a request → 420 + UNKNOWN-ATTRIBUTES. 0x001C (MI-SHA256) and 0x001D (PASSWORD-ALGORITHM) are allowlisted (understood despite generic parse). |
| I4 | proto-stun `header.rs`/`error.rs` | Reject message types with the top two bits set; unknown method → `UnknownMethod` (was mis-mapped to `UnknownAttribute`). |
| I6 | node `main.rs` | Cluster-mode nodes flip to `Readiness::Degraded` (→ `/ready` 503) while persistence write-drops are increasing; recover to `Ready` when they stop. Never overrides `Draining`. Single-node stays `Ready`. |
| I7 | processor + server | Idle rate-limiter buckets reclaimed on a maintenance tick (600s idle). |
| I8 | config | Tenant `shared_secret` equal to the built-in default is a production startup error. |
| I10 | management `lib.rs` | `serve_management` refuses to bind a non-loopback address unless `TURNA_ALLOW_PLAINTEXT_MANAGEMENT=1`. |
| I12 | processor | Binding integrity check accepts both MESSAGE-INTEGRITY and MI-SHA256. |
| B6 | transport `quic.rs`/`af_xdp.rs`, node `quic_listener.rs`/`af_xdp_listener.rs`, `neighbor.rs` | QUIC outbound and AF_XDP neighbor-resolve channels converted from unbounded to bounded (cap 1024); producers use `try_send` and drop on full. QUIC drops increment `send_errors` (mirrored to `quic_send_errors`). |
| M1–M7 | various | Software version from `CARGO_PKG_VERSION`; stale comments fixed; long-term unknown-user timing mitigation; migration lifetime=0 handling; dead `qos/backpressure.rs` removed; `unwrap`→`expect` in credential gen. |

Constants introduced (compile-time, not config): per-allocation 256 permissions /
256 channels / 32 peers-per-CreatePermission; queue depths 1024.

---

## 2. Confirmed known-limitations (deployment guidance)

These are properties of the current design, verified in code. They are not bugs
to fix blindly; they are constraints operators must account for.

### 2.1 Tarantool state-backend link is authenticated but not encrypted (D6)
`crates/state-backend/src/tarantool.rs` speaks iproto over plain `TcpStream`
(port 3301) with a chap-sha1 AUTH handshake. Credentials are protected by the
handshake, but allocation state on the wire is **plaintext**.
**Deploy on a trusted network segment, or tunnel it** (WireGuard / stunnel / a
service mesh). Do not route it across an untrusted network as-is.

### 2.2 Plaintext HTTP management interface (I10)
`turna_management::serve_management` is a plaintext, unauthenticated HTTP
interface exposing user CRUD. It is **not wired into any production binary** —
the production control plane is the mTLS gRPC server
(`services/control-plane`, default port 5350). The listener now refuses
non-loopback binds without `TURNA_ALLOW_PLAINTEXT_MANAGEMENT=1`.
**Use the mTLS gRPC control plane in production.** Treat the HTTP interface as
dev/loopback-only.

### 2.3 Bootstrap-admin on first registration (I11)
`UserStore::register` grants `Admin` to the first account created
(`self.users.is_empty()`). This store is **not reachable from any RPC or HTTP
endpoint** in the codebase (the gRPC surface exposes `add_user` for TURN
credentials, a different store; there is no `register` RPC).
**Keep operator-account registration off any public surface; bootstrap the
first admin offline (CLI/provisioning).** If a public registration endpoint is
ever added, gate the auto-admin promotion behind an explicit one-time
bootstrap token/flag before wiring it.

### 2.4 Experimental transports and B6 scope
The bounded-queue fix (B6) matters only when the experimental `quic` /
`web-transport` / `af-xdp` features are compiled in. In the default production
profile these are off. Queue caps (1024) and the AF_XDP neighbor-resolve
drop-on-miss are safe defaults; revisit them if you enable these transports at
scale.

### 2.5 Bandwidth cap is bidirectional on a shared window (B2)
`max_bytes_per_sec_per_allocation` now accounts for both client→peer and peer→client bytes on
one per-allocation window. If you previously reasoned about it as one-directional,
budget accordingly.

---

## 3. Explicitly NOT limitations (checked, found correct)

- **Permission / channel expiry survives persistence.** `writer.rs` stores
  `peer_ip → expires_at_ms` and `channel → (peer, expires_at_ms)`, and
  `rehydrate` restores them with their remaining lifetime. A common assumption
  that expiry is dropped on persist does **not** apply to this code.
- **Restored allocations keep their tenant.** `rehydrate` derives `tenant_id`
  from the port's owning pool (`tenant_id_for_port`), so per-tenant counters and
  keys stay correct after failover.

---

## 4. Verification still owed (cannot be closed by code review)

These need runtime, external tools, or a Linux/hardware setup — they are the
team's to run, not fixable in a patch.

- **B1 concurrency proof:** run the existing stress test under `loom`
  (~10⁴ interleavings) in addition to the thread-based test already added.
- **Per-feature build matrix (CI gate):** build/clippy each feature combination,
  including the no-feature build (to keep `#[cfg]` gating honest) and the
  Linux-only `af-xdp` path (the `build.rs` panics by design off-Linux).
- **Interop:** coturn and real browser (WebRTC) allocate/permission/channel flows.
- **Tarantool failover:** kill/restart backend under load; confirm rehydrate
  restores allocations and the I6 degraded→ready transition behaves.
- **Load / soak:** sustained throughput + multi-hour soak for leaks and counter
  drift (global/tenant/user counters vs actual map size).
- **Fuzzing:** extend STUN/TURN parser fuzz corpus around the new strict-length
  (I2) and 420 (I3) paths.
- **Dashboards/alerts:** wire `tarantool_writes_dropped_total`,
  `quic_send_errors`, `turna_backend_readiness`, and per-tenant/global allocation
  counters into monitoring; alert on Degraded readiness and write-drops.

---

## 5. Remaining runtime verification

The production unlimited-bandwidth guard, live user deletion diff-sync, and
EVEN-PORT create-error cleanup are implemented in source. They remain subject to
the final workspace, Tarantool, and live TURN verification gates listed in §4;
this document does not claim those runtime checks have been executed.
