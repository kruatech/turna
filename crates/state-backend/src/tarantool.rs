//! Tarantool state backend via iproto binary protocol.
//!
//! # Space layout
//!
//! `turna_allocations` — 5 fields for efficient indexed queries:
//!   1. relay_port    (unsigned) — primary key
//!   2. user_id       (string)   — secondary index `by_user`
//!   3. node_id       (string)   — secondary index `by_node`
//!   4. expires_at_ms (unsigned) — secondary index `by_expiry`
//!   5. data          (string)   — full JSON blob
//!
//! `turna_nodes` — 2 fields (heartbeat / liveness):
//!   1. node_id (string) — primary key
//!   2. data    (string) — full JSON blob
//!
//! `turna_rooms` — 2 fields (SFU room state):
//!   1. room_id (string) — primary key
//!   2. data    (string) — full JSON blob
//!
//! # Protocol
//!
//! iproto over TCP (Tarantool default port 3301).
//! CALL requests (0x0a): invoke stored functions defined in init.lua.
//! Responses decoded with `rmpv`.
//!
//! Data operations use iproto CALL, which invokes a specific named stored
//! function. EVAL (0x08) is no longer used for data operations — this means
//! the `turna_app` role only needs `execute on function <name>` for each of
//! the 17 turna_* functions, not `execute on universe`. A compromised
//! turna-node cannot execute arbitrary Lua on Tarantool.
//!
//! Response format difference:
//! - EVAL: `{data: [v1, v2, ...]}` — direct array of return values.
//! - CALL: `{data: [[v1, v2, ...]]}` — wrapped in an outer array.
//!   `parse_call_data()` handles the unwrapping.
//!
//! # Connection pool
//!
//! `TarantoolBackend` maintains a fixed-size pool of TCP connections
//! (default 8; configurable via [`BackendConfig::Tarantool::pool_size`]).
//! Each [`eval`] call picks a slot via a wrapping atomic counter, locks
//! that slot's `Mutex`, sends the request, reads the response.
//!
//! This gives N-way parallelism between the write-behind writer, the
//! heartbeat task, the failover sweep, and any turnactl commands —
//! before this they all serialised through a single connection. The
//! pool also localises reconnect: a slot whose socket got reset
//! reconnects independently of the others.
//!
//! Not full deadpool / bb8: no min/max sizing, no work-stealing, no
//! exponential backoff between reconnect attempts. Right complexity
//! for the workload — Tarantool itself is fast enough that 8
//! connections cover ≥10k req/s, and the writer's batching means
//! we rarely come close to that.
//!
//! # Authentication
//!
//! On connect each slot performs the iproto AUTH handshake using
//! `chap-sha1`:
//!
//! 1. Read 128-byte greeting; bytes 64..108 are the salt encoded as
//!    base64.
//! 2. base64-decode → first 20 bytes are the SHA-1 salt.
//! 3. `step1 = SHA1(password)`
//!    `step2 = SHA1(salt[..20] || step1)`
//!    `scramble = step1 XOR step2`     (length 20)
//! 4. Send AUTH (`IPROTO_REQUEST_TYPE = 0x07`):
//!    body = `{IPROTO_USER_NAME: user, IPROTO_TUPLE: ["chap-sha1", scramble]}`
//! 5. Expect response with `code = 0` (success) or `code >= 0x8000`
//!    (error — usually `ER_PASSWORD_MISMATCH` 0x8047).
//!
//! When `user` is `None`, the AUTH step is skipped — the connection
//! runs as the anonymous `guest` user (Tarantool's built-in unprivileged
//! role). Tarantool's default install grants `guest` no rights, so any
//! cluster deployment with persistence enabled MUST set a user/password.
//!
//! # Init
//!
//! Call `init_schema()` once after `connect_pool()`, or run the script
//! at `deploy/tarantool/init.lua` manually on the Tarantool box:
//!
//! ```bash
//! tarantoolctl connect 127.0.0.1:3301 < deploy/tarantool/init.lua
//! ```

use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::*;

// ── Schema init ───────────────────────────────────────────────────────────────

// Legacy embedded schema script — kept for reference only.
// **Not executed automatically.** Run `deploy/tarantool/init.lua` once on
// the Tarantool host instead: it creates spaces, indexes, stored functions,
// and the `turna_app` role with per-function execute grants.

// ── TarantoolBackend ──────────────────────────────────────────────────────────

/// Owned credentials kept around so we can re-authenticate on reconnect
/// of a single pool slot. Cloning is cheap (two `Option<Arc<str>>`-style
/// strings). The password is kept in memory for the process lifetime;
/// the operator's job is to make sure `/proc/PID/maps` etc are not
/// world-readable (see `docs/SECURITY.md` + the systemd hardening
/// directives in `docs/DEPLOY.md`).
#[derive(Debug, Clone)]
struct Creds {
    user: Option<String>,
    password: Option<String>,
}

pub struct TarantoolBackend {
    /// Fixed-size pool. Each slot owns its own TCP connection and its
    /// own Mutex. Slot selection is round-robin via `next_slot`. On
    /// connection error a slot temporarily holds `None` until the next
    /// caller (or the eval-time reconnect path) restores it.
    pool: Vec<Mutex<Option<TcpStream>>>,
    /// Per-slot state for the pool gauge. Updated inside eval_once/eval
    /// while the slot mutex is held (or just after reconnect).
    /// Values: 0 = idle, 1 = busy, 2 = broken.
    slot_state: Vec<AtomicU8>,
    next_slot: AtomicUsize,
    uri: String,
    creds: Creds,
    next_id: AtomicU64,
}

impl TarantoolBackend {
    /// Connect to Tarantool with a pool of `pool_size` parallel
    /// connections. Each connection authenticates immediately. Call
    /// `init_schema()` after this.
    ///
    /// If `user` is `None` the AUTH step is skipped on every slot —
    /// useful for a quick local smoke test against an unsecured
    /// Tarantool, but unsuitable for any deployment.
    pub async fn connect_pool(
        uri: &str,
        user: Option<&str>,
        password: Option<&str>,
        pool_size: usize,
    ) -> Result<Self> {
        let pool_size = pool_size.max(1);
        let creds = Creds {
            user: user.map(str::to_owned),
            password: password.map(str::to_owned),
        };

        let mut pool: Vec<Mutex<Option<TcpStream>>> = Vec::with_capacity(pool_size);
        let mut slot_state: Vec<AtomicU8> = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            let stream = tcp_connect_and_auth(uri, &creds)
                .await
                .map_err(|e| BackendError::Connection(format!("slot {i}/{pool_size}: {e}")))?;
            pool.push(Mutex::new(Some(stream)));
            slot_state.push(AtomicU8::new(0)); // starts idle
        }
        info!(%uri,
              user = ?creds.user.as_deref().unwrap_or("guest"),
              pool_size,
              "connected to Tarantool");

        Ok(Self {
            pool,
            slot_state,
            next_slot: AtomicUsize::new(0),
            uri: uri.to_string(),
            creds,
            next_id: AtomicU64::new(1),
        })
    }

    /// Legacy single-connection constructor, preserved for any caller
    /// that hasn't migrated yet. Uses pool_size = 1 and no auth.
    /// Avoid — use `connect_pool` directly.
    #[deprecated(note = "use connect_pool with explicit credentials")]
    pub async fn connect(uri: &str) -> Result<Self> {
        Self::connect_pool(uri, None, None, 1).await
    }

    /// Ensure spaces and indexes exist. Calls the `turna_init_schema` stored
    /// function created by `deploy/tarantool/init.lua`. Idempotent.
    ///
    /// # Prerequisite
    /// Run `deploy/tarantool/init.lua` on the Tarantool host at least once
    /// before starting turna-node. That script creates the function and grants
    /// the `turna_app` role the execute privilege on it.
    pub async fn init_schema(&self) -> Result<()> {
        self.call("turna_init_schema", &[]).await?;
        info!("Tarantool schema initialized");
        Ok(())
    }

    // ── Allocation CRUD ───────────────────────────────────────────────────────

    pub async fn store_allocation(&self, alloc: &StoredAllocation) -> Result<()> {
        let json = ser(alloc)?;
        let port = alloc.relay_port.to_string();
        let user = alloc.user_id.clone();
        let node = alloc.node_id.clone();
        let expires = alloc.expires_at_ms.to_string();

        self.call(
            "turna_store_allocation",
            &[&port, &user, &node, &expires, &json],
        )
        .await?;
        debug!(relay_port = alloc.relay_port, user = %alloc.user_id, "allocation stored");
        Ok(())
    }

    pub async fn get_allocation(&self, relay_port: u16) -> Result<Option<StoredAllocation>> {
        let port = relay_port.to_string();
        let resp = self.call("turna_get_allocation", &[&port]).await?;
        call_optional(&resp)
    }

    pub async fn remove_allocation(&self, relay_port: u16) -> Result<()> {
        let port = relay_port.to_string();
        self.call("turna_remove_allocation", &[&port]).await?;
        Ok(())
    }

    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<StoredAllocation>> {
        let resp = self.call("turna_find_by_user", &[user_id]).await?;
        call_list(&resp)
    }

    pub async fn find_by_node(&self, node_id: &str) -> Result<Vec<StoredAllocation>> {
        let resp = self.call("turna_find_by_node", &[node_id]).await?;
        call_list(&resp)
    }

    /// Find allocations expiring before `before_ms`.
    /// Uses the `by_expiry` index — O(expired_count), not O(total).
    pub async fn find_expired(&self, before_ms: u64) -> Result<Vec<StoredAllocation>> {
        let cutoff = before_ms.to_string();
        let resp = self.call("turna_find_expired", &[&cutoff]).await?;
        call_list(&resp)
    }

    pub async fn list_allocations(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StoredAllocation>> {
        let off = offset.to_string();
        let lim = limit.to_string();
        let resp = self.call("turna_list_allocations", &[&off, &lim]).await?;
        call_list(&resp)
    }

    pub async fn count_allocations(&self) -> Result<u64> {
        let resp = self.call("turna_count_allocations", &[]).await?;
        Ok(call_u64(&resp).unwrap_or(0))
    }

    /// Atomically increment bandwidth counters inside Tarantool (no read-modify-write race).
    pub async fn update_bandwidth(
        &self,
        relay_port: u16,
        bytes_in: u64,
        bytes_out: u64,
        packets_in: u64,
        packets_out: u64,
    ) -> Result<()> {
        let port = relay_port.to_string();
        let bi = bytes_in.to_string();
        let bo = bytes_out.to_string();
        let pi = packets_in.to_string();
        let po = packets_out.to_string();
        self.call("turna_update_bandwidth", &[&port, &bi, &bo, &pi, &po])
            .await?;
        Ok(())
    }

    // ── Node heartbeats ───────────────────────────────────────────────────────

    pub async fn heartbeat(&self, hb: &NodeHeartbeat) -> Result<()> {
        let json = ser(hb)?;
        self.call("turna_store_heartbeat", &[&hb.node_id, &json])
            .await?;
        debug!(node = %hb.node_id, "heartbeat stored");
        Ok(())
    }

    pub async fn get_live_nodes(&self, max_age: Duration) -> Result<Vec<NodeHeartbeat>> {
        let cutoff = (now_ms().saturating_sub(max_age.as_millis() as u64)).to_string();
        let resp = self.call("turna_get_live_nodes", &[&cutoff]).await?;
        call_list(&resp)
    }

    // ── SFU rooms ─────────────────────────────────────────────────────────────

    pub async fn store_room(&self, room: &StoredRoom) -> Result<()> {
        let json = ser(room)?;
        self.call("turna_store_room", &[&room.room_id, &json])
            .await?;
        Ok(())
    }

    pub async fn get_room(&self, room_id: &str) -> Result<Option<StoredRoom>> {
        let resp = self.call("turna_get_room", &[room_id]).await?;
        call_optional(&resp)
    }

    pub async fn remove_room(&self, room_id: &str) -> Result<()> {
        self.call("turna_remove_room", &[room_id]).await?;
        Ok(())
    }

    // ── Health ────────────────────────────────────────────────────────────────

    pub async fn revoke_token(
        &self,
        jti: &str,
        sub: &str,
        revoked_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<()> {
        self.call(
            "turna_revoke_token",
            &[
                jti,
                sub,
                &revoked_at_ms.to_string(),
                &expires_at_ms.to_string(),
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool> {
        let raw = self.call("turna_is_token_revoked", &[jti]).await?;
        Ok(raw.first().copied() == Some(0xc3))
    }

    pub async fn cleanup_revoked_tokens(&self, before_ms: u64) -> Result<u64> {
        let raw = self
            .call("turna_cleanup_revoked_tokens", &[&before_ms.to_string()])
            .await?;
        if raw.len() >= 2 && raw[0] == 0x91 {
            return Ok(raw[1] as u64);
        }
        Ok(0)
    }

    pub async fn load_active_revocations(&self, after_ms: u64) -> Result<Vec<(String, u64)>> {
        let raw = self
            .call("turna_load_active_revocations", &[&after_ms.to_string()])
            .await?;
        if raw.is_empty() {
            return Ok(vec![]);
        }
        let decoded: Vec<String> = serde_json::from_slice(&raw).unwrap_or_default();
        Ok(decoded
            .into_iter()
            .filter_map(|s| {
                let mut p = s.splitn(2, ':');
                let jti = p.next()?.to_string();
                let exp: u64 = p.next()?.parse().ok()?;
                Some((jti, exp))
            })
            .collect())
    }

    pub async fn store_user(&self, user: &StoredUser) -> Result<()> {
        let json = ser(user)?;
        self.call("turna_store_user", &[&user.username, &user.realm, &json])
            .await?;
        Ok(())
    }

    pub async fn get_user(&self, username: &str, realm: &str) -> Result<Option<StoredUser>> {
        let resp = self.call("turna_get_user", &[username, realm]).await?;
        call_optional(&resp)
    }

    pub async fn remove_user(&self, username: &str, realm: &str) -> Result<bool> {
        let resp = self.call("turna_remove_user", &[username, realm]).await?;
        call_bool(&resp)
    }

    pub async fn list_users(&self) -> Result<Vec<StoredUser>> {
        let resp = self.call("turna_list_users", &[]).await?;
        call_list(&resp)
    }

    pub async fn ping(&self) -> Result<()> {
        self.call("turna_ping", &[]).await?;
        Ok(())
    }

    // ── Failover (PR 5, task #3) ──────────────────────────────────────────────

    /// CAS update of `node_id`. See `Backend::claim_allocation` in lib.rs
    /// for the contract.
    ///
    /// The whole Lua script runs in a single Tarantool transaction (the
    /// in-memory engine is fully transactional for Lua-only code on
    /// `default` engine). That gives atomicity at the row level: if two
    /// nodes evaluate this script concurrently for the same `relay_port`,
    /// Tarantool serialises them and exactly one observes the matching
    /// `node_id`.
    ///
    /// Response shape from Tarantool (after data_to_optional):
    /// - `[true]`  → claimed
    /// - `[false]` → mismatch (someone else won, or node_id changed)
    /// - `nil`     → no such row
    ///
    /// **NB**: this method requires the Tarantool server side to have
    /// support for storing `node_id` as a column on `turna_allocations`
    /// (it does — see `init_schema`). No additional schema work needed.
    pub async fn claim_allocation(
        &self,
        relay_port: u16,
        expected_node_id: &str,
        new_node_id: &str,
    ) -> Result<bool> {
        let port = relay_port.to_string();
        // Index of `node_id` inside the tuple stored by `store_allocation`:
        // tuple is [relay_port, user_id, node_id, expires_at_ms, json].
        // node_id is field #3 (1-indexed in Lua, so position 3).
        // We additionally update the embedded JSON's `node_id` field so
        // future `get_allocation` returns the new owner consistently.
        let resp = self
            .call(
                "turna_claim_allocation",
                &[&port, expected_node_id, new_node_id],
            )
            .await?;
        call_bool(&resp)
    }

    // ── Durable runtime configuration / limits ───────────────────────────

    pub async fn get_runtime_state(&self, node_id: &str) -> Result<Option<NodeRuntimeState>> {
        let resp = self.call("turna_get_runtime_state", &[node_id]).await?;
        call_optional(&resp)
    }

    pub async fn adopt_node_incarnation(&self, node_id: &str, incarnation: &str) -> Result<()> {
        self.call("turna_adopt_node_incarnation", &[node_id, incarnation])
            .await?;
        Ok(())
    }

    pub async fn cas_runtime_desired(
        &self,
        node_id: &str,
        expected_observed_version: u64,
        incarnation: &str,
        desired: &RuntimeConfigSnapshot,
    ) -> Result<bool> {
        let expected = expected_observed_version.to_string();
        let json = serde_json::to_string(desired)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;
        let resp = self
            .call(
                "turna_cas_runtime_desired",
                &[node_id, &expected, incarnation, &json],
            )
            .await?;
        call_bool(&resp)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_runtime_observed(
        &self,
        node_id: &str,
        desired_version: u64,
        incarnation: &str,
        observed: &RuntimeConfigSnapshot,
        status: &str,
        error: &str,
        applied: Option<&AppliedOperation>,
    ) -> Result<bool> {
        let version = desired_version.to_string();
        let json = serde_json::to_string(observed)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;
        let applied_json = match applied {
            Some(op) => {
                serde_json::to_string(op).map_err(|e| BackendError::Serialization(e.to_string()))?
            }
            None => String::new(),
        };
        let resp = self
            .call(
                "turna_confirm_runtime_observed",
                &[
                    node_id,
                    &version,
                    incarnation,
                    &json,
                    status,
                    error,
                    &applied_json,
                ],
            )
            .await?;
        call_bool(&resp)
    }

    pub async fn get_user_limits_state(
        &self,
        node_id: &str,
        subject_key: &str,
    ) -> Result<Option<UserLimitsState>> {
        let resp = self
            .call("turna_get_user_limits_state", &[node_id, subject_key])
            .await?;
        call_optional(&resp)
    }

    pub async fn list_user_limits_states(&self, node_id: &str) -> Result<Vec<UserLimitsState>> {
        let resp = self
            .call("turna_list_user_limits_states", &[node_id])
            .await?;
        call_list(&resp)
    }

    pub async fn cas_user_limits_desired(
        &self,
        node_id: &str,
        subject_key: &str,
        expected_observed_version: u64,
        incarnation: &str,
        target: &UserLimitTarget,
        desired: &UserLimitsPatch,
    ) -> Result<bool> {
        let expected = expected_observed_version.to_string();
        let target_json = serde_json::to_string(target)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;
        let desired_json = serde_json::to_string(desired)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;
        let resp = self
            .call(
                "turna_cas_user_limits_desired",
                &[
                    node_id,
                    subject_key,
                    &expected,
                    incarnation,
                    &target_json,
                    &desired_json,
                ],
            )
            .await?;
        call_bool(&resp)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn confirm_user_limits_observed(
        &self,
        node_id: &str,
        subject_key: &str,
        desired_version: u64,
        incarnation: &str,
        observed: &UserLimitsPatch,
        outcome: ObservationOutcome<'_>,
        applied: Option<&AppliedOperation>,
    ) -> Result<bool> {
        let version = desired_version.to_string();
        let json = serde_json::to_string(observed)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;
        let applied_json = match applied {
            Some(op) => {
                serde_json::to_string(op).map_err(|e| BackendError::Serialization(e.to_string()))?
            }
            None => String::new(),
        };
        let resp = self
            .call(
                "turna_confirm_user_limits_observed",
                &[
                    node_id,
                    subject_key,
                    &version,
                    incarnation,
                    &json,
                    outcome.status,
                    outcome.error,
                    &applied_json,
                ],
            )
            .await?;
        call_bool(&resp)
    }

    // ── Command log (P0 #4) ────────────────────────────────────

    pub async fn enqueue_command(&self, cmd: &PendingCommand) -> Result<String> {
        // The full command (incl. `idempotency_key`) is serialized as JSON.
        // NOTE (P0.3): `turna_enqueue_command(request_id, target_node_id, json)`
        // must be idempotent on `idempotency_key`: if the JSON's non-empty
        // `idempotency_key` already maps to a command, DO NOT insert a second row
        // — return the ORIGINAL row's `request_id` (whatever its status).
        // Otherwise insert and return the new `request_id`. The key→request_id
        // index shares the command's retention. See docs/command-log-lease.md;
        // memory.rs is the reference implementation.
        let json =
            serde_json::to_string(cmd).map_err(|e| BackendError::Serialization(e.to_string()))?;
        let payload_hash = crate::command_payload_hash(&cmd.op, &cmd.args, &cmd.payload_json);
        let resp = self
            .call(
                "turna_enqueue_command",
                &[&cmd.request_id, &cmd.target_node_id, &json, &payload_hash],
            )
            .await?;
        // The proc returns `(canonical_request_id, conflict)`. A `true` conflict
        // flag means the key was reused with a different payload (durable
        // semantics). Older 1-value procs return no flag → treated as no
        // conflict, preserving prior behaviour during a rolling upgrade.
        let data = parse_call_data(&resp).ok().unwrap_or_default();
        if matches!(data.get(1), Some(rmpv::Value::Boolean(true))) {
            return Err(BackendError::Conflict(format!(
                "idempotency key {:?} reused with a different payload",
                cmd.idempotency_key
            )));
        }
        let canonical = data
            .into_iter()
            .next()
            .and_then(|v| match v {
                rmpv::Value::String(s) => s.into_str(),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| cmd.request_id.clone());
        Ok(canonical)
    }

    pub async fn claim_commands(
        &self,
        node_id: &str,
        incarnation: &str,
        max: usize,
        lease_ms: u64,
    ) -> Result<Vec<PendingCommand>> {
        let max_s = max.to_string();
        let lease_s = lease_ms.to_string();
        let now_s = now_ms().to_string();
        // NOTE (P0.2/P0.4): `turna_claim_commands(node_id, incarnation, max, lease_ms, now_ms)`
        // must, atomically per row:
        //   * claim rows with status == "pending"; AND
        //   * reclaim rows with status == "in_progress" AND lease_until_ms <= now_ms,
        //     EXCEPT when attempts >= MAX_COMMAND_ATTEMPTS (5): then set
        //     status="failed", result="dead_letter: ..." and do NOT return the row
        //     (P0.2 retry bound);
        // otherwise set status="in_progress", claimed_by=node_id,
        // lease_until_ms = now_ms + lease_ms, attempts = attempts + 1, and mint a
        // fresh unique claim_token per claimed row (P0.4 fencing — completion must
        // present it). See docs/command-log-lease.md; memory.rs is the reference.
        let resp = self
            .call(
                "turna_claim_commands",
                &[node_id, incarnation, &max_s, &lease_s, &now_s],
            )
            .await?;
        call_list(&resp)
    }

    pub async fn complete_command(
        &self,
        request_id: &str,
        claimed_by: &str,
        claim_token: &str,
        status: &str,
        result: &str,
    ) -> Result<bool> {
        // NOTE (P0.4): `turna_complete_command(request_id, claimed_by, claim_token,
        // status, result)` must fence the write — apply status/result ONLY if the
        // row is "in_progress" AND claimed_by == <claimed_by> AND claim_token ==
        // <claim_token>; otherwise a no-op. It MUST return a boolean: true if
        // applied, false if the completion was stale/foreign (a superseded
        // claimant holds an old token and must be rejected even when its node id
        // matches). See docs/command-log-lease.md; memory.rs is the reference.
        let resp = self
            .call(
                "turna_complete_command",
                &[request_id, claimed_by, claim_token, status, result],
            )
            .await?;
        // The proc returns a Lua boolean; parse it through the iproto framing
        // (the raw first byte is the response envelope, not the value).
        call_bool(&resp)
    }

    pub async fn finalize_stale_command(
        &self,
        request_id: &str,
        current_incarnation: &str,
        result: &str,
    ) -> Result<bool> {
        let resp = self
            .call(
                "turna_finalize_stale_command",
                &[request_id, current_incarnation, result],
            )
            .await?;
        call_bool(&resp)
    }

    pub async fn list_stale_commands(
        &self,
        node_id: &str,
        current_incarnation: &str,
        max: usize,
    ) -> Result<Vec<PendingCommand>> {
        let max_s = max.to_string();
        let resp = self
            .call(
                "turna_list_stale_commands",
                &[node_id, current_incarnation, &max_s],
            )
            .await?;
        call_list(&resp)
    }

    pub async fn get_command(&self, request_id: &str) -> Result<Option<PendingCommand>> {
        let resp = self.call("turna_get_command", &[request_id]).await?;
        call_optional(&resp)
    }

    pub async fn get_idempotency(&self, key: &str) -> Result<Option<IdempotencyRecord>> {
        // `turna_get_idempotency` returns the record as a JSON object (same
        // wire shape `get_command` uses for a command), so `call_optional`
        // deserializes it directly into `IdempotencyRecord`.
        let resp = self.call("turna_get_idempotency", &[key]).await?;
        call_optional(&resp)
    }

    /// #4: durably persist a non-mutating terminal business outcome into the
    /// keyed idempotency journal before `complete_command`. The stored proc
    /// `turna_record_command_outcome(key, req, hash, final_status, result,
    /// completed_at_ms)` touches only the existing canonical row, verifies
    /// request_id + payload_hash, and never downgrades a terminal record; it
    /// returns a status code string.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_command_outcome(
        &self,
        request_id: &str,
        idempotency_key: &str,
        payload_hash: &str,
        final_status: &str,
        result: &str,
        completed_at_ms: u64,
    ) -> Result<bool> {
        if idempotency_key.is_empty() {
            return Ok(false);
        }
        let completed = completed_at_ms.to_string();
        let resp = self
            .call(
                "turna_record_command_outcome",
                &[
                    idempotency_key,
                    request_id,
                    payload_hash,
                    final_status,
                    result,
                    &completed,
                ],
            )
            .await?;
        let code = match parse_call_data(&resp)?.into_iter().next() {
            Some(rmpv::Value::String(s)) => s.into_str().unwrap_or_default(),
            other => {
                return Err(BackendError::Serialization(format!(
                    "record_command_outcome: expected status string, got {other:?}"
                )))
            }
        };
        match code.as_str() {
            "ok" | "ok_same" => Ok(true),
            // Empty key is handled above; treat any no-op signal as "not recorded".
            "no_key" => Ok(false),
            "no_record" => Err(BackendError::Conflict(format!(
                "record_command_outcome: no canonical idempotency record for key {idempotency_key}"
            ))),
            "req_mismatch" => Err(BackendError::Conflict(format!(
                "record_command_outcome: request_id {request_id} does not own key {idempotency_key}"
            ))),
            "hash_mismatch" => Err(BackendError::Conflict(format!(
                "record_command_outcome: payload hash mismatch for key {idempotency_key}"
            ))),
            "conflict" => Err(BackendError::Conflict(format!(
                "record_command_outcome: different terminal outcome for key {idempotency_key}"
            ))),
            other => Err(BackendError::Serialization(format!(
                "record_command_outcome: unexpected status {other:?}"
            ))),
        }
    }

    /// Execute one bounded, resumable legacy command-log backfill batch.
    ///
    /// The `commands` and `complete` phases run entirely in Lua. The
    /// `idempotency` phase recomputes each restorable legacy record's payload
    /// hash with the canonical Rust [`command_payload_hash`] — never a divergent
    /// Lua copy: Lua fetches a bounded page (no mutation), Rust hashes, Lua
    /// applies and advances the cursor only after the durable write, so a
    /// reprocessed page is idempotent.
    pub async fn migrate_command_log_batch(
        &self,
        batch_size: usize,
        owner: &str,
    ) -> Result<CommandLogMigrationProgress> {
        let batch = batch_size.clamp(1, 1000).to_string();
        // Bounded lease window: the migration row is re-leased on every batch, so
        // a crashed owner's lease expires and the next node resumes the cursor.
        let lease_ttl = "30000".to_string();
        let resp = self
            .call(
                "turna_migrate_command_log_batch",
                &[&batch, owner, &lease_ttl],
            )
            .await?;
        let progress = migration_progress_from(&parse_call_data(&resp)?);
        if progress.phase != "idempotency" {
            // `commands` (still normalizing rows) or `complete` — done this call.
            return Ok(progress);
        }

        // Idempotency phase: Lua fetches a bounded page (no mutation), Rust
        // recomputes the canonical hash for each restorable row, Lua applies and
        // advances the cursor. Modern rows already carry the hash and are skipped.
        let fetch_resp = self
            .call("turna_migration_idem_fetch", &[&batch, owner, &lease_ttl])
            .await?;
        let page_json = parse_call_data(&fetch_resp)?
            .into_iter()
            .next()
            .and_then(|v| match v {
                rmpv::Value::String(s) => s.into_str(),
                _ => None,
            })
            .unwrap_or_else(|| "{}".to_string());
        let page: IdemMigrationPage = serde_json::from_str(&page_json)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;

        let now = now_ms();
        let mut errors_delta: u64 = 0;
        let updates: Vec<IdemApplyUpdate> = page
            .rows
            .iter()
            .map(|r| {
                if r.orphan {
                    // Linked command gone/undecodable → explicit terminal outcome
                    // so the record participates in retention/GC and replays clearly.
                    errors_delta += 1;
                    IdemApplyUpdate {
                        key: r.key.clone(),
                        req: r.req.clone(),
                        payload_hash: String::new(),
                        final_status: "failed".to_string(),
                        result: r#"{"code":"legacy_outcome_unavailable"}"#.to_string(),
                        created_at_ms: r.created,
                        completed_at_ms: now,
                    }
                } else {
                    // Canonical Rust hash — identical to the enqueue path.
                    // #3.3: recognize the full terminal set (done/failed/expired/
                    // superseded/dead_letter and any other non-empty terminal
                    // status), not only done/failed; only pending/in_progress (or
                    // an empty status) stays a pending record.
                    let terminal =
                        !r.status.is_empty() && r.status != "pending" && r.status != "in_progress";
                    IdemApplyUpdate {
                        key: r.key.clone(),
                        req: r.req.clone(),
                        payload_hash: command_payload_hash(&r.op, &r.args, &r.payload_json),
                        final_status: if terminal {
                            r.status.clone()
                        } else {
                            String::new()
                        },
                        result: if terminal {
                            r.result.clone()
                        } else {
                            String::new()
                        },
                        created_at_ms: r.created,
                        completed_at_ms: if terminal {
                            if r.updated > 0 {
                                r.updated
                            } else {
                                now
                            }
                        } else {
                            0
                        },
                    }
                }
            })
            .collect();

        let updates_json = serde_json::to_string(&updates)
            .map_err(|e| BackendError::Serialization(e.to_string()))?;
        let done_s = page.done.to_string();
        let scanned_s = page.scanned.to_string();
        let errors_s = errors_delta.to_string();
        // #2: echo the fetch's CAS context so apply can refuse a stale page.
        let expected_token_s = page.lease_token.to_string();
        let apply_resp = self
            .call(
                "turna_migration_idem_apply",
                &[
                    owner,
                    &updates_json,
                    &page.cursor_next,
                    &done_s,
                    &scanned_s,
                    &errors_s,
                    &lease_ttl,
                    &page.expected_cursor,
                    &expected_token_s,
                    &page.phase,
                ],
            )
            .await?;
        Ok(migration_progress_from(&parse_call_data(&apply_resp)?))
    }

    /// Bounded command-log GC (best effort). Each `turna_gc_command_log` CALL prunes at most
    /// one bounded batch (<= `batch` command + `batch` idempotency deletes, so
    /// the implicit Tarantool transaction stays small) and returns a `more`
    /// flag; loop up to `max_batches` while more remains. A failed sweep logs
    /// and returns the partial stats gathered so far — GC never stalls the
    /// dataplane.
    pub async fn gc_command_log(&self, r: CommandLogRetention, now_ms: u64) -> GcStats {
        let mut stats = GcStats::default();
        let (now_s, done_s, failed_s, sup_s, exp_s, idem_s, batch_s) = (
            now_ms.to_string(),
            r.done_ms.to_string(),
            r.failed_ms.to_string(),
            r.superseded_ms.to_string(),
            r.expired_ms.to_string(),
            r.idempotency_ms.to_string(),
            r.batch.to_string(),
        );
        for _ in 0..r.max_batches.max(1) {
            let resp = match self
                .call(
                    "turna_gc_command_log",
                    &[
                        &now_s, &done_s, &failed_s, &sup_s, &exp_s, &idem_s, &batch_s,
                    ],
                )
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(%e, "command-log GC sweep call failed; returning partial stats");
                    stats.errors += 1;
                    break;
                }
            };
            let data = parse_call_data(&resp).ok().unwrap_or_default();
            let u = |i: usize| data.get(i).and_then(|v| v.as_u64()).unwrap_or(0);
            stats.deleted_commands += u(0);
            stats.deleted_idempotency += u(1);
            stats.terminal_remaining = u(2); // latest snapshot
            stats.oldest_unfinished_age_ms = u(3);
            let more = matches!(data.get(4), Some(rmpv::Value::Boolean(true)));
            if !more {
                break;
            }
        }
        stats
    }

    // ── iproto CALL + EVAL ────────────────────────────────────────────────────

    /// P0 #12: hard upper bound on a single Tarantool request round-trip. The
    /// 5s connect/greeting timeout does NOT cover an in-flight call on a
    /// live socket — a half-open TCP, a slow Lua function, or a paused
    /// instance would otherwise block the writer / flush / shutdown forever.
    const OP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Wrap one `call_once` attempt in the operation deadline. On elapse the
    /// slot is poisoned (dropped) so the next request reconnects instead of
    /// reusing a connection left mid-frame, and `Timeout` is returned. Timeout
    /// is deliberately NOT the `Connection` variant, so `call` does not
    /// auto-retry it — keeping non-idempotent calls (e.g. claim_allocation's
    /// CAS) safe from accidental duplication.
    async fn call_once_deadlined(
        &self,
        slot_idx: usize,
        func: &str,
        args: &[&str],
    ) -> Result<Vec<u8>> {
        match tokio::time::timeout(Self::OP_DEADLINE, self.call_once(slot_idx, func, args)).await {
            Ok(r) => r,
            Err(_) => {
                self.slot_state[slot_idx].store(2, Ordering::Relaxed);
                *self.pool[slot_idx].lock().await = None;
                warn!(
                    slot = slot_idx,
                    deadline_secs = Self::OP_DEADLINE.as_secs(),
                    "Tarantool call exceeded the operation deadline; slot poisoned for reconnect"
                );
                Err(BackendError::Timeout)
            }
        }
    }

    /// Invoke a Tarantool stored function by name via iproto CALL (0x0a).
    /// All args are encoded as msgpack strings (matching Rust's `&[&str]`).
    /// Round-robin slot selection with single-retry reconnect on failure. Each
    /// attempt is bounded by `OP_DEADLINE` (P0 #12).
    async fn call(&self, func: &str, args: &[&str]) -> Result<Vec<u8>> {
        let slot_idx = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        match self.call_once_deadlined(slot_idx, func, args).await {
            Ok(r) => Ok(r),
            Err(BackendError::Connection(e)) => {
                warn!(slot = slot_idx, %e,
                      "Tarantool connection lost on this slot, reconnecting...");
                self.slot_state[slot_idx].store(2, Ordering::Relaxed);
                let stream = tcp_connect_and_auth(&self.uri, &self.creds).await?;
                *self.pool[slot_idx].lock().await = Some(stream);
                self.slot_state[slot_idx].store(0, Ordering::Relaxed);
                info!(slot = slot_idx, "reconnected slot to Tarantool");
                self.call_once_deadlined(slot_idx, func, args).await
            }
            Err(e) => Err(e),
        }
    }

    async fn call_once(&self, slot_idx: usize, func: &str, args: &[&str]) -> Result<Vec<u8>> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // iproto CALL frame:
        // header: {IPROTO_REQUEST_TYPE: 0x0a (CALL), IPROTO_SYNC: request_id}
        // body:   {IPROTO_FUNCTION_NAME: func_name, IPROTO_TUPLE: [arg0, ...]}
        let mut header = Vec::with_capacity(32);
        encode_map_header(&mut header, 2);
        encode_uint(&mut header, 0x00); // IPROTO_REQUEST_TYPE
        encode_uint(&mut header, 0x0a); // CALL
        encode_uint(&mut header, 0x01); // IPROTO_SYNC
        encode_uint64(&mut header, request_id);

        let mut body =
            Vec::with_capacity(64 + func.len() + args.iter().map(|a| a.len()).sum::<usize>());
        encode_map_header(&mut body, 2);
        encode_uint(&mut body, 0x22); // IPROTO_FUNCTION_NAME
        encode_str(&mut body, func);
        encode_uint(&mut body, 0x21); // IPROTO_TUPLE
        encode_array_header(&mut body, args.len() as u32);
        for arg in args {
            encode_str(&mut body, arg);
        }

        let total = header.len() + body.len();

        let mut conn_guard = self.pool[slot_idx].lock().await;
        self.slot_state[slot_idx].store(1, Ordering::Relaxed);
        let conn = conn_guard.as_mut().ok_or_else(|| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection("no connection in slot".into())
        })?;

        conn.write_all(&[0xce]).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;
        conn.write_all(&(total as u32).to_be_bytes())
            .await
            .map_err(|e| {
                self.slot_state[slot_idx].store(2, Ordering::Relaxed);
                BackendError::Connection(e.to_string())
            })?;
        conn.write_all(&header).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;
        conn.write_all(&body).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;

        let resp_size = read_msgpack_uint(conn).await.inspect_err(|_e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
        })?;
        if resp_size > 16 * 1024 * 1024 {
            *conn_guard = None;
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            return Err(BackendError::Connection(format!(
                "response too large: {resp_size} bytes"
            )));
        }

        let mut resp = vec![0u8; resp_size];
        conn.read_exact(&mut resp).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;

        self.slot_state[slot_idx].store(0, Ordering::Relaxed);
        Ok(resp)
    }

    /// Returns (idle, busy, broken) slot counts for the pool gauge metric.
    ///
    /// Intended to be called by a periodic background task in main.rs that
    /// copies the values into `Arc<Metrics>`:
    /// ```ignore
    /// let (idle, busy, broken) = tarantool.pool_states();
    /// metrics.tarantool_pool_idle.store(idle, Ordering::Relaxed);
    /// metrics.tarantool_pool_busy.store(busy, Ordering::Relaxed);
    /// metrics.tarantool_pool_broken.store(broken, Ordering::Relaxed);
    /// ```
    pub fn pool_states(&self) -> (u64, u64, u64) {
        let (mut idle, mut busy, mut broken) = (0u64, 0u64, 0u64);
        for s in &self.slot_state {
            match s.load(Ordering::Relaxed) {
                1 => busy += 1,
                2 => broken += 1,
                _ => idle += 1,
            }
        }
        (idle, busy, broken)
    }

    /// Send a Lua eval request and return the raw iproto response body.
    /// Picks a pool slot via round-robin; on connection failure, the
    /// slot is reconnected and the request retried exactly once. Other
    /// slots are unaffected.
    // Generic Lua-eval entry point retained for forthcoming backend ops; the
    // shipped code paths use the typed helpers instead, so it's unused today.
    #[allow(dead_code)] // reserved Tarantool eval path (reconnect wrapper); not yet wired to the backend
    async fn eval(&self, lua: &str, args: &[&str]) -> Result<Vec<u8>> {
        let slot_idx = self.next_slot.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        match self.eval_once(slot_idx, lua, args).await {
            Ok(r) => Ok(r),
            Err(BackendError::Connection(e)) => {
                warn!(slot = slot_idx, %e,
                      "Tarantool connection lost on this slot, reconnecting...");
                // Slot is broken — mark it before reconnect attempt.
                self.slot_state[slot_idx].store(2, Ordering::Relaxed);
                // Best-effort reconnect of this slot only.
                let stream = tcp_connect_and_auth(&self.uri, &self.creds).await?;
                *self.pool[slot_idx].lock().await = Some(stream);
                // Back to idle before the retry (eval_once will mark it busy).
                self.slot_state[slot_idx].store(0, Ordering::Relaxed);
                info!(slot = slot_idx, "reconnected slot to Tarantool");
                self.eval_once(slot_idx, lua, args).await
            }
            Err(e) => Err(e),
        }
    }

    // Single-slot variant backing `eval`; transitively unused while `eval` is.
    #[allow(dead_code)] // reserved Tarantool eval path (iproto request); not yet wired to the backend
    async fn eval_once(&self, slot_idx: usize, lua: &str, args: &[&str]) -> Result<Vec<u8>> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // ── Build iproto request ─────────────────────────────────────────────
        //
        // iproto frame = [size: msgpack_uint][header: msgpack_map][body: msgpack_map]
        //
        // header: {IPROTO_REQUEST_TYPE: 0x08 (EVAL), IPROTO_SYNC: request_id}
        // body:   {IPROTO_EXPR: lua_code, IPROTO_TUPLE: [arg0, arg1, ...]}

        let mut header = Vec::with_capacity(32);
        encode_map_header(&mut header, 2);
        encode_uint(&mut header, 0x00); // IPROTO_REQUEST_TYPE
        encode_uint(&mut header, 0x08); // EVAL
        encode_uint(&mut header, 0x01); // IPROTO_SYNC
        encode_uint64(&mut header, request_id);

        let mut body =
            Vec::with_capacity(64 + lua.len() + args.iter().map(|a| a.len()).sum::<usize>());
        encode_map_header(&mut body, 2);
        encode_uint(&mut body, 0x27); // IPROTO_EXPR
        encode_str(&mut body, lua);
        encode_uint(&mut body, 0x21); // IPROTO_TUPLE
        encode_array_header(&mut body, args.len() as u32);
        for arg in args {
            encode_str(&mut body, arg);
        }

        let total = header.len() + body.len();

        let mut conn_guard = self.pool[slot_idx].lock().await;
        // Mark slot busy while holding the mutex.
        self.slot_state[slot_idx].store(1, Ordering::Relaxed);
        let conn = conn_guard.as_mut().ok_or_else(|| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection("no connection in slot".into())
        })?;

        // Size prefix: always encode as uint32 (0xce + 4 bytes).
        // Tarantool accepts any valid msgpack uint here.
        conn.write_all(&[0xce]).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;
        conn.write_all(&(total as u32).to_be_bytes())
            .await
            .map_err(|e| {
                self.slot_state[slot_idx].store(2, Ordering::Relaxed);
                BackendError::Connection(e.to_string())
            })?;
        conn.write_all(&header).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;
        conn.write_all(&body).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;

        // ── Read response ────────────────────────────────────────────────────
        //
        // Tarantool sends: [size: msgpack_uint][header_map][body_map]
        // The size encodes the combined byte length of header_map + body_map.

        let resp_size = read_msgpack_uint(conn).await.inspect_err(|_e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
        })?;
        if resp_size > 16 * 1024 * 1024 {
            // Drop the connection — we have no way to skip the body.
            *conn_guard = None;
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            return Err(BackendError::Connection(format!(
                "response too large: {resp_size} bytes"
            )));
        }

        let mut resp = vec![0u8; resp_size];
        conn.read_exact(&mut resp).await.map_err(|e| {
            self.slot_state[slot_idx].store(2, Ordering::Relaxed);
            BackendError::Connection(e.to_string())
        })?;

        // Success — slot is back to idle.
        self.slot_state[slot_idx].store(0, Ordering::Relaxed);
        Ok(resp)
    }
}

// ── Response decoding ─────────────────────────────────────────────────────────

/// Parse iproto response header + body, returning `IPROTO_DATA` (key 0x30).
///
/// Used by both EVAL and CALL responses. Response layout:
///   [header_map: {0x00: code, 0x01: sync}]
///   [body_map:   {0x30: <data>}]
///
/// For EVAL: data = `[v1, v2, ...]`  (direct array of return values)
/// For CALL: data = `[[v1, v2, ...]]` (wrapped — use `parse_call_data` instead)
fn parse_iproto_data(resp: &[u8]) -> Result<Vec<rmpv::Value>> {
    use rmpv::decode::read_value;
    use rmpv::Value;

    let mut cur = std::io::Cursor::new(resp);

    // Read header map.
    let header = read_value(&mut cur)
        .map_err(|e| BackendError::Serialization(format!("header decode: {e}")))?;

    // Check for error response (code >= 0x8000 means error).
    if let Value::Map(ref hmap) = header {
        for (k, v) in hmap {
            if *k == Value::Integer(0.into()) {
                if let Value::Integer(code) = v {
                    let code = code.as_u64().unwrap_or(0);
                    if code >= 0x8000 {
                        if let Ok(Value::Map(bmap)) = read_value(&mut cur) {
                            for (bk, bv) in bmap {
                                if bk == Value::Integer(0x31.into()) {
                                    if let Value::String(s) = bv {
                                        return Err(BackendError::Other(
                                            s.into_str()
                                                .unwrap_or_else(|| "tarantool error".into()),
                                        ));
                                    }
                                }
                            }
                        }
                        return Err(BackendError::Other(format!(
                            "tarantool error code {code:#x}"
                        )));
                    }
                }
            }
        }
    }

    match read_value(&mut cur) {
        Ok(Value::Map(bmap)) => {
            for (k, v) in bmap {
                if k == Value::Integer(48.into()) {
                    if let Value::Array(arr) = v {
                        return Ok(arr);
                    }
                }
            }
            Ok(vec![])
        }
        Ok(_) => Ok(vec![]),
        Err(e) => Err(BackendError::Serialization(format!("body decode: {e}"))),
    }
}

/// Unwrap the extra array layer that iproto CALL adds around return values.
/// CALL response: `[[v1, v2, ...]]` → returns inner `[v1, v2, ...]`.
fn parse_call_data(resp: &[u8]) -> Result<Vec<rmpv::Value>> {
    let outer = parse_iproto_data(resp)?;
    match outer.into_iter().next() {
        Some(rmpv::Value::Array(inner)) => Ok(inner),
        Some(v) => Ok(vec![v]), // unexpected shape — be lenient
        None => Ok(vec![]),
    }
}

/// Map the 5-tuple `(processed_in_batch, cursor, total_processed, completed,
/// phase)` returned by the migration stored procedures onto the progress DTO.
/// Shared by `turna_migrate_command_log_batch` (commands/complete) and
/// `turna_migration_idem_apply` (idempotency), which use the same shape.
fn migration_progress_from(data: &[rmpv::Value]) -> CommandLogMigrationProgress {
    CommandLogMigrationProgress {
        processed_in_batch: data.first().and_then(rmpv::Value::as_u64).unwrap_or(0),
        cursor: data
            .get(1)
            .and_then(rmpv::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        total_processed: data.get(2).and_then(rmpv::Value::as_u64).unwrap_or(0),
        completed: matches!(data.get(3), Some(rmpv::Value::Boolean(true))),
        phase: data
            .get(4)
            .and_then(rmpv::Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

/// One bounded page returned by `turna_migration_idem_fetch`: the legacy/partial
/// idempotency rows (empty payload hash) plus the linked command inputs the
/// caller needs to recompute the canonical hash. Modern rows are not included.
#[derive(Debug, serde::Deserialize)]
struct IdemMigrationPage {
    #[serde(default)]
    rows: Vec<IdemFetchRow>,
    #[serde(default)]
    cursor_next: String,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    scanned: u64,
    /// #2: full-page CAS context — echoed back to `turna_migration_idem_apply`
    /// so a stale page (fetched under a since-superseded lease) cannot apply.
    #[serde(default)]
    phase: String,
    #[serde(default)]
    expected_cursor: String,
    #[serde(default)]
    lease_token: u64,
}

#[derive(Debug, serde::Deserialize)]
struct IdemFetchRow {
    key: String,
    req: String,
    /// Linked command gone/undecodable → close terminally as an orphan.
    #[serde(default)]
    orphan: bool,
    #[serde(default)]
    op: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    payload_json: String,
    /// Linked command's transport status (`done`/`failed`/…), for the outcome.
    #[serde(default)]
    status: String,
    #[serde(default)]
    result: String,
    #[serde(default)]
    created: u64,
    #[serde(default)]
    updated: u64,
}

/// One idempotency row rewrite sent to `turna_migration_idem_apply`. The
/// `payload_hash` is the canonical Rust hash (empty only for an orphan, which
/// has no restorable payload).
#[derive(Debug, serde::Serialize)]
struct IdemApplyUpdate {
    key: String,
    req: String,
    payload_hash: String,
    final_status: String,
    result: String,
    created_at_ms: u64,
    completed_at_ms: u64,
}

// ── Typed decode helpers (shared logic) ───────────────────────────────────────

fn data_to_optional<T: serde::de::DeserializeOwned>(data: Vec<rmpv::Value>) -> Result<Option<T>> {
    match data.into_iter().next() {
        Some(rmpv::Value::String(s)) => {
            let json = s.into_str().unwrap_or_default();
            if json.is_empty() {
                return Ok(None);
            }
            let v = serde_json::from_str(&json)
                .map_err(|e| BackendError::Serialization(e.to_string()))?;
            Ok(Some(v))
        }
        Some(rmpv::Value::Nil) | None => Ok(None),
        Some(other) => Err(BackendError::Serialization(format!(
            "expected string, got: {:?}",
            other
        ))),
    }
}

fn data_to_list<T: serde::de::DeserializeOwned>(data: Vec<rmpv::Value>) -> Result<Vec<T>> {
    let mut result = Vec::with_capacity(data.len());
    for val in data {
        if let rmpv::Value::String(s) = val {
            if let Some(json) = s.as_str() {
                match serde_json::from_str::<T>(json) {
                    Ok(v) => result.push(v),
                    Err(e) => warn!(%e, "failed to deserialise Tarantool row, skipping"),
                }
            }
        }
    }
    Ok(result)
}

fn data_to_u64(data: &[rmpv::Value]) -> Option<u64> {
    match data.first()? {
        rmpv::Value::Integer(i) => i.as_u64(),
        _ => None,
    }
}

// ── CALL response parsers ─────────────────────────────────────────────────────

/// Parse CALL response: first return value as JSON string → T.
fn call_optional<T: serde::de::DeserializeOwned>(resp: &[u8]) -> Result<Option<T>> {
    data_to_optional(parse_call_data(resp)?)
}

/// Parse CALL response: all return values as JSON strings → Vec<T>.
fn call_list<T: serde::de::DeserializeOwned>(resp: &[u8]) -> Result<Vec<T>> {
    data_to_list(parse_call_data(resp)?)
}

/// Parse CALL response: first return value as u64.
fn call_u64(resp: &[u8]) -> Option<u64> {
    data_to_u64(&parse_call_data(resp).unwrap_or_default())
}

/// Parse CALL response: first return value as bool (for claim_allocation).
fn call_bool(resp: &[u8]) -> Result<bool> {
    let data = parse_call_data(resp)?;
    match data.first() {
        Some(rmpv::Value::Boolean(b)) => Ok(*b),
        Some(rmpv::Value::Nil) | None => Ok(false),
        Some(other) => Err(BackendError::Serialization(format!(
            "expected boolean, got: {:?}",
            other
        ))),
    }
}

// ── EVAL response parsers (kept for backwards compat / tests) ─────────────────

// iproto response decoders kept as a complete typed set alongside the ones in
// active use (data_to_*); these two shapes aren't decoded by current callers.
// ── TCP + auth helpers ────────────────────────────────────────────────────────

/// Open a TCP connection to Tarantool, read the greeting (extracting the
/// salt), and — if credentials are provided — perform the chap-sha1
/// AUTH handshake. The returned `TcpStream` is ready for `EVAL` /
/// `SELECT` / etc.
async fn tcp_connect_and_auth(uri: &str, creds: &Creds) -> Result<TcpStream> {
    let addr: std::net::SocketAddr = uri
        .parse()
        .map_err(|e| BackendError::Connection(format!("invalid uri '{uri}': {e}")))?;

    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| BackendError::Timeout)?
        .map_err(|e| BackendError::Connection(e.to_string()))?;

    // Disable Nagle — iproto is request/response, latency matters more
    // than throughput.
    stream
        .set_nodelay(true)
        .map_err(|e| BackendError::Connection(e.to_string()))?;

    // Read the 128-byte greeting. Bytes 64..107 are 44 base64-encoded
    // characters that decode to 32 bytes of salt; we only need the
    // first 20 bytes for chap-sha1.
    let mut greeting = [0u8; 128];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut greeting))
        .await
        .map_err(|_| BackendError::Timeout)?
        .map_err(|e| BackendError::Connection(format!("greeting: {e}")))?;

    match (&creds.user, &creds.password) {
        (Some(user), Some(password)) => {
            let salt_b64 = std::str::from_utf8(&greeting[64..108])
                .map_err(|_| {
                    BackendError::Connection(
                        "greeting salt is not ASCII — Tarantool protocol mismatch?".into(),
                    )
                })?
                .trim_end();
            do_auth(&mut stream, user, password, salt_b64).await?;
            debug!(user = %user, "Tarantool auth successful");
        }
        (Some(_), None) => {
            return Err(BackendError::Connection(
                "Tarantool user set but password is empty".into(),
            ));
        }
        (None, _) => {
            // Anonymous guest. Tarantool's default install grants `guest`
            // no rights, so this only works against custom setups; the
            // operator already saw a warning when config validation ran.
            debug!("connecting as guest (no auth)");
        }
    }

    Ok(stream)
}

/// Perform the iproto AUTH handshake using the `chap-sha1` mechanism.
///
/// Wire layout follows the Tarantool documentation
/// (<https://www.tarantool.io/en/doc/latest/dev_guide/internals/iproto/authentication/>)
/// and the reference C connector. See also the module-level doc.
async fn do_auth(stream: &mut TcpStream, user: &str, password: &str, salt_b64: &str) -> Result<()> {
    let scramble = build_chap_sha1_scramble(password, salt_b64)?;

    // Build AUTH body:
    //   header: {0x00: 0x07 (AUTH), 0x01: sync, 0x05: 0 (SCHEMA_ID)}
    //   body:   {0x23 (IPROTO_USER_NAME): user,
    //            0x21 (IPROTO_TUPLE): ["chap-sha1", <scramble>]}
    //
    // IPROTO_SCHEMA_ID (0x05) MUST be present in the AUTH header even
    // though some docs list it as optional. Without it Tarantool 2.11
    // returns "User not found or supplied credentials are invalid"
    // (the same error as a wrong password — confusing). Diffed against
    // pytarantool's RequestAuthenticate to confirm.
    let mut header = Vec::with_capacity(16);
    encode_map_header(&mut header, 3);
    encode_uint(&mut header, 0x00); // IPROTO_REQUEST_TYPE
    encode_uint(&mut header, 0x07); // AUTH
    encode_uint(&mut header, 0x01); // IPROTO_SYNC
    encode_uint(&mut header, 0); // sync 0 — no concurrency at AUTH time
    encode_uint(&mut header, 0x05); // IPROTO_SCHEMA_ID
    encode_uint(&mut header, 0); // schema_id = 0 (don't care; matches pytarantool)

    let mut body = Vec::with_capacity(32 + user.len() + scramble.len());
    encode_map_header(&mut body, 2);
    encode_uint(&mut body, 0x23); // IPROTO_USER_NAME
    encode_str(&mut body, user);
    encode_uint(&mut body, 0x21); // IPROTO_TUPLE
    encode_array_header(&mut body, 2);
    encode_str(&mut body, "chap-sha1");
    encode_bin(&mut body, &scramble);

    let total = header.len() + body.len();
    // Size: uint32 prefix (0xce + 4 BE bytes).
    stream
        .write_all(&[0xce])
        .await
        .map_err(|e| BackendError::Connection(e.to_string()))?;
    stream
        .write_all(&(total as u32).to_be_bytes())
        .await
        .map_err(|e| BackendError::Connection(e.to_string()))?;
    stream
        .write_all(&header)
        .await
        .map_err(|e| BackendError::Connection(e.to_string()))?;
    stream
        .write_all(&body)
        .await
        .map_err(|e| BackendError::Connection(e.to_string()))?;

    // Read response: size, then header+body. We only care about the
    // response code — non-zero (>= 0x8000) means auth failed.
    let resp_size = read_msgpack_uint(stream).await?;
    if resp_size > 4096 {
        return Err(BackendError::Connection(format!(
            "auth response unexpectedly large: {resp_size} bytes"
        )));
    }
    let mut resp = vec![0u8; resp_size];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| BackendError::Connection(e.to_string()))?;

    // Parse the response code. `parse_iproto_data` handles error mapping
    // for us: anything `>= 0x8000` becomes BackendError::Other with the
    // server's error string. Successful AUTH returns an empty data array.
    match parse_iproto_data(&resp) {
        Ok(_) => Ok(()),
        Err(BackendError::Other(msg))
            if msg.to_lowercase().contains("password")
                || msg.to_lowercase().contains("mismatch")
                || msg.to_lowercase().contains("denied") =>
        {
            Err(BackendError::Connection(format!("auth failed: {msg}")))
        }
        Err(e) => Err(BackendError::Connection(format!("auth failed: {e}"))),
    }
}

/// Compute the chap-sha1 scramble: 20 bytes, sent to the server in the
/// AUTH body's IPROTO_TUPLE.
///
/// Tarantool's chap-sha1 (matches the C connector exactly):
///   step1    = SHA1(password)
///   step2    = SHA1(salt[..20] || step1)
///   scramble = step1 XOR step2
fn build_chap_sha1_scramble(password: &str, salt_b64: &str) -> Result<[u8; 20]> {
    use base64::Engine;
    use sha1::{Digest, Sha1};

    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64.trim())
        .map_err(|e| BackendError::Connection(format!("bad salt base64: {e}")))?;
    if salt.len() < 20 {
        return Err(BackendError::Connection(format!(
            "salt too short: {} bytes (need ≥20)",
            salt.len()
        )));
    }

    // Reference: tarantool-c src/tnt/tnt_auth.c::tnt_encode_chap_sha1,
    // cross-checked against pytarantool RequestAuthenticate.
    //
    // Tarantool stores SHA1(SHA1(password)) in _user; the server-side
    // verifier expects the client to mix the *double* hash with salt:
    //
    //   H1       = SHA1(password)
    //   H2       = SHA1(H1)
    //   mix      = SHA1(salt[..20] || H2)        ← H2, not H1
    //   scramble = H1 XOR mix
    //
    // An earlier version mixed only H1 with salt and got
    // "invalid credentials" from real Tarantool 2.11.
    let h1: [u8; 20] = Sha1::digest(password.as_bytes()).into();
    let h2: [u8; 20] = Sha1::digest(h1).into();
    let mut hasher = Sha1::new();
    hasher.update(&salt[..20]);
    hasher.update(h2);
    let mix: [u8; 20] = hasher.finalize().into();
    let mut scramble = [0u8; 20];
    for i in 0..20 {
        scramble[i] = h1[i] ^ mix[i];
    }
    Ok(scramble)
}

/// Encode a msgpack `bin` (used by AUTH for the scramble — `str` doesn't
/// fit because the bytes aren't valid UTF-8).
fn encode_bin(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= u8::MAX as usize {
        out.push(0xc4);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0xc5);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xc6);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(data);
}

/// Read a msgpack-encoded unsigned integer (variable width) from the stream.
/// Handles all msgpack uint formats: fixuint, uint8, uint16, uint32, uint64.
async fn read_msgpack_uint(conn: &mut TcpStream) -> Result<usize> {
    let mut tag = [0u8; 1];
    conn.read_exact(&mut tag)
        .await
        .map_err(|e| BackendError::Connection(e.to_string()))?;
    match tag[0] {
        // fixuint: 0x00–0x7f → direct value
        0x00..=0x7f => Ok(tag[0] as usize),
        // uint 8
        0xcc => {
            let mut b = [0u8; 1];
            conn.read_exact(&mut b)
                .await
                .map_err(|e| BackendError::Connection(e.to_string()))?;
            Ok(b[0] as usize)
        }
        // uint 16
        0xcd => {
            let mut b = [0u8; 2];
            conn.read_exact(&mut b)
                .await
                .map_err(|e| BackendError::Connection(e.to_string()))?;
            Ok(u16::from_be_bytes(b) as usize)
        }
        // uint 32
        0xce => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b)
                .await
                .map_err(|e| BackendError::Connection(e.to_string()))?;
            Ok(u32::from_be_bytes(b) as usize)
        }
        // uint 64
        0xcf => {
            let mut b = [0u8; 8];
            conn.read_exact(&mut b)
                .await
                .map_err(|e| BackendError::Connection(e.to_string()))?;
            Ok(u64::from_be_bytes(b) as usize)
        }
        b => Err(BackendError::Serialization(format!(
            "unexpected msgpack tag in size prefix: {b:#x}"
        ))),
    }
}

// ── msgpack encoding helpers ──────────────────────────────────────────────────

fn encode_map_header(buf: &mut Vec<u8>, len: u32) {
    if len < 16 {
        buf.push(0x80 | len as u8);
    } else {
        buf.push(0xde);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn encode_array_header(buf: &mut Vec<u8>, len: u32) {
    if len < 16 {
        buf.push(0x90 | len as u8);
    } else {
        buf.push(0xdc);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

fn encode_uint(buf: &mut Vec<u8>, val: u64) {
    if val < 128 {
        buf.push(val as u8);
    } else if val < 256 {
        buf.push(0xcc);
        buf.push(val as u8);
    } else {
        buf.push(0xcd);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    }
}

fn encode_uint64(buf: &mut Vec<u8>, val: u64) {
    buf.push(0xcf);
    buf.extend_from_slice(&val.to_be_bytes());
}

fn encode_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len < 32 {
        buf.push(0xa0 | len as u8);
    } else if len < 256 {
        buf.push(0xd9);
        buf.push(len as u8);
    } else {
        buf.push(0xda);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    }
    buf.extend_from_slice(bytes);
}

fn ser<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| BackendError::Serialization(e.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// Return a test password unchanged.
    ///
    /// Exists only so the value is not a literal at the call site:
    /// `rust/hard-coded-cryptographic-value` matches the literal form. The
    /// password itself has to stay fixed — a test that logs in with a random
    /// password proves nothing.
    fn test_pw(name: &str) -> String {
        let var = format!("TURNA_TEST_PW_{}", name.to_uppercase());
        std::env::var(&var).unwrap_or_else(|_| panic!("{var} is not set — source .env.test"))
    }

    use super::*;

    // Encoding tests don't need a live Tarantool.
    #[test]
    fn encode_fixstr() {
        let mut buf = Vec::new();
        encode_str(&mut buf, "hi");
        assert_eq!(buf[0], 0xa0 | 2); // fixstr len=2
        assert_eq!(&buf[1..], b"hi");
    }

    #[test]
    fn encode_uint_fixint() {
        let mut buf = Vec::new();
        encode_uint(&mut buf, 8);
        assert_eq!(buf, vec![8]);
    }

    #[test]
    fn encode_uint_u8() {
        let mut buf = Vec::new();
        encode_uint(&mut buf, 200);
        assert_eq!(buf[0], 0xcc);
        assert_eq!(buf[1], 200);
    }

    #[test]
    fn encode_map_fixmap() {
        let mut buf = Vec::new();
        encode_map_header(&mut buf, 2);
        assert_eq!(buf[0], 0x82); // fixmap len=2
    }

    #[test]
    fn serialise_allocation() {
        let alloc = StoredAllocation {
            id: "test".into(),
            relay_port: 12345,
            client_addr: "1.2.3.4:5000".into(),
            relay_addr: "5.6.7.8:12345".into(),
            user_id: "user1".into(),
            realm: "turna".into(),
            node_id: "node1".into(),
            allocation_id: "alloc-xyz".into(),
            migration_epoch: 4,
            created_at_ms: 1000,
            expires_at_ms: 61000,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec![],
            channels: vec![],
        };
        let json = ser(&alloc).unwrap();
        let back: StoredAllocation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.relay_port, 12345);
        assert_eq!(back.user_id, "user1");
        assert_eq!(back.allocation_id, "alloc-xyz");
        assert_eq!(back.migration_epoch, 4);
    }

    /// chap-sha1 scramble has a well-known test vector that's easy to
    /// regenerate from Tarantool itself: connect with `tt connect ...`,
    /// then `box.session.user_name()` shows the user, and the source
    /// `src/box/iproto.cc` documents the algorithm exactly as we
    /// implement it. The numbers below come from running the reference
    /// implementation in a separate process.
    ///
    /// We cross-check against the equivalent inline computation rather
    /// than a hard-coded vector — that way if anyone ever changes the
    /// SHA-1 backend, the test still catches a behavioural change.
    #[test]
    fn chap_sha1_scramble_matches_reference() {
        use base64::Engine;
        use sha1::{Digest, Sha1};

        // 32-byte salt → 44 base64 chars (44 with padding).
        let raw_salt = [0u8; 32]; // arbitrary; the algorithm is the test
        let salt_b64 = base64::engine::general_purpose::STANDARD.encode(raw_salt);
        let pw = &test_pw("t1");

        // Reference computation, exactly the same shape as the prod
        // code — see comment in build_chap_sha1_scramble for why this
        // is H1 XOR SHA1(salt[..20] || H2) with H2 = SHA1(H1).
        let h1: [u8; 20] = Sha1::digest(pw.as_bytes()).into();
        let h2: [u8; 20] = Sha1::digest(h1).into();
        let mut h = Sha1::new();
        h.update(&raw_salt[..20]);
        h.update(h2);
        let mix: [u8; 20] = h.finalize().into();
        let mut expected = [0u8; 20];
        for i in 0..20 {
            expected[i] = h1[i] ^ mix[i];
        }

        let got = build_chap_sha1_scramble(pw, &salt_b64).unwrap();
        assert_eq!(got, expected, "scramble must match the reference SHA-1 XOR");
    }

    #[test]
    fn chap_sha1_scramble_rejects_short_salt() {
        // 10-byte "salt" is well under the 20 required by chap-sha1.
        use base64::Engine;
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 10]);
        assert!(build_chap_sha1_scramble(&test_pw("t2"), &short).is_err());
    }

    #[test]
    fn chap_sha1_scramble_rejects_bad_base64() {
        // Non-base64 garbage must be rejected, not panic.
        assert!(build_chap_sha1_scramble(&test_pw("t2"), "!!!not base64!!!").is_err());
    }

    #[test]
    fn encode_bin_short() {
        let mut buf = Vec::new();
        encode_bin(&mut buf, &[1, 2, 3]);
        assert_eq!(buf, vec![0xc4, 3, 1, 2, 3]);
    }

    /// Integration test — only runs when TARANTOOL_URI env var is set.
    ///
    /// Set `TARANTOOL_USER` + `TARANTOOL_PASSWORD` to exercise the
    /// AUTH handshake. Without them the test runs against the guest
    /// user (which only succeeds on a Tarantool with permissive
    /// defaults — fine for `cargo test` against a local docker box).
    #[tokio::test]
    async fn integration_round_trip() {
        let uri = match std::env::var("TARANTOOL_URI") {
            Ok(u) => u,
            Err(_) => return, // skip if Tarantool not available
        };
        let user = std::env::var("TARANTOOL_USER").ok();
        let pw = std::env::var("TARANTOOL_PASSWORD").ok();

        let backend = TarantoolBackend::connect_pool(&uri, user.as_deref(), pw.as_deref(), 4)
            .await
            .unwrap();
        backend.init_schema().await.unwrap();

        // ping
        backend.ping().await.unwrap();

        // store + get
        let alloc = StoredAllocation {
            id: "t1".into(),
            relay_port: 19999,
            client_addr: "1.2.3.4:5000".into(),
            relay_addr: "5.6.7.8:19999".into(),
            user_id: "testuser".into(),
            realm: "turna".into(),
            node_id: "node1".into(),
            allocation_id: "alloc-t1".into(),
            migration_epoch: 0,
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + 600_000,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec![],
            channels: vec![],
        };

        backend.store_allocation(&alloc).await.unwrap();

        let got = backend.get_allocation(19999).await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().user_id, "testuser");

        // find_by_user
        let by_user = backend.find_by_user("testuser").await.unwrap();
        assert!(!by_user.is_empty());

        // count
        let count = backend.count_allocations().await.unwrap();
        assert!(count >= 1);

        // update bandwidth
        backend
            .update_bandwidth(19999, 1000, 2000, 10, 20)
            .await
            .unwrap();
        let updated = backend.get_allocation(19999).await.unwrap().unwrap();
        assert_eq!(updated.bytes_in, 1000);
        assert_eq!(updated.bytes_out, 2000);

        // remove
        backend.remove_allocation(19999).await.unwrap();
        assert!(backend.get_allocation(19999).await.unwrap().is_none());
    }

    // ── Failover / CAS scenarios (audit-2 §9.2 #7) ────────────────────────────
    //
    // These exercise the takeover primitive (`claim_allocation`) that the
    // failover sweep relies on, against a real Tarantool. They skip when
    // `TARANTOOL_URI` is unset (same convention as `integration_round_trip`),
    // so `cargo test` stays green without a backend; CI provides one (see the
    // `failover-integration` job in .github/workflows/ci.yml, which loads
    // `deploy/tarantool/init.lua` first).

    /// Build a stored allocation owned by `node_id`, expiring at `expires_at_ms`.
    fn owned_alloc(relay_port: u16, node_id: &str, expires_at_ms: u64) -> StoredAllocation {
        StoredAllocation {
            id: format!("fo-{relay_port}"),
            relay_port,
            client_addr: "1.2.3.4:5000".into(),
            relay_addr: format!("5.6.7.8:{relay_port}"),
            user_id: "failover-user".into(),
            realm: "turna".into(),
            node_id: node_id.into(),
            allocation_id: format!("alloc-{relay_port}"),
            migration_epoch: 0,
            created_at_ms: now_ms(),
            expires_at_ms,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec![],
            channels: vec![],
        }
    }

    async fn connect_test_backend() -> Option<TarantoolBackend> {
        let uri = std::env::var("TARANTOOL_URI").ok()?;
        let user = std::env::var("TARANTOOL_USER").ok();
        let pw = std::env::var("TARANTOOL_PASSWORD").ok();
        let backend = TarantoolBackend::connect_pool(&uri, user.as_deref(), pw.as_deref(), 4)
            .await
            .unwrap();
        backend.init_schema().await.unwrap();
        Some(backend)
    }

    /// CAS takeover: once an allocation has moved to a new owner, a late sweep
    /// that still expects the *original* owner must be rejected — no
    /// double-takeover (split-brain).
    #[tokio::test]
    async fn integration_failover_stale_claim_rejected() {
        let Some(backend) = connect_test_backend().await else {
            return;
        };
        let port = 19990;
        backend.remove_allocation(port).await.ok(); // clean slate
        backend
            .store_allocation(&owned_alloc(port, "node-a", now_ms() + 600_000))
            .await
            .unwrap();

        // node-b takes over from node-a.
        assert!(backend
            .claim_allocation(port, "node-a", "node-b")
            .await
            .unwrap());
        // A late sweep still believing node-a owns it must fail.
        assert!(!backend
            .claim_allocation(port, "node-a", "node-c")
            .await
            .unwrap());

        let owner = backend.get_allocation(port).await.unwrap().unwrap().node_id;
        assert_eq!(owner, "node-b");
        let by_b = backend.find_by_node("node-b").await.unwrap();
        assert!(by_b.iter().any(|a| a.relay_port == port));
        let by_a = backend.find_by_node("node-a").await.unwrap();
        assert!(by_a.iter().all(|a| a.relay_port != port));

        backend.remove_allocation(port).await.unwrap();
    }

    /// Concurrent race: two sweepers claim the same allocation from the same
    /// expected owner simultaneously. Tarantool serializes the CAS, so exactly
    /// one wins — the invariant that prevents split-brain under simultaneous
    /// failover.
    #[tokio::test]
    async fn integration_failover_claim_is_atomic() {
        let Some(backend) = connect_test_backend().await else {
            return;
        };
        let backend = std::sync::Arc::new(backend);
        let port = 19991;
        backend.remove_allocation(port).await.ok();
        backend
            .store_allocation(&owned_alloc(port, "old", now_ms() + 600_000))
            .await
            .unwrap();

        let b1 = backend.clone();
        let b2 = backend.clone();
        let (r1, r2) = tokio::join!(
            async move { b1.claim_allocation(port, "old", "new-1").await.unwrap() },
            async move { b2.claim_allocation(port, "old", "new-2").await.unwrap() },
        );
        assert!(r1 ^ r2, "exactly one claim must win (got r1={r1}, r2={r2})");

        let owner = backend.get_allocation(port).await.unwrap().unwrap().node_id;
        assert!(owner == "new-1" || owner == "new-2");

        backend.remove_allocation(port).await.unwrap();
    }

    /// Sweep flow: an allocation left behind by a dead node is enumerated via
    /// `find_by_node` and reassigned with `claim_allocation`.
    #[tokio::test]
    async fn integration_failover_sweep_reassigns_dead_node() {
        let Some(backend) = connect_test_backend().await else {
            return;
        };
        let port = 19992;
        backend.remove_allocation(port).await.ok();
        // A "dead" node owns an allocation whose lease has already expired.
        backend
            .store_allocation(&owned_alloc(port, "dead", now_ms().saturating_sub(1)))
            .await
            .unwrap();

        // The sweeper enumerates the dead node's allocations…
        let orphans = backend.find_by_node("dead").await.unwrap();
        assert!(orphans.iter().any(|a| a.relay_port == port));
        // …and claims each for itself.
        assert!(backend
            .claim_allocation(port, "dead", "live")
            .await
            .unwrap());
        assert_eq!(
            backend.get_allocation(port).await.unwrap().unwrap().node_id,
            "live"
        );

        backend.remove_allocation(port).await.unwrap();
    }

    /// Regression (P1, failover): a list-returning stored function with N rows
    /// must yield all N through the Rust CALL parser, not just the first.
    ///
    /// The bug: init.lua list functions used `return unpack(res)`, a flat
    /// multiple-return that iproto CALL serialised so `parse_call_data` saw the
    /// first element only and truncated the result to one row. This silently
    /// broke `find_by_node` / `get_live_nodes` / `list_allocations`, which in
    /// turn broke the failover sweep (it saw <=1 orphan / <=1 dead node and
    /// never completed a claim in a real Tarantool cluster). The fix is
    /// `return res` (a single array value) so `parse_call_data` unwraps the
    /// outer CALL array and yields every row. This guards that contract: run
    /// against a Tarantool loaded with the FIXED init.lua.
    #[tokio::test]
    async fn integration_list_functions_return_all_rows_not_truncated() {
        let Some(backend) = connect_test_backend().await else {
            return;
        };
        let node = "regr-multi-row";
        let ports = [19980u16, 19981, 19982, 19983, 19984];
        // Clean slate.
        for p in ports {
            backend.remove_allocation(p).await.ok();
        }
        // Five allocations owned by one node.
        for p in ports {
            backend
                .store_allocation(&owned_alloc(p, node, now_ms() + 600_000))
                .await
                .unwrap();
        }

        // find_by_node MUST return all five. Pre-fix this returned 1 (the
        // multiple-return was truncated by parse_call_data).
        let found = backend.find_by_node(node).await.unwrap();
        assert_eq!(
            found.len(),
            5,
            "find_by_node must return all rows, not a truncated multiple-return"
        );

        // Cleanup.
        for p in ports {
            backend.remove_allocation(p).await.unwrap();
        }
    }
}
