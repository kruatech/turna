//! Pluggable state backend for Turna cluster mode.
//!
//! Backends:
//! - `InMemoryBackend`   — standalone, no external deps (default for single-node)
//! - `TarantoolBackend` — production cluster (feature: tarantool, enabled by default)
//!
//! # Choosing a backend
//!
//! Single-node / dev:
//! ```toml
//! # turn.toml
//! [state]
//! type = "memory"
//! ```
//!
//! Cluster:
//! ```toml
//! [state]
//! type    = "tarantool"
//! uri     = "127.0.0.1:3301"
//! ```
//!
//! # Tarantool setup
//!
//! Run the init script once after starting Tarantool:
//! ```bash
//! tarantoolctl connect 127.0.0.1:3301 < deploy/tarantool_init.lua
//! ```
//! The init script is embedded in `tarantool::INIT_SCRIPT`.

pub mod memory;
#[cfg(feature = "tarantool")]
pub mod tarantool;

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("connection: {0}")]
    Connection(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("timeout")]
    Timeout,
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("backend: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, BackendError>;

// ── Data models ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAllocation {
    pub id: String,
    pub relay_port: u16,
    pub client_addr: String,
    pub relay_addr: String,
    pub user_id: String,
    pub realm: String,
    pub node_id: String,
    /// RFC 8016 stable allocation identity (the value a MOBILITY-TICKET is
    /// minted against). Persisted so that after a cross-node failover the
    /// adopting node rehydrates with the *same* id and a ticket issued by the
    /// original owner still validates. `#[serde(default)]` keeps rows written
    /// before this field existed readable (they decode to an empty id, and the
    /// rehydrate path then mints a fresh one — pre-RFC-8016 behaviour).
    #[serde(default)]
    pub allocation_id: String,
    /// RFC 8016 migration generation (anti-replay). Persisted alongside
    /// `allocation_id` so the epoch survives failover and a captured
    /// older-epoch ticket stays rejected on the new owner. `#[serde(default)]`
    /// → old rows decode as epoch 0.
    #[serde(default)]
    pub migration_epoch: u64,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub permissions: Vec<String>,
    pub channels: Vec<StoredChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChannel {
    pub number: u16,
    pub peer_addr: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    pub node_id: String,
    /// Process-unique node incarnation. Commands are fenced to this value so a
    /// restarted process cannot apply work claimed by its predecessor.
    #[serde(default)]
    pub incarnation: String,
    pub addr: String,
    pub active_allocations: u64,
    pub total_bandwidth_bps: u64,
    pub cpu_usage_pct: f32,
    pub memory_usage_pct: f32,
    pub uptime_secs: u64,
    pub version: String,
    pub last_seen_ms: u64,
    pub draining: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRoom {
    pub room_id: String,
    pub participants: Vec<StoredParticipant>,
    pub created_at_ms: u64,
    pub recording: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredParticipant {
    pub peer_id: String,
    pub node_id: String,
    pub display_name: Option<String>,
    pub joined_at_ms: u64,
}

/// A long-term TURN user persisted in the state backend (R8).
///
/// Variant B: the plaintext password is never stored. Both pre-derived
/// long-term keys are kept as lowercase hex, so a node can rehydrate its
/// `AuthRegistry` directly and answer either MESSAGE-INTEGRITY variant
/// (RFC 5389 / RFC 8489).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub username: String,
    pub realm: String,
    /// hex(HMAC-SHA-1 key = MD5(username:realm:password)) — RFC 5389.
    pub key_md5_hex: String,
    /// hex(SHA-256 long-term key) — RFC 8489.
    pub key_sha256_hex: String,
    #[serde(default)]
    pub organization: Option<String>,
    pub created_at_ms: u64,
}

/// Storage/wire representation of the node's one immutable runtime snapshot.
/// The node converts this directly to/from `turna_config::RuntimeSnapshot` and
/// `turna_session::RuntimeLimits`; it is not an independently mutable model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeConfigSnapshot {
    pub schema_version: u32,
    pub version: u64,
    pub max_allocations: usize,
    pub max_allocations_per_user: usize,
    #[serde(alias = "max_bytes_per_sec")]
    pub max_bytes_per_sec_per_allocation: u64,
}

impl RuntimeConfigSnapshot {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// §2.1: metadata of the last successfully-applied management operation. Stored
/// atomically with the observed-version bump in `confirm_*_observed` so a replay
/// after a lost `complete_command` (crash / lease-expiry reclaim / incarnation
/// change) returns the original terminal result instead of re-applying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedOperation {
    pub request_id: String,
    pub op: String,
    #[serde(default)]
    pub idempotency_key: String,
    pub payload_hash: String,
    pub applied_version: u64,
    /// Serialized typed business result (UpdateConfigResult / SetUserLimitsResult).
    pub terminal_result: String,
    pub applied_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRuntimeState {
    pub node_id: String,
    #[serde(default)]
    pub incarnation: String,
    pub desired_version: u64,
    pub observed_version: u64,
    pub desired_snapshot: RuntimeConfigSnapshot,
    pub observed_snapshot: RuntimeConfigSnapshot,
    /// `desired` | `applying` | `observed` | `failed`.
    pub status: String,
    #[serde(default)]
    pub last_error: String,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub last_applied: Option<AppliedOperation>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitMode {
    #[default]
    Inherit,
    Value,
    Unlimited,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitU32 {
    pub mode: LimitMode,
    #[serde(default)]
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitU64 {
    pub mode: LimitMode,
    #[serde(default)]
    pub value: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLimitsPatch {
    #[serde(default)]
    pub max_allocations: Option<LimitU32>,
    #[serde(default)]
    #[serde(alias = "max_bytes_per_sec")]
    pub max_bytes_per_sec_per_allocation: Option<LimitU64>,
    #[serde(default)]
    pub max_lifetime_secs: Option<LimitU32>,
}

impl UserLimitsPatch {
    pub fn is_empty(&self) -> bool {
        self.max_allocations.is_none()
            && self.max_bytes_per_sec_per_allocation.is_none()
            && self.max_lifetime_secs.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserLimitScope {
    Global,
    Tenant,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserLimitTarget {
    pub scope: UserLimitScope,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub username: String,
}

impl UserLimitTarget {
    pub fn subject_key(&self) -> String {
        fn component(value: &str) -> String {
            format!("{}:{value}", value.len())
        }

        match self.scope {
            UserLimitScope::Global => "global".to_string(),
            UserLimitScope::Tenant => format!(
                "tenant:{}:{}",
                component(&self.realm),
                component(&self.tenant)
            ),
            UserLimitScope::User => format!(
                "user:{}:{}:{}",
                component(&self.realm),
                component(&self.tenant),
                component(&self.username)
            ),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveUserLimits {
    /// 0 = unlimited when `allocations_disabled` is false.
    pub max_allocations: u32,
    #[serde(default)]
    pub allocations_disabled: bool,
    /// 0 = unlimited when `bandwidth_disabled` is false.
    #[serde(alias = "max_bytes_per_sec")]
    pub max_bytes_per_sec_per_allocation: u64,
    #[serde(default)]
    pub bandwidth_disabled: bool,
    /// 0 = bootstrap ceiling when `lifetime_disabled` is false.
    pub max_lifetime_secs: u32,
    #[serde(default)]
    pub lifetime_disabled: bool,
    #[serde(default)]
    pub inherited_fields: Vec<String>,
    /// §7-B: fields clamped to a finite node ceiling.
    #[serde(default)]
    pub capped_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserLimitsState {
    #[serde(default)]
    pub schema_version: u32,
    pub node_id: String,
    pub subject_key: String,
    pub target: UserLimitTarget,
    #[serde(default)]
    pub incarnation: String,
    pub desired_version: u64,
    pub observed_version: u64,
    pub desired_patch: UserLimitsPatch,
    pub observed_patch: UserLimitsPatch,
    pub status: String,
    #[serde(default)]
    pub last_error: String,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub last_applied: Option<AppliedOperation>,
}

#[derive(Debug, Clone, Copy)]
pub struct ObservationOutcome<'a> {
    pub status: &'a str,
    pub error: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateConfigCommand {
    pub schema_version: u32,
    pub expected_version: u64,
    pub max_allocations: Option<usize>,
    pub max_allocations_per_user: Option<usize>,
    #[serde(alias = "max_bytes_per_sec")]
    pub max_bytes_per_sec_per_allocation: Option<u64>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateConfigResult {
    pub request_id: String,
    pub previous_version: u64,
    pub observed_version: u64,
    pub changed: bool,
    pub applied: RuntimeConfigSnapshot,
    pub terminal_status: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub rolled_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetUserLimitsCommand {
    pub schema_version: u32,
    pub expected_version: u64,
    pub target: UserLimitTarget,
    pub patch: UserLimitsPatch,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetUserLimitsResult {
    pub request_id: String,
    pub previous_version: u64,
    pub observed_version: u64,
    pub effective: EffectiveUserLimits,
    pub max_user_allocations_in_scope: u32,
    pub max_user_allocations_above_limit: bool,
    pub terminal_status: String,
    #[serde(default)]
    pub error: String,
}

/// P0 #4: a durable, node-targeted command in the control→node command log.
/// The control-plane enqueues a command; the owning node claims it (CAS
/// pending→in_progress), applies it to its real runtime state, and marks it
/// done/failed. `request_id` gives idempotency/dedup; `target_node_id` fences
/// application to the intended node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommand {
    pub request_id: String,
    pub target_node_id: String,
    pub op: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Typed JSON payload for versioned commands. Legacy operations continue to
    /// use `args`; new operations hash and decode this canonical payload.
    #[serde(default)]
    pub payload_json: String,
    /// Process incarnation the command is fenced to. Empty is accepted only for
    /// legacy commands created before incarnation fencing.
    #[serde(default)]
    pub target_incarnation: String,
    /// "pending" | "in_progress" | "done" | "failed"
    pub status: String,
    #[serde(default)]
    pub result: String,
    pub created_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    /// Node that currently holds the claim (P0.4 fencing). Empty while `pending`.
    #[serde(default)]
    pub claimed_by: String,
    /// Wall-clock deadline (epoch ms) of the current claim's lease. An
    /// `in_progress` command past this may be reclaimed by another claim (P0.2).
    #[serde(default)]
    pub lease_until_ms: u64,
    /// How many times this command has been claimed (incremented on each claim,
    /// including lease-expiry reclaims). Bounds retries.
    #[serde(default)]
    pub attempts: u32,
    /// Unique token minted on each successful claim (P0.4 fencing). A completion
    /// must present the token of the claim it belongs to; a stale claimant whose
    /// lease expired and was reclaimed holds an old token and is rejected — even
    /// if the reclaiming worker shares the same `claimed_by` node id.
    #[serde(default)]
    pub claim_token: String,
    /// Client-supplied idempotency key (P0.3). When non-empty, `enqueue_command`
    /// deduplicates on it: a retry carrying the same key returns the original
    /// command's `request_id` instead of creating a second command, so a
    /// management operation runs at most once even if the API caller retries.
    /// Empty = no idempotency (each call is a distinct command, as before).
    #[serde(default)]
    pub idempotency_key: String,
}

/// A durable idempotency record for a command-log key. It deliberately outlives
/// the command it guards (see `CommandLogConfig::retain_idempotency_secs`) so a
/// replay arriving after the command row has been GC'd still returns the
/// original outcome instead of re-running the operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// Canonical `request_id` of the command this key first created.
    pub request_id: String,
    /// Stable hash of the normalized `(op, args)` payload. A replay with the
    /// same key but a different payload is a conflict, not a dedup hit.
    pub payload_hash: String,
    /// Terminal status of the guarded command once known (`""` while pending).
    #[serde(default)]
    pub final_status: String,
    /// Result of the guarded command once terminal.
    #[serde(default)]
    pub result: String,
    /// When the record was created (epoch ms).
    pub created_at_ms: u64,
    /// When the guarded command reached a terminal state (epoch ms), or `0`.
    #[serde(default)]
    pub completed_at_ms: u64,
}

/// Resolved command-log retention windows (epoch-ms deltas) + GC batch bounds.
/// Lives in the backend crate (not `turna-config`) so the backend stays free of
/// a config dependency; the control-plane maps `CommandLogConfig` onto this.
#[derive(Debug, Clone, Copy)]
pub struct CommandLogRetention {
    pub done_ms: u64,
    pub failed_ms: u64,
    pub superseded_ms: u64,
    pub expired_ms: u64,
    pub idempotency_ms: u64,
    /// Max records deleted per batch.
    pub batch: usize,
    /// Max batches per sweep.
    pub max_batches: u32,
}

/// Result of one command-log GC sweep, for logging + metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    pub deleted_commands: u64,
    pub deleted_idempotency: u64,
    /// Terminal commands still present after the sweep.
    pub terminal_remaining: u64,
    /// Age of the oldest non-terminal command (epoch-ms delta), for backlog alerts.
    pub oldest_unfinished_age_ms: u64,
    /// Backend GC errors during this sweep (0 for the in-memory backend, which
    /// cannot fail). The control-plane sweep degrades on a sustained non-zero.
    pub errors: u64,
}

/// Result of one bounded command-log schema migration batch. The cursor and
/// cumulative count are persisted by the backend so interrupted upgrades resume
/// without rescanning the whole command space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandLogMigrationProgress {
    pub processed_in_batch: u64,
    pub total_processed: u64,
    pub cursor: String,
    pub completed: bool,
    /// #4 (B): current phase — `commands` | `idempotency` | `complete`.
    pub phase: String,
}

/// Stable, dependency-free content hash of a command's `(op, args)` payload,
/// used to distinguish an idempotency-key *retry* (same payload) from key
/// *reuse* with a different payload (a conflict). Length-prefixed so field
/// boundaries never collide by concatenation. FNV-1a/64 — deterministic across
/// nodes and restarts; not a cryptographic digest (management payloads are
/// authenticated, so collision-crafting is out of the threat model; swap in
/// SHA-256 if that changes).
pub fn command_payload_hash(op: &str, args: &[String], payload_json: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    fn feed(h: &mut u64, bytes: &[u8]) {
        for &b in bytes {
            *h ^= b as u64;
            *h = h.wrapping_mul(FNV_PRIME);
        }
    }
    let mut h = FNV_OFFSET;
    feed(&mut h, &(op.len() as u64).to_le_bytes());
    feed(&mut h, op.as_bytes());
    if payload_json.is_empty() {
        feed(&mut h, &(args.len() as u64).to_le_bytes());
        for a in args {
            feed(&mut h, &(a.len() as u64).to_le_bytes());
            feed(&mut h, a.as_bytes());
        }
    } else {
        feed(&mut h, &(payload_json.len() as u64).to_le_bytes());
        feed(&mut h, payload_json.as_bytes());
    }
    format!("{h:016x}")
}

/// Max claim attempts before a command is dead-lettered (moved to terminal
/// `failed`) instead of being reclaimed again — bounds infinite retry (P0.2).
pub const MAX_COMMAND_ATTEMPTS: u32 = 5;

/// Mint a process-unique, monotonic claim token (P0.4). Dependency-free: node
/// id + pid + nanoseconds + a monotonic counter, so no two claims — across
/// threads, lease reclaims, or same-millisecond bursts — share a token.
pub fn new_claim_token(node_id: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{node_id}-{}-{nanos}-{seq}", std::process::id())
}

// ── Backend enum dispatch ──────────────────────────────────────────

pub enum Backend {
    Memory(memory::InMemoryBackend),
    #[cfg(feature = "tarantool")]
    Tarantool(tarantool::TarantoolBackend),
}

macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            Backend::Memory(b) => b.$method($($arg),*).await,
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.$method($($arg),*).await,
        }
    };
}

impl Backend {
    pub async fn store_allocation(&self, alloc: &StoredAllocation) -> Result<()> {
        dispatch!(self, store_allocation, alloc)
    }
    pub async fn get_allocation(&self, relay_port: u16) -> Result<Option<StoredAllocation>> {
        dispatch!(self, get_allocation, relay_port)
    }
    pub async fn remove_allocation(&self, relay_port: u16) -> Result<()> {
        dispatch!(self, remove_allocation, relay_port)
    }
    pub async fn find_by_user(&self, user_id: &str) -> Result<Vec<StoredAllocation>> {
        dispatch!(self, find_by_user, user_id)
    }
    pub async fn find_by_node(&self, node_id: &str) -> Result<Vec<StoredAllocation>> {
        dispatch!(self, find_by_node, node_id)
    }
    pub async fn find_expired(&self, before_ms: u64) -> Result<Vec<StoredAllocation>> {
        dispatch!(self, find_expired, before_ms)
    }
    pub async fn list_allocations(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<StoredAllocation>> {
        dispatch!(self, list_allocations, offset, limit)
    }
    pub async fn count_allocations(&self) -> Result<u64> {
        dispatch!(self, count_allocations)
    }
    pub async fn update_bandwidth(
        &self,
        relay_port: u16,
        bytes_in: u64,
        bytes_out: u64,
        packets_in: u64,
        packets_out: u64,
    ) -> Result<()> {
        dispatch!(
            self,
            update_bandwidth,
            relay_port,
            bytes_in,
            bytes_out,
            packets_in,
            packets_out
        )
    }
    pub async fn heartbeat(&self, hb: &NodeHeartbeat) -> Result<()> {
        dispatch!(self, heartbeat, hb)
    }
    pub async fn get_live_nodes(&self, max_age: Duration) -> Result<Vec<NodeHeartbeat>> {
        dispatch!(self, get_live_nodes, max_age)
    }
    pub async fn store_room(&self, room: &StoredRoom) -> Result<()> {
        dispatch!(self, store_room, room)
    }
    pub async fn get_room(&self, room_id: &str) -> Result<Option<StoredRoom>> {
        dispatch!(self, get_room, room_id)
    }
    pub async fn remove_room(&self, room_id: &str) -> Result<()> {
        dispatch!(self, remove_room, room_id)
    }

    #[cfg_attr(not(feature = "tarantool"), allow(unused_variables))]
    pub async fn revoke_token(
        &self,
        jti: &str,
        sub: &str,
        revoked_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.revoke_token(jti, sub, revoked_at_ms, expires_at_ms).await,
            Backend::Memory(_) => Ok(()),
        }
    }

    #[cfg_attr(not(feature = "tarantool"), allow(unused_variables))]
    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.is_token_revoked(jti).await,
            Backend::Memory(_) => Ok(false),
        }
    }

    #[cfg_attr(not(feature = "tarantool"), allow(unused_variables))]
    pub async fn cleanup_revoked_tokens(&self, before_ms: u64) -> Result<u64> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.cleanup_revoked_tokens(before_ms).await,
            Backend::Memory(_) => Ok(0),
        }
    }

    #[cfg_attr(not(feature = "tarantool"), allow(unused_variables))]
    pub async fn load_active_revocations(&self, after_ms: u64) -> Result<Vec<(String, u64)>> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.load_active_revocations(after_ms).await,
            Backend::Memory(_) => Ok(vec![]),
        }
    }

    pub async fn ping(&self) -> Result<()> {
        dispatch!(self, ping)
    }

    // ── User store (R8: runtime long-term users) ──────────────────────────────
    //
    // Cluster-shared auth state, like the token blacklist: the source of truth
    // is Tarantool. On the in-memory backend this is process-local (single-node
    // / dev convenience) — it cannot synchronise users across separate
    // processes, so a multi-process cluster MUST use the Tarantool backend.

    pub async fn store_user(&self, user: &StoredUser) -> Result<()> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.store_user(user).await,
            Backend::Memory(b) => b.store_user(user).await,
        }
    }

    pub async fn get_user(&self, username: &str, realm: &str) -> Result<Option<StoredUser>> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.get_user(username, realm).await,
            Backend::Memory(b) => b.get_user(username, realm).await,
        }
    }

    pub async fn remove_user(&self, username: &str, realm: &str) -> Result<bool> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.remove_user(username, realm).await,
            Backend::Memory(b) => b.remove_user(username, realm).await,
        }
    }

    pub async fn list_users(&self) -> Result<Vec<StoredUser>> {
        match self {
            #[cfg(feature = "tarantool")]
            Backend::Tarantool(b) => b.list_users().await,
            Backend::Memory(b) => b.list_users().await,
        }
    }

    // ── Failover (PR 5, task #3) ──────────────────────────────────────────────

    /// Atomically transfer ownership of an allocation from `expected_node_id`
    /// to `new_node_id`.
    ///
    /// Returns:
    /// - `Ok(true)`  — the record existed, its `node_id` matched
    ///   `expected_node_id`, and it has been updated to `new_node_id`.
    /// - `Ok(false)` — the record does not exist, or its `node_id` did
    ///   not match (another node won the race). Caller should skip.
    /// - `Err(_)`    — backend error (transport, serialization, etc.).
    ///   Caller should log and retry on the next failover sweep.
    ///
    /// **Atomicity** is critical: two surviving nodes may both observe
    /// that node-X is dead and try to claim the same allocation. CAS
    /// guarantees exactly one wins. The other gets `Ok(false)` and moves
    /// on without disturbing the state.
    pub async fn claim_allocation(
        &self,
        relay_port: u16,
        expected_node_id: &str,
        new_node_id: &str,
    ) -> Result<bool> {
        dispatch!(
            self,
            claim_allocation,
            relay_port,
            expected_node_id,
            new_node_id
        )
    }

    // ── Durable runtime configuration / limits ───────────────────────────

    pub async fn get_runtime_state(&self, node_id: &str) -> Result<Option<NodeRuntimeState>> {
        dispatch!(self, get_runtime_state, node_id)
    }

    /// Adopt all durable runtime/limits records for `node_id` into the current
    /// process incarnation. Called once during startup, before readiness and
    /// before the command consumer starts. This is the only path allowed to
    /// replace an old incarnation without changing desired/observed versions.
    pub async fn adopt_node_incarnation(&self, node_id: &str, incarnation: &str) -> Result<()> {
        dispatch!(self, adopt_node_incarnation, node_id, incarnation)
    }

    pub async fn cas_runtime_desired(
        &self,
        node_id: &str,
        expected_observed_version: u64,
        incarnation: &str,
        desired: &RuntimeConfigSnapshot,
    ) -> Result<bool> {
        dispatch!(
            self,
            cas_runtime_desired,
            node_id,
            expected_observed_version,
            incarnation,
            desired
        )
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
        dispatch!(
            self,
            confirm_runtime_observed,
            node_id,
            desired_version,
            incarnation,
            observed,
            status,
            error,
            applied
        )
    }

    pub async fn get_user_limits_state(
        &self,
        node_id: &str,
        subject_key: &str,
    ) -> Result<Option<UserLimitsState>> {
        dispatch!(self, get_user_limits_state, node_id, subject_key)
    }

    pub async fn list_user_limits_states(&self, node_id: &str) -> Result<Vec<UserLimitsState>> {
        dispatch!(self, list_user_limits_states, node_id)
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
        dispatch!(
            self,
            cas_user_limits_desired,
            node_id,
            subject_key,
            expected_observed_version,
            incarnation,
            target,
            desired
        )
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
        dispatch!(
            self,
            confirm_user_limits_observed,
            node_id,
            subject_key,
            desired_version,
            incarnation,
            observed,
            outcome,
            applied
        )
    }

    // ── Command log (P0 #4) ────────────────────────────────────

    /// Enqueue a command for a node to apply. Idempotent on `request_id`:
    /// re-enqueuing the same id is a no-op (dedup).
    /// Enqueue a command. Returns the **canonical** `request_id` the caller
    /// should poll: normally `cmd.request_id`, but if `cmd.idempotency_key` is
    /// non-empty and a command with that key already exists, the existing
    /// command's `request_id` is returned and no new command is created (P0.3
    /// cross-retry idempotency). A dedup hit returns the prior command whatever
    /// its status (pending/in_progress/done/failed) — same key, same outcome.
    pub async fn enqueue_command(&self, cmd: &PendingCommand) -> Result<String> {
        dispatch!(self, enqueue_command, cmd)
    }

    /// Atomically claim up to `max` pending commands targeted at `node_id`,
    /// flipping each pending→in_progress. Only the owning node claims its
    /// commands (fencing by `target_node_id`).
    pub async fn claim_commands(
        &self,
        node_id: &str,
        incarnation: &str,
        max: usize,
        lease_ms: u64,
    ) -> Result<Vec<PendingCommand>> {
        dispatch!(self, claim_commands, node_id, incarnation, max, lease_ms)
    }

    /// Mark a claimed command done/failed. Fenced (P0.4): the write applies only
    /// if the row is `in_progress`, `claimed_by` matches, AND `claim_token`
    /// matches the token minted for that claim. Returns `Ok(true)` when applied,
    /// `Ok(false)` when the completion was stale/foreign and ignored (a
    /// `StaleClaim`) so the caller can log/alert instead of assuming success.
    pub async fn complete_command(
        &self,
        request_id: &str,
        claimed_by: &str,
        claim_token: &str,
        status: &str,
        result: &str,
    ) -> Result<bool> {
        dispatch!(
            self,
            complete_command,
            request_id,
            claimed_by,
            claim_token,
            status,
            result
        )
    }

    /// Fetch a command by id (control-plane polls this to await completion).
    /// §2.3/§2.4: atomically finalize a *stale-incarnation* non-terminal command
    /// to `done` with a caller-built typed result. Fenced: acts only when the
    /// command exists, is non-terminal, and its `target_incarnation` is non-empty
    /// and differs from `current_incarnation` (a live or legacy command is left
    /// untouched). Bypasses claim-token fencing — a stale command was never
    /// claimed by the current process. Returns `true` iff it transitioned the
    /// command to `done`.
    pub async fn finalize_stale_command(
        &self,
        request_id: &str,
        current_incarnation: &str,
        result: &str,
    ) -> Result<bool> {
        dispatch!(
            self,
            finalize_stale_command,
            request_id,
            current_incarnation,
            result
        )
    }

    /// §2.4: list up to `max` non-terminal commands targeting `node_id` whose
    /// `target_incarnation` is non-empty and differs from `current_incarnation`
    /// (left behind by a prior incarnation; `claim_commands` fences them out).
    pub async fn list_stale_commands(
        &self,
        node_id: &str,
        current_incarnation: &str,
        max: usize,
    ) -> Result<Vec<PendingCommand>> {
        dispatch!(self, list_stale_commands, node_id, current_incarnation, max)
    }

    pub async fn get_command(&self, request_id: &str) -> Result<Option<PendingCommand>> {
        dispatch!(self, get_command, request_id)
    }

    /// Fetch the durable idempotency record for a key, if any. Unlike a command
    /// row, this record outlives the command (see `retain_idempotency_secs`), so
    /// after GC has pruned the command a replay can still recover the original
    /// terminal outcome from here instead of polling a row that will never
    /// reappear (the post-GC replay path in `enqueue_and_await`).
    pub async fn get_idempotency(&self, key: &str) -> Result<Option<IdempotencyRecord>> {
        dispatch!(self, get_idempotency, key)
    }

    /// #4: durably persist a terminal business outcome (`no_op` / `conflict` /
    /// `failed`) into the keyed idempotency journal BEFORE `complete_command`,
    /// so a lost completion replays the ORIGINAL outcome instead of re-running
    /// validation/CAS against since-changed state. `applied` is journaled
    /// atomically inside `confirm_*_observed`; this covers the non-mutating
    /// outcomes with the same journal contract. Only touches the existing
    /// canonical record; never downgrades a terminal one (same outcome →
    /// `Ok(true)`, different outcome → `Conflict`); empty key → `Ok(false)`.
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
        dispatch!(
            self,
            record_command_outcome,
            request_id,
            idempotency_key,
            payload_hash,
            final_status,
            result,
            completed_at_ms
        )
    }

    pub async fn migrate_command_log_batch(
        &self,
        batch_size: usize,
        owner: &str,
    ) -> Result<CommandLogMigrationProgress> {
        dispatch!(self, migrate_command_log_batch, batch_size, owner)
    }

    /// Prune terminal commands and aged idempotency records. This is best
    /// effort: it returns partial `GcStats` on a backend error rather than
    /// stalling the dataplane, and remains bounded by the configured batch and
    /// maximum-batch limits.
    pub async fn gc_command_log(&self, retention: CommandLogRetention, now_ms: u64) -> GcStats {
        dispatch!(self, gc_command_log, retention, now_ms)
    }
}

// ── Factory ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[derive(Default)]
pub enum BackendConfig {
    #[serde(rename = "memory")]
    #[default]
    Memory,
    #[serde(rename = "tarantool")]
    Tarantool {
        /// `host:port` of the Tarantool server.
        uri: String,
        /// Authenticated user. When `None` the connection runs as the
        /// anonymous `guest` user — which works on a default Tarantool
        /// install with public spaces, but is unsuitable for production.
        ///
        /// Pass via `[cluster.backend.user]` in `turn.toml` or the
        /// `TURNA_BACKEND_USER` env var.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        /// Password for the named user. Use `${TURNA_BACKEND_PASSWORD}` or
        /// `file:///run/secrets/tarantool-password` in `turn.toml` — never
        /// hard-code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
        /// Number of parallel TCP connections to maintain to Tarantool.
        ///
        /// The legacy single-`Mutex<TcpStream>` model serialised every
        /// backend operation onto one in-flight request, which became
        /// the bottleneck of the write-behind writer at high load.
        /// Defaults to 8: matches a typical Tarantool default
        /// `iproto_threads` and gives ample parallelism for the
        /// writer + heartbeat + failover sweep concurrently.
        ///
        /// `None` → use the default (`DEFAULT_POOL_SIZE`). Range `1..=64`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pool_size: Option<usize>,
    },
}

/// Default size of the per-`TarantoolBackend` TCP connection pool. See
/// `BackendConfig::Tarantool::pool_size`.
pub const DEFAULT_POOL_SIZE: usize = 8;

pub async fn create_backend(config: &BackendConfig) -> Result<Backend> {
    match config {
        BackendConfig::Memory => {
            tracing::info!("state backend: in-memory (single-node mode)");
            Ok(Backend::Memory(memory::InMemoryBackend::new()))
        }
        #[cfg(feature = "tarantool")]
        BackendConfig::Tarantool { uri, user, password, pool_size } => {
            let pool_size = pool_size.unwrap_or(DEFAULT_POOL_SIZE).clamp(1, 64);
            tracing::info!(%uri,
                user = ?user.as_deref().unwrap_or("guest"),
                pool_size,
                "state backend: tarantool");
            let b = tarantool::TarantoolBackend::connect_pool(
                uri,
                user.as_deref(),
                password.as_deref(),
                pool_size,
            ).await?;
            b.init_schema().await?;
            Ok(Backend::Tarantool(b))
        }
        #[cfg(not(feature = "tarantool"))]
        BackendConfig::Tarantool { .. } => {
            Err(BackendError::Other(
                "Tarantool backend not compiled. Add features = [\"tarantool\"] to turna-state-backend dependency.".into()
            ))
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub use memory::InMemoryBackend;

#[cfg(test)]
mod payload_hash_tests {
    //! Test vectors for the canonical [`command_payload_hash`]. The command-log
    //! migration recomputes legacy hashes with this exact function (never a Lua
    //! copy), so these vectors pin its contract: determinism, the empty-payload
    //! branch (hash over `op` + `args`) vs the typed-payload branch (hash over
    //! `op` + `payload_json`, ignoring `args`), and length-prefix separation.
    use super::command_payload_hash;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn deterministic_for_identical_inputs() {
        let a = command_payload_hash("drain", &s(&["node-1"]), "");
        let b = command_payload_hash("drain", &s(&["node-1"]), "");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16); // 16 lowercase hex chars ({h:016x})
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn typed_payload_ignores_args() {
        // Non-empty payload_json → hashed over (op, payload_json); args excluded.
        let with_args = command_payload_hash("update_config", &s(&["ignored"]), r#"{"v":1}"#);
        let no_args = command_payload_hash("update_config", &[], r#"{"v":1}"#);
        assert_eq!(with_args, no_args);
    }

    #[test]
    fn empty_payload_hashes_args() {
        // Empty payload_json → hashed over (op, args); different args differ.
        let a = command_payload_hash("delete_allocation", &s(&["alloc-a"]), "");
        let b = command_payload_hash("delete_allocation", &s(&["alloc-b"]), "");
        assert_ne!(a, b);
    }

    #[test]
    fn length_prefix_prevents_boundary_collision() {
        // Length prefixing means concatenation can't collide across fields:
        // op "ab"+arg "c" must not equal op "a"+arg "bc".
        let x = command_payload_hash("ab", &s(&["c"]), "");
        let y = command_payload_hash("a", &s(&["bc"]), "");
        assert_ne!(x, y);
    }

    #[test]
    fn distinct_op_or_payload_differs() {
        assert_ne!(
            command_payload_hash("drain", &[], r#"{"x":1}"#),
            command_payload_hash("undrain", &[], r#"{"x":1}"#),
        );
        assert_ne!(
            command_payload_hash("update_config", &[], r#"{"x":1}"#),
            command_payload_hash("update_config", &[], r#"{"x":2}"#),
        );
    }
}
