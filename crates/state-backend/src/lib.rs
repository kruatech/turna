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

// ── Backend enum dispatch ─────────────────────────────────────────────────────

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

    pub async fn revoke_token(
        &self,
        jti: &str,
        sub: &str,
        revoked_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<()> {
        match self {
            Backend::Tarantool(b) => b.revoke_token(jti, sub, revoked_at_ms, expires_at_ms).await,
            Backend::Memory(_) => Ok(()),
        }
    }

    pub async fn is_token_revoked(&self, jti: &str) -> Result<bool> {
        match self {
            Backend::Tarantool(b) => b.is_token_revoked(jti).await,
            Backend::Memory(_) => Ok(false),
        }
    }

    pub async fn cleanup_revoked_tokens(&self, before_ms: u64) -> Result<u64> {
        match self {
            Backend::Tarantool(b) => b.cleanup_revoked_tokens(before_ms).await,
            Backend::Memory(_) => Ok(0),
        }
    }

    pub async fn load_active_revocations(&self, after_ms: u64) -> Result<Vec<(String, u64)>> {
        match self {
            Backend::Tarantool(b) => b.load_active_revocations(after_ms).await,
            Backend::Memory(_) => Ok(vec![]),
        }
    }

    pub async fn ping(&self) -> Result<()> {
        dispatch!(self, ping)
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
