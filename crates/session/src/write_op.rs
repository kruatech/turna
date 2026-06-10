//! Write-behind event log for [`AllocationStore`](crate::AllocationStore).
//!
//! See `docs/design/allocation-store-persistence.md` (§4) for the rationale.
//!
//! # Lifecycle
//!
//! The hot path mutates `AllocationStore`'s in-memory state synchronously,
//! then emits a [`WriteOp`] into a tokio mpsc channel. A separate async
//! writer task (lives outside this crate — see `services/node/src/main.rs`)
//! drains the channel, batches events, and flushes them to a persistence
//! backend (Tarantool in production, in-memory for tests).
//!
//! # Why a dedicated event type rather than `StoredAllocation`
//!
//! Several reasons:
//!
//! 1. **Small per-mutation payload.** A `Refresh` only needs a relay port
//!    and a new expiry timestamp — no point copying the entire allocation.
//! 2. **No tight coupling to `turna-state-backend`.** This crate stays
//!    backend-agnostic. The writer task is what knows how to translate a
//!    `WriteOp` into a `Backend` call.
//! 3. **Coalescing.** With separate event variants, the writer can collapse
//!    `Create` + `Refresh` for the same port into a single `Create` with
//!    the updated expiry, etc. See design doc §4 D4.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

/// Convert a wall-clock instant into milliseconds since the Unix epoch.
///
/// We use `SystemTime` rather than `std::time::Instant` here because
/// `Instant` is opaque and not comparable across processes — the writer
/// task and the failover-claim task on a peer node both reason in epoch
/// milliseconds (matching `StoredAllocation::expires_at_ms`).
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// A single durable side-effect that follows an in-memory mutation.
///
/// The variants intentionally mirror — but are not identical to — the
/// methods on [`AllocationStore`](crate::AllocationStore). For example,
/// `add_permission` and `add_channel` cover both the "create" and
/// "refresh" cases on the in-memory side; on the wire we always send the
/// full new expiry so the writer can be stateless.
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// A brand-new allocation was created.
    ///
    /// Carries everything the backend needs to reconstruct the allocation
    /// after a restart, *except* the cryptographic key (see design doc §9
    /// question 4 — failover with ephemeral credentials is deferred).
    Create {
        relay_port: u16,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        created_at_ms: u64,
        expires_at_ms: u64,
        /// RFC 8016 stable allocation identity, persisted so a MOBILITY-TICKET
        /// minted by this node still validates after a cross-node failover
        /// rehydrates the allocation elsewhere.
        allocation_id: String,
        /// RFC 8016 migration generation at creation time (always 0 for a
        /// fresh allocation; carried explicitly so the persist path is
        /// uniform with `ReKey`).
        migration_epoch: u64,
    },

    /// Allocation lifetime was extended (or it expired naturally if
    /// `expires_at_ms` is in the past — though in practice we send
    /// `Remove` for the zero-lifetime case).
    Refresh { relay_port: u16, expires_at_ms: u64 },

    /// Allocation was removed (Refresh with lifetime=0, explicit cleanup,
    /// or expiry sweep).
    Remove { relay_port: u16 },

    /// Allocation was re-keyed from one client 5-tuple to another
    /// (RFC 8016 Connection Migration). The relay binding, permissions and
    /// channels are unchanged — only the client address moves. The writer
    /// updates the persisted record's `client_addr` column in place; the
    /// relay port (the coalescing owner key) is the join handle.
    ReKey {
        relay_port: u16,
        new_client_addr: SocketAddr,
        /// The migration generation *after* the re-key bump. Persisted so the
        /// backend record's epoch tracks the in-memory one — a captured
        /// older-epoch ticket then stays rejected even after a failover.
        new_epoch: u64,
    },

    /// A peer-address permission was added or refreshed.
    Permission {
        relay_port: u16,
        peer_ip: IpAddr,
        expires_at_ms: u64,
    },

    /// A channel binding was added or refreshed.
    Channel {
        relay_port: u16,
        number: u16,
        peer_addr: SocketAddr,
        expires_at_ms: u64,
    },
}

impl WriteOp {
    /// Relay port that "owns" this event — used by the writer task to
    /// coalesce multiple events for the same allocation into one batch
    /// entry (see design doc §4 D4).
    pub fn relay_port(&self) -> u16 {
        match self {
            WriteOp::Create { relay_port, .. }
            | WriteOp::Refresh { relay_port, .. }
            | WriteOp::Remove { relay_port }
            | WriteOp::ReKey { relay_port, .. }
            | WriteOp::Permission { relay_port, .. }
            | WriteOp::Channel { relay_port, .. } => *relay_port,
        }
    }
}
