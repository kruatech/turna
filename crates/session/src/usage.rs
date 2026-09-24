//! Usage (accounting) records — who relayed how much, for how long.
//!
//! # Where these come from
//!
//! The datapath already keeps per-allocation atomics (`bytes_relayed`,
//! `packets_relayed`, and the peer→client share). A record is a *read* of those
//! at a lifecycle event — teardown, or an interim tick in the node — so building
//! one costs nothing on the packet path. The store builds a `Stop` record in the
//! same function that folds an allocation into the per-tenant totals, which every
//! removal path already calls; a new removal path that forgot it would break the
//! tenant counters too, and those are tested.
//!
//! # What the numbers are
//!
//! Relayed **payload** bytes: the application data inside ChannelData or a
//! Send/Data indication, not the TURN framing and not STUN control traffic. The
//! client leg and the peer leg carry the same payload, so "from client" is both
//! what arrived on the client leg and what left on the peer leg; likewise "to
//! client". Packets dropped by the bandwidth quota or a missing permission are
//! not counted — they were not relayed.
//!
//! RFC 6062 TCP allocations are not counted: their data flows through a spliced
//! TCP connection that does not touch these counters. Their records carry
//! `bytes_counted = false` so a billing pipeline can tell "zero bytes" from "not
//! measured".
//!
//! # Identity
//!
//! `username`, `realm` and `tenant` are what the allocation authenticated with.
//! The client address is carried here and it is the sink that decides whether to
//! write it (`[turn.accounting] include_addresses`, off by default).

use std::net::SocketAddr;

use crate::{Allocation, TransportProto};

/// Payload relayed by one allocation, by direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllocationUsage {
    pub bytes_from_client: u64,
    pub packets_from_client: u64,
    pub bytes_to_client: u64,
    pub packets_to_client: u64,
}

/// Interim (allocation still live, cumulative so far) or stop (final).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageRecordKind {
    Interim,
    Stop,
}

impl UsageRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UsageRecordKind::Interim => "interim",
            UsageRecordKind::Stop => "stop",
        }
    }
}

/// Why an allocation ended. A contract once a billing system keys on it, like a
/// metric name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageEndReason {
    /// Lifetime ran out without a Refresh.
    Expired,
    /// The client released it (Refresh with lifetime 0).
    Released,
    /// Deleted through the management API.
    AdminDeleted,
    /// Lost during a failed migration, with nowhere to put it back.
    MigrationLost,
}

impl UsageEndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            UsageEndReason::Expired => "expired",
            UsageEndReason::Released => "released",
            UsageEndReason::AdminDeleted => "admin_deleted",
            UsageEndReason::MigrationLost => "migration_lost",
        }
    }
}

/// One accounting record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRecord {
    pub kind: UsageRecordKind,
    /// Set on `Stop` only.
    pub end_reason: Option<UsageEndReason>,
    /// Stable across RFC 8016 migration and across failover to another node.
    pub allocation_id: String,
    pub username: String,
    pub realm: String,
    /// `None` for the base (`[turn]`) realm.
    pub tenant: Option<String>,
    /// Relayed transport: `udp` (RFC 8656) or `tcp` (RFC 6062). The protocol on
    /// the client leg (UDP, TLS, DTLS, QUIC) is not tracked per allocation.
    pub transport: &'static str,
    pub client_addr: SocketAddr,
    pub relay_addr: SocketAddr,
    /// ms since the Unix epoch.
    pub start_ms: u64,
    /// When this record was taken; for `Stop`, when the allocation ended.
    pub event_ms: u64,
    pub usage: AllocationUsage,
    /// False when this allocation's payload is not measured (RFC 6062 TCP).
    pub bytes_counted: bool,
}

impl UsageRecord {
    pub fn from_allocation(
        a: &Allocation,
        kind: UsageRecordKind,
        end_reason: Option<UsageEndReason>,
        event_ms: u64,
    ) -> Self {
        let (transport, bytes_counted) = match a.transport {
            TransportProto::Udp => ("udp", true),
            TransportProto::Tcp => ("tcp", false),
        };
        Self {
            kind,
            end_reason,
            allocation_id: a.allocation_id.clone(),
            username: a.username.clone(),
            realm: a.realm.clone(),
            tenant: a.tenant_id.clone(),
            transport,
            client_addr: a.client_addr,
            relay_addr: a.relay_addr,
            start_ms: a.created_at_ms,
            event_ms,
            usage: a.usage(),
            bytes_counted,
        }
    }

    /// Whole seconds between start and this record.
    pub fn duration_secs(&self) -> u64 {
        self.event_ms.saturating_sub(self.start_ms) / 1000
    }
}
