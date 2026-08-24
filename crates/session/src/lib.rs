//! TURN allocation state and lifecycle management
//!
//! Features:
//! - Permission expiration (5 min per RFC 8656)
//! - Channel binding expiration (10 min per RFC 8656)
//! - Bandwidth quota per user
//! - Multiple allocations per user (different 5-tuples)
//! - Allocation audit trail
//! - **Optional write-behind log** for cluster persistence (see `write_op`
//!   module and `docs/design/allocation-store-persistence.md`)

pub mod write_op;
pub use write_op::{now_ms as epoch_ms, WriteOp};

use dashmap::DashMap;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use arc_swap::ArcSwap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::mpsc;

/// Permission lifetime per RFC 8656 section 9.
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300); // 5 minutes

/// Channel binding lifetime per RFC 8656 section 12.
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600); // 10 minutes

/// How long a port reserved via EVEN-PORT (R=1) is held for the follow-up
/// Allocate that presents the RESERVATION-TOKEN (RFC 8656 §7.2 suggests ~30s).
const RESERVATION_LIFETIME: Duration = Duration::from_secs(30);

/// B5: hard caps on per-allocation resources. Bounds memory on an authenticated
/// session — a client can otherwise send CreatePermission / ChannelBind without
/// limit. Refreshing an existing entry never counts against the cap.
const MAX_PERMISSIONS_PER_ALLOCATION: usize = 256;
const MAX_CHANNELS_PER_ALLOCATION: usize = 256;

/// Per-user allocation tracking is keyed by (realm, tenant, username), not the
/// bare username. Identical usernames in separate authentication namespaces
/// must never share an admission counter or allocation index.
type UserKey = (String, Option<String>, String);

/// Canonical S5 identity. Realm and tenant are both carried so identical
/// usernames in different authentication namespaces never share a limit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LimitSubject {
    pub realm: String,
    pub tenant_id: Option<String>,
    pub username: String,
}

impl LimitSubject {
    pub fn new(
        realm: impl Into<String>,
        tenant_id: Option<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            realm: realm.into(),
            tenant_id,
            username: username.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LimitMode {
    #[default]
    Inherit,
    Value,
    Unlimited,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LimitU32 {
    pub mode: LimitMode,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LimitU64 {
    pub mode: LimitMode,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserLimitsOverride {
    pub max_allocations: Option<LimitU32>,
    pub max_bytes_per_sec_per_allocation: Option<LimitU64>,
    pub max_lifetime_secs: Option<LimitU32>,
}

impl UserLimitsOverride {
    pub fn is_inherit_only(&self) -> bool {
        fn inherit32(value: Option<LimitU32>) -> bool {
            value
                .map(|limit| limit.mode == LimitMode::Inherit)
                .unwrap_or(true)
        }
        fn inherit64(value: Option<LimitU64>) -> bool {
            value
                .map(|limit| limit.mode == LimitMode::Inherit)
                .unwrap_or(true)
        }
        inherit32(self.max_allocations)
            && inherit64(self.max_bytes_per_sec_per_allocation)
            && inherit32(self.max_lifetime_secs)
    }
}

/// One immutable S5 cache. Management updates clone/modify/publish this value;
/// Allocate, Refresh and packet paths only perform local reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLimitsSnapshot {
    /// §8: monotonic cache generation — a LOCAL counter bumped on each actual
    /// publication of a changed snapshot (never on a no-op), independent of any
    /// subject's version. NOT used for CAS/expected_version; per-subject
    /// versions live in the durable UserLimitsState.
    pub generation: u64,
    pub bootstrap_max_lifetime_secs: u32,
    pub global: UserLimitsOverride,
    pub tenants: HashMap<(String, String), UserLimitsOverride>,
    pub users: HashMap<(String, String, String), UserLimitsOverride>,
}

impl UserLimitsSnapshot {
    fn empty() -> Self {
        Self {
            generation: 0,
            bootstrap_max_lifetime_secs: 0,
            global: UserLimitsOverride::default(),
            tenants: HashMap::new(),
            users: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveUserLimits {
    /// 0 means unlimited when `allocations_disabled` is false.
    pub max_allocations: usize,
    pub allocations_disabled: bool,
    /// 0 means unlimited when `bandwidth_disabled` is false.
    pub max_bytes_per_sec_per_allocation: u64,
    pub bandwidth_disabled: bool,
    /// 0 means no additional dynamic ceiling when `lifetime_disabled` is false.
    pub max_lifetime_secs: u32,
    pub lifetime_disabled: bool,
    pub inherited_fields: Vec<String>,
    /// §7-B: fields clamped to a finite node ceiling.
    pub capped_fields: Vec<String>,
}

/// A port reserved under a RESERVATION-TOKEN, pending a follow-up Allocate.
struct Reservation {
    port: u16,
    expires_at: Instant,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("max allocations reached")]
    MaxAllocations,
    #[error("allocation not found")]
    NotFound,
    #[error("no relay ports available")]
    NoPortsAvailable,
    #[error("permission denied for peer {0}")]
    PermissionDenied(SocketAddr),
    #[error("channel not found: 0x{0:04x}")]
    ChannelNotFound(u16),
    #[error("bandwidth quota exceeded for user {0}")]
    BandwidthExceeded(String),
    #[error("max allocations per user reached")]
    MaxAllocationsPerUser,
    /// The migration target 5-tuple already hosts a different allocation.
    /// Re-keying onto it would clobber that allocation, so we refuse.
    #[error("migration target address already in use")]
    MigrationTargetInUse,
    /// ChannelBind violates RFC 8656 §12.2 uniqueness: the channel is already
    /// bound to a different peer, or the peer to a different channel. Maps to
    /// a 400 (Bad Request) response.
    #[error("channel/peer binding conflict")]
    ChannelConflict,
    /// A concurrent Allocate on the same client 5-tuple already created an
    /// allocation for this slot (B1). The loser must release any relay port it
    /// bound; the processor's existing create-error path already does this.
    #[error("allocation already exists for this client address")]
    AllocationExists,
    /// A per-allocation resource cap (permissions or channel bindings) was hit
    /// (B5). Maps to 486 Allocation Quota Reached.
    #[error("per-allocation resource limit exceeded")]
    LimitExceeded,
    /// §8: the monotonic user-limits cache generation would overflow u64. Per the
    /// GA contract this is surfaced as an error rather than panicking; the current
    /// snapshot is left unpublished and unchanged.
    #[error("user-limits cache generation overflow")]
    CacheGenerationOverflow,
}

/// Permission with expiry.
#[derive(Debug, Clone)]
struct Permission {
    _peer_ip: std::net::IpAddr,
    expires_at: Instant,
}

impl Permission {
    fn new(peer_ip: std::net::IpAddr) -> Self {
        Self {
            _peer_ip: peer_ip,
            expires_at: Instant::now() + PERMISSION_LIFETIME,
        }
    }

    fn refresh(&mut self) {
        self.expires_at = Instant::now() + PERMISSION_LIFETIME;
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Channel binding with expiry.
#[derive(Debug, Clone)]
struct ChannelBinding {
    _channel: u16,
    peer_addr: SocketAddr,
    expires_at: Instant,
}

impl ChannelBinding {
    fn new(channel: u16, peer_addr: SocketAddr) -> Self {
        Self {
            _channel: channel,
            peer_addr,
            expires_at: Instant::now() + CHANNEL_LIFETIME,
        }
    }

    fn refresh(&mut self) {
        self.expires_at = Instant::now() + CHANNEL_LIFETIME;
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Relayed transport protocol for an allocation. UDP is the RFC 8656 default;
/// TCP is RFC 6062 (client uses CONNECT/CONNECTION-BIND, no relay UDP socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportProto {
    #[default]
    Udp,
    Tcp,
}

/// A single TURN allocation.
#[derive(Debug)]
pub struct Allocation {
    /// Stable identity, independent of the client 5-tuple. Minted once at
    /// creation and preserved across migration (RFC 8016): a MOBILITY-TICKET
    /// carries this id, and [`AllocationStore::re_key`] moves the allocation
    /// to a new `client_addr` while `allocation_id` stays constant. This is
    /// what lets identity survive a client address change.
    pub allocation_id: String,
    /// Migration generation counter (anti-replay for RFC 8016). Starts at 0;
    /// each successful [`AllocationStore::re_key`] bumps it. A MOBILITY-TICKET
    /// embeds the epoch it was minted at, so a captured older-epoch ticket no
    /// longer matches after a migration — effectively single-use, with no
    /// server-side replay cache.
    pub migration_epoch: u64,
    pub client_addr: SocketAddr,
    pub relay_addr: SocketAddr,
    pub username: String,
    pub key: Vec<u8>,
    /// Authenticated REALM covered by MESSAGE-INTEGRITY.
    pub realm: String,
    /// Owning tenant (multi-tenancy). `None` = base/default tenant.
    pub tenant_id: Option<String>,
    /// Relayed transport (RFC 8656 UDP default; RFC 6062 TCP). TCP allocations
    /// have no bound relay UDP socket — CONNECT/CONNECTION-BIND drive the datapath.
    pub transport: TransportProto,
    /// Permissions with expiry.
    permissions: HashMap<std::net::IpAddr, Permission>,
    /// Channel bindings with expiry.
    channel_bindings: HashMap<u16, ChannelBinding>,
    /// Reverse: peer address -> channel number.
    channels_reverse: HashMap<SocketAddr, u16>,
    /// When allocation expires.
    pub expires_at: Instant,
    pub created_at: Instant,
    /// Bytes relayed total.
    pub bytes_relayed: AtomicU64,
    /// Packets relayed total.
    pub packets_relayed: AtomicU64,
    /// Bytes in current second (for bandwidth limiting).
    bandwidth_window_bytes: AtomicU64,
    bandwidth_window_start: Mutex<Instant>,
}

impl Allocation {
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Check permission, respecting expiry.
    pub fn has_permission(&self, peer: &SocketAddr) -> bool {
        self.permissions
            .get(&peer.ip())
            .map(|p| !p.is_expired())
            .unwrap_or(false)
    }

    pub fn get_channel_peer(&self, channel: u16) -> Option<&SocketAddr> {
        self.channel_bindings
            .get(&channel)
            .filter(|b| !b.is_expired())
            .map(|b| &b.peer_addr)
    }

    pub fn get_peer_channel(&self, peer: &SocketAddr) -> Option<u16> {
        self.channels_reverse.get(peer).copied().filter(|ch| {
            self.channel_bindings
                .get(ch)
                .map(|b| !b.is_expired())
                .unwrap_or(false)
        })
    }

    pub fn add_bytes(&self, n: u64) {
        self.bytes_relayed.fetch_add(n, Ordering::Relaxed);
        self.packets_relayed.fetch_add(1, Ordering::Relaxed);
        self.bandwidth_window_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Check if bandwidth quota is exceeded. Returns current bps.
    #[allow(clippy::result_unit_err)]
    pub fn check_bandwidth(&self, max_bytes_per_sec_per_allocation: u64) -> Result<u64, ()> {
        let mut start = self.bandwidth_window_start.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*start);

        if elapsed >= Duration::from_secs(1) {
            // Roll the window under the lock: capture-and-zero the counter and
            // advance `start` together. `swap` is an atomic RMW, so every byte
            // from a concurrent (lock-free) `add_bytes` lands in exactly one
            // window — none are lost across the boundary.
            let bytes = self.bandwidth_window_bytes.swap(0, Ordering::Relaxed);
            *start = now;
            let bps = (bytes as f64 / elapsed.as_secs_f64()) as u64;
            // Enforce the completed window too (L6): previously a window
            // boundary always returned Ok, letting one packet per second slip
            // past the quota.
            return if bps > max_bytes_per_sec_per_allocation {
                Err(())
            } else {
                Ok(bps)
            };
        }

        let current = self.bandwidth_window_bytes.load(Ordering::Relaxed);
        if current > max_bytes_per_sec_per_allocation {
            Err(())
        } else {
            Ok(current)
        }
    }

    /// Cleanup expired permissions and channel bindings. Returns counts removed.
    pub fn cleanup_expired_entries(&mut self) -> (usize, usize) {
        let perm_before = self.permissions.len();
        self.permissions.retain(|_, p| !p.is_expired());
        let perms_removed = perm_before - self.permissions.len();

        let chan_before = self.channel_bindings.len();
        let expired_channels: Vec<u16> = self
            .channel_bindings
            .iter()
            .filter(|(_, b)| b.is_expired())
            .map(|(ch, _)| *ch)
            .collect();

        for ch in &expired_channels {
            if let Some(binding) = self.channel_bindings.remove(ch) {
                self.channels_reverse.remove(&binding.peer_addr);
            }
        }
        let chans_removed = chan_before - self.channel_bindings.len();

        (perms_removed, chans_removed)
    }

    /// Cheap read-only check: does this allocation have any expired permission
    /// or channel binding to prune? Lets the store classify under a short read
    /// lock and skip taking a write lock (`get_mut`) on allocations that have
    /// nothing stale — the common case between sweeps.
    pub fn has_stale_entries(&self) -> bool {
        self.permissions.values().any(|p| p.is_expired())
            || self.channel_bindings.values().any(|b| b.is_expired())
    }

    /// Time remaining before expiry.
    pub fn time_remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    pub fn permission_count(&self) -> usize {
        self.permissions.len()
    }

    pub fn permission_ips(&self) -> Vec<String> {
        self.permissions.keys().map(|ip| ip.to_string()).collect()
    }

    pub fn channel_list(&self) -> Vec<(u16, std::net::SocketAddr, std::time::Instant)> {
        self.channel_bindings
            .iter()
            .map(|(&ch, b)| (ch, b.peer_addr, b.expires_at))
            .collect()
    }

    pub fn channel_count(&self) -> usize {
        self.channel_bindings.len()
    }
}

/// Port allocator for relay addresses.
pub struct PortAllocator {
    min_port: u16,
    max_port: u16,
    next_port: Mutex<u16>,
    used: Mutex<HashSet<u16>>,
    /// Ports reserved via EVEN-PORT (R=1), keyed by RESERVATION-TOKEN. The port
    /// is also held in `used`; an expired-but-unclaimed reservation is swept
    /// (and its port released) on the next claim attempt. Lock order is always
    /// `used` then `reservations`.
    reservations: Mutex<HashMap<[u8; 8], Reservation>>,
}

/// Address family of a relay socket. Relay ports are drawn from one pool
/// regardless of family: a given port number is bound in exactly one family at a
/// time, which keeps the pool accounting (and `pool_for_port`) unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayFamily {
    V4,
    V6,
}

impl RelayFamily {
    pub fn of(addr: &std::net::SocketAddr) -> Self {
        if addr.is_ipv6() {
            Self::V6
        } else {
            Self::V4
        }
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6)
    }
}

/// Bind one relay UDP socket in `family`.
///
/// A v6 socket is bound with **`IPV6_V6ONLY`**. Without it a v6 wildcard bind also
/// receives v4 traffic on the same port (the Linux default is dual-stack), so one
/// relay port would straddle both families and the "one allocation, one family"
/// invariant would hold only by accident. The path already failed *closed* without
/// the option — a v4-mapped source normalises to plain v4
/// (`peer_filter::normalize_ip`), no v4 permission exists on a v6 allocation, and
/// the 443 family-mismatch check refuses v4 peers up front — but relying on three
/// downstream checks to compensate for a socket bound too widely is the kind of
/// implicit invariant that breaks when one of them is refactored. Now it is
/// explicit at the socket.
///
/// The option must be set between `socket()` and `bind()`, which `std` cannot
/// express, hence `socket2` under `cfg(unix)`. On a non-unix target the std bind is
/// used and the platform default applies; the downstream checks still hold.
fn bind_relay_socket(family: RelayFamily, port: u16) -> std::io::Result<std::net::UdpSocket> {
    match family {
        RelayFamily::V4 => std::net::UdpSocket::bind(("0.0.0.0", port)),
        #[cfg(unix)]
        RelayFamily::V6 => {
            let sock = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            sock.set_only_v6(true)?;
            sock.bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
            Ok(sock.into())
        }
        #[cfg(not(unix))]
        RelayFamily::V6 => std::net::UdpSocket::bind(std::net::SocketAddr::from((
            std::net::Ipv6Addr::UNSPECIFIED,
            port,
        ))),
    }
}

#[cfg(all(test, unix))]
mod v6only_tests {
    use super::*;

    #[test]
    fn v6_relay_socket_is_v6_only() {
        // The point of the option: binding v6 on a port must leave the same v4
        // port free. Without IPV6_V6ONLY this second bind fails with EADDRINUSE on
        // Linux, which is exactly the straddling we do not want.
        let v6 = match bind_relay_socket(RelayFamily::V6, 0) {
            Ok(s) => s,
            // A host with IPv6 disabled cannot exercise this; skip rather than
            // report a failure that is about the environment.
            Err(e) => {
                eprintln!("skipping: no IPv6 on this host ({e})");
                return;
            }
        };
        let port = v6.local_addr().expect("local_addr").port();
        let v4 = std::net::UdpSocket::bind(("0.0.0.0", port));
        assert!(
            v4.is_ok(),
            "v4 bind on port {port} must still be possible; the v6 socket is not \
             v6-only: {v4:?}"
        );
    }
}

impl PortAllocator {
    pub fn new(min_port: u16, max_port: u16) -> Self {
        Self {
            min_port,
            max_port,
            next_port: Mutex::new(min_port),
            used: Mutex::new(HashSet::new()),
            reservations: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `port` falls within this allocator's range. Used to route a
    /// port back to its owning pool on release/reserve (tenant ranges are
    /// disjoint by config validation, so the match is unique).
    pub fn contains(&self, port: u16) -> bool {
        port >= self.min_port && port <= self.max_port
    }

    pub fn allocate(&self) -> Result<u16, SessionError> {
        let mut next = self.next_port.lock();
        let mut used = self.used.lock();
        let start = *next;

        loop {
            if !used.contains(&*next) {
                let port = *next;
                used.insert(port);
                *next = if *next >= self.max_port {
                    self.min_port
                } else {
                    *next + 1
                };
                return Ok(port);
            }
            *next = if *next >= self.max_port {
                self.min_port
            } else {
                *next + 1
            };
            if *next == start {
                return Err(SessionError::NoPortsAvailable);
            }
        }
    }

    pub fn release(&self, port: u16) {
        self.used.lock().remove(&port);
    }

    /// True if the port is currently held by a live allocation.
    pub fn is_allocated(&self, port: u16) -> bool {
        self.used.lock().contains(&port)
    }

    /// Allocate a port AND bind its relay UDP socket, retrying on conflicts.
    ///
    /// Binding here — synchronously, before the caller responds — is what
    /// makes Allocate transactional: we only ever return success for a relay
    /// socket that actually exists. If a candidate port is still held by a
    /// not-yet-reaped relay socket (`EADDRINUSE`), it's returned to the pool
    /// and another is tried. Returns the port and a non-blocking std socket,
    /// or `None` if no port could be bound.
    pub fn allocate_and_bind(&self) -> Option<(u16, std::net::UdpSocket)> {
        self.allocate_and_bind_family(RelayFamily::V4)
    }

    /// Like [`allocate_and_bind`] but binds the relay socket in the requested
    /// address family (RFC 6156 REQUESTED-ADDRESS-FAMILY). A v6 socket is bound
    /// `only_v6`, so a v6 allocation never accidentally serves v4 peers — the
    /// families stay separable, which is what the 443 mismatch check relies on.
    pub fn allocate_and_bind_family(
        &self,
        family: RelayFamily,
    ) -> Option<(u16, std::net::UdpSocket)> {
        for _ in 0..64 {
            let port = self.allocate().ok()?;
            match bind_relay_socket(family, port) {
                Ok(sock) => {
                    let _ = sock.set_nonblocking(true);
                    return Some((port, sock));
                }
                Err(_) => {
                    self.release(port);
                }
            }
        }
        None
    }

    /// Lowest free *even* port in range, marked used. RFC 8656 §18.7 EVEN-PORT.
    fn allocate_even(&self) -> Option<u16> {
        let mut used = self.used.lock();
        let mut p = if self.min_port.is_multiple_of(2) {
            self.min_port
        } else {
            self.min_port.saturating_add(1)
        };
        while p <= self.max_port {
            if !used.contains(&p) {
                used.insert(p);
                return Some(p);
            }
            p = match p.checked_add(2) {
                Some(n) => n,
                None => break,
            };
        }
        None
    }

    /// Allocate an even port AND reserve the next-higher (odd) port under a
    /// fresh token (EVEN-PORT R=1). Both ports are marked used; the odd one is
    /// held only by the reservation until claimed. Returns `(even, token)`.
    fn allocate_even_with_reservation(&self) -> Option<(u16, [u8; 8])> {
        let mut used = self.used.lock();
        let mut p = if self.min_port.is_multiple_of(2) {
            self.min_port
        } else {
            self.min_port.saturating_add(1)
        };
        // Need p+1 within range for the odd reservation, so stop at max_port-1.
        while p < self.max_port {
            let odd = p + 1;
            if !used.contains(&p) && !used.contains(&odd) {
                used.insert(p);
                used.insert(odd);
                let token: [u8; 8] = rand::random();
                self.reservations.lock().insert(
                    token,
                    Reservation {
                        port: odd,
                        expires_at: Instant::now() + RESERVATION_LIFETIME,
                    },
                );
                return Some((p, token));
            }
            p = match p.checked_add(2) {
                Some(n) => n,
                None => break,
            };
        }
        None
    }

    /// Resolve a RESERVATION-TOKEN to its reserved port (still marked used).
    /// Expired reservations are swept and their ports released first. Returns
    /// `None` if the token is unknown or expired.
    fn claim_reservation(&self, token: &[u8; 8]) -> Option<u16> {
        let now = Instant::now();
        let mut used = self.used.lock();
        let mut res = self.reservations.lock();
        res.retain(|_, r| {
            if r.expires_at <= now {
                used.remove(&r.port); // release the leaked reserved port
                false
            } else {
                true
            }
        });
        res.remove(token).map(|r| r.port)
    }

    /// I9: cancel a reservation created by an EVEN-PORT (R=1) allocate — drop the
    /// token and release its reserved port. Used when post-reservation bookkeeping
    /// (e.g. `create_for_tenant`) fails, so the reserved odd port is freed
    /// immediately instead of lingering until the reservation-expiry sweep.
    pub fn cancel_reservation(&self, token: &[u8; 8]) {
        if let Some(r) = self.reservations.lock().remove(token) {
            self.release(r.port);
        }
    }

    /// EVEN-PORT allocate + bind. `reserve_next` mirrors the EVEN-PORT R bit;
    /// when set, the next-higher port is reserved and the token is returned for
    /// the caller to echo as a RESERVATION-TOKEN. Releases everything on bind
    /// failure and retries another even pair.
    pub fn allocate_even_and_bind(
        &self,
        reserve_next: bool,
    ) -> Option<(u16, std::net::UdpSocket, Option<[u8; 8]>)> {
        self.allocate_even_and_bind_family(reserve_next, RelayFamily::V4)
    }

    /// [`allocate_even_and_bind`] in an explicit address family.
    pub fn allocate_even_and_bind_family(
        &self,
        reserve_next: bool,
        family: RelayFamily,
    ) -> Option<(u16, std::net::UdpSocket, Option<[u8; 8]>)> {
        for _ in 0..64 {
            let (even, token) = if reserve_next {
                let (e, t) = self.allocate_even_with_reservation()?;
                (e, Some(t))
            } else {
                (self.allocate_even()?, None)
            };
            match bind_relay_socket(family, even) {
                Ok(sock) => {
                    let _ = sock.set_nonblocking(true);
                    return Some((even, sock, token));
                }
                Err(_) => {
                    self.release(even);
                    if let Some(t) = token {
                        if let Some(r) = self.reservations.lock().remove(&t) {
                            self.release(r.port);
                        }
                    }
                }
            }
        }
        None
    }

    /// Claim a RESERVATION-TOKEN and bind its reserved port. Releases the port
    /// on bind failure. Returns `None` if the token is invalid/expired.
    pub fn claim_and_bind(&self, token: &[u8; 8]) -> Option<(u16, std::net::UdpSocket)> {
        self.claim_and_bind_family(token, RelayFamily::V4)
    }

    /// [`claim_and_bind`] in an explicit address family. Note RFC 8656 §7.2 makes
    /// RESERVATION-TOKEN and REQUESTED-ADDRESS-FAMILY mutually exclusive, so in
    /// practice this is only ever called with `V4` today; the parameter exists so
    /// the three bind paths cannot drift.
    pub fn claim_and_bind_family(
        &self,
        token: &[u8; 8],
        family: RelayFamily,
    ) -> Option<(u16, std::net::UdpSocket)> {
        let port = self.claim_reservation(token)?;
        match bind_relay_socket(family, port) {
            Ok(sock) => {
                let _ = sock.set_nonblocking(true);
                Some((port, sock))
            }
            Err(_) => {
                self.release(port);
                None
            }
        }
    }

    /// Mark a specific port as used without going through the rotating
    /// allocator. Used by [`AllocationStore::rehydrate`] to re-claim ports
    /// of allocations that already existed before this process started.
    ///
    /// Returns `Err(NoPortsAvailable)` if the port is out of the configured
    /// range or already taken. (We reuse `NoPortsAvailable` rather than
    /// introduce a new variant — the caller treats both as "can't use this
    /// record" and proceeds to the next.)
    pub fn reserve(&self, port: u16) -> Result<(), SessionError> {
        if port < self.min_port || port > self.max_port {
            return Err(SessionError::NoPortsAvailable);
        }
        let mut used = self.used.lock();
        if used.contains(&port) {
            return Err(SessionError::NoPortsAvailable);
        }
        used.insert(port);
        Ok(())
    }
}

/// Bandwidth quota configuration.
pub struct BandwidthQuota {
    /// Max bytes per second per allocation. 0 = unlimited.
    pub max_bytes_per_sec_per_allocation: u64,
    /// Max allocations per username. 0 = unlimited.
    pub max_per_user: usize,
}

impl Default for BandwidthQuota {
    fn default() -> Self {
        Self {
            max_bytes_per_sec_per_allocation: 0, // unlimited
            max_per_user: 100,                   // 100 allocations per user
        }
    }
}

/// An isolated relay-port pool for one tenant (multi-tenancy). Disjoint ranges
/// across tenants (config-validated) guarantee a port maps to exactly one pool.
pub struct TenantPool {
    pub id: String,
    pub ports: PortAllocator,
    /// Max simultaneous allocations for this tenant. 0 = unlimited.
    pub max_allocations: usize,
    /// Per-tenant bandwidth / per-user limits. A zero field means "inherit the
    /// global quota" for that dimension.
    pub quota: BandwidthQuota,
}

/// Cumulative relayed traffic for one tenant. Accrued when an allocation is
/// removed (design (a): the per-allocation `bytes_relayed`/`packets_relayed`
/// are folded into the tenant total at teardown, so there is no per-packet
/// hot-path cost). Exposed for billing/observability via
/// [`AllocationStore::tenant_traffic_snapshot`].
#[derive(Default, Clone, Copy)]
pub struct TenantTraffic {
    pub bytes: u64,
    pub packets: u64,
    pub closed_allocations: u64,
}

/// Immutable, atomically-published view of the node-wide runtime limits.
///
/// S4-3: the store holds ONE `ArcSwap<RuntimeLimits>` rather than separate
/// atomics for each field. A runtime `update_config` publishes a whole new
/// snapshot in a single atomic swap, so every reader (allocation admission,
/// per-user quota, bandwidth limiter, metrics, the management read API) always
/// observes a self-consistent set of values plus the `version` they belong to —
/// never a torn mix from a half-applied change. Usage/reservation counters stay
/// as their own atomics; only configuration values live here.
///
/// This is the dataplane-side counterpart of `turna-config`'s `RuntimeSnapshot`;
/// the node command handler translates a validated config snapshot into this
/// type before publishing. `0` follows the existing store conventions:
/// `max_bytes_per_sec_per_allocation == 0` = unlimited bandwidth, `max_per_user == 0` = no
/// per-user cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeLimits {
    /// Observed config version this snapshot corresponds to. Boot = 0; each
    /// successful runtime change increments it by 1 (set by the publisher).
    pub version: u64,
    pub max_bytes_per_sec_per_allocation: u64,
    pub max_per_user: usize,
    pub max_allocations: usize,
}

/// Main allocation store — thread-safe via DashMap.
pub struct AllocationStore {
    allocations: DashMap<SocketAddr, Allocation>,
    relay_to_client: DashMap<SocketAddr, SocketAddr>,
    channel_to_client: DashMap<(u16, u16), SocketAddr>,
    /// Stable-id -> client address index (RFC 8016 Connection Migration).
    /// Lets a Refresh carrying a MOBILITY-TICKET find its allocation by id
    /// even when it arrives from a brand-new 5-tuple. Kept in lock-step with
    /// `allocations` by `create`/`rehydrate`/`re_key`/`remove`.
    id_to_client: DashMap<String, SocketAddr>,
    /// Monotonic source for `allocation_id`. Node-local and dependency-free;
    /// the ticket's HMAC — not the id — is what prevents forgery, so the id
    /// itself need not be unpredictable, only unique within this process.
    next_id: AtomicU64,
    /// Username -> list of client addresses (for multi-allocation tracking).
    user_allocations: DashMap<UserKey, Vec<SocketAddr>>,
    /// B1: atomic allocation counters for O(1), race-free quota reservation.
    /// `global_count` mirrors `allocations.len()`; `tenant_counts[tid]` mirrors
    /// the count for tenant `tid`. Every add path reserves (fetch_add→check→
    /// rollback); every remove path releases.
    global_count: std::sync::atomic::AtomicUsize,
    tenant_counts: DashMap<String, std::sync::atomic::AtomicUsize>,
    /// Race-free per-user reservations. The vector index remains for listing,
    /// while this counter is the admission-control source of truth.
    user_counts: DashMap<UserKey, std::sync::atomic::AtomicUsize>,
    pub ports: PortAllocator,
    /// Per-tenant isolated port pools (multi-tenancy). Empty = single-tenant.
    /// Built once at startup via [`AllocationStore::with_tenant_pool`]; read-only
    /// afterwards (small N → linear scan in `pool`/`pool_for_port` is fine).
    tenant_pools: Vec<TenantPool>,
    // S4/S5: node-local live limits, published as ONE immutable snapshot via a
    // single atomic swap (S4-3). A runtime `update_config` replaces the whole
    // `RuntimeLimits` at once, so readers never see a torn mix of fields or a
    // value that disagrees with the reported `version`. Lowering a limit below
    // current usage blocks NEW reservations (via the atomic counters) without
    // tearing down active allocations. These are the global values; per-tenant
    // overrides live in `tenant_pools` and are startup-only.
    runtime: ArcSwap<RuntimeLimits>,
    /// S5 immutable override cache. No backend access occurs on the dataplane.
    user_limits: ArcSwap<UserLimitsSnapshot>,
    /// Optional sink for write-behind persistence events.
    ///
    /// `None` (the default) preserves the legacy single-node, no-persistence
    /// behaviour. Call [`AllocationStore::attach_writer`] once at startup
    /// to enable cluster-mode persistence. See `write_op` module and
    /// `docs/design/allocation-store-persistence.md`.
    write_tx: OnceLock<mpsc::Sender<WriteOp>>,
    /// Number of `WriteOp` events dropped because the writer's bounded
    /// channel was full. The writer task copies this into the Prometheus
    /// `tarantool_writes_dropped_total` counter.
    ///
    /// We keep this on the store rather than threading `Arc<Metrics>`
    /// through every call site — keeps the crate dependency-free of
    /// `turna-health`.
    dropped_writes: AtomicU64,
    /// Cumulative per-tenant relayed traffic, accrued at allocation removal
    /// (see [`TenantTraffic`]). Kept on the store — not threaded through
    /// `Arc<Metrics>` — so the crate stays free of a `turna-health` dependency
    /// (same rationale as `dropped_writes`).
    tenant_traffic: std::sync::Mutex<std::collections::HashMap<String, TenantTraffic>>,
}

struct CounterReservation<'a> {
    store: &'a AllocationStore,
    user_key: UserKey,
    tenant_id: Option<String>,
    user_reserved: bool,
    tenant_reserved: bool,
    global_reserved: bool,
    committed: bool,
}

impl CounterReservation<'_> {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for CounterReservation<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.global_reserved {
            self.store.global_count.fetch_sub(1, Ordering::AcqRel);
        }
        if self.tenant_reserved {
            if let Some(tid) = self.tenant_id.as_deref() {
                if let Some(entry) = self.store.tenant_counts.get(tid) {
                    entry.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
        if self.user_reserved {
            if let Some(entry) = self.store.user_counts.get(&self.user_key) {
                entry.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

/// RAII ownership of a port already reserved in a pool. The processor commits
/// it only after every allocation index and counter is installed.
pub struct PortReservationGuard<'a> {
    pool: &'a PortAllocator,
    port: u16,
    committed: bool,
}

impl<'a> PortReservationGuard<'a> {
    pub fn new(pool: &'a PortAllocator, port: u16) -> Self {
        Self {
            pool,
            port,
            committed: false,
        }
    }

    pub fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PortReservationGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.pool.release(self.port);
        }
    }
}

impl AllocationStore {
    pub fn new(min_port: u16, max_port: u16, max_allocations: usize) -> Self {
        Self {
            allocations: DashMap::new(),
            relay_to_client: DashMap::new(),
            channel_to_client: DashMap::new(),
            id_to_client: DashMap::new(),
            next_id: AtomicU64::new(1),
            user_allocations: DashMap::new(),
            global_count: std::sync::atomic::AtomicUsize::new(0),
            tenant_counts: DashMap::new(),
            user_counts: DashMap::new(),
            ports: PortAllocator::new(min_port, max_port),
            tenant_pools: Vec::new(),
            runtime: ArcSwap::from_pointee(RuntimeLimits {
                version: 0,
                max_bytes_per_sec_per_allocation: BandwidthQuota::default()
                    .max_bytes_per_sec_per_allocation,
                max_per_user: BandwidthQuota::default().max_per_user,
                max_allocations,
            }),
            user_limits: ArcSwap::from_pointee(UserLimitsSnapshot::empty()),
            write_tx: OnceLock::new(),
            dropped_writes: AtomicU64::new(0),
            tenant_traffic: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn with_quota(self, quota: BandwidthQuota) -> Self {
        self.set_user_quota(quota.max_bytes_per_sec_per_allocation, quota.max_per_user);
        self
    }

    /// S4-3 commit point: atomically publish a whole new runtime snapshot in a
    /// single swap. The caller owns `version` (the node handler bumps it on a
    /// real change; a no-op keeps it). This is the ONLY place a new logical
    /// configuration becomes visible, so readers never observe a torn state.
    pub fn publish_runtime(&self, next: RuntimeLimits) {
        self.runtime.store(Arc::new(next));
    }

    /// Current published runtime snapshot (cheap, lock-free). Used by the node
    /// to report observed config state and by all limit readers.
    pub fn runtime_snapshot(&self) -> Arc<RuntimeLimits> {
        self.runtime.load_full()
    }

    /// S5: publish new per-user limits (bytes/sec + allocations per user).
    /// Compatibility wrapper: it does NOT write fields independently — it loads
    /// the current snapshot, changes only these two values, and republishes the
    /// whole snapshot in one atomic swap (version preserved). Read on the hot
    /// path (`bandwidth_limit_for`) and at allocate (`effective_max_per_user`);
    /// a lowered cap blocks new reservations while active allocations keep
    /// running. Safe on a shared `&self` (behind `Arc`).
    pub fn set_user_quota(&self, max_bytes_per_sec_per_allocation: u64, max_per_user: usize) {
        let mut next = (*self.runtime.load_full()).clone();
        next.max_bytes_per_sec_per_allocation = max_bytes_per_sec_per_allocation;
        next.max_per_user = max_per_user;
        self.runtime.store(Arc::new(next));
    }

    /// S4: publish a new global allocation cap. Compatibility wrapper over a
    /// full-snapshot swap (version preserved). A lowered cap makes
    /// `try_reserve_slot` reject new allocations once the live count is at/above
    /// it; existing allocations are untouched.
    pub fn set_max_allocations(&self, max_allocations: usize) {
        let mut next = (*self.runtime.load_full()).clone();
        next.max_allocations = max_allocations;
        self.runtime.store(Arc::new(next));
    }

    /// Current live global limits `(max_bytes_per_sec_per_allocation, max_per_user,
    /// max_allocations)` — read from the single published snapshot so the tuple
    /// is always internally consistent. Used by the node to report observed
    /// config state.
    pub fn live_limits(&self) -> (u64, usize, usize) {
        let rt = self.runtime.load();
        (
            rt.max_bytes_per_sec_per_allocation,
            rt.max_per_user,
            rt.max_allocations,
        )
    }

    /// Seed the protocol/bootstrap lifetime ceiling used by S5 inheritance.
    /// This updates the immutable limits cache, never a standalone atomic.
    pub fn set_bootstrap_max_lifetime(&self, seconds: u32) {
        let mut next = (*self.user_limits.load_full()).clone();
        next.bootstrap_max_lifetime_secs = seconds;
        // Bootstrap seed (generation 0 at startup); real limit publications advance
        // the generation via publish_user_limits.
        self.user_limits.store(Arc::new(next));
    }

    pub fn user_limits_snapshot(&self) -> Arc<UserLimitsSnapshot> {
        self.user_limits.load_full()
    }

    pub fn publish_user_limits(&self, mut next: UserLimitsSnapshot) -> Result<(), SessionError> {
        // §8: bump the LOCAL cache generation on an actual change only. Neutralise
        // the incoming generation before comparing content so a no-op publish
        // neither stores nor advances the counter.
        let current = self.user_limits.load();
        next.generation = current.generation;
        if next == *current.as_ref() {
            return Ok(());
        }
        // Overflow must NOT panic (GA contract): leave the current snapshot intact
        // and surface the error to the apply/restore path.
        let Some(generation) = current.generation.checked_add(1) else {
            return Err(SessionError::CacheGenerationOverflow);
        };
        next.generation = generation;
        self.user_limits.store(Arc::new(next));
        Ok(())
    }

    /// Clone the current cache and apply one observed override. This is used by
    /// the serialized node command handler; readers see either the old or the
    /// complete new map.
    pub fn limits_snapshot_with_override(
        &self,
        scope: &str,
        realm: &str,
        tenant: &str,
        username: &str,
        value: UserLimitsOverride,
    ) -> Result<UserLimitsSnapshot, SessionError> {
        let mut next = (*self.user_limits.load_full()).clone();
        match scope {
            "global" => next.global = value,
            "tenant" => {
                let key = (realm.to_string(), tenant.to_string());
                if value.is_inherit_only() {
                    next.tenants.remove(&key);
                } else {
                    next.tenants.insert(key, value);
                }
            }
            "user" => {
                let key = (realm.to_string(), tenant.to_string(), username.to_string());
                if value.is_inherit_only() {
                    next.users.remove(&key);
                } else {
                    next.users.insert(key, value);
                }
            }
            _ => return Err(SessionError::LimitExceeded),
        }
        Ok(next)
    }

    fn resolve_u32(
        candidates: impl IntoIterator<Item = Option<LimitU32>>,
        fallback: usize,
    ) -> (usize, bool, bool, bool) {
        // Returns (effective, inherited, disabled, capped). §7-B: a finite node
        // ceiling (fallback > 0) is a hard upper bound — a VALUE above it, or
        // UNLIMITED, is capped to the ceiling and flagged. `fallback == 0` means
        // the node itself permits unlimited, so the override applies as-is.
        for candidate in candidates.into_iter().flatten() {
            match candidate.mode {
                LimitMode::Inherit => continue,
                LimitMode::Disabled => return (0, false, true, false),
                LimitMode::Value => {
                    let requested = candidate.value as usize;
                    if fallback > 0 && requested > fallback {
                        return (fallback, false, false, true);
                    }
                    return (requested, false, false, false);
                }
                LimitMode::Unlimited => {
                    if fallback > 0 {
                        return (fallback, false, false, true);
                    }
                    return (0, false, false, false);
                }
            }
        }
        (fallback, true, false, false)
    }

    fn resolve_u64(
        candidates: impl IntoIterator<Item = Option<LimitU64>>,
        fallback: u64,
    ) -> (u64, bool, bool, bool) {
        // Returns (effective, inherited, disabled, capped). §7-B: see resolve_u32.
        for candidate in candidates.into_iter().flatten() {
            match candidate.mode {
                LimitMode::Inherit => continue,
                LimitMode::Disabled => return (0, false, true, false),
                LimitMode::Value => {
                    if fallback > 0 && candidate.value > fallback {
                        return (fallback, false, false, true);
                    }
                    return (candidate.value, false, false, false);
                }
                LimitMode::Unlimited => {
                    if fallback > 0 {
                        return (fallback, false, false, true);
                    }
                    return (0, false, false, false);
                }
            }
        }
        (fallback, true, false, false)
    }

    /// Resolve one consistent S5 view from one runtime snapshot and one limits
    /// snapshot. Each field inherits independently.
    pub fn effective_user_limits(
        &self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
    ) -> EffectiveUserLimits {
        let runtime = self.runtime.load_full();
        let limits = self.user_limits.load_full();
        let tenant = tenant_id.unwrap_or("");
        let user = limits
            .users
            .get(&(realm.to_string(), tenant.to_string(), username.to_string()));
        let tenant_override = limits.tenants.get(&(realm.to_string(), tenant.to_string()));
        let bootstrap_tenant = self.tenant_quota(tenant_id);

        let (max_allocations, alloc_inherited, allocations_disabled, alloc_capped) =
            Self::resolve_u32(
                [
                    user.and_then(|v| v.max_allocations),
                    tenant_override.and_then(|v| v.max_allocations),
                    limits.global.max_allocations,
                ],
                bootstrap_tenant
                    .and_then(|q| (q.max_per_user > 0).then_some(q.max_per_user))
                    .unwrap_or(runtime.max_per_user),
            );
        let (
            max_bytes_per_sec_per_allocation,
            bandwidth_inherited,
            bandwidth_disabled,
            bandwidth_capped,
        ) = Self::resolve_u64(
            [
                user.and_then(|v| v.max_bytes_per_sec_per_allocation),
                tenant_override.and_then(|v| v.max_bytes_per_sec_per_allocation),
                limits.global.max_bytes_per_sec_per_allocation,
            ],
            bootstrap_tenant
                .and_then(|q| {
                    (q.max_bytes_per_sec_per_allocation > 0)
                        .then_some(q.max_bytes_per_sec_per_allocation)
                })
                .unwrap_or(runtime.max_bytes_per_sec_per_allocation),
        );
        let (max_lifetime, lifetime_inherited, lifetime_disabled, lifetime_capped) =
            Self::resolve_u32(
                [
                    user.and_then(|v| v.max_lifetime_secs),
                    tenant_override.and_then(|v| v.max_lifetime_secs),
                    limits.global.max_lifetime_secs,
                ],
                limits.bootstrap_max_lifetime_secs as usize,
            );
        let mut inherited_fields = Vec::new();
        if alloc_inherited {
            inherited_fields.push("max_allocations".to_string());
        }
        if bandwidth_inherited {
            inherited_fields.push("max_bytes_per_sec_per_allocation".to_string());
        }
        if lifetime_inherited {
            inherited_fields.push("max_lifetime_secs".to_string());
        }
        // §7-B: fields whose requested value exceeded a finite node ceiling and
        // were clamped to it. Enforcement uses the (capped) effective value.
        let mut capped_fields = Vec::new();
        if alloc_capped {
            capped_fields.push("max_allocations".to_string());
        }
        if bandwidth_capped {
            capped_fields.push("max_bytes_per_sec_per_allocation".to_string());
        }
        if lifetime_capped {
            capped_fields.push("max_lifetime_secs".to_string());
        }
        EffectiveUserLimits {
            max_allocations,
            allocations_disabled,
            max_bytes_per_sec_per_allocation,
            bandwidth_disabled,
            max_lifetime_secs: max_lifetime as u32,
            lifetime_disabled,
            inherited_fields,
            capped_fields,
        }
    }

    pub fn current_user_usage(
        &self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
    ) -> usize {
        let key = (
            realm.to_string(),
            tenant_id.map(ToOwned::to_owned),
            username.to_string(),
        );
        self.user_counts
            .get(&key)
            .map(|value| value.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    pub fn current_tenant_usage(&self, tenant_id: &str) -> usize {
        self.tenant_counts
            .get(tenant_id)
            .map(|value| value.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Highest concurrent allocation usage of any user on this node. Global S5
    /// defaults are per-user limits, so management must compare them to this
    /// maximum rather than to the total number of allocations.
    pub fn max_user_usage(&self) -> usize {
        self.user_counts
            .iter()
            .map(|entry| entry.value().load(Ordering::Acquire))
            .max()
            .unwrap_or(0)
    }

    /// Highest concurrent allocation usage of any user in one realm/tenant.
    /// Tenant-level S5 limits are inherited by each user independently, so
    /// comparing an aggregate tenant allocation count to a per-user limit would
    /// report false over-limit states.
    pub fn max_user_usage_in_tenant(&self, realm: &str, tenant_id: &str) -> usize {
        self.user_counts
            .iter()
            .filter(|entry| entry.key().0 == realm && entry.key().1.as_deref() == Some(tenant_id))
            .map(|entry| entry.value().load(Ordering::Acquire))
            .max()
            .unwrap_or(0)
    }

    /// Register an isolated relay-port pool for a tenant. Builder; call once per
    /// tenant at startup. Ranges must be disjoint (the config layer validates).
    pub fn with_tenant_pool(
        mut self,
        id: impl Into<String>,
        min_port: u16,
        max_port: u16,
        max_allocations: usize,
        quota: BandwidthQuota,
    ) -> Self {
        self.tenant_pools.push(TenantPool {
            id: id.into(),
            ports: PortAllocator::new(min_port, max_port),
            max_allocations,
            quota,
        });
        self
    }

    /// The tenant's quota, if `tenant_id` names a registered tenant.
    fn tenant_quota(&self, tenant_id: Option<&str>) -> Option<&BandwidthQuota> {
        let id = tenant_id?;
        self.tenant_pools
            .iter()
            .find(|p| p.id == id)
            .map(|p| &p.quota)
    }

    /// Compatibility lookup for call sites that do not yet carry identity.
    pub fn effective_max_per_user(&self, tenant_id: Option<&str>) -> usize {
        self.effective_user_limits("", tenant_id, "")
            .max_allocations
    }

    /// Compatibility lookup for call sites that do not yet carry identity.
    pub fn bandwidth_limit_for(&self, tenant_id: Option<&str>) -> u64 {
        self.effective_user_limits("", tenant_id, "")
            .max_bytes_per_sec_per_allocation
    }

    pub fn bandwidth_limit_for_user(
        &self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
    ) -> u64 {
        self.bandwidth_policy_for_user(realm, tenant_id, username).0
    }

    pub fn bandwidth_policy_for_user(
        &self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
    ) -> (u64, bool) {
        let effective = self.effective_user_limits(realm, tenant_id, username);
        (
            effective.max_bytes_per_sec_per_allocation,
            effective.bandwidth_disabled,
        )
    }

    pub fn max_lifetime_for_user(
        &self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
    ) -> u32 {
        self.lifetime_policy_for_user(realm, tenant_id, username).0
    }

    pub fn lifetime_policy_for_user(
        &self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
    ) -> (u32, bool) {
        let effective = self.effective_user_limits(realm, tenant_id, username);
        (effective.max_lifetime_secs, effective.lifetime_disabled)
    }

    /// Select the port pool for a tenant at allocation time. `None` or an
    /// unknown id → the base pool.
    pub fn pool(&self, tenant_id: Option<&str>) -> &PortAllocator {
        match tenant_id {
            Some(id) => self
                .tenant_pools
                .iter()
                .find(|p| p.id == id)
                .map(|p| &p.ports)
                .unwrap_or(&self.ports),
            None => &self.ports,
        }
    }

    /// Route a port back to its owning pool (release/reserve), by range.
    pub fn pool_for_port(&self, port: u16) -> &PortAllocator {
        self.tenant_pools
            .iter()
            .find(|p| p.ports.contains(port))
            .map(|p| &p.ports)
            .unwrap_or(&self.ports)
    }

    /// Tenant id owning `port` by range, or `None` for the base pool.
    pub fn tenant_id_for_port(&self, port: u16) -> Option<String> {
        self.tenant_pools
            .iter()
            .find(|p| p.ports.contains(port))
            .map(|p| p.id.clone())
    }

    /// Per-tenant allocation cap, if configured (0 = unlimited).
    fn tenant_max_allocations(&self, tenant_id: &str) -> usize {
        self.tenant_pools
            .iter()
            .find(|p| p.id == tenant_id)
            .map(|p| p.max_allocations)
            .unwrap_or(0)
    }

    /// Enable write-behind persistence by attaching a bounded sender to
    /// the writer task. Must be called at most once — subsequent calls
    /// are silently ignored.
    ///
    /// Without this call, the store behaves exactly as in single-node
    /// mode and no `WriteOp` events are emitted (zero overhead).
    pub fn attach_writer(&self, tx: mpsc::Sender<WriteOp>) {
        if self.write_tx.set(tx).is_err() {
            tracing::warn!("attach_writer called more than once — ignoring");
        }
    }

    /// Number of `WriteOp` events that were dropped because the writer's
    /// bounded channel was full. Monotonically increasing.
    pub fn dropped_writes_count(&self) -> u64 {
        self.dropped_writes.load(Ordering::Relaxed)
    }

    /// P0 #16: relay ports of all live allocations. The node's reconciliation
    /// pass uses this to find backend "zombies" — rows whose `Remove` event was
    /// dropped under write-behind backpressure and would otherwise be adopted
    /// (resurrected) on failover.
    pub fn live_relay_ports(&self) -> Vec<u16> {
        self.allocations
            .iter()
            .map(|e| e.value().relay_addr.port())
            .collect()
    }

    /// P0 #16: re-emit the full authoritative live state as write-behind events.
    ///
    /// After a backpressure episode drops `WriteOp`s, the backend has diverged:
    /// missing `Create`s, stale `Refresh`/permission/channel state. Replaying
    /// every live allocation (plus its permissions and channel bindings) through
    /// the writer restores those rows. The writer upserts, so this is idempotent
    /// and safe to call repeatedly.
    ///
    /// Epoch timestamps are reconstructed from the monotonic `Instant`s via the
    /// current wall clock (`epoch_ms()` + remaining lifetime). The absolute
    /// value may differ slightly from the original `Create`, but the
    /// remaining-lifetime semantics that drive expiry are preserved.
    ///
    /// No-op when no writer is attached (standalone mode).
    pub fn resync_all(&self) {
        if self.write_tx.get().is_none() {
            return;
        }
        let now_i = Instant::now();
        let now_e = epoch_ms();
        let to_epoch = |t: Instant| -> u64 {
            if t >= now_i {
                now_e + t.duration_since(now_i).as_millis() as u64
            } else {
                now_e.saturating_sub(now_i.duration_since(t).as_millis() as u64)
            }
        };
        for entry in self.allocations.iter() {
            let a = entry.value();
            let relay_port = a.relay_addr.port();
            self.emit_write(WriteOp::Create {
                relay_port,
                client_addr: a.client_addr,
                relay_addr: a.relay_addr,
                username: a.username.clone(),
                realm: a.realm.clone(),
                created_at_ms: to_epoch(a.created_at),
                expires_at_ms: to_epoch(a.expires_at),
                allocation_id: a.allocation_id.clone(),
                migration_epoch: a.migration_epoch,
            });
            for (ip, perm) in a.permissions.iter() {
                self.emit_write(WriteOp::Permission {
                    relay_port,
                    peer_ip: *ip,
                    expires_at_ms: to_epoch(perm.expires_at),
                });
            }
            for (number, binding) in a.channel_bindings.iter() {
                self.emit_write(WriteOp::Channel {
                    relay_port,
                    number: *number,
                    peer_addr: binding.peer_addr,
                    expires_at_ms: to_epoch(binding.expires_at),
                });
            }
        }
    }

    /// Emit a reconcile ordering barrier through the write-behind channel
    /// (P0.1). Returns `false` if the channel is missing/closed or full — a
    /// dropped barrier means the caller must NOT trust any subsequent ack and
    /// should stay Degraded. On success the writer publishes `generation` to its
    /// reconcile-ack only after flushing all prior ops to the backend.
    pub fn emit_reconcile_barrier(&self, generation: u64) -> bool {
        match self.write_tx.get() {
            Some(tx) => tx.try_send(WriteOp::Barrier { generation }).is_ok(),
            None => false,
        }
    }

    /// Send a `WriteOp` if a writer is attached, **without blocking**.
    ///
    /// Three outcomes:
    /// - Channel has capacity → event enqueued.
    /// - Channel is full → event dropped, `dropped_writes` incremented,
    ///   one warn-throttled log emitted. This is the design doc §4 D3
    ///   "degraded mode" — see also §5 ("Slow Tarantool").
    /// - Receiver gone → silently dropped (writer task already exited;
    ///   normal during shutdown).
    #[inline]
    fn emit_write(&self, op: WriteOp) {
        let Some(tx) = self.write_tx.get() else {
            return;
        };
        match tx.try_send(op) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let prev = self.dropped_writes.fetch_add(1, Ordering::Relaxed);
                // Warn-throttle: log on first drop, then every power of two.
                // Keeps logs from flooding under sustained backpressure
                // while still surfacing the first incident immediately.
                if prev == 0 || (prev + 1).is_power_of_two() {
                    tracing::warn!(
                        dropped_total = prev + 1,
                        "writer channel full — WriteOp dropped \
                         (in-memory state remains consistent)"
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("writer channel closed — event ignored");
            }
        }
    }

    /// Mint a fresh, process-unique allocation id. See `next_id`.
    fn mint_id(&self) -> String {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("{n:016x}")
    }

    pub fn create(
        &self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        key: Vec<u8>,
        lifetime: u32,
    ) -> Result<(), SessionError> {
        self.create_for_identity(
            client_addr,
            relay_addr,
            username,
            key,
            lifetime,
            String::new(),
            None,
        )
    }

    fn reserve_counters<'a>(
        &'a self,
        realm: &str,
        tenant_id: Option<&str>,
        username: &str,
        max_per_user: usize,
        allocations_disabled: bool,
        max_global: usize,
    ) -> Result<CounterReservation<'a>, SessionError> {
        if allocations_disabled {
            return Err(SessionError::MaxAllocationsPerUser);
        }
        let user_key = (
            realm.to_string(),
            tenant_id.map(ToOwned::to_owned),
            username.to_string(),
        );
        let user = self
            .user_counts
            .entry(user_key.clone())
            .or_insert_with(|| AtomicUsize::new(0));
        if max_per_user > 0 && user.fetch_add(1, Ordering::AcqRel) >= max_per_user {
            user.fetch_sub(1, Ordering::AcqRel);
            return Err(SessionError::MaxAllocationsPerUser);
        }
        if max_per_user == 0 {
            user.fetch_add(1, Ordering::AcqRel);
        }
        drop(user);

        let mut guard = CounterReservation {
            store: self,
            user_key,
            tenant_id: tenant_id.map(ToOwned::to_owned),
            user_reserved: true,
            tenant_reserved: false,
            global_reserved: false,
            committed: false,
        };

        if let Some(tid) = tenant_id {
            let cap = self.tenant_max_allocations(tid);
            let entry = self
                .tenant_counts
                .entry(tid.to_string())
                .or_insert_with(|| AtomicUsize::new(0));
            if cap > 0 && entry.fetch_add(1, Ordering::AcqRel) >= cap {
                entry.fetch_sub(1, Ordering::AcqRel);
                return Err(SessionError::MaxAllocations);
            }
            if cap == 0 {
                entry.fetch_add(1, Ordering::AcqRel);
            }
            guard.tenant_reserved = true;
        }

        if max_global > 0 && self.global_count.fetch_add(1, Ordering::AcqRel) >= max_global {
            self.global_count.fetch_sub(1, Ordering::AcqRel);
            return Err(SessionError::MaxAllocations);
        }
        if max_global == 0 {
            self.global_count.fetch_add(1, Ordering::AcqRel);
        }
        guard.global_reserved = true;
        Ok(guard)
    }

    fn release_counters(&self, realm: &str, tenant_id: Option<&str>, username: &str) {
        let old = self.global_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(old > 0, "global allocation counter underflow");
        if let Some(tid) = tenant_id {
            if let Some(entry) = self.tenant_counts.get(tid) {
                let old = entry.fetch_sub(1, Ordering::AcqRel);
                debug_assert!(old > 0, "tenant allocation counter underflow");
            }
        }
        let user_key = (
            realm.to_string(),
            tenant_id.map(ToOwned::to_owned),
            username.to_string(),
        );
        if let Some(entry) = self.user_counts.get(&user_key) {
            let old = entry.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(old > 0, "user allocation counter underflow");
        }
    }

    /// Like [`create`](Self::create) but records the owning tenant and enforces
    /// the tenant's allocation cap. `tenant_id = None` is the base tenant and is
    /// identical to `create`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_for_tenant(
        &self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        key: Vec<u8>,
        lifetime: u32,
        tenant_id: Option<String>,
    ) -> Result<(), SessionError> {
        self.create_for_identity(
            client_addr,
            relay_addr,
            username,
            key,
            lifetime,
            String::new(),
            tenant_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_for_identity(
        &self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        key: Vec<u8>,
        lifetime: u32,
        realm: String,
        tenant_id: Option<String>,
    ) -> Result<(), SessionError> {
        let user_key: UserKey = (realm.clone(), tenant_id.clone(), username.clone());
        let realm_for_write = realm.clone();
        let effective = self.effective_user_limits(&realm, tenant_id.as_deref(), &username);
        let runtime = self.runtime.load_full();
        let mut reservation = self.reserve_counters(
            &realm,
            tenant_id.as_deref(),
            &username,
            effective.max_allocations,
            effective.allocations_disabled || effective.lifetime_disabled,
            runtime.max_allocations,
        )?;

        let now = Instant::now();
        let allocation_id = self.mint_id();
        let alloc = Allocation {
            allocation_id: allocation_id.clone(),
            migration_epoch: 0,
            client_addr,
            relay_addr,
            username: username.clone(),
            key,
            realm,
            tenant_id,
            transport: TransportProto::Udp,
            permissions: HashMap::new(),
            channel_bindings: HashMap::new(),
            channels_reverse: HashMap::new(),
            expires_at: now + Duration::from_secs(lifetime as u64),
            created_at: now,
            bytes_relayed: AtomicU64::new(0),
            packets_relayed: AtomicU64::new(0),
            bandwidth_window_bytes: AtomicU64::new(0),
            bandwidth_window_start: Mutex::new(now),
        };

        // B1: atomic insert-if-vacant. With N SO_REUSEPORT recv workers, two
        // Allocate retransmits on the same 5-tuple could both clear the
        // check-then-insert in the processor and both reach this insert, the
        // second silently clobbering the first and orphaning its relay port and
        // socket until restart. Gate on the allocations slot so exactly one wins.
        {
            use dashmap::mapref::entry::Entry;
            match self.allocations.entry(client_addr) {
                Entry::Occupied(_) => {
                    return Err(SessionError::AllocationExists);
                }
                Entry::Vacant(slot) => {
                    // Secondary indices are set while the slot is held, so the
                    // allocation is visible in `allocations` only once its
                    // relay/id/user indices already point at it.
                    self.relay_to_client.insert(relay_addr, client_addr);
                    self.id_to_client.insert(allocation_id.clone(), client_addr);
                    self.user_allocations
                        .entry(user_key)
                        .or_default()
                        .push(client_addr);
                    slot.insert(alloc);
                }
            }
        }
        reservation.commit();

        // Emit write-behind event — only after the in-memory state is
        // fully consistent (design doc §9 question 5).
        let now_epoch = epoch_ms();
        self.emit_write(WriteOp::Create {
            relay_port: relay_addr.port(),
            client_addr,
            relay_addr,
            username: username.clone(),
            realm: realm_for_write,
            created_at_ms: now_epoch,
            expires_at_ms: now_epoch + (lifetime as u64) * 1000,
            allocation_id,
            migration_epoch: 0,
        });

        tracing::info!(%client_addr, %relay_addr, %username, "allocation created");
        Ok(())
    }

    /// Restore an allocation from persistent storage **without** going
    /// through the normal create path.
    ///
    /// Differences vs [`Self::create`]:
    /// - Port is **reserved** at the supplied `relay_port`, not allocated
    ///   from the rotating pool. The caller (typically bulk-load on
    ///   startup) is asserting "this allocation already exists on the
    ///   wire and owns this port".
    /// - **No `WriteOp` is emitted.** Re-emitting would shove the entire
    ///   loaded state back into the writer queue and possibly cause a
    ///   write-back storm right after startup. The persisted state is
    ///   already in the backend by definition — there's nothing to write.
    /// - **`Allocation::key` is left empty (`Vec::new()`).** This is a
    ///   derived value (MD5 of `username:realm:password`) that lives in
    ///   the auth configuration, not in the persisted record. The first
    ///   authenticated request from the client (Refresh / CreatePermission /
    ///   ChannelBind / Send) calls `AuthMode::validate()` which
    ///   recomputes the key on the fly using `turna_crypto::long_term_key`.
    ///   This is correct for both `LongTerm` (static users) and
    ///   `SharedSecret` (TURN REST) modes, provided the auth config is
    ///   identical across cluster nodes — see design doc §9 question 4.
    /// - Quotas (`max_allocations`, `max_per_user`) are still enforced.
    ///   If we exceed them, bulk-load is loading more than the node is
    ///   configured for; we return an error and the caller logs and
    ///   moves on.
    ///
    /// Returns:
    /// - `Ok(true)`  — allocation was restored.
    /// - `Ok(false)` — record was already expired (`expires_at_ms` <= now);
    ///   skipped, port not reserved. Not an error.
    /// - `Err(_)`    — record was malformed, port unavailable, or quota
    ///   exceeded. Caller logs and continues with next record.
    #[allow(clippy::too_many_arguments)]
    pub fn rehydrate(
        &self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        realm: String,
        allocation_id: String,
        migration_epoch: u64,
        created_at_ms: u64,
        expires_at_ms: u64,
        permissions: impl IntoIterator<Item = (std::net::IpAddr, u64)>,
        channels: impl IntoIterator<Item = (u16, SocketAddr, u64)>,
    ) -> Result<bool, SessionError> {
        let now_epoch = epoch_ms();
        if expires_at_ms <= now_epoch {
            // Stale record — TTL already passed. Backend cleanup will
            // garbage-collect it on its next sweep.
            return Ok(false);
        }

        let tenant_id = self.tenant_id_for_port(relay_addr.port());
        let user_key: UserKey = (realm.clone(), tenant_id.clone(), username.clone());
        let effective = self.effective_user_limits(&realm, tenant_id.as_deref(), &username);
        let runtime = self.runtime.load_full();
        let mut reservation = self.reserve_counters(
            &realm,
            tenant_id.as_deref(),
            &username,
            effective.max_allocations,
            effective.allocations_disabled || effective.lifetime_disabled,
            runtime.max_allocations,
        )?;

        // Reserve the port. If it's already taken, somebody else (live
        // create()? a duplicate record?) got there first. Route to the owning
        // pool by range so tenant-range ports are reserved in the tenant pool
        // (the base pool would reject an out-of-range port).
        self.pool_for_port(relay_addr.port())
            .reserve(relay_addr.port())?;
        let mut port_reservation =
            PortReservationGuard::new(self.pool_for_port(relay_addr.port()), relay_addr.port());

        // Convert wall-clock epoch_ms back into a monotonic `Instant` by
        // anchoring against `Instant::now()`. We lose accuracy of the
        // original moment of creation, but `created_at` is only used for
        // observability — not correctness. `expires_at` is correctness-
        // critical and is reconstructed by adding the remaining lifetime.
        let now_inst = Instant::now();
        let remaining = Duration::from_millis(expires_at_ms - now_epoch);
        let age = Duration::from_millis(now_epoch.saturating_sub(created_at_ms));
        let created_at = now_inst.checked_sub(age).unwrap_or(now_inst);
        let expires_at = now_inst + remaining;

        // Reconstruct permissions / channel bindings. We need them so
        // persisted metadata remains internally consistent. Whether a transport
        // can reuse it depends on that transport recreating its relay endpoint;
        // metadata restoration alone does not preserve an active media path.
        let mut perms_map: HashMap<std::net::IpAddr, Permission> = HashMap::new();
        for (peer_ip, perm_expires) in permissions {
            if perm_expires <= now_epoch {
                continue;
            }
            let perm_remaining = Duration::from_millis(perm_expires - now_epoch);
            perms_map.insert(
                peer_ip,
                Permission {
                    _peer_ip: peer_ip,
                    expires_at: now_inst + perm_remaining,
                },
            );
        }

        let mut chan_map: HashMap<u16, ChannelBinding> = HashMap::new();
        let mut chans_reverse: HashMap<SocketAddr, u16> = HashMap::new();
        for (number, peer_addr, chan_expires) in channels {
            if chan_expires <= now_epoch {
                continue;
            }
            let chan_remaining = Duration::from_millis(chan_expires - now_epoch);
            chan_map.insert(
                number,
                ChannelBinding {
                    _channel: number,
                    peer_addr,
                    expires_at: now_inst + chan_remaining,
                },
            );
            chans_reverse.insert(peer_addr, number);
        }

        let alloc = Allocation {
            // Restore the persisted RFC 8016 identity so a MOBILITY-TICKET
            // issued by the previous owner can be validated by migration logic.
            // This does not recreate the previous owner's live relay socket.
            // A row written before this field existed decodes to an
            // empty id (serde default) — mint a fresh one then, matching the
            // old node-local behaviour (the old ticket simply won't be
            // portable, which is the pre-RFC-8016 status quo, not a regression).
            allocation_id: if allocation_id.is_empty() {
                self.mint_id()
            } else {
                allocation_id
            },
            // Restore the persisted migration generation so a captured
            // older-epoch ticket stays rejected on the new owner.
            migration_epoch,
            client_addr,
            relay_addr,
            username: username.clone(),
            // See doc comment above — recomputed on first auth.
            key: Vec::new(),
            realm,
            // Derived from the port's owning pool (tenant ranges are disjoint).
            tenant_id: self.tenant_id_for_port(relay_addr.port()),
            transport: TransportProto::Udp,
            permissions: perms_map,
            channel_bindings: chan_map,
            channels_reverse: chans_reverse,
            expires_at,
            created_at,
            bytes_relayed: AtomicU64::new(0),
            packets_relayed: AtomicU64::new(0),
            bandwidth_window_bytes: AtomicU64::new(0),
            bandwidth_window_start: Mutex::new(now_inst),
        };

        // Publish all secondary indices and the allocation under one vacant
        // primary-slot guard. A duplicate persisted row cannot overwrite a live
        // allocation or leak its counter/port reservations.
        {
            use dashmap::mapref::entry::Entry;
            match self.allocations.entry(client_addr) {
                Entry::Occupied(_) => return Err(SessionError::AllocationExists),
                Entry::Vacant(slot) => {
                    self.relay_to_client.insert(relay_addr, client_addr);
                    self.id_to_client
                        .insert(alloc.allocation_id.clone(), client_addr);
                    for &number in alloc.channel_bindings.keys() {
                        self.channel_to_client
                            .insert((relay_addr.port(), number), client_addr);
                    }
                    self.user_allocations
                        .entry(user_key)
                        .or_default()
                        .push(client_addr);
                    slot.insert(alloc);
                }
            }
        }
        reservation.commit();
        port_reservation.commit();

        tracing::debug!(%client_addr, %relay_addr, %username,
                        remaining_ms = remaining.as_millis() as u64,
                        "allocation rehydrated");
        // NB: deliberately no emit_write — see doc comment.
        Ok(true)
    }

    pub fn get(
        &self,
        client_addr: &SocketAddr,
    ) -> Option<dashmap::mapref::one::Ref<'_, SocketAddr, Allocation>> {
        self.allocations.get(client_addr)
    }

    pub fn get_mut(
        &self,
        client_addr: &SocketAddr,
    ) -> Option<dashmap::mapref::one::RefMut<'_, SocketAddr, Allocation>> {
        self.allocations.get_mut(client_addr)
    }

    pub fn get_by_relay(&self, relay_addr: &SocketAddr) -> Option<SocketAddr> {
        self.relay_to_client.get(relay_addr).map(|r| *r.value())
    }

    pub fn get_by_channel(&self, relay_port: u16, channel: u16) -> Option<SocketAddr> {
        self.channel_to_client
            .get(&(relay_port, channel))
            .map(|r| *r.value())
    }

    /// Resolve a stable allocation id to its *current* client address
    /// (RFC 8016). Returns `None` if no live allocation carries that id.
    pub fn get_by_id(&self, allocation_id: &str) -> Option<SocketAddr> {
        self.id_to_client.get(allocation_id).map(|r| *r.value())
    }

    /// Re-key an allocation from `old_addr` to `new_addr` — the core of
    /// RFC 8016 Connection Migration. The relay binding, permissions,
    /// channels, `allocation_id`, `username` and `key` are all preserved;
    /// only the client 5-tuple moves. Every index that is keyed on, or stores,
    /// the client address is updated in lock-step:
    ///
    /// - `allocations`       — entry moved from `old_addr` to `new_addr`
    /// - `relay_to_client`   — value (same relay key) → `new_addr`
    /// - `channel_to_client` — each `(relay_port, channel)` value → `new_addr`
    /// - `user_allocations`  — the user's vector entry `old_addr` → `new_addr`
    /// - `id_to_client`      — value → `new_addr`
    ///
    /// Returns the (unchanged) relay address on success — the caller echoes it
    /// back so the peer-facing media path is provably untouched.
    ///
    /// Errors:
    /// - [`SessionError::NotFound`] if no allocation lives at `old_addr`.
    /// - [`SessionError::MigrationTargetInUse`] if `new_addr` already hosts a
    ///   *different* allocation (we refuse to clobber it).
    ///
    /// Atomicity: this is not a single cross-shard transaction. For the
    /// intended use — a single migrating client rebinding its own allocation
    /// — there is no competing writer, so the brief window where `get(old)`
    /// and `get(new)` both miss is benign (the client has, by definition, just
    /// changed address). Concurrent migration of the *same* allocation is
    /// prevented one level up (the processor's per-ticket guard, Заход 2).
    pub fn re_key(
        &self,
        old_addr: &SocketAddr,
        new_addr: SocketAddr,
    ) -> Result<SocketAddr, SessionError> {
        // Idempotent no-op: refreshing from the same address is not a move.
        if *old_addr == new_addr {
            return self
                .allocations
                .get(old_addr)
                .map(|a| a.relay_addr)
                .ok_or(SessionError::NotFound);
        }

        // Refuse to overwrite a live allocation already sitting on the target.
        if self.allocations.contains_key(&new_addr) {
            return Err(SessionError::MigrationTargetInUse);
        }

        // Take ownership of the allocation out of the old slot.
        let (_, mut alloc) = self
            .allocations
            .remove(old_addr)
            .ok_or(SessionError::NotFound)?;

        let relay_addr = alloc.relay_addr;
        let relay_port = relay_addr.port();
        let allocation_id = alloc.allocation_id.clone();
        let username = alloc.username.clone();
        let realm = alloc.realm.clone();
        let tenant_id = alloc.tenant_id.clone();

        // Rewrite the owned copy, then re-insert under the new key.
        alloc.client_addr = new_addr;
        // Bump the migration generation so the just-used ticket (minted at the
        // previous epoch) can never be replayed against this allocation.
        alloc.migration_epoch = alloc.migration_epoch.wrapping_add(1);
        // Capture the post-bump epoch before `alloc` is moved back into the
        // map — the writer persists it so failover keeps anti-replay intact.
        let new_epoch = alloc.migration_epoch;
        let channels: Vec<u16> = alloc.channel_bindings.keys().copied().collect();
        self.allocations.insert(new_addr, alloc);

        // relay key is unchanged; only its value moves.
        self.relay_to_client.insert(relay_addr, new_addr);
        for ch in channels {
            self.channel_to_client.insert((relay_port, ch), new_addr);
        }
        self.id_to_client.insert(allocation_id, new_addr);
        if let Some(mut addrs) =
            self.user_allocations
                .get_mut(&(realm, tenant_id.clone(), username.clone()))
        {
            for a in addrs.iter_mut() {
                if a == old_addr {
                    *a = new_addr;
                }
            }
        }

        self.emit_write(WriteOp::ReKey {
            relay_port,
            new_client_addr: new_addr,
            new_epoch,
        });

        tracing::info!(%old_addr, %new_addr, %relay_addr, %username, "allocation re-keyed (migration)");
        Ok(relay_addr)
    }

    /// Add or refresh a permission (5 min lifetime per RFC).
    /// Mark an allocation's relayed transport (RFC 6062 TCP). Called right
    /// after creating a TCP allocation. Returns false if it's already gone.
    pub fn set_transport(&self, client_addr: &SocketAddr, transport: TransportProto) -> bool {
        match self.allocations.get_mut(client_addr) {
            Some(mut alloc) => {
                alloc.transport = transport;
                true
            }
            None => false,
        }
    }

    pub fn add_permission(
        &self,
        client_addr: &SocketAddr,
        peer_ip: std::net::IpAddr,
    ) -> Result<(), SessionError> {
        let relay_port = {
            let mut alloc = self
                .allocations
                .get_mut(client_addr)
                .ok_or(SessionError::NotFound)?;
            if let Some(perm) = alloc.permissions.get_mut(&peer_ip) {
                perm.refresh();
                tracing::debug!(%client_addr, %peer_ip, "permission refreshed");
            } else {
                // B5: bound distinct permissions per allocation.
                if alloc.permissions.len() >= MAX_PERMISSIONS_PER_ALLOCATION {
                    return Err(SessionError::LimitExceeded);
                }
                alloc.permissions.insert(peer_ip, Permission::new(peer_ip));
                tracing::debug!(%client_addr, %peer_ip, "permission added");
            }
            alloc.relay_addr.port()
            // `alloc` (the RefMut) is dropped here, releasing the shard lock
            // before we emit the write — keeps the channel send strictly
            // outside the DashMap critical section.
        };

        self.emit_write(WriteOp::Permission {
            relay_port,
            peer_ip,
            expires_at_ms: epoch_ms() + PERMISSION_LIFETIME.as_millis() as u64,
        });
        Ok(())
    }

    /// Add or refresh a channel binding (10 min lifetime per RFC).
    pub fn add_channel(
        &self,
        client_addr: &SocketAddr,
        channel: u16,
        peer_addr: SocketAddr,
    ) -> Result<(), SessionError> {
        let mut alloc = self
            .allocations
            .get_mut(client_addr)
            .ok_or(SessionError::NotFound)?;

        // RFC 8656 §12.2 / RFC 5766 §11.2 uniqueness invariants. Reject with a
        // conflict (→ 400) and make NO state change if either:
        //   (a) the requested channel is already bound to a *different* peer, or
        //   (b) the requested peer is already bound to a *different* channel.
        // The only mutating cases left after this are the same (channel, peer)
        // pair (refresh) or a brand-new pair (insert).
        if let Some(existing) = alloc.channel_bindings.get(&channel) {
            if existing.peer_addr != peer_addr {
                return Err(SessionError::ChannelConflict);
            }
        }
        if let Some(&bound_ch) = alloc.channels_reverse.get(&peer_addr) {
            if bound_ch != channel {
                return Err(SessionError::ChannelConflict);
            }
        }

        // B5: bound distinct channel bindings per allocation. A refresh of an
        // existing (channel, peer) pair is always allowed; only a brand-new
        // binding counts. Checked before any state change so an over-cap request
        // leaves the allocation untouched.
        if !alloc.channel_bindings.contains_key(&channel)
            && alloc.channel_bindings.len() >= MAX_CHANNELS_PER_ALLOCATION
        {
            return Err(SessionError::LimitExceeded);
        }

        // Also add/refresh permission for this peer
        if let Some(perm) = alloc.permissions.get_mut(&peer_addr.ip()) {
            perm.refresh();
        } else {
            alloc
                .permissions
                .insert(peer_addr.ip(), Permission::new(peer_addr.ip()));
        }

        if let Some(binding) = alloc.channel_bindings.get_mut(&channel) {
            binding.refresh();
            tracing::debug!(%client_addr, channel, %peer_addr, "channel refreshed");
        } else {
            alloc
                .channel_bindings
                .insert(channel, ChannelBinding::new(channel, peer_addr));
            alloc.channels_reverse.insert(peer_addr, channel);
            tracing::debug!(%client_addr, channel, %peer_addr, "channel bound");
        }

        let relay_port = alloc.relay_addr.port();
        drop(alloc);
        self.channel_to_client
            .insert((relay_port, channel), *client_addr);

        // Emit *two* events: ChannelBind implicitly refreshes a permission
        // (per RFC 8656 §11.2), and the persisted record tracks them
        // separately. Coalescing in the writer collapses both if needed.
        let now_epoch = epoch_ms();
        self.emit_write(WriteOp::Permission {
            relay_port,
            peer_ip: peer_addr.ip(),
            expires_at_ms: now_epoch + PERMISSION_LIFETIME.as_millis() as u64,
        });
        self.emit_write(WriteOp::Channel {
            relay_port,
            number: channel,
            peer_addr,
            expires_at_ms: now_epoch + CHANNEL_LIFETIME.as_millis() as u64,
        });
        Ok(())
    }

    /// Check bandwidth quota for an allocation. Returns Err if exceeded.
    /// Uses the allocation's tenant limit when set, else the global quota.
    pub fn check_bandwidth(&self, client_addr: &SocketAddr) -> Result<(), SessionError> {
        let alloc = self
            .allocations
            .get(client_addr)
            .ok_or(SessionError::NotFound)?;
        let (limit, disabled) = self.bandwidth_policy_for_user(
            &alloc.realm,
            alloc.tenant_id.as_deref(),
            &alloc.username,
        );
        if disabled {
            return Err(SessionError::BandwidthExceeded(alloc.username.clone()));
        }
        if limit == 0 {
            return Ok(()); // No limit
        }
        match alloc.check_bandwidth(limit) {
            Ok(_) => Ok(()),
            Err(()) => {
                let username = alloc.username.clone();
                Err(SessionError::BandwidthExceeded(username))
            }
        }
    }

    pub fn refresh(&self, client_addr: &SocketAddr, lifetime: u32) -> Result<(), SessionError> {
        let (relay_port, expires_at_ms) = {
            let mut alloc = self
                .allocations
                .get_mut(client_addr)
                .ok_or(SessionError::NotFound)?;
            if lifetime == 0 {
                let relay_addr = alloc.relay_addr;
                drop(alloc);
                // remove() emits its own WriteOp::Remove, no event here.
                return self.remove(client_addr, relay_addr);
            }
            alloc.expires_at = Instant::now() + Duration::from_secs(lifetime as u64);
            (
                alloc.relay_addr.port(),
                epoch_ms() + (lifetime as u64) * 1000,
            )
        };

        self.emit_write(WriteOp::Refresh {
            relay_port,
            expires_at_ms,
        });
        Ok(())
    }

    pub fn remove(
        &self,
        client_addr: &SocketAddr,
        relay_addr: SocketAddr,
    ) -> Result<(), SessionError> {
        if let Some((_, alloc)) = self.allocations.remove(client_addr) {
            self.release_counters(&alloc.realm, alloc.tenant_id.as_deref(), &alloc.username);
            self.accrue_tenant_traffic(&alloc);
            for &ch in alloc.channel_bindings.keys() {
                self.channel_to_client.remove(&(relay_addr.port(), ch));
            }
            self.relay_to_client.remove(&relay_addr);
            self.id_to_client.remove(&alloc.allocation_id);
            self.pool_for_port(relay_addr.port())
                .release(relay_addr.port());

            // Remove from user tracking
            if let Some(mut addrs) = self.user_allocations.get_mut(&(
                alloc.realm.clone(),
                alloc.tenant_id.clone(),
                alloc.username.clone(),
            )) {
                addrs.retain(|a| a != client_addr);
            }

            // Emit only when we actually removed something — a no-op
            // `remove()` shouldn't generate a backend round-trip.
            self.emit_write(WriteOp::Remove {
                relay_port: relay_addr.port(),
            });

            tracing::info!(%client_addr, %relay_addr, username = %alloc.username, "allocation removed");
        }
        Ok(())
    }

    /// Fold a removed allocation's relayed totals into its tenant's cumulative
    /// counters. Called from every whole-allocation removal path (`remove`,
    /// `force_remove`, and therefore `cleanup_expired_budget` which removes via
    /// `remove`). No-op for untenanted (base) allocations. Cheap: one mutex
    /// acquisition per allocation teardown, never on the packet path.
    fn accrue_tenant_traffic(&self, alloc: &Allocation) {
        let Some(tenant) = alloc.tenant_id.as_ref() else {
            return;
        };
        let bytes = alloc.bytes_relayed.load(Ordering::Relaxed);
        let packets = alloc.packets_relayed.load(Ordering::Relaxed);
        if let Ok(mut map) = self.tenant_traffic.lock() {
            let e = map.entry(tenant.clone()).or_default();
            e.bytes = e.bytes.saturating_add(bytes);
            e.packets = e.packets.saturating_add(packets);
            e.closed_allocations = e.closed_allocations.saturating_add(1);
        }
    }

    /// Snapshot of cumulative per-tenant relayed traffic for the `/metrics`
    /// exporter: `(tenant, bytes, packets, closed_allocations)`. Reflects all
    /// allocations torn down so far; bytes of currently-live allocations are
    /// counted when those allocations are removed.
    pub fn tenant_traffic_snapshot(&self) -> Vec<(String, u64, u64, u64)> {
        match self.tenant_traffic.lock() {
            Ok(map) => map
                .iter()
                .map(|(t, v)| (t.clone(), v.bytes, v.packets, v.closed_allocations))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Cleanup expired allocations, permissions, and channel bindings.
    pub fn cleanup_expired(&self) -> usize {
        self.cleanup_expired_budget(usize::MAX)
    }

    /// Sweep expired allocations and stale per-allocation entries.
    ///
    /// Returns the number of fully-expired allocations removed.
    ///
    /// Lock discipline (the fix for the all-shards stall): instead of holding
    /// each shard's write lock across a whole `iter_mut()` pass over the live
    /// datapath map, we take one read-only pass to classify, then act on each
    /// key with a brief, independent `get_mut` / `remove`. Allocations with
    /// nothing stale are skipped without ever taking a write lock. That turns a
    /// single long per-shard write-lock hold into a few short ones, so
    /// `store.get` on the hot path interleaves instead of stalling for the whole
    /// sweep.
    ///
    /// `max_ops` bounds the allocations classified this call, so a maintenance
    /// loop can cap its worst-case work under very large stores (100k+) and let
    /// the remainder roll to the next tick — the work is idempotent and
    /// order-independent, so no cursor is needed.
    pub fn cleanup_expired_budget(&self, max_ops: usize) -> usize {
        // 1. Read-only classification pass (short read locks, no write lock held
        //    across the map).
        let mut expired: Vec<(SocketAddr, SocketAddr)> = Vec::new();
        let mut to_clean: Vec<SocketAddr> = Vec::new();
        for r in self.allocations.iter() {
            if expired.len() + to_clean.len() >= max_ops {
                break;
            }
            if r.value().is_expired() {
                expired.push((*r.key(), r.value().relay_addr));
            } else if r.value().has_stale_entries() {
                to_clean.push(*r.key());
            }
        }

        // 2. Prune stale sub-entries on still-live allocations — one short
        //    write lock per allocation, released between each.
        for client in to_clean {
            if let Some(mut alloc) = self.allocations.get_mut(&client) {
                alloc.cleanup_expired_entries();
            }
        }

        // 3. Remove fully-expired allocations. Re-check expiry under a fresh
        //    lock first: a concurrent Refresh may have extended the lifetime
        //    since the classification pass (this also tightens the pre-existing
        //    scan-then-remove race down to a single get→remove gap).
        let mut count = 0;
        for (client, relay) in expired {
            let still_expired = self
                .allocations
                .get(&client)
                .map(|a| a.is_expired())
                .unwrap_or(false);
            if still_expired {
                let _ = self.remove(&client, relay);
                count += 1;
            }
        }

        self.user_allocations.retain(|_, v| !v.is_empty());
        self.user_counts
            .retain(|_, v| v.load(Ordering::Acquire) > 0);
        count
    }

    /// Get count of allocations for a username.
    pub fn user_allocation_count(&self, username: &str) -> usize {
        // Keep the legacy bare-username query by summing across realms and
        // tenants. Admission control itself always uses the canonical key.
        self.user_counts
            .iter()
            .filter(|e| e.key().2 == username)
            .map(|e| e.value().load(Ordering::Acquire))
            .sum()
    }

    pub fn len(&self) -> usize {
        self.allocations.len()
    }

    pub fn iter_all(&self) -> dashmap::iter::Iter<'_, std::net::SocketAddr, Allocation> {
        self.allocations.iter()
    }

    pub fn force_remove(&self, client_addr: &std::net::SocketAddr) {
        if let Some((_, alloc)) = self.allocations.remove(client_addr) {
            self.release_counters(&alloc.realm, alloc.tenant_id.as_deref(), &alloc.username);
            self.accrue_tenant_traffic(&alloc);
            self.relay_to_client.remove(&alloc.relay_addr);
            self.id_to_client.remove(&alloc.allocation_id);
            for &ch in alloc.channel_bindings.keys() {
                self.channel_to_client
                    .remove(&(alloc.relay_addr.port(), ch));
            }
            let relay_port = alloc.relay_addr.port();
            self.pool_for_port(relay_port).release(relay_port);
            if let Some(mut user_allocs) = self.user_allocations.get_mut(&(
                alloc.realm.clone(),
                alloc.tenant_id.clone(),
                alloc.username.clone(),
            )) {
                user_allocs.retain(|a| a != client_addr);
            }
            self.emit_write(WriteOp::Remove { relay_port });
        }
    }

    pub fn allocated_port_count(&self) -> usize {
        self.ports.used.lock().len()
    }

    pub fn available_port_count(&self) -> usize {
        let total = (self.ports.max_port - self.ports.min_port + 1) as usize;
        total - self.allocated_port_count()
    }

    pub fn is_empty(&self) -> bool {
        self.allocations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests — PR1 (write-behind scaffolding)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_write_behind {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::sync::mpsc;

    fn make_store() -> AllocationStore {
        AllocationStore::new(40000, 40100, 1000)
    }

    fn client(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn relay(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    /// Baseline: without `attach_writer`, no events should be emitted.
    /// This preserves the pre-PR1 behaviour byte-for-byte.
    #[test]
    fn no_writer_attached_is_zero_overhead() {
        let store = make_store();
        // We can't observe absence directly, but we can check that
        // operations succeed without anybody listening — i.e., the
        // `OnceLock::get()` short-circuit works.
        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .expect("create succeeded");
        store
            .refresh(&client(1000), 600)
            .expect("refresh succeeded");
        store
            .add_permission(&client(1000), "1.2.3.4".parse().unwrap())
            .expect("add_permission succeeded");
        store
            .remove(&client(1000), relay(40000))
            .expect("remove succeeded");
        assert_eq!(store.len(), 0);
    }

    /// With writer attached, `create` must emit exactly one `WriteOp::Create`.
    #[tokio::test]
    async fn create_emits_one_event() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store.attach_writer(tx);

        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .expect("create");

        match rx.try_recv() {
            Ok(WriteOp::Create {
                relay_port,
                username,
                ..
            }) => {
                assert_eq!(relay_port, 40000);
                assert_eq!(username, "alice");
            }
            other => panic!("expected Create, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "no more events expected");
    }

    /// P0 #16: `resync_all` re-emits the full live state (Create + one event
    /// per permission + one per channel) so a reconcile pass can repair a
    /// backend that dropped write-behind events.
    #[tokio::test]
    async fn resync_all_reemits_live_state() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store.attach_writer(tx);

        let c = client(1002);
        let r = relay(40002);
        let peer = SocketAddr::new("5.6.7.8".parse().unwrap(), 9000);
        store.create(c, r, "carol".into(), vec![], 600).unwrap();
        store
            .add_permission(&c, "1.2.3.4".parse().unwrap())
            .unwrap();
        store.add_channel(&c, 0x4000, peer).unwrap();

        // Drain the events emitted during setup.
        while rx.try_recv().is_ok() {}

        // Reconciliation re-emit of the authoritative live state.
        store.resync_all();

        let (mut creates, mut perms, mut chans, mut others) = (0, 0, 0, 0);
        while let Ok(op) = rx.try_recv() {
            match op {
                WriteOp::Create {
                    relay_port,
                    username,
                    ..
                } => {
                    assert_eq!(relay_port, 40002);
                    assert_eq!(username, "carol");
                    creates += 1;
                }
                WriteOp::Permission { relay_port, .. } => {
                    assert_eq!(relay_port, 40002);
                    perms += 1;
                }
                WriteOp::Channel {
                    relay_port, number, ..
                } => {
                    assert_eq!(relay_port, 40002);
                    assert_eq!(number, 0x4000);
                    chans += 1;
                }
                _ => others += 1,
            }
        }
        assert_eq!(creates, 1, "exactly one Create re-emitted");
        assert_eq!(perms, 2, "explicit + channel-implicit permissions");
        assert_eq!(chans, 1, "one channel binding");
        assert_eq!(others, 0, "resync emits no Refresh/Remove/ReKey");
    }

    /// A full lifecycle should emit Create, Refresh, Permission, Channel
    /// (+Permission), Remove — in that order. Note ChannelBind emits TWO
    /// events (Permission + Channel) per RFC implicit-permission rule.
    #[tokio::test]
    async fn lifecycle_emits_expected_sequence() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store.attach_writer(tx);

        let c = client(1001);
        let r = relay(40001);
        let peer = SocketAddr::new("5.6.7.8".parse().unwrap(), 9000);

        store.create(c, r, "bob".into(), vec![], 600).unwrap();
        store.refresh(&c, 300).unwrap();
        store
            .add_permission(&c, "1.2.3.4".parse().unwrap())
            .unwrap();
        store.add_channel(&c, 0x4000, peer).unwrap();
        store.remove(&c, r).unwrap();

        fn name(op: &WriteOp) -> &'static str {
            match op {
                WriteOp::Create { .. } => "Create",
                WriteOp::Refresh { .. } => "Refresh",
                WriteOp::Remove { .. } => "Remove",
                WriteOp::ReKey { .. } => "ReKey",
                WriteOp::Permission { .. } => "Permission",
                WriteOp::Channel { .. } => "Channel",
                WriteOp::Barrier { .. } => "Barrier",
            }
        }

        let mut seen = Vec::new();
        while let Ok(op) = rx.try_recv() {
            seen.push(name(&op));
        }
        // add_channel emits Permission then Channel — that's why
        // Permission appears twice (once standalone, once implicit).
        let expected = [
            "Create",
            "Refresh",
            "Permission",
            "Permission",
            "Channel",
            "Remove",
        ];
        assert_eq!(seen, expected, "event sequence mismatch");
    }

    /// Refresh with lifetime=0 should result in a single Remove event,
    /// not Refresh+Remove — the refresh path delegates to `remove()`.
    #[tokio::test]
    async fn refresh_zero_only_emits_remove() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store.attach_writer(tx);

        let c = client(1002);
        let r = relay(40002);
        store.create(c, r, "carol".into(), vec![], 600).unwrap();
        let _ = rx.try_recv(); // discard Create

        store.refresh(&c, 0).unwrap();
        match rx.try_recv() {
            Ok(WriteOp::Remove { relay_port }) => assert_eq!(relay_port, 40002),
            other => panic!("expected Remove, got {other:?}"),
        }
        assert!(rx.try_recv().is_err());
    }

    /// A no-op `remove` (allocation already gone) must NOT emit an event.
    #[tokio::test]
    async fn redundant_remove_emits_nothing() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store.attach_writer(tx);

        // Remove of a non-existent allocation — should be silent.
        store.remove(&client(9999), relay(40099)).unwrap();
        assert!(rx.try_recv().is_err(), "no event expected for no-op remove");
    }

    /// Attaching a writer twice is a defensive no-op (not a panic).
    #[tokio::test]
    async fn double_attach_writer_is_safe() {
        let store = make_store();
        let (tx1, mut rx1) = mpsc::channel(64);
        let (tx2, mut rx2) = mpsc::channel(64);
        store.attach_writer(tx1);
        store.attach_writer(tx2); // ignored

        store
            .create(client(1003), relay(40003), "dave".into(), vec![], 600)
            .unwrap();

        // The first sender should have received the event.
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_err());
    }

    /// If the writer task drops the receiver, the store keeps working
    /// (events are silently dropped — the in-memory state is the source
    /// of truth on the hot path).
    #[tokio::test]
    async fn dropped_receiver_does_not_break_store() {
        let store = make_store();
        let (tx, rx) = mpsc::channel(64);
        store.attach_writer(tx);
        drop(rx);

        // Should not panic, should not fail.
        store
            .create(client(1004), relay(40004), "eve".into(), vec![], 600)
            .unwrap();
        store.remove(&client(1004), relay(40004)).unwrap();
        assert_eq!(store.len(), 0);
    }

    /// PR2: when the bounded writer channel is full, events are dropped
    /// and counted, but the hot path never blocks.
    #[tokio::test]
    async fn full_channel_drops_events_and_counts() {
        let store = AllocationStore::new(40000, 40500, 10_000);
        // capacity=1 makes overflow easy to trigger
        let (tx, _rx) = mpsc::channel(1);
        store.attach_writer(tx);
        // We deliberately don't read from rx — the channel will fill up
        // after the first send and every subsequent emit will drop.

        for i in 0..10u16 {
            // Use distinct ports so create() itself succeeds (port allocator)
            // — what we're testing is the writer drop path, not allocation.
            store
                .create(client(2000 + i), relay(40000 + i), "x".into(), vec![], 600)
                .unwrap();
        }

        // 10 emits, capacity 1 → at least 9 must have been dropped.
        // (We can't pin the exact number because the channel might have
        //  buffered one before the receiver fell behind.)
        assert!(
            store.dropped_writes_count() >= 9,
            "expected >= 9 dropped, got {}",
            store.dropped_writes_count()
        );
    }

    // -----------------------------------------------------------------
    // PR3 — rehydrate
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rehydrate_basic_round_trip() {
        let store = make_store();
        let now = epoch_ms();

        let ok = store
            .rehydrate(
                client(3000),
                relay(40050),
                "alice".into(),
                "turna".into(),
                "rehy-alice".into(),
                0,
                now.saturating_sub(10_000),
                now + 600_000,
                std::iter::empty(),
                std::iter::empty(),
            )
            .unwrap();
        assert!(ok, "fresh expiry should rehydrate");
        assert_eq!(store.len(), 1);
        assert!(store.get(&client(3000)).is_some());
    }

    /// rehydrate must NOT emit a WriteOp even when a writer is attached.
    #[tokio::test]
    async fn rehydrate_never_emits() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(16);
        store.attach_writer(tx);

        store
            .rehydrate(
                client(3001),
                relay(40051),
                "bob".into(),
                "turna".into(),
                "rehy-bob".into(),
                0,
                epoch_ms().saturating_sub(10_000),
                epoch_ms() + 600_000,
                std::iter::empty(),
                std::iter::empty(),
            )
            .unwrap();

        assert!(
            rx.try_recv().is_err(),
            "rehydrate must not emit any WriteOp event"
        );
    }

    /// Expired record → Ok(false), no state change, port not reserved.
    #[tokio::test]
    async fn rehydrate_expired_returns_false() {
        let store = make_store();
        let now = epoch_ms();
        let ok = store
            .rehydrate(
                client(3002),
                relay(40052),
                "carol".into(),
                "turna".into(),
                "rehy-carol".into(),
                0,
                now.saturating_sub(120_000),
                now.saturating_sub(60_000), // already expired
                std::iter::empty(),
                std::iter::empty(),
            )
            .unwrap();
        assert!(!ok, "expired record should be skipped");
        assert_eq!(store.len(), 0);
        // Port must remain free — a subsequent create() should be able to
        // claim it via the normal allocator (we don't pin the exact port
        // returned by allocate(), so just confirm no conflict).
        assert!(
            store.ports.reserve(40052).is_ok(),
            "expired rehydrate must not have reserved the port"
        );
    }

    /// Rehydrating the same port twice fails on the second attempt
    /// (port already reserved). First call's state is intact.
    #[tokio::test]
    async fn rehydrate_double_port_conflict() {
        let store = make_store();
        let now = epoch_ms();
        store
            .rehydrate(
                client(3003),
                relay(40053),
                "dave".into(),
                "turna".into(),
                "rehy-dave".into(),
                0,
                now.saturating_sub(10_000),
                now + 600_000,
                std::iter::empty(),
                std::iter::empty(),
            )
            .unwrap();

        let err = store.rehydrate(
            client(3004),
            relay(40053),
            "eve".into(),
            "turna".into(),
            "rehy-eve".into(),
            0,
            now.saturating_sub(10_000),
            now + 600_000,
            std::iter::empty(),
            std::iter::empty(),
        );
        assert!(err.is_err(), "second rehydrate on same port must fail");
        assert_eq!(store.len(), 1, "first rehydrate must still be present");
    }

    /// Permissions/channels with expired timestamps are filtered out.
    /// Fresh ones are kept.
    #[tokio::test]
    async fn rehydrate_filters_expired_sub_records() {
        let store = make_store();
        let now = epoch_ms();
        let peer_ok: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let peer_old: std::net::IpAddr = "10.0.0.6".parse().unwrap();
        let chan_peer = SocketAddr::new("10.0.0.5".parse().unwrap(), 9000);

        let ok = store
            .rehydrate(
                client(3005),
                relay(40054),
                "frank".into(),
                "turna".into(),
                "rehy-frank".into(),
                0,
                now.saturating_sub(10_000),
                now + 600_000,
                // peer_ok has fresh expiry, peer_old already expired
                vec![(peer_ok, now + 60_000), (peer_old, now - 1)].into_iter(),
                vec![
                    (0x4000, chan_peer, now + 60_000), // fresh channel
                    (0x4001, chan_peer, now - 1),      // expired channel
                ]
                .into_iter(),
            )
            .unwrap();
        assert!(ok);

        // Channel 0x4000 must be reachable, 0x4001 must not.
        assert!(
            store.get_by_channel(40054, 0x4000).is_some(),
            "fresh channel should be present"
        );
        assert!(
            store.get_by_channel(40054, 0x4001).is_none(),
            "expired channel must not be present"
        );
    }

    // -----------------------------------------------------------------
    // Connection Migration (RFC 8016) — re_key + id index
    // -----------------------------------------------------------------

    /// Every allocation gets a unique, stable id, resolvable via `get_by_id`.
    #[test]
    fn allocation_id_is_minted_and_indexed() {
        let store = make_store();
        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .unwrap();
        store
            .create(client(1001), relay(40001), "alice".into(), vec![], 600)
            .unwrap();

        let id0 = store.get(&client(1000)).unwrap().allocation_id.clone();
        let id1 = store.get(&client(1001)).unwrap().allocation_id.clone();
        assert_ne!(id0, id1, "ids must be unique");
        assert_eq!(store.get_by_id(&id0), Some(client(1000)));
        assert_eq!(store.get_by_id(&id1), Some(client(1001)));
        assert_eq!(store.get_by_id("nonexistent"), None);
    }

    /// The heart of migration: re_key moves the allocation and *every* index
    /// that references the client address, while id / relay / channels survive.
    #[test]
    fn re_key_moves_every_index() {
        let store = make_store();
        let old = client(1000);
        let new = client(1500); // "new network" — different port/ip in practice
        let r = relay(40000);
        let peer = SocketAddr::new("5.6.7.8".parse().unwrap(), 9000);

        store.create(old, r, "alice".into(), vec![], 600).unwrap();
        store.add_permission(&old, peer.ip()).unwrap();
        store.add_channel(&old, 0x4000, peer).unwrap();
        let id = store.get(&old).unwrap().allocation_id.clone();

        // Pre-conditions.
        assert_eq!(
            store.get(&old).unwrap().migration_epoch,
            0,
            "epoch starts at 0"
        );
        assert_eq!(store.get_by_relay(&r), Some(old));
        assert_eq!(store.get_by_channel(40000, 0x4000), Some(old));
        assert_eq!(store.get_by_id(&id), Some(old));
        assert_eq!(store.user_allocation_count("alice"), 1);

        let relay_addr = store.re_key(&old, new).expect("re_key");
        assert_eq!(relay_addr, r, "relay address must be preserved");

        // Old 5-tuple is gone; new 5-tuple owns the allocation.
        assert!(store.get(&old).is_none());
        assert!(store.get(&new).is_some());
        assert_eq!(store.get(&new).unwrap().client_addr, new);
        // Epoch bumped exactly once (anti-replay handle).
        assert_eq!(
            store.get(&new).unwrap().migration_epoch,
            1,
            "epoch bumps on re_key"
        );
        // id is preserved and now points to the new address.
        assert_eq!(store.get(&new).unwrap().allocation_id, id);
        assert_eq!(store.get_by_id(&id), Some(new));
        // Reverse indices follow the move (relay key unchanged, value moved).
        assert_eq!(store.get_by_relay(&r), Some(new));
        assert_eq!(store.get_by_channel(40000, 0x4000), Some(new));
        // Permission survives.
        assert!(store.get(&new).unwrap().has_permission(&peer));
        // User tracking still shows exactly one allocation, under the new addr.
        assert_eq!(store.user_allocation_count("alice"), 1);
    }

    /// Re-keying onto an address that already hosts another allocation must be
    /// refused — we never clobber a live allocation.
    #[test]
    fn re_key_target_in_use_is_rejected() {
        let store = make_store();
        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .unwrap();
        store
            .create(client(1001), relay(40001), "bob".into(), vec![], 600)
            .unwrap();

        let err = store.re_key(&client(1000), client(1001)).unwrap_err();
        assert!(matches!(err, SessionError::MigrationTargetInUse));
        // Both allocations remain intact and untouched.
        assert!(store.get(&client(1000)).is_some());
        assert!(store.get(&client(1001)).is_some());
    }

    /// Re-keying an unknown source address is NotFound.
    #[test]
    fn re_key_unknown_source_is_not_found() {
        let store = make_store();
        let err = store.re_key(&client(9999), client(8888)).unwrap_err();
        assert!(matches!(err, SessionError::NotFound));
    }

    /// Re-key to the same address is an idempotent no-op returning the relay.
    #[test]
    fn re_key_same_address_is_noop() {
        let store = make_store();
        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .unwrap();
        let r = store.re_key(&client(1000), client(1000)).unwrap();
        assert_eq!(r, relay(40000));
        assert!(store.get(&client(1000)).is_some());
    }

    /// After re_key, removing under the *new* address fully cleans the id
    /// index (no dangling id → client mapping).
    #[test]
    fn re_key_then_remove_clears_id_index() {
        let store = make_store();
        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .unwrap();
        let id = store.get(&client(1000)).unwrap().allocation_id.clone();
        store.re_key(&client(1000), client(1500)).unwrap();
        store.remove(&client(1500), relay(40000)).unwrap();

        assert_eq!(store.get_by_id(&id), None, "id index must be cleared");
        assert_eq!(store.get_by_relay(&relay(40000)), None);
        assert_eq!(store.len(), 0);
    }

    /// re_key emits exactly one WriteOp::ReKey carrying the relay port and
    /// the new client address.
    #[tokio::test]
    async fn re_key_emits_rekey_event() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store
            .create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .unwrap();
        store.attach_writer(tx); // attach AFTER create so we only see ReKey

        store.re_key(&client(1000), client(1500)).unwrap();
        match rx.try_recv() {
            Ok(WriteOp::ReKey {
                relay_port,
                new_client_addr,
                new_epoch,
            }) => {
                assert_eq!(relay_port, 40000);
                assert_eq!(new_client_addr, client(1500));
                assert_eq!(new_epoch, 1, "first re_key bumps epoch 0 → 1");
            }
            other => panic!("expected ReKey, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one event expected");
    }
}

#[cfg(test)]
mod tenant_pool_tests {
    use super::*;

    fn addr(p: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], p))
    }

    #[tokio::test]
    async fn pools_are_isolated_and_routed_by_range() {
        let store = AllocationStore::new(40000, 40099, 10_000)
            .with_tenant_pool("acme", 50000, 50099, 0, BandwidthQuota::default())
            .with_tenant_pool("beta", 51000, 51099, 0, BandwidthQuota::default());

        // Each tenant allocates only from its own range; base from the base range.
        let pa = store.pool(Some("acme")).allocate().unwrap();
        let pb = store.pool(Some("beta")).allocate().unwrap();
        let p0 = store.pool(None).allocate().unwrap();
        assert!((50000..=50099).contains(&pa), "acme port {pa}");
        assert!((51000..=51099).contains(&pb), "beta port {pb}");
        assert!((40000..=40099).contains(&p0), "base port {p0}");

        // Range-based routing for release/reserve.
        assert_eq!(store.tenant_id_for_port(pa).as_deref(), Some("acme"));
        assert_eq!(store.tenant_id_for_port(pb).as_deref(), Some("beta"));
        assert_eq!(store.tenant_id_for_port(p0), None);
        assert!(store.pool_for_port(pa).contains(pa));
        assert!(store.pool_for_port(p0).contains(p0));
    }

    #[tokio::test]
    async fn per_tenant_allocation_cap_enforced() {
        let store = AllocationStore::new(40000, 40999, 10_000).with_tenant_pool(
            "acme",
            50000,
            50999,
            2,
            BandwidthQuota::default(),
        ); // cap = 2

        store
            .create_for_tenant(
                addr(1000),
                addr(50000),
                "u".into(),
                vec![],
                600,
                Some("acme".into()),
            )
            .unwrap();
        store
            .create_for_tenant(
                addr(1001),
                addr(50001),
                "u".into(),
                vec![],
                600,
                Some("acme".into()),
            )
            .unwrap();
        // Third allocation for the same tenant must hit the per-tenant cap.
        let third = store.create_for_tenant(
            addr(1002),
            addr(50002),
            "u".into(),
            vec![],
            600,
            Some("acme".into()),
        );
        assert!(matches!(third, Err(SessionError::MaxAllocations)));

        // A different tenant (or base) is unaffected by acme's cap.
        store
            .create_for_tenant(addr(2000), addr(40000), "u".into(), vec![], 600, None)
            .unwrap();
    }

    #[tokio::test]
    async fn release_returns_port_to_tenant_pool() {
        let store = AllocationStore::new(40000, 40099, 10_000).with_tenant_pool(
            "acme",
            50000,
            50001,
            0,
            BandwidthQuota::default(),
        ); // 2-port range

        let p = store.pool(Some("acme")).allocate().unwrap();
        store
            .create_for_tenant(
                addr(1000),
                addr(p),
                "u".into(),
                vec![],
                600,
                Some("acme".into()),
            )
            .unwrap();
        // The port is taken in acme's pool; re-reserving must fail.
        assert!(store.pool_for_port(p).reserve(p).is_err());

        // Removing the allocation must return the port to acme's pool.
        store.remove(&addr(1000), addr(p)).unwrap();
        assert!(
            store.pool_for_port(p).reserve(p).is_ok(),
            "port should be reusable in the tenant pool after release"
        );
    }
}

#[cfg(test)]
mod tenant_quota_tests {
    use super::*;

    fn addr(p: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], p))
    }

    #[tokio::test]
    async fn bandwidth_limit_resolves_tenant_then_global() {
        let store = AllocationStore::new(40000, 40099, 10_000)
            .with_quota(BandwidthQuota {
                max_bytes_per_sec_per_allocation: 1000,
                max_per_user: 0,
            })
            .with_tenant_pool(
                "acme",
                50000,
                50099,
                0,
                BandwidthQuota {
                    max_bytes_per_sec_per_allocation: 500,
                    max_per_user: 0,
                },
            )
            .with_tenant_pool(
                "beta",
                51000,
                51099,
                0,
                BandwidthQuota {
                    max_bytes_per_sec_per_allocation: 0,
                    max_per_user: 0,
                },
            );

        assert_eq!(store.bandwidth_limit_for(Some("acme")), 500); // tenant override
        assert_eq!(store.bandwidth_limit_for(Some("beta")), 1000); // 0 → inherit global
        assert_eq!(store.bandwidth_limit_for(None), 1000); // base → global
        assert_eq!(store.bandwidth_limit_for(Some("ghost")), 1000); // unknown → global
    }

    #[test]
    fn bandwidth_budget_is_per_allocation_not_aggregate() {
        // §5: the effective bandwidth policy (global→tenant→user inheritance)
        // yields a PER-ALLOCATION budget. Two allocations of the SAME user each
        // get the full budget against their OWN window; there is no shared,
        // user-wide aggregate bucket.
        let store = AllocationStore::new(40000, 40099, 10_000).with_quota(BandwidthQuota {
            max_bytes_per_sec_per_allocation: 1000,
            max_per_user: 0,
        });
        // "alice" has no narrower override, so she inherits the global budget.
        let limit = store.bandwidth_limit_for_user("example.org", None, "alice");
        assert_eq!(limit, 1000, "effective per-allocation budget");

        let client_a = addr(5000);
        let client_b = addr(5001);
        store
            .create(client_a, addr(40000), "alice".into(), vec![1], 600)
            .unwrap();
        store
            .create(client_b, addr(40001), "alice".into(), vec![2], 600)
            .unwrap();

        // Drain allocation A past its own per-allocation budget.
        {
            let a = store.allocations.get(&client_a).unwrap();
            a.add_bytes(limit + 1);
            assert!(
                a.check_bandwidth(limit).is_err(),
                "A exceeds its own per-allocation budget"
            );
        }
        // Allocation B is untouched: it still has its FULL independent budget.
        // A shared aggregate bucket, already drained by A, would wrongly deny B.
        {
            let b = store.allocations.get(&client_b).unwrap();
            assert!(
                b.check_bandwidth(limit).is_ok(),
                "B has an independent per-allocation budget"
            );
        }
    }

    #[tokio::test]
    async fn live_limit_setters_take_effect_atomically() {
        let store = AllocationStore::new(40000, 40999, 10_000).with_quota(BandwidthQuota {
            max_bytes_per_sec_per_allocation: 1000,
            max_per_user: 100,
        });
        // Seeded from with_quota / new.
        assert_eq!(store.bandwidth_limit_for(None), 1000);
        assert_eq!(store.effective_max_per_user(None), 100);
        assert_eq!(store.live_limits(), (1000, 100, 10_000));

        // S5: publish new per-user limits at runtime (shared &self).
        store.set_user_quota(500, 5);
        assert_eq!(store.bandwidth_limit_for(None), 500);
        assert_eq!(store.effective_max_per_user(None), 5);

        // S4: publish a new global allocation cap at runtime.
        store.set_max_allocations(42);
        assert_eq!(store.live_limits(), (500, 5, 42));

        // Tenant overrides are unaffected by global runtime changes.
        assert_eq!(store.bandwidth_limit_for(Some("acme")), 500); // no tenant here → global

        // S4-3: the node handler's commit point publishes a whole snapshot in
        // one atomic swap, carrying its version; readers observe one consistent
        // snapshot (never a torn mix).
        store.publish_runtime(RuntimeLimits {
            version: 7,
            max_bytes_per_sec_per_allocation: 2000,
            max_per_user: 9,
            max_allocations: 123,
        });
        let snap = store.runtime_snapshot();
        assert_eq!(snap.version, 7);
        assert_eq!(
            (
                snap.max_bytes_per_sec_per_allocation,
                snap.max_per_user,
                snap.max_allocations
            ),
            (2000, 9, 123)
        );
        assert_eq!(store.live_limits(), (2000, 9, 123));
        assert_eq!(store.bandwidth_limit_for(None), 2000);
    }

    #[tokio::test]
    async fn per_tenant_max_per_user_overrides_global() {
        // Global per-user cap disabled; acme caps at 2 per user.
        let store = AllocationStore::new(40000, 40999, 10_000)
            .with_quota(BandwidthQuota {
                max_bytes_per_sec_per_allocation: 0,
                max_per_user: 0,
            })
            .with_tenant_pool(
                "acme",
                50000,
                50999,
                0,
                BandwidthQuota {
                    max_bytes_per_sec_per_allocation: 0,
                    max_per_user: 2,
                },
            );

        assert_eq!(store.effective_max_per_user(Some("acme")), 2);
        assert_eq!(store.effective_max_per_user(None), 0); // base → global (0)

        let mk = |c: u16, r: u16| {
            store.create_for_tenant(
                addr(c),
                addr(r),
                "sameuser".into(),
                vec![],
                600,
                Some("acme".into()),
            )
        };
        mk(1000, 50000).unwrap();
        mk(1001, 50001).unwrap();
        // Third allocation for the same user in acme hits the per-tenant cap.
        assert!(matches!(
            mk(1002, 50002),
            Err(SessionError::MaxAllocationsPerUser)
        ));

        // Base tenant (global cap = 0) is unlimited for the same volume.
        for i in 0..5u16 {
            store
                .create_for_tenant(
                    addr(2000 + i),
                    addr(40000 + i),
                    "baseuser".into(),
                    vec![],
                    600,
                    None,
                )
                .unwrap();
        }
    }

    #[test]
    fn tenant_traffic_accrues_on_removal() {
        let store = AllocationStore::new(40000, 40099, 10_000);
        let client = addr(5000);
        let relay = addr(40000);
        store
            .create_for_tenant(
                client,
                relay,
                "u".into(),
                vec![1, 2, 3],
                600,
                Some("acme".into()),
            )
            .unwrap();

        // Relay some traffic; each add_bytes also bumps the packet counter.
        {
            let a = store.allocations.get(&client).unwrap();
            a.add_bytes(1000);
            a.add_bytes(500);
        } // drop the DashMap ref before remove()

        // Design (a): nothing is accrued until the allocation is torn down.
        assert!(store.tenant_traffic_snapshot().is_empty());

        store.remove(&client, relay).unwrap();

        let mut snap = store.tenant_traffic_snapshot();
        assert_eq!(snap.len(), 1);
        let (tenant, bytes, packets, closed) = snap.pop().unwrap();
        assert_eq!(tenant, "acme");
        assert_eq!(bytes, 1500);
        assert_eq!(packets, 2);
        assert_eq!(closed, 1);
    }

    #[test]
    fn base_tenant_traffic_not_tracked() {
        let store = AllocationStore::new(40000, 40099, 10_000);
        let client = addr(5001);
        let relay = addr(40001);
        store
            .create(client, relay, "u".into(), vec![1], 600)
            .unwrap(); // tenant_id = None
        {
            let a = store.allocations.get(&client).unwrap();
            a.add_bytes(999);
        }
        store.remove(&client, relay).unwrap();
        assert!(
            store.tenant_traffic_snapshot().is_empty(),
            "untenanted (base) traffic is not attributed to any tenant"
        );
    }

    #[test]
    fn channel_bind_uniqueness_conflicts() {
        let store = AllocationStore::new(40000, 40099, 10_000);
        let client = addr(6000);
        let relay = addr(40000);
        store
            .create(client, relay, "u".into(), vec![1], 600)
            .unwrap();
        let peer_a = addr(7000);
        let peer_b = addr(7001);

        // First bind succeeds.
        store.add_channel(&client, 0x4000, peer_a).unwrap();
        // Same channel, different peer → conflict (RFC 8656 §12.2), no state change.
        assert!(matches!(
            store.add_channel(&client, 0x4000, peer_b),
            Err(SessionError::ChannelConflict)
        ));
        // Different channel, peer already bound elsewhere → conflict.
        assert!(matches!(
            store.add_channel(&client, 0x4001, peer_a),
            Err(SessionError::ChannelConflict)
        ));
        // Re-binding the same (channel, peer) pair is a refresh → ok.
        store.add_channel(&client, 0x4000, peer_a).unwrap();
    }

    #[test]
    fn even_port_and_reservation_token() {
        let pool = PortAllocator::new(40000, 40010);

        // EVEN-PORT (R=0): an even port.
        let e = pool.allocate_even().expect("an even port");
        assert_eq!(e % 2, 0, "EVEN-PORT must yield an even port");

        // EVEN-PORT (R=1): even port + reserved next-higher odd port under a token.
        let (e2, tok) = pool
            .allocate_even_with_reservation()
            .expect("even + reservation");
        assert_eq!(e2 % 2, 0);

        // The token resolves to e2+1 exactly once (single-use).
        assert_eq!(pool.claim_reservation(&tok), Some(e2 + 1));
        assert_eq!(pool.claim_reservation(&tok), None, "token is single-use");

        // An unknown token resolves to nothing.
        assert_eq!(pool.claim_reservation(&[0u8; 8]), None);
    }
}

#[cfg(test)]
mod b1_concurrent_create_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Barrier};

    // B1 DoD: two concurrent create_for_tenant on the same client_addr from
    // different threads — exactly one wins, the other gets AllocationExists,
    // and only one allocation lands in the store. Looped to shake out the race.
    #[test]
    fn concurrent_create_same_client_only_one_wins() {
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 50000);
        for _ in 0..10_000 {
            let store = Arc::new(AllocationStore::new(40000, 40100, 1000));
            let barrier = Arc::new(Barrier::new(2));

            let mk = |relay_port: u16, user: &'static str| {
                let s = store.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    let relay =
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), relay_port);
                    b.wait();
                    s.create_for_tenant(client, relay, user.into(), vec![1], 600, None)
                })
            };

            let h1 = mk(40001, "u1");
            let h2 = mk(40002, "u2");
            let o1 = h1.join().unwrap();
            let o2 = h2.join().unwrap();

            let wins = [o1.is_ok(), o2.is_ok()].iter().filter(|w| **w).count();
            assert_eq!(wins, 1, "exactly one concurrent create must win");
            let losers = [&o1, &o2]
                .iter()
                .filter(|r| matches!(r, Err(SessionError::AllocationExists)))
                .count();
            assert_eq!(losers, 1, "the loser must get AllocationExists");
            assert!(
                store.get(&client).is_some(),
                "winner's allocation must exist"
            );
        }
    }
}

#[cfg(test)]
mod b5_resource_caps_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn store_with_alloc() -> (AllocationStore, SocketAddr) {
        let store = AllocationStore::new(40000, 40100, 1000);
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 50000);
        let relay = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 40001);
        store
            .create(client, relay, "u".into(), vec![1], 600)
            .unwrap();
        (store, client)
    }

    #[test]
    fn permission_cap_enforced_refresh_exempt() {
        let (store, client) = store_with_alloc();
        for i in 0..MAX_PERMISSIONS_PER_ALLOCATION {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32 + i as u32));
            store.add_permission(&client, ip).expect("under cap");
        }
        let over = IpAddr::V4(Ipv4Addr::from(0x0c00_0000u32));
        assert!(matches!(
            store.add_permission(&client, over),
            Err(SessionError::LimitExceeded)
        ));
        let first = IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32));
        assert!(store.add_permission(&client, first).is_ok());
    }

    #[test]
    fn channel_cap_enforced_refresh_exempt() {
        let (store, client) = store_with_alloc();
        for i in 0..MAX_CHANNELS_PER_ALLOCATION {
            let ch = 0x4000u16 + i as u16;
            let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32 + i as u32)), 9000);
            store.add_channel(&client, ch, peer).expect("under cap");
        }
        let over_ch = 0x4000u16 + MAX_CHANNELS_PER_ALLOCATION as u16;
        let over_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0c00_0000u32)), 9000);
        assert!(matches!(
            store.add_channel(&client, over_ch, over_peer),
            Err(SessionError::LimitExceeded)
        ));
        let peer0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0b00_0000u32)), 9000);
        assert!(store.add_channel(&client, 0x4000, peer0).is_ok());
    }
}

#[cfg(test)]
mod b4_tenant_scoped_user_key_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn c(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn per_user_tracking_is_tenant_scoped() {
        // B4: alice@A and alice@B must not share a per-user bucket.
        let store = AllocationStore::new(40000, 40100, 1000);
        store
            .create_for_tenant(
                c(50000),
                c(40001),
                "alice".into(),
                vec![1],
                600,
                Some("A".into()),
            )
            .unwrap();
        store
            .create_for_tenant(
                c(50001),
                c(40002),
                "alice".into(),
                vec![1],
                600,
                Some("B".into()),
            )
            .unwrap();

        assert_eq!(
            store
                .user_allocations
                .get(&(String::new(), Some("A".to_string()), "alice".to_string()))
                .map(|v| v.len())
                .unwrap_or(0),
            1
        );
        assert_eq!(
            store
                .user_allocations
                .get(&(String::new(), Some("B".to_string()), "alice".to_string()))
                .map(|v| v.len())
                .unwrap_or(0),
            1
        );
        assert_eq!(store.user_allocation_count("alice"), 2);
    }
}

#[cfg(test)]
mod b1_atomic_quota_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Barrier};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn concurrent_creates_never_exceed_global_cap() {
        // B1 DoD: 100 racing Allocate at max=10 → stored count never exceeds 10.
        for _ in 0..100 {
            let store = Arc::new(AllocationStore::new(40000, 41000, 10));
            let barrier = Arc::new(Barrier::new(100));
            let mut hs = Vec::new();
            for i in 0..100u16 {
                let s = store.clone();
                let b = barrier.clone();
                hs.push(std::thread::spawn(move || {
                    b.wait();
                    s.create_for_tenant(
                        addr(50000 + i),
                        addr(40000 + i),
                        "u".into(),
                        vec![1],
                        600,
                        None,
                    )
                }));
            }
            let ok = hs
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|r| r.is_ok())
                .count();
            assert!(
                store.len() <= 10,
                "global cap exceeded: len={}",
                store.len()
            );
            assert_eq!(ok, store.len(), "Ok count must equal stored count");
        }
    }

    #[test]
    fn release_on_remove_frees_capacity() {
        let store = AllocationStore::new(40000, 41000, 1);
        store
            .create_for_tenant(addr(50000), addr(40000), "u".into(), vec![1], 600, None)
            .unwrap();
        assert!(matches!(
            store.create_for_tenant(addr(50001), addr(40001), "u".into(), vec![1], 600, None),
            Err(SessionError::MaxAllocations)
        ));
        store.remove(&addr(50000), addr(40000)).unwrap();
        assert!(store
            .create_for_tenant(addr(50001), addr(40001), "u".into(), vec![1], 600, None)
            .is_ok());
    }
}

#[cfg(test)]
mod s5_runtime_limits_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Barrier};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn concurrent_user_limit_one_admits_exactly_one() {
        let store = Arc::new(AllocationStore::new(40000, 40100, 100));
        store.publish_runtime(RuntimeLimits {
            version: 1,
            max_bytes_per_sec_per_allocation: 0,
            max_per_user: 1,
            max_allocations: 100,
        });
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for i in 0..2u16 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.create_for_identity(
                    addr(50000 + i),
                    addr(40000 + i),
                    "alice".into(),
                    vec![1],
                    600,
                    "example.org".into(),
                    Some("tenant-a".into()),
                )
            }));
        }
        let admitted = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(Result::is_ok)
            .count();
        assert_eq!(admitted, 1);
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.current_user_usage("example.org", Some("tenant-a"), "alice"),
            1
        );
    }

    #[test]
    fn duplicate_insert_rolls_back_all_usage_reservations() {
        let store = AllocationStore::new(40000, 40100, 100);
        store.publish_runtime(RuntimeLimits {
            version: 1,
            max_bytes_per_sec_per_allocation: 0,
            max_per_user: 10,
            max_allocations: 100,
        });
        let client = addr(50000);
        store
            .create_for_identity(
                client,
                addr(40000),
                "alice".into(),
                vec![1],
                600,
                "example.org".into(),
                Some("tenant-a".into()),
            )
            .unwrap();
        assert!(matches!(
            store.create_for_identity(
                client,
                addr(40001),
                "alice".into(),
                vec![1],
                600,
                "example.org".into(),
                Some("tenant-a".into()),
            ),
            Err(SessionError::AllocationExists)
        ));
        assert_eq!(store.len(), 1);
        assert_eq!(store.global_count.load(Ordering::Acquire), 1);
        assert_eq!(store.current_tenant_usage("tenant-a"), 1);
        assert_eq!(
            store.current_user_usage("example.org", Some("tenant-a"), "alice"),
            1
        );
    }

    #[test]
    fn rehydrate_port_failure_rolls_back_usage_reservations() {
        let store = AllocationStore::new(40000, 40000, 100);
        store.ports.reserve(40000).unwrap();
        let now = epoch_ms();
        let result = store.rehydrate(
            addr(50000),
            addr(40000),
            "alice".into(),
            "example.org".into(),
            "alloc-1".into(),
            0,
            now,
            now + 60_000,
            std::iter::empty(),
            std::iter::empty(),
        );
        assert!(result.is_err());
        assert_eq!(store.len(), 0);
        assert_eq!(store.global_count.load(Ordering::Acquire), 0);
        assert_eq!(store.current_user_usage("example.org", None, "alice"), 0);
    }

    #[test]
    fn duplicate_remove_never_underflows_usage() {
        let store = AllocationStore::new(40000, 40100, 100);
        let client = addr(50000);
        let relay = addr(40000);
        store
            .create_for_identity(
                client,
                relay,
                "alice".into(),
                vec![1],
                600,
                "example.org".into(),
                None,
            )
            .unwrap();
        store.remove(&client, relay).unwrap();
        store.remove(&client, relay).unwrap();
        assert_eq!(store.global_count.load(Ordering::Acquire), 0);
        assert_eq!(store.current_user_usage("example.org", None, "alice"), 0);
    }

    #[test]
    fn global_limit_usage_reports_highest_user_not_total_allocations() {
        let store = AllocationStore::new(40000, 40100, 100);
        for (client, relay, username) in [
            (50000, 40000, "alice"),
            (50001, 40001, "alice"),
            (50002, 40002, "bob"),
        ] {
            store
                .create_for_identity(
                    addr(client),
                    addr(relay),
                    username.into(),
                    vec![1],
                    600,
                    "example.org".into(),
                    None,
                )
                .unwrap();
        }
        assert_eq!(store.len(), 3);
        assert_eq!(store.max_user_usage(), 2);
    }

    #[test]
    fn same_username_is_isolated_by_realm() {
        let store = AllocationStore::new(40000, 40100, 100);
        store.publish_runtime(RuntimeLimits {
            version: 1,
            max_bytes_per_sec_per_allocation: 0,
            max_per_user: 1,
            max_allocations: 100,
        });
        for (client, relay, realm) in [(50000, 40000, "a.example"), (50001, 40001, "b.example")] {
            store
                .create_for_identity(
                    addr(client),
                    addr(relay),
                    "alice".into(),
                    vec![1],
                    600,
                    realm.into(),
                    None,
                )
                .unwrap();
        }
        assert!(matches!(
            store.create_for_identity(
                addr(50002),
                addr(40002),
                "alice".into(),
                vec![1],
                600,
                "a.example".into(),
                None,
            ),
            Err(SessionError::MaxAllocationsPerUser)
        ));
        assert_eq!(store.current_user_usage("a.example", None, "alice"), 1);
        assert_eq!(store.current_user_usage("b.example", None, "alice"), 1);
    }

    #[test]
    fn user_then_tenant_then_global_precedence_is_field_independent() {
        let store = AllocationStore::new(40000, 40100, 100);
        store.publish_runtime(RuntimeLimits {
            version: 1,
            max_bytes_per_sec_per_allocation: 1_000,
            max_per_user: 10,
            max_allocations: 100,
        });
        let global = UserLimitsOverride {
            max_allocations: Some(LimitU32 {
                mode: LimitMode::Value,
                value: 8,
            }),
            max_bytes_per_sec_per_allocation: Some(LimitU64 {
                mode: LimitMode::Value,
                value: 800,
            }),
            max_lifetime_secs: None,
        };
        store
            .publish_user_limits(
                store
                    .limits_snapshot_with_override("global", "", "", "", global)
                    .unwrap(),
            )
            .unwrap();
        let tenant = UserLimitsOverride {
            max_allocations: Some(LimitU32 {
                mode: LimitMode::Value,
                value: 4,
            }),
            max_bytes_per_sec_per_allocation: None,
            max_lifetime_secs: None,
        };
        store
            .publish_user_limits(
                store
                    .limits_snapshot_with_override("tenant", "example.org", "tenant-a", "", tenant)
                    .unwrap(),
            )
            .unwrap();
        let user = UserLimitsOverride {
            max_allocations: None,
            max_bytes_per_sec_per_allocation: Some(LimitU64 {
                mode: LimitMode::Value,
                value: 200,
            }),
            max_lifetime_secs: None,
        };
        store
            .publish_user_limits(
                store
                    .limits_snapshot_with_override("user", "example.org", "tenant-a", "alice", user)
                    .unwrap(),
            )
            .unwrap();
        let effective = store.effective_user_limits("example.org", Some("tenant-a"), "alice");
        assert_eq!(effective.max_allocations, 4);
        assert_eq!(effective.max_bytes_per_sec_per_allocation, 200);
    }

    #[test]
    fn user_limits_generation_overflow_errors_without_panic() {
        let store = AllocationStore::new(40000, 40100, 100);
        // Seed the cache generation at the u64 ceiling.
        store
            .user_limits
            .store(std::sync::Arc::new(UserLimitsSnapshot {
                generation: u64::MAX,
                ..UserLimitsSnapshot::empty()
            }));
        // A changed snapshot cannot advance past u64::MAX → error, no publish, no
        // panic; the current snapshot is left intact.
        let changed = UserLimitsSnapshot {
            bootstrap_max_lifetime_secs: 123,
            ..UserLimitsSnapshot::empty()
        };
        let err = store.publish_user_limits(changed).unwrap_err();
        assert!(matches!(err, SessionError::CacheGenerationOverflow));
        let after = store.user_limits_snapshot();
        assert_eq!(after.generation, u64::MAX);
        assert_eq!(after.bootstrap_max_lifetime_secs, 0);
    }

    #[test]
    fn generation_bumps_only_on_actual_change() {
        let store = AllocationStore::new(40000, 40100, 100);
        let g0 = store.user_limits_snapshot().generation;
        let changed = UserLimitsSnapshot {
            bootstrap_max_lifetime_secs: 100,
            ..UserLimitsSnapshot::empty()
        };
        // An actual content change bumps the generation once.
        store.publish_user_limits(changed.clone()).unwrap();
        let g1 = store.user_limits_snapshot().generation;
        assert_eq!(g1, g0 + 1, "actual change bumps generation");
        // Republishing identical content is a no-op: no store, no bump.
        store.publish_user_limits(changed).unwrap();
        let g2 = store.user_limits_snapshot().generation;
        assert_eq!(g2, g1, "no-op publish does not bump generation");
    }

    #[test]
    fn node_ceiling_is_not_bypassed_by_user_unlimited() {
        // §7-B: a finite node bandwidth ceiling is a hard upper bound; a user
        // UNLIMITED override is capped to it, not honoured as unlimited.
        let store = AllocationStore::new(40000, 40099, 10_000).with_quota(BandwidthQuota {
            max_bytes_per_sec_per_allocation: 1000,
            max_per_user: 0,
        });
        store
            .publish_user_limits(
                store
                    .limits_snapshot_with_override(
                        "user",
                        "example.org",
                        "",
                        "alice",
                        UserLimitsOverride {
                            max_bytes_per_sec_per_allocation: Some(LimitU64 {
                                mode: LimitMode::Unlimited,
                                value: 0,
                            }),
                            ..Default::default()
                        },
                    )
                    .unwrap(),
            )
            .unwrap();
        let eff = store.effective_user_limits("example.org", None, "alice");
        assert_eq!(
            eff.max_bytes_per_sec_per_allocation, 1000,
            "capped to node ceiling"
        );
        assert!(!eff.bandwidth_disabled);
        assert!(eff
            .capped_fields
            .iter()
            .any(|f| f == "max_bytes_per_sec_per_allocation"));
    }

    #[test]
    fn requested_allocation_cap_above_ceiling_is_capped() {
        // §7-B: a requested per-user allocation cap above the finite node ceiling
        // is clamped to the ceiling; enforcement uses the capped value.
        let store = AllocationStore::new(40000, 40099, 10_000).with_quota(BandwidthQuota {
            max_bytes_per_sec_per_allocation: 0,
            max_per_user: 5,
        });
        store
            .publish_user_limits(
                store
                    .limits_snapshot_with_override(
                        "user",
                        "example.org",
                        "",
                        "alice",
                        UserLimitsOverride {
                            max_allocations: Some(LimitU32 {
                                mode: LimitMode::Value,
                                value: 50,
                            }),
                            ..Default::default()
                        },
                    )
                    .unwrap(),
            )
            .unwrap();
        let eff = store.effective_user_limits("example.org", None, "alice");
        assert_eq!(
            eff.max_allocations, 5,
            "requested 50 capped to node ceiling 5"
        );
        assert!(eff.capped_fields.iter().any(|f| f == "max_allocations"));
    }

    #[test]
    fn runtime_readers_never_observe_a_mixed_snapshot() {
        let store = Arc::new(AllocationStore::new(40000, 40100, 100));
        let a = RuntimeLimits {
            version: 10,
            max_bytes_per_sec_per_allocation: 100,
            max_per_user: 1,
            max_allocations: 10,
        };
        let b = RuntimeLimits {
            version: 20,
            max_bytes_per_sec_per_allocation: 200,
            max_per_user: 2,
            max_allocations: 20,
        };
        store.publish_runtime(a.clone());
        let writer_store = Arc::clone(&store);
        let writer = std::thread::spawn(move || {
            for i in 0..20_000 {
                writer_store.publish_runtime(if i % 2 == 0 { a.clone() } else { b.clone() });
            }
        });
        for _ in 0..20_000 {
            let snapshot = store.runtime_snapshot();
            let tuple = (
                snapshot.version,
                snapshot.max_bytes_per_sec_per_allocation,
                snapshot.max_per_user,
                snapshot.max_allocations,
            );
            assert!(
                tuple == (10, 100, 1, 10) || tuple == (20, 200, 2, 20),
                "mixed runtime snapshot observed: {tuple:?}"
            );
        }
        writer.join().unwrap();
    }
}

#[cfg(test)]
mod i9_reservation_cancel_tests {
    use super::*;

    #[test]
    fn cancel_reservation_frees_reserved_port() {
        let pool = PortAllocator::new(40000, 40010);
        // EVEN-PORT (R=1): reserves even `p` and odd `p+1`, issues a token.
        let (even, sock, token) = pool
            .allocate_even_and_bind(true)
            .expect("allocate even+reservation");
        let token = token.expect("R=1 must issue a reservation token");
        let odd = even + 1;
        assert!(
            pool.used.lock().contains(&even) && pool.used.lock().contains(&odd),
            "both even and reserved-odd start out used"
        );

        // Simulate a create-error path: release the relay port, cancel the token.
        pool.release(even);
        pool.cancel_reservation(&token);

        assert!(!pool.used.lock().contains(&even), "relay port freed");
        assert!(
            !pool.used.lock().contains(&odd),
            "reserved odd port freed (I9)"
        );
        assert!(
            !pool.reservations.lock().contains_key(&token),
            "reservation entry dropped"
        );
        drop(sock);
    }
}
