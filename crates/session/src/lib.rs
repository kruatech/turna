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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
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
    /// Owning tenant (multi-tenancy). `None` = base/default tenant.
    pub tenant_id: Option<String>,
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
    pub fn check_bandwidth(&self, max_bytes_per_sec: u64) -> Result<u64, ()> {
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
            return if bps > max_bytes_per_sec { Err(()) } else { Ok(bps) };
        }

        let current = self.bandwidth_window_bytes.load(Ordering::Relaxed);
        if current > max_bytes_per_sec {
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
        for _ in 0..64 {
            let port = self.allocate().ok()?;
            match std::net::UdpSocket::bind(("0.0.0.0", port)) {
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

    /// EVEN-PORT allocate + bind. `reserve_next` mirrors the EVEN-PORT R bit;
    /// when set, the next-higher port is reserved and the token is returned for
    /// the caller to echo as a RESERVATION-TOKEN. Releases everything on bind
    /// failure and retries another even pair.
    pub fn allocate_even_and_bind(
        &self,
        reserve_next: bool,
    ) -> Option<(u16, std::net::UdpSocket, Option<[u8; 8]>)> {
        for _ in 0..64 {
            let (even, token) = if reserve_next {
                let (e, t) = self.allocate_even_with_reservation()?;
                (e, Some(t))
            } else {
                (self.allocate_even()?, None)
            };
            match std::net::UdpSocket::bind(("0.0.0.0", even)) {
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
        let port = self.claim_reservation(token)?;
        match std::net::UdpSocket::bind(("0.0.0.0", port)) {
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
    pub max_bytes_per_sec: u64,
    /// Max allocations per username. 0 = unlimited.
    pub max_per_user: usize,
}

impl Default for BandwidthQuota {
    fn default() -> Self {
        Self {
            max_bytes_per_sec: 0, // unlimited
            max_per_user: 100,    // 100 allocations per user
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
    user_allocations: DashMap<String, Vec<SocketAddr>>,
    pub ports: PortAllocator,
    /// Per-tenant isolated port pools (multi-tenancy). Empty = single-tenant.
    /// Built once at startup via [`AllocationStore::with_tenant_pool`]; read-only
    /// afterwards (small N → linear scan in `pool`/`pool_for_port` is fine).
    tenant_pools: Vec<TenantPool>,
    max_allocations: usize,
    pub quota: BandwidthQuota,
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

impl AllocationStore {
    pub fn new(min_port: u16, max_port: u16, max_allocations: usize) -> Self {
        Self {
            allocations: DashMap::new(),
            relay_to_client: DashMap::new(),
            channel_to_client: DashMap::new(),
            id_to_client: DashMap::new(),
            next_id: AtomicU64::new(1),
            user_allocations: DashMap::new(),
            ports: PortAllocator::new(min_port, max_port),
            tenant_pools: Vec::new(),
            max_allocations,
            quota: BandwidthQuota::default(),
            write_tx: OnceLock::new(),
            dropped_writes: AtomicU64::new(0),
            tenant_traffic: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn with_quota(mut self, quota: BandwidthQuota) -> Self {
        self.quota = quota;
        self
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

    /// Effective bandwidth limit (bytes/sec) for an allocation: the tenant's
    /// value when set (> 0), otherwise the global quota. `0` = unlimited.
    pub fn bandwidth_limit_for(&self, tenant_id: Option<&str>) -> u64 {
        match self.tenant_quota(tenant_id) {
            Some(q) if q.max_bytes_per_sec > 0 => q.max_bytes_per_sec,
            _ => self.quota.max_bytes_per_sec,
        }
    }

    /// Effective per-user allocation cap: the tenant's value when set (> 0),
    /// otherwise the global quota. `0` = no per-user cap.
    fn effective_max_per_user(&self, tenant_id: Option<&str>) -> usize {
        match self.tenant_quota(tenant_id) {
            Some(q) if q.max_per_user > 0 => q.max_per_user,
            _ => self.quota.max_per_user,
        }
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
        self.create_for_tenant(client_addr, relay_addr, username, key, lifetime, None)
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
        if self.allocations.len() >= self.max_allocations {
            return Err(SessionError::MaxAllocations);
        }

        // Per-tenant allocation cap (isolation): a tenant cannot exceed its own
        // limit, independent of other tenants or the global cap.
        if let Some(tid) = tenant_id.as_deref() {
            let cap = self.tenant_max_allocations(tid);
            if cap > 0 {
                let count = self
                    .allocations
                    .iter()
                    .filter(|e| e.value().tenant_id.as_deref() == Some(tid))
                    .count();
                if count >= cap {
                    return Err(SessionError::MaxAllocations);
                }
            }
        }

        // Check per-user limit (per-tenant override when the tenant sets one).
        let max_per_user = self.effective_max_per_user(tenant_id.as_deref());
        if max_per_user > 0 {
            let count = self
                .user_allocations
                .get(&username)
                .map(|v| v.len())
                .unwrap_or(0);
            if count >= max_per_user {
                return Err(SessionError::MaxAllocationsPerUser);
            }
        }

        let now = Instant::now();
        let allocation_id = self.mint_id();
        let alloc = Allocation {
            allocation_id: allocation_id.clone(),
            migration_epoch: 0,
            client_addr,
            relay_addr,
            username: username.clone(),
            key,
            tenant_id,
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

        self.relay_to_client.insert(relay_addr, client_addr);
        self.id_to_client.insert(allocation_id.clone(), client_addr);
        self.allocations.insert(client_addr, alloc);

        // Track per-user
        self.user_allocations
            .entry(username.clone())
            .or_default()
            .push(client_addr);

        // Emit write-behind event — only after the in-memory state is
        // fully consistent (design doc §9 question 5).
        let now_epoch = epoch_ms();
        self.emit_write(WriteOp::Create {
            relay_port: relay_addr.port(),
            client_addr,
            relay_addr,
            username: username.clone(),
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

        if self.allocations.len() >= self.max_allocations {
            return Err(SessionError::MaxAllocations);
        }
        if self.quota.max_per_user > 0 {
            let count = self
                .user_allocations
                .get(&username)
                .map(|v| v.len())
                .unwrap_or(0);
            if count >= self.quota.max_per_user {
                return Err(SessionError::MaxAllocationsPerUser);
            }
        }

        // Reserve the port. If it's already taken, somebody else (live
        // create()? a duplicate record?) got there first. Route to the owning
        // pool by range so tenant-range ports are reserved in the tenant pool
        // (the base pool would reject an out-of-range port).
        self.pool_for_port(relay_addr.port())
            .reserve(relay_addr.port())?;

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
        // existing clients can continue using their established
        // permissions without re-issuing CreatePermission immediately.
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
            // issued by the previous owner validates here after a cross-node
            // failover. A row written before this field existed decodes to an
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
            // Derived from the port's owning pool (tenant ranges are disjoint).
            tenant_id: self.tenant_id_for_port(relay_addr.port()),
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

        // Reverse indices: relay→client, (relay_port, channel)→client.
        self.relay_to_client.insert(relay_addr, client_addr);
        self.id_to_client
            .insert(alloc.allocation_id.clone(), client_addr);
        for (&number, _) in alloc.channel_bindings.iter() {
            self.channel_to_client
                .insert((relay_addr.port(), number), client_addr);
        }
        self.allocations.insert(client_addr, alloc);
        self.user_allocations
            .entry(username.clone())
            .or_default()
            .push(client_addr);

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
        if let Some(mut addrs) = self.user_allocations.get_mut(&username) {
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
        let limit = self.bandwidth_limit_for(alloc.tenant_id.as_deref());
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
            self.accrue_tenant_traffic(&alloc);
            for &ch in alloc.channel_bindings.keys() {
                self.channel_to_client.remove(&(relay_addr.port(), ch));
            }
            self.relay_to_client.remove(&relay_addr);
            self.id_to_client.remove(&alloc.allocation_id);
            self.pool_for_port(relay_addr.port())
                .release(relay_addr.port());

            // Remove from user tracking
            if let Some(mut addrs) = self.user_allocations.get_mut(&alloc.username) {
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
        count
    }

    /// Get count of allocations for a username.
    pub fn user_allocation_count(&self, username: &str) -> usize {
        self.user_allocations
            .get(username)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.allocations.len()
    }

    pub fn iter_all(&self) -> dashmap::iter::Iter<'_, std::net::SocketAddr, Allocation> {
        self.allocations.iter()
    }

    pub fn force_remove(&self, client_addr: &std::net::SocketAddr) {
        if let Some((_, alloc)) = self.allocations.remove(client_addr) {
            self.accrue_tenant_traffic(&alloc);
            self.relay_to_client.remove(&alloc.relay_addr);
            self.id_to_client.remove(&alloc.allocation_id);
            for &ch in alloc.channel_bindings.keys() {
                self.channel_to_client
                    .remove(&(alloc.relay_addr.port(), ch));
            }
            let relay_port = alloc.relay_addr.port();
            self.pool_for_port(relay_port).release(relay_port);
            if let Some(mut user_allocs) = self.user_allocations.get_mut(&alloc.username) {
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
        assert_eq!(store.get(&old).unwrap().migration_epoch, 0, "epoch starts at 0");
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
        assert_eq!(store.get(&new).unwrap().migration_epoch, 1, "epoch bumps on re_key");
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
        let store = AllocationStore::new(40000, 40999, 10_000)
            .with_tenant_pool("acme", 50000, 50999, 2, BandwidthQuota::default()); // cap = 2

        store
            .create_for_tenant(addr(1000), addr(50000), "u".into(), vec![], 600, Some("acme".into()))
            .unwrap();
        store
            .create_for_tenant(addr(1001), addr(50001), "u".into(), vec![], 600, Some("acme".into()))
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
        let store = AllocationStore::new(40000, 40099, 10_000)
            .with_tenant_pool("acme", 50000, 50001, 0, BandwidthQuota::default()); // 2-port range

        let p = store.pool(Some("acme")).allocate().unwrap();
        store
            .create_for_tenant(addr(1000), addr(p), "u".into(), vec![], 600, Some("acme".into()))
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
            .with_quota(BandwidthQuota { max_bytes_per_sec: 1000, max_per_user: 0 })
            .with_tenant_pool("acme", 50000, 50099, 0,
                BandwidthQuota { max_bytes_per_sec: 500, max_per_user: 0 })
            .with_tenant_pool("beta", 51000, 51099, 0,
                BandwidthQuota { max_bytes_per_sec: 0, max_per_user: 0 });

        assert_eq!(store.bandwidth_limit_for(Some("acme")), 500); // tenant override
        assert_eq!(store.bandwidth_limit_for(Some("beta")), 1000); // 0 → inherit global
        assert_eq!(store.bandwidth_limit_for(None), 1000); // base → global
        assert_eq!(store.bandwidth_limit_for(Some("ghost")), 1000); // unknown → global
    }

    #[tokio::test]
    async fn per_tenant_max_per_user_overrides_global() {
        // Global per-user cap disabled; acme caps at 2 per user.
        let store = AllocationStore::new(40000, 40999, 10_000)
            .with_quota(BandwidthQuota { max_bytes_per_sec: 0, max_per_user: 0 })
            .with_tenant_pool("acme", 50000, 50999, 0,
                BandwidthQuota { max_bytes_per_sec: 0, max_per_user: 2 });

        assert_eq!(store.effective_max_per_user(Some("acme")), 2);
        assert_eq!(store.effective_max_per_user(None), 0); // base → global (0)

        let mk = |c: u16, r: u16| store.create_for_tenant(
            addr(c), addr(r), "sameuser".into(), vec![], 600, Some("acme".into()));
        mk(1000, 50000).unwrap();
        mk(1001, 50001).unwrap();
        // Third allocation for the same user in acme hits the per-tenant cap.
        assert!(matches!(mk(1002, 50002), Err(SessionError::MaxAllocationsPerUser)));

        // Base tenant (global cap = 0) is unlimited for the same volume.
        for i in 0..5u16 {
            store.create_for_tenant(addr(2000 + i), addr(40000 + i),
                "baseuser".into(), vec![], 600, None).unwrap();
        }
    }

    #[test]
    fn tenant_traffic_accrues_on_removal() {
        let store = AllocationStore::new(40000, 40099, 10_000);
        let client = addr(5000);
        let relay = addr(40000);
        store
            .create_for_tenant(client, relay, "u".into(), vec![1, 2, 3], 600, Some("acme".into()))
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
        store.create(client, relay, "u".into(), vec![1], 600).unwrap(); // tenant_id = None
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
        store.create(client, relay, "u".into(), vec![1], 600).unwrap();
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
