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
pub use write_op::{WriteOp, now_ms as epoch_ms};

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
    pub client_addr: SocketAddr,
    pub relay_addr: SocketAddr,
    pub username: String,
    pub key: Vec<u8>,
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
        self.channels_reverse
            .get(peer)
            .copied()
            .filter(|ch| {
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
    pub fn check_bandwidth(&self, max_bytes_per_sec: u64) -> Result<u64, ()> {
        let mut start = self.bandwidth_window_start.lock();
        let now = Instant::now();
        let elapsed = now.duration_since(*start).as_secs_f64();

        if elapsed >= 1.0 {
            // Reset window
            let bytes = self.bandwidth_window_bytes.swap(0, Ordering::Relaxed);
            *start = now;
            let bps = (bytes as f64 / elapsed) as u64;
            return Ok(bps);
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
        let expired_channels: Vec<u16> = self.channel_bindings
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
        self.channel_bindings.iter()
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
}

impl PortAllocator {
    pub fn new(min_port: u16, max_port: u16) -> Self {
        Self {
            min_port,
            max_port,
            next_port: Mutex::new(min_port),
            used: Mutex::new(HashSet::new()),
        }
    }

    pub fn allocate(&self) -> Result<u16, SessionError> {
        let mut next = self.next_port.lock();
        let mut used = self.used.lock();
        let start = *next;

        loop {
            if !used.contains(&*next) {
                let port = *next;
                used.insert(port);
                *next = if *next >= self.max_port { self.min_port } else { *next + 1 };
                return Ok(port);
            }
            *next = if *next >= self.max_port { self.min_port } else { *next + 1 };
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
            max_bytes_per_sec: 0,        // unlimited
            max_per_user: 100,           // 100 allocations per user
        }
    }
}

/// Main allocation store — thread-safe via DashMap.
pub struct AllocationStore {
    allocations: DashMap<SocketAddr, Allocation>,
    relay_to_client: DashMap<SocketAddr, SocketAddr>,
    channel_to_client: DashMap<(u16, u16), SocketAddr>,
    /// Username -> list of client addresses (for multi-allocation tracking).
    user_allocations: DashMap<String, Vec<SocketAddr>>,
    pub ports: PortAllocator,
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
}

impl AllocationStore {
    pub fn new(min_port: u16, max_port: u16, max_allocations: usize) -> Self {
        Self {
            allocations: DashMap::new(),
            relay_to_client: DashMap::new(),
            channel_to_client: DashMap::new(),
            user_allocations: DashMap::new(),
            ports: PortAllocator::new(min_port, max_port),
            max_allocations,
            quota: BandwidthQuota::default(),
            write_tx: OnceLock::new(),
            dropped_writes: AtomicU64::new(0),
        }
    }

    pub fn with_quota(mut self, quota: BandwidthQuota) -> Self {
        self.quota = quota;
        self
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
        let Some(tx) = self.write_tx.get() else { return; };
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

    pub fn create(
        &self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        key: Vec<u8>,
        lifetime: u32,
    ) -> Result<(), SessionError> {
        if self.allocations.len() >= self.max_allocations {
            return Err(SessionError::MaxAllocations);
        }

        // Check per-user limit
        if self.quota.max_per_user > 0 {
            let count = self.user_allocations
                .get(&username)
                .map(|v| v.len())
                .unwrap_or(0);
            if count >= self.quota.max_per_user {
                return Err(SessionError::MaxAllocationsPerUser);
            }
        }

        let now = Instant::now();
        let alloc = Allocation {
            client_addr,
            relay_addr,
            username: username.clone(),
            key,
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
            relay_port:    relay_addr.port(),
            client_addr,
            relay_addr,
            username:      username.clone(),
            created_at_ms: now_epoch,
            expires_at_ms: now_epoch + (lifetime as u64) * 1000,
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
    pub fn rehydrate(
        &self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        username: String,
        created_at_ms: u64,
        expires_at_ms: u64,
        permissions: impl IntoIterator<Item = (std::net::IpAddr, u64)>,
        channels:    impl IntoIterator<Item = (u16, SocketAddr, u64)>,
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
            let count = self.user_allocations.get(&username)
                .map(|v| v.len()).unwrap_or(0);
            if count >= self.quota.max_per_user {
                return Err(SessionError::MaxAllocationsPerUser);
            }
        }

        // Reserve the port. If it's already taken, somebody else (live
        // create()? a duplicate record?) got there first.
        self.ports.reserve(relay_addr.port())?;

        // Convert wall-clock epoch_ms back into a monotonic `Instant` by
        // anchoring against `Instant::now()`. We lose accuracy of the
        // original moment of creation, but `created_at` is only used for
        // observability — not correctness. `expires_at` is correctness-
        // critical and is reconstructed by adding the remaining lifetime.
        let now_inst   = Instant::now();
        let remaining  = Duration::from_millis(expires_at_ms - now_epoch);
        let age        = Duration::from_millis(now_epoch.saturating_sub(created_at_ms));
        let created_at = now_inst.checked_sub(age).unwrap_or(now_inst);
        let expires_at = now_inst + remaining;

        // Reconstruct permissions / channel bindings. We need them so
        // existing clients can continue using their established
        // permissions without re-issuing CreatePermission immediately.
        let mut perms_map: HashMap<std::net::IpAddr, Permission> = HashMap::new();
        for (peer_ip, perm_expires) in permissions {
            if perm_expires <= now_epoch { continue; }
            let perm_remaining = Duration::from_millis(perm_expires - now_epoch);
            perms_map.insert(peer_ip, Permission {
                _peer_ip:   peer_ip,
                expires_at: now_inst + perm_remaining,
            });
        }

        let mut chan_map: HashMap<u16, ChannelBinding> = HashMap::new();
        let mut chans_reverse: HashMap<SocketAddr, u16> = HashMap::new();
        for (number, peer_addr, chan_expires) in channels {
            if chan_expires <= now_epoch { continue; }
            let chan_remaining = Duration::from_millis(chan_expires - now_epoch);
            chan_map.insert(number, ChannelBinding {
                _channel:   number,
                peer_addr,
                expires_at: now_inst + chan_remaining,
            });
            chans_reverse.insert(peer_addr, number);
        }

        let alloc = Allocation {
            client_addr,
            relay_addr,
            username: username.clone(),
            // See doc comment above — recomputed on first auth.
            key: Vec::new(),
            permissions:      perms_map,
            channel_bindings: chan_map,
            channels_reverse: chans_reverse,
            expires_at,
            created_at,
            bytes_relayed:        AtomicU64::new(0),
            packets_relayed:      AtomicU64::new(0),
            bandwidth_window_bytes: AtomicU64::new(0),
            bandwidth_window_start: Mutex::new(now_inst),
        };

        // Reverse indices: relay→client, (relay_port, channel)→client.
        self.relay_to_client.insert(relay_addr, client_addr);
        for (&number, _) in alloc.channel_bindings.iter() {
            self.channel_to_client.insert((relay_addr.port(), number), client_addr);
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

    pub fn get(&self, client_addr: &SocketAddr) -> Option<dashmap::mapref::one::Ref<'_, SocketAddr, Allocation>> {
        self.allocations.get(client_addr)
    }

    pub fn get_mut(&self, client_addr: &SocketAddr) -> Option<dashmap::mapref::one::RefMut<'_, SocketAddr, Allocation>> {
        self.allocations.get_mut(client_addr)
    }

    pub fn get_by_relay(&self, relay_addr: &SocketAddr) -> Option<SocketAddr> {
        self.relay_to_client.get(relay_addr).map(|r| *r.value())
    }

    pub fn get_by_channel(&self, relay_port: u16, channel: u16) -> Option<SocketAddr> {
        self.channel_to_client.get(&(relay_port, channel)).map(|r| *r.value())
    }

    /// Add or refresh a permission (5 min lifetime per RFC).
    pub fn add_permission(&self, client_addr: &SocketAddr, peer_ip: std::net::IpAddr) -> Result<(), SessionError> {
        let relay_port = {
            let mut alloc = self.allocations.get_mut(client_addr).ok_or(SessionError::NotFound)?;
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
    pub fn add_channel(&self, client_addr: &SocketAddr, channel: u16, peer_addr: SocketAddr) -> Result<(), SessionError> {
        let mut alloc = self.allocations.get_mut(client_addr).ok_or(SessionError::NotFound)?;

        // Also add/refresh permission for this peer
        if let Some(perm) = alloc.permissions.get_mut(&peer_addr.ip()) {
            perm.refresh();
        } else {
            alloc.permissions.insert(peer_addr.ip(), Permission::new(peer_addr.ip()));
        }

        if let Some(binding) = alloc.channel_bindings.get_mut(&channel) {
            binding.refresh();
            tracing::debug!(%client_addr, channel, %peer_addr, "channel refreshed");
        } else {
            alloc.channel_bindings.insert(channel, ChannelBinding::new(channel, peer_addr));
            alloc.channels_reverse.insert(peer_addr, channel);
            tracing::debug!(%client_addr, channel, %peer_addr, "channel bound");
        }

        let relay_port = alloc.relay_addr.port();
        drop(alloc);
        self.channel_to_client.insert((relay_port, channel), *client_addr);

        // Emit *two* events: ChannelBind implicitly refreshes a permission
        // (per RFC 8656 §11.2), and the persisted record tracks them
        // separately. Coalescing in the writer collapses both if needed.
        let now_epoch = epoch_ms();
        self.emit_write(WriteOp::Permission {
            relay_port,
            peer_ip:       peer_addr.ip(),
            expires_at_ms: now_epoch + PERMISSION_LIFETIME.as_millis() as u64,
        });
        self.emit_write(WriteOp::Channel {
            relay_port,
            number:        channel,
            peer_addr,
            expires_at_ms: now_epoch + CHANNEL_LIFETIME.as_millis() as u64,
        });
        Ok(())
    }

    /// Check bandwidth quota for an allocation. Returns Err if exceeded.
    pub fn check_bandwidth(&self, client_addr: &SocketAddr) -> Result<(), SessionError> {
        if self.quota.max_bytes_per_sec == 0 {
            return Ok(()); // No limit
        }
        let alloc = self.allocations.get(client_addr).ok_or(SessionError::NotFound)?;
        match alloc.check_bandwidth(self.quota.max_bytes_per_sec) {
            Ok(_) => Ok(()),
            Err(()) => {
                let username = alloc.username.clone();
                Err(SessionError::BandwidthExceeded(username))
            }
        }
    }

    pub fn refresh(&self, client_addr: &SocketAddr, lifetime: u32) -> Result<(), SessionError> {
        let (relay_port, expires_at_ms) = {
            let mut alloc = self.allocations.get_mut(client_addr).ok_or(SessionError::NotFound)?;
            if lifetime == 0 {
                let relay_addr = alloc.relay_addr;
                drop(alloc);
                // remove() emits its own WriteOp::Remove, no event here.
                return self.remove(client_addr, relay_addr);
            }
            alloc.expires_at = Instant::now() + Duration::from_secs(lifetime as u64);
            (alloc.relay_addr.port(),
             epoch_ms() + (lifetime as u64) * 1000)
        };

        self.emit_write(WriteOp::Refresh { relay_port, expires_at_ms });
        Ok(())
    }

    pub fn remove(&self, client_addr: &SocketAddr, relay_addr: SocketAddr) -> Result<(), SessionError> {
        if let Some((_, alloc)) = self.allocations.remove(client_addr) {
            for (&ch, _) in &alloc.channel_bindings {
                self.channel_to_client.remove(&(relay_addr.port(), ch));
            }
            self.relay_to_client.remove(&relay_addr);
            self.ports.release(relay_addr.port());

            // Remove from user tracking
            if let Some(mut addrs) = self.user_allocations.get_mut(&alloc.username) {
                addrs.retain(|a| a != client_addr);
            }

            // Emit only when we actually removed something — a no-op
            // `remove()` shouldn't generate a backend round-trip.
            self.emit_write(WriteOp::Remove { relay_port: relay_addr.port() });

            tracing::info!(%client_addr, %relay_addr, username = %alloc.username, "allocation removed");
        }
        Ok(())
    }

    /// Cleanup expired allocations, permissions, and channel bindings.
    pub fn cleanup_expired(&self) -> usize {
        // Clean expired permissions/channels inside live allocations
        for mut entry in self.allocations.iter_mut() {
            entry.value_mut().cleanup_expired_entries();
        }

        // Remove fully expired allocations
        let expired: Vec<(SocketAddr, SocketAddr)> = self.allocations.iter()
            .filter(|r| r.value().is_expired())
            .map(|r| (*r.key(), r.value().relay_addr))
            .collect();

        let count = expired.len();
        for (client, relay) in expired {
            let _ = self.remove(&client, relay);
        }

        // Clean empty user entries
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
            self.relay_to_client.remove(&alloc.relay_addr);
            for (&ch, _) in &alloc.channel_bindings {
                self.channel_to_client.remove(&(alloc.relay_addr.port(), ch));
            }
            let relay_port = alloc.relay_addr.port();
            self.ports.release(relay_port);
            if let Some(mut user_allocs) = self.user_allocations.get_mut(&alloc.username) {
                user_allocs.retain(|a| a != client_addr);
            }
            self.emit_write(WriteOp::Remove { relay_port });
        }
    }

    pub fn allocated_port_count(&self) -> usize { self.ports.used.lock().len() }

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
        store.create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .expect("create succeeded");
        store.refresh(&client(1000), 600).expect("refresh succeeded");
        store.add_permission(&client(1000), "1.2.3.4".parse().unwrap())
            .expect("add_permission succeeded");
        store.remove(&client(1000), relay(40000)).expect("remove succeeded");
        assert_eq!(store.len(), 0);
    }

    /// With writer attached, `create` must emit exactly one `WriteOp::Create`.
    #[tokio::test]
    async fn create_emits_one_event() {
        let store = make_store();
        let (tx, mut rx) = mpsc::channel(64);
        store.attach_writer(tx);

        store.create(client(1000), relay(40000), "alice".into(), vec![], 600)
            .expect("create");

        match rx.try_recv() {
            Ok(WriteOp::Create { relay_port, username, .. }) => {
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
        store.add_permission(&c, "1.2.3.4".parse().unwrap()).unwrap();
        store.add_channel(&c, 0x4000, peer).unwrap();
        store.remove(&c, r).unwrap();

        fn name(op: &WriteOp) -> &'static str {
            match op {
                WriteOp::Create     { .. } => "Create",
                WriteOp::Refresh    { .. } => "Refresh",
                WriteOp::Remove     { .. } => "Remove",
                WriteOp::Permission { .. } => "Permission",
                WriteOp::Channel    { .. } => "Channel",
            }
        }

        let mut seen = Vec::new();
        while let Ok(op) = rx.try_recv() {
            seen.push(name(&op));
        }
        // add_channel emits Permission then Channel — that's why
        // Permission appears twice (once standalone, once implicit).
        let expected = ["Create", "Refresh", "Permission", "Permission", "Channel", "Remove"];
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

        store.create(client(1003), relay(40003), "dave".into(), vec![], 600).unwrap();

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
        store.create(client(1004), relay(40004), "eve".into(), vec![], 600).unwrap();
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
            store.create(client(2000 + i), relay(40000 + i),
                         "x".into(), vec![], 600).unwrap();
        }

        // 10 emits, capacity 1 → at least 9 must have been dropped.
        // (We can't pin the exact number because the channel might have
        //  buffered one before the receiver fell behind.)
        assert!(store.dropped_writes_count() >= 9,
                "expected >= 9 dropped, got {}", store.dropped_writes_count());
    }

    // -----------------------------------------------------------------
    // PR3 — rehydrate
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn rehydrate_basic_round_trip() {
        let store = make_store();
        let now = epoch_ms();

        let ok = store.rehydrate(
            client(3000), relay(40050),
            "alice".into(),
            now.saturating_sub(10_000),
            now + 600_000,
            std::iter::empty(),
            std::iter::empty(),
        ).unwrap();
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

        store.rehydrate(
            client(3001), relay(40051),
            "bob".into(),
            epoch_ms().saturating_sub(10_000),
            epoch_ms() + 600_000,
            std::iter::empty(),
            std::iter::empty(),
        ).unwrap();

        assert!(rx.try_recv().is_err(),
                "rehydrate must not emit any WriteOp event");
    }

    /// Expired record → Ok(false), no state change, port not reserved.
    #[tokio::test]
    async fn rehydrate_expired_returns_false() {
        let store = make_store();
        let now = epoch_ms();
        let ok = store.rehydrate(
            client(3002), relay(40052),
            "carol".into(),
            now.saturating_sub(120_000),
            now.saturating_sub(60_000), // already expired
            std::iter::empty(), std::iter::empty(),
        ).unwrap();
        assert!(!ok, "expired record should be skipped");
        assert_eq!(store.len(), 0);
        // Port must remain free — a subsequent create() should be able to
        // claim it via the normal allocator (we don't pin the exact port
        // returned by allocate(), so just confirm no conflict).
        assert!(store.ports.reserve(40052).is_ok(),
                "expired rehydrate must not have reserved the port");
    }

    /// Rehydrating the same port twice fails on the second attempt
    /// (port already reserved). First call's state is intact.
    #[tokio::test]
    async fn rehydrate_double_port_conflict() {
        let store = make_store();
        let now = epoch_ms();
        store.rehydrate(
            client(3003), relay(40053), "dave".into(),
            now.saturating_sub(10_000), now + 600_000,
            std::iter::empty(), std::iter::empty(),
        ).unwrap();

        let err = store.rehydrate(
            client(3004), relay(40053), "eve".into(),
            now.saturating_sub(10_000), now + 600_000,
            std::iter::empty(), std::iter::empty(),
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
        let peer_ok:  std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let peer_old: std::net::IpAddr = "10.0.0.6".parse().unwrap();
        let chan_peer = SocketAddr::new("10.0.0.5".parse().unwrap(), 9000);

        let ok = store.rehydrate(
            client(3005), relay(40054), "frank".into(),
            now.saturating_sub(10_000), now + 600_000,
            // peer_ok has fresh expiry, peer_old already expired
            vec![(peer_ok, now + 60_000), (peer_old, now - 1)].into_iter(),
            vec![
                (0x4000, chan_peer, now + 60_000), // fresh channel
                (0x4001, chan_peer, now - 1),      // expired channel
            ].into_iter(),
        ).unwrap();
        assert!(ok);

        // Channel 0x4000 must be reachable, 0x4001 must not.
        assert!(store.get_by_channel(40054, 0x4000).is_some(),
                "fresh channel should be present");
        assert!(store.get_by_channel(40054, 0x4001).is_none(),
                "expired channel must not be present");
    }
}