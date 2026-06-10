//! Pure packet processing logic — no I/O, no async.
//!
//! Takes raw bytes + source addr, returns a list of actions (send responses,
//! forward data). The caller handles actual I/O.
//! Integrates with Metrics for counters and draining support.
//!
//! # Zero-copy strategy
//!
//! `process()` takes ownership of `Bytes` (an Arc-backed byte slice).
//! For ChannelData — the hot path — the returned `Action::Forward` carries
//! a `Bytes::slice()` of the original buffer: pointer arithmetic only,
//! no heap allocation.
//!
//! STUN responses (auth challenges, errors, binding) are built fresh and are
//! small (~100-500 bytes); one allocation per STUN handshake is acceptable.

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use turna_auth::AuthRegistry;
use turna_cluster::HashRing;
use turna_health::Metrics;
use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::{self, StunMessage};
use turna_proto_stun::method::Method;
use turna_proto_turn as turn;
use turna_qos::{TieredLimits, TieredRateLimiter};
use turna_rtp_analyzer::RtpAnalyzer;
use turna_session::AllocationStore;
use turna_transport::migration::MigrationManager;

use crate::peer_filter::{is_forbidden_peer, normalize_addr, normalize_ip};

/// Action to take after processing a packet.
///
/// All data-carrying variants use `Bytes` — cloning is an atomic refcount
/// increment with no heap allocation.
pub enum Action {
    /// Send a response via the main TURN socket.
    /// Used for STUN responses — data is small, built fresh.
    Send { data: Bytes, target: SocketAddr },

    /// Forward a payload via a relay socket.
    ///
    /// Replaces the old `ZeroCopyForward { offset, len }` pair.
    /// `data` is a `Bytes::slice()` of the original recv buffer —
    /// literally just a pointer + length, no copy.
    Forward {
        data: Bytes,
        target: SocketAddr,
        relay_port: u16,
    },

    /// Send via a relay socket (Send Indication path).
    SendViaRelay {
        data: Bytes,
        target: SocketAddr,
        relay_port: u16,
    },

    /// Register an already-bound relay socket for this port. The socket is
    /// bound synchronously in `handle_allocate` *before* the Allocate
    /// success is emitted, so registration cannot fail (transactional).
    RegisterRelay {
        port: u16,
        socket: std::net::UdpSocket,
        client_addr: SocketAddr,
        /// RFC 8016 sharded ownership: the owning allocation id, threaded to
        /// the io_uring worker so it registers the relay route on bind.
        allocation_id: String,
    },

    /// Close and unregister the relay socket for this port (on release), so
    /// its fd is freed and the port can be safely reused.
    CloseRelay { port: u16 },

    /// No action needed.
    None,
}

// ── Nonce manager ────────────────────────────────────────────────────────────

struct NonceManager {
    current: RwLock<String>,
    previous: RwLock<Option<String>>,
    start: Instant,
    /// Elapsed-ms (from `start`) at the last rotation. Atomic so the common
    /// "not due yet" path takes no lock at all.
    last_rotation_ms: AtomicU64,
    /// Elapsed-ms when `previous` was last set — bounds the grace window.
    rotation_time_ms: AtomicU64,
    rotation_interval: Duration,
    grace_period: Duration,
}

impl NonceManager {
    fn new() -> Self {
        Self {
            current: RwLock::new(turna_crypto::generate_nonce()),
            previous: RwLock::new(None),
            start: Instant::now(),
            last_rotation_ms: AtomicU64::new(0),
            rotation_time_ms: AtomicU64::new(0),
            rotation_interval: Duration::from_secs(600),
            grace_period: Duration::from_secs(30),
        }
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn current(&self) -> String {
        self.maybe_rotate();
        self.current.read().clone()
    }

    fn validate(&self, nonce: &str) -> NonceStatus {
        self.maybe_rotate();
        if nonce == self.current.read().as_str() {
            return NonceStatus::Valid;
        }
        if let Some(prev) = self.previous.read().as_ref() {
            if nonce == prev.as_str() {
                let rot = self.rotation_time_ms.load(Ordering::Acquire);
                if self.now_ms().saturating_sub(rot) < self.grace_period.as_millis() as u64 {
                    return NonceStatus::Valid;
                }
            }
        }
        NonceStatus::Stale
    }

    fn maybe_rotate(&self) {
        let now = self.now_ms();
        let last = self.last_rotation_ms.load(Ordering::Acquire);
        // Common path: not due — no lock, no write.
        if now.saturating_sub(last) < self.rotation_interval.as_millis() as u64 {
            return;
        }
        // Exactly one caller wins the CAS and performs the rotation; the rest
        // see the updated timestamp and skip. Exclusive locks are taken only
        // here (≈ once per rotation_interval), not per request.
        if self
            .last_rotation_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let old = self.current.read().clone();
            *self.previous.write() = Some(old);
            *self.current.write() = turna_crypto::generate_nonce();
            self.rotation_time_ms.store(now, Ordering::Release);
            debug!("nonce rotated");
        }
    }
}

enum NonceStatus {
    Valid,
    Stale,
}

// ── PacketProcessor ──────────────────────────────────────────────────────────

/// Shared cluster-routing state used to redirect new clients to their owner node.
#[derive(Clone)]
pub struct ClusterRouting {
    pub local_node_id: String,
    pub hash_ring: Arc<RwLock<HashRing>>,
    /// Lame-duck flag: while set, new clients are redirected to another node
    /// even ones this node would normally own, so it can drain before exit.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
}

impl ClusterRouting {
    pub fn new(local_node_id: String, hash_ring: Arc<RwLock<HashRing>>) -> Self {
        Self {
            local_node_id,
            hash_ring,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Enter lame-duck mode: stop taking new clients (existing stay put).
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Current live cluster membership (for `turnactl`/management surfaces).
    pub fn members(&self) -> Vec<turna_cluster::ClusterNode> {
        self.hash_ring.read().snapshot()
    }
}

/// Pure packet processor — shared between async (tokio) and io_uring modes.
pub struct PacketProcessor {
    store: Arc<AllocationStore>,
    auth: Arc<AuthRegistry>,
    rate_limiter: TieredRateLimiter,
    external_ip: std::net::IpAddr,
    nonce_mgr: NonceManager,
    metrics: Arc<Metrics>,
    rtp_analyzer: Arc<RtpAnalyzer>,
    mtu: u16,
    cluster: Option<ClusterRouting>,
    /// RFC 8016 Connection Migration. `None` = feature disabled (the default);
    /// `Some` holds the ticket signer/verifier. Only `&self` methods are used,
    /// so no interior mutability is needed.
    migration: Option<MigrationManager>,
}

impl PacketProcessor {
    pub fn new(
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::with_mtu(store, auth, external_ip, metrics, 1280)
    }

    pub fn new_with_cluster(
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
        cluster: Option<ClusterRouting>,
    ) -> Self {
        Self::with_mtu_and_cluster(store, auth, external_ip, metrics, 1280, cluster)
    }

    pub fn with_mtu(
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
        mtu: u16,
    ) -> Self {
        Self::with_mtu_and_cluster(store, auth, external_ip, metrics, mtu, None)
    }

    pub fn with_mtu_and_cluster(
        store: Arc<AllocationStore>,
        auth: Arc<AuthRegistry>,
        external_ip: std::net::IpAddr,
        metrics: Arc<Metrics>,
        mtu: u16,
        cluster: Option<ClusterRouting>,
    ) -> Self {
        Self {
            store,
            auth,
            rate_limiter: {
                let mut limits = TieredLimits::default();
                let env_pair = |bkey: &str, rkey: &str, pair: &mut (u32, u32)| {
                    if let Some(b) = std::env::var(bkey).ok().and_then(|v| v.parse().ok()) {
                        pair.0 = b;
                    }
                    if let Some(r) = std::env::var(rkey).ok().and_then(|v| v.parse().ok()) {
                        pair.1 = r;
                    }
                };
                env_pair(
                    "TURNA_RATE_LIMIT_BURST",
                    "TURNA_RATE_LIMIT_RPS",
                    &mut limits.per_ip,
                );
                env_pair(
                    "TURNA_PREFIX_BURST",
                    "TURNA_PREFIX_RPS",
                    &mut limits.per_prefix,
                );
                env_pair(
                    "TURNA_ALLOCATE_BURST",
                    "TURNA_ALLOCATE_RPS",
                    &mut limits.allocate,
                );
                env_pair(
                    "TURNA_CREATE_PERM_BURST",
                    "TURNA_CREATE_PERM_RPS",
                    &mut limits.create_permission,
                );
                env_pair(
                    "TURNA_CHANNEL_BIND_BURST",
                    "TURNA_CHANNEL_BIND_RPS",
                    &mut limits.channel_bind,
                );
                TieredRateLimiter::new(limits)
            },
            external_ip,
            nonce_mgr: NonceManager::new(),
            metrics,
            rtp_analyzer: Arc::new(RtpAnalyzer::new()),
            mtu,
            cluster,
            migration: None,
        }
    }

    pub fn store(&self) -> &Arc<AllocationStore> {
        &self.store
    }

    /// Attach an RFC 8016 migration ticket signer/verifier. Builder-style so
    /// existing constructor call sites are untouched; `services/node` calls
    /// this when `turn.migration.enabled`.
    pub fn with_migration(mut self, migration: Option<MigrationManager>) -> Self {
        self.migration = migration;
        self
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }
    pub fn rtp_analyzer(&self) -> &Arc<RtpAnalyzer> {
        &self.rtp_analyzer
    }

    // ── Main entry point ─────────────────────────────────────────────────────

    /// Process a raw incoming packet.
    ///
    /// Takes **ownership** of `raw: Bytes` so that downstream `Action::Forward`
    /// can carry a zero-copy slice (`raw.slice(offset..end)`) without any
    /// memcpy.
    ///
    /// For the tokio path, obtain `raw` by:
    /// ```ignore
    /// let mut buf = pool.acquire();
    /// unsafe { buf.set_len(MAX_UDP_PACKET); }
    /// let (n, src) = socket.recv_from(&mut buf).await?;
    /// buf.truncate(n);
    /// let raw: Bytes = buf.freeze();      // one allocation, zero-copy after
    /// let actions = processor.process(raw, src);
    /// ```
    pub fn process(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        self.metrics
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(raw.len() as u64, Ordering::Relaxed);

        // Cheap stateless protocol classification BEFORE rate limiting.
        //
        // Garbage traffic must not touch the limiter/state/auth path: under
        // UDP floods that turns malformed packets into lock/map pressure and
        // hides the benefit of the socket BPF filter.  Keep this check limited
        // to fixed header bytes and length fields.
        let is_channel = message::is_channel_data(&raw);
        let is_stun = message::is_stun_message(&raw);

        if !is_channel && !is_stun {
            self.metrics
                .malformed_packets
                .fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        if !self.rate_limiter.check_ingress(src.ip()) {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        if is_channel {
            let t0 = std::time::Instant::now();
            let actions = self.process_channel_data(raw, src);
            self.metrics
                .histograms
                .observe("turna_relay_forward_duration_seconds", t0.elapsed());
            return actions;
        }
        let t0 = std::time::Instant::now();
        let actions = self.process_stun(raw, src);
        self.metrics
            .histograms
            .observe("turna_stun_request_duration_seconds", t0.elapsed());
        actions
    }

    /// Compatibility shim for the io_uring handler which provides `&[u8]`.
    ///
    /// Copies once into `Bytes` then delegates to `process()`.
    /// The io_uring path achieves true zero-copy at a lower level
    /// (kernel-registered buffers + `ZeroCopyViaRelay`), so this
    /// extra copy does not appear on the hot path there.
    #[inline]
    pub fn process_slice(&self, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        self.process(Bytes::copy_from_slice(raw), src)
    }

    // ── Relay recv (peer → client) ────────────────────────────────────────────

    /// Process data received on a relay socket (peer → client direction).
    ///
    /// `data` comes from a separate socket recv buffer; one copy into the
    /// ChannelData frame header is unavoidable here, but this is not the
    /// hot path (most bidirectional media uses ChannelData client→server).
    pub fn process_relay_recv(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        relay_addr: SocketAddr,
    ) -> Vec<Action> {
        // Normalize so ::ffff: peers match the permission stored as v4 (C3).
        let peer_addr = normalize_addr(peer_addr);

        let Some(client_addr) = self.store.get_by_relay(&relay_addr) else {
            return vec![Action::None];
        };

        let alloc = match self.store.get(&client_addr) {
            Some(a) => a,
            None => return vec![Action::None],
        };

        if !alloc.has_permission(&peer_addr) {
            drop(alloc);
            return vec![Action::None];
        }

        alloc.add_bytes(data.len() as u64);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.rtp_analyzer.analyze(data, peer_addr);

        // Prefer ChannelData if a channel is bound.
        if let Some(channel) = alloc.get_peer_channel(&peer_addr) {
            let ch = channel;
            let ca = alloc.client_addr;
            drop(alloc);

            // Build ChannelData frame: 4-byte header + payload (one copy).
            let frame_len = (4 + data.len() + 3) & !3; // include 4-byte padding
            let mut buf = BytesMut::with_capacity(frame_len);
            buf.resize(frame_len, 0);
            let written = message::encode_channel_data(&mut buf, ch, data);
            buf.truncate(written);

            return vec![Action::Send {
                data: buf.freeze(),
                target: ca,
            }];
        }

        // Fallback: Data Indication.
        let ca = alloc.client_addr;
        drop(alloc);

        let mut ind =
            StunMessage::with_transaction_id(Method::Data, MessageClass::Indication, [0; 12]);
        ind.add(Attribute::XorPeerAddress(peer_addr));
        ind.add(Attribute::Data(data.to_vec()));

        let mut buf = [0u8; 4096];
        let len = ind.encode(&mut buf);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: ca,
        }]
    }

    // ── ChannelData (hot path) ────────────────────────────────────────────────

    fn process_channel_data(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        let Ok((channel, data_slice)) = message::decode_channel_data(&raw) else {
            return vec![Action::None];
        };

        let alloc = match self.store.get(&src) {
            Some(a) => a,
            None => return vec![Action::None],
        };

        let Some(peer_addr) = alloc.get_channel_peer(channel).copied() else {
            return vec![Action::None];
        };

        let bw_limit = self.store.bandwidth_limit_for(alloc.tenant_id.as_deref());
        if bw_limit > 0 {
            if alloc.check_bandwidth(bw_limit).is_err() {
                debug!(%src, "bandwidth quota exceeded, dropping packet");
                self.metrics.quota_exceeded.fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }
        }

        alloc.add_bytes(data_slice.len() as u64);
        self.metrics
            .zero_copy_forwards
            .fetch_add(1, Ordering::Relaxed);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(data_slice.len() as u64, Ordering::Relaxed);
        let relay_port = alloc.relay_addr.port();
        drop(alloc);

        self.rtp_analyzer.analyze(data_slice, src);

        // Zero-copy slice: pointer arithmetic + AtomicAdd, no memcpy.
        //
        // data_slice is &[u8] pointing into `raw` (guaranteed by decode_channel_data).
        // We compute the byte offset and use Bytes::slice() which only adjusts
        // the start pointer and length — no allocation, no copy.
        let offset = data_slice.as_ptr() as usize - raw.as_ptr() as usize;
        let data = raw.slice(offset..offset + data_slice.len());

        vec![Action::Forward {
            data,
            target: peer_addr,
            relay_port,
        }]
    }

    // ── STUN dispatch ─────────────────────────────────────────────────────────

    /// Validate credentials via the registry, recording observability as a
    /// side effect: auth-processing latency into the `turna_auth_duration_seconds`
    /// histogram, and on failure a reason-coded counter keyed by the
    /// `AuthError` variant. The per-reason counters are a breakdown *under* the
    /// total `auth_failures`, which the call sites still bump — so the totals
    /// stay consistent and behaviour is unchanged.
    fn auth_validate(
        &self,
        msg: &StunMessage,
        raw: &[u8],
    ) -> Result<turna_auth::AuthResolution, turna_auth::AuthError> {
        let started = std::time::Instant::now();
        let r = self.auth.validate(msg, raw);
        self.metrics
            .histograms
            .observe("turna_auth_duration_seconds", started.elapsed());
        if let Err(e) = &r {
            let counter = match e {
                turna_auth::AuthError::MissingCredentials => {
                    &self.metrics.auth_fail_missing_credentials
                }
                turna_auth::AuthError::InvalidCredentials => {
                    &self.metrics.auth_fail_invalid_credentials
                }
                turna_auth::AuthError::Expired => &self.metrics.auth_fail_expired,
                turna_auth::AuthError::IntegrityFailed => &self.metrics.auth_fail_integrity,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    fn process_stun(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        let msg = match StunMessage::decode(&raw) {
            Ok(m) => m,
            Err(e) => {
                warn!(%src, %e, "STUN decode error");
                self.metrics
                    .parser_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }
        };

        if matches!(msg.class, MessageClass::Request) {
            if let Some(actions) = self.maybe_redirect_new_client(&msg, src) {
                return actions;
            }
        }

        match (&msg.class, &msg.method) {
            (MessageClass::Request, Method::Binding) => self.handle_binding(&msg, &raw, src),
            (MessageClass::Request, Method::Allocate) => {
                if !self.rate_limiter.check_allocate(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(&msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_allocate(&msg, &raw, src)
            }
            (MessageClass::Request, Method::Refresh) => self.handle_refresh(&msg, &raw, src),
            (MessageClass::Request, Method::CreatePermission) => {
                if !self.rate_limiter.check_create_permission(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(&msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_create_permission(&msg, &raw, src)
            }
            (MessageClass::Request, Method::ChannelBind) => {
                if !self.rate_limiter.check_channel_bind(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(&msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_channel_bind(&msg, &raw, src)
            }
            (MessageClass::Indication, Method::Send) => {
                self.handle_send_indication(&msg, &raw, src)
            }
            _ => vec![Action::None],
        }
    }

    fn maybe_redirect_new_client(&self, msg: &StunMessage, src: SocketAddr) -> Option<Vec<Action>> {
        let routing = self.cluster.as_ref()?;

        // Existing local sessions stay local even if the ring changes.
        if self.store.get(&src).is_some() {
            return None;
        }

        let key = format!("{}:{}", src.ip(), src.port());
        let draining = routing.is_draining();
        let target = {
            let ring = routing.hash_ring.read();
            if draining {
                // Lame-duck: hand every new client to the next-best node so this
                // node can exit cleanly. If we're the only node, fall through to
                // serving locally (there is nowhere to drain to).
                ring.get_node_excluding(&key, &routing.local_node_id).cloned()
            } else {
                ring.get_node(&key).cloned()
            }
        }?;

        // When not draining and we own the key, serve locally. When draining,
        // `target` already excludes us, so we always redirect.
        if !draining && target.node_id == routing.local_node_id {
            return None;
        }

        debug!(
            %src,
            draining,
            local_node_id = %routing.local_node_id,
            target_node_id = %target.node_id,
            alternate = %target.turn_addr,
            "redirecting new TURN/STUN client to alternate cluster node"
        );
        Some(self.redirect_to(target.turn_addr, msg, src))
    }

    pub fn redirect_to(
        &self,
        alternate_addr: SocketAddr,
        msg: &StunMessage,
        src: SocketAddr,
    ) -> Vec<Action> {
        let resp =
            turn::build_redirect_response(msg.method, msg.transaction_id, alternate_addr, src);
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        self.metrics.cluster_redirects.fetch_add(1, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }]
    }

    // ── STUN handlers ─────────────────────────────────────────────────────────

    fn handle_binding(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        // RFC 5389 §10.1.2: if MESSAGE-INTEGRITY present, validate it over the
        // actual message bytes (not an empty buffer).
        let has_integrity = msg.attributes.iter().any(|a| {
            matches!(
                a,
                turna_proto_stun::attribute::Attribute::MessageIntegrity(_)
            )
        });
        if has_integrity {
            if self.auth_validate(msg, raw).is_err() {
                self.metrics
                    .auth_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        }

        let mut resp = StunMessage::with_transaction_id(
            Method::Binding,
            MessageClass::SuccessResponse,
            msg.transaction_id,
        );
        resp.add(Attribute::XorMappedAddress(src));
        resp.add(Attribute::Software("turna 0.1".into()));

        let mut buf = [0u8; 256];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }]
    }

    fn handle_allocate(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if self.metrics.is_draining() {
            return self.encode_error(msg, src, 508, "Server Draining");
        }
        if self.store.get(&src).is_some() {
            return self.encode_error(msg, src, 437, "Allocation Mismatch");
        }
        if msg.get_requested_transport() != Some(turn::TRANSPORT_UDP) {
            return self.encode_error(msg, src, 442, "Unsupported Transport Protocol");
        }
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }

        let resolution = match self.auth_validate(msg, raw) {
            Ok(r) => r,
            Err(e) => {
                warn!(%src, %e, "auth failed");
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };
        // Tenant identity is the result of auth resolution — derived ONLY from
        // the authenticated realm (see turna_auth::AuthRegistry). Network/listener
        // hints never enter here.
        let key = resolution.key;
        let tenant_id = resolution.tenant_id;

        // Allocate the relay port from the *resolved tenant's* isolated pool.
        let (relay_port, relay_sock) = match self
            .store
            .pool(tenant_id.as_deref())
            .allocate_and_bind()
        {
            Some(x) => x,
            None => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
        };

        let relay_addr = SocketAddr::new(self.external_ip, relay_port);
        let lifetime = msg
            .get_lifetime()
            .unwrap_or(turn::DEFAULT_LIFETIME)
            .min(turn::MAX_LIFETIME);
        let username = msg.get_username().unwrap_or("").to_string();

        if let Err(_) = self.store.create_for_tenant(
            src,
            relay_addr,
            username,
            key.clone(),
            lifetime,
            tenant_id.clone(),
        ) {
            self.store.pool_for_port(relay_port).release(relay_port);
            // relay_sock dropped here → socket closed, port freed.
            return self.encode_error(msg, src, 508, "Insufficient Capacity");
        }

        self.metrics
            .active_allocations
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .total_allocations
            .fetch_add(1, Ordering::Relaxed);
        // Per-tenant observability (multi-tenancy). Base tenant (None) is not
        // labelled — it is already covered by turna_total_allocations.
        if let Some(t) = tenant_id.as_deref() {
            self.metrics.record_tenant_allocation(t);
        }

        let mut resp = turn::build_allocate_response(msg.transaction_id, relay_addr, src, lifetime);
        // RFC 8016: if migration is enabled and the client opted in by sending a
        // MOBILITY-TICKET (typically zero-length) in the request, issue one bound
        // to this allocation's id + epoch. Added BEFORE encode_with_integrity so
        // MESSAGE-INTEGRITY covers the ticket.
        if let Some(mgr) = &self.migration {
            if msg.has_mobility_ticket() {
                if let Some(a) = self.store.get(&src) {
                    let token = mgr.issue_token(&a.allocation_id, a.migration_epoch);
                    drop(a);
                    resp.add(Attribute::MobilityTicket(token.token));
                }
            }
        }
        let mut buf = [0u8; 1024];
        let len = resp.encode_with_integrity(&mut buf, &key);
        info!(%src, %relay_addr, lifetime, "allocation created");
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);

        // RFC 8016: stamp the relay route with the owning allocation id so the
        // io_uring worker pool can forward relay sends to this owner after a
        // client migration reshards onto another worker.
        let allocation_id = self
            .store
            .get(&src)
            .map(|a| a.allocation_id.clone())
            .unwrap_or_default();

        vec![
            Action::RegisterRelay {
                port: relay_port,
                socket: relay_sock,
                client_addr: src,
                allocation_id,
            },
            Action::Send {
                data: Bytes::copy_from_slice(&buf[..len]),
                target: src,
            },
        ]
    }

    fn handle_refresh(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }
        let key = match self.auth_validate(msg, raw) {
            Ok(r) => r.key,
            Err(_) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };

        let lifetime = msg
            .get_lifetime()
            .unwrap_or(turn::DEFAULT_LIFETIME)
            .min(turn::MAX_LIFETIME);

        // RFC 8016 Connection Migration: a Refresh arriving from an address with
        // no allocation may be a migrating client presenting a MOBILITY-TICKET
        // minted for an allocation that currently lives on its OLD address.
        // MESSAGE-INTEGRITY was already verified above (the client proved its
        // long-term credentials), so the ticket only needs to prove *which*
        // allocation and that it isn't a replay (epoch).
        if self.store.get(&src).is_none() {
            if let Some(actions) = self.try_migration_refresh(msg, src, &key, lifetime) {
                return actions;
            }
            // Not a (valid) migration attempt → fall through; the refresh below
            // will 437 on the unknown source as before.
        }

        // Capture the relay port before refresh, so a release (lifetime 0)
        // can tell the server to close the relay socket.
        let relay_port = self.store.get(&src).map(|a| a.relay_addr.port());
        match self.store.refresh(&src, lifetime) {
            Ok(_) => {
                let mut resp = turn::build_success_response(Method::Refresh, msg.transaction_id);
                resp.add(Attribute::Lifetime(lifetime));
                let mut buf = [0u8; 1024];
                let len = resp.encode_with_integrity(&mut buf, &key);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                let mut actions = vec![Action::Send {
                    data: Bytes::copy_from_slice(&buf[..len]),
                    target: src,
                }];
                if lifetime == 0 {
                    self.metrics
                        .active_allocations
                        .fetch_sub(1, Ordering::Relaxed);
                    if let Some(port) = relay_port {
                        actions.push(Action::CloseRelay { port });
                    }
                }
                actions
            }
            Err(_) => self.encode_error(msg, src, 437, "Allocation Mismatch"),
        }
    }

    /// RFC 8016 migration on the Refresh path. Returns:
    /// - `Some(actions)` — this was a mobility attempt (success **or** a
    ///   definitive reject), so the caller must not fall through.
    /// - `None` — not a migration attempt (no/empty ticket, or feature off);
    ///   the caller proceeds with the normal Refresh handling.
    ///
    /// `key` is the long-term key already validated against MESSAGE-INTEGRITY
    /// by the caller, so a successful migration required BOTH a valid ticket
    /// and valid credentials.
    fn try_migration_refresh(
        &self,
        msg: &StunMessage,
        src: SocketAddr,
        key: &[u8],
        lifetime: u32,
    ) -> Option<Vec<Action>> {
        let mgr = self.migration.as_ref()?;
        let ticket = msg.get_mobility_ticket()?;
        if ticket.is_empty() {
            // A zero-length ticket is the Allocate opt-in marker, never a valid
            // Refresh ticket — not a migration.
            return None;
        }

        // Validate signature + TTL → (allocation_id, epoch).
        let (alloc_id, epoch) = match mgr.verify_ticket(ticket) {
            Some(v) => v,
            None => return Some(self.encode_error(msg, src, 437, "Allocation Mismatch")),
        };
        let old_addr = match self.store.get_by_id(&alloc_id) {
            Some(a) => a,
            None => return Some(self.encode_error(msg, src, 437, "Allocation Mismatch")),
        };
        // Anti-replay: the ticket's epoch must equal the allocation's current
        // epoch. A re-keyed allocation has a bumped epoch, so a captured older
        // ticket no longer matches.
        if self.store.get(&old_addr).map(|a| a.migration_epoch) != Some(epoch) {
            return Some(self.encode_error(msg, src, 437, "Allocation Mismatch"));
        }

        // Re-key old → new (relay address preserved; epoch bumped inside).
        let relay_addr = match self.store.re_key(&old_addr, src) {
            Ok(r) => r,
            Err(_) => return Some(self.encode_error(msg, src, 437, "Allocation Mismatch")),
        };
        // Apply the requested lifetime to the migrated allocation.
        let _ = self.store.refresh(&src, lifetime);

        // Success response: LIFETIME + XOR-MAPPED-ADDRESS(new addr) + a fresh
        // ticket at the bumped epoch so the client can migrate again.
        let new_epoch = self
            .store
            .get(&src)
            .map(|a| a.migration_epoch)
            .unwrap_or(epoch.wrapping_add(1));
        let mut resp = turn::build_success_response(Method::Refresh, msg.transaction_id);
        resp.add(Attribute::Lifetime(lifetime));
        resp.add(Attribute::XorMappedAddress(src));
        let new_token = mgr.issue_token(&alloc_id, new_epoch);
        resp.add(Attribute::MobilityTicket(new_token.token));

        let mut buf = [0u8; 1024];
        let len = resp.encode_with_integrity(&mut buf, key);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        info!(%src, %old_addr, %relay_addr, "allocation migrated (RFC 8016)");

        Some(vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }])
    }

    fn handle_create_permission(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        src: SocketAddr,
    ) -> Vec<Action> {
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }
        let key = match self.auth_validate(msg, raw) {
            Ok(r) => r.key,
            Err(_) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };

        let Some(peer_addr) = msg.get_xor_peer_address() else {
            return self.encode_error(msg, src, 400, "Bad Request");
        };

        // Normalize ::ffff: → v4 and reject special-use peers (C2/C3).
        let peer_ip = normalize_ip(peer_addr.ip());
        if is_forbidden_peer(peer_ip) {
            warn!(%src, %peer_ip, "CreatePermission to forbidden peer denied");
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return self.encode_error(msg, src, 403, "Forbidden");
        }

        match self.store.add_permission(&src, peer_ip) {
            Ok(_) => {
                let resp =
                    turn::build_success_response(Method::CreatePermission, msg.transaction_id);
                let mut buf = [0u8; 1024];
                let len = resp.encode_with_integrity(&mut buf, &key);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                vec![Action::Send {
                    data: Bytes::copy_from_slice(&buf[..len]),
                    target: src,
                }]
            }
            Err(_) => self.encode_error(msg, src, 437, "Allocation Mismatch"),
        }
    }

    fn handle_channel_bind(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }
        let key = match self.auth_validate(msg, raw) {
            Ok(r) => r.key,
            Err(_) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };

        let Some(channel) = msg.get_channel_number() else {
            return self.encode_error(msg, src, 400, "Bad Request");
        };
        let Some(peer_addr) = msg.get_xor_peer_address() else {
            return self.encode_error(msg, src, 400, "Bad Request");
        };

        if !turn::is_valid_channel(channel) {
            return self.encode_error(msg, src, 400, "Bad Request: invalid channel");
        }

        // Normalize ::ffff: → v4 and reject special-use peers (C2/C3).
        let peer_addr = normalize_addr(peer_addr);
        if is_forbidden_peer(peer_addr.ip()) {
            warn!(%src, peer = %peer_addr.ip(), "ChannelBind to forbidden peer denied");
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return self.encode_error(msg, src, 403, "Forbidden");
        }

        match self.store.add_channel(&src, channel, peer_addr) {
            Ok(_) => {
                let resp = turn::build_success_response(Method::ChannelBind, msg.transaction_id);
                let mut buf = [0u8; 1024];
                let len = resp.encode_with_integrity(&mut buf, &key);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                vec![Action::Send {
                    data: Bytes::copy_from_slice(&buf[..len]),
                    target: src,
                }]
            }
            Err(_) => self.encode_error(msg, src, 437, "Allocation Mismatch"),
        }
    }

    fn handle_send_indication(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        src: SocketAddr,
    ) -> Vec<Action> {
        let Some(peer_addr) = msg.get_xor_peer_address() else {
            return vec![Action::None];
        };
        let Some(data) = msg.get_data() else {
            return vec![Action::None];
        };

        // Normalize ::ffff: → v4 and reject special-use peers (C2/C3).
        let peer_addr = normalize_addr(peer_addr);
        if is_forbidden_peer(peer_addr.ip()) {
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        // DONT-FRAGMENT: drop if payload exceeds MTU.
        let has_dont_fragment = msg
            .attributes
            .iter()
            .any(|a| matches!(a, turna_proto_stun::attribute::Attribute::DontFragment));
        if has_dont_fragment && data.len() > self.mtu as usize {
            debug!(%src, len = data.len(), mtu = self.mtu, "DONT-FRAGMENT: packet too large, dropping");
            return vec![Action::None];
        }

        let alloc = match self.store.get(&src) {
            Some(a) => a,
            None => return vec![Action::None],
        };

        if !alloc.has_permission(&peer_addr) {
            return vec![Action::None];
        }

        alloc.add_bytes(data.len() as u64);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        let relay_port = alloc.relay_addr.port();
        drop(alloc);

        // `raw` here is a &[u8] (not the owned Bytes), so one copy into an
        // owned Bytes is required. This is the Send-indication path, not the
        // hot path — bidirectional media uses ChannelData (process_channel_data),
        // which is genuinely zero-copy via Bytes::slice().
        let offset = data.as_ptr() as usize - raw.as_ptr() as usize;
        let data_bytes = Bytes::copy_from_slice(&raw[offset..offset + data.len()]);

        vec![Action::SendViaRelay {
            data: data_bytes,
            target: peer_addr,
            relay_port,
        }]
    }

    // ── Response builders ─────────────────────────────────────────────────────

    fn encode_error(
        &self,
        msg: &StunMessage,
        dst: SocketAddr,
        code: u16,
        reason: &str,
    ) -> Vec<Action> {
        let resp = turn::build_error_response(msg.method, msg.transaction_id, code, reason);
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: dst,
        }]
    }

    fn encode_auth_challenge(&self, msg: &StunMessage, dst: SocketAddr) -> Vec<Action> {
        let resp = turn::build_auth_challenge(
            msg.method,
            msg.transaction_id,
            self.auth.default_realm(),
            &self.nonce_mgr.current(),
        );
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: dst,
        }]
    }

    fn encode_stale_nonce(&self, msg: &StunMessage, dst: SocketAddr) -> Vec<Action> {
        let mut resp =
            turn::build_error_response(msg.method, msg.transaction_id, 438, "Stale Nonce");
        resp.add(Attribute::Realm(self.auth.default_realm().to_string()));
        resp.add(Attribute::Nonce(self.nonce_mgr.current()));
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: dst,
        }]
    }

    fn validate_nonce(&self, msg: &StunMessage, dst: SocketAddr) -> Option<Vec<Action>> {
        if let Some(nonce) = msg.get_nonce() {
            match self.nonce_mgr.validate(nonce) {
                NonceStatus::Valid => None,
                NonceStatus::Stale => Some(self.encode_stale_nonce(msg, dst)),
            }
        } else {
            // Fail closed: an authenticated request without a NONCE is
            // answered with a 401 challenge carrying REALM + a fresh NONCE,
            // rather than being allowed through on MESSAGE-INTEGRITY alone.
            Some(self.encode_auth_challenge(msg, dst))
        }
    }
}
