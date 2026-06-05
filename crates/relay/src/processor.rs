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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use bytes::{Bytes, BytesMut};
use tracing::{info, warn, debug};

use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::{self, StunMessage};
use turna_proto_stun::method::Method;
use turna_proto_turn as turn;
use turna_session::AllocationStore;
use turna_auth::AuthMode;
use turna_qos::{TieredRateLimiter, TieredLimits};
use turna_health::Metrics;
use turna_rtp_analyzer::RtpAnalyzer;

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
    Forward { data: Bytes, target: SocketAddr, relay_port: u16 },

    /// Send via a relay socket (Send Indication path).
    SendViaRelay { data: Bytes, target: SocketAddr, relay_port: u16 },

    /// Register an already-bound relay socket for this port. The socket is
    /// bound synchronously in `handle_allocate` *before* the Allocate
    /// success is emitted, so registration cannot fail (transactional).
    RegisterRelay { port: u16, socket: std::net::UdpSocket, client_addr: SocketAddr },

    /// Close and unregister the relay socket for this port (on release), so
    /// its fd is freed and the port can be safely reused.
    CloseRelay { port: u16 },

    /// No action needed.
    None,
}

// ── Nonce manager ────────────────────────────────────────────────────────────

struct NonceManager {
    current:           RwLock<String>,
    previous:          RwLock<Option<String>>,
    start:             Instant,
    /// Elapsed-ms (from `start`) at the last rotation. Atomic so the common
    /// "not due yet" path takes no lock at all.
    last_rotation_ms:  AtomicU64,
    /// Elapsed-ms when `previous` was last set — bounds the grace window.
    rotation_time_ms:  AtomicU64,
    rotation_interval: Duration,
    grace_period:      Duration,
}

impl NonceManager {
    fn new() -> Self {
        Self {
            current:           RwLock::new(turna_crypto::generate_nonce()),
            previous:          RwLock::new(None),
            start:             Instant::now(),
            last_rotation_ms:  AtomicU64::new(0),
            rotation_time_ms:  AtomicU64::new(0),
            rotation_interval: Duration::from_secs(600),
            grace_period:      Duration::from_secs(30),
        }
    }

    #[inline]
    fn now_ms(&self) -> u64 { self.start.elapsed().as_millis() as u64 }

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
        let now  = self.now_ms();
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

enum NonceStatus { Valid, Stale }

// ── PacketProcessor ──────────────────────────────────────────────────────────

/// Pure packet processor — shared between async (tokio) and io_uring modes.
pub struct PacketProcessor {
    store:        Arc<AllocationStore>,
    auth:         Arc<AuthMode>,
    rate_limiter: TieredRateLimiter,
    external_ip:  std::net::IpAddr,
    nonce_mgr:    NonceManager,
    metrics:      Arc<Metrics>,
    rtp_analyzer: Arc<RtpAnalyzer>,
    mtu:          u16,
}

impl PacketProcessor {
    pub fn new(
        store:       Arc<AllocationStore>,
        auth:        Arc<AuthMode>,
        external_ip: std::net::IpAddr,
        metrics:     Arc<Metrics>,
    ) -> Self {
        Self::with_mtu(store, auth, external_ip, metrics, 1280)
    }

    pub fn with_mtu(
        store:       Arc<AllocationStore>,
        auth:        Arc<AuthMode>,
        external_ip: std::net::IpAddr,
        metrics:     Arc<Metrics>,
        mtu:         u16,
    ) -> Self {
        Self {
            store, auth,
            rate_limiter: {
                let mut limits = TieredLimits::default();
                let env_pair = |bkey: &str, rkey: &str, pair: &mut (u32, u32)| {
                    if let Some(b) = std::env::var(bkey).ok().and_then(|v| v.parse().ok()) { pair.0 = b; }
                    if let Some(r) = std::env::var(rkey).ok().and_then(|v| v.parse().ok()) { pair.1 = r; }
                };
                env_pair("TURNA_RATE_LIMIT_BURST", "TURNA_RATE_LIMIT_RPS", &mut limits.per_ip);
                env_pair("TURNA_PREFIX_BURST", "TURNA_PREFIX_RPS", &mut limits.per_prefix);
                env_pair("TURNA_ALLOCATE_BURST", "TURNA_ALLOCATE_RPS", &mut limits.allocate);
                env_pair("TURNA_CREATE_PERM_BURST", "TURNA_CREATE_PERM_RPS", &mut limits.create_permission);
                env_pair("TURNA_CHANNEL_BIND_BURST", "TURNA_CHANNEL_BIND_RPS", &mut limits.channel_bind);
                TieredRateLimiter::new(limits)
            },
            external_ip,
            nonce_mgr:    NonceManager::new(),
            metrics,
            rtp_analyzer: Arc::new(RtpAnalyzer::new()),
            mtu,
        }
    }

    pub fn store(&self)        -> &Arc<AllocationStore> { &self.store }
    pub fn metrics(&self)      -> &Arc<Metrics>         { &self.metrics }
    pub fn rtp_analyzer(&self) -> &Arc<RtpAnalyzer>     { &self.rtp_analyzer }

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
        self.metrics.packets_received.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_received.fetch_add(raw.len() as u64, Ordering::Relaxed);

        // Cheap stateless protocol classification BEFORE rate limiting.
        //
        // Garbage traffic must not touch the limiter/state/auth path: under
        // UDP floods that turns malformed packets into lock/map pressure and
        // hides the benefit of the socket BPF filter.  Keep this check limited
        // to fixed header bytes and length fields.
        let is_channel = message::is_channel_data(&raw);
        let is_stun    = message::is_stun_message(&raw);

        if !is_channel && !is_stun {
            self.metrics.malformed_packets.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        if !self.rate_limiter.check_ingress(src.ip()) {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        if is_channel {
            return self.process_channel_data(raw, src);
        }
        self.process_stun(raw, src)
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
        data:       &[u8],
        peer_addr:  SocketAddr,
        relay_addr: SocketAddr,
    ) -> Vec<Action> {
        // Normalize so ::ffff: peers match the permission stored as v4 (C3).
        let peer_addr = normalize_addr(peer_addr);

        let Some(client_addr) = self.store.get_by_relay(&relay_addr) else {
            return vec![Action::None];
        };

        let alloc = match self.store.get(&client_addr) {
            Some(a) => a,
            None    => return vec![Action::None],
        };

        if !alloc.has_permission(&peer_addr) {
            drop(alloc);
            return vec![Action::None];
        }

        alloc.add_bytes(data.len() as u64);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
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

            return vec![Action::Send { data: buf.freeze(), target: ca }];
        }

        // Fallback: Data Indication.
        let ca = alloc.client_addr;
        drop(alloc);

        let mut ind = StunMessage::with_transaction_id(
            Method::Data, MessageClass::Indication, [0; 12],
        );
        ind.add(Attribute::XorPeerAddress(peer_addr));
        ind.add(Attribute::Data(data.to_vec()));

        let mut buf = [0u8; 4096];
        let len = ind.encode(&mut buf);
        vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: ca }]
    }

    // ── ChannelData (hot path) ────────────────────────────────────────────────

    fn process_channel_data(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        let Ok((channel, data_slice)) = message::decode_channel_data(&raw) else {
            return vec![Action::None];
        };

        let alloc = match self.store.get(&src) {
            Some(a) => a,
            None    => return vec![Action::None],
        };

        let Some(peer_addr) = alloc.get_channel_peer(channel).copied() else {
            return vec![Action::None];
        };

        if self.store.quota.max_bytes_per_sec > 0 {
            if alloc.check_bandwidth(self.store.quota.max_bytes_per_sec).is_err() {
                debug!(%src, "bandwidth quota exceeded, dropping packet");
                self.metrics.quota_exceeded.fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }
        }

        alloc.add_bytes(data_slice.len() as u64);
        self.metrics.zero_copy_forwards.fetch_add(1, Ordering::Relaxed);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(data_slice.len() as u64, Ordering::Relaxed);
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

        vec![Action::Forward { data, target: peer_addr, relay_port }]
    }

    // ── STUN dispatch ─────────────────────────────────────────────────────────

    fn process_stun(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        let msg = match StunMessage::decode(&raw) {
            Ok(m)  => m,
            Err(e) => { warn!(%src, %e, "STUN decode error"); self.metrics.parser_rejections.fetch_add(1, Ordering::Relaxed); return vec![Action::None]; }
        };

        match (&msg.class, &msg.method) {
            (MessageClass::Request, Method::Binding)          => self.handle_binding(&msg, &raw, src),
            (MessageClass::Request, Method::Allocate) => {
                if !self.rate_limiter.check_allocate(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(&msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_allocate(&msg, &raw, src)
            }
            (MessageClass::Request, Method::Refresh)          => self.handle_refresh(&msg, &raw, src),
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
            (MessageClass::Indication, Method::Send)          => self.handle_send_indication(&msg, &raw, src),
            _ => vec![Action::None],
        }
    }

    // ── STUN handlers ─────────────────────────────────────────────────────────

    fn handle_binding(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        // RFC 5389 §10.1.2: if MESSAGE-INTEGRITY present, validate it over the
        // actual message bytes (not an empty buffer).
        let has_integrity = msg.attributes.iter().any(|a| {
            matches!(a, turna_proto_stun::attribute::Attribute::MessageIntegrity(_))
        });
        if has_integrity {
            if self.auth.validate(msg, raw).is_err() {
                self.metrics.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        }

        let mut resp = StunMessage::with_transaction_id(
            Method::Binding, MessageClass::SuccessResponse, msg.transaction_id,
        );
        resp.add(Attribute::XorMappedAddress(src));
        resp.add(Attribute::Software("turna 0.1".into()));

        let mut buf = [0u8; 256];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: src }]
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

        let key = match self.auth.validate(msg, raw) {
            Ok(k)  => k,
            Err(e) => {
                warn!(%src, %e, "auth failed");
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };

        let (relay_port, relay_sock) = match self.store.ports.allocate_and_bind() {
            Some(x) => x,
            None    => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
        };

        let relay_addr = SocketAddr::new(self.external_ip, relay_port);
        let lifetime   = msg.get_lifetime().unwrap_or(turn::DEFAULT_LIFETIME).min(turn::MAX_LIFETIME);
        let username   = msg.get_username().unwrap_or("").to_string();

        if let Err(_) = self.store.create(src, relay_addr, username, key.clone(), lifetime) {
            self.store.ports.release(relay_port);
            // relay_sock dropped here → socket closed, port freed.
            return self.encode_error(msg, src, 508, "Insufficient Capacity");
        }

        self.metrics.active_allocations.fetch_add(1, Ordering::Relaxed);
        self.metrics.total_allocations.fetch_add(1, Ordering::Relaxed);

        let resp = turn::build_allocate_response(msg.transaction_id, relay_addr, src, lifetime);
        let mut buf = [0u8; 1024];
        let len = resp.encode_with_integrity(&mut buf, &key);
        info!(%src, %relay_addr, lifetime, "allocation created");
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);

        vec![
            Action::RegisterRelay { port: relay_port, socket: relay_sock, client_addr: src },
            Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: src },
        ]
    }

    fn handle_refresh(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }
        let key = match self.auth.validate(msg, raw) {
            Ok(k)  => k,
            Err(_) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };

        let lifetime = msg.get_lifetime().unwrap_or(turn::DEFAULT_LIFETIME).min(turn::MAX_LIFETIME);
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
                let mut actions = vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: src }];
                if lifetime == 0 {
                    self.metrics.active_allocations.fetch_sub(1, Ordering::Relaxed);
                    if let Some(port) = relay_port {
                        actions.push(Action::CloseRelay { port });
                    }
                }
                actions
            }
            Err(_) => self.encode_error(msg, src, 437, "Allocation Mismatch"),
        }
    }

    fn handle_create_permission(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }
        let key = match self.auth.validate(msg, raw) {
            Ok(k)  => k,
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
                let resp = turn::build_success_response(Method::CreatePermission, msg.transaction_id);
                let mut buf = [0u8; 1024];
                let len = resp.encode_with_integrity(&mut buf, &key);
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: src }]
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
        let key = match self.auth.validate(msg, raw) {
            Ok(k)  => k,
            Err(_) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                return self.encode_auth_challenge(msg, src);
            }
        };

        let Some(channel)   = msg.get_channel_number()    else { return self.encode_error(msg, src, 400, "Bad Request"); };
        let Some(peer_addr) = msg.get_xor_peer_address()  else { return self.encode_error(msg, src, 400, "Bad Request"); };

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
                vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: src }]
            }
            Err(_) => self.encode_error(msg, src, 437, "Allocation Mismatch"),
        }
    }

    fn handle_send_indication(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        let Some(peer_addr) = msg.get_xor_peer_address() else { return vec![Action::None]; };
        let Some(data)      = msg.get_data()              else { return vec![Action::None]; };

        // Normalize ::ffff: → v4 and reject special-use peers (C2/C3).
        let peer_addr = normalize_addr(peer_addr);
        if is_forbidden_peer(peer_addr.ip()) {
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        // DONT-FRAGMENT: drop if payload exceeds MTU.
        let has_dont_fragment = msg.attributes.iter().any(|a| {
            matches!(a, turna_proto_stun::attribute::Attribute::DontFragment)
        });
        if has_dont_fragment && data.len() > self.mtu as usize {
            debug!(%src, len = data.len(), mtu = self.mtu, "DONT-FRAGMENT: packet too large, dropping");
            return vec![Action::None];
        }

        let alloc = match self.store.get(&src) {
            Some(a) => a,
            None    => return vec![Action::None],
        };

        if !alloc.has_permission(&peer_addr) { return vec![Action::None]; }

        alloc.add_bytes(data.len() as u64);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        let relay_port = alloc.relay_addr.port();
        drop(alloc);

        // `raw` here is a &[u8] (not the owned Bytes), so one copy into an
        // owned Bytes is required. This is the Send-indication path, not the
        // hot path — bidirectional media uses ChannelData (process_channel_data),
        // which is genuinely zero-copy via Bytes::slice().
        let offset = data.as_ptr() as usize - raw.as_ptr() as usize;
        let data_bytes = Bytes::copy_from_slice(&raw[offset..offset + data.len()]);

        vec![Action::SendViaRelay { data: data_bytes, target: peer_addr, relay_port }]
    }

    // ── Response builders ─────────────────────────────────────────────────────

    fn encode_error(&self, msg: &StunMessage, dst: SocketAddr, code: u16, reason: &str) -> Vec<Action> {
        let resp = turn::build_error_response(msg.method, msg.transaction_id, code, reason);
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: dst }]
    }

    fn encode_auth_challenge(&self, msg: &StunMessage, dst: SocketAddr) -> Vec<Action> {
        let resp = turn::build_auth_challenge(
            msg.method, msg.transaction_id,
            self.auth.realm(), &self.nonce_mgr.current(),
        );
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: dst }]
    }

    fn encode_stale_nonce(&self, msg: &StunMessage, dst: SocketAddr) -> Vec<Action> {
        let mut resp = turn::build_error_response(msg.method, msg.transaction_id, 438, "Stale Nonce");
        resp.add(Attribute::Realm(self.auth.realm().to_string()));
        resp.add(Attribute::Nonce(self.nonce_mgr.current()));
        let mut buf = [0u8; 512];
        let len = resp.encode(&mut buf);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        vec![Action::Send { data: Bytes::copy_from_slice(&buf[..len]), target: dst }]
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
