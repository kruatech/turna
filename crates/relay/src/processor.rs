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
use std::sync::{Arc, OnceLock};
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
use turna_session::{AllocationStore, SessionError, TransportProto};
use turna_transport::migration::MigrationManager;

use crate::peer_filter::{is_forbidden_peer, normalize_addr, normalize_ip};
use crate::tcp_relay::TcpRelayManager;

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

    /// Forward a payload via a relay socket by `(offset, len)` into the original
    /// recv buffer, instead of an owned `Bytes` (P1).
    ///
    /// Emitted only on the borrowed-slice ingress paths (io_uring / AF_XDP) via
    /// `process_slice`, where the payload still lives in the kernel-registered
    /// recv buffer. The worker forwards straight from that buffer
    /// (`ForwardAction::ZeroCopyViaRelay`), skipping the whole-packet
    /// `Bytes::copy_from_slice`. The tokio path keeps using `Forward { data }`,
    /// which is already zero-copy via `Bytes::slice`. `offset`/`len` are
    /// relative to the slice handed to `process_slice` (== the buffer slot).
    ForwardZeroCopy {
        offset: usize,
        len: usize,
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

    /// Register a relayed TCP listener for RFC 6062 §4.4 peer-initiated
    /// connections. The listener is bound synchronously in `handle_allocate_tcp`
    /// (on `0.0.0.0:relay_port`, mirroring the UDP relay pool) before the Allocate
    /// success is emitted. The TLS bridge adopts it, accepts peer connections,
    /// registers each with the TCP relay manager, and notifies the client with a
    /// ConnectionAttempt indication routed by `client_addr`. `owner_key` is the
    /// allocation's long-term key, so a later ConnectionBind must match (O#1).
    RegisterTcpListener {
        relay_port: u16,
        listener: std::net::TcpListener,
        client_addr: SocketAddr,
        owner_key: Vec<u8>,
    },

    /// Close and unregister the relay socket for this port (on release), so
    /// its fd is freed and the port can be safely reused.
    CloseRelay { port: u16 },

    /// No action needed.
    None,
}

// ── Encode-result handling (M2) ──────────────────────────────────────────────

/// Resolve a STUN encode result, or drop the outbound packet on the
/// (practically unreachable) buffer-overflow path instead of panicking.
///
/// Server responses are encoded into fixed stack buffers that are sized for
/// the message, so `Err` should never occur for them; the one attacker-
/// influenced caller is the Data-Indication fallback in `process_relay_recv`,
/// where an oversized peer payload now drops the indication rather than
/// panicking the worker. `$drop` is the value returned from the enclosing
/// handler when encoding overflows.
macro_rules! encode_or_drop {
    ($expr:expr, $drop:expr) => {
        match $expr {
            Ok(written) => written,
            Err(err) => {
                warn!(error = %err, "STUN message did not fit its buffer; dropping response");
                return $drop;
            }
        }
    };
}

/// Sign `resp` with the same MESSAGE-INTEGRITY variant the request used: if the
/// request carried MESSAGE-INTEGRITY-SHA256 (RFC 8489), respond with HMAC-SHA-256,
/// otherwise the RFC 5389 HMAC-SHA-1. `key` is the long-term key derived during
/// auth — already the matching digest (see `turna_auth::AuthMode::validate`).
fn encode_with_integrity_auto(
    resp: &StunMessage,
    buf: &mut [u8],
    key: &[u8],
    req: &StunMessage,
) -> Result<usize, turna_proto_stun::StunError> {
    if req.get_message_integrity_sha256().is_some() {
        resp.encode_with_integrity_sha256(buf, key)
    } else {
        resp.encode_with_integrity(buf, key)
    }
}

// ── Latency-histogram sampling (P2) ──────────────────────────────────────────
//
// Two `Instant::now()` reads plus an atomic histogram update on every packet
// cost measurable cycles at hundreds of thousands of pps. Sample 1-in-N
// instead. Default N = 1 (sample everything — identical to the previous
// behaviour); operators under load set `TURNA_LATENCY_SAMPLE_N` to trade
// histogram fidelity for fewer clock reads on the hot path.
fn latency_sample_n() -> u64 {
    static N: OnceLock<u64> = OnceLock::new();
    *N.get_or_init(|| {
        std::env::var("TURNA_LATENCY_SAMPLE_N")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(1)
    })
}

#[inline]
fn should_sample() -> bool {
    let n = latency_sample_n();
    if n <= 1 {
        return true;
    }
    static CTR: AtomicU64 = AtomicU64::new(0);
    CTR.fetch_add(1, Ordering::Relaxed).is_multiple_of(n)
}

/// P1 kill switch. The zero-copy ChannelData forward path (offset/len straight
/// from the kernel-registered recv buffer) is on by default; set
/// `TURNA_URING_ZEROCOPY_FORWARD` to `0`/`false`/`no` to fall back to the
/// previous copy-then-`process()` path without a rebuild — e.g. if a buffer
/// lifecycle regression shows up under a soak/bench run.
fn zerocopy_forward_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var("TURNA_URING_ZEROCOPY_FORWARD")
                .ok()
                .as_deref(),
            Some("0") | Some("false") | Some("no")
        )
    })
}

/// A3-F4: set the IPv4 "Don't Fragment" bit on a relay socket so the kernel
/// stamps DF on every datagram relayed for this allocation (and refuses to
/// fragment — oversized sends fail with EMSGSIZE, and the path MTU drops surface
/// as ICMP "fragmentation needed", which the Data-error path can relay back).
///
/// Applied per allocation when the client set DONT-FRAGMENT on Allocate
/// (RFC 8656 §16.4). The relay socket binds IPv4 (`0.0.0.0`), so only the IPv4
/// knob is needed today; an IPv6 relay would also want `IPV6_MTU_DISCOVER`.
#[cfg(target_os = "linux")]
fn set_dont_fragment(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // IP_MTU_DISCOVER = IP_PMTUDISC_DO → kernel sets DF and never fragments.
    let val: libc::c_int = libc::IP_PMTUDISC_DO;
    // SAFETY: `fd` is the caller's open socket; `val` is a c_int living for the call,
    // optlen = size_of::<c_int>().
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &val as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Non-Linux builds (e.g. macOS dev hosts) are a no-op: production runs on
/// Linux, and the dev build only needs the control-plane logic to compile.
#[cfg(not(target_os = "linux"))]
fn set_dont_fragment(_fd: std::os::fd::RawFd) -> std::io::Result<()> {
    Ok(())
}

// ── Nonce manager ────────────────────────────────────────────────────────────

/// Stateless, per-client nonce issuer (F-7). The nonce is an HMAC over the
/// client address and an issue timestamp, keyed by a random per-process key, so
/// it carries no server-side state and is bound to the client it was issued to:
/// a nonce handed to one peer cannot be replayed by another. The key is
/// ephemeral — after a restart, outstanding nonces simply trigger a fresh 401
/// challenge.
struct NonceManager {
    server_key: [u8; 32],
    start: Instant,
    /// How long an issued nonce stays valid, including a grace window for the
    /// client's in-flight retry.
    max_age: Duration,
}

impl NonceManager {
    fn new() -> Self {
        Self {
            server_key: turna_crypto::random_key_32(),
            start: Instant::now(),
            // 600s lifetime + 30s grace, matching the previous rotation policy.
            max_age: Duration::from_secs(630),
        }
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Issue a fresh nonce bound to `client`.
    fn issue(&self, client: SocketAddr) -> String {
        turna_crypto::issue_client_nonce(&self.server_key, &client.to_string(), self.now_ms())
    }

    /// Validate `nonce` for `client`: the MAC must match (same client + key) and
    /// the nonce must not be older than `max_age`.
    fn validate(&self, client: SocketAddr, nonce: &str) -> NonceStatus {
        let max_age_ms = self.max_age.as_millis() as u64;
        match turna_crypto::verify_client_nonce(&self.server_key, &client.to_string(), nonce) {
            Some(issued_ms) if self.now_ms().saturating_sub(issued_ms) <= max_age_ms => {
                NonceStatus::Valid
            }
            _ => NonceStatus::Stale,
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

    /// Leave lame-duck mode (undrain): resume owning new clients. Without this,
    /// an undrain command could not reverse the routing drain flag, leaving the
    /// node excluded from routing while it reports Ready (P0.5).
    pub fn end_drain(&self) {
        self.draining.store(false, Ordering::Relaxed);
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
/// Outcome of validating an RFC 6062 CONNECT request. The async outbound TCP
/// connect is performed by the TCP-relay bridge, not the sync processor.
pub enum ConnectDecision {
    /// Validation passed: open a TCP connection to `peer`, group it under this
    /// allocation's `relay_port`, and sign the response with `key`.
    Proceed {
        peer: SocketAddr,
        key: Vec<u8>,
        relay_port: u16,
    },
    /// Validation failed (auth challenge / error): send these actions as-is.
    Reject(Vec<Action>),
}

/// Outcome of validating an RFC 6062 ConnectionBind request. The atomic claim of
/// the pending peer connection and the raw stream handoff are done by the caller
/// (TCP-relay bridge), since they need the live stream.
pub enum ConnBindDecision {
    /// `key` is the authenticated client's long-term key — the caller passes it
    /// to `TcpRelayManager::claim` so a ConnectionBind can only bind a peer
    /// connection owned by the same credentials (RFC 6062 §4.4, O#1).
    Proceed {
        connection_id: u32,
        key: Vec<u8>,
        success: Vec<u8>,
    },
    Reject(Vec<Action>),
}

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
    /// RFC 6062 TCP relay engine. `None` = TCP allocations disabled (Allocate
    /// with REQUESTED-TRANSPORT=TCP → 442).
    tcp_relay: Option<Arc<TcpRelayManager>>,
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
            tcp_relay: None,
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

    /// Attach an RFC 6062 TCP relay engine (builder-style; call sites
    /// untouched). When present, Allocate with REQUESTED-TRANSPORT=TCP is
    /// accepted instead of 442.
    pub fn with_tcp_relay(mut self, tcp_relay: Option<Arc<TcpRelayManager>>) -> Self {
        self.tcp_relay = tcp_relay;
        self
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }
    pub fn rtp_analyzer(&self) -> &Arc<RtpAnalyzer> {
        &self.rtp_analyzer
    }

    /// I2: drop rate-limiter buckets idle longer than `max_age_secs`. Memory is
    /// bounded by `max_entries` per tier already, but without periodic cleanup
    /// idle buckets linger until restart; the maintenance loop calls this.
    pub fn cleanup_rate_limiter(&self, max_age_secs: f64) {
        self.rate_limiter.cleanup(max_age_secs);
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
        // UDP / SCTP / borrowed-slice ingress — not a TCP control connection, so
        // an RFC 6062 TCP allocation request is rejected in `handle_allocate`.
        self.process_impl(raw, src, false)
    }

    /// TLS/TCP control-connection ingress (the TURNS bridge). Permits RFC 6062
    /// TCP allocations, which MUST arrive over a TCP/TLS control connection
    /// (§4.1); all other ingress uses [`process`] with UDP semantics.
    pub fn process_tcp_control(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        self.process_impl(raw, src, true)
    }

    fn process_impl(&self, raw: Bytes, src: SocketAddr, ingress_tcp: bool) -> Vec<Action> {
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

        if is_channel {
            // P5: ChannelData on an established session is legitimately
            // high-rate media (the ~95% path). The per-prefix tier of the
            // ingress limiter exists mainly to catch pre-auth STUN floods;
            // running both per-IP and per-prefix sharded-lock checks on every
            // media packet is a redundant second lock. Unknown-source
            // ChannelData is dropped at the allocation lookup in
            // `process_channel_data`, and established sessions are bounded by
            // the per-allocation bandwidth quota — so a cheaper per-IP-only
            // gate (single shard lock) is sufficient here.
            if !self.rate_limiter.check_ingress_ip(src.ip()) {
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }
            // P2: only read the clock / update the histogram on sampled packets.
            if should_sample() {
                let t0 = std::time::Instant::now();
                let actions = self.process_channel_data(raw, src);
                self.metrics
                    .histograms
                    .observe("turna_relay_forward_duration_seconds", t0.elapsed());
                return actions;
            }
            return self.process_channel_data(raw, src);
        }

        // STUN is pre-auth: keep the full per-IP + per-prefix ingress gate.
        if !self.rate_limiter.check_ingress(src.ip()) {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }
        if should_sample() {
            let t0 = std::time::Instant::now();
            let actions = self.process_stun(raw, src, ingress_tcp);
            self.metrics
                .histograms
                .observe("turna_stun_request_duration_seconds", t0.elapsed());
            return actions;
        }
        self.process_stun(raw, src, ingress_tcp)
    }

    /// Entry point for the borrowed-slice ingress paths (io_uring / AF_XDP),
    /// where `raw` points into a kernel-registered recv buffer.
    ///
    /// ChannelData forwards (the hot path) are resolved directly on the slice
    /// and returned as `Action::ForwardZeroCopy { offset, len, .. }` — the
    /// payload is never copied into an owned `Bytes`; the worker sends straight
    /// from the recv buffer. Everything else (STUN, Send Indication, malformed,
    /// or the kill switch disabled) takes one copy and goes through the full
    /// `process()` pipeline, which is rare relative to media.
    #[inline]
    pub fn process_slice(&self, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if zerocopy_forward_enabled() && message::is_channel_data(raw) {
            self.metrics
                .packets_received
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_received
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            // ChannelData uses the per-IP-only ingress gate (see P5 in process()).
            if !self.rate_limiter.check_ingress_ip(src.ip()) {
                self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }

            let decision = if should_sample() {
                let t0 = std::time::Instant::now();
                let d = self.channel_data_decision(raw, src);
                self.metrics
                    .histograms
                    .observe("turna_relay_forward_duration_seconds", t0.elapsed());
                d
            } else {
                self.channel_data_decision(raw, src)
            };

            return match decision {
                Some((offset, len, target, relay_port)) => vec![Action::ForwardZeroCopy {
                    offset,
                    len,
                    target,
                    relay_port,
                }],
                None => vec![Action::None],
            };
        }

        // Non-hot path (or kill switch off): one copy, then the full pipeline.
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
        // I3: don't relay peer->client on an expired allocation.
        if alloc.is_expired() {
            drop(alloc);
            return vec![Action::None];
        }

        if !alloc.has_permission(&peer_addr) {
            drop(alloc);
            return vec![Action::None];
        }

        // P3: pull everything we need out of the allocation, then release the
        // DashMap shard `Ref` BEFORE the (relatively expensive) RTP analysis and
        // metric updates. Holding it across `analyze()` serializes refresh /
        // re_key / add_permission on the same shard for no reason — the
        // ChannelData hot path already drops early; bring this path in line.
        // B2: enforce the per-allocation bandwidth quota on the peer->client
        // direction too. Note `add_bytes`/`check_bandwidth` share one per-alloc
        // window, so `max_bytes_per_sec_per_allocation` now bounds both directions combined.
        let (bw_limit, bandwidth_disabled) = self.store.bandwidth_policy_for_user(
            &alloc.realm,
            alloc.tenant_id.as_deref(),
            &alloc.username,
        );
        if bandwidth_disabled || (bw_limit > 0 && alloc.check_bandwidth(bw_limit).is_err()) {
            drop(alloc);
            debug!(%peer_addr, "bandwidth quota exceeded, dropping relay->client packet");
            self.metrics.quota_exceeded.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }
        alloc.add_bytes(data.len() as u64);
        let ca = alloc.client_addr;
        let channel = alloc.get_peer_channel(&peer_addr);
        drop(alloc);

        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        self.rtp_analyzer.analyze(data, peer_addr);

        // Prefer ChannelData if a channel is bound.
        if let Some(ch) = channel {
            // Build ChannelData frame: 4-byte header + payload (one copy).
            let frame_len = (4 + data.len() + 3) & !3; // include 4-byte padding
            let mut buf = BytesMut::with_capacity(frame_len);
            buf.resize(frame_len, 0);
            let written = encode_or_drop!(
                message::encode_channel_data(&mut buf, ch, data),
                vec![Action::None]
            );
            buf.truncate(written);

            return vec![Action::Send {
                data: buf.freeze(),
                target: ca,
            }];
        }

        // Fallback: Data Indication.
        let mut ind =
            StunMessage::with_transaction_id(Method::Data, MessageClass::Indication, [0; 12]);
        ind.add(Attribute::XorPeerAddress(peer_addr));
        ind.add(Attribute::Data(data.to_vec()));

        let mut buf = [0u8; 4096];
        let len = encode_or_drop!(ind.encode(&mut buf), vec![Action::None]);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: ca,
        }]
    }

    // ── ChannelData (hot path) ────────────────────────────────────────────────

    /// Core ChannelData forward decision over a borrowed slice. Returns the
    /// payload's `(offset, len)` within `raw` plus the peer target and relay
    /// port — or `None` to drop. Shared by the owned path (`process_channel_data`,
    /// tokio) and the borrowed paths (`process_slice`, io_uring / AF_XDP) so the
    /// two can't drift. All accounting — bandwidth quota, byte/packet counters,
    /// RTP analysis — happens here exactly once.
    fn channel_data_decision(
        &self,
        raw: &[u8],
        src: SocketAddr,
    ) -> Option<(usize, usize, SocketAddr, u16)> {
        let Ok((channel, data_slice)) = message::decode_channel_data(raw) else {
            return None;
        };

        let alloc = self.store.get(&src)?;
        // I3: the allocation's own expiry is swept only every ~5s; drop on an
        // expired allocation now rather than relaying through that window.
        if alloc.is_expired() {
            return None;
        }
        let peer_addr = alloc.get_channel_peer(channel).copied()?;

        let (bw_limit, bandwidth_disabled) = self.store.bandwidth_policy_for_user(
            &alloc.realm,
            alloc.tenant_id.as_deref(),
            &alloc.username,
        );
        if bandwidth_disabled || (bw_limit > 0 && alloc.check_bandwidth(bw_limit).is_err()) {
            debug!(%src, "bandwidth quota exceeded, dropping packet");
            self.metrics.quota_exceeded.fetch_add(1, Ordering::Relaxed);
            return None;
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

        // data_slice points into `raw` (guaranteed by decode_channel_data), so
        // this offset is valid against the very buffer the caller still holds.
        let offset = data_slice.as_ptr() as usize - raw.as_ptr() as usize;
        Some((offset, data_slice.len(), peer_addr, relay_port))
    }

    fn process_channel_data(&self, raw: Bytes, src: SocketAddr) -> Vec<Action> {
        match self.channel_data_decision(&raw, src) {
            // Zero-copy slice of the owned recv buffer: pointer + length, no copy.
            Some((offset, len, target, relay_port)) => vec![Action::Forward {
                data: raw.slice(offset..offset + len),
                target,
                relay_port,
            }],
            None => vec![Action::None],
        }
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
        let r = if should_sample() {
            let started = std::time::Instant::now();
            let r = self.auth.validate(msg, raw);
            self.metrics
                .histograms
                .observe("turna_auth_duration_seconds", started.elapsed());
            r
        } else {
            self.auth.validate(msg, raw)
        };
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
                turna_auth::AuthError::BadRequest => &self.metrics.auth_fail_bad_request,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    fn process_stun(&self, raw: Bytes, src: SocketAddr, ingress_tcp: bool) -> Vec<Action> {
        let msg = match StunMessage::decode(&raw) {
            Ok(m) => m,
            Err(e) => {
                // Anti-amplification: a packet that fails to decode (truncated,
                // garbage, or a malformed attribute such as a bad-length /
                // unknown-family REQUESTED-ADDRESS-FAMILY) is dropped SILENTLY —
                // no STUN/TURN error is returned. Answering generic decode
                // failures would let a spoofed source IP turn this UDP port into
                // a reflection/amplification vector. Semantic errors (420/440/
                // 442/…) are only produced once a message parses cleanly, so the
                // syntax layer rejects quietly while the protocol layer answers.
                warn!(%src, %e, "STUN decode error");
                self.metrics
                    .parser_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }
        };

        if matches!(msg.class, MessageClass::Request) {
            // I3: reject unknown comprehension-required attributes with 420 before
            // routing/auth — a request we can't parse must not be redirected.
            if let Some(actions) = self.reject_unknown_comprehension_required(&msg, src) {
                return actions;
            }
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
                self.handle_allocate(&msg, &raw, src, ingress_tcp)
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

    /// I3 (RFC 5389 §7.3.1): answer 420 UNKNOWN-ATTRIBUTES for comprehension-
    /// required (type < 0x8000) attributes we didn't understand. 0x001C
    /// (MESSAGE-INTEGRITY-SHA256) and 0x001D (PASSWORD-ALGORITHM) are understood
    /// despite being parsed generically, so they never trigger 420.
    fn reject_unknown_comprehension_required(
        &self,
        msg: &StunMessage,
        src: SocketAddr,
    ) -> Option<Vec<Action>> {
        let unknown: Vec<u16> = msg
            .attributes
            .iter()
            .filter_map(|a| match a {
                Attribute::Unknown { attr_type, .. }
                    if *attr_type < 0x8000
                        && *attr_type
                            != turna_proto_stun::attribute::ATTR_MESSAGE_INTEGRITY_SHA256
                        && *attr_type != turna_proto_stun::attribute::ATTR_PASSWORD_ALGORITHM =>
                {
                    Some(*attr_type)
                }
                _ => None,
            })
            .collect();
        if unknown.is_empty() {
            return None;
        }
        let mut resp =
            turn::build_error_response(msg.method, msg.transaction_id, 420, "Unknown Attribute");
        resp.add(Attribute::UnknownAttributes(unknown));
        let mut buf = [0u8; 512];
        let len = encode_or_drop!(resp.encode(&mut buf), Some(vec![Action::None]));
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        Some(vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }])
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
                ring.get_node_excluding(&key, &routing.local_node_id)
                    .cloned()
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
        let len = encode_or_drop!(resp.encode(&mut buf), vec![Action::None]);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        self.metrics
            .cluster_redirects
            .fetch_add(1, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }]
    }

    // ── STUN handlers ─────────────────────────────────────────────────────────

    fn handle_binding(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        // RFC 5389 §10.1.2: if MESSAGE-INTEGRITY present, validate it over the
        // actual message bytes (not an empty buffer).
        // A client may authenticate a Binding with RFC 5389 MESSAGE-INTEGRITY
        // (HMAC-SHA-1) or RFC 8489 MESSAGE-INTEGRITY-SHA256. Checking only the
        // SHA-1 variant let a SHA256-only Binding through unauthenticated (I6).
        let has_integrity =
            msg.get_message_integrity().is_some() || msg.get_message_integrity_sha256().is_some();
        if has_integrity && self.auth_validate(msg, raw).is_err() {
            self.metrics
                .auth_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return self.encode_auth_challenge(msg, src);
        }

        let mut resp = StunMessage::with_transaction_id(
            Method::Binding,
            MessageClass::SuccessResponse,
            msg.transaction_id,
        );
        resp.add(Attribute::XorMappedAddress(src));
        resp.add(Attribute::Software(
            concat!("turna ", env!("CARGO_PKG_VERSION")).into(),
        ));

        let mut buf = [0u8; 256];
        let len = encode_or_drop!(resp.encode(&mut buf), vec![Action::None]);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }]
    }

    fn handle_allocate(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        src: SocketAddr,
        ingress_tcp: bool,
    ) -> Vec<Action> {
        if self.metrics.is_draining() {
            return self.encode_error(msg, src, 508, "Server Draining");
        }

        // A3-L1: authenticate first (RFC 5766 §6.2). Running the 437/442 checks
        // before auth let an unauthenticated client probe whether an allocation
        // already exists on this 5-tuple (437 vs 401 disclosure). Challenge and
        // validate first, then do the allocation-mismatch / transport checks.
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
                if matches!(e, turna_auth::AuthError::BadRequest) {
                    return self.encode_error(msg, src, 400, "Bad Request");
                }
                return self.encode_auth_challenge(msg, src);
            }
        };
        // Tenant identity is the result of auth resolution — derived ONLY from
        // the authenticated realm (see turna_auth::AuthRegistry). Network/listener
        // hints never enter here.
        let token_max_lifetime = resolution.max_lifetime_secs;
        let key = resolution.key;
        let realm = resolution.realm;
        let tenant_id = resolution.tenant_id;

        // RFC 7635 §6.1: an OAuth token with no remaining lifetime cannot
        // authorize a new allocation — capping the granted lifetime by it would
        // yield a 0-second (already-dead) allocation. Reject with 401 so the
        // client re-authorizes with a fresh token. (A token expired beyond the
        // clock-skew grace is already refused in decrypt_access_token; this
        // catches the in-grace, zero-remaining boundary, before any relay port is
        // allocated.) `None` = non-OAuth (long-term) auth, which has no cap.
        if token_max_lifetime == Some(0) {
            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            return self.encode_error(msg, src, 401, "Unauthorized");
        }

        // Post-auth checks (A3-L1): only an authenticated client reaches here.
        if self.store.get(&src).is_some() {
            return self.encode_error(msg, src, 437, "Allocation Mismatch");
        }
        let requested_transport = msg.get_requested_transport();
        let want_tcp = requested_transport == Some(turn::TRANSPORT_TCP) && self.tcp_relay.is_some();
        if requested_transport != Some(turn::TRANSPORT_UDP) && !want_tcp {
            return self.encode_error(msg, src, 442, "Unsupported Transport Protocol");
        }
        if want_tcp && !ingress_tcp {
            // RFC 6062 §4.1: a TCP allocation MUST be requested over a TCP/TLS
            // control connection. A TCP-transport request arriving over UDP /
            // SCTP / any non-TCP ingress is rejected here (previously it created
            // a half-working allocation whose relayed listener was then dropped).
            return self.encode_error(msg, src, 400, "Bad Request");
        }
        if want_tcp {
            // RFC 6062 TCP allocation: no relay UDP socket, no RegisterRelay.
            return self.handle_allocate_tcp(
                msg,
                src,
                key.clone(),
                realm.clone(),
                tenant_id.clone(),
                token_max_lifetime,
            );
        }

        // RFC 8656 §14.1 / §7.2: REQUESTED-ADDRESS-FAMILY. This build is
        // IPv4-only (see RC scope): an explicit IPv4 request is accepted, an
        // IPv6 request is refused with 440 Address Family not Supported, and a
        // malformed attribute was already rejected at parse time (the packet
        // fails to decode → handled as a bad request upstream). §7.2 also makes
        // REQUESTED-ADDRESS-FAMILY and RESERVATION-TOKEN mutually exclusive.
        match msg.get_requested_address_family() {
            None | Some(turna_proto_stun::attribute::AddressFamily::Ipv4) => {}
            Some(turna_proto_stun::attribute::AddressFamily::Ipv6) => {
                return self.encode_error(msg, src, 440, "Address Family not Supported");
            }
        }
        if msg.get_requested_address_family().is_some() && msg.get_reservation_token().is_some() {
            return self.encode_error(msg, src, 400, "Bad Request");
        }

        // Allocate the relay port from the *resolved tenant's* isolated pool.
        // RFC 8656 §7.2: EVEN-PORT and RESERVATION-TOKEN are mutually exclusive.
        let even_port = msg.get_even_port();
        let reservation_token = msg.get_reservation_token();
        if even_port.is_some() && reservation_token.is_some() {
            return self.encode_error(msg, src, 400, "Bad Request");
        }
        let pool = self.store.pool(tenant_id.as_deref());
        let (relay_port, relay_sock, issued_token) = if let Some(token) = reservation_token {
            // Follow-up Allocate: bind the port reserved by an earlier EVEN-PORT
            // (R=1) request. An unknown/expired token yields 508.
            match pool.claim_and_bind(&token) {
                Some((p, s)) => (p, s, None),
                None => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
            }
        } else if let Some(reserve_next) = even_port {
            match pool.allocate_even_and_bind(reserve_next) {
                Some(x) => x,
                None => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
            }
        } else {
            match pool.allocate_and_bind() {
                Some((p, s)) => (p, s, None),
                None => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
            }
        };

        // A3-F4: honour an allocation-scoped DONT-FRAGMENT (RFC 8656 §16.4) by
        // setting the real IP DF bit on this allocation's relay socket. io_uring
        // sends go out on this same fd, so the option applies to all relayed
        // traffic. Set before the socket is handed to RegisterRelay.
        let dont_fragment = msg
            .attributes
            .iter()
            .any(|a| matches!(a, turna_proto_stun::attribute::Attribute::DontFragment));
        if dont_fragment {
            use std::os::fd::AsRawFd;
            if let Err(e) = set_dont_fragment(relay_sock.as_raw_fd()) {
                warn!(%src, %e, "DONT-FRAGMENT: failed to set DF on relay socket");
            }
        }

        let relay_addr = SocketAddr::new(self.external_ip, relay_port);
        let mut port_reservation = turna_session::PortReservationGuard::new(
            self.store.pool_for_port(relay_port),
            relay_port,
        );
        let mut lifetime = msg
            .get_lifetime()
            .unwrap_or(turn::DEFAULT_LIFETIME)
            .min(turn::MAX_LIFETIME);
        // RFC 7635 §6.1: never grant an allocation longer than the authorizing
        // OAuth token's remaining lifetime.
        if let Some(max) = token_max_lifetime {
            lifetime = lifetime.min(max);
        }
        let username = msg.get_username().unwrap_or("").to_string();
        let (dynamic_lifetime, lifetime_disabled) =
            self.store
                .lifetime_policy_for_user(&realm, tenant_id.as_deref(), &username);
        if lifetime_disabled {
            if let Some(token) = issued_token.as_ref() {
                self.store
                    .pool_for_port(relay_port)
                    .cancel_reservation(token);
            }
            return self.encode_error(msg, src, 486, "Allocation Quota Reached");
        }
        if dynamic_lifetime > 0 {
            lifetime = lifetime.min(dynamic_lifetime);
        }

        if let Err(e) = self.store.create_for_identity(
            src,
            relay_addr,
            username,
            key.clone(),
            lifetime,
            realm.clone(),
            tenant_id.clone(),
        ) {
            // I9: an EVEN-PORT (R=1) allocate reserved the next-higher port and
            // issued a token; if create bookkeeping failed, cancel it too so the
            // reserved odd port isn't held until the reservation-expiry sweep.
            if let Some(t) = issued_token {
                self.store.pool_for_port(relay_port).cancel_reservation(&t);
            }
            // relay_sock dropped here → socket closed, port freed.
            // B1: a lost create race (a concurrent Allocate on the same 5-tuple
            // already won the slot) is an Allocation Mismatch (437), not a
            // capacity failure (508).
            return match e {
                SessionError::AllocationExists => {
                    self.encode_error(msg, src, 437, "Allocation Mismatch")
                }
                _ => self.encode_error(msg, src, 508, "Insufficient Capacity"),
            };
        }

        port_reservation.commit();
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

        // A3-Q2: a single lookup of the freshly-created allocation, reused for
        // the MOBILITY-TICKET below and the relay-route stamp further down (this
        // path previously did two get(&src) calls = two shard-lock acquisitions).
        let (allocation_id, migration_epoch) = match self.store.get(&src) {
            Some(a) => (a.allocation_id.clone(), a.migration_epoch),
            None => (String::new(), 0),
        };

        let mut resp = turn::build_allocate_response(msg.transaction_id, relay_addr, src, lifetime);
        // RFC 8016: if migration is enabled and the client opted in by sending a
        // MOBILITY-TICKET (typically zero-length) in the request, issue one bound
        // to this allocation's id + epoch. Added BEFORE encode_with_integrity so
        // MESSAGE-INTEGRITY covers the ticket.
        if let Some(mgr) = &self.migration {
            if msg.has_mobility_ticket() {
                let token = mgr.issue_token(&allocation_id, migration_epoch);
                resp.add(Attribute::MobilityTicket(token.token));
            }
        }
        // RFC 8656 §7.3: echo a RESERVATION-TOKEN when EVEN-PORT (R=1) reserved
        // the next-higher port. Added before encode so MESSAGE-INTEGRITY covers it.
        if let Some(tok) = issued_token {
            resp.add(Attribute::ReservationToken(tok));
        }
        let mut buf = [0u8; 1024];
        let len = encode_or_drop!(
            encode_with_integrity_auto(&resp, &mut buf, &key, msg),
            vec![Action::None]
        );
        info!(%src, %relay_addr, lifetime, "allocation created");
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);

        // RFC 8016: stamp the relay route with the owning allocation id (looked
        // up once above) so the io_uring worker pool can forward relay sends to
        // this owner after a client migration reshards onto another worker.
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

    /// RFC 6062 TCP allocation. Reserves a relay port WITHOUT binding a UDP
    /// socket and records the allocation with `transport = Tcp`. No
    /// RegisterRelay is emitted (there is no relay UDP socket); CONNECT /
    /// CONNECTION-BIND drive the datapath via the TCP relay bridge.
    fn handle_allocate_tcp(
        &self,
        msg: &StunMessage,
        src: SocketAddr,
        key: Vec<u8>,
        realm: String,
        tenant_id: Option<String>,
        token_max_lifetime: Option<u32>,
    ) -> Vec<Action> {
        // RFC 6062 §4.1: EVEN-PORT / RESERVATION-TOKEN / DONT-FRAGMENT MUST NOT
        // appear with a TCP allocation.
        let has_df = msg
            .attributes
            .iter()
            .any(|a| matches!(a, turna_proto_stun::attribute::Attribute::DontFragment));
        if msg.get_even_port().is_some() || msg.get_reservation_token().is_some() || has_df {
            return self.encode_error(msg, src, 400, "Bad Request");
        }
        // IPv4-only build (mirrors the UDP path): refuse an explicit IPv6 family.
        if matches!(
            msg.get_requested_address_family(),
            Some(turna_proto_stun::attribute::AddressFamily::Ipv6)
        ) {
            return self.encode_error(msg, src, 440, "Address Family not Supported");
        }

        let mut lifetime = msg
            .get_lifetime()
            .unwrap_or(turn::DEFAULT_LIFETIME)
            .min(turn::MAX_LIFETIME);
        if let Some(max) = token_max_lifetime {
            lifetime = lifetime.min(max);
        }
        let username = msg.get_username().unwrap_or("").to_string();
        let (dynamic_lifetime, lifetime_disabled) =
            self.store
                .lifetime_policy_for_user(&realm, tenant_id.as_deref(), &username);
        if lifetime_disabled {
            return self.encode_error(msg, src, 486, "Allocation Quota Reached");
        }
        if dynamic_lifetime > 0 {
            lifetime = lifetime.min(dynamic_lifetime);
        }

        // Reserve a relay port without a UDP socket (TCP relay has none).
        let relay_port = match self.store.pool(tenant_id.as_deref()).allocate() {
            Ok(p) => p,
            Err(_) => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
        };
        let relay_addr = SocketAddr::new(self.external_ip, relay_port);
        let mut port_reservation = turna_session::PortReservationGuard::new(
            self.store.pool_for_port(relay_port),
            relay_port,
        );

        // RFC 6062 §4.4: the relayed TCP listener is part of a *successful* TCP
        // allocation (peer-initiated connections require it). Bind it before
        // committing the allocation; on failure, release the port and reject the
        // Allocate rather than hand back a half-working allocation.
        let listener = match std::net::TcpListener::bind(("0.0.0.0", relay_port)) {
            Ok(l) => l,
            Err(e) => {
                warn!(%relay_addr, error = %e, "RFC 6062: relayed TCP listener bind failed");
                return self.encode_error(msg, src, 508, "Insufficient Capacity");
            }
        };

        if let Err(e) = self.store.create_for_identity(
            src,
            relay_addr,
            username,
            key.clone(),
            lifetime,
            realm,
            tenant_id.clone(),
        ) {
            return match e {
                SessionError::AllocationExists => {
                    self.encode_error(msg, src, 437, "Allocation Mismatch")
                }
                _ => self.encode_error(msg, src, 508, "Insufficient Capacity"),
            };
        }
        port_reservation.commit();
        // Mark as TCP so CONNECT is permitted (RFC 6062).
        self.store.set_transport(&src, TransportProto::Tcp);

        self.metrics
            .active_allocations
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .total_allocations
            .fetch_add(1, Ordering::Relaxed);
        if let Some(t) = tenant_id.as_deref() {
            self.metrics.record_tenant_allocation(t);
        }

        let resp = turn::build_allocate_response(msg.transaction_id, relay_addr, src, lifetime);
        let mut buf = [0u8; 1024];
        let len = encode_or_drop!(
            encode_with_integrity_auto(&resp, &mut buf, &key, msg),
            vec![Action::None]
        );
        info!(%src, %relay_addr, lifetime, "TCP allocation created (RFC 6062)");
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);

        // Hand the pre-bound relayed listener to the bridge, which runs the
        // peer-initiated accept loop; emit it before the Allocate success so the
        // listener is live by the time the client learns its relayed address.
        vec![
            Action::RegisterTcpListener {
                relay_port,
                listener,
                client_addr: src,
                owner_key: key.clone(),
            },
            Action::Send {
                data: Bytes::copy_from_slice(&buf[..len]),
                target: src,
            },
        ]
    }

    /// RFC 6062 §4.3 CONNECT validation (sync). Authenticates, requires a TCP
    /// allocation on this 5-tuple, a XOR-PEER-ADDRESS, and an existing
    /// permission for that peer. The async outbound connect is done by the
    /// caller (the TCP-relay bridge).
    pub fn connect_decision(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        src: SocketAddr,
    ) -> ConnectDecision {
        if msg.get_username().is_none() {
            return ConnectDecision::Reject(self.encode_auth_challenge(msg, src));
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return ConnectDecision::Reject(stale);
        }
        let key = match self.auth_validate(msg, raw) {
            Ok(r) => r.key,
            Err(e) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                if matches!(e, turna_auth::AuthError::BadRequest) {
                    return ConnectDecision::Reject(self.encode_error(
                        msg,
                        src,
                        400,
                        "Bad Request",
                    ));
                }
                return ConnectDecision::Reject(self.encode_auth_challenge(msg, src));
            }
        };
        let peer = match msg.get_xor_peer_address() {
            Some(p) => p,
            None => {
                return ConnectDecision::Reject(self.encode_error(msg, src, 400, "Bad Request"))
            }
        };
        // Must be an existing TCP allocation on this 5-tuple, with a permission
        // for the peer (RFC 6062 §4.3 → 437 / 400 / 403).
        let (is_tcp, has_perm, relay_port) = match self.store.get(&src) {
            Some(a) => (
                a.transport == TransportProto::Tcp,
                a.has_permission(&peer),
                a.relay_addr.port(),
            ),
            None => {
                return ConnectDecision::Reject(self.encode_error(
                    msg,
                    src,
                    437,
                    "Allocation Mismatch",
                ))
            }
        };
        if !is_tcp {
            return ConnectDecision::Reject(self.encode_error(msg, src, 400, "Bad Request"));
        }
        if !has_perm {
            return ConnectDecision::Reject(self.encode_error(msg, src, 403, "Forbidden"));
        }
        ConnectDecision::Proceed {
            peer,
            key,
            relay_port,
        }
    }

    /// Build a signed RFC 6062 CONNECT success response carrying CONNECTION-ID.
    pub fn build_connect_success(
        &self,
        conn_id: u32,
        key: &[u8],
        orig: &StunMessage,
    ) -> Option<Vec<u8>> {
        let mut resp = turn::build_success_response(Method::Connect, orig.transaction_id);
        resp.add(Attribute::ConnectionId(conn_id));
        let mut buf = [0u8; 512];
        match encode_with_integrity_auto(&resp, &mut buf, key, orig) {
            Ok(len) => Some(buf[..len].to_vec()),
            Err(_) => None,
        }
    }

    /// Encode an RFC 6062 CONNECT failure (e.g. 447) for the bridge to send.
    pub fn encode_connect_error(
        &self,
        orig: &StunMessage,
        src: SocketAddr,
        code: u16,
        reason: &str,
    ) -> Vec<Action> {
        self.encode_error(orig, src, code, reason)
    }

    /// RFC 6062 §4.4 ConnectionBind validation (sync): authenticate and extract
    /// CONNECTION-ID + a signed success response. The claim of the pending
    /// connection and raw handoff are done by the caller via the relay manager.
    pub fn connection_bind_decision(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        src: SocketAddr,
    ) -> ConnBindDecision {
        if msg.get_username().is_none() {
            return ConnBindDecision::Reject(self.encode_auth_challenge(msg, src));
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return ConnBindDecision::Reject(stale);
        }
        let key = match self.auth_validate(msg, raw) {
            Ok(r) => r.key,
            Err(e) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                if matches!(e, turna_auth::AuthError::BadRequest) {
                    return ConnBindDecision::Reject(self.encode_error(
                        msg,
                        src,
                        400,
                        "Bad Request",
                    ));
                }
                return ConnBindDecision::Reject(self.encode_auth_challenge(msg, src));
            }
        };
        let connection_id = match msg.get_connection_id() {
            Some(id) => id,
            None => {
                return ConnBindDecision::Reject(self.encode_error(msg, src, 400, "Bad Request"))
            }
        };
        match self.build_connection_bind_success(&key, msg) {
            Some(success) => ConnBindDecision::Proceed {
                connection_id,
                key,
                success,
            },
            None => ConnBindDecision::Reject(self.encode_error(msg, src, 500, "Server Error")),
        }
    }

    /// Build a signed RFC 6062 ConnectionBind success (no attributes beyond
    /// MESSAGE-INTEGRITY, per §4.4).
    pub fn build_connection_bind_success(&self, key: &[u8], orig: &StunMessage) -> Option<Vec<u8>> {
        let resp = turn::build_success_response(Method::ConnectionBind, orig.transaction_id);
        let mut buf = [0u8; 256];
        match encode_with_integrity_auto(&resp, &mut buf, key, orig) {
            Ok(len) => Some(buf[..len].to_vec()),
            Err(_) => None,
        }
    }

    /// Encode an RFC 6062 ConnectionAttempt indication (peer-initiated, §4.4) for
    /// delivery to the client over its control connection. Unauthenticated (see
    /// `turn::build_connection_attempt`); returns `None` only on an encode error.
    pub fn build_connection_attempt_indication(
        &self,
        connection_id: u32,
        peer: SocketAddr,
    ) -> Option<Vec<u8>> {
        let ind = turn::build_connection_attempt(connection_id, peer);
        let mut buf = [0u8; 256];
        match ind.encode(&mut buf) {
            Ok(len) => Some(buf[..len].to_vec()),
            Err(_) => None,
        }
    }

    fn handle_refresh(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        if msg.get_username().is_none() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }
        let resolution = match self.auth_validate(msg, raw) {
            Ok(r) => r,
            Err(e) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                if matches!(e, turna_auth::AuthError::BadRequest) {
                    return self.encode_error(msg, src, 400, "Bad Request");
                }
                return self.encode_auth_challenge(msg, src);
            }
        };
        let key = resolution.key;
        let token_max_lifetime = resolution.max_lifetime_secs;
        let realm = resolution.realm;
        let tenant_id = resolution.tenant_id;

        let mut lifetime = msg
            .get_lifetime()
            .unwrap_or(turn::DEFAULT_LIFETIME)
            .min(turn::MAX_LIFETIME);
        // RFC 7635 §6.1: an OAuth token with no remaining lifetime can no longer
        // authorize *extending* an allocation. Reject (401) rather than let the
        // cap silently force the lifetime to 0 and release the allocation out
        // from under a client that asked to keep it. An explicit release
        // (client-sent LIFETIME == 0) is always honoured, since releasing never
        // extends the allocation beyond the token. At this point `lifetime` is
        // still the client's requested value (the cap is applied just below).
        if token_max_lifetime == Some(0) && lifetime > 0 {
            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            return self.encode_error(msg, src, 401, "Unauthorized");
        }
        // Otherwise cap the granted lifetime by the token's remaining life.
        if let Some(max) = token_max_lifetime {
            lifetime = lifetime.min(max);
        }
        if lifetime > 0 {
            let username = msg.get_username().unwrap_or("");
            let (dynamic_max, lifetime_disabled) =
                self.store
                    .lifetime_policy_for_user(&realm, tenant_id.as_deref(), username);
            if lifetime_disabled {
                return self.encode_error(msg, src, 486, "Allocation Quota Reached");
            }
            if dynamic_max > 0 {
                lifetime = lifetime.min(dynamic_max);
            }
        }

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
                let len = encode_or_drop!(
                    encode_with_integrity_auto(&resp, &mut buf, &key, msg),
                    vec![Action::None]
                );
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
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
        // Apply the requested lifetime to the migrated allocation. Capture the
        // relay port first: a release (lifetime 0) removes the re-keyed
        // allocation here, so keep the gauge honest and close the relay
        // deterministically instead of leaving it for the sweep (I4).
        let migrated_relay_port = relay_addr.port();
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
        let len = encode_or_drop!(
            encode_with_integrity_auto(&resp, &mut buf, key, msg),
            Some(vec![Action::None])
        );
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        info!(%src, %old_addr, %relay_addr, "allocation migrated (RFC 8016)");

        let mut actions = vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }];
        if lifetime == 0 {
            self.metrics
                .active_allocations
                .fetch_sub(1, Ordering::Relaxed);
            actions.push(Action::CloseRelay {
                port: migrated_relay_port,
            });
        }
        Some(actions)
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
            Err(e) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                if matches!(e, turna_auth::AuthError::BadRequest) {
                    return self.encode_error(msg, src, 400, "Bad Request");
                }
                return self.encode_auth_challenge(msg, src);
            }
        };

        // RFC 5766 §9.2 / RFC 8656 §9.2: a CreatePermission may carry multiple
        // XOR-PEER-ADDRESS attributes (clients batch all ICE candidates in one
        // request). Collect them all — handling only the first silently drops
        // permissions for the rest.
        let peers: Vec<std::net::IpAddr> = msg
            .attributes
            .iter()
            .filter_map(|a| match a {
                turna_proto_stun::attribute::Attribute::XorPeerAddress(p) => {
                    Some(normalize_ip(p.ip()))
                }
                _ => None,
            })
            .collect();
        if peers.is_empty() {
            return self.encode_error(msg, src, 400, "Bad Request");
        }
        // B5: bound peers in a single CreatePermission (batched ICE candidates)
        // so one request can't inflate the permission table.
        const MAX_PEERS: usize = 32;
        if peers.len() > MAX_PEERS {
            return self.encode_error(msg, src, 400, "Bad Request: too many peers");
        }

        // Atomic policy: validate every peer first. If any is forbidden, reject
        // the whole request (403) and create no permissions.
        for peer_ip in &peers {
            if is_forbidden_peer(*peer_ip) {
                warn!(%src, %peer_ip, "CreatePermission to forbidden peer denied");
                self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
                return self.encode_error(msg, src, 403, "Forbidden");
            }
        }

        // Then install all permissions. add_permission only fails if the
        // allocation is gone (437); the first call establishes existence, so in
        // practice this is all-or-nothing.
        for peer_ip in &peers {
            if let Err(e) = self.store.add_permission(&src, *peer_ip) {
                return match e {
                    SessionError::LimitExceeded => {
                        self.encode_error(msg, src, 486, "Allocation Quota Reached")
                    }
                    _ => self.encode_error(msg, src, 437, "Allocation Mismatch"),
                };
            }
        }

        let resp = turn::build_success_response(Method::CreatePermission, msg.transaction_id);
        let mut buf = [0u8; 1024];
        let len = encode_or_drop!(
            encode_with_integrity_auto(&resp, &mut buf, &key, msg),
            vec![Action::None]
        );
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: src,
        }]
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
            Err(e) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                if matches!(e, turna_auth::AuthError::BadRequest) {
                    return self.encode_error(msg, src, 400, "Bad Request");
                }
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
                let len = encode_or_drop!(
                    encode_with_integrity_auto(&resp, &mut buf, &key, msg),
                    vec![Action::None]
                );
                self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
                vec![Action::Send {
                    data: Bytes::copy_from_slice(&buf[..len]),
                    target: src,
                }]
            }
            // A3-H1: a channel/peer uniqueness violation is a client error → 400.
            Err(SessionError::ChannelConflict) => self.encode_error(msg, src, 400, "Bad Request"),
            Err(SessionError::LimitExceeded) => {
                self.encode_error(msg, src, 486, "Allocation Quota Reached")
            }
            Err(_) => self.encode_error(msg, src, 437, "Allocation Mismatch"),
        }
    }

    fn handle_send_indication(
        &self,
        msg: &StunMessage,
        _raw: &[u8],
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
        // I3: drop a Send-indication relay on an expired allocation.
        if alloc.is_expired() {
            return vec![Action::None];
        }

        if !alloc.has_permission(&peer_addr) {
            return vec![Action::None];
        }

        // B2: enforce the per-allocation bandwidth quota on the Send-indication
        // egress path too, not only ChannelData — otherwise a client bypasses
        // `max_bytes_per_sec_per_allocation` entirely by relaying via Send/Data Indications.
        let (bw_limit, bandwidth_disabled) = self.store.bandwidth_policy_for_user(
            &alloc.realm,
            alloc.tenant_id.as_deref(),
            &alloc.username,
        );
        if bandwidth_disabled || (bw_limit > 0 && alloc.check_bandwidth(bw_limit).is_err()) {
            debug!(%src, "bandwidth quota exceeded, dropping Send indication");
            self.metrics.quota_exceeded.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        alloc.add_bytes(data.len() as u64);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        let relay_port = alloc.relay_addr.port();
        drop(alloc);

        // The Send-indication path copies the DATA payload into an owned
        // `Bytes`. This is not the hot path — bidirectional media uses
        // ChannelData (process_channel_data), which is genuinely zero-copy via
        // Bytes::slice().
        //
        // A3-C1: `data` comes from `msg.get_data()`, which is a slice into the
        // *owned* `Attribute::Data(Vec<u8>)` produced by the parser — a separate
        // allocation from the receive buffer. The previous code computed an
        // offset by subtracting the receive-buffer pointer from `data`'s pointer
        // (pointer arithmetic across two allocations), producing a bogus offset
        // that panicked on the slice index. Copy the slice directly.
        let data_bytes = Bytes::copy_from_slice(data);

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
        let len = encode_or_drop!(resp.encode(&mut buf), vec![Action::None]);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: dst,
        }]
    }

    fn encode_auth_challenge(&self, msg: &StunMessage, dst: SocketAddr) -> Vec<Action> {
        let realm = self.auth.default_realm();
        let nonce = self.nonce_mgr.issue(dst);
        // RFC 7635 §6.1: when the base realm uses OAuth, advertise the
        // authorization server in the 401 so a token-less client learns where to
        // obtain a token; otherwise send the standard credential challenge.
        let resp = match self.auth.base_oauth_identity() {
            Some(as_id) => turn::build_oauth_challenge(
                msg.method,
                msg.transaction_id,
                realm,
                &nonce,
                as_id.as_bytes(),
            ),
            None => turn::build_auth_challenge(msg.method, msg.transaction_id, realm, &nonce),
        };
        let mut buf = [0u8; 512];
        let len = encode_or_drop!(resp.encode(&mut buf), vec![Action::None]);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: dst,
        }]
    }

    fn encode_stale_nonce(&self, msg: &StunMessage, dst: SocketAddr) -> Vec<Action> {
        let mut resp =
            turn::build_error_response(msg.method, msg.transaction_id, 438, "Stale Nonce");
        resp.add(Attribute::Realm(self.auth.default_realm().to_string()));
        resp.add(Attribute::Nonce(self.nonce_mgr.issue(dst)));
        let mut buf = [0u8; 512];
        let len = encode_or_drop!(resp.encode(&mut buf), vec![Action::None]);
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        vec![Action::Send {
            data: Bytes::copy_from_slice(&buf[..len]),
            target: dst,
        }]
    }

    fn validate_nonce(&self, msg: &StunMessage, dst: SocketAddr) -> Option<Vec<Action>> {
        if let Some(nonce) = msg.get_nonce() {
            match self.nonce_mgr.validate(dst, nonce) {
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

#[cfg(test)]
mod a3_send_indication_tests {
    use super::*;
    use turna_auth::AuthMode;

    #[test]
    fn requested_address_family_ipv4_not_reported_as_unknown() {
        // Regression (interop): turnutils_uclient -X sends REQUESTED-ADDRESS-FAMILY
        // (0x0017). It is now a typed attribute, so it must NOT be reported as an
        // unknown comprehension-required attribute — i.e. no 420 listing 0x0017.
        // (This is the exact case that made coturn's `-X` client fail before.)
        let p = test_processor();
        let client: SocketAddr = "127.0.0.1:50123".parse().unwrap();
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg.attributes.push(Attribute::RequestedAddressFamily(
            turna_proto_stun::attribute::AddressFamily::Ipv4,
        ));
        let mut buf = [0u8; 512];
        let n = msg.encode(&mut buf).unwrap();
        let actions = p.process(Bytes::copy_from_slice(&buf[..n]), client);
        // The request is unauthenticated, so the response is an auth challenge —
        // but whatever it is, it must never be a 420 that lists 0x0017.
        for a in &actions {
            if let Action::Send { data, .. } = a {
                if let Ok(resp) = StunMessage::decode(data) {
                    assert!(
                        !resp.attributes.iter().any(|x| matches!(
                            x, Attribute::UnknownAttributes(v) if v.contains(&0x0017)
                        )),
                        "REQUESTED-ADDRESS-FAMILY (0x0017) must not appear in UNKNOWN-ATTRIBUTES"
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_comprehension_required_yields_420() {
        let p = test_processor();
        let client: SocketAddr = "127.0.0.1:50100".parse().unwrap();

        // Required unknown (0x0021) → 420 + UNKNOWN-ATTRIBUTES.
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg.attributes.push(Attribute::Unknown {
            attr_type: 0x0021,
            value: vec![],
        });
        let mut buf = [0u8; 512];
        let n = msg.encode(&mut buf).unwrap();
        let actions = p.process(Bytes::copy_from_slice(&buf[..n]), client);
        let sent = actions
            .iter()
            .find_map(|a| match a {
                Action::Send { data, .. } => Some(data.clone()),
                _ => None,
            })
            .expect("expected a Send response");
        let resp = StunMessage::decode(&sent).unwrap();
        assert!(matches!(resp.class, MessageClass::ErrorResponse));
        assert!(
            resp.attributes.iter().any(|a| matches!(
                a, Attribute::UnknownAttributes(v) if v.contains(&0x0021)
            )),
            "response must list the unknown required attribute"
        );

        // Optional unknown (0x8021) → NOT 420.
        let mut msg2 = StunMessage::new(Method::Allocate, MessageClass::Request);
        msg2.attributes.push(Attribute::Unknown {
            attr_type: 0x8021,
            value: vec![],
        });
        let n2 = msg2.encode(&mut buf).unwrap();
        let actions2 = p.process(Bytes::copy_from_slice(&buf[..n2]), client);
        let has_420 = actions2.iter().any(|a| {
            matches!(a, Action::Send { data, .. }
            if StunMessage::decode(data)
                .map(|m| m.attributes.iter().any(|x| matches!(x, Attribute::UnknownAttributes(_))))
                .unwrap_or(false))
        });
        assert!(
            !has_420,
            "comprehension-optional unknown must not trigger 420"
        );
    }

    #[test]
    fn nonce_is_client_bound_and_validates() {
        let mgr = NonceManager::new();
        let a: SocketAddr = "203.0.113.7:51000".parse().unwrap();
        let b: SocketAddr = "203.0.113.8:51000".parse().unwrap();
        let n = mgr.issue(a);
        assert!(matches!(mgr.validate(a, &n), NonceStatus::Valid));
        // A nonce issued to `a` must not validate for a different client.
        assert!(matches!(mgr.validate(b, &n), NonceStatus::Stale));
        // Garbage input is Stale, never a panic.
        assert!(matches!(mgr.validate(a, "garbage"), NonceStatus::Stale));
    }

    fn test_processor() -> PacketProcessor {
        let store = Arc::new(AllocationStore::new(49152, 65535, 1000));
        let auth = Arc::new(AuthRegistry::new(AuthMode::SharedSecret {
            realm: "turna".into(),
            secret: b"test-secret".to_vec(),
        }));
        PacketProcessor::new(
            store,
            auth,
            "127.0.0.1".parse().unwrap(),
            Arc::new(Metrics::new()),
        )
    }

    /// A3-C1 regression: a Send Indication on an allocation with a matching
    /// permission used to panic — `handle_send_indication` subtracted
    /// `raw.as_ptr()` from `data.as_ptr()`, but `data` is a slice into the
    /// owned `Attribute::Data(Vec<u8>)`, a different allocation, so the offset
    /// was bogus and the subsequent slice index panicked. This is the normal
    /// relay path for clients that use Send/Data Indications instead of
    /// ChannelData, so it broke real interop, not just an edge case.
    #[test]
    fn send_indication_relays_payload_without_panic() {
        let p = test_processor();
        let client: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let relay: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        let peer: SocketAddr = "8.8.8.8:7000".parse().unwrap(); // global unicast — passes the peer filter

        // Seed an allocation + a permission for the peer's IP.
        p.store()
            .create(client, relay, "u".into(), vec![1, 2, 3], 600)
            .unwrap();
        p.store().add_permission(&client, peer.ip()).unwrap();

        // Build a Send Indication carrying XOR-PEER-ADDRESS + DATA, encode to
        // the wire, and feed it through the real `process` path.
        let mut msg = StunMessage::new(Method::Send, MessageClass::Indication);
        msg.attributes.push(Attribute::XorPeerAddress(peer));
        msg.attributes.push(Attribute::Data(b"hello-peer".to_vec()));
        let mut buf = [0u8; 1500];
        let n = msg.encode(&mut buf).expect("encode test message");

        let actions = p.process(Bytes::copy_from_slice(&buf[..n]), client);

        // Exactly the relayed payload, addressed to the peer — no panic.
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendViaRelay { data, target, .. }
                    if *target == peer && data.as_ref() == b"hello-peer"
            )),
            "expected a SendViaRelay carrying the payload to the peer"
        );
    }

    /// Send Indication without a permission must be silently dropped (no relay,
    /// no panic) — guards the early-return paths around the A3-C1 fix.
    #[test]
    fn send_indication_without_permission_is_dropped() {
        let p = test_processor();
        let client: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let relay: SocketAddr = "127.0.0.1:49153".parse().unwrap();
        let peer: SocketAddr = "8.8.8.8:7001".parse().unwrap();

        p.store()
            .create(client, relay, "u".into(), vec![1, 2, 3], 600)
            .unwrap();
        // no add_permission

        let mut msg = StunMessage::new(Method::Send, MessageClass::Indication);
        msg.attributes.push(Attribute::XorPeerAddress(peer));
        msg.attributes.push(Attribute::Data(b"hello-peer".to_vec()));
        let mut buf = [0u8; 1500];
        let n = msg.encode(&mut buf).expect("encode test message");

        let actions = p.process(Bytes::copy_from_slice(&buf[..n]), client);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendViaRelay { .. })),
            "a Send Indication without a permission must not relay"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod a3_f4_dont_fragment_tests {
    use super::set_dont_fragment;
    use std::os::fd::AsRawFd;

    #[test]
    fn set_dont_fragment_sets_pmtudisc_do() {
        let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        set_dont_fragment(sock.as_raw_fd()).expect("setsockopt IP_MTU_DISCOVER should succeed");

        // Read the option back to confirm DF/PMTUD is enabled.
        let mut val: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt failed");
        assert_eq!(val, libc::IP_PMTUDISC_DO);
    }
}
