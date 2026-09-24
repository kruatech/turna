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
/// A client address as it should appear in a log.
///
/// Verbatim when `[observability] log_allocation_addresses` is true, which is
/// the
/// default and the existing behaviour. Otherwise `ip-<12 hex>` under a salt
/// generated once per process: an incident stays traceable across the lines of one
/// node's lifetime, and the address is not recoverable from the log afterwards.
///
/// One function rather than a conditional at each site. The three call sites must
/// agree, and a log where two lines carry an address and the third carries a hash
/// is worse than either choice made consistently — a reader correlating them gets
/// nothing and does not know why.
///
/// The two branches deliberately differ in granularity: verbatim is `ip:port`,
/// the hash covers the IP ONLY. Two concurrent sessions from one host therefore
/// share a label — `ip-<hash>` says so, and per-IP correlation across a client's
/// reconnects is the point. An operator reading these lines is looking at hosts,
/// not sessions; use `allocation_id` to tell sessions apart.
fn loggable_addr(addr: &std::net::SocketAddr) -> String {
    if LOG_ALLOCATION_ADDRESSES.load(std::sync::atomic::Ordering::Relaxed) {
        return addr.to_string();
    }
    hash_ip(&addr.ip())
}

/// What authentication established about a client, as one value.
///
/// These four travel together from `AuthRegistry::resolve` to wherever an
/// allocation is created, and splitting them across a parameter list made
/// `handle_allocate_tcp` take eight arguments — which is the symptom, not the
/// problem. The problem is that four names were standing in for one idea.
///
/// `subject` is the quota identity: for TURN REST credentials the USERNAME
/// without its `<expiry>:` prefix, so a fresh credential does not read as a
/// fresh person. `key` is the long-term key the MESSAGE-INTEGRITY check
/// produced, and `realm` / `tenant_id` say which tenant's limits apply.
#[derive(Clone)]
struct AuthedIdentity {
    key: Vec<u8>,
    realm: String,
    tenant_id: Option<String>,
    subject: String,
}

/// Throttles for the log sites that run BEFORE authentication.
///
/// All three sat at `warn!`, once per packet, with attacker-controlled content
/// — the parser's error text, the source address, the rate limiter's refusal.
/// A single gigabit host is ~1.5 M packets/second, so the log became the denial
/// of service: journald's own rate limit starts dropping the whole stream, and
/// what it drops includes the messages an operator needs to see what is
/// happening.
///
/// The counters (`parser_rejections`, auth failures) are the signal; the line
/// only has to say it is happening, and `occurrences` says how much.
/// What to advertise in SOFTWARE, from `[turn] software_attribute`.
///
/// Process-wide: the value cannot differ between responses, and threading it to
/// the one place it is read would mean a parameter on the Binding path for a
/// string chosen once at startup.
static SOFTWARE_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);

/// `"none"` | `"product"` | `"full"`. Anything else is treated as `product`,
/// the safe middle — an unrecognised value must not silently reveal more.
pub fn set_software_attribute(mode: &str) {
    let v = match mode.trim().to_ascii_lowercase().as_str() {
        "none" => 0u8,
        "full" => 2,
        _ => 1,
    };
    SOFTWARE_MODE.store(v, std::sync::atomic::Ordering::Relaxed);
}

fn software_attribute() -> Option<&'static str> {
    match SOFTWARE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        2 => Some(concat!("turna ", env!("CARGO_PKG_VERSION"))),
        _ => Some("turna"),
    }
}

/// `[turn.auth] advertise_userhash`: prefix every nonce with the RFC 8489
/// "nonce cookie" that sets Security Feature bit 1, "Username anonymity", so a
/// conforming client sends USERHASH instead of USERNAME (§9.2.5).
///
/// Accepting USERHASH needs no switch — a request carrying it used to be
/// answered 420 and is now authenticated, which no working client can have
/// depended on. *Advertising* it is a switch, because it changes every nonce on
/// the wire and obliges clients to change what they send. Off by default.
///
/// Process-wide, like `SOFTWARE_MODE`: set once at startup, before any
/// processor is built, and read by each processor's nonce issuer when it is
/// constructed. The node builds up to three processors (main, QUIC/DTLS,
/// AF_XDP); a builder on each would be three places to forget.
static ADVERTISE_USERHASH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Called by the node before any processor is constructed.
pub fn set_advertise_userhash(on: bool) {
    ADVERTISE_USERHASH.store(on, std::sync::atomic::Ordering::Relaxed);
}

static DECODE_ERROR_LOG: turna_common::LogThrottle = turna_common::LogThrottle::new();
static UNAUTH_BUDGET_LOG: turna_common::LogThrottle = turna_common::LogThrottle::new();
static AUTH_FAILED_LOG: turna_common::LogThrottle = turna_common::LogThrottle::new();

/// The salted label itself, shared by [`loggable_addr`] and [`loggable_ip`] so
/// one host cannot end up with two labels depending on which call site saw it.
fn hash_ip(ip: &std::net::IpAddr) -> String {
    use std::sync::OnceLock;
    static SALT: OnceLock<u64> = OnceLock::new();
    // Eight random bytes from /dev/urandom, once per process.
    //
    // This used to derive the salt from the process start time, which is the
    // exact fallback `observability::syslog` documents CodeQL catching and
    // rejecting: a restart time is often observable from outside — a rolling
    // upgrade, a status page, a gap in the metrics — and the search space then
    // collapses against four billion IPv4 addresses. A label that *looks* like a
    // hash and protects nothing is worse than no label, because nobody checks.
    //
    // If the read fails, addresses are written verbatim and the reason is logged
    // once, rather than substituting something weaker.
    let salt = *SALT.get_or_init(|| {
        use std::io::Read;
        let mut buf = [0u8; 8];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)) {
            Ok(()) => u64::from_le_bytes(buf),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "could not read /dev/urandom, so client addresses will NOT be \
                     redacted in logs — they are written verbatim. A salt derived \
                     from anything predictable would look like a hash and protect \
                     nothing, so none is produced."
                );
                0
            }
        }
    });
    if salt == 0 {
        return ip.to_string();
    }
    // FNV-1a. Not cryptographic and does not need to be: the salt is never
    // written anywhere, and what this provides is a stable label within a process
    // rather than resistance to an attacker who already holds the log.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ salt;
    for b in ip.to_string().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("ip-{h:012x}")
}

/// A peer or client IP as it should appear in a log.
///
/// The `IpAddr` sibling of [`loggable_addr`], for the sites that have no port:
/// peer addresses from CreatePermission and ChannelBind. Same salt, so a host
/// carries one label across every line about it — a permission denial and the
/// allocation it belongs to correlate, which is the whole reason the hash is
/// stable within a process.
fn loggable_ip(ip: &std::net::IpAddr) -> String {
    if LOG_ALLOCATION_ADDRESSES.load(std::sync::atomic::Ordering::Relaxed) {
        return ip.to_string();
    }
    // NOT `loggable_addr(&SocketAddr::new(*ip, 0))`: that would print `1.2.3.4:0`
    // in the verbatim branch, inventing a port these call sites do not have.
    hash_ip(ip)
}

/// Set once at startup from configuration.
static LOG_ALLOCATION_ADDRESSES: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Called by the node before serving.
pub fn set_log_allocation_addresses(on: bool) {
    LOG_ALLOCATION_ADDRESSES.store(on, std::sync::atomic::Ordering::Relaxed);
}

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
/// (RFC 8656 §16.4).
///
/// The option is family-specific: `IPPROTO_IP`/`IP_MTU_DISCOVER` on an
/// `AF_INET6` socket fails (or, worse, silently does nothing), so a v6 relay
/// socket needs `IPPROTO_IPV6`/`IPV6_MTU_DISCOVER` instead. Now that IPv6
/// relaying exists (`[turn] external_ip6`), the caller passes the family it bound.
#[cfg(target_os = "linux")]
fn set_dont_fragment(
    fd: std::os::fd::RawFd,
    family: turna_session::RelayFamily,
) -> std::io::Result<()> {
    // *_PMTUDISC_DO → kernel sets DF and never fragments.
    let val: libc::c_int = libc::IP_PMTUDISC_DO;
    let (level, name) = if family.is_v6() {
        (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    };
    // SAFETY: `fd` is the caller's open socket; `val` is a c_int living for the call,
    // optlen = size_of::<c_int>().
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
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
fn set_dont_fragment(
    _fd: std::os::fd::RawFd,
    _family: turna_session::RelayFamily,
) -> std::io::Result<()> {
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
    /// RFC 8489 §9.2 "nonce cookie" prepended to every issued nonce, or `None`
    /// (the default) for the historical cookie-less nonce.
    cookie: Option<&'static str>,
}

/// RFC 8489 §9.2 nonce cookie with only Security Feature bit 1, "Username
/// anonymity", set (§18.1): `"obMatJos2"` followed by the base64 of the
/// 24-bit feature set `0x40 0x00 0x00`, which is `"QAAA"`.
///
/// Bit 0, "Password algorithms", is deliberately clear. Setting it obliges the
/// server to send PASSWORD-ALGORITHMS in every 401 and 438 (§9.2.4), and a
/// client that sees the bit without the attribute must give up (§9.2.5) —
/// turna does not send PASSWORD-ALGORITHMS, so setting that bit would lock out
/// every RFC 8489 client.
const USERHASH_NONCE_COOKIE: &str = "obMatJos2QAAA";

impl NonceManager {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_cookie(None)
    }

    fn with_cookie(cookie: Option<&'static str>) -> Self {
        Self {
            server_key: turna_crypto::random_key_32(),
            start: Instant::now(),
            // 600s lifetime + 30s grace, matching the previous rotation policy.
            max_age: Duration::from_secs(630),
            cookie,
        }
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Issue a fresh nonce bound to `client`.
    fn issue(&self, client: SocketAddr) -> String {
        let nonce =
            turna_crypto::issue_client_nonce(&self.server_key, &client.to_string(), self.now_ms());
        match self.cookie {
            Some(cookie) => format!("{cookie}{nonce}"),
            None => nonce,
        }
    }

    /// Validate `nonce` for `client`: the MAC must match (same client + key) and
    /// the nonce must not be older than `max_age`.
    fn validate(&self, client: SocketAddr, nonce: &str) -> NonceStatus {
        let max_age_ms = self.max_age.as_millis() as u64;
        // With a cookie configured, a nonce without it was not issued by this
        // process (or was issued before a restart that turned the cookie on):
        // stale, so the client is handed a fresh one carrying the feature bits.
        let nonce = match self.cookie {
            Some(cookie) => match nonce.strip_prefix(cookie) {
                Some(rest) => rest,
                None => return NonceStatus::Stale,
            },
            None => nonce,
        };
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
    udp_transactions: crate::udp_transactions::UdpTransactions,
    store: Arc<AllocationStore>,
    auth: Arc<AuthRegistry>,
    rate_limiter: TieredRateLimiter,
    /// Second limiter, for sources inside `trusted_prefixes`. `None` when no
    /// prefix is configured, which is the default — one limiter, exactly as
    /// before.
    ///
    /// A second limiter rather than a branch inside `TieredRateLimiter`: the
    /// tiers are independent token buckets, so "which bucket" is the only
    /// decision, and making it at the door keeps every `check_*` on the hot path
    /// unchanged.
    trusted_limiter: Option<TieredRateLimiter>,
    /// Ranges whose sources use `trusted_limiter`. Empty unless configured.
    trusted_prefixes: Vec<crate::peer_filter::Cidr>,
    /// Budget for replies sent to an address that has not authenticated:
    /// Binding responses and 401 challenges.
    ///
    /// Separate from the ingress tiers because the thing being limited is
    /// different. Ingress bounds what a source may *ask*, and the generous
    /// defaults are right for that — a real client sends thousands of packets a
    /// second once it is relaying. This bounds what the node *emits* to an
    /// unproven address, and a real client needs a handful of those in total:
    /// a Binding or two, a challenge, then it is authenticated and out of scope.
    ///
    /// The distinction matters under spoofing, where the source address is the
    /// victim: a 48-byte response to a 20-byte request, up to the per-IP ingress
    /// refill of 50 000/second, is 2.4 MB/s aimed at whoever the attacker named.
    unauth_reply_limiter: TieredRateLimiter,
    external_ip: std::net::IpAddr,
    /// RFC 6156 IPv6 relayed transport. `None` (the default) keeps the historical
    /// IPv4-only behaviour: an explicit `REQUESTED-ADDRESS-FAMILY = IPv6` is
    /// refused with 440. `Some(v6)` is the address advertised in
    /// XOR-RELAYED-ADDRESS for v6 allocations; the relay socket is bound v6.
    /// Set with [`PacketProcessor::with_external_ip6`] so no constructor
    /// signature changes.
    external_ip6: Option<std::net::Ipv6Addr>,
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

/// Rate-limit tiers handed to a [`PacketProcessor`].
///
/// Until 0.5.0 these came only from `TURNA_*` environment variables read inside
/// the constructor, so the values in force were in no config file and no config
/// dump — an operator hitting the Allocate ceiling had nothing to look at.
#[derive(Debug, Clone)]
pub struct RateLimitSettings {
    /// Applied to every source not matched by `trusted_prefixes`.
    pub default: TieredLimits,
    /// Applied to sources inside `trusted_prefixes`.
    pub trusted: TieredLimits,
    /// CIDR ranges whose sources get the `trusted` tier: the offices and VPN
    /// pools where hundreds of users share one NAT address.
    pub trusted_prefixes: Vec<String>,
}

impl RateLimitSettings {
    /// Apply the legacy `TURNA_*` overrides on top of `base`.
    ///
    /// **Deprecated.** Kept because someone may have these exported in a running
    /// deployment right now, and removing them silently would change limits on
    /// the next restart with nothing in the log. Each one that is set warns, and
    /// they go away in the release after next. `[turn.rate_limit]` is the
    /// supported place.
    pub fn env_overrides(base: TieredLimits) -> TieredLimits {
        let mut limits = base;
        let env_pair = |bkey: &str, rkey: &str, pair: &mut (u32, u32)| {
            for (key, slot) in [(bkey, &mut pair.0), (rkey, &mut pair.1)] {
                if let Some(v) = std::env::var(key).ok().and_then(|v| v.parse().ok()) {
                    tracing::warn!(
                        env = key,
                        value = v,
                        "rate limit set through an environment variable; this is \
                         deprecated — move it to [turn.rate_limit] in the config file, \
                         where it is visible in --dump-config"
                    );
                    *slot = v;
                }
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
        limits
    }
}

impl PacketProcessor {
    /// Replace the rate limiters with configured ones.
    ///
    /// A builder, like [`with_external_ip6`](Self::with_external_ip6), so no
    /// constructor signature changes and the call sites that do not have a
    /// config keep working.
    ///
    /// The environment overrides still apply on top, so a deployment that has
    /// them exported keeps its current behaviour (and now says so in the log).
    pub fn with_rate_limits(mut self, settings: &RateLimitSettings) -> Self {
        self.rate_limiter =
            TieredRateLimiter::new(RateLimitSettings::env_overrides(settings.default));
        self.trusted_prefixes =
            crate::peer_filter::parse_ranges(&settings.trusted_prefixes, "trusted_prefixes");
        // No prefixes means no second limiter to keep: `limiter_for` then never
        // looks at the list, and the hot path is byte-identical to before.
        self.trusted_limiter = if self.trusted_prefixes.is_empty() {
            None
        } else {
            tracing::info!(
                prefixes = self.trusted_prefixes.len(),
                // `.1` is the refill rate; `.0` is the burst depth.
                allocate_rps = settings.trusted.allocate.1,
                "trusted rate-limit tier active"
            );
            Some(TieredRateLimiter::new(settings.trusted))
        };
        self
    }

    /// Which limiter governs this source.
    ///
    /// Linear scan: the list is an operator's own prefixes, so single digits in
    /// practice, and `peer_filter` matches its allow/deny lists the same way on
    /// a hotter path.
    #[inline]
    fn limiter_for(&self, ip: std::net::IpAddr) -> &TieredRateLimiter {
        match &self.trusted_limiter {
            Some(trusted) if self.trusted_prefixes.iter().any(|c| c.contains(ip)) => trusted,
            _ => &self.rate_limiter,
        }
    }
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
        let nonce_mgr = NonceManager::with_cookie(Self::nonce_cookie_for(
            &auth,
            ADVERTISE_USERHASH.load(Ordering::Relaxed),
        ));
        Self {
            udp_transactions: crate::udp_transactions::UdpTransactions::new(),
            store,
            auth,
            rate_limiter: TieredRateLimiter::new(RateLimitSettings::env_overrides(
                TieredLimits::default(),
            )),
            trusted_limiter: None,
            trusted_prefixes: Vec::new(),
            // (64, 8): a legitimate client needs single digits of these, ever.
            // Only `per_ip` is consulted; the other tiers are set to the same
            // values rather than left at their generous defaults so that a
            // future caller reaching for one does not get an accidental
            // free pass.
            unauth_reply_limiter: TieredRateLimiter::new(TieredLimits {
                per_ip: (64, 8),
                per_prefix: (512, 64),
                allocate: (64, 8),
                create_permission: (64, 8),
                channel_bind: (64, 8),
            }),
            external_ip,
            external_ip6: None,
            nonce_mgr,
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

    /// The nonce cookie this processor issues, per [`set_advertise_userhash`].
    ///
    /// Withheld (with a warning) unless every realm can resolve a USERHASH:
    /// advertising the bit to a TURN REST client would make it send a hash
    /// that cannot be inverted, and it would never authenticate again. Config
    /// validation refuses that combination first; this is the second line, for
    /// embedders that call the setter without going through the config.
    fn nonce_cookie_for(auth: &AuthRegistry, advertise: bool) -> Option<&'static str> {
        if !advertise {
            return None;
        }
        if !auth.all_realms_support_userhash() {
            warn!(
                "advertise_userhash ignored: a realm on this node uses TURN REST or \
                 OAuth credentials, which cannot resolve a USERHASH"
            );
            return None;
        }
        Some(USERHASH_NONCE_COOKIE)
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
        // Mirrored here rather than at the eviction site: the counter lives in
        // turna-qos, which has no Metrics handle, and this runs on the same
        // five-second sweep that already visits the limiter.
        self.metrics.rate_limiter_evictions.store(
            self.rate_limiter.evictions()
                + self
                    .trusted_limiter
                    .as_ref()
                    .map(|t| t.evictions())
                    .unwrap_or(0),
            Ordering::Relaxed,
        );
        // The trusted limiter holds its own per-IP buckets and would otherwise
        // grow without bound — the leak would be invisible, because the tier
        // that leaks is the one serving the busiest sources.
        if let Some(trusted) = &self.trusted_limiter {
            trusted.cleanup(max_age_secs);
        }
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

    /// Release the allocation owned by `client` because its **control
    /// connection** went away (a TURNS/TCP connection closed, or a DTLS/QUIC
    /// session ended).
    ///
    /// For the connection-oriented transports the allocation's 5-tuple ceases
    /// to exist the moment the connection does, so leaving it to expire by TTL
    /// held the relay port (and its fd) for up to a full lifetime and let a
    /// later client reusing the same source port inherit the 437 conflict.
    ///
    /// Implemented as a zero-lifetime refresh — the same teardown the client
    /// would trigger with `Refresh(lifetime=0)` — so allocation accounting and
    /// port release follow exactly one code path. Returns the actions the
    /// caller must dispatch (`CloseRelay` for the relay socket), empty if this
    /// address had no allocation.
    ///
    /// This is sync, so it does NOT touch the RFC 6062 peer connections
    /// (`TcpRelayManager::cleanup_allocation` is async): the TURNS bridge does
    /// that itself right after calling this.
    pub fn release_for_closed_connection(&self, client: SocketAddr) -> Vec<Action> {
        let relay_port = self.store.get(&client).map(|a| a.relay_addr.port());
        let Some(port) = relay_port else {
            return Vec::new();
        };
        if self.store.refresh(&client, 0).is_err() {
            return Vec::new();
        }
        self.metrics
            .active_allocations
            .fetch_sub(1, Ordering::Relaxed);
        tracing::debug!(
            %client,
            relay_port = port,
            "allocation released: control connection closed"
        );
        vec![Action::CloseRelay { port }]
    }

    /// Called only after QUIC has validated a new network path for the same
    /// connection. Unlike RFC 8016 this is not a client-supplied mobility ticket.
    /// Re-key every allocation index before the bridge starts using the new src.
    pub fn migrate_quic_allocation(
        &self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) -> Result<(), SessionError> {
        if old_addr == new_addr {
            return Ok(());
        }
        if self.store.get(&old_addr).is_some() {
            self.store.re_key(&old_addr, new_addr).map(|_| ())
        } else if self.store.get(&new_addr).is_some() {
            Err(SessionError::MigrationTargetInUse)
        } else {
            // A session may migrate before its first Allocate.
            Ok(())
        }
    }

    /// Owned-buffer ingress for the encrypted session transports (DTLS records,
    /// QUIC datagrams, WebTransport stream messages).
    ///
    /// These transports decrypt into an owned `Vec<u8>` and deliver it through a
    /// channel, so there is no kernel-registered recv buffer to send from. They
    /// therefore MUST NOT use [`process_slice`], which emits
    /// [`Action::ForwardZeroCopy`] (offset/len into the caller's slice) for the
    /// ChannelData hot path: `RelayEgress::dispatch` cannot resolve an
    /// offset/len back into bytes, so every client→peer media packet was being
    /// dropped. This entry point takes the buffer by value and always goes
    /// through the owning [`process`] pipeline, which emits
    /// [`Action::Forward`] with real `Bytes`.
    ///
    /// `ingress_tcp` is false: RFC 6062 TCP allocations require a TCP/TLS
    /// control connection with a second connection for ConnectionBind, which
    /// these transports do not provide.
    pub fn process_owned(&self, raw: Vec<u8>, src: SocketAddr) -> Vec<Action> {
        self.process_impl(Bytes::from(raw), src, false)
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
            if !self.limiter_for(src.ip()).check_ingress_ip(src.ip()) {
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
        if !self.limiter_for(src.ip()).check_ingress(src.ip()) {
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
            if !self.limiter_for(src.ip()).check_ingress_ip(src.ip()) {
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
            debug!(peer_addr = %loggable_addr(&peer_addr), "bandwidth quota exceeded, dropping relay->client packet");
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
            debug!(src = %loggable_addr(&src), "bandwidth quota exceeded, dropping packet");
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
                if let Some(occurrences) = DECODE_ERROR_LOG.should_log() {
                    warn!(src = %loggable_addr(&src), %e, occurrences, "STUN decode error");
                }
                self.metrics
                    .parser_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return vec![Action::None];
            }
        };

        let cacheable = !ingress_tcp
            && raw.len() <= 4096
            && matches!(msg.class, MessageClass::Request)
            && msg.has_user_identity()
            && (matches!(msg.method, Method::Refresh)
                || (matches!(msg.method, Method::Allocate)
                    && msg.get_requested_transport() == Some(17)));
        if cacheable {
            // Serializes duplicate transactions through mutation and publication.
            // Only response bytes are replayed: never RegisterRelay/CloseRelay.
            let mut cache = self.udp_transactions.lock(src);
            cache.expire(Instant::now());
            match cache.lookup(src, &raw) {
                crate::udp_transactions::Lookup::Reply(data) => {
                    self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .bytes_sent
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    return vec![Action::Send { data, target: src }];
                }
                crate::udp_transactions::Lookup::Conflict => return vec![Action::None],
                crate::udp_transactions::Lookup::Miss => {}
            }
            let actions = self.dispatch_stun(&msg, &raw, src, ingress_tcp);
            for action in &actions {
                if let Action::Send { data, target } = action {
                    if *target == src
                        && data.len() >= 20
                        && data[0] & 0x01 != 0
                        && data[1] & 0x10 == 0
                    {
                        cache.insert(src, raw.clone(), data.clone(), Instant::now());
                        break;
                    }
                }
            }
            return actions;
        }
        self.dispatch_stun(&msg, &raw, src, ingress_tcp)
    }

    fn dispatch_stun(
        &self,
        msg: &StunMessage,
        raw: &Bytes,
        src: SocketAddr,
        ingress_tcp: bool,
    ) -> Vec<Action> {
        if matches!(msg.class, MessageClass::Request) {
            // I3: reject unknown comprehension-required attributes with 420 before
            // routing/auth — a request we can't parse must not be redirected.
            // `false`: this is the TURN listener, which has no alternate
            // address, so CHANGE-REQUEST is refused here too (RFC 5780 §6).
            if let Some(actions) = self.reject_unknown_comprehension_required(msg, src, false) {
                return actions;
            }
            if let Some(actions) = self.maybe_redirect_new_client(msg, src) {
                return actions;
            }
        }

        match (&msg.class, &msg.method) {
            (MessageClass::Request, Method::Binding) => self.handle_binding(msg, raw, src),
            (MessageClass::Request, Method::Allocate) => {
                if !self.limiter_for(src.ip()).check_allocate(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_allocate(msg, raw, src, ingress_tcp)
            }
            (MessageClass::Request, Method::Refresh) => self.handle_refresh(msg, raw, src),
            (MessageClass::Request, Method::CreatePermission) => {
                if !self.limiter_for(src.ip()).check_create_permission(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_create_permission(msg, raw, src)
            }
            (MessageClass::Request, Method::ChannelBind) => {
                if !self.limiter_for(src.ip()).check_channel_bind(src.ip()) {
                    self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return self.encode_error(msg, src, 486, "Allocation Quota Reached");
                }
                self.handle_channel_bind(msg, raw, src)
            }
            (MessageClass::Indication, Method::Send) => self.handle_send_indication(msg, raw, src),
            _ => vec![Action::None],
        }
    }

    /// I3 (RFC 5389 §7.3.1): answer 420 UNKNOWN-ATTRIBUTES for comprehension-
    /// required (type < 0x8000) attributes we didn't understand. 0x001C
    /// (MESSAGE-INTEGRITY-SHA256) and 0x001D (PASSWORD-ALGORITHM) are understood
    /// despite being parsed generically, so they never trigger 420.
    ///
    /// CHANGE-REQUEST decodes to a typed attribute, but RFC 5780 §6 requires a
    /// server that cannot answer from an alternate address to refuse it with
    /// 420 — which is every socket except the NAT-discovery ones. Only the
    /// discovery responder passes `change_request_ok = true`. PADDING and
    /// RESPONSE-PORT stay untyped and are refused everywhere (see
    /// `handle_nat_discovery`).
    fn reject_unknown_comprehension_required(
        &self,
        msg: &StunMessage,
        src: SocketAddr,
        change_request_ok: bool,
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
                Attribute::ChangeRequest { .. } if !change_request_ok => {
                    Some(turna_proto_stun::attribute::ATTR_CHANGE_REQUEST)
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
            src = %loggable_addr(&src),
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

    /// May this address be sent an unauthenticated reply right now?
    ///
    /// Silence is the correct refusal: answering "you are rate limited" is
    /// itself an unauthenticated reply to a possibly-spoofed address, which is
    /// the thing being limited.
    fn allow_unauth_reply(&self, src: SocketAddr) -> bool {
        if self.unauth_reply_limiter.check_ingress_ip(src.ip()) {
            return true;
        }
        self.metrics
            .unauth_replies_suppressed
            .fetch_add(1, Ordering::Relaxed);
        if let Some(occurrences) = UNAUTH_BUDGET_LOG.should_log() {
            warn!(
                src = %loggable_addr(&src),
                occurrences,
                "unauthenticated-reply budget exhausted for this source; dropping \
                 silently. Sustained, this is reflection: the source address of a \
                 spoofed request is the victim the reply would be aimed at."
            );
        }
        false
    }

    fn handle_binding(&self, msg: &StunMessage, raw: &[u8], src: SocketAddr) -> Vec<Action> {
        // Reflection budget. A Binding response is 48 bytes for a 20-byte
        // request and needs no credentials, so the only thing between a spoofed
        // request and the victim is how many replies this node will emit to one
        // address.
        if !self.allow_unauth_reply(src) {
            return vec![Action::None];
        }
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
        // SOFTWARE is optional (RFC 5389 §15.10) and this response is
        // unauthenticated, so whatever goes here is handed to anyone who sends
        // 20 bytes — including a scanner matching versions against CVE lists.
        // It is also ~16 bytes of free amplification on a reflected Binding.
        //
        // `product` is the production default: enough for an operator debugging
        // interop to see which implementation answered, without naming the
        // release. `full` stays available outside production, where knowing the
        // exact build is worth more than hiding it.
        if let Some(sw) = software_attribute() {
            resp.add(Attribute::Software(sw.into()));
        }

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

    /// RFC 5780 NAT behaviour discovery: answer a Binding request that arrived
    /// on one of the four discovery sockets (`local` is that socket's address).
    ///
    /// Returns the response and the address it must be **sent from**, which is
    /// the point of the exercise — the caller owns the four sockets and picks
    /// the one bound to that address. `None` means drop silently.
    ///
    /// Everything that guards the TURN listener's Binding path guards this one:
    /// the configured ingress tiers, then the unauthenticated-reply budget,
    /// because a discovery response is an unauthenticated reply like any other
    /// and a slightly larger one (MAPPED-ADDRESS, RESPONSE-ORIGIN and
    /// OTHER-ADDRESS on top of XOR-MAPPED-ADDRESS). Two reflection vectors the
    /// RFC itself names are closed by not implementing their attributes:
    /// PADDING (§7.6, "divide the message into IP fragments") and RESPONSE-PORT
    /// (§7.5, send somewhere other than the source) are comprehension-required
    /// and answered 420, so a response always goes to the request's source
    /// address and is never padded. Both are optional for a server.
    ///
    /// Only Binding is served. A TURN method here is dropped, not answered:
    /// these sockets are not a TURN listener, and replying would advertise
    /// one.
    pub fn handle_nat_discovery(
        &self,
        raw: &[u8],
        src: SocketAddr,
        local: SocketAddr,
        topology: &crate::nat_discovery::NatDiscoveryTopology,
    ) -> Option<(Bytes, SocketAddr)> {
        self.metrics
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(raw.len() as u64, Ordering::Relaxed);
        if !message::is_stun_message(raw) {
            self.metrics
                .malformed_packets
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if !self.limiter_for(src.ip()).check_ingress(src.ip()) {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let msg = match StunMessage::decode(raw) {
            Ok(m) => m,
            Err(_) => {
                // Silent, as on the TURN listener: an error answer to garbage
                // is a reflection vector.
                self.metrics
                    .parser_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if !matches!(
            (&msg.class, &msg.method),
            (MessageClass::Request, Method::Binding)
        ) {
            return None;
        }
        // Every reply from here on — 420, 401 or success — is unauthenticated
        // (or not yet authenticated), so the budget is charged first.
        if !self.allow_unauth_reply(src) {
            return None;
        }
        if let Some(actions) = self.reject_unknown_comprehension_required(&msg, src, true) {
            // 420 goes out from the socket the request arrived on (Da:Dp).
            return actions.into_iter().find_map(|a| match a {
                Action::Send { data, .. } => Some((data, local)),
                _ => None,
            });
        }
        // Same rule as `handle_binding`: MESSAGE-INTEGRITY, when present, must
        // verify. A failure is a 401 from Da:Dp.
        let has_integrity =
            msg.get_message_integrity().is_some() || msg.get_message_integrity_sha256().is_some();
        if has_integrity && self.auth_validate(&msg, raw).is_err() {
            self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            // The challenge re-checks the budget; one reply was already allowed
            // for this request, so charge it once and build the 401 directly.
            let realm = self.auth.default_realm();
            let nonce = self.nonce_mgr.issue(src);
            let resp = turn::build_auth_challenge(msg.method, msg.transaction_id, realm, &nonce);
            let mut buf = [0u8; 512];
            let len = resp.encode(&mut buf).ok()?;
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(len as u64, Ordering::Relaxed);
            return Some((Bytes::copy_from_slice(&buf[..len]), local));
        }

        // RFC 5780 §6.1, Table 1: the source of the response follows the
        // CHANGE-REQUEST flags; OTHER-ADDRESS is Ca:Cp whatever they say.
        let (change_ip, change_port) = msg.get_change_request().unwrap_or((false, false));
        let from = topology.response_source(local, change_ip, change_port)?;
        let other = topology.other_address(local)?;

        let mut resp = StunMessage::with_transaction_id(
            Method::Binding,
            MessageClass::SuccessResponse,
            msg.transaction_id,
        );
        // §6.1: "The server MUST include both MAPPED-ADDRESS and
        // XOR-MAPPED-ADDRESS in its Response."
        resp.add(Attribute::XorMappedAddress(src));
        resp.add(Attribute::MappedAddress(src));
        // §6.1: RESPONSE-ORIGIN is the address actually sent from; OTHER-ADDRESS
        // is included because this server has an alternate address and port.
        resp.add(Attribute::ResponseOrigin(from));
        resp.add(Attribute::OtherAddress(other));
        if let Some(sw) = software_attribute() {
            resp.add(Attribute::Software(sw.into()));
        }
        let mut buf = [0u8; 256];
        let len = resp.encode(&mut buf).ok()?;
        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);
        Some((Bytes::copy_from_slice(&buf[..len]), from))
    }

    fn handle_allocate(
        &self,
        msg: &StunMessage,
        raw: &[u8],
        src: SocketAddr,
        ingress_tcp: bool,
    ) -> Vec<Action> {
        // A3-L1: authenticate first (RFC 5766 §6.2). Running the 437/442 checks
        // before auth let an unauthenticated client probe whether an allocation
        // already exists on this 5-tuple (437 vs 401 disclosure). Challenge and
        // validate first, then do the allocation-mismatch / transport checks.
        if !msg.has_user_identity() {
            return self.encode_auth_challenge(msg, src);
        }
        if let Some(stale) = self.validate_nonce(msg, src) {
            return stale;
        }

        let resolution = match self.auth_validate(msg, raw) {
            Ok(r) => r,
            Err(e) => {
                if let Some(occurrences) = AUTH_FAILED_LOG.should_log() {
                    warn!(src = %loggable_addr(&src), %e, occurrences, "auth failed");
                }
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
        // Drain is reported only to a client that proved who it is.
        //
        // This check used to sit above the challenge — seven lines above the
        // comment that explains why 437 and 442 were moved *below* it, for
        // exactly the same two reasons. A 508 before authentication is an
        // unauthenticated reply to a source address that may be spoofed, so it
        // both amplifies and tells a scanner the node's lifecycle state. The
        // client that needs to know a node is draining is a real client, and it
        // finds out one round trip later: 401 challenge, credentials, then 508
        // (or 300 Try Alternate in a cluster).
        if self.metrics.is_draining() {
            return self.encode_error(msg, src, 508, "Server Draining");
        }

        // The identity quotas are keyed on. For TURN REST this is the USERNAME
        // without its `<expiry>:` prefix, so a fresh credential does not read as
        // a fresh person — see `AuthMode::subject_of`.
        let subject = resolution.subject;

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
                AuthedIdentity {
                    key: key.clone(),
                    realm: realm.clone(),
                    tenant_id: tenant_id.clone(),
                    subject: subject.clone(),
                },
                token_max_lifetime,
            );
        }

        // RFC 8656 §14.1 / §7.2 + RFC 6156: REQUESTED-ADDRESS-FAMILY. An IPv6
        // request is honoured only when this node was given a v6 address to
        // advertise (`with_external_ip6`); otherwise it is still refused with 440,
        // because handing out a relayed candidate we cannot route is worse than an
        // honest refusal. A malformed attribute was already rejected at parse
        // time. §7.2 also makes REQUESTED-ADDRESS-FAMILY and RESERVATION-TOKEN
        // mutually exclusive.
        let relay_family = match msg.get_requested_address_family() {
            None | Some(turna_proto_stun::attribute::AddressFamily::Ipv4) => {
                turna_session::RelayFamily::V4
            }
            Some(turna_proto_stun::attribute::AddressFamily::Ipv6) => {
                if self.external_ip6.is_none() {
                    return self.encode_error(msg, src, 440, "Address Family not Supported");
                }
                turna_session::RelayFamily::V6
            }
        };
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
            match pool.allocate_even_and_bind_family(reserve_next, relay_family) {
                Some(x) => x,
                None => return self.encode_error(msg, src, 508, "Insufficient Capacity"),
            }
        } else {
            match pool.allocate_and_bind_family(relay_family) {
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
            if let Err(e) = set_dont_fragment(relay_sock.as_raw_fd(), relay_family) {
                warn!(src = %loggable_addr(&src), %e, "DONT-FRAGMENT: failed to set DF on relay socket");
            }
        }

        // Advertise the address matching the family the socket was bound in.
        let relay_addr = match relay_family {
            turna_session::RelayFamily::V6 => SocketAddr::new(
                std::net::IpAddr::V6(
                    self.external_ip6
                        .expect("V6 is only selected when external_ip6 is set"),
                ),
                relay_port,
            ),
            turna_session::RelayFamily::V4 => SocketAddr::new(self.external_ip, relay_port),
        };
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
        // Kept for the log line below; accounting uses `subject`. A USERHASH
        // request has no USERNAME to log, and logging the hash would only
        // re-identify what the client chose to hide; `subject` already names
        // the user for the operator.
        let credential = msg.get_username().unwrap_or("(userhash)").to_string();
        let (dynamic_lifetime, lifetime_disabled) =
            self.store
                .lifetime_policy_for_user(&realm, tenant_id.as_deref(), &subject);
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

        // `subject`, not the raw USERNAME: the allocation's identity field is
        // what every quota and every `set_user_limits` override keys on, and for
        // TURN REST the raw string carries an expiry that changes per credential.
        // The credential itself is logged below, so the audit trail keeps it.
        if let Err(e) = self.store.create_for_identity(
            src,
            relay_addr,
            subject.clone(),
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
        info!(src = %loggable_addr(&src), %relay_addr, lifetime, subject = %subject, %credential, "allocation created");
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
        identity: AuthedIdentity,
        token_max_lifetime: Option<u32>,
    ) -> Vec<Action> {
        let AuthedIdentity {
            key,
            realm,
            tenant_id,
            subject,
        } = identity;
        // RFC 6062 §4.1: EVEN-PORT / RESERVATION-TOKEN / DONT-FRAGMENT MUST NOT
        // appear with a TCP allocation.
        let has_df = msg
            .attributes
            .iter()
            .any(|a| matches!(a, turna_proto_stun::attribute::Attribute::DontFragment));
        if msg.get_even_port().is_some() || msg.get_reservation_token().is_some() || has_df {
            return self.encode_error(msg, src, 400, "Bad Request");
        }
        // RFC 6062 TCP allocations stay IPv4-only even when `external_ip6` is set:
        // the TCP relay datapath has no v6 path yet, so an IPv6 family request is
        // refused with 440 rather than accepted and then unable to CONNECT.
        //
        // Two ways a v6 family can arrive here, and BOTH have to be refused:
        //
        //  1. the client asks for it (REQUESTED-ADDRESS-FAMILY = IPv6);
        //  2. the operator configured `[turn] external_ip` as a v6 literal, which
        //     `config::validate()` accepts and nothing downstream ties to
        //     `tcp_relay`. The client sends no family attribute, so case 1 never
        //     fires — yet `relay_addr` below is built from `self.external_ip` and
        //     would advertise a v6 XOR-RELAYED-ADDRESS while the relayed listener
        //     binds `0.0.0.0`. The Allocate would SUCCEED and peer-initiated
        //     connections (RFC 6062 §4.4) could never arrive at the address the
        //     client was just handed, with nothing logged and no error anywhere.
        //
        // Case 2 is the dangerous one precisely because it looks like it worked.
        // Refusing with the same 440 keeps the observable behaviour equal to what
        // docs/feature-support.md already promises ("an IPv6 TCP allocation answers
        // 440") instead of splitting it by how the family was chosen.
        let requested_v6 = matches!(
            msg.get_requested_address_family(),
            Some(turna_proto_stun::attribute::AddressFamily::Ipv6)
        );
        if requested_v6 || self.external_ip.is_ipv6() {
            if !requested_v6 {
                warn!(
                    external_ip = %self.external_ip,
                    "RFC 6062: refusing TCP allocation because [turn] external_ip is IPv6 \
                     and the TCP relay datapath is IPv4-only; the relayed listener would \
                     bind 0.0.0.0 and never receive peer-initiated connections"
                );
            }
            return self.encode_error(msg, src, 440, "Address Family not Supported");
        }

        let mut lifetime = msg
            .get_lifetime()
            .unwrap_or(turn::DEFAULT_LIFETIME)
            .min(turn::MAX_LIFETIME);
        if let Some(max) = token_max_lifetime {
            lifetime = lifetime.min(max);
        }
        // Kept for the log line below; accounting uses `subject`. A USERHASH
        // request has no USERNAME to log, and logging the hash would only
        // re-identify what the client chose to hide; `subject` already names
        // the user for the operator.
        let credential = msg.get_username().unwrap_or("(userhash)").to_string();
        let (dynamic_lifetime, lifetime_disabled) =
            self.store
                .lifetime_policy_for_user(&realm, tenant_id.as_deref(), &subject);
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
        // Same bind address as the UDP relay sockets: a TCP allocation that
        // listened on every interface while the UDP ones were pinned to the
        // public address would reopen on the private side exactly the surface
        // `[turn.relay] bind_ip` exists to close.
        let listener =
            match std::net::TcpListener::bind((turna_session::relay_bind_addr_v4(), relay_port)) {
                Ok(l) => l,
                Err(e) => {
                    warn!(%relay_addr, error = %e, "RFC 6062: relayed TCP listener bind failed");
                    return self.encode_error(msg, src, 508, "Insufficient Capacity");
                }
            };

        if let Err(e) = self.store.create_for_identity(
            src,
            relay_addr,
            subject.clone(),
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
        info!(src = %loggable_addr(&src), %relay_addr, lifetime, subject = %subject, %credential, "TCP allocation created (RFC 6062)");
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
        if !msg.has_user_identity() {
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

    /// RFC 6156 §4.2: a relayed transport address can only reach peers in its own
    /// address family. Returns true when `peer` does not match the allocation's
    /// relayed family, which the callers answer with **443 Peer Address Family
    /// Mismatch**. Peers are already normalised (`::ffff:` → v4) before this, so
    /// a v4-mapped literal is compared as v4.
    fn peer_family_mismatch(&self, src: &SocketAddr, peer: &std::net::IpAddr) -> bool {
        match self.store.get(src) {
            Some(a) => a.relay_addr.is_ipv6() != peer.is_ipv6(),
            // No allocation: the caller's own 437 path reports that; do not turn it
            // into a 443.
            None => false,
        }
    }

    /// Enable RFC 6156 IPv6 relayed transport by giving the address to advertise
    /// in XOR-RELAYED-ADDRESS for v6 allocations. Additive builder so the four
    /// existing constructors keep their signatures.
    ///
    /// Without this, `REQUESTED-ADDRESS-FAMILY = IPv6` stays refused with 440 —
    /// which is the correct answer for a node that has no routable v6 address to
    /// hand out.
    pub fn with_external_ip6(mut self, ip6: Option<std::net::Ipv6Addr>) -> Self {
        self.external_ip6 = ip6;
        self
    }

    /// In-place form of [`with_external_ip6`], for callers that already own the
    /// processor by `&mut` (see `RelayServer::with_external_ip6`, which reaches it
    /// through `Arc::get_mut` immediately after construction).
    pub fn set_external_ip6(&mut self, ip6: Option<std::net::Ipv6Addr>) {
        self.external_ip6 = ip6;
    }

    /// The relayed address family this node can offer, for diagnostics.
    pub fn relay_ipv6_enabled(&self) -> bool {
        self.external_ip6.is_some()
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
        if !msg.has_user_identity() {
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
        if !msg.has_user_identity() {
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
        let subject = resolution.subject;

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
            // The raw USERNAME, as before. A USERHASH request has none; for it
            // the resolved name stands in, which for a long-term user — the only
            // kind a USERHASH can resolve to — is the same string.
            let username = msg.get_username().unwrap_or(subject.as_str());
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
        info!(
            src = %loggable_addr(&src),
            old_addr = %loggable_addr(&old_addr),
            %relay_addr,
            "allocation migrated (RFC 8016)"
        );

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
        if !msg.has_user_identity() {
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
                warn!(src = %loggable_addr(&src), peer_ip = %loggable_ip(peer_ip), "CreatePermission to forbidden peer denied");
                self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
                return self.encode_error(msg, src, 403, "Forbidden");
            }
            // RFC 6156 §4.2: the relayed address family is fixed at Allocate; a
            // peer in the other family is unreachable through this relay socket.
            // Refuse the whole request rather than install a permission that can
            // never carry traffic.
            if self.peer_family_mismatch(&src, peer_ip) {
                warn!(src = %loggable_addr(&src), peer_ip = %loggable_ip(peer_ip), "CreatePermission peer address family mismatch");
                self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
                return self.encode_error(msg, src, 443, "Peer Address Family Mismatch");
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
        if !msg.has_user_identity() {
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
            warn!(src = %loggable_addr(&src), peer = %loggable_ip(&peer_addr.ip()), "ChannelBind to forbidden peer denied");
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return self.encode_error(msg, src, 403, "Forbidden");
        }
        // RFC 6156 §4.2: see `peer_family_mismatch`.
        if self.peer_family_mismatch(&src, &peer_addr.ip()) {
            warn!(src = %loggable_addr(&src), peer = %loggable_ip(&peer_addr.ip()), "ChannelBind peer address family mismatch");
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return self.encode_error(msg, src, 443, "Peer Address Family Mismatch");
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
        // RFC 6156 §4.2 family mismatch. An indication has no error response, so
        // this is a counted silent drop rather than a 443.
        if self.peer_family_mismatch(&src, &peer_addr.ip()) {
            self.metrics.peer_rejected.fetch_add(1, Ordering::Relaxed);
            return vec![Action::None];
        }

        // DONT-FRAGMENT: drop if payload exceeds MTU.
        let has_dont_fragment = msg
            .attributes
            .iter()
            .any(|a| matches!(a, turna_proto_stun::attribute::Attribute::DontFragment));
        if has_dont_fragment && data.len() > self.mtu as usize {
            debug!(src = %loggable_addr(&src), len = data.len(), mtu = self.mtu, "DONT-FRAGMENT: packet too large, dropping");
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
            debug!(src = %loggable_addr(&src), "bandwidth quota exceeded, dropping Send indication");
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
        // A 401 is also an unauthenticated reply, and a larger one than a
        // Binding response. It shares the budget.
        if !self.allow_unauth_reply(dst) {
            return vec![Action::None];
        }
        let realm = self.auth.default_realm();
        let nonce = self.nonce_mgr.issue(dst);
        // RFC 7635 §6.1: when the base realm uses OAuth, advertise the
        // authorization server in the 401 so a token-less client learns where to
        // obtain a token; otherwise send the standard credential challenge.
        // Owned `String` since the registry's backend moved behind an ArcSwap;
        // `as_id.as_bytes()` below is unchanged.
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
    /// A deliberately invalid nonce, from the environment. Not a secret.
    fn bad_nonce() -> String {
        std::env::var("TURNA_TEST_BAD_NONCE_GARBLED")
            .expect("TURNA_TEST_BAD_NONCE_GARBLED is not set — source .env.test")
    }

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
        assert!(matches!(mgr.validate(a, &bad_nonce()), NonceStatus::Stale));
    }

    fn test_processor() -> PacketProcessor {
        let store = Arc::new(AllocationStore::new(49152, 65535, 1000));
        let auth = Arc::new(AuthRegistry::new(AuthMode::SharedSecret {
            realm: "turna".into(),
            secret: std::env::var("TURNA_TEST_NONCE_SECRET")
                .expect("TURNA_TEST_NONCE_SECRET is not set — source .env.test")
                .into_bytes(),
            previous: None,
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
        set_dont_fragment(sock.as_raw_fd(), turna_session::RelayFamily::V4)
            .expect("setsockopt IP_MTU_DISCOVER should succeed");

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

    #[cfg(target_os = "linux")]
    #[test]
    fn set_dont_fragment_uses_the_v6_knob_on_a_v6_socket() {
        // Regression guard for the family split: IPPROTO_IP on an AF_INET6 socket
        // does not set DF, so a v6 allocation with DONT-FRAGMENT would silently
        // fragment.
        let sock = match std::net::UdpSocket::bind("[::1]:0") {
            Ok(s) => s,
            // A host with IPv6 disabled (EAFNOSUPPORT) cannot exercise this;
            // skip rather than report a failure that is about the environment,
            // as `session::v6only_tests` does.
            Err(e) => {
                eprintln!("skipping: no IPv6 on this host ({e})");
                return;
            }
        };
        set_dont_fragment(sock.as_raw_fd(), turna_session::RelayFamily::V6)
            .expect("setsockopt IPV6_MTU_DISCOVER should succeed");

        let mut val: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt IPV6_MTU_DISCOVER failed");
        assert_eq!(val, libc::IP_PMTUDISC_DO);
    }
}

#[cfg(test)]
mod udp_replay_tests {
    use super::*;

    fn test_password() -> &'static str {
        static PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PASSWORD
            .get_or_init(|| {
                turna_crypto::random_key_32()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .as_str()
    }

    fn processor() -> PacketProcessor {
        PacketProcessor::new(
            Arc::new(AllocationStore::new(24000, 24999, 128)),
            Arc::new(AuthRegistry::new(turna_auth::AuthMode::long_term(
                "retry-test",
                [("retry", test_password())],
            ))),
            "127.0.0.1".parse().unwrap(),
            Arc::new(Metrics::new()),
        )
    }
    fn request(p: &PacketProcessor, src: SocketAddr, method: Method, lifetime: u32) -> Bytes {
        let mut msg = StunMessage::new(method, MessageClass::Request);
        if matches!(method, Method::Allocate) {
            msg.add(Attribute::RequestedTransport(17));
        }
        msg.add(Attribute::Lifetime(lifetime));
        msg.add(Attribute::Username("retry".into()));
        msg.add(Attribute::Realm("retry-test".into()));
        msg.add(Attribute::Nonce(p.nonce_mgr.issue(src)));
        let mut buf = [0; 1024];
        let n = msg
            .encode_with_integrity(
                &mut buf,
                &turna_crypto::long_term_key("retry", "retry-test", test_password()),
            )
            .unwrap();
        Bytes::copy_from_slice(&buf[..n])
    }
    fn response(actions: &[Action]) -> Bytes {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Send { data, .. } => Some(data.clone()),
                _ => None,
            })
            .unwrap()
    }
    #[test]
    fn udp_replay_lost_allocate_and_delete_responses() {
        let p = processor();
        let src = "127.0.0.1:40111".parse().unwrap();
        let alloc = request(&p, src, Method::Allocate, 600);
        // Keep the bound relay socket alive, as a real action executor does.
        let first = p.process(alloc.clone(), src);
        assert!(matches!(
            StunMessage::decode(&response(&first)).unwrap().class,
            MessageClass::SuccessResponse
        ));
        assert!(first
            .iter()
            .any(|a| matches!(a, Action::RegisterRelay { .. })));
        let repeated = p.process(alloc.clone(), src);
        assert_eq!(repeated.len(), 1);
        assert_eq!(response(&first), response(&repeated));
        assert_eq!(p.metrics.total_allocations.load(Ordering::Relaxed), 1);
        let delete = request(&p, src, Method::Refresh, 0);
        let deleted = p.process(delete.clone(), src);
        assert!(deleted
            .iter()
            .any(|a| matches!(a, Action::CloseRelay { .. })));
        let repeated = p.process(delete, src);
        assert_eq!(repeated.len(), 1);
        assert_eq!(response(&deleted), response(&repeated));
        assert_eq!(p.metrics.active_allocations.load(Ordering::Relaxed), 0);
        // Delayed old Allocate must not resurrect the released allocation.
        assert_eq!(response(&first), response(&p.process(alloc, src)));
        assert!(p.store.get(&src).is_none());
    }
    #[test]
    fn udp_replay_changed_bytes_and_concurrent_duplicates() {
        let p = Arc::new(processor());
        let src = "127.0.0.1:40112".parse().unwrap();
        let raw = request(&p, src, Method::Allocate, 600);
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let p = p.clone();
                let raw = raw.clone();
                std::thread::spawn(move || p.process(raw, src))
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            results
                .iter()
                .flatten()
                .filter(|a| matches!(a, Action::RegisterRelay { .. }))
                .count(),
            1
        );
        for r in &results {
            assert_eq!(response(r), response(&results[0]));
        }
        let mut changed = raw.to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(matches!(
            p.process(Bytes::from(changed), src).as_slice(),
            [Action::None]
        ));
        assert_eq!(p.metrics.total_allocations.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod userhash_tests {
    //! RFC 8489 USERHASH through the processor: a request that names its user
    //! by hash is authenticated like one that names it by USERNAME, and is
    //! accounted to the same subject.
    use super::*;
    use turna_proto_stun::attribute::ATTR_USERHASH;

    const REALM: &str = "hash-test";

    fn password() -> &'static str {
        static PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        PASSWORD
            .get_or_init(|| {
                turna_crypto::random_key_32()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .as_str()
    }

    fn long_term_processor() -> PacketProcessor {
        PacketProcessor::new(
            Arc::new(AllocationStore::new(25000, 25999, 128)),
            Arc::new(AuthRegistry::new(turna_auth::AuthMode::long_term(
                REALM,
                [("alice", password())],
            ))),
            "127.0.0.1".parse().unwrap(),
            Arc::new(Metrics::new()),
        )
    }

    /// A request naming `user` by USERHASH only, signed with
    /// MESSAGE-INTEGRITY-SHA256 under `pass`.
    fn hashed_request(
        p: &PacketProcessor,
        src: SocketAddr,
        method: Method,
        user: &str,
        pass: &str,
        extra: Vec<Attribute>,
    ) -> Bytes {
        let mut msg = StunMessage::new(method, MessageClass::Request);
        for a in extra {
            msg.add(a);
        }
        msg.add(Attribute::UserHash(turna_crypto::userhash(user, REALM)));
        msg.add(Attribute::Realm(REALM.into()));
        msg.add(Attribute::Nonce(p.nonce_mgr.issue(src)));
        let key = turna_crypto::long_term_key_sha256(user, REALM, pass);
        let mut buf = [0; 1024];
        let n = msg.encode_with_integrity_sha256(&mut buf, &key).unwrap();
        Bytes::copy_from_slice(&buf[..n])
    }

    fn reply(actions: &[Action]) -> StunMessage {
        actions
            .iter()
            .find_map(|a| match a {
                Action::Send { data, .. } => Some(StunMessage::decode(data).unwrap()),
                _ => None,
            })
            .expect("a reply")
    }

    fn error_code(msg: &StunMessage) -> Option<u16> {
        msg.attributes.iter().find_map(|a| match a {
            Attribute::ErrorCode { code, .. } => Some(*code),
            _ => None,
        })
    }

    /// The 420 this replaces: USERHASH (0x001E) is comprehension-required, and
    /// before it had a typed variant every request carrying it was refused as
    /// an unknown attribute.
    #[test]
    fn userhash_allocate_refresh_permission_succeed() {
        let p = long_term_processor();
        let src: SocketAddr = "127.0.0.1:41001".parse().unwrap();

        let alloc = hashed_request(
            &p,
            src,
            Method::Allocate,
            "alice",
            password(),
            vec![Attribute::RequestedTransport(17), Attribute::Lifetime(600)],
        );
        let actions = p.process(alloc, src);
        let resp = reply(&actions);
        assert!(
            matches!(resp.class, MessageClass::SuccessResponse),
            "USERHASH Allocate must succeed, got {:?}",
            error_code(&resp)
        );
        // Signed with the SHA-256 key the client used (RFC 8489 §9.2.4).
        assert!(resp.get_message_integrity_sha256().is_some());
        // Accounted to the resolved user, not to an empty USERNAME.
        assert_eq!(p.store.get(&src).unwrap().username, "alice");

        let perm = hashed_request(
            &p,
            src,
            Method::CreatePermission,
            "alice",
            password(),
            vec![Attribute::XorPeerAddress("8.8.8.8:9".parse().unwrap())],
        );
        assert!(matches!(
            reply(&p.process(perm, src)).class,
            MessageClass::SuccessResponse
        ));

        let refresh = hashed_request(
            &p,
            src,
            Method::Refresh,
            "alice",
            password(),
            vec![Attribute::Lifetime(0)],
        );
        let actions = p.process(refresh, src);
        assert!(matches!(
            reply(&actions).class,
            MessageClass::SuccessResponse
        ));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::CloseRelay { .. })));
    }

    #[test]
    fn unknown_userhash_is_challenged_not_420() {
        let p = long_term_processor();
        let src: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let req = hashed_request(
            &p,
            src,
            Method::Allocate,
            "mallory",
            "whatever",
            vec![Attribute::RequestedTransport(17)],
        );
        let resp = reply(&p.process(req, src));
        // RFC 8489 §9.2.4: an invalid USERHASH is answered 401.
        assert_eq!(error_code(&resp), Some(401));
        assert!(!resp
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::UnknownAttributes(v) if v.contains(&ATTR_USERHASH))));
    }

    /// TURN REST cannot resolve a hash; the answer is 401, never a crash, a
    /// 420 or an allocation keyed to an empty name.
    #[test]
    fn shared_secret_realm_answers_userhash_with_401() {
        let p = PacketProcessor::new(
            Arc::new(AllocationStore::new(26000, 26999, 128)),
            Arc::new(AuthRegistry::new(turna_auth::AuthMode::SharedSecret {
                realm: REALM.into(),
                secret: b"rest-secret".to_vec(),
                previous: None,
            })),
            "127.0.0.1".parse().unwrap(),
            Arc::new(Metrics::new()),
        );
        let src: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let req = hashed_request(
            &p,
            src,
            Method::Allocate,
            "4102444800:alice",
            "irrelevant",
            vec![Attribute::RequestedTransport(17)],
        );
        assert_eq!(error_code(&reply(&p.process(req, src))), Some(401));
        assert!(p.store.get(&src).is_none());
    }

    #[test]
    fn nonce_cookie_round_trips_and_marks_username_anonymity() {
        let mgr = NonceManager::with_cookie(Some(USERHASH_NONCE_COOKIE));
        let src: SocketAddr = "127.0.0.1:41004".parse().unwrap();
        let nonce = mgr.issue(src);
        // RFC 8489 §9.2: "obMatJos2" + base64 of the 24 feature bits. Bit 1
        // (Username anonymity) set, bit 0 (Password algorithms) clear.
        // "QAAA" is base64 of 0x40 0x00 0x00: 010000|000000|000000|000000.
        assert!(nonce.starts_with("obMatJos2QAAA"), "{nonce}");
        assert!(matches!(mgr.validate(src, &nonce), NonceStatus::Valid));

        // A cookie-less nonce (issued before the cookie was turned on) is stale.
        let plain = NonceManager::with_cookie(None);
        let old = plain.issue(src);
        assert!(!old.starts_with("obMatJos2"));
        assert!(matches!(mgr.validate(src, &old), NonceStatus::Stale));
    }

    #[test]
    fn cookie_is_withheld_unless_every_realm_resolves_userhash() {
        let lt = AuthRegistry::new(turna_auth::AuthMode::long_term(REALM, [("a", "b")]));
        assert_eq!(PacketProcessor::nonce_cookie_for(&lt, false), None);
        assert_eq!(
            PacketProcessor::nonce_cookie_for(&lt, true),
            Some(USERHASH_NONCE_COOKIE)
        );
        let mixed = AuthRegistry::new(turna_auth::AuthMode::long_term(REALM, [("a", "b")]))
            .with_tenant(
                "t",
                turna_auth::AuthMode::SharedSecret {
                    realm: "other".into(),
                    secret: b"s".to_vec(),
                    previous: None,
                },
            );
        assert_eq!(PacketProcessor::nonce_cookie_for(&mixed, true), None);
    }
}

#[cfg(test)]
mod nat_discovery_tests {
    //! RFC 5780 through the processor. The socket plumbing is tested in
    //! `nat_discovery`; here, what each request is answered with and from where.
    use super::*;
    use crate::nat_discovery::NatDiscoveryTopology;
    use turna_proto_stun::attribute::ATTR_CHANGE_REQUEST;

    fn topo() -> NatDiscoveryTopology {
        NatDiscoveryTopology::new(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.2".parse().unwrap(),
            3478,
            3479,
        )
        .unwrap()
    }

    fn processor() -> PacketProcessor {
        PacketProcessor::new(
            Arc::new(AllocationStore::new(27000, 27999, 16)),
            Arc::new(AuthRegistry::new(turna_auth::AuthMode::long_term(
                "nat",
                [("u", "p")],
            ))),
            "127.0.0.1".parse().unwrap(),
            Arc::new(Metrics::new()),
        )
    }

    fn binding(extra: Vec<Attribute>) -> Vec<u8> {
        let mut m = StunMessage::new(Method::Binding, MessageClass::Request);
        for a in extra {
            m.add(a);
        }
        let mut buf = [0u8; 256];
        let n = m.encode(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plain_binding_carries_all_four_addresses() {
        let p = processor();
        let src = sa("198.51.100.7:40000");
        let local = sa("127.0.0.1:3478");
        let (bytes, from) = p
            .handle_nat_discovery(&binding(vec![]), src, local, &topo())
            .expect("a reply");
        assert_eq!(from, local, "no CHANGE-REQUEST: answer from Da:Dp");
        let r = StunMessage::decode(&bytes).unwrap();
        assert!(matches!(r.class, MessageClass::SuccessResponse));
        assert!(r
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::XorMappedAddress(x) if *x == src)));
        assert!(r
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::MappedAddress(x) if *x == src)));
        assert_eq!(r.get_response_origin(), Some(local));
        assert_eq!(r.get_other_address(), Some(sa("127.0.0.2:3479")));
    }

    #[test]
    fn change_request_moves_the_source_and_response_origin_follows() {
        let p = processor();
        let src = sa("198.51.100.7:40001");
        let local = sa("127.0.0.1:3478");
        for (ip, port, want) in [
            (true, false, "127.0.0.2:3478"),
            (false, true, "127.0.0.1:3479"),
            (true, true, "127.0.0.2:3479"),
        ] {
            let req = binding(vec![Attribute::ChangeRequest {
                change_ip: ip,
                change_port: port,
            }]);
            let (bytes, from) = p.handle_nat_discovery(&req, src, local, &topo()).unwrap();
            assert_eq!(from, sa(want));
            let r = StunMessage::decode(&bytes).unwrap();
            assert_eq!(r.get_response_origin(), Some(sa(want)));
            assert_eq!(r.get_other_address(), Some(sa("127.0.0.2:3479")));
        }
    }

    /// PADDING (0x0026) and RESPONSE-PORT (0x0027) are the two attributes the
    /// RFC's security section worries about; both are optional for a server
    /// and refused here, from the socket the request arrived on.
    #[test]
    fn padding_and_response_port_are_refused_with_420() {
        let p = processor();
        let src = sa("198.51.100.7:40002");
        let local = sa("127.0.0.2:3479");
        for (typ, value) in [(0x0026u16, vec![0u8; 64]), (0x0027, vec![0x13, 0x88, 0, 0])] {
            let req = binding(vec![Attribute::Unknown {
                attr_type: typ,
                value,
            }]);
            let (bytes, from) = p.handle_nat_discovery(&req, src, local, &topo()).unwrap();
            assert_eq!(from, local);
            let r = StunMessage::decode(&bytes).unwrap();
            assert!(r
                .attributes
                .iter()
                .any(|a| matches!(a, Attribute::UnknownAttributes(v) if v == &vec![typ])));
        }
    }

    #[test]
    fn turn_methods_are_not_served_on_discovery_sockets() {
        let p = processor();
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::RequestedTransport(17));
        let mut buf = [0u8; 128];
        let n = m.encode(&mut buf).unwrap();
        assert!(p
            .handle_nat_discovery(
                &buf[..n],
                sa("198.51.100.7:40003"),
                sa("127.0.0.1:3478"),
                &topo()
            )
            .is_none());
    }

    /// Replies share the unauthenticated-reply budget: a flood from one
    /// (possibly spoofed) source stops being answered.
    #[test]
    fn replies_are_bounded_by_the_unauthenticated_budget() {
        let p = processor();
        let src = sa("198.51.100.8:40004");
        let req = binding(vec![Attribute::ChangeRequest {
            change_ip: true,
            change_port: true,
        }]);
        let answered = (0..500)
            .filter(|_| {
                p.handle_nat_discovery(&req, src, sa("127.0.0.1:3478"), &topo())
                    .is_some()
            })
            .count();
        assert!(answered < 500, "all 500 were answered");
        assert!(answered >= 1);
        assert!(p.metrics.unauth_replies_suppressed.load(Ordering::Relaxed) > 0);
    }

    /// The TURN listener has no alternate address, so RFC 5780 §6 requires it
    /// to refuse CHANGE-REQUEST with 420 — the same answer it gave when the
    /// attribute was not understood at all.
    #[test]
    fn turn_listener_still_refuses_change_request() {
        let p = processor();
        let src = sa("198.51.100.7:40005");
        let req = binding(vec![Attribute::ChangeRequest {
            change_ip: true,
            change_port: false,
        }]);
        let actions = p.process(Bytes::from(req), src);
        let r = actions
            .iter()
            .find_map(|a| match a {
                Action::Send { data, .. } => Some(StunMessage::decode(data).unwrap()),
                _ => None,
            })
            .expect("a reply");
        assert!(r.attributes.iter().any(
            |a| matches!(a, Attribute::UnknownAttributes(v) if v == &vec![ATTR_CHANGE_REQUEST])
        ));
        // And a plain Binding there still has no OTHER-ADDRESS (§6: a server
        // without an alternate address MUST NOT include it).
        let actions = p.process(Bytes::from(binding(vec![])), src);
        let r = actions
            .iter()
            .find_map(|a| match a {
                Action::Send { data, .. } => Some(StunMessage::decode(data).unwrap()),
                _ => None,
            })
            .unwrap();
        assert!(r.get_other_address().is_none());
        assert!(r.get_response_origin().is_none());
    }
}
