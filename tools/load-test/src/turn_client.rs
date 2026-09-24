//! Minimal TURN client for load-testing.
//!
//! Implements just enough of RFC 5389/5766 for the bench scenarios:
//! STUN message building, long-term-credential MESSAGE-INTEGRITY
//! (HMAC-SHA1 over MD5 key), the TURN REST credential convention
//! (coturn `use-auth-secret` / eturnal `secret` / turna SharedSecret),
//! Allocate → CreatePermission → ChannelBind flow and ChannelData
//! framing.
//!
//! Deliberately self-contained: the load generator must not depend on
//! the server crates it measures, so every byte here is built by hand.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use tokio::net::UdpSocket;
#[cfg(test)]
use tokio::time::timeout;

pub const MAGIC: u32 = 0x2112A442;

// Methods (request class = method as-is; success resp = | 0x0100; error = | 0x0110).
pub const M_ALLOCATE: u16 = 0x0003;
pub const M_REFRESH: u16 = 0x0004;
pub const M_CREATE_PERM: u16 = 0x0008;
pub const M_CHANNEL_BIND: u16 = 0x0009;

// Attributes.
const A_USERNAME: u16 = 0x0006;
const A_MESSAGE_INTEGRITY: u16 = 0x0008;
const A_ERROR_CODE: u16 = 0x0009;
const A_CHANNEL_NUMBER: u16 = 0x000C;
const A_LIFETIME: u16 = 0x000D;
const A_XOR_PEER_ADDRESS: u16 = 0x0012;
const A_REALM: u16 = 0x0014;
const A_NONCE: u16 = 0x0015;
const A_XOR_RELAYED_ADDRESS: u16 = 0x0016;
const A_REQUESTED_TRANSPORT: u16 = 0x0019;
/// RFC 6156 §4.1.1. Value is one byte of family (0x01 v4, 0x02 v6) + 3 reserved.
const A_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
/// RFC 8656 §7.2 ADDITIONAL-ADDRESS-FAMILY. Comprehension-optional, so a server
/// that does not implement it ignores it silently — which is what makes it worth
/// probing explicitly rather than assuming.
const A_ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;

/// Address-family codes as they appear on the wire.
pub const FAMILY_V4: u8 = 0x01;
pub const FAMILY_V6: u8 = 0x02;

/// Sentinel returned by the probe helpers for "the server answered success". Not a
/// STUN error code — STUN has none for success.
pub const PROBE_SUCCESS: u16 = 0;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum Creds {
    /// Static long-term user/password (coturn `lt-cred-mech` + `user=`).
    Static { user: String, pass: String },
    /// TURN REST API: username = "<unix_expiry>:<uid>",
    /// password = base64(HMAC-SHA1(secret, username)).
    /// Understood by turna (SharedSecret), coturn (use-auth-secret) and
    /// eturnal (secret), and by our bench pion server's auth handler.
    Rest {
        secret: String,
        uid: String,
        ttl_s: u64,
    },
}

impl Creds {
    /// Materialize a (username, password) pair for one session.
    pub fn materialize(&self) -> (String, String) {
        match self {
            Creds::Static { user, pass } => (user.clone(), pass.clone()),
            Creds::Rest { secret, uid, ttl_s } => {
                let exp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + ttl_s;
                let user = format!("{exp}:{uid}");
                let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(user.as_bytes());
                let pass = base64_std(&mac.finalize().into_bytes());
                (user, pass)
            }
        }
    }
}

/// RFC 5389 §15.4 long-term credential key: MD5("user:realm:pass").
/// Local address the clients bind their sockets on, from `--bind-ip`.
///
/// It exists because a loopback bind cannot reach a peer on another interface. The
/// AF_XDP lab is exactly that case: the node sits on `10.123.0.1` over a veth pair
/// and the client has to send from `10.123.0.2`. Binding `0.0.0.0` is not a
/// substitute — `local_addr()` would then return `0.0.0.0`, and that is the address
/// that goes into CreatePermission, where it means nothing.
pub static BIND_IP: std::sync::OnceLock<std::net::IpAddr> = std::sync::OnceLock::new();

/// `ip:0` for a peer socket of the given family, honouring `--bind-ip`.
///
/// Falls back to loopback, which is what every local check wants. If `--bind-ip` was
/// given in the other family it is ignored rather than silently producing an
/// unreachable peer — a v4 peer on a v6 allocation is refused with 443 by design, and
/// that refusal would look like a server fault.
/// Local address for a **control** socket talking to `server`.
///
/// The family follows the server's address, not a flag. A control socket bound in the
/// wrong family cannot send at all: the request never leaves, `allocate` fails without
/// a response to report, and the caller sees an error with no cause — which is exactly
/// how an IPv6 run looked before this existed. It reported 10 setup errors and zero
/// packets while the server logged nothing, because nothing ever reached it.
/// How many distinct loopback source addresses to spread control sockets over.
/// 1 (the default) means every client uses `127.0.0.1`, as before.
pub static SOURCE_SPREAD: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// Round-robin position within the spread. One bump per control socket.
static SPREAD_NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Local address for a **control** socket, spread across `--source-ips`
/// addresses in `127.0.0.0/8` when that flag is set.
///
/// Rotates rather than taking a client index, so no caller changes: each client
/// binds its control socket exactly once, in `allocate_family`, and round-robin
/// by call order distributes them the same way an index would.
///
/// This exists because the per-source-IP allocate limit is 32/s with a burst of
/// 16 (`TieredLimits::allocate`), and every client sharing `127.0.0.1` means a
/// load test measures that limiter rather than the server: 38 requested channels
/// produced 122 refusals against 59 allocations.
///
/// A real deployment does not look like that. Clients arrive from many
/// addresses, where the per-IP limit never binds and `per_prefix` (40 000/s) is
/// the ceiling that matters. One source address is the everyone-behind-one-NAT
/// case — worth testing deliberately, but not capacity.
///
/// `--bind-ip` wins when set: it exists for labs where the server is not on
/// loopback and the source must be a specific address, and overriding it here
/// would break those. IPv6 is not spread — `::2` is not local the way
/// `127.0.0.2` is, and adding it needs interface configuration.
pub fn control_bind_addr(server: SocketAddr) -> String {
    if BIND_IP.get().is_some() || server.is_ipv6() {
        return peer_bind_addr(server.is_ipv6());
    }
    match SOURCE_SPREAD.get().copied().unwrap_or(1) {
        0 | 1 => peer_bind_addr(false),
        spread => {
            // Capped at 250 to stay inside the last octet; a run needing more
            // sources than that needs more than one host anyway.
            let spread = spread.min(250);
            let n = SPREAD_NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % spread + 1;
            format!("127.0.0.{n}:0")
        }
    }
}

pub fn peer_bind_addr(v6: bool) -> String {
    match BIND_IP.get() {
        Some(ip) if ip.is_ipv6() == v6 => format!("{}", std::net::SocketAddr::new(*ip, 0)),
        _ if v6 => "[::1]:0".to_string(),
        _ => "127.0.0.1:0".to_string(),
    }
}

pub fn long_term_key(user: &str, realm: &str, pass: &str) -> [u8; 16] {
    md5::compute(format!("{user}:{realm}:{pass}")).0
}

/// Standard base64 (with padding), hand-rolled to avoid a dependency.
fn base64_std(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TBL[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------------------
// STUN message building
// ---------------------------------------------------------------------------

pub struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    pub fn request(method: u16) -> Self {
        let mut buf = vec![0u8; 20];
        buf[0..2].copy_from_slice(&method.to_be_bytes());
        buf[4..8].copy_from_slice(&MAGIC.to_be_bytes());
        for b in &mut buf[8..20] {
            *b = rand::random();
        }
        Self { buf }
    }

    pub fn txid(&self) -> [u8; 12] {
        let mut t = [0u8; 12];
        t.copy_from_slice(&self.buf[8..20]);
        t
    }

    fn set_len(&mut self) {
        let l = (self.buf.len() - 20) as u16;
        self.buf[2..4].copy_from_slice(&l.to_be_bytes());
    }

    pub fn add(&mut self, typ: u16, val: &[u8]) {
        self.buf.extend_from_slice(&typ.to_be_bytes());
        self.buf
            .extend_from_slice(&(val.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(val);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self.set_len();
    }

    pub fn add_requested_transport_udp(&mut self) {
        self.add(A_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    }

    /// RFC 6156 REQUESTED-ADDRESS-FAMILY.
    pub fn add_requested_address_family(&mut self, family: u8) {
        self.add(A_REQUESTED_ADDRESS_FAMILY, &[family, 0, 0, 0]);
    }

    /// RFC 8656 ADDITIONAL-ADDRESS-FAMILY. Only IPv6 is legal here; passing v4 is
    /// how you check the server answers 400 rather than accepting it.
    pub fn add_additional_address_family(&mut self, family: u8) {
        self.add(A_ADDITIONAL_ADDRESS_FAMILY, &[family, 0, 0, 0]);
    }
    pub fn add_lifetime(&mut self, secs: u32) {
        self.add(A_LIFETIME, &secs.to_be_bytes());
    }
    pub fn add_username(&mut self, u: &str) {
        self.add(A_USERNAME, u.as_bytes());
    }
    pub fn add_realm(&mut self, r: &str) {
        self.add(A_REALM, r.as_bytes());
    }
    pub fn add_nonce(&mut self, n: &[u8]) {
        self.add(A_NONCE, n);
    }
    pub fn add_channel_number(&mut self, ch: u16) {
        self.add(A_CHANNEL_NUMBER, &[(ch >> 8) as u8, ch as u8, 0, 0]);
    }
    pub fn add_xor_peer(&mut self, a: SocketAddr) {
        let txid = self.txid();
        let v = xor_addr_encode(a, &txid);
        self.add(A_XOR_PEER_ADDRESS, &v);
    }

    pub fn encode(self) -> Vec<u8> {
        self.buf
    }

    /// Append MESSAGE-INTEGRITY. Per RFC 5389 §15.4 the HMAC is computed
    /// with the header length field already covering the MI attribute.
    pub fn encode_with_integrity(mut self, key: &[u8; 16]) -> Vec<u8> {
        let with_mi = ((self.buf.len() - 20) + 24) as u16;
        self.buf[2..4].copy_from_slice(&with_mi.to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(&self.buf);
        let tag = mac.finalize().into_bytes();
        self.buf
            .extend_from_slice(&A_MESSAGE_INTEGRITY.to_be_bytes());
        self.buf.extend_from_slice(&20u16.to_be_bytes());
        self.buf.extend_from_slice(&tag);
        self.buf
    }
}

fn xor_addr_encode(a: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.push(0);
    let xport = a.port() ^ (MAGIC >> 16) as u16;
    match a.ip() {
        IpAddr::V4(ip) => {
            v.push(0x01);
            v.extend_from_slice(&xport.to_be_bytes());
            let o = ip.octets();
            let m = MAGIC.to_be_bytes();
            for i in 0..4 {
                v.push(o[i] ^ m[i]);
            }
        }
        IpAddr::V6(ip) => {
            v.push(0x02);
            v.extend_from_slice(&xport.to_be_bytes());
            let o = ip.octets();
            let mut mask = [0u8; 16];
            mask[0..4].copy_from_slice(&MAGIC.to_be_bytes());
            mask[4..16].copy_from_slice(txid);
            for i in 0..16 {
                v.push(o[i] ^ mask[i]);
            }
        }
    }
    v
}

fn xor_addr_decode(val: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if val.len() < 8 {
        return None;
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = xport ^ (MAGIC >> 16) as u16;
    match family {
        0x01 => {
            let m = MAGIC.to_be_bytes();
            let ip =
                std::net::Ipv4Addr::new(val[4] ^ m[0], val[5] ^ m[1], val[6] ^ m[2], val[7] ^ m[3]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if val.len() >= 20 => {
            let mut mask = [0u8; 16];
            mask[0..4].copy_from_slice(&MAGIC.to_be_bytes());
            mask[4..16].copy_from_slice(txid);
            let mut o = [0u8; 16];
            for i in 0..16 {
                o[i] = val[4 + i] ^ mask[i];
            }
            Some(SocketAddr::new(IpAddr::V6(o.into()), port))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

pub fn is_success(buf: &[u8]) -> bool {
    buf.len() >= 20 && (u16::from_be_bytes([buf[0], buf[1]]) & 0x0110) == 0x0100
}
pub fn is_error(buf: &[u8]) -> bool {
    buf.len() >= 20 && (u16::from_be_bytes([buf[0], buf[1]]) & 0x0110) == 0x0110
}

pub fn get_attr(buf: &[u8], want: u16) -> Option<&[u8]> {
    if buf.len() < 20 {
        return None;
    }
    let mlen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + mlen).min(buf.len());
    let mut i = 20;
    while i + 4 <= end {
        let typ = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let vstart = i + 4;
        if vstart + len > end {
            return None;
        }
        if typ == want {
            return Some(&buf[vstart..vstart + len]);
        }
        i = vstart + len;
        while i % 4 != 0 {
            i += 1;
        }
    }
    None
}

pub fn error_code(buf: &[u8]) -> Option<u16> {
    let v = get_attr(buf, A_ERROR_CODE)?;
    if v.len() < 4 {
        return None;
    }
    Some((v[2] & 0x07) as u16 * 100 + v[3] as u16)
}

pub fn get_realm(buf: &[u8]) -> Option<String> {
    get_attr(buf, A_REALM).map(|v| String::from_utf8_lossy(v).into_owned())
}
pub fn get_nonce(buf: &[u8]) -> Option<Vec<u8>> {
    get_attr(buf, A_NONCE).map(|v| v.to_vec())
}
pub fn get_relayed_addr(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    xor_addr_decode(get_attr(buf, A_XOR_RELAYED_ADDRESS)?, txid)
}

// ---------------------------------------------------------------------------
// ChannelData framing
// ---------------------------------------------------------------------------

pub fn channel_data_frame(ch: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + payload.len() + 3);
    v.extend_from_slice(&ch.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

// ---------------------------------------------------------------------------
// Session: authenticated request loop with stale-nonce retry
// ---------------------------------------------------------------------------

pub struct Session {
    pub sock: UdpSocket,
    pub server: SocketAddr,
    /// Relay transport address the server assigned. The load scenarios send to
    /// the server's main port and do not read it; the `conformance` mode does —
    /// checking that an IPv6 Allocate actually yields an IPv6 relayed address is
    /// the point of that probe.
    pub relayed: SocketAddr,
    realm: String,
    nonce: Vec<u8>,
    user: String,
    key: [u8; 16],
    /// Server answered Allocate without a 401 challenge (no-auth mode).
    no_auth: bool,
    rtt_ms: u64,
}

/// Send `pkt`, wait (up to `ms`) for a STUN response whose transaction id
/// matches `txid`, method and source. Retry identical bytes with exponential
/// backoff (initial 500 ms), bounded by the original total deadline.
async fn send_recv(
    sock: &UdpSocket,
    server: SocketAddr,
    pkt: &[u8],
    txid: &[u8; 12],
    ms: u64,
) -> Option<Vec<u8>> {
    // Bounded exponential retransmission inside the caller's total deadline.
    // Keep the identical bytes/transaction ID. A nonce challenge is a new
    // transaction and is handled by the caller instead.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    let mut rto = Duration::from_millis(500);
    let mut buf = vec![0u8; 65536];
    let mut attempts = 0u32;
    loop {
        if tokio::time::Instant::now() >= deadline {
            let id = txid.iter().map(|b| format!("{b:02x}")).collect::<String>();
            eprintln!("UDP transaction timeout: local={:?} server={server} txid={id} attempts={attempts} deadline_ms={ms}", sock.local_addr().ok());
            return None;
        }
        tokio::time::timeout_at(deadline, sock.send_to(pkt, server))
            .await
            .ok()?
            .ok()?;
        attempts += 1;
        let until = (tokio::time::Instant::now() + rto).min(deadline);
        loop {
            match tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    if from == server
                        && n >= 20
                        && &buf[8..20] == txid
                        && buf[4..8] == MAGIC.to_be_bytes()
                        && usize::from(u16::from_be_bytes([buf[2], buf[3]])) + 20 == n
                        && (is_success(&buf[..n]) || is_error(&buf[..n]))
                        && buf[0] & !0x01 == pkt[0] & !0x01
                        && buf[1] & !0x10 == pkt[1] & !0x10
                    {
                        return Some(buf[..n].to_vec());
                    }
                }
                Ok(Err(_)) => return None,
                Err(_) => break,
            }
        }
        rto = rto.saturating_mul(2);
    }
}

/// Probe an unauthenticated Allocate carrying ADDITIONAL-ADDRESS-FAMILY, and
/// report the STUN code the server answered with.
///
/// Unauthenticated on purpose: the attribute is parsed (or not) before
/// authentication matters, so a `401` challenge means "the attribute did not
/// offend the parser", while a `400` means the server implements the RFC 8656 §7.2
/// validation. Both are informative; neither needs credentials.
///
/// `family` is the value placed in the attribute. RFC 8656 allows only IPv6 there,
/// so passing `FAMILY_V4` is how you check whether the server rejects the illegal
/// combination or silently ignores it.
pub async fn probe_additional_address_family(
    server: SocketAddr,
    rtt_ms: u64,
    family: u8,
    with_raf: bool,
) -> Option<u16> {
    let sock = UdpSocket::bind(control_bind_addr(server)).await.ok()?;
    let mut m = Msg::request(M_ALLOCATE);
    m.add_requested_transport_udp();
    if with_raf {
        // RFC 8656 §7.2: mutually exclusive with ADDITIONAL-ADDRESS-FAMILY.
        m.add_requested_address_family(FAMILY_V6);
    }
    m.add_additional_address_family(family);
    m.add_lifetime(600);
    let txid = m.txid();
    let pkt = m.encode();
    let resp = send_recv(&sock, server, &pkt, &txid, rtt_ms).await?;
    if is_success(&resp) {
        // 0 is not a STUN code; it stands for "answered success". Callers treat it
        // the same as a 401 challenge here — both mean the attribute did not make
        // the server reject the request.
        return Some(PROBE_SUCCESS);
    }
    error_code(&resp)
}

/// An Allocate rejection, with the STUN error code when the server sent one.
/// `allocate` collapses this to a message; the conformance checks need the code,
/// because "refused with 440" and "timed out" mean opposite things.
#[derive(Debug)]
pub struct AllocError(pub &'static str, pub Option<u16>);

/// Full authenticated Allocate, optionally requesting an address family
/// (`FAMILY_V4` / `FAMILY_V6`). `None` sends no REQUESTED-ADDRESS-FAMILY at all,
/// which is the default client behaviour and must stay indistinguishable from
/// asking for v4.
pub async fn allocate_family(
    server: SocketAddr,
    creds: &Creds,
    rtt_ms: u64,
    family: Option<u8>,
) -> Result<Session, AllocError> {
    let sock = UdpSocket::bind(control_bind_addr(server))
        .await
        .map_err(|_| AllocError("bind", None))?;

    // 1. Unauthenticated Allocate → expect 401 challenge (or success on
    //    a no-auth server).
    let mut m = Msg::request(M_ALLOCATE);
    m.add_requested_transport_udp();
    if let Some(f) = family {
        m.add_requested_address_family(f);
    }
    m.add_lifetime(600);
    let txid = m.txid();
    let pkt = m.encode();
    let resp = send_recv(&sock, server, &pkt, &txid, rtt_ms)
        .await
        .ok_or(AllocError("alloc: no response to probe", None))?;

    if is_success(&resp) {
        let relayed =
            get_relayed_addr(&resp, &txid).ok_or(AllocError("alloc: no relayed addr", None))?;
        return Ok(Session {
            sock,
            server,
            relayed,
            realm: String::new(),
            nonce: Vec::new(),
            user: String::new(),
            key: [0; 16],
            no_auth: true,
            rtt_ms,
        });
    }
    if !is_error(&resp) || error_code(&resp) != Some(401) {
        // Not a challenge and not a success: the server refused outright. A
        // family request that the server does not support lands here (440), and
        // that is a legitimate answer to report rather than an error to hide.
        return Err(AllocError(
            "alloc: expected 401 challenge",
            error_code(&resp),
        ));
    }
    let realm = get_realm(&resp).ok_or(AllocError("alloc: 401 without realm", None))?;
    let mut nonce = get_nonce(&resp).ok_or(AllocError("alloc: 401 without nonce", None))?;

    // 2. Authenticated Allocate (retry once on 438/401 with fresh nonce).
    let (user, pass) = creds.materialize();
    let key = long_term_key(&user, &realm, &pass);
    for _attempt in 0..2 {
        let mut m = Msg::request(M_ALLOCATE);
        m.add_requested_transport_udp();
        if let Some(f) = family {
            m.add_requested_address_family(f);
        }
        m.add_lifetime(600);
        m.add_username(&user);
        m.add_realm(&realm);
        m.add_nonce(&nonce);
        let txid = m.txid();
        let pkt = m.encode_with_integrity(&key);
        let resp = send_recv(&sock, server, &pkt, &txid, rtt_ms)
            .await
            .ok_or(AllocError("alloc: no response to authed request", None))?;
        if is_success(&resp) {
            let relayed =
                get_relayed_addr(&resp, &txid).ok_or(AllocError("alloc: no relayed addr", None))?;
            return Ok(Session {
                sock,
                server,
                relayed,
                realm,
                nonce,
                user,
                key,
                no_auth: false,
                rtt_ms,
            });
        }
        match error_code(&resp) {
            Some(438) | Some(401) => {
                if let Some(n) = get_nonce(&resp) {
                    nonce = n;
                    continue;
                }
                return Err(AllocError("alloc: stale nonce without replacement", None));
            }
            code => {
                return Err(AllocError("alloc: authed request rejected", code));
            }
        }
    }
    Err(AllocError("alloc: nonce retry exhausted", None))
}

impl Session {
    /// Churn retains the source socket: nonces are bound to its full address.
    pub async fn churn_request(&mut self, allocate: bool) -> Result<(), AllocError> {
        for _ in 0..2 {
            let mut m = Msg::request(if allocate { M_ALLOCATE } else { M_REFRESH });
            if allocate {
                m.add_requested_transport_udp();
            }
            m.add_lifetime(if allocate { 600 } else { 0 });
            let txid = m.txid();
            let pkt = if self.no_auth {
                m.encode()
            } else {
                m.add_username(&self.user);
                m.add_realm(&self.realm);
                m.add_nonce(&self.nonce);
                m.encode_with_integrity(&self.key)
            };
            let resp = send_recv(&self.sock, self.server, &pkt, &txid, self.rtt_ms)
                .await
                .ok_or(AllocError(
                    if allocate {
                        "churn allocate: response timeout"
                    } else {
                        "churn delete: response timeout"
                    },
                    None,
                ))?;
            if is_success(&resp) {
                if allocate {
                    self.relayed = get_relayed_addr(&resp, &txid)
                        .ok_or(AllocError("churn: missing relay address", None))?;
                } else if get_attr(&resp, A_LIFETIME) != Some(&[0, 0, 0, 0][..]) {
                    return Err(AllocError("churn: deletion not confirmed", None));
                }
                return Ok(());
            }
            let code = error_code(&resp);
            match code {
                Some(438) | Some(401) if !self.no_auth => {
                    self.nonce = get_nonce(&resp)
                        .ok_or(AllocError("churn: challenge missing nonce", code))?;
                }
                _ => return Err(AllocError("churn: rejected", code)),
            }
        }
        Err(AllocError("churn: nonce retry exhausted", None))
    }

    /// Run one authenticated request; retries once on stale nonce.
    async fn auth_request(
        &mut self,
        method: u16,
        fill: impl Fn(&mut Msg),
    ) -> Result<Vec<u8>, &'static str> {
        for _attempt in 0..2 {
            let mut m = Msg::request(method);
            fill(&mut m);
            let txid = m.txid();
            let pkt = if self.no_auth {
                m.encode()
            } else {
                m.add_username(&self.user);
                m.add_realm(&self.realm);
                m.add_nonce(&self.nonce);
                // NB: fill() must add its attrs before USERNAME for some
                // strict servers? RFC imposes no ordering — keep simple.
                m.encode_with_integrity(&self.key)
            };
            let resp = send_recv(&self.sock, self.server, &pkt, &txid, self.rtt_ms)
                .await
                .ok_or("req: timeout")?;
            if is_success(&resp) {
                return Ok(resp);
            }
            match error_code(&resp) {
                Some(438) | Some(401) if !self.no_auth => {
                    if let Some(n) = get_nonce(&resp) {
                        self.nonce = n;
                        // Key derivation may embed the nonce only via the
                        // digest of user:realm:pass — unchanged. Retry.
                        continue;
                    }
                    return Err("req: stale nonce without replacement");
                }
                _ => return Err("req: rejected"),
            }
        }
        Err("req: nonce retry exhausted")
    }

    /// One CreatePermission, reporting the STUN error code instead of collapsing
    /// it to a message. The conformance checks need the code: `443` (family
    /// mismatch) and `403` (forbidden peer) are both "rejected", and telling them
    /// apart is the whole point of the check.
    ///
    /// No nonce retry: these are single-shot probes on an already-authenticated
    /// session, and retrying would blur which answer came from which request.
    pub async fn create_permission_code(&mut self, peer: SocketAddr) -> Result<(), Option<u16>> {
        let mut m = Msg::request(M_CREATE_PERM);
        m.add_xor_peer(peer);
        let pkt = if self.no_auth {
            m.encode()
        } else {
            m.add_username(&self.user);
            m.add_realm(&self.realm);
            m.add_nonce(&self.nonce);
            m.encode_with_integrity(&self.key)
        };
        let txid: [u8; 12] = pkt[8..20].try_into().expect("txid slice");
        let resp = send_recv(&self.sock, self.server, &pkt, &txid, self.rtt_ms)
            .await
            .ok_or(None)?;
        if is_success(&resp) {
            return Ok(());
        }
        Err(error_code(&resp))
    }

    pub async fn create_permission(&mut self, peer: SocketAddr) -> Result<(), &'static str> {
        self.auth_request(M_CREATE_PERM, move |m| m.add_xor_peer(peer))
            .await
            .map(|_| ())
    }

    /// Refresh the allocation and re-assert the permission and channel binding.
    ///
    /// A session that runs longer than ten minutes has to do this or it stops working
    /// with no error at all: the allocation lasts 600 s (RFC 8656 §7.2), the permission
    /// 300 s (§9), the channel binding 600 s (§11.2), and the server is required to
    /// drop ChannelData once the binding is gone.
    ///
    /// Measured consequence, before this existed: a 1755 s phase delivered
    /// 600/1755 ≈ 34 % of what it sent, identically on every transport, and it looked
    /// like a capacity cliff. Rehearsals of 244 s never crossed the deadline and passed
    /// clean, which is what made it confusing.
    pub async fn refresh(&mut self, ch: u16, peer: SocketAddr) -> Result<(), &'static str> {
        self.auth_request(M_REFRESH, |m| m.add_lifetime(600))
            .await
            .map_err(|_| "refresh failed")?;
        self.create_permission(peer).await?;
        self.channel_bind(ch, peer).await
    }

    pub async fn channel_bind(&mut self, ch: u16, peer: SocketAddr) -> Result<(), &'static str> {
        self.auth_request(M_CHANNEL_BIND, move |m| {
            m.add_channel_number(ch);
            m.add_xor_peer(peer);
        })
        .await
        .map(|_| ())
    }

    /// Refresh with lifetime 0 releases the allocation server-side so
    /// repeated bench runs don't exhaust the relay port range.
    pub async fn release(&mut self) {
        let _ = self.auth_request(M_REFRESH, |m| m.add_lifetime(0)).await;
    }
}

#[cfg(test)]
mod churn_tests {
    use super::*;

    async fn session(server: SocketAddr) -> Session {
        Session {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            server,
            relayed: "127.0.0.1:23000".parse().unwrap(),
            realm: "test".into(),
            nonce: b"old".to_vec(),
            user: "user".into(),
            key: long_term_key("user", "test", "pass"),
            no_auth: false,
            rtt_ms: 1000,
        }
    }

    fn response(request: &[u8], kind: u16) -> Msg {
        let mut m = Msg::request(kind);
        m.buf[8..20].copy_from_slice(&request[8..20]);
        m
    }

    #[tokio::test]
    async fn churn_reuses_socket_and_recovers_stale_nonce() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sess = session(server.local_addr().unwrap()).await;
        let source = sess.sock.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let mut buf = [0u8; 1600];
            for step in 0..3 {
                let (n, addr) = timeout(Duration::from_secs(2), server.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(addr, source);
                assert!(get_attr(&buf[..n], A_MESSAGE_INTEGRITY).is_some());
                let nonce = if step == 2 {
                    b"fresh".as_slice()
                } else {
                    b"old".as_slice()
                };
                assert_eq!(get_nonce(&buf[..n]).unwrap(), nonce);
                let mut reply = response(
                    &buf[..n],
                    if step == 0 {
                        0x0104
                    } else if step == 1 {
                        0x0113
                    } else {
                        0x0103
                    },
                );
                if step == 0 {
                    reply.add_lifetime(0);
                } else if step == 1 {
                    reply.add(A_ERROR_CODE, &[0, 0, 4, 38]);
                    reply.add_nonce(b"fresh");
                } else {
                    reply.add(
                        A_XOR_RELAYED_ADDRESS,
                        &xor_addr_encode("127.0.0.1:23001".parse().unwrap(), &reply.txid()),
                    );
                }
                server.send_to(&reply.encode(), addr).await.unwrap();
            }
        });
        sess.churn_request(false).await.unwrap();
        sess.churn_request(true).await.unwrap();
        assert_eq!(sess.relayed.port(), 23001);
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn churn_preserves_rejection_code() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sess = session(server.local_addr().unwrap()).await;
        let peer = tokio::spawn(async move {
            let mut buf = [0u8; 1600];
            let (n, addr) = timeout(Duration::from_secs(2), server.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let mut reply = response(&buf[..n], 0x0113);
            reply.add(A_ERROR_CODE, &[0, 0, 5, 8]);
            server.send_to(&reply.encode(), addr).await.unwrap();
        });
        assert_eq!(sess.churn_request(true).await.unwrap_err().1, Some(508));
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn churn_refuses_unconfirmed_deletion() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sess = session(server.local_addr().unwrap()).await;
        let peer = tokio::spawn(async move {
            let mut buf = [0u8; 1600];
            let (n, addr) = timeout(Duration::from_secs(2), server.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let mut reply = response(&buf[..n], 0x0104);
            reply.add_lifetime(600);
            server.send_to(&reply.encode(), addr).await.unwrap();
        });
        assert_eq!(
            sess.churn_request(false).await.unwrap_err().0,
            "churn: deletion not confirmed"
        );
        peer.await.unwrap();
    }
}

#[cfg(test)]
mod udp_retry_tests {
    use super::*;
    #[tokio::test]
    async fn retry_identical_transaction_after_dropped_request_and_response() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut msg = Msg::request(M_REFRESH);
        msg.add_lifetime(0);
        let txid = msg.txid();
        let raw = msg.encode();
        let expected = raw.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; 1600];
            let mut reply = None;
            for step in 0..3 {
                let (n, src) = timeout(Duration::from_secs(3), server.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buf[..n], expected.as_slice());
                if step == 0 {
                    continue;
                } // request lost before processing
                if step == 1 {
                    let mut r = Msg::request(0x0104);
                    r.buf[8..20].copy_from_slice(&txid);
                    r.add_lifetime(0);
                    reply = Some(r.encode());
                    continue; // response lost after processing
                }
                server.send_to(reply.as_ref().unwrap(), src).await.unwrap();
            }
        });
        let reply = send_recv(&client, addr, &raw, &txid, 2500).await.unwrap();
        assert_eq!(get_attr(&reply, A_LIFETIME), Some(&[0, 0, 0, 0][..]));
        task.await.unwrap();
    }
    #[tokio::test]
    async fn retry_rejects_wrong_source_and_stops_at_deadline() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let msg = Msg::request(M_REFRESH);
        let txid = msg.txid();
        let raw = msg.encode();
        let mut response = Msg::request(0x0104);
        response.buf[8..20].copy_from_slice(&txid);
        attacker
            .send_to(&response.encode(), client.local_addr().unwrap())
            .await
            .unwrap();
        assert!(timeout(
            Duration::from_secs(1),
            send_recv(&client, addr, &raw, &txid, 100)
        )
        .await
        .unwrap()
        .is_none());
    }
}
