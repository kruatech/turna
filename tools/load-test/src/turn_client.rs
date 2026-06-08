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
pub fn long_term_key(user: &str, realm: &str, pass: &str) -> [u8; 16] {
    md5::compute(format!("{user}:{realm}:{pass}")).0
}

/// Standard base64 (with padding), hand-rolled to avoid a dependency.
fn base64_std(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
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
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
        self.set_len();
    }

    pub fn add_requested_transport_udp(&mut self) {
        self.add(A_REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
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

pub fn get_attr<'a>(buf: &'a [u8], want: u16) -> Option<&'a [u8]> {
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
    /// Relay transport address the server assigned. Not read by the
    /// current bench scenarios (they send to the server's main port);
    /// kept for diagnostics and future scenarios.
    #[allow(dead_code)]
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
/// matches `txid`. Non-matching datagrams (e.g. relayed data) are skipped.
async fn send_recv(
    sock: &UdpSocket,
    server: SocketAddr,
    pkt: &[u8],
    txid: &[u8; 12],
    ms: u64,
) -> Option<Vec<u8>> {
    sock.send_to(pkt, server).await.ok()?;
    let mut buf = vec![0u8; 1600];
    let deadline = Duration::from_millis(ms);
    let fut = async {
        loop {
            let (n, _) = sock.recv_from(&mut buf).await.ok()?;
            if n >= 20 && &buf[8..20] == txid {
                return Some(buf[..n].to_vec());
            }
        }
    };
    timeout(deadline, fut).await.ok().flatten()
}

/// Full authenticated Allocate. Returns a Session ready for
/// CreatePermission / ChannelBind / Refresh, plus the relayed address.
pub async fn allocate(
    server: SocketAddr,
    creds: &Creds,
    rtt_ms: u64,
) -> Result<Session, &'static str> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.map_err(|_| "bind")?;

    // 1. Unauthenticated Allocate → expect 401 challenge (or success on
    //    a no-auth server).
    let mut m = Msg::request(M_ALLOCATE);
    m.add_requested_transport_udp();
    m.add_lifetime(600);
    let txid = m.txid();
    let pkt = m.encode();
    let resp = send_recv(&sock, server, &pkt, &txid, rtt_ms)
        .await
        .ok_or("alloc: no response to probe")?;

    if is_success(&resp) {
        let relayed = get_relayed_addr(&resp, &txid).ok_or("alloc: no relayed addr")?;
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
        return Err("alloc: expected 401 challenge");
    }
    let realm = get_realm(&resp).ok_or("alloc: 401 without realm")?;
    let mut nonce = get_nonce(&resp).ok_or("alloc: 401 without nonce")?;

    // 2. Authenticated Allocate (retry once on 438/401 with fresh nonce).
    let (user, pass) = creds.materialize();
    let key = long_term_key(&user, &realm, &pass);
    for _attempt in 0..2 {
        let mut m = Msg::request(M_ALLOCATE);
        m.add_requested_transport_udp();
        m.add_lifetime(600);
        m.add_username(&user);
        m.add_realm(&realm);
        m.add_nonce(&nonce);
        let txid = m.txid();
        let pkt = m.encode_with_integrity(&key);
        let resp = send_recv(&sock, server, &pkt, &txid, rtt_ms)
            .await
            .ok_or("alloc: no response to authed request")?;
        if is_success(&resp) {
            let relayed = get_relayed_addr(&resp, &txid).ok_or("alloc: no relayed addr")?;
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
                return Err("alloc: stale nonce without replacement");
            }
            _ => return Err("alloc: authed request rejected"),
        }
    }
    Err("alloc: nonce retry exhausted")
}

impl Session {
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

    pub async fn create_permission(&mut self, peer: SocketAddr) -> Result<(), &'static str> {
        self.auth_request(M_CREATE_PERM, move |m| m.add_xor_peer(peer))
            .await
            .map(|_| ())
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
