//! Stateless address validation for the DTLS demultiplexer (RFC 6347 §4.2.1).
//!
//! # What this is for
//!
//! On the demux path a datagram from an unknown address used to allocate a
//! channel, a map entry, a `DTLSConn` and a task before anything had proved the
//! source address was real. One ~100-byte ClientHello bought `accept_timeout`
//! seconds of that, so a spoofed flood was an out-of-memory kill in seconds,
//! from any address, with no credentials.
//!
//! `max_pending_handshakes` bounds how much a flood can allocate. It does not
//! stop the allocation happening before the sender is known to exist, which is
//! the actual defect. This module closes it: a ClientHello without a cookie this
//! node issued gets a HelloVerifyRequest and **nothing is allocated**. The reply
//! is one datagram, derived rather than stored, so a flood of a million spoofed
//! ClientHellos costs a million HMACs and zero bytes of retained state.
//!
//! This is what OpenSSL's `DTLSv1_listen` does, and what the stock
//! `webrtc-dtls` `listen()` path did before the demultiplexer replaced it.
//!
//! # The cookie
//!
//! `HMAC-SHA256(key, client_addr ‖ time_bucket)`, truncated to 32 bytes, where
//! the key is 32 bytes of `/dev/urandom` read once per process. Binding to the
//! address is what makes it worth anything: a cookie harvested by a real client
//! is useless from any other address. The time bucket bounds replay without
//! keeping state — one previous bucket is also accepted, so a handshake that
//! straddles a boundary is not failed for arriving a second late.
//!
//! # What it does not do
//!
//! `webrtc-dtls` performs its own HelloVerifyRequest inside `DTLSConn`. If it
//! still does so after this gate, a client pays two cookie round trips instead
//! of one — slower, not broken, and the protocol allows it. If that shows up as
//! doubled handshake latency, the fix is on the `webrtc-dtls` side, not here;
//! removing this gate would put the memory back at the mercy of the sender.

use std::net::SocketAddr;

/// DTLS record: `ContentType(1) Version(2) Epoch(2) SequenceNumber(6) Length(2)`.
const RECORD_HEADER: usize = 13;
/// Handshake: `MsgType(1) Length(3) MessageSeq(2) FragmentOffset(3) FragmentLength(3)`.
const HANDSHAKE_HEADER: usize = 12;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_HELLO_VERIFY_REQUEST: u8 = 3;
/// DTLS 1.0 on the wire (0xfefd is 1.2). RFC 6347 §4.2.1 requires
/// HelloVerifyRequest to carry `{254, 255}` regardless of the negotiated
/// version, so that a client which does not yet know the server's version can
/// still parse it.
const DTLS_1_0: [u8; 2] = [0xfe, 0xff];

/// Seconds a cookie stays valid within its own bucket. The previous bucket is
/// accepted too, so the real window is 30-60 seconds — longer than any
/// legitimate client needs to answer, short enough that a harvested cookie is
/// not a lasting credential. It is bound to the address anyway.
const BUCKET_SECS: u64 = 30;

fn cookie_key() -> Option<&'static [u8; 32]> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    KEY.get_or_init(|| {
        use std::io::Read;
        let mut buf = [0u8; 32];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)) {
            Ok(()) => Some(buf),
            Err(e) => {
                // No key, no gate. Failing open is the right direction here:
                // `max_pending_handshakes` still bounds the damage, whereas
                // refusing every handshake would turn an unreadable
                // `/dev/urandom` into a total outage.
                tracing::error!(
                    error = %e,
                    "could not read /dev/urandom for the DTLS cookie key; address \
                     validation is DISABLED and spoofed ClientHellos will allocate \
                     state up to max_pending_handshakes"
                );
                None
            }
        }
    })
    .as_ref()
}

/// Constant-time comparison.
///
/// Local rather than borrowed from `turna-common`, which this crate does not
/// depend on and should not start depending on for four lines. Timing here is
/// not obviously exploitable — the attacker would be learning a cookie bound to
/// their own address — but a comparison that returns early on the first
/// differing byte is the kind of thing that becomes exploitable after somebody
/// changes what is being compared.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn bucket_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / BUCKET_SECS)
        .unwrap_or(0)
}

fn compute(key: &[u8; 32], addr: &SocketAddr, bucket: u64) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    match addr.ip() {
        std::net::IpAddr::V4(v4) => mac.update(&v4.octets()),
        std::net::IpAddr::V6(v6) => mac.update(&v6.octets()),
    }
    mac.update(&addr.port().to_be_bytes());
    mac.update(&bucket.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// What the demultiplexer should do with a datagram from an unknown address.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The address is validated; proceed to allocate state.
    Accept,
    /// Send these bytes back and allocate nothing.
    SendHelloVerifyRequest(Vec<u8>),
    /// Not a ClientHello, or malformed. Drop it in silence — replying would
    /// make this an amplifier for whatever the sender actually sent.
    Drop,
}

/// Decide whether a first datagram has proved its source address.
pub fn check(datagram: &[u8], remote: SocketAddr) -> Verdict {
    let Some(key) = cookie_key() else {
        // Gate disabled; the error was logged once at startup.
        return Verdict::Accept;
    };
    let Some(hello) = parse_client_hello(datagram) else {
        return Verdict::Drop;
    };

    let now = bucket_now();
    // The previous bucket too: a handshake that crosses a boundary must not
    // fail for arriving one second late.
    for bucket in [now, now.saturating_sub(1)] {
        let expected = compute(key, &remote, bucket);
        if constant_time_eq(hello.cookie, &expected) {
            return Verdict::Accept;
        }
    }

    Verdict::SendHelloVerifyRequest(build_hello_verify_request(
        &compute(key, &remote, now),
        hello.message_seq,
        hello.record_epoch,
        hello.record_seq,
    ))
}

struct ClientHello<'a> {
    cookie: &'a [u8],
    message_seq: u16,
    record_epoch: u16,
    record_seq: [u8; 6],
}

/// Parse only as far as the cookie.
///
/// Everything after it — cipher suites, compression, extensions — is the
/// client's business and none of it is read here. Parsing less is the point:
/// this runs on unvalidated input from anybody, so every field it touches is
/// attack surface, and it touches five.
fn parse_client_hello(buf: &[u8]) -> Option<ClientHello<'_>> {
    if buf.len() < RECORD_HEADER + HANDSHAKE_HEADER {
        return None;
    }
    if buf[0] != CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let record_epoch = u16::from_be_bytes([buf[3], buf[4]]);
    // Epoch 0 is the only one a ClientHello can arrive in. Anything else on a
    // first datagram is not the start of a handshake.
    if record_epoch != 0 {
        return None;
    }
    let mut record_seq = [0u8; 6];
    record_seq.copy_from_slice(&buf[5..11]);
    let record_len = u16::from_be_bytes([buf[11], buf[12]]) as usize;
    if buf.len() < RECORD_HEADER + record_len || record_len < HANDSHAKE_HEADER {
        return None;
    }
    let hs = &buf[RECORD_HEADER..RECORD_HEADER + record_len];
    if hs[0] != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let message_seq = u16::from_be_bytes([hs[4], hs[5]]);
    // A fragmented ClientHello is refused rather than reassembled: reassembly
    // means holding state for an unvalidated address, which is the thing this
    // module exists to avoid. A ClientHello that needs fragmenting is far
    // outside anything a normal client sends.
    let frag_offset = u32::from_be_bytes([0, hs[6], hs[7], hs[8]]);
    let frag_len = u32::from_be_bytes([0, hs[9], hs[10], hs[11]]) as usize;
    let hs_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
    if frag_offset != 0 || frag_len != hs_len {
        return None;
    }
    let body = hs.get(HANDSHAKE_HEADER..HANDSHAKE_HEADER + frag_len)?;

    // ClientHello body: version(2) random(32) session_id_len(1) session_id
    //                   cookie_len(1) cookie ...
    let mut p = 2 + 32;
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    let cookie_len = *body.get(p)? as usize;
    p += 1;
    let cookie = body.get(p..p + cookie_len)?;

    Some(ClientHello {
        cookie,
        message_seq,
        record_epoch,
        record_seq,
    })
}

/// Build the HelloVerifyRequest record carrying `cookie`.
///
/// `message_seq` is echoed from the ClientHello, as RFC 6347 §4.2.1 requires:
/// the client's next ClientHello uses `message_seq + 1`, and a server that
/// invented its own number would leave the client unable to match the flight.
fn build_hello_verify_request(
    cookie: &[u8; 32],
    message_seq: u16,
    record_epoch: u16,
    record_seq: [u8; 6],
) -> Vec<u8> {
    // body: server_version(2) cookie_len(1) cookie
    let body_len = 2 + 1 + cookie.len();
    let mut out = Vec::with_capacity(RECORD_HEADER + HANDSHAKE_HEADER + body_len);

    out.push(CONTENT_TYPE_HANDSHAKE);
    out.extend_from_slice(&DTLS_1_0);
    out.extend_from_slice(&record_epoch.to_be_bytes());
    out.extend_from_slice(&record_seq);
    out.extend_from_slice(&((HANDSHAKE_HEADER + body_len) as u16).to_be_bytes());

    out.push(HANDSHAKE_HELLO_VERIFY_REQUEST);
    let l = (body_len as u32).to_be_bytes();
    out.extend_from_slice(&l[1..4]); // length, 24-bit
    out.extend_from_slice(&message_seq.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0]); // fragment_offset
    out.extend_from_slice(&l[1..4]); // fragment_length == length

    out.extend_from_slice(&DTLS_1_0);
    out.push(cookie.len() as u8);
    out.extend_from_slice(cookie);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(cookie: &[u8]) -> Vec<u8> {
        let body_len = 2 + 32 + 1 + 1 + cookie.len();
        let mut hs = Vec::new();
        hs.push(HANDSHAKE_CLIENT_HELLO);
        let l = (body_len as u32).to_be_bytes();
        hs.extend_from_slice(&l[1..4]);
        hs.extend_from_slice(&0u16.to_be_bytes()); // message_seq
        hs.extend_from_slice(&[0, 0, 0]); // fragment_offset
        hs.extend_from_slice(&l[1..4]);
        hs.extend_from_slice(&[0xfe, 0xfd]); // client_version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id_len
        hs.push(cookie.len() as u8);
        hs.extend_from_slice(cookie);

        let mut rec = Vec::new();
        rec.push(CONTENT_TYPE_HANDSHAKE);
        rec.extend_from_slice(&[0xfe, 0xfd]);
        rec.extend_from_slice(&0u16.to_be_bytes()); // epoch
        rec.extend_from_slice(&[0u8; 6]); // sequence
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn addr(port: u16) -> SocketAddr {
        format!("192.0.2.7:{port}").parse().unwrap()
    }

    /// The whole point: an unproven address is answered without allocating.
    #[test]
    fn a_cookieless_client_hello_gets_a_hello_verify_request() {
        let Verdict::SendHelloVerifyRequest(reply) = check(&hello(&[]), addr(5000)) else {
            panic!("a ClientHello with no cookie must be challenged, not accepted");
        };
        assert_eq!(reply[0], CONTENT_TYPE_HANDSHAKE);
        assert_eq!(reply[RECORD_HEADER], HANDSHAKE_HELLO_VERIFY_REQUEST);
    }

    /// And the cookie it just issued is accepted when replayed from the same
    /// address.
    #[test]
    fn the_issued_cookie_validates_from_the_same_address() {
        let a = addr(5001);
        let Verdict::SendHelloVerifyRequest(reply) = check(&hello(&[]), a) else {
            panic!("expected a challenge");
        };
        // cookie sits after the record header, handshake header and
        // server_version + cookie_len
        let off = RECORD_HEADER + HANDSHAKE_HEADER + 3;
        let cookie = &reply[off..];
        assert_eq!(check(&hello(cookie), a), Verdict::Accept);
    }

    /// Binding to the address is what makes the cookie worth issuing: one
    /// harvested by a real client is useless from anywhere else.
    #[test]
    fn a_cookie_does_not_travel_to_another_address() {
        let Verdict::SendHelloVerifyRequest(reply) = check(&hello(&[]), addr(5002)) else {
            panic!("expected a challenge");
        };
        let off = RECORD_HEADER + HANDSHAKE_HEADER + 3;
        let cookie = reply[off..].to_vec();
        assert!(
            matches!(
                check(&hello(&cookie), addr(5003)),
                Verdict::SendHelloVerifyRequest(_)
            ),
            "a cookie issued to one address must not validate another"
        );
    }

    /// Anything that is not a well-formed ClientHello is dropped in silence.
    /// Replying would make this an amplifier for whatever was actually sent.
    #[test]
    fn malformed_input_is_dropped_not_answered() {
        assert_eq!(check(&[], addr(5004)), Verdict::Drop);
        assert_eq!(check(&[22, 0, 0], addr(5004)), Verdict::Drop);
        // Right shape, wrong content type.
        let mut d = hello(&[]);
        d[0] = 23;
        assert_eq!(check(&d, addr(5004)), Verdict::Drop);
        // Truncated cookie length.
        let mut d = hello(&[]);
        let last = d.len() - 1;
        d[last] = 200;
        assert_eq!(check(&d, addr(5004)), Verdict::Drop);
    }
}
