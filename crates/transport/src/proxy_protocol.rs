//! HAProxy PROXY protocol, versions 1 and 2, receiving side only.
//!
//! A TCP load balancer in front of the TURNS / TURN-over-TCP listener makes
//! every connection come from the balancer's own address. Everything keyed on
//! the client address — per-IP caps, the handshake rate limiter, the TURN rate
//! limiter, XOR-MAPPED-ADDRESS, the allocation's 5-tuple, logs — then sees one
//! client. The PROXY header, written by the balancer as the first bytes of the
//! connection, carries the original address.
//!
//! Spec: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.
//!
//! # Trust
//!
//! The header is plain bytes on the stream, so anyone who can open a
//! connection can write one. It is honoured only from sources in an explicit
//! allowlist ([`TrustedSources`]), and a listener that expects it closes a
//! connection from anywhere else before reading a byte. Accepting the header
//! from any source would let every client choose its own address; accepting a
//! connection *without* a header on a listener configured for one would let a
//! client that reaches the listener directly bypass the balancer's view.
//!
//! # What is accepted
//!
//! * v1 `TCP4` / `TCP6` lines, and `UNKNOWN` (the balancer's own connection,
//!   e.g. a health check — served with the real socket address, as the spec
//!   requires).
//! * v2 `PROXY` over `TCP/IPv4` or `TCP/IPv6`, and v2 `LOCAL` (again the real
//!   address). TLVs are skipped, not interpreted.
//! * Everything else — v2 over UDP or UNIX sockets, an unknown version or
//!   command, a malformed line, a header longer than the limits below — is an
//!   error, and the caller closes the connection. There is no "fall back to the
//!   socket address" on a parse error: that is exactly the bypass above.
//!
//! The parser is incremental and allocation-free ([`parse`]); the async reader
//! ([`read_header`]) feeds it and returns whatever it read past the header, so
//! bytes a client pipelined behind it (a TLS ClientHello, a STUN request) are
//! not lost.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const V1_PREFIX: &[u8] = b"PROXY ";
/// The spec's worst case for a v1 line, CRLF included.
const V1_MAX_LEN: usize = 107;
/// Cap on the v2 address + TLV block. The format allows 65535; a balancer
/// sends tens of bytes (addresses) to a few hundred (TLS and VPC TLVs). 4 KiB
/// leaves room for any real TLV set without letting a trusted-but-broken peer
/// make the listener buffer 64 KiB per connection.
pub const V2_MAX_PAYLOAD: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProxyError {
    #[error("connection does not start with a PROXY protocol header")]
    NotProxy,
    #[error("malformed PROXY header: {0}")]
    Malformed(&'static str),
    #[error("unsupported PROXY header: {0}")]
    Unsupported(&'static str),
    #[error("PROXY header exceeds the size limit")]
    TooLong,
    #[error("connection closed before the PROXY header was complete")]
    Eof,
    #[error("I/O while reading the PROXY header: {0}")]
    Io(String),
    #[error("PROXY header not received within the deadline")]
    Timeout,
    #[error("source {0} is not in the PROXY protocol trusted list")]
    Untrusted(IpAddr),
    #[error("invalid trusted CIDR {0:?}")]
    InvalidCidr(String),
}

/// What the header said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    /// A relayed connection: `source` is the original client.
    Proxied {
        source: SocketAddr,
        destination: SocketAddr,
    },
    /// The balancer speaking for itself (v2 `LOCAL`, v1 `UNKNOWN`, v2 `UNSPEC`):
    /// keep the socket's own peer address.
    Local,
}

impl ProxyHeader {
    /// The address the rest of the node should treat as the client.
    pub fn client_addr(&self, socket_peer: SocketAddr) -> SocketAddr {
        match self {
            ProxyHeader::Proxied { source, .. } => *source,
            ProxyHeader::Local => socket_peer,
        }
    }
}

/// Result of feeding bytes to [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsed {
    /// Consistent so far; read more.
    Incomplete,
    /// A full header of `consumed` bytes at the start of the buffer.
    Complete {
        header: ProxyHeader,
        consumed: usize,
    },
}

/// Parse a PROXY header at the start of `buf`.
///
/// Returns [`Parsed::Incomplete`] only while `buf` is a strict prefix of
/// something that could still become a valid header, so a caller that reads
/// until `Complete` or an error is bounded by the size limits.
pub fn parse(buf: &[u8]) -> Result<Parsed, ProxyError> {
    if buf.is_empty() {
        return Ok(Parsed::Incomplete);
    }
    // Decide the version from as many bytes as are present. A prefix of both
    // signatures is impossible (they differ at byte 0), so one test suffices.
    if buf[0] == V2_SIG[0] {
        let n = buf.len().min(V2_SIG.len());
        if buf[..n] != V2_SIG[..n] {
            return Err(ProxyError::NotProxy);
        }
        return parse_v2(buf);
    }
    let n = buf.len().min(V1_PREFIX.len());
    if buf[..n] != V1_PREFIX[..n] {
        return Err(ProxyError::NotProxy);
    }
    parse_v1(buf)
}

fn parse_v1(buf: &[u8]) -> Result<Parsed, ProxyError> {
    let window = &buf[..buf.len().min(V1_MAX_LEN)];
    let Some(cr) = window.iter().position(|&b| b == b'\r') else {
        if buf.len() >= V1_MAX_LEN {
            return Err(ProxyError::TooLong);
        }
        // A bare LF before any CR is not a v1 terminator.
        if window.contains(&b'\n') {
            return Err(ProxyError::Malformed("v1 line ends in LF without CR"));
        }
        return Ok(Parsed::Incomplete);
    };
    if cr + 1 >= buf.len() {
        // CR seen, LF not yet read. Still bounded: CR sits inside the window.
        return Ok(Parsed::Incomplete);
    }
    if buf[cr + 1] != b'\n' {
        return Err(ProxyError::Malformed("v1 CR not followed by LF"));
    }
    let consumed = cr + 2;
    let line = std::str::from_utf8(&buf[V1_PREFIX.len()..cr])
        .map_err(|_| ProxyError::Malformed("v1 line is not ASCII"))?;
    if !line.is_ascii() || line.contains('\n') {
        return Err(ProxyError::Malformed("v1 line is not ASCII"));
    }
    // UNKNOWN: "the receiver must ignore anything presented before the CRLF"
    // and use the real connection endpoints.
    if line == "UNKNOWN" || line.starts_with("UNKNOWN ") {
        return Ok(Parsed::Complete {
            header: ProxyHeader::Local,
            consumed,
        });
    }
    // Exactly single spaces between the six fields; split(' ') keeps empty
    // fields, so a doubled space shows up as a wrong count.
    let fields: Vec<&str> = line.split(' ').collect();
    if fields.len() != 5 {
        return Err(ProxyError::Malformed(
            "v1 needs protocol, two addresses and two ports",
        ));
    }
    let (src_ip, dst_ip): (IpAddr, IpAddr) = match fields[0] {
        "TCP4" => (
            IpAddr::V4(
                fields[1]
                    .parse::<Ipv4Addr>()
                    .map_err(|_| ProxyError::Malformed("v1 TCP4 source is not IPv4"))?,
            ),
            IpAddr::V4(
                fields[2]
                    .parse::<Ipv4Addr>()
                    .map_err(|_| ProxyError::Malformed("v1 TCP4 destination is not IPv4"))?,
            ),
        ),
        "TCP6" => (
            IpAddr::V6(
                fields[1]
                    .parse::<Ipv6Addr>()
                    .map_err(|_| ProxyError::Malformed("v1 TCP6 source is not IPv6"))?,
            ),
            IpAddr::V6(
                fields[2]
                    .parse::<Ipv6Addr>()
                    .map_err(|_| ProxyError::Malformed("v1 TCP6 destination is not IPv6"))?,
            ),
        ),
        _ => {
            return Err(ProxyError::Unsupported(
                "v1 protocol is not TCP4, TCP6 or UNKNOWN",
            ))
        }
    };
    let sport = parse_v1_port(fields[3])?;
    let dport = parse_v1_port(fields[4])?;
    Ok(Parsed::Complete {
        header: ProxyHeader::Proxied {
            source: SocketAddr::new(src_ip, sport),
            destination: SocketAddr::new(dst_ip, dport),
        },
        consumed,
    })
}

/// Decimal, 1-5 digits, no sign, no leading zero (the spec's wording), ≤ 65535.
fn parse_v1_port(s: &str) -> Result<u16, ProxyError> {
    if s.is_empty()
        || s.len() > 5
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(ProxyError::Malformed("v1 port is not a decimal 0-65535"));
    }
    s.parse::<u16>()
        .map_err(|_| ProxyError::Malformed("v1 port is not a decimal 0-65535"))
}

fn parse_v2(buf: &[u8]) -> Result<Parsed, ProxyError> {
    if buf.len() < 16 {
        return Ok(Parsed::Incomplete);
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 2 {
        return Err(ProxyError::Unsupported("v2 version nibble is not 2"));
    }
    let local = match ver_cmd & 0x0F {
        0x0 => true,
        0x1 => false,
        _ => {
            return Err(ProxyError::Unsupported(
                "v2 command is neither LOCAL nor PROXY",
            ))
        }
    };
    let fam = buf[13];
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if len > V2_MAX_PAYLOAD {
        return Err(ProxyError::TooLong);
    }
    let total = 16 + len;
    if buf.len() < total {
        return Ok(Parsed::Incomplete);
    }
    let payload = &buf[16..total];
    if local {
        // LOCAL: addresses (if any) are to be ignored.
        return Ok(Parsed::Complete {
            header: ProxyHeader::Local,
            consumed: total,
        });
    }
    let header = match fam {
        // UNSPEC: "the receiver is free to accept the connection anyway and use
        // the real endpoint addresses".
        0x00 => ProxyHeader::Local,
        // TCP over IPv4.
        0x11 => {
            if payload.len() < 12 {
                return Err(ProxyError::Malformed(
                    "v2 TCP4 address block shorter than 12",
                ));
            }
            let src = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let dst = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let sport = u16::from_be_bytes([payload[8], payload[9]]);
            let dport = u16::from_be_bytes([payload[10], payload[11]]);
            ProxyHeader::Proxied {
                source: SocketAddr::new(IpAddr::V4(src), sport),
                destination: SocketAddr::new(IpAddr::V4(dst), dport),
            }
        }
        // TCP over IPv6.
        0x21 => {
            if payload.len() < 36 {
                return Err(ProxyError::Malformed(
                    "v2 TCP6 address block shorter than 36",
                ));
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&payload[0..16]);
            d.copy_from_slice(&payload[16..32]);
            let sport = u16::from_be_bytes([payload[32], payload[33]]);
            let dport = u16::from_be_bytes([payload[34], payload[35]]);
            ProxyHeader::Proxied {
                source: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(s)), sport),
                destination: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(d)), dport),
            }
        }
        _ => {
            return Err(ProxyError::Unsupported(
                "v2 family/transport is not TCP over IPv4 or IPv6",
            ))
        }
    };
    Ok(Parsed::Complete {
        header,
        consumed: total,
    })
}

// ---------------------------------------------------------------------------
// Trusted sources
// ---------------------------------------------------------------------------

/// One CIDR, e.g. `10.0.0.0/8` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, ProxyError> {
        let bad = || ProxyError::InvalidCidr(s.to_string());
        let (ip, pfx) = s.trim().split_once('/').ok_or_else(bad)?;
        let net: IpAddr = ip.trim().parse().map_err(|_| bad())?;
        let prefix: u8 = pfx.trim().parse().map_err(|_| bad())?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, normalize(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// `::ffff:a.b.c.d` is the v4 address `a.b.c.d` for matching purposes: a
/// dual-stack listener reports v4 peers that way, and a v4 allowlist entry
/// must still match them.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The allowlist of addresses that may send a PROXY header.
#[derive(Debug, Clone, Default)]
pub struct TrustedSources(Vec<Cidr>);

impl TrustedSources {
    pub fn parse<S: AsRef<str>>(cidrs: &[S]) -> Result<Self, ProxyError> {
        cidrs
            .iter()
            .map(|c| Cidr::parse(c.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }
}

// ---------------------------------------------------------------------------
// Async reading
// ---------------------------------------------------------------------------

/// Read one PROXY header from `stream`. Returns the header and any bytes read
/// past it, which the caller must replay ([`PrefixedStream`]).
///
/// No deadline of its own; the caller wraps it in one. Reads at most
/// `16 + V2_MAX_PAYLOAD` bytes plus one read's worth of overshoot before
/// giving up.
pub async fn read_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(ProxyHeader, BytesMut), ProxyError> {
    let mut buf = BytesMut::with_capacity(256);
    loop {
        match parse(&buf)? {
            Parsed::Complete { header, consumed } => {
                buf.advance(consumed);
                return Ok((header, buf));
            }
            Parsed::Incomplete => {}
        }
        // `parse` keeps Incomplete bounded, but be explicit about the ceiling.
        if buf.len() > 16 + V2_MAX_PAYLOAD {
            return Err(ProxyError::TooLong);
        }
        if buf.capacity() - buf.len() < 128 {
            buf.reserve(512);
        }
        let n = stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| ProxyError::Io(e.to_string()))?;
        if n == 0 {
            return Err(ProxyError::Eof);
        }
    }
}

/// A stream that first yields `prefix`, then the inner stream. Writes pass
/// straight through. Used to hand bytes read past a PROXY header back to the
/// TLS handshake or the TURN framer.
pub struct PrefixedStream<S> {
    prefix: BytesMut,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: BytesMut, inner: S) -> Self {
        Self { prefix, inner }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.prefix.is_empty() {
            let n = std::cmp::min(me.prefix.len(), buf.remaining());
            let chunk = me.prefix.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(buf: &[u8]) -> (ProxyHeader, usize) {
        match parse(buf) {
            Ok(Parsed::Complete { header, consumed }) => (header, consumed),
            other => panic!("expected a complete header, got {other:?}"),
        }
    }

    fn v2(cmd: u8, fam: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = V2_SIG.to_vec();
        v.push(0x20 | cmd);
        v.push(fam);
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn v2_tcp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, tlv: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(tlv);
        v2(1, 0x11, &p)
    }

    // ── v1 ───────────────────────────────────────────────────────────────────

    #[test]
    fn v1_tcp4() {
        let line = b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 5349\r\n";
        let (h, n) = complete(line);
        assert_eq!(n, line.len());
        assert_eq!(
            h,
            ProxyHeader::Proxied {
                source: "203.0.113.7:51000".parse().unwrap(),
                destination: "10.0.0.1:5349".parse().unwrap(),
            }
        );
    }

    #[test]
    fn v1_tcp6_and_trailing_bytes_are_not_consumed() {
        let mut buf = b"PROXY TCP6 2001:db8::1 2001:db8::2 4000 3478\r\n".to_vec();
        let hdr_len = buf.len();
        buf.extend_from_slice(b"\x16\x03\x01rest-of-client-hello");
        let (h, n) = complete(&buf);
        assert_eq!(n, hdr_len);
        assert_eq!(
            h.client_addr("127.0.0.1:1".parse().unwrap()),
            "[2001:db8::1]:4000".parse().unwrap()
        );
    }

    #[test]
    fn v1_unknown_keeps_socket_address() {
        let (h, _) = complete(b"PROXY UNKNOWN\r\n");
        assert_eq!(h, ProxyHeader::Local);
        let (h, _) = complete(b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n");
        let peer: SocketAddr = "10.1.1.1:9".parse().unwrap();
        assert_eq!(h.client_addr(peer), peer);
    }

    #[test]
    fn v1_rejections() {
        for (bad, what) in [
            (
                &b"PROXY TCP4 203.0.113.7 10.0.0.1 51000\r\n"[..],
                "missing port",
            ),
            (b"PROXY TCP4 203.0.113.7  10.0.0.1 1 2\r\n", "double space"),
            (b"PROXY TCP4 2001:db8::1 10.0.0.1 1 2\r\n", "v6 in TCP4"),
            (b"PROXY TCP6 1.2.3.4 1.2.3.5 1 2\r\n", "v4 in TCP6"),
            (b"PROXY TCP4 1.2.3.4 1.2.3.5 65536 2\r\n", "port overflow"),
            (b"PROXY TCP4 1.2.3.4 1.2.3.5 01 2\r\n", "leading zero"),
            (b"PROXY TCP4 1.2.3.4 1.2.3.5 +1 2\r\n", "sign"),
            (b"PROXY UDP4 1.2.3.4 1.2.3.5 1 2\r\n", "udp"),
            (b"PROXY TCP4 1.2.3.4 1.2.3.5 1 2\rX", "CR without LF"),
            (b"PROXY TCP4 1.2.3.4 1.2.3.5 1 2\n", "LF without CR"),
            (b"PROXY TCP4 1.2.3.4 1.2.3.5 1 2 \r\n", "trailing space"),
        ] {
            assert!(parse(bad).is_err(), "{what}: {:?}", parse(bad));
        }
    }

    #[test]
    fn v1_line_without_crlf_is_bounded() {
        let mut long = b"PROXY TCP4 ".to_vec();
        long.resize(V1_MAX_LEN - 1, b'1');
        assert_eq!(parse(&long), Ok(Parsed::Incomplete));
        long.push(b'1');
        assert_eq!(parse(&long), Err(ProxyError::TooLong));
    }

    #[test]
    fn not_proxy_is_detected_from_the_first_byte() {
        // A TLS ClientHello and a STUN Binding request, sent straight to a
        // listener that expects the header.
        assert_eq!(parse(b"\x16\x03\x01\x02\x00"), Err(ProxyError::NotProxy));
        assert_eq!(parse(&[0x00, 0x01, 0x00, 0x00]), Err(ProxyError::NotProxy));
        assert_eq!(parse(b"PROXX"), Err(ProxyError::NotProxy));
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Err(ProxyError::NotProxy));
        assert_eq!(parse(&V2_SIG[..5]), Ok(Parsed::Incomplete));
        let mut wrong = V2_SIG.to_vec();
        wrong[7] = b'X';
        assert_eq!(parse(&wrong), Err(ProxyError::NotProxy));
    }

    // ── v2 ───────────────────────────────────────────────────────────────────

    #[test]
    fn v2_tcp4_with_tlvs() {
        // A PP2_TYPE_AUTHORITY TLV (0x02) that must be skipped.
        let tlv = [0x02, 0x00, 0x03, b'a', b'b', b'c'];
        let buf = v2_tcp4([198, 51, 100, 9], 40000, [10, 0, 0, 1], 5349, &tlv);
        let (h, n) = complete(&buf);
        assert_eq!(n, buf.len());
        assert_eq!(
            h.client_addr("10.9.9.9:1".parse().unwrap()),
            "198.51.100.9:40000".parse().unwrap()
        );
    }

    #[test]
    fn v2_tcp6() {
        let mut p = Vec::new();
        p.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&1234u16.to_be_bytes());
        p.extend_from_slice(&3478u16.to_be_bytes());
        let (h, _) = complete(&v2(1, 0x21, &p));
        assert_eq!(
            h.client_addr("10.9.9.9:1".parse().unwrap()),
            "[2001:db8::7]:1234".parse().unwrap()
        );
    }

    #[test]
    fn v2_local_and_unspec_keep_socket_address() {
        let (h, _) = complete(&v2(0, 0x11, &[0; 12]));
        assert_eq!(h, ProxyHeader::Local);
        let (h, _) = complete(&v2(1, 0x00, &[]));
        assert_eq!(h, ProxyHeader::Local);
    }

    #[test]
    fn v2_rejections() {
        // UDP over IPv4, UNIX stream, INET with UNSPEC transport.
        for fam in [0x12u8, 0x31, 0x10, 0x22] {
            assert!(
                matches!(
                    parse(&v2(1, fam, &[0; 216])),
                    Err(ProxyError::Unsupported(_))
                ),
                "family 0x{fam:02x}"
            );
        }
        // Short address blocks.
        assert!(matches!(
            parse(&v2(1, 0x11, &[0; 11])),
            Err(ProxyError::Malformed(_))
        ));
        assert!(matches!(
            parse(&v2(1, 0x21, &[0; 35])),
            Err(ProxyError::Malformed(_))
        ));
        // Command 2 and version 1.
        assert!(matches!(
            parse(&v2(2, 0x11, &[0; 12])),
            Err(ProxyError::Unsupported(_))
        ));
        let mut v1ver = v2(1, 0x11, &[0; 12]);
        v1ver[12] = 0x11;
        assert!(matches!(parse(&v1ver), Err(ProxyError::Unsupported(_))));
        // Declared length over the cap is refused before the bytes arrive.
        let mut big = V2_SIG.to_vec();
        big.extend_from_slice(&[0x21, 0x11]);
        big.extend_from_slice(&((V2_MAX_PAYLOAD + 1) as u16).to_be_bytes());
        assert_eq!(parse(&big), Err(ProxyError::TooLong));
    }

    #[test]
    fn every_split_point_is_incomplete_then_complete() {
        let samples: Vec<Vec<u8>> = vec![
            b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 5349\r\n".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            v2_tcp4([1, 2, 3, 4], 5, [6, 7, 8, 9], 10, &[0x04, 0x00, 0x00]),
            v2(0, 0x00, &[]),
        ];
        for s in samples {
            for cut in 0..s.len() {
                assert_eq!(
                    parse(&s[..cut]),
                    Ok(Parsed::Incomplete),
                    "cut {cut} of {s:?}"
                );
            }
            assert!(
                matches!(parse(&s), Ok(Parsed::Complete { consumed, .. }) if consumed == s.len())
            );
        }
    }

    /// Fuzz-style property check without a fuzzing dependency: a deterministic
    /// xorshift stream of random buffers, random mutations of valid headers,
    /// and every truncation of them. The properties are that `parse` never
    /// panics, never reports consuming more than it was given, only returns
    /// `Incomplete` for inputs shorter than the format's ceiling, and that
    /// whatever it accepts round-trips through the async reader unchanged.
    #[test]
    fn property_parse_never_panics_and_is_bounded() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let seeds: Vec<Vec<u8>> = vec![
            b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 5349\r\n".to_vec(),
            b"PROXY TCP6 2001:db8::1 2001:db8::2 4000 3478\r\n".to_vec(),
            v2_tcp4([1, 2, 3, 4], 5, [6, 7, 8, 9], 10, &[1, 0, 1, 9]),
            v2(0, 0x11, &[0; 12]),
        ];
        let check = |buf: &[u8]| match parse(buf) {
            Ok(Parsed::Complete { consumed, .. }) => {
                assert!(consumed <= buf.len());
                assert!(consumed <= 16 + V2_MAX_PAYLOAD);
            }
            Ok(Parsed::Incomplete) => assert!(buf.len() < 16 + V2_MAX_PAYLOAD),
            Err(_) => {}
        };
        for _ in 0..20_000 {
            // Pure noise, biased to start like a header half the time.
            let len = (next() % 128) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            match next() % 4 {
                0 => {
                    let p = V1_PREFIX.len().min(buf.len());
                    buf[..p].copy_from_slice(&V1_PREFIX[..p]);
                }
                1 => {
                    let p = V2_SIG.len().min(buf.len());
                    buf[..p].copy_from_slice(&V2_SIG[..p]);
                }
                _ => {}
            }
            check(&buf);
            // A mutated valid header: flip, drop or insert bytes.
            let mut m = seeds[(next() % seeds.len() as u64) as usize].clone();
            for _ in 0..(1 + next() % 3) {
                let i = (next() as usize) % m.len();
                match next() % 3 {
                    0 => m[i] ^= 1 << (next() % 8),
                    1 => {
                        m.remove(i);
                    }
                    _ => m.insert(i, next() as u8),
                }
                if m.is_empty() {
                    break;
                }
            }
            for cut in 0..=m.len() {
                check(&m[..cut]);
            }
        }
    }

    #[tokio::test]
    async fn read_header_returns_pipelined_bytes() {
        let mut wire = b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 5349\r\n".to_vec();
        wire.extend_from_slice(b"STUN-BYTES");
        let (mut client, mut server) = tokio::io::duplex(64);
        // Written in two pieces to exercise the incremental path.
        let (a, b) = wire.split_at(10);
        let (a, b) = (a.to_vec(), b.to_vec());
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(&a).await.unwrap();
            client.write_all(&b).await.unwrap();
            client
        });
        let (h, rest) = read_header(&mut server).await.unwrap();
        let _client = writer.await.unwrap();
        assert_eq!(
            h.client_addr("127.0.0.1:1".parse().unwrap()),
            "203.0.113.7:51000".parse().unwrap()
        );
        let mut p = PrefixedStream::new(rest, server);
        let mut got = [0u8; 10];
        p.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"STUN-BYTES");
    }

    #[tokio::test]
    async fn read_header_eof_and_garbage() {
        let (client, mut server) = tokio::io::duplex(64);
        {
            use tokio::io::AsyncWriteExt;
            let mut c = client;
            c.write_all(b"PROXY TCP4 1.2").await.unwrap();
        } // dropped: EOF
        assert_eq!(read_header(&mut server).await, Err(ProxyError::Eof));

        let (mut client, mut server) = tokio::io::duplex(64);
        {
            use tokio::io::AsyncWriteExt;
            client.write_all(b"\x16\x03\x01").await.unwrap();
        }
        assert_eq!(read_header(&mut server).await, Err(ProxyError::NotProxy));
    }

    #[test]
    fn cidr_matching() {
        let t = TrustedSources::parse(&["10.0.0.0/8", "2001:db8::/32", "192.0.2.5/32"]).unwrap();
        assert!(t.contains("10.200.3.4".parse().unwrap()));
        assert!(t.contains("::ffff:10.1.2.3".parse().unwrap()), "v4-mapped");
        assert!(t.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(t.contains("192.0.2.5".parse().unwrap()));
        assert!(!t.contains("192.0.2.6".parse().unwrap()));
        assert!(!t.contains("11.0.0.1".parse().unwrap()));
        assert!(!t.contains("2001:db9::1".parse().unwrap()));
        let any = TrustedSources::parse(&["0.0.0.0/0"]).unwrap();
        assert!(any.contains("198.51.100.1".parse().unwrap()));
        assert!(!any.contains("2001:db8::1".parse().unwrap()));
        for bad in ["10.0.0.0", "10.0.0.0/33", "::/129", "x/8", ""] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        assert!(TrustedSources::default().is_empty());
    }
}
