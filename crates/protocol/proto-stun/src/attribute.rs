//! STUN/TURN attribute types and parsing

use crate::error::{Result, StunError};
use crate::header::MAGIC_COOKIE;
use std::net::SocketAddr;

// Comprehension-required attributes
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// RFC 5389 §15.5: alternate server for 300 Try Alternate redirects.
pub const ATTR_ALTERNATE_SERVER: u16 = 0x0003;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

// Comprehension-optional
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

// TURN attributes
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;

// ── DoS / abuse caps ─────────────────────────────────────────────────────────
//
// Rationale: the STUN wire format gives each attribute a u16 length field, so
// a single attribute can declare up to 65535 bytes. Without a cap, an attacker
// from the open internet can force allocations of that size on every packet,
// and `parse_attributes` happily walks them. Real attributes are far smaller:
//
//   USERNAME / REALM / NONCE / SOFTWARE: ≤ 763 bytes (RFC 5389 §15)
//   DATA (TURN Send/Data Indication):    MTU-bounded in practice (≤ ~1500)
//   Fixed-size attrs (Lifetime, etc.):   ≤ 24 bytes
//
// 1500 covers all realistic cases with margin. If a legitimate use needs more,
// raise this constant deliberately rather than removing the check.

/// Maximum allowed value length for a single STUN attribute.
pub const MAX_ATTRIBUTE_VALUE_LEN: usize = 1500;

/// Maximum number of attributes in a single STUN message. Real TURN/STUN
/// messages have 3–8 attributes; 32 is a comfortable ceiling.
pub const MAX_ATTRIBUTES_PER_MESSAGE: usize = 32;

#[derive(Debug, Clone)]
pub enum Attribute {
    MappedAddress(SocketAddr),
    AlternateServer(SocketAddr),
    XorMappedAddress(SocketAddr),
    Username(String),
    MessageIntegrity([u8; 20]),
    Fingerprint(u32),
    ErrorCode { code: u16, reason: String },
    Realm(String),
    Nonce(String),
    Software(String),
    // TURN
    Lifetime(u32),
    RequestedTransport(u8),
    XorPeerAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    ChannelNumber(u16),
    Data(Vec<u8>),
    DontFragment,
    Unknown { attr_type: u16, value: Vec<u8> },
}

impl Attribute {
    pub fn attr_type(&self) -> u16 {
        match self {
            Self::MappedAddress(_) => ATTR_MAPPED_ADDRESS,
            Self::AlternateServer(_) => ATTR_ALTERNATE_SERVER,
            Self::XorMappedAddress(_) => ATTR_XOR_MAPPED_ADDRESS,
            Self::Username(_) => ATTR_USERNAME,
            Self::MessageIntegrity(_) => ATTR_MESSAGE_INTEGRITY,
            Self::Fingerprint(_) => ATTR_FINGERPRINT,
            Self::ErrorCode { .. } => ATTR_ERROR_CODE,
            Self::Realm(_) => ATTR_REALM,
            Self::Nonce(_) => ATTR_NONCE,
            Self::Software(_) => ATTR_SOFTWARE,
            Self::Lifetime(_) => ATTR_LIFETIME,
            Self::RequestedTransport(_) => ATTR_REQUESTED_TRANSPORT,
            Self::XorPeerAddress(_) => ATTR_XOR_PEER_ADDRESS,
            Self::XorRelayedAddress(_) => ATTR_XOR_RELAYED_ADDRESS,
            Self::ChannelNumber(_) => ATTR_CHANNEL_NUMBER,
            Self::Data(_) => ATTR_DATA,
            Self::DontFragment => ATTR_DONT_FRAGMENT,
            Self::Unknown { attr_type, .. } => *attr_type,
        }
    }

    /// Encode attribute value into buffer. Returns bytes written.
    pub fn encode_value(&self, buf: &mut [u8], transaction_id: &[u8; 12]) -> usize {
        match self {
            Self::XorMappedAddress(addr)
            | Self::XorPeerAddress(addr)
            | Self::XorRelayedAddress(addr) => encode_xor_address(buf, addr, transaction_id),
            // RFC 5389 §15.5: ALTERNATE-SERVER is encoded like MAPPED-ADDRESS
            // (plain, NOT XOR). Encoding it as XOR breaks spec-compliant
            // clients (pion, libnice) parsing the 300 Try Alternate redirect.
            Self::MappedAddress(addr) | Self::AlternateServer(addr) => {
                encode_address(buf, addr)
            }
            Self::Username(s) | Self::Realm(s) | Self::Nonce(s) | Self::Software(s) => {
                let b = s.as_bytes();
                buf[..b.len()].copy_from_slice(b);
                b.len()
            }
            Self::MessageIntegrity(hmac) => {
                buf[..20].copy_from_slice(hmac);
                20
            }
            Self::Fingerprint(fp) => {
                buf[..4].copy_from_slice(&fp.to_be_bytes());
                4
            }
            Self::ErrorCode { code, reason } => {
                let class = (*code / 100) as u8;
                let number = (*code % 100) as u8;
                buf[0] = 0;
                buf[1] = 0;
                buf[2] = class;
                buf[3] = number;
                let rb = reason.as_bytes();
                buf[4..4 + rb.len()].copy_from_slice(rb);
                4 + rb.len()
            }
            Self::Lifetime(secs) => {
                buf[..4].copy_from_slice(&secs.to_be_bytes());
                4
            }
            Self::RequestedTransport(proto) => {
                buf[0] = *proto;
                buf[1] = 0;
                buf[2] = 0;
                buf[3] = 0;
                4
            }
            Self::ChannelNumber(ch) => {
                buf[..2].copy_from_slice(&ch.to_be_bytes());
                buf[2] = 0;
                buf[3] = 0;
                4
            }
            Self::Data(data) => {
                buf[..data.len()].copy_from_slice(data);
                data.len()
            }
            Self::DontFragment => 0,
            Self::Unknown { value, .. } => {
                buf[..value.len()].copy_from_slice(value);
                value.len()
            }
        }
    }
}

pub fn decode_xor_address(buf: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    if buf.len() < 8 {
        return Err(StunError::AttributeParse("xor address too short".into()));
    }
    let family = buf[1];
    let xor_port = u16::from_be_bytes([buf[2], buf[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            let xor_ip = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let ip = xor_ip ^ MAGIC_COOKIE;
            let addr = std::net::Ipv4Addr::from(ip);
            Ok(SocketAddr::new(addr.into(), port))
        }
        0x02 => {
            if buf.len() < 20 {
                return Err(StunError::AttributeParse(
                    "ipv6 xor address too short".into(),
                ));
            }
            let mut xor_ip = [0u8; 16];
            xor_ip.copy_from_slice(&buf[4..20]);
            let mut cookie_tid = [0u8; 16];
            cookie_tid[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            cookie_tid[4..].copy_from_slice(transaction_id);
            for i in 0..16 {
                xor_ip[i] ^= cookie_tid[i];
            }
            let addr = std::net::Ipv6Addr::from(xor_ip);
            Ok(SocketAddr::new(addr.into(), port))
        }
        _ => Err(StunError::AttributeParse(format!(
            "unknown address family: {family}"
        ))),
    }
}

pub fn encode_xor_address(buf: &mut [u8], addr: &SocketAddr, transaction_id: &[u8; 12]) -> usize {
    let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
    buf[0] = 0;
    match addr {
        SocketAddr::V4(v4) => {
            buf[1] = 0x01;
            buf[2..4].copy_from_slice(&port.to_be_bytes());
            let ip = u32::from_be_bytes(v4.ip().octets()) ^ MAGIC_COOKIE;
            buf[4..8].copy_from_slice(&ip.to_be_bytes());
            8
        }
        SocketAddr::V6(v6) => {
            buf[1] = 0x02;
            buf[2..4].copy_from_slice(&port.to_be_bytes());
            let mut ip_bytes = v6.ip().octets();
            let mut cookie_tid = [0u8; 16];
            cookie_tid[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            cookie_tid[4..].copy_from_slice(transaction_id);
            for i in 0..16 {
                ip_bytes[i] ^= cookie_tid[i];
            }
            buf[4..20].copy_from_slice(&ip_bytes);
            20
        }
    }
}

pub fn encode_address(buf: &mut [u8], addr: &SocketAddr) -> usize {
    buf[0] = 0;
    match addr {
        SocketAddr::V4(v4) => {
            buf[1] = 0x01;
            buf[2..4].copy_from_slice(&addr.port().to_be_bytes());
            buf[4..8].copy_from_slice(&v4.ip().octets());
            8
        }
        SocketAddr::V6(v6) => {
            buf[1] = 0x02;
            buf[2..4].copy_from_slice(&addr.port().to_be_bytes());
            buf[4..20].copy_from_slice(&v6.ip().octets());
            20
        }
    }
}

pub fn decode_address(buf: &[u8]) -> Result<SocketAddr> {
    if buf.len() < 8 {
        return Err(StunError::AttributeParse("address too short".into()));
    }
    let family = buf[1];
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Ok(SocketAddr::new(ip.into(), port))
        }
        0x02 => {
            if buf.len() < 20 {
                return Err(StunError::AttributeParse("ipv6 too short".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => Err(StunError::AttributeParse(format!(
            "unknown family: {family}"
        ))),
    }
}

pub fn parse_attributes(buf: &[u8], transaction_id: &[u8; 12]) -> Result<Vec<Attribute>> {
    let mut attrs = Vec::new();
    let mut pos = 0;

    while pos + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        // ── DoS guard #1: cap individual attribute value size. Reject BEFORE
        //    bounds-checking against buf so an attacker can't get a different
        //    error path for huge values.
        if attr_len > MAX_ATTRIBUTE_VALUE_LEN {
            return Err(StunError::AttributeValueTooLong {
                attr_type,
                len: attr_len,
                max: MAX_ATTRIBUTE_VALUE_LEN,
            });
        }

        if pos + attr_len > buf.len() {
            return Err(StunError::BufferTooShort {
                need: pos + attr_len,
                have: buf.len(),
            });
        }

        // ── DoS guard #2: cap total attribute count, checked BEFORE pushing.
        if attrs.len() >= MAX_ATTRIBUTES_PER_MESSAGE {
            return Err(StunError::TooManyAttributes {
                count: attrs.len() + 1,
                max: MAX_ATTRIBUTES_PER_MESSAGE,
            });
        }

        let value = &buf[pos..pos + attr_len];

        let attr = match attr_type {
            ATTR_MAPPED_ADDRESS => Attribute::MappedAddress(decode_address(value)?),
            // RFC 5389 §15.5: ALTERNATE-SERVER uses the plain MAPPED-ADDRESS
            // format, so it is decoded without XOR.
            ATTR_ALTERNATE_SERVER => Attribute::AlternateServer(decode_address(value)?),
            ATTR_XOR_MAPPED_ADDRESS => {
                Attribute::XorMappedAddress(decode_xor_address(value, transaction_id)?)
            }
            ATTR_USERNAME => Attribute::Username(String::from_utf8_lossy(value).into()),
            ATTR_MESSAGE_INTEGRITY => {
                if value.len() != 20 {
                    return Err(StunError::AttributeParse(format!(
                        "MESSAGE-INTEGRITY must be 20 bytes, got {}",
                        value.len()
                    )));
                }
                let mut hmac = [0u8; 20];
                hmac.copy_from_slice(value);
                Attribute::MessageIntegrity(hmac)
            }
            ATTR_FINGERPRINT => {
                if value.len() != 4 {
                    return Err(StunError::AttributeParse(format!(
                        "FINGERPRINT must be 4 bytes, got {}",
                        value.len()
                    )));
                }
                Attribute::Fingerprint(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            ATTR_ERROR_CODE => {
                if value.len() < 4 {
                    return Err(StunError::AttributeParse(format!(
                        "ERROR-CODE must be at least 4 bytes, got {}",
                        value.len()
                    )));
                }
                let class = value[2] as u16;
                let number = value[3] as u16;
                let code = class * 100 + number;
                let reason = String::from_utf8_lossy(&value[4..]).into();
                Attribute::ErrorCode { code, reason }
            }
            ATTR_REALM => Attribute::Realm(String::from_utf8_lossy(value).into()),
            ATTR_NONCE => Attribute::Nonce(String::from_utf8_lossy(value).into()),
            ATTR_SOFTWARE => Attribute::Software(String::from_utf8_lossy(value).into()),
            ATTR_LIFETIME => {
                if value.len() != 4 {
                    return Err(StunError::AttributeParse(format!(
                        "LIFETIME must be 4 bytes, got {}",
                        value.len()
                    )));
                }
                Attribute::Lifetime(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
            }
            ATTR_REQUESTED_TRANSPORT => {
                if value.is_empty() {
                    return Err(StunError::AttributeParse(
                        "REQUESTED-TRANSPORT empty".into(),
                    ));
                }
                Attribute::RequestedTransport(value[0])
            }
            ATTR_XOR_PEER_ADDRESS => {
                Attribute::XorPeerAddress(decode_xor_address(value, transaction_id)?)
            }
            ATTR_XOR_RELAYED_ADDRESS => {
                Attribute::XorRelayedAddress(decode_xor_address(value, transaction_id)?)
            }
            ATTR_CHANNEL_NUMBER => {
                if value.len() < 2 {
                    return Err(StunError::AttributeParse(format!(
                        "CHANNEL-NUMBER too short: {}",
                        value.len()
                    )));
                }
                Attribute::ChannelNumber(u16::from_be_bytes([value[0], value[1]]))
            }
            ATTR_DATA => Attribute::Data(value.to_vec()),
            ATTR_DONT_FRAGMENT => Attribute::DontFragment,
            _ => Attribute::Unknown {
                attr_type,
                value: value.to_vec(),
            },
        };

        attrs.push(attr);

        // Padding to 4-byte boundary
        let padded = (attr_len + 3) & !3;
        pos += padded;
    }

    Ok(attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: [u8; 12] = [0u8; 12];

    /// Build a single attribute with the given type and value, padded to 4
    /// bytes. Returns the raw bytes ready to pass to `parse_attributes`.
    fn build_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&attr_type.to_be_bytes());
        buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
        buf.extend_from_slice(value);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        buf
    }

    #[test]
    fn rejects_oversized_attribute_value() {
        // Declare an attribute claiming to be 2000 bytes (above the cap of 1500).
        // The value bytes themselves can be whatever — we should reject on the
        // length check before reading them.
        let mut buf = Vec::new();
        buf.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        buf.extend_from_slice(&2000u16.to_be_bytes());
        // Don't bother filling the body — the check fires before bounds-check.
        buf.extend_from_slice(&[0u8; 2000]);

        let err = parse_attributes(&buf, &TID).unwrap_err();
        match err {
            StunError::AttributeValueTooLong {
                attr_type,
                len,
                max,
            } => {
                assert_eq!(attr_type, ATTR_SOFTWARE);
                assert_eq!(len, 2000);
                assert_eq!(max, MAX_ATTRIBUTE_VALUE_LEN);
            }
            other => panic!("expected AttributeValueTooLong, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_too_many_attributes() {
        // Stack MAX+1 zero-length SOFTWARE attributes (4 bytes each).
        let mut buf = Vec::new();
        for _ in 0..(MAX_ATTRIBUTES_PER_MESSAGE + 1) {
            buf.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes());
        }

        let err = parse_attributes(&buf, &TID).unwrap_err();
        match err {
            StunError::TooManyAttributes { max, .. } => {
                assert_eq!(max, MAX_ATTRIBUTES_PER_MESSAGE);
            }
            other => panic!("expected TooManyAttributes, got: {other:?}"),
        }
    }

    #[test]
    fn accepts_attribute_at_max_length() {
        let body = vec![b'x'; MAX_ATTRIBUTE_VALUE_LEN];
        let buf = build_attr(ATTR_SOFTWARE, &body);

        let attrs = parse_attributes(&buf, &TID).expect("attr exactly at MAX must be accepted");
        assert_eq!(attrs.len(), 1);
        match &attrs[0] {
            Attribute::Software(s) => assert_eq!(s.len(), MAX_ATTRIBUTE_VALUE_LEN),
            other => panic!("expected Software, got: {other:?}"),
        }
    }

    #[test]
    fn accepts_attribute_one_over_max_rejected() {
        // Confirm the boundary is exact: MAX+1 fails.
        let mut buf = Vec::new();
        let bad_len = (MAX_ATTRIBUTE_VALUE_LEN + 1) as u16;
        buf.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        buf.extend_from_slice(&bad_len.to_be_bytes());
        buf.extend_from_slice(&vec![0u8; bad_len as usize]);

        let err = parse_attributes(&buf, &TID).unwrap_err();
        assert!(matches!(err, StunError::AttributeValueTooLong { .. }));
    }

    #[test]
    fn fixed_size_attrs_with_wrong_length_rejected() {
        // LIFETIME must be exactly 4 bytes. Send 3 — must error rather than
        // panic via slice indexing.
        let buf = build_attr(ATTR_LIFETIME, &[0u8; 3]);
        let err = parse_attributes(&buf, &TID).unwrap_err();
        assert!(
            matches!(err, StunError::AttributeParse(_)),
            "expected AttributeParse, got: {err:?}"
        );
    }

    #[test]
    fn message_integrity_with_wrong_length_rejected() {
        // 19 bytes instead of the required 20 — must not panic on copy_from_slice.
        let buf = build_attr(ATTR_MESSAGE_INTEGRITY, &[0u8; 19]);
        let err = parse_attributes(&buf, &TID).unwrap_err();
        assert!(matches!(err, StunError::AttributeParse(_)));
    }

    #[test]
    fn normal_message_still_parses() {
        // A realistic Allocate request: REQUESTED-TRANSPORT + LIFETIME +
        // USERNAME + REALM + NONCE + MESSAGE-INTEGRITY. All within bounds.
        let mut buf = Vec::new();
        buf.extend_from_slice(&build_attr(ATTR_REQUESTED_TRANSPORT, &[17, 0, 0, 0]));
        buf.extend_from_slice(&build_attr(ATTR_LIFETIME, &600u32.to_be_bytes()));
        buf.extend_from_slice(&build_attr(ATTR_USERNAME, b"1700000000:testuser"));
        buf.extend_from_slice(&build_attr(ATTR_REALM, b"turna"));
        buf.extend_from_slice(&build_attr(ATTR_NONCE, b"abcdefghijklmnopqrstuv"));
        buf.extend_from_slice(&build_attr(ATTR_MESSAGE_INTEGRITY, &[0u8; 20]));

        let attrs = parse_attributes(&buf, &TID).expect("normal message must parse");
        assert_eq!(attrs.len(), 6);
    }

    #[test]
    fn alternate_server_plain_address_roundtrip_ipv4() {
        let addr: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let attr = Attribute::AlternateServer(addr);
        let mut value = [0u8; 32];
        let len = attr.encode_value(&mut value, &TID);
        assert_eq!(len, 8);

        // RFC 5389 §15.5: must be plain MAPPED-ADDRESS, i.e. NOT XOR'd.
        assert_eq!(value[0], 0x00, "reserved byte");
        assert_eq!(value[1], 0x01, "IPv4 family");
        assert_eq!(u16::from_be_bytes([value[2], value[3]]), 3478, "plain port");
        assert_eq!(&value[4..8], &[192, 0, 2, 10], "plain IPv4 address");

        let buf = build_attr(ATTR_ALTERNATE_SERVER, &value[..len]);
        let attrs = parse_attributes(&buf, &TID).unwrap();
        assert!(matches!(attrs.as_slice(), [Attribute::AlternateServer(a)] if *a == addr));
    }

    #[test]
    fn alternate_server_plain_address_roundtrip_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        let attr = Attribute::AlternateServer(addr);
        let mut value = [0u8; 32];
        let len = attr.encode_value(&mut value, &TID);
        assert_eq!(len, 20);
        assert_eq!(value[1], 0x02, "IPv6 family");
        assert_eq!(u16::from_be_bytes([value[2], value[3]]), 3478, "plain port");

        let buf = build_attr(ATTR_ALTERNATE_SERVER, &value[..len]);
        let attrs = parse_attributes(&buf, &TID).unwrap();
        assert!(matches!(attrs.as_slice(), [Attribute::AlternateServer(a)] if *a == addr));
    }
}
