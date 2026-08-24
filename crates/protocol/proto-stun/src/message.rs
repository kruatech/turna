//! Complete STUN message: header + attributes + encode/decode

use crate::attribute::{self, ensure, Attribute};
use crate::error::{Result, StunError};
use crate::header::{encode_message_type, MessageClass, MessageHeader, HEADER_SIZE};
use crate::integrity;
use crate::method::Method;

#[derive(Debug, Clone)]
pub struct StunMessage {
    pub class: MessageClass,
    pub method: Method,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    pub fn new(method: Method, class: MessageClass) -> Self {
        let mut transaction_id = [0u8; 12];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut transaction_id);
        Self {
            class,
            method,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn with_transaction_id(method: Method, class: MessageClass, tid: [u8; 12]) -> Self {
        Self {
            class,
            method,
            transaction_id: tid,
            attributes: Vec::new(),
        }
    }

    pub fn add(&mut self, attr: Attribute) {
        self.attributes.push(attr);
    }

    /// Find first attribute matching a predicate.
    pub fn get<F, T>(&self, f: F) -> Option<T>
    where
        F: Fn(&Attribute) -> Option<T>,
    {
        self.attributes.iter().find_map(f)
    }

    pub fn get_username(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Username(u) => Some(u.as_str()),
            _ => None,
        })
    }

    pub fn get_realm(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Realm(r) => Some(r.as_str()),
            _ => None,
        })
    }

    pub fn get_nonce(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Nonce(n) => Some(n.as_str()),
            _ => None,
        })
    }

    pub fn get_lifetime(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Lifetime(l) => Some(*l),
            _ => None,
        })
    }

    pub fn get_requested_transport(&self) -> Option<u8> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::RequestedTransport(t) => Some(*t),
            _ => None,
        })
    }

    pub fn get_xor_peer_address(&self) -> Option<std::net::SocketAddr> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::XorPeerAddress(addr) => Some(*addr),
            _ => None,
        })
    }

    pub fn get_channel_number(&self) -> Option<u16> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::ChannelNumber(ch) => Some(*ch),
            _ => None,
        })
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Data(d) => Some(d.as_slice()),
            _ => None,
        })
    }

    /// RFC 8016 MOBILITY-TICKET bytes, if present. In an Allocate *request* a
    /// client opts into mobility by including this attribute (typically with a
    /// zero-length value); in a Refresh it carries the server-issued ticket.
    pub fn get_mobility_ticket(&self) -> Option<&[u8]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::MobilityTicket(t) => Some(t.as_slice()),
            _ => None,
        })
    }

    /// First ORIGIN attribute (draft-ietf-tram-stun-origin), if present. The
    /// value is a forgeable client hint — never treat it as auth/tenant truth.
    pub fn get_origin(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Origin(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// All ORIGIN attributes (senders MAY include several per the draft).
    pub fn origins(&self) -> impl Iterator<Item = &str> {
        self.attributes.iter().filter_map(|a| match a {
            Attribute::Origin(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// RFC 6062 CONNECTION-ID, if present.
    pub fn get_connection_id(&self) -> Option<u32> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::ConnectionId(id) => Some(*id),
            _ => None,
        })
    }

    /// RFC 7635 ACCESS-TOKEN bytes (opaque, still encrypted), if present.
    pub fn get_access_token(&self) -> Option<&[u8]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::AccessToken(t) => Some(t.as_slice()),
            _ => None,
        })
    }

    /// RFC 7635 THIRD-PARTY-AUTHORIZATION bytes, if present.
    pub fn get_third_party_authorization(&self) -> Option<&[u8]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::ThirdPartyAuthorization(t) => Some(t.as_slice()),
            _ => None,
        })
    }

    /// Whether a MOBILITY-TICKET attribute is present at all (the Allocate
    /// opt-in signal — value may be empty).
    pub fn has_mobility_ticket(&self) -> bool {
        self.attributes
            .iter()
            .any(|a| matches!(a, Attribute::MobilityTicket(_)))
    }

    /// RFC 8656 §18.7: EVEN-PORT. `Some(reserve_next)` if present, where
    /// `reserve_next` is the R bit (reserve the next-higher port).
    pub fn get_even_port(&self) -> Option<bool> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::EvenPort(r) => Some(*r),
            _ => None,
        })
    }

    /// RFC 8656 §18.10: RESERVATION-TOKEN, if present.
    pub fn get_reservation_token(&self) -> Option<[u8; 8]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::ReservationToken(t) => Some(*t),
            _ => None,
        })
    }

    /// RFC 8656 §14.1: REQUESTED-ADDRESS-FAMILY, if present. A malformed value
    /// or length is rejected at parse time, so a present attribute is always a
    /// valid `AddressFamily`.
    pub fn get_requested_address_family(&self) -> Option<attribute::AddressFamily> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::RequestedAddressFamily(f) => Some(*f),
            _ => None,
        })
    }

    pub fn get_message_integrity(&self) -> Option<&[u8; 20]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::MessageIntegrity(h) => Some(h),
            _ => None,
        })
    }

    /// MESSAGE-INTEGRITY-SHA256 value, if present. The attribute decodes into
    /// `Attribute::Unknown` (we don't add a typed variant in Stage 1), so it is
    /// matched by type code here.
    pub fn get_message_integrity_sha256(&self) -> Option<&[u8]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Unknown { attr_type, value }
                if *attr_type == attribute::ATTR_MESSAGE_INTEGRITY_SHA256 =>
            {
                Some(value.as_slice())
            }
            _ => None,
        })
    }

    /// PASSWORD-ALGORITHM (RFC 8489) identifier the client declared, if present.
    /// Decodes from `Attribute::Unknown` (no typed variant); reads the leading
    /// 2-byte algorithm field of the attribute value.
    pub fn get_password_algorithm(&self) -> Option<u16> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Unknown { attr_type, value }
                if *attr_type == attribute::ATTR_PASSWORD_ALGORITHM && value.len() >= 2 =>
            {
                Some(u16::from_be_bytes([value[0], value[1]]))
            }
            _ => None,
        })
    }

    /// Decode a STUN message from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let header = MessageHeader::decode(buf)?;
        let total = HEADER_SIZE + header.length as usize;

        if buf.len() < total {
            return Err(StunError::BufferTooShort {
                need: total,
                have: buf.len(),
            });
        }

        let attributes =
            attribute::parse_attributes(&buf[HEADER_SIZE..total], &header.transaction_id)?;

        Ok(Self {
            class: header.class,
            method: header.method,
            transaction_id: header.transaction_id,
            attributes,
        })
    }

    /// Encode message to bytes (without MESSAGE-INTEGRITY or FINGERPRINT).
    /// Returns `StunError::BufferTooShort` if either the internal attribute
    /// scratch buffer or `buf` cannot hold the message, instead of panicking
    /// (M2). For correctly-sized buffers the only added cost is a few length
    /// comparisons.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        // Encode attributes first to calculate length
        let mut attr_buf = [0u8; 4096];
        let mut attr_len = 0;

        for attr in &self.attributes {
            let at = attr.attr_type();
            // Skip integrity/fingerprint — added separately
            if at == attribute::ATTR_MESSAGE_INTEGRITY || at == attribute::ATTR_FINGERPRINT {
                continue;
            }
            // Room for this attribute's 4-byte header before its value slice.
            ensure(attr_buf.len(), attr_len + 4)?;
            let value_len =
                attr.encode_value(&mut attr_buf[attr_len + 4..], &self.transaction_id)?;
            // Attribute header: type (2) + length (2)
            attr_buf[attr_len..attr_len + 2].copy_from_slice(&at.to_be_bytes());
            attr_buf[attr_len + 2..attr_len + 4].copy_from_slice(&(value_len as u16).to_be_bytes());
            attr_len += 4 + value_len;
            // Pad to 4 bytes
            let padded = (attr_len + 3) & !3;
            ensure(attr_buf.len(), padded)?;
            for b in &mut attr_buf[attr_len..padded] {
                *b = 0;
            }
            attr_len = padded;
        }

        // The output buffer must hold the 20-byte header plus all attributes.
        ensure(buf.len(), HEADER_SIZE + attr_len)?;

        // Write header
        let msg_type = encode_message_type(self.method, &self.class);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[2..4].copy_from_slice(&(attr_len as u16).to_be_bytes());
        buf[4..8].copy_from_slice(&crate::header::MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&self.transaction_id);

        // Write attributes
        buf[20..20 + attr_len].copy_from_slice(&attr_buf[..attr_len]);

        Ok(HEADER_SIZE + attr_len)
    }

    /// Encode with MESSAGE-INTEGRITY and FINGERPRINT.
    pub fn encode_with_integrity(&self, buf: &mut [u8], key: &[u8]) -> Result<usize> {
        let mut len = self.encode(buf)?;

        // MESSAGE-INTEGRITY adds 4 + 20 = 24 bytes.
        ensure(buf.len(), len + 24)?;
        // Adjust length to include MESSAGE-INTEGRITY before computing the HMAC.
        let mi_total_len = (len - HEADER_SIZE + 24) as u16;
        buf[2..4].copy_from_slice(&mi_total_len.to_be_bytes());

        let hmac = integrity::compute_message_integrity(&buf[..len], key);

        // Write MESSAGE-INTEGRITY attribute
        buf[len..len + 2].copy_from_slice(&attribute::ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        buf[len + 2..len + 4].copy_from_slice(&20u16.to_be_bytes());
        buf[len + 4..len + 24].copy_from_slice(&hmac);
        len += 24;

        // FINGERPRINT adds 4 + 4 = 8 bytes.
        ensure(buf.len(), len + 8)?;
        // Adjust length to include FINGERPRINT before computing it.
        let fp_total_len = (len - HEADER_SIZE + 8) as u16;
        buf[2..4].copy_from_slice(&fp_total_len.to_be_bytes());

        let fp = integrity::compute_fingerprint(&buf[..len]);
        buf[len..len + 2].copy_from_slice(&attribute::ATTR_FINGERPRINT.to_be_bytes());
        buf[len + 2..len + 4].copy_from_slice(&4u16.to_be_bytes());
        buf[len + 4..len + 8].copy_from_slice(&fp.to_be_bytes());
        len += 8;

        // Final length
        buf[2..4].copy_from_slice(&((len - HEADER_SIZE) as u16).to_be_bytes());

        Ok(len)
    }

    /// Encode with MESSAGE-INTEGRITY-SHA256 (RFC 8489) followed by FINGERPRINT.
    /// Mirrors [`encode_with_integrity`] but writes the full 32-byte
    /// HMAC-SHA-256 tag. Does not change the SHA-1 path.
    pub fn encode_with_integrity_sha256(&self, buf: &mut [u8], key: &[u8]) -> Result<usize> {
        let mut len = self.encode(buf)?;

        // MESSAGE-INTEGRITY-SHA256 adds 4 + 32 = 36 bytes.
        ensure(buf.len(), len + 36)?;
        // Adjust length to include MESSAGE-INTEGRITY-SHA256 before the HMAC.
        let mi_total_len = (len - HEADER_SIZE + 36) as u16;
        buf[2..4].copy_from_slice(&mi_total_len.to_be_bytes());

        let hmac = integrity::compute_message_integrity_sha256(&buf[..len], key);

        buf[len..len + 2].copy_from_slice(&attribute::ATTR_MESSAGE_INTEGRITY_SHA256.to_be_bytes());
        buf[len + 2..len + 4].copy_from_slice(&32u16.to_be_bytes());
        buf[len + 4..len + 36].copy_from_slice(&hmac);
        len += 36;

        // FINGERPRINT adds 4 + 4 = 8 bytes.
        ensure(buf.len(), len + 8)?;
        let fp_total_len = (len - HEADER_SIZE + 8) as u16;
        buf[2..4].copy_from_slice(&fp_total_len.to_be_bytes());

        let fp = integrity::compute_fingerprint(&buf[..len]);
        buf[len..len + 2].copy_from_slice(&attribute::ATTR_FINGERPRINT.to_be_bytes());
        buf[len + 2..len + 4].copy_from_slice(&4u16.to_be_bytes());
        buf[len + 4..len + 8].copy_from_slice(&fp.to_be_bytes());
        len += 8;

        // Final length
        buf[2..4].copy_from_slice(&((len - HEADER_SIZE) as u16).to_be_bytes());

        Ok(len)
    }

    /// Verify MESSAGE-INTEGRITY against a key.
    pub fn verify_integrity(&self, raw: &[u8], key: &[u8]) -> bool {
        let Some(expected) = self.get_message_integrity() else {
            return false;
        };

        // Find MESSAGE-INTEGRITY position in raw bytes
        let mut pos = HEADER_SIZE;
        while pos + 4 <= raw.len() {
            let attr_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            let attr_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
            if attr_type == attribute::ATTR_MESSAGE_INTEGRITY {
                // I1: nothing but FINGERPRINT may follow MESSAGE-INTEGRITY.
                if !only_fingerprint_after(raw, pos + 4 + 20) {
                    return false;
                }
                // Build temp buffer with adjusted length
                let mut tmp = raw[..pos].to_vec();
                let adjusted_len = (pos - HEADER_SIZE + 24) as u16;
                tmp[2..4].copy_from_slice(&adjusted_len.to_be_bytes());
                return integrity::verify_message_integrity(&tmp, key, expected);
            }
            pos += 4 + ((attr_len + 3) & !3);
        }
        false
    }

    /// Verify MESSAGE-INTEGRITY-SHA256 against a key (RFC 8489). Independent of
    /// the SHA-1 path; the caller decides which to require. The HMAC covers the
    /// message up to this attribute, with the length field adjusted to include
    /// it (and excluding anything after, e.g. FINGERPRINT).
    pub fn verify_integrity_sha256(&self, raw: &[u8], key: &[u8]) -> bool {
        let Some(expected) = self.get_message_integrity_sha256() else {
            return false;
        };

        let mut pos = HEADER_SIZE;
        while pos + 4 <= raw.len() {
            let attr_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            let attr_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
            if attr_type == attribute::ATTR_MESSAGE_INTEGRITY_SHA256 {
                // I1: nothing but FINGERPRINT may follow MESSAGE-INTEGRITY-SHA256.
                if !only_fingerprint_after(raw, pos + 4 + ((attr_len + 3) & !3)) {
                    return false;
                }
                let mut tmp = raw[..pos].to_vec();
                let adjusted_len = (pos - HEADER_SIZE + 4 + attr_len) as u16;
                tmp[2..4].copy_from_slice(&adjusted_len.to_be_bytes());
                return integrity::verify_message_integrity_sha256(&tmp, key, expected);
            }
            pos += 4 + ((attr_len + 3) & !3);
        }
        false
    }
}

/// I1: after MESSAGE-INTEGRITY[-SHA256] only FINGERPRINT may appear (RFC 5389
/// §15.4 / RFC 8489 §14.6). True iff every attribute from `pos` onward is
/// FINGERPRINT (or none). Stops a signed prefix from being extended with an
/// unauthenticated trailing attribute that `get_*()` would still honour.
fn only_fingerprint_after(raw: &[u8], mut pos: usize) -> bool {
    while pos + 4 <= raw.len() {
        let attr_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let attr_len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        if attr_type != attribute::ATTR_FINGERPRINT {
            return false;
        }
        pos += 4 + ((attr_len + 3) & !3);
    }
    true
}

/// Check if a buffer looks like a STUN message (first two bits are 0, magic cookie present).
pub fn is_stun_message(buf: &[u8]) -> bool {
    if buf.len() < HEADER_SIZE {
        return false;
    }
    // First two bits must be 0
    if buf[0] & 0xC0 != 0 {
        return false;
    }
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    cookie == crate::header::MAGIC_COOKIE
}

/// Check if buffer is a well-formed TURN ChannelData frame.
///
/// This is intentionally stricter than checking only the first two bits:
/// random garbage has a 25% chance to start with a value in 0x4000..=0x7FFF.
/// Validate the full channel number and the embedded length so malformed
/// ChannelData-shaped packets are dropped before rate limiting and state lookup.
/// Upper bound is 0x7FFE (0x7FFF is reserved) to match proto-turn's CHANNEL_MAX.
pub fn is_channel_data(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }

    let channel = u16::from_be_bytes([buf[0], buf[1]]);
    if !(0x4000..=0x7FFE).contains(&channel) {
        return false;
    }

    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    buf.len() >= 4 + length
}

/// Decode a ChannelData header: returns (channel_number, data_slice).
pub fn decode_channel_data(buf: &[u8]) -> Result<(u16, &[u8])> {
    if buf.len() < 4 {
        return Err(StunError::BufferTooShort {
            need: 4,
            have: buf.len(),
        });
    }
    let channel = u16::from_be_bytes([buf[0], buf[1]]);
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 4 + length {
        return Err(StunError::BufferTooShort {
            need: 4 + length,
            have: buf.len(),
        });
    }
    Ok((channel, &buf[4..4 + length]))
}

/// Encode a ChannelData message. Returns `StunError::BufferTooShort` if `buf`
/// is smaller than the padded frame, instead of panicking on an `assert!` (M2).
pub fn encode_channel_data(buf: &mut [u8], channel: u16, data: &[u8]) -> Result<usize> {
    let total = 4 + data.len();
    let padded = (total + 3) & !3;
    if buf.len() < padded {
        return Err(StunError::BufferTooShort {
            need: padded,
            have: buf.len(),
        });
    }
    buf[0..2].copy_from_slice(&channel.to_be_bytes());
    buf[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
    buf[4..4 + data.len()].copy_from_slice(data);
    for b in &mut buf[total..padded] {
        *b = 0;
    }
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_request_roundtrip() {
        let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
        msg.add(Attribute::Software("turna 0.1".into()));

        let mut buf = [0u8; 1024];
        let len = msg.encode(&mut buf).unwrap();

        let decoded = StunMessage::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.method, Method::Binding);
        assert!(matches!(decoded.class, MessageClass::Request));
        assert_eq!(decoded.transaction_id, msg.transaction_id);
    }

    #[test]
    fn test_binding_with_integrity() {
        let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
        msg.add(Attribute::Username("user".into()));

        let key = b"testkey";
        let mut buf = [0u8; 1024];
        let len = msg.encode_with_integrity(&mut buf, key).unwrap();

        let decoded = StunMessage::decode(&buf[..len]).unwrap();
        assert!(decoded.verify_integrity(&buf[..len], key));
        assert!(!decoded.verify_integrity(&buf[..len], b"wrongkey"));
    }

    #[test]
    fn integrity_rejects_attribute_after_message_integrity() {
        // I1: a validly-signed message must not verify if a non-FINGERPRINT
        // attribute is appended after MESSAGE-INTEGRITY.
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::Username("alice".into()));
        let key = b"secret-key-1234";
        let mut buf = [0u8; 512];
        let len = m.encode_with_integrity(&mut buf, key).unwrap();

        assert!(StunMessage::decode(&buf[..len])
            .unwrap()
            .verify_integrity(&buf[..len], key));

        let mut tampered = buf[..len].to_vec();
        tampered.extend_from_slice(&0x0006u16.to_be_bytes());
        tampered.extend_from_slice(&0u16.to_be_bytes());
        let new_body = (len - HEADER_SIZE + 4) as u16;
        tampered[2..4].copy_from_slice(&new_body.to_be_bytes());

        let decoded = StunMessage::decode(&tampered).unwrap();
        assert!(
            !decoded.verify_integrity(&tampered, key),
            "an attribute after MESSAGE-INTEGRITY must invalidate the signature (I1)"
        );
    }

    #[test]
    fn test_is_stun_message() {
        let msg = StunMessage::new(Method::Binding, MessageClass::Request);
        let mut buf = [0u8; 256];
        let len = msg.encode(&mut buf).unwrap();
        assert!(is_stun_message(&buf[..len]));
        assert!(!is_channel_data(&buf[..len]));
    }

    #[test]
    fn test_channel_data_classifier_rejects_bad_length() {
        // Channel-shaped garbage must not reach rate limiter / state path.
        let buf = [0x40, 0x01, 0x00, 0x10, 0xaa, 0xbb];
        assert!(!is_channel_data(&buf));
    }

    #[test]
    fn test_channel_data_classifier_rejects_out_of_range_channel() {
        let high = [0x80, 0x00, 0x00, 0x00];
        let low = [0x3f, 0xff, 0x00, 0x00];
        assert!(!is_channel_data(&high));
        assert!(!is_channel_data(&low));
    }

    #[test]
    fn test_channel_data_roundtrip() {
        let mut buf = [0u8; 256];
        let data = b"hello world";
        let len = encode_channel_data(&mut buf, 0x4001, data).unwrap();
        assert!(is_channel_data(&buf[..len]));

        let (ch, decoded_data) = decode_channel_data(&buf[..len]).unwrap();
        assert_eq!(ch, 0x4001);
        assert_eq!(decoded_data, data);
    }

    // ── Mutation-kill: accessor getters (present -> Some(exact), absent -> None) ──

    #[test]
    fn getters_return_present_attribute_values() {
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::Realm("myrealm".into()));
        m.add(Attribute::RequestedTransport(17));
        m.add(Attribute::Data(vec![1, 2, 3]));
        m.add(Attribute::MobilityTicket(vec![9, 9]));
        m.add(Attribute::EvenPort(true));
        m.add(Attribute::ReservationToken([7u8; 8]));

        assert_eq!(m.get_realm(), Some("myrealm"));
        assert_eq!(m.get_requested_transport(), Some(17));
        assert_eq!(m.get_data(), Some(&[1u8, 2, 3][..]));
        assert_eq!(m.get_mobility_ticket(), Some(&[9u8, 9][..]));
        assert!(m.has_mobility_ticket());
        assert_eq!(m.get_even_port(), Some(true));
        assert_eq!(m.get_reservation_token(), Some([7u8; 8]));

        let realm = m.get(|a| match a {
            Attribute::Realm(r) => Some(r.clone()),
            _ => None,
        });
        assert_eq!(realm.as_deref(), Some("myrealm"));
    }

    #[test]
    fn getters_return_none_when_attribute_absent() {
        let m = StunMessage::new(Method::Allocate, MessageClass::Request);
        assert_eq!(m.get_realm(), None);
        assert_eq!(m.get_requested_transport(), None);
        assert_eq!(m.get_data(), None);
        assert_eq!(m.get_mobility_ticket(), None);
        assert!(!m.has_mobility_ticket());
        assert_eq!(m.get_even_port(), None);
        assert_eq!(m.get_reservation_token(), None);
        let none: Option<String> = m.get(|a| match a {
            Attribute::Realm(r) => Some(r.clone()),
            _ => None,
        });
        assert_eq!(none, None);
    }

    // ── Mutation-kill: codec boundaries ─────────────────────────────────────────

    #[test]
    fn decode_ignores_trailing_bytes_but_needs_full_body() {
        let tid = [1u8; 12];
        let mut m = StunMessage::with_transaction_id(Method::Binding, MessageClass::Request, tid);
        m.add(Attribute::Username("u".into()));
        let mut buf = [0u8; 512];
        let len = m.encode(&mut buf).unwrap();

        let mut extended = buf[..len].to_vec();
        extended.push(0xFF);
        let decoded = StunMessage::decode(&extended).expect("decode must ignore trailing bytes");
        assert_eq!(decoded.get_username(), Some("u"));

        assert!(StunMessage::decode(&buf[..len - 1]).is_err());
    }

    #[test]
    fn encode_skips_message_integrity_attribute() {
        let tid = [2u8; 12];
        let mut without =
            StunMessage::with_transaction_id(Method::Binding, MessageClass::Request, tid);
        without.add(Attribute::Username("u".into()));
        let mut with =
            StunMessage::with_transaction_id(Method::Binding, MessageClass::Request, tid);
        with.add(Attribute::Username("u".into()));
        with.add(Attribute::MessageIntegrity([0u8; 20]));

        let mut b1 = [0u8; 512];
        let mut b2 = [0u8; 512];
        let l1 = without.encode(&mut b1).unwrap();
        let l2 = with.encode(&mut b2).unwrap();
        assert_eq!(l1, l2, "encode must skip MESSAGE-INTEGRITY");
        assert_eq!(&b1[..l1], &b2[..l2]);
    }

    #[test]
    fn is_stun_message_boundaries() {
        let m = StunMessage::new(Method::Binding, MessageClass::Request);
        let mut buf = [0u8; 64];
        let len = m.encode(&mut buf).unwrap();
        assert!(is_stun_message(&buf[..len]));

        assert!(!is_stun_message(&[0u8; 4]));
        let mut bad_bits = buf[..len].to_vec();
        bad_bits[0] |= 0xC0;
        assert!(!is_stun_message(&bad_bits));
        let mut bad_cookie = buf[..len].to_vec();
        bad_cookie[4] ^= 0xFF;
        assert!(!is_stun_message(&bad_cookie));
    }

    #[test]
    fn is_channel_data_min_length_boundary() {
        let mut b = [0u8; 8];
        let l = encode_channel_data(&mut b, 0x4001, &[]).unwrap();
        assert_eq!(l, 4);
        assert!(is_channel_data(&b[..l]));
        assert!(!is_channel_data(&[0x40, 0x01, 0x00]));
    }

    #[test]
    fn decode_channel_data_length_boundaries() {
        let mut b = [0u8; 8];
        let l = encode_channel_data(&mut b, 0x4002, &[]).unwrap();
        let (ch, d) = decode_channel_data(&b[..l]).unwrap();
        assert_eq!(ch, 0x4002);
        assert!(d.is_empty());

        let full = [0x40u8, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        let (ch2, d2) = decode_channel_data(&full).unwrap();
        assert_eq!(ch2, 0x4003);
        assert_eq!(d2, &[0xAA, 0xBB]);

        let trunc = [0x40u8, 0x04, 0x00, 0x04, 0xAA, 0xBB];
        assert!(decode_channel_data(&trunc).is_err());
    }

    #[test]
    fn encode_channel_data_exact_buffer_fits() {
        let data = [1u8, 2, 3];
        let mut exact = [0u8; 8];
        assert!(encode_channel_data(&mut exact, 0x4005, &data).is_ok());
        let mut short = [0u8; 7];
        assert!(encode_channel_data(&mut short, 0x4005, &data).is_err());
    }

    #[test]
    fn encode_with_integrity_verify_roundtrip_and_declared_length() {
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::Username("alice".into()));
        let key = b"secret-key-1234";
        let mut buf = [0u8; 512];
        let len = m.encode_with_integrity(&mut buf, key).unwrap();

        let decoded = StunMessage::decode(&buf[..len]).unwrap();
        assert!(decoded.verify_integrity(&buf[..len], key));
        assert!(!decoded.verify_integrity(&buf[..len], b"other-key-9999"));

        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(declared, len - 20);
    }

    #[test]
    fn encode_with_integrity_sha256_roundtrip_and_isolation_from_sha1() {
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::Username("alice".into()));
        let key = b"secret-key-1234";
        let mut buf = [0u8; 512];
        let len = m.encode_with_integrity_sha256(&mut buf, key).unwrap();

        let decoded = StunMessage::decode(&buf[..len]).unwrap();
        assert!(decoded.verify_integrity_sha256(&buf[..len], key));
        assert!(!decoded.verify_integrity_sha256(&buf[..len], b"other-key-9999"));

        // There is no SHA-1 MESSAGE-INTEGRITY here, so the SHA-1 verifier fails.
        assert!(!decoded.verify_integrity(&buf[..len], key));
        // The SHA-256 tag is exposed via the type code.
        assert_eq!(
            decoded.get_message_integrity_sha256().map(|t| t.len()),
            Some(32)
        );

        let declared = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        assert_eq!(declared, len - 20);
    }

    // The three tests below exist because `cargo mutants` showed these getters could
    // be replaced by `None` — or have their type check replaced by `true` — with every
    // test still passing. A getter nothing asserts on is a getter that can silently
    // start returning the wrong attribute, and two of these sit in the authentication
    // path.

    #[test]
    fn requested_address_family_is_read_back() {
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        assert_eq!(
            msg.get_requested_address_family(),
            None,
            "absent attribute must read as None"
        );

        msg.add(Attribute::RequestedAddressFamily(
            attribute::AddressFamily::Ipv6,
        ));
        assert_eq!(
            msg.get_requested_address_family(),
            Some(attribute::AddressFamily::Ipv6),
            "IPv6 must not be reported as IPv4 or as absent — the relayed family \
             depends on this"
        );

        let mut v4 = StunMessage::new(Method::Allocate, MessageClass::Request);
        v4.add(Attribute::RequestedAddressFamily(
            attribute::AddressFamily::Ipv4,
        ));
        assert_eq!(
            v4.get_requested_address_family(),
            Some(attribute::AddressFamily::Ipv4)
        );
    }

    #[test]
    fn message_integrity_sha256_is_found_by_type_not_by_position() {
        let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
        assert_eq!(msg.get_message_integrity_sha256(), None);

        // A decoy of the same length, added first. Without it the getter could match
        // on anything at all and still return the right bytes, because there would be
        // only one Unknown attribute to find.
        msg.add(Attribute::Unknown {
            attr_type: attribute::ATTR_PASSWORD_ALGORITHMS,
            value: vec![0xAAu8; 32],
        });
        msg.add(Attribute::Unknown {
            attr_type: attribute::ATTR_MESSAGE_INTEGRITY_SHA256,
            value: vec![0xBBu8; 32],
        });

        assert_eq!(
            msg.get_message_integrity_sha256(),
            Some([0xBBu8; 32].as_slice()),
            "matched the first unknown attribute instead of the SHA-256 tag"
        );
    }

    #[test]
    fn password_algorithm_reads_the_declared_value() {
        let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
        assert_eq!(msg.get_password_algorithm(), None);

        // Decoy first, for the same reason as above.
        msg.add(Attribute::Unknown {
            attr_type: attribute::ATTR_PASSWORD_ALGORITHMS,
            value: vec![0x00, 0x01, 0x00, 0x00],
        });
        // 0x0002 = SHA-256 (RFC 8489 §18.5). Deliberately not 0 or 1: a mutant
        // returning either of those constants has to fail here.
        msg.add(Attribute::Unknown {
            attr_type: attribute::ATTR_PASSWORD_ALGORITHM,
            value: vec![0x00, 0x02, 0x00, 0x00],
        });

        assert_eq!(msg.get_password_algorithm(), Some(2));

        // A value too short to hold the algorithm field is not a zero algorithm, it
        // is no algorithm.
        let mut short = StunMessage::new(Method::Allocate, MessageClass::Request);
        short.add(Attribute::Unknown {
            attr_type: attribute::ATTR_PASSWORD_ALGORITHM,
            value: vec![0x00],
        });
        assert_eq!(short.get_password_algorithm(), None);
    }
}
