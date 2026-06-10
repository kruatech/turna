//! Complete STUN message: header + attributes + encode/decode

use crate::attribute::{self, Attribute};
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
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut transaction_id);
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

    /// Whether a MOBILITY-TICKET attribute is present at all (the Allocate
    /// opt-in signal — value may be empty).
    pub fn has_mobility_ticket(&self) -> bool {
        self.attributes
            .iter()
            .any(|a| matches!(a, Attribute::MobilityTicket(_)))
    }

    pub fn get_message_integrity(&self) -> Option<&[u8; 20]> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::MessageIntegrity(h) => Some(h),
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
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        // Encode attributes first to calculate length
        let mut attr_buf = [0u8; 4096];
        let mut attr_len = 0;

        for attr in &self.attributes {
            let at = attr.attr_type();
            // Skip integrity/fingerprint — added separately
            if at == attribute::ATTR_MESSAGE_INTEGRITY || at == attribute::ATTR_FINGERPRINT {
                continue;
            }
            let value_len = attr.encode_value(&mut attr_buf[attr_len + 4..], &self.transaction_id);
            // Attribute header: type (2) + length (2)
            attr_buf[attr_len..attr_len + 2].copy_from_slice(&at.to_be_bytes());
            attr_buf[attr_len + 2..attr_len + 4].copy_from_slice(&(value_len as u16).to_be_bytes());
            attr_len += 4 + value_len;
            // Pad to 4 bytes
            let padded = (attr_len + 3) & !3;
            for b in &mut attr_buf[attr_len..padded] {
                *b = 0;
            }
            attr_len = padded;
        }

        // Write header
        let msg_type = encode_message_type(self.method, &self.class);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[2..4].copy_from_slice(&(attr_len as u16).to_be_bytes());
        buf[4..8].copy_from_slice(&crate::header::MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&self.transaction_id);

        // Write attributes
        buf[20..20 + attr_len].copy_from_slice(&attr_buf[..attr_len]);

        HEADER_SIZE + attr_len
    }

    /// Encode with MESSAGE-INTEGRITY and FINGERPRINT.
    pub fn encode_with_integrity(&self, buf: &mut [u8], key: &[u8]) -> usize {
        let mut len = self.encode(buf);

        // Adjust length to include MESSAGE-INTEGRITY (4 + 20 = 24)
        let mi_total_len = (len - HEADER_SIZE + 24) as u16;
        buf[2..4].copy_from_slice(&mi_total_len.to_be_bytes());

        let hmac = integrity::compute_message_integrity(&buf[..len], key);

        // Write MESSAGE-INTEGRITY attribute
        buf[len..len + 2].copy_from_slice(&attribute::ATTR_MESSAGE_INTEGRITY.to_be_bytes());
        buf[len + 2..len + 4].copy_from_slice(&20u16.to_be_bytes());
        buf[len + 4..len + 24].copy_from_slice(&hmac);
        len += 24;

        // Adjust length to include FINGERPRINT (4 + 4 = 8)
        let fp_total_len = (len - HEADER_SIZE + 8) as u16;
        buf[2..4].copy_from_slice(&fp_total_len.to_be_bytes());

        let fp = integrity::compute_fingerprint(&buf[..len]);
        buf[len..len + 2].copy_from_slice(&attribute::ATTR_FINGERPRINT.to_be_bytes());
        buf[len + 2..len + 4].copy_from_slice(&4u16.to_be_bytes());
        buf[len + 4..len + 8].copy_from_slice(&fp.to_be_bytes());
        len += 8;

        // Final length
        buf[2..4].copy_from_slice(&((len - HEADER_SIZE) as u16).to_be_bytes());

        len
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

/// Encode a ChannelData message.
pub fn encode_channel_data(buf: &mut [u8], channel: u16, data: &[u8]) -> usize {
    let total = 4 + data.len();
    let padded = (total + 3) & !3;
    assert!(
        buf.len() >= padded,
        "encode_channel_data: buffer too small: need {padded} (4 + {} payload + {} padding), have {}",
        data.len(), padded - total, buf.len(),
    );
    buf[0..2].copy_from_slice(&channel.to_be_bytes());
    buf[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
    buf[4..4 + data.len()].copy_from_slice(data);
    for b in &mut buf[total..padded] {
        *b = 0;
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_request_roundtrip() {
        let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
        msg.add(Attribute::Software("turna 0.1".into()));

        let mut buf = [0u8; 1024];
        let len = msg.encode(&mut buf);

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
        let len = msg.encode_with_integrity(&mut buf, key);

        let decoded = StunMessage::decode(&buf[..len]).unwrap();
        assert!(decoded.verify_integrity(&buf[..len], key));
        assert!(!decoded.verify_integrity(&buf[..len], b"wrongkey"));
    }

    #[test]
    fn test_is_stun_message() {
        let msg = StunMessage::new(Method::Binding, MessageClass::Request);
        let mut buf = [0u8; 256];
        let len = msg.encode(&mut buf);
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
        let len = encode_channel_data(&mut buf, 0x4001, data);
        assert!(is_channel_data(&buf[..len]));

        let (ch, decoded_data) = decode_channel_data(&buf[..len]).unwrap();
        assert_eq!(ch, 0x4001);
        assert_eq!(decoded_data, data);
    }
}
