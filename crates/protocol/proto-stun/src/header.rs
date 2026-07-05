//! STUN message header (20 bytes)

use crate::error::{Result, StunError};
use crate::method::Method;

pub const HEADER_SIZE: usize = 20;
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// Maximum STUN message length we accept, as declared in the header's u16
/// length field.
///
/// The wire format allows up to 65535. We cap to a value that fits one MTU
/// plus reasonable TURN overhead (auth attributes + DATA up to MTU + small
/// metadata). This is the first line of defence against a single packet
/// claiming "I have 64KB of attributes" and forcing us to allocate.
///
/// 4096 covers the worst realistic case:
///   USERNAME 763 + REALM 763 + NONCE 763 + DATA 1500 + small fixed attrs
///   = ~3878 bytes of attributes + 20 bytes header.
///
/// If a legitimate workload needs more, raise this constant deliberately.
pub const MAX_MESSAGE_LEN: u16 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl MessageClass {
    pub fn from_raw(raw: u16) -> Self {
        let c0 = (raw >> 4) & 0x1;
        let c1 = (raw >> 8) & 0x1;
        match (c1, c0) {
            (0, 0) => Self::Request,
            (0, 1) => Self::Indication,
            (1, 0) => Self::SuccessResponse,
            (1, 1) => Self::ErrorResponse,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub class: MessageClass,
    pub method: Method,
    pub length: u16,
    pub transaction_id: [u8; 12],
}

/// Encode method + class into the 16-bit message type field.
pub fn encode_message_type(method: Method, class: &MessageClass) -> u16 {
    let m = method.as_u16();
    let (c1, c0) = match class {
        MessageClass::Request => (0u16, 0u16),
        MessageClass::Indication => (0, 1),
        MessageClass::SuccessResponse => (1, 0),
        MessageClass::ErrorResponse => (1, 1),
    };

    let m_low = m & 0x000F;
    let m_mid = (m >> 4) & 0x0007;
    let m_high = (m >> 7) & 0x001F;

    m_low | (c0 << 4) | (m_mid << 5) | (c1 << 8) | (m_high << 9)
}

/// Extract method bits from the 16-bit message type field.
pub fn extract_method(msg_type: u16) -> u16 {
    let m_low = msg_type & 0x000F;
    let m_mid = (msg_type >> 5) & 0x0007;
    let m_high = (msg_type >> 9) & 0x001F;
    m_low | (m_mid << 4) | (m_high << 7)
}

impl MessageHeader {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(StunError::BufferTooShort {
                need: HEADER_SIZE,
                have: buf.len(),
            });
        }

        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        if cookie != MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie);
        }

        // RFC 5389 §6: the two most-significant bits of every STUN message are 0.
        if msg_type & 0xC000 != 0 {
            return Err(StunError::InvalidMessageType(msg_type));
        }

        if !length.is_multiple_of(4) {
            return Err(StunError::InvalidLength);
        }

        // DoS guard: reject messages claiming more than MAX_MESSAGE_LEN of
        // attribute bytes. Without this, an attacker can declare 65535 and
        // force a 64KB allocation per packet.
        if length > MAX_MESSAGE_LEN {
            return Err(StunError::MessageTooLong {
                len: length,
                max: MAX_MESSAGE_LEN,
            });
        }

        let raw_method = extract_method(msg_type);
        let method = Method::from_raw(raw_method).ok_or(StunError::UnknownMethod(raw_method))?;
        let class = MessageClass::from_raw(msg_type);

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&buf[8..20]);

        Ok(Self {
            class,
            method,
            length,
            transaction_id,
        })
    }

    pub fn encode(&self, buf: &mut [u8]) {
        let msg_type = encode_message_type(self.method, &self.class);
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[2..4].copy_from_slice(&self.length.to_be_bytes());
        buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf[8..20].copy_from_slice(&self.transaction_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(msg_type: u16, length: u16) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&msg_type.to_be_bytes());
        buf[2..4].copy_from_slice(&length.to_be_bytes());
        buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        // transaction_id stays zeroed
        buf
    }

    #[test]
    fn rejects_oversized_message() {
        // Binding Request (type 0x0001) declaring length = MAX_MESSAGE_LEN + 4.
        // Must be aligned to 4 bytes, otherwise InvalidLength fires first.
        let bad_len: u16 = MAX_MESSAGE_LEN + 4;
        let buf = header_bytes(0x0001, bad_len);

        let err = MessageHeader::decode(&buf).unwrap_err();
        match err {
            StunError::MessageTooLong { len, max } => {
                assert_eq!(len, bad_len);
                assert_eq!(max, MAX_MESSAGE_LEN);
            }
            other => panic!("expected MessageTooLong, got: {other:?}"),
        }
    }

    #[test]
    fn accepts_message_at_max_length() {
        // Length = MAX (which is 4-aligned by construction). Should decode.
        let buf = header_bytes(0x0001, MAX_MESSAGE_LEN);
        let header = MessageHeader::decode(&buf).expect("max length must decode");
        assert_eq!(header.length, MAX_MESSAGE_LEN);
    }

    #[test]
    fn rejects_non_multiple_of_four() {
        // Length = 7 — odd, not a multiple of 4. Must fail with InvalidLength
        // (the alignment check is more specific than MessageTooLong here).
        let buf = header_bytes(0x0001, 7);
        let err = MessageHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, StunError::InvalidLength));
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let mut buf = header_bytes(0x0001, 0);
        buf[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        let err = MessageHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, StunError::InvalidMagicCookie));
    }

    #[test]
    fn rejects_top_bits_set() {
        for bad in [0x8001u16, 0xC001] {
            let buf = header_bytes(bad, 0);
            match MessageHeader::decode(&buf) {
                Err(StunError::InvalidMessageType(t)) => assert_eq!(t, bad),
                other => panic!("expected InvalidMessageType for {bad:#06x}, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_method_is_reported_as_unknown_method() {
        // msg_type 0x0002 → method 0x0002 (unassigned), class Request, top bits 0.
        let buf = header_bytes(0x0002, 0);
        assert!(matches!(
            MessageHeader::decode(&buf),
            Err(StunError::UnknownMethod(2))
        ));
    }
}
