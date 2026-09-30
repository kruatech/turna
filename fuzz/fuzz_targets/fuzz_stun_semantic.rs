//! Semantic/structured STUN mutation fuzzer
//!
//! Unlike `fuzz_stun` (random bytes), this target generates
//! **valid STUN frames** and applies **semantic mutations**:
//!
//! - duplicate attributes
//! - wrong MESSAGE-INTEGRITY (1-bit flip)
//! - wrong FINGERPRINT
//! - wrong attribute order (INTEGRITY before USERNAME)
//! - oversized values exactly at the MAX_ATTRIBUTE_VALUE_LEN boundary
//! - invalid transaction ID patterns
//!
//! Contract: no input causes a panic, hang or OOM.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::attribute::Attribute;

const FUZZ_KEY: &[u8] = b"fuzz_integrity_key_32bytes_pad__";

#[derive(Debug, Arbitrary)]
enum StunMutation {
    /// Valid Binding Request — baseline.
    ValidBinding,
    /// Duplicate USERNAME.
    DuplicateAttr,
    /// MESSAGE-INTEGRITY with a bit flip in the HMAC.
    CorruptedIntegrity { flip_byte: u8, flip_bit: u8 },
    /// FINGERPRINT with a wrong CRC32.
    WrongFingerprint(u32),
    /// INTEGRITY placed before USERNAME (violates RFC 5389 §15.4).
    IntegrityBeforeUsername,
    /// Attribute exactly MAX_ATTRIBUTE_VALUE_LEN long (boundary value).
    AttrAtMaxLen,
    /// Attribute MAX_ATTRIBUTE_VALUE_LEN + 1 long (must be rejected).
    AttrOverMaxLen,
    /// Transaction ID = all zeros.
    ZeroTransactionId,
    /// Transaction ID = all 0xFF.
    MaxTransactionId,
    /// LIFETIME with the maximum u32.
    MaxLifetime,
    /// Invalid family in XOR-MAPPED-ADDRESS (neither 0x01 nor 0x02).
    UnknownAddressFamily(u8),
    /// Several XOR-PEER-ADDRESS attributes in a row.
    RepeatedPeerAddress(u8),
    /// Empty DATA attribute.
    EmptyData,
}

fn build_mutated(mutation: &StunMutation) -> Vec<u8> {
    match mutation {
        StunMutation::ValidBinding => {
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Software("fuzz".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::DuplicateAttr => {
            let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
            msg.add(Attribute::Username("user".into()));
            msg.add(Attribute::Username("user".into())); // duplicate
            msg.add(Attribute::Realm("realm".into()));
            msg.add(Attribute::Nonce("nonce".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::CorruptedIntegrity { flip_byte, flip_bit } => {
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Username("user".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
            let mut raw = buf[..n].to_vec();
            // Flip a bit in the last 20 bytes (HMAC-SHA1)
            if n >= 20 {
                let idx = n - 20 + (*flip_byte as usize % 20);
                raw[idx] ^= 1 << (*flip_bit % 8);
            }
            raw
        }

        StunMutation::WrongFingerprint(fp) => {
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Fingerprint(*fp)); // arbitrary CRC
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::IntegrityBeforeUsername => {
            // Build the raw buffer by hand: INTEGRITY header before USERNAME
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            // Add in the "wrong" order
            msg.add(Attribute::MessageIntegrity([0u8; 20]));
            msg.add(Attribute::Username("user".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::AttrAtMaxLen => {
            // SOFTWARE exactly 1500 bytes long — must be accepted
            let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
            msg.add(Attribute::Software("X".repeat(1500)));
            let mut buf = vec![0u8; 4096];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::AttrOverMaxLen => {
            // Hand-encode an attribute with length 1501 (exceeds the limit).
            // The parser must return Err, not panic.
            let mut hdr = [0u8; 20];
            // Binding Request header
            hdr[0] = 0x00; hdr[1] = 0x01; // type
            hdr[2] = 0x05; hdr[3] = 0xE8; // length = 1504 (1501 + 3 padding), aligned
            hdr[4] = 0x21; hdr[5] = 0x12; hdr[6] = 0xA4; hdr[7] = 0x42; // magic
            let mut raw = hdr.to_vec();
            raw.extend_from_slice(&[0x80u8, 0x22]); // SOFTWARE type
            raw.extend_from_slice(&1501u16.to_be_bytes()); // declared len = 1501
            raw.extend(std::iter::repeat(b'X').take(1504)); // padded
            raw
        }

        StunMutation::ZeroTransactionId => {
            let mut msg = StunMessage::with_transaction_id(
                Method::Binding, MessageClass::Request, [0u8; 12],
            );
            msg.add(Attribute::Software("zero-tid".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::MaxTransactionId => {
            let mut msg = StunMessage::with_transaction_id(
                Method::Binding, MessageClass::Request, [0xFFu8; 12],
            );
            msg.add(Attribute::Software("max-tid".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::MaxLifetime => {
            let mut msg = StunMessage::new(Method::Refresh, MessageClass::Request);
            msg.add(Attribute::Lifetime(u32::MAX));
            msg.add(Attribute::Username("u".into()));
            msg.add(Attribute::Realm("r".into()));
            msg.add(Attribute::Nonce("n".into()));
            let mut buf = [0u8; 512];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::UnknownAddressFamily(family) => {
            // Hand-build an XOR-MAPPED-ADDRESS with an invalid family
            let mut hdr = [0u8; 20];
            hdr[0] = 0x01; hdr[1] = 0x01; // Binding Success
            hdr[2] = 0x00; hdr[3] = 0x0C; // length = 12
            hdr[4] = 0x21; hdr[5] = 0x12; hdr[6] = 0xA4; hdr[7] = 0x42;
            let mut raw = hdr.to_vec();
            raw.extend_from_slice(&[0x00, 0x20]); // XOR-MAPPED-ADDRESS
            raw.extend_from_slice(&8u16.to_be_bytes()); // len = 8
            raw.push(0x00); raw.push(*family); // invalid family
            raw.extend_from_slice(&[0x00u8; 6]); // port + addr
            raw
        }

        StunMutation::RepeatedPeerAddress(count) => {
            let mut msg = StunMessage::new(Method::CreatePermission, MessageClass::Request);
            let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
            for _ in 0..(*count as usize).min(30) {
                msg.add(Attribute::XorPeerAddress(peer));
            }
            msg.add(Attribute::Username("u".into()));
            msg.add(Attribute::Realm("r".into()));
            msg.add(Attribute::Nonce("n".into()));
            let mut buf = vec![0u8; 8192];
            let n = msg.encode_with_integrity(&mut buf, FUZZ_KEY).unwrap();
            buf[..n].to_vec()
        }

        StunMutation::EmptyData => {
            let mut msg = StunMessage::new(Method::Send, MessageClass::Indication);
            let peer: std::net::SocketAddr = "10.0.0.1:5000".parse().unwrap();
            msg.add(Attribute::XorPeerAddress(peer));
            msg.add(Attribute::Data(vec![]));
            let mut buf = [0u8; 512];
            let n = msg.encode(&mut buf).unwrap();
            buf[..n].to_vec()
        }
    }
}

fuzz_target!(|mutation: StunMutation| {
    let raw = build_mutated(&mutation);

    // No path may panic
    let _ = StunMessage::decode(&raw);
    let _ = turna_proto_stun::message::is_stun_message(&raw);
    let _ = turna_proto_stun::message::is_channel_data(&raw);
    let _ = turna_proto_stun::header::MessageHeader::decode(&raw);
    let _ = turna_proto_stun::attribute::parse_attributes(
        if raw.len() > 20 { &raw[20..] } else { &[] },
        &[0u8; 12],
    );

    if let Ok(msg) = StunMessage::decode(&raw) {
        let _ = msg.verify_integrity(&raw, FUZZ_KEY);
    }
});
