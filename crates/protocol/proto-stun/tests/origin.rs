//! ORIGIN attribute (draft-ietf-tram-stun-origin, type 0x802F) codec tests.
//!
//! ORIGIN is comprehension-optional, variable-length UTF-8, and a sender MAY
//! include several. It is a forgeable hint — these tests only cover the codec
//! (parse/encode/getter), not any policy use.

use turna_proto_stun::attribute::{Attribute, ATTR_ORIGIN};
use turna_proto_stun::header::{MessageClass, MAGIC_COOKIE};
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

#[test]
fn origin_roundtrips_and_preserves_multiple_in_order() {
    let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
    msg.add(Attribute::Origin("https://a.example".to_string()));
    msg.add(Attribute::Origin("https://b.example:8443".to_string()));

    let mut buf = [0u8; 256];
    let len = msg.encode(&mut buf).expect("ORIGIN must encode");
    let decoded = StunMessage::decode(&buf[..len]).expect("must decode");

    assert_eq!(decoded.get_origin(), Some("https://a.example"));
    let all: Vec<&str> = decoded.origins().collect();
    assert_eq!(all, vec!["https://a.example", "https://b.example:8443"]);
}

#[test]
fn absent_origin_is_none() {
    let msg = StunMessage::new(Method::Binding, MessageClass::Request);
    let mut buf = [0u8; 64];
    let len = msg.encode(&mut buf).unwrap();
    let decoded = StunMessage::decode(&buf[..len]).unwrap();
    assert_eq!(decoded.get_origin(), None);
    assert_eq!(decoded.origins().count(), 0);
}

/// A malformed (non-UTF-8) ORIGIN must NOT fail the whole message — it is
/// comprehension-optional and forgeable, so it is decoded lossily.
#[test]
fn invalid_utf8_origin_decodes_lossily_without_error() {
    // Header: Binding request, magic cookie, zero transaction id.
    let mut m = Vec::new();
    m.extend_from_slice(&0x0001u16.to_be_bytes()); // type
    m.extend_from_slice(&0x0008u16.to_be_bytes()); // message length = 8 (attr hdr 4 + padded value 4)
    m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m.extend_from_slice(&[0u8; 12]); // transaction id
                                     // ORIGIN attribute with a 2-byte invalid-UTF-8 value (0xff 0xfe), padded to 4.
    m.extend_from_slice(&ATTR_ORIGIN.to_be_bytes());
    m.extend_from_slice(&0x0002u16.to_be_bytes()); // value length = 2
    m.extend_from_slice(&[0xff, 0xfe, 0x00, 0x00]); // value + 2 padding bytes

    let decoded = StunMessage::decode(&m).expect("malformed ORIGIN must not fail the message");
    // Lossy decode: an origin string is present (contains U+FFFD replacements).
    assert!(
        decoded.get_origin().is_some(),
        "ORIGIN should be present (lossy)"
    );
}
