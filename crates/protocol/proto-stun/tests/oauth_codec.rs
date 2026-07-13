//! RFC 7635 (third-party / OAuth authorization) codec: ACCESS-TOKEN and
//! THIRD-PARTY-AUTHORIZATION attributes.
//!
//! Codec layer only — the attributes carry opaque bytes here. The AEAD token
//! decryption, timestamp/lifetime validation, and MESSAGE-INTEGRITY-with-mac_key
//! verification live in the auth layer (a separate, security-sensitive step).

use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

#[test]
fn access_token_roundtrips_as_opaque_bytes() {
    // A plausible token framing (nonce_length || nonce || ciphertext) — the codec
    // does not interpret it, just preserves the bytes verbatim.
    let token = vec![
        0x00, 0x04, // nonce_length = 4
        0xAA, 0xBB, 0xCC, 0xDD, // nonce
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // (encrypted) block, opaque here
    ];
    let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
    msg.add(Attribute::AccessToken(token.clone()));

    let mut buf = [0u8; 128];
    let len = msg.encode(&mut buf).expect("ACCESS-TOKEN must encode");
    let decoded = StunMessage::decode(&buf[..len]).expect("must decode");

    assert_eq!(decoded.get_access_token(), Some(token.as_slice()));
}

#[test]
fn third_party_authorization_roundtrips() {
    let as_id = b"https://auth.example.com".to_vec();
    let mut msg = StunMessage::new(Method::Allocate, MessageClass::ErrorResponse);
    msg.add(Attribute::ThirdPartyAuthorization(as_id.clone()));

    let mut buf = [0u8; 128];
    let len = msg.encode(&mut buf).unwrap();
    let decoded = StunMessage::decode(&buf[..len]).unwrap();

    assert_eq!(
        decoded.get_third_party_authorization(),
        Some(as_id.as_slice())
    );
    // No ACCESS-TOKEN present → None.
    assert_eq!(decoded.get_access_token(), None);
}

#[test]
fn empty_access_token_roundtrips() {
    let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
    msg.add(Attribute::AccessToken(Vec::new()));
    let mut buf = [0u8; 64];
    let len = msg.encode(&mut buf).unwrap();
    let decoded = StunMessage::decode(&buf[..len]).unwrap();
    assert_eq!(decoded.get_access_token(), Some(&[][..]));
}
