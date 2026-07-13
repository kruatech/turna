//! RFC 6062 (TCP relay) codec: methods + CONNECTION-ID attribute.
//!
//! Covers the STUN wire layer only — Connect / ConnectionBind / ConnectionAttempt
//! methods and the CONNECTION-ID attribute. The relay data-plane
//! (`TcpRelayManager`) and its processor/server wiring are separate.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

#[test]
fn tcp_relay_methods_parse_from_raw() {
    assert_eq!(Method::from_raw(0x000A), Some(Method::Connect));
    assert_eq!(Method::from_raw(0x000B), Some(Method::ConnectionBind));
    assert_eq!(Method::from_raw(0x000C), Some(Method::ConnectionAttempt));
    assert_eq!(Method::Connect.as_u16(), 0x000A);
}

#[test]
fn connect_request_with_peer_roundtrips() {
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 5000);
    let mut msg = StunMessage::new(Method::Connect, MessageClass::Request);
    msg.add(Attribute::XorPeerAddress(peer));

    let mut buf = [0u8; 128];
    let len = msg.encode(&mut buf).expect("Connect must encode");
    let decoded = StunMessage::decode(&buf[..len]).expect("must decode");

    assert_eq!(decoded.method, Method::Connect);
    assert!(matches!(decoded.class, MessageClass::Request));
    assert_eq!(decoded.get_xor_peer_address(), Some(peer));
}

#[test]
fn connect_response_carries_connection_id() {
    let mut msg = StunMessage::new(Method::Connect, MessageClass::SuccessResponse);
    msg.add(Attribute::ConnectionId(0xDEAD_BEEF));

    let mut buf = [0u8; 64];
    let len = msg.encode(&mut buf).expect("response must encode");
    let decoded = StunMessage::decode(&buf[..len]).expect("must decode");

    assert_eq!(decoded.method, Method::Connect);
    assert_eq!(decoded.get_connection_id(), Some(0xDEAD_BEEF));
}

#[test]
fn connection_bind_request_carries_connection_id() {
    let mut msg = StunMessage::new(Method::ConnectionBind, MessageClass::Request);
    msg.add(Attribute::ConnectionId(0x0000_0001));

    let mut buf = [0u8; 64];
    let len = msg.encode(&mut buf).unwrap();
    let decoded = StunMessage::decode(&buf[..len]).unwrap();

    assert_eq!(decoded.method, Method::ConnectionBind);
    assert_eq!(decoded.get_connection_id(), Some(1));
}

#[test]
fn connection_id_length_guard_via_corruption() {
    // Encode a valid ConnectionBind+CONNECTION-ID (correct STUN message type is
    // produced by the library, not hand-built), then corrupt the attribute's
    // declared length to 2 and confirm decode fails rather than misparsing.
    let mut msg = StunMessage::new(Method::ConnectionBind, MessageClass::Request);
    msg.add(Attribute::ConnectionId(0x0000_0001));
    let mut buf = [0u8; 64];
    let len = msg.encode(&mut buf).unwrap();

    // Attribute area starts at byte 20; layout is [type:2][len:2][value:4].
    // Overwrite the length field (bytes 22..24) with 2.
    buf[22] = 0x00;
    buf[23] = 0x02;
    assert!(
        StunMessage::decode(&buf[..len]).is_err(),
        "corrupted CONNECTION-ID length must be rejected, not misparsed"
    );
}
