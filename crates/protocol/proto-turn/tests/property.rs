//! Property tests for TURN message builders.
//!
//! These keep the TURN crate covered directly instead of relying only on the
//! lower-level `proto-stun` ChannelData/property tests. The builders here are
//! public API: a refactor must preserve the method/class, transaction id and
//! required TURN attributes after encode -> decode.

use proptest::prelude::*;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use turna_proto_turn::{
    build_allocate_request, build_allocate_response, build_auth_challenge,
    build_channel_bind_request, build_create_permission_request, build_redirect_response,
    Attribute, MessageClass, Method, StunMessage, CHANNEL_MAX, CHANNEL_MIN, TRANSPORT_UDP,
};

fn arb_token() -> impl Strategy<Value = String> {
    // Keep values well below the STUN per-attribute cap while still exercising
    // padding and string roundtrips.
    "[a-zA-Z0-9_.@:-]{1,96}".prop_map(|s| s)
}

fn arb_tid() -> impl Strategy<Value = [u8; 12]> {
    any::<[u8; 12]>()
}

fn arb_ipv4_socket_addr() -> impl Strategy<Value = SocketAddr> {
    (any::<[u8; 4]>(), 1024u16..=65535).prop_map(|(octets, port)| {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
    })
}

fn arb_lifetime() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0u32), Just(1u32), Just(600u32), Just(3600u32), any::<u32>()]
}

fn arb_channel() -> impl Strategy<Value = u16> {
    CHANNEL_MIN..=CHANNEL_MAX
}

fn encode_decode(msg: &StunMessage) -> StunMessage {
    let mut buf = [0u8; 2048];
    let len = msg.encode(&mut buf).expect("TURN builder output must encode");
    StunMessage::decode(&buf[..len]).expect("encoded TURN builder output must decode")
}

fn get_xor_relayed_address(msg: &StunMessage) -> Option<SocketAddr> {
    msg.attributes.iter().find_map(|attr| match attr {
        Attribute::XorRelayedAddress(addr) => Some(*addr),
        _ => None,
    })
}

fn get_xor_mapped_address(msg: &StunMessage) -> Option<SocketAddr> {
    msg.attributes.iter().find_map(|attr| match attr {
        Attribute::XorMappedAddress(addr) => Some(*addr),
        _ => None,
    })
}

fn get_alternate_server(msg: &StunMessage) -> Option<SocketAddr> {
    msg.attributes.iter().find_map(|attr| match attr {
        Attribute::AlternateServer(addr) => Some(*addr),
        _ => None,
    })
}

fn get_error_code(msg: &StunMessage) -> Option<(u16, String)> {
    msg.attributes.iter().find_map(|attr| match attr {
        Attribute::ErrorCode { code, reason } => Some((*code, reason.clone())),
        _ => None,
    })
}

proptest! {
    #[test]
    fn prop_allocate_request_builder_roundtrip(
        username in arb_token(),
        realm in arb_token(),
        nonce in arb_token(),
    ) {
        let msg = build_allocate_request(&username, &realm, &nonce);
        let decoded = encode_decode(&msg);

        prop_assert_eq!(decoded.method, Method::Allocate);
        prop_assert_eq!(decoded.class, MessageClass::Request);
        prop_assert_eq!(decoded.get_requested_transport(), Some(TRANSPORT_UDP));
        prop_assert_eq!(decoded.get_username(), Some(username.as_str()));
        prop_assert_eq!(decoded.get_realm(), Some(realm.as_str()));
        prop_assert_eq!(decoded.get_nonce(), Some(nonce.as_str()));
    }

    #[test]
    fn prop_allocate_response_builder_roundtrip(
        tid in arb_tid(),
        relayed_addr in arb_ipv4_socket_addr(),
        mapped_addr in arb_ipv4_socket_addr(),
        lifetime in arb_lifetime(),
    ) {
        let msg = build_allocate_response(tid, relayed_addr, mapped_addr, lifetime);
        let decoded = encode_decode(&msg);

        prop_assert_eq!(decoded.method, Method::Allocate);
        prop_assert_eq!(decoded.class, MessageClass::SuccessResponse);
        prop_assert_eq!(decoded.transaction_id, tid);
        prop_assert_eq!(decoded.get_lifetime(), Some(lifetime));
        prop_assert_eq!(get_xor_relayed_address(&decoded), Some(relayed_addr));
        prop_assert_eq!(get_xor_mapped_address(&decoded), Some(mapped_addr));
    }

    #[test]
    fn prop_create_permission_request_builder_roundtrip(
        peer_addr in arb_ipv4_socket_addr(),
        username in arb_token(),
        realm in arb_token(),
        nonce in arb_token(),
    ) {
        let msg = build_create_permission_request(peer_addr, &username, &realm, &nonce);
        let decoded = encode_decode(&msg);

        prop_assert_eq!(decoded.method, Method::CreatePermission);
        prop_assert_eq!(decoded.class, MessageClass::Request);
        prop_assert_eq!(decoded.get_xor_peer_address(), Some(peer_addr));
        prop_assert_eq!(decoded.get_username(), Some(username.as_str()));
        prop_assert_eq!(decoded.get_realm(), Some(realm.as_str()));
        prop_assert_eq!(decoded.get_nonce(), Some(nonce.as_str()));
    }

    #[test]
    fn prop_channel_bind_request_builder_roundtrip(
        channel in arb_channel(),
        peer_addr in arb_ipv4_socket_addr(),
        username in arb_token(),
        realm in arb_token(),
        nonce in arb_token(),
    ) {
        let msg = build_channel_bind_request(channel, peer_addr, &username, &realm, &nonce);
        let decoded = encode_decode(&msg);

        prop_assert_eq!(decoded.method, Method::ChannelBind);
        prop_assert_eq!(decoded.class, MessageClass::Request);
        prop_assert_eq!(decoded.get_channel_number(), Some(channel));
        prop_assert_eq!(decoded.get_xor_peer_address(), Some(peer_addr));
        prop_assert_eq!(decoded.get_username(), Some(username.as_str()));
        prop_assert_eq!(decoded.get_realm(), Some(realm.as_str()));
        prop_assert_eq!(decoded.get_nonce(), Some(nonce.as_str()));
    }

    #[test]
    fn prop_auth_challenge_builder_roundtrip(
        tid in arb_tid(),
        realm in arb_token(),
        nonce in arb_token(),
    ) {
        let msg = build_auth_challenge(Method::Allocate, tid, &realm, &nonce);
        let decoded = encode_decode(&msg);

        prop_assert_eq!(decoded.method, Method::Allocate);
        prop_assert_eq!(decoded.class, MessageClass::ErrorResponse);
        prop_assert_eq!(decoded.transaction_id, tid);
        prop_assert_eq!(decoded.get_realm(), Some(realm.as_str()));
        prop_assert_eq!(decoded.get_nonce(), Some(nonce.as_str()));
        prop_assert_eq!(get_error_code(&decoded), Some((401, "Unauthorized".to_string())));
    }

    #[test]
    fn prop_redirect_builder_roundtrip(
        tid in arb_tid(),
        alternate_addr in arb_ipv4_socket_addr(),
        src_addr in arb_ipv4_socket_addr(),
    ) {
        let msg = build_redirect_response(Method::Allocate, tid, alternate_addr, src_addr);
        let decoded = encode_decode(&msg);

        prop_assert_eq!(decoded.method, Method::Allocate);
        prop_assert_eq!(decoded.class, MessageClass::ErrorResponse);
        prop_assert_eq!(decoded.transaction_id, tid);
        prop_assert_eq!(get_error_code(&decoded), Some((300, "Try Alternate".to_string())));
        prop_assert_eq!(get_alternate_server(&decoded), Some(alternate_addr));
    }
}
