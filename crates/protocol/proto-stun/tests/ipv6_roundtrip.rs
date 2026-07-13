//! IPv6 roundtrip for XOR-address attributes.
//!
//! `property.rs` only exercises IPv4 addresses; `rfc5769_vectors.rs` decodes one
//! fixed IPv6 XOR-MAPPED-ADDRESS. Neither covers the *generative* IPv6 encode→decode
//! path, where the XOR spans the magic cookie **and** the transaction id (unlike
//! IPv4, which XORs only the cookie). This file closes that gap for all three
//! XOR-address attributes.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use proptest::prelude::*;
use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

fn arb_ipv6_socket() -> impl Strategy<Value = SocketAddr> {
    (any::<[u8; 16]>(), 1u16..=u16::MAX)
        .prop_map(|(octets, port)| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
}

fn arb_tid() -> impl Strategy<Value = [u8; 12]> {
    any::<[u8; 12]>()
}

/// Build a message carrying one XOR-address attribute, encode it, decode it back,
/// and return the address the decoder produced for `want_type`.
fn roundtrip_xor(kind: u8, addr: SocketAddr, tid: [u8; 12]) -> Option<SocketAddr> {
    let attr = match kind {
        0 => Attribute::XorMappedAddress(addr),
        1 => Attribute::XorPeerAddress(addr),
        _ => Attribute::XorRelayedAddress(addr),
    };
    let mut msg =
        StunMessage::with_transaction_id(Method::Allocate, MessageClass::SuccessResponse, tid);
    msg.add(attr);

    let mut buf = [0u8; 128];
    let len = msg.encode(&mut buf).expect("IPv6 XOR address must encode");
    let decoded = StunMessage::decode(&buf[..len]).expect("encoded IPv6 message must decode");

    decoded.attributes.iter().find_map(|a| match (kind, a) {
        (0, Attribute::XorMappedAddress(sa)) => Some(*sa),
        (1, Attribute::XorPeerAddress(sa)) => Some(*sa),
        (2, Attribute::XorRelayedAddress(sa)) => Some(*sa),
        _ => None,
    })
}

proptest! {
    #[test]
    fn ipv6_xor_mapped_roundtrips(addr in arb_ipv6_socket(), tid in arb_tid()) {
        prop_assert_eq!(roundtrip_xor(0, addr, tid), Some(addr));
    }

    #[test]
    fn ipv6_xor_peer_roundtrips(addr in arb_ipv6_socket(), tid in arb_tid()) {
        prop_assert_eq!(roundtrip_xor(1, addr, tid), Some(addr));
    }

    #[test]
    fn ipv6_xor_relayed_roundtrips(addr in arb_ipv6_socket(), tid in arb_tid()) {
        prop_assert_eq!(roundtrip_xor(2, addr, tid), Some(addr));
    }
}
