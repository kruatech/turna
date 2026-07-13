//! RFC 5769 known-answer vectors.
//!
//! `property.rs` proves `decode(encode(x)) == x` — but a symmetric XOR/endianness
//! bug survives a roundtrip because it cancels out. These vectors decode the
//! authoritative sample messages from RFC 5769 (the byte strings are copied
//! verbatim from the RFC's own Appendix A C source, `respv4[]` / `respv6[]`) and
//! assert the decoded XOR-MAPPED-ADDRESS against the RFC's stated answer. This is
//! exactly the class of bug the RFC vectors exist to catch.
//!
//! Note: MESSAGE-INTEGRITY / FINGERPRINT verification is intentionally not asserted
//! here — that needs the long-term key and is covered by the auth path. These
//! vectors target the XOR-MAPPED-ADDRESS decode, which needs no key.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::MessageClass;
use turna_proto_stun::message::StunMessage;
use turna_proto_stun::method::Method;

/// RFC 5769 §2.2 — Sample IPv4 Response. Mapped address: 192.0.2.1 port 32853.
const RESP_V4: &[u8] = b"\x01\x01\x00\x3c\
\x21\x12\xa4\x42\
\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\
\x80\x22\x00\x0b\
\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\
\x00\x20\x00\x08\
\x00\x01\xa1\x47\xe1\x12\xa6\x43\
\x00\x08\x00\x14\
\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\
\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7\
\x80\x28\x00\x04\
\xc0\x7d\x4c\x96";

/// RFC 5769 §2.3 — Sample IPv6 Response.
/// Mapped address: 2001:db8:1234:5678:11:2233:4455:6677 port 32853.
const RESP_V6: &[u8] = b"\x01\x01\x00\x48\
\x21\x12\xa4\x42\
\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\
\x80\x22\x00\x0b\
\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\
\x00\x20\x00\x14\
\x00\x02\xa1\x47\
\x01\x13\xa9\xfa\xa5\xd3\xf1\x79\
\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9\
\x00\x08\x00\x14\
\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\
\x82\x92\xc2\x75\xbf\xe3\xed\x41\
\x80\x28\x00\x04\
\xc8\xfb\x0b\x4c";

const EXPECTED_TID: [u8; 12] = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

fn xor_mapped(msg: &StunMessage) -> Option<SocketAddr> {
    msg.attributes.iter().find_map(|a| match a {
        Attribute::XorMappedAddress(sa) => Some(*sa),
        _ => None,
    })
}

#[test]
fn rfc5769_ipv4_response_decodes_to_known_address() {
    let msg = StunMessage::decode(RESP_V4).expect("RFC 5769 §2.2 must decode");
    assert!(matches!(msg.class, MessageClass::SuccessResponse));
    assert_eq!(msg.method, Method::Binding);
    assert_eq!(msg.transaction_id, EXPECTED_TID);

    let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32853);
    assert_eq!(
        xor_mapped(&msg),
        Some(expected),
        "XOR-MAPPED-ADDRESS must un-XOR to 192.0.2.1:32853"
    );
}

#[test]
fn rfc5769_ipv6_response_decodes_to_known_address() {
    let msg = StunMessage::decode(RESP_V6).expect("RFC 5769 §2.3 must decode");
    assert!(matches!(msg.class, MessageClass::SuccessResponse));
    assert_eq!(msg.method, Method::Binding);
    assert_eq!(msg.transaction_id, EXPECTED_TID);

    let expected_ip: Ipv6Addr = "2001:db8:1234:5678:11:2233:4455:6677"
        .parse()
        .expect("literal IPv6 parses");
    let expected = SocketAddr::new(IpAddr::V6(expected_ip), 32853);
    assert_eq!(
        xor_mapped(&msg),
        Some(expected),
        "XOR-MAPPED-ADDRESS must un-XOR to the RFC 5769 IPv6 address:32853"
    );
}
