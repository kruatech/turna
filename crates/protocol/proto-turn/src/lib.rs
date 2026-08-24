//! TURN protocol helpers (RFC 8656)
//!
//! Built on top of turna-proto-stun. Provides TURN-specific message builders
//! and allocation state types.

pub use turna_proto_stun::attribute::Attribute;
pub use turna_proto_stun::header::MessageClass;
pub use turna_proto_stun::message::{is_channel_data, is_stun_message, StunMessage};
pub use turna_proto_stun::method::Method;

use std::net::SocketAddr;

/// UDP transport protocol number for REQUESTED-TRANSPORT.
pub const TRANSPORT_UDP: u8 = 17;
/// RFC 6062 TCP relayed transport (REQUESTED-TRANSPORT protocol value).
pub const TRANSPORT_TCP: u8 = 6;
/// SCTP (IANA protocol number 132, RFC 4960). NOTE: there is NO TURN RFC that
/// defines SCTP as a *relayed* transport — this constant exists for TURN-over-SCTP
/// as a client *control* transport (relayed side stays UDP). Do not treat it as a
/// standardized relayed-transport value.
pub const TRANSPORT_SCTP: u8 = 132;

/// Default TURN allocation lifetime in seconds.
pub const DEFAULT_LIFETIME: u32 = 600;

/// Maximum TURN allocation lifetime in seconds.
pub const MAX_LIFETIME: u32 = 3600;

/// Channel number range: 0x4000..=0x7FFE
pub const CHANNEL_MIN: u16 = 0x4000;
pub const CHANNEL_MAX: u16 = 0x7FFE;

pub fn is_valid_channel(ch: u16) -> bool {
    (CHANNEL_MIN..=CHANNEL_MAX).contains(&ch)
}

/// Build an Allocate request.
pub fn build_allocate_request(username: &str, realm: &str, nonce: &str) -> StunMessage {
    let mut msg = StunMessage::new(Method::Allocate, MessageClass::Request);
    msg.add(Attribute::RequestedTransport(TRANSPORT_UDP));
    msg.add(Attribute::Username(username.to_string()));
    msg.add(Attribute::Realm(realm.to_string()));
    msg.add(Attribute::Nonce(nonce.to_string()));
    msg
}

/// Build an Allocate success response.
pub fn build_allocate_response(
    tid: [u8; 12],
    relayed_addr: SocketAddr,
    mapped_addr: SocketAddr,
    lifetime: u32,
) -> StunMessage {
    let mut msg =
        StunMessage::with_transaction_id(Method::Allocate, MessageClass::SuccessResponse, tid);
    msg.add(Attribute::XorRelayedAddress(relayed_addr));
    msg.add(Attribute::XorMappedAddress(mapped_addr));
    msg.add(Attribute::Lifetime(lifetime));
    msg
}

/// Build a CreatePermission request.
pub fn build_create_permission_request(
    peer_addr: SocketAddr,
    username: &str,
    realm: &str,
    nonce: &str,
) -> StunMessage {
    let mut msg = StunMessage::new(Method::CreatePermission, MessageClass::Request);
    msg.add(Attribute::XorPeerAddress(peer_addr));
    msg.add(Attribute::Username(username.to_string()));
    msg.add(Attribute::Realm(realm.to_string()));
    msg.add(Attribute::Nonce(nonce.to_string()));
    msg
}

/// Build a ChannelBind request.
pub fn build_channel_bind_request(
    channel: u16,
    peer_addr: SocketAddr,
    username: &str,
    realm: &str,
    nonce: &str,
) -> StunMessage {
    let mut msg = StunMessage::new(Method::ChannelBind, MessageClass::Request);
    msg.add(Attribute::ChannelNumber(channel));
    msg.add(Attribute::XorPeerAddress(peer_addr));
    msg.add(Attribute::Username(username.to_string()));
    msg.add(Attribute::Realm(realm.to_string()));
    msg.add(Attribute::Nonce(nonce.to_string()));
    msg
}

/// Build an RFC 6062 §4.4 ConnectionAttempt indication — sent to the client over
/// its (already authenticated) control connection when a peer opens a TCP
/// connection to the relayed transport address. The client answers by opening a
/// new connection and ConnectionBind-ing `connection_id`. Indications carry no
/// MESSAGE-INTEGRITY (the control channel authenticates the server, and the
/// subsequent ConnectionBind requires the client's own credentials + ownership
/// check, so the id is useless to anyone else).
pub fn build_connection_attempt(connection_id: u32, peer_addr: SocketAddr) -> StunMessage {
    let mut msg = StunMessage::new(Method::ConnectionAttempt, MessageClass::Indication);
    msg.add(Attribute::ConnectionId(connection_id));
    msg.add(Attribute::XorPeerAddress(peer_addr));
    msg
}

/// Build a simple success response (for CreatePermission, ChannelBind, Refresh).
pub fn build_success_response(method: Method, tid: [u8; 12]) -> StunMessage {
    StunMessage::with_transaction_id(method, MessageClass::SuccessResponse, tid)
}

/// Build an error response.
pub fn build_error_response(method: Method, tid: [u8; 12], code: u16, reason: &str) -> StunMessage {
    let mut msg = StunMessage::with_transaction_id(method, MessageClass::ErrorResponse, tid);
    msg.add(Attribute::ErrorCode {
        code,
        reason: reason.to_string(),
    });
    msg
}

/// Build a 300 Try Alternate redirect response.
///
/// The response keeps the original request method, per STUN message-type
/// encoding rules, and carries the alternate TURN endpoint in
/// ALTERNATE-SERVER. The `src` argument is accepted for call-site symmetry
/// with packet processors; the wire encoding only needs the transaction id.
pub fn build_redirect_response(
    method: Method,
    tid: [u8; 12],
    alternate_addr: SocketAddr,
    _src: SocketAddr,
) -> StunMessage {
    let mut msg = build_error_response(method, tid, 300, "Try Alternate");
    msg.add(Attribute::AlternateServer(alternate_addr));
    msg
}

/// Build a 401 Unauthorized response with REALM and NONCE (for auth challenge).
///
/// Also advertises PASSWORD-ALGORITHMS (RFC 8489) so an RFC 8489 client may
/// choose MESSAGE-INTEGRITY-SHA256. The attribute is comprehension-optional
/// (0x8002), so RFC 5389 clients ignore it and continue with HMAC-SHA-1.
pub fn build_auth_challenge(
    method: Method,
    tid: [u8; 12],
    realm: &str,
    nonce: &str,
) -> StunMessage {
    use turna_proto_stun::attribute::{
        ATTR_PASSWORD_ALGORITHMS, PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256,
    };
    let mut msg = build_error_response(method, tid, 401, "Unauthorized");
    msg.add(Attribute::Realm(realm.to_string()));
    msg.add(Attribute::Nonce(nonce.to_string()));

    // Each entry: {algorithm: u16, params-length: u16, params...}. MD5 and
    // SHA-256 carry no parameters, so each entry is 4 bytes.
    let mut algos = Vec::with_capacity(8);
    for algo in [PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256] {
        algos.extend_from_slice(&algo.to_be_bytes());
        algos.extend_from_slice(&0u16.to_be_bytes());
    }
    msg.add(Attribute::Unknown {
        attr_type: ATTR_PASSWORD_ALGORITHMS,
        value: algos,
    });
    msg
}

/// RFC 7635 §6.1 third-party (OAuth) 401 challenge: a standard auth challenge
/// plus a THIRD-PARTY-AUTHORIZATION attribute advertising the authorization
/// server identity, so a client without a token learns where to obtain one.
pub fn build_oauth_challenge(
    method: Method,
    tid: [u8; 12],
    realm: &str,
    nonce: &str,
    as_identity: &[u8],
) -> StunMessage {
    let mut msg = build_auth_challenge(method, tid, realm, nonce);
    msg.add(Attribute::ThirdPartyAuthorization(as_identity.to_vec()));
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `300 Try Alternate` must carry ALTERNATE-SERVER as attribute type
    /// **0x8023**, checked on the encoded bytes rather than through the enum.
    ///
    /// This is a wire-format regression test, and it exists because the constant was
    /// `0x0003` — which is RFC 5780 CHANGE-REQUEST, a different attribute entirely.
    /// Every cluster redirect and every lame-duck drain therefore shipped a `300`
    /// whose alternate address no conforming client could find, so the redirect
    /// silently did nothing. Nothing caught it: the enum variant was right, the
    /// round-trip tests passed because they used the same wrong constant on both
    /// sides, and the documentation claimed the value had already been corrected.
    ///
    /// Asserting the literal bytes is the point. A test written against
    /// `ATTR_ALTERNATE_SERVER` would have passed throughout the bug.
    #[test]
    fn redirect_encodes_alternate_server_as_0x8023() {
        let alt: std::net::SocketAddr = "203.0.113.7:3478".parse().unwrap();
        let tid = [0x11u8; 12];
        let msg = build_redirect_response(
            Method::Allocate,
            tid,
            alt,
            "198.51.100.9:50000".parse().unwrap(),
        );

        let mut buf = [0u8; 512];
        let len = msg.encode(&mut buf).expect("redirect must encode");
        let wire = &buf[..len];

        // Walk the TLV attributes after the 20-byte STUN header and collect the
        // types actually present on the wire.
        let mut types = Vec::new();
        let mut alt_value: Option<&[u8]> = None;
        let mut off = 20usize;
        while off + 4 <= wire.len() {
            let t = u16::from_be_bytes([wire[off], wire[off + 1]]);
            let l = u16::from_be_bytes([wire[off + 2], wire[off + 3]]) as usize;
            let vstart = off + 4;
            assert!(vstart + l <= wire.len(), "attribute {t:#06x} runs past the message");
            types.push(t);
            if t == 0x8023 {
                alt_value = Some(&wire[vstart..vstart + l]);
            }
            off = vstart + l + ((4 - (l % 4)) % 4); // 4-byte alignment padding
        }

        assert!(
            types.contains(&0x8023),
            "no ALTERNATE-SERVER (0x8023) on the wire; attribute types present: {:#06x?}",
            types
        );
        assert!(
            !types.contains(&0x0003),
            "0x0003 is on the wire — that is RFC 5780 CHANGE-REQUEST, not \
             ALTERNATE-SERVER. This is the exact regression this test guards: types \
             present {:#06x?}",
            types
        );

        // ALTERNATE-SERVER uses the plain MAPPED-ADDRESS encoding (RFC 5389 §15.5):
        // 0x00, family, port, address — NOT xor-mapped. Getting this wrong is the
        // other way a client fails to find the alternate.
        let v = alt_value.expect("value captured above");
        assert_eq!(v.len(), 8, "IPv4 MAPPED-ADDRESS is 8 bytes, got {}", v.len());
        assert_eq!(v[0], 0x00, "leading byte must be zero");
        assert_eq!(v[1], 0x01, "family must be 0x01 for IPv4");
        assert_eq!(
            u16::from_be_bytes([v[2], v[3]]),
            3478,
            "port must be the plain port, unxored"
        );
        assert_eq!(&v[4..8], &[203, 0, 113, 7], "address must be plain, unxored");
    }

    /// The error code itself, on the wire, for the same reason.
    #[test]
    fn redirect_encodes_error_code_300() {
        let msg = build_redirect_response(
            Method::Allocate,
            [0u8; 12],
            "203.0.113.7:3478".parse().unwrap(),
            "198.51.100.9:50000".parse().unwrap(),
        );
        let mut buf = [0u8; 512];
        let len = msg.encode(&mut buf).expect("encode");
        let wire = &buf[..len];

        let mut off = 20usize;
        let mut code = None;
        while off + 4 <= wire.len() {
            let t = u16::from_be_bytes([wire[off], wire[off + 1]]);
            let l = u16::from_be_bytes([wire[off + 2], wire[off + 3]]) as usize;
            if t == 0x0009 && l >= 4 {
                // ERROR-CODE: two reserved bytes, then class and number.
                code = Some(u16::from(wire[off + 6]) * 100 + u16::from(wire[off + 7]));
            }
            off += 4 + l + ((4 - (l % 4)) % 4);
        }
        assert_eq!(code, Some(300), "expected 300 Try Alternate on the wire");
    }

    #[test]
    fn auth_challenge_advertises_password_algorithms() {
        let msg = build_auth_challenge(Method::Allocate, [0u8; 12], "realm", "nonce");
        let value = msg
            .attributes
            .iter()
            .find_map(|a| match a {
                Attribute::Unknown { attr_type, value }
                    if *attr_type == turna_proto_stun::attribute::ATTR_PASSWORD_ALGORITHMS =>
                {
                    Some(value.clone())
                }
                _ => None,
            })
            .expect("challenge must carry PASSWORD-ALGORITHMS");
        // MD5 (0x0001, len 0) then SHA-256 (0x0002, len 0).
        assert_eq!(value, vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00]);
        // REALM and NONCE are still present.
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::Realm(r) if r == "realm")));
        assert!(msg
            .attributes
            .iter()
            .any(|a| matches!(a, Attribute::Nonce(n) if n == "nonce")));
    }
}
