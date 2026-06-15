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

#[cfg(test)]
mod tests {
    use super::*;

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
