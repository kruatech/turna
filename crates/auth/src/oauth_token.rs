//! RFC 7635 self-contained ACCESS-TOKEN: an issuer and an inspector.
//!
//! turna only ever *consumes* these tokens; this module exists for the OAuth
//! verification kit (`tools/oauth-verify`, `docs/runbooks/oauth-verification.md`).
//! It lets an operator
//!
//! - **mint** a token exactly as an authorization server does, to exercise a
//!   node's OAuth path before a real AS is wired in, and
//! - **inspect** a token minted by their real AS with turna's own decoder, to
//!   see whether the two agree on the format before any packet is sent.
//!
//! Minting here does **not** verify OAuth interop — a token issuer written next
//! to the validator tests one reading of RFC 7635 against itself
//! (`docs/OPEN-DECISIONS.md`, "OAuth"). The production gate is lifted on
//! evidence from tokens minted by a real AS; this module only makes collecting
//! that evidence mechanical.
//!
//! # Format (RFC 7635 §6.2, as coturn implements it)
//!
//! ```text
//! u16  nonce_length
//! u8[] nonce                         (12 bytes for AES-GCM)
//! AEAD-seal(key = AS-RS key, nonce, aad = server name) of:
//!     u16  key_length
//!     u8[] mac_key                   (20 bytes for HMAC-SHA-1, 32 for SHA-256)
//!     u64  timestamp                 (fixed point: seconds << 16 | 1/64000 fractions)
//!     u32  lifetime                  (seconds)
//! ```
//!
//! AES-128-GCM for a 16-byte AS-RS key, AES-256-GCM for a 32-byte one; the
//! 16-byte GCM tag follows the ciphertext. The AAD is the STUN server name
//! (`[turn.auth.oauth] server_name`), which binds a token to one server.

use crate::AuthError;

/// What an AS puts inside a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenContents {
    /// The session key the client signs MESSAGE-INTEGRITY with.
    pub mac_key: Vec<u8>,
    /// Issue time, whole seconds since the Unix epoch.
    pub timestamp_secs: u64,
    /// Validity from `timestamp_secs`, seconds.
    pub lifetime: u32,
}

/// Seal `contents` into a self-contained ACCESS-TOKEN, as an authorization
/// server does. `nonce` must be unique per token under one AS-RS key (GCM).
///
/// `as_rs_key`: 16 bytes (AES-128-GCM) or 32 bytes (AES-256-GCM).
pub fn encode_access_token(
    as_rs_key: &[u8],
    server_name: &str,
    nonce: &[u8; 12],
    contents: &TokenContents,
) -> Result<Vec<u8>, AuthError> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

    if contents.mac_key.is_empty() || contents.mac_key.len() > u16::MAX as usize {
        return Err(AuthError::BadRequest);
    }
    let mut block = Vec::with_capacity(2 + contents.mac_key.len() + 12);
    block.extend_from_slice(&(contents.mac_key.len() as u16).to_be_bytes());
    block.extend_from_slice(&contents.mac_key);
    // §6.2 fixed point: whole seconds in the top 48 bits, no fraction.
    block.extend_from_slice(&(contents.timestamp_secs << 16).to_be_bytes());
    block.extend_from_slice(&contents.lifetime.to_be_bytes());

    let n = Nonce::from(*nonce);
    let payload = Payload {
        msg: &block,
        aad: server_name.as_bytes(),
    };
    let sealed = match as_rs_key.len() {
        16 => Aes128Gcm::new_from_slice(as_rs_key)
            .map_err(|_| AuthError::BadRequest)?
            .encrypt(&n, payload),
        32 => Aes256Gcm::new_from_slice(as_rs_key)
            .map_err(|_| AuthError::BadRequest)?
            .encrypt(&n, payload),
        _ => return Err(AuthError::BadRequest),
    }
    .map_err(|_| AuthError::BadRequest)?;

    let mut token = Vec::with_capacity(2 + nonce.len() + sealed.len());
    token.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    token.extend_from_slice(nonce);
    token.extend_from_slice(&sealed);
    Ok(token)
}

/// Decrypt a token with turna's own decoder — the one the validator uses — and
/// return its contents **without** judging freshness, so an expired token or a
/// clock disagreement can be seen rather than only reported as `Expired`.
///
/// Errors mean turna could not open it: wrong AS-RS key, wrong server name
/// (AAD), or a layout that is not RFC 7635 §6.2 as read here.
pub fn inspect_access_token(
    token: &[u8],
    as_rs_keys: &[Vec<u8>],
    server_name: &str,
) -> Result<TokenContents, AuthError> {
    let opened = crate::open_access_token(token, as_rs_keys, server_name)?;
    Ok(TokenContents {
        mac_key: opened.mac_key,
        timestamp_secs: opened.timestamp >> 16,
        lifetime: opened.lifetime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthMode;
    use turna_proto_stun::attribute::Attribute;
    use turna_proto_stun::header::MessageClass;
    use turna_proto_stun::message::StunMessage;
    use turna_proto_stun::method::Method;

    fn key(len: usize) -> Vec<u8> {
        turna_crypto::random_key_32()[..len].to_vec()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn nonce() -> [u8; 12] {
        turna_crypto::random_key_32()[..12].try_into().unwrap()
    }

    #[test]
    fn minted_tokens_round_trip_through_the_decoder() {
        for as_len in [16, 32] {
            let as_rs = key(as_len);
            let c = TokenContents {
                mac_key: key(20),
                timestamp_secs: now(),
                lifetime: 600,
            };
            let t = encode_access_token(&as_rs, "turn.example", &nonce(), &c).unwrap();
            assert_eq!(
                inspect_access_token(&t, std::slice::from_ref(&as_rs), "turn.example").unwrap(),
                c
            );
            // Wrong server name = wrong AAD = does not open.
            assert!(inspect_access_token(&t, &[as_rs], "other.example").is_err());
        }
    }

    /// The minted token is accepted by the real validator, end to end through
    /// MESSAGE-INTEGRITY keyed with the enclosed mac_key.
    #[test]
    fn minted_tokens_validate_in_auth_mode() {
        let as_rs = key(32);
        let mac_key = key(32);
        let t = encode_access_token(
            &as_rs,
            "turn.example",
            &nonce(),
            &TokenContents {
                mac_key: mac_key.clone(),
                timestamp_secs: now(),
                lifetime: 600,
            },
        )
        .unwrap();
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::AccessToken(t));
        let mut buf = [0u8; 512];
        let n = m.encode_with_integrity_sha256(&mut buf, &mac_key).unwrap();
        let raw = buf[..n].to_vec();
        let msg = StunMessage::decode(&raw).unwrap();
        let mode = AuthMode::oauth("example", vec![as_rs], "turn.example");
        let (k, life) = mode.validate_with_lifetime(&msg, &raw).unwrap();
        assert_eq!(k, mac_key);
        assert!(life.unwrap() <= 600);
    }

    #[test]
    fn inspect_shows_an_expired_token_instead_of_refusing_it() {
        let as_rs = key(16);
        let c = TokenContents {
            mac_key: key(20),
            timestamp_secs: now() - 7_200,
            lifetime: 60,
        };
        let t = encode_access_token(&as_rs, "s", &nonce(), &c).unwrap();
        assert_eq!(inspect_access_token(&t, &[as_rs], "s").unwrap(), c);
    }

    #[test]
    fn bad_keys_are_refused_when_minting() {
        let c = TokenContents {
            mac_key: key(20),
            timestamp_secs: 1,
            lifetime: 1,
        };
        assert!(encode_access_token(&key(24), "s", &nonce(), &c).is_err());
        let empty = TokenContents {
            mac_key: Vec::new(),
            ..c
        };
        assert!(encode_access_token(&key(16), "s", &nonce(), &empty).is_err());
    }
}
