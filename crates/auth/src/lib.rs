//! turna-auth — TURN credential validation + platform user authentication.
//!
//! # TURN auth (existing)
//! [`AuthMode`] validates STUN messages for TURN allocations.
//! [`rotation`] handles credential rotation without dropping sessions.
//!
//! # User auth (Phase 2)
//! [`store::UserStore`] — in-memory user store (Argon2 + JWT).
//! [`user::User`]       — platform user model.
//! [`jwt::Claims`]      — JWT token claims.

pub mod jwt;
pub mod rotation;
pub mod store;
pub mod tenant;
pub mod user;

pub use tenant::{AuthRegistry, AuthResolution};

use thiserror::Error;
use turna_proto_stun::message::StunMessage;

// ── TURN auth errors ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing credentials")]
    MissingCredentials,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("expired credentials")]
    Expired,
    #[error("integrity check failed")]
    IntegrityFailed,
    /// RFC 8489 §9.2.5: a PASSWORD-ALGORITHM that is unknown or inconsistent
    /// with the integrity attribute actually used → 400 Bad Request.
    #[error("bad request")]
    BadRequest,
}

// ── TURN auth mode ────────────────────────────────────────────────────────────

/// TURN authentication mode.
pub enum AuthMode {
    /// Long-term credentials with static users.
    LongTerm {
        realm: String,
        users: Vec<(String, String)>,
    },
    /// Time-limited credentials with shared secret.
    SharedSecret { realm: String, secret: Vec<u8> },
}

impl AuthMode {
    /// Validate a STUN message's credentials. Returns the key on success.
    pub fn validate(&self, msg: &StunMessage, raw: &[u8]) -> Result<Vec<u8>, AuthError> {
        let username = msg.get_username().ok_or(AuthError::MissingCredentials)?;
        let realm = msg.get_realm().ok_or(AuthError::MissingCredentials)?;
        // Strict: the REALM in the request must match the server's realm.
        // (The key is already derived from the server realm, so a mismatch
        // would fail integrity anyway — this rejects it explicitly and early.)
        if realm != self.realm() {
            return Err(AuthError::InvalidCredentials);
        }

        // Resolve the user's password (cleartext for LongTerm; REST-derived for
        // SharedSecret). The long-term *key* is derived from it below, with the
        // digest chosen by the integrity attribute the client actually used.
        let password: String = match self {
            AuthMode::LongTerm { users, .. } => {
                let (_, password) = users
                    .iter()
                    .find(|(u, _)| u == username)
                    .ok_or(AuthError::InvalidCredentials)?;
                password.clone()
            }
            AuthMode::SharedSecret { secret, .. } => {
                // TURN REST API (coturn-compatible): username is
                // "<unix_expiry>:<userid>". The credential is only valid until
                // the embedded timestamp; without this check a leaked
                // ephemeral credential never expires.
                let (ts_str, _userid) = username
                    .split_once(':')
                    .ok_or(AuthError::InvalidCredentials)?;
                let expiry: u64 = ts_str.parse().map_err(|_| AuthError::InvalidCredentials)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if expiry < now {
                    return Err(AuthError::Expired);
                }

                use hmac::{Hmac, Mac};
                use sha1::Sha1;
                let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
                mac.update(username.as_bytes());
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    mac.finalize().into_bytes(),
                )
            }
        };

        let server_realm = self.realm();
        let has_sha256 = msg.get_message_integrity_sha256().is_some();

        // RFC 8489: if the client declared a PASSWORD-ALGORITHM (0x001D), it must
        // be consistent with the integrity attribute actually present. We do NOT
        // require 0x001D to be present — legacy (RFC 5389) clients omit it.
        //
        // NOTE (Stage 3 follow-up): the precise error code for an *unknown*
        // algorithm should be 400 Bad Request per RFC 8489, but the current
        // `AuthError` model maps every auth failure to a 401 challenge. Until the
        // error model gains a Bad-Request path, any mismatch or unknown algorithm
        // is rejected here as `InvalidCredentials`. This is why we advertise +
        // accept MESSAGE-INTEGRITY-SHA256 but do not claim full RFC 8489
        // compliance yet.
        if let Some(algo) = msg.get_password_algorithm() {
            use turna_proto_stun::attribute::{PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256};
            let consistent = match algo {
                PASSWORD_ALGORITHM_SHA256 => has_sha256,
                PASSWORD_ALGORITHM_MD5 => !has_sha256,
                _ => false,
            };
            if !consistent {
                return Err(AuthError::BadRequest);
            }
        }

        // Prefer MESSAGE-INTEGRITY-SHA256 when present (RFC 8489); otherwise fall
        // back to the RFC 5389 MESSAGE-INTEGRITY (HMAC-SHA-1 + MD5 key). When no
        // SHA-256 attribute is present, behaviour is byte-for-byte unchanged.
        if has_sha256 {
            let key = turna_crypto::long_term_key_sha256(username, server_realm, &password);
            if !msg.verify_integrity_sha256(raw, &key) {
                return Err(AuthError::IntegrityFailed);
            }
            Ok(key)
        } else {
            let key = turna_crypto::long_term_key(username, server_realm, &password);
            if !msg.verify_integrity(raw, &key) {
                return Err(AuthError::IntegrityFailed);
            }
            Ok(key)
        }
    }

    pub fn realm(&self) -> &str {
        match self {
            AuthMode::LongTerm { realm, .. } => realm,
            AuthMode::SharedSecret { realm, .. } => realm,
        }
    }
}

// suppress unused import warnings for deps used only in inline blocks
use base64 as _;
use hmac as _;
use sha1 as _;

#[cfg(test)]
mod f10_tests {
    use super::*;
    use turna_proto_stun::attribute::{
        Attribute, ATTR_PASSWORD_ALGORITHM, PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256,
    };
    use turna_proto_stun::header::MessageClass;
    use turna_proto_stun::message::StunMessage;
    use turna_proto_stun::method::Method;

    /// Build an Allocate request with Username+Realm (and optionally a declared
    /// PASSWORD-ALGORITHM), signed with SHA-256 or SHA-1 using `pass`. Returns
    /// the decoded message and the raw bytes.
    fn signed(
        realm: &str,
        user: &str,
        pass: &str,
        sha256: bool,
        declared_algo: Option<u16>,
    ) -> (StunMessage, Vec<u8>) {
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::Username(user.into()));
        m.add(Attribute::Realm(realm.into()));
        if let Some(algo) = declared_algo {
            let mut v = algo.to_be_bytes().to_vec();
            v.extend_from_slice(&0u16.to_be_bytes());
            m.add(Attribute::Unknown {
                attr_type: ATTR_PASSWORD_ALGORITHM,
                value: v,
            });
        }
        let mut buf = [0u8; 512];
        let len = if sha256 {
            let key = turna_crypto::long_term_key_sha256(user, realm, pass);
            m.encode_with_integrity_sha256(&mut buf, &key).unwrap()
        } else {
            let key = turna_crypto::long_term_key(user, realm, pass);
            m.encode_with_integrity(&mut buf, &key).unwrap()
        };
        let raw = buf[..len].to_vec();
        let decoded = StunMessage::decode(&raw).unwrap();
        (decoded, raw)
    }

    fn long_term() -> AuthMode {
        AuthMode::LongTerm {
            realm: "r".into(),
            users: vec![("u".into(), "p".into())],
        }
    }

    #[test]
    fn accepts_sha256_signed_request_and_returns_32b_key() {
        let (msg, raw) = signed("r", "u", "p", true, None);
        let key = long_term().validate(&msg, &raw).expect("sha256 accepted");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn still_accepts_sha1_signed_request_and_returns_16b_key() {
        let (msg, raw) = signed("r", "u", "p", false, None);
        let key = long_term().validate(&msg, &raw).expect("sha1 accepted");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn rejects_wrong_password_under_sha256() {
        let (msg, raw) = signed("r", "u", "WRONG", true, None);
        assert!(matches!(
            long_term().validate(&msg, &raw),
            Err(AuthError::IntegrityFailed)
        ));
    }

    #[test]
    fn password_algorithm_consistency_is_enforced_when_present() {
        // Declared SHA-256 + MI-SHA256 → ok.
        let (msg, raw) = signed("r", "u", "p", true, Some(PASSWORD_ALGORITHM_SHA256));
        assert!(long_term().validate(&msg, &raw).is_ok());

        // Declared MD5 + plain MI (SHA-1) → ok.
        let (msg, raw) = signed("r", "u", "p", false, Some(PASSWORD_ALGORITHM_MD5));
        assert!(long_term().validate(&msg, &raw).is_ok());

        // Declared SHA-256 but only SHA-1 MI present → 400 Bad Request.
        let (msg, raw) = signed("r", "u", "p", false, Some(PASSWORD_ALGORITHM_SHA256));
        assert!(matches!(
            long_term().validate(&msg, &raw),
            Err(AuthError::BadRequest)
        ));

        // Unknown declared algorithm → 400 Bad Request (even with a valid SHA-256 tag).
        let (msg, raw) = signed("r", "u", "p", true, Some(0x00FF));
        assert!(matches!(
            long_term().validate(&msg, &raw),
            Err(AuthError::BadRequest)
        ));
    }
}
