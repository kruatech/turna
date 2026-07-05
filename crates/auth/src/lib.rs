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

use std::sync::Arc;

use dashmap::DashMap;
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

/// Pre-derived long-term keys for one LongTerm user (Variant B: the plaintext
/// password is never stored). Both digests are kept so the server can answer
/// whichever MESSAGE-INTEGRITY variant the client uses (RFC 5389 vs RFC 8489).
#[derive(Debug, Clone)]
pub struct UserKeys {
    /// RFC 5389 key: HMAC-SHA-1 key = MD5(username:realm:password).
    pub key_md5: Vec<u8>,
    /// RFC 8489 key: SHA-256 variant of the long-term key.
    pub key_sha256: Vec<u8>,
}

impl UserKeys {
    /// Derive both keys from a plaintext password. The password is consumed
    /// here and never retained.
    pub fn derive(username: &str, realm: &str, password: &str) -> Self {
        Self {
            key_md5: turna_crypto::long_term_key(username, realm, password),
            key_sha256: turna_crypto::long_term_key_sha256(username, realm, password),
        }
    }
}

/// TURN authentication mode.
pub enum AuthMode {
    /// Long-term credentials. Users are stored as pre-derived keys (Variant B:
    /// no plaintext password retained). Interior-mutable (`Arc<DashMap>`) so the
    /// management API can add/remove users at runtime without `&mut self`.
    LongTerm {
        realm: String,
        users: Arc<DashMap<String, UserKeys>>,
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

        let server_realm = self.realm();
        let has_sha256 = msg.get_message_integrity_sha256().is_some();

        // Resolve the verification key for the digest the client actually used.
        //
        // LongTerm (Variant B): both long-term keys are pre-derived at user
        // creation and stored; no plaintext password is kept. Select the one
        // matching the integrity attribute present.
        // SharedSecret (REST, coturn-compatible): derive the ephemeral key from
        // the time-limited credential at request time.
        let key: Vec<u8> = match self {
            AuthMode::LongTerm { users, .. } => {
                match users.get(username) {
                    Some(entry) => {
                        if has_sha256 {
                            entry.key_sha256.clone()
                        } else {
                            entry.key_md5.clone()
                        }
                    }
                    None => {
                        // M3: equalize response latency between known and unknown
                        // users so timing doesn't leak whether `username` exists
                        // (enumeration). Run one integrity verify against a fixed
                        // dummy key — the same dominant HMAC cost as the real
                        // path — then reject. The result is discarded; an unknown
                        // user is always InvalidCredentials. Not a constant-time
                        // guarantee, but it closes the obvious early-return gap.
                        const DUMMY_KEY: [u8; 32] = [0x2b; 32];
                        if has_sha256 {
                            let _ = msg.verify_integrity_sha256(raw, &DUMMY_KEY);
                        } else {
                            let _ = msg.verify_integrity(raw, &DUMMY_KEY);
                        }
                        return Err(AuthError::InvalidCredentials);
                    }
                }
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
                let password = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    mac.finalize().into_bytes(),
                );
                if has_sha256 {
                    turna_crypto::long_term_key_sha256(username, server_realm, &password)
                } else {
                    turna_crypto::long_term_key(username, server_realm, &password)
                }
            }
        };

        // RFC 8489: if the client declared a PASSWORD-ALGORITHM (0x001D), it must
        // be consistent with the integrity attribute actually present. We do NOT
        // require 0x001D to be present — legacy (RFC 5389) clients omit it.
        //
        // RFC 8489: an inconsistent or unknown PASSWORD-ALGORITHM is a 400 Bad
        // Request. `AuthError::BadRequest` carries that through — the processor
        // maps it to a 400 response (see `handle_allocate`/`handle_refresh`),
        // distinct from the 401 challenge used for other auth failures.
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

        // Verify MESSAGE-INTEGRITY with the resolved key: SHA-256 (RFC 8489)
        // when present, otherwise RFC 5389 HMAC-SHA-1 (+ MD5 key).
        if has_sha256 {
            if !msg.verify_integrity_sha256(raw, &key) {
                return Err(AuthError::IntegrityFailed);
            }
        } else if !msg.verify_integrity(raw, &key) {
            return Err(AuthError::IntegrityFailed);
        }
        Ok(key)
    }

    pub fn realm(&self) -> &str {
        match self {
            AuthMode::LongTerm { realm, .. } => realm,
            AuthMode::SharedSecret { realm, .. } => realm,
        }
    }

    /// Build a LongTerm backend from `(username, password)` pairs, pre-deriving
    /// both long-term keys so the plaintext password is never retained.
    pub fn long_term<I, U, P>(realm: impl Into<String>, users: I) -> Self
    where
        I: IntoIterator<Item = (U, P)>,
        U: AsRef<str>,
        P: AsRef<str>,
    {
        let realm = realm.into();
        let map: DashMap<String, UserKeys> = DashMap::new();
        for (u, p) in users {
            let (u, p) = (u.as_ref(), p.as_ref());
            map.insert(u.to_string(), UserKeys::derive(u, &realm, p));
        }
        AuthMode::LongTerm {
            realm,
            users: Arc::new(map),
        }
    }

    /// Add (or replace) a LongTerm user at runtime. No-op on SharedSecret.
    /// Returns `true` if applied (i.e. this is a LongTerm backend).
    pub fn add_user(&self, username: &str, password: &str) -> bool {
        match self {
            AuthMode::LongTerm { realm, users } => {
                users.insert(
                    username.to_string(),
                    UserKeys::derive(username, realm, password),
                );
                true
            }
            AuthMode::SharedSecret { .. } => false,
        }
    }

    /// Remove a LongTerm user at runtime. No-op on SharedSecret. Returns `true`
    /// if a user was present and removed.
    pub fn remove_user(&self, username: &str) -> bool {
        match self {
            AuthMode::LongTerm { users, .. } => users.remove(username).is_some(),
            AuthMode::SharedSecret { .. } => false,
        }
    }

    /// Whether a LongTerm user exists. Always `false` for SharedSecret.
    pub fn has_user(&self, username: &str) -> bool {
        match self {
            AuthMode::LongTerm { users, .. } => users.contains_key(username),
            AuthMode::SharedSecret { .. } => false,
        }
    }

    /// Insert a user from pre-derived keys (Variant B rehydration: no password
    /// is available — e.g. loading from the state backend at startup). No-op on
    /// SharedSecret. Returns `true` if applied.
    pub fn add_user_keys(&self, username: &str, keys: UserKeys) -> bool {
        match self {
            AuthMode::LongTerm { users, .. } => {
                users.insert(username.to_string(), keys);
                true
            }
            AuthMode::SharedSecret { .. } => false,
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
        AuthMode::long_term("r", [("u", "p")])
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
