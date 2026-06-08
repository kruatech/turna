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
pub mod user;

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

        let key = match self {
            AuthMode::LongTerm { realm, users } => {
                let (_, password) = users
                    .iter()
                    .find(|(u, _)| u == username)
                    .ok_or(AuthError::InvalidCredentials)?;
                turna_crypto::long_term_key(username, realm, password)
            }
            AuthMode::SharedSecret { realm, secret } => {
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

                let password_from_username = {
                    use hmac::{Hmac, Mac};
                    use sha1::Sha1;
                    let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
                    mac.update(username.as_bytes());
                    let result = mac.finalize();
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        result.into_bytes(),
                    )
                };
                turna_crypto::long_term_key(username, realm, &password_from_username)
            }
        };

        if !msg.verify_integrity(raw, &key) {
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
}

// suppress unused import warnings for deps used only in inline blocks
use base64 as _;
use hmac as _;
use sha1 as _;
