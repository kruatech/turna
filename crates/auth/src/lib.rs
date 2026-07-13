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
    /// RFC 7635 third-party (OAuth 2.0) authorization. The client presents an
    /// ACCESS-TOKEN; the server shares the long-term AS-RS key with the
    /// authorization server and uses it to AEAD-decrypt the self-contained
    /// token, then verifies MESSAGE-INTEGRITY with the enclosed `mac_key`.
    /// `server_name` is the AEAD associated-data (RFC 7635 §6.2), binding a
    /// token to this server so it cannot be replayed at a sibling server that
    /// shares the same AS-RS key.
    OAuth {
        realm: String,
        /// AS-RS symmetric keys shared with the authorization server. Multiple
        /// keys support rotation: a token sealed with any of them validates
        /// (trial decryption). 16 B → AES-128-GCM, 32 B → AES-256-GCM.
        as_rs_keys: Vec<Vec<u8>>,
        /// RFC 7635 §6.1 kid-tagged keys: when the client's USERNAME matches a
        /// `kid`, that key is selected directly (no trial-decrypt). On no match
        /// the server trial-decrypts across these + `as_rs_keys`.
        kid_keys: Vec<(String, Vec<u8>)>,
        /// RFC 7635 §6.1 strict selection: unknown/absent kid is rejected rather
        /// than trial-decrypted. See [`OAuthConfig::strict_kid`] in turna-config.
        strict_kid: bool,
        server_name: String,
        /// Authorization-server identity advertised in the 401 THIRD-PARTY-
        /// AUTHORIZATION challenge (RFC 7635 §6.1). Defaults to `server_name`.
        as_identity: String,
    },
}

impl AuthMode {
    /// Validate a STUN message's credentials. Returns the key on success.
    pub fn validate(&self, msg: &StunMessage, raw: &[u8]) -> Result<Vec<u8>, AuthError> {
        // RFC 7635 third-party auth uses an ACCESS-TOKEN, not USERNAME/REALM —
        // handle it before the long-term credential extraction below.
        if let AuthMode::OAuth { .. } = self {
            return self
                .validate_oauth(msg, raw)
                .map(|(mac_key, _lifetime)| mac_key);
        }
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
            AuthMode::OAuth { .. } => unreachable!("OAuth handled by early dispatch above"),
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

    /// Like [`validate`] but also returns the OAuth token's remaining lifetime in
    /// seconds, so the caller can cap the allocation lifetime to it (RFC 7635
    /// §6.1). `None` for non-OAuth modes (there is no token lifetime to bind).
    pub fn validate_with_lifetime(
        &self,
        msg: &StunMessage,
        raw: &[u8],
    ) -> Result<(Vec<u8>, Option<u32>), AuthError> {
        match self {
            AuthMode::OAuth { .. } => self
                .validate_oauth(msg, raw)
                .map(|(k, life)| (k, Some(life))),
            _ => self.validate(msg, raw).map(|k| (k, None)),
        }
    }

    pub fn realm(&self) -> &str {
        match self {
            AuthMode::LongTerm { realm, .. } => realm,
            AuthMode::SharedSecret { realm, .. } => realm,
            AuthMode::OAuth { realm, .. } => realm,
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
            AuthMode::SharedSecret { .. } | AuthMode::OAuth { .. } => false,
        }
    }

    /// Remove a LongTerm user at runtime. No-op on SharedSecret. Returns `true`
    /// if a user was present and removed.
    pub fn remove_user(&self, username: &str) -> bool {
        match self {
            AuthMode::LongTerm { users, .. } => users.remove(username).is_some(),
            AuthMode::SharedSecret { .. } | AuthMode::OAuth { .. } => false,
        }
    }

    /// Whether a LongTerm user exists. Always `false` for SharedSecret.
    pub fn has_user(&self, username: &str) -> bool {
        match self {
            AuthMode::LongTerm { users, .. } => users.contains_key(username),
            AuthMode::SharedSecret { .. } | AuthMode::OAuth { .. } => false,
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
            AuthMode::SharedSecret { .. } | AuthMode::OAuth { .. } => false,
        }
    }
}

impl AuthMode {
    /// Build an RFC 7635 OAuth (third-party) auth backend. `as_rs_keys` is the
    /// keyring shared with the authorization server (each 16 B → AES-128-GCM,
    /// 32 B → AES-256-GCM; multiple entries allow key rotation); `server_name` is
    /// the AEAD associated data that binds tokens to this server.
    pub fn oauth(
        realm: impl Into<String>,
        as_rs_keys: Vec<Vec<u8>>,
        server_name: impl Into<String>,
    ) -> Self {
        let server_name = server_name.into();
        AuthMode::OAuth {
            realm: realm.into(),
            as_rs_keys,
            kid_keys: Vec::new(),
            strict_kid: false,
            as_identity: server_name.clone(),
            server_name,
        }
    }

    /// Like [`AuthMode::oauth`] but with an explicit authorization-server identity
    /// for the 401 THIRD-PARTY-AUTHORIZATION challenge (RFC 7635 §6.1). An empty
    /// `as_identity` falls back to `server_name`.
    pub fn oauth_with_identity(
        realm: impl Into<String>,
        as_rs_keys: Vec<Vec<u8>>,
        server_name: impl Into<String>,
        as_identity: impl Into<String>,
    ) -> Self {
        let server_name = server_name.into();
        let as_identity = as_identity.into();
        let as_identity = if as_identity.is_empty() {
            server_name.clone()
        } else {
            as_identity
        };
        AuthMode::OAuth {
            realm: realm.into(),
            as_rs_keys,
            kid_keys: Vec::new(),
            strict_kid: false,
            as_identity,
            server_name,
        }
    }

    /// Like [`AuthMode::oauth_with_identity`] but also accepts RFC 7635 kid-tagged
    /// keys for USERNAME-based key selection (falls back to trial-decrypt on no
    /// match). See [`OAuthConfig::keys`] in turna-config.
    pub fn oauth_full(
        realm: impl Into<String>,
        as_rs_keys: Vec<Vec<u8>>,
        kid_keys: Vec<(String, Vec<u8>)>,
        strict_kid: bool,
        server_name: impl Into<String>,
        as_identity: impl Into<String>,
    ) -> Self {
        let server_name = server_name.into();
        let as_identity = as_identity.into();
        let as_identity = if as_identity.is_empty() {
            server_name.clone()
        } else {
            as_identity
        };
        AuthMode::OAuth {
            realm: realm.into(),
            as_rs_keys,
            kid_keys,
            strict_kid,
            as_identity,
            server_name,
        }
    }

    /// The authorization-server identity to advertise in a 401 THIRD-PARTY-
    /// AUTHORIZATION challenge, or `None` when this mode is not OAuth.
    pub fn oauth_identity(&self) -> Option<&str> {
        match self {
            AuthMode::OAuth { as_identity, .. } => Some(as_identity),
            _ => None,
        }
    }

    /// RFC 7635 third-party validation: AEAD-decrypt the ACCESS-TOKEN with the
    /// AS-RS key, check the token's timestamp/lifetime, then verify
    /// MESSAGE-INTEGRITY with the enclosed `mac_key`. Returns `mac_key` on
    /// success (the processor signs the response with it, per RFC 7635 §9).
    fn validate_oauth(&self, msg: &StunMessage, raw: &[u8]) -> Result<(Vec<u8>, u32), AuthError> {
        let (as_rs_keys, kid_keys, strict_kid, server_name) = match self {
            AuthMode::OAuth {
                as_rs_keys,
                kid_keys,
                strict_kid,
                server_name,
                ..
            } => (as_rs_keys, kid_keys, *strict_kid, server_name),
            _ => unreachable!("validate_oauth called on non-OAuth mode"),
        };
        let token = msg
            .get_access_token()
            .ok_or(AuthError::MissingCredentials)?;
        // RFC 7635 §6.1 key selection. If the USERNAME names a configured kid, use
        // that key alone. Otherwise: in strict mode an unknown/absent kid is
        // rejected; in the default (rotation-friendly) mode we trial-decrypt
        // across the kid keyring + `as_rs_keys`.
        let trial_all = || -> Vec<Vec<u8>> {
            kid_keys
                .iter()
                .map(|(_, k)| k.clone())
                .chain(as_rs_keys.iter().cloned())
                .collect()
        };
        let candidate_keys: Vec<Vec<u8>> = match msg.get_username() {
            Some(kid) => match kid_keys.iter().find(|(k, _)| k.as_str() == kid) {
                Some((_, key)) => vec![key.clone()],
                None if strict_kid => return Err(AuthError::InvalidCredentials),
                None => trial_all(),
            },
            None if strict_kid => return Err(AuthError::MissingCredentials),
            None => trial_all(),
        };
        let (mac_key, remaining) = decrypt_access_token(token, &candidate_keys, server_name)?;
        if mac_key.is_empty() {
            return Err(AuthError::InvalidCredentials);
        }
        // MESSAGE-INTEGRITY keyed by mac_key: SHA-256 when the client used it,
        // else RFC 5389 HMAC-SHA-1 (RFC 7635 mandates 160-bit mac_key support).
        if msg.get_message_integrity_sha256().is_some() {
            if !msg.verify_integrity_sha256(raw, &mac_key) {
                return Err(AuthError::IntegrityFailed);
            }
        } else if !msg.verify_integrity(raw, &mac_key) {
            return Err(AuthError::IntegrityFailed);
        }
        Ok((mac_key, remaining))
    }
}

/// RFC 7635 §6.1 allowable clock skew (Delta) for the token freshness window.
const OAUTH_CLOCK_SKEW_SECS: u64 = 5;

/// RFC 7635 token freshness check, kept free of the system clock so the logic is
/// unit-testable with an injected `now_secs`.
///
/// * `ts_fixed_point` is the raw 64-bit ACCESS-TOKEN timestamp. Per RFC 7635
///   §6.2 it is fixed-point: the top 48 bits are whole seconds since the Unix
///   epoch and the low 16 bits are 1/64000-second fractions. Second granularity
///   is enough for an expiry/freshness check, so we take `>> 16` (reading the
///   whole 64 bits as seconds — the previous behaviour — inflated the value by
///   ~2^16 and made every RFC-issued token look permanently valid).
/// * Accept iff `lifetime + Delta > |now - TS|` (RFC 7635 §6.1). The symmetric
///   absolute difference rejects both stale tokens and tokens dated too far into
///   the future, within the `skew` (Delta) allowance.
fn token_time_valid(ts_fixed_point: u64, lifetime: u32, now_secs: u64, skew_secs: u64) -> bool {
    let ts_secs = ts_fixed_point >> 16;
    ts_secs.abs_diff(now_secs) < (lifetime as u64).saturating_add(skew_secs)
}

/// Decrypt an RFC 7635 §6.2 self-contained ACCESS-TOKEN and return the enclosed
/// `mac_key`. Layout: `u16 nonce_len | nonce | AEAD{ u16 key_len | mac_key |
/// u64 timestamp | u32 lifetime }`, where `timestamp` is a 64-bit fixed-point
/// value (top 48 bits seconds, low 16 bits 1/64000 fractions). AEAD is AES-GCM
/// keyed by the AS-RS key with the server name as associated data.
fn decrypt_access_token(
    token: &[u8],
    as_rs_keys: &[Vec<u8>],
    server_name: &str,
) -> Result<(Vec<u8>, u32), AuthError> {
    if token.len() < 2 {
        return Err(AuthError::InvalidCredentials);
    }
    let nonce_len = u16::from_be_bytes([token[0], token[1]]) as usize;
    let rest = &token[2..];
    if rest.len() < nonce_len {
        return Err(AuthError::InvalidCredentials);
    }
    let (nonce, ciphertext) = rest.split_at(nonce_len);

    // Trial-decrypt across the keyring (AS-RS key rotation): the first key whose
    // AEAD tag authenticates wins. No key id is carried in the token, so each
    // configured key is tried; all failing → invalid.
    let plaintext = as_rs_keys
        .iter()
        .find_map(|key| aead_decrypt(key, nonce, server_name.as_bytes(), ciphertext).ok())
        .ok_or(AuthError::InvalidCredentials)?;

    if plaintext.len() < 2 {
        return Err(AuthError::InvalidCredentials);
    }
    let key_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    let need = 2 + key_len + 8 + 4;
    if plaintext.len() < need {
        return Err(AuthError::InvalidCredentials);
    }
    let mac_key = plaintext[2..2 + key_len].to_vec();
    let ts = u64::from_be_bytes(plaintext[2 + key_len..2 + key_len + 8].try_into().unwrap());
    let lifetime = u32::from_be_bytes(
        plaintext[2 + key_len + 8..2 + key_len + 12]
            .try_into()
            .unwrap(),
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // RFC 7635 §6.1: reject unless within the (symmetric, skew-tolerant) window.
    if !token_time_valid(ts, lifetime, now, OAUTH_CLOCK_SKEW_SECS) {
        return Err(AuthError::Expired);
    }
    // Remaining validity (seconds) = token end − now, clamped to u32. The caller
    // caps the allocation lifetime by this so it never outlives the token.
    let ts_secs = ts >> 16;
    let remaining = ts_secs
        .saturating_add(lifetime as u64)
        .saturating_sub(now)
        .min(u32::MAX as u64) as u32;
    Ok((mac_key, remaining))
}

/// AES-GCM AEAD decrypt (RFC 5116). Key length selects AES-128 (16 B) or
/// AES-256 (32 B); the GCM nonce is 96 bits (12 bytes).
fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AuthError> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
    if nonce.len() != 12 {
        return Err(AuthError::InvalidCredentials);
    }
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| AuthError::InvalidCredentials)?
            .decrypt(nonce, payload)
            .map_err(|_| AuthError::IntegrityFailed),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| AuthError::InvalidCredentials)?
            .decrypt(nonce, payload)
            .map_err(|_| AuthError::IntegrityFailed),
        _ => Err(AuthError::InvalidCredentials),
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

#[cfg(test)]
mod oauth_tests {
    use super::*;
    use turna_proto_stun::attribute::Attribute;
    use turna_proto_stun::header::MessageClass;
    use turna_proto_stun::message::StunMessage;
    use turna_proto_stun::method::Method;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Build an RFC 7635 ACCESS-TOKEN: `nonce_len | nonce | AES-128-GCM{ key_len
    /// | mac_key | ts | lifetime }` with `server_name` as AAD.
    fn make_token(
        as_rs_key: &[u8],
        server_name: &str,
        mac_key: &[u8],
        ts: u64,
        lifetime: u32,
    ) -> Vec<u8> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Nonce};
        let mut block = Vec::new();
        block.extend_from_slice(&(mac_key.len() as u16).to_be_bytes());
        block.extend_from_slice(mac_key);
        // RFC 7635 §6.2 fixed-point: whole seconds in the top 48 bits.
        block.extend_from_slice(&(ts << 16).to_be_bytes());
        block.extend_from_slice(&lifetime.to_be_bytes());
        let nonce_bytes = [0x11u8; 12];
        let ct = Aes128Gcm::new_from_slice(as_rs_key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &block,
                    aad: server_name.as_bytes(),
                },
            )
            .unwrap();
        let mut token = Vec::new();
        token.extend_from_slice(&(nonce_bytes.len() as u16).to_be_bytes());
        token.extend_from_slice(&nonce_bytes);
        token.extend_from_slice(&ct);
        token
    }

    fn signed_with_token(token: &[u8], mi_key: &[u8]) -> (StunMessage, Vec<u8>) {
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::AccessToken(token.to_vec()));
        let mut buf = [0u8; 512];
        let len = m.encode_with_integrity(&mut buf, mi_key).unwrap();
        let raw = buf[..len].to_vec();
        (StunMessage::decode(&raw).unwrap(), raw)
    }

    #[test]
    fn accepts_valid_oauth_token_and_returns_mac_key() {
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20]; // 160-bit, per RFC 7635
        let token = make_token(&as_rs_key, "turn.example.com", &mac_key, now(), 3600);
        let (msg, raw) = signed_with_token(&token, &mac_key);
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "turn.example.com");
        let got = mode.validate(&msg, &raw).expect("valid token accepted");
        assert_eq!(got, mac_key.to_vec());
    }

    #[test]
    fn keyring_accepts_token_sealed_with_any_configured_key() {
        let key_a = [0x11u8; 16];
        let key_b = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        // Token sealed with the "new" key B; the server still lists both keys.
        let token = make_token(&key_b, "turn.example.com", &mac_key, now(), 3600);
        let (msg, raw) = signed_with_token(&token, &mac_key);
        let mode = AuthMode::oauth(
            "example.com",
            vec![key_a.to_vec(), key_b.to_vec()],
            "turn.example.com",
        );
        let got = mode
            .validate(&msg, &raw)
            .expect("token under any keyring key accepted");
        assert_eq!(got, mac_key.to_vec());
        // A key not in the ring is rejected.
        let other = AuthMode::oauth("example.com", vec![key_a.to_vec()], "turn.example.com");
        assert!(
            other.validate(&msg, &raw).is_err(),
            "token not sealed with any listed key must fail"
        );
    }

    #[test]
    fn kid_username_selects_matching_key() {
        // RFC 7635 §6.1: the USERNAME carries the kid; the server must select that
        // key directly rather than trial-decrypting.
        let key_a = [0x11u8; 16];
        let key_b = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        // Token sealed with key B, which is registered under kid "kb".
        let token = make_token(&key_b, "turn.example.com", &mac_key, now(), 3600);
        let mode = AuthMode::oauth_full(
            "example.com",
            vec![],
            vec![
                ("ka".to_string(), key_a.to_vec()),
                ("kb".to_string(), key_b.to_vec()),
            ],
            false,
            "turn.example.com",
            "",
        );

        // USERNAME = "kb" → selects key B → decrypts.
        let with_kid = |kid: &str| {
            let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
            m.add(Attribute::Username(kid.to_string()));
            m.add(Attribute::AccessToken(token.clone()));
            let mut buf = [0u8; 512];
            let len = m.encode_with_integrity(&mut buf, &mac_key).unwrap();
            let raw = buf[..len].to_vec();
            (StunMessage::decode(&raw).unwrap(), raw)
        };

        let (msg, raw) = with_kid("kb");
        assert_eq!(
            mode.validate(&msg, &raw).expect("kid 'kb' selects key B"),
            mac_key.to_vec()
        );

        // USERNAME = "ka" selects key A, which cannot decrypt a token sealed with
        // key B → rejected (no silent fallback to trial-decrypt).
        let (msg2, raw2) = with_kid("ka");
        assert!(
            mode.validate(&msg2, &raw2).is_err(),
            "a mismatched kid selects the wrong key and must be rejected"
        );
    }

    #[test]
    fn strict_kid_rejects_unknown_and_missing_username() {
        // RFC 7635 §6.1 strict profile: an unknown or absent kid must NOT fall
        // back to trial-decrypt (which could accept a token under another key).
        let key_b = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        let token = make_token(&key_b, "turn.example.com", &mac_key, now(), 3600);
        let mode = AuthMode::oauth_full(
            "example.com",
            vec![],
            vec![("kb".to_string(), key_b.to_vec())],
            true, // strict
            "turn.example.com",
            "",
        );
        let build = |u: Option<&str>| {
            let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
            if let Some(u) = u {
                m.add(Attribute::Username(u.to_string()));
            }
            m.add(Attribute::AccessToken(token.clone()));
            let mut buf = [0u8; 512];
            let len = m.encode_with_integrity(&mut buf, &mac_key).unwrap();
            let raw = buf[..len].to_vec();
            (StunMessage::decode(&raw).unwrap(), raw)
        };
        // Known kid still authenticates.
        let (m1, r1) = build(Some("kb"));
        assert!(
            mode.validate(&m1, &r1).is_ok(),
            "known kid must pass in strict mode"
        );
        // Unknown kid → rejected (would have trial-decrypted with key_b otherwise).
        let (m2, r2) = build(Some("nope"));
        assert!(
            mode.validate(&m2, &r2).is_err(),
            "unknown kid must be rejected in strict mode"
        );
        // Absent USERNAME → rejected in strict mode.
        let (m3, r3) = build(None);
        assert!(
            mode.validate(&m3, &r3).is_err(),
            "missing kid must be rejected in strict mode"
        );
    }

    #[test]
    fn validate_with_lifetime_reports_token_remaining() {
        // Stage 3: OAuth validation surfaces the token's remaining lifetime so
        // the allocation can be capped to it (RFC 7635 §6.1).
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        let token = make_token(&as_rs_key, "turn.example.com", &mac_key, now(), 3600);
        let (msg, raw) = signed_with_token(&token, &mac_key);
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "turn.example.com");
        let (key, life) = mode
            .validate_with_lifetime(&msg, &raw)
            .expect("valid token");
        assert_eq!(key, mac_key.to_vec());
        let life = life.expect("OAuth must report a token lifetime");
        // Minted now with 3600s lifetime → remaining ≈ 3600 (allow small skew).
        assert!(life > 3500 && life <= 3600, "remaining lifetime = {life}");
    }

    #[test]
    fn token_expired_within_skew_grace_reports_zero_remaining() {
        // RFC 7635 §6.1 boundary: a token that expired up to the clock-skew grace
        // (OAUTH_CLOCK_SKEW_SECS) ago still authenticates, but its remaining
        // lifetime is 0. The processor turns a Some(0) into a 401 rather than
        // granting a 0-second (already-dead) allocation.
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        // Issued 12s ago with a 10s lifetime → expired 2s ago, still inside the
        // 5s skew window (|12| < 10 + 5), so it authenticates with 0 remaining.
        let token = make_token(&as_rs_key, "turn.example.com", &mac_key, now() - 12, 10);
        let (msg, raw) = signed_with_token(&token, &mac_key);
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "turn.example.com");
        let (_key, life) = mode
            .validate_with_lifetime(&msg, &raw)
            .expect("an in-grace expired token must still authenticate");
        assert_eq!(
            life,
            Some(0),
            "expired-but-in-grace token must report zero remaining lifetime"
        );
    }

    #[test]
    fn rejects_wrong_server_name_aad() {
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        let token = make_token(&as_rs_key, "turn.example.com", &mac_key, now(), 3600);
        let (msg, raw) = signed_with_token(&token, &mac_key);
        // AEAD AAD (server name) mismatch → decrypt fails.
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "other.example.com");
        assert!(mode.validate(&msg, &raw).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        let token = make_token(
            &as_rs_key,
            "turn.example.com",
            &mac_key,
            now() - 10_000,
            3600,
        );
        let (msg, raw) = signed_with_token(&token, &mac_key);
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "turn.example.com");
        assert!(matches!(mode.validate(&msg, &raw), Err(AuthError::Expired)));
    }

    #[test]
    fn rejects_tampered_integrity() {
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        let token = make_token(&as_rs_key, "turn.example.com", &mac_key, now(), 3600);
        // Sign the request with a key different from the token's mac_key → MI fails.
        let (msg, raw) = signed_with_token(&token, &[0x00u8; 20]);
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "turn.example.com");
        assert!(matches!(
            mode.validate(&msg, &raw),
            Err(AuthError::IntegrityFailed)
        ));
    }

    #[test]
    fn token_time_window_uses_fixed_point_and_is_symmetric() {
        // Real RFC 7635 fixed-point timestamp: seconds in the top 48 bits and a
        // non-zero 1/64000 fraction in the low 16 bits (which must be ignored).
        let secs = 1_700_000_000u64;
        let ts = (secs << 16) | 12_345;
        assert_eq!(ts >> 16, secs, "fraction bits must not shift the second");

        // Inside the validity window.
        assert!(token_time_valid(ts, 3600, secs, 0));
        assert!(token_time_valid(ts, 3600, secs + 3599, 0));
        // Exactly at expiry and one second later (no skew) are rejected.
        assert!(!token_time_valid(ts, 3600, secs + 3600, 0));
        assert!(!token_time_valid(ts, 3600, secs + 3601, 0));
        // The clock-skew allowance (Delta) tolerates a small overshoot.
        assert!(token_time_valid(ts, 3600, secs + 3603, 5));
        // Dated too far into the future is rejected — this is exactly the case the
        // old plain-u64-seconds parse mis-accepted as "never expired".
        let future = (secs + 100_000) << 16;
        assert!(!token_time_valid(future, 3600, secs, 5));
        // A reception time far in the past relative to TS is also rejected.
        assert!(!token_time_valid(ts, 3600, secs.saturating_sub(100_000), 5));
    }

    #[test]
    fn rejects_future_dated_token() {
        let as_rs_key = [0x42u8; 16];
        let mac_key = [0x37u8; 20];
        // With a correct fixed-point parse and the symmetric window a token dated
        // far in the future must be rejected, not treated as valid forever.
        let token = make_token(
            &as_rs_key,
            "turn.example.com",
            &mac_key,
            now() + 100_000,
            3600,
        );
        let (msg, raw) = signed_with_token(&token, &mac_key);
        let mode = AuthMode::oauth("example.com", vec![as_rs_key.to_vec()], "turn.example.com");
        assert!(matches!(mode.validate(&msg, &raw), Err(AuthError::Expired)));
    }
}
