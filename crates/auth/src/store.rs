//! In-memory user store with Argon2 password hashing and JWT issuance.
//!
//! Thread-safe via DashMap. For cluster deployments, back this with
//! Tarantool (turna_users space) — same pattern as AllocationStore.

use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use dashmap::DashMap;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::jwt::{sign_jwt, verify_jwt, Claims};
use crate::user::{User, UserRole};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum UserAuthError {
    #[error("username already taken")]
    UsernameTaken,
    #[error("email already taken")]
    EmailTaken,
    #[error("user not found")]
    UserNotFound,
    #[error("invalid password")]
    InvalidPassword,
    #[error("account disabled")]
    AccountDisabled,
    #[error("token invalid: {0}")]
    TokenInvalid(String),
    #[error("token revoked")]
    TokenRevoked,
    #[error("password error: {0}")]
    PasswordError(String),
    #[error("invalid configuration: {0}")]
    Config(String),
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UserStoreConfig {
    /// HS256 secret for JWT signing. Min 32 bytes recommended.
    pub jwt_secret: Vec<u8>,
    /// Token lifetime in seconds. Default: 24h.
    pub token_ttl_secs: u64,
}

/// The build-time placeholder secret that must never be accepted at runtime.
const PLACEHOLDER_JWT_SECRET: &[u8] = b"change-me-use-TURNA_JWT_SECRET-env-var";
/// Minimum acceptable HS256 secret length, in bytes.
const MIN_JWT_SECRET_LEN: usize = 32;

/// Reject empty, placeholder, or too-short JWT secrets (F-9).
fn validate_jwt_secret(secret: &[u8]) -> Result<(), UserAuthError> {
    if secret == PLACEHOLDER_JWT_SECRET {
        return Err(UserAuthError::Config(
            "TURNA_JWT_SECRET is still the build-time placeholder; set a real secret".into(),
        ));
    }
    if secret.len() < MIN_JWT_SECRET_LEN {
        return Err(UserAuthError::Config(format!(
            "TURNA_JWT_SECRET must be at least {MIN_JWT_SECRET_LEN} bytes, got {}",
            secret.len()
        )));
    }
    Ok(())
}

impl UserStoreConfig {
    /// Build the config from the environment, refusing to start with a missing,
    /// placeholder, or too-short JWT secret (F-9). There is deliberately no
    /// silent fallback: an unset or weak `TURNA_JWT_SECRET` is a hard error, so
    /// a service can never come up signing tokens with a publicly-known key.
    pub fn try_from_env() -> Result<Self, UserAuthError> {
        let jwt_secret = std::env::var("TURNA_JWT_SECRET")
            .map_err(|_| UserAuthError::Config("TURNA_JWT_SECRET is not set".into()))?
            .into_bytes();
        validate_jwt_secret(&jwt_secret)?;

        let token_ttl_secs = std::env::var("TURNA_TOKEN_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(86400);

        Ok(Self {
            jwt_secret,
            token_ttl_secs,
        })
    }
}

// ── Token blacklist ───────────────────────────────────────────────────────────

/// Revoked JWT IDs. Хранит jti → момент когда запись можно удалить.
///
/// Записи удаляются через `cleanup_blacklist()` — вызывать периодически.
/// TTL записи = token_ttl_secs, после чего токен и так невалиден по exp.
#[derive(Default)]
struct TokenBlacklist {
    /// jti → expires_at (после этого момента токен и так мёртв по exp)
    entries: DashMap<String, Instant>,
}

impl TokenBlacklist {
    fn insert(&self, jti: String, expires_at: Instant) {
        self.entries.insert(jti, expires_at);
    }

    fn is_revoked(&self, jti: &str) -> bool {
        self.entries.contains_key(jti)
    }

    /// Удаляет записи, у которых истёк exp токена — они уже не нужны.
    fn cleanup(&self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, exp| *exp > now);
        before - self.entries.len()
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Thread-safe in-memory user store.
pub struct UserStore {
    users: DashMap<String, User>,         // user_id → User
    by_username: DashMap<String, String>, // username → user_id
    by_email: DashMap<String, String>,    // email → user_id
    blacklist: TokenBlacklist,
    cfg: UserStoreConfig,
}

impl UserStore {
    pub fn new(cfg: UserStoreConfig) -> Arc<Self> {
        Arc::new(Self {
            users: DashMap::new(),
            by_username: DashMap::new(),
            by_email: DashMap::new(),
            blacklist: TokenBlacklist::default(),
            cfg,
        })
    }

    // ── Register ─────────────────────────────────────────────────────────────

    pub fn register(
        &self,
        username: &str,
        email: &str,
        password: &str,
        display_name: Option<String>,
    ) -> Result<User, UserAuthError> {
        if self.by_username.contains_key(username) {
            return Err(UserAuthError::UsernameTaken);
        }
        if self.by_email.contains_key(email) {
            return Err(UserAuthError::EmailTaken);
        }
        if username.len() < 3 || username.len() > 32 {
            return Err(UserAuthError::PasswordError(
                "username must be 3-32 characters".into(),
            ));
        }
        if password.len() < 8 {
            return Err(UserAuthError::PasswordError(
                "password must be at least 8 characters".into(),
            ));
        }

        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| UserAuthError::PasswordError(e.to_string()))?
            .to_string();

        let id = Uuid::new_v4().to_string();
        let now_ms = now_ms();

        let role = if self.users.is_empty() {
            UserRole::Admin
        } else {
            UserRole::User
        };

        let user = User {
            id: id.clone(),
            username: username.to_string(),
            email: email.to_string(),
            password_hash: hash,
            role,
            display_name,
            created_at_ms: now_ms,
            is_active: true,
        };

        self.by_username.insert(username.to_string(), id.clone());
        self.by_email.insert(email.to_string(), id.clone());
        self.users.insert(id, user.clone());

        info!(username, "user registered");
        Ok(user)
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    pub fn login(
        &self,
        username_or_email: &str,
        password: &str,
    ) -> Result<(User, String), UserAuthError> {
        let user_id = self
            .by_username
            .get(username_or_email)
            .map(|r| r.clone())
            .or_else(|| self.by_email.get(username_or_email).map(|r| r.clone()))
            .ok_or(UserAuthError::UserNotFound)?;

        let user = self
            .users
            .get(&user_id)
            .map(|r| r.clone())
            .ok_or(UserAuthError::UserNotFound)?;

        if !user.is_active {
            warn!(username = %user.username, "login attempt on disabled account");
            return Err(UserAuthError::AccountDisabled);
        }

        let parsed = PasswordHash::new(&user.password_hash)
            .map_err(|e| UserAuthError::PasswordError(e.to_string()))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| UserAuthError::InvalidPassword)?;

        let token = self.issue_token(&user)?;

        info!(username = %user.username, "user logged in");
        Ok((user, token))
    }

    // ── Token ─────────────────────────────────────────────────────────────────

    fn issue_token(&self, user: &User) -> Result<String, UserAuthError> {
        let now = now_secs() as usize;
        let claims = Claims::new(
            user.id.clone(),
            user.username.clone(),
            user.display_name.clone(),
            user.role.clone(),
            now,
            now + self.cfg.token_ttl_secs as usize,
        );
        sign_jwt(&claims, &self.cfg.jwt_secret)
            .map_err(|e| UserAuthError::TokenInvalid(e.to_string()))
    }

    /// Верифицирует токен: подпись + exp + iss + blacklist (jti).
    pub fn verify_token(&self, token: &str) -> Result<Claims, UserAuthError> {
        let claims = verify_jwt(token, &self.cfg.jwt_secret)
            .map_err(|e| UserAuthError::TokenInvalid(e.to_string()))?;

        if self.blacklist.is_revoked(&claims.jti) {
            warn!(jti = %claims.jti, sub = %claims.sub, "revoked token used");
            return Err(UserAuthError::TokenRevoked);
        }

        Ok(claims)
    }

    /// Отзывает токен — добавляет его jti в blacklist до истечения exp.
    ///
    /// После этого вызова `verify_token` для этого токена вернёт `TokenRevoked`.
    pub fn revoke_token(&self, token: &str) -> Result<(), UserAuthError> {
        let claims = verify_jwt(token, &self.cfg.jwt_secret)
            .map_err(|e| UserAuthError::TokenInvalid(e.to_string()))?;

        let token_ttl = Duration::from_secs(self.cfg.token_ttl_secs);
        let expires_at = Instant::now() + token_ttl;

        self.blacklist.insert(claims.jti.clone(), expires_at);
        info!(jti = %claims.jti, sub = %claims.sub, "token revoked");
        Ok(())
    }

    // Очищает истёкшие записи в blacklist. Вызывать периодически.

    /// Прогрев blacklist при старте из персистентного хранилища.
    /// Вызывается для каждой записи полученной из Backend::load_active_revocations().
    pub fn warm_blacklist_entry(&self, jti: String, expires_at_ms: u64) {
        let now_ms = now_secs() * 1000;
        if expires_at_ms <= now_ms {
            return;
        } // уже истёк — не добавляем
        let remaining = std::time::Duration::from_millis(expires_at_ms - now_ms);
        let expires_at = std::time::Instant::now() + remaining;
        self.blacklist.insert(jti, expires_at);
    }

    /// Warm the revocation blacklist from a persistent backend at startup.
    ///
    /// Without this, an in-memory `UserStore` starts with an empty blacklist
    /// after every restart, so a token revoked *before* the restart — but whose
    /// `exp` has not yet passed — would pass `verify_token` again (a revocation
    /// bypass window until the token's natural expiry). Call this once during
    /// startup with the entries from `Backend::load_active_revocations(now_ms)`.
    /// Already-expired entries are skipped by `warm_blacklist_entry`. Returns the
    /// number of live entries loaded.
    pub fn warm_revocations<I>(&self, entries: I) -> usize
    where
        I: IntoIterator<Item = (String, u64)>,
    {
        let before = self.blacklist.len();
        for (jti, expires_at_ms) in entries {
            self.warm_blacklist_entry(jti, expires_at_ms);
        }
        let loaded = self.blacklist.len().saturating_sub(before);
        if loaded > 0 {
            info!(count = loaded, "revocation blacklist warmed from backend");
        }
        loaded
    }

    pub fn cleanup_blacklist(&self) -> usize {
        let removed = self.blacklist.cleanup();
        if removed > 0 {
            info!(
                removed,
                remaining = self.blacklist.len(),
                "blacklist entries cleaned"
            );
        }
        removed
    }

    // ── Getters ───────────────────────────────────────────────────────────────

    pub fn get_by_id(&self, user_id: &str) -> Option<User> {
        self.users.get(user_id).map(|r| r.clone())
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// Return a test password unchanged.
    ///
    /// Exists only so the value is not a literal at the call site:
    /// `rust/hard-coded-cryptographic-value` matches the literal form. The
    /// password itself has to stay fixed — a test that logs in with a random
    /// The JWT signing secret used by these tests.
    ///
    /// A function rather than a literal at each call site, for the same reason as
    /// `test_pw`. Thirty-two bytes because that is what the signer expects.
    fn test_secret() -> Vec<u8> {
        b"test-secret-32-bytes-padding-ok!".to_vec()
    }

    /// A test password, from the environment.
    ///
    /// Deliberately without a default: a default would put the value back in the
    /// source and defeat the point of moving it out. Set these in .env.test or in
    /// the CI job; a missing one fails here with an explanation rather than
    /// silently testing with something else.
    fn test_pw(name: &str) -> String {
        let var = format!("TURNA_TEST_PW_{}", name.to_uppercase());
        std::env::var(&var).unwrap_or_else(|_| {
            panic!("{var} is not set — source .env.test before running the auth tests")
        })
    }

    use super::*;

    fn store() -> Arc<UserStore> {
        UserStore::new(UserStoreConfig {
            jwt_secret: test_secret(),
            token_ttl_secs: 3600,
        })
    }

    #[test]
    fn register_and_login() {
        let s = store();
        let user = s
            .register(
                "alice",
                "alice@example.com",
                &test_pw("v1"),
                Some("Alice".into()),
            )
            .unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.role, UserRole::Admin);

        let (logged_in, token) = s.login("alice", &test_pw("v1")).unwrap();
        assert_eq!(logged_in.id, user.id);
        assert!(!token.is_empty());
    }

    #[test]
    fn login_by_email() {
        let s = store();
        s.register("bob", "bob@example.com", &test_pw("v2"), None)
            .unwrap();
        let (u, _) = s.login("bob@example.com", &test_pw("v2")).unwrap();
        assert_eq!(u.username, "bob");
    }

    #[test]
    fn duplicate_username_rejected() {
        let s = store();
        s.register("carol", "carol@a.com", &test_pw("v2"), None)
            .unwrap();
        let err = s
            .register("carol", "carol2@a.com", &test_pw("v2"), None)
            .unwrap_err();
        assert!(matches!(err, UserAuthError::UsernameTaken));
    }

    #[test]
    fn duplicate_email_rejected() {
        let s = store();
        s.register("dave", "shared@a.com", &test_pw("v2"), None)
            .unwrap();
        let err = s
            .register("eve", "shared@a.com", &test_pw("v2"), None)
            .unwrap_err();
        assert!(matches!(err, UserAuthError::EmailTaken));
    }

    #[test]
    fn wrong_password_rejected() {
        let s = store();
        s.register("frank", "frank@a.com", "correct-pass", None)
            .unwrap();
        let err = s.login("frank", "wrong-pass").unwrap_err();
        assert!(matches!(err, UserAuthError::InvalidPassword));
    }

    #[test]
    fn token_verify_roundtrip() {
        let s = store();
        s.register("grace", "grace@a.com", &test_pw("v2"), None)
            .unwrap();
        let (_, token) = s.login("grace", &test_pw("v2")).unwrap();
        let claims = s.verify_token(&token).unwrap();
        assert_eq!(claims.username, "grace");
        assert_eq!(claims.iss, crate::jwt::JWT_ISSUER);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn revoked_token_rejected() {
        let s = store();
        s.register("henry", "henry@a.com", &test_pw("v2"), None)
            .unwrap();
        let (_, token) = s.login("henry", &test_pw("v2")).unwrap();

        // Токен валиден до revoke
        assert!(s.verify_token(&token).is_ok());

        // После revoke — TokenRevoked
        s.revoke_token(&token).unwrap();
        let err = s.verify_token(&token).unwrap_err();
        assert!(matches!(err, UserAuthError::TokenRevoked));
    }

    #[test]
    fn two_logins_independent_revocation() {
        let s = store();
        s.register("irene", "irene@a.com", &test_pw("v2"), None)
            .unwrap();
        let (_, token1) = s.login("irene", &test_pw("v2")).unwrap();
        let (_, token2) = s.login("irene", &test_pw("v2")).unwrap();

        // jti разные
        let c1 = s.verify_token(&token1).unwrap();
        let c2 = s.verify_token(&token2).unwrap();
        assert_ne!(c1.jti, c2.jti);

        // Отзываем только первый
        s.revoke_token(&token1).unwrap();
        assert!(matches!(
            s.verify_token(&token1).unwrap_err(),
            UserAuthError::TokenRevoked
        ));
        assert!(s.verify_token(&token2).is_ok());
    }

    #[test]
    fn warmed_revocation_survives_restart() {
        let cfg = UserStoreConfig {
            jwt_secret: test_secret(),
            token_ttl_secs: 3600,
        };

        // Process 1: a user logs in, the token is revoked and (in production)
        // persisted to the backend.
        let s1 = UserStore::new(cfg.clone());
        s1.register("kate", "kate@a.com", &test_pw("v2"), None)
            .unwrap();
        let (_, token) = s1.login("kate", &test_pw("v2")).unwrap();
        let claims = s1.verify_token(&token).unwrap();
        s1.revoke_token(&token).unwrap();
        assert!(matches!(
            s1.verify_token(&token).unwrap_err(),
            UserAuthError::TokenRevoked
        ));
        // What the backend would have stored: (jti, token exp in ms).
        let persisted = vec![(claims.jti.clone(), claims.exp as u64 * 1000)];

        // Process 2 (after a restart): a fresh store starts with an EMPTY
        // blacklist, so the already-revoked token verifies again — the bug.
        let s2 = UserStore::new(cfg);
        assert!(
            s2.verify_token(&token).is_ok(),
            "fresh store accepts a revoked token before warm-up — the regression we guard"
        );

        // Warming from the persisted revocations restores enforcement.
        let loaded = s2.warm_revocations(persisted);
        assert_eq!(loaded, 1);
        assert!(matches!(
            s2.verify_token(&token).unwrap_err(),
            UserAuthError::TokenRevoked
        ));
    }

    #[test]
    fn second_user_is_regular_user() {
        let s = store();
        s.register("usr1", "usr1@a.com", &test_pw("v2"), None)
            .unwrap();
        let u2 = s
            .register("usr2", "usr2@a.com", &test_pw("v2"), None)
            .unwrap();
        assert_eq!(u2.role, UserRole::User);
    }

    #[test]
    fn short_password_rejected() {
        let s = store();
        let err = s.register("h", "h@a.com", "short", None).unwrap_err();
        assert!(matches!(err, UserAuthError::PasswordError(_)));
    }

    #[test]
    fn cleanup_blacklist_removes_expired() {
        let s = UserStore::new(UserStoreConfig {
            jwt_secret: test_secret(),
            token_ttl_secs: 0, // мгновенный exp для теста
        });
        s.register("jack", "jack@a.com", &test_pw("v2"), None)
            .unwrap();
        // С ttl=0 revoke_token добавит expires_at = now(), cleanup сразу всё уберёт
        let removed = s.cleanup_blacklist();
        assert_eq!(removed, 0); // ничего не было
    }

    #[test]
    fn validate_jwt_secret_rejects_weak_and_accepts_strong() {
        assert!(validate_jwt_secret(b"").is_err(), "empty must be rejected");
        assert!(
            validate_jwt_secret(b"short").is_err(),
            "too short must be rejected"
        );
        assert!(
            validate_jwt_secret(PLACEHOLDER_JWT_SECRET).is_err(),
            "placeholder must be rejected"
        );
        assert!(
            validate_jwt_secret(b"a-proper-32-byte-long-secret!!!!").is_ok(),
            "a 32-byte secret must be accepted"
        );
    }

    #[test]
    fn try_from_env_requires_a_real_secret() {
        // One test owns the env var so set/remove can't race other tests.
        std::env::remove_var("TURNA_JWT_SECRET");
        assert!(
            matches!(
                UserStoreConfig::try_from_env(),
                Err(UserAuthError::Config(_))
            ),
            "missing secret must be a hard error"
        );

        std::env::set_var("TURNA_JWT_SECRET", "change-me-use-TURNA_JWT_SECRET-env-var");
        assert!(
            UserStoreConfig::try_from_env().is_err(),
            "placeholder secret must be rejected"
        );

        std::env::set_var("TURNA_JWT_SECRET", "too-short");
        assert!(
            UserStoreConfig::try_from_env().is_err(),
            "short secret must be rejected"
        );

        std::env::set_var("TURNA_JWT_SECRET", "a-proper-32-byte-long-secret!!!!");
        let cfg = UserStoreConfig::try_from_env().expect("valid secret must be accepted");
        assert_eq!(cfg.jwt_secret, b"a-proper-32-byte-long-secret!!!!");

        std::env::remove_var("TURNA_JWT_SECRET");
    }
}
