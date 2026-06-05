//! OAuth / JWT аутентификация для TURN (RFC 7635)
//!
//! Три режима:
//! 1. Long-term credentials (RFC 5389) — HA1 = MD5(user:realm:pass)
//! 2. Time-limited credentials — coturn-совместимый: username = "timestamp:user"
//! 3. OAuth Bearer Token (RFC 7635) — JWT HS256/RS256

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("stale nonce")]
    StaleNonce,
    #[error("missing credentials")]
    MissingCredentials,
    #[error("MESSAGE-INTEGRITY failed")]
    IntegrityFailed,
    #[error("token expired (exp={0})")]
    TokenExpired(u64),
    #[error("token not yet valid (nbf={0})")]
    TokenNotYetValid(u64),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("credential expired")]
    CredentialExpired,
    #[error("invalid credential format")]
    InvalidFormat,
    #[error("key not found: kid={0}")]
    KeyNotFound(String),
}

pub type Result<T> = std::result::Result<T, OAuthError>;

// ---------------------------------------------------------------------------
// Auth Provider Trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub username: String,
    pub realm: String,
    pub integrity_key: Vec<u8>,
    pub metadata: AuthMetadata,
}

#[derive(Debug, Clone, Default)]
pub struct AuthMetadata {
    pub organization: Option<String>,
    pub max_bandwidth: Option<u64>,
    pub max_allocations: Option<u32>,
    pub max_lifetime: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub message_integrity: Vec<u8>,
    pub message_bytes: Vec<u8>,
    pub client_ip: String,
}

#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &str;
    fn can_handle(&self, req: &AuthRequest) -> bool;
    async fn authenticate(&self, req: &AuthRequest) -> Result<AuthContext>;
}

// ---------------------------------------------------------------------------
// 1. Long-Term Credentials (RFC 5389)
// ---------------------------------------------------------------------------

pub struct LongTermAuth {
    realm: String,
    users: Arc<RwLock<HashMap<String, Vec<u8>>>>, // username → HA1
}

impl LongTermAuth {
    pub fn new(realm: String) -> Self {
        Self { realm, users: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub async fn add_user(&self, username: &str, password: &str) {
        let ha1 = compute_ha1(username, &self.realm, password);
        self.users.write().await.insert(username.into(), ha1);
    }

    pub async fn add_user_ha1(&self, username: &str, ha1: Vec<u8>) {
        self.users.write().await.insert(username.into(), ha1);
    }

    pub async fn remove_user(&self, username: &str) -> bool {
        self.users.write().await.remove(username).is_some()
    }
}

#[async_trait::async_trait]
impl AuthProvider for LongTermAuth {
    fn name(&self) -> &str { "long-term" }
    fn can_handle(&self, req: &AuthRequest) -> bool { !req.username.starts_with("oauth:") }

    async fn authenticate(&self, req: &AuthRequest) -> Result<AuthContext> {
        let users = self.users.read().await;
        let ha1 = users.get(&req.username).ok_or_else(|| OAuthError::UserNotFound(req.username.clone()))?;
        verify_integrity(ha1, &req.message_bytes, &req.message_integrity)?;
        Ok(AuthContext { username: req.username.clone(), realm: self.realm.clone(), integrity_key: ha1.clone(), metadata: Default::default() })
    }
}

// ---------------------------------------------------------------------------
// 2. Time-Limited (coturn-compatible)
// ---------------------------------------------------------------------------

pub struct TimeLimitedAuth {
    realm: String,
    secret: Vec<u8>,
    tolerance: Duration,
}

impl TimeLimitedAuth {
    pub fn new(realm: String, secret: Vec<u8>) -> Self {
        Self { realm, secret, tolerance: Duration::from_secs(60) }
    }

    pub fn with_tolerance(mut self, t: Duration) -> Self { self.tolerance = t; self }

    /// Генерирует credentials для сигнального сервера.
    pub fn generate(&self, username: &str, lifetime: Duration) -> (String, String) {
        let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + lifetime.as_secs();
        let user = format!("{exp}:{username}");
        let mut mac = HmacSha256::new_from_slice(&self.secret).unwrap();
        mac.update(user.as_bytes());
        let pass = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        (user, pass)
    }
}

#[async_trait::async_trait]
impl AuthProvider for TimeLimitedAuth {
    fn name(&self) -> &str { "time-limited" }

    fn can_handle(&self, req: &AuthRequest) -> bool {
        req.username.split_once(':').and_then(|(ts, _)| ts.parse::<u64>().ok()).is_some()
    }

    async fn authenticate(&self, req: &AuthRequest) -> Result<AuthContext> {
        let (ts_str, _) = req.username.split_once(':').ok_or(OAuthError::InvalidFormat)?;
        let expiry: u64 = ts_str.parse().map_err(|_| OAuthError::InvalidFormat)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now > expiry + self.tolerance.as_secs() { return Err(OAuthError::CredentialExpired); }

        let mut mac = HmacSha256::new_from_slice(&self.secret).unwrap();
        mac.update(req.username.as_bytes());
        let pass = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let ha1 = compute_ha1(&req.username, &self.realm, &pass);
        verify_integrity(&ha1, &req.message_bytes, &req.message_integrity)?;

        Ok(AuthContext { username: req.username.clone(), realm: self.realm.clone(), integrity_key: ha1, metadata: Default::default() })
    }
}

// ---------------------------------------------------------------------------
// 3. OAuth Bearer Token (RFC 7635)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
pub struct TurnClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)] pub nbf: Option<u64>,
    #[serde(default)] pub org: Option<String>,
    #[serde(default)] pub max_bw: Option<u64>,
    #[serde(default)] pub max_alloc: Option<u32>,
    #[serde(default)] pub max_lifetime: Option<u32>,
}

pub struct OAuthBearerAuth {
    realm: String,
    allowed_issuers: Vec<String>,
    hmac_secret: Option<Vec<u8>>,
    tolerance: Duration,
}

impl OAuthBearerAuth {
    pub fn new(realm: String, allowed_issuers: Vec<String>, hmac_secret: Option<Vec<u8>>) -> Self {
        Self { realm, allowed_issuers, hmac_secret, tolerance: Duration::from_secs(60) }
    }

    fn validate_jwt(&self, token: &str) -> Result<TurnClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 { return Err(OAuthError::InvalidToken("not 3 parts".into())); }

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header_bytes = b64.decode(parts[0]).map_err(|e| OAuthError::InvalidToken(format!("header: {e}")))?;
        let hdr: JwtHeader = serde_json::from_slice(&header_bytes).map_err(|e| OAuthError::InvalidToken(format!("header json: {e}")))?;

        let payload_bytes = b64.decode(parts[1]).map_err(|e| OAuthError::InvalidToken(format!("payload: {e}")))?;
        let claims: TurnClaims = serde_json::from_slice(&payload_bytes).map_err(|e| OAuthError::InvalidToken(format!("claims: {e}")))?;

        let sig = b64.decode(parts[2]).map_err(|e| OAuthError::InvalidToken(format!("sig: {e}")))?;
        let signed = format!("{}.{}", parts[0], parts[1]);

        match hdr.alg.as_str() {
            "HS256" => {
                let secret = self.hmac_secret.as_ref().ok_or_else(|| OAuthError::InvalidToken("no HMAC secret".into()))?;
                let mut mac = HmacSha256::new_from_slice(secret).unwrap();
                mac.update(signed.as_bytes());
                mac.verify_slice(&sig).map_err(|_| OAuthError::InvalidSignature)?;
            }
            alg => return Err(OAuthError::UnsupportedAlg(alg.into())),
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let tol = self.tolerance.as_secs();
        if now > claims.exp + tol { return Err(OAuthError::TokenExpired(claims.exp)); }
        if let Some(nbf) = claims.nbf { if now + tol < nbf { return Err(OAuthError::TokenNotYetValid(nbf)); } }
        if !self.allowed_issuers.is_empty() && !self.allowed_issuers.contains(&claims.iss) {
            return Err(OAuthError::InvalidToken(format!("issuer '{}' not allowed", claims.iss)));
        }
        if claims.aud != self.realm {
            return Err(OAuthError::InvalidToken(format!("aud '{}' != realm '{}'", claims.aud, self.realm)));
        }

        Ok(claims)
    }
}

#[derive(Deserialize)]
struct JwtHeader { alg: String }

#[async_trait::async_trait]
impl AuthProvider for OAuthBearerAuth {
    fn name(&self) -> &str { "oauth-bearer" }
    fn can_handle(&self, req: &AuthRequest) -> bool { req.username.starts_with("oauth:") }

    async fn authenticate(&self, req: &AuthRequest) -> Result<AuthContext> {
        let token = req.username.strip_prefix("oauth:").ok_or(OAuthError::InvalidFormat)?;
        let claims = self.validate_jwt(token)?;
        let ha1 = compute_ha1(&claims.sub, &self.realm, token);

        Ok(AuthContext {
            username: claims.sub,
            realm: self.realm.clone(),
            integrity_key: ha1,
            metadata: AuthMetadata {
                organization: claims.org,
                max_bandwidth: claims.max_bw,
                max_allocations: claims.max_alloc,
                max_lifetime: claims.max_lifetime,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Composite Auth (chain)
// ---------------------------------------------------------------------------

pub struct CompositeAuth {
    providers: Vec<Box<dyn AuthProvider>>,
}

impl CompositeAuth {
    pub fn new() -> Self { Self { providers: Vec::new() } }

    pub fn add(mut self, p: impl AuthProvider + 'static) -> Self {
        self.providers.push(Box::new(p)); self
    }

    pub async fn authenticate(&self, req: &AuthRequest) -> Result<AuthContext> {
        let mut last = OAuthError::MissingCredentials;
        for p in &self.providers {
            if !p.can_handle(req) { continue; }
            match p.authenticate(req).await {
                Ok(ctx) => { debug!(provider = p.name(), user = %ctx.username, "auth ok"); return Ok(ctx); }
                Err(e) => { last = e; }
            }
        }
        Err(last)
    }
}

// ---------------------------------------------------------------------------
// Nonce Manager
// ---------------------------------------------------------------------------

pub struct NonceManager {
    nonces: Arc<RwLock<HashMap<String, (std::time::Instant, String)>>>,
    lifetime: Duration,
}

impl NonceManager {
    pub fn new(lifetime: Duration) -> Self {
        Self { nonces: Arc::new(RwLock::new(HashMap::new())), lifetime }
    }

    pub async fn generate(&self, client_ip: &str) -> String {
        let nonce = hex::encode(rand::random::<[u8; 24]>());
        self.nonces.write().await.insert(nonce.clone(), (std::time::Instant::now(), client_ip.into()));
        nonce
    }

    pub async fn validate(&self, nonce: &str, client_ip: &str) -> bool {
        self.nonces.read().await.get(nonce).map(|(t, ip)| t.elapsed() < self.lifetime && ip == client_ip).unwrap_or(false)
    }

    pub async fn consume(&self, nonce: &str) -> bool {
        self.nonces.write().await.remove(nonce).is_some()
    }

    pub async fn cleanup(&self) -> usize {
        let mut n = self.nonces.write().await;
        let before = n.len();
        n.retain(|_, (t, _)| t.elapsed() < self.lifetime);
        before - n.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn compute_ha1(user: &str, realm: &str, pass: &str) -> Vec<u8> {
    md5::compute(format!("{user}:{realm}:{pass}")).to_vec()
}

fn verify_integrity(key: &[u8], msg: &[u8], expected: &[u8]) -> Result<()> {
    type HmacSha1 = Hmac<sha1::Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.verify_slice(expected).map_err(|_| OAuthError::IntegrityFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ha1_deterministic() {
        let a = compute_ha1("u", "r", "p");
        let b = compute_ha1("u", "r", "p");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[tokio::test]
    async fn long_term_add_remove() {
        let auth = LongTermAuth::new("r".into());
        auth.add_user("a", "p").await;
        assert!(auth.users.read().await.contains_key("a"));
        assert!(auth.remove_user("a").await);
        assert!(!auth.remove_user("a").await);
    }

    #[test]
    fn time_limited_generate() {
        let auth = TimeLimitedAuth::new("r".into(), b"secret".to_vec());
        let (user, pass) = auth.generate("alice", Duration::from_secs(3600));
        let (ts, name) = user.split_once(':').unwrap();
        assert!(ts.parse::<u64>().is_ok());
        assert_eq!(name, "alice");
        assert!(!pass.is_empty());
    }

    #[tokio::test]
    async fn nonce_lifecycle() {
        let nm = NonceManager::new(Duration::from_secs(60));
        let n = nm.generate("1.2.3.4").await;
        assert!(nm.validate(&n, "1.2.3.4").await);
        assert!(!nm.validate(&n, "5.6.7.8").await);
        assert!(nm.consume(&n).await);
        assert!(!nm.validate(&n, "1.2.3.4").await);
    }

    #[test]
    fn routing_oauth_vs_longterm() {
        let lt = LongTermAuth::new("r".into());
        let req_oauth = AuthRequest { username: "oauth:eyJ...".into(), realm: "r".into(), nonce: "".into(), message_integrity: vec![], message_bytes: vec![], client_ip: "1.2.3.4".into() };
        assert!(!lt.can_handle(&req_oauth));
        let req_normal = AuthRequest { username: "alice".into(), ..req_oauth };
        assert!(lt.can_handle(&req_normal));
    }
}
