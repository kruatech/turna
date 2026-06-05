//! JWT tokens for platform authentication.

use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
    errors::Error as JwtError,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::user::UserRole;

/// Issuer claim — проверяется при каждой верификации.
pub const JWT_ISSUER: &str = "turna-auth";

/// JWT claims embedded in every access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// JWT ID — уникальный идентификатор токена (replay protection).
    pub jti: String,
    /// Issuer.
    pub iss: String,
    /// User ID (UUID).
    pub sub: String,
    /// Username.
    pub username: String,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// User role.
    pub role: UserRole,
    /// Issued-at (Unix seconds).
    pub iat: usize,
    /// Expiry (Unix seconds).
    pub exp: usize,
}

impl Claims {
    /// Создаёт Claims с заполненными jti и iss.
    pub fn new(
        sub: String,
        username: String,
        display_name: Option<String>,
        role: UserRole,
        iat: usize,
        exp: usize,
    ) -> Self {
        Self {
            jti: Uuid::new_v4().to_string(),
            iss: JWT_ISSUER.to_string(),
            sub,
            username,
            display_name,
            role,
            iat,
            exp,
        }
    }
}

/// Sign a JWT with HS256.
pub fn sign_jwt(claims: &Claims, secret: &[u8]) -> Result<String, JwtError> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Verify and decode a JWT.
///
/// Проверяет: подпись, exp, iss == JWT_ISSUER.
/// Проверку jti против blacklist делает `UserStore::verify_token`.
pub fn verify_jwt(token: &str, secret: &[u8]) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[JWT_ISSUER]);
    validation.validate_exp = true;
    validation.leeway = 0;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &validation,
    )?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(sub: &str) -> Claims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        Claims::new(
            sub.into(),
            "alice".into(),
            Some("Alice".into()),
            UserRole::User,
            now,
            now + 3600,
        )
    }

    #[test]
    fn sign_and_verify() {
        let secret = b"test-secret-key-32-bytes-minimum";
        let claims = make_claims("user-123");
        let token = sign_jwt(&claims, secret).unwrap();
        let decoded = verify_jwt(&token, secret).unwrap();
        assert_eq!(decoded.sub, "user-123");
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.role, UserRole::User);
        assert_eq!(decoded.iss, JWT_ISSUER);
        assert!(!decoded.jti.is_empty());
    }

    #[test]
    fn jti_unique_per_token() {
        let secret = b"test-secret-key-32-bytes-minimum";
        let t1 = sign_jwt(&make_claims("u1"), secret).unwrap();
        let t2 = sign_jwt(&make_claims("u1"), secret).unwrap();
        let c1 = verify_jwt(&t1, secret).unwrap();
        let c2 = verify_jwt(&t2, secret).unwrap();
        assert_ne!(c1.jti, c2.jti);
    }

    #[test]
    fn wrong_secret_fails() {
        let token = sign_jwt(&make_claims("u1"), b"secret-a-32-bytes-paddingpadding").unwrap();
        assert!(verify_jwt(&token, b"secret-b-32-bytes-paddingpadding").is_err());
    }

    #[test]
    fn expired_token_fails() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let mut claims = make_claims("u1");
        claims.exp = now - 10;
        claims.iat = now - 100;
        let token = sign_jwt(&claims, b"secret").unwrap();
        assert!(verify_jwt(&token, b"secret").is_err());
    }

    #[test]
    fn wrong_issuer_rejected() {
        // Форжим токен с другим iss вручную
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let mut claims = make_claims("u1");
        claims.iss = "evil-issuer".to_string();
        claims.exp = now + 3600;
        let secret = b"test-secret-key-32-bytes-minimum";
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        ).unwrap();
        assert!(verify_jwt(&token, secret).is_err());
    }
}
