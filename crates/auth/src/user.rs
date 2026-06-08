//! User model for platform authentication.

use serde::{Deserialize, Serialize};

/// Platform user role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
    Guest,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
            UserRole::Guest => "guest",
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Platform user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    /// Argon2 hash — never serialised in API responses.
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: UserRole,
    pub display_name: Option<String>,
    pub created_at_ms: u64,
    pub is_active: bool,
}

impl User {
    /// Public view — safe to send to clients.
    pub fn public(&self) -> UserPublic {
        UserPublic {
            id: self.id.clone(),
            username: self.username.clone(),
            role: self.role.clone(),
            display_name: self.display_name.clone(),
        }
    }
}

/// Subset of User safe to return in API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub display_name: Option<String>,
}
