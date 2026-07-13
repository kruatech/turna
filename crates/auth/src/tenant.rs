//! Multi-tenant TURN auth (P1).
//!
//! Security model (canonical identity = authenticated realm):
//!
//!   * The `tenant_id` is derived ONLY from the realm that is covered by a
//!     valid MESSAGE-INTEGRITY — i.e. the realm whose credentials actually
//!     verified the request. A network hint (listener address) may *narrow*
//!     which realms are acceptable, but it never selects the tenant.
//!   * The long-term key is `H(username : realm : password)`, so the realm is
//!     cryptographically bound to the request. A client cannot claim another
//!     tenant's realm without that tenant's credentials — its integrity check
//!     would fail. This is what makes "tenant = request realm" safe.
//!   * Pre-auth requests resolve no tenant: the 401 challenge uses only
//!     [`AuthRegistry::default_realm`] and grants/leaks nothing.
//!   * An unknown realm (matching neither a tenant nor the base realm) is
//!     rejected — there is no backend to validate it against, and silent
//!     fallback would be a privilege hazard.

use std::collections::HashMap;

use turna_proto_stun::message::StunMessage;

use crate::{AuthError, AuthMode};

/// Outcome of resolving + validating a request's credentials.
#[derive(Debug, Clone)]
pub struct AuthResolution {
    /// Resolved tenant id, or `None` for the base (`[turn]`) realm — i.e. the
    /// default/single-tenant deployment.
    pub tenant_id: Option<String>,
    /// The authenticated realm (equal to the request's REALM).
    pub realm: String,
    /// Derived long-term key, for response MESSAGE-INTEGRITY.
    pub key: Vec<u8>,
    /// For OAuth (RFC 7635): the token's remaining lifetime in seconds, so the
    /// allocation lifetime can be capped to it (§6.1). `None` for long-term /
    /// shared-secret auth (no token lifetime to bind).
    pub max_lifetime_secs: Option<u32>,
}

/// Multi-tenant auth: a base [`AuthMode`] (the `[turn]` realm) plus per-realm
/// tenant auth backends. Resolution is by *authenticated* realm only.
///
/// Single-tenant deployments use `AuthRegistry::new(base)` with no tenants and
/// behave exactly as a bare `AuthMode` did (resolution returns `tenant_id =
/// None`).
pub struct AuthRegistry {
    /// realm → (tenant_id, auth backend) for explicit tenants.
    tenants: HashMap<String, (String, AuthMode)>,
    /// Base auth (the `[turn]` realm); also the default 401 challenge realm.
    base: AuthMode,
}

impl AuthRegistry {
    pub fn new(base: AuthMode) -> Self {
        Self {
            tenants: HashMap::new(),
            base,
        }
    }

    /// Register a tenant. The tenant is keyed by its auth backend's realm.
    /// Panics only on a programming error (duplicate realm) — config validation
    /// already rejects duplicate realms before this is reached.
    pub fn with_tenant(mut self, tenant_id: impl Into<String>, auth: AuthMode) -> Self {
        let realm = auth.realm().to_string();
        self.tenants.insert(realm, (tenant_id.into(), auth));
        self
    }

    /// Number of explicit tenants (0 = single-tenant).
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Realm to advertise in a pre-auth 401 challenge when there is no better
    /// (listener) hint. Tenant identity is NOT decided here.
    pub fn default_realm(&self) -> &str {
        self.base.realm()
    }

    /// The base realm's authorization-server identity for a 401 THIRD-PARTY-
    /// AUTHORIZATION challenge (RFC 7635 §6.1), or `None` when the base realm is
    /// not OAuth. Pre-auth challenges use the base realm only.
    pub fn base_oauth_identity(&self) -> Option<&str> {
        self.base.oauth_identity()
    }

    /// Resolve the tenant and validate credentials in one step.
    ///
    /// The realm carried by the (integrity-protected) request selects the
    /// backend; MESSAGE-INTEGRITY is then verified against THAT backend. Only a
    /// successful verification yields a `tenant_id`. Network hints never enter.
    pub fn validate(&self, msg: &StunMessage, raw: &[u8]) -> Result<AuthResolution, AuthError> {
        let realm = msg.get_realm().ok_or(AuthError::MissingCredentials)?;
        // Normalise to &str regardless of whether get_realm yields &str/String.
        let realm_ref: &str = realm;

        if let Some((tenant_id, auth)) = self.tenants.get(realm_ref) {
            // Tenant realm: validate against the tenant's backend.
            let (key, max_lifetime_secs) = auth.validate_with_lifetime(msg, raw)?;
            Ok(AuthResolution {
                tenant_id: Some(tenant_id.clone()),
                realm: realm_ref.to_string(),
                key,
                max_lifetime_secs,
            })
        } else if realm_ref == self.base.realm() {
            // Base realm: default/single-tenant.
            let (key, max_lifetime_secs) = self.base.validate_with_lifetime(msg, raw)?;
            Ok(AuthResolution {
                tenant_id: None,
                realm: realm_ref.to_string(),
                key,
                max_lifetime_secs,
            })
        } else {
            // Unknown realm — no backend to authenticate against. Reject; never
            // fall back (that would let an arbitrary realm reach the base creds).
            Err(AuthError::InvalidCredentials)
        }
    }

    // ── Runtime user management (R8) ──────────────────────────────────────────
    //
    // Mutates the in-memory LongTerm store through the shared `Arc<DashMap>`
    // inside `AuthMode`, so `&self` suffices (the registry is held as an
    // `Arc<AuthRegistry>` shared across workers + the gRPC core).

    /// Add (or replace) a user in the base (`[turn]`) realm. Returns `true` if
    /// applied (base backend is LongTerm).
    pub fn add_user(&self, username: &str, password: &str) -> bool {
        self.base.add_user(username, password)
    }

    /// Remove a user from the base realm. Returns `true` if removed.
    pub fn remove_user(&self, username: &str) -> bool {
        self.base.remove_user(username)
    }

    /// Add a user to a specific realm (base or a tenant's). Returns `false` if
    /// the realm is unknown or its backend is SharedSecret.
    pub fn add_user_for_realm(&self, realm: &str, username: &str, password: &str) -> bool {
        if realm == self.base.realm() {
            self.base.add_user(username, password)
        } else if let Some((_, auth)) = self.tenants.get(realm) {
            auth.add_user(username, password)
        } else {
            false
        }
    }

    /// Remove a user from a specific realm. Returns `false` if the realm is
    /// unknown or no such user existed.
    pub fn remove_user_for_realm(&self, realm: &str, username: &str) -> bool {
        if realm == self.base.realm() {
            self.base.remove_user(username)
        } else if let Some((_, auth)) = self.tenants.get(realm) {
            auth.remove_user(username)
        } else {
            false
        }
    }

    /// Insert a user from pre-derived keys into a specific realm (base or a
    /// tenant's). Used to rehydrate the registry from the state backend on
    /// startup. Returns `false` if the realm is unknown or SharedSecret.
    pub fn add_user_with_keys(&self, realm: &str, username: &str, keys: crate::UserKeys) -> bool {
        if realm == self.base.realm() {
            self.base.add_user_keys(username, keys)
        } else if let Some((_, auth)) = self.tenants.get(realm) {
            auth.add_user_keys(username, keys)
        } else {
            false
        }
    }
}
