//! Role-based access control for the management plane.
//!
//! # Shape
//!
//! Permissions are verbs on resources — `allocations:read`, `config:write`. Roles
//! are named sets of permissions. Identities map to roles. That is the ordinary
//! RBAC arrangement and it is used here because it is the one an operator already
//! knows: a new deployment does not have to learn a scheme invented for this
//! project.
//!
//! # Roles live in configuration, not in this file
//!
//! The three built-in roles below are defaults, not the vocabulary. An operator
//! can define `oncall` with exactly the permissions their rota needs without
//! touching Rust, and that matters because the interesting roles are the ones
//! nobody anticipated. A hardcoded enum would make every new role a release.
//!
//! # Identity comes from the client certificate
//!
//! The management plane already requires mTLS and already derives an actor string
//! from the certificate fingerprint for the audit log. RBAC binds to the same
//! thing, so there is one notion of "who" rather than two that can disagree.
//!
//! Mapping is by fingerprint, not by a field inside the certificate. Reading a
//! role out of the certificate's OU would be less configuration, and it would put
//! authorisation in the hands of whoever signs certificates — which for a private
//! CA is often the same person, but not always, and the moment it is not the
//! separation matters. A fingerprint list is explicit about who granted what.
//!
//! # Default deny, and what that costs
//!
//! An identity with no mapping gets nothing. That is the safe direction, and it
//! means enabling RBAC on a running deployment locks out every existing client
//! until they are mapped — so it is off unless `[management.rbac] enabled = true`,
//! and the disabled path is a straight bypass rather than an implicit
//! "everyone is admin" role. An implicit role would appear in audit entries as a
//! real grant and be indistinguishable from a deliberate one.

use std::collections::{HashMap, HashSet};

/// A permission: `resource:action`.
///
/// Stored as a string rather than an enum on purpose — the set of resources
/// grows with the API, and an enum would mean a config referring to a permission
/// this binary does not know is a parse error rather than a warning. A warning is
/// better: a config shared across a fleet mid-upgrade should not fail to load on
/// the older half.
pub type Permission = String;

/// Every permission the management surface currently checks.
///
/// Listed so `validate()` can warn about a role granting something misspelled —
/// `allocations:delete` versus `allocation:delete` is exactly the typo that
/// silently grants nothing and looks like it granted something.
pub const KNOWN_PERMISSIONS: &[&str] = &[
    "allocations:read",
    "allocations:delete",
    "allocations:watch",
    "config:read",
    "config:write",
    "users:read",
    "users:write",
    "limits:write",
    "stats:read",
    "audit:read",
    "node:drain",
    "node:shutdown",
];

/// Built-in roles, as defaults an operator can override or ignore.
///
/// The split follows what the operations actually cost rather than tidiness:
///
/// - `viewer` — everything that cannot change state. Safe for a dashboard's
///   service account or a support engineer looking at a live incident.
/// - `operator` — the above, plus the day-to-day interventions: freeing a stuck
///   allocation, adjusting a user's limits, draining a node for a rolling
///   upgrade. Deliberately *not* `config:write` or `users:write`: changing the
///   shared secret or the user table is a different kind of act from draining a
///   node, even though both are routine.
/// - `admin` — everything, including `node:shutdown`.
///
/// `shutdown` is in `admin` alone because it is the one operation whose blast
/// radius is the whole node and which no amount of care makes reversible.
pub fn builtin_roles() -> HashMap<String, HashSet<Permission>> {
    let viewer: HashSet<Permission> = [
        "allocations:read",
        "allocations:watch",
        "config:read",
        "users:read",
        "stats:read",
        "audit:read",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let mut operator = viewer.clone();
    operator.extend(
        ["allocations:delete", "limits:write", "node:drain"]
            .iter()
            .map(|s| s.to_string()),
    );

    let admin: HashSet<Permission> = KNOWN_PERMISSIONS.iter().map(|s| s.to_string()).collect();

    HashMap::from([
        ("viewer".to_string(), viewer),
        ("operator".to_string(), operator),
        ("admin".to_string(), admin),
    ])
}

/// The active policy: roles, and which identity holds which.
#[derive(Debug, Clone, Default)]
pub struct RbacPolicy {
    enabled: bool,
    /// role name -> permissions
    roles: HashMap<String, HashSet<Permission>>,
    /// certificate fingerprint (lower-case hex, no colons) -> role names
    bindings: HashMap<String, Vec<String>>,
    /// Resolved permissions per fingerprint, computed once at load.
    ///
    /// Cached because this is consulted on every RPC and the alternative is
    /// walking the role list per call. The cost is that a policy change needs a
    /// reload, which is stated in the config documentation rather than left for
    /// an operator to discover by editing a file and seeing nothing happen.
    resolved: HashMap<String, HashSet<Permission>>,
}

/// Why a request was refused, in a form worth putting in an audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The identity has no role binding at all.
    UnknownIdentity,
    /// The identity has roles, none of which grant the permission.
    Insufficient {
        needed: Permission,
        held: Vec<Permission>,
    },
    /// RBAC is on but the caller presented no client certificate, so there is no
    /// identity to authorise. Distinct from `UnknownIdentity`: one is a
    /// configuration gap, the other is a caller who skipped mTLS.
    NoIdentity,
}

impl Denial {
    /// A message safe to return over the wire.
    ///
    /// Deliberately does not list the permissions the caller *does* hold, nor
    /// which identities exist. Both are useful for debugging and both tell an
    /// unauthorised caller about the shape of the policy. The full detail goes to
    /// the audit log, which is read by someone who is already inside.
    pub fn public_message(&self) -> String {
        match self {
            Denial::NoIdentity => {
                "no client certificate presented; the management plane requires mTLS \
                 when RBAC is enabled"
                    .to_string()
            }
            Denial::UnknownIdentity | Denial::Insufficient { .. } => {
                "permission denied".to_string()
            }
        }
    }

    /// Full detail, for the audit entry.
    pub fn audit_detail(&self, needed: &str) -> String {
        match self {
            Denial::NoIdentity => format!("denied {needed}: no client certificate"),
            Denial::UnknownIdentity => {
                format!("denied {needed}: identity has no role binding")
            }
            Denial::Insufficient { held, .. } => {
                let mut h: Vec<&str> = held.iter().map(|s| s.as_str()).collect();
                h.sort_unstable();
                format!("denied {needed}: holds [{}]", h.join(", "))
            }
        }
    }
}

impl RbacPolicy {
    /// A policy that permits everything — the shape when RBAC is disabled.
    ///
    /// Not an implicit "admin" role: `check` short-circuits, so nothing appears
    /// in an audit entry as though a grant had been evaluated. An implicit role
    /// would be indistinguishable in the log from a deliberate one, which is the
    /// worse outcome for anybody later asking who was allowed to do what.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Build from configuration.
    ///
    /// `extra_roles` are merged over the built-ins, so an operator can redefine
    /// `operator` as well as add `oncall`. Redefining is allowed on purpose: a
    /// deployment that considers `allocations:delete` too sharp for its operators
    /// should be able to say so without inventing a parallel role name.
    pub fn new(
        enabled: bool,
        extra_roles: HashMap<String, HashSet<Permission>>,
        bindings: HashMap<String, Vec<String>>,
    ) -> Self {
        let mut roles = builtin_roles();
        for (name, perms) in extra_roles {
            roles.insert(name, perms);
        }

        let mut resolved: HashMap<String, HashSet<Permission>> = HashMap::new();
        for (fp, role_names) in &bindings {
            let mut perms = HashSet::new();
            for r in role_names {
                if let Some(p) = roles.get(r) {
                    perms.extend(p.iter().cloned());
                }
            }
            // Fingerprints are compared lower-case: a certificate tool that emits
            // upper-case hex should not silently produce an identity that never
            // matches.
            resolved.insert(fp.to_lowercase(), perms);
        }

        Self {
            enabled,
            roles,
            bindings,
            resolved,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Does `identity` hold `permission`?
    ///
    /// `identity` is the fingerprint form used by the audit log (`cert:<hex>`),
    /// or an address when no certificate was presented. The `cert:` prefix is
    /// stripped here so callers can pass the actor string they already have
    /// rather than deriving a second one — two derivations that can disagree is
    /// how an audit entry comes to name a different principal than the one that
    /// was authorised.
    pub fn check(&self, identity: &str, permission: &str) -> Result<(), Denial> {
        if !self.enabled {
            return Ok(());
        }

        let fp = match identity.strip_prefix("cert:") {
            Some(f) => f.to_lowercase(),
            // No certificate: the actor is an address. Under RBAC that is not an
            // identity, however trusted the network.
            None => return Err(Denial::NoIdentity),
        };

        match self.resolved.get(&fp) {
            None => Err(Denial::UnknownIdentity),
            Some(perms) if perms.contains(permission) => Ok(()),
            Some(perms) => Err(Denial::Insufficient {
                needed: permission.to_string(),
                held: perms.iter().cloned().collect(),
            }),
        }
    }

    /// Problems worth telling an operator about at startup.
    ///
    /// Warnings rather than errors, with one exception. A config that refers to a
    /// role this binary does not know, or a permission it does not check, is
    /// probably a typo — but it is also what a fleet mid-upgrade looks like, and
    /// refusing to start the older half of a fleet is a worse failure than
    /// running with a role that grants less than intended.
    ///
    /// The exception is a policy that is enabled with no bindings: that locks out
    /// every client and there is no reading of it that is what somebody meant.
    pub fn validate(&self) -> (Vec<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        if !self.enabled {
            return (warnings, errors);
        }

        if self.bindings.is_empty() {
            errors.push(
                "[management.rbac] enabled = true with no bindings: every management \
                 request would be denied. Add at least one binding, or disable RBAC."
                    .to_string(),
            );
        }

        let known: HashSet<&str> = KNOWN_PERMISSIONS.iter().copied().collect();
        for (name, perms) in &self.roles {
            for p in perms {
                if !known.contains(p.as_str()) {
                    warnings.push(format!(
                        "role {name:?} grants {p:?}, which no management RPC checks. \
                         Misspelled? A permission nothing checks grants nothing."
                    ));
                }
            }
        }

        for (fp, role_names) in &self.bindings {
            if role_names.is_empty() {
                warnings.push(format!(
                    "identity {fp} is bound to no roles, so it can do nothing. \
                     Remove the binding or give it a role."
                ));
            }
            for r in role_names {
                if !self.roles.contains_key(r) {
                    warnings.push(format!(
                        "identity {fp} is bound to role {r:?}, which is not defined. \
                         That grant is silently empty."
                    ));
                }
            }
        }

        // A policy where nobody can shut the node down is a legitimate choice, but
        // one where nobody can change configuration is usually an oversight —
        // there would be no way to fix the policy itself through the API.
        let anyone_can_write_config = self.resolved.values().any(|p| p.contains("config:write"));
        if !anyone_can_write_config {
            warnings.push(
                "no identity holds config:write, so the configuration cannot be \
                 changed through the management API by anyone. Deliberate?"
                    .to_string(),
            );
        }

        (warnings, errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RbacPolicy {
        RbacPolicy::new(
            true,
            HashMap::new(),
            HashMap::from([
                ("AABBCC".to_string(), vec!["viewer".to_string()]),
                ("ddeeff".to_string(), vec!["admin".to_string()]),
                ("112233".to_string(), vec!["nosuchrole".to_string()]),
            ]),
        )
    }

    #[test]
    fn viewer_reads_but_does_not_delete() {
        let p = policy();
        assert!(p.check("cert:aabbcc", "allocations:read").is_ok());
        assert!(matches!(
            p.check("cert:aabbcc", "allocations:delete"),
            Err(Denial::Insufficient { .. })
        ));
    }

    /// The binding was written in upper case and the fingerprint arrives lower.
    /// Without normalisation this grant would exist in the config and never
    /// apply — the kind of failure that reads as "RBAC is broken" rather than as
    /// a case mismatch.
    #[test]
    fn fingerprint_case_does_not_matter() {
        let p = policy();
        assert!(p.check("cert:AABBCC", "allocations:read").is_ok());
        assert!(p.check("cert:aabbcc", "allocations:read").is_ok());
    }

    #[test]
    fn admin_holds_every_known_permission() {
        let p = policy();
        for perm in KNOWN_PERMISSIONS {
            assert!(
                p.check("cert:ddeeff", perm).is_ok(),
                "admin should hold {perm}"
            );
        }
    }

    /// An address is not an identity under RBAC, and the denial says which
    /// problem it is: a caller who skipped mTLS, not a missing binding.
    #[test]
    fn no_certificate_is_a_distinct_denial() {
        let p = policy();
        assert_eq!(
            p.check("127.0.0.1:5555", "stats:read"),
            Err(Denial::NoIdentity)
        );
    }

    #[test]
    fn unbound_identity_is_denied_and_distinguishable() {
        let p = policy();
        assert_eq!(
            p.check("cert:999999", "stats:read"),
            Err(Denial::UnknownIdentity)
        );
    }

    /// Disabled RBAC permits without evaluating, so nothing can appear in an
    /// audit entry as a grant that was never granted.
    #[test]
    fn disabled_permits_everything() {
        let p = RbacPolicy::disabled();
        assert!(p.check("cert:whatever", "node:shutdown").is_ok());
        assert!(p.check("127.0.0.1:1", "node:shutdown").is_ok());
    }

    #[test]
    fn enabled_without_bindings_is_an_error_not_a_warning() {
        let p = RbacPolicy::new(true, HashMap::new(), HashMap::new());
        let (_warnings, errors) = p.validate();
        assert!(
            errors.iter().any(|e| e.contains("no bindings")),
            "a policy that denies everyone must not start quietly"
        );
    }

    #[test]
    fn undefined_role_warns_rather_than_failing() {
        let (warnings, errors) = policy().validate();
        assert!(
            errors.is_empty(),
            "a typo in a role name must not stop the node"
        );
        assert!(warnings.iter().any(|w| w.contains("nosuchrole")));
    }

    /// A custom role can be added without touching this file, and can also
    /// redefine a built-in — a deployment that finds `operator` too sharp should
    /// be able to narrow it rather than invent `operator2`.
    #[test]
    fn custom_roles_extend_and_override() {
        let p = RbacPolicy::new(
            true,
            HashMap::from([
                (
                    "oncall".to_string(),
                    HashSet::from(["node:drain".to_string(), "stats:read".to_string()]),
                ),
                (
                    "operator".to_string(),
                    HashSet::from(["stats:read".to_string()]),
                ),
            ]),
            HashMap::from([
                ("aa".to_string(), vec!["oncall".to_string()]),
                ("bb".to_string(), vec!["operator".to_string()]),
            ]),
        );
        assert!(p.check("cert:aa", "node:drain").is_ok());
        assert!(p.check("cert:aa", "allocations:delete").is_err());
        // Redefined: the built-in operator would have had allocations:delete.
        assert!(p.check("cert:bb", "allocations:delete").is_err());
        assert!(p.check("cert:bb", "stats:read").is_ok());
    }

    /// Two roles on one identity union their permissions.
    #[test]
    fn multiple_roles_union() {
        let p = RbacPolicy::new(
            true,
            HashMap::new(),
            HashMap::from([(
                "cc".to_string(),
                vec!["viewer".to_string(), "operator".to_string()],
            )]),
        );
        assert!(p.check("cert:cc", "allocations:read").is_ok());
        assert!(p.check("cert:cc", "node:drain").is_ok());
        assert!(p.check("cert:cc", "node:shutdown").is_err());
    }

    /// The public message must not describe the policy: an unauthorised caller
    /// learning which permissions exist, or which they hold, is a disclosure.
    #[test]
    fn public_message_reveals_nothing() {
        let d = Denial::Insufficient {
            needed: "node:shutdown".to_string(),
            held: vec!["stats:read".to_string(), "config:read".to_string()],
        };
        let msg = d.public_message();
        assert!(!msg.contains("shutdown"));
        assert!(!msg.contains("stats:read"));
        // The audit entry, read by someone already inside, carries the detail.
        assert!(d.audit_detail("node:shutdown").contains("stats:read"));
    }
}
