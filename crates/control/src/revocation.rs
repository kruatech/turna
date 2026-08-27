//! Revoking a management client certificate without rotating the CA.
//!
//! # What this is, and what it is not
//!
//! **It is a deny-list of certificate fingerprints, checked at the application
//! layer.** A revoked certificate completes the TLS handshake and is refused on
//! its first RPC.
//!
//! **It is not RFC 5280 CRL validation.** There is no CA-signed revocation list,
//! no `nextUpdate` freshness rule, no distribution point. If you need those —
//! because a compliance regime names them, or because your CA already publishes
//! CRLs you want honoured — this is not it, and `docs/security/mtls-revocation.md`
//! describes the work that is.
//!
//! # Why this shape rather than TLS-level CRL
//!
//! `tonic`'s `ServerTlsConfig` is a thin wrapper over tokio-rustls and exposes no
//! CRL hook. Real TLS-level revocation needs a custom
//! `WebPkiClientVerifier::builder(roots).with_crls(crls)` and therefore either a
//! tonic version that accepts a custom `ServerConfig`, or terminating TLS in an
//! accept loop and feeding streams to `serve_with_incoming`. Both are real work.
//!
//! Meanwhile the operational goal — a leaked certificate stops working, and the
//! other twenty do not have to be reissued — is reachable in a hundred lines,
//! because the pieces exist. `actor_of` already derives a fingerprint from the
//! peer certificate for the audit log, and RBAC already maps fingerprints to
//! roles. Revocation is the same lookup with the opposite answer.
//!
//! # Three ways this is better than CRL here, and two ways worse
//!
//! Better: **it works air-gapped by construction.** A CRL has to reach the node
//! from the CA; a local file is a local file. This matters because the deployments
//! that most need revocation are the ones with no route off the host — the case
//! `scripts/verify/air-gap.sh` exists to prove.
//!
//! Better: **the operator controls it directly.** Revoking is one line in a file
//! and a reload, not a CA operation.
//!
//! Better: **it composes with what is already there.** One notion of identity,
//! one place a fingerprint means something.
//!
//! Worse: **refusal happens after the handshake, not during it.** A revoked
//! client establishes TLS and is then refused. It costs a handshake and it means
//! the refusal is an application error rather than a TLS alert — which is visible
//! in the audit log and not in a packet capture.
//!
//! Worse: **it is per-node configuration, not a distributed list.** Ten nodes need
//! the file ten times. For a fleet that is a configuration-management problem;
//! for a CRL it would be a fetch.
//!
//! # Fail-closed, and what that costs
//!
//! If the file is configured and cannot be read, the node **refuses to start**.
//!
//! The alternative — start and accept everyone — is how a revocation list comes to
//! be believed while doing nothing. A typo in the path would produce a node that
//! looks configured and honours no revocation, and nobody would find out until
//! the leaked certificate was used.
//!
//! Refusing to start is loud, happens at deploy time rather than at incident
//! time, and is the direction a security control should fail in.

use std::collections::HashSet;
use std::path::Path;

/// Fingerprints that may not be used, however valid their certificate.
#[derive(Debug, Clone, Default)]
pub struct RevocationList {
    /// SHA-256 fingerprints, lower-case hex, no colons.
    revoked: HashSet<String>,
    /// Where it came from, for the log line and for `reload`.
    source: Option<String>,
}

/// Why a list could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    Unreadable {
        path: String,
        reason: String,
    },
    /// A line that is not a fingerprint and not a comment.
    ///
    /// An error rather than a skipped line: a mistyped fingerprint is a
    /// revocation that silently does not apply, and the whole point of this file
    /// is that entries in it take effect.
    BadEntry {
        path: String,
        line: usize,
        text: String,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Unreadable { path, reason } => write!(
                f,
                "revocation list {path:?} could not be read: {reason}. The node \
                 refuses to start rather than accept every certificate — a list \
                 that is configured and unread is worse than none, because it \
                 looks like protection."
            ),
            LoadError::BadEntry { path, line, text } => write!(
                f,
                "revocation list {path}:{line} is not a SHA-256 fingerprint: \
                 {text:?}. Expected 64 hex characters, no colons. Get one with: \
                 openssl x509 -in client.pem -noout -fingerprint -sha256 \
                 | cut -d= -f2 | tr -d : | tr 'A-Z' 'a-z'"
            ),
        }
    }
}

impl std::error::Error for LoadError {}

impl RevocationList {
    /// An empty list — nothing revoked. The state when no path is configured.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load from a file.
    ///
    /// Format: one fingerprint per line. `#` starts a comment, and a comment
    /// after a fingerprint is allowed — an operator revoking a certificate will
    /// want to write down why, and a format that forbids that produces a file
    /// full of unexplained hex.
    ///
    /// ```text
    /// # laptop lost 2026-08-14, ticket OPS-4471
    /// 3fa1c9...  # alice@example.com, issued 2026-06-01
    /// 7bd204...
    /// ```
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|e| LoadError::Unreadable {
            path: display.clone(),
            reason: e.to_string(),
        })?;

        let mut revoked = HashSet::new();
        for (i, raw) in text.lines().enumerate() {
            // Strip a trailing comment, then whitespace. Order matters: doing it
            // the other way leaves the comment attached to the fingerprint.
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            // Colons tolerated on input because `openssl -fingerprint` emits them
            // and an operator pasting its output should not have to know that.
            // Stored without, so comparison has one form.
            let normalised: String = line
                .chars()
                .filter(|c| *c != ':')
                .flat_map(|c| c.to_lowercase())
                .collect();
            if normalised.len() != 64 || !normalised.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(LoadError::BadEntry {
                    path: display,
                    line: i + 1,
                    text: line.to_string(),
                });
            }
            revoked.insert(normalised);
        }

        Ok(Self {
            revoked,
            source: Some(display),
        })
    }

    /// Reload from the same path.
    ///
    /// A revocation that needs a restart to take effect is one that does not take
    /// effect during the incident it was written for.
    ///
    /// On failure the old list is kept and the error returned. Emptying the list
    /// because a reload failed would turn a bad edit into an outage of the control
    /// itself — the opposite of what a reload is for.
    pub fn reload(&self) -> Result<Self, LoadError> {
        match &self.source {
            Some(p) => Self::load(p),
            None => Ok(Self::empty()),
        }
    }

    /// Is this identity revoked?
    ///
    /// Takes the actor string the audit log uses (`cert:<hex>`) rather than a bare
    /// fingerprint, so callers pass what they already have. Two derivations of the
    /// same identity is how an audit entry comes to name a principal that was not
    /// the one checked.
    ///
    /// An identity with no certificate is **not** revoked by this — it was never
    /// authenticated in the first place, and whether to accept it is RBAC's
    /// question, not this one. Conflating them would make a single control
    /// responsible for two different refusals and obscure which fired.
    pub fn is_revoked(&self, identity: &str) -> bool {
        if self.revoked.is_empty() {
            return false;
        }
        match identity.strip_prefix("cert:") {
            Some(fp) => self.revoked.contains(&fp.to_lowercase()),
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(contents: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "turna-revoke-test-{}-{}",
            std::process::id(),
            contents.len()
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    const FP_A: &str = "3fa1c9d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0";
    const FP_B: &str = "7bd204a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d";

    #[test]
    fn empty_list_revokes_nothing() {
        let r = RevocationList::empty();
        assert!(!r.is_revoked(&format!("cert:{FP_A}")));
        assert!(r.is_empty());
    }

    #[test]
    fn loads_fingerprints_and_ignores_comments() {
        let p = write_temp(&format!(
            "# laptop lost, ticket OPS-4471\n{FP_A}  # alice, issued 2026-06-01\n\n{FP_B}\n"
        ));
        let r = RevocationList::load(&p).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.is_revoked(&format!("cert:{FP_A}")));
        assert!(r.is_revoked(&format!("cert:{FP_B}")));
        std::fs::remove_file(p).ok();
    }

    /// `openssl x509 -fingerprint` emits colons and upper case. An operator
    /// pasting its output must not have to know that this file wants neither.
    #[test]
    fn accepts_openssl_output_form() {
        let colonised = FP_A
            .to_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let p = write_temp(&format!("{colonised}\n"));
        let r = RevocationList::load(&p).unwrap();
        assert!(
            r.is_revoked(&format!("cert:{FP_A}")),
            "colon-separated upper-case input should match the lower-case form"
        );
        std::fs::remove_file(p).ok();
    }

    /// A mistyped fingerprint is a revocation that silently does not apply. The
    /// entire purpose of the file is that entries in it take effect, so a bad one
    /// is an error and not a skipped line.
    #[test]
    fn a_malformed_entry_is_an_error_not_a_skipped_line() {
        for bad in [
            "not-a-fingerprint",
            "3fa1c9",
            &FP_A[..63],
            &format!("{FP_A}00"),
        ] {
            let p = write_temp(&format!("{FP_B}\n{bad}\n"));
            let e = RevocationList::load(&p).unwrap_err();
            assert!(
                matches!(e, LoadError::BadEntry { .. }),
                "{bad:?} should be rejected, got {e:?}"
            );
            // And the message must say how to produce a correct one, because the
            // person reading it is mid-incident.
            assert!(e.to_string().contains("openssl"));
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn an_unreadable_file_is_an_error_that_explains_itself() {
        let e = RevocationList::load("/nonexistent/turna-revoke-list").unwrap_err();
        assert!(matches!(e, LoadError::Unreadable { .. }));
        let msg = e.to_string();
        // The message has to carry why refusing to start is right, or somebody
        // will "fix" it by making the load optional.
        assert!(msg.contains("refuses to start"));
        assert!(msg.contains("looks like protection"));
    }

    /// An identity with no certificate is not this control's business. Answering
    /// "revoked" for it would make one control responsible for two different
    /// refusals, and an audit reader could not tell which fired.
    #[test]
    fn an_unauthenticated_identity_is_not_revoked() {
        let p = write_temp(&format!("{FP_A}\n"));
        let r = RevocationList::load(&p).unwrap();
        assert!(!r.is_revoked("127.0.0.1:5555"));
        assert!(!r.is_revoked("unknown"));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn case_of_the_presented_fingerprint_does_not_matter() {
        let p = write_temp(&format!("{FP_A}\n"));
        let r = RevocationList::load(&p).unwrap();
        assert!(r.is_revoked(&format!("cert:{}", FP_A.to_uppercase())));
        std::fs::remove_file(p).ok();
    }

    /// Reload is what makes this usable during an incident. A revocation that
    /// needs a restart is one that does not apply when it was written.
    #[test]
    fn reload_picks_up_an_addition() {
        let p = write_temp(&format!("{FP_A}\n"));
        let r = RevocationList::load(&p).unwrap();
        assert_eq!(r.len(), 1);

        std::fs::write(&p, format!("{FP_A}\n{FP_B}\n")).unwrap();
        let r2 = r.reload().unwrap();
        assert_eq!(r2.len(), 2);
        assert!(r2.is_revoked(&format!("cert:{FP_B}")));
        std::fs::remove_file(p).ok();
    }

    /// A failed reload keeps the old list. Emptying it because an edit was bad
    /// would turn a typo into an outage of the control itself.
    #[test]
    fn a_failed_reload_leaves_the_old_list_intact() {
        let p = write_temp(&format!("{FP_A}\n"));
        let r = RevocationList::load(&p).unwrap();
        std::fs::write(&p, "garbage\n").unwrap();
        assert!(r.reload().is_err());
        // The original is unchanged — `reload` returns a new list rather than
        // mutating, so a failure cannot damage the one in service.
        assert!(r.is_revoked(&format!("cert:{FP_A}")));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn an_empty_file_is_valid_and_revokes_nothing() {
        let p = write_temp("# nothing revoked yet\n\n");
        let r = RevocationList::load(&p).unwrap();
        assert!(r.is_empty());
        assert!(!r.is_revoked(&format!("cert:{FP_A}")));
        std::fs::remove_file(p).ok();
    }
}
