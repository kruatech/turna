//! Connection Migration — maintain sessions across IP changes.
//!
//! When a client moves between networks (Wi-Fi→LTE, roaming),
//! its IP changes. Without migration: session drops, call reconnects.
//! With migration: session continues seamlessly.
//!
//! Mechanisms:
//! 1. **QUIC native** — built-in, connection ID based (free with WebTransport)
//! 2. **UDP hint-based** — client sends Allocate with migration-token,
//!    server rebinds existing allocation to new 5-tuple
//! 3. **ICE restart** — standard WebRTC mechanism (slower, but works everywhere)
//!
//! This module implements the hint-based mechanism for TURN
//! and tracks QUIC migrations via events.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Migration Token
// ---------------------------------------------------------------------------

/// Opaque migration token issued to client.
///
/// Encodes: allocation_id + HMAC for tamper protection.
/// Client stores it and presents on reconnection from new IP.
#[derive(Debug, Clone)]
pub struct MigrationToken {
    /// Opaque token bytes (base64-encoded for transport).
    pub token: Vec<u8>,
    /// Associated allocation/session ID.
    pub session_id: String,
    /// Issued at.
    pub issued_at: Instant,
    /// Valid for.
    pub ttl: Duration,
}

impl MigrationToken {
    /// Generate a new migration token.
    pub fn generate(session_id: &str, secret: &[u8], ttl: Duration) -> Self {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let payload = format!("{session_id}:{now_secs}");
        let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
        mac.update(payload.as_bytes());
        let sig = mac.finalize().into_bytes();

        // Hex-encode the signature so the whole token is valid UTF-8. The raw
        // 20-byte HMAC is almost never valid UTF-8, which previously made
        // validate()'s from_utf8() check fail and reject every token.
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        let mut token = payload.into_bytes();
        token.push(b':');
        token.extend_from_slice(sig_hex.as_bytes());

        Self {
            token,
            session_id: session_id.into(),
            issued_at: Instant::now(),
            ttl,
        }
    }

    /// Validate a migration token.
    pub fn validate(token_bytes: &[u8], secret: &[u8], max_age: Duration) -> Option<String> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        // Token is "<session_id>:<issued_secs>:<hex_signature>" — all ASCII.
        let token_str = std::str::from_utf8(token_bytes).ok()?;
        let (payload, sig_hex) = token_str.rsplit_once(':')?;
        let sig_bytes = decode_hex(sig_hex)?;

        // Verify HMAC over the payload.
        let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
        mac.update(payload.as_bytes());
        if mac.verify_slice(&sig_bytes).is_err() {
            return None;
        }

        // payload = "<session_id>:<issued_secs>"; split the timestamp off the
        // right so a session id may itself contain ':'.
        let (session_id, issued) = payload.rsplit_once(':')?;
        let issued_secs: u64 = issued.parse().ok()?;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now_secs - issued_secs > max_age.as_secs() {
            return None; // Token expired
        }

        Some(session_id.to_string())
    }

    pub fn is_expired(&self) -> bool {
        self.issued_at.elapsed() > self.ttl
    }
}

/// Decode a lowercase hex string into bytes. Returns None on odd length or
/// any non-hex digit.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Migration Manager
// ---------------------------------------------------------------------------

/// Tracks pending and completed migrations.
pub struct MigrationManager {
    /// session_id → old_addr (for rollback).
    pending: HashMap<String, PendingMigration>,
    /// Recently completed migrations (for dedup).
    completed: HashMap<String, CompletedMigration>,
    /// Token secret for HMAC.
    secret: Vec<u8>,
    /// Token TTL.
    token_ttl: Duration,
    /// Migration timeout.
    migration_timeout: Duration,
}

// Reserved for the QUIC connection-migration bookkeeping that the manager
// will populate; not constructed by the currently-enabled paths.
#[allow(dead_code)]
struct PendingMigration {
    session_id: String,
    old_addr: SocketAddr,
    new_addr: SocketAddr,
    started_at: Instant,
}

// Companion to PendingMigration above; same reservation rationale.
#[allow(dead_code)]
struct CompletedMigration {
    old_addr: SocketAddr,
    new_addr: SocketAddr,
    completed_at: Instant,
}

impl MigrationManager {
    pub fn new(secret: Vec<u8>) -> Self {
        Self {
            pending: HashMap::new(),
            completed: HashMap::new(),
            secret,
            token_ttl: Duration::from_secs(300), // 5 min
            migration_timeout: Duration::from_secs(30),
        }
    }

    /// Issue a migration token for a session.
    pub fn issue_token(&self, session_id: &str) -> MigrationToken {
        MigrationToken::generate(session_id, &self.secret, self.token_ttl)
    }

    /// Attempt migration: validate token, return session_id if valid.
    ///
    /// After validation, caller should:
    /// 1. Update allocation's client_addr to new_addr
    /// 2. Update permissions/channels
    /// 3. Send success response
    pub fn attempt_migration(
        &mut self,
        token_bytes: &[u8],
        new_addr: SocketAddr,
        old_addr: SocketAddr,
    ) -> Option<String> {
        let session_id = MigrationToken::validate(
            token_bytes, &self.secret, self.token_ttl,
        )?;

        self.pending.insert(session_id.clone(), PendingMigration {
            session_id: session_id.clone(),
            old_addr,
            new_addr,
            started_at: Instant::now(),
        });

        info!(
            session = %session_id,
            %old_addr, %new_addr,
            "migration attempt"
        );

        Some(session_id)
    }

    /// Complete a migration (after allocation rebind succeeds).
    pub fn complete_migration(&mut self, session_id: &str) {
        if let Some(pending) = self.pending.remove(session_id) {
            let elapsed = pending.started_at.elapsed();
            self.completed.insert(session_id.to_string(), CompletedMigration {
                old_addr: pending.old_addr,
                new_addr: pending.new_addr,
                completed_at: Instant::now(),
            });
            info!(
                session = session_id,
                elapsed_ms = elapsed.as_millis(),
                "migration completed"
            );
        }
    }

    /// Handle QUIC connection migration event.
    ///
    /// QUIC handles migration natively via connection IDs.
    /// This just records the event for logging/metrics.
    pub fn on_quic_migration(
        &mut self,
        session_id: &str,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) {
        info!(
            session = session_id,
            %old_addr, %new_addr,
            "QUIC connection migrated"
        );
        self.completed.insert(session_id.to_string(), CompletedMigration {
            old_addr,
            new_addr,
            completed_at: Instant::now(),
        });
    }

    /// Cleanup timed-out pending migrations.
    pub fn cleanup(&mut self) -> usize {
        let timeout = self.migration_timeout;
        let before = self.pending.len();
        self.pending.retain(|_, m| m.started_at.elapsed() < timeout);
        let expired = before - self.pending.len();

        // Also clean old completed entries (> 5 min)
        self.completed.retain(|_, m| m.completed_at.elapsed() < Duration::from_secs(300));

        if expired > 0 {
            warn!(expired, "migration attempts timed out");
        }
        expired
    }

    pub fn pending_count(&self) -> usize { self.pending.len() }
    pub fn completed_count(&self) -> usize { self.completed.len() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_generate_validate() {
        let secret = b"test-secret";
        let token = MigrationToken::generate("session1", secret, Duration::from_secs(60));
        let result = MigrationToken::validate(&token.token, secret, Duration::from_secs(60));
        assert_eq!(result, Some("session1".to_string()));
    }

    #[test]
    fn token_wrong_secret() {
        let token = MigrationToken::generate("s1", b"secret1", Duration::from_secs(60));
        let result = MigrationToken::validate(&token.token, b"secret2", Duration::from_secs(60));
        assert!(result.is_none());
    }

    #[test]
    fn migration_lifecycle() {
        let mut mgr = MigrationManager::new(b"secret".to_vec());

        let token = mgr.issue_token("alloc1");
        let old: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let new: SocketAddr = "10.0.0.2:6000".parse().unwrap();

        let sid = mgr.attempt_migration(&token.token, new, old).unwrap();
        assert_eq!(sid, "alloc1");
        assert_eq!(mgr.pending_count(), 1);

        mgr.complete_migration("alloc1");
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.completed_count(), 1);
    }

    #[test]
    fn quic_migration_recorded() {
        let mut mgr = MigrationManager::new(b"s".to_vec());
        mgr.on_quic_migration(
            "quic-sess",
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
        );
        assert_eq!(mgr.completed_count(), 1);
    }
}
