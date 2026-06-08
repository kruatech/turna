//! Credential Rotation — обновление credentials без разрыва сессий
//!
//! - Grace period: старые credentials действуют ещё N секунд после истечения
//! - Overlap: при ротации и старые, и новые принимаются
//! - Уведомление signaling о скором истечении через callback

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Grace period после истечения (старые ещё принимаются).
    pub grace_period: Duration,
    /// За сколько до истечения предупреждать.
    pub pre_expiry_notify: Duration,
    /// Макс. активных credentials на аллокацию (2 = текущие + следующие).
    pub max_active_credentials: usize,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(60),
            pre_expiry_notify: Duration::from_secs(120),
            max_active_credentials: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Credential Entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CredentialEntry {
    pub username: String,
    pub integrity_key: Vec<u8>,
    pub created_at: Instant,
    /// None = бессрочные (long-term).
    pub expires_at: Option<Instant>,
    pub kind: CredentialKind,
    pub expiry_notified: bool,
    pub organization: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    LongTerm,
    TimeLimited,
    OAuthBearer,
}

impl CredentialEntry {
    pub fn is_valid(&self, grace: Duration) -> bool {
        match self.expires_at {
            None => true,
            Some(exp) => Instant::now() < exp + grace,
        }
    }

    pub fn expiring_soon(&self, pre_notify: Duration) -> bool {
        match self.expires_at {
            None => false,
            Some(exp) => {
                let now = Instant::now();
                now + pre_notify >= exp && now < exp
            }
        }
    }

    pub fn is_expired_hard(&self) -> bool {
        match self.expires_at {
            None => false,
            Some(exp) => Instant::now() >= exp,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-allocation credential state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AllocationCreds {
    entries: Vec<CredentialEntry>,
    allocation_id: String,
    base_username: String,
}

impl AllocationCreds {
    fn new(allocation_id: String, base_username: String, initial: CredentialEntry) -> Self {
        Self {
            entries: vec![initial],
            allocation_id,
            base_username,
        }
    }

    fn push(&mut self, entry: CredentialEntry, max_active: usize) {
        self.entries.push(entry);
        while self.entries.len() > max_active {
            self.entries.remove(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Expiring credential info (for notifications)
// ---------------------------------------------------------------------------

/// Информация о скоро истекающих credentials.
#[derive(Debug, Clone)]
pub struct ExpiringCredential {
    pub allocation_id: String,
    pub username: String,
    pub remaining: Duration,
}

// ---------------------------------------------------------------------------
// Validate result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateResult {
    Valid { in_grace_period: bool },
    Invalid,
    AllocationNotFound,
}

// ---------------------------------------------------------------------------
// Manager (sync, no tokio needed)
// ---------------------------------------------------------------------------

/// Credential rotation manager. Thread-safe через std::sync::RwLock.
pub struct CredentialRotationManager {
    config: RotationConfig,
    allocations: RwLock<HashMap<String, AllocationCreds>>,
}

impl CredentialRotationManager {
    pub fn new(config: RotationConfig) -> Self {
        Self {
            config,
            allocations: RwLock::new(HashMap::new()),
        }
    }

    /// Регистрирует аллокацию с начальными credentials.
    pub fn register(&self, allocation_id: &str, base_username: &str, credentials: CredentialEntry) {
        let mut allocs = self.allocations.write().unwrap();
        allocs.insert(
            allocation_id.to_string(),
            AllocationCreds::new(
                allocation_id.to_string(),
                base_username.to_string(),
                credentials,
            ),
        );
        debug!(
            alloc = allocation_id,
            user = base_username,
            "credentials registered"
        );
    }

    /// Ротация: добавляет новые credentials, старые остаются в grace period.
    pub fn rotate(&self, allocation_id: &str, new_credentials: CredentialEntry) -> bool {
        let mut allocs = self.allocations.write().unwrap();
        if let Some(state) = allocs.get_mut(allocation_id) {
            state.push(new_credentials, self.config.max_active_credentials);
            info!(alloc = allocation_id, "credentials rotated");
            true
        } else {
            warn!(alloc = allocation_id, "rotation for unknown allocation");
            false
        }
    }

    /// Проверяет credentials. Пробует все активные (новые → старые).
    pub fn validate(&self, allocation_id: &str, check: impl Fn(&[u8]) -> bool) -> ValidateResult {
        let allocs = self.allocations.read().unwrap();
        let state = match allocs.get(allocation_id) {
            Some(s) => s,
            None => return ValidateResult::AllocationNotFound,
        };

        for entry in state.entries.iter().rev() {
            if !entry.is_valid(self.config.grace_period) {
                continue;
            }
            if check(&entry.integrity_key) {
                let in_grace = entry.is_expired_hard();
                if in_grace {
                    debug!(
                        alloc = allocation_id,
                        "validated with grace-period credentials"
                    );
                }
                return ValidateResult::Valid {
                    in_grace_period: in_grace,
                };
            }
        }

        ValidateResult::Invalid
    }

    /// Удаляет аллокацию.
    pub fn remove(&self, allocation_id: &str) {
        self.allocations.write().unwrap().remove(allocation_id);
    }

    /// Собирает список аллокаций с истекающими credentials.
    /// Вызывать периодически. Результат передаёте в signaling для ротации.
    pub fn collect_expiring(&self) -> Vec<ExpiringCredential> {
        let mut allocs = self.allocations.write().unwrap();
        let mut result = Vec::new();

        for state in allocs.values_mut() {
            for entry in &mut state.entries {
                if entry.expiring_soon(self.config.pre_expiry_notify) && !entry.expiry_notified {
                    if let Some(exp) = entry.expires_at {
                        let remaining = exp.saturating_duration_since(Instant::now());
                        result.push(ExpiringCredential {
                            allocation_id: state.allocation_id.clone(),
                            username: state.base_username.clone(),
                            remaining,
                        });
                        entry.expiry_notified = true;
                        info!(
                            alloc = %state.allocation_id,
                            user = %state.base_username,
                            remaining_secs = remaining.as_secs(),
                            "credentials expiring soon"
                        );
                    }
                }
            }
        }

        result
    }

    /// Cleanup: удаляет полностью просроченные (за пределами grace).
    pub fn cleanup(&self) -> usize {
        let mut allocs = self.allocations.write().unwrap();
        let grace = self.config.grace_period;
        let mut cleaned = 0usize;

        allocs.retain(|_, state| {
            let before = state.entries.len();
            state.entries.retain(|e| e.is_valid(grace));
            cleaned += before - state.entries.len();
            !state.entries.is_empty()
        });

        cleaned
    }

    pub fn allocation_count(&self) -> usize {
        self.allocations.read().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cred(kind: CredentialKind, expires_in: Option<Duration>) -> CredentialEntry {
        CredentialEntry {
            username: "test".into(),
            integrity_key: vec![1, 2, 3, 4],
            created_at: Instant::now(),
            expires_at: expires_in.map(|d| Instant::now() + d),
            kind,
            expiry_notified: false,
            organization: None,
        }
    }

    #[test]
    fn long_term_never_expires() {
        let cred = make_cred(CredentialKind::LongTerm, None);
        assert!(cred.is_valid(Duration::from_secs(0)));
        assert!(!cred.expiring_soon(Duration::from_secs(999)));
    }

    #[test]
    fn time_limited_expires() {
        let cred = make_cred(CredentialKind::TimeLimited, Some(Duration::from_millis(10)));
        assert!(cred.is_valid(Duration::from_secs(0)));
        std::thread::sleep(Duration::from_millis(20));
        assert!(!cred.is_valid(Duration::from_secs(0)));
        assert!(cred.is_valid(Duration::from_secs(5))); // grace
    }

    #[test]
    fn expiring_soon_detection() {
        let cred = make_cred(CredentialKind::OAuthBearer, Some(Duration::from_secs(30)));
        assert!(cred.expiring_soon(Duration::from_secs(60)));
        assert!(!cred.expiring_soon(Duration::from_secs(10)));
    }

    #[test]
    fn register_validate() {
        let mgr = CredentialRotationManager::new(RotationConfig::default());
        let cred = make_cred(CredentialKind::LongTerm, None);
        let key = cred.integrity_key.clone();

        mgr.register("a1", "alice", cred);
        assert_eq!(
            mgr.validate("a1", |k| k == &key),
            ValidateResult::Valid {
                in_grace_period: false
            }
        );
    }

    #[test]
    fn rotation_both_work() {
        let mgr = CredentialRotationManager::new(RotationConfig::default());

        let old = CredentialEntry {
            integrity_key: vec![1, 1, 1],
            ..make_cred(CredentialKind::TimeLimited, Some(Duration::from_secs(300)))
        };
        let old_key = old.integrity_key.clone();
        mgr.register("a1", "alice", old);

        let new = CredentialEntry {
            integrity_key: vec![2, 2, 2],
            ..make_cred(CredentialKind::TimeLimited, Some(Duration::from_secs(600)))
        };
        let new_key = new.integrity_key.clone();
        mgr.rotate("a1", new);

        assert_eq!(
            mgr.validate("a1", |k| k == &old_key),
            ValidateResult::Valid {
                in_grace_period: false
            }
        );
        assert_eq!(
            mgr.validate("a1", |k| k == &new_key),
            ValidateResult::Valid {
                in_grace_period: false
            }
        );
    }

    #[test]
    fn unknown_allocation() {
        let mgr = CredentialRotationManager::new(RotationConfig::default());
        assert_eq!(
            mgr.validate("nope", |_| true),
            ValidateResult::AllocationNotFound
        );
    }

    #[test]
    fn collect_expiring() {
        let mgr = CredentialRotationManager::new(RotationConfig {
            pre_expiry_notify: Duration::from_secs(60),
            ..Default::default()
        });
        let cred = make_cred(CredentialKind::TimeLimited, Some(Duration::from_secs(30)));
        mgr.register("a1", "alice", cred);

        let expiring = mgr.collect_expiring();
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].allocation_id, "a1");

        // Second call: already notified
        let expiring2 = mgr.collect_expiring();
        assert!(expiring2.is_empty());
    }

    #[test]
    fn cleanup() {
        let mgr = CredentialRotationManager::new(RotationConfig {
            grace_period: Duration::from_millis(5),
            ..Default::default()
        });
        let cred = make_cred(CredentialKind::TimeLimited, Some(Duration::from_millis(1)));
        mgr.register("a1", "alice", cred);

        std::thread::sleep(Duration::from_millis(20));
        let cleaned = mgr.cleanup();
        assert_eq!(cleaned, 1);
        assert_eq!(mgr.allocation_count(), 0);
    }
}
