//! Session Migration — перенос аллокаций между TURN-нодами
//!
//! - Нода падает → сессии переезжают
//! - Drain → плановый вывод ноды
//! - Rebalance → разгрузка hot ноды
//!
//! Сериализация через JSON (serde_json из вызывающего кода, если нужен).
//! Здесь — только координация и state machine.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("target rejected: {0}")]
    TargetRejected(String),
    #[error("port {0} unavailable on target")]
    PortUnavailable(u16),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("allocation {0} not found")]
    NotFound(String),
    #[error("already migrating {0}")]
    AlreadyInProgress(String),
    #[error("max concurrent migrations ({0}) reached")]
    MaxConcurrent(usize),
}

pub type Result<T> = std::result::Result<T, MigrationError>;

// ---------------------------------------------------------------------------
// Migration Payload
// ---------------------------------------------------------------------------

/// Полное состояние аллокации для переноса.
#[derive(Debug, Clone)]
pub struct MigrationPayload {
    pub allocation_id: String,
    pub username: String,
    pub realm: String,
    pub client_addr: SocketAddr,
    pub relay_port: u16,
    pub transport: String,
    pub integrity_key: Vec<u8>,
    pub remaining_lifetime: u32,
    /// peer_addr → remaining seconds.
    pub permissions: HashMap<SocketAddr, u32>,
    /// channel_number → (peer_addr, remaining seconds).
    pub channels: HashMap<u16, (SocketAddr, u32)>,
    pub organization: Option<String>,
    pub source_node_id: String,
    pub source_node_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub allocation_id: String,
    pub success: bool,
    pub new_relay_addr: Option<SocketAddr>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Reason
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationReason {
    NodeFailure,
    Drain,
    Rebalance,
    Manual,
}

// ---------------------------------------------------------------------------
// Coordinator (source node)
// ---------------------------------------------------------------------------

pub struct MigrationCoordinator {
    in_progress: HashMap<String, MigrationStatus>,
    default_timeout: Duration,
    max_concurrent: usize,
}

#[derive(Debug, Clone)]
// Reserved for the in-progress live-migration tracking feature; the type is
// constructed by code paths not yet enabled in this build.
#[allow(dead_code)]
struct MigrationStatus {
    target_node: String,
    reason: MigrationReason,
    started_at: Instant,
}

impl MigrationCoordinator {
    pub fn new(max_concurrent: usize, default_timeout: Duration) -> Self {
        Self {
            in_progress: HashMap::new(),
            default_timeout,
            max_concurrent,
        }
    }

    pub fn start(
        &mut self,
        allocation_id: &str,
        target_node: &str,
        reason: MigrationReason,
    ) -> Result<()> {
        if self.in_progress.contains_key(allocation_id) {
            return Err(MigrationError::AlreadyInProgress(allocation_id.into()));
        }
        if self.in_progress.len() >= self.max_concurrent {
            return Err(MigrationError::MaxConcurrent(self.max_concurrent));
        }

        self.in_progress.insert(
            allocation_id.to_string(),
            MigrationStatus {
                target_node: target_node.to_string(),
                reason,
                started_at: Instant::now(),
            },
        );

        info!(
            alloc = allocation_id,
            target = target_node,
            ?reason,
            "migration started"
        );
        Ok(())
    }

    pub fn complete(&mut self, allocation_id: &str, success: bool) {
        if let Some(status) = self.in_progress.remove(allocation_id) {
            let ms = status.started_at.elapsed().as_millis();
            if success {
                info!(
                    alloc = allocation_id,
                    elapsed_ms = ms,
                    "migration completed"
                );
            } else {
                warn!(alloc = allocation_id, elapsed_ms = ms, "migration failed");
            }
        }
    }

    pub fn cleanup_timed_out(&mut self) -> Vec<String> {
        let timeout = self.default_timeout;
        let timed_out: Vec<String> = self
            .in_progress
            .iter()
            .filter(|(_, s)| s.started_at.elapsed() > timeout)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &timed_out {
            self.in_progress.remove(id);
            warn!(alloc = id, "migration timed out");
        }

        timed_out
    }

    pub fn in_progress_count(&self) -> usize {
        self.in_progress.len()
    }
    pub fn is_migrating(&self, allocation_id: &str) -> bool {
        self.in_progress.contains_key(allocation_id)
    }
}

// ---------------------------------------------------------------------------
// Drain Manager
// ---------------------------------------------------------------------------

/// Управляет плановым выводом ноды.
pub struct DrainManager {
    coordinator: MigrationCoordinator,
    draining: bool,
    pending: Vec<String>,
    completed: Vec<String>,
    failed: Vec<(String, String)>,
}

impl DrainManager {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            coordinator: MigrationCoordinator::new(max_concurrent, Duration::from_secs(60)),
            draining: false,
            pending: Vec::new(),
            completed: Vec::new(),
            failed: Vec::new(),
        }
    }

    /// Начинает drain.
    pub fn start_drain(&mut self, allocation_ids: Vec<String>) {
        self.draining = true;
        self.pending = allocation_ids;
        self.completed.clear();
        self.failed.clear();
        info!(total = self.pending.len(), "drain started");
    }

    /// Следующая аллокация для миграции.
    pub fn next_to_migrate(&mut self) -> Option<String> {
        if !self.draining || self.pending.is_empty() {
            return None;
        }
        if self.coordinator.in_progress_count() >= self.coordinator.max_concurrent {
            return None;
        }
        Some(self.pending.remove(0))
    }

    pub fn on_result(&mut self, allocation_id: &str, success: bool, error: Option<String>) {
        self.coordinator.complete(allocation_id, success);
        if success {
            self.completed.push(allocation_id.to_string());
        } else {
            self.failed
                .push((allocation_id.to_string(), error.unwrap_or_default()));
        }
    }

    pub fn is_complete(&self) -> bool {
        self.draining && self.pending.is_empty() && self.coordinator.in_progress_count() == 0
    }

    pub fn progress(&self) -> DrainProgress {
        DrainProgress {
            total: self.pending.len()
                + self.completed.len()
                + self.failed.len()
                + self.coordinator.in_progress_count(),
            pending: self.pending.len(),
            in_progress: self.coordinator.in_progress_count(),
            completed: self.completed.len(),
            failed: self.failed.len(),
        }
    }

    /// Доступ к координатору (для start/complete).
    pub fn coordinator_mut(&mut self) -> &mut MigrationCoordinator {
        &mut self.coordinator
    }
}

#[derive(Debug, Clone)]
pub struct DrainProgress {
    pub total: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub completed: usize,
    pub failed: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_lifecycle() {
        let mut c = MigrationCoordinator::new(5, Duration::from_secs(30));
        c.start("a1", "node-2", MigrationReason::Drain).unwrap();
        assert!(c.is_migrating("a1"));
        assert_eq!(c.in_progress_count(), 1);

        c.complete("a1", true);
        assert!(!c.is_migrating("a1"));
        assert_eq!(c.in_progress_count(), 0);
    }

    #[test]
    fn duplicate_rejected() {
        let mut c = MigrationCoordinator::new(5, Duration::from_secs(30));
        c.start("a1", "n2", MigrationReason::Rebalance).unwrap();
        assert!(c.start("a1", "n3", MigrationReason::Rebalance).is_err());
    }

    #[test]
    fn max_concurrent() {
        let mut c = MigrationCoordinator::new(2, Duration::from_secs(30));
        c.start("a1", "n2", MigrationReason::Drain).unwrap();
        c.start("a2", "n2", MigrationReason::Drain).unwrap();
        assert!(c.start("a3", "n2", MigrationReason::Drain).is_err());
    }

    #[test]
    fn drain_progress() {
        let mut dm = DrainManager::new(2);
        dm.start_drain(vec!["a1".into(), "a2".into(), "a3".into()]);

        let p = dm.progress();
        assert_eq!(p.total, 3);
        assert_eq!(p.pending, 3);

        let next = dm.next_to_migrate().unwrap();
        assert_eq!(next, "a1");

        dm.coordinator_mut()
            .start("a1", "n2", MigrationReason::Drain)
            .unwrap();
        dm.on_result("a1", true, None);

        let p = dm.progress();
        assert_eq!(p.completed, 1);
        assert_eq!(p.pending, 2);
    }

    #[test]
    fn drain_complete() {
        let mut dm = DrainManager::new(10);
        dm.start_drain(vec!["a1".into()]);

        let id = dm.next_to_migrate().unwrap();
        dm.coordinator_mut()
            .start(&id, "n2", MigrationReason::Drain)
            .unwrap();
        dm.on_result(&id, true, None);

        assert!(dm.is_complete());
    }
}
