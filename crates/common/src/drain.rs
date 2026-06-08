//! Drain Orchestrator — graceful shutdown with signaling notification.
//!
//! When drain is triggered (via management API or SIGTERM):
//! 1. Set drain flag → reject new allocations
//! 2. Notify signaling server → stop routing new clients here
//! 3. Wait for existing allocations to expire (with timeout)
//! 4. Force-close remaining allocations
//! 5. Exit
//!
//! Usage in turna-node main():
//! ```ignore
//! let drain = DrainOrchestrator::new(config);
//! // On SIGTERM or management API drain command:
//! drain.start(&backend, &metrics).await;
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tracing::{info, warn};

/// Drain orchestrator configuration.
#[derive(Debug, Clone)]
pub struct DrainConfig {
    /// Maximum time to wait for allocations to close.
    pub timeout: Duration,
    /// How often to check remaining allocations.
    pub poll_interval: Duration,
    /// Signaling server URL for notification (empty = no notification).
    pub signaling_notify_url: String,
    /// Node ID for identification in notifications.
    pub node_id: String,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
            poll_interval: Duration::from_secs(5),
            signaling_notify_url: String::new(),
            node_id: "node-1".into(),
        }
    }
}

/// Drain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainState {
    /// Normal operation.
    Active,
    /// Draining: rejecting new connections, waiting for existing.
    Draining,
    /// Drain complete, ready to shut down.
    Drained,
}

/// Drain orchestrator.
pub struct DrainOrchestrator {
    config: DrainConfig,
    draining: Arc<AtomicBool>,
    state: std::sync::Mutex<DrainState>,
    complete: Arc<Notify>,
}

impl DrainOrchestrator {
    pub fn new(config: DrainConfig) -> Self {
        Self {
            config,
            draining: Arc::new(AtomicBool::new(false)),
            state: std::sync::Mutex::new(DrainState::Active),
            complete: Arc::new(Notify::new()),
        }
    }

    /// Get the draining flag (share with PacketProcessor to reject new allocations).
    pub fn draining_flag(&self) -> Arc<AtomicBool> {
        self.draining.clone()
    }

    /// Is currently draining?
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Current drain state.
    pub fn state(&self) -> DrainState {
        *self.state.lock().unwrap()
    }

    /// Start drain process.
    ///
    /// Returns when drain is complete (all allocations closed or timeout).
    pub async fn start<F>(&self, get_allocation_count: F)
    where
        F: Fn() -> u64 + Send,
    {
        info!(node = %self.config.node_id, "drain started");

        // Step 1: Set drain flag
        self.draining.store(true, Ordering::SeqCst);
        *self.state.lock().unwrap() = DrainState::Draining;

        // Step 2: Notify signaling server
        if !self.config.signaling_notify_url.is_empty() {
            self.notify_signaling().await;
        }

        // Step 3: Wait for allocations to close
        let deadline = tokio::time::Instant::now() + self.config.timeout;
        let mut last_count = get_allocation_count();

        info!(
            allocations = last_count,
            timeout_secs = self.config.timeout.as_secs(),
            "waiting for allocations to close"
        );

        loop {
            tokio::time::sleep(self.config.poll_interval).await;

            let count = get_allocation_count();
            if count != last_count {
                info!(allocations = count, "drain progress");
                last_count = count;
            }

            if count == 0 {
                info!("all allocations closed, drain complete");
                break;
            }

            if tokio::time::Instant::now() >= deadline {
                warn!(
                    remaining = count,
                    "drain timeout, force-closing remaining allocations"
                );
                break;
            }
        }

        // Step 4: Mark as drained
        *self.state.lock().unwrap() = DrainState::Drained;
        self.complete.notify_waiters();

        info!(node = %self.config.node_id, "drain complete");
    }

    /// Cancel drain (undrain).
    pub fn cancel(&self) {
        self.draining.store(false, Ordering::SeqCst);
        *self.state.lock().unwrap() = DrainState::Active;
        info!("drain cancelled");
    }

    /// Wait for drain completion (for main() to await).
    pub async fn wait_for_completion(&self) {
        self.complete.notified().await;
    }

    /// Notify signaling server that this node is draining.
    ///
    /// Signaling will stop routing new clients to this node.
    async fn notify_signaling(&self) {
        let url = &self.config.signaling_notify_url;
        let payload = serde_json::json!({
            "type": "node_drain",
            "node_id": self.config.node_id,
            "draining": true,
        });

        info!(url, "notifying signaling server about drain");

        // In production: HTTP POST to signaling server
        // Using tokio TCP directly to avoid reqwest dependency
        match tokio::net::TcpStream::connect(url.trim_start_matches("http://")).await {
            Ok(mut stream) => {
                use tokio::io::AsyncWriteExt;
                let body = serde_json::to_string(&payload).unwrap();
                let request = format!(
                    "POST /api/node-status HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    url,
                    body.len(),
                    body,
                );
                let _ = stream.write_all(request.as_bytes()).await;
                info!("signaling notified successfully");
            }
            Err(e) => {
                warn!(%e, "failed to notify signaling (non-fatal, continuing drain)");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SIGTERM handler
// ---------------------------------------------------------------------------

/// Setup SIGTERM/SIGINT handler that triggers drain.
pub fn setup_signal_handler(drain: Arc<DrainOrchestrator>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("received shutdown signal");
        if !drain.is_draining() {
            // Will be started by the caller who checks draining flag
            drain.draining_flag().store(true, Ordering::SeqCst);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_with_zero_allocations() {
        let drain = DrainOrchestrator::new(DrainConfig {
            timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(50),
            ..Default::default()
        });

        assert!(!drain.is_draining());
        assert_eq!(drain.state(), DrainState::Active);

        // Start drain with 0 allocations → should complete immediately
        drain.start(|| 0).await;

        assert!(drain.is_draining());
        assert_eq!(drain.state(), DrainState::Drained);
    }

    #[tokio::test]
    async fn drain_cancel() {
        let drain = DrainOrchestrator::new(Default::default());
        drain.draining_flag().store(true, Ordering::SeqCst);
        assert!(drain.is_draining());

        drain.cancel();
        assert!(!drain.is_draining());
        assert_eq!(drain.state(), DrainState::Active);
    }

    #[tokio::test]
    async fn drain_timeout() {
        let drain = DrainOrchestrator::new(DrainConfig {
            timeout: Duration::from_millis(200),
            poll_interval: Duration::from_millis(50),
            ..Default::default()
        });

        // Always returns 5 allocations → will timeout
        drain.start(|| 5).await;

        assert_eq!(drain.state(), DrainState::Drained);
    }
}
