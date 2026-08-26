//! Node heartbeat task.
//!
//! Periodically publishes `NodeHeartbeat` records to the state backend so
//! that peer nodes can tell we're alive. PR 5 (failover claim) will use
//! the absence of a recent heartbeat as the signal "this node is dead,
//! it's safe to take over its allocations".
//!
//! Design notes:
//!
//! - **Best-effort.** A failed heartbeat is logged and skipped. We never
//!   take down the node because we couldn't reach the backend; the
//!   next tick tries again. From a peer's perspective a dropped
//!   heartbeat is indistinguishable from a network blip, and the
//!   `max_age` window on the peer side (PR 5) is generous enough to
//!   tolerate several misses.
//!
//! - **Wall-clock vs uptime.** `last_seen_ms` uses `epoch_ms()` because
//!   peers compare it to their own wall clock to decide "how stale is
//!   this heartbeat". `uptime_secs` uses `metrics.start_time.elapsed()`
//!   which is monotonic and not affected by clock skew.
//!
//! - **Draining on shutdown.** When `shutdown_rx` flips, we emit one
//!   final heartbeat with `draining = true` and then exit. This lets
//!   peers immediately know we're going away rather than waiting for
//!   our heartbeat to age out — important for fast failover.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use turna_health::Metrics;
use turna_session::epoch_ms;
use turna_state_backend::{Backend, NodeHeartbeat};

/// Configuration for the heartbeat task.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    pub node_id: String,
    /// Unique for this process start. Durable commands are fenced to it so a
    /// command claimed by an older process cannot mutate a restarted node.
    pub incarnation: String,
    /// Address other nodes should use to reach us. Typically
    /// `external_ip:turn_port`. Used by PR 5 failover to know where the
    /// (now-dead) node's clients were routed.
    pub addr: String,
    pub version: String,
    pub interval: Duration,
}

/// Default tick interval — 1s. Paired with the failover live window (default
/// 3s) and the suspicion debounce, this gives ~5s failover detection while
/// tolerating a dropped beat. Overridable via `[cluster.failure_detection]`.
#[allow(dead_code)]
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

fn build_heartbeat(
    cfg: &HeartbeatConfig,
    metrics: &Metrics,
    draining: bool,
    cpu_pct: f32,
    mem_pct: f32,
    bw_bps: u64,
) -> NodeHeartbeat {
    NodeHeartbeat {
        node_id: cfg.node_id.clone(),
        incarnation: cfg.incarnation.clone(),
        addr: cfg.addr.clone(),
        active_allocations: metrics.active_allocations.load(Ordering::Relaxed),
        total_bandwidth_bps: bw_bps,
        cpu_usage_pct: cpu_pct,
        memory_usage_pct: mem_pct,
        uptime_secs: metrics.start_time.elapsed().as_secs(),
        version: cfg.version.clone(),
        last_seen_ms: epoch_ms(),
        draining: draining || metrics.is_draining(),
    }
}

/// Run the heartbeat loop. Returns when `shutdown_rx` flips to `true`.
///
/// One final heartbeat with `draining = true` is sent before exit, even
/// if the backend has been failing recently — best-effort, but we still
/// try.
pub async fn run_heartbeat(
    backend: Arc<Backend>,
    metrics: Arc<Metrics>,
    cfg: HeartbeatConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!(
        node_id  = %cfg.node_id,
        addr     = %cfg.addr,
        version  = %cfg.version,
        interval = ?cfg.interval,
        "heartbeat task started"
    );

    let mut ticker = interval(cfg.interval);
    // If we fall behind (the backend was slow for several seconds),
    // don't try to "make up" — skip ahead. Heartbeats are not cumulative.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut consecutive_errors: u32 = 0;
    // Track byte counters between ticks to compute bandwidth delta.
    let mut prev_bytes: u64 = 0;
    loop {
        tokio::select! {
            biased;

            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    info!("heartbeat: shutdown — sending final draining=true");
                    let hb = build_heartbeat(&cfg, &metrics, /*draining=*/ true,
                                             0.0, 0.0, 0);
                    if let Err(e) = backend.heartbeat(&hb).await {
                        warn!(error = ?e, "heartbeat: final send failed");
                    }
                    return;
                }
            }

            _ = ticker.tick() => {
                // ── Bandwidth delta ──────────────────────────────────────────
                let cur_bytes = metrics.bytes_received.load(Ordering::Relaxed)
                    .saturating_add(metrics.bytes_sent.load(Ordering::Relaxed));
                let bw_bps = ((cur_bytes.saturating_sub(prev_bytes)) as f64
                    / cfg.interval.as_secs_f64() * 8.0) as u64;
                prev_bytes = cur_bytes;

                // ── CPU + memory ─────────────────────────────────────────────
                // Read from the shared sampler rather than taking our own: it
                // keeps a persistent `System` and so measures CPU over its whole
                // interval, where a fresh instance per tick only sees the
                // library's ~100 ms settling window. It also means one /proc
                // reader on a node whose job includes measuring its own load.
                //
                // 0.0 before the first sample lands. The heartbeat is periodic and
                // the next one will carry a real figure; reporting 0 once is
                // better than blocking a heartbeat on a resource read.
                let cpu_pct = metrics.host_cpu().unwrap_or(0) as f32;
                let mem_pct = metrics.host_memory().unwrap_or(0) as f32;

                let hb = build_heartbeat(&cfg, &metrics, /*draining=*/ false,
                                         cpu_pct, mem_pct, bw_bps);
                match backend.heartbeat(&hb).await {
                    Ok(()) => {
                        if consecutive_errors > 0 {
                            info!(
                                recovered_after = consecutive_errors,
                                "heartbeat: backend recovered"
                            );
                        }
                        consecutive_errors = 0;
                        debug!(
                            active = hb.active_allocations,
                            "heartbeat sent"
                        );
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        // Warn-throttle: first failure + every power of two.
                        // Same pattern as the writer's drop logging.
                        if consecutive_errors == 1
                           || consecutive_errors.is_power_of_two() {
                            warn!(
                                consecutive_errors,
                                error = ?e,
                                "heartbeat: backend send failed"
                            );
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use turna_state_backend::{create_backend, BackendConfig};

    fn make_cfg() -> HeartbeatConfig {
        HeartbeatConfig {
            node_id: "test-node".into(),
            incarnation: "test-incarnation".into(),
            addr: "127.0.0.1:3478".into(),
            version: "0.1.0-test".into(),
            interval: Duration::from_millis(30),
        }
    }

    async fn fresh_backend() -> Arc<Backend> {
        Arc::new(create_backend(&BackendConfig::Memory).await.unwrap())
    }

    /// Heartbeat fires on schedule and the backend can see us as live.
    #[tokio::test]
    async fn first_tick_publishes_record() {
        let backend = fresh_backend().await;
        let metrics = Arc::new(Metrics::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        let bk = backend.clone();
        let mt = metrics.clone();
        let cfg = make_cfg();
        let handle = tokio::spawn(async move {
            run_heartbeat(bk, mt, cfg, sd_rx).await;
        });

        // Wait long enough for at least 2 ticks (30ms each).
        tokio::time::sleep(Duration::from_millis(100)).await;

        let live = backend
            .get_live_nodes(Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(live.len(), 1, "exactly one node should be live");
        assert_eq!(live[0].node_id, "test-node");
        assert_eq!(live[0].addr, "127.0.0.1:3478");
        assert_eq!(live[0].version, "0.1.0-test");
        assert!(!live[0].draining, "live node must not be draining");

        sd_tx.send(true).unwrap();
        handle.await.unwrap();
    }

    /// Shutdown emits one last heartbeat with draining=true.
    #[tokio::test]
    async fn shutdown_publishes_draining_true() {
        let backend = fresh_backend().await;
        let metrics = Arc::new(Metrics::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        let bk = backend.clone();
        let mt = metrics.clone();
        // Use a long interval so the ticker doesn't fire on its own;
        // we want to assert exclusively on the shutdown path.
        let cfg = HeartbeatConfig {
            interval: Duration::from_secs(60),
            ..make_cfg()
        };
        let handle = tokio::spawn(async move {
            run_heartbeat(bk, mt, cfg, sd_rx).await;
        });

        // Give the task a moment to enter its select loop.
        tokio::time::sleep(Duration::from_millis(20)).await;
        sd_tx.send(true).unwrap();
        handle.await.unwrap();

        let live = backend
            .get_live_nodes(Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(live.len(), 1, "shutdown should still produce a record");
        assert!(
            live[0].draining,
            "final heartbeat must mark the node as draining"
        );
    }

    /// `active_allocations` reflects the live `Metrics` value at the
    /// moment of each tick — not a snapshot captured at task startup.
    #[tokio::test]
    async fn active_allocations_is_read_per_tick() {
        let backend = fresh_backend().await;
        let metrics = Arc::new(Metrics::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        let bk = backend.clone();
        let mt = metrics.clone();
        let cfg = make_cfg();
        let handle = tokio::spawn(async move {
            run_heartbeat(bk, mt, cfg, sd_rx).await;
        });

        // Let one heartbeat go through with 0 allocations.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let first = backend
            .get_live_nodes(Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(first[0].active_allocations, 0);

        // Bump the gauge, wait for the next tick.
        metrics.active_allocations.store(42, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(70)).await;
        let second = backend
            .get_live_nodes(Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            second[0].active_allocations, 42,
            "tick must read current metric value, not startup snapshot"
        );

        sd_tx.send(true).unwrap();
        handle.await.unwrap();
    }

    /// `set_draining(true)` on Metrics propagates into the next
    /// heartbeat even if `shutdown_rx` hasn't flipped yet.
    #[tokio::test]
    async fn metrics_draining_flag_is_reflected() {
        let backend = fresh_backend().await;
        let metrics = Arc::new(Metrics::new());
        let (sd_tx, sd_rx) = watch::channel(false);

        let bk = backend.clone();
        let mt = metrics.clone();
        let cfg = make_cfg();
        let handle = tokio::spawn(async move {
            run_heartbeat(bk, mt, cfg, sd_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(40)).await;
        let before = backend
            .get_live_nodes(Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!before[0].draining);

        metrics.set_draining(true);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let after = backend
            .get_live_nodes(Duration::from_secs(10))
            .await
            .unwrap();
        assert!(
            after[0].draining,
            "Metrics::set_draining must show up in subsequent heartbeats"
        );

        sd_tx.send(true).unwrap();
        handle.await.unwrap();
    }
}
