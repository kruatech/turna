//! Failover claim task.
//!
//! Periodically scans the cluster for nodes whose heartbeats have aged
//! out and reclaims their allocations to this node via the new
//! `Backend::claim_allocation` CAS primitive. Successfully claimed
//! allocations are rehydrated into the local `AllocationStore` so that
//! the next request from the affected client lands on us.
//!
//! See `docs/design/allocation-store-persistence.md` §4 ("Failover claim")
//! and §9 ("Open questions") for the rationale and caveats.
//!
//! # Algorithm (one sweep)
//!
//! 1. Ask the backend for all nodes ever seen (`max_age` = very large)
//!    and all currently live nodes (`max_age` = `live_window`).
//! 2. Dead set = (all − live − myself).
//! 3. For each dead node:
//!    a. `find_by_node(dead_id)` → list of orphan allocations.
//!    b. For each orphan: `claim_allocation(port, dead_id, my_id)`.
//!    c. On a successful claim, refetch the now-updated `StoredAllocation`
//!    and call `bulk_load::apply_one` to rehydrate it locally.
//!    d. If rehydrate fails (e.g. our own port range conflict), revert
//!    the claim via `claim_allocation(port, my_id, dead_id)`. Better
//!    to leave the orphan in place than corrupt local state.
//!
//! # What this does NOT do
//!
//! - **No clock-skew compensation.** We rely on `last_seen_ms` being a
//!   reasonable wall-clock estimate from each node. NTP-class skew (<1s)
//!   is well within the `live_window` margin. If two nodes' clocks are
//!   minutes apart, the older one might be mis-classified as dead — but
//!   the CAS still keeps us safe (it'll just spin trying to claim
//!   allocations that the "alive" node keeps re-asserting via its own
//!   heartbeats).
//!
//! - **No lease leases.** Once we claim, the allocation is ours until
//!   we remove it or another node decides we're dead. There is no
//!   "soft lease" that auto-expires.
//!
//! - **No retry on transient backend errors.** A failed sweep is a
//!   one-tick gap. The next sweep tries again from scratch.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use turna_health::Metrics;
use turna_session::AllocationStore;
use turna_state_backend::Backend;

use crate::bulk_load;

#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Our node id. Allocations belonging to other nodes are candidates;
    /// our own are not.
    pub node_id: String,
    /// How often to run a full sweep.
    pub sweep_interval: Duration,
    /// A peer node is considered alive if its `last_seen_ms` is within
    /// this many seconds of `now`. Should be ≥ 3× the heartbeat interval
    /// to tolerate a few missed beats without triggering false failover.
    pub live_window: Duration,
    /// Consecutive stale sweeps a peer must accumulate before it is declared
    /// dead and its allocations are claimed (≥1). Debounces a single missed
    /// heartbeat so a tight `live_window` does not cause false failover.
    pub suspicion_ticks: u32,
}

/// Default sweep cadence — every 1s. With a 1s heartbeat and a 3s live
/// window, a dead node is confirmed within roughly
/// `live_window + suspicion_ticks × sweep_interval` ≈ 3s + 2×1s = 5s.
#[allow(dead_code)]
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Default "live" window — 3s (a peer is stale after ~3 missed 1s beats).
#[allow(dead_code)]
pub const DEFAULT_LIVE_WINDOW: Duration = Duration::from_secs(3);
/// Default suspicion debounce — confirm dead only after 2 consecutive stale
/// sweeps, so a single dropped heartbeat never triggers failover.
#[allow(dead_code)]
pub const DEFAULT_SUSPICION_TICKS: u32 = 2;

/// `max_age` parameter for `get_live_nodes` when we want to enumerate
/// *every* node that has ever sent a heartbeat. The in-memory backend
/// uses `saturating_sub`, so anything large works; we pick something
/// concrete and obviously huge for readability.
const ALL_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 100);

/// Counters useful for tests and for surfacing on `/metrics` in a
/// follow-up PR. Not wired into `turna_health::Metrics` here to keep this
/// PR small.
#[derive(Debug, Default)]
pub struct FailoverStats {
    pub sweeps: u64,
    pub dead_nodes_seen: u64,
    pub orphans_seen: u64,
    pub claimed: u64,
    pub claim_lost_race: u64,
    pub claim_revert_attempted: u64,
    pub backend_errors: u64,
}

/// Run the failover task to completion. Returns when `shutdown_rx`
/// flips to `true`.
pub async fn run_failover(
    backend: Arc<Backend>,
    store: Arc<AllocationStore>,
    cfg: FailoverConfig,
    metrics: Arc<Metrics>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> FailoverStats {
    info!(
        node_id        = %cfg.node_id,
        sweep_interval = ?cfg.sweep_interval,
        live_window    = ?cfg.live_window,
        "failover task started"
    );

    let mut stats = FailoverStats::default();
    // Per-peer consecutive-stale counters for the suspicion debounce.
    let mut suspicion: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut ticker = interval(cfg.sweep_interval);
    // Same rationale as heartbeat: don't replay missed ticks.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    info!(?stats, "failover task exiting on shutdown");
                    return stats;
                }
            }

            _ = ticker.tick() => {
                // Snapshot counters before sweep to compute deltas after.
                let prev_claimed = stats.claimed;
                let prev_lost    = stats.claim_lost_race;
                let prev_errors  = stats.backend_errors;

                let sweep_start = std::time::Instant::now();
                if let Err(e) = sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion).await {
                    stats.backend_errors += 1;
                    warn!(error = ?e, "failover: sweep failed");
                }
                let elapsed_us = sweep_start.elapsed().as_micros() as u64;

                // Propagate deltas to shared Prometheus metrics.
                use std::sync::atomic::Ordering;
                metrics.failover_claimed_total.fetch_add(
                    stats.claimed - prev_claimed, Ordering::Relaxed);
                metrics.failover_lost_race_total.fetch_add(
                    stats.claim_lost_race - prev_lost, Ordering::Relaxed);
                metrics.failover_errors_total.fetch_add(
                    stats.backend_errors - prev_errors, Ordering::Relaxed);
                metrics.failover_sweep_duration_us.store(elapsed_us, Ordering::Relaxed);
            }
        }
    }
}

/// One pass. Public-ish for tests; not exposed beyond the crate.
pub(crate) async fn sweep_once(
    backend: &Arc<Backend>,
    store: &Arc<AllocationStore>,
    cfg: &FailoverConfig,
    stats: &mut FailoverStats,
    suspicion: &mut std::collections::HashMap<String, u32>,
) -> Result<(), turna_state_backend::BackendError> {
    stats.sweeps += 1;

    let all = backend.get_live_nodes(ALL_TIME).await?;
    let live = backend.get_live_nodes(cfg.live_window).await?;

    use std::collections::HashSet;
    let live_ids: HashSet<&str> = live.iter().map(|n| n.node_id.as_str()).collect();
    let me = cfg.node_id.as_str();

    // Nodes whose LAST heartbeat announced `draining = true`. A draining node
    // is leaving on purpose, so once it goes stale we can claim it immediately
    // without the suspicion debounce — there is no false-positive risk. `all`
    // carries each node's most recent heartbeat, including the final draining
    // one emitted on shutdown.
    let draining_ids: HashSet<&str> = all
        .iter()
        .filter(|n| n.draining)
        .map(|n| n.node_id.as_str())
        .collect();

    // Nodes that look stale on THIS sweep: seen at some point, not currently
    // live, and not us.
    let stale: Vec<String> = all
        .iter()
        .map(|n| n.node_id.clone())
        .filter(|id| id.as_str() != me && !live_ids.contains(id.as_str()))
        .collect();

    // Suspicion debounce: a peer must stay stale for `suspicion_ticks`
    // consecutive sweeps before we treat it as dead. This keeps the live
    // window tight without a single dropped heartbeat causing a false
    // failover. Counters for peers that are no longer stale are dropped
    // (a recovered peer starts again from zero).
    let stale_set: HashSet<String> = stale.iter().cloned().collect();
    suspicion.retain(|id, _| stale_set.contains(id));
    for id in &stale {
        *suspicion.entry(id.clone()).or_insert(0) += 1;
    }
    let ticks = cfg.suspicion_ticks.max(1);

    // A stale node is "confirmed dead" if it cleared the suspicion threshold,
    // OR it had announced draining (explicit goodbye → claim on first sight).
    let dead: Vec<&str> = stale
        .iter()
        .filter(|id| {
            draining_ids.contains(id.as_str()) || suspicion.get(*id).copied().unwrap_or(0) >= ticks
        })
        .map(|s| s.as_str())
        .collect();

    if dead.is_empty() {
        debug!("failover: no confirmed-dead nodes this sweep");
        return Ok(());
    }
    stats.dead_nodes_seen += dead.len() as u64;
    info!(dead_count = dead.len(), "failover: confirmed-dead nodes");

    for dead_id in dead {
        let orphans = match backend.find_by_node(dead_id).await {
            Ok(o) => o,
            Err(e) => {
                stats.backend_errors += 1;
                warn!(dead_id, error = ?e, "failover: find_by_node failed; skipping this node");
                continue;
            }
        };
        stats.orphans_seen += orphans.len() as u64;

        for stored in orphans {
            let port = stored.relay_port;
            let claimed = match backend.claim_allocation(port, dead_id, &cfg.node_id).await {
                Ok(c) => c,
                Err(e) => {
                    stats.backend_errors += 1;
                    warn!(port, dead_id, error = ?e, "failover: claim CAS errored");
                    continue;
                }
            };
            if !claimed {
                stats.claim_lost_race += 1;
                debug!(
                    port,
                    dead_id, "failover: claim lost (already taken or vanished)"
                );
                continue;
            }

            // We won the CAS — fetch the now-updated record (with our
            // node_id stamped) and rehydrate it locally. We refetch
            // rather than reuse `stored` so a concurrent update wins
            // last-write semantics consistently.
            let fresh = match backend.get_allocation(port).await {
                Ok(Some(a)) => a,
                Ok(None) => {
                    warn!(
                        port,
                        "failover: claimed allocation vanished before re-fetch"
                    );
                    // Nothing to revert — the row is gone.
                    continue;
                }
                Err(e) => {
                    stats.backend_errors += 1;
                    warn!(port, error = ?e, "failover: re-fetch after claim failed");
                    // Leave the row claimed; next sweep will catch up.
                    continue;
                }
            };

            match bulk_load::apply_one(store, &fresh) {
                Ok(true) => {
                    stats.claimed += 1;
                    info!(port, dead_id, "failover: rehydrated claimed allocation");
                }
                Ok(false) => {
                    // Expired in flight. Just delete it; the dead node
                    // can't write it back.
                    let _ = backend.remove_allocation(port).await;
                    debug!(port, "failover: claimed record was expired, removed");
                }
                Err(reason) => {
                    // Rehydrate refused (e.g. port already used locally,
                    // or quota exceeded). We do NOT want to leave the
                    // record stamped with our id — another live node
                    // could pick it up after this one dies. Revert.
                    stats.claim_revert_attempted += 1;
                    warn!(
                        port,
                        dead_id, reason, "failover: rehydrate refused; reverting claim"
                    );
                    if let Err(e) = backend.claim_allocation(port, &cfg.node_id, dead_id).await {
                        // We tried. The orphan stays in our name but
                        // not in our memory — the next sweep on another
                        // node (or our own next attempt) can retry.
                        stats.backend_errors += 1;
                        warn!(port, error = ?e, "failover: revert CAS failed");
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use turna_state_backend::{
        create_backend, BackendConfig, NodeHeartbeat, StoredAllocation, StoredChannel,
    };

    fn now_ms() -> u64 {
        turna_session::epoch_ms()
    }

    fn live_hb(node_id: &str) -> NodeHeartbeat {
        NodeHeartbeat {
            node_id: node_id.into(),
            addr: "10.0.0.1:3478".into(),
            active_allocations: 0,
            total_bandwidth_bps: 0,
            cpu_usage_pct: 0.0,
            memory_usage_pct: 0.0,
            uptime_secs: 60,
            version: "test".into(),
            last_seen_ms: now_ms(),
            draining: false,
        }
    }

    fn stale_hb(node_id: &str) -> NodeHeartbeat {
        NodeHeartbeat {
            last_seen_ms: now_ms().saturating_sub(120_000), // 2 min ago — dead
            ..live_hb(node_id)
        }
    }

    fn alloc_for(node: &str, port: u16) -> StoredAllocation {
        let client_port: u16 = 20_000u16.wrapping_add(port);
        StoredAllocation {
            id: format!("{node}:{port}"),
            relay_port: port,
            client_addr: format!("127.0.0.1:{client_port}"),
            relay_addr: format!("10.0.0.1:{port}"),
            user_id: "alice".into(),
            realm: "turna".into(),
            node_id: node.into(),
            allocation_id: format!("alloc-{node}-{port}"),
            migration_epoch: 5,
            created_at_ms: now_ms().saturating_sub(60_000),
            expires_at_ms: now_ms() + 600_000,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            permissions: vec!["10.0.0.2".into()],
            channels: vec![StoredChannel {
                number: 0x4000,
                peer_addr: "10.0.0.2:9000".into(),
                expires_at_ms: now_ms() + 600_000,
            }],
        }
    }

    async fn fresh() -> (Arc<Backend>, Arc<AllocationStore>) {
        let b = Arc::new(create_backend(&BackendConfig::Memory).await.unwrap());
        let s = Arc::new(AllocationStore::new(40000, 41000, 10_000));
        (b, s)
    }

    fn cfg(node_id: &str) -> FailoverConfig {
        FailoverConfig {
            node_id: node_id.into(),
            sweep_interval: Duration::from_millis(30),
            live_window: Duration::from_secs(60),
            // Existing tests assert claim-on-first-stale-sweep; keep ticks=1.
            suspicion_ticks: 1,
        }
    }

    /// Fresh suspicion map for single-sweep tests.
    fn susp() -> std::collections::HashMap<String, u32> {
        std::collections::HashMap::new()
    }

    /// One dead node, three orphans, fresh local store → all rehydrated.
    #[tokio::test]
    async fn basic_claim_of_three_orphans() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        backend.heartbeat(&stale_hb("node-dead")).await.unwrap();
        for port in [40010, 40011, 40012] {
            backend
                .store_allocation(&alloc_for("node-dead", port))
                .await
                .unwrap();
        }

        let mut stats = FailoverStats::default();
        sweep_once(&backend, &store, &cfg("node-me"), &mut stats, &mut susp())
            .await
            .unwrap();

        assert_eq!(stats.claimed, 3);
        assert_eq!(stats.dead_nodes_seen, 1);
        assert_eq!(stats.orphans_seen, 3);
        // All three should now be tagged as node-me in the backend.
        for port in [40010, 40011, 40012] {
            let a = backend.get_allocation(port).await.unwrap().unwrap();
            assert_eq!(a.node_id, "node-me", "port {port} should be ours");
        }
        // And present in our local store.
        assert_eq!(store.len(), 3);
        // RFC 8016: the adopted allocations must keep their original identity
        // so a MOBILITY-TICKET minted by node-dead validates here.
        let c: std::net::SocketAddr = "127.0.0.1:60010".parse().unwrap(); // 20000 + 40010
        let a = store.get(&c).expect("rehydrated after claim");
        assert_eq!(a.allocation_id, "alloc-node-dead-40010");
        assert_eq!(a.migration_epoch, 5);
        assert_eq!(store.get_by_id("alloc-node-dead-40010"), Some(c));
    }

    /// We don't claim our own allocations.
    #[tokio::test]
    async fn does_not_claim_self() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        backend
            .store_allocation(&alloc_for("node-me", 40020))
            .await
            .unwrap();

        let mut stats = FailoverStats::default();
        sweep_once(&backend, &store, &cfg("node-me"), &mut stats, &mut susp())
            .await
            .unwrap();
        assert_eq!(stats.claimed, 0);
        assert_eq!(stats.dead_nodes_seen, 0);
    }

    /// Live nodes' allocations are left alone.
    #[tokio::test]
    async fn does_not_claim_live_peers() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        backend.heartbeat(&live_hb("node-peer")).await.unwrap();
        backend
            .store_allocation(&alloc_for("node-peer", 40030))
            .await
            .unwrap();

        let mut stats = FailoverStats::default();
        sweep_once(&backend, &store, &cfg("node-me"), &mut stats, &mut susp())
            .await
            .unwrap();

        assert_eq!(stats.claimed, 0);
        let a = backend.get_allocation(40030).await.unwrap().unwrap();
        assert_eq!(
            a.node_id, "node-peer",
            "peer's allocation must not be touched"
        );
    }

    /// CAS race: two survivors call claim concurrently — exactly one wins.
    /// (Single Backend instance shared — that's the realistic case in
    /// production: both nodes talk to the same Tarantool.)
    #[tokio::test]
    async fn cas_serialises_concurrent_claims() {
        let (backend, _) = fresh().await;
        backend
            .store_allocation(&alloc_for("node-dead", 40040))
            .await
            .unwrap();

        let b1 = backend.clone();
        let b2 = backend.clone();
        let t1 =
            tokio::spawn(async move { b1.claim_allocation(40040, "node-dead", "node-A").await });
        let t2 =
            tokio::spawn(async move { b2.claim_allocation(40040, "node-dead", "node-B").await });
        let r1 = t1.await.unwrap().unwrap();
        let r2 = t2.await.unwrap().unwrap();
        assert!(r1 ^ r2, "exactly one of the two CAS attempts must succeed");
        let owner = backend
            .get_allocation(40040)
            .await
            .unwrap()
            .unwrap()
            .node_id;
        assert!(
            owner == "node-A" || owner == "node-B",
            "owner must be one of the contestants, got {owner}"
        );
    }

    /// Rehydrate failure (port already taken locally) → claim is reverted
    /// so another sweep can retry.
    #[tokio::test]
    async fn rehydrate_failure_reverts_claim() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        backend.heartbeat(&stale_hb("node-dead")).await.unwrap();
        backend
            .store_allocation(&alloc_for("node-dead", 40050))
            .await
            .unwrap();

        // Pre-occupy port 40050 locally — rehydrate's reserve() will fail.
        store.ports.reserve(40050).unwrap();

        let mut stats = FailoverStats::default();
        sweep_once(&backend, &store, &cfg("node-me"), &mut stats, &mut susp())
            .await
            .unwrap();

        assert_eq!(
            stats.claimed, 0,
            "rehydrate refused → no claim should be recorded as successful"
        );
        assert!(
            stats.claim_revert_attempted >= 1,
            "we should have attempted a revert"
        );
        // The record should still belong to node-dead so another sweep
        // (or another surviving node) can try again.
        let owner = backend
            .get_allocation(40050)
            .await
            .unwrap()
            .unwrap()
            .node_id;
        assert_eq!(
            owner, "node-dead",
            "failed rehydrate must revert CAS so the orphan stays with the dead node"
        );
    }

    /// A peer going stale is NOT claimed until it has been stale for
    /// `suspicion_ticks` consecutive sweeps.
    #[tokio::test]
    async fn suspicion_debounces_transient_staleness() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        backend.heartbeat(&stale_hb("node-dead")).await.unwrap();
        backend
            .store_allocation(&alloc_for("node-dead", 40060))
            .await
            .unwrap();

        let cfg = FailoverConfig {
            node_id: "node-me".into(),
            sweep_interval: Duration::from_millis(30),
            live_window: Duration::from_secs(60),
            suspicion_ticks: 3, // require 3 consecutive stale sweeps
        };
        let mut suspicion = susp();

        // Sweeps 1 and 2: stale but below threshold → no claim yet.
        for _ in 0..2 {
            let mut stats = FailoverStats::default();
            sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion)
                .await
                .unwrap();
            assert_eq!(stats.claimed, 0, "must not claim before suspicion_ticks");
        }
        // Sweep 3: threshold reached → claim.
        let mut stats = FailoverStats::default();
        sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion)
            .await
            .unwrap();
        assert_eq!(stats.claimed, 1, "claim once suspicion_ticks reached");
        let owner = backend
            .get_allocation(40060)
            .await
            .unwrap()
            .unwrap()
            .node_id;
        assert_eq!(owner, "node-me");
    }

    /// A peer that recovers resets its suspicion counter, so the debounce
    /// restarts rather than accumulating across separate stale gaps.
    #[tokio::test]
    async fn suspicion_resets_when_peer_recovers() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        backend
            .store_allocation(&alloc_for("node-peer", 40070))
            .await
            .unwrap();

        let cfg = FailoverConfig {
            node_id: "node-me".into(),
            sweep_interval: Duration::from_millis(30),
            live_window: Duration::from_secs(60),
            suspicion_ticks: 3,
        };
        let mut suspicion = susp();

        // Peer stale for 2 sweeps (below threshold).
        backend.heartbeat(&stale_hb("node-peer")).await.unwrap();
        for _ in 0..2 {
            let mut stats = FailoverStats::default();
            sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion)
                .await
                .unwrap();
        }
        // Peer recovers → its counter must reset.
        backend.heartbeat(&live_hb("node-peer")).await.unwrap();
        {
            let mut stats = FailoverStats::default();
            sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion)
                .await
                .unwrap();
        }
        assert_eq!(
            suspicion.get("node-peer").copied().unwrap_or(0),
            0,
            "recovered peer's suspicion counter must reset"
        );

        // Goes stale again: needs a fresh full debounce — 2 sweeps must not claim.
        backend.heartbeat(&stale_hb("node-peer")).await.unwrap();
        for _ in 0..2 {
            let mut stats = FailoverStats::default();
            sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion)
                .await
                .unwrap();
            assert_eq!(stats.claimed, 0, "debounce must restart after recovery");
        }
    }

    /// A draining node that has gone stale is claimed immediately, bypassing
    /// the suspicion debounce — draining is an explicit goodbye.
    #[tokio::test]
    async fn draining_node_claimed_immediately() {
        let (backend, store) = fresh().await;
        backend.heartbeat(&live_hb("node-me")).await.unwrap();
        // Final heartbeat: draining + already aged out (the node has exited).
        let bye = NodeHeartbeat {
            draining: true,
            last_seen_ms: now_ms().saturating_sub(120_000),
            ..live_hb("node-dead")
        };
        backend.heartbeat(&bye).await.unwrap();
        backend
            .store_allocation(&alloc_for("node-dead", 40080))
            .await
            .unwrap();

        // High suspicion_ticks would normally need 5 stale sweeps; draining
        // bypasses the debounce.
        let cfg = FailoverConfig {
            node_id: "node-me".into(),
            sweep_interval: Duration::from_millis(30),
            live_window: Duration::from_secs(60),
            suspicion_ticks: 5,
        };
        let mut suspicion = susp();
        let mut stats = FailoverStats::default();
        sweep_once(&backend, &store, &cfg, &mut stats, &mut suspicion)
            .await
            .unwrap();

        assert_eq!(
            stats.claimed, 1,
            "draining node must be claimed on first sweep"
        );
        let owner = backend
            .get_allocation(40080)
            .await
            .unwrap()
            .unwrap()
            .node_id;
        assert_eq!(owner, "node-me");
    }
}
