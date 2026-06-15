//! `TurnCoreImpl` — concrete implementation of `TurnCore` backed by
//! `AllocationStore` (turna-session) and `Metrics` (turna-health).
//!
//! Wire it up in `turna-node/main.rs`:
//! ```ignore
//! let core = Arc::new(TurnCoreImpl::new(
//!     store.clone(),
//!     metrics.clone(),
//!     shutdown_tx.clone(),
//! ));
//! tokio::spawn(start_grpc_server(GrpcConfig::default(), core));
//! ```

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use turna_health::Metrics;
use turna_session::AllocationStore;

use crate::grpc::{
    AllocationEvent, AllocationInfo, ChannelInfo, ConfigUpdate, CoreError, CurrentConfig,
    EventType, ServerStatsInfo, TopTalkerInfo, TurnCore,
};

// ── TurnCoreImpl ──────────────────────────────────────────────────────────────

pub struct TurnCoreImpl {
    store: Arc<AllocationStore>,
    metrics: Arc<Metrics>,
    /// Broadcast channel for streaming `WatchAllocations` updates.
    events_tx: broadcast::Sender<AllocationEvent>,
    /// Sends shutdown signal to the relay server.
    shutdown_tx: watch::Sender<bool>,
    /// Server start time for uptime calculation.
    started_at: Instant,
    /// Runtime-mutable config fields.
    config: Arc<std::sync::RwLock<RuntimeConfig>>,
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    realm: String,
    external_ipv4: String,
    listen_addresses: Vec<String>,
    min_port: u32,
    max_port: u32,
    default_lifetime: u32,
    max_lifetime: u32,
    max_allocations_per_user: u32,
    max_bandwidth_per_user_bps: u64,
    nonce_lifetime_seconds: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            realm: "turna".into(),
            external_ipv4: "0.0.0.0".into(),
            listen_addresses: vec!["0.0.0.0:3478".into()],
            min_port: 49152,
            max_port: 65535,
            default_lifetime: 600,
            max_lifetime: 3600,
            max_allocations_per_user: 10,
            max_bandwidth_per_user_bps: 0,
            nonce_lifetime_seconds: 600,
        }
    }
}

impl TurnCoreImpl {
    pub fn new(
        store: Arc<AllocationStore>,
        metrics: Arc<Metrics>,
        shutdown_tx: watch::Sender<bool>,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(1024);
        Self {
            store,
            metrics,
            events_tx,
            shutdown_tx,
            started_at: Instant::now(),
            config: Arc::new(std::sync::RwLock::new(RuntimeConfig::default())),
        }
    }

    /// Configure initial values from node config.
#[allow(clippy::too_many_arguments)]
    pub fn with_config(
        self,
        realm: impl Into<String>,
        external_ip: impl Into<String>,
        listen_addrs: Vec<String>,
        min_port: u32,
        max_port: u32,
        default_lifetime: u32,
        max_lifetime: u32,
    ) -> Self {
        {
            let mut cfg = self.config.write().unwrap();
            cfg.realm = realm.into();
            cfg.external_ipv4 = external_ip.into();
            cfg.listen_addresses = listen_addrs;
            cfg.min_port = min_port;
            cfg.max_port = max_port;
            cfg.default_lifetime = default_lifetime;
            cfg.max_lifetime = max_lifetime;
        }
        self
    }

    /// Publish an allocation event to all `WatchAllocations` subscribers.
    pub fn emit_event(&self, kind: EventType, alloc: AllocationInfo, reason: Option<String>) {
        let ev = AllocationEvent {
            event_type: kind,
            allocation: alloc,
            reason,
        };
        // Ignore send errors — no subscribers is normal.
        let _ = self.events_tx.send(ev);
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn all_allocations(&self) -> Vec<AllocationInfo> {
        self.store
            .iter_all()
            .map(|a| AllocationInfo {
                id: a.relay_addr.to_string(),
                username: a.username.clone(),
                realm: self.config.read().unwrap().realm.clone(),
                client_address: a.client_addr,
                relay_address: a.relay_addr,
                created_at_ms: instant_to_ms(a.created_at),
                expires_at_ms: instant_to_ms(a.expires_at),
                transport: "UDP".into(),
                address_family: if a.client_addr.is_ipv6() {
                    "IPv6"
                } else {
                    "IPv4"
                }
                .into(),
                organization: None,
                bytes_in: a.bytes_relayed.load(Ordering::Relaxed),
                bytes_out: 0,
                packets_in: a.packets_relayed.load(Ordering::Relaxed),
                packets_out: 0,
                permissions: a.permission_ips(),
                channels: a
                    .channel_list()
                    .into_iter()
                    .map(|(num, peer, exp)| ChannelInfo {
                        number: num,
                        peer_addr: peer.to_string(),
                        expires_at_ms: instant_to_ms(exp),
                    })
                    .collect(),
            })
            .collect()
    }
}

// ── TurnCore implementation ───────────────────────────────────────────────────

#[async_trait::async_trait]
impl TurnCore for TurnCoreImpl {
    async fn list_allocations(
        &self,
        user: Option<&str>,
        org: Option<&str>,
        limit: usize,
        token: Option<&str>,
    ) -> Result<(Vec<AllocationInfo>, Option<String>, usize), CoreError> {
        let offset: usize = token.and_then(|t| t.parse().ok()).unwrap_or(0);

        let mut all = self.all_allocations();

        // Filter
        if let Some(u) = user {
            all.retain(|a| a.username == u);
        }
        if let Some(o) = org {
            all.retain(|a| a.organization.as_deref() == Some(o));
        }

        let total = all.len();
        let page: Vec<_> = all.into_iter().skip(offset).take(limit).collect();
        let next_offset = offset + page.len();
        let next_token = if next_offset < total {
            Some(next_offset.to_string())
        } else {
            None
        };

        Ok((page, next_token, total))
    }

    async fn get_allocation(&self, id: &str) -> Result<AllocationInfo, CoreError> {
        // `id` = relay_addr string, e.g. "5.6.7.8:12345"
        self.all_allocations()
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| CoreError::NotFound(format!("allocation {id}")))
    }

    async fn delete_allocation(&self, id: &str, reason: &str) -> Result<(), CoreError> {
        // Find client_addr corresponding to this relay id
        let alloc = self.get_allocation(id).await?;
        self.store.force_remove(&alloc.client_address);
        self.metrics
            .active_allocations
            .fetch_sub(1, Ordering::Relaxed);
        info!(id, reason, "allocation deleted via gRPC");
        self.emit_event(EventType::Deleted, alloc, Some(reason.into()));
        Ok(())
    }

    async fn server_stats(&self) -> ServerStatsInfo {
        let m = &self.metrics;
        let active = m.active_allocations.load(Ordering::Relaxed);
        let total = m.total_allocations.load(Ordering::Relaxed);
        let bytes_in = m.bytes_received.load(Ordering::Relaxed);
        let bytes_out = m.bytes_sent.load(Ordering::Relaxed);
        let pps = m.packets_received.load(Ordering::Relaxed); // approximate

        // Count unique users
        let mut users = std::collections::HashSet::new();
        for a in self.all_allocations() {
            users.insert(a.username);
        }

        ServerStatsInfo {
            uptime_seconds: self.started_at.elapsed().as_secs(),
            active_allocations: active as u32,
            total_allocations: total,
            total_bytes_in: bytes_in,
            total_bytes_out: bytes_out,
            active_users: users.len() as u32,
            pps,
            allocated_ports: self.store.allocated_port_count() as u32,
            available_ports: self.store.available_port_count() as u32,
            draining: m.is_draining(),
            avg_latency_us: m
                .histograms
                .get("turna_stun_request_duration_seconds")
                .map(|h| (h.avg_seconds() * 1_000_000.0) as u64)
                .unwrap_or(0),
            p99_latency_us: m
                .histograms
                .get("turna_stun_request_duration_seconds")
                .map(|h| (h.percentile(0.99) * 1_000_000.0) as u64)
                .unwrap_or(0),
            blocked_ips: 0,
        }
    }

    async fn top_talkers(&self, limit: usize, sort_by: &str) -> Vec<TopTalkerInfo> {
        // Aggregate by username
        let mut by_user: std::collections::HashMap<String, TopTalkerInfo> =
            std::collections::HashMap::new();

        for a in self.all_allocations() {
            let entry = by_user.entry(a.username.clone()).or_insert(TopTalkerInfo {
                username: a.username,
                organization: a.organization,
                allocations: 0,
                total_bytes: 0,
                bandwidth_bps: 0,
            });
            entry.allocations += 1;
            entry.total_bytes += a.bytes_in + a.bytes_out;
        }

        let mut talkers: Vec<_> = by_user.into_values().collect();
        match sort_by {
            "bytes" | "" => talkers.sort_by_key(|b| std::cmp::Reverse(b.total_bytes)),
            "allocations" => talkers.sort_by_key(|b| std::cmp::Reverse(b.allocations)),
            "bandwidth" => talkers.sort_by_key(|b| std::cmp::Reverse(b.bandwidth_bps)),
            _ => talkers.sort_by_key(|b| std::cmp::Reverse(b.total_bytes)),
        }
        talkers.truncate(limit);
        talkers
    }

    async fn update_config(&self, update: ConfigUpdate) -> Result<(), CoreError> {
        let mut cfg = self.config.write().unwrap();
        if let Some(v) = update.max_lifetime {
            cfg.max_lifetime = v;
        }
        if let Some(v) = update.max_allocations_per_user {
            cfg.max_allocations_per_user = v;
        }
        if let Some(v) = update.max_bandwidth_per_user_bps {
            cfg.max_bandwidth_per_user_bps = v;
        }
        if let Some(v) = update.draining {
            drop(cfg);
            self.metrics.set_draining(v);
            info!(draining = v, "draining updated via gRPC");
            return Ok(());
        }
        info!("config updated via gRPC");
        Ok(())
    }

    async fn add_user(&self, user: &str, _pass: &str, _org: Option<&str>) -> Result<(), CoreError> {
        // Runtime user management is not supported by the current auth modes:
        // LongTerm users are defined in config and SharedSecret/REST mode has
        // no per-user records. Returning Unimplemented (not Ok) so operators
        // get an honest failure instead of believing a user was created.
        // TODO: wire to turna-auth UserStore once it supports runtime CRUD.
        warn!(
            username = user,
            "add_user via gRPC rejected: runtime user management not supported"
        );
        Err(CoreError::Unimplemented(
            "runtime user management is not supported; configure LongTerm users in \
             turn.toml or use SharedSecret/REST credentials"
                .into(),
        ))
    }

    async fn remove_user(&self, user: &str, force: bool) -> Result<u32, CoreError> {
        // There is no runtime user store to delete a user record from (see
        // add_user), so without `force` this RPC has nothing to do. Report that
        // honestly as Unimplemented instead of returning a misleading success.
        // With `force` we drop the user's *active allocations* (not a user
        // record); the response's allocations_deleted conveys what happened.
        if !force {
            return Err(CoreError::Unimplemented(
                "runtime user removal is not supported; pass force to drop the user's \
                 active allocations, or manage LongTerm users in turn.toml"
                    .into(),
            ));
        }

        let allocs: Vec<_> = self
            .all_allocations()
            .into_iter()
            .filter(|a| a.username == user)
            .collect();
        let mut deleted = 0u32;
        for a in allocs {
            self.store.force_remove(&a.client_address);
            self.metrics
                .active_allocations
                .fetch_sub(1, Ordering::Relaxed);
            deleted += 1;
        }
        info!(
            username = user,
            deleted, "user allocations force-dropped via gRPC"
        );
        Ok(deleted)
    }

    async fn set_draining(&self, draining: bool) -> Result<u32, CoreError> {
        self.metrics.set_draining(draining);
        let active = self.metrics.active_allocations.load(Ordering::Relaxed) as u32;
        info!(draining, active, "draining set via gRPC");
        Ok(active)
    }

    async fn shutdown(&self, graceful: bool, timeout: Duration) -> Result<u32, CoreError> {
        let remaining = self.metrics.active_allocations.load(Ordering::Relaxed) as u32;
        info!(graceful, ?timeout, remaining, "shutdown initiated via gRPC");

        if graceful {
            self.metrics.set_draining(true);
            // Give existing allocations time to drain
            tokio::time::sleep(timeout.min(Duration::from_secs(30))).await;
        }

        if let Err(e) = self.shutdown_tx.send(true) {
            warn!(%e, "failed to send shutdown signal");
        }

        Ok(remaining)
    }

    fn subscribe_events(&self) -> broadcast::Receiver<AllocationEvent> {
        self.events_tx.subscribe()
    }

    fn get_config(&self) -> CurrentConfig {
        let cfg = self.config.read().unwrap();
        CurrentConfig {
            realm: cfg.realm.clone(),
            min_port: cfg.min_port,
            max_port: cfg.max_port,
            default_lifetime: cfg.default_lifetime,
            max_lifetime: cfg.max_lifetime,
            max_allocations_per_user: cfg.max_allocations_per_user,
            max_bandwidth_per_user_bps: cfg.max_bandwidth_per_user_bps,
            draining: self.metrics.is_draining(),
            external_ipv4: cfg.external_ipv4.clone(),
            listen_addresses: cfg.listen_addresses.clone(),
            nonce_lifetime_seconds: cfg.nonce_lifetime_seconds,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn instant_to_ms(instant: Instant) -> u64 {
    let now_instant = Instant::now();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if instant > now_instant {
        let delta = instant.duration_since(now_instant).as_millis() as u64;
        now_ms + delta
    } else {
        let delta = now_instant.duration_since(instant).as_millis() as u64;
        now_ms.saturating_sub(delta)
    }
}
