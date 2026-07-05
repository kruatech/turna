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
use turna_state_backend::{now_ms, Backend, StoredUser};

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
    /// Shared state backend for runtime user CRUD (R8). `None` → user
    /// management returns Unimplemented (no backend configured).
    user_backend: Option<Arc<Backend>>,
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
            user_backend: None,
        }
    }

    /// Attach a shared state backend so runtime user CRUD (AddUser/RemoveUser)
    /// persists to the cluster store. Without it, user management is
    /// Unimplemented.
    pub fn with_user_backend(mut self, backend: Arc<Backend>) -> Self {
        self.user_backend = Some(backend);
        self
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
            let mut cfg = self
                .config
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                realm: self
                    .config
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .realm
                    .clone(),
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

    /// Allocation list with a cluster-wide view: when a shared state backend is
    /// attached (control-plane), read from it; otherwise fall back to the local
    /// in-process store (embedded/node mode). This is what makes the
    /// control-plane's read RPCs reflect the real cluster instead of its own
    /// empty store.
    async fn cluster_allocations(&self) -> Vec<AllocationInfo> {
        if let Some(backend) = self.user_backend.clone() {
            // Cap the pull; gRPC pagination/aggregation happens on top of this.
            match backend.list_allocations(0, 100_000).await {
                Ok(list) => return list.into_iter().map(stored_to_info).collect(),
                Err(e) => {
                    warn!(%e, "list_allocations from backend failed; using local store");
                }
            }
        }
        self.all_allocations()
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

        let mut all = self.cluster_allocations().await;

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
        self.cluster_allocations()
            .await
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
        let total = m.total_allocations.load(Ordering::Relaxed);
        let pps = m.packets_received.load(Ordering::Relaxed); // approximate

        // Allocation-derived figures come from the shared backend when one is
        // attached (cluster-wide view); otherwise from the local store. The
        // runtime gauges below (ports, latency, pps) stay node-local — the
        // backend does not persist them, so on a standalone control-plane they
        // read as zero/local rather than cluster-aggregated.
        let cluster = self.cluster_allocations().await;
        let backend_mode = self.user_backend.is_some();
        let active = if backend_mode {
            cluster.len() as u64
        } else {
            m.active_allocations.load(Ordering::Relaxed)
        };
        let (bytes_in, bytes_out) = if backend_mode {
            cluster
                .iter()
                .fold((0u64, 0u64), |(i, o), a| (i + a.bytes_in, o + a.bytes_out))
        } else {
            (
                m.bytes_received.load(Ordering::Relaxed),
                m.bytes_sent.load(Ordering::Relaxed),
            )
        };
        let mut users = std::collections::HashSet::new();
        for a in &cluster {
            users.insert(a.username.clone());
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

        for a in self.cluster_allocations().await {
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
        let mut cfg = self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    async fn add_user(&self, user: &str, pass: &str, org: Option<&str>) -> Result<(), CoreError> {
        // R8: persist the long-term user to the shared backend (source of
        // truth). Variant B — store the two pre-derived keys, never the
        // password. Nodes rehydrate their AuthRegistry from this on startup.
        let Some(backend) = self.user_backend.clone() else {
            warn!(
                username = user,
                "add_user via gRPC rejected: no state backend configured"
            );
            return Err(CoreError::Unimplemented(
                "runtime user management requires a state backend; set [cluster.backend] \
                 (type = \"tarantool\") so users are shared across the cluster"
                    .into(),
            ));
        };
        let realm = self
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .realm
            .clone();
        let su = StoredUser {
            username: user.to_string(),
            realm: realm.clone(),
            key_md5_hex: bytes_to_hex(&turna_crypto::long_term_key(user, &realm, pass)),
            key_sha256_hex: bytes_to_hex(&turna_crypto::long_term_key_sha256(user, &realm, pass)),
            organization: org.map(|s| s.to_string()),
            created_at_ms: now_ms(),
        };
        backend
            .store_user(&su)
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        info!(username = user, realm = %realm, "user added via gRPC");
        Ok(())
    }

    async fn remove_user(&self, user: &str, force: bool) -> Result<u32, CoreError> {
        // R8: remove the persisted user record (source of truth) when a backend
        // is configured. With `force` we additionally drop the user's active
        // allocations on this node; allocations_deleted conveys how many.
        let realm = self
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .realm
            .clone();
        match self.user_backend.clone() {
            Some(backend) => {
                backend
                    .remove_user(user, &realm)
                    .await
                    .map_err(|e| CoreError::Internal(e.to_string()))?;
            }
            None => {
                if !force {
                    return Err(CoreError::Unimplemented(
                        "runtime user removal requires a state backend; pass force to drop \
                         the user's active allocations, or set [cluster.backend]"
                            .into(),
                    ));
                }
            }
        }

        let deleted = if force {
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
            deleted
        } else {
            0
        };
        info!(username = user, deleted, force, "user removed via gRPC");
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
        let cfg = self
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Map a backend `StoredAllocation` to the gRPC `AllocationInfo`. Mirrors the
/// local-store mapping in `all_allocations`. Fields the backend does not
/// persist on an allocation (transport, organization) use the same defaults as
/// the local path; `address_family` is derived from the client address.
fn stored_to_info(a: turna_state_backend::StoredAllocation) -> AllocationInfo {
    let client_address = a
        .client_addr
        .parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    let relay_address = a
        .relay_addr
        .parse()
        .unwrap_or_else(|_| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    AllocationInfo {
        id: a.relay_addr.clone(),
        username: a.user_id,
        realm: a.realm,
        client_address,
        relay_address,
        created_at_ms: a.created_at_ms,
        expires_at_ms: a.expires_at_ms,
        transport: "UDP".into(),
        address_family: if client_address.is_ipv6() {
            "IPv6"
        } else {
            "IPv4"
        }
        .into(),
        organization: None,
        bytes_in: a.bytes_in,
        bytes_out: a.bytes_out,
        packets_in: a.packets_in,
        packets_out: a.packets_out,
        permissions: a.permissions,
        channels: a
            .channels
            .into_iter()
            .map(|c| ChannelInfo {
                number: c.number,
                peer_addr: c.peer_addr,
                expires_at_ms: c.expires_at_ms,
            })
            .collect(),
    }
}

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
