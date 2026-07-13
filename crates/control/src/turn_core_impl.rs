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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use turna_health::Metrics;
use turna_session::AllocationStore;
use turna_state_backend::{
    now_ms, Backend, BackendError, PendingCommand, SetUserLimitsCommand, SetUserLimitsResult,
    StoredUser, UpdateConfigCommand, UpdateConfigResult,
};

/// Monotonic per-process sequence for command request ids.
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// Build a process-unique command `request_id` (P0.3). A millisecond clock
/// alone collides when two admin calls land in the same millisecond, and the
/// backend dedups by `request_id` — so one command silently vanishes. Combining
/// a nanosecond clock, the process id, and a monotonic counter makes collisions
/// effectively impossible. NOTE: this does not give cross-retry idempotency; an
/// API-supplied idempotency key is the follow-up for de-duplicating retries.
fn unique_request_id(prefix: &str) -> String {
    let seq = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}-{}-{}-{}", std::process::id(), nanos, seq)
}

use crate::grpc::{
    AllocationEvent, AllocationInfo, ChannelInfo, ConfigUpdate, CoreError, EventType,
    ServerStatsInfo, TopTalkerInfo, TurnCore, UserLimitsUpdate,
};

// ── TurnCoreImpl ──────────────────────────────────────────────────────────────

pub struct TurnCoreImpl {
    store: Arc<AllocationStore>,
    metrics: Arc<Metrics>,
    /// Broadcast channel for streaming `WatchAllocations` updates.
    events_tx: broadcast::Sender<AllocationEvent>,
    /// Retained for constructor API compatibility. Node shutdown is NOT
    /// routed through here anymore (see `shutdown`); kept so `new`'s
    /// signature and the control-plane wiring do not change.
    #[allow(dead_code)]
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
        }
    }
}

impl TurnCoreImpl {
    /// Enqueue a legacy argument-based command and return the node result.
    async fn enqueue_and_await(
        &self,
        node_id: &str,
        op: &str,
        args: Vec<String>,
        idempotency_key: &str,
    ) -> Result<String, CoreError> {
        self.enqueue_command_and_await(node_id, op, args, String::new(), idempotency_key)
            .await
            .map(|(_, result)| result)
    }

    /// Enqueue one node-targeted command and wait for its durable terminal
    /// outcome. New operations use `payload_json`; legacy operations use
    /// `args`. The command is fenced to the process incarnation most recently
    /// advertised by the target node.
    async fn enqueue_command_and_await(
        &self,
        node_id: &str,
        op: &str,
        args: Vec<String>,
        payload_json: String,
        idempotency_key: &str,
    ) -> Result<(String, String), CoreError> {
        if node_id.trim().is_empty() {
            return Err(CoreError::Invalid(format!(
                "{op} requires a non-empty node_id"
            )));
        }
        if idempotency_key.trim().is_empty() {
            return Err(CoreError::Invalid(format!(
                "{op} requires a non-empty idempotency_key"
            )));
        }
        let backend = self.user_backend.clone().ok_or_else(|| {
            CoreError::FailedPrecondition(format!(
                "{op} requires a shared state backend to route the command to the node"
            ))
        })?;
        let incarnation = backend
            .get_live_nodes(Duration::from_secs(30))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
            .into_iter()
            .find(|node| node.node_id == node_id)
            .map(|node| node.incarnation)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CoreError::NotFound(format!(
                    "target node {node_id} has no live heartbeat/incarnation"
                ))
            })?;

        let now = now_ms();
        let request_id = unique_request_id(&format!("{op}-{node_id}"));
        let cmd = PendingCommand {
            request_id: request_id.clone(),
            target_node_id: node_id.to_string(),
            op: op.to_string(),
            args,
            payload_json,
            target_incarnation: incarnation,
            status: "pending".into(),
            result: String::new(),
            created_at_ms: now,
            updated_at_ms: now,
            claimed_by: String::new(),
            lease_until_ms: 0,
            attempts: 0,
            claim_token: String::new(),
            idempotency_key: idempotency_key.to_string(),
        };
        let request_id = backend.enqueue_command(&cmd).await.map_err(|e| match e {
            BackendError::Conflict(message) => CoreError::AlreadyExists(message),
            other => CoreError::Internal(other.to_string()),
        })?;
        self.metrics
            .management_commands_accepted_total
            .fetch_add(1, Ordering::Relaxed);
        info!(
            op,
            node = node_id,
            request_id,
            "command enqueued; awaiting node confirmation"
        );

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match backend.get_command(&request_id).await {
                Ok(Some(c)) if c.status == "done" => return Ok((request_id, c.result)),
                Ok(Some(c)) if c.status == "failed" => {
                    return Err(CoreError::Internal(format!(
                        "node {node_id} failed to apply {op}: {}",
                        c.result
                    )));
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    let mut attempt = 0u8;
                    loop {
                        match backend.get_idempotency(idempotency_key).await {
                            Ok(Some(rec)) => match rec.final_status.as_str() {
                                "done" => return Ok((rec.request_id, rec.result)),
                                "failed" => {
                                    return Err(CoreError::Internal(format!(
                                        "node {node_id} failed to apply {op}: {}",
                                        rec.result
                                    )));
                                }
                                "superseded" => {
                                    return Err(CoreError::AlreadyExists(format!(
                                        "{op} on node {node_id} was superseded by a newer command for the same key"
                                    )));
                                }
                                "expired" => {
                                    return Err(CoreError::Invalid(format!(
                                        "{op} on node {node_id} expired before it was applied"
                                    )));
                                }
                                "" => break,
                                other => {
                                    return Err(CoreError::Internal(format!(
                                        "{op} on node {node_id} ended in unexpected terminal state '{other}'"
                                    )));
                                }
                            },
                            Ok(None) => break,
                            Err(BackendError::Connection(_)) | Err(BackendError::Timeout)
                                if attempt < 2 && Instant::now() < deadline =>
                            {
                                attempt += 1;
                                self.metrics
                                    .command_log_idempotency_lookup_errors_total
                                    .fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            Err(error) => {
                                self.metrics
                                    .command_log_idempotency_lookup_errors_total
                                    .fetch_add(1, Ordering::Relaxed);
                                return Err(CoreError::Internal(format!(
                                    "idempotency lookup for {op} on node {node_id} failed: {error}"
                                )));
                            }
                        }
                    }
                }
                Err(error) => return Err(CoreError::Internal(error.to_string())),
            }
            if Instant::now() >= deadline {
                return Err(CoreError::Internal(format!(
                    "timed out waiting for node {node_id} to apply {op}"
                )));
            }
        }
    }

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
                realm: a.realm.clone(),
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

    async fn delete_allocation(
        &self,
        id: &str,
        reason: &str,
        idempotency_key: &str,
    ) -> Result<(), CoreError> {
        // P0 #4: do NOT mutate this process's local store (that was the fake
        // success). Route a durable command to the node that actually owns the
        // allocation, then wait for that node to confirm it applied.
        let Some(backend) = self.user_backend.clone() else {
            return Err(CoreError::Unimplemented(
                "deleting an allocation requires a shared state backend so the \
                 command can be routed to the owning node; set [cluster.backend]"
                    .into(),
            ));
        };
        // `id` is the relay_addr string (e.g. "5.6.7.8:50100"); the trailing
        // port is the key allocations are stored under.
        let relay_port: u16 = id
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| CoreError::NotFound(format!("allocation {id}")))?;
        let stored = backend
            .get_allocation(relay_port)
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))?
            .ok_or_else(|| CoreError::NotFound(format!("allocation {id}")))?;

        self.enqueue_and_await(
            &stored.node_id,
            "delete_allocation",
            vec![id.to_string(), reason.to_string()],
            idempotency_key,
        )
        .await?;
        info!(id, node = %stored.node_id, "allocation delete confirmed by node");
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
            backend_mode,
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

    async fn update_config(&self, update: ConfigUpdate) -> Result<UpdateConfigResult, CoreError> {
        if update.node_id.trim().is_empty() {
            return Err(CoreError::Invalid("node_id is required".into()));
        }
        if update.idempotency_key.trim().is_empty() {
            return Err(CoreError::Invalid("idempotency_key is required".into()));
        }
        if update.max_allocations.is_none()
            && update.max_allocations_per_user.is_none()
            && update.max_bytes_per_sec_per_allocation.is_none()
        {
            return Err(CoreError::Invalid(
                "update_config patch must contain at least one field".into(),
            ));
        }
        let command = UpdateConfigCommand {
            schema_version: 1,
            expected_version: update.expected_version,
            max_allocations: update.max_allocations.map(|value| value as usize),
            max_allocations_per_user: update.max_allocations_per_user.map(|value| value as usize),
            max_bytes_per_sec_per_allocation: update.max_bytes_per_sec_per_allocation,
            reason: update.reason,
        };
        let payload = serde_json::to_string(&command)
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        let (request_id, raw_result) = self
            .enqueue_command_and_await(
                &update.node_id,
                "update_config",
                Vec::new(),
                payload,
                &update.idempotency_key,
            )
            .await?;
        let mut result: UpdateConfigResult =
            serde_json::from_str(&raw_result).map_err(|error| {
                CoreError::Internal(format!(
                    "node returned invalid update_config result: {error}"
                ))
            })?;
        if result.request_id.is_empty() {
            result.request_id = request_id;
        }
        match result.terminal_status.as_str() {
            "applied" => {
                self.metrics
                    .config_update_applied_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            "no_op" => {
                self.metrics
                    .config_update_noop_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            "conflict" => {
                self.metrics
                    .config_update_conflicts_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.metrics
                    .config_update_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        if result.rolled_back {
            self.metrics
                .config_update_rollback_total
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    async fn set_user_limits(
        &self,
        update: UserLimitsUpdate,
    ) -> Result<SetUserLimitsResult, CoreError> {
        if update.node_id.trim().is_empty() {
            return Err(CoreError::Invalid("node_id is required".into()));
        }
        if update.idempotency_key.trim().is_empty() {
            return Err(CoreError::Invalid("idempotency_key is required".into()));
        }
        if update.patch.is_empty() {
            return Err(CoreError::Invalid(
                "set_user_limits patch must contain at least one field".into(),
            ));
        }
        // §7-B: a finite requested lifetime above the node's absolute lifetime
        // ceiling (seeded from the protocol MAX_LIFETIME) is rejected outright, so
        // an over-limit value never enters the command log. Values at or below the
        // ceiling are accepted; broader-scope ceilings still cap the effective
        // value at resolution time. A zero ceiling means the node imposes none.
        if let Some(limit) = update.patch.max_lifetime_secs.as_ref() {
            if matches!(limit.mode, turna_state_backend::LimitMode::Value) {
                // #8: the node's absolute lifetime ceiling comes from the runtime
                // config (Default = protocol MAX_LIFETIME = 3600), which is always
                // seeded at construction — never a possibly-unseeded user-limits
                // store snapshot that would let this ingress check silently no-op.
                let ceiling = self
                    .config
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .max_lifetime;
                if ceiling > 0 && limit.value > ceiling {
                    return Err(CoreError::Invalid(format!(
                        "max_lifetime_secs {} exceeds the absolute lifetime ceiling {}",
                        limit.value, ceiling
                    )));
                }
            }
        }
        let command = SetUserLimitsCommand {
            schema_version: 1,
            expected_version: update.expected_version,
            target: update.target,
            patch: update.patch,
            reason: update.reason,
        };
        let payload = serde_json::to_string(&command)
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        let (request_id, raw_result) = self
            .enqueue_command_and_await(
                &update.node_id,
                "set_user_limits",
                Vec::new(),
                payload,
                &update.idempotency_key,
            )
            .await?;
        let mut result: SetUserLimitsResult =
            serde_json::from_str(&raw_result).map_err(|error| {
                CoreError::Internal(format!(
                    "node returned invalid set_user_limits result: {error}"
                ))
            })?;
        if result.request_id.is_empty() {
            result.request_id = request_id;
        }
        match result.terminal_status.as_str() {
            "applied" => {
                self.metrics
                    .user_limits_applied_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            "no_op" => {
                self.metrics
                    .user_limits_noop_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            "conflict" => {
                self.metrics
                    .user_limits_conflicts_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.metrics
                    .user_limits_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(result)
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

    async fn set_draining(
        &self,
        node_id: &str,
        draining: bool,
        idempotency_key: &str,
    ) -> Result<u32, CoreError> {
        // P0 #4: route to the specific node via the durable command log and wait
        // for it to actually flip readiness/routing. No local-only fake success.
        let result = self
            .enqueue_and_await(
                node_id,
                "set_draining",
                vec![draining.to_string()],
                idempotency_key,
            )
            .await?;
        // #8: surface the node's real remaining-allocation count (same wire format
        // as shutdown) instead of a hardcoded 0.
        let remaining = result
            .strip_prefix("remaining_allocations=")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        Ok(remaining)
    }

    async fn shutdown(
        &self,
        node_id: &str,
        graceful: bool,
        timeout: Duration,
        idempotency_key: &str,
    ) -> Result<u32, CoreError> {
        // P0 #4/P0.6: route a shutdown command to the specific node and wait for it
        // to begin draining + signal its own shutdown. Pass graceful/timeout through
        // (previously dropped) and surface the node's real remaining-allocation count
        // instead of a hardcoded 0.
        let result = self
            .enqueue_and_await(
                node_id,
                "shutdown",
                vec![graceful.to_string(), timeout.as_secs().to_string()],
                idempotency_key,
            )
            .await?;
        let remaining = result
            .strip_prefix("remaining_allocations=")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0);
        Ok(remaining)
    }

    fn subscribe_events(&self) -> broadcast::Receiver<AllocationEvent> {
        self.events_tx.subscribe()
    }

    async fn get_config(
        &self,
        node_id: &str,
    ) -> Result<turna_state_backend::NodeRuntimeState, CoreError> {
        if node_id.trim().is_empty() {
            return Err(CoreError::Invalid("node_id is required".into()));
        }
        let backend = self.user_backend.clone().ok_or_else(|| {
            CoreError::FailedPrecondition(
                "node runtime config requires a shared state backend".into(),
            )
        })?;
        backend
            .get_runtime_state(node_id)
            .await
            .map_err(|error| CoreError::Internal(error.to_string()))?
            .ok_or_else(|| CoreError::NotFound(format!("runtime config for node {node_id}")))
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

#[cfg(test)]
mod tests {
    use super::*;
    use turna_state_backend::{CommandLogRetention, InMemoryBackend};

    // End-to-end regression for the post-GC replay defect: the bug lived between
    // the backend and `TurnCoreImpl::enqueue_and_await`. A command runs, is GC'd,
    // and a replay with the same idempotency key must return the recorded outcome
    // via the idempotency fallback instead of polling to a timeout.
    #[tokio::test]
    async fn post_gc_replay_resolves_from_idempotency_record() {
        let backend = Arc::new(Backend::Memory(InMemoryBackend::new()));

        let now = now_ms();
        backend
            .heartbeat(&turna_state_backend::NodeHeartbeat {
                node_id: "node-1".into(),
                incarnation: "inc-1".into(),
                addr: "127.0.0.1:3478".into(),
                active_allocations: 0,
                total_bandwidth_bps: 0,
                cpu_usage_pct: 0.0,
                memory_usage_pct: 0.0,
                uptime_secs: 1,
                version: "test".into(),
                last_seen_ms: now,
                draining: false,
            })
            .await
            .unwrap();
        let cmd = PendingCommand {
            request_id: "orig-req".into(),
            target_node_id: "node-1".into(),
            op: "set_draining".into(),
            args: vec!["true".into()],
            payload_json: String::new(),
            target_incarnation: "inc-1".into(),
            status: "pending".into(),
            result: String::new(),
            created_at_ms: now,
            updated_at_ms: now,
            claimed_by: String::new(),
            lease_until_ms: 0,
            attempts: 0,
            claim_token: String::new(),
            idempotency_key: "k".into(),
        };
        assert_eq!(backend.enqueue_command(&cmd).await.unwrap(), "orig-req");
        let claimed = backend
            .claim_commands("node-1", "inc-1", 10, 60_000)
            .await
            .unwrap();
        assert!(backend
            .complete_command(
                "orig-req",
                "node-1",
                &claimed[0].claim_token,
                "done",
                "remaining_allocations=3",
            )
            .await
            .unwrap());

        // GC well past the done window; the idempotency record is retained.
        let day = 24 * 3600 * 1000u64;
        let retention = CommandLogRetention {
            done_ms: day,
            failed_ms: day,
            superseded_ms: day,
            expired_ms: day,
            idempotency_ms: 30 * day,
            batch: 100,
            max_batches: 10,
        };
        let stats = backend.gc_command_log(retention, now + 10 * day).await;
        assert_eq!(stats.deleted_commands, 1);
        assert!(backend.get_command("orig-req").await.unwrap().is_none());

        // Replay the SAME intent (same op/args/key) through the control impl.
        let (shutdown_tx, _rx) = watch::channel(false);
        let store = Arc::new(AllocationStore::new(49152, 65535, 1000));
        let metrics = Arc::new(Metrics::new());
        let core = TurnCoreImpl::new(store, metrics, shutdown_tx).with_user_backend(backend);

        let out = core
            .enqueue_and_await("node-1", "set_draining", vec!["true".into()], "k")
            .await
            .expect("post-GC replay must resolve from the idempotency record");
        assert_eq!(out, "remaining_allocations=3");
    }

    #[tokio::test]
    async fn lifetime_above_absolute_ceiling_is_rejected() {
        use turna_state_backend::{
            LimitMode, LimitU32, UserLimitScope, UserLimitTarget, UserLimitsPatch,
        };
        // §7-B: a finite requested lifetime above the node's absolute ceiling is
        // rejected as InvalidArgument before it can enter the command log.
        let (shutdown_tx, _rx) = watch::channel(false);
        let store = Arc::new(AllocationStore::new(49152, 65535, 1000));
        store.set_bootstrap_max_lifetime(3600); // absolute lifetime ceiling
        let metrics = Arc::new(Metrics::new());
        let core = TurnCoreImpl::new(store, metrics, shutdown_tx);

        let update = UserLimitsUpdate {
            node_id: "node-1".into(),
            idempotency_key: "k".into(),
            expected_version: 0,
            target: UserLimitTarget {
                scope: UserLimitScope::User,
                tenant: String::new(),
                realm: "example.org".into(),
                username: "alice".into(),
            },
            patch: UserLimitsPatch {
                max_lifetime_secs: Some(LimitU32 {
                    mode: LimitMode::Value,
                    value: 9999,
                }),
                ..Default::default()
            },
            reason: "test".into(),
        };
        let err = core.set_user_limits(update).await.unwrap_err();
        assert!(
            matches!(err, CoreError::Invalid(_)),
            "over-ceiling lifetime must be rejected"
        );
    }
}
