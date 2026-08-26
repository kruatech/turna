//! gRPC Management Server — full implementation.
//!
//! Exposes all TurnaManagement RPCs to ops tooling (turnactl, Grafana, etc.).
//! Runs on a separate port (default 5350) with optional mTLS.
//!
//! # Graceful shutdown
//!
//! `start_grpc_server` accepts a `shutdown` future.  When it resolves:
//!
//! 1. A `CancellationToken` fires — all open `WatchAllocations` /
//!    `WatchMetrics` streams return `None` on their next poll, causing tonic
//!    to close those connections cleanly (client receives status OK rather
//!    than connection-reset).
//! 2. A drain loop waits up to `config.drain_timeout` for `grpc_active_streams`
//!    to reach 0.  If the timeout expires the server stops anyway and
//!    `grpc_forced_kills_total` is incremented.
//! 3. New connections are rejected immediately after the shutdown signal fires
//!    (tonic `serve_with_shutdown` behaviour).

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use tokio::sync::broadcast;
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};
use tokio_stream::StreamExt as _; // filter_map, then, next for tokio streams
use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use turna_health::Metrics;
use turna_state_backend::{
    command_payload_hash, LimitMode as BackendLimitMode, LimitU32 as BackendLimitU32,
    LimitU64 as BackendLimitU64, NodeRuntimeState,
    SetUserLimitsCommand as BackendSetUserLimitsCommand, SetUserLimitsResult,
    UpdateConfigCommand as BackendUpdateConfigCommand, UpdateConfigResult,
    UserLimitScope as BackendUserLimitScope, UserLimitTarget as BackendUserLimitTarget,
    UserLimitsPatch as BackendUserLimitsPatch,
};

use crate::audit::AuditLog;

// ── Proto generated code ──────────────────────────────────────────────────────

pub mod proto {
    tonic::include_proto!("turna.management.v1");
}

use proto::{
    turna_management_server::{TurnaManagement, TurnaManagementServer},
    *,
};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub listen_addr: SocketAddr,
    pub tls: Option<GrpcTlsConfig>,
    pub max_message_size: usize,
    pub enable_reflection: bool,
    /// How long to wait for active streams to finish before forcing shutdown.
    /// Default: 30 seconds.
    pub drain_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct GrpcTlsConfig {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    /// Path to the CA that signs client certificates. Only read when
    /// `require_client_auth` is true (mTLS). Ignored in server-only TLS.
    pub client_ca_cert: PathBuf,
    /// `true` => mTLS: the server requires and verifies a client certificate
    /// against `client_ca_cert`. `false` => server-only TLS: clients are NOT
    /// asked for a certificate (authenticate them by another mechanism).
    pub require_client_auth: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:5350".parse().unwrap(),
            tls: None,
            max_message_size: 4 * 1024 * 1024,
            enable_reflection: true,
            drain_timeout: Duration::from_secs(30),
        }
    }
}

// ── TurnCore trait ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
pub trait TurnCore: Send + Sync + 'static {
    async fn list_allocations(
        &self,
        user: Option<&str>,
        org: Option<&str>,
        limit: usize,
        token: Option<&str>,
    ) -> Result<(Vec<AllocationInfo>, Option<String>, usize), CoreError>;

    async fn get_allocation(&self, id: &str) -> Result<AllocationInfo, CoreError>;
    async fn delete_allocation(
        &self,
        id: &str,
        reason: &str,
        idempotency_key: &str,
    ) -> Result<(), CoreError>;
    async fn server_stats(&self) -> ServerStatsInfo;
    async fn top_talkers(&self, limit: usize, sort_by: &str) -> Vec<TopTalkerInfo>;
    async fn update_config(&self, update: ConfigUpdate) -> Result<UpdateConfigResult, CoreError>;
    async fn set_user_limits(
        &self,
        update: UserLimitsUpdate,
    ) -> Result<SetUserLimitsResult, CoreError>;
    async fn add_user(&self, user: &str, pass: &str, org: Option<&str>) -> Result<(), CoreError>;
    async fn remove_user(&self, user: &str, force: bool) -> Result<u32, CoreError>;
    async fn set_draining(
        &self,
        node_id: &str,
        draining: bool,
        idempotency_key: &str,
    ) -> Result<u32, CoreError>;
    async fn shutdown(
        &self,
        node_id: &str,
        graceful: bool,
        timeout: Duration,
        idempotency_key: &str,
    ) -> Result<u32, CoreError>;
    fn subscribe_events(&self) -> broadcast::Receiver<AllocationEvent>;
    async fn get_config(&self, node_id: &str) -> Result<NodeRuntimeState, CoreError>;
}

// ── Domain types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AllocationInfo {
    pub id: String,
    pub username: String,
    pub realm: String,
    pub client_address: SocketAddr,
    pub relay_address: SocketAddr,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub transport: String,
    pub address_family: String,
    pub organization: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub permissions: Vec<String>,
    pub channels: Vec<ChannelInfo>,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub number: u16,
    pub peer_addr: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ServerStatsInfo {
    pub uptime_seconds: u64,
    pub active_allocations: u32,
    pub total_allocations: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub active_users: u32,
    pub pps: u64,
    pub allocated_ports: u32,
    pub available_ports: u32,
    pub draining: bool,
    pub avg_latency_us: u64,
    pub p99_latency_us: u64,
    pub blocked_ips: u32,
    /// True when a shared cluster backend is attached: the allocation figures
    /// above are cluster-wide, but the runtime gauges (ports/pps/latency/
    /// draining/blocked_ips) are this control-plane node's local view only.
    pub backend_mode: bool,
}

#[derive(Debug, Clone)]
pub struct TopTalkerInfo {
    pub username: String,
    pub organization: Option<String>,
    pub allocations: u32,
    pub total_bytes: u64,
    pub bandwidth_bps: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigUpdate {
    pub node_id: String,
    pub idempotency_key: String,
    pub expected_version: u64,
    pub max_allocations: Option<u32>,
    pub max_allocations_per_user: Option<u32>,
    pub max_bytes_per_sec_per_allocation: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct UserLimitsUpdate {
    pub node_id: String,
    pub idempotency_key: String,
    pub expected_version: u64,
    pub target: BackendUserLimitTarget,
    pub patch: BackendUserLimitsPatch,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AllocationEvent {
    pub event_type: EventType,
    pub allocation: AllocationInfo,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Created,
    Deleted,
    Refreshed,
    Expired,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("unimplemented: {0}")]
    Unimplemented(String),
}

impl From<CoreError> for Status {
    fn from(e: CoreError) -> Status {
        match e {
            CoreError::NotFound(m) => Status::not_found(m),
            CoreError::AlreadyExists(m) => Status::already_exists(m),
            CoreError::Invalid(m) => Status::invalid_argument(m),
            CoreError::FailedPrecondition(m) => Status::failed_precondition(m),
            CoreError::Internal(m) => Status::internal(m),
            CoreError::Unimplemented(m) => Status::unimplemented(m),
        }
    }
}

// ── Active-stream counter helpers ─────────────────────────────────────────────

/// RAII guard: increments the counter on creation, decrements on drop.
struct StreamGuard(Arc<AtomicU64>);

impl StreamGuard {
    fn new(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counter))
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Wrap `inner` so that the `active_streams` counter stays accurate:
/// - incremented when the stream is created,
/// - decremented when the stream is dropped (client disconnect, completion,
///   or cancellation).
///
/// Uses `futures::stream::unfold` internally. `take_until` must be applied
/// **before** passing to this function so the unfold future is Send.
fn counted_stream<S>(
    inner: S,
    active_streams: &Arc<AtomicU64>,
) -> impl Stream<Item = S::Item> + Send + 'static
where
    S: Stream + Send + 'static,
    S::Item: Send + 'static,
{
    let guard = StreamGuard::new(active_streams);
    futures::stream::unfold((Box::pin(inner), guard), |(mut s, g)| async move {
        // Use fully-qualified syntax to avoid ambiguity between
        // tokio_stream::StreamExt and futures::StreamExt.
        futures::StreamExt::next(&mut s)
            .await
            .map(|item| (item, (s, g)))
    })
}

// ── Proto conversion helpers ──────────────────────────────────────────────────

fn alloc_to_proto(a: AllocationInfo) -> Allocation {
    Allocation {
        id: a.id,
        username: a.username,
        realm: a.realm,
        client_address: a.client_address.to_string(),
        relay_address: a.relay_address.to_string(),
        created_at: ms_to_iso(a.created_at_ms),
        expires_at: ms_to_iso(a.expires_at_ms),
        remaining_lifetime: remaining_secs(a.expires_at_ms),
        transport: a.transport,
        address_family: a.address_family,
        organization: a.organization.unwrap_or_default(),
        traffic: Some(TrafficStats {
            bytes_from_client: a.bytes_in,
            bytes_to_client: a.bytes_out,
            packets_from_client: a.packets_in,
            packets_to_client: a.packets_out,
            bytes_from_peers: 0,
            bytes_to_peers: 0,
        }),
        permissions: a
            .permissions
            .into_iter()
            .map(|p| Permission {
                peer_address: p,
                expires_at: String::new(),
            })
            .collect(),
        channels: a
            .channels
            .into_iter()
            .map(|c| Channel {
                number: c.number as u32,
                peer_address: c.peer_addr,
                expires_at: ms_to_iso(c.expires_at_ms),
            })
            .collect(),
    }
}

fn ms_to_iso(ms: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let t = UNIX_EPOCH + Duration::from_millis(ms);
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            let s = secs % 60;
            let m = (secs / 60) % 60;
            let h = (secs / 3600) % 24;
            let days = secs / 86400;
            format!("{}T{:02}:{:02}:{:02}Z", days_to_date(days), h, m, s)
        }
        Err(_) => "1970-01-01T00:00:00Z".into(),
    }
}

fn days_to_date(days: u64) -> String {
    let year = 1970 + days / 365;
    let month = (days % 365) / 30 + 1;
    let day = (days % 365) % 30 + 1;
    format!("{year}-{month:02}-{day:02}")
}

fn remaining_secs(expires_at_ms: u64) -> u32 {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if expires_at_ms > now_ms {
        ((expires_at_ms - now_ms) / 1000) as u32
    } else {
        0
    }
}

fn event_type_to_proto(e: EventType) -> i32 {
    match e {
        EventType::Created => allocation_event::Type::Created as i32,
        EventType::Deleted => allocation_event::Type::Deleted as i32,
        EventType::Refreshed => allocation_event::Type::Refreshed as i32,
        EventType::Expired => allocation_event::Type::Expired as i32,
    }
}

// ── gRPC Service implementation ───────────────────────────────────────────────

struct TurnaManagementService {
    core: Arc<dyn TurnCore>,
    /// Fired when the server starts shutting down.
    shutdown_token: CancellationToken,
    /// Counts currently open streaming RPCs.
    active_streams: Arc<AtomicU64>,
    /// Tamper-evident audit log of privileged operations.
    audit: Arc<AuditLog>,
    /// #9 high-assurance: require an idempotency key on destructive ops
    /// (delete_allocation / set_draining / shutdown).
    require_idempotency_key: bool,
}

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl TurnaManagement for TurnaManagementService {
    // ── Allocations ───────────────────────────────────────────────────────────

    async fn list_allocations(
        &self,
        req: Request<ListAllocationsRequest>,
    ) -> Result<Response<ListAllocationsResponse>, Status> {
        let r = req.into_inner();
        let (allocs, next_token, total) = self
            .core
            .list_allocations(
                opt_str(&r.username_filter),
                opt_str(&r.organization_filter),
                if r.page_size == 0 {
                    100
                } else {
                    r.page_size as usize
                },
                opt_str(&r.page_token),
            )
            .await
            .map_err(Status::from)?;

        Ok(Response::new(ListAllocationsResponse {
            allocations: allocs.into_iter().map(alloc_to_proto).collect(),
            next_page_token: next_token.unwrap_or_default(),
            total_count: total as u32,
        }))
    }

    async fn get_allocation(
        &self,
        req: Request<GetAllocationRequest>,
    ) -> Result<Response<Allocation>, Status> {
        let alloc = self
            .core
            .get_allocation(&req.into_inner().id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(alloc_to_proto(alloc)))
    }

    async fn delete_allocation(
        &self,
        req: Request<DeleteAllocationRequest>,
    ) -> Result<Response<DeleteAllocationResponse>, Status> {
        // D-enforcement (fail-closed): never perform a destructive/privileged
        // operation we cannot record. If the audit log is degraded (write or
        // rotation failure), refuse rather than act unaudited.
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing destructive operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        // #9 high-assurance: destructive ops require an idempotency key so a
        // lost-response retry cannot create a second effect.
        if self.require_idempotency_key && r.idempotency_key.trim().is_empty() {
            return Err(Status::invalid_argument(
                "idempotency_key is required for this operation (high-assurance mode)",
            ));
        }
        let detail = format!("id={} reason={}", r.id, r.reason);
        // #2 durable intent: persist that we are about to act BEFORE the effect;
        // refuse if it cannot be made durable (never perform an unauditable op).
        if !self
            .audit
            .record_checked(&actor, "delete_allocation.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        let outcome = self
            .core
            .delete_allocation(&r.id, &r.reason, &r.idempotency_key)
            .await;
        self.audit
            .record(&actor, "delete_allocation", detail, outcome.is_ok());
        outcome.map_err(Status::from)?;
        Ok(Response::new(DeleteAllocationResponse { success: true }))
    }

    // ── Streaming: WatchAllocations ───────────────────────────────────────────

    type WatchAllocationsStream = BoxStream<AllocationEvent_>;

    async fn watch_allocations(
        &self,
        req: Request<WatchAllocationsRequest>,
    ) -> Result<Response<Self::WatchAllocationsStream>, Status> {
        let r = req.into_inner();
        let user_filter = r.username_filter.clone();
        let org_filter = r.organization_filter.clone();
        let rx = self.core.subscribe_events();
        let cancel = self.shutdown_token.clone();

        // Build filtered event stream.
        // filter_map comes from tokio_stream::StreamExt (imported via `as _`).
        let filtered = BroadcastStream::new(rx).filter_map(move |res| {
            let user_filter = user_filter.clone();
            let org_filter = org_filter.clone();
            match res {
                Ok(ev) => {
                    if !user_filter.is_empty() && ev.allocation.username != user_filter {
                        return None;
                    }
                    if !org_filter.is_empty()
                        && ev.allocation.organization.as_deref() != Some(&org_filter)
                    {
                        return None;
                    }
                    Some(Ok(AllocationEvent_ {
                        event_type: event_type_to_proto(ev.event_type),
                        allocation: Some(alloc_to_proto(ev.allocation)),
                        timestamp: ms_to_iso(now_ms()),
                        reason: ev.reason.unwrap_or_default(),
                    }))
                }
                Err(_) => None, // lagged — skip
            }
        });

        // Stop cleanly when the server shuts down.
        // UFCS avoids importing futures::StreamExt globally (which would
        // conflict with tokio_stream::StreamExt already in scope).
        let events =
            futures::StreamExt::take_until(filtered, async move { cancel.cancelled().await });

        // Wrap to keep grpc_active_streams accurate.
        let stream = counted_stream(events, &self.active_streams);
        Ok(Response::new(Box::pin(stream)))
    }

    // ── Config ────────────────────────────────────────────────────────────────

    async fn get_config(
        &self,
        req: Request<GetConfigRequest>,
    ) -> Result<Response<NodeRuntimeConfig>, Status> {
        let node_id = req.into_inner().node_id;
        if node_id.trim().is_empty() {
            return Err(Status::invalid_argument("node_id is required"));
        }
        let state = self.core.get_config(&node_id).await.map_err(Status::from)?;
        Ok(Response::new(node_runtime_to_proto(state)))
    }

    async fn update_config(
        &self,
        req: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing privileged operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        if r.node_id.trim().is_empty() {
            return Err(Status::invalid_argument("node_id is required"));
        }
        if r.idempotency_key.trim().is_empty() {
            return Err(Status::invalid_argument("idempotency_key is required"));
        }
        if r.max_allocations.is_none()
            && r.max_allocations_per_user.is_none()
            && r.max_bytes_per_sec_per_allocation.is_none()
        {
            return Err(Status::invalid_argument(
                "patch must contain at least one field",
            ));
        }
        let mut update = ConfigUpdate {
            node_id: r.node_id,
            idempotency_key: r.idempotency_key,
            expected_version: r.expected_version,
            max_allocations: r.max_allocations,
            max_allocations_per_user: r.max_allocations_per_user,
            max_bytes_per_sec_per_allocation: r.max_bytes_per_sec_per_allocation,
            reason: r.reason,
        };
        let changed_fields = [
            update.max_allocations.map(|_| "max_allocations"),
            update
                .max_allocations_per_user
                .map(|_| "max_allocations_per_user"),
            update
                .max_bytes_per_sec_per_allocation
                .map(|_| "max_bytes_per_sec_per_allocation"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        // §7: reason is mandatory for audit-critical mutations. Reject empty
        // input at ingress so it never enters the command log (InvalidArgument).
        update.reason = normalize_reason(&update.reason, "update_config")?;
        let audit_command = BackendUpdateConfigCommand {
            schema_version: 1,
            expected_version: update.expected_version,
            max_allocations: update.max_allocations.map(|value| value as usize),
            max_allocations_per_user: update.max_allocations_per_user.map(|value| value as usize),
            max_bytes_per_sec_per_allocation: update.max_bytes_per_sec_per_allocation,
            reason: update.reason.clone(),
        };
        let audit_payload = serde_json::to_string(&audit_command).map_err(|error| {
            Status::internal(format!("audit payload serialization failed: {error}"))
        })?;
        let payload_hash = command_payload_hash("update_config", &[], &audit_payload);
        let detail = format!(
            "node={} key={} payload_hash={} expected_version={} changed_fields={} reason={}",
            update.node_id,
            update.idempotency_key,
            payload_hash,
            update.expected_version,
            changed_fields.join(","),
            update.reason,
        );
        if !self
            .audit
            .record_checked(&actor, "update_config.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        match self.core.update_config(update).await {
            Ok(result) => {
                let complete = format!(
                    "{} previous_version={} observed_version={} changed={} status={} error={} rolled_back={}",
                    detail,
                    result.previous_version,
                    result.observed_version,
                    result.changed,
                    result.terminal_status,
                    result.error,
                    result.rolled_back,
                );
                let success = matches!(result.terminal_status.as_str(), "applied" | "no_op");
                self.audit
                    .record(&actor, "update_config", complete, success);
                Ok(Response::new(update_config_result_to_proto(result)))
            }
            Err(error) => {
                self.audit.record(
                    &actor,
                    "update_config",
                    format!("{detail} error={error}"),
                    false,
                );
                Err(Status::from(error))
            }
        }
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    async fn get_server_stats(
        &self,
        _req: Request<GetServerStatsRequest>,
    ) -> Result<Response<ServerStats>, Status> {
        let s = self.core.server_stats().await;
        Ok(Response::new(ServerStats {
            uptime_seconds: s.uptime_seconds,
            active_allocations: s.active_allocations,
            total_allocations: s.total_allocations,
            total_traffic: Some(TrafficStats {
                bytes_from_client: s.total_bytes_in,
                bytes_to_client: s.total_bytes_out,
                packets_from_client: 0,
                packets_to_client: 0,
                bytes_from_peers: 0,
                bytes_to_peers: 0,
            }),
            active_users: s.active_users,
            pps: s.pps,
            allocated_ports: s.allocated_ports,
            available_ports: s.available_ports,
            draining: s.draining,
            avg_latency_us: s.avg_latency_us,
            p99_latency_us: s.p99_latency_us,
            blocked_ips: s.blocked_ips,
            backend_mode: s.backend_mode,
        }))
    }

    async fn get_top_talkers(
        &self,
        req: Request<GetTopTalkersRequest>,
    ) -> Result<Response<GetTopTalkersResponse>, Status> {
        let r = req.into_inner();
        let talkers = self.core.top_talkers(r.limit as usize, &r.sort_by).await;
        Ok(Response::new(GetTopTalkersResponse {
            talkers: talkers
                .into_iter()
                .map(|t| TopTalker {
                    username: t.username,
                    organization: t.organization.unwrap_or_default(),
                    allocations: t.allocations,
                    total_bytes: t.total_bytes,
                    bandwidth_bps: t.bandwidth_bps,
                })
                .collect(),
        }))
    }

    // ── Streaming: WatchMetrics ───────────────────────────────────────────────

    type WatchMetricsStream = BoxStream<MetricsSnapshot>;

    async fn watch_metrics(
        &self,
        req: Request<WatchMetricsRequest>,
    ) -> Result<Response<Self::WatchMetricsStream>, Status> {
        let interval_secs = req.into_inner().interval_seconds.max(1);
        let core = self.core.clone();
        let cancel = self.shutdown_token.clone();

        let interval = tokio::time::interval(Duration::from_secs(interval_secs as u64));

        // then comes from tokio_stream::StreamExt (imported via `as _`).
        let polled = IntervalStream::new(interval).then(move |_| {
            let core = core.clone();
            async move {
                let s = core.server_stats().await;
                Ok(MetricsSnapshot {
                    timestamp: ms_to_iso(now_ms()),
                    stats: Some(ServerStats {
                        uptime_seconds: s.uptime_seconds,
                        active_allocations: s.active_allocations,
                        total_allocations: s.total_allocations,
                        total_traffic: Some(TrafficStats {
                            bytes_from_client: s.total_bytes_in,
                            bytes_to_client: s.total_bytes_out,
                            ..Default::default()
                        }),
                        active_users: s.active_users,
                        pps: s.pps,
                        allocated_ports: s.allocated_ports,
                        available_ports: s.available_ports,
                        draining: s.draining,
                        avg_latency_us: s.avg_latency_us,
                        p99_latency_us: s.p99_latency_us,
                        blocked_ips: s.blocked_ips,
                        backend_mode: s.backend_mode,
                    }),
                })
            }
        });

        let snapshots =
            futures::StreamExt::take_until(polled, async move { cancel.cancelled().await });
        let stream = counted_stream(snapshots, &self.active_streams);
        Ok(Response::new(Box::pin(stream)))
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    async fn add_user(
        &self,
        req: Request<AddUserRequest>,
    ) -> Result<Response<AddUserResponse>, Status> {
        // D-enforcement (fail-closed): never perform a destructive/privileged
        // operation we cannot record. If the audit log is degraded (write or
        // rotation failure), refuse rather than act unaudited.
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing destructive operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        // Record identifiers only — never the password.
        let detail = format!("user={} org={:?}", r.username, opt_str(&r.organization));
        // #2 durable intent: persist that we are about to act BEFORE the effect;
        // refuse if it cannot be made durable (never perform an unauditable op).
        if !self
            .audit
            .record_checked(&actor, "add_user.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        let outcome = self
            .core
            .add_user(&r.username, &r.password, opt_str(&r.organization))
            .await;
        self.audit
            .record(&actor, "add_user", detail, outcome.is_ok());
        outcome.map_err(Status::from)?;
        Ok(Response::new(AddUserResponse { success: true }))
    }

    async fn remove_user(
        &self,
        req: Request<RemoveUserRequest>,
    ) -> Result<Response<RemoveUserResponse>, Status> {
        // D-enforcement (fail-closed): never perform a destructive/privileged
        // operation we cannot record. If the audit log is degraded (write or
        // rotation failure), refuse rather than act unaudited.
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing destructive operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        let detail = format!("user={} force={}", r.username, r.force_delete_allocations);
        // #2 durable intent: persist that we are about to act BEFORE the effect;
        // refuse if it cannot be made durable (never perform an unauditable op).
        if !self
            .audit
            .record_checked(&actor, "remove_user.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        let outcome = self
            .core
            .remove_user(&r.username, r.force_delete_allocations)
            .await;
        self.audit
            .record(&actor, "remove_user", detail, outcome.is_ok());
        let deleted = outcome.map_err(Status::from)?;
        Ok(Response::new(RemoveUserResponse {
            success: true,
            allocations_deleted: deleted,
        }))
    }

    async fn set_user_limits(
        &self,
        req: Request<SetUserLimitsRequest>,
    ) -> Result<Response<SetUserLimitsResponse>, Status> {
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing privileged operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        if r.node_id.trim().is_empty() {
            return Err(Status::invalid_argument("node_id is required"));
        }
        if r.idempotency_key.trim().is_empty() {
            return Err(Status::invalid_argument("idempotency_key is required"));
        }
        let target = r
            .target
            .ok_or_else(|| Status::invalid_argument("target is required"))?;
        let patch = r
            .patch
            .ok_or_else(|| Status::invalid_argument("patch is required"))?;
        let mut update = UserLimitsUpdate {
            node_id: r.node_id,
            idempotency_key: r.idempotency_key,
            expected_version: r.expected_version,
            target: user_limit_target_from_proto(target)?,
            patch: user_limits_patch_from_proto(patch)?,
            reason: r.reason,
        };
        if update.patch.is_empty() {
            return Err(Status::invalid_argument(
                "patch must contain at least one field",
            ));
        }
        let changed_fields = [
            update
                .patch
                .max_allocations
                .as_ref()
                .map(|_| "max_allocations"),
            update
                .patch
                .max_bytes_per_sec_per_allocation
                .as_ref()
                .map(|_| "max_bytes_per_sec_per_allocation"),
            update
                .patch
                .max_lifetime_secs
                .as_ref()
                .map(|_| "max_lifetime_secs"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        // §7: reason is mandatory for audit-critical mutations. Reject empty
        // input at ingress so it never enters the command log (InvalidArgument).
        update.reason = normalize_reason(&update.reason, "set_user_limits")?;
        let audit_command = BackendSetUserLimitsCommand {
            schema_version: 1,
            expected_version: update.expected_version,
            target: update.target.clone(),
            patch: update.patch.clone(),
            reason: update.reason.clone(),
        };
        let audit_payload = serde_json::to_string(&audit_command).map_err(|error| {
            Status::internal(format!("audit payload serialization failed: {error}"))
        })?;
        let payload_hash = command_payload_hash("set_user_limits", &[], &audit_payload);
        let detail = format!(
            "node={} key={} payload_hash={} expected_version={} subject={} changed_fields={} reason={}",
            update.node_id,
            update.idempotency_key,
            payload_hash,
            update.expected_version,
            update.target.subject_key(),
            changed_fields.join(","),
            update.reason,
        );
        if !self
            .audit
            .record_checked(&actor, "set_user_limits.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        match self.core.set_user_limits(update).await {
            Ok(result) => {
                let complete = format!(
                    "{} previous_version={} observed_version={} max_user_allocations_in_scope={} max_user_allocations_above_limit={} status={} error={}",
                    detail,
                    result.previous_version,
                    result.observed_version,
                    result.max_user_allocations_in_scope,
                    result.max_user_allocations_above_limit,
                    result.terminal_status,
                    result.error,
                );
                let success = matches!(result.terminal_status.as_str(), "applied" | "no_op");
                self.audit
                    .record(&actor, "set_user_limits", complete, success);
                Ok(Response::new(set_user_limits_result_to_proto(result)))
            }
            Err(error) => {
                self.audit.record(
                    &actor,
                    "set_user_limits",
                    format!("{detail} error={error}"),
                    false,
                );
                Err(Status::from(error))
            }
        }
    }

    // ── Server control ────────────────────────────────────────────────────────

    async fn set_draining(
        &self,
        req: Request<SetDrainingRequest>,
    ) -> Result<Response<SetDrainingResponse>, Status> {
        // D-enforcement (fail-closed): never perform a destructive/privileged
        // operation we cannot record. If the audit log is degraded (write or
        // rotation failure), refuse rather than act unaudited.
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing destructive operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        // #9 high-assurance: destructive ops require an idempotency key so a
        // lost-response retry cannot create a second effect.
        if self.require_idempotency_key && r.idempotency_key.trim().is_empty() {
            return Err(Status::invalid_argument(
                "idempotency_key is required for this operation (high-assurance mode)",
            ));
        }
        let detail = format!("node={} draining={}", r.node_id, r.draining);
        // #2 durable intent: persist that we are about to act BEFORE the effect;
        // refuse if it cannot be made durable (never perform an unauditable op).
        if !self
            .audit
            .record_checked(&actor, "set_draining.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        let outcome = self
            .core
            .set_draining(&r.node_id, r.draining, &r.idempotency_key)
            .await;
        self.audit
            .record(&actor, "set_draining", detail, outcome.is_ok());
        let active = outcome.map_err(Status::from)?;
        Ok(Response::new(SetDrainingResponse {
            success: true,
            active_allocations: active,
        }))
    }

    async fn shutdown(
        &self,
        req: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        // D-enforcement (fail-closed): never perform a destructive/privileged
        // operation we cannot record. If the audit log is degraded (write or
        // rotation failure), refuse rather than act unaudited.
        if !self.audit.is_healthy() {
            return Err(Status::failed_precondition(
                "audit log degraded; refusing destructive operation (fail-closed)",
            ));
        }
        let actor = actor_of(&req);
        let r = req.into_inner();
        // #9 high-assurance: destructive ops require an idempotency key so a
        // lost-response retry cannot create a second effect.
        if self.require_idempotency_key && r.idempotency_key.trim().is_empty() {
            return Err(Status::invalid_argument(
                "idempotency_key is required for this operation (high-assurance mode)",
            ));
        }
        let detail = format!(
            "node={} graceful={} timeout_s={}",
            r.node_id, r.graceful, r.timeout_seconds
        );
        // #2 durable intent: persist that we are about to act BEFORE the effect;
        // refuse if it cannot be made durable (never perform an unauditable op).
        if !self
            .audit
            .record_checked(&actor, "shutdown.intent", &detail, true)
        {
            return Err(Status::failed_precondition(
                "audit intent not durable; refusing operation (fail-closed)",
            ));
        }
        let outcome = self
            .core
            .shutdown(
                &r.node_id,
                r.graceful,
                Duration::from_secs(r.timeout_seconds as u64),
                &r.idempotency_key,
            )
            .await;
        self.audit
            .record(&actor, "shutdown", detail, outcome.is_ok());
        let remaining = outcome.map_err(Status::from)?;
        Ok(Response::new(ShutdownResponse {
            accepted: true,
            remaining_allocations: remaining,
        }))
    }

    // ── Audit ─────────────────────────────────────────────────────────────────

    async fn verify_audit(
        &self,
        _req: Request<VerifyAuditRequest>,
    ) -> Result<Response<VerifyAuditResponse>, Status> {
        let (intact, broken_at_seq) = match self.audit.verify() {
            Ok(_) => (true, 0),
            Err(seq) => (false, seq),
        };
        let mut resp = VerifyAuditResponse {
            intact,
            broken_at_seq,
            total_recorded: self.audit.total_recorded(),
            retained: self.audit.len() as u64,
            disk_checked: false,
            disk_intact: false,
            disk_broken_at_seq: 0,
            disk_entries: 0,
            disk_first_seq: 0,
            disk_last_seq: 0,
            disk_segments: 0,
        };
        // When persistence is enabled, also verify the full on-disk chain across
        // every rotated segment plus the live file.
        if let Some(result) = self.audit.verify_persisted_self() {
            resp.disk_checked = true;
            match result {
                Ok(v) => {
                    resp.disk_intact = true;
                    resp.disk_entries = v.entries;
                    resp.disk_first_seq = v.first_seq;
                    resp.disk_last_seq = v.last_seq;
                    resp.disk_segments = v.segments as u64;
                }
                Err(crate::audit::AuditVerifyError::ChainBreak { seq }) => {
                    resp.disk_broken_at_seq = seq;
                }
                Err(_) => {}
            }
        }
        Ok(Response::new(resp))
    }

    async fn get_audit_log(
        &self,
        req: Request<GetAuditLogRequest>,
    ) -> Result<Response<GetAuditLogResponse>, Status> {
        let limit = req.into_inner().limit as usize;
        let mut snap = self.audit.snapshot();
        if limit != 0 && snap.len() > limit {
            // Keep the most recent `limit` entries.
            snap = snap.split_off(snap.len() - limit);
        }
        let records = snap
            .into_iter()
            .map(|e| AuditRecord {
                seq: e.seq,
                ts_ms: e.ts_ms,
                actor: e.actor,
                action: e.action,
                detail: e.detail,
                outcome: e.outcome,
                prev_hash: crate::audit::hex32(&e.prev_hash),
                entry_hash: crate::audit::hex32(&e.entry_hash),
            })
            .collect();
        Ok(Response::new(GetAuditLogResponse {
            records,
            total_recorded: self.audit.total_recorded(),
        }))
    }
}

// ── Type aliases for generated streaming types ────────────────────────────────
type AllocationEvent_ = proto::AllocationEvent;

// ── Server launcher ───────────────────────────────────────────────────────────

/// Retained in-memory audit entries (tail); the complete chain is emitted on the
/// `audit` tracing target regardless of this cap.
const AUDIT_RING_CAPACITY: usize = 1024;

/// Caller identity for the audit log. Prefers the authenticated mTLS client
/// credential: a SHA-256 fingerprint of the peer's leaf certificate uniquely
/// identifies the client without parsing the X.509 structure (no extra
/// dependency). Falls back to the peer socket address when no client
/// certificate is presented (server-only TLS / loopback).
/// Identify the caller, and log their correlation id if they sent one.
///
/// The logging lives here rather than in each RPC because every operation that
/// needs to know who called it already calls this — five call sites instead of
/// sixteen, and no way for a new privileged RPC to forget.
///
/// A `debug!` rather than `info!`: the id is only useful to somebody already
/// tracing a specific request, and an unconditional line per RPC on a management
/// plane that also serves streaming metrics is noise. The RPC's own audit entry
/// and error paths log at info.
fn actor_of<T>(req: &Request<T>) -> String {
    let correlation = correlation_of(req);
    if !correlation.is_empty() {
        tracing::debug!(
            target: "management",
            correlation_id = %correlation,
            "management RPC carries a caller correlation id"
        );
    }
    if let Some(certs) = req.peer_certs() {
        if let Some(leaf) = certs.first() {
            let der: &[u8] = leaf.as_ref();
            let fp = turna_crypto::sha256(der);
            return format!("cert:{}", crate::audit::hex32(&fp));
        }
    }
    req.remote_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Metadata key carrying a caller-supplied correlation identifier.
///
/// Lower-case because gRPC metadata keys are case-insensitive but tonic requires
/// the lower form when constructing them.
pub const CORRELATION_HEADER: &str = "x-turna-correlation-id";

/// Maximum length kept. Long enough for a UUID, a W3C traceparent, or a
/// reasonable composite; short enough that a caller cannot use it as a channel.
const CORRELATION_MAX: usize = 128;

/// A caller's opaque correlation identifier, or empty if absent.
///
/// **Sanitised deliberately.** This string arrives from whoever called the RPC
/// and lands in a log line and an audit entry. A newline in it would let a caller
/// write a second audit record of their choosing, and the audit log is
/// hash-chained precisely because its contents are meant to be trustworthy —
/// a chain over forgeable entries proves only that the forgery came in order.
///
/// So: printable ASCII only, everything else dropped rather than escaped, and
/// truncated. Dropped rather than escaped because an escaped control character is
/// still a control character to the next thing that unescapes it, and this value
/// passes through more than one consumer.
fn correlation_of<T>(req: &Request<T>) -> String {
    let Some(raw) = req.metadata().get(CORRELATION_HEADER) else {
        return String::new();
    };
    let Ok(s) = raw.to_str() else {
        // Binary metadata under a text key: the caller sent something that is not
        // an identifier. Ignored rather than lossily decoded.
        return String::new();
    };
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(CORRELATION_MAX)
        .collect()
}

/// Start the gRPC management server with graceful shutdown support.
///
/// When `shutdown` resolves (e.g. on SIGTERM):
/// 1. New connections are rejected immediately.
/// 2. Active streaming RPCs are cancelled via `CancellationToken`.
/// 3. Drain loop waits up to `config.drain_timeout` then exits.
///
/// # Example
/// ```ignore
/// let (tx, mut rx) = tokio::sync::watch::channel(false);
/// // signal handler: tx.send(true)
/// let shutdown_fut = async move { rx.changed().await.ok(); };
/// start_grpc_server(GrpcConfig::default(), core, metrics, shutdown_fut).await?;
/// ```
pub async fn start_grpc_server(
    config: GrpcConfig,
    core: Arc<dyn TurnCore>,
    metrics: Arc<Metrics>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let shutdown_token = CancellationToken::new();
    let active_streams = Arc::new(AtomicU64::new(0));

    // Audit sink. Persistent + tamper-evident when TURNA_AUDIT_LOG_PATH is set;
    // the HMAC key comes from TURNA_AUDIT_HMAC_KEY (hex, out-of-band — never in
    // the log). If persistence is requested but the existing chain fails to open
    // or verify, we FAIL CLOSED (refuse to start) rather than silently downgrade
    // to in-memory, which would hide tampering.
    let audit = {
        // Distinguish "unset" (unkeyed integrity-only is allowed) from "set but
        // invalid" (a typo would silently disable tamper-evidence — fail closed).
        let key = match std::env::var("TURNA_AUDIT_HMAC_KEY") {
            Ok(h) if !h.is_empty() => match crate::audit::parse_hex_key(&h) {
                Some(k) if k.len() >= 32 => Some(k),
                Some(_) => {
                    return Err("TURNA_AUDIT_HMAC_KEY must be at least 32 bytes \
                                (64 hex chars) of random key material"
                        .into());
                }
                None => {
                    return Err("TURNA_AUDIT_HMAC_KEY is set but is not valid hex; \
                                refusing to start (a typo would silently disable \
                                the audit log's tamper-evidence)"
                        .into());
                }
            },
            _ => None,
        };
        match std::env::var("TURNA_AUDIT_LOG_PATH") {
            Ok(p) if !p.is_empty() => {
                if key.is_none() {
                    warn!(
                        "TURNA_AUDIT_LOG_PATH set without a valid TURNA_AUDIT_HMAC_KEY:                          the audit log is integrity-only, not tamper-evident against a                          privileged attacker"
                    );
                }
                match AuditLog::open(AUDIT_RING_CAPACITY, &p, key) {
                    Ok(log) => {
                        info!(path = %p, "management audit log persistence enabled");
                        Arc::new(log)
                    }
                    Err(e) => {
                        return Err(format!(
                            "audit log open/verify failed for {p}: {e:?} (refusing to                              start; persistence was explicitly requested)"
                        )
                        .into());
                    }
                }
            }
            _ => Arc::new(AuditLog::new(AUDIT_RING_CAPACITY)),
        }
    };

    // #9: high-assurance mode — require an idempotency key on destructive ops so a
    // lost-response retry cannot create a second effect. Off by default.
    let require_idempotency_key = matches!(
        std::env::var("TURNA_REQUIRE_IDEMPOTENCY_KEY")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    );

    let svc = TurnaManagementServer::new(TurnaManagementService {
        core,
        shutdown_token: shutdown_token.clone(),
        active_streams: Arc::clone(&active_streams),
        audit,
        require_idempotency_key,
    })
    .max_decoding_message_size(config.max_message_size)
    .max_encoding_message_size(config.max_message_size);

    let mut builder = Server::builder();

    if let Some(tls_cfg) = &config.tls {
        let cert = std::fs::read(&tls_cfg.server_cert)?;
        let key = std::fs::read(&tls_cfg.server_key)?;
        let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(&cert, &key));
        if tls_cfg.require_client_auth {
            // mTLS: require and verify a client certificate against the CA.
            let ca = std::fs::read(&tls_cfg.client_ca_cert)?;
            tls = tls.client_ca_root(Certificate::from_pem(&ca));
            builder = builder.tls_config(tls)?;
            info!(addr = %config.listen_addr,
                  "gRPC management server starting (mTLS — client certificate required)");
        } else {
            // server-only TLS: do NOT set client_ca_root, so clients are not
            // asked for a certificate. Authenticate them by another mechanism.
            builder = builder.tls_config(tls)?;
            info!(addr = %config.listen_addr,
                  "gRPC management server starting (TLS — server-only, no client certificate)");
        }
    } else {
        info!(addr = %config.listen_addr, "gRPC management server starting (no TLS — dev mode)");
    }

    let drain_timeout = config.drain_timeout;
    let listen_addr = config.listen_addr;

    let shutdown_sequence = async move {
        // Step 1: wait for external signal
        shutdown.await;
        info!(addr = %listen_addr, "gRPC shutdown signal — cancelling active streams");

        // Step 2: cancel all streaming RPCs
        shutdown_token.cancel();

        // Step 3: drain loop
        let drain_start = std::time::Instant::now();
        let forced = loop {
            let active = active_streams.load(Ordering::Relaxed);
            if active == 0 {
                break false;
            }
            if drain_start.elapsed() >= drain_timeout {
                warn!(
                    active_streams = active,
                    timeout_secs = drain_timeout.as_secs(),
                    "gRPC drain timeout — forcing shutdown"
                );
                break true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        // Step 4: record metrics
        let drain_ms = drain_start.elapsed().as_millis() as u64;
        metrics
            .grpc_shutdown_drain_ms
            .store(drain_ms, Ordering::Relaxed);
        if forced {
            metrics.grpc_forced_kills.fetch_add(1, Ordering::Relaxed);
        }

        info!(drain_ms, forced, "gRPC graceful drain complete");
    };

    builder
        .add_service(svc)
        .serve_with_shutdown(config.listen_addr, shutdown_sequence)
        .await?;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn runtime_snapshot_to_proto(
    snapshot: turna_state_backend::RuntimeConfigSnapshot,
) -> RuntimeConfigSnapshot {
    RuntimeConfigSnapshot {
        version: snapshot.version,
        max_allocations: snapshot.max_allocations.min(u32::MAX as usize) as u32,
        max_allocations_per_user: snapshot.max_allocations_per_user.min(u32::MAX as usize) as u32,
        max_bytes_per_sec_per_allocation: snapshot.max_bytes_per_sec_per_allocation,
    }
}

fn node_runtime_to_proto(state: NodeRuntimeState) -> NodeRuntimeConfig {
    let pending = if state.desired_version != state.observed_version || state.status != "observed" {
        Some(runtime_snapshot_to_proto(state.desired_snapshot))
    } else {
        None
    };
    NodeRuntimeConfig {
        node_id: state.node_id,
        desired_version: state.desired_version,
        observed_version: state.observed_version,
        observed: Some(runtime_snapshot_to_proto(state.observed_snapshot)),
        pending_desired: pending,
        status: state.status,
        last_apply_error: state.last_error,
        updated_at_ms: state.updated_at_ms,
    }
}

fn update_config_result_to_proto(result: UpdateConfigResult) -> UpdateConfigResponse {
    UpdateConfigResponse {
        request_id: result.request_id,
        previous_version: result.previous_version,
        observed_version: result.observed_version,
        changed: result.changed,
        applied: Some(runtime_snapshot_to_proto(result.applied)),
        terminal_status: result.terminal_status,
        error: result.error,
        rolled_back: result.rolled_back,
    }
}

fn limit_mode_from_proto(mode: i32) -> Result<BackendLimitMode, Status> {
    match LimitMode::try_from(mode).map_err(|_| Status::invalid_argument("invalid limit mode"))? {
        LimitMode::Inherit => Ok(BackendLimitMode::Inherit),
        LimitMode::Value => Ok(BackendLimitMode::Value),
        LimitMode::Unlimited => Ok(BackendLimitMode::Unlimited),
        LimitMode::Disabled => Ok(BackendLimitMode::Disabled),
    }
}

fn limit_u32_from_proto(value: UInt32Limit) -> Result<BackendLimitU32, Status> {
    let mode = limit_mode_from_proto(value.mode)?;
    if mode == BackendLimitMode::Value && value.value == 0 {
        return Err(Status::invalid_argument(
            "VALUE requires a non-zero value; use UNLIMITED or DISABLED explicitly",
        ));
    }
    if mode != BackendLimitMode::Value && value.value != 0 {
        return Err(Status::invalid_argument(
            "limit value must be zero unless mode is VALUE",
        ));
    }
    Ok(BackendLimitU32 {
        mode,
        value: value.value,
    })
}

fn limit_u64_from_proto(value: UInt64Limit) -> Result<BackendLimitU64, Status> {
    let mode = limit_mode_from_proto(value.mode)?;
    if mode == BackendLimitMode::Value && value.value == 0 {
        return Err(Status::invalid_argument(
            "VALUE requires a non-zero value; use UNLIMITED or DISABLED explicitly",
        ));
    }
    if mode != BackendLimitMode::Value && value.value != 0 {
        return Err(Status::invalid_argument(
            "limit value must be zero unless mode is VALUE",
        ));
    }
    Ok(BackendLimitU64 {
        mode,
        value: value.value,
    })
}

fn user_limits_patch_from_proto(patch: UserLimitsPatch) -> Result<BackendUserLimitsPatch, Status> {
    Ok(BackendUserLimitsPatch {
        max_allocations: patch
            .max_allocations
            .map(limit_u32_from_proto)
            .transpose()?,
        max_bytes_per_sec_per_allocation: patch
            .max_bytes_per_sec_per_allocation
            .map(limit_u64_from_proto)
            .transpose()?,
        max_lifetime_secs: patch
            .max_lifetime_secs
            .map(limit_u32_from_proto)
            .transpose()?,
    })
}

/// §7-B: maximum accepted length (in characters) of an audit `reason`.
const MAX_REASON_LEN: usize = 500;

/// §7-B: normalise an audit-critical `reason`. Trim surrounding whitespace,
/// reject empty input, cap the length, and forbid control characters so that a
/// single-line, bounded, normalised value is what enters the command log and
/// audit trail. Returns InvalidArgument on any violation.
fn normalize_reason(reason: &str, op: &str) -> Result<String, Status> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{op}: reason is required and must not be empty"
        )));
    }
    if trimmed.chars().count() > MAX_REASON_LEN {
        return Err(Status::invalid_argument(format!(
            "{op}: reason must be at most {MAX_REASON_LEN} characters"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(Status::invalid_argument(format!(
            "{op}: reason must not contain control characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn user_limit_target_from_proto(target: UserLimitTarget) -> Result<BackendUserLimitTarget, Status> {
    let scope = match UserLimitScope::try_from(target.scope)
        .map_err(|_| Status::invalid_argument("invalid user-limit scope"))?
    {
        UserLimitScope::Unspecified => {
            return Err(Status::invalid_argument(
                "user-limit scope is required and must not be UNSPECIFIED",
            ));
        }
        UserLimitScope::Global => BackendUserLimitScope::Global,
        UserLimitScope::Tenant => BackendUserLimitScope::Tenant,
        UserLimitScope::User => BackendUserLimitScope::User,
    };
    match scope {
        BackendUserLimitScope::Global => {
            if !target.tenant.is_empty() || !target.realm.is_empty() || !target.username.is_empty()
            {
                return Err(Status::invalid_argument(
                    "global target must not contain realm, tenant, or username",
                ));
            }
        }
        BackendUserLimitScope::Tenant => {
            if target.realm.trim().is_empty() || target.tenant.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "tenant target requires non-empty realm and tenant",
                ));
            }
            if !target.username.is_empty() {
                return Err(Status::invalid_argument(
                    "tenant target must not contain username",
                ));
            }
        }
        BackendUserLimitScope::User => {
            if target.realm.trim().is_empty() || target.username.trim().is_empty() {
                return Err(Status::invalid_argument(
                    "user target requires non-empty realm and username; tenant may be empty for the base realm",
                ));
            }
        }
    }
    Ok(BackendUserLimitTarget {
        scope,
        tenant: target.tenant,
        realm: target.realm,
        username: target.username,
    })
}

fn set_user_limits_result_to_proto(result: SetUserLimitsResult) -> SetUserLimitsResponse {
    SetUserLimitsResponse {
        request_id: result.request_id,
        previous_version: result.previous_version,
        observed_version: result.observed_version,
        effective: Some(EffectiveUserLimits {
            max_allocations: result.effective.max_allocations,
            max_bytes_per_sec_per_allocation: result.effective.max_bytes_per_sec_per_allocation,
            max_lifetime_secs: result.effective.max_lifetime_secs,
            inherited_fields: result.effective.inherited_fields,
            capped_fields: result.effective.capped_fields,
            allocations_disabled: result.effective.allocations_disabled,
            bandwidth_disabled: result.effective.bandwidth_disabled,
            lifetime_disabled: result.effective.lifetime_disabled,
        }),
        max_user_allocations_in_scope: result.max_user_allocations_in_scope,
        max_user_allocations_above_limit: result.max_user_allocations_above_limit,
        terminal_status: result.terminal_status,
        error: result.error,
    }
}

fn opt_str(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_error_to_status() {
        assert_eq!(
            Status::from(CoreError::NotFound("x".into())).code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            Status::from(CoreError::Invalid("x".into())).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            Status::from(CoreError::Internal("x".into())).code(),
            tonic::Code::Internal
        );
        assert_eq!(
            Status::from(CoreError::AlreadyExists("x".into())).code(),
            tonic::Code::AlreadyExists
        );
    }

    #[test]
    fn remaining_secs_future() {
        let future_ms = now_ms() + 60_000;
        let r = remaining_secs(future_ms);
        assert!((59..=60).contains(&r), "expected ~60s remaining, got {r}");
    }

    #[test]
    fn remaining_secs_past() {
        assert_eq!(remaining_secs(0), 0);
    }

    #[test]
    fn opt_str_empty() {
        assert_eq!(opt_str(""), None);
        assert_eq!(opt_str("user"), Some("user"));
    }

    #[test]
    fn update_config_optional_zero_roundtrips_with_presence() {
        use prost::Message;

        let absent = UpdateConfigRequest {
            node_id: "node-a".into(),
            idempotency_key: "key-a".into(),
            expected_version: 0,
            max_allocations: None,
            max_allocations_per_user: None,
            max_bytes_per_sec_per_allocation: None,
            reason: String::new(),
        };
        let explicit_zero = UpdateConfigRequest {
            max_bytes_per_sec_per_allocation: Some(0),
            ..absent.clone()
        };

        let decoded_absent =
            UpdateConfigRequest::decode(absent.encode_to_vec().as_slice()).unwrap();
        let decoded_zero =
            UpdateConfigRequest::decode(explicit_zero.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded_absent.max_bytes_per_sec_per_allocation, None);
        assert_eq!(decoded_zero.max_bytes_per_sec_per_allocation, Some(0));
    }

    #[test]
    fn user_limit_modes_do_not_overload_zero() {
        assert_eq!(
            limit_u32_from_proto(UInt32Limit {
                mode: LimitMode::Unlimited as i32,
                value: 0,
            })
            .unwrap()
            .mode,
            BackendLimitMode::Unlimited
        );
        assert_eq!(
            limit_u32_from_proto(UInt32Limit {
                mode: LimitMode::Disabled as i32,
                value: 0,
            })
            .unwrap()
            .mode,
            BackendLimitMode::Disabled
        );
        assert!(limit_u32_from_proto(UInt32Limit {
            mode: LimitMode::Value as i32,
            value: 0,
        })
        .is_err());
        assert!(limit_u32_from_proto(UInt32Limit {
            mode: LimitMode::Inherit as i32,
            value: 1,
        })
        .is_err());
    }

    #[test]
    fn stream_guard_increments_and_decrements() {
        let counter = Arc::new(AtomicU64::new(0));
        {
            let _g1 = StreamGuard::new(&counter);
            assert_eq!(counter.load(Ordering::Relaxed), 1);
            let _g2 = StreamGuard::new(&counter);
            assert_eq!(counter.load(Ordering::Relaxed), 2);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn counted_stream_decrements_on_exhaustion() {
        let counter = Arc::new(AtomicU64::new(0));
        let items = futures::stream::iter(vec![1u32, 2, 3]);
        let mut s = Box::pin(counted_stream(items, &counter));

        assert_eq!(counter.load(Ordering::Relaxed), 1);
        while futures::StreamExt::next(&mut s).await.is_some() {}
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn counted_stream_decrements_on_drop() {
        let counter = Arc::new(AtomicU64::new(0));
        let items = futures::stream::iter(vec![1u32, 2, 3]);
        let s = Box::pin(counted_stream(items, &counter));

        assert_eq!(counter.load(Ordering::Relaxed), 1);
        drop(s);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn normalize_reason_trims_and_validates() {
        // Valid input is trimmed.
        assert_eq!(
            normalize_reason("  tighten quota  ", "update_config").unwrap(),
            "tighten quota"
        );
        // Empty / whitespace-only is rejected.
        assert!(normalize_reason("", "update_config").is_err());
        assert!(normalize_reason("   ", "set_user_limits").is_err());
        // Control characters (newline, tab, NUL) are rejected.
        assert!(normalize_reason("line1\nline2", "update_config").is_err());
        assert!(normalize_reason("tab\there", "update_config").is_err());
        assert!(normalize_reason("nul\0", "set_user_limits").is_err());
        // At the length limit is accepted; over the limit is rejected.
        assert!(normalize_reason(&"x".repeat(MAX_REASON_LEN), "update_config").is_ok());
        assert!(normalize_reason(&"x".repeat(MAX_REASON_LEN + 1), "update_config").is_err());
    }
}
