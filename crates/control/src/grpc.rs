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
    pub client_ca_cert: PathBuf,
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
    async fn delete_allocation(&self, id: &str, reason: &str) -> Result<(), CoreError>;
    async fn server_stats(&self) -> ServerStatsInfo;
    async fn top_talkers(&self, limit: usize, sort_by: &str) -> Vec<TopTalkerInfo>;
    async fn update_config(&self, update: ConfigUpdate) -> Result<(), CoreError>;
    async fn add_user(&self, user: &str, pass: &str, org: Option<&str>) -> Result<(), CoreError>;
    async fn remove_user(&self, user: &str, force: bool) -> Result<u32, CoreError>;
    async fn set_draining(&self, draining: bool) -> Result<u32, CoreError>;
    async fn shutdown(&self, graceful: bool, timeout: Duration) -> Result<u32, CoreError>;
    fn subscribe_events(&self) -> broadcast::Receiver<AllocationEvent>;
    fn get_config(&self) -> CurrentConfig;
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
    pub max_lifetime: Option<u32>,
    pub max_allocations_per_user: Option<u32>,
    pub max_bandwidth_per_user_bps: Option<u64>,
    pub draining: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CurrentConfig {
    pub realm: String,
    pub min_port: u32,
    pub max_port: u32,
    pub default_lifetime: u32,
    pub max_lifetime: u32,
    pub max_allocations_per_user: u32,
    pub max_bandwidth_per_user_bps: u64,
    pub draining: bool,
    pub external_ipv4: String,
    pub listen_addresses: Vec<String>,
    pub nonce_lifetime_seconds: u32,
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
        let r = req.into_inner();
        self.core
            .delete_allocation(&r.id, &r.reason)
            .await
            .map_err(Status::from)?;
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
        _req: Request<GetConfigRequest>,
    ) -> Result<Response<ServerConfig>, Status> {
        let c = self.core.get_config();
        Ok(Response::new(ServerConfig {
            realm: c.realm,
            min_port: c.min_port,
            max_port: c.max_port,
            default_lifetime: c.default_lifetime,
            max_lifetime: c.max_lifetime,
            max_allocations_per_user: c.max_allocations_per_user,
            max_bandwidth_per_user_bps: c.max_bandwidth_per_user_bps,
            draining: c.draining,
            external_ipv4: c.external_ipv4,
            external_ipv6: String::new(),
            listen_addresses: c.listen_addresses,
            nonce_lifetime_seconds: c.nonce_lifetime_seconds,
        }))
    }

    async fn update_config(
        &self,
        req: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        let r = req.into_inner();
        let update = ConfigUpdate {
            max_lifetime: r.max_lifetime,
            max_allocations_per_user: r.max_allocations_per_user,
            max_bandwidth_per_user_bps: r.max_bandwidth_per_user_bps,
            draining: r.draining,
        };
        self.core
            .update_config(update)
            .await
            .map_err(Status::from)?;
        let c = self.core.get_config();
        Ok(Response::new(UpdateConfigResponse {
            success: true,
            current: Some(ServerConfig {
                realm: c.realm,
                min_port: c.min_port,
                max_port: c.max_port,
                default_lifetime: c.default_lifetime,
                max_lifetime: c.max_lifetime,
                max_allocations_per_user: c.max_allocations_per_user,
                max_bandwidth_per_user_bps: c.max_bandwidth_per_user_bps,
                draining: c.draining,
                external_ipv4: c.external_ipv4,
                external_ipv6: String::new(),
                listen_addresses: c.listen_addresses,
                nonce_lifetime_seconds: c.nonce_lifetime_seconds,
            }),
            warnings: vec![],
        }))
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
        let r = req.into_inner();
        self.core
            .add_user(&r.username, &r.password, opt_str(&r.organization))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(AddUserResponse { success: true }))
    }

    async fn remove_user(
        &self,
        req: Request<RemoveUserRequest>,
    ) -> Result<Response<RemoveUserResponse>, Status> {
        let r = req.into_inner();
        let deleted = self
            .core
            .remove_user(&r.username, r.force_delete_allocations)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(RemoveUserResponse {
            success: true,
            allocations_deleted: deleted,
        }))
    }

    async fn set_user_limits(
        &self,
        _req: Request<SetUserLimitsRequest>,
    ) -> Result<Response<SetUserLimitsResponse>, Status> {
        // The per-user rate limiter this RPC was meant to drive was dead code
        // (never wired to the datapath) and has been removed (M3). Returning a
        // fake `success: true` created a false sense of enforcement; report it
        // honestly as unimplemented instead.
        Err(Status::unimplemented(
            "per-user rate limits are not implemented",
        ))
    }

    // ── Server control ────────────────────────────────────────────────────────

    async fn set_draining(
        &self,
        req: Request<SetDrainingRequest>,
    ) -> Result<Response<SetDrainingResponse>, Status> {
        let r = req.into_inner();
        let active = self
            .core
            .set_draining(r.draining)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(SetDrainingResponse {
            success: true,
            active_allocations: active,
        }))
    }

    async fn shutdown(
        &self,
        req: Request<ShutdownRequest>,
    ) -> Result<Response<ShutdownResponse>, Status> {
        let r = req.into_inner();
        let remaining = self
            .core
            .shutdown(r.graceful, Duration::from_secs(r.timeout_seconds as u64))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(ShutdownResponse {
            accepted: true,
            remaining_allocations: remaining,
        }))
    }
}

// ── Type aliases for generated streaming types ────────────────────────────────
type AllocationEvent_ = proto::AllocationEvent;

// ── Server launcher ───────────────────────────────────────────────────────────

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

    let svc = TurnaManagementServer::new(TurnaManagementService {
        core,
        shutdown_token: shutdown_token.clone(),
        active_streams: Arc::clone(&active_streams),
    })
    .max_decoding_message_size(config.max_message_size)
    .max_encoding_message_size(config.max_message_size);

    let mut builder = Server::builder();

    if let Some(tls_cfg) = &config.tls {
        let cert = std::fs::read(&tls_cfg.server_cert)?;
        let key = std::fs::read(&tls_cfg.server_key)?;
        let ca = std::fs::read(&tls_cfg.client_ca_cert)?;
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(&cert, &key))
            .client_ca_root(Certificate::from_pem(&ca));
        builder = builder.tls_config(tls)?;
        info!(addr = %config.listen_addr, "gRPC management server starting (mTLS)");
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
}
