//! Health check HTTP endpoint
//!
//! Minimal HTTP server on a separate port. No external HTTP framework.
//! - GET /health  → 200 OK / 503 draining
//! - GET /ready   → 200 OK / 503 (not ready or draining)
//! - GET /status  → JSON with node stats
//! - GET /metrics → Prometheus text format
pub mod load_reporter;

use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

/// 2.4 process readiness state. Surfaced on `/ready` and as the
/// `turna_backend_readiness` gauge (0=starting, 1=ready, 2=degraded, 3=draining).
/// NOTE: single process-level state machine; true per-backend readiness
/// (separate state per tokio/io_uring/dtls/af_xdp) is not yet wired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    Starting = 0,
    Ready = 1,
    Degraded = 2,
    Draining = 3,
}

impl Readiness {
    fn from_u8(v: u8) -> Readiness {
        match v {
            1 => Readiness::Ready,
            2 => Readiness::Degraded,
            3 => Readiness::Draining,
            _ => Readiness::Starting,
        }
    }
}
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

/// One node as reported by `GET /cluster`.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterNodeInfo {
    pub node_id: String,
    pub turn_addr: String,
    /// True for the node answering the request.
    pub is_self: bool,
}

/// Supplies the current cluster membership to the health server's `/cluster`
/// endpoint. Implemented in turna-node over the gossip ring; a single-node
/// deployment returns just the local node, so the endpoint behaves the same
/// whether you run one instance or many.
pub trait ClusterView: Send + Sync {
    fn nodes(&self) -> Vec<ClusterNodeInfo>;
}

/// Shared metrics that are updated by relay workers.
pub struct Metrics {
    pub is_draining: AtomicBool,
    /// 2.4 readiness: traffic path usable (set once listeners are up).
    pub readiness: AtomicU8,
    /// P0.5 derived-readiness input: in-memory state has diverged from the
    /// backend (write drops seen, not yet reconciled). Combined with `is_draining`
    /// by `refresh_readiness`, so an undrain cannot mask an active divergence.
    pub backend_diverged: AtomicBool,
    /// 2.4 per-backend readiness (observability). With fail-fast startup these
    /// are all-or-nothing at boot; `Degraded` is reserved for future
    /// non-fatal backend failures.
    pub transport_readiness: AtomicU8,
    pub dtls_readiness: AtomicU8,
    pub tls_readiness: AtomicU8,
    pub sctp_readiness: AtomicU8,
    pub quic_readiness: AtomicU8,
    /// AF_XDP datapath readiness, same encoding as the others. AF_XDP was the only
    /// datapath still sharing the process-level `backend_readiness`, which meant a
    /// dead XSK socket was indistinguishable from a dead tokio datapath — and on a
    /// kernel-bypass path that is exactly the failure worth naming.
    pub afxdp_readiness: AtomicU8,
    /// #6/#4.5: management-plane readiness sub-signal (0=starting, 1=ready,
    /// 2=degraded, 3=draining), DISTINCT from the dataplane `readiness` flag so a
    /// bounded/resumable command-log migration gates the management plane without
    /// holding the TURN dataplane not-ready. Ready only once the mandatory
    /// migration phases complete; a non-management node leaves it Ready (nothing
    /// to gate). Exposed as `turna_management_readiness`.
    pub management_readiness: AtomicU8,
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub active_allocations: AtomicU64,
    pub total_allocations: AtomicU64,

    // Capacity limits, published by the node at startup rather than read from
    // config here: this crate has no view of config, and threading it in would
    // mean changing `serve_*`'s signature for the third time this week.
    //
    // `capacity_max_allocations == 0` means "not published", which is reported as
    // UNAVAILABLE rather than as unlimited headroom. An unset limit read as
    // infinite capacity is exactly the kind of default that puts a node into
    // service claiming room it does not have.
    // Relay port pool occupancy, summed across the global pool and any
    // tenant pools. Summed rather than labelled per tenant: labels are how a
    // Prometheus instance dies when a customer has ten thousand tenants, and
    // §10 asks for cardinality protection in the same specification that asks
    // for this metric. Per-tenant detail: AllocationStore::port_pool_usage().
    /// Relayed traffic rate over the last ten seconds. Fed by a one-second
    /// ticker in the node; read by `/capacity` and, later, by admission
    /// control.
    pub rates: RateSampler,

    /// Host CPU and memory, whole percent, refreshed every five seconds by a
    /// sampler task in the node.
    ///
    /// `u64::MAX` means "never sampled" — distinct from 0, which is a real and
    /// unremarkable reading. Without that distinction a node whose sampler had
    /// died would look idle, which is the worst possible way to be wrong about
    /// load.
    pub host_cpu_percent: AtomicU64,
    pub host_memory_percent: AtomicU64,

    pub relay_ports_in_use: AtomicU64,
    pub relay_ports_total: AtomicU64,

    pub capacity_max_allocations: AtomicU64,
    pub capacity_soft_percent: AtomicU64,
    pub capacity_hard_percent: AtomicU64,
    pub auth_failures: AtomicU64,
    pub rate_limited: AtomicU64,
    pub zero_copy_forwards: AtomicU64,
    /// Пакеты дропнутые из-за переполнения send channel (backpressure).
    pub send_queue_dropped: AtomicU64,
    /// STUN messages that failed to decode (malformed header/attributes).
    pub parser_rejections: AtomicU64,
    /// Packets that were neither STUN nor ChannelData (unknown protocol).
    pub malformed_packets: AtomicU64,
    /// Packets dropped because a relay bandwidth quota was exceeded.
    pub quota_exceeded: AtomicU64,
    /// Permission/ChannelBind/Send requests refused because the peer address
    /// is in a denied (special-use) range — see relay::peer_filter.
    pub peer_rejected: AtomicU64,
    /// A3-O1: packet-processing panics caught by the worker's panic guard.
    /// A non-zero rate means a packet tripped a bug in `PacketProcessor`; the
    /// worker survived (the offending packet was dropped). Alert on rate > 0.
    pub processor_panics: AtomicU64,
    // RTP quality (updated periodically)
    pub rtp_streams: AtomicU64,
    pub rtp_avg_loss_pct_x100: AtomicU64, // loss% * 100 (e.g. 250 = 2.50%)
    pub rtp_max_loss_pct_x100: AtomicU64,
    pub rtp_avg_jitter_us: AtomicU64, // jitter in microseconds
    pub rtp_max_jitter_us: AtomicU64,
    pub rtp_total_bitrate_kbps: AtomicU64,
    pub start_time: std::time::Instant,

    // ── Tarantool reconnect metrics ───────────────────────────────────────────
    // Updated by the service layer via `TarantoolBackend::reconnect_stats()`.
    // Example (in a periodic background task):
    //   let s = tarantool_backend.reconnect_stats();
    //   metrics.tarantool_reconnect_attempts.store(s.attempts, Ordering::Relaxed);
    //   metrics.tarantool_reconnect_successes.store(s.successes, Ordering::Relaxed);
    //   metrics.tarantool_connection_state.store(s.state as u64, Ordering::Relaxed);
    pub tarantool_reconnect_attempts: AtomicU64,
    pub tarantool_reconnect_successes: AtomicU64,
    /// 0 = connected, 1 = reconnecting, 2 = failed (matches `ConnState` in turna-state-backend).
    pub tarantool_connection_state: AtomicU64,

    // ── gRPC server metrics ───────────────────────────────────────────────────
    /// Number of currently open streaming RPCs (WatchAllocations, WatchMetrics).
    pub grpc_active_streams: AtomicU64,
    /// Duration of the most recent graceful drain in milliseconds.
    pub grpc_shutdown_drain_ms: AtomicU64,
    /// Total number of times drain timeout expired before all streams closed.
    pub grpc_forced_kills: AtomicU64,

    // ── Failover metrics (PR A, task 2.1) ─────────────────────────────────────
    /// Total allocations successfully claimed from dead nodes.
    pub failover_claimed_total: AtomicU64,
    /// Total CAS attempts lost to a concurrent claim by another node.
    pub failover_lost_race_total: AtomicU64,
    /// Total backend errors during failover sweeps.
    pub failover_errors_total: AtomicU64,
    /// Duration of the most recent failover sweep in microseconds.
    pub failover_sweep_duration_us: AtomicU64,

    // ── Tarantool connection pool gauge (PR A, task 2.2) ──────────────────────
    // Updated by TarantoolBackend::pool_states() via a periodic background
    // task in main.rs (same pattern as tarantool_reconnect_* above).
    /// Pool slots currently idle (mutex not held).
    pub tarantool_pool_idle: AtomicU64,
    /// Pool slots currently busy (request in flight).
    pub tarantool_pool_busy: AtomicU64,
    /// Pool slots currently broken (last I/O failed, awaiting reconnect).
    pub tarantool_pool_broken: AtomicU64,

    // ── Tarantool write-behind writer metrics (PR2, task #3) ──────────────────
    // Mirror counters owned by `services/node/src/writer.rs`. The writer
    // task copies its internal `WriterCounters` here after every flush so
    // they show up on `/metrics`.
    /// Total batches flushed to the backend.
    pub tarantool_writer_batches: AtomicU64,
    /// Total operations applied (sum across Create/Refresh/Remove/Perm/Chan).
    pub tarantool_writer_ops: AtomicU64,
    /// Number of events the writer was able to merge with another
    /// (e.g. Refresh+Refresh → keep latest, Create+Remove → drop both).
    pub tarantool_writer_coalesced: AtomicU64,
    /// Backend errors from per-port flush attempts. Independent of
    /// `tarantool_reconnect_*` (those track the transport layer).
    pub tarantool_writer_errors: AtomicU64,
    /// Events dropped on the hot path because the writer's bounded
    /// channel was full. Indicates Tarantool is keeping up or not.
    pub tarantool_writes_dropped: AtomicU64,

    // ── Cluster (gossip + TURN-redirect balancing) ───────────────────────────
    /// Total `300 Try Alternate` redirects this node has sent to hand a new
    /// client to its owner node.
    pub cluster_redirects: AtomicU64,
    /// Current number of live nodes in the gossip ring (including self).
    /// Updated by the gossip topology callback in main.rs.
    pub cluster_nodes: AtomicU64,

    // ── Command-log migration and GC (control-plane) ──────────────────────────
    /// Cumulative command rows deleted by GC.
    pub command_log_gc_deleted_commands_total: AtomicU64,
    /// Cumulative idempotency records deleted by GC.
    pub command_log_gc_deleted_idempotency_total: AtomicU64,
    /// Cumulative failed GC sweeps.
    pub command_log_gc_errors_total: AtomicU64,
    /// Terminal command rows still present after the last sweep (gauge).
    pub command_log_terminal_remaining: AtomicU64,
    /// Age (ms) since enqueue (`created_at_ms`) of the oldest not-yet-terminal
    /// command at the last sweep (gauge). Same semantics in both backends.
    pub command_log_oldest_unfinished_ms: AtomicU64,
    /// Idempotency lookup failures observed while resolving post-GC replay.
    pub command_log_idempotency_lookup_errors_total: AtomicU64,
    /// Legacy command rows normalized by the bounded resumable migration.
    pub command_log_migration_processed_total: AtomicU64,
    /// Backend/procedure failures while advancing command-log migration.
    pub command_log_migration_errors_total: AtomicU64,
    /// Whether the command-log migration has reached its completion marker.
    pub command_log_migration_completed: AtomicU64,

    // ── Runtime management (S4/S5) ────────────────────────────────────────────
    pub management_commands_accepted_total: AtomicU64,
    pub config_update_applied_total: AtomicU64,
    pub config_update_noop_total: AtomicU64,
    pub config_update_conflicts_total: AtomicU64,
    pub config_update_failures_total: AtomicU64,
    pub config_update_rollback_total: AtomicU64,
    pub config_observed_version: AtomicU64,
    pub config_desired_observed_mismatch: AtomicU64,
    pub config_oldest_unapplied_ms: AtomicU64,
    pub user_limits_applied_total: AtomicU64,
    pub user_limits_noop_total: AtomicU64,
    pub user_limits_conflicts_total: AtomicU64,
    pub user_limits_failures_total: AtomicU64,
    pub user_limits_over_limit_subjects: AtomicU64,

    // ── Auth reason codes ──────────────────────────────────────────────────────
    // Reason-coded auth failures (each is also counted in `auth_failures`),
    // keyed by the turna_auth::AuthError variant the validator returned.
    pub auth_fail_missing_credentials: AtomicU64,
    pub auth_fail_invalid_credentials: AtomicU64,
    pub auth_fail_expired: AtomicU64,
    pub auth_fail_integrity: AtomicU64,
    pub auth_fail_bad_request: AtomicU64,

    // ── Experimental transports: QUIC/WebTransport + DTLS (RFC 7350) ──────────
    // Mirrored from the transport-layer QuicStats/DtlsStats by a periodic copy
    // task in the node listeners (the transport crate is leaf-level and cannot
    // depend on turna-health). `*_active` are gauges; the rest are counters.
    pub quic_active: AtomicU64,
    pub quic_sessions_total: AtomicU64,
    pub quic_closed_total: AtomicU64,
    pub quic_datagrams_rx: AtomicU64,
    pub quic_datagrams_tx: AtomicU64,
    pub quic_streams_opened: AtomicU64,
    pub quic_control_bytes_tx: AtomicU64,
    pub quic_send_errors: AtomicU64,
    pub dtls_active: AtomicU64,
    pub dtls_sessions_total: AtomicU64,
    pub dtls_rejected_over_cap: AtomicU64,
    pub dtls_closed_total: AtomicU64,
    pub dtls_idle_timeouts: AtomicU64,
    pub dtls_bytes_rx: AtomicU64,
    pub dtls_bytes_tx: AtomicU64,
    pub dtls_outbound_dropped: AtomicU64,
    pub dtls_rejected_per_ip: AtomicU64,
    pub dtls_outbound_oversize: AtomicU64,
    pub dtls_accept_timeouts: AtomicU64,
    pub dtls_handshake_failures: AtomicU64,
    pub dtls_inbound_dropped: AtomicU64,
    pub dtls_rejected_rate_limit: AtomicU64,
    pub dtls_cert_reloads: AtomicU64,
    pub dtls_cert_reload_failures: AtomicU64,
    pub quic_handshake_failures: AtomicU64,
    pub quic_control_dropped_no_stream: AtomicU64,
    pub quic_rejected_over_cap: AtomicU64,
    pub quic_rejected_per_ip: AtomicU64,
    pub quic_cert_reloads: AtomicU64,
    pub quic_cert_reload_failures: AtomicU64,
    pub quic_rejected_rate_limit: AtomicU64,
    pub quic_migrations: AtomicU64,
    // TURNS (TLS-over-TCP). Mirrored from `turna_transport::tcp_tls::TlsStats`
    // by the TURNS bridge; all zero when the listener is disabled or not built.
    pub tls_active: AtomicU64,
    pub tls_conns_total: AtomicU64,
    pub tls_closed_total: AtomicU64,
    pub tls_handshake_failures: AtomicU64,
    pub tls_handshake_timeouts: AtomicU64,
    pub tls_rejected_over_cap: AtomicU64,
    pub tls_rejected_per_ip: AtomicU64,
    pub tls_idle_timeouts: AtomicU64,
    pub tls_framing_errors: AtomicU64,
    pub tls_accept_errors: AtomicU64,
    pub tls_bytes_rx: AtomicU64,
    pub tls_bytes_tx: AtomicU64,
    pub tls_cert_reloads: AtomicU64,
    pub tls_cert_reload_failures: AtomicU64,
    pub tls_rejected_rate_limit: AtomicU64,
    pub tls_alpn_rejected: AtomicU64,

    // TURN-over-SCTP. Mirrored from `turna_transport::sctp::SctpStats` by the
    // SCTP bridge; all zero when the listener is disabled or not built.
    //
    // No handshake, certificate or ALPN counters here, unlike TURNS: this
    // transport has none of those, and a series that can only ever read zero
    // costs an operator more than an absent one.
    pub sctp_active: AtomicU64,
    pub sctp_conns_total: AtomicU64,
    pub sctp_closed_total: AtomicU64,
    pub sctp_rejected_over_cap: AtomicU64,
    pub sctp_rejected_per_ip: AtomicU64,
    pub sctp_rejected_rate_limit: AtomicU64,
    pub sctp_idle_timeouts: AtomicU64,
    pub sctp_framing_errors: AtomicU64,
    pub sctp_accept_errors: AtomicU64,
    pub sctp_send_dropped: AtomicU64,
    pub sctp_bytes_rx: AtomicU64,
    pub sctp_bytes_tx: AtomicU64,

    // ── io_uring worker-pool ring utilisation (Linux io-uring backend) ───────
    // Summed across workers by a periodic copy task in the node's io_uring arm.
    // `*_total` are monotonic; the rest are last-sampled gauges. All zero on
    // non-io_uring backends/builds.
    pub uring_workers: AtomicU64,
    pub uring_cqe_drained_total: AtomicU64,
    pub uring_cqe_batches_total: AtomicU64,
    pub uring_cqe_max_batch: AtomicU64,
    pub uring_sq_push_failed_total: AtomicU64,
    pub uring_sq_len: AtomicU64,
    pub uring_sq_capacity: AtomicU64,
    pub uring_cq_len: AtomicU64,
    pub uring_buffers_available: AtomicU64,
    pub uring_relay_capacity_exhausted_total: AtomicU64,
    /// 2.2 (D5): currently-occupied io_uring send slots (main + relay, summed).
    pub uring_inflight_send_slots: AtomicU64,
    /// 2.2 (D4): main send slots seen stalled >5s without a SendMsg CQE (summed).
    pub uring_send_slot_stalled_total: AtomicU64,
    // ── AF_XDP datapath (Linux af-xdp backend; loop-level counters) ──────────
    pub afxdp_rx_frames_total: AtomicU64,
    pub afxdp_rx_bytes_total: AtomicU64,
    pub afxdp_tx_frames_total: AtomicU64,
    pub afxdp_tx_bytes_total: AtomicU64,
    pub afxdp_parse_drops_total: AtomicU64,
    pub afxdp_tx_drops_total: AtomicU64,
    pub afxdp_relay_ports_registered: AtomicU64,
    pub afxdp_umem_free_frames: AtomicU64,
    pub afxdp_arp_replies_total: AtomicU64,
    pub afxdp_ndp_replies_total: AtomicU64,
    pub afxdp_neighbor_unresolved: AtomicU64,
    pub afxdp_tx_inflight: AtomicU64,
    pub afxdp_neighbor_cache_entries: AtomicU64,

    // ── Latency histograms ─────────────────────────────────────────────────────
    /// Request-latency histograms (STUN/relay/auth/allocation-lifetime). The
    /// processor `observe`s into named entries; rendered on `/metrics`.
    pub histograms: histogram::HistogramRegistry,

    // ── Multi-tenancy ─────────────────────────────────────────────────────────
    /// Per-tenant total allocations (monotonic). Keyed by tenant id. A `Mutex`
    /// is fine here — allocation is not the per-packet hot path. Expiry happens
    /// in the session crate (which has no metrics handle), so this is a total
    /// counter, not an active gauge.
    pub tenant_allocations_total: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            is_draining: AtomicBool::new(false),
            readiness: AtomicU8::new(Readiness::Starting as u8),
            backend_diverged: AtomicBool::new(false),
            transport_readiness: AtomicU8::new(Readiness::Starting as u8),
            dtls_readiness: AtomicU8::new(Readiness::Starting as u8),
            tls_readiness: AtomicU8::new(Readiness::Starting as u8),
            sctp_readiness: AtomicU8::new(Readiness::Starting as u8),
            quic_readiness: AtomicU8::new(Readiness::Starting as u8),
            afxdp_readiness: AtomicU8::new(Readiness::Starting as u8),
            management_readiness: AtomicU8::new(Readiness::Starting as u8),
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            active_allocations: AtomicU64::new(0),
            total_allocations: AtomicU64::new(0),
            rates: RateSampler::new(),
            host_cpu_percent: AtomicU64::new(u64::MAX),
            host_memory_percent: AtomicU64::new(u64::MAX),
            relay_ports_in_use: AtomicU64::new(0),
            relay_ports_total: AtomicU64::new(0),
            capacity_max_allocations: AtomicU64::new(0),
            capacity_soft_percent: AtomicU64::new(75),
            capacity_hard_percent: AtomicU64::new(95),
            auth_failures: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            zero_copy_forwards: AtomicU64::new(0),
            send_queue_dropped: AtomicU64::new(0),
            parser_rejections: AtomicU64::new(0),
            malformed_packets: AtomicU64::new(0),
            quota_exceeded: AtomicU64::new(0),
            peer_rejected: AtomicU64::new(0),
            processor_panics: AtomicU64::new(0),
            rtp_streams: AtomicU64::new(0),
            rtp_avg_loss_pct_x100: AtomicU64::new(0),
            rtp_max_loss_pct_x100: AtomicU64::new(0),
            rtp_avg_jitter_us: AtomicU64::new(0),
            rtp_max_jitter_us: AtomicU64::new(0),
            rtp_total_bitrate_kbps: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
            tarantool_reconnect_attempts: AtomicU64::new(0),
            tarantool_reconnect_successes: AtomicU64::new(0),
            tarantool_connection_state: AtomicU64::new(0),
            grpc_active_streams: AtomicU64::new(0),
            grpc_shutdown_drain_ms: AtomicU64::new(0),
            grpc_forced_kills: AtomicU64::new(0),
            // PR2: writer
            tarantool_writer_batches: AtomicU64::new(0),
            tarantool_writer_ops: AtomicU64::new(0),
            tarantool_writer_coalesced: AtomicU64::new(0),
            tarantool_writer_errors: AtomicU64::new(0),
            tarantool_writes_dropped: AtomicU64::new(0),
            // PR A: failover
            failover_claimed_total: AtomicU64::new(0),
            failover_lost_race_total: AtomicU64::new(0),
            failover_errors_total: AtomicU64::new(0),
            failover_sweep_duration_us: AtomicU64::new(0),
            // PR A: pool gauge
            tarantool_pool_idle: AtomicU64::new(0),
            tarantool_pool_busy: AtomicU64::new(0),
            tarantool_pool_broken: AtomicU64::new(0),
            // Cluster
            cluster_redirects: AtomicU64::new(0),
            cluster_nodes: AtomicU64::new(0),
            command_log_gc_deleted_commands_total: AtomicU64::new(0),
            command_log_gc_deleted_idempotency_total: AtomicU64::new(0),
            command_log_gc_errors_total: AtomicU64::new(0),
            command_log_terminal_remaining: AtomicU64::new(0),
            command_log_oldest_unfinished_ms: AtomicU64::new(0),
            command_log_idempotency_lookup_errors_total: AtomicU64::new(0),
            command_log_migration_processed_total: AtomicU64::new(0),
            command_log_migration_errors_total: AtomicU64::new(0),
            command_log_migration_completed: AtomicU64::new(0),
            management_commands_accepted_total: AtomicU64::new(0),
            config_update_applied_total: AtomicU64::new(0),
            config_update_noop_total: AtomicU64::new(0),
            config_update_conflicts_total: AtomicU64::new(0),
            config_update_failures_total: AtomicU64::new(0),
            config_update_rollback_total: AtomicU64::new(0),
            config_observed_version: AtomicU64::new(0),
            config_desired_observed_mismatch: AtomicU64::new(0),
            config_oldest_unapplied_ms: AtomicU64::new(0),
            user_limits_applied_total: AtomicU64::new(0),
            user_limits_noop_total: AtomicU64::new(0),
            user_limits_conflicts_total: AtomicU64::new(0),
            user_limits_failures_total: AtomicU64::new(0),
            user_limits_over_limit_subjects: AtomicU64::new(0),
            auth_fail_missing_credentials: AtomicU64::new(0),
            auth_fail_invalid_credentials: AtomicU64::new(0),
            auth_fail_expired: AtomicU64::new(0),
            auth_fail_integrity: AtomicU64::new(0),
            auth_fail_bad_request: AtomicU64::new(0),
            quic_active: AtomicU64::new(0),
            quic_sessions_total: AtomicU64::new(0),
            quic_closed_total: AtomicU64::new(0),
            quic_datagrams_rx: AtomicU64::new(0),
            quic_datagrams_tx: AtomicU64::new(0),
            quic_streams_opened: AtomicU64::new(0),
            quic_control_bytes_tx: AtomicU64::new(0),
            quic_send_errors: AtomicU64::new(0),
            dtls_active: AtomicU64::new(0),
            dtls_sessions_total: AtomicU64::new(0),
            dtls_rejected_over_cap: AtomicU64::new(0),
            dtls_closed_total: AtomicU64::new(0),
            dtls_idle_timeouts: AtomicU64::new(0),
            dtls_bytes_rx: AtomicU64::new(0),
            dtls_bytes_tx: AtomicU64::new(0),
            dtls_outbound_dropped: AtomicU64::new(0),
            dtls_rejected_per_ip: AtomicU64::new(0),
            dtls_outbound_oversize: AtomicU64::new(0),
            dtls_accept_timeouts: AtomicU64::new(0),
            dtls_handshake_failures: AtomicU64::new(0),
            dtls_inbound_dropped: AtomicU64::new(0),
            dtls_rejected_rate_limit: AtomicU64::new(0),
            dtls_cert_reloads: AtomicU64::new(0),
            dtls_cert_reload_failures: AtomicU64::new(0),
            quic_handshake_failures: AtomicU64::new(0),
            quic_control_dropped_no_stream: AtomicU64::new(0),
            quic_rejected_over_cap: AtomicU64::new(0),
            quic_rejected_per_ip: AtomicU64::new(0),
            quic_cert_reloads: AtomicU64::new(0),
            quic_cert_reload_failures: AtomicU64::new(0),
            quic_rejected_rate_limit: AtomicU64::new(0),
            quic_migrations: AtomicU64::new(0),
            tls_active: AtomicU64::new(0),
            tls_conns_total: AtomicU64::new(0),
            tls_closed_total: AtomicU64::new(0),
            tls_handshake_failures: AtomicU64::new(0),
            tls_handshake_timeouts: AtomicU64::new(0),
            tls_rejected_over_cap: AtomicU64::new(0),
            tls_rejected_per_ip: AtomicU64::new(0),
            tls_idle_timeouts: AtomicU64::new(0),
            tls_framing_errors: AtomicU64::new(0),
            tls_accept_errors: AtomicU64::new(0),
            tls_bytes_rx: AtomicU64::new(0),
            tls_bytes_tx: AtomicU64::new(0),
            tls_cert_reloads: AtomicU64::new(0),
            tls_cert_reload_failures: AtomicU64::new(0),
            tls_rejected_rate_limit: AtomicU64::new(0),
            tls_alpn_rejected: AtomicU64::new(0),
            sctp_active: AtomicU64::new(0),
            sctp_conns_total: AtomicU64::new(0),
            sctp_closed_total: AtomicU64::new(0),
            sctp_rejected_over_cap: AtomicU64::new(0),
            sctp_rejected_per_ip: AtomicU64::new(0),
            sctp_rejected_rate_limit: AtomicU64::new(0),
            sctp_idle_timeouts: AtomicU64::new(0),
            sctp_framing_errors: AtomicU64::new(0),
            sctp_accept_errors: AtomicU64::new(0),
            sctp_send_dropped: AtomicU64::new(0),
            sctp_bytes_rx: AtomicU64::new(0),
            sctp_bytes_tx: AtomicU64::new(0),
            uring_workers: AtomicU64::new(0),
            uring_cqe_drained_total: AtomicU64::new(0),
            uring_cqe_batches_total: AtomicU64::new(0),
            uring_cqe_max_batch: AtomicU64::new(0),
            uring_sq_push_failed_total: AtomicU64::new(0),
            uring_sq_len: AtomicU64::new(0),
            uring_sq_capacity: AtomicU64::new(0),
            uring_cq_len: AtomicU64::new(0),
            uring_buffers_available: AtomicU64::new(0),
            uring_relay_capacity_exhausted_total: AtomicU64::new(0),
            uring_inflight_send_slots: AtomicU64::new(0),
            uring_send_slot_stalled_total: AtomicU64::new(0),
            afxdp_rx_frames_total: AtomicU64::new(0),
            afxdp_rx_bytes_total: AtomicU64::new(0),
            afxdp_tx_frames_total: AtomicU64::new(0),
            afxdp_tx_bytes_total: AtomicU64::new(0),
            afxdp_parse_drops_total: AtomicU64::new(0),
            afxdp_tx_drops_total: AtomicU64::new(0),
            afxdp_relay_ports_registered: AtomicU64::new(0),
            afxdp_umem_free_frames: AtomicU64::new(0),
            afxdp_arp_replies_total: AtomicU64::new(0),
            afxdp_ndp_replies_total: AtomicU64::new(0),
            afxdp_neighbor_unresolved: AtomicU64::new(0),
            afxdp_tx_inflight: AtomicU64::new(0),
            afxdp_neighbor_cache_entries: AtomicU64::new(0),
            histograms: histogram::HistogramRegistry::new(),
            tenant_allocations_total: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn set_draining(&self, val: bool) {
        self.is_draining.store(val, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::SeqCst)
    }

    pub fn set_readiness(&self, r: Readiness) {
        self.readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_transport_readiness(&self, r: Readiness) {
        self.transport_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_dtls_readiness(&self, r: Readiness) {
        self.dtls_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_sctp_readiness(&self, r: Readiness) {
        self.sctp_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_tls_readiness(&self, r: Readiness) {
        self.tls_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_quic_readiness(&self, r: Readiness) {
        self.quic_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn set_afxdp_readiness(&self, r: Readiness) {
        self.afxdp_readiness.store(r as u8, Ordering::SeqCst);
    }

    /// #6/#4.5: set management-plane readiness (see the field docs). Distinct
    /// from the dataplane `readiness` flag; does not affect `/ready` for the TURN
    /// dataplane.
    pub fn set_management_readiness(&self, r: Readiness) {
        self.management_readiness.store(r as u8, Ordering::SeqCst);
    }

    pub fn readiness(&self) -> Readiness {
        Readiness::from_u8(self.readiness.load(Ordering::SeqCst))
    }

    pub fn is_ready(&self) -> bool {
        self.readiness() == Readiness::Ready
    }

    /// P0.5 derived-readiness input: mark/clear in-memory↔backend divergence.
    pub fn set_backend_diverged(&self, val: bool) {
        self.backend_diverged.store(val, Ordering::SeqCst);
    }

    pub fn backend_diverged(&self) -> bool {
        self.backend_diverged.load(Ordering::SeqCst)
    }

    /// P0.5 derived readiness: recompute process readiness from its inputs rather
    /// than assigning it imperatively. Drain (operator intent) wins, then an active
    /// backend divergence (Degraded), else Ready. Never yields `Starting`, so call
    /// it only after boot has brought the traffic path up; boot itself still sets
    /// `Starting`/`Ready` explicitly.
    pub fn refresh_readiness(&self) {
        let r = if self.is_draining() {
            Readiness::Draining
        } else if self.backend_diverged() {
            Readiness::Degraded
        } else {
            Readiness::Ready
        };
        self.readiness.store(r as u8, Ordering::SeqCst);
    }

    /// Record one allocation for a tenant (multi-tenancy observability).
    /// Called from the relay processor when a tenant-scoped allocation succeeds.
    pub fn record_tenant_allocation(&self, tenant: &str) {
        if let Ok(mut map) = self.tenant_allocations_total.lock() {
            *map.entry(tenant.to_string()).or_insert(0) += 1;
        }
    }

    /// Render per-tenant Prometheus lines (labelled counter). Empty when no
    /// tenant allocations have occurred, so single-tenant output is unchanged.
    fn render_tenant_metrics(&self) -> String {
        let map = match self.tenant_allocations_total.lock() {
            Ok(g) => g,
            Err(_) => return String::new(),
        };
        if map.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "# HELP turna_tenant_allocations_total Total allocations per tenant\n\
             # TYPE turna_tenant_allocations_total counter\n",
        );
        for (tenant, count) in map.iter() {
            // Escape per Prometheus label-value rules: backslash then quote.
            let esc = tenant.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!(
                "turna_tenant_allocations_total{{tenant=\"{esc}\"}} {count}\n"
            ));
        }
        out
    }

    /// Render reason-coded auth failures as a single labelled counter. The
    /// labels sum to (at most) `turna_auth_failures`; emitted unconditionally so
    /// scrapes have a stable series set.
    fn render_auth_reason_metrics(&self) -> String {
        format!(
            "# HELP turna_auth_failures_by_reason_total Auth failures by AuthError reason\n\
             # TYPE turna_auth_failures_by_reason_total counter\n\
             turna_auth_failures_by_reason_total{{reason=\"missing_credentials\"}} {}\n\
             turna_auth_failures_by_reason_total{{reason=\"invalid_credentials\"}} {}\n\
             turna_auth_failures_by_reason_total{{reason=\"expired\"}} {}\n\
             turna_auth_failures_by_reason_total{{reason=\"integrity_failed\"}} {}\n\
             turna_auth_failures_by_reason_total{{reason=\"bad_request\"}} {}\n",
            self.auth_fail_missing_credentials.load(Ordering::Relaxed),
            self.auth_fail_invalid_credentials.load(Ordering::Relaxed),
            self.auth_fail_expired.load(Ordering::Relaxed),
            self.auth_fail_integrity.load(Ordering::Relaxed),
            self.auth_fail_bad_request.load(Ordering::Relaxed),
        )
    }

    /// Command-log and runtime-management counters/gauges. Labels are avoided
    /// so arbitrary node/user identities cannot create unbounded cardinality.
    fn render_command_log_metrics(&self) -> String {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "# HELP turna_command_log_gc_deleted_commands_total Command rows deleted by GC\n\
             # TYPE turna_command_log_gc_deleted_commands_total counter\n\
             turna_command_log_gc_deleted_commands_total {}\n\
             # HELP turna_command_log_gc_deleted_idempotency_total Idempotency records deleted by GC\n\
             # TYPE turna_command_log_gc_deleted_idempotency_total counter\n\
             turna_command_log_gc_deleted_idempotency_total {}\n\
             # HELP turna_command_log_gc_errors_total Failed command-log GC sweeps\n\
             # TYPE turna_command_log_gc_errors_total counter\n\
             turna_command_log_gc_errors_total {}\n\
             # HELP turna_command_log_terminal_remaining Terminal command rows present after the last sweep\n\
             # TYPE turna_command_log_terminal_remaining gauge\n\
             turna_command_log_terminal_remaining {}\n\
             # HELP turna_command_log_oldest_unfinished_ms Age of the oldest non-terminal command\n\
             # TYPE turna_command_log_oldest_unfinished_ms gauge\n\
             turna_command_log_oldest_unfinished_ms {}\n\
             # HELP turna_command_log_idempotency_lookup_errors_total Idempotency lookup errors\n\
             # TYPE turna_command_log_idempotency_lookup_errors_total counter\n\
             turna_command_log_idempotency_lookup_errors_total {}\n\
             # HELP turna_command_log_migration_processed_total Legacy command rows normalized by bounded migration\n\
             # TYPE turna_command_log_migration_processed_total counter\n\
             turna_command_log_migration_processed_total {}\n\
             # HELP turna_command_log_migration_errors_total Command-log migration backend errors\n\
             # TYPE turna_command_log_migration_errors_total counter\n\
             turna_command_log_migration_errors_total {}\n\
             # HELP turna_command_log_migration_completed Command-log migration completion marker\n\
             # TYPE turna_command_log_migration_completed gauge\n\
             turna_command_log_migration_completed {}\n\
             # HELP turna_management_commands_accepted_total Durable management commands accepted\n\
             # TYPE turna_management_commands_accepted_total counter\n\
             turna_management_commands_accepted_total {}\n\
             # HELP turna_config_update_applied_total Runtime config updates applied\n\
             # TYPE turna_config_update_applied_total counter\n\
             turna_config_update_applied_total {}\n\
             # HELP turna_config_update_noop_total Runtime config no-op updates\n\
             # TYPE turna_config_update_noop_total counter\n\
             turna_config_update_noop_total {}\n\
             # HELP turna_config_update_conflicts_total Runtime config version conflicts\n\
             # TYPE turna_config_update_conflicts_total counter\n\
             turna_config_update_conflicts_total {}\n\
             # HELP turna_config_update_failures_total Runtime config update failures\n\
             # TYPE turna_config_update_failures_total counter\n\
             turna_config_update_failures_total {}\n\
             # HELP turna_config_update_rollback_total Runtime config rollbacks\n\
             # TYPE turna_config_update_rollback_total counter\n\
             turna_config_update_rollback_total {}\n\
             # HELP turna_config_observed_version Current local observed config version\n\
             # TYPE turna_config_observed_version gauge\n\
             turna_config_observed_version {}\n\
             # HELP turna_config_desired_observed_mismatch Desired/observed mismatch count\n\
             # TYPE turna_config_desired_observed_mismatch gauge\n\
             turna_config_desired_observed_mismatch {}\n\
             # HELP turna_config_oldest_unapplied_ms Age of oldest unapplied desired config\n\
             # TYPE turna_config_oldest_unapplied_ms gauge\n\
             turna_config_oldest_unapplied_ms {}\n\
             # HELP turna_user_limits_applied_total User-limit updates applied\n\
             # TYPE turna_user_limits_applied_total counter\n\
             turna_user_limits_applied_total {}\n\
             # HELP turna_user_limits_noop_total User-limit no-op updates\n\
             # TYPE turna_user_limits_noop_total counter\n\
             turna_user_limits_noop_total {}\n\
             # HELP turna_user_limits_conflicts_total User-limit version conflicts\n\
             # TYPE turna_user_limits_conflicts_total counter\n\
             turna_user_limits_conflicts_total {}\n\
             # HELP turna_user_limits_failures_total User-limit update failures\n\
             # TYPE turna_user_limits_failures_total counter\n\
             turna_user_limits_failures_total {}\n\
             # HELP turna_user_limits_over_limit_subjects Subjects currently above their allocation limit\n\
             # TYPE turna_user_limits_over_limit_subjects gauge\n\
             turna_user_limits_over_limit_subjects {}\n",
            l(&self.command_log_gc_deleted_commands_total),
            l(&self.command_log_gc_deleted_idempotency_total),
            l(&self.command_log_gc_errors_total),
            l(&self.command_log_terminal_remaining),
            l(&self.command_log_oldest_unfinished_ms),
            l(&self.command_log_idempotency_lookup_errors_total),
            l(&self.command_log_migration_processed_total),
            l(&self.command_log_migration_errors_total),
            l(&self.command_log_migration_completed),
            l(&self.management_commands_accepted_total),
            l(&self.config_update_applied_total),
            l(&self.config_update_noop_total),
            l(&self.config_update_conflicts_total),
            l(&self.config_update_failures_total),
            l(&self.config_update_rollback_total),
            l(&self.config_observed_version),
            l(&self.config_desired_observed_mismatch),
            l(&self.config_oldest_unapplied_ms),
            l(&self.user_limits_applied_total),
            l(&self.user_limits_noop_total),
            l(&self.user_limits_conflicts_total),
            l(&self.user_limits_failures_total),
            l(&self.user_limits_over_limit_subjects),
        )
    }

    /// mirrored from the transport layer by the node's periodic copy task. All
    /// zero unless the corresponding transport is enabled and built in.
    fn render_transport_metrics(&self) -> String {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        format!(
            "# HELP turna_quic_active_sessions Active QUIC/WebTransport sessions\n\
             # TYPE turna_quic_active_sessions gauge\n\
             turna_quic_active_sessions {}\n\
             # HELP turna_quic_sessions_total QUIC/WebTransport sessions accepted since start\n\
             # TYPE turna_quic_sessions_total counter\n\
             turna_quic_sessions_total {}\n\
             # HELP turna_quic_closed_total QUIC/WebTransport sessions closed since start\n\
             # TYPE turna_quic_closed_total counter\n\
             turna_quic_closed_total {}\n\
             # HELP turna_quic_datagrams_rx_total Inbound QUIC datagrams\n\
             # TYPE turna_quic_datagrams_rx_total counter\n\
             turna_quic_datagrams_rx_total {}\n\
             # HELP turna_quic_datagrams_tx_total Outbound QUIC datagrams\n\
             # TYPE turna_quic_datagrams_tx_total counter\n\
             turna_quic_datagrams_tx_total {}\n\
             # HELP turna_quic_streams_opened_total Client-opened bidi streams\n\
             # TYPE turna_quic_streams_opened_total counter\n\
             turna_quic_streams_opened_total {}\n\
             # HELP turna_quic_control_bytes_tx_total Bytes written on QUIC control streams\n\
             # TYPE turna_quic_control_bytes_tx_total counter\n\
             turna_quic_control_bytes_tx_total {}\n\
             # HELP turna_quic_send_errors_total QUIC outbound send failures\n\
             # TYPE turna_quic_send_errors_total counter\n\
             turna_quic_send_errors_total {}\n\
             # HELP turna_dtls_active_sessions Active DTLS sessions\n\
             # TYPE turna_dtls_active_sessions gauge\n\
             turna_dtls_active_sessions {}\n\
             # HELP turna_dtls_sessions_total DTLS sessions accepted since start\n\
             # TYPE turna_dtls_sessions_total counter\n\
             turna_dtls_sessions_total {}\n\
             # HELP turna_dtls_rejected_over_cap_total DTLS sessions refused at max_sessions cap\n\
             # TYPE turna_dtls_rejected_over_cap_total counter\n\
             turna_dtls_rejected_over_cap_total {}\n\
             # HELP turna_dtls_closed_total DTLS sessions closed since start\n\
             # TYPE turna_dtls_closed_total counter\n\
             turna_dtls_closed_total {}\n\
             # HELP turna_dtls_idle_timeouts_total DTLS sessions closed by idle timeout\n\
             # TYPE turna_dtls_idle_timeouts_total counter\n\
             turna_dtls_idle_timeouts_total {}\n\
             # HELP turna_dtls_bytes_rx_total Decrypted bytes received over DTLS\n\
             # TYPE turna_dtls_bytes_rx_total counter\n\
             turna_dtls_bytes_rx_total {}\n\
             # HELP turna_dtls_bytes_tx_total Bytes encrypted+sent over DTLS\n\
             # TYPE turna_dtls_bytes_tx_total counter\n\
             turna_dtls_bytes_tx_total {}\n\
             # HELP turna_dtls_outbound_dropped_total Outbound DTLS datagrams dropped because a session egress queue was full (DTL-3 drop-newest)\n\
             # TYPE turna_dtls_outbound_dropped_total counter\n\
             turna_dtls_outbound_dropped_total {}\n\
             # HELP turna_dtls_rejected_per_ip_total DTLS sessions refused because the source IP hit max_sessions_per_ip (DTL-9)\n\
             # TYPE turna_dtls_rejected_per_ip_total counter\n\
             turna_dtls_rejected_per_ip_total {}\n\
             # HELP turna_uring_workers io_uring worker threads in the pool\n\
             # TYPE turna_uring_workers gauge\n\
             turna_uring_workers {}\n\
             # HELP turna_uring_cqe_drained_total Completion queue entries drained (summed over workers)\n\
             # TYPE turna_uring_cqe_drained_total counter\n\
             turna_uring_cqe_drained_total {}\n\
             # HELP turna_uring_cqe_batches_total Drain iterations that pulled >=1 CQE (summed over workers)\n\
             # TYPE turna_uring_cqe_batches_total counter\n\
             turna_uring_cqe_batches_total {}\n\
             # HELP turna_uring_cqe_max_batch Largest single CQE drain seen (max over workers)\n\
             # TYPE turna_uring_cqe_max_batch gauge\n\
             turna_uring_cqe_max_batch {}\n\
             # HELP turna_uring_sq_push_failed_total Submission-queue pushes that failed because the SQ was full (summed)\n\
             # TYPE turna_uring_sq_push_failed_total counter\n\
             turna_uring_sq_push_failed_total {}\n\
             # HELP turna_uring_sq_len Last-sampled submission-queue occupancy (summed over workers)\n\
             # TYPE turna_uring_sq_len gauge\n\
             turna_uring_sq_len {}\n\
             # HELP turna_uring_sq_capacity Total submission-queue capacity across workers\n\
             # TYPE turna_uring_sq_capacity gauge\n\
             turna_uring_sq_capacity {}\n\
             # HELP turna_uring_cq_len Last-sampled completion-queue occupancy (summed over workers)\n\
             # TYPE turna_uring_cq_len gauge\n\
             turna_uring_cq_len {}\n\
             # HELP turna_uring_buffers_available Free registered RX buffers (summed over workers)\n\
             # TYPE turna_uring_buffers_available gauge\n\
             turna_uring_buffers_available {}\n\
             # HELP turna_uring_relay_capacity_exhausted_total Relay allocations rejected because the per-worker relay msghdr pool was full (summed)\n\
             # TYPE turna_uring_relay_capacity_exhausted_total counter\n\
             turna_uring_relay_capacity_exhausted_total {}\n\
             # HELP turna_uring_inflight_send_slots Currently-occupied io_uring send slots, main + relay (summed over workers)\n\
             # TYPE turna_uring_inflight_send_slots gauge\n\
             turna_uring_inflight_send_slots {}\n\
             # HELP turna_uring_send_slot_stalled_total Main send slots seen stalled >5s without a SendMsg completion; not reused (summed)\n\
             # TYPE turna_uring_send_slot_stalled_total counter\n\
             turna_uring_send_slot_stalled_total {}\n\
             # HELP turna_afxdp_rx_frames_total AF_XDP frames received off the queue\n\
             # TYPE turna_afxdp_rx_frames_total counter\n\
             turna_afxdp_rx_frames_total {}\n\
             # HELP turna_afxdp_rx_bytes_total AF_XDP bytes received (TURN payloads)\n\
             # TYPE turna_afxdp_rx_bytes_total counter\n\
             turna_afxdp_rx_bytes_total {}\n\
             # HELP turna_afxdp_tx_frames_total AF_XDP frames sent\n\
             # TYPE turna_afxdp_tx_frames_total counter\n\
             turna_afxdp_tx_frames_total {}\n\
             # HELP turna_afxdp_tx_bytes_total AF_XDP bytes sent\n\
             # TYPE turna_afxdp_tx_bytes_total counter\n\
             turna_afxdp_tx_bytes_total {}\n\
             # HELP turna_afxdp_parse_drops_total Frames received that matched no TURN/relay port (undemuxable)\n\
             # TYPE turna_afxdp_parse_drops_total counter\n\
             turna_afxdp_parse_drops_total {}\n\
             # HELP turna_afxdp_tx_drops_total AF_XDP send failures\n\
             # TYPE turna_afxdp_tx_drops_total counter\n\
             turna_afxdp_tx_drops_total {}\n\
             # HELP turna_afxdp_relay_ports_registered Relay ports currently demuxed by the AF_XDP datapath\n\
             # TYPE turna_afxdp_relay_ports_registered gauge\n\
             turna_afxdp_relay_ports_registered {}\n\
             # HELP turna_afxdp_umem_free_frames Free UMEM frames available for RX/TX\n\
             # TYPE turna_afxdp_umem_free_frames gauge\n\
             turna_afxdp_umem_free_frames {}\n\
             # HELP turna_afxdp_arp_replies_total ARP replies sent by the AF_XDP datapath for its own IP\n\
             # TYPE turna_afxdp_arp_replies_total counter\n\
             turna_afxdp_arp_replies_total {}\n\
             # HELP turna_afxdp_ndp_replies_total IPv6 Neighbour Advertisements sent by the AF_XDP datapath for its own IP\n\
             # TYPE turna_afxdp_ndp_replies_total counter\n\
             turna_afxdp_ndp_replies_total {}\n\
             # HELP turna_afxdp_neighbor_unresolved Next-hop TX MAC unresolved (1=zero placeholder, TX will not deliver; 0=resolved)\n\
             # TYPE turna_afxdp_neighbor_unresolved gauge\n\
             turna_afxdp_neighbor_unresolved {}\n\
             # HELP turna_afxdp_tx_inflight Frames submitted to the AF_XDP TX ring but not yet completed\n\
             # TYPE turna_afxdp_tx_inflight gauge\n\
             turna_afxdp_tx_inflight {}\n\
             # HELP turna_afxdp_neighbor_cache_entries Resolved next-hop MAC entries currently cached\n\
             # TYPE turna_afxdp_neighbor_cache_entries gauge\n\
             turna_afxdp_neighbor_cache_entries {}\n\
             # HELP turna_dtls_outbound_oversize_total Outbound DTLS datagrams dropped for exceeding the configured record MTU\n\
             # TYPE turna_dtls_outbound_oversize_total counter\n\
             turna_dtls_outbound_oversize_total {}\n\
             # HELP turna_dtls_accept_timeouts_total DTLS handshakes abandoned because accept() exceeded accept_timeout_secs (liveness guard for webrtc-rs/webrtc#614)\n\
             # TYPE turna_dtls_accept_timeouts_total counter\n\
             turna_dtls_accept_timeouts_total {}\n\
             # HELP turna_dtls_handshake_failures_total DTLS handshakes that failed (demux path only; not observable on the stock listener)\n\
             # TYPE turna_dtls_handshake_failures_total counter\n\
             turna_dtls_handshake_failures_total {}\n\
             # HELP turna_dtls_inbound_dropped_total Inbound DTLS datagrams dropped because a peer queue was full (demux path)\n\
             # TYPE turna_dtls_inbound_dropped_total counter\n\
             turna_dtls_inbound_dropped_total {}\n\
             # HELP turna_dtls_rejected_rate_limit_total DTLS handshakes refused by the per-IP rate limiter before any DTLS state existed (demux path)\n\
             # TYPE turna_dtls_rejected_rate_limit_total counter\n\
             turna_dtls_rejected_rate_limit_total {}\n\
             # HELP turna_dtls_cert_reloads_total Successful DTLS certificate hot-reloads (demux path)\n\
             # TYPE turna_dtls_cert_reloads_total counter\n\
             turna_dtls_cert_reloads_total {}\n\
             # HELP turna_dtls_cert_reload_failures_total Failed DTLS certificate hot-reloads; the previous certificate stays in service\n\
             # TYPE turna_dtls_cert_reload_failures_total counter\n\
             turna_dtls_cert_reload_failures_total {}\n\
             # HELP turna_quic_handshake_failures_total QUIC/WebTransport sessions that failed before becoming usable\n\
             # TYPE turna_quic_handshake_failures_total counter\n\
             turna_quic_handshake_failures_total {}\n\
             # HELP turna_quic_control_dropped_no_stream_total QUIC control responses dropped because the session had no open bidi stream\n\
             # TYPE turna_quic_control_dropped_no_stream_total counter\n\
             turna_quic_control_dropped_no_stream_total {}\n\
             # HELP turna_quic_rejected_over_cap_total QUIC sessions refused at the max_sessions cap\n\
             # TYPE turna_quic_rejected_over_cap_total counter\n\
             turna_quic_rejected_over_cap_total {}\n\
             # HELP turna_quic_rejected_per_ip_total QUIC sessions refused at max_sessions_per_ip\n\
             # TYPE turna_quic_rejected_per_ip_total counter\n\
             turna_quic_rejected_per_ip_total {}\n\
             # HELP turna_quic_cert_reloads_total Successful QUIC/WebTransport certificate hot-reloads\n\
             # TYPE turna_quic_cert_reloads_total counter\n\
             turna_quic_cert_reloads_total {}\n\
             # HELP turna_quic_cert_reload_failures_total Failed QUIC/WebTransport certificate hot-reloads (previous certificate kept)\n\
             # TYPE turna_quic_cert_reload_failures_total counter\n\
             turna_quic_cert_reload_failures_total {}\n\
             # HELP turna_quic_rejected_rate_limit_total QUIC/WebTransport handshakes refused by the per-IP rate limiter\n\
             # TYPE turna_quic_rejected_rate_limit_total counter\n\
             turna_quic_rejected_rate_limit_total {}\n\
             # HELP turna_quic_migrations_total Observed QUIC client address changes (connection migration)\n\
             # TYPE turna_quic_migrations_total counter\n\
             turna_quic_migrations_total {}\n\
             # HELP turna_tls_active_connections Active TURNS (TLS-over-TCP) connections\n\
             # TYPE turna_tls_active_connections gauge\n\
             turna_tls_active_connections {}\n\
             # HELP turna_tls_connections_total TURNS connections accepted since start\n\
             # TYPE turna_tls_connections_total counter\n\
             turna_tls_connections_total {}\n\
             # HELP turna_tls_closed_total TURNS connections closed since start\n\
             # TYPE turna_tls_closed_total counter\n\
             turna_tls_closed_total {}\n\
             # HELP turna_tls_handshake_failures_total TURNS TLS handshakes that failed\n\
             # TYPE turna_tls_handshake_failures_total counter\n\
             turna_tls_handshake_failures_total {}\n\
             # HELP turna_tls_handshake_timeouts_total TURNS TLS handshakes that exceeded handshake_timeout_secs\n\
             # TYPE turna_tls_handshake_timeouts_total counter\n\
             turna_tls_handshake_timeouts_total {}\n\
             # HELP turna_tls_rejected_over_cap_total TURNS connections refused at the max_connections cap\n\
             # TYPE turna_tls_rejected_over_cap_total counter\n\
             turna_tls_rejected_over_cap_total {}\n\
             # HELP turna_tls_rejected_per_ip_total TURNS connections refused at max_connections_per_ip\n\
             # TYPE turna_tls_rejected_per_ip_total counter\n\
             turna_tls_rejected_per_ip_total {}\n\
             # HELP turna_tls_idle_timeouts_total TURNS connections closed by the idle read timeout\n\
             # TYPE turna_tls_idle_timeouts_total counter\n\
             turna_tls_idle_timeouts_total {}\n\
             # HELP turna_tls_framing_errors_total TURNS connections closed on invalid or over-sized TURN-over-TCP framing\n\
             # TYPE turna_tls_framing_errors_total counter\n\
             turna_tls_framing_errors_total {}\n\
             # HELP turna_tls_accept_errors_total TURNS accept() errors survived without stopping the listener\n\
             # TYPE turna_tls_accept_errors_total counter\n\
             turna_tls_accept_errors_total {}\n\
             # HELP turna_tls_bytes_rx_total Decrypted bytes read from TURNS clients\n\
             # TYPE turna_tls_bytes_rx_total counter\n\
             turna_tls_bytes_rx_total {}\n\
             # HELP turna_tls_bytes_tx_total Bytes written to TURNS clients\n\
             # TYPE turna_tls_bytes_tx_total counter\n\
             turna_tls_bytes_tx_total {}\n\
             # HELP turna_tls_cert_reloads_total Successful TURNS certificate hot-reloads\n\
             # TYPE turna_tls_cert_reloads_total counter\n\
             turna_tls_cert_reloads_total {}\n\
             # HELP turna_tls_cert_reload_failures_total Failed TURNS certificate hot-reloads (previous certificate kept)\n\
             # TYPE turna_tls_cert_reload_failures_total counter\n\
             turna_tls_cert_reload_failures_total {}\n\
             # HELP turna_tls_rejected_rate_limit_total TURNS connections refused by the per-IP handshake rate limiter\n\
             # TYPE turna_tls_rejected_rate_limit_total counter\n\
             turna_tls_rejected_rate_limit_total {}\n\
             # HELP turna_tls_alpn_rejected_total TURNS connections refused because alpn_required was set and the client negotiated no ALPN\n\
             # TYPE turna_tls_alpn_rejected_total counter\n\
             turna_tls_alpn_rejected_total {}\n\
             # HELP turna_sctp_active_associations Active TURN-over-SCTP associations\n\
             # TYPE turna_sctp_active_associations gauge\n\
             turna_sctp_active_associations {}\n\
             # HELP turna_sctp_associations_total TURN-over-SCTP associations accepted since start\n\
             # TYPE turna_sctp_associations_total counter\n\
             turna_sctp_associations_total {}\n\
             # HELP turna_sctp_closed_total TURN-over-SCTP associations closed since start\n\
             # TYPE turna_sctp_closed_total counter\n\
             turna_sctp_closed_total {}\n\
             # HELP turna_sctp_rejected_over_cap_total SCTP associations refused at the max_connections cap\n\
             # TYPE turna_sctp_rejected_over_cap_total counter\n\
             turna_sctp_rejected_over_cap_total {}\n\
             # HELP turna_sctp_rejected_per_ip_total SCTP associations refused at max_connections_per_ip\n\
             # TYPE turna_sctp_rejected_per_ip_total counter\n\
             turna_sctp_rejected_per_ip_total {}\n\
             # HELP turna_sctp_rejected_rate_limit_total SCTP associations refused by the per-IP rate limiter\n\
             # TYPE turna_sctp_rejected_rate_limit_total counter\n\
             turna_sctp_rejected_rate_limit_total {}\n\
             # HELP turna_sctp_idle_timeouts_total SCTP associations closed by the idle read timeout\n\
             # TYPE turna_sctp_idle_timeouts_total counter\n\
             turna_sctp_idle_timeouts_total {}\n\
             # HELP turna_sctp_framing_errors_total SCTP associations closed on invalid or over-sized TURN-over-stream framing\n\
             # TYPE turna_sctp_framing_errors_total counter\n\
             turna_sctp_framing_errors_total {}\n\
             # HELP turna_sctp_accept_errors_total SCTP accept() errors survived without stopping the listener\n\
             # TYPE turna_sctp_accept_errors_total counter\n\
             turna_sctp_accept_errors_total {}\n\
             # HELP turna_sctp_send_dropped_total Outbound SCTP frames dropped because the per-association channel was full or gone\n\
             # TYPE turna_sctp_send_dropped_total counter\n\
             turna_sctp_send_dropped_total {}\n\
             # HELP turna_sctp_bytes_rx_total Bytes read from TURN-over-SCTP clients\n\
             # TYPE turna_sctp_bytes_rx_total counter\n\
             turna_sctp_bytes_rx_total {}\n\
             # HELP turna_sctp_bytes_tx_total Bytes written to TURN-over-SCTP clients\n\
             # TYPE turna_sctp_bytes_tx_total counter\n\
             turna_sctp_bytes_tx_total {}\n\
             # HELP turna_backend_readiness Process readiness (0=starting,1=ready,2=degraded,3=draining)\n\
             # TYPE turna_backend_readiness gauge\n\
             turna_backend_readiness {}\n\
             # HELP turna_transport_readiness Primary UDP transport backend readiness (0=starting,1=ready,2=degraded,3=draining)\n\
             # TYPE turna_transport_readiness gauge\n\
             turna_transport_readiness {}\n\
             # HELP turna_dtls_readiness DTLS listener readiness (0=starting,1=ready,2=degraded,3=draining; starting if DTLS disabled)\n\
             # TYPE turna_dtls_readiness gauge\n\
             turna_dtls_readiness {}\n\
             # HELP turna_tls_readiness TURNS listener readiness (0=starting,1=ready,2=degraded,3=draining; starting if TURNS disabled)\n\
             # TYPE turna_tls_readiness gauge\n\
             turna_tls_readiness {}\n\
             # HELP turna_sctp_readiness TURN-over-SCTP listener readiness (0=starting,1=ready,2=degraded,3=draining; starting if SCTP disabled)\n\
             # TYPE turna_sctp_readiness gauge\n\
             turna_sctp_readiness {}\n\
             # HELP turna_relay_ports_in_use Relay ports currently held by an allocation or an unclaimed EVEN-PORT reservation\n\
             # TYPE turna_relay_ports_in_use gauge\n\
             turna_relay_ports_in_use {}\n\
             # HELP turna_relay_ports_total Relay ports configured across the global pool and any tenant pools\n\
             # TYPE turna_relay_ports_total gauge\n\
             turna_relay_ports_total {}\n\
             # HELP turna_relay_ports_utilization_percent Percent of the relay port range in use\n\
             # TYPE turna_relay_ports_utilization_percent gauge\n\
             turna_relay_ports_utilization_percent {}\n\
             # HELP turna_quic_readiness QUIC/WebTransport listener readiness (0=starting,1=ready,2=degraded,3=draining; starting if QUIC disabled)\n\
             # TYPE turna_quic_readiness gauge\n\
             turna_quic_readiness {}\n\
             # HELP turna_afxdp_readiness AF_XDP datapath readiness (0=starting,1=ready,2=degraded,3=draining; starting if AF_XDP is not the selected backend)\n\
             # TYPE turna_afxdp_readiness gauge\n\
             turna_afxdp_readiness {}\n\
             # HELP turna_management_readiness Management-plane readiness incl. command-log migration (0=starting,1=ready,2=degraded,3=draining)\n\
             # TYPE turna_management_readiness gauge\n\
             turna_management_readiness {}\n",
            l(&self.quic_active),
            l(&self.quic_sessions_total),
            l(&self.quic_closed_total),
            l(&self.quic_datagrams_rx),
            l(&self.quic_datagrams_tx),
            l(&self.quic_streams_opened),
            l(&self.quic_control_bytes_tx),
            l(&self.quic_send_errors),
            l(&self.dtls_active),
            l(&self.dtls_sessions_total),
            l(&self.dtls_rejected_over_cap),
            l(&self.dtls_closed_total),
            l(&self.dtls_idle_timeouts),
            l(&self.dtls_bytes_rx),
            l(&self.dtls_bytes_tx),
            l(&self.dtls_outbound_dropped),
            l(&self.dtls_rejected_per_ip),
            l(&self.uring_workers),
            l(&self.uring_cqe_drained_total),
            l(&self.uring_cqe_batches_total),
            l(&self.uring_cqe_max_batch),
            l(&self.uring_sq_push_failed_total),
            l(&self.uring_sq_len),
            l(&self.uring_sq_capacity),
            l(&self.uring_cq_len),
            l(&self.uring_buffers_available),
            l(&self.uring_relay_capacity_exhausted_total),
            l(&self.uring_inflight_send_slots),
            l(&self.uring_send_slot_stalled_total),
            l(&self.afxdp_rx_frames_total),
            l(&self.afxdp_rx_bytes_total),
            l(&self.afxdp_tx_frames_total),
            l(&self.afxdp_tx_bytes_total),
            l(&self.afxdp_parse_drops_total),
            l(&self.afxdp_tx_drops_total),
            l(&self.afxdp_relay_ports_registered),
            l(&self.afxdp_umem_free_frames),
            l(&self.afxdp_arp_replies_total),
            l(&self.afxdp_ndp_replies_total),
            l(&self.afxdp_neighbor_unresolved),
            l(&self.afxdp_tx_inflight),
            l(&self.afxdp_neighbor_cache_entries),
            l(&self.dtls_outbound_oversize),
            l(&self.dtls_accept_timeouts),
            l(&self.dtls_handshake_failures),
            l(&self.dtls_inbound_dropped),
            l(&self.dtls_rejected_rate_limit),
            l(&self.dtls_cert_reloads),
            l(&self.dtls_cert_reload_failures),
            l(&self.quic_handshake_failures),
            l(&self.quic_control_dropped_no_stream),
            l(&self.quic_rejected_over_cap),
            l(&self.quic_rejected_per_ip),
            l(&self.quic_cert_reloads),
            l(&self.quic_cert_reload_failures),
            l(&self.quic_rejected_rate_limit),
            l(&self.quic_migrations),
            l(&self.tls_active),
            l(&self.tls_conns_total),
            l(&self.tls_closed_total),
            l(&self.tls_handshake_failures),
            l(&self.tls_handshake_timeouts),
            l(&self.tls_rejected_over_cap),
            l(&self.tls_rejected_per_ip),
            l(&self.tls_idle_timeouts),
            l(&self.tls_framing_errors),
            l(&self.tls_accept_errors),
            l(&self.tls_bytes_rx),
            l(&self.tls_bytes_tx),
            l(&self.tls_cert_reloads),
            l(&self.tls_cert_reload_failures),
            l(&self.tls_rejected_rate_limit),
            l(&self.tls_alpn_rejected),
            l(&self.sctp_active),
            l(&self.sctp_conns_total),
            l(&self.sctp_closed_total),
            l(&self.sctp_rejected_over_cap),
            l(&self.sctp_rejected_per_ip),
            l(&self.sctp_rejected_rate_limit),
            l(&self.sctp_idle_timeouts),
            l(&self.sctp_framing_errors),
            l(&self.sctp_accept_errors),
            l(&self.sctp_send_dropped),
            l(&self.sctp_bytes_rx),
            l(&self.sctp_bytes_tx),
            self.readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.transport_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.dtls_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.tls_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.sctp_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            l(&self.relay_ports_in_use),
            l(&self.relay_ports_total),
            {
                let total = self.relay_ports_total.load(std::sync::atomic::Ordering::Relaxed);
                let used = self.relay_ports_in_use.load(std::sync::atomic::Ordering::Relaxed);
                // 0 rather than 100 when no range is published: unlike capacity
                // state, an unreported port range is not a reason to call the node
                // full — it means the sampler has not run yet.
                // checked_div over a manual zero test: clippy's manual_checked_ops
                // rejects the latter, and the None arm carries the meaning anyway —
                // no range published yet, which is 0 rather than 100 so an alert on
                // a high value cannot fire during startup.
                used.saturating_mul(100)
                    .checked_div(total)
                    .map_or(0, |v| v.min(100))
            },
            self.quic_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.afxdp_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.management_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes and packets per second, averaged over a sliding ten-second window.
///
/// The cumulative counters answer "how much since start"; a node deciding
/// whether it is saturated needs "how much right now", and cannot wait for a
/// Prometheus scrape to tell it.
///
/// Ten one-second buckets in a fixed ring. `tick()` is called once a second by a
/// task in the node; the read path is three atomic loads and no lock, because
/// `/capacity` calls it and is meant to be cheap enough to call before every
/// session placement.
///
/// **Why ten seconds.** Short enough to catch saturation before the egress queue
/// begins dropping; long enough that one burst does not flip the node to
/// SATURATED and divert its callers. Relayed media is bursty — a rate computed
/// from a single sample would report saturation on every keyframe, which is a
/// worse failure than reporting nothing at all.
pub struct RateSampler {
    /// Per-bucket deltas. Index `pos % WINDOW` is the bucket being filled.
    bytes_buckets: [AtomicU64; Self::WINDOW],
    packets_buckets: [AtomicU64; Self::WINDOW],
    /// Counter values at the last tick, for computing the delta.
    last_bytes: AtomicU64,
    last_packets: AtomicU64,
    /// Ticks since start. Doubles as the ring position and as the "have we
    /// filled the window yet" test — before `WINDOW` ticks the mean would be
    /// divided by buckets that were never written.
    ticks: AtomicU64,
}

impl Default for RateSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl RateSampler {
    const WINDOW: usize = 10;

    pub fn new() -> Self {
        Self {
            bytes_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            packets_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            last_bytes: AtomicU64::new(0),
            last_packets: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
        }
    }

    /// Record one second's worth of traffic. Called once a second.
    ///
    /// `total_bytes` and `total_packets` are the cumulative counters; the delta
    /// against the previous tick becomes this bucket. `saturating_sub` because a
    /// counter that appears to go backwards (it should not, but a reordered
    /// relaxed load could) must produce zero rather than a vast number that
    /// reads as saturation.
    pub fn tick(&self, total_bytes: u64, total_packets: u64) {
        let n = self.ticks.fetch_add(1, Ordering::Relaxed) as usize;
        let slot = n % Self::WINDOW;

        let prev_b = self.last_bytes.swap(total_bytes, Ordering::Relaxed);
        let prev_p = self.last_packets.swap(total_packets, Ordering::Relaxed);

        self.bytes_buckets[slot].store(total_bytes.saturating_sub(prev_b), Ordering::Relaxed);
        self.packets_buckets[slot].store(total_packets.saturating_sub(prev_p), Ordering::Relaxed);
    }

    /// Mean bytes/second over the window, or `None` until the window has filled.
    ///
    /// `None` rather than a partial mean on purpose: a rate averaged over three
    /// buckets when ten are expected understates by more than two thirds, and a
    /// node that under-reports its load during the first ten seconds after start
    /// is a node that accepts work it cannot serve. The caller decides what to do
    /// with "not yet known" — `/capacity` reports the signal as unavailable
    /// rather than guessing.
    pub fn bytes_per_sec(&self) -> Option<u64> {
        self.mean(&self.bytes_buckets)
    }

    /// Mean packets/second over the window, or `None` until it has filled.
    pub fn packets_per_sec(&self) -> Option<u64> {
        self.mean(&self.packets_buckets)
    }

    fn mean(&self, buckets: &[AtomicU64; Self::WINDOW]) -> Option<u64> {
        if (self.ticks.load(Ordering::Relaxed) as usize) < Self::WINDOW {
            return None;
        }
        let sum: u64 = buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .fold(0u64, |a, b| a.saturating_add(b));
        Some(sum / Self::WINDOW as u64)
    }

    /// Seconds of history collected, capped at the window size. For diagnostics
    /// and for a caller wanting to know how much to trust a fresh reading.
    pub fn samples(&self) -> usize {
        (self.ticks.load(Ordering::Relaxed) as usize).min(Self::WINDOW)
    }
}

/// Capacity state, in the vocabulary the enterprise spec asks for.
///
/// Ordered by decreasing willingness to take work, which is also the order the
/// checks run in: the first that matches wins, so DRAINING beats SATURATED and a
/// node that is both reports the one that will not change on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CapacityState {
    /// Accepting work with headroom.
    Available,
    /// Accepting work, but past the soft threshold or with a degraded
    /// dependency. A caller with a choice should choose elsewhere.
    Degraded,
    /// Shutting down. Will not take new work and existing work is being wound
    /// down. Distinct from SATURATED because it does not recover.
    Draining,
    /// At or past the hard threshold, or shedding. New work will suffer.
    Saturated,
    /// Not able to serve: startup incomplete, or no capacity limit published so
    /// there is nothing to reason about.
    Unavailable,
}

/// `GET /capacity` — per-node capacity, for a caller deciding where to place a
/// session.
///
/// Both the state and the numbers behind it are returned. The state is our
/// opinion; the numbers let a caller form its own, which matters because the
/// thresholds here are generic and a deployment's real limit is usually
/// something else — bandwidth on a shared uplink, or a licence count.
#[derive(Debug, serde::Serialize)]
struct CapacityResponse {
    /// Response schema version. Increment on any change that is not additive.
    version: u32,
    state: CapacityState,
    /// Why, in a form worth logging. Empty when AVAILABLE.
    reasons: Vec<&'static str>,
    active_allocations: u64,
    max_allocations: u64,
    /// Percent of `max_allocations` in use. 100 when the limit is unpublished,
    /// pairing with UNAVAILABLE rather than reading as empty.
    utilization_percent: u64,
    soft_threshold_percent: u64,
    hard_threshold_percent: u64,
    ready: bool,
    draining: bool,
    /// Relayed bytes/second over the last ten seconds. `null` until the window
    /// has filled — a partial mean would understate the load, and a node that
    /// under-reports during its first ten seconds accepts work it cannot serve.
    bytes_per_sec: Option<u64>,
    /// Relayed packets/second over the last ten seconds. `null` on the same terms.
    packets_per_sec: Option<u64>,
    /// Host CPU, whole percent. `null` until the first sample.
    cpu_percent: Option<u64>,
    /// Host memory in use, whole percent. `null` until the first sample.
    memory_percent: Option<u64>,
    /// Which inputs this state actually weighed.
    ///
    /// Present so a caller is not left to assume the state considered load it
    /// could not see. The spec asks for bps, pps, CPU and memory pressure in
    /// admission decisions; none of those is here yet, and saying so in the
    /// response is cheaper than a caller discovering it during an incident.
    signals: CapacitySignals,
}

#[derive(Debug, serde::Serialize)]
struct CapacitySignals {
    allocations: bool,
    send_queue_pressure: bool,
    readiness: bool,
    /// Rate of bytes relayed. Counters exist; a rate needs a sampler.
    bandwidth_rate: bool,
    /// Rate of packets relayed. Same.
    packet_rate: bool,
    /// Host CPU load. No source in this crate.
    cpu: bool,
    /// Host memory pressure. No source in this crate.
    memory: bool,
}

impl Metrics {
    /// Store a host CPU and memory sample, whole percent.
    pub fn set_host_load(&self, cpu_percent: u64, memory_percent: u64) {
        self.host_cpu_percent
            .store(cpu_percent.min(100), Ordering::Relaxed);
        self.host_memory_percent
            .store(memory_percent.min(100), Ordering::Relaxed);
    }

    /// Host CPU percent, or `None` if no sample has been taken yet.
    pub fn host_cpu(&self) -> Option<u64> {
        match self.host_cpu_percent.load(Ordering::Relaxed) {
            u64::MAX => None,
            v => Some(v),
        }
    }

    /// Host memory percent, or `None` if no sample has been taken yet.
    pub fn host_memory(&self) -> Option<u64> {
        match self.host_memory_percent.load(Ordering::Relaxed) {
            u64::MAX => None,
            v => Some(v),
        }
    }

    /// Publish the node's capacity limits. Called once at startup.
    ///
    /// Until this is called, `/capacity` reports UNAVAILABLE: a node that does
    /// not know its own ceiling cannot honestly claim headroom.
    pub fn set_capacity_limits(&self, max_allocations: u64, soft_percent: u64, hard_percent: u64) {
        self.capacity_max_allocations
            .store(max_allocations, Ordering::SeqCst);
        self.capacity_soft_percent
            .store(soft_percent.min(100), Ordering::SeqCst);
        self.capacity_hard_percent
            .store(hard_percent.min(100), Ordering::SeqCst);
    }

    fn capacity(&self) -> CapacityResponse {
        let max = self.capacity_max_allocations.load(Ordering::Relaxed);
        let active = self.active_allocations.load(Ordering::Relaxed);
        let soft = self.capacity_soft_percent.load(Ordering::Relaxed);
        let hard = self.capacity_hard_percent.load(Ordering::Relaxed);
        let draining = self.is_draining();
        let ready = self.is_ready();
        // Any drop means the egress queue has already overflowed at least once.
        // Treated as saturation rather than degradation: by the time a frame is
        // dropped the damage is done, and a caller placing more work on this
        // node makes it worse.
        let shedding = self.send_queue_dropped.load(Ordering::Relaxed) > 0;

        // 100 when no limit is published, pairing with the UNAVAILABLE state
        // below: a node that does not know its ceiling must not read as empty.
        // Opposite default from the port gauge above, and deliberately so — there
        // an unpublished range means "not sampled yet", here it means "cannot
        // reason about headroom".
        let utilization = active
            .saturating_mul(100)
            .checked_div(max)
            .map_or(100, |v| v.min(100));

        let mut reasons: Vec<&'static str> = Vec::new();
        let state = if draining {
            reasons.push("node is draining");
            CapacityState::Draining
        } else if !ready {
            reasons.push("node is not ready");
            CapacityState::Unavailable
        } else if max == 0 {
            reasons.push("no capacity limit published; cannot reason about headroom");
            CapacityState::Unavailable
        } else if utilization >= hard {
            reasons.push("allocations at or above the hard threshold");
            CapacityState::Saturated
        } else if shedding {
            reasons.push("send queue has dropped frames");
            CapacityState::Saturated
        } else if utilization >= soft {
            reasons.push("allocations at or above the soft threshold");
            CapacityState::Degraded
        } else if self.readiness() == Readiness::Degraded {
            reasons.push("a listener or backend reports degraded");
            CapacityState::Degraded
        } else {
            CapacityState::Available
        };

        CapacityResponse {
            version: 1,
            state,
            reasons,
            active_allocations: active,
            max_allocations: max,
            utilization_percent: utilization,
            soft_threshold_percent: soft,
            hard_threshold_percent: hard,
            ready,
            draining,
            bytes_per_sec: self.rates.bytes_per_sec(),
            packets_per_sec: self.rates.packets_per_sec(),
            cpu_percent: self.host_cpu(),
            memory_percent: self.host_memory(),
            signals: CapacitySignals {
                allocations: true,
                send_queue_pressure: true,
                readiness: true,
                bandwidth_rate: self.rates.bytes_per_sec().is_some(),
                packet_rate: self.rates.packets_per_sec().is_some(),
                cpu: self.host_cpu().is_some(),
                memory: self.host_memory().is_some(),
            },
        }
    }
}

#[derive(Serialize)]
struct StatusResponse {
    status: &'static str,
    draining: bool,
    uptime_secs: u64,
    active_allocations: u64,
    total_allocations: u64,
    packets_received: u64,
    packets_sent: u64,
    bytes_received: u64,
    bytes_sent: u64,
    auth_failures: u64,
    rate_limited: u64,
    zero_copy_forwards: u64,
    send_queue_dropped: u64,
    parser_rejections: u64,
    malformed_packets: u64,
    quota_exceeded: u64,
    peer_rejected: u64,
    rtp_streams: u64,
    rtp_avg_loss_percent: f64,
    rtp_max_loss_percent: f64,
    rtp_avg_jitter_ms: f64,
    rtp_max_jitter_ms: f64,
    rtp_total_bitrate_kbps: u64,
}

/// Snapshot of the io_uring relay-route forwarding counters (RFC 8016 sharded
/// ownership). Mirrors `turna_transport::relay_route::RelayRouteSnapshot`, but
/// is declared here so the health crate stays free of a `turna-transport`
/// dependency and of the `io-uring` feature: the node maps one into the other
/// inside the provider closure below.
#[derive(Debug, Clone, Copy, Default)]
pub struct RelayRouteMetrics {
    pub send_local: u64,
    pub send_forwarded: u64,
    pub send_forward_failed: u64,
    pub send_stale: u64,
    pub route_miss: u64,
    pub owner_cleanup_stale: u64,
}

/// Pulls a fresh [`RelayRouteMetrics`] on each `/metrics` scrape. `None` (the
/// default) omits the relay-route block entirely — e.g. on builds without the
/// io_uring datapath, where no route table exists.
pub type RelayRouteMetricsProvider = Arc<dyn Fn() -> RelayRouteMetrics + Send + Sync>;

/// Render the relay-route forwarding counters in Prometheus text format,
/// including the derived `turna_relay_route_forwarded_ratio` gauge — the
/// per-scrape "cost of migration" (forwarded / (local + forwarded)).
fn render_relay_route_metrics(s: &RelayRouteMetrics) -> String {
    let denom = s.send_local + s.send_forwarded;
    let ratio = if denom == 0 {
        0.0
    } else {
        s.send_forwarded as f64 / denom as f64
    };
    format!(
        "# HELP turna_relay_route_send_local_total Relay sends handled by the owning worker locally\n\
         # TYPE turna_relay_route_send_local_total counter\n\
         turna_relay_route_send_local_total {}\n\
         # HELP turna_relay_route_send_forwarded_total Relay sends forwarded to the owning worker after a reshard\n\
         # TYPE turna_relay_route_send_forwarded_total counter\n\
         turna_relay_route_send_forwarded_total {}\n\
         # HELP turna_relay_route_send_forward_failed_total Forwarded relay sends that failed to deliver to the owner\n\
         # TYPE turna_relay_route_send_forward_failed_total counter\n\
         turna_relay_route_send_forward_failed_total {}\n\
         # HELP turna_relay_route_send_stale_total Forwarded sends dropped because the owner's (allocation,generation) no longer matched\n\
         # TYPE turna_relay_route_send_stale_total counter\n\
         turna_relay_route_send_stale_total {}\n\
         # HELP turna_relay_route_miss_total Relay sends with no route (port not owned by any worker)\n\
         # TYPE turna_relay_route_miss_total counter\n\
         turna_relay_route_miss_total {}\n\
         # HELP turna_relay_route_owner_cleanup_stale_total Conditional route cleanups skipped because the port was already re-owned\n\
         # TYPE turna_relay_route_owner_cleanup_stale_total counter\n\
         turna_relay_route_owner_cleanup_stale_total {}\n\
         # HELP turna_relay_route_forwarded_ratio Fraction of relay sends forwarded cross-worker (cost of migration)\n\
         # TYPE turna_relay_route_forwarded_ratio gauge\n\
         turna_relay_route_forwarded_ratio {:.4}\n",
        s.send_local,
        s.send_forwarded,
        s.send_forward_failed,
        s.send_stale,
        s.route_miss,
        s.owner_cleanup_stale,
        ratio,
    )
}

/// Pulls a per-tenant relayed-traffic snapshot on each `/metrics` scrape:
/// `(tenant, bytes, packets, closed_allocations)`. Supplied by the node from
/// Maximum tenants emitted individually per metric family.
///
/// Five families carry a `tenant` label. Without a cap, a deployment with ten
/// thousand tenants returns fifty thousand series on every scrape from every
/// node, and Prometheus's memory use is proportional to series count — the
/// operator discovers this when it dies rather than when it grows.
///
/// 100 by default: a deployment with a handful of real tenants sees no change,
/// and the worst case becomes 500 series rather than unbounded.
static TENANT_SERIES_CAP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(100);

/// Label value used for the aggregate of everything past the cap.
///
/// Double underscore because a tenant identifier could plausibly be "other";
/// this one is chosen to be awkward on purpose.
const TENANT_OTHER: &str = "__other";

/// Longest tenant name emitted. A name is an identifier from configuration, and
/// one long enough to matter inflates every line of every scrape.
const TENANT_NAME_MAX: usize = 64;

/// Override how many tenants are emitted individually. 0 disables the cap, which
/// is a decision an operator can make for a deployment they know is small.
pub fn set_tenant_series_cap(n: usize) {
    TENANT_SERIES_CAP.store(n, std::sync::atomic::Ordering::Relaxed);
}

fn tenant_cap() -> usize {
    TENANT_SERIES_CAP.load(std::sync::atomic::Ordering::Relaxed)
}

/// Escape a tenant name for a Prometheus label value, and truncate it.
fn tenant_label(t: &str) -> String {
    let mut out = t.replace('\\', "\\\\").replace('"', "\\\"");
    if out.len() > TENANT_NAME_MAX {
        out.truncate(TENANT_NAME_MAX);
        out.push('~');
    }
    out
}

/// Split tenants into those emitted individually and an aggregate of the rest.
///
/// Ranked by `weight` descending, so the tenants an operator is most likely to
/// investigate stay visible and the long tail collapses. Returns
/// `(kept, other_count)` — the caller sums the tail itself, since what to sum
/// differs per family.
fn cap_tenants<T: Copy>(
    samples: &[(String, T)],
    weight: impl Fn(&T) -> u64,
) -> (Vec<(String, T)>, usize) {
    let cap = tenant_cap();
    if cap == 0 || samples.len() <= cap {
        return (samples.to_vec(), 0);
    }
    let mut ranked: Vec<(String, T)> = samples.to_vec();
    ranked.sort_by_key(|(_, v)| std::cmp::Reverse(weight(v)));
    let omitted = ranked.len() - cap;
    ranked.truncate(cap);
    (ranked, omitted)
}

/// `AllocationStore::tenant_traffic_snapshot`. `None` omits
/// the block (single-tenant deployments never populate it).
pub type TenantTrafficProvider = Arc<dyn Fn() -> Vec<(String, u64, u64, u64)> + Send + Sync>;

/// Render cumulative per-tenant relayed traffic in Prometheus text format,
/// grouped one metric family at a time (Prometheus requires a family's samples
/// to be contiguous). Empty when no tenant traffic has been recorded, so
/// single-tenant output is unchanged.
fn render_tenant_traffic_metrics(samples: &[(String, u64, u64, u64)]) -> String {
    if samples.is_empty() {
        return String::new();
    }

    // Ranked by bytes: of the three counters here, bytes is the one an operator
    // chases first, and using a single ranking for all three keeps the same
    // tenants visible across families — a tenant present in one and aggregated
    // in another would be worse than either.
    let triples: Vec<(String, (u64, u64, u64))> = samples
        .iter()
        .map(|(t, b, p, c)| (t.clone(), (*b, *p, *c)))
        .collect();
    let (kept, omitted) = cap_tenants(&triples, |(b, _, _)| *b);
    let tail: (u64, u64, u64) = if omitted == 0 {
        (0, 0, 0)
    } else {
        let kept_names: std::collections::HashSet<&str> =
            kept.iter().map(|(t, _)| t.as_str()).collect();
        triples
            .iter()
            .filter(|(t, _)| !kept_names.contains(t.as_str()))
            .fold((0u64, 0u64, 0u64), |(a, b2, c2), (_, (b, p, c))| {
                (a + b, b2 + p, c2 + c)
            })
    };

    let esc = |t: &str| tenant_label(t);
    let mut out = String::new();

    // Emitted whether or not anything was omitted, so the series exists to alert
    // on and a dashboard does not have to cope with it appearing and vanishing.
    out.push_str(
        "# HELP turna_tenant_series_omitted Tenants aggregated into __other because the per-family cap was reached\n\
         # TYPE turna_tenant_series_omitted gauge\n",
    );
    out.push_str(&format!("turna_tenant_series_omitted {omitted}\n"));

    out.push_str(
        "# HELP turna_tenant_bytes_relayed_total Bytes relayed per tenant (accrued at allocation close)\n\
         # TYPE turna_tenant_bytes_relayed_total counter\n",
    );
    for (t, (bytes, _, _)) in &kept {
        out.push_str(&format!(
            "turna_tenant_bytes_relayed_total{{tenant=\"{}\"}} {bytes}\n",
            esc(t)
        ));
    }

    if omitted > 0 {
        out.push_str(&format!(
            "turna_tenant_bytes_relayed_total{{tenant=\"{}\"}} {}\n",
            TENANT_OTHER, tail.0
        ));
    }
    out.push_str(
        "# HELP turna_tenant_packets_relayed_total Packets relayed per tenant (accrued at allocation close)\n\
         # TYPE turna_tenant_packets_relayed_total counter\n",
    );
    for (t, (_, packets, _)) in &kept {
        out.push_str(&format!(
            "turna_tenant_packets_relayed_total{{tenant=\"{}\"}} {packets}\n",
            esc(t)
        ));
    }

    if omitted > 0 {
        out.push_str(&format!(
            "turna_tenant_packets_relayed_total{{tenant=\"{}\"}} {}\n",
            TENANT_OTHER, tail.1
        ));
    }
    out.push_str(
        "# HELP turna_tenant_allocations_closed_total Allocations closed per tenant\n\
         # TYPE turna_tenant_allocations_closed_total counter\n",
    );
    for (t, (_, _, closed)) in &kept {
        out.push_str(&format!(
            "turna_tenant_allocations_closed_total{{tenant=\"{}\"}} {closed}\n",
            esc(t)
        ));
    }
    if omitted > 0 {
        out.push_str(&format!(
            "turna_tenant_allocations_closed_total{{tenant=\"{}\"}} {}\n",
            TENANT_OTHER, tail.2
        ));
    }

    out
}

/// Start health check HTTP server.
pub async fn serve(addr: SocketAddr, metrics: Arc<Metrics>) -> std::io::Result<()> {
    serve_with_cluster(addr, metrics, None).await
}

/// Like [`serve`], but also answers `GET /cluster` with the current cluster
/// membership supplied by `cluster`. Pass `None` for no `/cluster` endpoint.
///
/// Signature kept stable for existing callers; for relay-route metrics use
/// [`serve_with_cluster_routes`].
pub async fn serve_with_cluster(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    cluster: Option<Arc<dyn ClusterView>>,
) -> std::io::Result<()> {
    serve_with_cluster_routes(addr, metrics, cluster, None, None).await
}

/// Like [`serve_with_cluster`], but also exposes the io_uring relay-route
/// forwarding counters on `/metrics`.
///
/// `relay_routes`, when `Some`, adds the `turna_relay_route_*` block (including
/// the derived `turna_relay_route_forwarded_ratio` gauge) to `/metrics`; pass
/// `None` to omit it — e.g. on builds without the io_uring datapath, where no
/// route table exists.
/// Bind the health port, returning the listener for [`serve_on`].
///
/// Split out from `serve_*` so a caller can fail startup when the port is
/// unavailable. Binding inside a spawned task means the error surfaces nowhere:
/// the node keeps serving traffic while the operator believes the port they
/// configured is being scraped. It is worse than no health endpoint, because
/// whatever else holds that port answers in its place — a scrape can end up
/// reading an unrelated process and reporting it as this node.
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

pub async fn serve_with_cluster_routes(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    cluster: Option<Arc<dyn ClusterView>>,
    relay_routes: Option<RelayRouteMetricsProvider>,
    tenant_traffic: Option<TenantTrafficProvider>,
) -> std::io::Result<()> {
    let listener = bind(addr).await?;
    serve_on(
        listener,
        addr,
        metrics,
        cluster,
        relay_routes,
        tenant_traffic,
    )
    .await
}

/// Serve on an already-bound listener.
pub async fn serve_on(
    listener: TcpListener,
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    cluster: Option<Arc<dyn ClusterView>>,
    relay_routes: Option<RelayRouteMetricsProvider>,
    tenant_traffic: Option<TenantTrafficProvider>,
) -> std::io::Result<()> {
    info!(%addr, "health check server started");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        let cluster = cluster.clone();
        let relay_routes = relay_routes.clone();
        let tenant_traffic = tenant_traffic.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };

            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");

            let (status, body, content_type) = match path {
                "/cluster" => match &cluster {
                    Some(cv) => (
                        "200 OK",
                        serde_json::to_string(&cv.nodes()).unwrap_or_else(|_| "[]".into()),
                        "application/json",
                    ),
                    None => ("200 OK", "[]".to_string(), "application/json"),
                },
                "/capacity" => {
                    // 200 in every state, including SATURATED and UNAVAILABLE:
                    // the body carries the state, and a caller asking "can you
                    // take this" needs an answer rather than an error it has to
                    // interpret. `/ready` remains the endpoint that speaks in
                    // status codes for load balancers.
                    let cap = metrics.capacity();
                    (
                        "200 OK",
                        serde_json::to_string(&cap).unwrap_or_else(|_| "{}".into()),
                        "application/json",
                    )
                }
                "/health" => {
                    if metrics.is_draining() {
                        (
                            "503 Service Unavailable",
                            "draining".to_string(),
                            "text/plain",
                        )
                    } else {
                        ("200 OK", "ok".to_string(), "text/plain")
                    }
                }
                "/ready" => {
                    // 2.4 readiness: `/health` is liveness; `/ready` also gates
                    // on startup completion and flips to 503 on drain so a load
                    // balancer stops sending new clients during shutdown.
                    if metrics.is_draining() {
                        (
                            "503 Service Unavailable",
                            "draining".to_string(),
                            "text/plain",
                        )
                    } else if metrics.is_ready() {
                        ("200 OK", "ready".to_string(), "text/plain")
                    } else {
                        (
                            "503 Service Unavailable",
                            "not ready".to_string(),
                            "text/plain",
                        )
                    }
                }
                "/status" => {
                    let resp = StatusResponse {
                        status: if metrics.is_draining() {
                            "draining"
                        } else {
                            "ok"
                        },
                        draining: metrics.is_draining(),
                        uptime_secs: metrics.start_time.elapsed().as_secs(),
                        active_allocations: metrics.active_allocations.load(Ordering::Relaxed),
                        total_allocations: metrics.total_allocations.load(Ordering::Relaxed),
                        packets_received: metrics.packets_received.load(Ordering::Relaxed),
                        packets_sent: metrics.packets_sent.load(Ordering::Relaxed),
                        bytes_received: metrics.bytes_received.load(Ordering::Relaxed),
                        bytes_sent: metrics.bytes_sent.load(Ordering::Relaxed),
                        auth_failures: metrics.auth_failures.load(Ordering::Relaxed),
                        rate_limited: metrics.rate_limited.load(Ordering::Relaxed),
                        zero_copy_forwards: metrics.zero_copy_forwards.load(Ordering::Relaxed),
                        send_queue_dropped: metrics.send_queue_dropped.load(Ordering::Relaxed),
                        parser_rejections: metrics.parser_rejections.load(Ordering::Relaxed),
                        malformed_packets: metrics.malformed_packets.load(Ordering::Relaxed),
                        quota_exceeded: metrics.quota_exceeded.load(Ordering::Relaxed),
                        peer_rejected: metrics.peer_rejected.load(Ordering::Relaxed),
                        rtp_streams: metrics.rtp_streams.load(Ordering::Relaxed),
                        rtp_avg_loss_percent: metrics.rtp_avg_loss_pct_x100.load(Ordering::Relaxed)
                            as f64
                            / 100.0,
                        rtp_max_loss_percent: metrics.rtp_max_loss_pct_x100.load(Ordering::Relaxed)
                            as f64
                            / 100.0,
                        rtp_avg_jitter_ms: metrics.rtp_avg_jitter_us.load(Ordering::Relaxed) as f64
                            / 1000.0,
                        rtp_max_jitter_ms: metrics.rtp_max_jitter_us.load(Ordering::Relaxed) as f64
                            / 1000.0,
                        rtp_total_bitrate_kbps: metrics
                            .rtp_total_bitrate_kbps
                            .load(Ordering::Relaxed),
                    };
                    (
                        "200 OK",
                        serde_json::to_string_pretty(&resp).unwrap(),
                        "application/json",
                    )
                }
                "/metrics" => {
                    let m = &metrics;
                    let mut body = format!(
                        "# HELP turna_active_allocations Current active TURN allocations\n\
                         # TYPE turna_active_allocations gauge\n\
                         turna_active_allocations {}\n\
                         # HELP turna_total_allocations Total allocations since start\n\
                         # TYPE turna_total_allocations counter\n\
                         turna_total_allocations {}\n\
                         # HELP turna_packets_received Total packets received\n\
                         # TYPE turna_packets_received counter\n\
                         turna_packets_received {}\n\
                         # HELP turna_packets_sent Total packets sent\n\
                         # TYPE turna_packets_sent counter\n\
                         turna_packets_sent {}\n\
                         # HELP turna_bytes_received Total bytes received\n\
                         # TYPE turna_bytes_received counter\n\
                         turna_bytes_received {}\n\
                         # HELP turna_bytes_sent Total bytes sent\n\
                         # TYPE turna_bytes_sent counter\n\
                         turna_bytes_sent {}\n\
                         # HELP turna_auth_failures Total auth failures\n\
                         # TYPE turna_auth_failures counter\n\
                         turna_auth_failures {}\n\
                         # HELP turna_rate_limited Total rate limited requests\n\
                         # TYPE turna_rate_limited counter\n\
                         turna_rate_limited {}\n\
                         # HELP turna_zero_copy_forwards Total zero-copy forwards\n\
                         # TYPE turna_zero_copy_forwards counter\n\
                         turna_zero_copy_forwards {}\n\
                         # HELP turna_draining Whether node is draining\n\
                         # TYPE turna_draining gauge\n\
                         turna_draining {}\n\
                         # HELP turna_uptime_seconds Uptime in seconds\n\
                         # TYPE turna_uptime_seconds gauge\n\
                         turna_uptime_seconds {}\n\
                         # HELP turna_rtp_streams Active RTP streams\n\
                         # TYPE turna_rtp_streams gauge\n\
                         turna_rtp_streams {}\n\
                         # HELP turna_rtp_avg_loss_percent Average packet loss percent\n\
                         # TYPE turna_rtp_avg_loss_percent gauge\n\
                         turna_rtp_avg_loss_percent {:.2}\n\
                         # HELP turna_rtp_max_loss_percent Max packet loss percent\n\
                         # TYPE turna_rtp_max_loss_percent gauge\n\
                         turna_rtp_max_loss_percent {:.2}\n\
                         # HELP turna_rtp_avg_jitter_ms Average jitter in ms\n\
                         # TYPE turna_rtp_avg_jitter_ms gauge\n\
                         turna_rtp_avg_jitter_ms {:.2}\n\
                         # HELP turna_rtp_max_jitter_ms Max jitter in ms\n\
                         # TYPE turna_rtp_max_jitter_ms gauge\n\
                         turna_rtp_max_jitter_ms {:.2}\n\
                         # HELP turna_rtp_total_bitrate_kbps Total RTP bitrate kbps\n\
                         # TYPE turna_rtp_total_bitrate_kbps gauge\n\
                         turna_rtp_total_bitrate_kbps {}\n\
                         # HELP turna_send_queue_dropped_total Packets dropped due to full send channel\n\
                         # TYPE turna_send_queue_dropped_total counter\n\
                         turna_send_queue_dropped_total {}\n\
                         # HELP turna_parser_rejections_total STUN messages rejected by parser\n\
                         # TYPE turna_parser_rejections_total counter\n\
                         turna_parser_rejections_total {}\n\
                         # HELP turna_malformed_packets_total Packets with unknown protocol\n\
                         # TYPE turna_malformed_packets_total counter\n\
                         turna_malformed_packets_total {}\n\
                         # HELP turna_quota_exceeded_total Packets dropped due to bandwidth quota\n\
                         # TYPE turna_quota_exceeded_total counter\n\
                         turna_quota_exceeded_total {}\n\
                         # HELP turna_peer_rejected_total Permission/ChannelBind/Send requests to denied peer ranges\n\
                         # TYPE turna_peer_rejected_total counter\n\
                         turna_peer_rejected_total {}\n\
                         # HELP tarantool_reconnect_attempts_total Total Tarantool reconnect attempts\n\
                         # TYPE tarantool_reconnect_attempts_total counter\n\
                         tarantool_reconnect_attempts_total {}\n\
                         # HELP tarantool_reconnect_success_total Total successful Tarantool reconnects\n\
                         # TYPE tarantool_reconnect_success_total counter\n\
                         tarantool_reconnect_success_total {}\n\
                         # HELP tarantool_connection_state Connection state (0=connected 1=reconnecting 2=failed)\n\
                         # TYPE tarantool_connection_state gauge\n\
                         tarantool_connection_state {}\n\
                         # HELP grpc_active_streams Currently open gRPC streaming RPCs\n\
                         # TYPE grpc_active_streams gauge\n\
                         grpc_active_streams {}\n\
                         # HELP grpc_shutdown_drain_ms Duration of last graceful drain in ms\n\
                         # TYPE grpc_shutdown_drain_ms gauge\n\
                         grpc_shutdown_drain_ms {}\n\
                         # HELP grpc_forced_kills_total Times drain timeout expired before streams closed\n\
                         # TYPE grpc_forced_kills_total counter\n\
                         grpc_forced_kills_total {}\n\
                         # HELP tarantool_writer_batches_total Total batches flushed by the writer task\n\
                         # TYPE tarantool_writer_batches_total counter\n\
                         tarantool_writer_batches_total {}\n\
                         # HELP tarantool_writer_ops_total Total WriteOps applied by the writer task\n\
                         # TYPE tarantool_writer_ops_total counter\n\
                         tarantool_writer_ops_total {}\n\
                         # HELP tarantool_writer_coalesced_total Events coalesced inside a batch\n\
                         # TYPE tarantool_writer_coalesced_total counter\n\
                         tarantool_writer_coalesced_total {}\n\
                         # HELP tarantool_writer_errors_total Backend errors during flush\n\
                         # TYPE tarantool_writer_errors_total counter\n\
                         tarantool_writer_errors_total {}\n\
                         # HELP tarantool_writes_dropped_total Events dropped because the writer channel was full\n\
                         # TYPE tarantool_writes_dropped_total counter\n\
                         tarantool_writes_dropped_total {}\n\
                         # HELP failover_claimed_total Allocations claimed from dead nodes\n\
                         # TYPE failover_claimed_total counter\n\
                         failover_claimed_total {}\n\
                         # HELP failover_lost_race_total CAS claims lost to concurrent claimer\n\
                         # TYPE failover_lost_race_total counter\n\
                         failover_lost_race_total {}\n\
                         # HELP failover_errors_total Backend errors during failover sweeps\n\
                         # TYPE failover_errors_total counter\n\
                         failover_errors_total {}\n\
                         # HELP failover_sweep_duration_us Duration of last failover sweep in microseconds\n\
                         # TYPE failover_sweep_duration_us gauge\n\
                         failover_sweep_duration_us {}\n\
                         # HELP tarantool_pool_slots Pool connection slot states\n\
                         # TYPE tarantool_pool_slots gauge\n\
                         tarantool_pool_slots{{state=\"idle\"}} {}\n\
                         tarantool_pool_slots{{state=\"busy\"}} {}\n\
                         tarantool_pool_slots{{state=\"broken\"}} {}\n\
                         # HELP turna_cluster_redirects_total Total 300 Try Alternate redirects sent\n\
                         # TYPE turna_cluster_redirects_total counter\n\
                         turna_cluster_redirects_total {}\n\
                         # HELP turna_cluster_nodes Live nodes in the gossip ring (including self)\n\
                         # TYPE turna_cluster_nodes gauge\n\
                         turna_cluster_nodes {}\n",
                        m.active_allocations.load(Ordering::Relaxed),
                        m.total_allocations.load(Ordering::Relaxed),
                        m.packets_received.load(Ordering::Relaxed),
                        m.packets_sent.load(Ordering::Relaxed),
                        m.bytes_received.load(Ordering::Relaxed),
                        m.bytes_sent.load(Ordering::Relaxed),
                        m.auth_failures.load(Ordering::Relaxed),
                        m.rate_limited.load(Ordering::Relaxed),
                        m.zero_copy_forwards.load(Ordering::Relaxed),
                        if m.is_draining() { 1 } else { 0 },
                        m.start_time.elapsed().as_secs(),
                        m.rtp_streams.load(Ordering::Relaxed),
                        m.rtp_avg_loss_pct_x100.load(Ordering::Relaxed) as f64 / 100.0,
                        m.rtp_max_loss_pct_x100.load(Ordering::Relaxed) as f64 / 100.0,
                        m.rtp_avg_jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                        m.rtp_max_jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                        m.rtp_total_bitrate_kbps.load(Ordering::Relaxed),
                        m.send_queue_dropped.load(Ordering::Relaxed),
                        m.parser_rejections.load(Ordering::Relaxed),
                        m.malformed_packets.load(Ordering::Relaxed),
                        m.quota_exceeded.load(Ordering::Relaxed),
                        m.peer_rejected.load(Ordering::Relaxed),
                        m.tarantool_reconnect_attempts.load(Ordering::Relaxed),
                        m.tarantool_reconnect_successes.load(Ordering::Relaxed),
                        m.tarantool_connection_state.load(Ordering::Relaxed),
                        m.grpc_active_streams.load(Ordering::Relaxed),
                        m.grpc_shutdown_drain_ms.load(Ordering::Relaxed),
                        m.grpc_forced_kills.load(Ordering::Relaxed),
                        m.tarantool_writer_batches.load(Ordering::Relaxed),
                        m.tarantool_writer_ops.load(Ordering::Relaxed),
                        m.tarantool_writer_coalesced.load(Ordering::Relaxed),
                        m.tarantool_writer_errors.load(Ordering::Relaxed),
                        m.tarantool_writes_dropped.load(Ordering::Relaxed),
                        m.failover_claimed_total.load(Ordering::Relaxed),
                        m.failover_lost_race_total.load(Ordering::Relaxed),
                        m.failover_errors_total.load(Ordering::Relaxed),
                        m.failover_sweep_duration_us.load(Ordering::Relaxed),
                        m.tarantool_pool_idle.load(Ordering::Relaxed),
                        m.tarantool_pool_busy.load(Ordering::Relaxed),
                        m.tarantool_pool_broken.load(Ordering::Relaxed),
                        m.cluster_redirects.load(Ordering::Relaxed),
                        m.cluster_nodes.load(Ordering::Relaxed),
                    );
                    body.push_str(&m.render_tenant_metrics());
                    body.push_str(&format!(
                        "# HELP turna_processor_panics_total Packet-processing panics caught by the worker guard\n\
                         # TYPE turna_processor_panics_total counter\n\
                         turna_processor_panics_total {}\n",
                        m.processor_panics.load(Ordering::Relaxed)
                    ));
                    body.push_str(&m.render_auth_reason_metrics());
                    body.push_str(&m.render_transport_metrics());
                    body.push_str(&m.render_command_log_metrics());
                    body.push_str(&m.histograms.render_prometheus());
                    if let Some(provider) = &relay_routes {
                        body.push_str(&render_relay_route_metrics(&provider()));
                    }
                    if let Some(provider) = &tenant_traffic {
                        body.push_str(&render_tenant_traffic_metrics(&provider()));
                    }
                    ("200 OK", body, "text/plain; version=0.0.4")
                }
                _ => ("404 Not Found", "not found".to_string(), "text/plain"),
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );

            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}
pub mod histogram;
#[cfg(test)]
mod metrics_format_regression {
    // RC observability: the /metrics body must be valid Prometheus text —
    // no line may begin with whitespace before a metric name or # HELP/# TYPE
    // comment. A previous edit left five counters without `\n\` line
    // continuations, which injected the source indentation into the output.
    use super::*;
    use std::sync::atomic::Ordering;

    /// Reproduce the exact `/metrics` counter block that the server renders.
    /// This mirrors the format! in `serve_with_cluster_routes`; if that block
    /// changes, update here too. We assert structural validity, not values.
    fn render_core_metrics(m: &Metrics) -> String {
        // Reuse the real render helpers for the parts that have them.
        let mut body = format!(
            concat!(
                "# HELP turna_send_queue_dropped_total Packets dropped due to full send channel\n",
                "# TYPE turna_send_queue_dropped_total counter\n",
                "turna_send_queue_dropped_total {}\n",
                "# HELP turna_parser_rejections_total STUN messages rejected by parser\n",
                "# TYPE turna_parser_rejections_total counter\n",
                "turna_parser_rejections_total {}\n",
                "# HELP turna_malformed_packets_total Packets with unknown protocol\n",
                "# TYPE turna_malformed_packets_total counter\n",
                "turna_malformed_packets_total {}\n",
                "# HELP turna_quota_exceeded_total Packets dropped due to bandwidth quota\n",
                "# TYPE turna_quota_exceeded_total counter\n",
                "turna_quota_exceeded_total {}\n",
                "# HELP turna_peer_rejected_total Permission/ChannelBind/Send requests to denied peer ranges\n",
                "# TYPE turna_peer_rejected_total counter\n",
                "turna_peer_rejected_total {}\n",
            ),
            m.send_queue_dropped.load(Ordering::Relaxed),
            m.parser_rejections.load(Ordering::Relaxed),
            m.malformed_packets.load(Ordering::Relaxed),
            m.quota_exceeded.load(Ordering::Relaxed),
            m.peer_rejected.load(Ordering::Relaxed),
        );
        body.push_str(&m.render_auth_reason_metrics());
        body.push_str(&m.render_transport_metrics());
        body
    }

    /// No metric/comment line may start with whitespace (Prometheus rejects a
    /// leading space before a sample; a stray indent means a broken `\n\`).
    #[test]
    fn metrics_text_has_no_indented_lines() {
        let m = Metrics::new();
        for block in [render_core_metrics(&m)] {
            for line in block.lines() {
                if line.is_empty() {
                    continue;
                }
                assert!(
                    !line.starts_with(' ') && !line.starts_with('\t'),
                    "metrics line must not be indented: {line:?}"
                );
            }
        }
    }

    /// The five previously-broken counters must be present with exact names,
    /// each as a bare `name value` sample line (no leading indent).
    #[test]
    fn previously_broken_counters_present_and_flush_left() {
        let m = Metrics::new();
        let body = render_core_metrics(&m);
        for name in [
            "turna_send_queue_dropped_total",
            "turna_parser_rejections_total",
            "turna_malformed_packets_total",
            "turna_quota_exceeded_total",
            "turna_peer_rejected_total",
        ] {
            let sample = format!("{name} ");
            assert!(
                body.lines().any(|l| l.starts_with(&sample)),
                "expected a flush-left sample line for {name}"
            );
        }
    }

    /// turna_auth_failures_by_reason_total must render one series per reason,
    /// all flush-left (guards the labelled-counter helper too).
    #[test]
    fn auth_reason_metrics_flush_left() {
        let m = Metrics::new();
        let body = m.render_auth_reason_metrics();
        for line in body.lines() {
            assert!(
                !line.starts_with(' ') && !line.starts_with('\t'),
                "auth reason line indented: {line:?}"
            );
        }
        assert!(body.contains("turna_auth_failures_by_reason_total{reason=\"integrity_failed\"}"));
    }

    #[test]
    fn derived_readiness_undrain_does_not_clobber_divergence() {
        // P0.5 / review L: with derived readiness, an undrain must not force Ready
        // while a backend divergence is still active.
        let m = Metrics::new();
        // Post-boot baseline.
        m.set_readiness(Readiness::Ready);

        // A divergence appears (writer drops seen).
        m.set_backend_diverged(true);
        m.refresh_readiness();
        assert_eq!(m.readiness(), Readiness::Degraded);

        // Operator drains — drain (intent) wins over divergence.
        m.set_draining(true);
        m.refresh_readiness();
        assert_eq!(m.readiness(), Readiness::Draining);

        // Operator undrains while still diverged — must fall back to Degraded,
        // NOT Ready (the old imperative path could clobber this).
        m.set_draining(false);
        m.refresh_readiness();
        assert_eq!(
            m.readiness(),
            Readiness::Degraded,
            "undrain must not mask an active divergence"
        );

        // Reconcile confirms consistency — only now Ready.
        m.set_backend_diverged(false);
        m.refresh_readiness();
        assert_eq!(m.readiness(), Readiness::Ready);
    }
}
