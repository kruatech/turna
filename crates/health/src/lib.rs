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
    /// 2.4 per-backend readiness (observability). With fail-fast startup these
    /// are all-or-nothing at boot; `Degraded` is reserved for future
    /// non-fatal backend failures.
    pub transport_readiness: AtomicU8,
    pub dtls_readiness: AtomicU8,
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub active_allocations: AtomicU64,
    pub total_allocations: AtomicU64,
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
            transport_readiness: AtomicU8::new(Readiness::Starting as u8),
            dtls_readiness: AtomicU8::new(Readiness::Starting as u8),
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            active_allocations: AtomicU64::new(0),
            total_allocations: AtomicU64::new(0),
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

    pub fn readiness(&self) -> Readiness {
        Readiness::from_u8(self.readiness.load(Ordering::SeqCst))
    }

    pub fn is_ready(&self) -> bool {
        self.readiness() == Readiness::Ready
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

    /// Render the experimental-transport (QUIC/WebTransport + DTLS) counters,
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
             # HELP turna_backend_readiness Process readiness (0=starting,1=ready,2=degraded,3=draining)\n\
             # TYPE turna_backend_readiness gauge\n\
             turna_backend_readiness {}\n\
             # HELP turna_transport_readiness Primary UDP transport backend readiness (0=starting,1=ready,2=degraded,3=draining)\n\
             # TYPE turna_transport_readiness gauge\n\
             turna_transport_readiness {}\n\
             # HELP turna_dtls_readiness DTLS listener readiness (0=starting,1=ready,2=degraded,3=draining; starting if DTLS disabled)\n\
             # TYPE turna_dtls_readiness gauge\n\
             turna_dtls_readiness {}\n",
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
            self.readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.transport_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
            self.dtls_readiness.load(std::sync::atomic::Ordering::Relaxed) as u64,
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
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
    let esc = |t: &str| t.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::new();

    out.push_str(
        "# HELP turna_tenant_bytes_relayed_total Bytes relayed per tenant (accrued at allocation close)\n\
         # TYPE turna_tenant_bytes_relayed_total counter\n",
    );
    for (t, bytes, _, _) in samples {
        out.push_str(&format!(
            "turna_tenant_bytes_relayed_total{{tenant=\"{}\"}} {bytes}\n",
            esc(t)
        ));
    }

    out.push_str(
        "# HELP turna_tenant_packets_relayed_total Packets relayed per tenant (accrued at allocation close)\n\
         # TYPE turna_tenant_packets_relayed_total counter\n",
    );
    for (t, _, packets, _) in samples {
        out.push_str(&format!(
            "turna_tenant_packets_relayed_total{{tenant=\"{}\"}} {packets}\n",
            esc(t)
        ));
    }

    out.push_str(
        "# HELP turna_tenant_allocations_closed_total Allocations closed per tenant\n\
         # TYPE turna_tenant_allocations_closed_total counter\n",
    );
    for (t, _, _, closed) in samples {
        out.push_str(&format!(
            "turna_tenant_allocations_closed_total{{tenant=\"{}\"}} {closed}\n",
            esc(t)
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
pub async fn serve_with_cluster_routes(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    cluster: Option<Arc<dyn ClusterView>>,
    relay_routes: Option<RelayRouteMetricsProvider>,
    tenant_traffic: Option<TenantTrafficProvider>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
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
                    None => (
                        "200 OK",
                        "[]".to_string(),
                        "application/json",
                    ),
                },
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
                         # HELP turna_send_queue_dropped_total Packets dropped due to full send channel
                         # TYPE turna_send_queue_dropped_total counter
                         turna_send_queue_dropped_total {}
                         # HELP turna_parser_rejections_total STUN messages rejected by parser
                         # TYPE turna_parser_rejections_total counter
                         turna_parser_rejections_total {}
                         # HELP turna_malformed_packets_total Packets with unknown protocol
                         # TYPE turna_malformed_packets_total counter
                         turna_malformed_packets_total {}
                         # HELP turna_quota_exceeded_total Packets dropped due to bandwidth quota
                         # TYPE turna_quota_exceeded_total counter
                         turna_quota_exceeded_total {}
                         # HELP turna_peer_rejected_total Permission/ChannelBind/Send requests to denied peer ranges
                         # TYPE turna_peer_rejected_total counter
                         turna_peer_rejected_total {}
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
