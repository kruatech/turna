//! Health check HTTP endpoint
//!
//! Minimal HTTP server on a separate port. No external HTTP framework.
//! - GET /health  → 200 OK / 503 draining
//! - GET /status  → JSON with node stats
//! - GET /metrics → Prometheus text format
pub mod load_reporter;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use serde::Serialize;

/// Shared metrics that are updated by relay workers.
pub struct Metrics {
    pub is_draining: AtomicBool,
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
    // RTP quality (updated periodically)
    pub rtp_streams: AtomicU64,
    pub rtp_avg_loss_pct_x100: AtomicU64,   // loss% * 100 (e.g. 250 = 2.50%)
    pub rtp_max_loss_pct_x100: AtomicU64,
    pub rtp_avg_jitter_us: AtomicU64,        // jitter in microseconds
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
    pub tarantool_reconnect_attempts:  AtomicU64,
    pub tarantool_reconnect_successes: AtomicU64,
    /// 0 = connected, 1 = reconnecting, 2 = failed (matches `ConnState` in turna-state-backend).
    pub tarantool_connection_state:    AtomicU64,

    // ── gRPC server metrics ───────────────────────────────────────────────────
    /// Number of currently open streaming RPCs (WatchAllocations, WatchMetrics).
    pub grpc_active_streams:       AtomicU64,
    /// Duration of the most recent graceful drain in milliseconds.
    pub grpc_shutdown_drain_ms:    AtomicU64,
    /// Total number of times drain timeout expired before all streams closed.
    pub grpc_forced_kills:         AtomicU64,

    // ── Failover metrics (PR A, task 2.1) ─────────────────────────────────────
    /// Total allocations successfully claimed from dead nodes.
    pub failover_claimed_total:     AtomicU64,
    /// Total CAS attempts lost to a concurrent claim by another node.
    pub failover_lost_race_total:   AtomicU64,
    /// Total backend errors during failover sweeps.
    pub failover_errors_total:      AtomicU64,
    /// Duration of the most recent failover sweep in microseconds.
    pub failover_sweep_duration_us: AtomicU64,

    // ── Tarantool connection pool gauge (PR A, task 2.2) ──────────────────────
    // Updated by TarantoolBackend::pool_states() via a periodic background
    // task in main.rs (same pattern as tarantool_reconnect_* above).
    /// Pool slots currently idle (mutex not held).
    pub tarantool_pool_idle:   AtomicU64,
    /// Pool slots currently busy (request in flight).
    pub tarantool_pool_busy:   AtomicU64,
    /// Pool slots currently broken (last I/O failed, awaiting reconnect).
    pub tarantool_pool_broken: AtomicU64,

    // ── Tarantool write-behind writer metrics (PR2, task #3) ──────────────────
    // Mirror counters owned by `services/node/src/writer.rs`. The writer
    // task copies its internal `WriterCounters` here after every flush so
    // they show up on `/metrics`.
    /// Total batches flushed to the backend.
    pub tarantool_writer_batches:   AtomicU64,
    /// Total operations applied (sum across Create/Refresh/Remove/Perm/Chan).
    pub tarantool_writer_ops:       AtomicU64,
    /// Number of events the writer was able to merge with another
    /// (e.g. Refresh+Refresh → keep latest, Create+Remove → drop both).
    pub tarantool_writer_coalesced: AtomicU64,
    /// Backend errors from per-port flush attempts. Independent of
    /// `tarantool_reconnect_*` (those track the transport layer).
    pub tarantool_writer_errors:    AtomicU64,
    /// Events dropped on the hot path because the writer's bounded
    /// channel was full. Indicates Tarantool is keeping up or not.
    pub tarantool_writes_dropped:   AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            is_draining: AtomicBool::new(false),
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
            quota_exceeded:    AtomicU64::new(0),
            peer_rejected:     AtomicU64::new(0),
            rtp_streams: AtomicU64::new(0),
            rtp_avg_loss_pct_x100: AtomicU64::new(0),
            rtp_max_loss_pct_x100: AtomicU64::new(0),
            rtp_avg_jitter_us: AtomicU64::new(0),
            rtp_max_jitter_us: AtomicU64::new(0),
            rtp_total_bitrate_kbps: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
            tarantool_reconnect_attempts:  AtomicU64::new(0),
            tarantool_reconnect_successes: AtomicU64::new(0),
            tarantool_connection_state:    AtomicU64::new(0),
            grpc_active_streams:           AtomicU64::new(0),
            grpc_shutdown_drain_ms:        AtomicU64::new(0),
            grpc_forced_kills:             AtomicU64::new(0),
            // PR2: writer
            tarantool_writer_batches:      AtomicU64::new(0),
            tarantool_writer_ops:          AtomicU64::new(0),
            tarantool_writer_coalesced:    AtomicU64::new(0),
            tarantool_writer_errors:       AtomicU64::new(0),
            tarantool_writes_dropped:      AtomicU64::new(0),
            // PR A: failover
            failover_claimed_total:        AtomicU64::new(0),
            failover_lost_race_total:      AtomicU64::new(0),
            failover_errors_total:         AtomicU64::new(0),
            failover_sweep_duration_us:    AtomicU64::new(0),
            // PR A: pool gauge
            tarantool_pool_idle:           AtomicU64::new(0),
            tarantool_pool_busy:           AtomicU64::new(0),
            tarantool_pool_broken:         AtomicU64::new(0),
        }
    }

    pub fn set_draining(&self, val: bool) {
        self.is_draining.store(val, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.is_draining.load(Ordering::SeqCst)
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

/// Start health check HTTP server.
pub async fn serve(addr: SocketAddr, metrics: Arc<Metrics>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "health check server started");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = metrics.clone();

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
                "/health" => {
                    if metrics.is_draining() {
                        ("503 Service Unavailable", "draining".to_string(), "text/plain")
                    } else {
                        ("200 OK", "ok".to_string(), "text/plain")
                    }
                }
                "/status" => {
                    let resp = StatusResponse {
                        status: if metrics.is_draining() { "draining" } else { "ok" },
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
                        rtp_avg_loss_percent: metrics.rtp_avg_loss_pct_x100.load(Ordering::Relaxed) as f64 / 100.0,
                        rtp_max_loss_percent: metrics.rtp_max_loss_pct_x100.load(Ordering::Relaxed) as f64 / 100.0,
                        rtp_avg_jitter_ms: metrics.rtp_avg_jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                        rtp_max_jitter_ms: metrics.rtp_max_jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                        rtp_total_bitrate_kbps: metrics.rtp_total_bitrate_kbps.load(Ordering::Relaxed),
                    };
                    ("200 OK", serde_json::to_string_pretty(&resp).unwrap(), "application/json")
                }
                "/metrics" => {
                    let m = &metrics;
                    let body = format!(
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
                         tarantool_pool_slots{{state=\"broken\"}} {}\n",
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
                    );
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
}pub mod histogram;
