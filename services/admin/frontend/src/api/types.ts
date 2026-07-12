// Shapes returned by the turna-admin bridge.
// Field names for /status are taken verbatim from the node (crates/health/src/lib.rs).
// New fields added after reading the actual StatusResponse struct.

export interface NodeStatus {
  status: string
  draining: boolean
  uptime_secs: number
  active_allocations: number
  total_allocations: number
  packets_received: number
  packets_sent: number
  bytes_received: number
  bytes_sent: number
  auth_failures: number
  rate_limited: number
  zero_copy_forwards: number
  send_queue_dropped: number
  parser_rejections: number
  malformed_packets: number
  quota_exceeded: number
  peer_rejected: number
  rtp_streams: number
  rtp_avg_loss_percent: number
  // Fields confirmed in StatusResponse but missing from original TZ §1.2:
  rtp_max_loss_percent: number
  rtp_avg_jitter_ms: number
  rtp_max_jitter_ms: number
  rtp_total_bitrate_kbps: number
  // tolerate fields the node may add later without breaking the UI
  [key: string]: unknown
}

export interface LabeledSample {
  labels: Record<string, string>
  value: number
}

export interface NormalizedMetrics {
  counters: Record<string, number>
  gauges: Record<string, number>
  labeled: Record<string, LabeledSample[]>
}
