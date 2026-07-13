// Shapes returned by the turna-admin bridge.
// Field names for /status are taken verbatim from the node.

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
  rtp_max_loss_percent: number
  rtp_avg_jitter_ms: number
  rtp_max_jitter_ms: number
  rtp_total_bitrate_kbps: number
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

export interface RuntimeConfigSnapshot {
  version: number
  max_allocations: number
  max_allocations_per_user: number
  max_bytes_per_sec_per_allocation: number
}

export interface NodeRuntimeConfig {
  node_id: string
  desired_version: number
  observed_version: number
  observed: RuntimeConfigSnapshot | null
  pending_desired: RuntimeConfigSnapshot | null
  status: string
  last_apply_error: string
  updated_at_ms: number
}

export interface UpdateConfigResult {
  request_id: string
  previous_version: number
  observed_version: number
  changed: boolean
  applied: RuntimeConfigSnapshot | null
  terminal_status: string
  error: string
  rolled_back: boolean
}

export type LimitMode = 'inherit' | 'value' | 'unlimited' | 'disabled'

export interface LimitInput {
  mode: LimitMode
  value?: number
}

export interface EffectiveUserLimits {
  max_allocations: number
  allocations_disabled: boolean
  max_bytes_per_sec_per_allocation: number
  bandwidth_disabled: boolean
  max_lifetime_secs: number
  lifetime_disabled: boolean
  inherited_fields: string[]
  capped_fields: string[]
}

export interface SetUserLimitsResult {
  request_id: string
  previous_version: number
  observed_version: number
  effective: EffectiveUserLimits | null
  max_user_allocations_in_scope: number
  max_user_allocations_above_limit: boolean
  terminal_status: string
  error: string
}
