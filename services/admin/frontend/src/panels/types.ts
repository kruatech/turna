import type { NodeStatus, NormalizedMetrics } from '../api/types'
import type { Snapshot } from '../hooks/usePolling'
import type { ClusterNode } from '../api/client'

export interface PanelProps {
  status: NodeStatus | null
  metrics: NormalizedMetrics | null
  history: Snapshot[]
  frozen: boolean
  clusterNodes?: ClusterNode[]
}
