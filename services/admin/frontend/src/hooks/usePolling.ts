import { useCallback, useEffect, useRef, useState } from 'react'
import { api, NodeUnreachable, type ClusterNode } from '../api/client'
import type { NodeStatus, NormalizedMetrics } from '../api/types'

export interface Snapshot {
  t: number
  status: NodeStatus | null
  metrics: NormalizedMetrics | null
}

const MAX_POINTS = 120
export const INTERVALS = [2000, 5000, 10000, 30000] as const

export function usePolling() {
  const [intervalMs, setIntervalMs] = useState(5000)
  const [paused, setPaused]         = useState(false)
  const [status, setStatus]         = useState<NodeStatus | null>(null)
  const [metrics, setMetrics]       = useState<NormalizedMetrics | null>(null)
  const [live, setLive]             = useState<boolean | null>(null)
  const [ready, setReady]           = useState<boolean | null>(null)
  const [clusterNodes, setClusterNodes] = useState<ClusterNode[]>([])
  const [unreachable, setUnreachable]   = useState(false)
  const [loading, setLoading]       = useState(false)
  const [lastUpdated, setLastUpdated]   = useState<number | null>(null)
  const [history, setHistory]       = useState<Snapshot[]>([])
  const inFlight = useRef(false)

  const tick = useCallback(async () => {
    if (inFlight.current) return
    inFlight.current = true
    setLoading(true)
    try {
      const [s, m, h, r, cl] = await Promise.all([
        api.status(), api.metrics(), api.health(), api.ready(),
        api.cluster().catch(() => [] as ClusterNode[]), // /cluster may not exist on all builds
      ])
      const now = Date.now()
      setStatus(s); setMetrics(m); setLive(h); setReady(r); setClusterNodes(cl)
      setUnreachable(false); setLastUpdated(now)
      setHistory(prev => {
        const next = [...prev, { t: now, status: s, metrics: m }]
        return next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next
      })
    } catch (e) {
      if (e instanceof NodeUnreachable) setUnreachable(true)
    } finally { inFlight.current = false; setLoading(false) }
  }, [])

  useEffect(() => {
    void tick()
    if (paused) return
    const id = window.setInterval(() => void tick(), intervalMs)
    return () => window.clearInterval(id)
  }, [tick, intervalMs, paused])

  return {
    status, metrics, live, ready, clusterNodes,
    unreachable, loading, lastUpdated, history,
    intervalMs, setIntervalMs, paused, setPaused,
    refreshNow: useCallback(() => void tick(), [tick]),
  }
}
