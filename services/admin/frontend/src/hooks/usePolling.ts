import { useCallback, useEffect, useRef, useState } from 'react'
import { api, AuthRequired, NodeUnreachable, promptAdminToken, setAdminToken, type ClusterNode } from '../api/client'
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
  const [authRequired, setAuthRequired] = useState(false)
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
      setUnreachable(false); setAuthRequired(false); setLastUpdated(now)
      setHistory(prev => {
        const next = [...prev, { t: now, status: s, metrics: m }]
        return next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next
      })
    } catch (e) {
      if (e instanceof NodeUnreachable) setUnreachable(true)
      if (e instanceof AuthRequired) {
        // A rejected token is dropped rather than replayed: the backend delays
        // every failed attempt, and polling with it would keep that going.
        setAdminToken('')
        setAuthRequired(true)
      }
    } finally { inFlight.current = false; setLoading(false) }
  }, [])

  // Polling stops while no valid token is held and resumes once one is entered.
  useEffect(() => {
    if (authRequired) return
    void tick()
    if (paused) return
    const id = window.setInterval(() => void tick(), intervalMs)
    return () => window.clearInterval(id)
  }, [tick, intervalMs, paused, authRequired])

  const enterToken = useCallback(() => {
    if (promptAdminToken()) setAuthRequired(false)
  }, [])

  return {
    status, metrics, live, ready, clusterNodes,
    unreachable, authRequired, enterToken, loading, lastUpdated, history,
    intervalMs, setIntervalMs, paused, setPaused,
    refreshNow: useCallback(() => void tick(), [tick]),
  }
}
