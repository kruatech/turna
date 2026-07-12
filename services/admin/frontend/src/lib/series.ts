import type { Snapshot } from '../hooks/usePolling'
import type { NodeStatus, NormalizedMetrics } from '../api/types'
import { timeLabel } from '../format/format'

export interface Point {
  t: number
  label: string
  value: number
}

// Absolute value of a /status field over time.
export function statusSeries(history: Snapshot[], pick: (s: NodeStatus) => number): Point[] {
  return history
    .filter((h) => h.status)
    .map((h) => ({ t: h.t, label: timeLabel(h.t), value: pick(h.status as NodeStatus) }))
}

// Per-second rate as delta between adjacent snapshots (instantaneous rps/bps).
export function rateSeries(history: Snapshot[], pick: (s: NodeStatus) => number): Point[] {
  const out: Point[] = []
  for (let i = 1; i < history.length; i++) {
    const a = history[i - 1].status
    const b = history[i].status
    if (!a || !b) continue
    const dt = (history[i].t - history[i - 1].t) / 1000
    if (dt <= 0) continue
    const rate = Math.max(0, (pick(b) - pick(a)) / dt)
    out.push({ t: history[i].t, label: timeLabel(history[i].t), value: rate })
  }
  return out
}

export function lastRate(pts: Point[]): number {
  return pts.length ? pts[pts.length - 1].value : 0
}

// Metric lookup: check gauges then counters (name taken verbatim).
export function metric(m: NormalizedMetrics | null, name: string): number | undefined {
  if (!m) return undefined
  if (name in m.gauges) return m.gauges[name]
  if (name in m.counters) return m.counters[name]
  return undefined
}

export function metricOr(m: NormalizedMetrics | null, name: string, dflt = 0): number {
  const v = metric(m, name)
  return v === undefined ? dflt : v
}

// Rate of a counter metric over history (per second).
export function metricRateSeries(history: Snapshot[], name: string): Point[] {
  const out: Point[] = []
  for (let i = 1; i < history.length; i++) {
    const a = history[i - 1].metrics
    const b = history[i].metrics
    if (!a || !b) continue
    const av = a.counters[name] ?? a.gauges[name]
    const bv = b.counters[name] ?? b.gauges[name]
    if (av === undefined || bv === undefined) continue
    const dt = (history[i].t - history[i - 1].t) / 1000
    if (dt <= 0) continue
    out.push({ t: history[i].t, label: timeLabel(history[i].t), value: Math.max(0, (bv - av) / dt) })
  }
  return out
}

// True if any metric whose name contains one of the substrings is present and
// non-zero (used to decide whether experimental-transport panels are shown).
export function anyNonZeroMatching(m: NormalizedMetrics | null, substrings: string[]): boolean {
  if (!m) return false
  const buckets = [m.counters, m.gauges]
  for (const b of buckets) {
    for (const [k, v] of Object.entries(b)) {
      if (v !== 0 && substrings.some((s) => k.includes(s))) return true
    }
  }
  for (const k of Object.keys(m.labeled)) {
    if (substrings.some((s) => k.includes(s))) return true
  }
  return false
}

export function keysWithPrefix(m: NormalizedMetrics | null, prefix: string): string[] {
  if (!m) return []
  const out = new Set<string>()
  for (const k of Object.keys(m.counters)) if (k.startsWith(prefix)) out.add(k)
  for (const k of Object.keys(m.gauges)) if (k.startsWith(prefix)) out.add(k)
  for (const k of Object.keys(m.labeled)) if (k.startsWith(prefix)) out.add(k)
  return [...out].sort()
}
