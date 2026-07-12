import { useEffect, useState } from 'react'
import { Badge } from '../ui/Badge'
import { useI18n } from '../i18n'
import { useTheme } from '../theme/theme'
import { formatDuration } from '../format/format'
import { metric } from '../lib/series'
import { INTERVALS } from '../hooks/usePolling'
import type { NodeStatus, NormalizedMetrics } from '../api/types'
import type { Status } from '../ui/tokens'
import type { NavId } from './Sidebar'

function readiness(v: number | undefined): { s: Status; label: string } {
  switch (v) {
    case 1: return { s: 'ok',       label: 'Ready' }
    case 2: return { s: 'degraded', label: 'Degraded' }
    case 3: return { s: 'draining', label: 'Draining' }
    default: return { s: 'neutral', label: 'Starting' }
  }
}

export function Topbar({ page, status, metrics, live, ready,
  lastUpdated, loading, intervalMs, setIntervalMs, paused, setPaused, refreshNow }:
  { page: NavId; status: NodeStatus | null; metrics: NormalizedMetrics | null
    live: boolean | null; ready: boolean | null
    lastUpdated: number | null; loading: boolean
    intervalMs: number; setIntervalMs: (n: number) => void
    paused: boolean; setPaused: (b: boolean) => void; refreshNow: () => void }) {
  const { t, lang, setLang } = useI18n()
  const { theme, toggle } = useTheme()
  const [, tick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => tick(n => n + 1), 1000)
    return () => clearInterval(id)
  }, [])

  const r      = readiness(metric(metrics, 'turna_backend_readiness'))
  const panics = metric(metrics, 'turna_processor_panics_total') ?? 0
  const ago    = lastUpdated ? Math.floor((Date.now() - lastUpdated) / 1000) : null

  const pageTitle: Record<NavId, string> = {
    overview:    t('nav.overview'),
    allocations: t('nav.allocations'),
    users:       t('nav.users'),
    nodes:       t('nav.nodes'),
    cluster:     t('nav.cluster'),
    events:      t('nav.events'),
    metrics:     t('nav.metrics'),
    config:      t('nav.config'),
    diagnostics: t('nav.diagnostics'),
  }

  return (
    <header className="flex h-14 shrink-0 items-center border-b border-[--border] bg-[--card] px-5 gap-4">
      <h1 className="text-base font-semibold text-[--ink] mr-2 shrink-0">{pageTitle[page]}</h1>

      <div className="flex items-center gap-2 flex-wrap min-w-0">
        {/* liveness from /health */}
        {live !== null && <Badge kind={live ? 'ok' : 'error'} label={live ? 'live' : 'down'} />}
        {/* readiness from /ready */}
        {ready !== null && !ready && <Badge kind="draining" label="not ready" />}
        {/* backend_readiness from metrics */}
        <Badge kind={r.s} label={r.label} />
        {panics > 0 && <Badge kind="error" label={`⚠ panics: ${panics}`} />}
        {status?.draining && <Badge kind="draining" label="draining" />}
      </div>

      <div className="ml-auto flex items-center gap-2 shrink-0">
        <span className="flex items-center gap-1.5 font-mono text-[11px] text-[--muted]">
          {loading && <span className="pulse h-1.5 w-1.5 rounded-full bg-teal-400 inline-block" />}
          {paused ? t('topbar.paused') : ago === null ? t('topbar.nodata') : `${t('header.lastUpdated')} ${ago}${t('header.secondsAgo')}`}
        </span>

        <select value={paused ? 'pause' : String(intervalMs)}
          onChange={e => { const v = e.target.value; if (v === 'pause') setPaused(true); else { setPaused(false); setIntervalMs(Number(v)) } }}
          className="rounded-lg border border-[--border] bg-[--raised] px-2.5 py-1.5 text-xs font-mono text-[--ink] focus:outline-none focus:border-teal-400/50 cursor-pointer transition-colors">
          {INTERVALS.map(ms => <option key={ms} value={ms}>{ms/1000}s</option>)}
          <option value="pause">⏸ {t('topbar.paused')}</option>
        </select>

        <button onClick={refreshNow}
          className="flex h-8 w-8 items-center justify-center rounded-lg border border-[--border] bg-[--raised] text-[--muted] hover:text-teal-400 hover:border-teal-400/40 transition-all">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M12 7A5 5 0 1 1 9.5 2.9" strokeLinecap="round"/>
            <path d="M9.5 1.5v2.5H12" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>

        {status && (
          <span className="font-mono text-[11px] text-[--muted] hidden lg:block">
            ↑ {formatDuration(status.uptime_secs, lang)}
          </span>
        )}
        <div className="h-4 w-px bg-[--border]" />
        <button onClick={() => setLang(lang === 'ru' ? 'en' : 'ru')}
          className="flex h-8 items-center rounded-lg border border-[--border] bg-[--raised] px-2.5 font-mono text-xs uppercase text-[--muted] hover:text-[--ink] hover:border-teal-400/40 transition-all">
          {lang}
        </button>
        <button onClick={toggle}
          className="flex h-8 w-8 items-center justify-center rounded-lg border border-[--border] bg-[--raised] text-[--muted] hover:text-[--ink] hover:border-teal-400/40 transition-all">
          {theme === 'dark'
            ? <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M11.5 8.5A5 5 0 1 1 5.5 2.5a3.5 3.5 0 0 0 6 6z"/></svg>
            : <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="7" cy="7" r="2.5"/><path d="M7 1v1.5M7 11.5V13M1 7h1.5M11.5 7H13M2.9 2.9l1 1M10.1 10.1l1 1M10.1 2.9l-1 1M3.9 10.1l-1 1" strokeLinecap="round"/></svg>
          }
        </button>
      </div>
    </header>
  )
}
