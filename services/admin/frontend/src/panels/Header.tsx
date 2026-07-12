import { useEffect, useState } from 'react'
import { Badge } from '../ui/Badge'
import { useI18n } from '../i18n'
import { useTheme } from '../theme/theme'
import { formatDuration } from '../format/format'
import { metric } from '../lib/series'
import { INTERVALS } from '../hooks/usePolling'
import type { NodeStatus, NormalizedMetrics } from '../api/types'
import type { StatusKind } from '../ui/status'

function readinessInfo(v: number | undefined): { kind: StatusKind; key: string } {
  switch (v) {
    case 0: return { kind: 'neutral', key: 'readiness.0' }
    case 1: return { kind: 'ok', key: 'readiness.1' }
    case 2: return { kind: 'degraded', key: 'readiness.2' }
    case 3: return { kind: 'draining', key: 'readiness.3' }
    default: return { kind: 'neutral', key: 'readiness.unknown' }
  }
}

export function Header({
  status, metrics, live, lastUpdated, loading,
  intervalMs, setIntervalMs, paused, setPaused, refreshNow,
}: {
  status: NodeStatus | null
  metrics: NormalizedMetrics | null
  live: boolean | null
  lastUpdated: number | null
  loading: boolean
  intervalMs: number
  setIntervalMs: (n: number) => void
  paused: boolean
  setPaused: (b: boolean) => void
  refreshNow: () => void
}) {
  const { t, lang, setLang } = useI18n()
  const { theme, toggle } = useTheme()
  const [, force] = useState(0)
  useEffect(() => {
    const id = window.setInterval(() => force((n) => n + 1), 1000)
    return () => window.clearInterval(id)
  }, [])

  const readiness = readinessInfo(metric(metrics, 'turna_backend_readiness'))
  const panics = metric(metrics, 'turna_processor_panics_total') ?? 0
  const ago = lastUpdated ? Math.floor((Date.now() - lastUpdated) / 1000) : null

  return (
    <header className="sticky top-0 z-20 border-b border-surface-line bg-surface-base/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-5 py-0 h-14">

        {/* Logo */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex h-8 w-8 items-center justify-center rounded-chip bg-accent-tealDim">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
              <circle cx="8" cy="8" r="2" fill="#2dd4bf"/>
            </svg>
          </div>
          <div className="leading-none">
            <div className="text-sm font-semibold text-ink tracking-tight">turna</div>
            <div className="text-[10px] font-mono text-ink-faint">admin · stage 1</div>
          </div>
        </div>

        <div className="h-5 w-px bg-surface-lineMid shrink-0" />

        {/* Status badges */}
        <div className="flex items-center gap-2 flex-wrap">
          {status && (
            <Badge
              kind={status.draining ? 'draining' : status.status === 'ok' ? 'ok' : 'neutral'}
              label={status.draining ? t('status.draining') : t('status.ok')}
            />
          )}
          <Badge kind={readiness.kind} label={t(readiness.key)} />
          {live !== null && (
            <Badge kind={live ? 'ok' : 'draining'} label={live ? t('header.live') : t('header.notLive')} />
          )}
          {panics > 0 && (
            <Badge kind="error" label={`${t('header.panics')}: ${panics.toLocaleString(lang)}`} />
          )}
          {status && (
            <span className="font-mono text-[11px] text-ink-faint">
              ↑ {formatDuration(status.uptime_secs, lang)}
            </span>
          )}
        </div>

        {/* Right controls */}
        <div className="ml-auto flex items-center gap-2 shrink-0">
          {/* last updated */}
          <span className="font-mono text-[11px] text-ink-faint flex items-center gap-1.5">
            {loading && <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-accent-teal inline-block" />}
            {ago === null
              ? t('header.never')
              : paused
                ? t('header.paused')
                : `${ago}${t('header.secondsAgo')}`}
          </span>

          <div className="h-4 w-px bg-surface-lineMid" />

          {/* interval */}
          <select
            className="rounded-chip border border-surface-lineMid bg-surface-raised px-2.5 py-1 text-[11px] font-mono text-ink-soft hover:border-accent-teal/40 transition-colors focus:outline-none focus:border-accent-teal/60 cursor-pointer"
            value={paused ? 'pause' : String(intervalMs)}
            onChange={(e) => {
              const v = e.target.value
              if (v === 'pause') setPaused(true)
              else { setPaused(false); setIntervalMs(Number(v)) }
            }}
          >
            {INTERVALS.map((ms) => (
              <option key={ms} value={ms} className="bg-surface-card">{ms / 1000}s</option>
            ))}
            <option value="pause" className="bg-surface-card">⏸ pause</option>
          </select>

          {/* refresh */}
          <button
            onClick={refreshNow}
            className="flex h-7 w-7 items-center justify-center rounded-chip border border-surface-lineMid bg-surface-raised text-ink-soft hover:border-accent-teal/50 hover:text-accent-teal transition-all"
            title={t('header.refreshNow')}
          >
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M11.5 6.5A5 5 0 1 1 9 2.4" strokeLinecap="round"/>
              <path d="M9 1v2.4H11.4" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>

          {/* lang */}
          <button
            onClick={() => setLang(lang === 'ru' ? 'en' : 'ru')}
            className="flex h-7 items-center rounded-chip border border-surface-lineMid bg-surface-raised px-2.5 font-mono text-[11px] uppercase text-ink-soft hover:border-accent-teal/50 hover:text-accent-teal transition-all"
          >
            {lang}
          </button>

          {/* theme */}
          <button
            onClick={toggle}
            className="flex h-7 w-7 items-center justify-center rounded-chip border border-surface-lineMid bg-surface-raised text-ink-soft hover:border-accent-teal/50 hover:text-accent-teal transition-all"
            title={t('header.theme')}
          >
            {theme === 'dark'
              ? <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><path d="M10.5 7.8A5 5 0 1 1 4.2 1.5a3.5 3.5 0 0 0 6.3 6.3z"/></svg>
              : <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><circle cx="6" cy="6" r="2.5"/><path d="M6 1v1M6 10v1M1 6h1M10 6h1M2.6 2.6l.7.7M8.7 8.7l.7.7M8.7 3.3l-.7.7M3.3 8.7l-.7.7" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" fill="none"/></svg>
            }
          </button>
        </div>
      </div>
    </header>
  )
}
