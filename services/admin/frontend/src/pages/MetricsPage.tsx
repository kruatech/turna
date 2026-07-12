import { useState, useMemo } from 'react'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import type { PanelProps } from '../panels/types'

export function MetricsPage({ metrics }: PanelProps) {
  const { t, lang } = useI18n()
  const [search, setSearch] = useState('')
  const [tab, setTab] = useState<'counters' | 'gauges' | 'labeled'>('counters')

  const q = search.toLowerCase()

  const counters = useMemo(() =>
    Object.entries(metrics?.counters ?? {}).filter(([k]) => k.includes(q)).sort(([a], [b]) => a.localeCompare(b)),
    [metrics, q])

  const gauges = useMemo(() =>
    Object.entries(metrics?.gauges ?? {}).filter(([k]) => k.includes(q)).sort(([a], [b]) => a.localeCompare(b)),
    [metrics, q])

  const labeled = useMemo(() =>
    Object.entries(metrics?.labeled ?? {}).filter(([k]) => k.includes(q)).sort(([a], [b]) => a.localeCompare(b)),
    [metrics, q])

  if (!metrics) return (
    <div className="card flex items-center justify-center h-48 text-[--muted] text-sm fade-up">{t('metrics.noData')}</div>
  )

  const tabs: { id: typeof tab; label: string; count: number }[] = [
    { id: 'counters', label: t('metrics.counters'), count: Object.keys(metrics.counters).length },
    { id: 'gauges',   label: t('metrics.gauges'),   count: Object.keys(metrics.gauges).length },
    { id: 'labeled',  label: t('metrics.labeled'),  count: Object.keys(metrics.labeled).length },
  ]

  return (
    <div className="space-y-4 fade-up">
      {/* search + tabs */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex gap-1 rounded-xl border border-[--border] bg-[--raised] p-1">
          {tabs.map(tb => (
            <button key={tb.id} onClick={() => setTab(tb.id)}
              className={'flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-all ' +
                (tab === tb.id ? 'bg-[--card] text-[--ink] shadow-sm' : 'text-[--muted] hover:text-[--ink]')}>
              {tb.label}
              <span className={'rounded-full px-1.5 py-0.5 font-mono text-[10px] ' +
                (tab === tb.id ? 'bg-teal-400/15 text-teal-400' : 'bg-[--raised] text-[--faint]')}>
                {tb.count}
              </span>
            </button>
          ))}
        </div>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder={t('metrics.search')}
          className="rounded-lg border border-[--border] bg-[--card] px-3 py-2 text-xs font-mono text-[--ink] placeholder-[--faint] focus:outline-none focus:border-teal-400/50 w-full sm:w-64" />
      </div>

      {/* table */}
      <div className="card overflow-hidden">
        {tab !== 'labeled' ? (
          <>
            <div className="grid grid-cols-[1fr_auto] border-b border-[--border] font-mono text-[10px] uppercase tracking-widest text-[--faint]">
              <div className="px-5 py-3">{t('metrics.name')}</div>
              <div className="px-5 py-3 text-right">{t('metrics.value')}</div>
            </div>
            <div className="divide-y divide-[--border] max-h-[70vh] overflow-y-auto">
              {(tab === 'counters' ? counters : gauges).map(([k, v]) => (
                <div key={k} className="grid grid-cols-[1fr_auto] font-mono text-xs hover:bg-[--raised] transition-colors">
                  <div className="px-5 py-2.5 text-[--muted] truncate" title={k}>{k}</div>
                  <div className="px-5 py-2.5 text-right font-semibold text-[--ink] tabular-nums">{formatCount(v, lang)}</div>
                </div>
              ))}
              {(tab === 'counters' ? counters : gauges).length === 0 && (
                <div className="px-5 py-8 text-center text-xs text-[--faint]">—</div>
              )}
            </div>
          </>
        ) : (
          <>
            <div className="grid grid-cols-[1fr_1fr_auto] border-b border-[--border] font-mono text-[10px] uppercase tracking-widest text-[--faint]">
              <div className="px-5 py-3">{t('metrics.name')}</div>
              <div className="px-5 py-3">{t('metrics.labels')}</div>
              <div className="px-5 py-3 text-right">{t('metrics.value')}</div>
            </div>
            <div className="divide-y divide-[--border] max-h-[70vh] overflow-y-auto">
              {labeled.flatMap(([k, samples]) =>
                samples.map((s, i) => (
                  <div key={k + i} className="grid grid-cols-[1fr_1fr_auto] font-mono text-xs hover:bg-[--raised] transition-colors">
                    <div className="px-5 py-2.5 text-[--muted] truncate" title={k}>{k}</div>
                    <div className="px-5 py-2.5 text-[--faint] truncate">
                      {Object.entries(s.labels).map(([lk, lv]) => `${lk}="${lv}"`).join(' ')}
                    </div>
                    <div className="px-5 py-2.5 text-right font-semibold text-[--ink] tabular-nums">{formatCount(s.value, lang)}</div>
                  </div>
                ))
              )}
              {labeled.length === 0 && <div className="px-5 py-8 text-center text-xs text-[--faint]">—</div>}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
