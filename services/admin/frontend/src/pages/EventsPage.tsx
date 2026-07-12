import { useState, useEffect, useRef } from 'react'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { timeLabel } from '../format/format'
import type { PanelProps } from '../panels/types'
import type { NormalizedMetrics } from '../api/types'

interface Event {
  id: number
  time: string
  metric: string
  delta: number
  value: number
  labels?: string
  kind: 'grew' | 'new'
}

let eid = 0

function diffMetrics(prev: NormalizedMetrics, curr: NormalizedMetrics): Omit<Event, 'id' | 'time'>[] {
  const out: Omit<Event, 'id' | 'time'>[] = []
  // counters
  for (const [k, v] of Object.entries(curr.counters)) {
    const pv = prev.counters[k]
    if (pv === undefined && v > 0) out.push({ metric: k, delta: v, value: v, kind: 'new' })
    else if (pv !== undefined && v > pv) out.push({ metric: k, delta: v - pv, value: v, kind: 'grew' })
  }
  // gauges
  for (const [k, v] of Object.entries(curr.gauges)) {
    const pv = prev.gauges[k]
    if (pv === undefined) out.push({ metric: k, delta: v, value: v, kind: 'new' })
    else if (v !== pv) out.push({ metric: k, delta: v - pv, value: v, kind: 'grew' })
  }
  // labeled
  for (const [k, samples] of Object.entries(curr.labeled)) {
    for (const s of samples) {
      const labelStr = Object.entries(s.labels).map(([lk, lv]) => `${lk}="${lv}"`).join(', ')
      const prevSamples = prev.labeled[k] ?? []
      const prevSample = prevSamples.find(p => JSON.stringify(p.labels) === JSON.stringify(s.labels))
      if (!prevSample && s.value > 0) out.push({ metric: k, delta: s.value, value: s.value, labels: labelStr, kind: 'new' })
      else if (prevSample && s.value > prevSample.value) out.push({ metric: k, delta: s.value - prevSample.value, value: s.value, labels: labelStr, kind: 'grew' })
    }
  }
  return out
}

export function EventsPage({ history }: PanelProps) {
  const { t, lang } = useI18n()
  const [events, setEvents] = useState<Event[]>([])
  const prevMetrics = useRef<NormalizedMetrics | null>(null)

  useEffect(() => {
    if (history.length < 2) return
    const last = history[history.length - 1]
    const prev = history[history.length - 2]
    if (!last.metrics || !prev.metrics) return
    if (last.metrics === prevMetrics.current) return
    prevMetrics.current = last.metrics
    const diffs = diffMetrics(prev.metrics, last.metrics)
    if (diffs.length === 0) return
    const now = timeLabel(last.t)
    const newEvents: Event[] = diffs.map(d => ({ ...d, id: ++eid, time: now }))
    setEvents(prev => [...newEvents, ...prev].slice(0, 200))
  }, [history])

  const kindColor = { grew: 'text-amber-400', new: 'text-teal-400' }
  const kindBg    = { grew: 'bg-amber-400/8', new: 'bg-teal-400/8' }

  return (
    <div className="space-y-4 fade-up">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-[--ink]">{t('events.title')}</h2>
          <p className="text-xs text-[--muted] mt-0.5">{t('events.desc')}</p>
        </div>
        {events.length > 0 && (
          <button onClick={() => setEvents([])}
            className="rounded-lg border border-[--border] bg-[--raised] px-3 py-1.5 text-xs text-[--muted] hover:text-[--ink] transition-colors">
            {t('events.clear')}
          </button>
        )}
      </div>

      {events.length === 0 ? (
        <div className="card flex items-center justify-center h-48 text-[--muted] text-sm">
          {t('events.noEvents')}
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="grid grid-cols-[auto_1fr_auto_auto] gap-0 font-mono text-xs border-b border-[--border]">
            <div className="px-4 py-2.5 font-semibold uppercase tracking-widest text-[--faint]">{t('events.time')}</div>
            <div className="px-4 py-2.5 font-semibold uppercase tracking-widest text-[--faint]">{t('events.metric')}</div>
            <div className="px-4 py-2.5 font-semibold uppercase tracking-widest text-[--faint] text-right">{t('events.delta')}</div>
            <div className="px-4 py-2.5 font-semibold uppercase tracking-widest text-[--faint] text-right">{t('events.value')}</div>
          </div>
          <div className="divide-y divide-[--border] max-h-[70vh] overflow-y-auto">
            {events.map(ev => (
              <div key={ev.id} className={'grid grid-cols-[auto_1fr_auto_auto] gap-0 font-mono text-xs items-center ' + kindBg[ev.kind]}>
                <div className="px-4 py-2.5 text-[--faint] whitespace-nowrap">{ev.time}</div>
                <div className="px-4 py-2.5 text-[--ink] overflow-hidden">
                  <div className="truncate">{ev.metric}</div>
                  {ev.labels && <div className="text-[--faint] text-[10px] truncate mt-0.5">{ev.labels}</div>}
                </div>
                <div className={'px-4 py-2.5 text-right font-semibold ' + kindColor[ev.kind]}>
                  {ev.delta > 0 ? '+' : ''}{formatCount(ev.delta, lang)}
                </div>
                <div className="px-4 py-2.5 text-right text-[--muted]">{formatCount(ev.value, lang)}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
