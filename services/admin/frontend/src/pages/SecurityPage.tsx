import { Card } from '../ui/Card'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { metricOr, rateSeries } from '../lib/series'
import type { PanelProps } from '../panels/types'
import type { NodeStatus } from '../api/types'

export function SecurityPage({ status, metrics, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return <div className="flex items-center justify-center h-48 text-[--muted]">{t('se.waiting')}</div>
  const prev     = history.length >= 2 ? history[history.length - 2].status : null
  const d        = (pick: (s: NodeStatus) => number) => prev ? Math.max(0, pick(status) - pick(prev)) : 0
  const panics   = metricOr(metrics, 'turna_processor_panics_total', 0)
  const byReason = metrics?.labeled['turna_auth_failures_by_reason_total'] ?? []
  const authH    = rateSeries(history, s => s.auth_failures)
  const ROWS = [
    { label: t('sec.authFailures'),    value: status.auth_failures,     delta: d(s => s.auth_failures),     hot: true },
    { label: t('sec.rateLimited'),     value: status.rate_limited,      delta: d(s => s.rate_limited),      hot: true },
    { label: t('sec.parserRejections'),value: status.parser_rejections, delta: d(s => s.parser_rejections), hot: false },
    { label: t('sec.malformed'),       value: status.malformed_packets, delta: d(s => s.malformed_packets), hot: false },
    { label: t('sec.quotaExceeded'),   value: status.quota_exceeded,    delta: d(s => s.quota_exceeded),    hot: true },
    { label: t('sec.peerRejected'),    value: status.peer_rejected,     delta: d(s => s.peer_rejected),     hot: false },
  ]
  return (
    <div className="space-y-5 fade-up">
      {panics > 0 && (
        <div className="flex items-center gap-3 rounded-xl bg-rose-400/10 px-5 py-3 ring-1 ring-rose-400/25">
          <span className="h-2 w-2 rounded-full bg-rose-400 pulse shrink-0"/>
          <span className="text-sm font-semibold text-rose-400">{t('sec.panicAlert')}: {formatCount(panics, lang)}</span>
        </div>
      )}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        {ROWS.map(({ label, value, delta, hot }) => (
          <div key={label} className="card p-4">
            <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div>
            <div className={'font-mono text-2xl font-semibold vf ' + (hot && value > 0 ? 'text-amber-400' : 'text-[--ink]')}>
              {formatCount(value, lang)}
            </div>
            {delta > 0 && <div className="mt-1 text-xs font-mono text-rose-400">▲{formatCount(delta, lang)} {t('se.sincePoll')}</div>}
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title={t('se.authHist')} frozen={frozen}>
          <MiniChart data={authH} color="#f87171" height={140} fmt={v => formatCount(v, lang)} />
        </Card>
        {byReason.length > 0 && (
          <Card title={t('se.byReason')} frozen={frozen}>
            <div className="space-y-1">
              {byReason.map((s, i) => (
                <div key={i} className="flex items-center justify-between py-1.5 border-b border-[--border] last:border-0">
                  <span className="font-mono text-sm text-[--muted]">{s.labels.reason ?? '—'}</span>
                  <span className={'font-mono text-sm font-semibold ' + (s.value > 0 ? 'text-amber-400' : 'text-[--ink]')}>
                    {formatCount(s.value, lang)}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
