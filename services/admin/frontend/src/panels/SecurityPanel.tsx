import { Card } from '../ui/Card'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { metricOr } from '../lib/series'
import type { PanelProps } from './types'
import type { NodeStatus } from '../api/types'

function Counter({ label, value, delta, lang }: { label: string; value: number; delta: number; lang: 'ru' | 'en' }) {
  const hot = value > 0
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-widest text-ink-faint">{label}</span>
      <div className="flex items-baseline gap-1.5">
        <span className={'value-fade font-mono text-xl font-semibold tabular-nums leading-none ' +
          (hot ? 'text-status-degraded' : 'text-ink')}>
          {formatCount(value, lang)}
        </span>
        {delta > 0 && (
          <span className="font-mono text-xs font-medium text-status-error">▲{formatCount(delta, lang)}</span>
        )}
      </div>
    </div>
  )
}

export function SecurityPanel({ status, metrics, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return null

  const byReason = metrics?.labeled['turna_auth_failures_by_reason_total'] ?? []
  const panics = metricOr(metrics, 'turna_processor_panics_total', 0)
  const prev = history.length >= 2 ? history[history.length - 2].status : null
  const d = (pick: (s: NodeStatus) => number): number => prev ? Math.max(0, pick(status) - pick(prev)) : 0

  return (
    <Card title={t('panel.security')} frozen={frozen}>
      {panics > 0 && (
        <div className="mb-4 flex items-center gap-2.5 rounded-chip bg-status-errorDim px-3 py-2 ring-1 ring-status-error/30">
          <span className="h-1.5 w-1.5 rounded-full bg-status-error shrink-0" />
          <span className="text-xs font-medium text-status-error">{t('sec.panicAlert')}: {formatCount(panics, lang)}</span>
        </div>
      )}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Counter label={t('sec.authFailures')}    value={status.auth_failures}    delta={d(s => s.auth_failures)}    lang={lang} />
        <Counter label={t('sec.rateLimited')}     value={status.rate_limited}     delta={d(s => s.rate_limited)}     lang={lang} />
        <Counter label={t('sec.parserRejections')}value={status.parser_rejections}delta={d(s => s.parser_rejections)}lang={lang} />
        <Counter label={t('sec.malformed')}       value={status.malformed_packets}delta={d(s => s.malformed_packets)}lang={lang} />
        <Counter label={t('sec.quotaExceeded')}   value={status.quota_exceeded}   delta={d(s => s.quota_exceeded)}   lang={lang} />
        <Counter label={t('sec.peerRejected')}    value={status.peer_rejected}    delta={d(s => s.peer_rejected)}    lang={lang} />
      </div>
      {byReason.length > 0 && (
        <div className="mt-4 border-t border-surface-line pt-4">
          <span className="mb-2 block text-[10px] font-semibold uppercase tracking-widest text-ink-faint">{t('sec.byReason')}</span>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-widest text-ink-faint">
                <th className="pb-2 font-semibold">{t('sec.reason')}</th>
                <th className="pb-2 text-right font-semibold">{t('sec.value')}</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {byReason.map((s, i) => (
                <tr key={i} className="border-t border-surface-line">
                  <td className="py-1.5 text-ink-soft">{s.labels.reason ?? '—'}</td>
                  <td className="py-1.5 text-right tabular-nums text-ink">{formatCount(s.value, lang)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {history.length >= 2 && (
        <p className="mt-3 text-[10px] text-ink-faint">▲ = {t('sec.since')}</p>
      )}
    </Card>
  )
}
