import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { metricOr, anyNonZeroMatching, keysWithPrefix, metric } from '../lib/series'
import type { PanelProps } from './types'

export function BackpressurePanel({ status, metrics, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return null
  const droppedStatus = status.send_queue_dropped
  const droppedMetric = metricOr(metrics, 'turna_send_queue_dropped_total', droppedStatus)
  const dropped = Math.max(droppedStatus, droppedMetric)
  const warn = dropped > 0
  return (
    <Card title={t('panel.backpressure')} frozen={frozen}>
      <Stat
        label={t('bp.sendQueueDropped')}
        value={formatCount(dropped, lang)}
        status={warn ? 'degraded' : 'ok'}
        sub={warn ? t('bp.warn') : t('bp.ok')}
      />
    </Card>
  )
}

export function TransportsPanel({ metrics, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  const families = ['uring', 'afxdp', 'af_xdp', 'quic', 'dtls']
  if (!anyNonZeroMatching(metrics, families)) return null
  const names = new Set<string>()
  for (const f of families) for (const k of keysWithPrefix(metrics, '')) if (k.includes(f)) names.add(k)
  const rows = [...names].sort()
  return (
    <Card title={t('panel.transports')} frozen={frozen}>
      <table className="w-full text-sm">
        <tbody className="font-mono">
          {rows.map((n) => (
            <tr key={n} className="border-t border-surface-line first:border-0">
              <td className="py-1.5 pr-4 text-ink-soft">{n}</td>
              <td className="py-1.5 text-right tabular-nums text-ink">{formatCount(metric(metrics, n) ?? 0, lang)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}
