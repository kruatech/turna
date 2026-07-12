import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { Badge } from '../ui/Badge'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatCount, formatRate } from '../format/format'
import { metric, metricOr, metricRateSeries, lastRate } from '../lib/series'
import type { PanelProps } from './types'
import { strokeColor } from '../ui/status'

export function PersistencePanel({ metrics, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  const connState = metric(metrics, 'tarantool_connection_state')
  if (connState === undefined) return null

  const conn: { kind: 'ok' | 'degraded' | 'error'; key: string } =
    connState === 0 ? { kind: 'ok', key: 'persist.connected' }
    : connState === 1 ? { kind: 'degraded', key: 'persist.reconnecting' }
    : { kind: 'error', key: 'persist.disconnected' }

  const ops     = metricOr(metrics, 'tarantool_writer_ops_total', 0)
  const batches = metricOr(metrics, 'tarantool_writer_batches_total', 0)
  const errors  = metricOr(metrics, 'tarantool_writer_errors_total', 0)
  const dropped = metricOr(metrics, 'tarantool_writes_dropped_total', 0)
  const opsRate = metricRateSeries(history, 'tarantool_writer_ops_total')

  return (
    <Card
      title={t('panel.persistence')}
      frozen={frozen}
      right={<Badge kind={conn.kind} label={`${t('persist.connection')}: ${t(conn.key)}`} />}
    >
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label={t('persist.writerOps')}     value={formatCount(ops, lang)} />
        <Stat label={t('persist.writerBatches')} value={formatCount(batches, lang)} />
        <Stat label={t('persist.writerErrors')}  value={formatCount(errors, lang)}  status={errors > 0 ? 'error' : 'neutral'} />
        <Stat label={t('persist.writesDropped')} value={formatCount(dropped, lang)} status={dropped > 0 ? 'error' : 'neutral'} />
      </div>
      <div className="mt-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-[10px] font-semibold uppercase tracking-widest text-ink-faint">{t('persist.opsRate')}</span>
          <span className="font-mono text-xs text-ink-soft">{formatRate(lastRate(opsRate), lang, 'ops/s')}</span>
        </div>
        <MiniChart data={opsRate} color={strokeColor.ok} fmt={(v) => formatRate(v, lang, 'ops/s')} />
      </div>
    </Card>
  )
}
