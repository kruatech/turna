import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatCount, formatRate } from '../format/format'
import { metric, metricOr, metricRateSeries, lastRate } from '../lib/series'
import type { PanelProps } from '../panels/types'

export function PersistencePage({ metrics, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  const connState = metric(metrics, 'tarantool_connection_state')
  if (connState === undefined) {
    return (
      <div className="card flex items-center gap-4 p-6 fade-up">
        <Badge kind="neutral" label={t('pe.notConfigured')} />
      </div>
    )
  }
  const conn: { kind: 'ok' | 'degraded' | 'error'; label: string } =
    connState === 0 ? { kind: 'ok',       label: t('persist.connected') }
    : connState === 1 ? { kind: 'degraded', label: t('persist.reconnecting') }
    : { kind: 'error', label: t('persist.disconnected') }
  const ops     = metricOr(metrics, 'tarantool_writer_ops_total', 0)
  const batches = metricOr(metrics, 'tarantool_writer_batches_total', 0)
  const errors  = metricOr(metrics, 'tarantool_writer_errors_total', 0)
  const dropped = metricOr(metrics, 'tarantool_writes_dropped_total', 0)
  const opsRate = metricRateSeries(history, 'tarantool_writer_ops_total')
  return (
    <div className="space-y-5 fade-up">
      <div className="card flex items-center gap-4 p-5">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-1.5">{t('pe.title')}</div>
          <Badge kind={conn.kind} label={conn.label} />
        </div>
        <div className="ml-auto font-mono text-xs text-[--muted]">{t('pe.hint')}</div>
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <MC label={t('pe.ops')}     value={formatCount(ops, lang)} />
        <MC label={t('pe.batches')} value={formatCount(batches, lang)} />
        <MC label={t('pe.errors')}  value={formatCount(errors, lang)}  crit={errors > 0} />
        <MC label={t('pe.dropped')} value={formatCount(dropped, lang)} crit={dropped > 0} />
      </div>
      <Card title={t('pe.opsTitle')} frozen={frozen}>
        <div className="mb-3 flex items-baseline gap-2">
          <span className="font-mono text-3xl font-semibold text-emerald-400">{formatRate(lastRate(opsRate), lang, '')}</span>
          <span className="text-sm text-[--muted]">ops/s</span>
        </div>
        <MiniChart data={opsRate} color="#34d399" height={140} fmt={v => formatRate(v, lang, 'ops/s')} />
      </Card>
    </div>
  )
}
function MC({ label, value, crit }: { label: string; value: string; crit?: boolean }) {
  return <div className="card p-5"><div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div><div className={'font-mono text-2xl font-semibold vf ' + (crit ? 'text-rose-400' : 'text-[--ink]')}>{value}</div></div>
}
