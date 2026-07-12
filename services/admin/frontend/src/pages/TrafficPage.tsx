import { Card } from '../ui/Card'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatBytes, formatBytesRate, formatCount, formatRate } from '../format/format'
import { rateSeries, lastRate } from '../lib/series'
import type { PanelProps } from '../panels/types'

export function TrafficPage({ status, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return <div className="flex items-center justify-center h-48 text-[--muted]">{t('ov.waiting')}</div>
  const bpsIn  = rateSeries(history, s => s.bytes_received)
  const bpsOut = rateSeries(history, s => s.bytes_sent)
  const rpsIn  = rateSeries(history, s => s.packets_received)
  const rpsOut = rateSeries(history, s => s.packets_sent)
  const zcShare = status.packets_sent > 0 ? ((status.zero_copy_forwards / status.packets_sent) * 100).toFixed(1) : '0'
  return (
    <div className="space-y-5 fade-up">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { label: t('tr.bytesIn'),  value: formatBytes(status.bytes_received, lang), sub: formatBytesRate(lastRate(bpsIn), lang),  color: 'text-teal-400' },
          { label: t('tr.bytesOut'), value: formatBytes(status.bytes_sent, lang),     sub: formatBytesRate(lastRate(bpsOut), lang), color: 'text-violet-400' },
          { label: t('tr.pktsIn'),   value: formatCount(status.packets_received, lang),sub: formatRate(lastRate(rpsIn), lang, 'pps'), color: 'text-sky-400' },
          { label: t('tr.pktsOut'),  value: formatCount(status.packets_sent, lang),   sub: formatRate(lastRate(rpsOut), lang,'pps'), color: 'text-[--ink]' },
        ].map(({ label, value, sub, color }) => (
          <div key={label} className="card p-4">
            <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div>
            <div className={'font-mono text-xl font-semibold tabular-nums vf ' + color}>{value}</div>
            <div className="text-xs text-[--muted] mt-1">{sub}</div>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title={t('tr.bpsIn')}  frozen={frozen}><MiniChart data={bpsIn}  color="#2dd4bf" height={140} fmt={v => formatBytesRate(v, lang)} /></Card>
        <Card title={t('tr.bpsOut')} frozen={frozen}><MiniChart data={bpsOut} color="#818cf8" height={140} fmt={v => formatBytesRate(v, lang)} /></Card>
        <Card title={t('tr.rpsIn')}  frozen={frozen}><MiniChart data={rpsIn}  color="#38bdf8" height={120} fmt={v => formatRate(v, lang,'pps')} /></Card>
        <Card title={t('tr.rpsOut')} frozen={frozen}><MiniChart data={rpsOut} color="#fb923c" height={120} fmt={v => formatRate(v, lang,'pps')} /></Card>
      </div>
      <Card title={t('tr.zeroCopy')} frozen={frozen}>
        <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
          <SC label={t('tr.forwards')}     value={formatCount(status.zero_copy_forwards, lang)} sub={zcShare + t('tr.shareOf')} color="text-emerald-400" />
          <SC label={t('tr.queueDropped')} value={formatCount(status.send_queue_dropped, lang)} color={status.send_queue_dropped > 0 ? 'text-amber-400' : 'text-[--ink]'} />
        </div>
      </Card>
    </div>
  )
}
function SC({ label, value, sub, color }: { label: string; value: string; sub?: string; color: string }) {
  return <div className="card p-4"><div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div><div className={'font-mono text-xl font-semibold tabular-nums vf ' + color}>{value}</div>{sub && <div className="text-xs text-[--muted] mt-1">{sub}</div>}</div>
}
