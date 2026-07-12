import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatBytes, formatBytesRate, formatCount, formatRate } from '../format/format'
import { rateSeries, lastRate } from '../lib/series'
import type { PanelProps } from './types'
import { strokeColor } from '../ui/status'

export function TrafficPanel({ status, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return null

  const rps = rateSeries(history, (s) => s.packets_sent + s.packets_received)
  const bps = rateSeries(history, (s) => s.bytes_sent + s.bytes_received)
  const zcShare = status.packets_sent > 0 ? (status.zero_copy_forwards / status.packets_sent) * 100 : 0

  return (
    <Card title={t('panel.traffic')} frozen={frozen}>
      <div className="grid grid-cols-2 gap-5 sm:grid-cols-4">
        <Stat label={t('traffic.packetsIn')}  value={formatCount(status.packets_received, lang)} />
        <Stat label={t('traffic.packetsOut')} value={formatCount(status.packets_sent, lang)} />
        <Stat label={t('traffic.bytesIn')}    value={formatBytes(status.bytes_received, lang)} />
        <Stat label={t('traffic.bytesOut')}   value={formatBytes(status.bytes_sent, lang)} />
      </div>

      <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-widest text-ink-faint">{t('traffic.rps')}</span>
            <span className="font-mono text-xs text-ink-soft">{formatRate(lastRate(rps), lang, 'pps')}</span>
          </div>
          <MiniChart data={rps} color={strokeColor.neutral} fmt={(v) => formatRate(v, lang, 'pps')} />
        </div>
        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-widest text-ink-faint">{t('traffic.bps')}</span>
            <span className="font-mono text-xs text-ink-soft">{formatBytesRate(lastRate(bps), lang)}</span>
          </div>
          <MiniChart data={bps} color="#a78bfa" fmt={(v) => formatBytesRate(v, lang)} />
        </div>
      </div>

      <div className="mt-4 border-t border-surface-line pt-4">
        <Stat
          label={t('traffic.zeroCopy')}
          value={formatCount(status.zero_copy_forwards, lang)}
          sub={`${zcShare.toFixed(1)}% ${t('traffic.zeroCopyShare')}`}
        />
      </div>
    </Card>
  )
}
