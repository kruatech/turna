import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatCount, timeLabel } from '../format/format'
import type { Point } from '../lib/series'
import type { Snapshot } from '../hooks/usePolling'
import type { PanelProps } from './types'

// Loss over each polling interval: lost / expected between adjacent /status
// snapshots. Both are node-wide counters fed by the RTP analyzer, so this is
// the relayed-media loss rate right now, not an average since the stream began.
export function intervalLossSeries(history: Snapshot[]): Point[] {
  const out: Point[] = []
  for (let i = 1; i < history.length; i++) {
    const a = history[i - 1].status
    const b = history[i].status
    if (!a || !b) continue
    const exp = (b.rtp_packets_expected_total ?? 0) - (a.rtp_packets_expected_total ?? 0)
    const lost = (b.rtp_packets_lost_total ?? 0) - (a.rtp_packets_lost_total ?? 0)
    if (exp <= 0) continue
    out.push({ t: history[i].t, label: timeLabel(history[i].t), value: Math.max(0, (lost / exp) * 100) })
  }
  return out
}

const pct = (v: number) => `${v.toFixed(v < 10 ? 2 : 1)}%`
const ms = (v: number) => v.toFixed(v < 10 ? 2 : 1)

export function RtpPanel({ status, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return null
  const streams = status.rtp_streams
  const loss = intervalLossSeries(history)
  const lastLoss = loss.length ? loss[loss.length - 1].value : undefined
  const hasCounters = status.rtp_packets_total !== undefined
  return (
    <Card title={t('panel.rtp')} frozen={frozen}>
      {streams > 0 || (status.rtp_packets_total ?? 0) > 0 ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label={t('rtp.streams')} value={formatCount(streams, lang)} status="ok" />
            <Stat label={t('rtp.lossNow')}
              value={lastLoss === undefined ? '—' : pct(lastLoss)}
              status={lastLoss !== undefined && lastLoss > 2 ? 'degraded' : 'neutral'}
              sub={t('rtp.lossNowSub')} />
            <Stat label={t('rtp.avgLoss')} value={pct(status.rtp_avg_loss_percent)}
              status={status.rtp_avg_loss_percent > 2 ? 'degraded' : 'neutral'}
              sub={`${t('rtp.maxLoss')}: ${pct(status.rtp_max_loss_percent)}`} />
            <Stat label={t('rtp.bitrate')} value={formatCount(status.rtp_total_bitrate_kbps, lang)} unit={t('rtp.kbps')} />
            <Stat label={t('rtp.avgJitter')} value={ms(status.rtp_avg_jitter_ms)} unit={t('rtp.ms')}
              sub={`${t('rtp.maxJitter')}: ${ms(status.rtp_max_jitter_ms)} ${t('rtp.ms')}`} />
            {hasCounters && (
              <>
                <Stat label={t('rtp.jitterP95')} value={ms(status.rtp_jitter_p95_ms ?? 0)} unit={t('rtp.ms')} />
                <Stat label={t('rtp.lossP95')} value={pct(status.rtp_loss_p95_percent ?? 0)} />
                <Stat label={t('rtp.outOfOrder')} value={formatCount(status.rtp_packets_out_of_order_total ?? 0, lang)}
                  sub={`${formatCount(status.rtp_packets_lost_total ?? 0, lang)} ${t('rtp.lostOf')} ${formatCount(status.rtp_packets_expected_total ?? 0, lang)}`} />
              </>
            )}
          </div>
          {loss.length > 1 && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-widest text-[--faint] mb-1">{t('rtp.lossChart')}</div>
              <MiniChart data={loss} color="#f59e0b" height={90} fmt={pct} />
            </div>
          )}
          <p className="text-xs text-[--muted] leading-snug">{t('rtp.note')}</p>
        </div>
      ) : (
        <p className="text-sm text-ink-faint">{t('rtp.none')}</p>
      )}
    </Card>
  )
}
