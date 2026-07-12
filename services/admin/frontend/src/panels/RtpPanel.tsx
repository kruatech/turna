import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import type { PanelProps } from './types'

export function RtpPanel({ status, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return null
  const streams = status.rtp_streams
  return (
    <Card title={t('panel.rtp')} frozen={frozen}>
      {streams > 0 ? (
        <div className="grid grid-cols-2 gap-4">
          <Stat label={t('rtp.streams')} value={formatCount(streams, lang)} status="ok" />
          <Stat label={t('rtp.avgLoss')} value={`${status.rtp_avg_loss_percent.toFixed(1)}%`}
            status={status.rtp_avg_loss_percent > 2 ? 'degraded' : 'neutral'} />
        </div>
      ) : (
        <p className="text-sm text-ink-faint">{t('rtp.none')}</p>
      )}
    </Card>
  )
}
