import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { statusSeries } from '../lib/series'
import type { PanelProps } from './types'
import { strokeColor } from '../ui/status'

export function AllocationsPanel({ status, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return null
  const active = statusSeries(history, (s) => s.active_allocations)

  return (
    <Card title={t('panel.allocations')} frozen={frozen}>
      <div className="grid grid-cols-2 gap-5">
        <Stat
          label={t('alloc.active')}
          value={formatCount(status.active_allocations, lang)}
          status={status.active_allocations > 0 ? 'ok' : 'neutral'}
        />
        <Stat label={t('alloc.total')} value={formatCount(status.total_allocations, lang)} />
      </div>
      <div className="mt-4">
        <span className="mb-2 block text-[10px] font-semibold uppercase tracking-widest text-ink-faint">
          {t('alloc.activeOverTime')}
        </span>
        <MiniChart data={active} color={strokeColor.ok} fmt={(v) => formatCount(v, lang)} />
      </div>
    </Card>
  )
}
