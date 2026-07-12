import { Card } from '../ui/Card'
import { Stat } from '../ui/Stat'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { metric, metricOr } from '../lib/series'
import type { PanelProps } from './types'

export function ClusterPanel({ metrics, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  const redirects = metricOr(metrics, 'turna_cluster_redirects_total', 0)
  const claimed   = metricOr(metrics, 'failover_claimed_total', 0)
  const lost      = metricOr(metrics, 'failover_lost_race_total', 0)
  const errors    = metricOr(metrics, 'failover_errors_total', 0)
  const sweepUs   = metric(metrics, 'failover_sweep_duration_us')
  const tarantoolState = metric(metrics, 'tarantool_connection_state')
  const standalone = redirects === 0 && claimed === 0 && lost === 0 && errors === 0 && tarantoolState === undefined

  return (
    <Card title={t('panel.cluster')} frozen={frozen}>
      {standalone ? (
        <p className="text-sm text-ink-faint">{t('cluster.standalone')}</p>
      ) : (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <Stat label={t('cluster.redirects')}      value={formatCount(redirects, lang)} />
          <Stat label={t('cluster.failoverClaimed')} value={formatCount(claimed, lang)} />
          <Stat label={t('cluster.failoverLost')}   value={formatCount(lost, lang)}   status={lost > 0 ? 'degraded' : 'neutral'} />
          <Stat label={t('cluster.failoverErrors')} value={formatCount(errors, lang)} status={errors > 0 ? 'error' : 'neutral'} />
          {sweepUs !== undefined && (
            <Stat label={t('cluster.sweepDuration')} value={`${formatCount(sweepUs, lang)}`} unit="µs" />
          )}
        </div>
      )}
    </Card>
  )
}
