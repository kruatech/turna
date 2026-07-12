import { useState, useCallback } from 'react'
import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { metric, metricOr } from '../lib/series'
import { api } from '../api/client'
import type { ClusterNode } from '../api/client'
import type { PanelProps } from '../panels/types'

interface FailoverStatus {
  claimed_total?: number
  lost_race_total?: number
  errors_total?: number
  last_sweep_us?: number
  draining?: boolean
  [key: string]: unknown
}

export function ClusterPage({ metrics, frozen, clusterNodes = [] }: PanelProps) {
  const { t, lang } = useI18n()

  const redirects    = metricOr(metrics, 'turna_cluster_redirects_total', 0)
  const claimed      = metricOr(metrics, 'failover_claimed_total', 0)
  const lost         = metricOr(metrics, 'failover_lost_race_total', 0)
  const errors       = metricOr(metrics, 'failover_errors_total', 0)
  const sweepUs      = metric(metrics, 'failover_sweep_duration_us')
  const clusterCount = metricOr(metrics, 'turna_cluster_nodes', clusterNodes.length)
  const standalone   = redirects === 0 && claimed === 0 && lost === 0 && errors === 0 && clusterCount <= 1

  const [fsData, setFsData]       = useState<FailoverStatus | null>(null)
  const [fsLoading, setFsLoading] = useState(false)
  const [fsError, setFsError]     = useState<string | null>(null)

  const loadFailover = useCallback(async () => {
    setFsLoading(true); setFsError(null)
    try { setFsData(await api.manage.failoverStatus() as FailoverStatus) }
    catch { setFsError(t('nodes.actionError')) }
    finally { setFsLoading(false) }
  }, [t])

  return (
    <div className="space-y-5 fade-up">
      {standalone ? (
        <div className="card flex items-center gap-4 p-6">
          <Badge kind="neutral" label="standalone" />
          <span className="text-[--muted]">{t('cl.standaloneDesc')}</span>
        </div>
      ) : (
        <>
          {/* cluster nodes from /cluster API */}
          {clusterNodes.length > 0 && (
            <div className="card overflow-hidden">
              <div className="border-b border-[--border] px-5 py-3 flex items-center justify-between">
                <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">
                  {t('nodes.clusterNodes')} ({clusterCount})
                </h2>
              </div>
              <div className="divide-y divide-[--border]">
                <div className="grid grid-cols-3 font-mono text-[10px] uppercase tracking-widest text-[--faint] px-5 py-2">
                  <span>Node ID</span><span>TURN addr</span><span/>
                </div>
                {clusterNodes.map((n: ClusterNode) => (
                  <div key={n.node_id} className="grid grid-cols-3 items-center px-5 py-3 hover:bg-[--raised] transition-colors">
                    <span className="font-mono text-sm font-semibold text-teal-400">{n.node_id}</span>
                    <span className="font-mono text-sm text-[--muted]">{n.turn_addr}</span>
                    <span className="flex justify-end">
                      {n.is_self && <Badge kind="ok" label="self" />}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* metrics from polling */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <MC label={t('cluster.redirects')}       value={formatCount(redirects, lang)} />
            <MC label={t('cluster.failoverClaimed')} value={formatCount(claimed,   lang)} />
            <MC label={t('cluster.failoverLost')}    value={formatCount(lost,      lang)} warn={lost > 0} />
            <MC label={t('cluster.failoverErrors')}  value={formatCount(errors,    lang)} crit={errors > 0} />
          </div>

          {sweepUs !== undefined && (
            <Card title={t('cl.sweepTitle')} frozen={frozen}>
              <div className="font-mono text-3xl font-semibold text-violet-400">
                {formatCount(sweepUs, lang)} <span className="text-base text-[--muted]">{t('cluster.us')}</span>
              </div>
              <div className="text-xs text-[--muted] mt-1">{t('cl.sweepDesc')}</div>
            </Card>
          )}

          {/* live failover.status */}
          <div className="card overflow-hidden">
            <div className="flex items-center justify-between border-b border-[--border] px-5 py-3">
              <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">
                {t('cluster.failoverDetail')}
              </h2>
              <button onClick={loadFailover} disabled={fsLoading}
                className="flex items-center gap-1.5 rounded-lg border border-[--border] bg-[--raised] px-3 py-1.5 text-xs text-[--muted] hover:text-[--ink] disabled:opacity-50 transition-all">
                {fsLoading
                  ? <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-teal-400 border-t-transparent"/>
                  : <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10 6A4 4 0 1 1 8 2.5" strokeLinecap="round"/><path d="M8 1v2.5H10.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
                }
                {t('cluster.refresh')}
              </button>
            </div>
            {fsError && <div className="px-5 py-4 text-sm text-rose-400">{fsError}</div>}
            {fsData && (
              <div className="divide-y divide-[--border] font-mono text-sm">
                {Object.entries(fsData).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between px-5 py-2.5 hover:bg-[--raised] transition-colors">
                    <span className="text-[--muted]">{k}</span>
                    <span className={(k.includes('error') && Number(v) > 0 ? 'text-rose-400' : k.includes('lost') && Number(v) > 0 ? 'text-amber-400' : 'text-[--ink]') + ' font-semibold'}>
                      {String(v)}
                    </span>
                  </div>
                ))}
              </div>
            )}
            {!fsData && !fsLoading && !fsError && (
              <div className="px-5 py-8 text-center text-sm text-[--faint]">{t('cluster.refresh')} →</div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function MC({ label, value, warn, crit }: { label: string; value: string; warn?: boolean; crit?: boolean }) {
  return (
    <div className="card p-5">
      <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div>
      <div className={'font-mono text-2xl font-semibold vf ' + (crit ? 'text-rose-400' : warn ? 'text-amber-400' : 'text-[--ink]')}>{value}</div>
    </div>
  )
}
