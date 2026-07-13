import { useState, useCallback, useRef } from 'react'
import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatDuration, formatCount, formatBytes } from '../format/format'
import { statusSeries, rateSeries, metric, metricOr } from '../lib/series'
import { api } from '../api/client'
import type { PanelProps } from '../panels/types'
import type { Status } from '../ui/tokens'

function readinessInfo(v: number | undefined): { kind: Status; label: string } {
  switch (v) {
    case 0: return { kind: 'neutral',  label: 'Starting' }
    case 1: return { kind: 'ok',       label: 'Ready' }
    case 2: return { kind: 'degraded', label: 'Degraded' }
    case 3: return { kind: 'draining', label: 'Draining' }
    default: return { kind: 'neutral', label: '—' }
  }
}

export function NodesPage({ status, metrics, history, frozen, clusterNodes = [] }: PanelProps) {
  const { t, lang } = useI18n()
  const [draining, setDraining]   = useState(false)
  const [toast, setToast]         = useState<{ msg: string; ok: boolean } | null>(null)

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok })
    setTimeout(() => setToast(null), 2500)
  }

  // High-assurance idempotency: one stable key per drain/undrain INTENT, reused
  // across retries (a network-timeout retry must dedup, not create a second
  // command) and cleared on success so the next toggle gets a fresh key.
  // Required when the backend runs with TURNA_REQUIRE_IDEMPOTENCY_KEY=true.
  const drainKey = useRef<string>('')
  const undrainKey = useRef<string>('')
  const newKey = () =>
    (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`

  // node.drain / node.undrain target a node by id; resolve "this" node from the
  // cluster list (is_self, or the sole node), falling back to a node_id the
  // status endpoint may carry. An empty id is rejected server-side, so the
  // actions no-op with an error toast until one is known.
  const selfNode = clusterNodes.find(n => n.is_self)
    ?? (clusterNodes.length === 1 ? clusterNodes[0] : undefined)
  // `status` may carry a node_id the typed `NodeStatus` doesn't declare; read it
  // via one narrow cast to an unknown-valued field, then narrow by typeof (avoids
  // an over-aggressive `status as { node_id: string }` cast TS rejects).
  const statusMaybe = status as { node_id?: unknown } | null | undefined
  const statusNodeId =
    typeof statusMaybe?.node_id === 'string' ? statusMaybe.node_id : undefined
  const selfNodeId = selfNode?.node_id ?? statusNodeId

  const doDrain = useCallback(async () => {
    if (!selfNodeId) { showToast(t('nodes.actionError'), false); return }
    if (!confirm(t('nodes.drainConfirm'))) return
    if (!drainKey.current) drainKey.current = newKey()
    setDraining(true)
    try {
      await api.manage.nodeDrain(selfNodeId, drainKey.current)
      showToast(t('nodes.drainSuccess'), true)
      drainKey.current = '' // intent complete
    } catch { showToast(t('nodes.actionError'), false) } // keep key for retry
    finally { setDraining(false) }
  }, [t, selfNodeId])

  const doUndrain = useCallback(async () => {
    if (!selfNodeId) { showToast(t('nodes.actionError'), false); return }
    if (!confirm(t('nodes.undrainConfirm'))) return
    if (!undrainKey.current) undrainKey.current = newKey()
    setDraining(true)
    try {
      await api.manage.nodeUndrain(selfNodeId, undrainKey.current)
      showToast(t('nodes.undrainSuccess'), true)
      undrainKey.current = '' // intent complete
    } catch { showToast(t('nodes.actionError'), false) } // keep key for retry
    finally { setDraining(false) }
  }, [t, selfNodeId])

  if (!status) return <div className="flex items-center justify-center h-48 text-[--muted]">{t('ov.waiting')}</div>

  const r            = readinessInfo(metric(metrics, 'turna_backend_readiness'))
  const clusterNodeCount = metricOr(metrics, 'turna_cluster_nodes', 0)
  const isCluster        = clusterNodeCount > 1
  const bps          = rateSeries(history, s => s.bytes_sent + s.bytes_received)
  const activ        = statusSeries(history, s => s.active_allocations)
  const authH        = rateSeries(history, s => s.auth_failures)

  return (
    <div className="space-y-5 fade-up">
      {toast && (
        <div className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-50 rounded-xl px-5 py-3 text-sm font-medium ring-1 shadow-xl ${
          toast.ok
            ? 'bg-emerald-500/15 text-emerald-400 ring-emerald-400/30'
            : 'bg-rose-500/15 text-rose-400 ring-rose-400/30'
        }`}>
          {toast.msg}
        </div>
      )}

      {/* node card */}
      <div className="card p-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-teal-400/10">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" strokeWidth="1.5">
                <rect x="2" y="4" width="20" height="8" rx="2"/>
                <rect x="2" y="14" width="20" height="6" rx="2"/>
                <circle cx="6" cy="8" r="1" fill="#2dd4bf"/>
                <circle cx="6" cy="17" r="1" fill="#2dd4bf"/>
              </svg>
            </div>
            <div>
              <div className="text-xl font-bold text-[--ink]">turna-node</div>
              <div className="font-mono text-xs text-[--muted] mt-0.5">
                {isCluster ? `${t('nodes.clusterNodes')}: ${clusterNodeCount}` : t('nodes.standalone')}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Badge kind={status.draining ? 'draining' : status.status === 'ok' ? 'ok' : 'neutral'}
              label={status.draining ? t('status.draining') : t('status.ok')} />
            <Badge kind={r.kind} label={r.label} />
            {isCluster && (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-sky-400/10 px-2.5 py-1 text-xs font-medium font-mono text-sky-400 ring-1 ring-sky-400/25">
                {clusterNodeCount} {t('nodes.clusterNodes').toLowerCase()}
              </span>
            )}

            {/* drain / undrain buttons */}
            {!status.draining ? (
              <button onClick={doDrain} disabled={draining}
                className="flex items-center gap-1.5 rounded-xl border border-orange-400/30 bg-orange-400/8 px-3 py-1.5 text-xs font-semibold text-orange-400 hover:bg-orange-400/15 disabled:opacity-50 transition-all">
                {draining
                  ? <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-orange-400 border-t-transparent"/>
                  : <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="6" cy="6" r="4"/><path d="M6 3v3l2 1" strokeLinecap="round"/></svg>
                }
                {t('nodes.drain')}
              </button>
            ) : (
              <button onClick={doUndrain} disabled={draining}
                className="flex items-center gap-1.5 rounded-xl border border-emerald-400/30 bg-emerald-400/8 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-400/15 disabled:opacity-50 transition-all">
                {draining
                  ? <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-emerald-400 border-t-transparent"/>
                  : <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M2 6a4 4 0 1 0 4-4" strokeLinecap="round"/><path d="M2 2v4h4" strokeLinecap="round" strokeLinejoin="round"/></svg>
                }
                {t('nodes.undrain')}
              </button>
            )}
          </div>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-6 sm:grid-cols-4 border-t border-[--border] pt-5">
          <Kv label={t('nodes.uptime')}       value={formatDuration(status.uptime_secs, lang)} />
          <Kv label={t('nodes.status')}       value={status.status} />
          <Kv label={t('nodes.draining')}     value={status.draining ? '✓' : t('nodes.notDraining')} />
          <Kv label={t('nodes.clusterNodes')} value={String(clusterNodeCount)} />
        </div>
      </div>

      {/* stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { label: t('alloc.active'), value: formatCount(status.active_allocations, lang), color: 'text-teal-400' },
          { label: t('alloc.total'),  value: formatCount(status.total_allocations, lang),  color: 'text-[--ink]' },
          { label: t('tr.bytesIn'),   value: formatBytes(status.bytes_received, lang),     color: 'text-sky-400' },
          { label: t('tr.bytesOut'),  value: formatBytes(status.bytes_sent, lang),         color: 'text-violet-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="card p-4">
            <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div>
            <div className={'font-mono text-2xl font-semibold tabular-nums vf ' + color}>{value}</div>
          </div>
        ))}
      </div>

      {/* charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title={t('ov.throughput')} frozen={frozen}>
            <MiniChart data={bps} color="#2dd4bf" height={160} fmt={v => formatBytes(v, lang) + '/s'} />
          </Card>
        </div>
        <div className="space-y-4">
          <Card title={t('nav.allocations')} frozen={frozen}>
            <MiniChart data={activ} color="#818cf8" height={68} fmt={v => formatCount(v, lang)} />
          </Card>
          <Card title={t('sec.authFailures')} frozen={frozen}>
            <MiniChart data={authH} color="#f87171" height={68} fmt={v => formatCount(v, lang)} />
          </Card>
        </div>
      </div>

      {/* security snapshot */}
      <Card title={t('nav.security')} frozen={frozen}>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
          {[
            { label: t('sec.authFailures'),    v: status.auth_failures,     hot: true },
            { label: t('sec.rateLimited'),     v: status.rate_limited,      hot: true },
            { label: t('sec.parserRejections'),v: status.parser_rejections, hot: false },
            { label: t('sec.malformed'),       v: status.malformed_packets, hot: false },
            { label: t('sec.quotaExceeded'),   v: status.quota_exceeded,    hot: true },
            { label: t('sec.peerRejected'),    v: status.peer_rejected,     hot: false },
          ].map(({ label, v, hot }) => (
            <div key={label}>
              <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-1">{label}</div>
              <div className={'font-mono text-xl font-semibold vf ' + (hot && v > 0 ? 'text-amber-400' : 'text-[--ink]')}>{v.toLocaleString()}</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

function Kv({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-1">{label}</div>
      <div className="font-mono text-sm font-medium text-[--ink]">{value}</div>
    </div>
  )
}
