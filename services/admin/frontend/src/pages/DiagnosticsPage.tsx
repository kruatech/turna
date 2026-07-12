import { Card } from '../ui/Card'
import { useI18n } from '../i18n'
import { formatCount, formatBytes } from '../format/format'
import { metricOr, anyNonZeroMatching, keysWithPrefix, metric } from '../lib/series'
import type { PanelProps } from '../panels/types'

function readinessLabel(v: number): string {
  return ['Starting', 'Ready', 'Degraded', 'Draining'][v] ?? '?'
}
function readinessColor(v: number): string {
  return v === 1 ? 'text-emerald-400' : v === 2 ? 'text-amber-400' : v === 3 ? 'text-orange-400' : 'text-[--muted]'
}

export function DiagnosticsPage({ status, metrics, frozen }: PanelProps) {
  const { t, lang } = useI18n()

  // transport readiness (confirmed in health/src/lib.rs)
  const backendReady   = metricOr(metrics, 'turna_backend_readiness', 0)
  const transportReady = metricOr(metrics, 'turna_transport_readiness', 0)
  const dtlsReady      = metricOr(metrics, 'turna_dtls_readiness', 0)

  // gRPC metrics (from /metrics)
  const grpcStreams = metricOr(metrics, 'grpc_active_streams', 0)
  const grpcDrainMs = metricOr(metrics, 'grpc_shutdown_drain_ms', 0)
  const grpcKills   = metricOr(metrics, 'grpc_forced_kills_total', 0)
  const hasGrpc     = grpcStreams > 0 || grpcDrainMs > 0 || grpcKills > 0

  // Tarantool pool slots{state="idle/busy/broken"} — labeled metric
  const poolSlots = metrics?.labeled['tarantool_pool_slots'] ?? []
  const poolIdle   = poolSlots.find(s => s.labels.state === 'idle')?.value ?? 0
  const poolBusy   = poolSlots.find(s => s.labels.state === 'busy')?.value ?? 0
  const poolBroken = poolSlots.find(s => s.labels.state === 'broken')?.value ?? 0
  const hasPool    = poolSlots.length > 0

  // QUIC/DTLS
  const quicBytesRx = metricOr(metrics, 'turna_quic_bytes_rx_total', 0)  // note: may not exist
  const quicActive  = metricOr(metrics, 'turna_quic_active_sessions', 0)
  const dtlsActive  = metricOr(metrics, 'turna_dtls_active_sessions', 0)
  const dtlsBytesRx = metricOr(metrics, 'turna_dtls_bytes_rx_total', 0)
  const dtlsBytesTx = metricOr(metrics, 'turna_dtls_bytes_tx_total', 0)
  const hasQD       = quicActive > 0 || dtlsActive > 0 || dtlsBytesRx > 0

  // relay-route (io_uring)
  const rrLocal  = metricOr(metrics, 'turna_relay_route_send_local_total', 0)
  const rrFwd    = metricOr(metrics, 'turna_relay_route_send_forwarded_total', 0)
  const rrFail   = metricOr(metrics, 'turna_relay_route_send_forward_failed_total', 0)
  const rrRatio  = metric(metrics, 'turna_relay_route_forwarded_ratio')
  const hasRR    = rrLocal > 0 || rrFwd > 0

  // per-tenant traffic: labeled families
  const tenantBytes   = metrics?.labeled['turna_tenant_bytes_relayed_total']   ?? []
  const tenantPkts    = metrics?.labeled['turna_tenant_packets_relayed_total']  ?? []
  const tenantClosed  = metrics?.labeled['turna_tenant_allocations_closed_total'] ?? []
  const hasTenantTraffic = tenantBytes.length > 0

  // latency histograms — any *_bucket or *_count metrics
  const histKeys = keysWithPrefix(metrics, '').filter(k => k.endsWith('_bucket') || k.endsWith('_count') || k.endsWith('_sum'))
  const hasHist  = histKeys.length > 0

  const panics = metricOr(metrics, 'turna_processor_panics_total', 0)

  return (
    <div className="space-y-5 fade-up">
      {/* transport readiness — all 3 backends */}
      <Card title={t('diag.transportReady')} frozen={frozen}>
        <div className="grid grid-cols-3 gap-6">
          {[
            { label: t('diag.backend'),   v: backendReady },
            { label: t('diag.transport'), v: transportReady },
            { label: t('diag.dtls'),      v: dtlsReady },
          ].map(({ label, v }) => (
            <div key={label}>
              <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-1">{label}</div>
              <div className={'font-mono text-xl font-semibold ' + readinessColor(v)}>{readinessLabel(v)}</div>
              <div className="font-mono text-xs text-[--faint]">{v}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* /status snapshot */}
      {status && (
        <Card title={t('di.statusSnapshot')} frozen={frozen}>
          <div className="grid grid-cols-2 gap-x-8 gap-y-0 font-mono text-sm sm:grid-cols-3">
            {[
              ['status',               status.status],
              ['draining',             String(status.draining)],
              ['send_queue_dropped',   formatCount(status.send_queue_dropped, lang)],
              ['quota_exceeded',       formatCount(status.quota_exceeded, lang)],
              ['parser_rejections',    formatCount(status.parser_rejections, lang)],
              ['malformed_packets',    formatCount(status.malformed_packets, lang)],
              ['bytes_received',       formatBytes(status.bytes_received, lang)],
              ['bytes_sent',           formatBytes(status.bytes_sent, lang)],
              ['rtp_streams',          String(status.rtp_streams)],
              ['rtp_avg_jitter_ms',    (status.rtp_avg_jitter_ms ?? 0).toFixed(2) + ' ms'],
              ['rtp_max_jitter_ms',    (status.rtp_max_jitter_ms ?? 0).toFixed(2) + ' ms'],
              ['rtp_max_loss_percent', (status.rtp_max_loss_percent ?? 0).toFixed(2) + '%'],
              ['rtp_total_bitrate',    (status.rtp_total_bitrate_kbps ?? 0) + ' kbps'],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between border-b border-[--border] py-2">
                <span className="text-[--muted]">{k}</span>
                <span className="font-semibold text-[--ink]">{v}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* processor + cluster */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Card title={t('di.processor')} frozen={frozen}>
          <div className="grid grid-cols-2 gap-6">
            <KV label={t('sec.processorPanics')} value={formatCount(panics, lang)} crit={panics > 0} />
            <KV label={t('cluster.redirects')}   value={formatCount(metricOr(metrics,'turna_cluster_redirects_total',0), lang)} />
            <KV label={t('cluster.failoverClaimed')} value={formatCount(metricOr(metrics,'failover_claimed_total',0), lang)} />
            <KV label={t('cluster.failoverErrors')}  value={formatCount(metricOr(metrics,'failover_errors_total',0), lang)} warn={metricOr(metrics,'failover_errors_total',0)>0} />
          </div>
        </Card>

        {/* gRPC stats */}
        {hasGrpc && (
          <Card title={t('diag.grpc')} frozen={frozen}>
            <div className="grid grid-cols-3 gap-4">
              <KV label={t('diag.grpcStreams')}  value={formatCount(grpcStreams, lang)} />
              <KV label={t('diag.grpcDrainMs')} value={grpcDrainMs + ' ms'} />
              <KV label={t('diag.grpcKills')}   value={formatCount(grpcKills, lang)} warn={grpcKills > 0} />
            </div>
          </Card>
        )}
      </div>

      {/* Tarantool pool slots */}
      {hasPool && (
        <Card title={t('diag.tarantoolPool')} frozen={frozen}>
          <div className="grid grid-cols-3 gap-6">
            <KV label={t('diag.poolIdle')}   value={formatCount(poolIdle, lang)}   />
            <KV label={t('diag.poolBusy')}   value={formatCount(poolBusy, lang)}   />
            <KV label={t('diag.poolBroken')} value={formatCount(poolBroken, lang)} warn={poolBroken > 0} />
          </div>
        </Card>
      )}

      {/* QUIC / DTLS */}
      {hasQD && (
        <Card title="QUIC / DTLS" frozen={frozen}>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {quicActive > 0 && <KV label="QUIC active" value={formatCount(quicActive, lang)} />}
            {metricOr(metrics,'turna_quic_sessions_total',0) > 0 && <KV label="QUIC sessions" value={formatCount(metricOr(metrics,'turna_quic_sessions_total',0), lang)} />}
            {dtlsActive > 0 && <KV label="DTLS active" value={formatCount(dtlsActive, lang)} />}
            {dtlsBytesRx > 0 && <KV label="DTLS rx" value={formatBytes(dtlsBytesRx, lang)} />}
            {dtlsBytesTx > 0 && <KV label="DTLS tx" value={formatBytes(dtlsBytesTx, lang)} />}
            {metricOr(metrics,'turna_dtls_outbound_dropped_total',0) > 0 && (
              <KV label="DTLS dropped" value={formatCount(metricOr(metrics,'turna_dtls_outbound_dropped_total',0), lang)} warn />
            )}
          </div>
        </Card>
      )}

      {/* relay route */}
      {hasRR && (
        <Card title={t('diag.relayRoute')} frozen={frozen}>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KV label="send_local"   value={formatCount(rrLocal, lang)} />
            <KV label="forwarded"    value={formatCount(rrFwd, lang)} />
            <KV label="fwd_failed"   value={formatCount(rrFail, lang)} warn={rrFail > 0} />
            {rrRatio !== undefined && <KV label="ratio" value={(rrRatio * 100).toFixed(2) + '%'} />}
          </div>
        </Card>
      )}

      {/* per-tenant traffic (bytes/packets/closed) */}
      {hasTenantTraffic && (
        <Card title={t('diag.tenantTraffic')} frozen={frozen}>
          <div className="divide-y divide-[--border]">
            <div className="grid grid-cols-4 font-mono text-[10px] uppercase tracking-widest text-[--faint] py-2">
              <span>Tenant</span>
              <span className="text-right">{t('diag.bytes')}</span>
              <span className="text-right">{t('diag.packets')}</span>
              <span className="text-right">{t('diag.closed')}</span>
            </div>
            {tenantBytes.map((s, i) => {
              const tenant = Object.values(s.labels)[0] ?? '?'
              const pkts   = tenantPkts.find(p => Object.values(p.labels)[0] === tenant)?.value ?? 0
              const closed = tenantClosed.find(c => Object.values(c.labels)[0] === tenant)?.value ?? 0
              return (
                <div key={i} className="grid grid-cols-4 font-mono text-xs py-2 hover:bg-[--raised] transition-colors">
                  <span className="text-teal-400 font-semibold">{tenant}</span>
                  <span className="text-right text-[--ink]">{formatBytes(s.value, lang)}</span>
                  <span className="text-right text-[--ink]">{formatCount(pkts, lang)}</span>
                  <span className="text-right text-[--ink]">{formatCount(closed, lang)}</span>
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {/* latency histograms (show bucket keys count only — raw data in Metrics tab) */}
      {hasHist && (
        <Card title={t('diag.histograms')} frozen={frozen}>
          <p className="text-sm text-[--muted] mb-3">
            {histKeys.length} histogram метрик. Полные данные — в разделе Метрики.
          </p>
          <div className="flex flex-wrap gap-2">
            {[...new Set(histKeys.map(k => k.replace(/_bucket$|_count$|_sum$/, '')))].map(name => (
              <span key={name} className="rounded-lg bg-[--raised] px-2.5 py-1 font-mono text-xs text-[--muted] ring-1 ring-[--border]">{name}</span>
            ))}
          </div>
        </Card>
      )}

      {/* experimental transports */}
      {anyNonZeroMatching(metrics, ['uring', 'afxdp', 'af_xdp']) && (
        <Card title={t('di.transports')} frozen={frozen}>
          <div className="font-mono text-sm divide-y divide-[--border]">
            {keysWithPrefix(metrics, '').filter(k => ['uring','afxdp','af_xdp'].some(f => k.includes(f))).sort().map(k => (
              <div key={k} className="flex justify-between py-2">
                <span className="text-[--muted]">{k}</span>
                <span className="text-[--ink]">{formatCount(metric(metrics, k) ?? 0, lang)}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

function KV({ label, value, crit, warn }: { label: string; value: string; crit?: boolean; warn?: boolean }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-1">{label}</div>
      <div className={'font-mono text-lg font-semibold vf ' + (crit ? 'text-rose-400' : warn ? 'text-amber-400' : 'text-[--ink]')}>{value}</div>
    </div>
  )
}
