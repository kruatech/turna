import { Card } from '../ui/Card'
import { IconBox } from '../ui/IconBox'
import { MiniChart } from '../ui/MiniChart'
import { ProgressBar } from '../ui/ProgressBar'
import { useI18n } from '../i18n'
import { formatBytes, formatBytesRate, formatCount } from '../format/format'
import { rateSeries, statusSeries, lastRate, metricOr } from '../lib/series'
import type { PanelProps } from '../panels/types'
import type { ReactNode } from 'react'

export function OverviewPage({ status, metrics, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  if (!status) return <div className="flex items-center justify-center h-48 text-[--muted]">{t('ov.waiting')}</div>

  const rps         = rateSeries(history, s => s.packets_sent + s.packets_received)
  const bps         = rateSeries(history, s => s.bytes_sent + s.bytes_received)
  const activ       = statusSeries(history, s => s.active_allocations)
  const errS        = rateSeries(history, s => s.auth_failures + s.parser_rejections + s.malformed_packets)
  const clusterNodes = metricOr(metrics, 'turna_cluster_nodes', 0)

  return (
    <div className="space-y-5 fade-up">
      {/* KPI row */}
      <div className={`grid grid-cols-2 gap-4 ${clusterNodes > 1 ? 'sm:grid-cols-5' : 'sm:grid-cols-4'}`}>
        <KpiCard color="teal"   icon={<AllocIcon />}  value={String(status.active_allocations)}        label={t('ov.activeAlloc')} chart={activ} cc="#2dd4bf" />
        <KpiCard color="sky"    icon={<BandIcon />}   value={formatBytesRate(lastRate(bps), lang)}      label={t('ov.bandwidth')}   chart={bps}   cc="#38bdf8" />
        <KpiCard color="violet" icon={<PktIcon />}    value={formatCount(lastRate(rps), lang) + ' pps'} label={t('ov.pps')}        chart={rps}   cc="#818cf8" />
        <KpiCard color="rose"   icon={<ErrIcon />}    value={formatCount(lastRate(errS), lang) + '/s'}  label={t('ov.errors')}     chart={errS}  cc="#f87171" />
        {clusterNodes > 1 && (
          <KpiCard color="emerald" icon={<ClusterIcon />} value={String(clusterNodes)} label={t('nodes.clusterNodes')} chart={[]} cc="#34d399" />
        )}
      </div>

      {/* bandwidth chart + allocations */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title={t('ov.throughput')} frozen={frozen}
            right={
              <div className="flex gap-3 text-xs text-[--muted]">
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-teal-400"/>{t('ov.incoming')}</span>
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-violet-400"/>{t('ov.outgoing')}</span>
              </div>
            }>
            <p className="mb-3 text-xs text-[--muted]">{history.length} {t('ov.intervals')}</p>
            <MiniChart data={bps} color="#2dd4bf" height={160} fmt={v => formatBytesRate(v, lang)} />
          </Card>
        </div>
        <Card title={t('nav.allocations')} frozen={frozen}>
          <div className="flex flex-col gap-5">
            <BigStat value={String(status.active_allocations)} label={t('ov.activeNow')} color="text-teal-400" />
            <BigStat value={String(status.total_allocations)}  label={t('ov.lifetime')}  color="text-[--ink]" />
            <div>
              <div className="mb-2 text-[11px] text-[--muted]">{t('ov.activeTime')}</div>
              <MiniChart data={activ} color="#2dd4bf" height={80} fmt={v => formatCount(v, lang)} />
            </div>
          </div>
        </Card>
      </div>

      {/* bottom row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Card title={t('ov.transport')} frozen={frozen}>
          {status.packets_sent > 0 ? (
            <div className="space-y-3">
              <Row label={t('tr.pktsIn')}  value={formatCount(status.packets_received, lang)} />
              <Row label={t('tr.pktsOut')} value={formatCount(status.packets_sent, lang)} />
              <div className="border-t border-[--border] pt-3 space-y-2">
                <Row label={t('tr.bytesIn')}  value={formatBytes(status.bytes_received, lang)} />
                <Row label={t('tr.bytesOut')} value={formatBytes(status.bytes_sent, lang)} />
              </div>
            </div>
          ) : (
            <p className="text-sm text-[--muted]">{t('ov.noTransport')}</p>
          )}
        </Card>

        <Card title={t('ov.security')} frozen={frozen}>
          <div className="space-y-2.5">
            <SecRow label={t('sec.authFailures')}    value={status.auth_failures}     hot />
            <SecRow label={t('sec.rateLimited')}     value={status.rate_limited}      hot />
            <SecRow label={t('sec.malformed')}       value={status.malformed_packets} />
            <SecRow label={t('sec.parserRejections')}value={status.parser_rejections} />
            <SecRow label={t('sec.peerRejected')}    value={status.peer_rejected} />
          </div>
        </Card>

        <Card title={t('ov.dataplane')} frozen={frozen}>
          <div className="space-y-4">
            <BigStat value={formatCount(status.zero_copy_forwards, lang)} label={t('traffic.zeroCopy')} color="text-sky-400" />
            <div>
              <div className="mb-1.5 flex justify-between text-[11px] text-[--muted]">
                <span>{t('ov.sendQueue')}</span>
                <span className={status.send_queue_dropped > 0 ? 'text-amber-400' : 'text-emerald-400'}>
                  {status.send_queue_dropped > 0 ? `${status.send_queue_dropped} ${t('ov.dropped')}` : t('ov.queueOk')}
                </span>
              </div>
              <ProgressBar value={status.send_queue_dropped} max={Math.max(status.send_queue_dropped, 100)}
                color={status.send_queue_dropped > 0 ? '#fbbf24' : '#34d399'} />
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}

function KpiCard({ color, icon, value, label, chart, cc }:
  { color: string; icon: ReactNode; value: string; label: string; chart: any[]; cc: string }) {
  return (
    <div className="card overflow-hidden">
      <div className="flex items-start justify-between px-5 pt-5 pb-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{label}</div>
          <div className="font-mono text-2xl font-semibold tabular-nums text-[--ink] vf">{value}</div>
        </div>
        <IconBox color={color} size={10}>{icon}</IconBox>
      </div>
      {chart.length > 0 && <MiniChart data={chart} color={cc} height={56} />}
    </div>
  )
}

function BigStat({ value, label, color }: { value: string; label: string; color: string }) {
  return <div><div className={'font-mono text-3xl font-semibold tabular-nums vf ' + color}>{value}</div><div className="text-xs text-[--muted] mt-0.5">{label}</div></div>
}
function Row({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between py-1"><span className="text-sm text-[--muted]">{label}</span><span className="font-mono text-sm font-medium text-[--ink]">{value}</span></div>
}
function SecRow({ label, value, hot }: { label: string; value: number; hot?: boolean }) {
  return <div className="flex items-center justify-between"><span className="text-sm text-[--muted]">{label}</span><span className={'font-mono text-sm font-semibold ' + (hot && value > 0 ? 'text-amber-400' : 'text-[--ink]')}>{value.toLocaleString()}</span></div>
}
function AllocIcon()   { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="4" width="16" height="12" rx="2"/><path d="M7 10h6M10 7v6" strokeLinecap="round"/></svg> }
function BandIcon()    { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 15L7 9l3 3 3-6 4 2" strokeLinecap="round" strokeLinejoin="round"/></svg> }
function PktIcon()     { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="10" r="7"/><path d="M10 7v3l2 2" strokeLinecap="round"/></svg> }
function ErrIcon()     { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10 3L18 17H2L10 3z" strokeLinejoin="round"/><path d="M10 9v3M10 14h.01" strokeLinecap="round"/></svg> }
function ClusterIcon() { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="10" r="3"/><circle cx="3" cy="4" r="2"/><circle cx="17" cy="4" r="2"/><circle cx="3" cy="16" r="2"/><circle cx="17" cy="16" r="2"/><path d="M5 5l3.5 3.5M11.5 11.5L15 15M15 5l-3.5 3.5M8.5 11.5L5 15" strokeLinecap="round"/></svg> }
