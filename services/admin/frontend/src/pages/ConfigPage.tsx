import { useState } from 'react'
import { useI18n } from '../i18n'
import { metricOr, metric } from '../lib/series'
import type { PanelProps } from '../panels/types'

const BRIDGE_CONFIG = [
  { param: '--listen',           env: 'TURNA_ADMIN_LISTEN',           value: '127.0.0.1:8080', desc: 'Адрес, на котором слушает turna-admin' },
  { param: '--turna-addr',       env: 'TURNA_ADMIN_TURNA_ADDR',       value: 'http://127.0.0.1:9090', desc: 'Management-адрес ноды (:9090 health)' },
  { param: '--static-dir',       env: 'TURNA_ADMIN_STATIC_DIR',       value: './dist', desc: 'Папка со статикой фронтенда' },
  { param: '--upstream-timeout', env: 'TURNA_ADMIN_UPSTREAM_TIMEOUT', value: '3s', desc: 'Таймаут запроса к ноде' },
]
const STAGE2_CONFIG = [
  { param: '--grpc-addr',  env: '—', value: ':5350',  desc: 'gRPC control-plane (этап 2)' },
  { param: '--tls-ca',     env: '—', value: '—',       desc: 'mTLS CA (этап 2)' },
  { param: '--auth-token', env: '—', value: '—',       desc: 'Аутентификация UI (этап 2)' },
]

export function ConfigPage({ status, metrics }: PanelProps) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)

  const rawStatus = status ? JSON.stringify(status, null, 2) : null

  // node runtime info from metrics
  const clusterNodes = metricOr(metrics, 'turna_cluster_nodes', 0)
  const readiness    = metric(metrics, 'turna_backend_readiness')
  const readinessLabel = ['Starting', 'Ready', 'Degraded', 'Draining'][readiness ?? 0] ?? '—'

  // node config info visible from /status
  const nodeInfo = status ? [
    { key: 'status',         value: status.status },
    { key: 'draining',       value: String(status.draining) },
    { key: 'uptime_secs',    value: String(status.uptime_secs) },
    { key: 'readiness',      value: readinessLabel },
    { key: 'cluster_nodes',  value: String(clusterNodes) },
    { key: 'max_allocations',value: '—' }, // не приходит в /status
    { key: 'realm',          value: '—' }, // не приходит в /status (из turn.toml)
  ] : []

  async function copyStatus() {
    if (!rawStatus) return
    try { await navigator.clipboard.writeText(rawStatus) }
    catch {
      const ta = document.createElement('textarea')
      ta.value = rawStatus; ta.style.position = 'fixed'; ta.style.opacity = '0'
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove()
    }
    setCopied(true); setTimeout(() => setCopied(false), 1800)
  }

  return (
    <div className="space-y-5 fade-up">
      {/* node runtime state */}
      {status && (
        <div className="card overflow-hidden">
          <div className="border-b border-[--border] px-5 py-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">Runtime state (из /status + /metrics)</h2>
          </div>
          <div className="divide-y divide-[--border]">
            <div className="grid grid-cols-2 font-mono text-[10px] uppercase tracking-widest text-[--faint] px-5 py-2">
              <span>Ключ</span><span>Значение</span>
            </div>
            {nodeInfo.map(({ key, value }) => (
              <div key={key} className="grid grid-cols-2 px-5 py-2.5 hover:bg-[--raised] transition-colors">
                <span className="font-mono text-sm text-[--muted]">{key}</span>
                <span className="font-mono text-sm font-semibold text-[--ink]">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* bridge config */}
      <div className="card overflow-hidden">
        <div className="border-b border-[--border] px-5 py-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">{t('config.title')}</h2>
          <p className="text-xs text-[--muted] mt-1">{t('config.desc')}</p>
        </div>
        <div className="divide-y divide-[--border]">
          <div className="grid grid-cols-3 font-mono text-[10px] uppercase tracking-widest text-[--faint] px-5 py-2.5">
            <span>{t('config.param')}</span><span>{t('config.env')}</span><span>{t('config.current')}</span>
          </div>
          {BRIDGE_CONFIG.map(row => (
            <div key={row.param} className="grid grid-cols-3 items-start px-5 py-3 hover:bg-[--raised] transition-colors">
              <div>
                <div className="font-mono text-sm font-medium text-teal-400">{row.param}</div>
                <div className="text-[11px] text-[--faint] mt-0.5">{row.desc}</div>
              </div>
              <div className="font-mono text-xs text-[--muted] pt-0.5">{row.env}</div>
              <div className="font-mono text-sm font-semibold text-[--ink]">{row.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* stage 2 reserved */}
      <div className="card overflow-hidden opacity-60">
        <div className="border-b border-[--border] px-5 py-3 flex items-center gap-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">{t('config.stage2')}</h2>
          <span className="rounded-full bg-[--raised] px-2 py-0.5 font-mono text-[10px] text-[--faint] ring-1 ring-[--border]">501</span>
        </div>
        <p className="px-5 py-3 text-xs text-[--muted]">{t('config.stage2Desc')}</p>
        <div className="divide-y divide-[--border]">
          {STAGE2_CONFIG.map(row => (
            <div key={row.param} className="grid grid-cols-3 items-start px-5 py-2.5">
              <span className="font-mono text-sm text-[--faint]">{row.param}</span>
              <span className="font-mono text-xs text-[--faint]">{row.env}</span>
              <span className="font-mono text-xs text-[--faint]">{row.desc}</span>
            </div>
          ))}
        </div>
      </div>

      {/* raw /status */}
      {rawStatus && (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between border-b border-[--border] px-5 py-3">
            <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">{t('config.rawStatus')}</h2>
            <button onClick={copyStatus}
              className="flex items-center gap-1.5 rounded-lg border border-[--border] bg-[--raised] px-3 py-1.5 text-xs text-[--muted] hover:text-[--ink] transition-colors">
              {copied ? <><span className="text-emerald-400">✓</span> {t('config.copied')}</> : t('config.copy')}
            </button>
          </div>
          <pre className="overflow-x-auto p-5 font-mono text-xs text-[--muted] leading-relaxed max-h-80 overflow-y-auto">{rawStatus}</pre>
        </div>
      )}
    </div>
  )
}
