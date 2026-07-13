import { useEffect, useMemo, useState } from 'react'
import { api, newIdempotencyKey } from '../api/client'
import type { NodeRuntimeConfig, UpdateConfigResult } from '../api/types'
import { useI18n } from '../i18n'
import type { PanelProps } from '../panels/types'

function optionalNumber(enabled: boolean, value: string): number | undefined {
  if (!enabled) return undefined
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed < 0 || !Number.isInteger(parsed)) {
    throw new Error('value must be a non-negative integer')
  }
  return parsed
}

function statusClass(status: string): string {
  if (status === 'applied' || status === 'observed' || status === 'no_op') return 'text-emerald-400'
  if (status === 'conflict') return 'text-amber-400'
  return 'text-rose-400'
}

export function ConfigPage({ clusterNodes = [] }: PanelProps) {
  const { t } = useI18n()
  const suggestedNode = useMemo(
    () => clusterNodes.find(node => node.is_self)?.node_id ?? clusterNodes[0]?.node_id ?? '',
    [clusterNodes],
  )
  const [nodeId, setNodeId] = useState(suggestedNode)
  const [state, setState] = useState<NodeRuntimeConfig | null>(null)
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<UpdateConfigResult | null>(null)
  const [retryKey, setRetryKey] = useState('')
  const [reason, setReason] = useState('operator runtime update')
  const [enabled, setEnabled] = useState({ global: false, perUser: false, bandwidth: false })
  const [values, setValues] = useState({ global: '', perUser: '', bandwidth: '' })

  useEffect(() => {
    if (!nodeId && suggestedNode) setNodeId(suggestedNode)
  }, [nodeId, suggestedNode])

  async function loadConfig() {
    if (!nodeId.trim()) { setError(t('config.nodeRequired')); return }
    setLoading(true); setError('')
    try {
      const next = await api.manage.configGet(nodeId.trim())
      setState(next)
      const observed = next.observed
      if (observed) {
        setValues({
          global: String(observed.max_allocations),
          perUser: String(observed.max_allocations_per_user),
          bandwidth: String(observed.max_bytes_per_sec_per_allocation),
        })
      }
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setLoading(false) }
  }

  async function applyConfig() {
    if (!state) { setError(t('config.loadFirst')); return }
    if (!enabled.global && !enabled.perUser && !enabled.bandwidth) {
      setError(t('config.patchRequired')); return
    }
    setSubmitting(true); setError(''); setResult(null)
    const key = retryKey || newIdempotencyKey('config')
    setRetryKey(key)
    try {
      const next = await api.manage.configUpdate({
        node_id: nodeId.trim(),
        idempotency_key: key,
        expected_version: state.observed_version,
        max_allocations: optionalNumber(enabled.global, values.global),
        max_allocations_per_user: optionalNumber(enabled.perUser, values.perUser),
        max_bytes_per_sec_per_allocation: optionalNumber(enabled.bandwidth, values.bandwidth),
        reason: reason.trim(),
      })
      setResult(next)
      if (next.terminal_status === 'applied' || next.terminal_status === 'no_op') {
        setRetryKey('')
        await loadConfig()
      }
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setSubmitting(false) }
  }

  const observed = state?.observed ?? null
  const pending = state?.pending_desired ?? null

  return (
    <div className="space-y-5 fade-up max-w-4xl">
      <div className="card p-5 space-y-4">
        <div>
          <h2 className="text-lg font-bold text-[--ink]">{t('config.runtimeTitle')}</h2>
          <p className="text-sm text-[--muted] mt-1">{t('config.runtimeDesc')}</p>
        </div>
        <div className="flex gap-3">
          <input className="flex-1 rounded-lg border border-[--border] bg-[--raised] px-3 py-2 font-mono text-sm text-[--ink]"
            value={nodeId} onChange={e => setNodeId(e.target.value)} placeholder={t('config.nodeId')} />
          <button className="rounded-lg border border-[--border] bg-[--raised] px-4 py-2 text-sm text-[--ink] disabled:opacity-50"
            disabled={loading} onClick={() => void loadConfig()}>{loading ? t('common.loading') : t('config.load')}</button>
        </div>
      </div>

      {state && (
        <div className="card overflow-hidden">
          <div className="border-b border-[--border] px-5 py-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-[--ink]">{state.node_id}</h3>
              <p className="text-xs text-[--muted] mt-1">{t('config.desiredVersion')}: {state.desired_version} · {t('config.observedVersion')}: {state.observed_version}</p>
            </div>
            <span className={'font-mono text-xs font-semibold ' + statusClass(state.status)}>{state.status}</span>
          </div>
          <div className="grid gap-4 p-5 md:grid-cols-2">
            <Snapshot title={t('config.observed')} value={observed} />
            <Snapshot title={t('config.pending')} value={pending} />
          </div>
          {state.last_apply_error && <div className="border-t border-[--border] px-5 py-3 text-sm text-rose-400">{state.last_apply_error}</div>}
        </div>
      )}

      {state && (
        <div className="card p-5 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-[--ink]">{t('config.updateTitle')}</h3>
            <p className="text-xs text-[--muted] mt-1">{t('config.updateDesc')}</p>
          </div>
          <PatchRow label="max_allocations" checked={enabled.global} value={values.global}
            onChecked={value => setEnabled(v => ({ ...v, global: value }))}
            onValue={value => setValues(v => ({ ...v, global: value }))} />
          <PatchRow label="max_allocations_per_user" checked={enabled.perUser} value={values.perUser}
            onChecked={value => setEnabled(v => ({ ...v, perUser: value }))}
            onValue={value => setValues(v => ({ ...v, perUser: value }))} />
          <PatchRow label="max_bytes_per_sec_per_allocation" checked={enabled.bandwidth} value={values.bandwidth}
            onChecked={value => setEnabled(v => ({ ...v, bandwidth: value }))}
            onValue={value => setValues(v => ({ ...v, bandwidth: value }))} />
          <label className="block">
            <span className="text-xs text-[--muted]">{t('common.reason')}</span>
            <input className="mt-1 w-full rounded-lg border border-[--border] bg-[--raised] px-3 py-2 text-sm text-[--ink]"
              value={reason} onChange={e => setReason(e.target.value)} />
          </label>
          {retryKey && <p className="font-mono text-[11px] text-[--muted]">{t('common.retryKey')}: {retryKey}</p>}
          <button className="rounded-lg bg-teal-500 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-50"
            disabled={submitting} onClick={() => void applyConfig()}>{submitting ? t('common.applying') : t('config.apply')}</button>
        </div>
      )}

      {result && (
        <div className="card p-5">
          <div className={'text-sm font-semibold ' + statusClass(result.terminal_status)}>{result.terminal_status}</div>
          <div className="mt-2 font-mono text-xs text-[--muted]">request_id={result.request_id} · {result.previous_version} → {result.observed_version} · changed={String(result.changed)} · rolled_back={String(result.rolled_back)}</div>
          {result.error && <p className="mt-3 text-sm text-rose-400">{result.error}</p>}
        </div>
      )}
      {error && <div className="card border border-rose-400/30 p-4 text-sm text-rose-400">{error}</div>}
    </div>
  )
}

function PatchRow({ label, checked, value, onChecked, onValue }: {
  label: string; checked: boolean; value: string
  onChecked: (value: boolean) => void; onValue: (value: string) => void
}) {
  return (
    <label className="grid grid-cols-[auto_1fr_180px] items-center gap-3 rounded-lg border border-[--border] p-3">
      <input type="checkbox" checked={checked} onChange={e => onChecked(e.target.checked)} />
      <span className="font-mono text-sm text-[--ink]">{label}</span>
      <input type="number" min="0" step="1" disabled={!checked} value={value} onChange={e => onValue(e.target.value)}
        className="rounded-lg border border-[--border] bg-[--raised] px-3 py-2 font-mono text-sm text-[--ink] disabled:opacity-40" />
    </label>
  )
}

function Snapshot({ title, value }: { title: string; value: NodeRuntimeConfig['observed'] }) {
  return (
    <div className="rounded-xl border border-[--border] p-4">
      <h4 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">{title}</h4>
      {value ? (
        <dl className="mt-3 space-y-2 font-mono text-xs">
          <Row k="version" v={value.version} /><Row k="max_allocations" v={value.max_allocations} />
          <Row k="max_allocations_per_user" v={value.max_allocations_per_user} />
          <Row k="max_bytes_per_sec_per_allocation" v={value.max_bytes_per_sec_per_allocation} />
        </dl>
      ) : <p className="mt-3 text-xs text-[--faint]">—</p>}
    </div>
  )
}

function Row({ k, v }: { k: string; v: number }) {
  return <div className="flex justify-between gap-4"><dt className="text-[--muted]">{k}</dt><dd className="text-[--ink]">{v}</dd></div>
}
