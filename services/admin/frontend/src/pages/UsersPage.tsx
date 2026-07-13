import { useEffect, useMemo, useState } from 'react'
import { api, newIdempotencyKey } from '../api/client'
import type { LimitInput, LimitMode, SetUserLimitsResult } from '../api/types'
import { useI18n } from '../i18n'
import type { PanelProps } from '../panels/types'

type LimitFieldState = { enabled: boolean; mode: LimitMode; value: string }

const emptyLimit = (): LimitFieldState => ({ enabled: false, mode: 'inherit', value: '' })

function toLimit(field: LimitFieldState): LimitInput | undefined {
  if (!field.enabled) return undefined
  if (field.mode !== 'value') return { mode: field.mode }
  const value = Number(field.value)
  if (!Number.isInteger(value) || value <= 0) throw new Error('VALUE requires a positive integer')
  return { mode: 'value', value }
}

function statusClass(status: string): string {
  if (status === 'applied' || status === 'no_op') return 'text-emerald-400'
  if (status === 'conflict') return 'text-amber-400'
  return 'text-rose-400'
}

export function UsersPage({ clusterNodes = [] }: PanelProps) {
  const { t } = useI18n()
  const suggestedNode = useMemo(
    () => clusterNodes.find(node => node.is_self)?.node_id ?? clusterNodes[0]?.node_id ?? '',
    [clusterNodes],
  )
  const [nodeId, setNodeId] = useState(suggestedNode)
  useEffect(() => { if (!nodeId && suggestedNode) setNodeId(suggestedNode) }, [nodeId, suggestedNode])

  return (
    <div className="space-y-5 fade-up max-w-4xl">
      <div>
        <h2 className="text-xl font-bold text-[--ink]">{t('nav.users')}</h2>
        <p className="mt-1 text-sm text-[--muted]">{t('users.desc')}</p>
      </div>
      <UserCreate />
      <UserRemove />
      <LimitsForm nodeId={nodeId} setNodeId={setNodeId} />
    </div>
  )
}

function UserCreate() {
  const { t } = useI18n()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [organization, setOrganization] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit() {
    setBusy(true); setMessage('')
    try {
      await api.manage.userAdd(username.trim(), password, organization.trim())
      setMessage(t('users.added')); setPassword('')
    } catch (e) { setMessage(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }
  return (
    <section className="card p-5 space-y-3">
      <h3 className="text-sm font-semibold text-[--ink]">{t('users.op.add')}</h3>
      <div className="grid gap-3 md:grid-cols-3">
        <Input label={t('users.username')} value={username} onChange={setUsername} />
        <Input label={t('users.password')} value={password} onChange={setPassword} type="password" />
        <Input label={t('users.organization')} value={organization} onChange={setOrganization} />
      </div>
      <button disabled={busy || !username.trim() || !password} onClick={() => void submit()}
        className="rounded-lg bg-teal-500 px-4 py-2 text-sm font-semibold text-slate-950 disabled:opacity-40">{busy ? t('common.applying') : t('users.add')}</button>
      {message && <p className="text-sm text-[--muted]">{message}</p>}
    </section>
  )
}

function UserRemove() {
  const { t } = useI18n()
  const [username, setUsername] = useState('')
  const [force, setForce] = useState(false)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit() {
    if (!confirm(t('users.removeConfirm'))) return
    setBusy(true); setMessage('')
    try {
      const result = await api.manage.userRemove(username.trim(), force)
      setMessage(`${t('users.removed')}: ${result.allocations_deleted}`)
    } catch (e) { setMessage(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }
  return (
    <section className="card p-5 space-y-3">
      <h3 className="text-sm font-semibold text-[--ink]">{t('users.op.remove')}</h3>
      <div className="grid gap-3 md:grid-cols-2">
        <Input label={t('users.username')} value={username} onChange={setUsername} />
        <label className="flex items-end gap-2 pb-2 text-sm text-[--muted]"><input type="checkbox" checked={force} onChange={e => setForce(e.target.checked)} />{t('users.force')}</label>
      </div>
      <button disabled={busy || !username.trim()} onClick={() => void submit()}
        className="rounded-lg bg-rose-500 px-4 py-2 text-sm font-semibold text-white disabled:opacity-40">{busy ? t('common.applying') : t('users.remove')}</button>
      {message && <p className="text-sm text-[--muted]">{message}</p>}
    </section>
  )
}

function LimitsForm({ nodeId, setNodeId }: { nodeId: string; setNodeId: (value: string) => void }) {
  const { t } = useI18n()
  const [scope, setScope] = useState<'global' | 'tenant' | 'user'>('user')
  const [realm, setRealm] = useState('turna')
  const [tenant, setTenant] = useState('')
  const [username, setUsername] = useState('')
  const [expectedVersion, setExpectedVersion] = useState('0')
  const [reason, setReason] = useState('operator user-limit update')
  const [allocations, setAllocations] = useState<LimitFieldState>(emptyLimit)
  const [bandwidth, setBandwidth] = useState<LimitFieldState>(emptyLimit)
  const [lifetime, setLifetime] = useState<LimitFieldState>(emptyLimit)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<SetUserLimitsResult | null>(null)
  const [resultScope, setResultScope] = useState<'global' | 'tenant' | 'user'>('user')
  const [retryKey, setRetryKey] = useState('')

  async function submit() {
    if (!nodeId.trim()) { setError(t('config.nodeRequired')); return }
    if (scope !== 'global' && !realm.trim()) { setError(t('users.realmRequired')); return }
    if (scope === 'tenant' && !tenant.trim()) { setError(t('users.tenantRequired')); return }
    if (scope === 'user' && !username.trim()) { setError(t('users.usernameRequired')); return }
    if (!allocations.enabled && !bandwidth.enabled && !lifetime.enabled) { setError(t('users.patchRequired')); return }
    const expected = Number(expectedVersion)
    if (!Number.isInteger(expected) || expected < 0) { setError(t('users.versionInvalid')); return }

    const key = retryKey || newIdempotencyKey('limits')
    setRetryKey(key); setBusy(true); setError(''); setResult(null)
    try {
      const next = await api.manage.userSetLimits({
        node_id: nodeId.trim(), scope,
        realm: scope === 'global' ? '' : realm.trim(),
        tenant: scope === 'global' ? '' : tenant.trim(),
        username: scope === 'user' ? username.trim() : '',
        idempotency_key: key, expected_version: expected,
        max_allocations: toLimit(allocations),
        max_bytes_per_sec_per_allocation: toLimit(bandwidth),
        max_lifetime_secs: toLimit(lifetime),
        reason: reason.trim(),
      })
      setResultScope(scope)
      setResult(next)
      if (next.terminal_status === 'conflict') {
        // A version correction changes the payload and therefore must be a new intent.
        setExpectedVersion(String(next.observed_version)); setRetryKey('')
      } else if (next.terminal_status === 'applied' || next.terminal_status === 'no_op') {
        setExpectedVersion(String(next.observed_version)); setRetryKey('')
      }
    } catch (e) { setError(e instanceof Error ? e.message : String(e)) }
    finally { setBusy(false) }
  }

  return (
    <section className="card p-5 space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-[--ink]">{t('users.op.limits')}</h3>
        <p className="mt-1 text-xs text-[--muted]">{t('users.limitsDesc')}</p>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <Input label={t('config.nodeId')} value={nodeId} onChange={setNodeId} />
        <label className="block"><span className="text-xs text-[--muted]">{t('users.scope')}</span><select value={scope} onChange={e => setScope(e.target.value as typeof scope)} className="mt-1 w-full rounded-lg border border-[--border] bg-[--raised] px-3 py-2 text-sm text-[--ink]"><option value="global">global</option><option value="tenant">tenant</option><option value="user">user</option></select></label>
        <Input label={t('users.expectedVersion')} value={expectedVersion} onChange={setExpectedVersion} type="number" />
        {scope !== 'global' && <Input label={t('users.realm')} value={realm} onChange={setRealm} />}
        {scope !== 'global' && <Input label={t('users.tenant')} value={tenant} onChange={setTenant} />}
        {scope === 'user' && <Input label={t('users.username')} value={username} onChange={setUsername} />}
      </div>
      <LimitRow label="max_allocations" state={allocations} setState={setAllocations} />
      <LimitRow label="max_bytes_per_sec_per_allocation" state={bandwidth} setState={setBandwidth} />
      <LimitRow label="max_lifetime_secs" state={lifetime} setState={setLifetime} />
      <Input label={t('common.reason')} value={reason} onChange={setReason} />
      {retryKey && <p className="font-mono text-[11px] text-[--muted]">{t('common.retryKey')}: {retryKey}</p>}
      <button disabled={busy} onClick={() => void submit()} className="rounded-lg bg-violet-500 px-4 py-2 text-sm font-semibold text-white disabled:opacity-40">{busy ? t('common.applying') : t('users.applyLimits')}</button>
      {result && <LimitsResult result={result} scope={resultScope} />}
      {error && <p className="text-sm text-rose-400">{error}</p>}
    </section>
  )
}

function LimitRow({ label, state, setState }: { label: string; state: LimitFieldState; setState: (value: LimitFieldState) => void }) {
  return (
    <div className="grid grid-cols-[auto_1fr_180px_180px] items-center gap-3 rounded-lg border border-[--border] p-3">
      <input type="checkbox" checked={state.enabled} onChange={e => setState({ ...state, enabled: e.target.checked })} />
      <span className="font-mono text-sm text-[--ink]">{label}</span>
      <select disabled={!state.enabled} value={state.mode} onChange={e => setState({ ...state, mode: e.target.value as LimitMode })} className="rounded-lg border border-[--border] bg-[--raised] px-3 py-2 text-sm text-[--ink] disabled:opacity-40"><option value="inherit">inherit</option><option value="value">value</option><option value="unlimited">unlimited</option><option value="disabled">disabled</option></select>
      <input type="number" min="1" step="1" disabled={!state.enabled || state.mode !== 'value'} value={state.value} onChange={e => setState({ ...state, value: e.target.value })} className="rounded-lg border border-[--border] bg-[--raised] px-3 py-2 font-mono text-sm text-[--ink] disabled:opacity-40" />
    </div>
  )
}

function LimitsResult({ result, scope }: { result: SetUserLimitsResult; scope: 'global' | 'tenant' | 'user' }) {
  return (
    <div className="rounded-xl border border-[--border] p-4">
      <div className={'text-sm font-semibold ' + statusClass(result.terminal_status)}>{result.terminal_status}</div>
      <p className="mt-2 font-mono text-xs text-[--muted]">request_id={result.request_id} · {result.previous_version} → {result.observed_version}</p>
      <p className="mt-2 text-xs text-[--muted]">{scope === 'user' ? `Current allocations: ${result.max_user_allocations_in_scope}` : scope === 'tenant' ? `Highest allocations for one user in tenant: ${result.max_user_allocations_in_scope}` : `Highest allocations for one user globally: ${result.max_user_allocations_in_scope}`}</p>
      {result.max_user_allocations_above_limit && <p className="mt-2 text-sm text-amber-400">Highest per-user usage exceeds the effective limit</p>}
      {result.effective && <p className="mt-2 font-mono text-xs text-[--muted]">allocations={result.effective.allocations_disabled ? 'disabled' : result.effective.max_allocations || 'unlimited'} · bytes/s={result.effective.bandwidth_disabled ? 'disabled' : result.effective.max_bytes_per_sec_per_allocation || 'unlimited'} · lifetime={result.effective.lifetime_disabled ? 'disabled' : result.effective.max_lifetime_secs}</p>}
      {result.error && <p className="mt-2 text-sm text-rose-400">{result.error}</p>}
    </div>
  )
}

function Input({ label, value, onChange, type = 'text' }: { label: string; value: string; onChange: (value: string) => void; type?: string }) {
  return <label className="block"><span className="text-xs text-[--muted]">{label}</span><input type={type} value={value} onChange={e => onChange(e.target.value)} className="mt-1 w-full rounded-lg border border-[--border] bg-[--raised] px-3 py-2 text-sm text-[--ink]" /></label>
}
