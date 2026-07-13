import { useState, useCallback, useRef } from 'react'
import { Card } from '../ui/Card'
import { Badge } from '../ui/Badge'
import { MiniChart } from '../ui/MiniChart'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { statusSeries } from '../lib/series'
import { api, type AllocEntry } from '../api/client'
import type { PanelProps } from '../panels/types'

export function AllocationsPage({ status, metrics, history, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  const active  = statusSeries(history, s => s.active_allocations)
  const tenants = metrics?.labeled['turna_tenant_allocations_total'] ?? []

  const [allocs, setAllocs]   = useState<AllocEntry[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState<string | null>(null)
  const [killing, setKilling] = useState<string | null>(null)
  const [toast, setToast]     = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 2500) }

  // High-assurance idempotency: one stable key per kill INTENT (per allocation
  // id), reused across retries so a network-timeout retry dedups on the backend
  // instead of creating a second command. A fresh UUID per retry would defeat
  // dedup. Cleared on success so a later, distinct kill gets a new key. Required
  // when the backend runs with TURNA_REQUIRE_IDEMPOTENCY_KEY=true.
  const killKeys = useRef<Record<string, string>>({})
  const newKey = () =>
    (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`

  const loadAllocs = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const res = await api.manage.allocList(100)
      setAllocs(res.allocations ?? [])
    } catch (e) {
      setError(t('alloc.loadError'))
    } finally { setLoading(false) }
  }, [t])

  const killAlloc = useCallback(async (id: string) => {
    if (!id) return
    if (!confirm(t('alloc.killConfirm') + id)) return
    const key = killKeys.current[id] ?? (killKeys.current[id] = newKey())
    setKilling(id)
    try {
      await api.manage.allocKill(id, undefined, key)
      showToast(t('alloc.killed') + ' ' + id)
      delete killKeys.current[id] // intent complete — a later kill is a new intent
      setAllocs(prev => prev ? prev.filter(a => a.id !== id) : prev)
    } catch { showToast(t('nodes.actionError')) } // keep key so a retry reuses it
    finally { setKilling(null) }
  }, [t])

  if (!status) return <div className="flex items-center justify-center h-48 text-[--muted]">{t('ov.waiting')}</div>

  return (
    <div className="space-y-5 fade-up">
      {toast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 rounded-xl bg-emerald-500/15 px-5 py-3 text-sm font-medium text-emerald-400 ring-1 ring-emerald-400/30 shadow-xl">
          {toast}
        </div>
      )}

      {/* summary */}
      <div className="grid grid-cols-2 gap-4">
        <div className="card p-5">
          <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{t('alloc.active')}</div>
          <div className="font-mono text-5xl font-bold text-teal-400 vf">{formatCount(status.active_allocations, lang)}</div>
          <div className="text-sm text-[--muted] mt-1">{t('al.activeNow')}</div>
        </div>
        <div className="card p-5">
          <div className="text-[10px] font-semibold uppercase tracking-widest text-[--muted] mb-2">{t('alloc.total')}</div>
          <div className="font-mono text-5xl font-bold text-[--ink] vf">{formatCount(status.total_allocations, lang)}</div>
          <div className="text-sm text-[--muted] mt-1">{t('al.lifetime')}</div>
        </div>
      </div>

      {/* history chart */}
      <Card title={t('al.history')} frozen={frozen}>
        <MiniChart data={active} color="#2dd4bf" height={180} fmt={v => formatCount(v, lang)} />
      </Card>

      {/* per-tenant breakdown */}
      {tenants.length > 0 && (
        <Card title={t('al.topTenants')} frozen={frozen}>
          <div className="space-y-2">
            {tenants.slice(0, 15).map((s, i) => (
              <div key={i} className="flex items-center gap-3">
                <span className="w-5 text-center font-mono text-xs text-[--faint]">{i+1}</span>
                <span className="flex-1 font-mono text-sm text-[--ink]">
                  {Object.entries(s.labels).map(([k, v]) => `${k}=${v}`).join(' ')}
                </span>
                <span className="font-mono text-sm font-semibold text-teal-400">{formatCount(s.value, lang)}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* live allocation list */}
      <div className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-[--border] px-5 py-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">{t('alloc.liveList')}</h2>
          <button onClick={loadAllocs} disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-[--border] bg-[--raised] px-3 py-1.5 text-xs text-[--muted] hover:text-[--ink] disabled:opacity-50 transition-all">
            {loading
              ? <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-teal-400 border-t-transparent"/>
              : <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M10 6A4 4 0 1 1 8 2.5" strokeLinecap="round"/><path d="M8 1v2.5H10.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
            }
            {t('alloc.refresh')}
          </button>
        </div>

        {error && <div className="px-5 py-4 text-sm text-rose-400">{error}</div>}

        {allocs === null && !loading && (
          <div className="px-5 py-8 text-center text-sm text-[--faint]">
            {t('alloc.refresh')} →
          </div>
        )}

        {loading && (
          <div className="px-5 py-8 text-center text-sm text-[--muted]">{t('alloc.loading')}</div>
        )}

        {allocs !== null && !loading && allocs.length === 0 && (
          <div className="px-5 py-8 text-center text-sm text-[--faint]">{t('alloc.empty')}</div>
        )}

        {allocs !== null && allocs.length > 0 && (
          <>
            <div className="grid grid-cols-[auto_1fr_1fr_auto_auto_auto] gap-0 border-b border-[--border] font-mono text-[10px] uppercase tracking-widest text-[--faint] px-4 py-2">
              <span className="pr-4">{t('alloc.relayPort')}</span>
              <span className="pr-4">{t('alloc.username')}</span>
              <span className="pr-4">{t('alloc.peer')}</span>
              <span className="pr-4">{t('alloc.transport')}</span>
              <span className="pr-4">{t('alloc.lifetime')}</span>
              <span/>
            </div>
            <div className="divide-y divide-[--border] max-h-[60vh] overflow-y-auto">
              {allocs.map((a, i) => (
                <div key={i} className="grid grid-cols-[auto_1fr_1fr_auto_auto_auto] gap-0 items-center px-4 py-2.5 hover:bg-[--raised] transition-colors font-mono text-xs">
                  <span className="pr-4 text-teal-400 font-semibold">{a.relay_address ?? '—'}</span>
                  <span className="pr-4 text-[--ink] truncate">{a.username ?? '—'}</span>
                  <span className="pr-4 text-[--muted] truncate">{a.client_address ?? '—'}</span>
                  <span className="pr-4">
                    {a.transport && (
                      <Badge kind="neutral" label={String(a.transport)} />
                    )}
                  </span>
                  <span className="pr-4 text-[--muted]">{a.remaining_lifetime !== undefined ? a.remaining_lifetime + 's' : '—'}</span>
                  <button
                    onClick={() => killAlloc(a.id ?? '')}
                    disabled={killing === a.id || !a.id}
                    className="rounded-lg border border-rose-400/30 bg-rose-400/8 px-2.5 py-1 text-xs font-medium text-rose-400 hover:bg-rose-400/15 disabled:opacity-40 transition-all">
                    {killing === a.id
                      ? <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-rose-400 border-t-transparent"/>
                      : t('alloc.kill')}
                  </button>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
