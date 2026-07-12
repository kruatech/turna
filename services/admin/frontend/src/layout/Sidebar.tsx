import { useI18n } from '../i18n'

export type NavId = 'overview' | 'allocations' | 'users' | 'nodes' | 'cluster' | 'events' | 'metrics' | 'config' | 'diagnostics'

export function Sidebar({ active, onChange, collapsed, onCollapse }:
  { active: NavId; onChange: (id: NavId) => void; collapsed: boolean; onCollapse: () => void }) {
  const { t } = useI18n()

  const NAV: { id: NavId; key: string; icon: React.ReactNode; dot?: boolean; dim?: boolean }[] = [
    { id: 'overview',    key: 'nav.overview',    icon: <IcoOverview /> },
    { id: 'allocations', key: 'nav.allocations', icon: <IcoAlloc /> },
    { id: 'users',       key: 'nav.users',       icon: <IcoUsers />, dim: true },
    { id: 'nodes',       key: 'nav.nodes',       icon: <IcoNodes /> },
    { id: 'cluster',     key: 'nav.cluster',     icon: <IcoCluster /> },
    { id: 'events',      key: 'nav.events',      icon: <IcoEvents />, dot: true },
    { id: 'metrics',     key: 'nav.metrics',     icon: <IcoMetrics /> },
    { id: 'config',      key: 'nav.config',      icon: <IcoConfig /> },
    { id: 'diagnostics', key: 'nav.diagnostics', icon: <IcoDiag /> },
  ]

  return (
    <aside className={'flex flex-col border-r border-[--sidebar-border] bg-[--sidebar] transition-all duration-200 shrink-0 ' + (collapsed ? 'w-16' : 'w-56')}>
      {/* logo */}
      <div className="flex h-14 items-center gap-3 border-b border-[--sidebar-border] px-4 shrink-0">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-teal-400/10">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="#2dd4bf" strokeWidth="1.5"/>
            <circle cx="8" cy="8" r="2" fill="#2dd4bf"/>
          </svg>
        </div>
        {!collapsed && (
          <div className="leading-none overflow-hidden">
            <div className="text-sm font-bold text-[--ink] truncate">Turna</div>
            <div className="text-[10px] font-mono text-[--muted]">Control Plane</div>
          </div>
        )}
      </div>

      {/* nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
        {NAV.map(({ id, key, icon, dot, dim }) => {
          const isActive = active === id
          return (
            <button key={id} onClick={() => onChange(id)} title={collapsed ? t(key) : undefined}
              className={
                'w-full flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all ' +
                (isActive
                  ? 'bg-[--sidebar-active-bg] text-[--sidebar-active-ink]'
                  : dim
                    ? 'text-[--faint] hover:bg-[--raised] hover:text-[--muted]'
                    : 'text-[--muted] hover:bg-[--raised] hover:text-[--ink]')
              }>
              <span className="shrink-0 w-4 h-4">{icon}</span>
              {!collapsed && (
                <span className="flex-1 flex items-center justify-between gap-2 min-w-0">
                  <span className="truncate">{t(key)}</span>
                  <span className="flex items-center gap-1.5 shrink-0">
                    {dot && <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />}
                    {dim && !isActive && (
                      <span className="rounded-full bg-[--raised] px-1.5 py-0.5 text-[9px] font-semibold text-[--faint] ring-1 ring-[--border]">
                        2
                      </span>
                    )}
                  </span>
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {/* collapse */}
      <button onClick={onCollapse}
        className="flex items-center gap-2 border-t border-[--sidebar-border] px-4 py-3 text-xs text-[--muted] hover:text-[--ink] transition-colors">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5"
          className={'transition-transform duration-200 ' + (collapsed ? 'rotate-180' : '')}>
          <path d="M9 2L4 7l5 5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        {!collapsed && <span>{t('nav.collapse')}</span>}
      </button>
    </aside>
  )
}

function IcoOverview()  { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="1" y="1" width="6" height="6" rx="1.5"/><rect x="9" y="1" width="6" height="6" rx="1.5"/><rect x="1" y="9" width="6" height="6" rx="1.5"/><rect x="9" y="9" width="6" height="6" rx="1.5"/></svg> }
function IcoAlloc()     { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="1" y="3" width="14" height="10" rx="2"/><path d="M5 8h6M8 5v6" strokeLinecap="round"/></svg> }
function IcoUsers()     { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="6" cy="5" r="2.5"/><path d="M1 13c0-2.8 2.2-5 5-5s5 2.2 5 5"/><circle cx="12" cy="5" r="2"/><path d="M14 13c0-2.2-1.3-4-3-4.5"/></svg> }
function IcoNodes()     { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="1" y="2" width="14" height="5" rx="1.5"/><rect x="1" y="9" width="14" height="5" rx="1.5"/><circle cx="3.5" cy="4.5" r=".8" fill="currentColor"/><circle cx="3.5" cy="11.5" r=".8" fill="currentColor"/></svg> }
function IcoEvents()    { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M8 2l1.5 4.5H14l-3.7 2.7 1.4 4.3L8 11l-3.7 2.5 1.4-4.3L2 6.5h4.5z" strokeLinejoin="round"/></svg> }
function IcoMetrics()   { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M1 12L4 8l3 2 3-5 3 2 2-3" strokeLinecap="round" strokeLinejoin="round"/></svg> }
function IcoConfig()    { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="2"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M11.4 3.2l-1.4 1.4M4.6 11.4l-1.4 1.4"/></svg> }
function IcoCluster()  { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="2"/><circle cx="3" cy="3" r="1.5"/><circle cx="13" cy="3" r="1.5"/><circle cx="3" cy="13" r="1.5"/><circle cx="13" cy="13" r="1.5"/><path d="M4.1 4.1L6.6 6.6M9.4 6.6L11.9 4.1M9.4 9.4L11.9 11.9M6.6 9.4L4.1 11.9"/></svg> }
function IcoDiag()      { return <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="6"/><path d="M8 5v3l2 1.5" strokeLinecap="round"/></svg> }
