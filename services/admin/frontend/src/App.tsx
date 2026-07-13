import { useState } from 'react'
import { usePolling } from './hooks/usePolling'
import { Sidebar, type NavId } from './layout/Sidebar'
import { Topbar } from './layout/Topbar'
import { OverviewPage }    from './pages/OverviewPage'
import { AllocationsPage } from './pages/AllocationsPage'
import { UsersPage }       from './pages/UsersPage'
import { NodesPage }       from './pages/NodesPage'
import { ClusterPage }     from './pages/ClusterPage'
import { EventsPage }      from './pages/EventsPage'
import { MetricsPage }     from './pages/MetricsPage'
import { ConfigPage }      from './pages/ConfigPage'
import { DiagnosticsPage } from './pages/DiagnosticsPage'
import type { PanelProps } from './panels/types'
import { useI18n } from './i18n'

export default function App() {
  const p = usePolling()
  const { t } = useI18n()
  const [page, setPage]           = useState<NavId>('overview')
  const [collapsed, setCollapsed] = useState(false)

  const props: PanelProps = {
    status:       p.status,
    metrics:      p.metrics,
    history:      p.history,
    frozen:       p.unreachable,
    clusterNodes: p.clusterNodes,
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar active={page} onChange={setPage}
        collapsed={collapsed} onCollapse={() => setCollapsed(c => !c)} />
      <div className="flex flex-1 flex-col overflow-hidden min-w-0">
        <Topbar page={page} status={p.status} metrics={p.metrics}
          live={p.live} ready={p.ready}
          lastUpdated={p.lastUpdated} loading={p.loading}
          intervalMs={p.intervalMs} setIntervalMs={p.setIntervalMs}
          paused={p.paused} setPaused={p.setPaused} refreshNow={p.refreshNow} />

        {p.unreachable && (
          <div className="flex items-center gap-2.5 border-b border-rose-400/20 bg-rose-400/8 px-5 py-2 shrink-0">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-400 pulse shrink-0" />
            <span className="text-xs font-medium text-rose-400">
              {t('topbar.unreachable')}
            </span>
          </div>
        )}

        <main className="flex-1 overflow-y-auto p-5">
          {page === 'overview'    && <OverviewPage    {...props} />}
          {page === 'allocations' && <AllocationsPage {...props} />}
          {page === 'users'       && <UsersPage {...props} />}
          {page === 'nodes'       && <NodesPage       {...props} />}
          {page === 'cluster'     && <ClusterPage     {...props} />}
          {page === 'events'      && <EventsPage      {...props} />}
          {page === 'metrics'     && <MetricsPage     {...props} />}
          {page === 'config'      && <ConfigPage      {...props} />}
          {page === 'diagnostics' && <DiagnosticsPage {...props} />}
        </main>
      </div>
    </div>
  )
}
