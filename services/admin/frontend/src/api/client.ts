import type { NodeStatus, NormalizedMetrics } from './types'

export class NodeUnreachable extends Error {
  constructor() { super('node_unreachable'); this.name = 'NodeUnreachable' }
}

async function getJson<T>(path: string): Promise<T> {
  let resp: Response
  try { resp = await fetch(path, { headers: { accept: 'application/json' } }) }
  catch { throw new NodeUnreachable() }
  if (resp.status === 503) throw new NodeUnreachable()
  if (!resp.ok) throw new Error(`http ${resp.status}`)
  return (await resp.json()) as T
}

async function getLive(path: string): Promise<boolean> {
  let resp: Response
  try { resp = await fetch(path) } catch { throw new NodeUnreachable() }
  return resp.ok
}

async function postManage<T = unknown>(command: string, params: Record<string, unknown> = {}): Promise<T> {
  let resp: Response
  try {
    resp = await fetch('/api/manage', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ command, params }),
    })
  } catch { throw new NodeUnreachable() }
  if (resp.status === 503) throw new NodeUnreachable()
  if (!resp.ok) throw new Error(`manage ${command}: http ${resp.status}`)
  return (await resp.json()) as T
}

export interface ClusterNode {
  node_id:   string
  turn_addr: string
  is_self:   boolean
}

export interface AllocEntry {
  relay_port?: number
  username?:   string
  peer?:       string
  transport?:  string
  lifetime?:   number
  [key: string]: unknown
}

export const api = {
  status:  () => getJson<NodeStatus>('/api/status'),
  metrics: () => getJson<NormalizedMetrics>('/api/metrics'),
  health:  () => getLive('/api/health'),
  ready:   () => getLive('/api/ready'),
  cluster: () => getJson<ClusterNode[]>('/api/cluster'),

  manage: {
    ping:           () => postManage('ping'),
    nodeDrain:      () => postManage('node.drain'),
    nodeUndrain:    () => postManage('node.undrain'),
    failoverStatus: () => postManage('failover.status'),
    allocCount:     () => postManage<{ count: number }>('allocations.count'),
    allocList:      (limit = 50) => postManage<{ allocations: AllocEntry[] }>('allocations.list', { limit }),
    allocGet:       (relay_port: number) => postManage('allocations.get', { relay_port }),
    allocKill:      (relay_port: number) => postManage('allocations.kill', { relay_port }),
    roomsList:      (limit = 50) => postManage<{ rooms: unknown[] }>('rooms.list', { limit }),
  },
}
