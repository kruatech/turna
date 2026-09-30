import type {
  LimitInput, NodeRuntimeConfig, NodeStatus, NormalizedMetrics,
  SetUserLimitsResult, UpdateConfigResult,
} from './types'

export class NodeUnreachable extends Error {
  constructor() { super('node_unreachable'); this.name = 'NodeUnreachable' }
}

// The backend was started with an admin token and this tab has none, or a
// wrong one. Since 0.5.0 the token guards every /api route, reads included,
// so a read failing this way is an auth problem, not a node problem.
export class AuthRequired extends Error {
  constructor() { super('auth_required'); this.name = 'AuthRequired' }
}

function isAuthFailure(resp: Response): boolean {
  return resp.status === 401 || resp.status === 403
}

function withToken(headers: Record<string, string>): Record<string, string> {
  const token = getAdminToken()
  if (token) headers['x-admin-token'] = token
  return headers
}

async function getJson<T>(path: string): Promise<T> {
  let resp: Response
  try { resp = await fetch(path, { headers: withToken({ accept: 'application/json' }) }) }
  catch { throw new NodeUnreachable() }
  if (resp.status === 503) throw new NodeUnreachable()
  if (isAuthFailure(resp)) throw new AuthRequired()
  if (!resp.ok) throw new Error(`http ${resp.status}`)
  return (await resp.json()) as T
}

async function getLive(path: string): Promise<boolean> {
  let resp: Response
  try { resp = await fetch(path, { headers: withToken({}) }) } catch { throw new NodeUnreachable() }
  // A 401 here would otherwise read as "not live", sending the operator after
  // a node that is fine.
  if (isAuthFailure(resp)) throw new AuthRequired()
  return resp.ok
}

// The operator's admin token lives in sessionStorage: per-tab, gone when the tab
// closes, and readable by any script running on this origin. That last part is
// real and is accepted deliberately, because neither alternative is better here:
// an in-memory variable is just as readable by an XSS that is already executing
// (and it additionally loses the token on every page reload), while an httpOnly
// cookie would need the node to issue Set-Cookie and defend against CSRF, and
// the management endpoint authenticates on the X-Admin-Token HEADER. An XSS on
// this origin can call /api/manage directly regardless of where the token sits.
// If that ever stops being acceptable, the fix is a cookie + CSRF token on the
// backend, not a different client-side hiding place.
const ADMIN_TOKEN_KEY = 'turna_admin_token'

export function getAdminToken(): string {
  try { return sessionStorage.getItem(ADMIN_TOKEN_KEY) ?? '' } catch { return '' }
}

export function setAdminToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(ADMIN_TOKEN_KEY, token)
    else sessionStorage.removeItem(ADMIN_TOKEN_KEY)
  } catch { /* storage unavailable */ }
}

// Ask the operator for the admin token and keep it for this tab. Returns
// whether a non-empty token was entered.
export function promptAdminToken(): boolean {
  const entered = typeof prompt === 'function'
    ? prompt('Admin token required (sent as the X-Admin-Token header):')
    : null
  if (!entered || !entered.trim()) return false
  setAdminToken(entered.trim())
  return true
}

async function postManage<T = unknown>(command: string, params: Record<string, unknown> = {}): Promise<T> {
  // Mutations require the operator's X-Admin-Token when the backend is secured.
  const send = async (): Promise<Response> => {
    return fetch('/api/manage', {
      method: 'POST',
      headers: withToken({ 'content-type': 'application/json' }),
      body: JSON.stringify({ command, params }),
    })
  }
  let resp: Response
  try { resp = await send() } catch { throw new NodeUnreachable() }
  if (resp.status === 503) throw new NodeUnreachable()
  // Missing/invalid token → prompt once, persist, retry, so a secured backend is
  // usable from the browser instead of failing every mutation with 401.
  if (isAuthFailure(resp)) {
    if (promptAdminToken()) {
      try { resp = await send() } catch { throw new NodeUnreachable() }
      // A token the node still rejects must NOT stay in sessionStorage. It would
      // be replayed on every later mutation, each one failing and prompting
      // again, and a typo would survive until the operator thought to close the
      // tab. Drop it so the next attempt starts from an empty prompt.
      if (isAuthFailure(resp)) setAdminToken('')
    }
  }
  if (!resp.ok) {
    let detail = `http ${resp.status}`
    try {
      const body = await resp.json() as { error?: string }
      if (body.error) detail = body.error
    } catch { /* non-JSON error */ }
    throw new Error(`manage ${command}: ${detail}`)
  }
  return (await resp.json()) as T
}

export function newIdempotencyKey(prefix: string): string {
  const suffix = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `${prefix}-${suffix}`
}

function limitParams(value?: LimitInput): Record<string, unknown> {
  if (!value) return {}
  return { mode: value.mode, value: value.mode === 'value' ? value.value ?? 0 : 0 }
}

export interface ClusterNode {
  node_id:   string
  turn_addr: string
  is_self:   boolean
}

export interface AllocEntry {
  id?:                 string
  username?:           string
  realm?:              string
  client_address?:     string
  relay_address?:      string
  transport?:          string
  expires_at?:         string | number
  remaining_lifetime?: number
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
    nodeDrain:      (node_id: string, idempotency_key?: string) =>
      postManage('node.drain', idempotency_key ? { node_id, idempotency_key } : { node_id }),
    nodeUndrain:    (node_id: string, idempotency_key?: string) =>
      postManage('node.undrain', idempotency_key ? { node_id, idempotency_key } : { node_id }),
    failoverStatus: () => postManage('failover.status'),
    allocCount:     () => postManage<{ count: number }>('allocations.count'),
    allocList:      (limit = 50) => postManage<{ allocations: AllocEntry[] }>('allocations.list', { limit }),
    allocGet:       (id: string) => postManage('allocations.get', { id }),
    allocKill:      (id: string, reason?: string, idempotency_key?: string) =>
      postManage('allocations.kill', {
        id,
        ...(reason ? { reason } : {}),
        ...(idempotency_key ? { idempotency_key } : {}),
      }),
    configGet: (node_id: string) =>
      postManage<NodeRuntimeConfig>('config.get', { node_id }),
    configUpdate: (params: {
      node_id: string
      idempotency_key: string
      expected_version: number
      max_allocations?: number
      max_allocations_per_user?: number
      max_bytes_per_sec_per_allocation?: number
      reason?: string
    }) => postManage<UpdateConfigResult>('config.update', params),
    userAdd: (username: string, password: string, organization?: string) =>
      postManage<{ ok: boolean }>('users.add', { username, password, organization }),
    userRemove: (username: string, force = false) =>
      postManage<{ ok: boolean; allocations_deleted: number }>('users.remove', { username, force }),
    userSetLimits: (params: {
      node_id: string
      scope: 'global' | 'tenant' | 'user'
      tenant?: string
      realm?: string
      username?: string
      idempotency_key: string
      expected_version: number
      max_allocations?: LimitInput
      max_bytes_per_sec_per_allocation?: LimitInput
      max_lifetime_secs?: LimitInput
      reason?: string
    }) => postManage<SetUserLimitsResult>('users.set_limits', {
      ...params,
      ...(params.max_allocations ? { max_allocations: limitParams(params.max_allocations) } : {}),
      ...(params.max_bytes_per_sec_per_allocation ? { max_bytes_per_sec_per_allocation: limitParams(params.max_bytes_per_sec_per_allocation) } : {}),
      ...(params.max_lifetime_secs ? { max_lifetime_secs: limitParams(params.max_lifetime_secs) } : {}),
    }),
  },
}
