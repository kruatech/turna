export type StatusKind = 'ok' | 'degraded' | 'draining' | 'error' | 'neutral'

export const badgeClass: Record<StatusKind, string> = {
  ok:       'bg-status-okDim text-status-ok ring-1 ring-status-ok/30',
  degraded: 'bg-status-degradedDim text-status-degraded ring-1 ring-status-degraded/30',
  draining: 'bg-status-drainDim text-status-drain ring-1 ring-status-drain/30',
  error:    'bg-status-errorDim text-status-error ring-1 ring-status-error/30',
  neutral:  'bg-surface-raised text-ink-soft ring-1 ring-surface-lineMid',
}

export const strokeColor: Record<StatusKind, string> = {
  ok:       '#22d3a6',
  degraded: '#fbbf24',
  draining: '#fb923c',
  error:    '#f87171',
  neutral:  '#60a5fa',
}

export const dotClass: Record<StatusKind, string> = {
  ok:       'bg-status-ok',
  degraded: 'bg-status-degraded',
  draining: 'bg-status-drain',
  error:    'bg-status-error',
  neutral:  'bg-ink-faint',
}

export const iconBg: Record<StatusKind, string> = {
  ok:       'bg-status-okDim text-status-ok',
  degraded: 'bg-status-degradedDim text-status-degraded',
  draining: 'bg-status-drainDim text-status-drain',
  error:    'bg-status-errorDim text-status-error',
  neutral:  'bg-surface-raised text-ink-soft',
}
