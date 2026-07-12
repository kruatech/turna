export type Status = 'ok' | 'degraded' | 'draining' | 'error' | 'neutral'

export const statusColor: Record<Status, { text: string; bg: string; ring: string; dot: string; stroke: string }> = {
  ok:       { text: 'text-emerald-400',  bg: 'bg-emerald/dim',   ring: 'ring-emerald-400/30',   dot: 'bg-emerald-400',  stroke: '#34d399' },
  degraded: { text: 'text-amber-400',    bg: 'bg-amber/dim',     ring: 'ring-amber-400/30',     dot: 'bg-amber-400',    stroke: '#fbbf24' },
  draining: { text: 'text-orange-400',   bg: 'bg-orange/dim',    ring: 'ring-orange-400/30',    dot: 'bg-orange-400',   stroke: '#fb923c' },
  error:    { text: 'text-rose-400',     bg: 'bg-rose/dim',      ring: 'ring-rose-400/30',      dot: 'bg-rose-400',     stroke: '#f87171' },
  neutral:  { text: 'text-[--muted]',    bg: 'bg-[--raised]',    ring: 'ring-[--border2]',      dot: 'bg-[--muted]',    stroke: '#38bdf8' },
}
export const iconBg: Record<string, string> = {
  teal:    'bg-teal-dim   text-teal',
  violet:  'bg-violet-dim text-violet',
  sky:     'bg-sky-dim    text-sky',
  amber:   'bg-amber-dim  text-amber',
  rose:    'bg-rose-dim   text-rose',
  emerald: 'bg-emerald-dim text-emerald',
  orange:  'bg-orange-dim text-orange',
}
