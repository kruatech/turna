import type { Status } from './tokens'
const cfg: Record<Status, string> = {
  ok:       'bg-emerald-400/10 text-emerald-400 ring-1 ring-emerald-400/25',
  degraded: 'bg-amber-400/10   text-amber-400   ring-1 ring-amber-400/25',
  draining: 'bg-orange-400/10  text-orange-400  ring-1 ring-orange-400/25',
  error:    'bg-rose-400/10    text-rose-400    ring-1 ring-rose-400/25',
  neutral:  'bg-[--raised]     text-[--muted]   ring-1 ring-[--border2]',
}
const dot: Record<Status, string> = {
  ok:'bg-emerald-400', degraded:'bg-amber-400', draining:'bg-orange-400', error:'bg-rose-400', neutral:'bg-[--muted]',
}
export function Badge({ kind, label }: { kind: Status; label: string }) {
  return (
    <span className={'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium font-mono ' + cfg[kind]}>
      <span className={'h-1.5 w-1.5 rounded-full shrink-0 ' + dot[kind]} />
      {label}
    </span>
  )
}
