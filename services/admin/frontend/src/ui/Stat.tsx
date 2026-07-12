import type { Status } from './tokens'
const tone: Record<Status, string> = {
  ok:'text-emerald-400', degraded:'text-amber-400', draining:'text-orange-400', error:'text-rose-400', neutral:'text-[--ink]',
}
export function Stat({ label, value, unit, sub, status = 'neutral', delta }:
  { label: string; value: string; unit?: string; sub?: string; status?: Status; delta?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-widest text-[--faint]">{label}</span>
      <div className="flex items-baseline gap-1.5">
        <span className={'vf font-mono text-2xl font-semibold tabular-nums leading-none ' + tone[status]}>{value}</span>
        {unit && <span className="font-mono text-sm text-[--muted]">{unit}</span>}
        {delta && <span className="font-mono text-xs text-rose-400">▲{delta}</span>}
      </div>
      {sub && <span className="text-xs text-[--muted] leading-tight">{sub}</span>}
    </div>
  )
}
