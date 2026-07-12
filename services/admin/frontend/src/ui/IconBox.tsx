import type { ReactNode } from 'react'
const colors: Record<string, string> = {
  teal:    'bg-teal-400/10    text-teal-400',
  violet:  'bg-violet-400/10  text-violet-400',
  sky:     'bg-sky-400/10     text-sky-400',
  amber:   'bg-amber-400/10   text-amber-400',
  rose:    'bg-rose-400/10    text-rose-400',
  emerald: 'bg-emerald-400/10 text-emerald-400',
  orange:  'bg-orange-400/10  text-orange-400',
}
export function IconBox({ color = 'teal', size = 10, children }:
  { color?: string; size?: number; children: ReactNode }) {
  return (
    <div className={`flex items-center justify-center rounded-xl ${colors[color] ?? colors.teal}`}
      style={{ width: size * 4, height: size * 4 }}>
      {children}
    </div>
  )
}
