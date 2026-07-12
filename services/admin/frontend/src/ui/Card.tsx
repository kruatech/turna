import type { ReactNode } from 'react'
export function Card({ title, right, children, frozen, className = '' }:
  { title?: string; right?: ReactNode; children: ReactNode; frozen?: boolean; className?: string }) {
  return (
    <section className={'card ' + (frozen ? 'opacity-50 ' : '') + className}>
      {(title || right) && (
        <header className="flex items-center justify-between gap-2 border-b border-[--border] px-5 py-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-widest text-[--muted]">{title}</h2>
          {right && <div className="flex items-center gap-2">{right}</div>}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}
