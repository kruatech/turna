export type Lang = 'ru' | 'en'

const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']

export function formatBytes(n: number, lang: Lang): string {
  if (!isFinite(n) || n < 0) return '—'
  let v = n
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  const num = i === 0 ? String(Math.round(v)) : v.toLocaleString(lang, { maximumFractionDigits: 1 })
  return `${num} ${UNITS[i]}`
}

export function formatBytesRate(n: number, lang: Lang): string {
  return `${formatBytes(n, lang)}/s`
}

export function formatCount(n: number, lang: Lang): string {
  if (!isFinite(n)) return '—'
  return Math.round(n).toLocaleString(lang)
}

export function formatRate(n: number, lang: Lang, unit: string): string {
  if (!isFinite(n) || n < 0) return '—'
  return `${n.toLocaleString(lang, { maximumFractionDigits: n < 10 ? 1 : 0 })} ${unit}`
}

export function formatDuration(secs: number, lang: Lang): string {
  if (!isFinite(secs) || secs < 0) return '—'
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = Math.floor(secs % 60)
  const L = lang === 'ru' ? { d: 'д', h: 'ч', m: 'мин', s: 'с' } : { d: 'd', h: 'h', m: 'm', s: 's' }
  const parts: string[] = []
  if (d) parts.push(`${d} ${L.d}`)
  if (h || d) parts.push(`${h} ${L.h}`)
  if (d || h) parts.push(`${m} ${L.m}`)
  else parts.push(`${m} ${L.m}`, `${s} ${L.s}`)
  return parts.join(' ')
}

export function timeLabel(t: number): string {
  return new Date(t).toLocaleTimeString()
}
