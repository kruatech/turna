import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import type { Lang } from '../format/format'
import { ru } from './ru'
import { en } from './en'

type Dict = Record<string, string>
const DICTS: Record<Lang, Dict> = { ru, en }
const KEY = 'turna-admin-lang'

interface I18nCtx {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: string) => string
}
const Ctx = createContext<I18nCtx | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const s = localStorage.getItem(KEY)
    return s === 'ru' || s === 'en' ? s : 'ru'
  })
  const setLang = useCallback((l: Lang) => {
    localStorage.setItem(KEY, l)
    setLangState(l)
  }, [])
  const t = useCallback((key: string) => DICTS[lang][key] ?? key, [lang])

  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>
}

export function useI18n(): I18nCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useI18n used outside I18nProvider')
  return c
}
