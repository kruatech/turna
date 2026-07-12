import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
type Theme = 'light' | 'dark'
interface Ctx { theme: Theme; toggle: () => void }
const C = createContext<Ctx | null>(null)
const KEY = 'turna-theme'
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, set] = useState<Theme>(() => {
    const s = localStorage.getItem(KEY)
    return s === 'light' ? 'light' : 'dark'
  })
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem(KEY, theme)
  }, [theme])
  const toggle = useCallback(() => set(p => p === 'dark' ? 'light' : 'dark'), [])
  return <C.Provider value={{ theme, toggle }}>{children}</C.Provider>
}
export function useTheme() {
  const c = useContext(C)
  if (!c) throw new Error('useTheme outside ThemeProvider')
  return c
}
