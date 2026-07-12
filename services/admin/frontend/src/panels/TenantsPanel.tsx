import { Card } from '../ui/Card'
import { useI18n } from '../i18n'
import { formatCount } from '../format/format'
import { keysWithPrefix, metric } from '../lib/series'
import type { PanelProps } from './types'

export function TenantsPanel({ metrics, frozen }: PanelProps) {
  const { t, lang } = useI18n()
  const tenantKeys = keysWithPrefix(metrics, 'turna_tenant')
  if (tenantKeys.length === 0) return null
  return (
    <Card title={t('panel.tenants')} frozen={frozen}>
      <table className="w-full text-sm">
        <tbody className="font-mono">
          {tenantKeys.map((k) => {
            const labeled = metrics?.labeled[k]
            if (labeled && labeled.length > 0) {
              return labeled.map((s, i) => (
                <tr key={k + i} className="border-t border-surface-line first:border-0">
                  <td className="py-1.5 pr-2 text-ink-soft">{k}</td>
                  <td className="py-1.5 pr-4 text-ink-faint">{Object.entries(s.labels).map(([lk,lv])=>`${lk}=${lv}`).join(' ')}</td>
                  <td className="py-1.5 text-right tabular-nums text-ink">{formatCount(s.value, lang)}</td>
                </tr>
              ))
            }
            return (
              <tr key={k} className="border-t border-surface-line first:border-0">
                <td className="py-1.5 pr-4 text-ink-soft" colSpan={2}>{k}</td>
                <td className="py-1.5 text-right tabular-nums text-ink">{formatCount(metric(metrics, k) ?? 0, lang)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </Card>
  )
}
