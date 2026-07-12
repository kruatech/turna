import { useI18n } from '../i18n'

const OPS = [
  { keyName: 'users.op.add',    keyDesc: 'users.op.addDesc',    color: 'teal',   icon: <AddIcon /> },
  { keyName: 'users.op.remove', keyDesc: 'users.op.removeDesc', color: 'rose',   icon: <RemoveIcon /> },
  { keyName: 'users.op.limits', keyDesc: 'users.op.limitsDesc', color: 'violet', icon: <LimitsIcon /> },
]

const colorMap: Record<string, { icon: string; badge: string; ring: string }> = {
  teal:   { icon: 'bg-teal-400/10 text-teal-400',   badge: 'bg-teal-400/10 text-teal-400 ring-teal-400/20',   ring: 'ring-teal-400/20' },
  rose:   { icon: 'bg-rose-400/10 text-rose-400',   badge: 'bg-rose-400/10 text-rose-400 ring-rose-400/20',   ring: 'ring-rose-400/20' },
  violet: { icon: 'bg-violet-400/10 text-violet-400', badge: 'bg-violet-400/10 text-violet-400 ring-violet-400/20', ring: 'ring-violet-400/20' },
}

export function UsersPage() {
  const { t } = useI18n()

  return (
    <div className="space-y-6 fade-up max-w-2xl">
      {/* header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <h2 className="text-xl font-bold text-[--ink]">{t('nav.users')}</h2>
          <span className="rounded-full bg-amber-400/10 px-3 py-1 text-xs font-semibold text-amber-400 ring-1 ring-amber-400/25">
            {t('users.stage2')}
          </span>
        </div>
        <p className="text-sm text-[--muted]">{t('users.desc')}</p>
      </div>

      {/* operation cards — like reference but dimmed */}
      <div className="space-y-3">
        {OPS.map(({ keyName, keyDesc, color, icon }) => {
          const c = colorMap[color]
          return (
            <div key={keyName}
              className="card flex items-center gap-4 p-5 opacity-60 cursor-not-allowed select-none">
              <div className={'flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ' + c.icon}>
                {icon}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2.5 mb-0.5">
                  <span className="text-sm font-semibold text-[--ink]">{t(keyName)}</span>
                  <span className={'rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 ' + c.badge}>
                    stage 2
                  </span>
                </div>
                <p className="text-xs text-[--muted] truncate">{t(keyDesc)}</p>
              </div>
              <svg className="w-4 h-4 text-[--faint] shrink-0" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M6 3l5 5-5 5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
          )
        })}
      </div>

      {/* why section */}
      <div className="card p-5">
        <div className="flex items-center gap-2.5 mb-3">
          <svg className="w-4 h-4 text-amber-400 shrink-0" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M8 2L14 13H2L8 2z" strokeLinejoin="round"/>
            <path d="M8 6v3M8 11v.5" strokeLinecap="round"/>
          </svg>
          <span className="text-sm font-semibold text-[--ink]">{t('users.why')}</span>
        </div>
        <p className="text-sm text-[--muted] leading-relaxed mb-4">{t('users.whyDesc')}</p>

        {/* config preview */}
        <div className="rounded-xl border border-[--border] overflow-hidden">
          {[
            { label: t('users.grpc'), value: t('users.grpcAddr'), mono: true },
            { label: t('users.auth'), value: t('users.authVal'),  mono: false },
            { label: t('users.mtls'), value: t('users.mtlsVal'),  mono: false },
          ].map(({ label, value, mono }, i, arr) => (
            <div key={label}
              className={'flex items-center justify-between px-4 py-3 ' +
                (i < arr.length - 1 ? 'border-b border-[--border] ' : '') +
                'hover:bg-[--raised] transition-colors'}>
              <span className="text-xs text-[--muted]">{label}</span>
              <span className={'text-xs font-medium ' + (mono ? 'font-mono text-teal-400' : 'text-[--faint]')}>{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function AddIcon()    { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="7" r="3"/><path d="M4 17c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M14 3v4M12 5h4" strokeLinecap="round"/></svg> }
function RemoveIcon() { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="10" cy="7" r="3"/><path d="M4 17c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M12 5h4" strokeLinecap="round"/></svg> }
function LimitsIcon() { return <svg className="w-5 h-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M3 10h14M3 6h10M3 14h7" strokeLinecap="round"/><circle cx="15" cy="14" r="2.5"/><path d="M15 11.5v1M15 16.5v1M12.5 14h1M16.5 14h1" strokeLinecap="round"/></svg> }
