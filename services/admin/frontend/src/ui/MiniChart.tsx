import { Area, AreaChart, ResponsiveContainer, Tooltip, YAxis } from 'recharts'
import type { Point } from '../lib/series'
export function MiniChart({ data, color = '#38bdf8', height = 80, fmt }:
  { data: Point[]; color?: string; height?: number; fmt?: (v: number) => string }) {
  const id = 'g' + color.replace('#', '')
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.3} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <YAxis hide domain={[0, 'auto']} />
          <Tooltip
            contentStyle={{ fontSize: 11, fontFamily: '"JetBrains Mono",monospace', borderRadius: 8,
              border: '1px solid rgba(255,255,255,.1)', background: 'rgba(13,15,23,.97)', color: '#e8eaf2',
              boxShadow: '0 8px 32px rgba(0,0,0,.5)' }}
            labelFormatter={(_, p) => (p?.[0] ? (p[0].payload as Point).label : '')}
            formatter={(v: number) => [fmt ? fmt(v) : String(Math.round(v)), '']}
            cursor={{ stroke: 'rgba(255,255,255,.08)', strokeWidth: 1 }}
          />
          <Area type="monotone" dataKey="value" stroke={color} strokeWidth={1.5}
            fill={`url(#${id})`} isAnimationActive={false} dot={false}
            activeDot={{ r: 3, fill: color, strokeWidth: 0 }} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
