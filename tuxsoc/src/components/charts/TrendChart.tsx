import {
  AreaChart, Area, XAxis, YAxis, Tooltip,
  ResponsiveContainer
} from 'recharts'

interface DataPoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

interface Props {
  data: DataPoint[]
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div
      className="rounded-lg p-3"
      style={{
        backgroundColor: 'rgba(17,24,39,0.95)',
        border: '1px solid rgba(30,40,60,0.7)',
        backdropFilter: 'blur(8px)',
      }}
    >
      <p className="text-[10px] font-mono mb-2" style={{ color: '#475569' }}>{label}</p>
      {payload.map((p: any) => (
        <div key={p.dataKey} className="flex items-center gap-2 text-[10px] font-mono mb-0.5">
          <div className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: p.color }} />
          <span style={{ color: '#64748b' }}>{p.dataKey.toUpperCase()}</span>
          <span className="ml-auto pl-4 font-semibold" style={{ color: p.color }}>{p.value}</span>
        </div>
      ))}
    </div>
  )
}

export function TrendChart({ data }: Props) {
  const sliced = data.slice(-7)

  return (
    <div
      className="rounded-xl p-6"
      style={{
        backgroundColor: 'rgba(17,24,39,0.85)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        border: '1px solid rgba(30,40,60,0.5)',
      }}
    >
      <div className="mb-4">
        <h3
          className="text-[10px] font-sans font-semibold tracking-widest uppercase"
          style={{ color: '#64748b' }}
        >
          Ticket Volume — 7 Days
        </h3>
      </div>

      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={sliced} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <defs>
            <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor="#EF4444" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor="#F97316" stopOpacity={0.2} />
              <stop offset="100%" stopColor="#F97316" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor="#EAB308" stopOpacity={0.15} />
              <stop offset="100%" stopColor="#EAB308" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%"   stopColor="#14B8A6" stopOpacity={0.15} />
              <stop offset="100%" stopColor="#14B8A6" stopOpacity={0} />
            </linearGradient>
          </defs>

          <XAxis
            dataKey="date"
            tick={{ fontSize: 9, fontFamily: 'monospace', fill: '#334155' }}
            tickFormatter={v => v.slice(5)}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            tick={{ fontSize: 9, fontFamily: 'monospace', fill: '#334155' }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />

          <Area type="monotone" dataKey="critical" stroke="#EF4444" strokeWidth={1.5}
            fill="url(#gradCritical)" dot={false} />
          <Area type="monotone" dataKey="high"     stroke="#F97316" strokeWidth={1.5}
            fill="url(#gradHigh)"     dot={false} />
          <Area type="monotone" dataKey="medium"   stroke="#EAB308" strokeWidth={1.5}
            fill="url(#gradMedium)"   dot={false} />
          <Area type="monotone" dataKey="low"      stroke="#14B8A6" strokeWidth={1.5}
            fill="url(#gradLow)"      dot={false} />
        </AreaChart>
      </ResponsiveContainer>

      <div className="flex gap-4 mt-3">
        {[['CRITICAL', '#EF4444'], ['HIGH', '#F97316'], ['MEDIUM', '#EAB308'], ['LOW', '#14B8A6']].map(([label, color]) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-3 h-0.5 rounded" style={{ backgroundColor: color }} />
            <span className="text-[9px] font-mono" style={{ color: '#334155' }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
