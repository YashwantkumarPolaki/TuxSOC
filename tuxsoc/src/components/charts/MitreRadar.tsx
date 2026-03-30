import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, Tooltip } from 'recharts'

interface DataPoint {
  tactic: string
  coverage: number
}

interface Props {
  data: DataPoint[]
}

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div
      className="rounded-lg p-2.5"
      style={{
        backgroundColor: 'rgba(17,24,39,0.95)',
        border: '1px solid rgba(30,40,60,0.7)',
        backdropFilter: 'blur(8px)',
      }}
    >
      <p className="text-[10px] font-mono font-semibold" style={{ color: '#06B6D4' }}>
        {payload[0]?.payload?.tactic}
      </p>
      <p className="text-[10px] font-mono mt-0.5" style={{ color: '#94a3b8' }}>
        {payload[0]?.value}% coverage
      </p>
    </div>
  )
}

export function MitreRadar({ data }: Props) {
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
          MITRE ATT&CK Coverage
        </h3>
      </div>
      <ResponsiveContainer width="100%" height={180}>
        <RadarChart data={data} margin={{ top: 0, right: 20, bottom: 0, left: 20 }}>
          <PolarGrid stroke="rgba(30,40,60,0.6)" />
          <PolarAngleAxis
            dataKey="tactic"
            tick={{ fontSize: 8, fontFamily: 'monospace', fill: '#334155' }}
          />
          <Radar
            name="Coverage"
            dataKey="coverage"
            stroke="#7C3AED"
            fill="#7C3AED"
            fillOpacity={0.18}
            strokeWidth={1.5}
          />
          <Tooltip content={<CustomTooltip />} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  )
}
