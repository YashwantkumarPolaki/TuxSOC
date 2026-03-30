import { motion } from 'framer-motion'
import { useCountUp } from '../../hooks/useCountUp'
import type { LucideIcon } from 'lucide-react'

interface Props {
  label: string
  value: number
  unit?: string
  decimals?: number
  icon: LucideIcon
  color?: 'default' | 'critical' | 'green' | 'cyan' | 'purple'
  trend?: 'up' | 'down' | 'neutral'
  trendValue?: string
}

const COLOR_MAP = {
  default: { accent: '#94a3b8', glow: 'none' },
  critical: { accent: '#EF4444', glow: '0 0 20px rgba(239,68,68,0.35)' },
  green:    { accent: '#22C55E', glow: '0 0 16px rgba(34,197,94,0.2)' },
  cyan:     { accent: '#06B6D4', glow: '0 0 16px rgba(6,182,212,0.2)' },
  purple:   { accent: '#7C3AED', glow: '0 0 16px rgba(124,58,237,0.2)' },
}

export function KPICard({ label, value, unit, decimals = 0, icon: Icon, color = 'default', trend, trendValue }: Props) {
  const displayValue = decimals > 0 ? value : Math.round(value)
  const animated = useCountUp(displayValue)
  const { accent, glow } = COLOR_MAP[color]

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: 'easeOut' }}
      className="p-6 rounded-xl flex flex-col gap-4"
      style={{
        backgroundColor: 'rgba(17,24,39,0.85)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        border: `1px solid rgba(30,40,60,0.5)`,
        boxShadow: glow,
      }}
    >
      {/* Label + icon row */}
      <div className="flex items-center justify-between">
        <span
          className="text-[10px] font-sans font-semibold tracking-widest uppercase"
          style={{ color: '#64748b' }}
        >
          {label}
        </span>
        <div
          className="p-2 rounded-lg"
          style={{ backgroundColor: `${accent}18`, border: `1px solid ${accent}25` }}
        >
          <Icon size={13} color={accent} strokeWidth={2} />
        </div>
      </div>

      {/* Value */}
      <div className="flex items-end gap-2 leading-none">
        <span
          className="text-4xl font-bold font-mono"
          style={{ color: accent, textShadow: color === 'critical' ? `0 0 20px rgba(239,68,68,0.5)` : 'none' }}
        >
          {decimals > 0 ? (animated / Math.pow(10, decimals)).toFixed(decimals) : animated}
        </span>
        {unit && (
          <span className="text-sm font-mono mb-1" style={{ color: '#475569' }}>
            {unit}
          </span>
        )}
      </div>

      {/* Trend */}
      {trend && trendValue && (
        <div className="flex items-center gap-1.5">
          <span
            className="text-[10px] font-mono"
            style={{
              color: trend === 'up' ? '#EF4444' : trend === 'down' ? '#22C55E' : '#64748b',
            }}
          >
            {trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→'} {trendValue}
          </span>
        </div>
      )}
    </motion.div>
  )
}
