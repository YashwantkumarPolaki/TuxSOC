import type { Severity } from '../../types/ticket'
import { getSeverityColor, getSeverityBg } from '../../utils/severity'

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const color = getSeverityColor(severity)
  const bg = getSeverityBg(severity)
  const px = size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs'

  return (
    <span
      className={`inline-flex items-center gap-1 font-mono font-semibold rounded-sm ${px}`}
      style={{ color, backgroundColor: bg, border: `1px solid ${color}30` }}
    >
      <span
        className="inline-block rounded-full"
        style={{ width: 5, height: 5, backgroundColor: color }}
      />
      {severity}
    </span>
  )
}
