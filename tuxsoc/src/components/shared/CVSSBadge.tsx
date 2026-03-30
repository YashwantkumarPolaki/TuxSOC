import { getCVSSColor } from '../../utils/severity'

interface Props {
  score: number
  size?: 'sm' | 'md'
}

export function CVSSBadge({ score, size = 'md' }: Props) {
  const color = getCVSSColor(score)
  const dim = size === 'sm' ? 32 : 40
  const fontSize = size === 'sm' ? 9 : 11
  const radius = dim / 2 - 3
  const circumference = 2 * Math.PI * radius
  const progress = (score / 10) * circumference

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: dim, height: dim }}>
      <svg width={dim} height={dim} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={dim / 2} cy={dim / 2} r={radius} fill="none" stroke="#1E2235" strokeWidth={2.5} />
        <circle
          cx={dim / 2} cy={dim / 2} r={radius}
          fill="none"
          stroke={color}
          strokeWidth={2.5}
          strokeDasharray={`${progress} ${circumference}`}
          strokeLinecap="round"
        />
      </svg>
      <span
        className="absolute font-mono font-bold"
        style={{ fontSize, color, lineHeight: 1 }}
      >
        {score.toFixed(1)}
      </span>
    </div>
  )
}
