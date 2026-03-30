import type { TicketStatus } from '../../types/ticket'

interface Props {
  status: TicketStatus
}

const CONFIG: Record<TicketStatus, { label: string; color: string; bg: string }> = {
  OPEN: { label: 'OPEN', color: '#EF4444', bg: 'rgba(239,68,68,0.1)' },
  IN_PROGRESS: { label: 'IN PROGRESS', color: '#EAB308', bg: 'rgba(234,179,8,0.1)' },
  RESOLVED: { label: 'RESOLVED', color: '#22C55E', bg: 'rgba(34,197,94,0.1)' },
}

export function StatusChip({ status }: Props) {
  const { label, color, bg } = CONFIG[status]
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 text-[10px] font-mono font-semibold rounded-sm"
      style={{ color, backgroundColor: bg, border: `1px solid ${color}30` }}
    >
      {label}
    </span>
  )
}
