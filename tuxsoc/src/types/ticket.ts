export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type TicketStatus = 'OPEN' | 'IN_PROGRESS' | 'RESOLVED'

export interface ActionEntry {
  id: string
  action: string
  status: 'completed' | 'pending' | 'failed'
  timestamp: string
  automated: boolean
}

export interface NoteEntry {
  id: string
  analyst: string
  content: string
  timestamp: string
}

export interface Ticket {
  id: string
  severity: Severity
  status: TicketStatus
  intent: string
  attackerIp: string
  affectedEntity: string
  cvssScore: number
  confidence: number
  source: string
  createdAt: string
  updatedAt: string
  actionsTaken: ActionEntry[]
  recommendations: string[]
  playbookId?: string
  notes: NoteEntry[]
  mitreTactics: string[]
  aiAnalysis: { intent: string | null; summary: string | null; kibanaQuery: string | null } | null
  suggestedPlaybook: {
    id: string
    title: string
    steps: string[]
    autoRemediation: string[]
    phases?: { phase: string; icon: string; color: string; steps: string[] }[]
    killChain?: { stage: string; tactic: string; event: string; severity: string }[]
    doraFlags?: string[]
  } | null
  // Master incident extras
  isMaster?: boolean
  correlatedLogIds?: string[]
  eventCount?: number
  parentIncidentId?: string
}
