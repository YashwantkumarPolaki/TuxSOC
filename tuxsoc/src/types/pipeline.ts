export type LayerStatus = 'ACTIVE' | 'IDLE' | 'ERROR'

export interface PipelineLayer {
  id: string
  name: string
  displayName: string
  status: LayerStatus
  lastEvent: string
  eventsPerMin: number
  recentLogs: string[]
}

export interface LivePipelineEvent {
  layer: string
  eventId: string
  timestamp: string
  status: 'processing' | 'passed' | 'flagged' | 'error'
}
