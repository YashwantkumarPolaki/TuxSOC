export type RevisedSeverity = 'Low' | 'Medium' | 'High' | 'Critical'

export interface FidelityResult {
  event_name:          string
  explanation:         string
  recommended_actions: string[]
  revised_severity:    RevisedSeverity
  original_ip:         string
  original_user:       string
  original_action:     string
  original_severity:   string
}

export interface NoisyIngestResponse {
  status:          string
  file:            string
  total_processed: number
  results:         FidelityResult[]
}
