/**
 * TypeScript contracts derived from the Python backend schemas.
 * Matches: fastapi_receiver.py → build_output(), response_formatter.py → format_enriched_log()
 */

// ── /health ──────────────────────────────────────────────────────────────
export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'error'
  service: string
}

// ── /ingest_file response ─────────────────────────────────────────────────
export interface RawEvent {
  source_ip:       string | null
  destination_ip:  string | null
  affected_user:   string | null
  affected_host:   string | null
  port:            number | null
  protocol:        string | null
  action:          string | null
  timestamp:       string
}

export interface Engine1Anomaly {
  pyod_score:      number
  is_outlier:      boolean
  ueba_flags:      string[]
  anomaly_score:   number
  anomaly_flagged: boolean
}

export interface Engine2ThreatIntel {
  ioc_matches:          string[]
  threat_intel_match:   boolean
  mitre_tactic:         string
  mitre_technique:      string
  mitre_technique_name: string
  // Real mitre_mapper fields (populated when layer_2_detection.inmemory_engine runs)
  mitre_url?:           string
  rule_id?:             string
  rule_name?:           string
  rule_confidence?:     number
}

export interface TimelineEntry {
  timestamp: string
  event:     string
  detail:    string
}

export interface Engine3Correlation {
  event_count:     number
  attack_timeline: TimelineEntry[]
}

// ── Layer 4 CVSS output (from layer_4_cvss.inmemory_cvss) ────────────────
export interface Layer4Cvss {
  base_score:          number   // 0.0–10.0 — the authoritative CVSS score
  severity:            string   // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  requires_auto_block: boolean
  dora_compliance:     boolean | null  // true=DORA triggered, false=not applicable, null=uncertain
  cvss_vector?:        string   // CVSS:3.1/AV:N/AC:L/... (when real scorer runs)
}

// ── Layer 3 AI Analysis placeholder ──────────────────────────────────────
export interface AiAnalysis {
  intent:        string | null
  kibana_query:  string | null
  summary:       string | null
}

// ── Layer 5 Playbook ──────────────────────────────────────────────────────
export interface KillChainStage {
  stage:    string
  tactic:   string
  event:    string
  severity: string
}

export interface PlaybookPhase {
  phase: string
  icon:  string
  color: string
  steps: string[]
}

export interface SuggestedPlaybook {
  id:               string
  title:            string
  steps:            string[]
  auto_remediation: string[]
  tactic_match:     string[]
  severity_floor:   string
  // BEC master playbook extras (optional)
  phases?:          PlaybookPhase[]
  kill_chain?:      KillChainStage[]
  dora_flags?:      string[]
}

/** One detection result from /ingest_file → detections[] */
export interface BackendDetection {
  incident_id:          string
  timestamp:            string
  log_type:             'network' | 'endpoint' | 'auth' | 'firewall' | 'iot'
  format?:              string
  raw_event:            RawEvent
  engine_1_anomaly:     Engine1Anomaly
  engine_2_threat_intel: Engine2ThreatIntel
  engine_3_correlation: Engine3Correlation
  layer4_cvss?:         Layer4Cvss
  ai_analysis?:         AiAnalysis | null
  suggested_playbook?:  SuggestedPlaybook
  // Master incident fields (present when is_master = true)
  is_master?:           boolean
  correlated_log_ids?:  string[]
  affected_user?:       string
  event_count?:         number
}

export interface IngestFileResponse {
  status:          'success' | 'error'
  file:            string
  total_processed: number
  detections:      BackendDetection[]
}

// ── Derived pipeline layer health ─────────────────────────────────────────
export type LayerHealth = 'ACTIVE' | 'IDLE' | 'ERROR'

export interface LayerHealthMap {
  layer_0_ingestion:    LayerHealth
  layer_1_feature_eng:  LayerHealth
  layer_2_detection:    LayerHealth
}
