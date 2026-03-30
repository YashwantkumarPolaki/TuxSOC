/**
 * adapters.ts
 * Maps raw BackendDetection objects → frontend Ticket + PipelineLayer types.
 * This is the single source of truth for the data contract translation.
 */

import type { BackendDetection } from '../types/backend'
import type { Ticket, Severity, TicketStatus, ActionEntry } from '../types/ticket'
import type { PipelineLayer } from '../types/pipeline'

// ── Severity mapping ──────────────────────────────────────────────────────
function deriveSeverity(d: BackendDetection): Severity {
  // If Layer 4 CVSS has scored this event, use its authoritative severity
  if (d.layer4_cvss?.severity) {
    const s = d.layer4_cvss.severity.toUpperCase()
    if (s === 'CRITICAL' || s === 'HIGH' || s === 'MEDIUM' || s === 'LOW') return s as Severity
  }

  const score = d.engine_1_anomaly.anomaly_score
  const action = (d.raw_event.action ?? '').toLowerCase()
  const iocHit = d.engine_2_threat_intel.threat_intel_match

  if (score >= 0.85 || iocHit || /brute.?force|credential.stuff|ransomware|c2|botnet/.test(action))
    return 'CRITICAL'
  if (score >= 0.70 || /lateral.mov|pass.the.hash|exfil|spray|sweep/.test(action))
    return 'HIGH'
  if (score >= 0.55 || d.engine_1_anomaly.ueba_flags.length > 0)
    return 'MEDIUM'
  return 'LOW'
}

// ── CVSS score — Layer 4 base_score takes priority ────────────────────────
function deriveCVSS(d: BackendDetection): number {
  // Use the authoritative Layer 4 score when available
  if (typeof d.layer4_cvss?.base_score === 'number') {
    return parseFloat(Math.min(10, d.layer4_cvss.base_score).toFixed(1))
  }
  // Fallback: approximate from anomaly_score (BACKEND.md formula)
  const base = d.engine_1_anomaly.anomaly_score * 10
  const iocBonus = d.engine_2_threat_intel.threat_intel_match ? 0.5 : 0
  return Math.min(10, parseFloat((base + iocBonus).toFixed(1)))
}

// ── Status ────────────────────────────────────────────────────────────────
function deriveStatus(_d: BackendDetection): TicketStatus {
  return 'OPEN'
}

// ── MITRE tactics — "Unknown" → "Heuristic Anomaly" ──────────────────────
function deriveMitreTactics(d: BackendDetection): string[] {
  const tactic = d.engine_2_threat_intel.mitre_tactic
  if (!tactic || tactic === 'N/A' || tactic === 'Unknown') return ['Heuristic Anomaly']
  return [tactic]
}

// ── Actions taken from engine_3 timeline ─────────────────────────────────
function deriveActions(d: BackendDetection): ActionEntry[] {
  return d.engine_3_correlation.attack_timeline.map((entry, i) => ({
    id: `${d.incident_id}-act-${i}`,
    action: entry.detail,
    status: 'completed' as const,
    timestamp: entry.timestamp,
    automated: true,
  }))
}

// ── Intent string — clean title, no "unknown — Unknown via Unknown" ───────
function deriveIntent(d: BackendDetection): string {
  // Layer 3 AI intent takes highest priority
  if (d.ai_analysis?.intent) return d.ai_analysis.intent

  const action = d.raw_event.action
  const tactic = d.engine_2_threat_intel.mitre_tactic
  const technique = d.engine_2_threat_intel.mitre_technique_name

  // If we have a real action string, use it
  if (action && action !== 'Unknown' && action !== 'N/A') {
    if (tactic && tactic !== 'N/A' && tactic !== 'Unknown'
        && technique && technique !== 'N/A' && technique !== 'Unknown') {
      return `${action} — ${tactic} via ${technique}`
    }
    return action
  }

  // Fallback: synthesise a clean title from log type + source IP
  const logType = d.log_type.charAt(0).toUpperCase() + d.log_type.slice(1)
  const srcIp = d.raw_event.source_ip ?? 'unknown source'
  return `${logType} activity from ${srcIp}`
}

// ── AI Analysis field ─────────────────────────────────────────────────────
function deriveAiAnalysis(d: BackendDetection): Ticket['aiAnalysis'] {
  if (d.ai_analysis === undefined) return null
  if (d.ai_analysis === null) return null
  return {
    intent:      d.ai_analysis.intent,
    summary:     d.ai_analysis.summary,
    kibanaQuery: d.ai_analysis.kibana_query,
  }
}

// ── Suggested playbook from Layer 5 ──────────────────────────────────────
function deriveSuggestedPlaybook(d: BackendDetection): Ticket['suggestedPlaybook'] {
  const pb = d.suggested_playbook
  if (!pb) return null
  return {
    id:              pb.id,
    title:           pb.title,
    steps:           pb.steps,
    autoRemediation: pb.auto_remediation,
    phases:          pb.phases,
    killChain:       pb.kill_chain,
    doraFlags:       pb.dora_flags,   // only present when anomaly_score > 0.7
  }
}

// ── Main adapter ──────────────────────────────────────────────────────────
export function detectionToTicket(d: BackendDetection): Ticket {
  const severity = deriveSeverity(d)
  // Prefer the root affected_user (set on master incidents and injected by Layer 5)
  const affectedUser = d.affected_user
    ?? d.raw_event.affected_user
    ?? d.raw_event.affected_host
    ?? d.raw_event.destination_ip
    ?? 'unknown'

  return {
    id: d.incident_id,
    severity,
    status: deriveStatus(d),
    intent: d.is_master
      ? (d.suggested_playbook?.title ?? deriveIntent(d))
      : deriveIntent(d),
    // Always pull source IP directly from raw_event — no fallback to 'unknown' if present
    attackerIp: d.raw_event.source_ip ?? 'unknown',
    affectedEntity: affectedUser,
    cvssScore: deriveCVSS(d),
    confidence: Math.round(d.engine_1_anomaly.anomaly_score * 100),
    source: d.log_type,
    createdAt: d.timestamp,
    updatedAt: d.timestamp,
    actionsTaken: deriveActions(d),
    recommendations: buildRecommendations(d),
    playbookId: d.suggested_playbook?.id,
    notes: [],
    mitreTactics: deriveMitreTactics(d),
    aiAnalysis: deriveAiAnalysis(d),
    suggestedPlaybook: deriveSuggestedPlaybook(d),
    isMaster: d.is_master,
    correlatedLogIds: d.correlated_log_ids,
    eventCount: d.event_count,
  }
}

function buildRecommendations(d: BackendDetection): string[] {
  const recs: string[] = []
  const action = (d.raw_event.action ?? '').toLowerCase()
  const flags = d.engine_1_anomaly.ueba_flags

  if (/brute.?force|spray/.test(action)) {
    recs.push('🔴 Block source IP at perimeter firewall immediately')
    recs.push('🔐 Force MFA re-enrollment for targeted accounts')
  }
  if (/exfil|outbound.transfer/.test(action)) {
    recs.push('📊 Review all outbound transfers in the last 24h')
    recs.push('🛡️ Apply DLP policy to affected host')
  }
  if (/lateral.mov|pass.the.hash|wmi|winrm/.test(action)) {
    recs.push('🔬 Isolate affected host and capture memory dump')
    recs.push('🌐 Check for C2 beaconing on ports 443/8443/4444')
  }
  if (flags.includes('off_hours_activity')) {
    recs.push('⏰ Investigate off-hours access — verify with user')
  }
  if (d.engine_2_threat_intel.threat_intel_match) {
    recs.push('🚨 IOC match confirmed — escalate to CISO immediately')
  }
  if (d.layer4_cvss?.requires_auto_block) {
    recs.push('🛑 Layer 4 CVSS: auto-block recommended — review firewall rules')
  }
  if (recs.length === 0) {
    recs.push('📋 Review event context and correlate with SIEM')
  }
  return recs
}

function mapToPlaybook(d: BackendDetection): string | undefined {
  const action = (d.raw_event.action ?? '').toLowerCase()
  if (/brute.?force|spray|credential/.test(action)) return 'PB-001'
  if (/sql.inject|sqli/.test(action)) return 'PB-002'
  if (/ransomware|dropper|payload/.test(action)) return 'PB-003'
  if (/swift|transaction|transfer/.test(action)) return 'PB-004'
  return undefined
}

// ── Pipeline layer health from detections ────────────────────────────────
export function derivePipelineHealth(
  detections: BackendDetection[],
  baseLayer: PipelineLayer,
  _layerIndex: number,
): PipelineLayer {
  if (detections.length === 0) return { ...baseLayer, status: 'IDLE' }

  const latest = detections[0]
  const hasError = detections.some(d =>
    d.engine_1_anomaly.anomaly_score === 0 && d.engine_3_correlation.event_count === 0
  )

  const eventsPerMin = Math.max(1, detections.length * 2)
  const lastEventId = latest.incident_id.split('-').slice(-1)[0]
  const lastEvent = `${lastEventId} • just now`

  const recentLogs = detections
    .slice(0, 3)
    .flatMap(d => d.engine_3_correlation.attack_timeline.slice(0, 2))
    .map(e => `[${e.event.toUpperCase()}] ${e.detail}`)
    .slice(0, 5)

  return {
    ...baseLayer,
    status: hasError ? 'ERROR' : 'ACTIVE',
    lastEvent,
    eventsPerMin,
    recentLogs: recentLogs.length > 0 ? recentLogs : baseLayer.recentLogs,
  }
}
