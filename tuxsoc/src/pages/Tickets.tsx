import { motion } from 'framer-motion'
import { Terminal, Brain, ExternalLink, Shield } from 'lucide-react'
import type { BackendState } from '../hooks/useBackendData'
import type { BackendDetection } from '../types/backend'

interface Props {
  state: BackendState
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#EF4444', HIGH: '#F97316', MEDIUM: '#EAB308', LOW: '#14B8A6',
}

function scoreColor(s: number) {
  if (s >= 0.85) return '#EF4444'
  if (s >= 0.70) return '#F97316'
  if (s >= 0.55) return '#EAB308'
  return '#14B8A6'
}

function Row({ label, value, color }: { label: string; value: string | number | null | undefined; color?: string }) {
  const display = value === null || value === undefined || value === '' ? 'null' : String(value)
  const isNull  = display === 'null'
  return (
    <div className="flex items-baseline gap-2 py-0.5">
      <span className="text-[10px] font-mono w-36 shrink-0" style={{ color: '#334155' }}>{label}</span>
      <span className="text-[11px] font-mono break-all"
        style={{ color: isNull ? '#1e3a5f' : (color ?? '#94a3b8') }}>
        {isNull ? 'null' : display}
      </span>
    </div>
  )
}

function Divider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 mt-3 mb-1">
      <span className="text-[9px] font-mono font-bold tracking-widest uppercase"
        style={{ color: '#1e3a5f' }}>── {label}</span>
      <div className="flex-1 h-px" style={{ backgroundColor: 'rgba(30,40,60,0.6)' }} />
    </div>
  )
}

function DetectionCard({ d, i }: { d: BackendDetection & { _layer1?: any; _layer2_risk?: any }; i: number }) {
  const e1   = d.engine_1_anomaly
  const e2   = d.engine_2_threat_intel
  const l1   = d._layer1 || {}
  const l2r  = d._layer2_risk || {}
  const l4   = d.layer4_cvss
  const ai   = d.ai_analysis

  const riskSev  = l2r.severity || 'LOW'
  const accentColor = SEV_COLOR[riskSev] ?? '#14B8A6'

  // Layer 1 feature blocks
  const temporal    = l1.temporal_features    || {}
  const behavioral  = l1.behavioral_features  || {}
  const identity    = l1.identity_features    || {}

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: i * 0.03, duration: 0.2 }}
      className="rounded-lg p-4"
      style={{
        backgroundColor: 'rgba(11,15,20,0.95)',
        border: '1px solid rgba(30,40,60,0.5)',
        boxShadow: `inset 3px 0 0 ${accentColor}`,
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono font-bold" style={{ color: '#3B82F6' }}>
          {d.incident_id}
        </span>
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm"
            style={{ color: accentColor, backgroundColor: `${accentColor}18`, border: `1px solid ${accentColor}40` }}>
            {riskSev}
          </span>
          {l2r.risk_score !== undefined && (
            <span className="text-[9px] font-mono" style={{ color: '#475569' }}>
              risk {l2r.risk_score}
            </span>
          )}
          <span className="text-[9px] font-mono" style={{ color: '#334155' }}>
            {new Date(d.timestamp).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {/* ── Layer 0 / Log Classifier ── */}
      <Divider label="Layer 0 — Log Classifier" />
      <Row label="log_type"   value={d.log_type}  color="#7C3AED" />
      <Row label="log_family" value={l1.log_family} />
      <Row label="format"     value={d.format} />
      <Row label="conf"       value={l1.classification_conf} />

      {/* ── Layer 0 / Network ── */}
      <Divider label="Network Features" />
      <Row label="source_ip"      value={d.raw_event.source_ip}      color="#3B82F6" />
      <Row label="destination_ip" value={d.raw_event.destination_ip} color="#3B82F6" />
      <Row label="port"           value={d.raw_event.port} />
      <Row label="protocol"       value={d.raw_event.protocol} />
      <Row label="action"         value={d.raw_event.action} />

      {/* ── Layer 0 / Entity ── */}
      <Divider label="Entity Context" />
      <Row label="affected_user" value={d.raw_event.affected_user} color="#22C55E" />
      <Row label="affected_host" value={d.raw_event.affected_host} color="#22C55E" />

      {/* ── Layer 1 / Temporal ── */}
      <Divider label="Layer 1 — Temporal Features" />
      <Row label="event_count_1m"  value={temporal.event_count_1m} />
      <Row label="event_count_1h"  value={temporal.event_count_1h} />
      <Row label="is_off_hours"    value={temporal.is_off_hours != null ? String(temporal.is_off_hours) : null}
           color={temporal.is_off_hours ? '#EAB308' : undefined} />
      <Row label="is_first_seen"   value={temporal.is_first_seen_source != null ? String(temporal.is_first_seen_source) : null} />
      <Row label="freq_accel"      value={temporal.is_frequency_accelerating != null ? String(temporal.is_frequency_accelerating) : null}
           color={temporal.is_frequency_accelerating ? '#F97316' : undefined} />

      {/* ── Layer 1 / Behavioral ── */}
      <Divider label="Layer 1 — Behavioral Features" />
      <Row label="deviation_score"    value={behavioral.deviation_score != null ? Number(behavioral.deviation_score).toFixed(3) : null}
           color={scoreColor(behavioral.deviation_score ?? 0)} />
      <Row label="is_new_ip_for_user" value={behavioral.is_new_ip_for_user != null ? String(behavioral.is_new_ip_for_user) : null}
           color={behavioral.is_new_ip_for_user ? '#EAB308' : undefined} />
      <Row label="is_new_user"        value={behavioral.is_new_user != null ? String(behavioral.is_new_user) : null} />
      <Row label="excessive_fails"    value={behavioral.excessive_failed_logins != null ? String(behavioral.excessive_failed_logins) : null}
           color={behavioral.excessive_failed_logins ? '#EF4444' : undefined} />

      {/* ── Layer 1 / Identity (Azure/O365) ── */}
      {identity.is_identity_event && (
        <>
          <Divider label="Layer 1 — Identity Features" />
          <Row label="risk_state"       value={identity.risk_state}  color={identity.is_risky_signin ? '#EF4444' : undefined} />
          <Row label="risk_level"       value={identity.risk_level}  color={identity.risk_level === 'high' ? '#EF4444' : undefined} />
          <Row label="is_risky_signin"  value={identity.is_risky_signin != null ? String(identity.is_risky_signin) : null}
               color={identity.is_risky_signin ? '#EF4444' : undefined} />
          <Row label="suspicious_ip"    value={identity.has_suspicious_ip_flag != null ? String(identity.has_suspicious_ip_flag) : null}
               color={identity.has_suspicious_ip_flag ? '#EF4444' : undefined} />
          <Row label="location"         value={identity.location} />
          <Row label="client_app"       value={identity.client_app_used} />
        </>
      )}

      {/* ── Layer 2 / Anomaly Scores ── */}
      <Divider label="Layer 2 — Anomaly Scores" />
      <Row label="pyod_score"      value={e1.pyod_score.toFixed(4)}    color={scoreColor(e1.pyod_score)} />
      <Row label="anomaly_score"   value={e1.anomaly_score.toFixed(4)} color={scoreColor(e1.anomaly_score)} />
      <Row label="is_outlier"      value={String(e1.is_outlier)} />
      <Row label="anomaly_flagged" value={String(e1.anomaly_flagged)} />
      {e1.ueba_flags.length > 0 && (
        <Row label="ueba_flags" value={e1.ueba_flags.join(', ')} color="#EAB308" />
      )}

      {/* ── Layer 2 / Threat Intel ── */}
      <Divider label="Layer 2 — Threat Intel" />
      <Row label="rule_id"      value={e2.rule_id}    color="#7C3AED" />
      {/* Rule name replaces the old generic "Summary" label */}
      <Row label="rule_name"    value={e2.rule_name}  color="#e2e8f0" />
      <Row label="confidence"   value={e2.rule_confidence != null ? `${(e2.rule_confidence * 100).toFixed(0)}%` : null} />
      <Row label="mitre_tactic" value={e2.mitre_tactic} color={e2.mitre_tactic !== 'Unknown' ? '#F97316' : undefined} />
      {/* Technique ID + clickable MITRE ATT&CK link */}
      <div className="flex items-baseline gap-2 py-0.5">
        <span className="text-[10px] font-mono w-36 shrink-0" style={{ color: '#334155' }}>mitre_technique</span>
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-[11px] font-mono" style={{ color: '#94a3b8' }}>
            {e2.mitre_technique !== 'Unknown' ? e2.mitre_technique : 'null'}
          </span>
          {e2.mitre_technique && e2.mitre_technique !== 'Unknown' && (
            <a
              href={e2.mitre_url || `https://attack.mitre.org/techniques/${e2.mitre_technique.replace('.', '/')}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-0.5 px-1 py-0.5 rounded transition-opacity hover:opacity-80"
              style={{ backgroundColor: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.3)' }}
              title={`View ${e2.mitre_technique} on MITRE ATT&CK`}
            >
              <ExternalLink size={8} style={{ color: '#F97316' }} />
              <span className="text-[8px] font-mono font-bold" style={{ color: '#F97316' }}>ATT&CK</span>
            </a>
          )}
        </div>
      </div>
      <Row label="technique_name" value={e2.mitre_technique_name} />
      <Row label="ioc_match"      value={String(e2.threat_intel_match)} color={e2.threat_intel_match ? '#EF4444' : undefined} />

      {/* ── Layer 4 / CVSS ── */}
      {l4 && (
        <>
          <Divider label="Layer 4 — CVSS Score" />
          <div className="flex items-baseline gap-2 py-0.5">
            <span className="text-[10px] font-mono w-36 shrink-0" style={{ color: '#334155' }}>base_score</span>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[11px] font-mono font-bold" style={{ color: scoreColor(l4.base_score / 10) }}>
                {l4.base_score.toFixed(1)}
              </span>
              {l4.cvss_vector && (
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(30,40,60,0.6)', color: '#475569', letterSpacing: '0.02em' }}>
                  {l4.cvss_vector}
                </span>
              )}
            </div>
          </div>
          <Row label="severity"   value={l4.severity}              color={SEV_COLOR[l4.severity]} />
          <Row label="auto_block" value={String(l4.requires_auto_block)} color={l4.requires_auto_block ? '#EF4444' : undefined} />
          <Row label="dora"       value={
            l4.dora_compliance === true  ? 'TRIGGERED' :
            l4.dora_compliance === false ? 'not applicable' : 'pending review'
          } color={l4.dora_compliance === true ? '#EAB308' : undefined} />
        </>
      )}

      {/* ── Layer 3 / AI Analysis ── */}
      <Divider label="Layer 3 — AI Analysis" />
      <div className="flex items-center gap-1 mb-1">
        <Brain size={9} style={{ color: '#7C3AED' }} />
        <span className="text-[9px] font-mono" style={{ color: '#7C3AED' }}>LAYER 3</span>
      </div>
      {ai?.intent ? (
        <p className="text-[11px] font-mono leading-relaxed" style={{ color: '#94a3b8' }}>{ai.intent}</p>
      ) : ai?.summary ? (
        <p className="text-[11px] font-mono leading-relaxed" style={{ color: '#94a3b8' }}>{ai.summary}</p>
      ) : e2.rule_name ? (
        /* Fallback: show rule_name from Layer 2 when AI is offline */
        <div className="flex items-center gap-1.5">
          <Shield size={9} style={{ color: '#475569' }} />
          <p className="text-[11px] font-mono" style={{ color: '#475569' }}>
            {e2.rule_name}
            <span className="ml-1 text-[9px]" style={{ color: '#1e3a5f' }}>(rule match — AI offline)</span>
          </p>
        </div>
      ) : (
        <p className="text-[11px] font-mono italic" style={{ color: '#1e3a5f' }}>
          Layer 3: Analysis in progress...
        </p>
      )}
    </motion.div>
  )
}

export function Tickets({ state }: Props) {
  const detections = state.rawDetections as Array<BackendDetection & { _layer1?: any; _layer2_risk?: any }>

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="p-8 space-y-6"
      style={{ backgroundColor: '#0B0F14', minHeight: '100%' }}
    >
      {/* Header */}
      <div className="flex justify-between items-end border-b pb-6"
        style={{ borderColor: 'rgba(30,40,60,0.6)' }}>
        <div>
          <h1 className="text-lg font-mono font-bold tracking-widest uppercase mb-1"
            style={{ color: '#e2e8f0' }}>
            Pipeline Debug View
          </h1>
          <p className="text-[11px] font-mono" style={{ color: '#334155' }}>
            Layer 1 enrichment + Layer 2 detection · one card per log line
          </p>
        </div>
        <div className="text-right">
          <div className="text-[9px] font-mono uppercase tracking-widest mb-1" style={{ color: '#334155' }}>
            Detections
          </div>
          <div className="text-2xl font-mono" style={{ color: '#3B82F6' }}>{detections.length}</div>
        </div>
      </div>

      {/* Cards */}
      <div className="grid gap-3">
        {detections.length === 0 ? (
          <div className="py-20 text-center border border-dashed rounded-xl"
            style={{ borderColor: 'rgba(30,40,60,0.6)' }}>
            <p className="text-[11px] font-mono" style={{ color: '#334155' }}>
              [IDLE] — Upload a log file via Log Ingest to populate this view
            </p>
          </div>
        ) : (
          detections.map((d, i) => <DetectionCard key={d.incident_id} d={d} i={i} />)
        )}
      </div>

      {/* Status bar */}
      <div className="p-3 rounded-lg flex items-center gap-3"
        style={{ backgroundColor: 'rgba(17,24,39,0.5)', border: '1px solid rgba(30,40,60,0.4)' }}>
        <Terminal size={13} style={{ color: '#334155' }} />
        <p className="text-[10px] font-mono" style={{ color: '#334155' }}>
          source: <span style={{ color: '#3B82F6' }}>useBackendData.rawDetections</span>
          {' '}·{' '}
          pipeline: <span style={{ color: '#22C55E' }}>Layer 0 → 1 → 2 → 3 → 4</span>
          {' '}·{' '}
          last sync: <span style={{ color: '#475569' }}>{state.lastSynced.toLocaleTimeString()}</span>
        </p>
      </div>
    </motion.div>
  )
}
