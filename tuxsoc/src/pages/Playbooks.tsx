import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, ChevronRight, Zap, AlertTriangle,
  BookOpen, GitBranch, AlertCircle
} from 'lucide-react'
import type { BackendState } from '../hooks/useBackendData'
import type { Ticket } from '../types/ticket'

interface Props { state: BackendState }

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#EF4444', HIGH: '#F97316', MEDIUM: '#EAB308', LOW: '#14B8A6',
}

// ── Attack Path Timeline (left column for master incidents) ───────────────
function AttackPath({ ticket }: { ticket: Ticket }) {
  const kc = ticket.suggestedPlaybook?.killChain

  return (
    <div className="flex flex-col gap-0">
      <div className="flex items-center gap-2 mb-4">
        <GitBranch size={12} style={{ color: '#EF4444' }} />
        <span className="text-[9px] font-mono font-bold tracking-widest uppercase"
          style={{ color: '#EF4444' }}>Attack Path</span>
      </div>

      {/* Kill chain stages */}
      {kc && kc.map((stage, i) => {
        const color = SEV_COLOR[stage.severity] ?? '#475569'
        const isLast = i === kc.length - 1
        return (
          <div key={i} className="flex gap-3">
            {/* Connector line */}
            <div className="flex flex-col items-center">
              <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 z-10"
                style={{ backgroundColor: `${color}20`, border: `1px solid ${color}60` }}>
                <span className="text-[8px] font-mono font-bold" style={{ color }}>{i + 1}</span>
              </div>
              {!isLast && <div className="w-px flex-1 my-1" style={{ backgroundColor: 'rgba(30,40,60,0.6)', minHeight: 24 }} />}
            </div>
            {/* Stage content */}
            <div className={`pb-4 ${isLast ? '' : ''}`}>
              <div className="text-[8px] font-mono font-bold uppercase tracking-widest mb-0.5"
                style={{ color }}>
                {stage.stage}
              </div>
              <div className="text-[10px] font-mono leading-snug mb-1" style={{ color: '#94a3b8' }}>
                {stage.event}
              </div>
              <div className="text-[9px] font-mono" style={{ color: '#334155' }}>
                {stage.tactic}
              </div>
            </div>
          </div>
        )
      })}

      {/* DORA flags */}
      {ticket.suggestedPlaybook?.doraFlags && ticket.suggestedPlaybook.doraFlags.length > 0 && (
        <div className="mt-4 p-3 rounded-lg"
          style={{ backgroundColor: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)' }}>
          <div className="text-[9px] font-mono font-bold uppercase tracking-widest mb-2"
            style={{ color: '#EAB308' }}>⚖️ DORA Flags</div>
          {ticket.suggestedPlaybook.doraFlags.map((flag, i) => (
            <div key={i} className="flex items-start gap-1.5 mb-1">
              <AlertCircle size={9} className="shrink-0 mt-0.5" style={{ color: '#EAB308' }} />
              <p className="text-[9px] font-mono leading-snug" style={{ color: '#92400e' }}>{flag}</p>
            </div>
          ))}
        </div>
      )}

      {/* Correlated event count */}
      {ticket.isMaster && (
        <div className="mt-4 p-3 rounded-lg"
          style={{ backgroundColor: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.2)' }}>
          <div className="text-[9px] font-mono" style={{ color: '#334155' }}>
            <span style={{ color: '#3B82F6' }}>{ticket.eventCount ?? '?'} log events</span> correlated into this master incident
          </div>
          {ticket.correlatedLogIds && (
            <div className="mt-1 flex flex-wrap gap-1">
              {ticket.correlatedLogIds.slice(0, 4).map(id => (
                <span key={id} className="text-[8px] font-mono px-1 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(30,40,60,0.5)', color: '#475569' }}>
                  {id.slice(-8)}
                </span>
              ))}
              {(ticket.correlatedLogIds.length > 4) && (
                <span className="text-[8px] font-mono" style={{ color: '#334155' }}>
                  +{ticket.correlatedLogIds.length - 4} more
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Build analyst narrative from steps + ticket context ───────────────────
function buildNarrative(steps: string[], ticket: Ticket): string {
  if (steps.length === 0) return 'No response steps defined.'

  const ip = ticket.attackerIp || 'the source host'
  const entity = ticket.affectedEntity || 'the affected system'
  const tactic = ticket.mitreTactics[0] || 'the detected threat'
  const sev = ticket.severity
  const count = ticket.eventCount ?? 1

  // Split steps into phases: immediate (first 2), investigation (middle), closure (last)
  const immediate   = steps.slice(0, 2)
  const investigate = steps.slice(2, steps.length - 1)
  const closure     = steps[steps.length - 1]

  const countPhrase = count > 1
    ? `A ${sev} severity incident has been confirmed across ${count} correlated log events`
    : `A ${sev} severity incident has been detected`

  const intro = `${countPhrase}, with ${tactic} activity originating from ${ip} targeting ${entity}.`

  const immediatePart = immediate.length > 0
    ? ` The immediate priority is to ${immediate[0].charAt(0).toLowerCase()}${immediate[0].slice(1)}${
        immediate[1] ? `, and to ${immediate[1].charAt(0).toLowerCase()}${immediate[1].slice(1)}` : ''
      }.`
    : ''

  const investigatePart = investigate.length > 0
    ? ` During the investigation phase, analysts should ${
        investigate
          .map((s, i) => {
            const lower = s.charAt(0).toLowerCase() + s.slice(1)
            if (i === 0) return lower
            if (i === investigate.length - 1) return `and ${lower}`
            return lower
          })
          .join(', ')
      }.`
    : ''

  const closurePart = closure
    ? ` To close the incident, ${closure.charAt(0).toLowerCase()}${closure.slice(1)}.`
    : ''

  return `${intro}${immediatePart}${investigatePart}${closurePart}`
}

// ── Phased playbook viewer ────────────────────────────────────────────────
function PhasedPlaybook({ ticket }: { ticket: Ticket }) {
  const pb = ticket.suggestedPlaybook!
  const phases = pb.phases

  if (!phases || phases.length === 0) {
    const narrative = buildNarrative(pb.steps, ticket)

    return (
      <div className="rounded-xl overflow-hidden"
        style={{ backgroundColor: 'rgba(11,15,20,0.95)', border: '1px solid rgba(30,40,60,0.5)' }}>
        <div className="px-5 py-3 flex items-center gap-2"
          style={{ borderBottom: '1px solid rgba(30,40,60,0.5)', backgroundColor: 'rgba(17,24,39,0.6)' }}>
          <BookOpen size={12} style={{ color: '#3B82F6' }} />
          <span className="text-[9px] font-mono font-bold tracking-widest uppercase"
            style={{ color: '#64748b' }}>Response Steps</span>
        </div>
        <div className="p-5">
          <p className="text-[11px] font-mono leading-loose" style={{ color: '#94a3b8' }}>{narrative}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      {phases.map((phase, pi) => (
        <motion.div
          key={pi}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: pi * 0.08, duration: 0.2 }}
          className="rounded-xl overflow-hidden"
          style={{ backgroundColor: 'rgba(11,15,20,0.95)', border: `1px solid ${phase.color}25` }}
        >
          <div className="px-5 py-3 flex items-center gap-2"
            style={{ borderBottom: `1px solid ${phase.color}20`, backgroundColor: `${phase.color}08` }}>
            <span className="text-sm">{phase.icon}</span>
            <span className="text-[10px] font-mono font-bold" style={{ color: phase.color }}>
              {phase.phase}
            </span>
          </div>
          <div className="p-4 flex flex-col gap-2">
            {phase.steps.map((step, si) => (
              <div key={si} className="flex items-start gap-3">
                <span className="shrink-0 w-5 h-5 rounded flex items-center justify-center text-[9px] font-mono font-bold mt-0.5"
                  style={{ backgroundColor: `${phase.color}18`, color: phase.color }}>
                  {si + 1}
                </span>
                <p className="text-[11px] font-mono leading-relaxed" style={{ color: '#94a3b8' }}>{step}</p>
              </div>
            ))}
          </div>
        </motion.div>
      ))}
    </div>
  )
}

// ── Full playbook viewer ──────────────────────────────────────────────────
function PlaybookViewer({ ticket }: { ticket: Ticket }) {
  const pb = ticket.suggestedPlaybook
  if (!pb) return (
    <div className="flex items-center justify-center h-48">
      <p className="text-[11px] font-mono" style={{ color: '#334155' }}>No playbook assigned.</p>
    </div>
  )

  const sevColor = SEV_COLOR[ticket.severity] ?? '#14B8A6'
  const isMaster = ticket.isMaster

  return (
    <motion.div
      key={ticket.id}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="flex flex-col gap-5"
    >
      {/* Header */}
      <div className="rounded-xl p-5"
        style={{ backgroundColor: 'rgba(17,24,39,0.9)', border: `1px solid ${sevColor}40` }}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm"
                style={{ color: sevColor, backgroundColor: `${sevColor}18`, border: `1px solid ${sevColor}40` }}>
                {ticket.severity}
              </span>
              {isMaster && (
                <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded-sm"
                  style={{ color: '#7C3AED', backgroundColor: 'rgba(124,58,237,0.15)', border: '1px solid rgba(124,58,237,0.3)' }}>
                  MASTER INCIDENT
                </span>
              )}
              <span className="text-[9px] font-mono" style={{ color: '#334155' }}>{pb.id}</span>
            </div>
            <h2 className="text-sm font-mono font-bold leading-snug" style={{ color: '#e2e8f0' }}>
              {pb.title}
            </h2>
            {isMaster && (
              <p className="text-[10px] font-mono mt-1" style={{ color: '#475569' }}>
                {ticket.eventCount} correlated events · user: {ticket.affectedEntity}
              </p>
            )}
          </div>
          <div className="text-right shrink-0">
            <div className="text-[9px] font-mono" style={{ color: '#334155' }}>CVSS</div>
            <div className="text-lg font-mono font-bold" style={{ color: sevColor }}>
              {ticket.cvssScore.toFixed(1)}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3 mt-4 pt-4"
          style={{ borderTop: '1px solid rgba(30,40,60,0.5)' }}>
          {[
            { label: 'Source IP',    value: ticket.attackerIp },
            { label: 'Affected',     value: ticket.affectedEntity },
            { label: 'MITRE Tactic', value: ticket.mitreTactics[0] || 'Unknown' },
          ].map(({ label, value }) => (
            <div key={label}>
              <div className="text-[9px] font-mono uppercase tracking-widest mb-0.5"
                style={{ color: '#334155' }}>{label}</div>
              <div className="text-[10px] font-mono truncate" style={{ color: '#64748b' }}>{value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Two-column layout for master incidents */}
      {isMaster && pb.killChain ? (
        <div className="grid grid-cols-5 gap-5">
          {/* Attack path — left */}
          <div className="col-span-2 rounded-xl p-4"
            style={{ backgroundColor: 'rgba(11,15,20,0.95)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <AttackPath ticket={ticket} />
          </div>
          {/* Phased playbook — right */}
          <div className="col-span-3">
            <PhasedPlaybook ticket={ticket} />
          </div>
        </div>
      ) : (
        <PhasedPlaybook ticket={ticket} />
      )}

      {/* Auto-remediation */}
      {pb.autoRemediation.length > 0 && (
        <div className="rounded-xl overflow-hidden"
          style={{ backgroundColor: 'rgba(11,15,20,0.95)', border: '1px solid rgba(239,68,68,0.2)' }}>
          <div className="px-5 py-3 flex items-center gap-2"
            style={{ borderBottom: '1px solid rgba(239,68,68,0.15)', backgroundColor: 'rgba(239,68,68,0.05)' }}>
            <Zap size={12} style={{ color: '#EF4444' }} />
            <span className="text-[9px] font-mono font-bold tracking-widest uppercase"
              style={{ color: '#EF4444' }}>Auto-Remediation Actions</span>
          </div>
          <div className="p-5">
            <p className="text-[11px] font-mono leading-loose" style={{ color: '#64748b' }}>
              {(() => {
                const actions = pb.autoRemediation
                if (actions.length === 0) return 'No automated actions configured.'
                const ip = ticket.attackerIp || 'the threat source'
                const first = `In response to the detected activity from ${ip}, the following automated actions have been triggered: ${actions[0].charAt(0).toLowerCase()}${actions[0].slice(1)}`
                const rest = actions.slice(1).map((a, i) => {
                  const lower = a.charAt(0).toLowerCase() + a.slice(1)
                  if (i === actions.length - 2) return `and finally ${lower}`
                  return lower
                })
                return [first, ...rest].join(', ') + '.'
              })()}
            </p>
          </div>
        </div>
      )}
    </motion.div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────
export function Playbooks({ state }: Props) {
  const tickets = state.tickets.filter(t => t.suggestedPlaybook !== null)

  // Sort: master incidents first, then by severity
  const sorted = [...tickets].sort((a, b) => {
    if (a.isMaster && !b.isMaster) return -1
    if (!a.isMaster && b.isMaster) return 1
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
    return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)
  })

  const [selectedId, setSelectedId] = useState<string | null>(
    sorted.length > 0 ? sorted[0].id : null
  )
  const selected = sorted.find(t => t.id === selectedId) ?? null

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.15 }}
      className="flex h-full"
      style={{ minHeight: 'calc(100vh - 56px)', backgroundColor: '#0B0F14' }}
    >
      {/* Left panel */}
      <div className="w-72 shrink-0 flex flex-col"
        style={{ borderRight: '1px solid rgba(30,40,60,0.5)' }}>
        <div className="px-5 py-4"
          style={{ borderBottom: '1px solid rgba(30,40,60,0.5)' }}>
          <div className="flex items-center gap-2">
            <Shield size={13} style={{ color: '#7C3AED' }} />
            <h1 className="text-[10px] font-mono font-bold tracking-widest uppercase"
              style={{ color: '#e2e8f0' }}>Response Playbooks</h1>
          </div>
          <p className="text-[9px] font-mono mt-1" style={{ color: '#334155' }}>
            {sorted.filter(t => t.isMaster).length} master · {sorted.filter(t => !t.isMaster).length} individual
          </p>
        </div>

        <div className="flex-1 overflow-y-auto">
          {sorted.length === 0 ? (
            <div className="p-5 text-center">
              <p className="text-[10px] font-mono" style={{ color: '#334155' }}>
                Upload a log file to generate playbooks
              </p>
            </div>
          ) : (
            sorted.map(ticket => {
              const sevColor = SEV_COLOR[ticket.severity] ?? '#14B8A6'
              const isSelected = ticket.id === selectedId
              return (
                <button
                  key={ticket.id}
                  onClick={() => setSelectedId(ticket.id)}
                  className="w-full text-left px-4 py-3 transition-colors flex items-start gap-3"
                  style={{
                    backgroundColor: isSelected ? 'rgba(124,58,237,0.08)' : 'transparent',
                    borderBottom: '1px solid rgba(30,40,60,0.35)',
                    borderLeft: isSelected ? '2px solid #7C3AED' : '2px solid transparent',
                  }}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                      <span className="text-[8px] font-mono font-bold px-1 py-0.5 rounded-sm"
                        style={{ color: sevColor, backgroundColor: `${sevColor}18` }}>
                        {ticket.severity}
                      </span>
                      {ticket.isMaster && (
                        <span className="text-[8px] font-mono font-bold px-1 py-0.5 rounded-sm"
                          style={{ color: '#7C3AED', backgroundColor: 'rgba(124,58,237,0.12)' }}>
                          MASTER
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] font-mono truncate"
                      style={{ color: isSelected ? '#e2e8f0' : '#64748b' }}>
                      {ticket.suggestedPlaybook?.title ?? 'Unknown Playbook'}
                    </p>
                    <p className="text-[9px] font-mono truncate mt-0.5" style={{ color: '#334155' }}>
                      {ticket.isMaster
                        ? `${ticket.eventCount} events · ${ticket.affectedEntity}`
                        : ticket.attackerIp}
                    </p>
                  </div>
                  <ChevronRight size={12} className="shrink-0 mt-1"
                    style={{ color: isSelected ? '#7C3AED' : '#334155' }} />
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 overflow-y-auto p-6">
        <AnimatePresence mode="wait">
          {selected ? (
            <PlaybookViewer key={selected.id} ticket={selected} />
          ) : (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center justify-center h-full gap-4 py-24"
            >
              <AlertTriangle size={32} style={{ color: '#1e3a5f' }} />
              <p className="text-xs font-mono" style={{ color: '#334155' }}>
                {sorted.length === 0
                  ? 'No playbooks yet — upload a log file via Log Ingest'
                  : 'Select an incident from the left panel'}
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}
