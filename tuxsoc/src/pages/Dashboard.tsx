import { motion } from 'framer-motion'
import { AlertTriangle, Activity, Shield, Layers } from 'lucide-react'
import { KPICard } from '../components/dashboard/KPICard'
import { PipelineVisualizer } from '../components/dashboard/PipelineVisualizer'
import { TrendChart } from '../components/charts/TrendChart'
import { MitreRadar } from '../components/charts/MitreRadar'
import { SeverityBadge } from '../components/shared/SeverityBadge'
import { StatusChip } from '../components/shared/StatusChip'
import { CVSSBadge } from '../components/shared/CVSSBadge'
import { formatTimeAgo, getSeverityColor } from '../utils/severity'
import { mockTrendData, mockMitreData, allMockTickets } from '../mock/mockData'
import type { SimulationState } from '../hooks/useSimulation'
import { useNavigate } from 'react-router-dom'

interface Props {
  simulation: SimulationState
}

export function Dashboard({ simulation }: Props) {
  const { layers, activeBeams, kpi } = simulation
  const navigate = useNavigate()
  const recentTickets = allMockTickets.slice(0, 5)

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.15 }}
      className="p-6 flex flex-col gap-6"
      style={{ backgroundColor: '#0B0F14', minHeight: '100%' }}
    >

      {/* ── KPI Bento Row ── */}
      <div
        className="rounded-xl p-1"
        style={{ border: '1px solid rgba(30,40,60,0.4)' }}
      >
        <div className="grid grid-cols-4 gap-1">
          <KPICard
            label="Active Tickets"
            value={kpi.totalTickets}
            icon={Layers}
            color="purple"
            trend="up"
            trendValue="+2 today"
          />
          <KPICard
            label="Critical"
            value={kpi.criticalCount}
            icon={AlertTriangle}
            color="critical"
            trend="up"
            trendValue="requires action"
          />
          <KPICard
            label="Avg CVSS Score"
            value={kpi.avgCvss}
            decimals={1}
            unit="/ 10"
            icon={Shield}
            color="cyan"
          />
          <KPICard
            label="Layers Online"
            value={kpi.layersOnline}
            unit="/ 8"
            icon={Activity}
            color="green"
          />
        </div>
      </div>

      {/* ── Pipeline Visualizer ── */}
      <PipelineVisualizer layers={layers} activeBeams={activeBeams} />

      {/* ── Charts Bento Row ── */}
      <div className="grid grid-cols-2 gap-6">
        <TrendChart data={mockTrendData} />
        <MitreRadar data={mockMitreData} />
      </div>

      {/* ── Recent Tickets ── */}
      <div
        className="rounded-xl overflow-hidden"
        style={{
          backgroundColor: 'rgba(17,24,39,0.85)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          border: '1px solid rgba(30,40,60,0.5)',
        }}
      >
        {/* Table header */}
        <div
          className="flex items-center justify-between px-6 py-4"
          style={{ borderBottom: '1px solid rgba(30,40,60,0.5)' }}
        >
          <h3
            className="text-[10px] font-sans font-semibold tracking-widest uppercase"
            style={{ color: '#64748b' }}
          >
            Recent Incidents
          </h3>
          <button
            onClick={() => navigate('/tickets')}
            className="text-[10px] font-mono transition-colors hover:opacity-80"
            style={{ color: '#7C3AED' }}
          >
            View all →
          </button>
        </div>

        {/* Ticket rows */}
        <div>
          {recentTickets.map((ticket, i) => {
            const isCritical = ticket.severity === 'CRITICAL'
            const severityColor = getSeverityColor(ticket.severity)

            return (
              <motion.div
                key={ticket.id}
                className="flex items-center gap-5 px-6 py-3.5 cursor-pointer"
                style={{
                  borderBottom: i < recentTickets.length - 1
                    ? '1px solid rgba(30,40,60,0.35)'
                    : 'none',
                  // Critical glow on row
                  boxShadow: isCritical ? 'inset 3px 0 0 #EF4444' : `inset 3px 0 0 ${severityColor}`,
                }}
                whileHover={{
                  backgroundColor: 'rgba(30,40,60,0.3)',
                  scale: 1.005,
                  transition: { duration: 0.15 },
                }}
                onClick={() => navigate('/tickets')}
              >
                <SeverityBadge severity={ticket.severity} size="sm" />

                <div className="flex-1 min-w-0">
                  <p
                    className="text-xs font-medium truncate"
                    style={{ color: isCritical ? '#fca5a5' : '#e2e8f0' }}
                  >
                    {ticket.intent}
                  </p>
                  <p className="text-[10px] font-mono mt-0.5 truncate" style={{ color: '#334155' }}>
                    {ticket.attackerIp}
                    <span style={{ color: '#1e3a5f' }}> → </span>
                    {ticket.affectedEntity}
                  </p>
                </div>

                <div className="flex items-center gap-4 shrink-0">
                  <CVSSBadge score={ticket.cvssScore} size="sm" />
                  <StatusChip status={ticket.status} />
                  <span className="text-[10px] font-mono w-16 text-right" style={{ color: '#334155' }}>
                    {formatTimeAgo(ticket.createdAt)}
                  </span>
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>
    </motion.div>
  )
}
