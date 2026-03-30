import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown } from 'lucide-react'
import type { PipelineLayer } from '../../types/pipeline'

interface Props {
  layer: PipelineLayer
  isBeamSource?: boolean
}

const STATUS_CONFIG = {
  ACTIVE: { color: '#22C55E', label: 'ACTIVE', pulse: true },
  IDLE:   { color: '#475569', label: 'IDLE',   pulse: false },
  ERROR:  { color: '#EF4444', label: 'ERROR',  pulse: true },
}

export function PipelineNode({ layer, isBeamSource = false }: Props) {
  const [expanded, setExpanded] = useState(false)
  const { color, label, pulse } = STATUS_CONFIG[layer.status]

  const isActive = layer.status === 'ACTIVE'
  const isError  = layer.status === 'ERROR'

  return (
    <div className="flex flex-col items-center" style={{ minWidth: 112 }}>
      <motion.div
        className="w-full rounded-lg cursor-pointer select-none"
        style={{
          backgroundColor: 'rgba(17,24,39,0.9)',
          backdropFilter: 'blur(8px)',
          border: isError
            ? '1px solid rgba(239,68,68,0.4)'
            : isBeamSource
            ? '1px solid rgba(59,130,246,0.5)'
            : '1px solid rgba(30,40,60,0.55)',
          boxShadow: isBeamSource
            ? '0 0 14px rgba(59,130,246,0.4)'
            : isActive
            ? `0 0 10px ${color}20`
            : 'none',
          // Active pipeline ring via outline
          outline: isBeamSource ? '2px solid #3B82F6' : 'none',
          outlineOffset: isBeamSource ? '2px' : '0',
        }}
        whileHover={{
          borderColor: `${color}60`,
          boxShadow: `0 0 16px ${color}30`,
        }}
        transition={{ duration: 0.15 }}
        onClick={() => setExpanded(v => !v)}
      >
        <div className="px-3 py-3">
          {/* Status row */}
          <div className="flex items-center justify-between mb-2.5">
            <div className="flex items-center gap-1.5">
              <motion.div
                className="rounded-full"
                style={{ width: 6, height: 6, backgroundColor: color, flexShrink: 0 }}
                animate={pulse ? { opacity: [1, 0.25, 1], scale: [1, 1.2, 1] } : { opacity: 1 }}
                transition={pulse ? { duration: 1.4, repeat: Infinity, ease: 'easeInOut' } : {}}
              />
              <span
                className="text-[9px] font-mono font-bold tracking-wider"
                style={{ color }}
              >
                {label}
              </span>
            </div>
            <motion.div
              animate={{ rotate: expanded ? 180 : 0 }}
              transition={{ duration: 0.2 }}
            >
              <ChevronDown size={10} color="#475569" />
            </motion.div>
          </div>

          {/* Layer name */}
          <div
            className="text-[10px] font-mono font-bold mb-2.5 leading-tight tracking-wide"
            style={{ color: '#e2e8f0' }}
          >
            {layer.displayName}
          </div>

          {/* Last event — monospace, engineered feel */}
          <div
            className="text-[9px] font-mono truncate mb-1.5"
            style={{ color: '#334155' }}
          >
            {layer.lastEvent}
          </div>

          {/* Events/min */}
          <div className="text-[9px] font-mono" style={{ color: '#475569' }}>
            <span style={{ color: '#06B6D4', fontWeight: 600 }}>{layer.eventsPerMin}</span>
            <span> evt/min</span>
          </div>
        </div>
      </motion.div>

      {/* Expanded log accordion */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: 'easeOut' }}
            className="w-full overflow-hidden"
            style={{ minWidth: 230, zIndex: 10, position: 'relative' }}
          >
            <div
              className="mt-1.5 rounded-lg p-3"
              style={{
                backgroundColor: '#0B0F14',
                border: '1px solid rgba(30,40,60,0.7)',
              }}
            >
              <div
                className="text-[9px] font-mono font-semibold tracking-widest uppercase mb-2"
                style={{ color: '#334155' }}
              >
                Last 5 Events
              </div>
              {layer.recentLogs.map((log, i) => (
                <div
                  key={i}
                  className="text-[9px] font-mono py-1 truncate"
                  style={{
                    color: '#475569',
                    borderBottom: i < layer.recentLogs.length - 1
                      ? '1px solid rgba(30,40,60,0.4)'
                      : 'none',
                  }}
                >
                  {log}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
