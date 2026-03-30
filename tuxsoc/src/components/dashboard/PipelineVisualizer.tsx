import { motion } from 'framer-motion'
import type { PipelineLayer } from '../../types/pipeline'
import { PipelineNode } from './PipelineNode'
import { DataBeam } from './DataBeam'

interface Props {
  layers: PipelineLayer[]
  activeBeams: Set<string>
}

export function PipelineVisualizer({ layers, activeBeams }: Props) {
  return (
    <div
      className="rounded-xl p-6"
      style={{
        backgroundColor: 'rgba(17,24,39,0.85)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        border: '1px solid rgba(30,40,60,0.5)',
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2
            className="text-[10px] font-sans font-semibold tracking-widest uppercase"
            style={{ color: '#64748b' }}
          >
            Incident Pipeline
          </h2>
          <p className="text-xs font-mono mt-1" style={{ color: '#334155' }}>
            Live event processing — click any node to inspect logs
          </p>
        </div>
        <div className="flex items-center gap-4">
          {[
            { label: 'ACTIVE', color: '#22C55E' },
            { label: 'IDLE',   color: '#475569' },
            { label: 'ERROR',  color: '#EF4444' },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1.5">
              <div
                className="rounded-full"
                style={{ width: 5, height: 5, backgroundColor: color }}
              />
              <span
                className="text-[9px] font-mono font-semibold tracking-wider"
                style={{ color: '#475569' }}
              >
                {label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Pipeline flow */}
      <div className="overflow-x-auto pb-1">
        <div className="flex items-start gap-0 min-w-max">
          {layers.map((layer, idx) => {
            const isLast = idx === layers.length - 1
            const beamKey = !isLast ? `${layer.id}→${layers[idx + 1].id}` : ''
            const beamActive = activeBeams.has(beamKey)
            // The node that is the source of an active beam gets the ring
            const isBeamSource = beamActive

            return (
              <div key={layer.id} className="flex items-start">
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.055, duration: 0.3, ease: 'easeOut' }}
                >
                  <PipelineNode layer={layer} isBeamSource={isBeamSource} />
                </motion.div>

                {!isLast && (
                  <div className="flex items-center mt-[22px] mx-1">
                    <DataBeam active={beamActive} />
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
