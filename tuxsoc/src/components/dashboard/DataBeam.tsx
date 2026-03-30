import { motion, AnimatePresence } from 'framer-motion'

interface Props {
  active: boolean
}

export function DataBeam({ active }: Props) {
  return (
    <div className="relative flex items-center" style={{ width: 32, height: 2 }}>
      {/* Static dashed base */}
      <svg width="32" height="2" className="absolute inset-0">
        <line
          x1="0" y1="1" x2="32" y2="1"
          stroke="#1E2235"
          strokeWidth="1.5"
          strokeDasharray="3 3"
        />
      </svg>

      {/* Animated beam */}
      <AnimatePresence>
        {active && (
          <motion.div
            key="beam"
            className="absolute inset-0 rounded-full"
            initial={{ scaleX: 0, originX: 0 }}
            animate={{ scaleX: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
            style={{
              height: 2,
              background: 'linear-gradient(90deg, #7C3AED, #06B6D4)',
              boxShadow: '0 0 6px #06B6D4',
            }}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
