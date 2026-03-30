import { motion } from 'framer-motion'

export function Investigations() {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.15 }} className="p-6">
      <div className="text-xs font-mono" style={{ color: '#4b5563' }}>Investigations page — coming next</div>
    </motion.div>
  )
}
