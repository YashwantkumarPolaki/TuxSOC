import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, AlertTriangle, WifiOff, CheckCircle } from 'lucide-react'

export type ToastLevel = 'info' | 'warn' | 'critical' | 'success'

export interface Toast {
  id: string
  level: ToastLevel
  title: string
  message?: string
  persistent?: boolean  // CRITICAL toasts never auto-dismiss
}

interface Props {
  toasts: Toast[]
  onDismiss: (id: string) => void
}

const LEVEL_CONFIG: Record<ToastLevel, { color: string; bg: string; border: string; Icon: any }> = {
  critical: { color: '#EF4444', bg: 'rgba(239,68,68,0.1)',  border: 'rgba(239,68,68,0.4)',  Icon: AlertTriangle },
  warn:     { color: '#EAB308', bg: 'rgba(234,179,8,0.1)',  border: 'rgba(234,179,8,0.4)',  Icon: AlertTriangle },
  info:     { color: '#06B6D4', bg: 'rgba(6,182,212,0.1)',  border: 'rgba(6,182,212,0.4)',  Icon: WifiOff },
  success:  { color: '#22C55E', bg: 'rgba(34,197,94,0.1)',  border: 'rgba(34,197,94,0.4)',  Icon: CheckCircle },
}

export function ToastSystem({ toasts, onDismiss }: Props) {
  return (
    <div className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2 items-end">
      <AnimatePresence>
        {toasts.map(toast => (
          <ToastItem key={toast.id} toast={toast} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  )
}

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  const { color, bg, border, Icon } = LEVEL_CONFIG[toast.level]

  useEffect(() => {
    if (toast.persistent || toast.level === 'critical') return
    const id = setTimeout(() => onDismiss(toast.id), 5000)
    return () => clearTimeout(id)
  }, [toast, onDismiss])

  return (
    <motion.div
      initial={{ opacity: 0, x: 40, y: 0 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 40 }}
      transition={{ type: 'spring', stiffness: 300, damping: 30 }}
      className="flex items-start gap-3 px-4 py-3 rounded-lg min-w-[280px] max-w-[360px]"
      style={{
        backgroundColor: bg,
        border: `1px solid ${border}`,
        backdropFilter: 'blur(12px)',
        boxShadow: toast.level === 'critical' ? `0 0 20px rgba(239,68,68,0.35)` : 'none',
      }}
    >
      <Icon size={14} color={color} className="mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold" style={{ color }}>{toast.title}</p>
        {toast.message && (
          <p className="text-[10px] font-mono mt-0.5" style={{ color: '#64748b' }}>{toast.message}</p>
        )}
      </div>
      <button onClick={() => onDismiss(toast.id)} className="shrink-0 mt-0.5">
        <X size={12} color="#475569" />
      </button>
    </motion.div>
  )
}

// ── Toast state manager hook ──────────────────────────────────────────────
export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const push = (toast: Omit<Toast, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    setToasts(prev => [...prev, { ...toast, id }])
  }

  const dismiss = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }

  return { toasts, push, dismiss }
}
