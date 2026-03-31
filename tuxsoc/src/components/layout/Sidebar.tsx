import { useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  LayoutDashboard, GitBranch, BookOpen,
  Upload, Shield
} from 'lucide-react'

const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/investigations', label: 'Investigations', icon: GitBranch },
  { path: '/playbooks', label: 'Playbooks', icon: BookOpen },
  { path: '/ingest', label: 'Log Ingest', icon: Upload },
  // { path: '/tickets', label: 'Tickets', icon: Ticket },
  // { path: '/trends', label: 'Trends', icon: TrendingUp },
  // { path: '/ingest', label: 'Log Ingest', icon: Upload },
  // { path: '/noisy-log-ingest', label: 'Fidelity Engine', icon: Zap }
];

interface Props {
  systemHealthy: boolean
}

export function Sidebar({ systemHealthy }: Props) {
  const [expanded, setExpanded] = useState(false)
  const location = useLocation()

  return (
    <motion.aside
      onHoverStart={() => setExpanded(true)}
      onHoverEnd={() => setExpanded(false)}
      animate={{ width: expanded ? 220 : 56 }}
      transition={{ duration: 0.2, ease: 'easeInOut' }}
      className="fixed left-0 top-0 h-full z-50 flex flex-col overflow-hidden"
      style={{
        backgroundColor: 'rgba(11,15,20,0.95)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderRight: '1px solid rgba(30,40,60,0.5)',
      }}
    >
      {/* Logo */}
      <div className="flex items-center h-14 px-3.5 gap-3 shrink-0" style={{ borderBottom: '1px solid rgba(30,40,60,0.5)' }}>
        <div className="shrink-0 w-7 h-7 flex items-center justify-center rounded-sm" style={{ backgroundColor: '#7C3AED20', border: '1px solid #7C3AED40' }}>
          <Shield size={15} color="#7C3AED" />
        </div>
        <motion.span
          animate={{ opacity: expanded ? 1 : 0, x: expanded ? 0 : -8 }}
          transition={{ duration: 0.15 }}
          className="text-sm font-bold tracking-widest whitespace-nowrap"
          style={{ color: '#e2e8f0', fontFamily: 'ui-monospace, monospace' }}
        >
          TuxSOC
        </motion.span>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-3 flex flex-col gap-0.5 px-2">
        {NAV_ITEMS.map(({ path, label, icon: Icon }) => {
          const active = path === '/' ? location.pathname === '/' : location.pathname.startsWith(path)
          return (
            <NavLink key={path} to={path}>
              <div
                className="flex items-center gap-3 px-2 py-2 rounded-md cursor-pointer transition-colors"
                style={{
                  backgroundColor: active ? '#7C3AED18' : 'transparent',
                  color: active ? '#7C3AED' : '#6b7280',
                }}
                onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = '#1A1D27' }}
                onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent' }}
              >
                <Icon size={16} className="shrink-0" />
                <motion.span
                  animate={{ opacity: expanded ? 1 : 0 }}
                  transition={{ duration: 0.12 }}
                  className="text-xs font-medium whitespace-nowrap"
                >
                  {label}
                </motion.span>
              </div>
            </NavLink>
          )
        })}
      </nav>

      {/* Bottom */}
      <div className="px-2 pb-4 flex flex-col gap-2" style={{ borderTop: '1px solid rgba(30,40,60,0.5)', paddingTop: 12 }}>
        {/* Fully Local pill */}
        <div className="flex items-center gap-2 px-2 py-1.5 rounded-md" style={{ backgroundColor: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
          <span className="text-sm shrink-0">🔒</span>
          <motion.span
            animate={{ opacity: expanded ? 1 : 0 }}
            transition={{ duration: 0.12 }}
            className="text-[10px] font-semibold whitespace-nowrap"
            style={{ color: '#22C55E' }}
          >
            Fully Local
          </motion.span>
        </div>

        {/* System health */}
        <div className="flex items-center gap-2 px-2 py-1">
          <div
            className="shrink-0 rounded-full"
            style={{
              width: 8, height: 8,
              backgroundColor: systemHealthy ? '#22C55E' : '#EF4444',
              boxShadow: `0 0 6px ${systemHealthy ? '#22C55E' : '#EF4444'}`,
            }}
          />
          <motion.span
            animate={{ opacity: expanded ? 1 : 0 }}
            transition={{ duration: 0.12 }}
            className="text-[10px] whitespace-nowrap"
            style={{ color: '#6b7280' }}
          >
            {systemHealthy ? 'All systems nominal' : 'Degraded'}
          </motion.span>
        </div>
      </div>
    </motion.aside>
  )
}
