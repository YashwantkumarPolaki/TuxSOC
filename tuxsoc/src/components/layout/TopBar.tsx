import { useState, useEffect } from 'react'
import { Search } from 'lucide-react'
import type { PipelineLayer } from '../../types/pipeline'
import type { BackendMode } from '../../hooks/useBackendData'

interface Props {
  pageTitle: string
  layers: PipelineLayer[]
  lastSynced: Date
  mode?: BackendMode
}

const STATUS_COLORS = { ACTIVE: '#22C55E', IDLE: '#6b7280', ERROR: '#EF4444' }

export function TopBar({ pageTitle, layers, lastSynced, mode = 'demo' }: Props) {
  const [syncAgo, setSyncAgo] = useState('0s ago')

  useEffect(() => {
    const update = () => {
      const diff = Math.floor((Date.now() - lastSynced.getTime()) / 1000)
      setSyncAgo(`${diff}s ago`)
    }
    update()
    const id = setInterval(update, 1000)
    return () => clearInterval(id)
  }, [lastSynced])

  return (
    <header
      className="fixed top-0 right-0 h-14 flex items-center px-4 gap-4 z-40"
      style={{
        left: 56,
        backgroundColor: 'rgba(11,15,20,0.92)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(30,40,60,0.5)',
      }}
    >
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-xs font-mono" style={{ color: '#6b7280' }}>TuxSOC</span>
        <span style={{ color: '#1E2235' }}>/</span>
        <span className="text-xs font-semibold" style={{ color: '#e2e8f0' }}>{pageTitle}</span>
      </div>

      {/* Search */}
      <div className="flex-1 max-w-sm mx-auto">
        <div
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg cursor-pointer"
          style={{ backgroundColor: 'rgba(17,24,39,0.8)', border: '1px solid rgba(30,40,60,0.6)' }}
        >
          <Search size={12} color="#6b7280" />
          <span className="text-xs flex-1" style={{ color: '#4b5563' }}>Search tickets, IPs, hashes...</span>
          <kbd className="text-[10px] px-1.5 py-0.5 rounded font-mono" style={{ backgroundColor: '#0A0B0F', color: '#6b7280', border: '1px solid #1E2235' }}>⌘K</kbd>
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4 ml-auto">
        {/* Sync status */}
        <span className="text-[11px] font-mono whitespace-nowrap" style={{ color: '#4b5563' }}>
          Last synced {syncAgo}
        </span>

        {/* Mode badge */}
        {mode !== 'live' && (
          <span
            className="text-[9px] font-mono font-semibold px-2 py-0.5 rounded-sm"
            style={{
              backgroundColor: mode === 'demo' ? 'rgba(234,179,8,0.12)' : 'rgba(6,182,212,0.12)',
              color: mode === 'demo' ? '#EAB308' : '#06B6D4',
              border: `1px solid ${mode === 'demo' ? 'rgba(234,179,8,0.3)' : 'rgba(6,182,212,0.3)'}`,
            }}
          >
            {mode === 'demo' ? '⚠ DEMO MODE' : '⟳ CONNECTING'}
          </span>
        )}

        {/* Layer status dots */}
        <div className="flex items-center gap-1">
          {layers.slice(0, 8).map(layer => (
            <div
              key={layer.id}
              title={`${layer.displayName}: ${layer.status}`}
              className="rounded-full"
              style={{
                width: 6, height: 6,
                backgroundColor: STATUS_COLORS[layer.status],
                boxShadow: layer.status === 'ACTIVE' ? `0 0 4px ${STATUS_COLORS.ACTIVE}` : 'none',
              }}
            />
          ))}
        </div>

        {/* Analyst avatar */}
        <div
          className="w-7 h-7 rounded-md flex items-center justify-center text-xs font-bold font-mono"
          style={{ backgroundColor: '#7C3AED20', border: '1px solid #7C3AED40', color: '#7C3AED' }}
        >
          JC
        </div>
      </div>
    </header>
  )
}
