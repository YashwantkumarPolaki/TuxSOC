import { useState, useEffect, useCallback, useRef } from 'react'
import type { PipelineLayer, LivePipelineEvent } from '../types/pipeline'
import type { LogLine } from '../types/watchdog'
import { mockPipelineLayers, mockLogLines } from '../mock/mockData'

const EVENT_PREFIXES = ['evt_brute', 'evt_sqli', 'evt_recon', 'evt_exfil', 'evt_priv_esc', 'evt_c2_beacon', 'evt_phish', 'evt_lateral']
const LOG_TEMPLATES = [
  { level: 'ERROR' as const, source: 'fw-01', content: 'DENY TCP {ip}:{port} -> 10.0.1.{n}:443 flags:SYN' },
  { level: 'WARN' as const, source: 'api-gw', content: 'POST /api/v2/auth 401 - {n} attempts from {ip}' },
  { level: 'INFO' as const, source: 'siem', content: 'CEF:0|Vendor|Product|1.0|threat|{type}|{score}|src={ip}' },
  { level: 'ERROR' as const, source: 'auth', content: 'Failed password for {user} from {ip} port {port}' },
  { level: 'DEBUG' as const, source: 'api-gw', content: 'Health check /api/health 200 OK latency:{n}ms' },
  { level: 'WARN' as const, source: 'edr', content: 'Suspicious process: cmd.exe /c whoami on {host}' },
  { level: 'INFO' as const, source: 'db-01', content: 'Query executed: SELECT * FROM accounts WHERE id={n} (2ms)' },
  { level: 'ERROR' as const, source: 'waf', content: 'BLOCK: SQL injection pattern detected from {ip}' },
]

function randomIp() {
  return `${Math.floor(Math.random() * 200 + 50)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
}

function randomPort() { return Math.floor(Math.random() * 60000 + 1024) }
function randomN() { return Math.floor(Math.random() * 999 + 1) }

function generateLogLine(): LogLine {
  const template = LOG_TEMPLATES[Math.floor(Math.random() * LOG_TEMPLATES.length)]
  const content = template.content
    .replace('{ip}', randomIp())
    .replace('{port}', String(randomPort()))
    .replace('{n}', String(randomN()))
    .replace('{user}', ['admin', 'root', 'svc_banking', 'operator'][Math.floor(Math.random() * 4)])
    .replace('{host}', ['workstation-fin-047', 'server-core-01', 'atm-mgmt-02'][Math.floor(Math.random() * 3)])
    .replace('{type}', ['brute-force', 'sqli', 'recon', 'c2-beacon'][Math.floor(Math.random() * 4)])
    .replace('{score}', String(Math.floor(Math.random() * 5 + 5)))

  return {
    id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    source: template.source,
    level: template.level,
    content,
  }
}

export interface SimulationState {
  layers: PipelineLayer[]
  liveEvents: LivePipelineEvent[]
  logStream: LogLine[]
  activeBeams: Set<string>
  kpi: { totalTickets: number; criticalCount: number; avgCvss: number; layersOnline: number }
}

export function useSimulation() {
  const [state, setState] = useState<SimulationState>({
    layers: mockPipelineLayers,
    liveEvents: [],
    logStream: mockLogLines,
    activeBeams: new Set(),
    kpi: { totalTickets: 8, criticalCount: 3, avgCvss: 7.4, layersOnline: 8 },
  })

  const beamProgressRef = useRef<number>(-1) // which beam index is active

  // Advance beam through pipeline every 600ms
  useEffect(() => {
    const interval = setInterval(() => {
      setState(prev => {
        const layerIds = prev.layers.map(l => l.id)
        const numBeams = layerIds.length - 1
        beamProgressRef.current = (beamProgressRef.current + 1) % (numBeams + 4) // pause at end

        const activeBeams = new Set<string>()
        if (beamProgressRef.current < numBeams) {
          const fromId = layerIds[beamProgressRef.current]
          const toId = layerIds[beamProgressRef.current + 1]
          activeBeams.add(`${fromId}→${toId}`)
        }

        // Update the active layer's lastEvent and eventsPerMin
        const eventId = EVENT_PREFIXES[Math.floor(Math.random() * EVENT_PREFIXES.length)]
        const layers = prev.layers.map((layer, idx) => {
          const isActive = idx === beamProgressRef.current
          return {
            ...layer,
            status: isActive ? 'ACTIVE' as const : layer.status,
            lastEvent: isActive ? `${eventId}_${Math.random().toString(36).slice(2, 5)} • 0s ago` : layer.lastEvent,
            eventsPerMin: isActive
              ? Math.max(1, layer.eventsPerMin + Math.floor(Math.random() * 20 - 10))
              : layer.eventsPerMin,
          }
        })

        return { ...prev, layers, activeBeams }
      })
    }, 600)

    return () => clearInterval(interval)
  }, [])

  // Generate new log lines every 1.2s
  useEffect(() => {
    const interval = setInterval(() => {
      const newLine = generateLogLine()
      setState(prev => ({
        ...prev,
        logStream: [newLine, ...prev.logStream].slice(0, 200),
      }))
    }, 1200)
    return () => clearInterval(interval)
  }, [])

  // Fluctuate KPI values every 5s
  useEffect(() => {
    const interval = setInterval(() => {
      setState(prev => ({
        ...prev,
        kpi: {
          totalTickets: prev.kpi.totalTickets + (Math.random() > 0.7 ? 1 : 0),
          criticalCount: Math.max(1, prev.kpi.criticalCount + (Math.random() > 0.85 ? 1 : 0)),
          avgCvss: parseFloat((prev.kpi.avgCvss + (Math.random() * 0.2 - 0.1)).toFixed(1)),
          layersOnline: 8,
        },
      }))
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  // Occasionally flip a layer to ERROR then back
  useEffect(() => {
    const interval = setInterval(() => {
      const layerIdx = Math.floor(Math.random() * 8)
      setState(prev => {
        const layers = prev.layers.map((l, i) =>
          i === layerIdx ? { ...l, status: 'ERROR' as const } : l
        )
        return { ...prev, layers }
      })
      setTimeout(() => {
        setState(prev => {
          const layers = prev.layers.map((l, i) =>
            i === layerIdx ? { ...l, status: 'ACTIVE' as const } : l
          )
          return { ...prev, layers }
        })
      }, 2000)
    }, 15000)
    return () => clearInterval(interval)
  }, [])

  const addLogLine = useCallback((line: LogLine) => {
    setState(prev => ({
      ...prev,
      logStream: [line, ...prev.logStream].slice(0, 200),
    }))
  }, [])

  return { state, addLogLine }
}
