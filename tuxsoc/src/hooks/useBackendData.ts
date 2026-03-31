/**
 * useBackendData.ts
 * Polls the FastAPI backend every 3 seconds.
 * Falls back to mock data if backend is unreachable.
 * Merges live detections with simulation state for pipeline animation.
 */

import { useState, useEffect, useRef, useCallback } from 'react'
import { apiClient, checkHealth } from '../api/client'
import { groupAndMergeDetections, derivePipelineHealth } from '../api/adapters'
import type { BackendDetection, IngestFileResponse } from '../types/backend'
import type { Ticket } from '../types/ticket'
import type { PipelineLayer } from '../types/pipeline'
import type { LogLine } from '../types/watchdog'
import { mockPipelineLayers, mockLogLines } from '../mock/mockData'

export type BackendMode = 'live' | 'demo' | 'connecting'

export interface IngestError {
  status: number | null   // HTTP status code, null = network error
  detail: string          // FastAPI detail string or generic message
}

export interface BackendState {
  mode: BackendMode
  tickets: Ticket[]
  layers: PipelineLayer[]
  logStream: LogLine[]
  activeBeams: Set<string>
  kpi: {
    totalTickets: number
    criticalCount: number
    avgCvss: number
    layersOnline: number
  }
  lastSynced: Date
  rawDetections: BackendDetection[]
}

// ── Log line builder from backend detection ───────────────────────────────
function detectionToLogLine(d: BackendDetection): LogLine {
  const score = d.engine_1_anomaly.anomaly_score
  const level: LogLine['level'] =
    score >= 0.85 ? 'ERROR' :
    score >= 0.70 ? 'WARN' :
    score >= 0.55 ? 'INFO' : 'DEBUG'

  return {
    id: `${d.incident_id}-${Date.now()}`,
    timestamp: d.timestamp,
    source: d.log_type,
    level,
    content: `[${d.incident_id}] ${d.raw_event.action ?? 'event'} | src=${d.raw_event.source_ip ?? '?'} → dst=${d.raw_event.destination_ip ?? '?'} | score=${score.toFixed(3)} | tactic=${d.engine_2_threat_intel.mitre_tactic}`,
  }
}

// ── Beam advancement (same logic as useSimulation) ────────────────────────
let beamIdx = -1
function advanceBeam(layers: PipelineLayer[]): Set<string> {
  const numBeams = layers.length - 1
  beamIdx = (beamIdx + 1) % (numBeams + 4)
  const active = new Set<string>()
  if (beamIdx < numBeams) {
    active.add(`${layers[beamIdx].id}→${layers[beamIdx + 1].id}`)
  }
  return active
}

// ── Initial state ─────────────────────────────────────────────────────────
function buildInitialState(): BackendState {
  return {
    mode: 'connecting',
    tickets: [],          // start empty — only real backend detections populate this
    layers: mockPipelineLayers,
    logStream: mockLogLines,
    activeBeams: new Set(),
    kpi: {
      totalTickets: 0,
      criticalCount: 0,
      avgCvss: 0,
      layersOnline: 8,
    },
    lastSynced: new Date(),
    rawDetections: [],
  }
}

export function useBackendData() {
  const [state, setState] = useState<BackendState>(buildInitialState)
  const healthChecked = useRef(false)
  const isLive = useRef(false)

  // ── Health probe on mount ─────────────────────────────────────────────
  useEffect(() => {
    checkHealth().then(healthy => {
      healthChecked.current = true
      if (!healthy) {
        setState(prev => ({ ...prev, mode: 'demo' }))
      } else {
        isLive.current = true
        setState(prev => ({ ...prev, mode: 'live' }))
      }
    })
  }, [])

  // ── Beam animation (always runs regardless of mode) ───────────────────
  useEffect(() => {
    const id = setInterval(() => {
      setState(prev => ({
        ...prev,
        activeBeams: advanceBeam(prev.layers),
      }))
    }, 600)
    return () => clearInterval(id)
  }, [])

  // ── Demo mode: generate mock log lines ────────────────────────────────
  useEffect(() => {
    if (state.mode !== 'demo') return
    const TEMPLATES = [
      { level: 'ERROR' as const, src: 'fw-01', msg: 'DENY TCP {ip}:{port} → 10.0.1.{n}:443' },
      { level: 'WARN'  as const, src: 'api-gw', msg: 'POST /api/v2/auth 401 — {n} attempts from {ip}' },
      { level: 'INFO'  as const, src: 'siem', msg: 'CEF:0|Vendor|Product|1.0|threat|brute-force|{n}|src={ip}' },
      { level: 'DEBUG' as const, src: 'api-gw', msg: 'Health check /api/health 200 OK latency:{n}ms' },
    ]
    const id = setInterval(() => {
      const t = TEMPLATES[Math.floor(Math.random() * TEMPLATES.length)]
      const ip = `${Math.floor(Math.random()*200+50)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`
      const line: LogLine = {
        id: `demo-${Date.now()}`,
        timestamp: new Date().toISOString(),
        source: t.src,
        level: t.level,
        content: t.msg.replace('{ip}', ip).replace('{port}', String(Math.floor(Math.random()*60000+1024))).replace('{n}', String(Math.floor(Math.random()*999+1))),
      }
      setState(prev => ({ ...prev, logStream: [line, ...prev.logStream].slice(0, 200) }))
    }, 1200)
    return () => clearInterval(id)
  }, [state.mode])

  // ── Live polling: /health + /pipeline/status ─────────────────────────
  useEffect(() => {
    if (state.mode !== 'live') return

    // Map backend layer keys → pipeline node indices
    const LAYER_KEY_MAP: Record<string, number> = {
      layer_0: 1,   // INGESTION node
      layer_1: 2,   // FEATURE ENG node
      layer_2: 3,   // DETECTION node
      layer_3: 4,   // AI ANALYSIS node
      layer_4: 5,   // CVSS node
      layer_5: 6,   // RESPONSE node
    }

    const poll = async () => {
      try {
        const healthRes = await apiClient.get('/health', { timeout: 3000 })
        const healthy = healthRes.data?.status === 'healthy'

        // Try to get per-layer status — graceful fallback if endpoint missing
        let layerStatus: Record<string, string> = {}
        try {
          const statusRes = await apiClient.get('/pipeline/status', { timeout: 2000 })
          layerStatus = statusRes.data ?? {}
        } catch { /* endpoint not yet available — ignore */ }

        setState(prev => {
          const layers = prev.layers.map((l, i) => {
            if (!healthy) {
              return { ...l, status: i === 0 ? 'ERROR' as const : 'IDLE' as const }
            }
            // Map pipeline/status response to node status
            const backendKey = Object.keys(LAYER_KEY_MAP).find(k => LAYER_KEY_MAP[k] === i)
            if (backendKey && layerStatus[backendKey]) {
              const s = layerStatus[backendKey]
              const mapped = s === 'active' ? 'ACTIVE' as const
                           : s === 'done'   ? 'ACTIVE' as const
                           : s === 'error'  ? 'ERROR'  as const
                           : 'IDLE' as const
              return { ...l, status: mapped }
            }
            return { ...l, status: 'ACTIVE' as const }
          })
          return { ...prev, layers, lastSynced: new Date() }
        })
      } catch {
        isLive.current = false
        setState(prev => ({
          ...prev,
          mode: 'demo',
          layers: prev.layers.map(l => ({ ...l, status: 'ERROR' as const })),
        }))
      }
    }

    poll()
    const id = setInterval(poll, 3000)
    return () => clearInterval(id)
  }, [state.mode])

  // ── Ingest file and get real detections ───────────────────────────────
  const clearTickets = useCallback(() => {
    setState(prev => ({
      ...prev,
      tickets: [],
      rawDetections: [],
      kpi: { ...prev.kpi, totalTickets: 0, criticalCount: 0, avgCvss: 0 },
    }))
  }, [])

  const ingestFile = useCallback(async (
    file: File,
    onError?: (err: IngestError) => void,
  ): Promise<BackendDetection[]> => {
    const form = new FormData()
    // Key MUST match the FastAPI parameter name: file: UploadFile = File(...)
    form.append('file', file)

    try {
      // Do NOT pass Content-Type header — let the browser set it automatically
      // so it includes the multipart boundary string. Forcing it causes 422.
      const res = await apiClient.post<IngestFileResponse>('/ingest_file', form, {
        timeout: 60000,
      })
      const detections = res.data.detections ?? []

      // Merge all detections into grouped master tickets
      const newTickets: Ticket[] = groupAndMergeDetections(detections)
      const newLogLines = detections.map(detectionToLogLine)

      setState(prev => {
        const layers = prev.layers.map((layer, i) => {
          if (i === 0) return derivePipelineHealth(detections, layer, 0)
          if (i === 3) return derivePipelineHealth(detections, layer, 3)
          if (i === 4) return derivePipelineHealth(detections, layer, 4)
          return { ...layer, status: 'ACTIVE' as const }
        })

        const allTickets: Ticket[] = [...newTickets]
        const criticalCount = allTickets.filter(t => t.severity === 'CRITICAL').length
        const avgCvss = allTickets.length > 0
          ? allTickets.reduce((s, t) => s + t.cvssScore, 0) / allTickets.length
          : 0

        return {
          ...prev,
          tickets: allTickets,
          rawDetections: detections,
          layers,
          logStream: [...newLogLines, ...prev.logStream].slice(0, 200),
          kpi: {
            totalTickets: allTickets.filter(t => t.status !== 'RESOLVED').length,
            criticalCount,
            avgCvss: parseFloat(avgCvss.toFixed(1)),
            layersOnline: layers.filter(l => l.status === 'ACTIVE').length,
          },
          lastSynced: new Date(),
        }
      })

      return detections

    } catch (err: any) {
      // Extract the exact FastAPI error detail for debugging
      const status = err?.response?.status ?? null
      const detail =
        err?.response?.data?.detail ??
        err?.response?.data?.message ??
        err?.message ??
        'Unknown pipeline error'

      // Always log to console so the analyst can see the raw FastAPI error
      console.error(
        `[TuxSOC] /ingest_file failed — HTTP ${status ?? 'network error'}:`,
        err?.response?.data ?? err?.message,
      )

      onError?.({ status, detail })
      throw err
    }
  }, [])

  return { state, ingestFile, clearTickets }
}