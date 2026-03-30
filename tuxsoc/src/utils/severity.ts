import type { Severity } from '../types/ticket'

export function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '#EF4444'
    case 'HIGH': return '#F97316'
    case 'MEDIUM': return '#EAB308'
    case 'LOW': return '#14B8A6'
  }
}

export function getSeverityBg(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return 'rgba(239,68,68,0.12)'
    case 'HIGH': return 'rgba(249,115,22,0.12)'
    case 'MEDIUM': return 'rgba(234,179,8,0.12)'
    case 'LOW': return 'rgba(20,184,166,0.12)'
  }
}

export function getCVSSColor(score: number): string {
  if (score >= 9) return '#EF4444'
  if (score >= 7) return '#F97316'
  if (score >= 4) return '#EAB308'
  return '#22C55E'
}

export function formatTimeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}
