import { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Upload, FileText, AlertTriangle, CheckCircle2,
  Loader2, X, ChevronDown, ChevronUp, Shield, Zap
} from 'lucide-react'
import axios from 'axios'
import type { FidelityResult, NoisyIngestResponse } from '../types/noisyIngest'

// ── Noisy engine runs on port 8002 ────────────────────────────────────────
const NOISY_ENGINE_URL = import.meta.env.VITE_NOISY_ENGINE_URL ?? 'http://localhost:8002'

// ── Severity colour config ────────────────────────────────────────────────
const SEV_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  Critical: { color: '#EF4444', bg: 'rgba(239,68,68,0.1)',  border: 'rgba(239,68,68,0.35)' },
  High:     { color: '#F97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.35)' },
  Medium:   { color: '#EAB308', bg: 'rgba(234,179,8,0.1)',  border: 'rgba(234,179,8,0.35)' },
  Low:      { color: '#14B8A6', bg: 'rgba(20,184,166,0.1)', border: 'rgba(20,184,166,0.35)' },
}

function SeverityBadge({ sev }: { sev: string }) {
  const cfg = SEV_CONFIG[sev] ?? SEV_CONFIG.Medium
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-[10px] font-mono font-bold"
      style={{ color: cfg.color, backgroundColor: cfg.bg, border: `1px solid ${cfg.border}` }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: cfg.color }} />
      {sev.toUpperCase()}
    </span>
  )
}

function ResultCard({ result, index }: { result: FidelityResult; index: number }) {
  const [expanded, setExpanded] = useState(false)
  const cfg = SEV_CONFIG[result.revised_severity] ?? SEV_CONFIG.Medium
  const isCriticalOrHigh = result.revised_severity === 'Critical' || result.revised_severity === 'High'

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04, duration: 0.25 }}
      className="rounded-xl overflow-hidden"
      style={{
        backgroundColor: 'rgba(17,24,39,0.85)',
        border: `1px solid ${isCriticalOrHigh ? cfg.border : 'rgba(30,40,60,0.5)'}`,
        boxShadow: isCriticalOrHigh ? `0 0 20px ${cfg.color}22` : 'none',
      }}
    >
      {/* Card header */}
      <div className="flex items-start justify-between gap-4 p-5">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <SeverityBadge sev={result.revised_severity} />
            {result.original_severity !== 'N/A' && result.original_severity !== result.revised_severity && (
              <span className="text-[9px] font-mono" style={{ color: '#475569' }}>
                was {result.original_severity}
              </span>
            )}
          </div>
          <h3 className="text-sm font-semibold leading-snug" style={{ color: '#e2e8f0' }}>
            {result.event_name}
          </h3>
          <div className="flex gap-4 mt-2">
            {result.original_ip !== 'N/A' && (
              <span className="text-[10px] font-mono" style={{ color: '#3B82F6' }}>
                {result.original_ip}
              </span>
            )}
            {result.original_user !== 'N/A' && (
              <span className="text-[10px] font-mono" style={{ color: '#64748b' }}>
                {result.original_user}
              </span>
            )}
          </div>
        </div>
        <button
          onClick={() => setExpanded(v => !v)}
          className="shrink-0 p-1.5 rounded-md transition-colors"
          style={{ color: '#475569' }}
        >
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Explanation (always visible) */}
      <div className="px-5 pb-4">
        <p className="text-xs leading-relaxed" style={{ color: '#64748b' }}>
          {result.explanation}
        </p>
      </div>

      {/* Expanded: action items */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div
              className="mx-5 mb-5 p-4 rounded-lg"
              style={{ backgroundColor: '#0B0F14', border: '1px solid rgba(30,40,60,0.6)' }}
            >
              <p
                className="text-[9px] font-mono font-semibold tracking-widest uppercase mb-3"
                style={{ color: '#334155' }}
              >
                Recommended Actions
              </p>
              <ol className="flex flex-col gap-2">
                {result.recommended_actions.map((action, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs" style={{ color: '#94a3b8' }}>
                    <span
                      className="shrink-0 w-4 h-4 rounded-sm flex items-center justify-center text-[9px] font-mono font-bold mt-0.5"
                      style={{ backgroundColor: `${cfg.color}20`, color: cfg.color }}
                    >
                      {i + 1}
                    </span>
                    {action}
                  </li>
                ))}
              </ol>

              {/* Original action string */}
              {result.original_action !== 'N/A' && (
                <div className="mt-4 pt-3" style={{ borderTop: '1px solid rgba(30,40,60,0.5)' }}>
                  <p className="text-[9px] font-mono" style={{ color: '#334155' }}>
                    ORIGINAL ACTION STRING
                  </p>
                  <p className="text-[10px] font-mono mt-1 break-all" style={{ color: '#475569' }}>
                    {result.original_action}
                  </p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export function NoisyLogIngest() {
  const [file, setFile] = useState<File | null>(null)
  const [status, setStatus] = useState<'idle' | 'processing' | 'done' | 'error'>('idle')
  const [results, setResults] = useState<FidelityResult[]>([])
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [preview, setPreview] = useState<string[]>([])

  const onDrop = useCallback((accepted: File[]) => {
    const f = accepted[0]
    if (!f) return
    setFile(f)
    setStatus('idle')
    setResults([])
    setErrorMsg(null)

    // Excel files are ZIP-based binary — readAsText produces "PK..." garbage.
    // Only preview text-based formats (CSV, TSV, plain log).
    const nameLower = f.name.toLowerCase()
    const isBinary = nameLower.endsWith('.xlsx') || nameLower.endsWith('.xls')

    if (isBinary) {
      setPreview([`[Excel file — ${(f.size / 1024).toFixed(1)} KB — binary format, no text preview]`])
      return
    }

    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result as string
      setPreview(text.split('\n').filter(Boolean).slice(0, 8))
    }
    reader.readAsText(f)
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
      'text/plain': ['.csv', '.txt', '.log'],
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
      'application/vnd.ms-excel': ['.xls'],
    },
    multiple: false,
  })

  const handleAnalyse = async () => {
    if (!file) return
    setStatus('processing')
    setErrorMsg(null)

    const form = new FormData()
    form.append('file', file)

    try {
      const res = await axios.post<NoisyIngestResponse>(
        `${NOISY_ENGINE_URL}/api/noisy-ingest`,
        form,
        { timeout: 600000 },  // 10 min — async batches of 3, but large files still take time
      )
      setResults(res.data.results ?? [])
      setStatus('done')
    } catch (err: any) {
      const detail =
        err?.response?.data?.detail ??
        err?.message ??
        'Unknown error — is the Noisy Engine running on port 8002?'
      setErrorMsg(typeof detail === 'string' ? detail : JSON.stringify(detail))
      setStatus('error')
    }
  }

  const reset = () => {
    setFile(null)
    setPreview([])
    setStatus('idle')
    setResults([])
    setErrorMsg(null)
  }

  const criticalCount = results.filter(r => r.revised_severity === 'Critical').length
  const highCount     = results.filter(r => r.revised_severity === 'High').length

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.15 }}
      className="p-6 max-w-5xl mx-auto flex flex-col gap-6"
      style={{ minHeight: '100%' }}
    >
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
         {/*<Zap size={14} color="#7C3AED" />*/}
          <h1 className="text-sm font-mono font-bold tracking-widest uppercase" style={{ color: '#e2e8f0' }}>
            Noisy Log Fidelity Engine
          </h1>
          {/*<span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded-sm"
            style={{ backgroundColor: 'rgba(124,58,237,0.15)', color: '#7C3AED', border: '1px solid rgba(124,58,237,0.3)' }}
          >
            LAYER 2.5
          </span>*/}
        </div>
        <p className="text-xs font-mono" style={{ color: '#475569' }}>
          Upload a noisy or mislabelled CSV or Excel log file. Ollama re-classifies each event from scratch.
        </p>
      </div>

      {/* Drop zone */}
      <div
        {...getRootProps()}
        className="rounded-xl p-10 border-2 border-dashed cursor-pointer transition-all duration-200 flex flex-col items-center gap-3"
        style={{
          borderColor: isDragActive ? '#7C3AED' : 'rgba(30,40,60,0.6)',
          backgroundColor: isDragActive ? 'rgba(124,58,237,0.05)' : 'rgba(17,24,39,0.5)',
          boxShadow: isDragActive ? '0 0 20px rgba(124,58,237,0.2)' : 'none',
        }}
      >
        <input {...getInputProps()} />
        <div
          className="p-4 rounded-full"
          style={{ backgroundColor: isDragActive ? 'rgba(124,58,237,0.15)' : 'rgba(30,40,60,0.6)' }}
        >
          <Upload size={28} color={isDragActive ? '#7C3AED' : '#475569'} />
        </div>
        <p className="text-sm font-medium" style={{ color: '#e2e8f0' }}>
          {isDragActive ? 'Drop the file here' : 'Drag & drop a CSV or Excel file'}
        </p>
        <p className="text-[10px] font-mono" style={{ color: '#334155' }}>
          CSV · Excel (.xlsx) · Any delimiter · Any column names · Schema-agnostic
        </p>
      </div>

      {/* File panel */}
      <AnimatePresence>
        {file && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="flex flex-col gap-4 overflow-hidden"
          >
            {/* File info */}
            <div
              className="flex items-center justify-between p-4 rounded-lg"
              style={{ backgroundColor: 'rgba(17,24,39,0.85)', border: '1px solid rgba(30,40,60,0.6)' }}
            >
              <div className="flex items-center gap-3">
                <FileText size={15} color="#7C3AED" />
                <div>
                  <p className="text-xs font-mono font-medium" style={{ color: '#e2e8f0' }}>{file.name}</p>
                  <p className="text-[10px] font-mono mt-0.5" style={{ color: '#475569' }}>
                    {(file.size / 1024).toFixed(1)} KB
                  </p>
                </div>
              </div>
              <button onClick={reset} style={{ color: '#475569' }}>
                <X size={14} />
              </button>
            </div>

            {/* CSV preview */}
            {preview.length > 0 && (
              <div
                className="rounded-lg p-4"
                style={{ backgroundColor: '#0B0F14', border: '1px solid rgba(30,40,60,0.6)' }}
              >
                <p className="text-[9px] font-mono tracking-widest uppercase mb-2" style={{ color: '#334155' }}>
                  Preview — first {preview.length} rows
                </p>
                {preview.map((line, i) => (
                  <div key={i} className="text-[10px] font-mono truncate py-0.5" style={{ color: '#475569' }}>
                    <span style={{ color: '#1e3a5f' }}>{String(i + 1).padStart(2, '0')} </span>
                    {line}
                  </div>
                ))}
              </div>
            )}

            {/* Error */}
            {errorMsg && (
              <div
                className="flex items-start gap-2 px-4 py-3 rounded-lg text-[10px] font-mono"
                style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.3)', color: '#fca5a5' }}
              >
                <AlertTriangle size={12} className="shrink-0 mt-0.5" color="#EF4444" />
                <span><span style={{ color: '#EF4444', fontWeight: 700 }}>ENGINE ERROR: </span>{errorMsg}</span>
              </div>
            )}

            {/* Analyse button */}
            <button
              onClick={handleAnalyse}
              disabled={status === 'processing'}
              className="w-full py-3 rounded-xl font-mono font-bold text-sm flex items-center justify-center gap-2 transition-all"
              style={{
                backgroundColor:
                  status === 'idle'       ? '#7C3AED' :
                  status === 'processing' ? 'rgba(30,40,60,0.6)' :
                  status === 'done'       ? '#16A34A' :
                  '#DC2626',
                color: status === 'processing' ? '#475569' : '#ffffff',
                cursor: status === 'processing' ? 'not-allowed' : 'pointer',
                boxShadow: status === 'idle' ? '0 0 20px rgba(124,58,237,0.3)' : 'none',
              }}
            >
              {status === 'idle'       && <><Zap size={15} /> Run Fidelity Analysis</>}
              {status === 'processing' && <><Loader2 size={15} className="animate-spin" /> De-noising in progress...</>}
              {status === 'done'       && <><CheckCircle2 size={15} /> Analysis Complete — {results.length} events</>}
              {status === 'error'      && <><AlertTriangle size={15} /> Retry Analysis</>}
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Processing overlay */}
      <AnimatePresence>
        {status === 'processing' && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex flex-col items-center gap-4 py-12"
          >
            <div className="relative">
              <div
                className="w-16 h-16 rounded-full flex items-center justify-center"
                style={{ backgroundColor: 'rgba(124,58,237,0.1)', border: '1px solid rgba(124,58,237,0.3)' }}
              >
                <Loader2 size={28} color="#7C3AED" className="animate-spin" />
              </div>
            </div>
            <div className="text-center">
              <p className="text-sm font-mono font-semibold" style={{ color: '#e2e8f0' }}>
                De-noising in progress...
              </p>
              <p className="text-[10px] font-mono mt-1" style={{ color: '#475569' }}>
                Ollama is re-classifying each event · This may take a moment
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Results */}
      <AnimatePresence>
        {status === 'done' && results.length > 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex flex-col gap-4"
          >
            {/* Summary bar */}
            <div
              className="flex items-center justify-between px-5 py-3 rounded-xl"
              style={{ backgroundColor: 'rgba(17,24,39,0.85)', border: '1px solid rgba(30,40,60,0.5)' }}
            >
              <div className="flex items-center gap-2">
                <Shield size={13} color="#7C3AED" />
                <span className="text-[10px] font-mono font-semibold tracking-widest uppercase" style={{ color: '#64748b' }}>
                  Fidelity Report — {results.length} events re-classified
                </span>
              </div>
              <div className="flex items-center gap-3">
                {criticalCount > 0 && (
                  <span className="text-[10px] font-mono font-bold" style={{ color: '#EF4444' }}>
                    {criticalCount} CRITICAL
                  </span>
                )}
                {highCount > 0 && (
                  <span className="text-[10px] font-mono font-bold" style={{ color: '#F97316' }}>
                    {highCount} HIGH
                  </span>
                )}
              </div>
            </div>

            {/* Result cards */}
            <div className="flex flex-col gap-3">
              {results.map((result, i) => (
                <ResultCard key={i} result={result} index={i} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
