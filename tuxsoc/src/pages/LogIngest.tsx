import { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { motion, AnimatePresence } from 'framer-motion'
import { Upload, FileText, CheckCircle2, AlertCircle, Loader2, X } from 'lucide-react'
import type { BackendDetection } from '../types/backend'

interface Props {
  ingestFile: (file: File) => Promise<BackendDetection[]>
}

export function LogIngest({ ingestFile }: Props) {
  const [file, setFile] = useState<File | null>(null)
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle')
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [resultSummary, setResultSummary] = useState<string | null>(null)
  const [preview, setPreview] = useState<string[]>([])

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const selected = acceptedFiles[0]
    if (!selected) return
    setFile(selected)
    setStatus('idle')
    setErrorMsg(null)
    setResultSummary(null)

    // Preview first 10 lines
    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result as string
      setPreview(text.split('\n').filter(Boolean).slice(0, 10))
    }
    reader.readAsText(selected)
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    // Accept any text-based log format — backend handles detection
    accept: {
      'text/plain': ['.log', '.txt'],
      'application/json': ['.json'],
      'text/csv': ['.csv'],
      'text/xml': ['.xml'],
      // CEF files have no standard MIME — accept as text
      'application/octet-stream': ['.cef', '.log'],
    },
    multiple: false,
  })

  const handleUpload = async () => {
    if (!file) return
    setStatus('uploading')
    setErrorMsg(null)
    setResultSummary(null)

    try {
      const detections = await ingestFile(file)
      setResultSummary(
        `${detections.length} event${detections.length !== 1 ? 's' : ''} processed — ` +
        `${detections.filter(d => d.engine_1_anomaly.anomaly_flagged).length} anomalies flagged`
      )
      setStatus('success')
      // Auto-reset after 4s so analyst can drop another file
      setTimeout(() => {
        setFile(null)
        setPreview([])
        setStatus('idle')
        setResultSummary(null)
      }, 4000)
    } catch (err: any) {
      // The toast is already fired by App.tsx via the onError callback.
      // Show the raw detail inline too so the analyst doesn't have to open DevTools.
      const detail =
        err?.response?.data?.detail ??
        err?.message ??
        'Unknown error — check console'
      setErrorMsg(typeof detail === 'string' ? detail : JSON.stringify(detail))
      setStatus('error')
    }
  }

  const reset = () => {
    setFile(null)
    setPreview([])
    setStatus('idle')
    setErrorMsg(null)
    setResultSummary(null)
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.15 }}
      className="p-8 max-w-4xl mx-auto"
    >
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-xl font-bold font-mono tracking-wide mb-1" style={{ color: '#e2e8f0' }}>
          Log Ingestion Portal
        </h1>
        <p className="text-xs font-mono" style={{ color: '#475569' }}>
          Upload any log file → 7-layer detection pipeline → tickets generated automatically
        </p>
      </div>

      {/* Drop zone */}
      <div
        {...getRootProps()}
        className="relative border-2 border-dashed rounded-xl p-12 transition-all duration-200 cursor-pointer"
        style={{
          borderColor: isDragActive ? '#3B82F6' : 'rgba(30,40,60,0.6)',
          backgroundColor: isDragActive ? 'rgba(59,130,246,0.05)' : 'rgba(17,24,39,0.5)',
          boxShadow: isDragActive ? '0 0 20px rgba(59,130,246,0.2)' : 'none',
        }}
      >
        <input {...getInputProps()} />
        <div className="flex flex-col items-center justify-center text-center gap-3">
          <div
            className="p-4 rounded-full"
            style={{ backgroundColor: isDragActive ? 'rgba(59,130,246,0.15)' : 'rgba(30,40,60,0.6)' }}
          >
            <Upload
              className="w-8 h-8"
              style={{ color: isDragActive ? '#3B82F6' : '#475569' }}
            />
          </div>
          <p className="text-base font-medium" style={{ color: '#e2e8f0' }}>
            {isDragActive ? 'Drop the log file here' : 'Drag & drop a log file'}
          </p>
          <p className="text-xs font-mono" style={{ color: '#334155' }}>
            .log · .txt · .json · .csv · .xml · .cef — any format, max 50 MB
          </p>
        </div>
      </div>

      {/* File panel */}
      <AnimatePresence>
        {file && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
            className="mt-6 flex flex-col gap-4 overflow-hidden"
          >
            {/* File info row */}
            <div
              className="flex items-center justify-between p-4 rounded-lg"
              style={{ backgroundColor: 'rgba(17,24,39,0.85)', border: '1px solid rgba(30,40,60,0.6)' }}
            >
              <div className="flex items-center gap-3">
                <FileText className="w-4 h-4 shrink-0" style={{ color: '#3B82F6' }} />
                <div>
                  <p className="text-sm font-mono font-medium" style={{ color: '#e2e8f0' }}>{file.name}</p>
                  <p className="text-[10px] font-mono mt-0.5" style={{ color: '#475569' }}>
                    {(file.size / 1024).toFixed(1)} KB
                  </p>
                </div>
              </div>
              <button
                onClick={reset}
                className="p-1 rounded transition-colors"
                style={{ color: '#475569' }}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Log preview */}
            {preview.length > 0 && (
              <div
                className="rounded-lg p-4 overflow-hidden"
                style={{ backgroundColor: '#0B0F14', border: '1px solid rgba(30,40,60,0.6)' }}
              >
                <p
                  className="text-[9px] font-mono font-semibold tracking-widest uppercase mb-2"
                  style={{ color: '#334155' }}
                >
                  Preview — first {preview.length} lines
                </p>
                {preview.map((line, i) => (
                  <div
                    key={i}
                    className="text-[10px] font-mono truncate py-0.5"
                    style={{ color: '#475569' }}
                  >
                    <span style={{ color: '#1e3a5f' }}>{String(i + 1).padStart(2, '0')} </span>
                    {line}
                  </div>
                ))}
              </div>
            )}

            {/* Result summary */}
            {resultSummary && (
              <div
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-mono"
                style={{
                  backgroundColor: 'rgba(34,197,94,0.08)',
                  border: '1px solid rgba(34,197,94,0.25)',
                  color: '#22C55E',
                }}
              >
                <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                {resultSummary}
              </div>
            )}

            {/* Error detail */}
            {errorMsg && (
              <div
                className="px-4 py-3 rounded-lg text-[10px] font-mono"
                style={{
                  backgroundColor: 'rgba(239,68,68,0.08)',
                  border: '1px solid rgba(239,68,68,0.3)',
                  color: '#fca5a5',
                }}
              >
                <span style={{ color: '#EF4444', fontWeight: 600 }}>PIPELINE ERROR: </span>
                {errorMsg}
              </div>
            )}

            {/* Upload button */}
            <button
              onClick={handleUpload}
              disabled={status === 'uploading' || status === 'success'}
              className="w-full py-3 rounded-lg font-bold font-mono text-sm flex items-center justify-center gap-2 transition-all"
              style={{
                backgroundColor:
                  status === 'idle'      ? '#2563EB' :
                  status === 'uploading' ? 'rgba(30,40,60,0.6)' :
                  status === 'success'   ? '#16A34A' :
                  /* error */              '#DC2626',
                color:
                  status === 'uploading' ? '#475569' : '#ffffff',
                cursor: status === 'uploading' || status === 'success' ? 'not-allowed' : 'pointer',
                boxShadow: status === 'idle' ? '0 0 16px rgba(37,99,235,0.3)' : 'none',
              }}
            >
              {status === 'idle'      && <><Upload className="w-4 h-4" /> Inject into Pipeline</>}
              {status === 'uploading' && <><Loader2 className="w-4 h-4 animate-spin" /> Processing through 7 layers...</>}
              {status === 'success'   && <><CheckCircle2 className="w-4 h-4" /> Analysis Complete</>}
              {status === 'error'     && <><AlertCircle className="w-4 h-4" /> Retry Upload</>}
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
