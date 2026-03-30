import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, useLocation, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Sidebar } from './components/layout/Sidebar'
import { TopBar } from './components/layout/TopBar'
import { ToastSystem, useToasts } from './components/shared/ToastSystem'
import { Dashboard } from './pages/Dashboard'
import { Tickets } from './pages/Tickets'
import { Investigations } from './pages/Investigations'
import { Playbooks } from './pages/Playbooks'
import { Trends } from './pages/Trends'
import { LogIngest } from './pages/LogIngest'
import { NoisyLogIngest } from './pages/NoisyLogIngest'
import { useBackendData } from './hooks/useBackendData'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 2, staleTime: 30000 } },
})

const PAGE_TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/tickets': 'Tickets',
  '/investigations': 'Investigations',
  '/playbooks': 'Playbooks',
  '/trends': 'Trends',
  '/ingest': 'Log Ingest',
  '/noisy-log-ingest': 'Noisy Log Ingest',
}

function AppShell() {
  const location = useLocation()
  const navigate  = useNavigate()
  const { state, ingestFile, clearTickets } = useBackendData()
  const { toasts, push, dismiss } = useToasts()
  const pageTitle = PAGE_TITLES[location.pathname] ?? 'TuxSOC'
  const systemHealthy = state.layers.every(l => l.status !== 'ERROR')

  // ── Mode change toasts ──────────────────────────────────────────────
  useEffect(() => {
    if (state.mode === 'demo') {
      push({
        level: 'warn',
        title: 'Offline — Demo Mode',
        message: 'Backend unreachable. Running on mock data.',
        persistent: false,
      })
    }
    if (state.mode === 'live') {
      push({
        level: 'success',
        title: 'Backend Connected',
        message: 'Live data from FastAPI pipeline active.',
      })
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.mode])

  // ── Critical ticket toasts ──────────────────────────────────────────
  useEffect(() => {
    const criticals = state.tickets.filter(
      t => t.severity === 'CRITICAL' && t.status === 'OPEN'
    )
    if (criticals.length > 0 && state.mode === 'live') {
      push({
        level: 'critical',
        title: `${criticals.length} CRITICAL incident${criticals.length > 1 ? 's' : ''} active`,
        message: criticals[0].intent,
        persistent: true,
      })
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.rawDetections.length])

  return (
    <div className="min-h-screen" style={{ backgroundColor: '#0B0F14' }}>
      <Sidebar systemHealthy={systemHealthy} />
      <TopBar
        pageTitle={pageTitle}
        layers={state.layers}
        lastSynced={state.lastSynced}
        mode={state.mode}
      />

      {/* Main content */}
      <main style={{ marginLeft: 56, marginTop: 56, minHeight: 'calc(100vh - 56px)' }}>
        <Routes>
          <Route path="/" element={
            <Dashboard
              simulation={{
                layers: state.layers,
                liveEvents: [],
                logStream: state.logStream,
                activeBeams: state.activeBeams,
                kpi: state.kpi,
              }}
            />
          } />
          <Route path="/tickets" element={<Tickets state={state} />} />
          <Route path="/investigations" element={<Investigations />} />
          <Route path="/playbooks" element={<Playbooks state={state} />} />
          <Route path="/trends" element={<Trends />} />
          <Route path="/ingest" element={
            <LogIngest
              onUploadStart={clearTickets}
              onSuccess={(detections) => {
                const pbCount = detections.filter(d => d.suggested_playbook).length
                push({
                  level: 'success',
                  title: `${detections.length} events processed — ${pbCount} playbook${pbCount !== 1 ? 's' : ''} generated`,
                  message: 'View response strategies →',
                  persistent: false,
                })
                // Navigate to Playbooks after a short delay so the toast is visible
                setTimeout(() => navigate('/playbooks'), 1200)
              }}
              ingestFile={(file) =>
                ingestFile(file, ({ status, detail }) => {
                  push({
                    level: 'critical',
                    title: `Pipeline Error${status ? ` — HTTP ${status}` : ' — Network Error'}`,
                    message: typeof detail === 'string' ? detail.slice(0, 120) : 'Check console for details',
                    persistent: false,
                  })
                })
              }
            />
          } />
          <Route path="/noisy-log-ingest" element={<NoisyLogIngest />} />
        </Routes>
      </main>

      <ToastSystem toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppShell />
      </BrowserRouter>
    </QueryClientProvider>
  )
}
